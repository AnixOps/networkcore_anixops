//! Desktop local proxy mode: the config envelope served as a SOCKS5/HTTP
//! listener on loopback.

#![cfg(feature = "local-proxy")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use engine_embedded::delay::{measure_delay, DelayError};
use engine_embedded::local_proxy::LocalProxy;
use engine_embedded::RuntimeErrorCode;
use inbound_mixed::MixedSettings;

const WAIT: Duration = Duration::from_secs(10);

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind(loopback()).unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            thread::spawn(move || {
                let mut reader = stream.try_clone().unwrap();
                let _ = std::io::copy(&mut reader, &mut stream);
            });
        }
    });
    addr
}

fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> (TcpStream, u8) {
    let SocketAddr::V4(target) = target else {
        panic!("ipv4 target expected");
    };
    let mut stream = TcpStream::connect(proxy).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).unwrap();
    assert_eq!(method, [0x05, 0x00]);
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).unwrap();
    (stream, reply[1])
}

#[test]
fn direct_config_relays_through_the_local_listener() {
    let echo = echo_server();
    let mut proxy = LocalProxy::start(
        br#"{"schema_version":1,"profile_id":"desktop","outbound":{"type":"direct"}}"#,
        loopback(),
        MixedSettings::default(),
    )
    .unwrap();
    assert!(proxy.is_running());
    assert_eq!(proxy.profile_id(), "desktop");
    assert_eq!(proxy.protocol(), "direct");

    let (mut stream, reply) = socks_connect(proxy.local_addr(), echo);
    assert_eq!(reply, 0x00);
    stream.write_all(b"hello").unwrap();
    let mut echoed = [0u8; 5];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"hello");

    proxy.stop();
    assert!(!proxy.is_running());
    assert!(TcpStream::connect(proxy.local_addr()).is_err());
    proxy.stop();
}

#[test]
fn routing_rules_apply_to_local_proxy_connections() {
    let echo = echo_server();
    let proxy = LocalProxy::start(
        br#"{"schema_version":1,"profile_id":"routed","routing":{"outbounds":{"node":{"type":"direct"}},"rules":["IP-CIDR,127.0.0.0/8,REJECT,no-resolve","FINAL,node"]}}"#,
        loopback(),
        MixedSettings::default(),
    )
    .unwrap();
    assert_eq!(proxy.protocol(), "routed");
    let (_stream, reply) = socks_connect(proxy.local_addr(), echo);
    assert_eq!(reply, 0x01, "rejected by rule");
}

#[test]
fn rule_sets_in_the_envelope_apply_to_local_proxy_connections() {
    let echo = echo_server();
    let proxy = LocalProxy::start(
        br#"{"schema_version":1,"profile_id":"routed","routing":{"outbounds":{"node":{"type":"direct"}},"rules":["RULE-SET,blocked,REJECT","FINAL,node"],"rule_sets":{"blocked":{"domain_suffix":["blocked.example"],"ip_cidr":["127.0.0.0/8"]}}}}"#,
        loopback(),
        MixedSettings::default(),
    )
    .unwrap();
    let (_stream, reply) = socks_connect(proxy.local_addr(), echo);
    assert_eq!(reply, 0x01, "rejected by the rule set");

    for bad in [
        // The rule names a set the envelope does not carry.
        br#"{"schema_version":1,"profile_id":"p","routing":{"outbounds":{"node":{"type":"direct"}},"rules":["RULE-SET,missing,REJECT","FINAL,node"]}}"#.as_slice(),
        br#"{"schema_version":1,"profile_id":"p","routing":{"outbounds":{"node":{"type":"direct"}},"rules":["FINAL,node"],"rule_sets":{"bad":{"ip_cidr":["10.0.0.0/40"]}}}}"#.as_slice(),
        br#"{"schema_version":1,"profile_id":"p","routing":{"outbounds":{"node":{"type":"direct"}},"rules":["FINAL,node"],"rule_sets":{"bad name":{}}}}"#.as_slice(),
    ] {
        let err = LocalProxy::start(bad, loopback(), MixedSettings::default())
            .err()
            .unwrap();
        assert_eq!(err.code, RuntimeErrorCode::ConfigRejected);
    }
}

#[test]
fn bad_configs_and_busy_ports_are_reported() {
    let err = LocalProxy::start(
        br#"{"schema_version":1,"profile_id":"p","outbound":{"type":"no-such-protocol"}}"#,
        loopback(),
        MixedSettings::default(),
    )
    .err()
    .unwrap();
    assert_eq!(err.code, RuntimeErrorCode::ConfigRejected);

    let taken = TcpListener::bind(loopback()).unwrap();
    let err = LocalProxy::start(
        br#"{"schema_version":1,"profile_id":"p","outbound":{"type":"direct"}}"#,
        taken.local_addr().unwrap(),
        MixedSettings::default(),
    )
    .err()
    .unwrap();
    assert_eq!(err.code, RuntimeErrorCode::ResourceExhausted);
}

const DIRECT: &[u8] =
    br#"{"schema_version":1,"profile_id":"desktop","outbound":{"type":"direct"}}"#;

/// Answers every connection with `reply` once it has read the request head.
fn http_server(reply: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind(loopback()).unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                assert!(head.starts_with(b"GET /generate_204 HTTP/1.1\r\n"));
                let _ = stream.write_all(reply);
                // The client closes once it has the status line.
                let _ = stream.read(&mut byte);
            });
        }
    });
    addr
}

#[test]
fn delay_test_times_the_status_line_through_the_outbound() {
    let server = http_server(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
    let delay = measure_delay(DIRECT, &format!("http://{server}/generate_204"), WAIT).unwrap();
    assert!(delay < WAIT);
}

#[test]
fn delay_test_reports_non_http_unreachable_and_bad_input() {
    let server = http_server(b"SSH-2.0-OpenSSH_9.6\r\n");
    assert_eq!(
        measure_delay(DIRECT, &format!("http://{server}/generate_204"), WAIT),
        Err(DelayError::NotHttp)
    );

    let closed = TcpListener::bind(loopback()).unwrap().local_addr().unwrap();
    assert!(matches!(
        measure_delay(DIRECT, &format!("http://{closed}/generate_204"), WAIT),
        Err(DelayError::Failed(_))
    ));

    // Accepts but never answers.
    let silent = TcpListener::bind(loopback()).unwrap();
    let silent_addr = silent.local_addr().unwrap();
    assert_eq!(
        measure_delay(
            DIRECT,
            &format!("http://{silent_addr}/generate_204"),
            Duration::from_millis(200)
        ),
        Err(DelayError::Timeout)
    );
    drop(silent);

    assert_eq!(
        measure_delay(DIRECT, "ftp://example.com/", WAIT),
        Err(DelayError::InvalidUrl)
    );
    assert!(matches!(
        measure_delay(b"{}", "http://example.com/", WAIT),
        Err(DelayError::Config(_))
    ));
}

fn own_process_name() -> String {
    std::env::current_exe()
        .unwrap()
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

#[test]
fn process_lookup_names_the_process_that_owns_a_connection() {
    let listener = TcpListener::bind(loopback()).unwrap();
    let server = listener.local_addr().unwrap();
    let client = TcpStream::connect(server).unwrap();
    let (_accepted, peer) = listener.accept().unwrap();
    assert_eq!(peer, client.local_addr().unwrap());
    assert_eq!(
        engine_embedded::process::process_name(peer, server),
        Some(own_process_name())
    );
    // No connection runs from `peer` to another port.
    let elsewhere = SocketAddr::new(server.ip(), server.port().wrapping_add(1));
    assert_eq!(
        engine_embedded::process::process_name(peer, elsewhere),
        None
    );
}

#[test]
fn process_name_rules_apply_to_local_proxy_connections() {
    let echo = echo_server();
    let own = own_process_name().to_uppercase();
    let config = format!(
        r#"{{"schema_version":1,"profile_id":"routed","routing":{{"outbounds":{{"node":{{"type":"direct"}}}},"rules":["PROCESS-NAME,other-app,node","AND,((PROCESS-NAME,{own}),(DST-PORT,{port})),REJECT","FINAL,node"]}}}}"#,
        port = echo.port()
    );
    let proxy = LocalProxy::start(config.as_bytes(), loopback(), MixedSettings::default()).unwrap();
    let (_stream, reply) = socks_connect(proxy.local_addr(), echo);
    assert_eq!(reply, 0x01, "rejected by the PROCESS-NAME rule");
    let listed = proxy.control_json(br#"{"cmd":"connections"}"#).unwrap();
    let listed: serde_json::Value = serde_json::from_slice(&listed).unwrap();
    let closed = &listed["closed"][0];
    assert_eq!(closed["process"], own_process_name());
    assert_eq!(closed["error"], "rejected");

    // Another process name does not match.
    let config = config.replace(&own, "other-app");
    let proxy = LocalProxy::start(config.as_bytes(), loopback(), MixedSettings::default()).unwrap();
    let (_stream, reply) = socks_connect(proxy.local_addr(), echo);
    assert_eq!(reply, 0x00);
}
