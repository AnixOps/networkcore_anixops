//! Desktop local proxy mode: the config envelope served as a SOCKS5/HTTP
//! listener on loopback.

#![cfg(feature = "local-proxy")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

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
