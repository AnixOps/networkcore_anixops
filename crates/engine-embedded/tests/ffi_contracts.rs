//! C ABI contract tests, calling the exported symbols the way Swift does.

use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

use engine_embedded::ffi::*;

const DIRECT_CONFIG: &str =
    r#"{"schema_version":1,"profile_id":"test-direct","outbound":{"type":"direct"}}"#;

fn init(config: &str) -> (i32, *mut NetworkCoreRuntime) {
    let mut handle = ptr::null_mut();
    let code = unsafe { networkcore_ios_runtime_init(config.as_ptr(), config.len(), &mut handle) };
    (code, handle)
}

fn status_json(handle: *mut NetworkCoreRuntime) -> serde_json::Value {
    let mut buffer = NetworkCoreBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe { networkcore_ios_runtime_collect_status(handle, &mut buffer) };
    assert_eq!(code, NETWORKCORE_IOS_OK);
    let bytes = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) }.to_vec();
    unsafe { networkcore_ios_runtime_free_buffer(buffer) };
    serde_json::from_slice(&bytes).unwrap()
}

extern "C" fn count_packets(context: *mut c_void, _packet: *const u8, _len: usize) {
    let counter = unsafe { &*(context as *const AtomicUsize) };
    counter.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn versions_match_the_swift_handshake() {
    assert_eq!(networkcore_ios_abi_version(), 1);
    assert_eq!(networkcore_ios_schema_version(), 1);
    assert_eq!(networkcore_ios_feature_set_version(), 2);
}

#[test]
fn init_rejects_bad_input_with_stable_codes() {
    let mut handle = ptr::null_mut();
    assert_eq!(
        unsafe { networkcore_ios_runtime_init(ptr::null(), 10, &mut handle) },
        NETWORKCORE_IOS_ERR_INVALID_ARGUMENT
    );
    assert!(handle.is_null());
    assert_eq!(
        unsafe {
            networkcore_ios_runtime_init(
                DIRECT_CONFIG.as_ptr(),
                DIRECT_CONFIG.len(),
                ptr::null_mut(),
            )
        },
        NETWORKCORE_IOS_ERR_INVALID_ARGUMENT
    );

    let (code, handle) = init("not json");
    assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED);
    assert!(handle.is_null());

    let (code, _) = init(r#"{"schema_version":2,"profile_id":"p","outbound":{"type":"direct"}}"#);
    assert_eq!(code, NETWORKCORE_IOS_ERR_SCHEMA_MISMATCH);

    let (code, _) =
        init(r#"{"schema_version":1,"profile_id":"p","outbound":{"type":"direct"},"extra":1}"#);
    assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED);

    let (code, _) =
        init(r#"{"schema_version":1,"profile_id":"bad id/../","outbound":{"type":"direct"}}"#);
    assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED);

    let (code, _) = init(
        r#"{"schema_version":1,"profile_id":"p","outbound":{"type":"shadowsocks","server":"example.com","port":8388,"method":"aes-256-cfb","password":"x"}}"#,
    );
    assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED);

    let (code, _) = init(
        r#"{"schema_version":1,"profile_id":"p","outbound":{"type":"shadowsocks","server":"example.com","port":8388,"method":"2022-blake3-aes-128-gcm","password":"c2hvcnQ="}}"#,
    );
    assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED);

    let (code, _) = init(r#"{"schema_version":1,"profile_id":"p","outbound":{"server":"x"}}"#);
    assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED);
}

#[test]
fn unknown_outbound_types_are_rejected_by_the_registry() {
    for kind in ["no-such-protocol", "Direct", ""] {
        let config = format!(
            r#"{{"schema_version":1,"profile_id":"p","outbound":{{"type":"{kind}","server":"192.0.2.1","port":1}}}}"#
        );
        let (code, handle) = init(&config);
        assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED, "{kind}");
        assert!(handle.is_null());
    }
}

#[test]
fn supported_types_follow_cargo_features() {
    let types = engine_embedded::protocols::supported_types();
    assert!(types.contains(&"direct"));
    assert_eq!(
        types.contains(&"shadowsocks"),
        cfg!(feature = "shadowsocks")
    );
    assert_eq!(types.contains(&"http"), cfg!(feature = "http"));
    assert_eq!(types.contains(&"hysteria2"), cfg!(feature = "hysteria2"));
    assert_eq!(types.contains(&"mieru"), cfg!(feature = "mieru"));
    assert_eq!(types.contains(&"snell"), cfg!(feature = "snell"));
    assert_eq!(types.contains(&"socks"), cfg!(feature = "socks"));
    assert_eq!(types.contains(&"trojan"), cfg!(feature = "trojan"));
    assert_eq!(types.contains(&"tuic"), cfg!(feature = "tuic"));
    assert_eq!(types.contains(&"vless"), cfg!(feature = "vless"));
    assert_eq!(types.contains(&"vmess"), cfg!(feature = "vmess"));
    assert_eq!(types.contains(&"wireguard"), cfg!(feature = "wireguard"));
}

#[cfg(feature = "wireguard")]
#[test]
fn wireguard_cannot_be_a_routed_node() {
    let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    let config = format!(
        r#"{{"schema_version":1,"profile_id":"p","routing":{{"outbounds":{{"wg":{{"type":"wireguard","private_key":"{key}","peer_public_key":"{key}","server":"192.0.2.1","port":51820}}}},"rules":["FINAL,wg"]}}}}"#
    );
    let (code, handle) = init(&config);
    assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED);
    assert!(handle.is_null());
}

#[cfg(feature = "shadowsocks")]
#[test]
fn shadowsocks_config_is_accepted_and_status_hides_the_key() {
    let password = "AAECAwQFBgcICQoLDA0ODw==";
    let config = format!(
        r#"{{"schema_version":1,"profile_id":"node-1","outbound":{{"type":"shadowsocks","server":"192.0.2.10","port":8388,"method":"2022-blake3-aes-128-gcm","password":"{password}"}}}}"#
    );
    let (code, handle) = init(&config);
    assert_eq!(code, NETWORKCORE_IOS_OK);
    assert!(!handle.is_null());

    let status = status_json(handle);
    assert_eq!(status["profile_id"], "node-1");
    assert_eq!(status["outbound"], "shadowsocks-2022");
    assert_eq!(status["state"], "initialized");
    assert!(!status.to_string().contains(password));
    assert!(!status.to_string().contains("192.0.2.10"));

    unsafe { networkcore_ios_runtime_free_handle(handle) };
}

#[cfg(feature = "vless")]
const VLESS_UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
#[cfg(feature = "vless")]
const REALITY_PUBLIC_KEY: &str = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw";

#[cfg(feature = "vless")]
fn vless_config(flow: &str, uuid: &str, public_key: &str, short_id: &str) -> String {
    format!(
        r#"{{"schema_version":1,"profile_id":"node-2","outbound":{{"type":"vless","server":"192.0.2.20","port":443,"uuid":"{uuid}","flow":"{flow}","reality":{{"server_name":"www.example.com","public_key":"{public_key}","short_id":"{short_id}"}}}}}}"#
    )
}

#[cfg(feature = "vless")]
#[test]
fn vless_reality_config_is_accepted_and_status_hides_credentials() {
    for flow in ["xtls-rprx-vision", ""] {
        let (code, handle) = init(&vless_config(
            flow,
            VLESS_UUID,
            REALITY_PUBLIC_KEY,
            "6ba85179e30d4fc2",
        ));
        assert_eq!(code, NETWORKCORE_IOS_OK, "flow {flow:?}");
        let status = status_json(handle).to_string();
        assert!(status.contains(r#""outbound":"vless""#));
        assert!(!status.contains(VLESS_UUID));
        assert!(!status.contains(REALITY_PUBLIC_KEY));
        assert!(!status.contains("6ba85179e30d4fc2"));
        assert!(!status.contains("192.0.2.20"));
        unsafe { networkcore_ios_runtime_free_handle(handle) };
    }
}

#[cfg(feature = "vless")]
#[test]
fn invalid_vless_reality_settings_are_rejected() {
    for config in [
        vless_config("xtls-rprx-vision", "not-a-uuid", REALITY_PUBLIC_KEY, ""),
        vless_config("xtls-rprx-direct", VLESS_UUID, REALITY_PUBLIC_KEY, ""),
        vless_config("", VLESS_UUID, "c2hvcnQ", ""),
        vless_config("", VLESS_UUID, REALITY_PUBLIC_KEY, "0011223344556677889"),
        vless_config("", VLESS_UUID, REALITY_PUBLIC_KEY, "zz"),
    ] {
        let (code, handle) = init(&config);
        assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED, "{config}");
        assert!(handle.is_null());
    }

    let (code, _) = init(
        r#"{"schema_version":1,"profile_id":"p","outbound":{"type":"vless","server":"192.0.2.20","port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","reality":{"server_name":"www.example.com","public_key":"Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw","spider_x":"/"}}}"#,
    );
    assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED);
}

#[test]
fn lifecycle_is_idempotent_and_null_safe() {
    let (code, handle) = init(DIRECT_CONFIG);
    assert_eq!(code, NETWORKCORE_IOS_OK);

    let packets = Box::new(AtomicUsize::new(0));
    let context = &*packets as *const AtomicUsize as *mut c_void;

    assert_eq!(
        unsafe { networkcore_ios_runtime_start_tunnel(handle, None, context) },
        NETWORKCORE_IOS_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        unsafe { networkcore_ios_runtime_start_tunnel(handle, Some(count_packets), context) },
        NETWORKCORE_IOS_OK
    );
    assert_eq!(
        unsafe { networkcore_ios_runtime_start_tunnel(handle, Some(count_packets), context) },
        NETWORKCORE_IOS_ERR_INVALID_ARGUMENT
    );
    assert_eq!(status_json(handle)["state"], "running");
    assert_eq!(status_json(handle)["last_error"], "invalid_argument");

    // Not an IP packet: accepted into the queue, then discarded by the stack.
    let junk = [0u8; 20];
    assert_eq!(
        unsafe { networkcore_ios_runtime_input_packet(handle, junk.as_ptr(), junk.len()) },
        NETWORKCORE_IOS_OK
    );
    assert_eq!(
        unsafe { networkcore_ios_runtime_input_packet(handle, ptr::null(), 20) },
        NETWORKCORE_IOS_ERR_INVALID_ARGUMENT
    );

    assert_eq!(
        unsafe { networkcore_ios_runtime_stop_tunnel(handle) },
        NETWORKCORE_IOS_OK
    );
    assert_eq!(
        unsafe { networkcore_ios_runtime_stop_tunnel(handle) },
        NETWORKCORE_IOS_OK
    );
    assert_eq!(status_json(handle)["state"], "stopped");
    assert_eq!(
        unsafe { networkcore_ios_runtime_input_packet(handle, junk.as_ptr(), junk.len()) },
        NETWORKCORE_IOS_ERR_PACKET_DROPPED
    );

    unsafe { networkcore_ios_runtime_free_handle(handle) };
    unsafe { networkcore_ios_runtime_free_handle(ptr::null_mut()) };
    assert_eq!(
        unsafe { networkcore_ios_runtime_stop_tunnel(ptr::null_mut()) },
        NETWORKCORE_IOS_ERR_INVALID_ARGUMENT
    );
    unsafe {
        networkcore_ios_runtime_free_buffer(NetworkCoreBuffer {
            ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        })
    };
    drop(packets);
}

fn control(handle: *mut NetworkCoreRuntime, request: &str) -> (i32, Option<serde_json::Value>) {
    let mut buffer = NetworkCoreBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let code = unsafe {
        networkcore_ios_runtime_control(handle, request.as_ptr(), request.len(), &mut buffer)
    };
    let answer = (!buffer.ptr.is_null() && buffer.len > 0).then(|| {
        let bytes = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) };
        serde_json::from_slice(bytes).unwrap()
    });
    unsafe { networkcore_ios_runtime_free_buffer(buffer) };
    (code, answer)
}

#[test]
fn control_answers_json_and_rejects_bad_requests() {
    let (code, handle) = init(DIRECT_CONFIG);
    assert_eq!(code, NETWORKCORE_IOS_OK);

    let (code, traffic) = control(handle, r#"{"cmd":"traffic"}"#);
    assert_eq!(code, NETWORKCORE_IOS_OK);
    let traffic = traffic.unwrap();
    assert_eq!(traffic["upload_total"], 0);
    assert_eq!(traffic["active"], 0);

    let (code, list) = control(handle, r#"{"cmd":"connections"}"#);
    assert_eq!(code, NETWORKCORE_IOS_OK);
    let list = list.unwrap();
    assert!(list["active"].as_array().unwrap().is_empty());
    assert!(list["closed"].as_array().unwrap().is_empty());

    let (code, closed) = control(handle, r#"{"cmd":"close_connection","id":7}"#);
    assert_eq!(code, NETWORKCORE_IOS_OK);
    assert_eq!(closed.unwrap()["closed"], false);

    let (code, answer) = control(handle, r#"{"cmd":"unknown"}"#);
    assert_eq!(code, NETWORKCORE_IOS_ERR_INVALID_ARGUMENT);
    assert!(answer.is_none());
    let (code, _) = control(handle, "");
    assert_eq!(code, NETWORKCORE_IOS_ERR_INVALID_ARGUMENT);
    let (code, _) = control(ptr::null_mut(), r#"{"cmd":"traffic"}"#);
    assert_eq!(code, NETWORKCORE_IOS_ERR_INVALID_ARGUMENT);
    let request = r#"{"cmd":"traffic"}"#;
    let code = unsafe {
        networkcore_ios_runtime_control(handle, request.as_ptr(), request.len(), ptr::null_mut())
    };
    assert_eq!(code, NETWORKCORE_IOS_ERR_INVALID_ARGUMENT);

    unsafe { networkcore_ios_runtime_free_handle(handle) };
}

#[test]
fn header_declares_every_exported_symbol() {
    let header = include_str!("../include/networkcore_ios_runtime.h");
    for symbol in [
        "networkcore_ios_abi_version",
        "networkcore_ios_schema_version",
        "networkcore_ios_feature_set_version",
        "networkcore_ios_runtime_init",
        "networkcore_ios_runtime_start_tunnel",
        "networkcore_ios_runtime_input_packet",
        "networkcore_ios_runtime_stop_tunnel",
        "networkcore_ios_runtime_collect_status",
        "networkcore_ios_runtime_control",
        "networkcore_ios_measure_delay",
        "networkcore_ios_runtime_free_buffer",
        "networkcore_ios_runtime_free_handle",
    ] {
        assert!(
            header.contains(&format!("{symbol}(")),
            "header is missing {symbol}"
        );
    }
    for (name, value) in [
        ("NETWORKCORE_IOS_OK", NETWORKCORE_IOS_OK),
        (
            "NETWORKCORE_IOS_ERR_SCHEMA_MISMATCH",
            NETWORKCORE_IOS_ERR_SCHEMA_MISMATCH,
        ),
        (
            "NETWORKCORE_IOS_ERR_INVALID_ARGUMENT",
            NETWORKCORE_IOS_ERR_INVALID_ARGUMENT,
        ),
        (
            "NETWORKCORE_IOS_ERR_CONFIG_REJECTED",
            NETWORKCORE_IOS_ERR_CONFIG_REJECTED,
        ),
        (
            "NETWORKCORE_IOS_ERR_PANIC_CAUGHT",
            NETWORKCORE_IOS_ERR_PANIC_CAUGHT,
        ),
        (
            "NETWORKCORE_IOS_ERR_PACKET_DROPPED",
            NETWORKCORE_IOS_ERR_PACKET_DROPPED,
        ),
        (
            "NETWORKCORE_IOS_ERR_DELAY_TIMEOUT",
            NETWORKCORE_IOS_ERR_DELAY_TIMEOUT,
        ),
        (
            "NETWORKCORE_IOS_ERR_DELAY_FAILED",
            NETWORKCORE_IOS_ERR_DELAY_FAILED,
        ),
    ] {
        // Compare whole lines: Windows checkouts may use CRLF.
        let define = format!("#define {name} {value}");
        assert!(
            header.lines().any(|line| line.trim_end() == define),
            "header value for {name}"
        );
    }
}

#[cfg(feature = "shadowsocks")]
#[test]
fn routing_config_is_accepted_and_status_hides_rules_and_keys() {
    let password = "AAECAwQFBgcICQoLDA0ODw==";
    let config = format!(
        r#"{{"schema_version":1,"profile_id":"routed","routing":{{"outbounds":{{"hk-1":{{"type":"shadowsocks","server":"192.0.2.10","port":8388,"method":"2022-blake3-aes-128-gcm","password":"{password}"}}}},"rules":["IP-CIDR,10.0.0.0/8,DIRECT,no-resolve","DOMAIN-SUFFIX,secret-rule.example,Proxy","FINAL,Proxy"],"groups":[{{"id":"Proxy","type":"select","members":["hk-1","DIRECT"]}}]}}}}"#
    );
    let (code, handle) = init(&config);
    assert_eq!(code, NETWORKCORE_IOS_OK);

    let status = status_json(handle).to_string();
    assert!(status.contains(r#""outbound":"routed""#));
    assert!(!status.contains(password));
    assert!(!status.contains("192.0.2.10"));
    assert!(!status.contains("secret-rule"));

    unsafe { networkcore_ios_runtime_free_handle(handle) };
}

#[test]
fn routing_config_rejects_ambiguous_or_invalid_sections() {
    let routing = r#""routing":{"outbounds":{"direct-node":{"type":"direct"}},"rules":["FINAL,direct-node"]}"#;

    let (code, handle) = init(&format!(
        r#"{{"schema_version":1,"profile_id":"p",{routing}}}"#
    ));
    assert_eq!(code, NETWORKCORE_IOS_OK);
    unsafe { networkcore_ios_runtime_free_handle(handle) };

    let (code, _) = init(&format!(
        r#"{{"schema_version":1,"profile_id":"p","outbound":{{"type":"direct"}},{routing}}}"#
    ));
    assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED);

    let (code, _) = init(r#"{"schema_version":1,"profile_id":"p"}"#);
    assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED);

    let (code, _) = init(
        r#"{"schema_version":1,"profile_id":"p","routing":{"outbounds":{"hk-1":{"type":"direct"}},"rules":["DOMAIN,a.example,missing"]}}"#,
    );
    assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED);

    let (code, _) = init(
        r#"{"schema_version":1,"profile_id":"p","routing":{"outbounds":{"bad id":{"type":"direct"}},"rules":["FINAL,DIRECT"]}}"#,
    );
    assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED);
}

#[cfg(feature = "local-proxy")]
fn measure_delay(config: &str, url: &str, timeout_ms: u32) -> (i32, u32) {
    let mut millis = u32::MAX;
    let code = unsafe {
        networkcore_ios_measure_delay(
            config.as_ptr(),
            config.len(),
            url.as_ptr(),
            url.len(),
            timeout_ms,
            &mut millis,
        )
    };
    (code, millis)
}

/// Serves one fixed reply to every request on loopback.
#[cfg(feature = "local-proxy")]
fn http_server(reply: &'static [u8]) -> std::net::SocketAddr {
    use std::io::{Read, Write};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            std::thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let _ = stream.write_all(reply);
                let _ = stream.read(&mut byte);
            });
        }
    });
    addr
}

#[cfg(feature = "local-proxy")]
#[test]
fn measure_delay_reports_milliseconds_through_the_outbound() {
    let server = http_server(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
    let (code, millis) = measure_delay(
        DIRECT_CONFIG,
        &format!("http://{server}/generate_204"),
        10_000,
    );
    assert_eq!(code, NETWORKCORE_IOS_OK);
    assert!((1..10_000).contains(&millis));
}

#[cfg(feature = "local-proxy")]
#[test]
fn measure_delay_maps_failures_to_stable_codes() {
    let not_http = http_server(b"SSH-2.0-OpenSSH_9.6\r\n");
    assert_eq!(
        measure_delay(DIRECT_CONFIG, &format!("http://{not_http}/"), 10_000),
        (NETWORKCORE_IOS_ERR_DELAY_FAILED, 0)
    );

    let closed = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    assert_eq!(
        measure_delay(DIRECT_CONFIG, &format!("http://{closed}/"), 10_000),
        (NETWORKCORE_IOS_ERR_DELAY_FAILED, 0)
    );

    // Accepts but never answers.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let silent_addr = silent.local_addr().unwrap();
    assert_eq!(
        measure_delay(DIRECT_CONFIG, &format!("http://{silent_addr}/"), 200),
        (NETWORKCORE_IOS_ERR_DELAY_TIMEOUT, 0)
    );
    drop(silent);

    assert_eq!(
        measure_delay(DIRECT_CONFIG, "ftp://example.com/", 1_000).0,
        NETWORKCORE_IOS_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        measure_delay(DIRECT_CONFIG, "http://example.com/", 0).0,
        NETWORKCORE_IOS_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        measure_delay("{}", "http://example.com/", 1_000).0,
        NETWORKCORE_IOS_ERR_CONFIG_REJECTED
    );
    assert_eq!(
        unsafe {
            networkcore_ios_measure_delay(
                DIRECT_CONFIG.as_ptr(),
                DIRECT_CONFIG.len(),
                "http://example.com/".as_ptr(),
                19,
                1_000,
                ptr::null_mut(),
            )
        },
        NETWORKCORE_IOS_ERR_INVALID_ARGUMENT
    );
}
