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
    assert_eq!(networkcore_ios_feature_set_version(), 1);
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
        r#"{"schema_version":1,"profile_id":"p","outbound":{"type":"shadowsocks","server":"example.com","port":8388,"method":"aes-256-gcm","password":"x"}}"#,
    );
    assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED);

    let (code, _) = init(
        r#"{"schema_version":1,"profile_id":"p","outbound":{"type":"shadowsocks","server":"example.com","port":8388,"method":"2022-blake3-aes-128-gcm","password":"c2hvcnQ="}}"#,
    );
    assert_eq!(code, NETWORKCORE_IOS_ERR_CONFIG_REJECTED);
}

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
    ] {
        // Compare whole lines: Windows checkouts may use CRLF.
        let define = format!("#define {name} {value}");
        assert!(
            header.lines().any(|line| line.trim_end() == define),
            "header value for {name}"
        );
    }
}

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
