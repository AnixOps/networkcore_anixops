//! Fuzzes the runtime control JSON the client sends while the engine runs,
//! through the same C entry point the iOS tunnel calls
//! (`networkcore_ios_runtime_control`).
//!
//! Two runtimes stay up for the whole run: one with policy groups, an inline
//! rule set and two nodes (every command has something to act on), and one
//! with a single outbound. Half of the inputs are raw bytes; the other half
//! are well-formed requests for a known command with fuzzed field values, so
//! the command handlers are reached as often as the JSON parser.
//!
//! The entry point catches panics and returns `NETWORKCORE_IOS_ERR_PANIC_CAUGHT`;
//! that code is a finding here, as is an answer that is not a JSON object or
//! an error code outside the documented set.

#![no_main]

use std::ptr;
use std::sync::OnceLock;

use arbitrary::{Arbitrary, Unstructured};
use engine_embedded::control::MAX_REQUEST_LEN;
use engine_embedded::ffi::{
    networkcore_ios_runtime_control, networkcore_ios_runtime_free_buffer,
    networkcore_ios_runtime_init, NetworkCoreBuffer, NetworkCoreRuntime,
    NETWORKCORE_IOS_ERR_INTERNAL_ERROR, NETWORKCORE_IOS_ERR_INVALID_ARGUMENT,
    NETWORKCORE_IOS_ERR_PANIC_CAUGHT, NETWORKCORE_IOS_OK,
};
use libfuzzer_sys::fuzz_target;

const ROUTED_CONFIG: &str = r#"{
  "schema_version": 1,
  "profile_id": "fuzz-routed",
  "routing": {
    "outbounds": {"hk-1": {"type": "direct"}, "jp-1": {"type": "direct"}},
    "rules": [
      "RULE-SET,ads,REJECT",
      "DOMAIN-SUFFIX,example.com,Proxy",
      "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
      "FINAL,Auto"
    ],
    "groups": [
      {"id": "Proxy", "type": "select", "members": ["hk-1", "jp-1", "DIRECT"]},
      {"id": "Auto", "type": "url-test", "members": ["hk-1", "jp-1"]}
    ],
    "rule_sets": {"ads": {"domain": ["ads.example"]}},
    "global": "Proxy"
  }
}"#;

const SINGLE_CONFIG: &str =
    r#"{"schema_version":1,"profile_id":"fuzz-single","outbound":{"type":"direct"}}"#;

const COMMANDS: [&str; 16] = [
    "traffic",
    "connections",
    "close_connection",
    "close_all",
    "mode",
    "set_mode",
    "groups",
    "select",
    "rule_sets",
    "update_rule_sets",
    "scripts",
    "script_notifications",
    "network_changed",
    "run_script",
    "outbound_health",
    "resume_outbound",
];

const NAMES: [&str; 8] = [
    "Proxy", "Auto", "hk-1", "jp-1", "DIRECT", "proxy", "rule", "global",
];

/// The runtimes, as addresses: the handles are only used from the fuzzing
/// thread, and the engine serializes access itself.
struct Runtimes {
    routed: usize,
    single: usize,
}

fn init(config: &str) -> usize {
    let mut handle: *mut NetworkCoreRuntime = ptr::null_mut();
    // SAFETY: `config` is valid for its length and `handle` is writable.
    let code = unsafe { networkcore_ios_runtime_init(config.as_ptr(), config.len(), &mut handle) };
    assert_eq!(code, NETWORKCORE_IOS_OK, "fuzz config rejected: {config}");
    assert!(!handle.is_null());
    handle as usize
}

fn runtimes() -> &'static Runtimes {
    static RUNTIMES: OnceLock<Runtimes> = OnceLock::new();
    RUNTIMES.get_or_init(|| Runtimes {
        routed: init(ROUTED_CONFIG),
        single: init(SINGLE_CONFIG),
    })
}

/// A field value: usually a plausible one, sometimes any JSON.
fn value(input: &mut Unstructured<'_>) -> arbitrary::Result<serde_json::Value> {
    Ok(match u8::arbitrary(input)? % 6 {
        0 => serde_json::Value::from(NAMES[usize::arbitrary(input)? % NAMES.len()]),
        1 => serde_json::Value::from(String::arbitrary(input)?),
        2 => serde_json::Value::from(u64::arbitrary(input)?),
        3 => serde_json::Value::from(i64::arbitrary(input)?),
        4 => serde_json::Value::from(bool::arbitrary(input)?),
        _ => serde_json::Value::Null,
    })
}

/// A request naming a known command, with fuzzed fields.
fn structured(input: &mut Unstructured<'_>) -> arbitrary::Result<Vec<u8>> {
    let mut request = serde_json::Map::new();
    let command = COMMANDS[usize::arbitrary(input)? % COMMANDS.len()];
    request.insert("cmd".into(), command.into());
    for field in ["id", "mode", "group", "member", "tag", "node"] {
        if bool::arbitrary(input)? {
            request.insert(field.into(), value(input)?);
        }
    }
    if bool::arbitrary(input)? {
        request.insert(String::arbitrary(input)?, value(input)?);
    }
    Ok(serde_json::to_vec(&request).unwrap_or_default())
}

fn control(handle: usize, request: &[u8]) {
    let mut buffer = NetworkCoreBuffer {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    // SAFETY: `handle` came from `networkcore_ios_runtime_init` and is never
    // freed; `request` is valid for its length; `buffer` is writable.
    let code = unsafe {
        networkcore_ios_runtime_control(
            handle as *mut NetworkCoreRuntime,
            request.as_ptr(),
            request.len(),
            &mut buffer,
        )
    };
    assert_ne!(code, NETWORKCORE_IOS_ERR_PANIC_CAUGHT, "control panicked");
    match code {
        NETWORKCORE_IOS_OK => {
            assert!(!buffer.ptr.is_null() && buffer.len > 0, "empty answer");
            // SAFETY: the library wrote `len` bytes at `ptr`.
            let answer = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) };
            let parsed: serde_json::Value = serde_json::from_slice(answer).expect("answer is JSON");
            assert!(parsed.is_object(), "answer is not an object");
            assert!(
                request.len() <= MAX_REQUEST_LEN,
                "an oversized request was accepted"
            );
        }
        NETWORKCORE_IOS_ERR_INVALID_ARGUMENT | NETWORKCORE_IOS_ERR_INTERNAL_ERROR => {
            assert_eq!(buffer.len, 0, "an error came with an answer");
        }
        other => panic!("unexpected control code {other}"),
    }
    // SAFETY: the buffer is exactly as the library returned it.
    unsafe { networkcore_ios_runtime_free_buffer(buffer) };
}

fuzz_target!(|data: &[u8]| {
    let runtimes = runtimes();
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let handle = if selector & 0x80 == 0 {
        runtimes.routed
    } else {
        runtimes.single
    };
    if selector & 1 == 0 {
        control(handle, rest);
    } else {
        let mut input = Unstructured::new(rest);
        if let Ok(request) = structured(&mut input) {
            control(handle, &request);
        }
    }
});
