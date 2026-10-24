//! Subscription text to node list, through the Rust API and the C ABI the
//! iOS app calls.

use node_import::ffi::{
    networkcore_import_abi_version, networkcore_import_free_buffer, networkcore_import_nodes,
    NetworkCoreImportBuffer, NETWORKCORE_IMPORT_ABI_VERSION, NETWORKCORE_IMPORT_ERR_EMPTY,
    NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT, NETWORKCORE_IMPORT_ERR_UNRECOGNIZED,
    NETWORKCORE_IMPORT_OK,
};
use node_import::{import_text, ImportError};

const LINKS: &str = "\
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@82.47.34.99:11111#HK
trojan://trojan-secret@example.com:443?sni=edge.example.com#HK%20Trojan
tuic://00000000-0000-0000-0000-000000000001:tuic%2Dpassword@tuic.example.test:443?sni=cdn.tuic.example.test&alpn=h3&congestion_control=bbr#TUIC%20Node
hysteria2://hy2-secret@edge.example.test:443?sni=cdn.example.test&obfs=gecko&obfs-password=mask-secret#Gecko
";

#[test]
fn links_become_outbounds_and_unsupported_nodes_keep_their_secrets() {
    let report = import_text(LINKS).unwrap();
    let protocols: Vec<_> = report
        .nodes
        .iter()
        .map(|node| node.protocol.as_str())
        .collect();
    assert_eq!(protocols, ["shadowsocks", "trojan", "tuic"]);
    let trojan = &report.nodes[1];
    assert_eq!(trojan.server, "example.com");
    assert_eq!(trojan.port, 443);
    assert_eq!(trojan.outbound["password"], "trojan-secret");
    assert_eq!(trojan.outbound["server_name"], "edge.example.com");

    assert_eq!(report.unsupported.len(), 1);
    assert_eq!(report.unsupported[0].protocol, "hysteria2");
    let unsupported = serde_json::to_string(&report.unsupported).unwrap();
    assert!(!unsupported.contains("secret"), "{unsupported}");
}

#[test]
fn empty_and_unknown_text_are_rejected() {
    assert_eq!(import_text("  \n"), Err(ImportError::Empty));
    assert_eq!(
        import_text("this is not a subscription"),
        Err(ImportError::Unrecognized)
    );
}

fn call(text: &[u8]) -> (i32, Option<serde_json::Value>) {
    let mut out = NetworkCoreImportBuffer {
        ptr: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    // SAFETY: `text` is a live slice and `out` is writable.
    let code = unsafe { networkcore_import_nodes(text.as_ptr(), text.len(), &mut out) };
    let json = (code == NETWORKCORE_IMPORT_OK).then(|| {
        // SAFETY: on success the buffer holds `len` bytes of JSON.
        let bytes = unsafe { std::slice::from_raw_parts(out.ptr, out.len) };
        serde_json::from_slice(bytes).unwrap()
    });
    // SAFETY: released once, as returned.
    unsafe { networkcore_import_free_buffer(out) };
    (code, json)
}

#[test]
fn c_abi_returns_the_report_as_json_and_stable_codes() {
    assert_eq!(
        networkcore_import_abi_version(),
        NETWORKCORE_IMPORT_ABI_VERSION
    );
    let (code, json) = call(LINKS.as_bytes());
    assert_eq!(code, NETWORKCORE_IMPORT_OK);
    let json = json.unwrap();
    assert_eq!(json["nodes"].as_array().unwrap().len(), 3);
    assert_eq!(json["nodes"][0]["outbound"]["type"], "shadowsocks");
    assert_eq!(json["unsupported"][0]["protocol"], "hysteria2");

    assert_eq!(call(b"").0, NETWORKCORE_IMPORT_ERR_EMPTY);
    assert_eq!(
        call(&[0xff, 0xfe]).0,
        NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT
    );
    assert_eq!(call(b"garbage").0, NETWORKCORE_IMPORT_ERR_UNRECOGNIZED);
    // SAFETY: null output is rejected before anything is read or written.
    let code =
        unsafe { networkcore_import_nodes(LINKS.as_ptr(), LINKS.len(), std::ptr::null_mut()) };
    assert_eq!(code, NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT);
}

#[test]
fn header_declares_every_symbol_and_code() {
    let header = include_str!("../include/networkcore_import.h");
    for symbol in [
        "networkcore_import_abi_version",
        "networkcore_import_nodes",
        "networkcore_import_free_buffer",
    ] {
        assert!(header.contains(&format!("{symbol}(")), "{symbol}");
    }
    for (name, value) in [
        ("NETWORKCORE_IMPORT_OK", 0),
        ("NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT", 1),
        ("NETWORKCORE_IMPORT_ERR_EMPTY", 2),
        ("NETWORKCORE_IMPORT_ERR_TOO_LARGE", 3),
        ("NETWORKCORE_IMPORT_ERR_UNRECOGNIZED", 4),
        ("NETWORKCORE_IMPORT_ERR_PANIC_CAUGHT", 5),
        ("NETWORKCORE_IMPORT_ERR_INTERNAL_ERROR", 6),
    ] {
        let define = format!("#define {name} {value}");
        assert!(
            header.lines().any(|line| line.trim_end() == define),
            "{name}"
        );
    }
    assert!(header.contains(&format!(
        "#define NETWORKCORE_IMPORT_ABI_VERSION {NETWORKCORE_IMPORT_ABI_VERSION}u"
    )));
}
