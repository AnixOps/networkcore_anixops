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

const CLASH: &str = r#"
proxies:
  - name: HK
    type: ss
    server: 82.47.34.99
    port: 11111
    cipher: aes-256-gcm
    password: hk-secret
  - name: JP
    type: trojan
    server: jp.example.com
    port: 443
    password: jp-secret
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - Auto
      - HK
      - DIRECT
  - name: Auto
    type: url-test
    proxies:
      - HK
      - JP
    url: http://www.gstatic.com/generate_204
    interval: 300
rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - DOMAIN,jp.example.org,JP
  - MATCH,Proxy
"#;

#[test]
fn clash_rules_and_groups_come_with_the_nodes() {
    let report = import_text(CLASH).unwrap();
    let ids: Vec<_> = report.nodes.iter().map(|node| node.id.as_str()).collect();
    assert_eq!(ids.len(), 2);
    let routing = report
        .routing
        .expect("every node runs, so routing is offered");
    let groups = routing["groups"].as_array().unwrap();
    let names: Vec<_> = groups
        .iter()
        .map(|group| group["id"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Proxy", "Auto"]);
    assert_eq!(groups[0]["type"], "select");
    assert_eq!(groups[1]["members"], serde_json::json!([ids[0], ids[1]]));
    let rules: Vec<_> = routing["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| rule.as_str().unwrap().to_string())
        .collect();
    assert!(
        rules
            .iter()
            .any(|rule| rule.ends_with(&format!(",{}", ids[1]))),
        "{rules:?}"
    );
    let text = serde_json::to_string(&routing).unwrap();
    assert!(!text.contains("secret"), "{text}");

    // Links carry no rules, and a subscription with an unsupported node offers none.
    assert!(import_text(LINKS).unwrap().routing.is_none());
    let with_unsupported = CLASH.replace("cipher: aes-256-gcm", "cipher: rc4-md5");
    let report = import_text(&with_unsupported).unwrap();
    assert!(report.routing.is_none());
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

#[test]
fn surge_and_clash_snell_nodes_become_snell_outbounds() {
    let surge = "\
[Proxy]
Snell v4 = snell, snell.example.test, 8443, psk=snell-secret, version=4, obfs=http, obfs-host=cdn.example.test, reuse=true
Snell v6 = snell, 192.0.2.6, 9443, psk=snell-secret-6, version=6, mode=unshaped
Snell v1 = snell, 192.0.2.1, 1443, psk=snell-secret-1
Snell tls = snell, 192.0.2.3, 3443, psk=snell-secret-3, version=3, obfs=tls
";
    let report = import_text(surge).unwrap();
    assert_eq!(report.nodes.len(), 3);
    let v4 = &report.nodes[0].outbound;
    assert_eq!(v4["type"], "snell");
    assert_eq!(v4["server"], "snell.example.test");
    assert_eq!(v4["port"], 8443);
    assert_eq!(v4["psk"], "snell-secret");
    assert_eq!(v4["version"], 4);
    assert_eq!(v4["obfs"], "http");
    assert_eq!(v4["obfs_host"], "cdn.example.test");
    assert_eq!(v4["reuse"], true);
    let v6 = &report.nodes[1].outbound;
    assert_eq!(
        (v6["version"].as_u64(), v6["mode"].as_str()),
        (Some(6), Some("unshaped"))
    );
    assert!(v6["obfs"].is_null());
    // A missing version means 1.
    assert_eq!(report.nodes[2].outbound["version"], 1);
    assert_eq!(report.unsupported.len(), 1);
    assert_eq!(report.unsupported[0].protocol, "snell");
    assert_eq!(
        report.unsupported[0].reason,
        "snell tls obfs is not implemented yet"
    );
    let unsupported = serde_json::to_string(&report.unsupported).unwrap();
    assert!(!unsupported.contains("secret"), "{unsupported}");

    let clash = r#"
proxies:
  - name: Snell
    type: snell
    server: snell.example.test
    port: 8443
    psk: clash-snell-secret
    version: 3
    obfs-opts:
      mode: http
      host: bing.com
"#;
    let report = import_text(clash).unwrap();
    assert_eq!(report.nodes.len(), 1);
    let outbound = &report.nodes[0].outbound;
    assert_eq!(report.nodes[0].protocol, "snell");
    assert_eq!(outbound["psk"], "clash-snell-secret");
    assert_eq!(outbound["version"], 3);
    assert_eq!(outbound["obfs"], "http");
    assert_eq!(outbound["obfs_host"], "bing.com");
}
