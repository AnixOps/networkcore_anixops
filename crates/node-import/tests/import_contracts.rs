//! Subscription text to node list, through the Rust API and the C ABI the
//! iOS app calls.

use node_import::ffi::{
    networkcore_import_abi_version, networkcore_import_free_buffer, networkcore_import_nodes,
    NetworkCoreImportBuffer, NETWORKCORE_IMPORT_ABI_VERSION, NETWORKCORE_IMPORT_ERR_EMPTY,
    NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT, NETWORKCORE_IMPORT_ERR_UNRECOGNIZED,
    NETWORKCORE_IMPORT_OK,
};
use node_import::ffi::{networkcore_import_share_link, NETWORKCORE_IMPORT_ERR_UNSUPPORTED};
use node_import::{import_text, share_link, ImportError};

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
        "networkcore_import_share_link",
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
        ("NETWORKCORE_IMPORT_ERR_UNSUPPORTED", 7),
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

/// Imports `text`, exports every node and imports the links again: the
/// outbounds and names must come back unchanged.
fn assert_round_trip(text: &str) {
    let first = import_text(text).unwrap();
    assert!(!first.nodes.is_empty(), "{text}");
    for node in &first.nodes {
        let link = share_link(&node.name, &node.outbound).unwrap();
        let link_text = if node.protocol == "snell" {
            format!("[Proxy]\n{link}\n")
        } else {
            link.clone()
        };
        let again = import_text(&link_text).unwrap_or_else(|_| panic!("{link}"));
        assert_eq!(again.nodes.len(), 1, "{link}");
        assert_eq!(again.nodes[0].outbound, node.outbound, "{link}");
        assert_eq!(again.nodes[0].name, node.name, "{link}");
    }
}

#[test]
fn share_links_import_back_to_the_same_outbound() {
    assert_round_trip(
        "\
ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@82.47.34.99:11111#HK%20%E9%A6%99%E6%B8%AF
ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206QUFBQUFBQUFBQUFBQUFBQUFBQUFBQT09@[2001:db8::7]:8388#SS%202022
trojan://trojan%2Fsecret@example.com:443?sni=edge.example.com&alpn=h2,http/1.1&allowInsecure=1&type=ws&path=%2Fws%3Fed%3D2048&host=cdn.example.com#Trojan%20WS
vless://00000000-0000-0000-0000-000000000002@vless.example.test:443?encryption=none&security=reality&sni=www.example.com&pbk=PUBLICKEY&sid=ab12&fp=chrome&flow=xtls-rprx-vision&type=tcp#Reality
vless://00000000-0000-0000-0000-000000000003@vless.example.test:8443?encryption=none&security=tls&sni=grpc.example.test&type=grpc&serviceName=tunnel#VLESS%20gRPC
vless://00000000-0000-0000-0000-000000000004@192.0.2.4:80?encryption=none&security=none&type=tcp#Plain
tuic://00000000-0000-0000-0000-000000000001:tuic%2Dpassword@tuic.example.test:443?sni=cdn.tuic.example.test&alpn=h3&congestion_control=bbr#TUIC%20Node
hysteria2://hy2-secret@edge.example.test:443?sni=cdn.example.test&insecure=1&obfs=salamander&obfs-password=mask-secret#Hy2
",
    );
    // VMess over TLS with WebSocket, as a v2rayN link.
    let vmess = serde_json::json!({
        "v": "2", "ps": "VMess WS", "add": "vmess.example.test", "port": "443",
        "id": "00000000-0000-0000-0000-000000000005", "aid": "0", "scy": "aes-128-gcm",
        "net": "ws", "type": "none", "host": "cdn.example.test", "path": "/v",
        "tls": "tls", "sni": "cdn.example.test", "alpn": "h2"
    });
    let encoded = base64_standard(vmess.to_string().as_bytes());
    assert_round_trip(&format!("vmess://{encoded}"));
    assert_round_trip(
        "[Proxy]\nSnell v4 = snell, snell.example.test, 8443, psk=snell-secret, version=4, obfs=http, obfs-host=cdn.example.test, reuse=true\n",
    );
}

/// Test-side base64, independent of the exporter's.
fn base64_standard(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[test]
fn share_links_are_refused_for_protocols_without_a_format() {
    let mieru = serde_json::json!({
        "type": "mieru", "server": "example.com", "port": 443,
        "username": "user", "password": "secret-pass", "transport": "TCP"
    });
    let error = share_link("M", &mieru).unwrap_err();
    assert!(!error.contains("secret"));
    assert!(share_link("X", &serde_json::json!({"type": "shadowsocks"})).is_err());
}

fn call_share_link(input: &[u8]) -> (i32, Option<String>) {
    let mut out = NetworkCoreImportBuffer {
        ptr: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    // SAFETY: valid input slice and output pointer.
    let code = unsafe { networkcore_import_share_link(input.as_ptr(), input.len(), &mut out) };
    let text = (code == NETWORKCORE_IMPORT_OK).then(|| {
        // SAFETY: the library returned `len` initialized bytes.
        let bytes = unsafe { std::slice::from_raw_parts(out.ptr, out.len) };
        String::from_utf8(bytes.to_vec()).unwrap()
    });
    // SAFETY: released once, as returned.
    unsafe { networkcore_import_free_buffer(out) };
    (code, text)
}

#[test]
fn c_abi_exports_share_links() {
    let report = import_text(LINKS).unwrap();
    let entry = serde_json::json!({
        "name": report.nodes[0].name,
        "outbound": report.nodes[0].outbound,
    });
    let (code, link) = call_share_link(entry.to_string().as_bytes());
    assert_eq!(code, NETWORKCORE_IMPORT_OK);
    let link = link.unwrap();
    assert!(link.starts_with("ss://"), "{link}");
    assert!(link.ends_with("#HK"), "{link}");

    assert_eq!(call_share_link(b"").0, NETWORKCORE_IMPORT_ERR_EMPTY);
    assert_eq!(
        call_share_link(b"not json").0,
        NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        call_share_link(br#"{"name":"x"}"#).0,
        NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT
    );
    assert_eq!(
        call_share_link(br#"{"name":"x","outbound":{"type":"mieru","server":"a","port":1}}"#).0,
        NETWORKCORE_IMPORT_ERR_UNSUPPORTED
    );
}
