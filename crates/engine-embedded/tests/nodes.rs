//! Subscription nodes to config envelope: supported protocols produce entries
//! the registry accepts, unsupported ones are named without their secrets.

#![cfg(all(feature = "shadowsocks", feature = "trojan", feature = "vless"))]

use std::sync::Arc;

use config_core::routing::{PolicyGroupSpec, RoutingSpec};
use control_domain::{Endpoint, MetadataEntry, NodeDescriptor, Protocol};
use engine_embedded::config::RuntimeConfig;
use engine_embedded::nodes::{outbound_for_node, routing_envelope, single_node_envelope};
use engine_embedded::protocols::default_registry;
use engine_outbound::TcpDialer;

fn node(id: &str, protocol: Protocol, metadata: &[(&str, &str)]) -> NodeDescriptor {
    NodeDescriptor {
        id: id.to_string(),
        name: id.to_string(),
        protocol,
        endpoint: Endpoint {
            host: "192.0.2.1".to_string(),
            port: 443,
        },
        tags: Vec::new(),
        metadata: metadata
            .iter()
            .map(|(key, value)| MetadataEntry {
                key: key.to_string(),
                value: value.to_string(),
            })
            .collect(),
    }
}

fn ss2022() -> NodeDescriptor {
    node(
        "ss",
        Protocol::Shadowsocks,
        &[
            ("shadowsocks.method", "2022-blake3-aes-128-gcm"),
            ("shadowsocks.password", "AAECAwQFBgcICQoLDA0ODw=="),
        ],
    )
}

fn vless_reality() -> NodeDescriptor {
    node(
        "vless",
        Protocol::Vless,
        &[
            ("vless.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("vless.flow", "xtls-rprx-vision"),
            ("tls.server_name", "www.example.com"),
            (
                "tls.reality.public_key",
                "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw",
            ),
            ("tls.reality.short_id", "6ba85179e30d4fc2"),
            ("tls.utls.fingerprint", "firefox"),
        ],
    )
}

fn trojan() -> NodeDescriptor {
    node(
        "trojan",
        Protocol::Trojan,
        &[
            ("trojan.password", "trojan-secret"),
            ("tls.server_name", "edge.example.com"),
            ("tls.insecure", "true"),
            ("tls.alpn", "h2, http/1.1"),
        ],
    )
}

fn builds(envelope: &str) -> &'static str {
    let config = RuntimeConfig::from_json(envelope.as_bytes()).expect("envelope is valid");
    config
        .build_outbound(&default_registry(), Arc::new(TcpDialer))
        .expect("registry accepts the outbound")
        .protocol()
}

#[test]
fn supported_nodes_become_registry_outbounds() {
    for (node, protocol) in [
        (ss2022(), "shadowsocks-2022"),
        (vless_reality(), "vless"),
        (trojan(), "trojan"),
    ] {
        let (envelope, chosen) =
            single_node_envelope("p", std::slice::from_ref(&node), None).unwrap();
        assert_eq!(chosen.id, node.id);
        assert_eq!(builds(&envelope), protocol);
    }
    let trojan = outbound_for_node(&trojan()).unwrap();
    assert_eq!(trojan["alpn"], serde_json::json!(["h2", "http/1.1"]));
    assert_eq!(trojan["insecure"], true);
}

#[test]
fn unsupported_nodes_are_reported_without_secrets() {
    let legacy_ss = node(
        "legacy",
        Protocol::Shadowsocks,
        &[
            ("shadowsocks.method", "aes-256-gcm"),
            ("shadowsocks.password", "legacy-secret"),
        ],
    );
    let vless_ws = node(
        "ws",
        Protocol::Vless,
        &[
            ("vless.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("v2ray.transport.type", "ws"),
        ],
    );
    let hysteria2 = node(
        "hy2",
        Protocol::Hysteria2,
        &[("hysteria2.password", "hy2-secret")],
    );
    for node in [legacy_ss, vless_ws, hysteria2] {
        let reason = outbound_for_node(&node).unwrap_err();
        assert!(!reason.contains("secret"), "{reason}");
    }
}

#[test]
fn selected_node_and_routing_envelopes() {
    let nodes = [ss2022(), vless_reality(), trojan()];
    let (_, chosen) = single_node_envelope("p", &nodes, Some("trojan")).unwrap();
    assert_eq!(chosen.id, "trojan");
    assert!(single_node_envelope("p", &nodes, Some("missing")).is_err());

    let spec = RoutingSpec {
        rules: vec![
            "DOMAIN-SUFFIX,example.org,trojan".to_string(),
            "FINAL,Proxy".to_string(),
        ],
        groups: vec![PolicyGroupSpec {
            id: "Proxy".to_string(),
            kind: "select".to_string(),
            members: vec!["ss".to_string(), "vless".to_string()],
            default: Some("vless".to_string()),
            url: None,
            interval_secs: None,
            tolerance_ms: None,
        }],
    };
    let envelope = routing_envelope("p", &nodes, &spec).unwrap();
    assert_eq!(builds(&envelope), "routed");

    let with_unsupported = [
        ss2022(),
        node("hy2", Protocol::Hysteria2, &[("hysteria2.password", "x")]),
    ];
    assert!(routing_envelope("p", &with_unsupported, &spec).is_err());
}
