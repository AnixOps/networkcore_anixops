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

fn ss_aead() -> NodeDescriptor {
    node(
        "ss-aead",
        Protocol::Shadowsocks,
        &[
            ("shadowsocks.method", "chacha20-ietf-poly1305"),
            ("shadowsocks.password", "plain-password"),
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
        (ss_aead(), "shadowsocks"),
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
fn trojan_websocket_nodes_carry_path_and_host() {
    let trojan_ws = node(
        "trojan-ws",
        Protocol::Trojan,
        &[
            ("trojan.password", "secret"),
            ("tls.server_name", "cdn.example"),
            ("v2ray.transport.type", "ws"),
            ("v2ray.transport.path", "/ws"),
            ("v2ray.transport.host", "front.example"),
        ],
    );
    let outbound = outbound_for_node(&trojan_ws).unwrap();
    assert_eq!(
        outbound["transport"],
        serde_json::json!({"type": "ws", "path": "/ws", "host": "front.example"})
    );
    let (envelope, _) = single_node_envelope("p", &[trojan_ws], None).unwrap();
    assert_eq!(builds(&envelope), "trojan");

    let trojan_grpc = node(
        "trojan-grpc",
        Protocol::Trojan,
        &[
            ("trojan.password", "secret"),
            ("v2ray.transport.type", "grpc"),
            ("v2ray.transport.service_name", "TunService"),
        ],
    );
    let outbound = outbound_for_node(&trojan_grpc).unwrap();
    assert_eq!(
        outbound["transport"],
        serde_json::json!({"type": "grpc", "service_name": "TunService"})
    );
    let (envelope, _) = single_node_envelope("p", &[trojan_grpc], None).unwrap();
    assert_eq!(builds(&envelope), "trojan");

    for transport in [
        &[("v2ray.transport.type", "grpc")][..],
        &[("v2ray.transport.type", "h2")],
    ] {
        let mut metadata = vec![("trojan.password", "secret")];
        metadata.extend_from_slice(transport);
        let unsupported = node("trojan-unsupported", Protocol::Trojan, &metadata);
        assert!(outbound_for_node(&unsupported).is_err());
    }
}

#[test]
fn vless_tls_and_websocket_nodes_map_to_the_standard_outbound() {
    let vless_ws_tls = node(
        "vless-ws",
        Protocol::Vless,
        &[
            ("vless.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("tls.enabled", "true"),
            ("tls.server_name", "cdn.example"),
            ("tls.alpn", "http/1.1"),
            ("v2ray.transport.type", "ws"),
            ("v2ray.transport.path", "/vl"),
        ],
    );
    let outbound = outbound_for_node(&vless_ws_tls).unwrap();
    assert_eq!(outbound["tls"]["server_name"], "cdn.example");
    assert_eq!(outbound["tls"]["alpn"], serde_json::json!(["http/1.1"]));
    assert_eq!(outbound["transport"]["path"], "/vl");
    assert!(outbound.get("reality").is_none());
    let (envelope, _) = single_node_envelope("p", &[vless_ws_tls], None).unwrap();
    assert_eq!(builds(&envelope), "vless");

    let vless_plain = node(
        "vless-plain",
        Protocol::Vless,
        &[
            ("vless.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("tls.enabled", "false"),
        ],
    );
    let outbound = outbound_for_node(&vless_plain).unwrap();
    assert!(outbound["tls"].is_null());
    let (envelope, _) = single_node_envelope("p", &[vless_plain], None).unwrap();
    assert_eq!(builds(&envelope), "vless");

    let vision_tls = node(
        "vision-tls",
        Protocol::Vless,
        &[
            ("vless.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("vless.flow", "xtls-rprx-vision"),
            ("tls.enabled", "true"),
        ],
    );
    assert!(outbound_for_node(&vision_tls).is_err());
}

#[cfg(feature = "vmess")]
#[test]
fn vmess_nodes_map_security_tls_and_websocket() {
    let vmess_ws_tls = node(
        "vmess-ws",
        Protocol::Vmess,
        &[
            ("vmess.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("vmess.security", "chacha20-poly1305"),
            ("vmess.alter_id", "0"),
            ("tls.enabled", "true"),
            ("tls.server_name", "cdn.example"),
            ("v2ray.transport.type", "ws"),
            ("v2ray.transport.path", "/vm"),
        ],
    );
    let outbound = outbound_for_node(&vmess_ws_tls).unwrap();
    assert_eq!(outbound["security"], "chacha20-poly1305");
    assert_eq!(outbound["tls"]["server_name"], "cdn.example");
    assert_eq!(outbound["transport"]["path"], "/vm");
    let (envelope, _) = single_node_envelope("p", &[vmess_ws_tls], None).unwrap();
    assert_eq!(builds(&envelope), "vmess");

    let vmess_plain = node(
        "vmess-plain",
        Protocol::Vmess,
        &[("vmess.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811")],
    );
    let outbound = outbound_for_node(&vmess_plain).unwrap();
    assert_eq!(outbound["security"], "auto");
    assert!(outbound["tls"].is_null());
    let (envelope, _) = single_node_envelope("p", &[vmess_plain], None).unwrap();
    assert_eq!(builds(&envelope), "vmess");

    for (key, value) in [("vmess.alter_id", "64"), ("vmess.security", "none")] {
        let unsupported = node(
            "vmess-legacy",
            Protocol::Vmess,
            &[
                ("vmess.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
                (key, value),
            ],
        );
        assert!(outbound_for_node(&unsupported).is_err(), "{key}={value}");
    }
}

#[cfg(feature = "hysteria2")]
#[test]
fn hysteria2_nodes_map_password_and_tls() {
    let hy2 = node(
        "hy2",
        Protocol::Hysteria2,
        &[
            ("hysteria2.password", "hy2-secret"),
            ("hysteria2.server_ports", "20000-30000"),
            ("tls.server_name", "hy2.example"),
            ("tls.insecure", "true"),
        ],
    );
    let outbound = outbound_for_node(&hy2).unwrap();
    assert_eq!(
        outbound,
        serde_json::json!({
            "type": "hysteria2",
            "server": "192.0.2.1",
            "port": 443,
            "password": "hy2-secret",
            "server_name": "hy2.example",
            "alpn": [],
            "insecure": true,
        })
    );
    let (envelope, _) = single_node_envelope("p", &[hy2], None).unwrap();
    assert_eq!(builds(&envelope), "hysteria2");

    let missing = node("hy2-missing", Protocol::Hysteria2, &[]);
    assert!(outbound_for_node(&missing).is_err());
}

#[cfg(feature = "tuic")]
#[test]
fn tuic_nodes_map_uuid_password_and_congestion() {
    let tuic = node(
        "tuic",
        Protocol::Tuic,
        &[
            ("tuic.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("tuic.password", "tuic-secret"),
            ("tuic.congestion_control", "bbr"),
            ("tls.server_name", "tuic.example"),
            ("tls.alpn", "h3"),
        ],
    );
    let outbound = outbound_for_node(&tuic).unwrap();
    assert_eq!(
        outbound,
        serde_json::json!({
            "type": "tuic",
            "server": "192.0.2.1",
            "port": 443,
            "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "password": "tuic-secret",
            "server_name": "tuic.example",
            "alpn": ["h3"],
            "insecure": false,
            "congestion_control": "bbr",
        })
    );
    let (envelope, _) = single_node_envelope("p", &[tuic], None).unwrap();
    assert_eq!(builds(&envelope), "tuic");

    let v4 = node(
        "tuic-v4",
        Protocol::Tuic,
        &[("tuic.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811")],
    );
    assert!(outbound_for_node(&v4).is_err());
}

#[test]
fn unsupported_nodes_are_reported_without_secrets() {
    let legacy_ss = node(
        "legacy",
        Protocol::Shadowsocks,
        &[
            ("shadowsocks.method", "aes-256-cfb"),
            ("shadowsocks.password", "legacy-secret"),
        ],
    );
    let vless_h2 = node(
        "h2",
        Protocol::Vless,
        &[
            ("vless.uuid", "b831381d-6324-4d53-ad4f-8cda48b30811"),
            ("v2ray.transport.type", "h2"),
        ],
    );
    let hysteria2 = node(
        "hy2",
        Protocol::Hysteria2,
        &[
            ("hysteria2.password", "hy2-secret"),
            ("hysteria2.obfs.type", "salamander"),
            ("hysteria2.obfs.password", "obfs-secret"),
        ],
    );
    for node in [legacy_ss, vless_h2, hysteria2] {
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
        node("hy1", Protocol::Hysteria, &[("hysteria.auth", "x")]),
    ];
    assert!(routing_envelope("p", &with_unsupported, &spec).is_err());
}
