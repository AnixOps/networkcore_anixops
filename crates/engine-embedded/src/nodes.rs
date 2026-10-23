//! Converts normalized subscription nodes (`control_domain::NodeDescriptor`)
//! into this engine's config envelope.
//!
//! Desktop clients parse subscriptions with `config-core` and hand the nodes
//! here instead of rendering a config for an external engine. A node whose
//! protocol or options this build cannot carry is reported as unsupported, so
//! the caller can say which node and why without exposing its credentials.

use std::collections::BTreeMap;

use config_core::routing::RoutingSpec;
use control_domain::{
    NodeDescriptor, Protocol, NODE_METADATA_HYSTERIA2_OBFS_TYPE, NODE_METADATA_HYSTERIA2_PASSWORD,
    NODE_METADATA_SHADOWSOCKS_METHOD, NODE_METADATA_SHADOWSOCKS_PASSWORD, NODE_METADATA_TLS_ALPN,
    NODE_METADATA_TLS_ENABLED, NODE_METADATA_TLS_INSECURE, NODE_METADATA_TLS_REALITY_PUBLIC_KEY,
    NODE_METADATA_TLS_REALITY_SHORT_ID, NODE_METADATA_TLS_SERVER_NAME,
    NODE_METADATA_TROJAN_PASSWORD, NODE_METADATA_V2RAY_TRANSPORT_HOST,
    NODE_METADATA_V2RAY_TRANSPORT_PATH, NODE_METADATA_V2RAY_TRANSPORT_SERVICE_NAME,
    NODE_METADATA_V2RAY_TRANSPORT_TYPE, NODE_METADATA_VLESS_FLOW, NODE_METADATA_VLESS_UUID,
    NODE_METADATA_VMESS_ALTER_ID, NODE_METADATA_VMESS_SECURITY, NODE_METADATA_VMESS_UUID,
};
use serde_json::{json, Value};

use crate::config::CONFIG_SCHEMA_VERSION;
use crate::protocols;

/// Why a node cannot be converted. Fixed text, no node values.
pub type Unsupported = &'static str;

/// The outbound entry (`{"type": ..., ...}`) for one node.
pub fn outbound_for_node(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let outbound = match &node.protocol {
        Protocol::Shadowsocks => shadowsocks(node)?,
        Protocol::Vless => vless(node)?,
        Protocol::Trojan => trojan(node)?,
        Protocol::Vmess => vmess(node)?,
        Protocol::Hysteria2 => hysteria2(node)?,
        _ => return Err("protocol is not implemented by the embedded engine yet"),
    };
    let kind = outbound["type"].as_str().unwrap_or_default();
    if !protocols::default_registry().contains(kind) {
        return Err("protocol is not compiled into this build");
    }
    Ok(outbound)
}

/// Envelope with one outbound for the selected node (or the first node), and
/// that node.
pub fn single_node_envelope(
    profile_id: &str,
    nodes: &[NodeDescriptor],
    selected_node_id: Option<&str>,
) -> Result<(String, NodeDescriptor), Unsupported> {
    let node = match selected_node_id {
        Some(id) => nodes.iter().find(|node| node.id == id),
        None => nodes.first(),
    }
    .ok_or("the selected node is not in the subscription")?;
    let outbound = outbound_for_node(node)?;
    let envelope = json!({
        "schema_version": CONFIG_SCHEMA_VERSION,
        "profile_id": profile_id,
        "outbound": outbound,
    });
    Ok((envelope.to_string(), node.clone()))
}

/// Envelope with every node as a routed outbound plus `routing`'s rules and
/// policy groups. Fails if any node is unsupported, since rules and groups may
/// refer to it.
pub fn routing_envelope(
    profile_id: &str,
    nodes: &[NodeDescriptor],
    routing: &RoutingSpec,
) -> Result<String, Unsupported> {
    let mut outbounds = BTreeMap::new();
    for node in nodes {
        outbounds.insert(node.id.clone(), outbound_for_node(node)?);
    }
    let groups: Vec<Value> = routing
        .groups
        .iter()
        .map(|group| {
            json!({
                "id": group.id,
                "type": group.kind,
                "members": group.members,
                "default": group.default,
                "url": group.url,
                "interval_secs": group.interval_secs,
                "tolerance_ms": group.tolerance_ms,
            })
        })
        .collect();
    let envelope = json!({
        "schema_version": CONFIG_SCHEMA_VERSION,
        "profile_id": profile_id,
        "routing": {
            "outbounds": outbounds,
            "rules": routing.rules,
            "groups": groups,
        },
    });
    Ok(envelope.to_string())
}

fn metadata<'a>(node: &'a NodeDescriptor, key: &str) -> Option<&'a str> {
    node.metadata
        .iter()
        .find(|entry| entry.key == key)
        .map(|entry| entry.value.trim())
        .filter(|value| !value.is_empty())
}

fn shadowsocks(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let method =
        metadata(node, NODE_METADATA_SHADOWSOCKS_METHOD).ok_or("shadowsocks method is missing")?;
    let password = metadata(node, NODE_METADATA_SHADOWSOCKS_PASSWORD)
        .ok_or("shadowsocks password is missing")?;
    if !matches!(
        method,
        "2022-blake3-aes-128-gcm"
            | "2022-blake3-aes-256-gcm"
            | "2022-blake3-chacha20-poly1305"
            | "aes-128-gcm"
            | "aes-256-gcm"
            | "chacha20-ietf-poly1305"
            | "chacha20-poly1305"
    ) {
        return Err("shadowsocks methods other than AEAD and 2022 ones are not implemented yet");
    }
    Ok(json!({
        "type": "shadowsocks",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "method": method,
        "password": password,
    }))
}

fn vless(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let uuid = metadata(node, NODE_METADATA_VLESS_UUID).ok_or("vless uuid is missing")?;
    let flow = metadata(node, NODE_METADATA_VLESS_FLOW).unwrap_or_default();
    let transport = v2ray_transport(node)?;
    if let Some(public_key) = metadata(node, NODE_METADATA_TLS_REALITY_PUBLIC_KEY) {
        if !transport.is_null() {
            return Err("vless REALITY over transports other than tcp is not implemented yet");
        }
        let server_name = metadata(node, NODE_METADATA_TLS_SERVER_NAME)
            .ok_or("vless REALITY server name is missing")?;
        // tls-mimic ships one Chrome fingerprint; other names fall back to it,
        // as the iOS importer does.
        return Ok(json!({
            "type": "vless",
            "server": node.endpoint.host,
            "port": node.endpoint.port,
            "uuid": uuid,
            "flow": flow,
            "reality": {
                "server_name": server_name,
                "public_key": public_key,
                "short_id": metadata(node, NODE_METADATA_TLS_REALITY_SHORT_ID).unwrap_or_default(),
                "fingerprint": "chrome",
            },
        }));
    }
    if !flow.is_empty() && flow != "none" {
        return Err("vless flows without REALITY are not implemented yet");
    }
    Ok(json!({
        "type": "vless",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "uuid": uuid,
        "tls": standard_tls(node),
        "transport": transport,
    }))
}

fn vmess(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let uuid = metadata(node, NODE_METADATA_VMESS_UUID).ok_or("vmess uuid is missing")?;
    let security = metadata(node, NODE_METADATA_VMESS_SECURITY).unwrap_or("auto");
    if !matches!(
        security,
        "auto" | "aes-128-gcm" | "chacha20-poly1305" | "chacha20-ietf-poly1305"
    ) {
        return Err("vmess security other than auto, aes-128-gcm and chacha20-poly1305 is not implemented yet");
    }
    if !matches!(
        metadata(node, NODE_METADATA_VMESS_ALTER_ID),
        None | Some("0")
    ) {
        return Err("vmess alterId other than 0 (legacy headers) is not supported");
    }
    let transport = v2ray_transport(node)?;
    Ok(json!({
        "type": "vmess",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "uuid": uuid,
        "security": security,
        "tls": standard_tls(node),
        "transport": transport,
    }))
}

/// Hysteria2 always runs TLS 1.3 over QUIC. Port hopping ranges are ignored:
/// the outbound connects to the node's main port, which hopping servers also
/// listen on.
fn hysteria2(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let password =
        metadata(node, NODE_METADATA_HYSTERIA2_PASSWORD).ok_or("hysteria2 password is missing")?;
    if metadata(node, NODE_METADATA_HYSTERIA2_OBFS_TYPE).is_some() {
        return Err("hysteria2 obfs (salamander) is not implemented yet");
    }
    Ok(json!({
        "type": "hysteria2",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "password": password,
        "server_name": metadata(node, NODE_METADATA_TLS_SERVER_NAME),
        "alpn": alpn_list(node),
        "insecure": metadata(node, NODE_METADATA_TLS_INSECURE) == Some("true"),
    }))
}

/// The standard TLS entry when the node enables TLS, otherwise `null`.
fn standard_tls(node: &NodeDescriptor) -> Value {
    if metadata(node, NODE_METADATA_TLS_ENABLED) != Some("true") {
        return Value::Null;
    }
    json!({
        "server_name": metadata(node, NODE_METADATA_TLS_SERVER_NAME),
        "alpn": alpn_list(node),
        "insecure": metadata(node, NODE_METADATA_TLS_INSECURE) == Some("true"),
    })
}

/// `null` for tcp, the `ws` or `grpc` transport entry, or unsupported.
fn v2ray_transport(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    match metadata(node, NODE_METADATA_V2RAY_TRANSPORT_TYPE) {
        None | Some("tcp") => Ok(Value::Null),
        Some("ws") => Ok(json!({
            "type": "ws",
            "path": metadata(node, NODE_METADATA_V2RAY_TRANSPORT_PATH).unwrap_or_default(),
            "host": metadata(node, NODE_METADATA_V2RAY_TRANSPORT_HOST).unwrap_or_default(),
        })),
        Some("grpc") => Ok(json!({
            "type": "grpc",
            "service_name": metadata(node, NODE_METADATA_V2RAY_TRANSPORT_SERVICE_NAME)
                .ok_or("grpc service name is missing")?,
        })),
        Some(_) => Err("transports other than tcp, ws and grpc are not implemented yet"),
    }
}

fn alpn_list(node: &NodeDescriptor) -> Vec<&str> {
    metadata(node, NODE_METADATA_TLS_ALPN)
        .map(|list| {
            list.split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn trojan(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let password =
        metadata(node, NODE_METADATA_TROJAN_PASSWORD).ok_or("trojan password is missing")?;
    let transport = v2ray_transport(node)?;
    if metadata(node, NODE_METADATA_TLS_ENABLED) == Some("false") {
        return Err("trojan without tls is not supported");
    }
    Ok(json!({
        "type": "trojan",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "password": password,
        "server_name": metadata(node, NODE_METADATA_TLS_SERVER_NAME),
        "alpn": alpn_list(node),
        "insecure": metadata(node, NODE_METADATA_TLS_INSECURE) == Some("true"),
        "transport": transport,
    }))
}
