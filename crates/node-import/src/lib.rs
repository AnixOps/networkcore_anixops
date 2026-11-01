//! Converts normalized subscription nodes (`control_domain::NodeDescriptor`)
//! into outbound entries (`{"type": ..., ...}`) of the embedded engine's
//! config envelope, and turns pasted or downloaded subscription text into a
//! list of them, with the subscription's rules and policy groups when the
//! engine can run them.
//!
//! [`share_link`] goes the other way, from an outbound entry to a share link.
//!
//! This crate carries no protocol code and no runtime, so the iOS app can link
//! it (see [`ffi`]) to import nodes without linking the packet tunnel engine.
//! A node whose protocol or options cannot be carried is reported with a fixed
//! reason, never with its credentials.

pub mod ffi;
pub mod share_link;

pub use share_link::share_link;

use config_core::routing::RoutingSpec;
use config_core::routing_import::{import_subscription_routing, ImportedRuleSet};
use control_domain::{
    NodeCatalog, NodeDescriptor, Protocol, SubscriptionService, SubscriptionSource,
    NODE_METADATA_ANX_ALPN, NODE_METADATA_ANX_FINGERPRINT, NODE_METADATA_ANX_JACKET,
    NODE_METADATA_ANX_PUBLIC_KEY, NODE_METADATA_ANX_SERVER_NAME, NODE_METADATA_ANX_USER_KEY,
    NODE_METADATA_ANX_WG_PORT, NODE_METADATA_HYSTERIA2_OBFS_PASSWORD,
    NODE_METADATA_HYSTERIA2_OBFS_TYPE, NODE_METADATA_HYSTERIA2_PASSWORD,
    NODE_METADATA_IWAN_ENCRYPT, NODE_METADATA_IWAN_MTU, NODE_METADATA_IWAN_PASSWORD,
    NODE_METADATA_IWAN_USERNAME, NODE_METADATA_MIERU_PASSWORD, NODE_METADATA_MIERU_PORT_RANGE,
    NODE_METADATA_MIERU_TRANSPORT, NODE_METADATA_MIERU_USERNAME, NODE_METADATA_SHADOWSOCKS_METHOD,
    NODE_METADATA_SHADOWSOCKS_PASSWORD, NODE_METADATA_SNELL_MODE, NODE_METADATA_SNELL_OBFS,
    NODE_METADATA_SNELL_OBFS_HOST, NODE_METADATA_SNELL_OBFS_URI, NODE_METADATA_SNELL_PSK,
    NODE_METADATA_SNELL_REUSE, NODE_METADATA_SNELL_USER_KEY, NODE_METADATA_SNELL_VERSION,
    NODE_METADATA_TLS_ALPN, NODE_METADATA_TLS_ENABLED, NODE_METADATA_TLS_INSECURE,
    NODE_METADATA_TLS_REALITY_PUBLIC_KEY, NODE_METADATA_TLS_REALITY_SHORT_ID,
    NODE_METADATA_TLS_SERVER_NAME, NODE_METADATA_TROJAN_PASSWORD,
    NODE_METADATA_TUIC_CONGESTION_CONTROL, NODE_METADATA_TUIC_PASSWORD, NODE_METADATA_TUIC_UUID,
    NODE_METADATA_V2RAY_TRANSPORT_EXTRA, NODE_METADATA_V2RAY_TRANSPORT_HOST,
    NODE_METADATA_V2RAY_TRANSPORT_MODE, NODE_METADATA_V2RAY_TRANSPORT_PATH,
    NODE_METADATA_V2RAY_TRANSPORT_SERVICE_NAME, NODE_METADATA_V2RAY_TRANSPORT_TYPE,
    NODE_METADATA_VIA, NODE_METADATA_VIA_UNRESOLVED, NODE_METADATA_VLESS_ENCRYPTION,
    NODE_METADATA_VLESS_FLOW, NODE_METADATA_VLESS_UUID, NODE_METADATA_VMESS_ALTER_ID,
    NODE_METADATA_VMESS_SECURITY, NODE_METADATA_VMESS_UUID,
};
use serde::Serialize;
use serde_json::{json, Value};

/// Why a node cannot be converted. Fixed text, no node values.
pub type Unsupported = &'static str;

/// The outbound entry for one node. Whether this build's engine compiles the
/// protocol in is the engine's call (`engine_embedded::nodes::outbound_for_node`).
///
/// A node that connects through another one carries `via` with that node's
/// id; [`report`] keeps it only when that node can run too.
pub fn outbound_json(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    if metadata(node, NODE_METADATA_VIA_UNRESOLVED).is_some() {
        return Err("it connects through an outbound that is not one of the imported nodes");
    }
    let mut outbound = match &node.protocol {
        Protocol::Shadowsocks => shadowsocks(node),
        Protocol::Vless => vless(node),
        Protocol::Trojan => trojan(node),
        Protocol::Vmess => vmess(node),
        Protocol::Hysteria2 => hysteria2(node),
        Protocol::Tuic => tuic(node),
        Protocol::Snell => snell(node),
        Protocol::Mieru => mieru(node),
        Protocol::Iwan => iwan(node),
        Protocol::Anx => anx(node),
        _ => Err("protocol is not implemented by the embedded engine yet"),
    }?;
    if let Some(via) = metadata(node, NODE_METADATA_VIA) {
        // These dial their own UDP or tunnel and cannot ride another node
        // (the engine's `supports_via`); one in a routed config would fail
        // the whole tunnel.
        if matches!(
            node.protocol,
            Protocol::Hysteria2
                | Protocol::Tuic
                | Protocol::Iwan
                | Protocol::Anx
                | Protocol::WireGuard
        ) {
            return Err("this protocol cannot connect through another node");
        }
        outbound["via"] = json!(via);
    }
    Ok(outbound)
}

/// Largest subscription text [`import_text`] accepts.
pub const MAX_IMPORT_TEXT_LEN: usize = 4 * 1024 * 1024;

/// Most nodes, rules and policy groups a routed config may carry. The engine
/// (`engine_embedded::config`) enforces the same limits.
pub const MAX_ROUTED_OUTBOUNDS: usize = 64;
pub const MAX_ROUTING_RULES: usize = 4096;
pub const MAX_POLICY_GROUPS: usize = 64;

/// Nodes found in a subscription text, in its order.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportReport {
    pub nodes: Vec<ImportedNode>,
    pub unsupported: Vec<UnsupportedNode>,
    /// The subscription's rules, policy groups and remote rule sets as the
    /// engine's `routing` section without `outbounds` (see [`routing_json`]
    /// and [`rule_sets_json`]). Present only when
    /// every node can run, every node id is a valid outbound id and the result
    /// fits the limits above; rules and groups name nodes by
    /// [`ImportedNode::id`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing: Option<Value>,
}

/// A node the engine can run. `outbound` holds its credentials.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ImportedNode {
    pub id: String,
    pub name: String,
    /// The outbound `type`.
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub outbound: Value,
}

/// A node that was recognized but cannot run, with a fixed reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnsupportedNode {
    pub name: String,
    pub protocol: String,
    pub reason: Unsupported,
}

/// Why a text yielded no node list. Fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    Empty,
    TooLarge,
    Unrecognized,
}

impl ImportError {
    pub fn as_str(self) -> &'static str {
        match self {
            ImportError::Empty => "subscription text is empty",
            ImportError::TooLarge => "subscription text is too large",
            ImportError::Unrecognized => "subscription text is not a supported format",
        }
    }
}

/// Parses share links, base64 link lists, Clash YAML, JSON outbound configs and
/// Surge, Loon or Quantumult X proxy lines.
pub fn import_text(text: &str) -> Result<ImportReport, ImportError> {
    if text.trim().is_empty() {
        return Err(ImportError::Empty);
    }
    if text.len() > MAX_IMPORT_TEXT_LEN {
        return Err(ImportError::TooLarge);
    }
    let service = config_core::CoreSubscriptionService::new();
    let source = SubscriptionSource {
        id: "import".to_string(),
        location: format!("inline:{text}"),
    };
    let catalog: NodeCatalog = service
        .fetch(&source)
        .and_then(|raw| service.parse(&raw))
        .and_then(|document| service.normalize(&document))
        .map_err(|_| ImportError::Unrecognized)?;
    let mut report = report(&catalog.nodes);
    report.routing = subscription_routing(text, &catalog.nodes, &report);
    Ok(report)
}

/// `rules` and `groups` of the engine's `routing` section for `spec`.
pub fn routing_json(spec: &RoutingSpec) -> Value {
    let groups: Vec<Value> = spec
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
    json!({ "rules": spec.rules, "groups": groups })
}

fn subscription_routing(
    text: &str,
    nodes: &[NodeDescriptor],
    report: &ImportReport,
) -> Option<Value> {
    if !report.unsupported.is_empty()
        || report.nodes.is_empty()
        || report.nodes.len() > MAX_ROUTED_OUTBOUNDS
        || !report.nodes.iter().all(|node| is_outbound_id(&node.id))
    {
        return None;
    }
    let imported = import_subscription_routing(text, nodes);
    let spec = imported.spec?;
    if spec.rules.len() > MAX_ROUTING_RULES || spec.groups.len() > MAX_POLICY_GROUPS {
        return None;
    }
    let mut routing = routing_json(&spec);
    if !imported.rule_sets.is_empty() {
        routing["rule_sets"] = rule_sets_json(&imported.rule_sets);
    }
    Some(routing)
}

/// The engine's `routing.rule_sets` object for imported remote sets, keyed by
/// id; unset fields are left out so the engine defaults apply.
pub fn rule_sets_json(rule_sets: &[ImportedRuleSet]) -> Value {
    let mut object = serde_json::Map::new();
    for set in rule_sets {
        let mut entry = serde_json::Map::new();
        entry.insert("url".to_string(), json!(set.url));
        if let Some(format) = set.format {
            entry.insert("format".to_string(), json!(format));
        }
        if let Some(interval_secs) = set.interval_secs {
            entry.insert("interval_secs".to_string(), json!(interval_secs));
        }
        if let Some(via) = &set.via {
            entry.insert("via".to_string(), json!(via));
        }
        object.insert(set.id.clone(), Value::Object(entry));
    }
    Value::Object(object)
}

/// Same rule as the engine's routing outbound ids: 1-128 of `[A-Za-z0-9._-]`.
fn is_outbound_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Splits `nodes` into runnable entries and unsupported ones.
pub fn report(nodes: &[NodeDescriptor]) -> ImportReport {
    let mut report = ImportReport {
        nodes: Vec::new(),
        unsupported: Vec::new(),
        routing: None,
    };
    for node in nodes {
        match outbound_json(node) {
            Ok(outbound) => report.nodes.push(ImportedNode {
                id: node.id.clone(),
                name: node.name.clone(),
                protocol: outbound["type"].as_str().unwrap_or_default().to_string(),
                server: node.endpoint.host.clone(),
                port: node.endpoint.port,
                outbound,
            }),
            Err(reason) => report.unsupported.push(UnsupportedNode {
                name: node.name.clone(),
                protocol: protocol_name(&node.protocol),
                reason,
            }),
        }
    }
    // A node whose `via` cannot run cannot run either; repeat for chains.
    loop {
        let ids: Vec<String> = report.nodes.iter().map(|node| node.id.clone()).collect();
        let Some(index) = report.nodes.iter().position(|node| {
            node.outbound["via"]
                .as_str()
                .is_some_and(|via| !ids.iter().any(|id| id == via))
        }) else {
            break;
        };
        let node = report.nodes.remove(index);
        report.unsupported.push(UnsupportedNode {
            name: node.name,
            protocol: node.protocol,
            reason: "it connects through a node that cannot run",
        });
    }
    report
}

fn protocol_name(protocol: &Protocol) -> String {
    match protocol {
        Protocol::Http => "http".to_string(),
        Protocol::Socks => "socks".to_string(),
        Protocol::Shadowsocks => "shadowsocks".to_string(),
        Protocol::Vmess => "vmess".to_string(),
        Protocol::Vless => "vless".to_string(),
        Protocol::Trojan => "trojan".to_string(),
        Protocol::Hysteria => "hysteria".to_string(),
        Protocol::Hysteria2 => "hysteria2".to_string(),
        Protocol::Tuic => "tuic".to_string(),
        Protocol::WireGuard => "wireguard".to_string(),
        Protocol::Mieru => "mieru".to_string(),
        Protocol::Snell => "snell".to_string(),
        Protocol::Iwan => "iwan".to_string(),
        Protocol::Anx => "anx".to_string(),
        Protocol::Other(name) => name.to_ascii_lowercase(),
    }
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
    // Xray's VLESS Encryption (`encryption=mlkem768x25519plus...`) wraps the
    // whole connection; dialing it as plain VLESS only gets random bytes back.
    if metadata(node, NODE_METADATA_VLESS_ENCRYPTION).is_some_and(|value| value != "none") {
        return Err("vless encryption (VLESS Encryption) is not implemented yet");
    }
    let flow = metadata(node, NODE_METADATA_VLESS_FLOW).unwrap_or_default();
    let transport = v2ray_transport(node)?;
    if let Some(public_key) = metadata(node, NODE_METADATA_TLS_REALITY_PUBLIC_KEY) {
        let xhttp = transport["type"] == "xhttp";
        if !transport.is_null() && !xhttp {
            return Err(
                "vless REALITY over transports other than tcp and xhttp is not implemented yet",
            );
        }
        if xhttp && !flow.is_empty() && flow != "none" {
            return Err("vless flows over xhttp are not supported");
        }
        let server_name = metadata(node, NODE_METADATA_TLS_SERVER_NAME)
            .ok_or("vless REALITY server name is missing")?;
        // tls-mimic ships one Chrome fingerprint; other names fall back to it,
        // as the iOS importer does.
        let mut outbound = json!({
            "type": "vless",
            "server": node.endpoint.host,
            "port": node.endpoint.port,
            "uuid": uuid,
            "flow": if xhttp { "" } else { flow },
            "reality": {
                "server_name": server_name,
                "public_key": public_key,
                "short_id": metadata(node, NODE_METADATA_TLS_REALITY_SHORT_ID).unwrap_or_default(),
                "fingerprint": "chrome",
            },
        });
        if xhttp {
            outbound["transport"] = transport;
        }
        return Ok(outbound);
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
    let obfs = match metadata(node, NODE_METADATA_HYSTERIA2_OBFS_TYPE) {
        None => Value::Null,
        Some("salamander") => json!({
            "type": "salamander",
            "password": metadata(node, NODE_METADATA_HYSTERIA2_OBFS_PASSWORD)
                .ok_or("hysteria2 obfs password is missing")?,
        }),
        Some(_) => return Err("hysteria2 obfs other than salamander is not implemented yet"),
    };
    Ok(json!({
        "type": "hysteria2",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "password": password,
        "server_name": metadata(node, NODE_METADATA_TLS_SERVER_NAME),
        "alpn": alpn_list(node),
        "insecure": metadata(node, NODE_METADATA_TLS_INSECURE) == Some("true"),
        "obfs": obfs,
    }))
}

/// TUIC v5 over QUIC (TLS 1.3 always on). The UDP relay mode does not matter
/// for TCP.
fn tuic(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let uuid = metadata(node, NODE_METADATA_TUIC_UUID).ok_or("tuic uuid is missing")?;
    let password = metadata(node, NODE_METADATA_TUIC_PASSWORD)
        .filter(|password| !password.is_empty())
        .ok_or("tuic password is missing (tuic v4 tokens are not supported)")?;
    Ok(json!({
        "type": "tuic",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "uuid": uuid,
        "password": password,
        "server_name": metadata(node, NODE_METADATA_TLS_SERVER_NAME),
        "alpn": alpn_list(node),
        "insecure": metadata(node, NODE_METADATA_TLS_INSECURE) == Some("true"),
        "congestion_control": metadata(node, NODE_METADATA_TUIC_CONGESTION_CONTROL),
    }))
}

/// Snell v1–v4 and v6 (v5 runs as v4). A missing version means 1, as in
/// Surge and Clash.
fn snell(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let psk = metadata(node, NODE_METADATA_SNELL_PSK).ok_or("snell psk is missing")?;
    let version = match metadata(node, NODE_METADATA_SNELL_VERSION) {
        None => 1,
        Some(raw) => raw
            .parse::<u8>()
            .ok()
            .filter(|version| (1..=6).contains(version))
            .ok_or("snell version must be between 1 and 6")?,
    };
    let mode = metadata(node, NODE_METADATA_SNELL_MODE).unwrap_or("default");
    if !matches!(mode, "default" | "unshaped" | "unsafe-raw") {
        return Err("snell mode must be default, unshaped or unsafe-raw");
    }
    let obfs = match metadata(node, NODE_METADATA_SNELL_OBFS) {
        None | Some("none") | Some("off") => None,
        Some("http") if version <= 4 => Some("http"),
        Some("http") => return Err("snell obfs needs version 4 or earlier"),
        Some("tls") => return Err("snell tls obfs is not implemented yet"),
        Some(_) => return Err("snell obfs must be http"),
    };
    Ok(json!({
        "type": "snell",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "psk": psk,
        "version": version,
        "mode": mode,
        "obfs": obfs,
        "obfs_host": obfs.and(metadata(node, NODE_METADATA_SNELL_OBFS_HOST)),
        "obfs_uri": obfs.and(metadata(node, NODE_METADATA_SNELL_OBFS_URI)),
        "reuse": metadata(node, NODE_METADATA_SNELL_REUSE) == Some("true"),
        "userkey": metadata(node, NODE_METADATA_SNELL_USER_KEY),
    }))
}

fn mieru(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let username =
        metadata(node, NODE_METADATA_MIERU_USERNAME).ok_or("mieru username is missing")?;
    let password =
        metadata(node, NODE_METADATA_MIERU_PASSWORD).ok_or("mieru password is missing")?;
    match metadata(node, NODE_METADATA_MIERU_TRANSPORT) {
        None => {}
        Some(transport) if transport.eq_ignore_ascii_case("tcp") => {}
        Some(transport) if transport.eq_ignore_ascii_case("udp") => {
            return Err("mieru udp transport is not implemented yet")
        }
        Some(_) => return Err("mieru transport must be TCP"),
    }
    // Multiplexing, handshake mode and traffic pattern only shape the
    // official client; the server accepts this client without them.
    Ok(json!({
        "type": "mieru",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "username": username,
        "password": password,
        "port_range": metadata(node, NODE_METADATA_MIERU_PORT_RANGE),
        "transport": "TCP",
    }))
}

/// iWAN has no confidentiality (docs/protocols/iwan.md §9); a subscription
/// uses it as the line other nodes connect through.
fn iwan(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let username = metadata(node, NODE_METADATA_IWAN_USERNAME).ok_or("iwan username is missing")?;
    let password = metadata(node, NODE_METADATA_IWAN_PASSWORD).ok_or("iwan password is missing")?;
    let mut outbound = json!({
        "type": "iwan",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "username": username,
        "password": password,
    });
    if let Some(mtu) = metadata(node, NODE_METADATA_IWAN_MTU) {
        let mtu: u16 = mtu.parse().map_err(|_| "iwan mtu is not a number")?;
        outbound["mtu"] = json!(mtu);
    }
    if let Some(encrypt) = metadata(node, NODE_METADATA_IWAN_ENCRYPT) {
        outbound["encrypt"] = json!(encrypt == "true");
    }
    Ok(outbound)
}

/// ANX-A under the A2 jacket. The public engine does not compile the
/// protocol in; a client build that does reads this entry (`type = "anx"`:
/// `server_name`, `public_key`, `user_key`, optional `alpn`, `fingerprint`).
fn anx(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let user_key = metadata(node, NODE_METADATA_ANX_USER_KEY).ok_or("anx user key is missing")?;
    let public_key =
        metadata(node, NODE_METADATA_ANX_PUBLIC_KEY).ok_or("anx server public key is missing")?;
    let mut outbound = json!({
        "type": "anx",
        "server": node.endpoint.host,
        "port": node.endpoint.port,
        "public_key": public_key,
        "user_key": user_key,
    });
    // No server name means no SNI in the ClientHello.
    if let Some(server_name) = metadata(node, NODE_METADATA_ANX_SERVER_NAME) {
        outbound["server_name"] = json!(server_name);
    }
    if let Some(alpn) = metadata(node, NODE_METADATA_ANX_ALPN) {
        let alpn: Vec<&str> = alpn
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .collect();
        outbound["alpn"] = json!(alpn);
    }
    if let Some(fingerprint) = metadata(node, NODE_METADATA_ANX_FINGERPRINT) {
        outbound["fingerprint"] = json!(fingerprint);
    }
    if let Some(jacket) = metadata(node, NODE_METADATA_ANX_JACKET) {
        outbound["jacket"] = json!(jacket);
    }
    if let Some(port) =
        metadata(node, NODE_METADATA_ANX_WG_PORT).and_then(|p| p.parse::<u16>().ok())
    {
        outbound["wg_port"] = json!(port);
    }
    Ok(outbound)
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
        Some("xhttp") => xhttp_transport(node),
        Some(_) => Err("transports other than tcp, ws, grpc and xhttp are not implemented yet"),
    }
}

/// The `xhttp` transport entry. Of the share link's `extra` settings, the
/// client-side ones the transport implements are kept, connection reuse
/// (`xmux`) and server-only ones are dropped, and anything that changes the
/// wire format makes the node unsupported.
fn xhttp_transport(node: &NodeDescriptor) -> Result<Value, Unsupported> {
    let mut transport = json!({
        "type": "xhttp",
        "path": metadata(node, NODE_METADATA_V2RAY_TRANSPORT_PATH).unwrap_or("/"),
        "host": metadata(node, NODE_METADATA_V2RAY_TRANSPORT_HOST).unwrap_or_default(),
        "mode": metadata(node, NODE_METADATA_V2RAY_TRANSPORT_MODE).unwrap_or("auto"),
    });
    if !matches!(
        transport["mode"].as_str(),
        Some("auto" | "packet-up" | "stream-up" | "stream-one")
    ) {
        return Err("xhttp mode must be auto, packet-up, stream-up or stream-one");
    }
    let Some(extra) = metadata(node, NODE_METADATA_V2RAY_TRANSPORT_EXTRA) else {
        return Ok(transport);
    };
    let Ok(Value::Object(extra)) = serde_json::from_str::<Value>(extra) else {
        return Err("xhttp extra is not a JSON object");
    };
    for (key, value) in extra {
        let field = match key.as_str() {
            "headers" => "headers",
            "xPaddingBytes" => "x_padding_bytes",
            "scMaxEachPostBytes" => "sc_max_each_post_bytes",
            "scMinPostsIntervalMs" => "sc_min_posts_interval_ms",
            "noGRPCHeader" => "no_grpc_header",
            "xmux" | "noSSEHeader" | "scMaxBufferedPosts" | "scStreamUpServerSecs" => continue,
            "downloadSettings" => {
                return Err("xhttp downloadSettings (split download server) is not implemented yet")
            }
            _ => return Err("xhttp extra options other than headers, padding and post sizing are not implemented yet"),
        };
        transport[field] = value;
    }
    Ok(transport)
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
