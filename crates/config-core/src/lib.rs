//! Pure configuration service for NetworkCore.
//!
//! This crate parses and normalizes the first minimal TOML configuration shape.
//! It performs no file I/O, network access, platform probing, or engine work.

pub mod sdwan_delivery;
pub mod windows_tunnel;

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use control_domain::{
    ConfigSnapshot, ConfigurationService, Diagnostic, DiagnosticSeverity, DomainError,
    DomainResult, Endpoint, ListenerBind, ListenerDescriptor, ListenerKind, ListenerNetwork,
    ListenerRoute, Metadata, MetadataEntry, NodeCatalog, NodeDescriptor, PlatformCapabilities,
    Protocol, RawSubscription, RouteAction, RuleSet, SchemaVersion, SubscriptionDocument,
    SubscriptionService, SubscriptionSource, NODE_METADATA_HYSTERIA2_OBFS_MAX_PACKET_SIZE,
    NODE_METADATA_HYSTERIA2_OBFS_MIN_PACKET_SIZE, NODE_METADATA_HYSTERIA2_OBFS_PASSWORD,
    NODE_METADATA_HYSTERIA2_OBFS_TYPE, NODE_METADATA_HYSTERIA2_PASSWORD,
    NODE_METADATA_HYSTERIA2_SERVER_PORTS, NODE_METADATA_SHADOWSOCKS_METHOD,
    NODE_METADATA_SHADOWSOCKS_PASSWORD, NODE_METADATA_SOURCE_FORMAT, NODE_METADATA_TLS_ALPN,
    NODE_METADATA_TLS_CERTIFICATE_PUBLIC_KEY_SHA256, NODE_METADATA_TLS_INSECURE,
    NODE_METADATA_TLS_SERVER_NAME, NODE_METADATA_TROJAN_PASSWORD,
    NODE_METADATA_TUIC_CONGESTION_CONTROL, NODE_METADATA_TUIC_PASSWORD, NODE_METADATA_TUIC_UUID,
    NODE_METADATA_VLESS_UUID, NODE_METADATA_VMESS_UUID,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub const CURRENT_SCHEMA_VERSION: u32 = 1;

pub const SOURCE_CONFIG_CORE: &str = "config.core";
pub const SOURCE_SUBSCRIPTION_CORE: &str = "subscription.core";

pub const CONFIG_PARSE_FAILED_CODE: &str = "config.core.parse_failed";
pub const CONFIG_SCHEMA_UNSUPPORTED_CODE: &str = "config.core.schema_unsupported";
pub const CONFIG_PROFILE_MISSING_CODE: &str = "config.core.profile_missing";
pub const CONFIG_PROFILE_EMPTY_CODE: &str = "config.core.profile_empty";
pub const CONFIG_PROFILE_CONFLICT_CODE: &str = "config.core.profile_conflict";
pub const CONFIG_LISTENER_ID_EMPTY_CODE: &str = "config.core.listener_id_empty";
pub const CONFIG_LISTENER_KIND_EMPTY_CODE: &str = "config.core.listener_kind_empty";
pub const CONFIG_LISTENER_BIND_HOST_EMPTY_CODE: &str = "config.core.listener_bind_host_empty";
pub const CONFIG_LISTENER_BIND_PORT_INVALID_CODE: &str = "config.core.listener_bind_port_invalid";
pub const CONFIG_LISTENER_NETWORK_UNSUPPORTED_CODE: &str =
    "config.core.listener_network_unsupported";
pub const CONFIG_LISTENER_ROUTE_MISSING_CODE: &str = "config.core.listener_route_missing";
pub const CONFIG_LISTENER_ROUTE_CONFLICT_CODE: &str = "config.core.listener_route_conflict";
pub const CONFIG_NODE_ID_EMPTY_CODE: &str = "config.core.node_id_empty";
pub const CONFIG_NODE_NAME_EMPTY_CODE: &str = "config.core.node_name_empty";
pub const CONFIG_NODE_PROTOCOL_EMPTY_CODE: &str = "config.core.node_protocol_empty";
pub const CONFIG_NODE_HOST_EMPTY_CODE: &str = "config.core.node_host_empty";
pub const CONFIG_NODE_PORT_INVALID_CODE: &str = "config.core.node_port_invalid";
pub const CONFIG_ROUTE_ID_EMPTY_CODE: &str = "config.core.route_id_empty";
pub const CONFIG_ROUTE_ACTION_UNSUPPORTED_CODE: &str = "config.core.route_action_unsupported";
pub const CONFIG_ROUTE_PROXY_NODE_MISSING_CODE: &str = "config.core.route_proxy_node_missing";
pub const CONFIG_MIGRATION_UNSUPPORTED_CODE: &str = "config.core.migration_unsupported";
pub const SUBSCRIPTION_SOURCE_ID_EMPTY_CODE: &str = "subscription.core.source_id_empty";
pub const SUBSCRIPTION_LOCATION_EMPTY_CODE: &str = "subscription.core.location_empty";
pub const SUBSCRIPTION_FETCH_UNSUPPORTED_CODE: &str = "subscription.core.fetch_unsupported";
pub const SUBSCRIPTION_INLINE_PAYLOAD_EMPTY_CODE: &str = "subscription.core.inline_payload_empty";
pub const SUBSCRIPTION_PARSE_FAILED_CODE: &str = "subscription.core.parse_failed";
pub const SUBSCRIPTION_LINK_UNSUPPORTED_CODE: &str = "subscription.core.link_unsupported";
pub const SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE: &str =
    "subscription.core.shadowsocks_link_invalid";
pub const SUBSCRIPTION_TROJAN_LINK_INVALID_CODE: &str = "subscription.core.trojan_link_invalid";
pub const SUBSCRIPTION_VLESS_LINK_INVALID_CODE: &str = "subscription.core.vless_link_invalid";
pub const SUBSCRIPTION_VMESS_LINK_INVALID_CODE: &str = "subscription.core.vmess_link_invalid";
pub const SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE: &str =
    "subscription.core.hysteria2_link_invalid";
pub const SUBSCRIPTION_TUIC_LINK_INVALID_CODE: &str = "subscription.core.tuic_link_invalid";
pub const SUBSCRIPTION_CLASH_YAML_INVALID_CODE: &str = "subscription.core.clash_yaml_invalid";
pub const SUBSCRIPTION_CLASH_YAML_UNSUPPORTED_CODE: &str =
    "subscription.core.clash_yaml_unsupported";
pub const SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE: &str = "subscription.core.sing_box_json_invalid";
pub const SUBSCRIPTION_SING_BOX_JSON_UNSUPPORTED_CODE: &str =
    "subscription.core.sing_box_json_unsupported";
pub const SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE: &str =
    "subscription.core.quantumult_x_proxy_line_invalid";
pub const SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_UNSUPPORTED_CODE: &str =
    "subscription.core.quantumult_x_proxy_line_unsupported";
pub const SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE: &str =
    "subscription.core.loon_proxy_line_invalid";
pub const SUBSCRIPTION_LOON_PROXY_LINE_UNSUPPORTED_CODE: &str =
    "subscription.core.loon_proxy_line_unsupported";
pub const SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE: &str =
    "subscription.core.surge_proxy_line_invalid";
pub const SUBSCRIPTION_SURGE_PROXY_LINE_UNSUPPORTED_CODE: &str =
    "subscription.core.surge_proxy_line_unsupported";

#[derive(Debug, Clone, Copy, Default)]
pub struct CoreConfigurationService;

impl CoreConfigurationService {
    pub const fn new() -> Self {
        Self
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CoreSubscriptionService;

impl CoreSubscriptionService {
    pub const fn new() -> Self {
        Self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedConfigDocument {
    pub schema_version: SchemaVersion,
    pub profiles: Vec<String>,
    pub listeners: Vec<ListenerDescriptor>,
    pub nodes: Vec<NodeDescriptor>,
    pub routes: Vec<RuleSet>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfigDocument {
    schema_version: Option<u32>,
    profile: Option<String>,
    profiles: Option<Vec<String>>,
    listeners: Option<Vec<RawListener>>,
    nodes: Option<Vec<RawNode>>,
    routes: Option<Vec<RawRoute>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSubscriptionDocument {
    nodes: Option<Vec<RawNode>>,
    routes: Option<Vec<RawRoute>>,
}

#[derive(Debug, Deserialize)]
struct RawClashDocument {
    proxies: Option<Vec<RawClashProxy>>,
}

#[derive(Debug, Deserialize)]
struct RawClashProxy {
    name: Option<RawClashScalar>,
    #[serde(rename = "type")]
    protocol: Option<RawClashScalar>,
    server: Option<RawClashScalar>,
    port: Option<RawClashScalar>,
    cipher: Option<RawClashScalar>,
    password: Option<RawClashScalar>,
    uuid: Option<RawClashScalar>,
}

#[derive(Debug, Deserialize)]
struct RawSingBoxDocument {
    outbounds: Option<Vec<RawSingBoxOutbound>>,
}

#[derive(Debug, Deserialize)]
struct RawSingBoxOutbound {
    #[serde(rename = "type")]
    protocol: Option<RawSingBoxScalar>,
    tag: Option<RawSingBoxScalar>,
    server: Option<RawSingBoxScalar>,
    server_port: Option<RawSingBoxScalar>,
    server_ports: Option<RawSingBoxStringList>,
    method: Option<RawSingBoxScalar>,
    password: Option<RawSingBoxScalar>,
    uuid: Option<RawSingBoxScalar>,
    congestion_control: Option<RawSingBoxScalar>,
    obfs: Option<RawSingBoxHysteria2Obfs>,
    tls: Option<RawSingBoxTls>,
}

#[derive(Debug, Deserialize)]
struct RawSingBoxHysteria2Obfs {
    #[serde(rename = "type")]
    kind: Option<RawSingBoxScalar>,
    password: Option<RawSingBoxScalar>,
    min_packet_size: Option<RawSingBoxScalar>,
    max_packet_size: Option<RawSingBoxScalar>,
}

#[derive(Debug, Deserialize)]
struct RawSingBoxTls {
    server_name: Option<RawSingBoxScalar>,
    insecure: Option<bool>,
    alpn: Option<RawSingBoxStringList>,
    certificate_public_key_sha256: Option<RawSingBoxStringList>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawClashScalar {
    Text(String),
    Integer(i64),
}

impl RawClashScalar {
    fn into_text(self) -> String {
        match self {
            Self::Text(value) => value,
            Self::Integer(value) => value.to_string(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawSingBoxScalar {
    Text(String),
    Integer(i64),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawSingBoxStringList {
    Text(String),
    Values(Vec<String>),
}

impl RawSingBoxScalar {
    fn into_text(self) -> String {
        match self {
            Self::Text(value) => value,
            Self::Integer(value) => value.to_string(),
        }
    }
}

impl RawSingBoxStringList {
    fn into_values(self) -> Vec<String> {
        match self {
            Self::Text(value) => vec![value],
            Self::Values(values) => values,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListener {
    id: String,
    enabled: Option<bool>,
    kind: String,
    bind_host: String,
    bind_port: i64,
    network: String,
    route: Option<String>,
    route_action: Option<String>,
    route_node: Option<String>,
    tags: Option<Vec<String>>,
    metadata: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawNode {
    id: String,
    name: Option<String>,
    protocol: String,
    host: String,
    port: i64,
    tags: Option<Vec<String>>,
    metadata: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoute {
    id: String,
    default_action: String,
    default_node: Option<String>,
}

impl ConfigurationService for CoreConfigurationService {
    fn validate(&self, raw_config: &str, _capabilities: &PlatformCapabilities) -> Vec<Diagnostic> {
        parse_config_document(raw_config)
            .err()
            .map(domain_error_to_diagnostic)
            .into_iter()
            .collect()
    }

    fn normalize(
        &self,
        raw_config: &str,
        _capabilities: &PlatformCapabilities,
    ) -> DomainResult<ConfigSnapshot> {
        let document = parse_config_document(raw_config)?;

        Ok(ConfigSnapshot {
            version: document.schema_version,
            profiles: document.profiles,
            listeners: document.listeners,
            nodes: document.nodes,
            policies: document.routes,
            dns: Vec::new(),
            plugins: Vec::new(),
        })
    }

    fn migrate(
        &self,
        raw_config: &str,
        from_version: SchemaVersion,
        to_version: SchemaVersion,
    ) -> DomainResult<String> {
        if from_version == to_version {
            return Ok(raw_config.to_string());
        }

        Err(domain_error(
            CONFIG_MIGRATION_UNSUPPORTED_CODE,
            "configuration migration is not supported by the minimal config service",
        ))
    }
}

impl SubscriptionService for CoreSubscriptionService {
    fn fetch(&self, source: &SubscriptionSource) -> DomainResult<RawSubscription> {
        let source_id = required_trimmed(
            source.id.clone(),
            SUBSCRIPTION_SOURCE_ID_EMPTY_CODE,
            "subscription source id cannot be empty",
        )?;
        let location = required_trimmed(
            source.location.clone(),
            SUBSCRIPTION_LOCATION_EMPTY_CODE,
            "subscription source location cannot be empty",
        )?;

        let Some(content) = location.strip_prefix("inline:") else {
            return Err(domain_error(
                SUBSCRIPTION_FETCH_UNSUPPORTED_CODE,
                "subscription source location is unsupported by the pure subscription service",
            ));
        };

        if content.trim().is_empty() {
            return Err(domain_error(
                SUBSCRIPTION_INLINE_PAYLOAD_EMPTY_CODE,
                "inline subscription payload cannot be empty",
            ));
        }

        Ok(RawSubscription {
            source_id,
            content: content.to_string(),
        })
    }

    fn parse(&self, raw_subscription: &RawSubscription) -> DomainResult<SubscriptionDocument> {
        let source_id = required_trimmed(
            raw_subscription.source_id.clone(),
            SUBSCRIPTION_SOURCE_ID_EMPTY_CODE,
            "subscription source id cannot be empty",
        )?;

        if let Ok(raw) = toml::from_str::<RawSubscriptionDocument>(&raw_subscription.content) {
            return Ok(SubscriptionDocument {
                nodes: collect_nodes(raw.nodes.unwrap_or_default())?,
                rules: collect_routes(raw.routes.unwrap_or_default())?,
                diagnostics: Vec::new(),
            });
        }

        if let Some(document) =
            parse_sing_box_json_subscription(&source_id, &raw_subscription.content)?
        {
            return Ok(document);
        }

        if let Some(document) =
            parse_clash_yaml_subscription(&source_id, &raw_subscription.content)?
        {
            return Ok(document);
        }

        if let Some(document) =
            parse_quantumult_x_proxy_line_subscription(&source_id, &raw_subscription.content)?
        {
            return Ok(document);
        }

        if let Some(document) =
            parse_loon_proxy_line_subscription(&source_id, &raw_subscription.content)?
        {
            return Ok(document);
        }

        if let Some(document) =
            parse_surge_proxy_line_subscription(&source_id, &raw_subscription.content)?
        {
            return Ok(document);
        }

        if let Some(document) = parse_link_subscription(&source_id, &raw_subscription.content)? {
            return Ok(document);
        }

        Err(domain_error(
            SUBSCRIPTION_PARSE_FAILED_CODE,
            "subscription payload could not be parsed as NetworkCore TOML, Clash YAML, sing-box JSON, Quantumult X proxy lines, Loon proxy lines, Surge proxy lines, or supported proxy links",
        ))
    }

    fn normalize(&self, document: &SubscriptionDocument) -> DomainResult<NodeCatalog> {
        Ok(NodeCatalog {
            nodes: document.nodes.clone(),
            rules: document.rules.clone(),
        })
    }
}

pub fn parse_config_document(raw_config: &str) -> DomainResult<ParsedConfigDocument> {
    let raw = toml::from_str::<RawConfigDocument>(raw_config).map_err(|_| {
        domain_error(
            CONFIG_PARSE_FAILED_CODE,
            "configuration could not be parsed as NetworkCore TOML",
        )
    })?;

    let schema_version = raw.schema_version.unwrap_or(CURRENT_SCHEMA_VERSION);
    if schema_version != CURRENT_SCHEMA_VERSION {
        return Err(domain_error(
            CONFIG_SCHEMA_UNSUPPORTED_CODE,
            "configuration schema version is unsupported",
        ));
    }

    let profiles = collect_profiles(raw.profile, raw.profiles)?;
    let listeners = collect_listeners(raw.listeners.unwrap_or_default())?;
    let nodes = collect_nodes(raw.nodes.unwrap_or_default())?;
    let routes = collect_routes(raw.routes.unwrap_or_default())?;

    Ok(ParsedConfigDocument {
        schema_version: SchemaVersion::new(schema_version),
        profiles,
        listeners,
        nodes,
        routes,
    })
}

fn collect_profiles(
    profile: Option<String>,
    profiles: Option<Vec<String>>,
) -> DomainResult<Vec<String>> {
    let profiles = match (profile, profiles) {
        (Some(_), Some(_)) => {
            return Err(domain_error(
                CONFIG_PROFILE_CONFLICT_CODE,
                "configuration must use either profile or profiles",
            ));
        }
        (Some(profile), None) => vec![profile],
        (None, Some(profiles)) => profiles,
        (None, None) => {
            return Err(domain_error(
                CONFIG_PROFILE_MISSING_CODE,
                "configuration must define at least one profile",
            ));
        }
    };

    if profiles.is_empty() {
        return Err(domain_error(
            CONFIG_PROFILE_MISSING_CODE,
            "configuration must define at least one profile",
        ));
    }

    let profiles = profiles
        .into_iter()
        .map(|profile| profile.trim().to_string())
        .collect::<Vec<_>>();

    if profiles.iter().any(String::is_empty) {
        return Err(domain_error(
            CONFIG_PROFILE_EMPTY_CODE,
            "configuration profiles cannot be empty",
        ));
    }

    Ok(profiles)
}

fn collect_listeners(raw_listeners: Vec<RawListener>) -> DomainResult<Vec<ListenerDescriptor>> {
    raw_listeners
        .into_iter()
        .map(normalize_listener)
        .collect::<DomainResult<Vec<_>>>()
}

fn normalize_listener(raw: RawListener) -> DomainResult<ListenerDescriptor> {
    let id = required_trimmed(
        raw.id,
        CONFIG_LISTENER_ID_EMPTY_CODE,
        "listener id cannot be empty",
    )?;
    let kind = parse_listener_kind(raw.kind)?;
    let bind_host = required_trimmed(
        raw.bind_host,
        CONFIG_LISTENER_BIND_HOST_EMPTY_CODE,
        "listener bind host cannot be empty",
    )?;
    let bind_port = parse_port(
        raw.bind_port,
        CONFIG_LISTENER_BIND_PORT_INVALID_CODE,
        "listener bind port must be between 1 and 65535",
    )?;

    Ok(ListenerDescriptor {
        id,
        enabled: raw.enabled.unwrap_or(true),
        kind,
        bind: ListenerBind {
            host: bind_host,
            port: bind_port,
        },
        network: parse_listener_network(raw.network)?,
        route: parse_listener_route(raw.route, raw.route_action, raw.route_node)?,
        tags: collect_tags(raw.tags),
        metadata: collect_metadata(raw.metadata),
    })
}

fn parse_listener_kind(raw: String) -> DomainResult<ListenerKind> {
    let kind = required_trimmed(
        raw,
        CONFIG_LISTENER_KIND_EMPTY_CODE,
        "listener kind cannot be empty",
    )?;

    Ok(match normalized_token(&kind).as_str() {
        "local_tcp" => ListenerKind::LocalTcp,
        "socks" => ListenerKind::Socks,
        "http" => ListenerKind::Http,
        "tun" => ListenerKind::Tun,
        _ => ListenerKind::Other(kind),
    })
}

fn parse_listener_network(raw: String) -> DomainResult<ListenerNetwork> {
    match normalized_token(&raw).as_str() {
        "tcp" => Ok(ListenerNetwork::Tcp),
        "udp" => Ok(ListenerNetwork::Udp),
        "tcp_udp" => Ok(ListenerNetwork::TcpUdp),
        _ => Err(domain_error(
            CONFIG_LISTENER_NETWORK_UNSUPPORTED_CODE,
            "listener network must be tcp, udp, or tcp_udp",
        )),
    }
}

fn parse_listener_route(
    route: Option<String>,
    route_action: Option<String>,
    route_node: Option<String>,
) -> DomainResult<ListenerRoute> {
    match (route, route_action) {
        (Some(route), None) => Ok(ListenerRoute::RuleSet {
            rule_set_id: required_trimmed(
                route,
                CONFIG_LISTENER_ROUTE_MISSING_CODE,
                "listener route cannot be empty",
            )?,
        }),
        (None, Some(action)) => Ok(ListenerRoute::DefaultAction(parse_route_action(
            action, route_node,
        )?)),
        (Some(_), Some(_)) => Err(domain_error(
            CONFIG_LISTENER_ROUTE_CONFLICT_CODE,
            "listener must use either route or route_action",
        )),
        (None, None) => Err(domain_error(
            CONFIG_LISTENER_ROUTE_MISSING_CODE,
            "listener must define route or route_action",
        )),
    }
}

fn collect_nodes(raw_nodes: Vec<RawNode>) -> DomainResult<Vec<NodeDescriptor>> {
    raw_nodes
        .into_iter()
        .map(normalize_node)
        .collect::<DomainResult<Vec<_>>>()
}

fn normalize_node(raw: RawNode) -> DomainResult<NodeDescriptor> {
    let id = required_trimmed(raw.id, CONFIG_NODE_ID_EMPTY_CODE, "node id cannot be empty")?;
    let name = match raw.name {
        Some(name) => required_trimmed(
            name,
            CONFIG_NODE_NAME_EMPTY_CODE,
            "node name cannot be empty",
        )?,
        None => id.clone(),
    };
    let host = required_trimmed(
        raw.host,
        CONFIG_NODE_HOST_EMPTY_CODE,
        "node host cannot be empty",
    )?;
    let port = parse_port(
        raw.port,
        CONFIG_NODE_PORT_INVALID_CODE,
        "node port must be between 1 and 65535",
    )?;

    Ok(NodeDescriptor {
        id,
        name,
        protocol: parse_protocol(raw.protocol)?,
        endpoint: Endpoint { host, port },
        tags: collect_tags(raw.tags),
        metadata: collect_metadata(raw.metadata),
    })
}

fn parse_link_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    if content.starts_with("ss://") || content.lines().any(|line| line.trim().contains("://")) {
        return parse_proxy_link_lines(source_id, content).map(Some);
    }

    if let Some(decoded) = decode_base64_text(content) {
        let decoded = decoded.trim();
        if decoded.lines().any(|line| line.trim().contains("://")) {
            return parse_proxy_link_lines(source_id, decoded).map(Some);
        }
    }

    Ok(None)
}

fn parse_clash_yaml_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    let raw = match serde_saphyr::from_str::<RawClashDocument>(content) {
        Ok(raw) => raw,
        Err(_) => return Ok(None),
    };
    let Some(proxies) = raw.proxies else {
        return Ok(None);
    };
    if proxies.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
            "clash yaml proxies cannot be empty",
        ));
    }

    let mut nodes = Vec::new();
    let mut seen_ids = BTreeSet::new();
    for proxy in proxies {
        let mut node = parse_clash_proxy(proxy, source_id)?;
        if !seen_ids.insert(node.id.clone()) {
            let base_id = node.id.clone();
            let mut suffix = seen_ids.len() + 1;
            loop {
                node.id = format!("{base_id}-{suffix}");
                if seen_ids.insert(node.id.clone()) {
                    break;
                }
                suffix += 1;
            }
        }
        nodes.push(node);
    }

    Ok(Some(SubscriptionDocument {
        nodes,
        rules: Vec::new(),
        diagnostics: Vec::new(),
    }))
}

fn parse_clash_proxy(raw: RawClashProxy, source_id: &str) -> DomainResult<NodeDescriptor> {
    let name = required_clash_scalar_field(raw.name, "clash proxy name cannot be empty")?;
    let protocol = required_clash_scalar_field(raw.protocol, "clash proxy type cannot be empty")?;
    let host = required_clash_scalar_field(raw.server, "clash proxy server cannot be empty")?;
    let port = required_clash_scalar_field(raw.port, "clash proxy port cannot be empty")?;
    let port = port.parse::<i64>().map_err(|_| {
        domain_error(
            SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
            "clash proxy port must be a number",
        )
    })?;
    let port = parse_port(
        port,
        SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
        "clash proxy port must be between 1 and 65535",
    )?;

    let protocol_token = normalized_token(&protocol);
    let (protocol, protocol_tag, mut metadata) = match protocol_token.as_str() {
        "ss" | "shadowsocks" => {
            let method = required_clash_scalar_field(
                raw.cipher,
                "clash shadowsocks cipher cannot be empty",
            )?;
            let password = required_clash_scalar_field(
                raw.password,
                "clash shadowsocks password cannot be empty",
            )?;
            (
                Protocol::Shadowsocks,
                "ss",
                vec![
                    MetadataEntry {
                        key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                        value: method,
                    },
                    MetadataEntry {
                        key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                        value: password,
                    },
                ],
            )
        }
        "trojan" => {
            let password =
                required_clash_scalar_field(raw.password, "clash trojan password cannot be empty")?;
            (
                Protocol::Trojan,
                "trojan",
                vec![MetadataEntry {
                    key: NODE_METADATA_TROJAN_PASSWORD.to_string(),
                    value: password,
                }],
            )
        }
        "vless" => {
            let uuid = required_clash_scalar_field(raw.uuid, "clash vless uuid cannot be empty")?;
            (
                Protocol::Vless,
                "vless",
                vec![MetadataEntry {
                    key: NODE_METADATA_VLESS_UUID.to_string(),
                    value: uuid,
                }],
            )
        }
        "vmess" => {
            let uuid = required_clash_scalar_field(raw.uuid, "clash vmess uuid cannot be empty")?;
            (
                Protocol::Vmess,
                "vmess",
                vec![MetadataEntry {
                    key: NODE_METADATA_VMESS_UUID.to_string(),
                    value: uuid,
                }],
            )
        }
        _ => {
            return Err(domain_error(
                SUBSCRIPTION_CLASH_YAML_UNSUPPORTED_CODE,
                "clash proxy type must be ss, trojan, vless, or vmess",
            ));
        }
    };

    let name_id = sanitize_identifier(&name);
    let name_id = if name_id.is_empty() {
        "node".to_string()
    } else {
        name_id
    };
    let id = format!("clash-{protocol_tag}-{name_id}");
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "clash-yaml".to_string(),
    });
    metadata.push(MetadataEntry {
        key: "subscription.source_id".to_string(),
        value: source_id.to_string(),
    });

    Ok(NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint { host, port },
        tags: vec![
            "subscription".to_string(),
            "clash-yaml".to_string(),
            protocol_tag.to_string(),
        ],
        metadata,
    })
}

fn required_clash_scalar_field(
    raw: Option<RawClashScalar>,
    message: &'static str,
) -> DomainResult<String> {
    let Some(raw) = raw else {
        return Err(domain_error(SUBSCRIPTION_CLASH_YAML_INVALID_CODE, message));
    };

    required_trimmed(
        raw.into_text(),
        SUBSCRIPTION_CLASH_YAML_INVALID_CODE,
        message,
    )
}

fn parse_sing_box_json_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    let raw = match serde_json::from_str::<RawSingBoxDocument>(content) {
        Ok(raw) => raw,
        Err(_) => return Ok(None),
    };
    let Some(outbounds) = raw.outbounds else {
        return Ok(None);
    };
    if outbounds.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            "sing-box json outbounds cannot be empty",
        ));
    }

    let mut nodes = Vec::new();
    let mut seen_ids = BTreeSet::new();
    for outbound in outbounds {
        let Some(mut node) = parse_sing_box_outbound(outbound, source_id)? else {
            continue;
        };
        if !seen_ids.insert(node.id.clone()) {
            let base_id = node.id.clone();
            let mut suffix = seen_ids.len() + 1;
            loop {
                node.id = format!("{base_id}-{suffix}");
                if seen_ids.insert(node.id.clone()) {
                    break;
                }
                suffix += 1;
            }
        }
        nodes.push(node);
    }

    if nodes.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_SING_BOX_JSON_UNSUPPORTED_CODE,
            "sing-box json outbounds must contain at least one supported proxy outbound",
        ));
    }

    Ok(Some(SubscriptionDocument {
        nodes,
        rules: Vec::new(),
        diagnostics: Vec::new(),
    }))
}

fn parse_sing_box_outbound(
    raw: RawSingBoxOutbound,
    source_id: &str,
) -> DomainResult<Option<NodeDescriptor>> {
    let RawSingBoxOutbound {
        protocol,
        tag,
        server,
        server_port,
        server_ports,
        method,
        password,
        uuid,
        congestion_control,
        obfs,
        tls,
    } = raw;
    let protocol =
        required_sing_box_scalar_field(protocol, "sing-box outbound type cannot be empty")?;
    let protocol_token = normalized_token(&protocol);
    if is_ignored_sing_box_outbound(&protocol_token) {
        return Ok(None);
    }

    let host = required_sing_box_scalar_field(server, "sing-box outbound server cannot be empty")?;
    let (port, server_ports) = parse_sing_box_outbound_port(
        server_port,
        server_ports.map(RawSingBoxStringList::into_values),
        matches!(protocol_token.as_str(), "hysteria2" | "hy2"),
    )?;

    let (protocol, protocol_tag, mut metadata) = match protocol_token.as_str() {
        "ss" | "shadowsocks" => {
            let method = required_sing_box_scalar_field(
                method,
                "sing-box shadowsocks method cannot be empty",
            )?;
            let password = required_sing_box_scalar_field(
                password,
                "sing-box shadowsocks password cannot be empty",
            )?;
            (
                Protocol::Shadowsocks,
                "ss",
                vec![
                    MetadataEntry {
                        key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                        value: method,
                    },
                    MetadataEntry {
                        key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                        value: password,
                    },
                ],
            )
        }
        "trojan" => {
            let password = required_sing_box_scalar_field(
                password,
                "sing-box trojan password cannot be empty",
            )?;
            (
                Protocol::Trojan,
                "trojan",
                vec![MetadataEntry {
                    key: NODE_METADATA_TROJAN_PASSWORD.to_string(),
                    value: password,
                }],
            )
        }
        "vless" => {
            let uuid = required_sing_box_scalar_field(uuid, "sing-box vless uuid cannot be empty")?;
            (
                Protocol::Vless,
                "vless",
                vec![MetadataEntry {
                    key: NODE_METADATA_VLESS_UUID.to_string(),
                    value: uuid,
                }],
            )
        }
        "vmess" => {
            let uuid = required_sing_box_scalar_field(uuid, "sing-box vmess uuid cannot be empty")?;
            (
                Protocol::Vmess,
                "vmess",
                vec![MetadataEntry {
                    key: NODE_METADATA_VMESS_UUID.to_string(),
                    value: uuid,
                }],
            )
        }
        "hysteria2" | "hy2" => {
            let password = required_sing_box_scalar_field(
                password,
                "sing-box hysteria2 password cannot be empty",
            )?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_HYSTERIA2_PASSWORD.to_string(),
                value: password,
            }];
            if let Some(server_ports) = server_ports {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_HYSTERIA2_SERVER_PORTS.to_string(),
                    value: server_ports,
                });
            }
            metadata.extend(sing_box_tls_metadata(tls, &host)?);
            append_sing_box_hysteria2_obfs_metadata(&mut metadata, obfs)?;
            (Protocol::Hysteria2, "hysteria2", metadata)
        }
        "tuic" => {
            let uuid = required_sing_box_scalar_field(uuid, "sing-box tuic uuid cannot be empty")?;
            let mut metadata = vec![MetadataEntry {
                key: NODE_METADATA_TUIC_UUID.to_string(),
                value: uuid,
            }];
            if let Some(password) = optional_sing_box_scalar_field(password) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_TUIC_PASSWORD.to_string(),
                    value: password,
                });
            }
            if let Some(congestion_control) = optional_sing_box_scalar_field(congestion_control) {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_TUIC_CONGESTION_CONTROL.to_string(),
                    value: congestion_control,
                });
            }
            metadata.extend(sing_box_tls_metadata(tls, &host)?);
            (Protocol::Tuic, "tuic", metadata)
        }
        _ => {
            return Err(domain_error(
                SUBSCRIPTION_SING_BOX_JSON_UNSUPPORTED_CODE,
                "sing-box outbound type must be shadowsocks, trojan, vless, vmess, hysteria2, or tuic for catalog import",
            ));
        }
    };

    let tag = optional_sing_box_scalar_field(tag);
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let fallback_id = format!("{host_id}-{port}");
    let name = tag
        .clone()
        .unwrap_or_else(|| format!("sing-box-{protocol_tag}-{fallback_id}"));
    let name_id = tag.as_deref().unwrap_or(&fallback_id);
    let name_id = sanitize_identifier(name_id);
    let name_id = if name_id.is_empty() {
        "node".to_string()
    } else {
        name_id
    };
    let id = format!("sing-box-{protocol_tag}-{name_id}");
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "sing-box-json".to_string(),
    });
    metadata.push(MetadataEntry {
        key: "subscription.source_id".to_string(),
        value: source_id.to_string(),
    });

    Ok(Some(NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint { host, port },
        tags: vec![
            "subscription".to_string(),
            "sing-box-json".to_string(),
            protocol_tag.to_string(),
        ],
        metadata,
    }))
}

fn parse_sing_box_outbound_port(
    server_port: Option<RawSingBoxScalar>,
    server_ports: Option<Vec<String>>,
    supports_port_ranges: bool,
) -> DomainResult<(u16, Option<String>)> {
    if supports_port_ranges {
        if let Some(server_ports) = server_ports {
            let normalized = normalize_hysteria2_server_port_ranges(
                server_ports,
                SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            )?;
            let first_port = normalized.first().ok_or_else(|| {
                domain_error(
                    SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
                    "sing-box hysteria2 server_ports cannot be empty",
                )
            })?;
            let first_port = hysteria2_server_port_range_start(
                first_port,
                SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            )?;
            return Ok((first_port, Some(normalized.join(","))));
        }
    }

    let port = required_sing_box_scalar_field(
        server_port,
        "sing-box outbound server_port cannot be empty",
    )?;
    let port = port.parse::<i64>().map_err(|_| {
        domain_error(
            SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            "sing-box outbound server_port must be a number",
        )
    })?;
    let port = parse_port(
        port,
        SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
        "sing-box outbound server_port must be between 1 and 65535",
    )?;

    Ok((port, None))
}

fn sing_box_tls_metadata(raw: Option<RawSingBoxTls>, host: &str) -> DomainResult<Metadata> {
    let (server_name, insecure, alpn, certificate_public_key_sha256) = match raw {
        Some(raw) => (
            optional_sing_box_scalar_field(raw.server_name).unwrap_or_else(|| host.to_string()),
            raw.insecure.unwrap_or(false),
            raw.alpn.map(RawSingBoxStringList::into_values),
            raw.certificate_public_key_sha256
                .map(RawSingBoxStringList::into_values),
        ),
        None => (host.to_string(), false, None, None),
    };
    let mut metadata = vec![
        MetadataEntry {
            key: NODE_METADATA_TLS_SERVER_NAME.to_string(),
            value: server_name,
        },
        MetadataEntry {
            key: NODE_METADATA_TLS_INSECURE.to_string(),
            value: insecure.to_string(),
        },
    ];
    if let Some(alpn) =
        normalize_non_empty_metadata_values(alpn, "sing-box tls alpn values cannot be empty")?
    {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_ALPN.to_string(),
            value: alpn.join(","),
        });
    }
    if let Some(certificate_public_key_sha256) = normalize_non_empty_metadata_values(
        certificate_public_key_sha256,
        "sing-box tls certificate_public_key_sha256 values cannot be empty",
    )? {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_CERTIFICATE_PUBLIC_KEY_SHA256.to_string(),
            value: certificate_public_key_sha256.join(","),
        });
    }
    Ok(metadata)
}

fn append_sing_box_hysteria2_obfs_metadata(
    metadata: &mut Metadata,
    obfs: Option<RawSingBoxHysteria2Obfs>,
) -> DomainResult<()> {
    let Some(obfs) = obfs else {
        return Ok(());
    };
    let kind =
        required_sing_box_scalar_field(obfs.kind, "sing-box hysteria2 obfs type cannot be empty")?;
    let kind = normalized_token(&kind);
    if !matches!(kind.as_str(), "salamander" | "gecko") {
        return Err(domain_error(
            SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            "sing-box hysteria2 obfs type must be salamander or gecko",
        ));
    }
    let password = required_sing_box_scalar_field(
        obfs.password,
        "sing-box hysteria2 obfs password cannot be empty",
    )?;
    metadata.push(MetadataEntry {
        key: NODE_METADATA_HYSTERIA2_OBFS_TYPE.to_string(),
        value: kind.clone(),
    });
    metadata.push(MetadataEntry {
        key: NODE_METADATA_HYSTERIA2_OBFS_PASSWORD.to_string(),
        value: password,
    });
    if kind == "gecko" {
        if let Some(value) = obfs.min_packet_size {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_HYSTERIA2_OBFS_MIN_PACKET_SIZE.to_string(),
                value: normalize_hysteria2_packet_size(
                    value.into_text(),
                    SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
                )?,
            });
        }
        if let Some(value) = obfs.max_packet_size {
            metadata.push(MetadataEntry {
                key: NODE_METADATA_HYSTERIA2_OBFS_MAX_PACKET_SIZE.to_string(),
                value: normalize_hysteria2_packet_size(
                    value.into_text(),
                    SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
                )?,
            });
        }
    }
    Ok(())
}

fn normalize_non_empty_metadata_values(
    values: Option<Vec<String>>,
    message: &'static str,
) -> DomainResult<Option<Vec<String>>> {
    values
        .map(|values| {
            values
                .into_iter()
                .map(|value| {
                    required_trimmed(value, SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE, message)
                })
                .collect::<DomainResult<Vec<_>>>()
        })
        .transpose()
}

fn is_ignored_sing_box_outbound(protocol_token: &str) -> bool {
    matches!(
        protocol_token,
        "direct" | "block" | "dns" | "selector" | "urltest" | "bridge"
    )
}

fn required_sing_box_scalar_field(
    raw: Option<RawSingBoxScalar>,
    message: &'static str,
) -> DomainResult<String> {
    let Some(raw) = raw else {
        return Err(domain_error(
            SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
            message,
        ));
    };

    required_trimmed(
        raw.into_text(),
        SUBSCRIPTION_SING_BOX_JSON_INVALID_CODE,
        message,
    )
}

fn optional_sing_box_scalar_field(raw: Option<RawSingBoxScalar>) -> Option<String> {
    let text = raw?.into_text().trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn parse_quantumult_x_proxy_line_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    let mut saw_server_local_section = false;
    let mut in_server_local_section = false;
    let mut proxy_lines = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("//")
            || line.starts_with(';')
        {
            continue;
        }

        if let Some(section) = parse_surge_section_header(line) {
            in_server_local_section = normalized_token(section).as_str() == "server_local";
            saw_server_local_section |= in_server_local_section;
            continue;
        }

        if in_server_local_section {
            proxy_lines.push(line.to_string());
        }
    }

    if !saw_server_local_section {
        return Ok(None);
    }
    if proxy_lines.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
            "quantumult x server_local section cannot be empty",
        ));
    }

    let mut nodes = Vec::new();
    let mut seen_ids = BTreeSet::new();
    for line in proxy_lines {
        let mut node = parse_quantumult_x_proxy_line(&line, source_id)?;
        if !seen_ids.insert(node.id.clone()) {
            let base_id = node.id.clone();
            let mut suffix = seen_ids.len() + 1;
            loop {
                node.id = format!("{base_id}-{suffix}");
                if seen_ids.insert(node.id.clone()) {
                    break;
                }
                suffix += 1;
            }
        }
        nodes.push(node);
    }

    Ok(Some(SubscriptionDocument {
        nodes,
        rules: Vec::new(),
        diagnostics: Vec::new(),
    }))
}

fn parse_quantumult_x_proxy_line(line: &str, source_id: &str) -> DomainResult<NodeDescriptor> {
    let (protocol, definition) = line.split_once('=').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
            "quantumult x proxy line must contain protocol and definition",
        )
    })?;
    let protocol_token = normalized_token(protocol);
    let parts = definition
        .split(',')
        .map(|part| part.trim().to_string())
        .collect::<Vec<_>>();
    let endpoint = parts.first().cloned().unwrap_or_default();
    let endpoint = required_trimmed(
        endpoint,
        SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
        "quantumult x proxy endpoint cannot be empty",
    )?;
    let (host, port) = parse_host_port_for(
        &endpoint,
        SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
        "quantumult x proxy",
    )?;
    let options = collect_quantumult_x_proxy_options(&parts[1..])?;

    let (protocol, protocol_tag, mut metadata) = match protocol_token.as_str() {
        "ss" | "shadowsocks" => {
            let method = required_quantumult_x_proxy_option(
                &options,
                &["method"],
                "quantumult x shadowsocks method cannot be empty",
            )?;
            let password = required_quantumult_x_proxy_option(
                &options,
                &["password"],
                "quantumult x shadowsocks password cannot be empty",
            )?;
            (
                Protocol::Shadowsocks,
                "ss",
                vec![
                    MetadataEntry {
                        key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                        value: method,
                    },
                    MetadataEntry {
                        key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                        value: password,
                    },
                ],
            )
        }
        "trojan" => {
            let password = required_quantumult_x_proxy_option(
                &options,
                &["password"],
                "quantumult x trojan password cannot be empty",
            )?;
            (
                Protocol::Trojan,
                "trojan",
                vec![MetadataEntry {
                    key: NODE_METADATA_TROJAN_PASSWORD.to_string(),
                    value: password,
                }],
            )
        }
        "vless" => {
            let uuid = required_quantumult_x_proxy_option(
                &options,
                &["password", "uuid"],
                "quantumult x vless uuid cannot be empty",
            )?;
            (
                Protocol::Vless,
                "vless",
                vec![MetadataEntry {
                    key: NODE_METADATA_VLESS_UUID.to_string(),
                    value: uuid,
                }],
            )
        }
        "vmess" => {
            let uuid = required_quantumult_x_proxy_option(
                &options,
                &["password", "uuid", "username"],
                "quantumult x vmess uuid cannot be empty",
            )?;
            (
                Protocol::Vmess,
                "vmess",
                vec![MetadataEntry {
                    key: NODE_METADATA_VMESS_UUID.to_string(),
                    value: uuid,
                }],
            )
        }
        "direct" | "reject" | "http" | "https" | "socks" | "socks5" | "ssr" | "shadowsocksr"
        | "hysteria" | "hysteria2" | "tuic" | "wireguard" => {
            return Err(domain_error(
                SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_UNSUPPORTED_CODE,
                "quantumult x proxy type must be shadowsocks, trojan, vless, or vmess for catalog import",
            ));
        }
        _ => {
            return Err(domain_error(
                SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_UNSUPPORTED_CODE,
                "quantumult x proxy type must be shadowsocks, trojan, vless, or vmess for catalog import",
            ));
        }
    };

    let name = optional_quantumult_x_proxy_option(&options, &["tag"]).unwrap_or_else(|| {
        let host_id = sanitize_identifier(&host);
        let host_id = if host_id.is_empty() {
            "host".to_string()
        } else {
            host_id
        };
        format!("quantumult-x-{protocol_tag}-{host_id}-{port}")
    });
    let name_id = sanitize_identifier(&name);
    let name_id = if name_id.is_empty() {
        "node".to_string()
    } else {
        name_id
    };
    let id = format!("quantumult-x-{protocol_tag}-{name_id}");
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "quantumult-x-proxy-line".to_string(),
    });
    metadata.push(MetadataEntry {
        key: "subscription.source_id".to_string(),
        value: source_id.to_string(),
    });

    Ok(NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint { host, port },
        tags: vec![
            "subscription".to_string(),
            "quantumult-x-proxy-line".to_string(),
            protocol_tag.to_string(),
        ],
        metadata,
    })
}

fn collect_quantumult_x_proxy_options(parts: &[String]) -> DomainResult<BTreeMap<String, String>> {
    let mut options = BTreeMap::new();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        let Some((key, value)) = part.split_once('=') else {
            return Err(domain_error(
                SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
                "quantumult x proxy option must use key=value",
            ));
        };
        let key = normalized_token(key);
        let value = strip_quantumult_x_quotes(value.to_string());
        let value = required_trimmed(
            value,
            SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE,
            "quantumult x proxy option value cannot be empty",
        )?;
        if !key.is_empty() {
            options.insert(key, value);
        }
    }
    Ok(options)
}

fn optional_quantumult_x_proxy_option(
    options: &BTreeMap<String, String>,
    keys: &[&str],
) -> Option<String> {
    for key in keys {
        if let Some(value) = options.get(*key) {
            return Some(value.clone());
        }
    }
    None
}

fn required_quantumult_x_proxy_option(
    options: &BTreeMap<String, String>,
    keys: &[&str],
    message: &'static str,
) -> DomainResult<String> {
    optional_quantumult_x_proxy_option(options, keys)
        .ok_or_else(|| domain_error(SUBSCRIPTION_QUANTUMULT_X_PROXY_LINE_INVALID_CODE, message))
}

fn strip_quantumult_x_quotes(value: String) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

fn parse_loon_proxy_line_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    let mut saw_proxy_section = false;
    let mut in_proxy_section = false;
    let mut proxy_lines = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        if let Some(section) = parse_surge_section_header(line) {
            in_proxy_section = normalized_token(section).as_str() == "proxy";
            saw_proxy_section |= in_proxy_section;
            continue;
        }

        if in_proxy_section {
            proxy_lines.push(line.to_string());
        }
    }

    if !saw_proxy_section {
        return Ok(None);
    }
    if proxy_lines.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
            "loon proxy section cannot be empty",
        ));
    }

    let mut parsed_nodes = Vec::new();
    for line in proxy_lines {
        let Some(node) = parse_loon_proxy_line(&line, source_id)? else {
            if parsed_nodes.is_empty() {
                return Ok(None);
            }
            return Err(domain_error(
                SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
                "loon proxy section cannot mix positional lines with other proxy line styles",
            ));
        };
        parsed_nodes.push(node);
    }

    if parsed_nodes.is_empty() {
        return Ok(None);
    }

    let mut nodes = Vec::new();
    let mut seen_ids = BTreeSet::new();
    for mut node in parsed_nodes {
        if !seen_ids.insert(node.id.clone()) {
            let base_id = node.id.clone();
            let mut suffix = seen_ids.len() + 1;
            loop {
                node.id = format!("{base_id}-{suffix}");
                if seen_ids.insert(node.id.clone()) {
                    break;
                }
                suffix += 1;
            }
        }
        nodes.push(node);
    }

    Ok(Some(SubscriptionDocument {
        nodes,
        rules: Vec::new(),
        diagnostics: Vec::new(),
    }))
}

fn parse_loon_proxy_line(line: &str, source_id: &str) -> DomainResult<Option<NodeDescriptor>> {
    let Some((name, definition)) = line.split_once('=') else {
        return Ok(None);
    };
    let name = required_trimmed(
        name.to_string(),
        SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
        "loon proxy name cannot be empty",
    )?;
    let parts = definition
        .split(',')
        .map(|part| part.trim().to_string())
        .collect::<Vec<_>>();
    if parts.len() < 3 || parts.iter().take(3).any(String::is_empty) {
        return Err(domain_error(
            SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
            "loon proxy line must contain type, server, and port",
        ));
    }

    let protocol_token = normalized_token(&parts[0]);
    let host = required_trimmed(
        parts[1].clone(),
        SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
        "loon proxy server cannot be empty",
    )?;
    let port = parts[2].parse::<i64>().map_err(|_| {
        domain_error(
            SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
            "loon proxy port must be a number",
        )
    })?;
    let port = parse_port(
        port,
        SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE,
        "loon proxy port must be between 1 and 65535",
    )?;

    let (protocol, protocol_tag, mut metadata) = match protocol_token.as_str() {
        "ss" | "shadowsocks" => {
            if loon_proxy_part_looks_like_key_value(&parts, 3)
                || loon_proxy_part_looks_like_key_value(&parts, 4)
            {
                return Ok(None);
            }
            let method =
                required_loon_proxy_part(&parts, 3, "loon shadowsocks method cannot be empty")?;
            let password =
                required_loon_proxy_part(&parts, 4, "loon shadowsocks password cannot be empty")?;
            (
                Protocol::Shadowsocks,
                "ss",
                vec![
                    MetadataEntry {
                        key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                        value: method,
                    },
                    MetadataEntry {
                        key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                        value: password,
                    },
                ],
            )
        }
        "trojan" => {
            if loon_proxy_part_looks_like_key_value(&parts, 3) {
                return Ok(None);
            }
            let password =
                required_loon_proxy_part(&parts, 3, "loon trojan password cannot be empty")?;
            (
                Protocol::Trojan,
                "trojan",
                vec![MetadataEntry {
                    key: NODE_METADATA_TROJAN_PASSWORD.to_string(),
                    value: password,
                }],
            )
        }
        "vless" => {
            if loon_proxy_part_looks_like_key_value(&parts, 3) {
                return Ok(None);
            }
            let uuid = required_loon_proxy_part(&parts, 3, "loon vless uuid cannot be empty")?;
            (
                Protocol::Vless,
                "vless",
                vec![MetadataEntry {
                    key: NODE_METADATA_VLESS_UUID.to_string(),
                    value: uuid,
                }],
            )
        }
        "vmess" => {
            if loon_proxy_part_looks_like_key_value(&parts, 3)
                || loon_proxy_part_looks_like_key_value(&parts, 4)
            {
                return Ok(None);
            }
            let uuid = required_loon_proxy_part(&parts, 4, "loon vmess uuid cannot be empty")?;
            (
                Protocol::Vmess,
                "vmess",
                vec![MetadataEntry {
                    key: NODE_METADATA_VMESS_UUID.to_string(),
                    value: uuid,
                }],
            )
        }
        "direct" | "reject" | "http" | "https" | "socks" | "socks5" | "ssr" | "shadowsocksr"
        | "hysteria" | "hysteria2" | "tuic" | "wireguard" => {
            return Err(domain_error(
                SUBSCRIPTION_LOON_PROXY_LINE_UNSUPPORTED_CODE,
                "loon proxy type must be shadowsocks, trojan, vless, or vmess for catalog import",
            ));
        }
        _ => return Ok(None),
    };

    let name_id = sanitize_identifier(&name);
    let name_id = if name_id.is_empty() {
        "node".to_string()
    } else {
        name_id
    };
    let id = format!("loon-{protocol_tag}-{name_id}");
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "loon-proxy-line".to_string(),
    });
    metadata.push(MetadataEntry {
        key: "subscription.source_id".to_string(),
        value: source_id.to_string(),
    });

    Ok(Some(NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint { host, port },
        tags: vec![
            "subscription".to_string(),
            "loon-proxy-line".to_string(),
            protocol_tag.to_string(),
        ],
        metadata,
    }))
}

fn loon_proxy_part_looks_like_key_value(parts: &[String], index: usize) -> bool {
    parts
        .get(index)
        .map(|part| part.contains('='))
        .unwrap_or_default()
}

fn required_loon_proxy_part(
    parts: &[String],
    index: usize,
    message: &'static str,
) -> DomainResult<String> {
    let value = parts.get(index).cloned().unwrap_or_default();
    let value = strip_loon_quotes(value);
    required_trimmed(value, SUBSCRIPTION_LOON_PROXY_LINE_INVALID_CODE, message)
}

fn strip_loon_quotes(value: String) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        value[1..value.len() - 1].to_string()
    } else {
        value.to_string()
    }
}

fn parse_surge_proxy_line_subscription(
    source_id: &str,
    content: &str,
) -> DomainResult<Option<SubscriptionDocument>> {
    let content = content.trim();
    if content.is_empty() {
        return Ok(None);
    }

    let mut saw_proxy_section = false;
    let mut in_proxy_section = false;
    let mut proxy_lines = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        if let Some(section) = parse_surge_section_header(line) {
            in_proxy_section = normalized_token(section).as_str() == "proxy";
            saw_proxy_section |= in_proxy_section;
            continue;
        }

        if in_proxy_section {
            proxy_lines.push(line.to_string());
        }
    }

    if !saw_proxy_section {
        return Ok(None);
    }
    if proxy_lines.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy section cannot be empty",
        ));
    }

    let mut nodes = Vec::new();
    let mut seen_ids = BTreeSet::new();
    for line in proxy_lines {
        let mut node = parse_surge_proxy_line(&line, source_id)?;
        if !seen_ids.insert(node.id.clone()) {
            let base_id = node.id.clone();
            let mut suffix = seen_ids.len() + 1;
            loop {
                node.id = format!("{base_id}-{suffix}");
                if seen_ids.insert(node.id.clone()) {
                    break;
                }
                suffix += 1;
            }
        }
        nodes.push(node);
    }

    Ok(Some(SubscriptionDocument {
        nodes,
        rules: Vec::new(),
        diagnostics: Vec::new(),
    }))
}

fn parse_surge_proxy_line(line: &str, source_id: &str) -> DomainResult<NodeDescriptor> {
    let (name, definition) = line.split_once('=').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy line must contain name and definition",
        )
    })?;
    let name = required_trimmed(
        name.to_string(),
        SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
        "surge proxy name cannot be empty",
    )?;
    let parts = definition
        .split(',')
        .map(|part| part.trim().to_string())
        .collect::<Vec<_>>();
    if parts.len() < 3 || parts.iter().take(3).any(String::is_empty) {
        return Err(domain_error(
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy line must contain type, server, and port",
        ));
    }

    let protocol_token = normalized_token(&parts[0]);
    let host = required_trimmed(
        parts[1].clone(),
        SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
        "surge proxy server cannot be empty",
    )?;
    let port = parts[2].parse::<i64>().map_err(|_| {
        domain_error(
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy port must be a number",
        )
    })?;
    let port = parse_port(
        port,
        SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
        "surge proxy port must be between 1 and 65535",
    )?;
    let options = collect_surge_proxy_options(&parts[3..])?;

    let (protocol, protocol_tag, mut metadata) = match protocol_token.as_str() {
        "ss" | "shadowsocks" => {
            let method = required_surge_proxy_option(
                &options,
                &["encrypt_method", "method"],
                "surge shadowsocks encrypt-method cannot be empty",
            )?;
            let password = required_surge_proxy_option(
                &options,
                &["password"],
                "surge shadowsocks password cannot be empty",
            )?;
            (
                Protocol::Shadowsocks,
                "ss",
                vec![
                    MetadataEntry {
                        key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                        value: method,
                    },
                    MetadataEntry {
                        key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                        value: password,
                    },
                ],
            )
        }
        "trojan" => {
            let password = required_surge_proxy_option(
                &options,
                &["password"],
                "surge trojan password cannot be empty",
            )?;
            (
                Protocol::Trojan,
                "trojan",
                vec![MetadataEntry {
                    key: NODE_METADATA_TROJAN_PASSWORD.to_string(),
                    value: password,
                }],
            )
        }
        "vmess" => {
            let uuid = required_surge_proxy_option(
                &options,
                &["username", "uuid"],
                "surge vmess username cannot be empty",
            )?;
            (
                Protocol::Vmess,
                "vmess",
                vec![MetadataEntry {
                    key: NODE_METADATA_VMESS_UUID.to_string(),
                    value: uuid,
                }],
            )
        }
        _ => {
            return Err(domain_error(
                SUBSCRIPTION_SURGE_PROXY_LINE_UNSUPPORTED_CODE,
                "surge proxy type must be ss, trojan, or vmess for catalog import",
            ));
        }
    };

    let name_id = sanitize_identifier(&name);
    let name_id = if name_id.is_empty() {
        "node".to_string()
    } else {
        name_id
    };
    let id = format!("surge-{protocol_tag}-{name_id}");
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: "surge-proxy-line".to_string(),
    });
    metadata.push(MetadataEntry {
        key: "subscription.source_id".to_string(),
        value: source_id.to_string(),
    });

    Ok(NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint { host, port },
        tags: vec![
            "subscription".to_string(),
            "surge-proxy-line".to_string(),
            protocol_tag.to_string(),
        ],
        metadata,
    })
}

fn parse_surge_section_header(line: &str) -> Option<&str> {
    line.strip_prefix('[')?.strip_suffix(']')
}

fn collect_surge_proxy_options(parts: &[String]) -> DomainResult<BTreeMap<String, String>> {
    let mut options = BTreeMap::new();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        let Some((key, value)) = part.split_once('=') else {
            return Err(domain_error(
                SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
                "surge proxy option must use key=value",
            ));
        };
        let key = normalized_token(key);
        let value = required_trimmed(
            value.to_string(),
            SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
            "surge proxy option value cannot be empty",
        )?;
        if !key.is_empty() {
            options.insert(key, value);
        }
    }
    Ok(options)
}

fn required_surge_proxy_option(
    options: &BTreeMap<String, String>,
    keys: &[&str],
    message: &'static str,
) -> DomainResult<String> {
    for key in keys {
        if let Some(value) = options.get(*key) {
            return required_trimmed(
                value.clone(),
                SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
                message,
            );
        }
    }

    Err(domain_error(
        SUBSCRIPTION_SURGE_PROXY_LINE_INVALID_CODE,
        message,
    ))
}

fn parse_proxy_link_lines(source_id: &str, content: &str) -> DomainResult<SubscriptionDocument> {
    let mut nodes = Vec::new();
    let mut seen_ids = BTreeSet::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut node = if line.starts_with("ss://") {
            parse_shadowsocks_link(line)?
        } else if line.starts_with("trojan://") {
            parse_trojan_link(line)?
        } else if line.starts_with("vless://") {
            parse_vless_link(line)?
        } else if line.starts_with("vmess://") {
            parse_vmess_link(line)?
        } else if line.starts_with("hysteria2://") || line.starts_with("hy2://") {
            parse_hysteria2_link(line)?
        } else if line.starts_with("tuic://") {
            parse_tuic_link(line)?
        } else {
            return Err(domain_error(
                SUBSCRIPTION_LINK_UNSUPPORTED_CODE,
                "only ss://, trojan://, vless://, vmess://, hysteria2://, hy2://, and tuic:// proxy links are supported in this alpha subscription parser",
            ));
        };
        if !seen_ids.insert(node.id.clone()) {
            let base_id = node.id.clone();
            let mut suffix = seen_ids.len() + 1;
            loop {
                node.id = format!("{base_id}-{suffix}");
                if seen_ids.insert(node.id.clone()) {
                    break;
                }
                suffix += 1;
            }
        }
        node.metadata.push(MetadataEntry {
            key: "subscription.source_id".to_string(),
            value: source_id.to_string(),
        });
        nodes.push(node);
    }

    if nodes.is_empty() {
        return Err(domain_error(
            SUBSCRIPTION_LINK_UNSUPPORTED_CODE,
            "subscription link list did not contain supported proxy links",
        ));
    }

    Ok(SubscriptionDocument {
        nodes,
        rules: Vec::new(),
        diagnostics: Vec::new(),
    })
}

fn parse_shadowsocks_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("ss://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
            "shadowsocks link must start with ss://",
        )
    })?;
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .and_then(|fragment| percent_decode(fragment).ok())
        .filter(|name| !name.trim().is_empty());
    let (main_without_query, _) = split_once_optional(without_fragment, '?');

    let decoded_main = if main_without_query.contains('@') {
        main_without_query.to_string()
    } else {
        decode_base64_text(main_without_query).ok_or_else(|| {
            domain_error(
                SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
                "shadowsocks link payload is not valid base64",
            )
        })?
    };

    let (userinfo, host_port) = decoded_main.rsplit_once('@').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
            "shadowsocks link must contain credentials and endpoint",
        )
    })?;
    let credentials = decode_base64_text(userinfo).unwrap_or_else(|| userinfo.to_string());
    let (method, password) = credentials.split_once(':').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
            "shadowsocks credentials must contain method and password",
        )
    })?;
    let method = required_trimmed(
        method.to_string(),
        SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
        "shadowsocks method cannot be empty",
    )?;
    let password = required_trimmed(
        password.to_string(),
        SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
        "shadowsocks password cannot be empty",
    )?;
    let (host, port) = parse_host_port_for(
        host_port,
        SUBSCRIPTION_SHADOWSOCKS_LINK_INVALID_CODE,
        "shadowsocks",
    )?;
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("ss-{}-{port}", host_id);
    let name = name.unwrap_or_else(|| id.clone());

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Shadowsocks,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "ss".to_string()],
        metadata: vec![
            MetadataEntry {
                key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                value: method,
            },
            MetadataEntry {
                key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                value: password,
            },
            MetadataEntry {
                key: NODE_METADATA_SOURCE_FORMAT.to_string(),
                value: "ss-url".to_string(),
            },
        ],
    })
}

fn parse_trojan_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("trojan://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_TROJAN_LINK_INVALID_CODE,
            "trojan link must start with trojan://",
        )
    })?;
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .and_then(|fragment| percent_decode(fragment).ok())
        .filter(|name| !name.trim().is_empty());
    let (main_without_query, _) = split_once_optional(without_fragment, '?');
    let (password, host_port) = main_without_query.rsplit_once('@').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_TROJAN_LINK_INVALID_CODE,
            "trojan link must contain password and endpoint",
        )
    })?;
    let password = percent_decode(password).unwrap_or_else(|_| password.to_string());
    let password = required_trimmed(
        password,
        SUBSCRIPTION_TROJAN_LINK_INVALID_CODE,
        "trojan password cannot be empty",
    )?;
    let (host, port) =
        parse_host_port_for(host_port, SUBSCRIPTION_TROJAN_LINK_INVALID_CODE, "trojan")?;
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("trojan-{}-{port}", host_id);
    let name = name.unwrap_or_else(|| id.clone());

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Trojan,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "trojan".to_string()],
        metadata: vec![
            MetadataEntry {
                key: NODE_METADATA_TROJAN_PASSWORD.to_string(),
                value: password,
            },
            MetadataEntry {
                key: NODE_METADATA_SOURCE_FORMAT.to_string(),
                value: "trojan-url".to_string(),
            },
        ],
    })
}

fn parse_vless_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("vless://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_VLESS_LINK_INVALID_CODE,
            "vless link must start with vless://",
        )
    })?;
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .and_then(|fragment| percent_decode(fragment).ok())
        .filter(|name| !name.trim().is_empty());
    let (main_without_query, _) = split_once_optional(without_fragment, '?');
    let (uuid, host_port) = main_without_query.rsplit_once('@').ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_VLESS_LINK_INVALID_CODE,
            "vless link must contain uuid and endpoint",
        )
    })?;
    let uuid = percent_decode(uuid).unwrap_or_else(|_| uuid.to_string());
    let uuid = required_trimmed(
        uuid,
        SUBSCRIPTION_VLESS_LINK_INVALID_CODE,
        "vless uuid cannot be empty",
    )?;
    let (host, port) =
        parse_host_port_for(host_port, SUBSCRIPTION_VLESS_LINK_INVALID_CODE, "vless")?;
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("vless-{}-{port}", host_id);
    let name = name.unwrap_or_else(|| id.clone());

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Vless,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "vless".to_string()],
        metadata: vec![
            MetadataEntry {
                key: NODE_METADATA_VLESS_UUID.to_string(),
                value: uuid,
            },
            MetadataEntry {
                key: NODE_METADATA_SOURCE_FORMAT.to_string(),
                value: "vless-url".to_string(),
            },
        ],
    })
}

fn parse_vmess_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("vmess://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
            "vmess link must start with vmess://",
        )
    })?;
    let decoded = decode_base64_text(payload).ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
            "vmess link payload is not valid base64",
        )
    })?;
    let value = serde_json::from_str::<serde_json::Value>(&decoded).map_err(|_| {
        domain_error(
            SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
            "vmess link payload is not valid json",
        )
    })?;
    let uuid = required_json_text_field(
        &value,
        "id",
        SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
        "vmess uuid cannot be empty",
    )?;
    let host = required_json_text_field(
        &value,
        "add",
        SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
        "vmess host cannot be empty",
    )?;
    let port = required_json_text_field(
        &value,
        "port",
        SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
        "vmess port cannot be empty",
    )?;
    let port = port.parse::<i64>().map_err(|_| {
        domain_error(
            SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
            "vmess port must be a number",
        )
    })?;
    let port = parse_port(
        port,
        SUBSCRIPTION_VMESS_LINK_INVALID_CODE,
        "vmess port must be between 1 and 65535",
    )?;
    let host_id = sanitize_identifier(&host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("vmess-{}-{port}", host_id);
    let name = optional_json_text_field(&value, "ps").unwrap_or_else(|| id.clone());

    Ok(NodeDescriptor {
        id,
        name,
        protocol: Protocol::Vmess,
        endpoint: Endpoint { host, port },
        tags: vec!["subscription".to_string(), "vmess".to_string()],
        metadata: vec![
            MetadataEntry {
                key: NODE_METADATA_VMESS_UUID.to_string(),
                value: uuid,
            },
            MetadataEntry {
                key: NODE_METADATA_SOURCE_FORMAT.to_string(),
                value: "vmess-url".to_string(),
            },
        ],
    })
}

fn parse_hysteria2_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link
        .strip_prefix("hysteria2://")
        .or_else(|| link.strip_prefix("hy2://"))
        .ok_or_else(|| {
            domain_error(
                SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
                "hysteria2 link must start with hysteria2:// or hy2://",
            )
        })?;
    let parsed = parse_quic_share_link(
        payload,
        SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
        "hysteria2",
    )?;
    let password = required_trimmed(
        parsed.userinfo.clone(),
        SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
        "hysteria2 password cannot be empty",
    )?;
    let mut metadata = vec![MetadataEntry {
        key: NODE_METADATA_HYSTERIA2_PASSWORD.to_string(),
        value: password,
    }];
    append_query_tls_metadata(
        &mut metadata,
        &parsed.query,
        &parsed.host,
        SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
    )?;
    if let Some(server_ports) = parsed.query.get("mport") {
        let server_ports = normalize_hysteria2_server_port_ranges(
            vec![server_ports.to_string()],
            SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
        )?
        .join(",");
        metadata.push(MetadataEntry {
            key: NODE_METADATA_HYSTERIA2_SERVER_PORTS.to_string(),
            value: server_ports,
        });
    }
    if let Some(kind) = parsed.query.get("obfs") {
        let kind = normalized_token(kind);
        if !matches!(kind.as_str(), "salamander" | "gecko") {
            return Err(domain_error(
                SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
                "hysteria2 obfs must be salamander or gecko",
            ));
        }
        let password = required_query_value(
            &parsed.query,
            "obfs-password",
            SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
            "hysteria2 obfs-password cannot be empty when obfs is configured",
        )?;
        metadata.push(MetadataEntry {
            key: NODE_METADATA_HYSTERIA2_OBFS_TYPE.to_string(),
            value: kind.clone(),
        });
        metadata.push(MetadataEntry {
            key: NODE_METADATA_HYSTERIA2_OBFS_PASSWORD.to_string(),
            value: password,
        });
        if kind == "gecko" {
            if let Some(value) = parsed.query.get("minpacketsize") {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_HYSTERIA2_OBFS_MIN_PACKET_SIZE.to_string(),
                    value: normalize_hysteria2_packet_size(
                        value.to_string(),
                        SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
                    )?,
                });
            }
            if let Some(value) = parsed.query.get("maxpacketsize") {
                metadata.push(MetadataEntry {
                    key: NODE_METADATA_HYSTERIA2_OBFS_MAX_PACKET_SIZE.to_string(),
                    value: normalize_hysteria2_packet_size(
                        value.to_string(),
                        SUBSCRIPTION_HYSTERIA2_LINK_INVALID_CODE,
                    )?,
                });
            }
        }
    }

    Ok(quic_node_descriptor(
        "hysteria2",
        Protocol::Hysteria2,
        parsed,
        metadata,
    ))
}

fn parse_tuic_link(link: &str) -> DomainResult<NodeDescriptor> {
    let payload = link.strip_prefix("tuic://").ok_or_else(|| {
        domain_error(
            SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
            "tuic link must start with tuic://",
        )
    })?;
    let parsed = parse_quic_share_link(payload, SUBSCRIPTION_TUIC_LINK_INVALID_CODE, "tuic")?;
    let (uuid, password) = parsed
        .userinfo
        .split_once(':')
        .map(|(uuid, password)| (uuid.to_string(), Some(password.to_string())))
        .unwrap_or_else(|| (parsed.userinfo.clone(), None));
    let uuid = required_trimmed(
        uuid,
        SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
        "tuic uuid cannot be empty",
    )?;
    let mut metadata = vec![MetadataEntry {
        key: NODE_METADATA_TUIC_UUID.to_string(),
        value: uuid,
    }];
    if let Some(password) = password {
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TUIC_PASSWORD.to_string(),
            value: password,
        });
    }
    if let Some(congestion_control) = parsed.query.get("congestion_control") {
        let congestion_control = required_trimmed(
            congestion_control.to_string(),
            SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
            "tuic congestion_control cannot be empty",
        )?;
        if !matches!(congestion_control.as_str(), "cubic" | "new_reno" | "bbr") {
            return Err(domain_error(
                SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
                "tuic congestion_control must be cubic, new_reno, or bbr",
            ));
        }
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TUIC_CONGESTION_CONTROL.to_string(),
            value: congestion_control,
        });
    }
    append_query_tls_metadata(
        &mut metadata,
        &parsed.query,
        &parsed.host,
        SUBSCRIPTION_TUIC_LINK_INVALID_CODE,
    )?;

    Ok(quic_node_descriptor(
        "tuic",
        Protocol::Tuic,
        parsed,
        metadata,
    ))
}

#[derive(Debug)]
struct ParsedQuicShareLink {
    userinfo: String,
    host: String,
    port: u16,
    name: Option<String>,
    query: BTreeMap<String, String>,
}

fn parse_quic_share_link(
    payload: &str,
    code: &'static str,
    protocol_name: &'static str,
) -> DomainResult<ParsedQuicShareLink> {
    let (without_fragment, fragment) = split_once_optional(payload, '#');
    let name = fragment
        .map(percent_decode)
        .transpose()
        .map_err(|_| {
            domain_error(
                code,
                format!("{protocol_name} link name is not valid percent encoding"),
            )
        })?
        .filter(|name| !name.trim().is_empty());
    let (authority, query) = split_once_optional(without_fragment, '?');
    let (userinfo, host_port) = authority.rsplit_once('@').ok_or_else(|| {
        domain_error(
            code,
            format!("{protocol_name} link must contain credentials and endpoint"),
        )
    })?;
    let userinfo = percent_decode(userinfo).map_err(|_| {
        domain_error(
            code,
            format!("{protocol_name} link credentials are not valid percent encoding"),
        )
    })?;
    let (host, port) = parse_host_port_for(host_port, code, protocol_name)?;
    let query = parse_share_link_query(query, code, protocol_name)?;
    Ok(ParsedQuicShareLink {
        userinfo,
        host,
        port,
        name,
        query,
    })
}

fn parse_share_link_query(
    query: Option<&str>,
    code: &'static str,
    protocol_name: &'static str,
) -> DomainResult<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    let Some(query) = query else {
        return Ok(values);
    };
    for entry in query.split('&') {
        if entry.is_empty() {
            continue;
        }
        let (key, value) = entry.split_once('=').ok_or_else(|| {
            domain_error(
                code,
                format!("{protocol_name} query fields must use key=value"),
            )
        })?;
        let key = percent_decode(key).map_err(|_| {
            domain_error(
                code,
                format!("{protocol_name} query key is not valid percent encoding"),
            )
        })?;
        let value = percent_decode(value).map_err(|_| {
            domain_error(
                code,
                format!("{protocol_name} query value is not valid percent encoding"),
            )
        })?;
        let key = key.trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(domain_error(
                code,
                format!("{protocol_name} query key cannot be empty"),
            ));
        }
        values.insert(key, value);
    }
    Ok(values)
}

fn quic_node_descriptor(
    protocol_tag: &'static str,
    protocol: Protocol,
    parsed: ParsedQuicShareLink,
    mut metadata: Metadata,
) -> NodeDescriptor {
    let host_id = sanitize_identifier(&parsed.host);
    let host_id = if host_id.is_empty() {
        "host".to_string()
    } else {
        host_id
    };
    let id = format!("{protocol_tag}-{host_id}-{}", parsed.port);
    let name = parsed.name.unwrap_or_else(|| id.clone());
    metadata.push(MetadataEntry {
        key: NODE_METADATA_SOURCE_FORMAT.to_string(),
        value: format!("{protocol_tag}-url"),
    });
    NodeDescriptor {
        id,
        name,
        protocol,
        endpoint: Endpoint {
            host: parsed.host,
            port: parsed.port,
        },
        tags: vec!["subscription".to_string(), protocol_tag.to_string()],
        metadata,
    }
}

fn append_query_tls_metadata(
    metadata: &mut Metadata,
    query: &BTreeMap<String, String>,
    host: &str,
    code: &'static str,
) -> DomainResult<()> {
    let server_name = query
        .get("sni")
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| host.to_string());
    metadata.push(MetadataEntry {
        key: NODE_METADATA_TLS_SERVER_NAME.to_string(),
        value: server_name,
    });
    let insecure = query
        .get("insecure")
        .or_else(|| query.get("allowinsecure"))
        .or_else(|| query.get("allow_insecure"))
        .map(|value| parse_share_link_boolean(value, code, "TLS insecure"))
        .transpose()?
        .unwrap_or(false);
    metadata.push(MetadataEntry {
        key: NODE_METADATA_TLS_INSECURE.to_string(),
        value: insecure.to_string(),
    });
    if let Some(alpn) = query.get("alpn") {
        let alpn = split_share_link_list(alpn, code, "TLS alpn")?;
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_ALPN.to_string(),
            value: alpn.join(","),
        });
    }
    if let Some(pins) = query.get("pinsha256").or_else(|| query.get("pcs")) {
        let pins = split_share_link_list(pins, code, "TLS certificate public-key sha256")?;
        metadata.push(MetadataEntry {
            key: NODE_METADATA_TLS_CERTIFICATE_PUBLIC_KEY_SHA256.to_string(),
            value: pins.join(","),
        });
    }
    Ok(())
}

fn parse_share_link_boolean(
    value: &str,
    code: &'static str,
    field_name: &'static str,
) -> DomainResult<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" => Ok(true),
        "0" | "false" | "" => Ok(false),
        _ => Err(domain_error(
            code,
            format!("{field_name} must be 0, 1, false, or true"),
        )),
    }
}

fn split_share_link_list(
    value: &str,
    code: &'static str,
    field_name: &'static str,
) -> DomainResult<Vec<String>> {
    let values = value
        .split(',')
        .map(|value| {
            required_trimmed(
                value.to_string(),
                code,
                format!("{field_name} cannot be empty"),
            )
        })
        .collect::<DomainResult<Vec<_>>>()?;
    if values.is_empty() {
        return Err(domain_error(code, format!("{field_name} cannot be empty")));
    }
    Ok(values)
}

fn required_query_value(
    query: &BTreeMap<String, String>,
    key: &'static str,
    code: &'static str,
    message: &'static str,
) -> DomainResult<String> {
    query
        .get(key)
        .cloned()
        .ok_or_else(|| domain_error(code, message))
        .and_then(|value| required_trimmed(value, code, message))
}

fn normalize_hysteria2_server_port_range(
    value: String,
    code: &'static str,
) -> DomainResult<String> {
    let value = required_trimmed(value, code, "hysteria2 server port range cannot be empty")?;
    let Some((start, end)) = value.split_once(':').or_else(|| value.split_once('-')) else {
        let port = parse_hysteria2_port(&value, code)?;
        return Ok(port.to_string());
    };
    let start = parse_hysteria2_port(start, code)?;
    let end = parse_hysteria2_port(end, code)?;
    if start > end {
        return Err(domain_error(
            code,
            "hysteria2 server port range start cannot exceed end",
        ));
    }
    Ok(format!("{start}:{end}"))
}

fn normalize_hysteria2_server_port_ranges(
    values: Vec<String>,
    code: &'static str,
) -> DomainResult<Vec<String>> {
    let mut normalized = Vec::new();
    for value in values {
        for range in value.split(',') {
            normalized.push(normalize_hysteria2_server_port_range(
                range.to_string(),
                code,
            )?);
        }
    }
    if normalized.is_empty() {
        return Err(domain_error(
            code,
            "hysteria2 server port ranges cannot be empty",
        ));
    }
    Ok(normalized)
}

fn hysteria2_server_port_range_start(value: &str, code: &'static str) -> DomainResult<u16> {
    let start = value
        .split_once(':')
        .map(|(start, _)| start)
        .unwrap_or(value);
    parse_hysteria2_port(start, code)
}

fn parse_hysteria2_port(value: &str, code: &'static str) -> DomainResult<u16> {
    let value = value.trim();
    let port = value
        .parse::<i64>()
        .map_err(|_| domain_error(code, "hysteria2 server port must be a number"))?;
    parse_port(
        port,
        code,
        "hysteria2 server port must be between 1 and 65535",
    )
}

fn normalize_hysteria2_packet_size(value: String, code: &'static str) -> DomainResult<String> {
    let value = required_trimmed(value, code, "hysteria2 obfs packet size cannot be empty")?;
    let value = value.parse::<u32>().map_err(|_| {
        domain_error(
            code,
            "hysteria2 obfs packet size must be a positive integer",
        )
    })?;
    if value == 0 {
        return Err(domain_error(
            code,
            "hysteria2 obfs packet size must be a positive integer",
        ));
    }
    Ok(value.to_string())
}

fn parse_host_port_for(
    value: &str,
    error_code: &'static str,
    protocol_name: &'static str,
) -> DomainResult<(String, u16)> {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest.split_once(']').ok_or_else(|| {
            domain_error(
                error_code,
                format!("IPv6 {protocol_name} endpoint must close with ]"),
            )
        })?;
        let port = rest.strip_prefix(':').ok_or_else(|| {
            domain_error(
                error_code,
                format!("{protocol_name} endpoint must contain a port"),
            )
        })?;
        (host.to_string(), port)
    } else {
        let (host, port) = value.rsplit_once(':').ok_or_else(|| {
            domain_error(
                error_code,
                format!("{protocol_name} endpoint must contain host and port"),
            )
        })?;
        (host.to_string(), port)
    };
    let host = required_trimmed(
        host,
        error_code,
        format!("{protocol_name} host cannot be empty"),
    )?;
    let port = port
        .parse::<i64>()
        .map_err(|_| domain_error(error_code, format!("{protocol_name} port must be a number")))?;
    let port = parse_port(
        port,
        error_code,
        format!("{protocol_name} port must be between 1 and 65535"),
    )?;

    Ok((host, port))
}

fn decode_base64_text(value: &str) -> Option<String> {
    let compact = value.split_whitespace().collect::<String>();
    let bytes = STANDARD
        .decode(compact.as_bytes())
        .or_else(|_| STANDARD_NO_PAD.decode(compact.as_bytes()))
        .or_else(|_| URL_SAFE.decode(compact.as_bytes()))
        .or_else(|_| URL_SAFE_NO_PAD.decode(compact.as_bytes()))
        .ok()?;

    String::from_utf8(bytes).ok()
}

fn percent_decode(value: &str) -> Result<String, ()> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;

    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hi = bytes.get(index + 1).and_then(|byte| hex_value(*byte));
            let lo = bytes.get(index + 2).and_then(|byte| hex_value(*byte));
            match (hi, lo) {
                (Some(hi), Some(lo)) => {
                    output.push((hi << 4) | lo);
                    index += 3;
                    continue;
                }
                _ => return Err(()),
            }
        }

        output.push(bytes[index]);
        index += 1;
    }

    String::from_utf8(output).map_err(|_| ())
}

fn required_json_text_field(
    value: &serde_json::Value,
    field: &'static str,
    code: &'static str,
    message: &'static str,
) -> DomainResult<String> {
    let Some(raw) = value.get(field) else {
        return Err(domain_error(code, message));
    };
    let text = match raw {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(value) => value.to_string(),
        _ => return Err(domain_error(code, message)),
    };

    required_trimmed(text, code, message)
}

fn optional_json_text_field(value: &serde_json::Value, field: &'static str) -> Option<String> {
    let text = match value.get(field)? {
        serde_json::Value::String(value) => value.clone(),
        serde_json::Value::Number(value) => value.to_string(),
        _ => return None,
    };
    let text = text.trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn split_once_optional(value: &str, separator: char) -> (&str, Option<&str>) {
    value
        .split_once(separator)
        .map(|(left, right)| (left, Some(right)))
        .unwrap_or((value, None))
}

fn sanitize_identifier(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    sanitized.trim_matches('-').to_string()
}

fn parse_protocol(raw: String) -> DomainResult<Protocol> {
    let protocol = required_trimmed(
        raw,
        CONFIG_NODE_PROTOCOL_EMPTY_CODE,
        "node protocol cannot be empty",
    )?;

    Ok(match normalized_token(&protocol).as_str() {
        "http" => Protocol::Http,
        "socks" => Protocol::Socks,
        "shadowsocks" => Protocol::Shadowsocks,
        "vmess" => Protocol::Vmess,
        "vless" => Protocol::Vless,
        "trojan" => Protocol::Trojan,
        "hysteria" => Protocol::Hysteria,
        "hysteria2" | "hy2" => Protocol::Hysteria2,
        "tuic" => Protocol::Tuic,
        _ => Protocol::Other(protocol),
    })
}

fn collect_routes(raw_routes: Vec<RawRoute>) -> DomainResult<Vec<RuleSet>> {
    raw_routes
        .into_iter()
        .map(normalize_route)
        .collect::<DomainResult<Vec<_>>>()
}

fn normalize_route(raw: RawRoute) -> DomainResult<RuleSet> {
    Ok(RuleSet {
        id: required_trimmed(
            raw.id,
            CONFIG_ROUTE_ID_EMPTY_CODE,
            "route id cannot be empty",
        )?,
        rules: Vec::new(),
        default_action: parse_route_action(raw.default_action, raw.default_node)?,
    })
}

fn parse_route_action(raw_action: String, node_id: Option<String>) -> DomainResult<RouteAction> {
    match normalized_token(&raw_action).as_str() {
        "direct" => Ok(RouteAction::Direct),
        "reject" => Ok(RouteAction::Reject),
        "proxy" => Ok(RouteAction::Proxy {
            node_id: required_trimmed(
                node_id.unwrap_or_default(),
                CONFIG_ROUTE_PROXY_NODE_MISSING_CODE,
                "proxy route action requires a node id",
            )?,
        }),
        _ => Err(domain_error(
            CONFIG_ROUTE_ACTION_UNSUPPORTED_CODE,
            "route action must be direct, proxy, or reject",
        )),
    }
}

fn collect_tags(tags: Option<Vec<String>>) -> Vec<String> {
    tags.unwrap_or_default()
        .into_iter()
        .map(|tag| tag.trim().to_string())
        .filter(|tag| !tag.is_empty())
        .collect()
}

fn collect_metadata(metadata: Option<BTreeMap<String, String>>) -> Metadata {
    metadata
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| MetadataEntry {
            key: key.trim().to_string(),
            value,
        })
        .filter(|entry| !entry.key.is_empty())
        .collect()
}

fn parse_port(value: i64, code: &'static str, message: impl Into<String>) -> DomainResult<u16> {
    if !(1..=(u16::MAX as i64)).contains(&value) {
        return Err(domain_error(code, message));
    }

    Ok(value as u16)
}

fn required_trimmed(
    value: String,
    code: &'static str,
    message: impl Into<String>,
) -> DomainResult<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        Err(domain_error(code, message))
    } else {
        Ok(value)
    }
}

fn normalized_token(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn domain_error(code: impl Into<String>, message: impl Into<String>) -> DomainError {
    DomainError::new(code, message)
}

fn domain_error_to_diagnostic(error: DomainError) -> Diagnostic {
    Diagnostic::new(
        DiagnosticSeverity::Error,
        error.code,
        error.message,
        Some(SOURCE_CONFIG_CORE.to_string()),
    )
}
