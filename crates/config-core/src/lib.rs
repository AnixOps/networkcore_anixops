//! Pure configuration service for NetworkCore.
//!
//! This crate parses and normalizes the first minimal TOML configuration shape.
//! It performs no file I/O, network access, platform probing, or engine work.

use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use control_domain::{
    ConfigSnapshot, ConfigurationService, Diagnostic, DiagnosticSeverity, DomainError,
    DomainResult, Endpoint, ListenerBind, ListenerDescriptor, ListenerKind, ListenerNetwork,
    ListenerRoute, Metadata, MetadataEntry, NodeCatalog, NodeDescriptor, PlatformCapabilities,
    Protocol, RawSubscription, RouteAction, RuleSet, SchemaVersion, SubscriptionDocument,
    SubscriptionService, SubscriptionSource, NODE_METADATA_SHADOWSOCKS_METHOD,
    NODE_METADATA_SHADOWSOCKS_PASSWORD, NODE_METADATA_SOURCE_FORMAT, NODE_METADATA_TROJAN_PASSWORD,
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
pub const SUBSCRIPTION_CLASH_YAML_INVALID_CODE: &str = "subscription.core.clash_yaml_invalid";
pub const SUBSCRIPTION_CLASH_YAML_UNSUPPORTED_CODE: &str =
    "subscription.core.clash_yaml_unsupported";

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
            parse_clash_yaml_subscription(&source_id, &raw_subscription.content)?
        {
            return Ok(document);
        }

        if let Some(document) = parse_link_subscription(&source_id, &raw_subscription.content)? {
            return Ok(document);
        }

        Err(domain_error(
            SUBSCRIPTION_PARSE_FAILED_CODE,
            "subscription payload could not be parsed as NetworkCore TOML, Clash YAML, or supported proxy links",
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
        } else {
            return Err(domain_error(
                SUBSCRIPTION_LINK_UNSUPPORTED_CODE,
                "only ss://, trojan://, vless://, and vmess:// proxy links are supported in this alpha subscription parser",
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
