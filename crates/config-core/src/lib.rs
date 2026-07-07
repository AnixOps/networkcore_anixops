//! Pure configuration service for NetworkCore.
//!
//! This crate parses and normalizes the first minimal TOML configuration shape.
//! It performs no file I/O, network access, platform probing, or engine work.

use control_domain::{
    ConfigSnapshot, ConfigurationService, Diagnostic, DiagnosticSeverity, DomainError,
    DomainResult, Endpoint, ListenerBind, ListenerDescriptor, ListenerKind, ListenerNetwork,
    ListenerRoute, Metadata, MetadataEntry, NodeCatalog, NodeDescriptor, PlatformCapabilities,
    Protocol, RawSubscription, RouteAction, RuleSet, SchemaVersion, SubscriptionDocument,
    SubscriptionService, SubscriptionSource,
};
use serde::Deserialize;
use std::collections::BTreeMap;

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
        let _source_id = required_trimmed(
            raw_subscription.source_id.clone(),
            SUBSCRIPTION_SOURCE_ID_EMPTY_CODE,
            "subscription source id cannot be empty",
        )?;
        let raw =
            toml::from_str::<RawSubscriptionDocument>(&raw_subscription.content).map_err(|_| {
                domain_error(
                    SUBSCRIPTION_PARSE_FAILED_CODE,
                    "subscription payload could not be parsed as NetworkCore TOML",
                )
            })?;

        Ok(SubscriptionDocument {
            nodes: collect_nodes(raw.nodes.unwrap_or_default())?,
            rules: collect_routes(raw.routes.unwrap_or_default())?,
            diagnostics: Vec::new(),
        })
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
    })
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

fn parse_port(value: i64, code: &'static str, message: &'static str) -> DomainResult<u16> {
    if !(1..=(u16::MAX as i64)).contains(&value) {
        return Err(domain_error(code, message));
    }

    Ok(value as u16)
}

fn required_trimmed(
    value: String,
    code: &'static str,
    message: &'static str,
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
