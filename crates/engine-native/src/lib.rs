//! Native proxy engine adapter contracts for NetworkCore.
//!
//! This crate intentionally exposes only descriptor, validation, and lifecycle
//! diagnostics until a real in-process runtime handle exists.

use control_domain::{
    Diagnostic, DiagnosticSeverity, DomainError, DomainResult, ListenerDescriptor, ListenerKind,
    ListenerRoute, NodeDescriptor, Protocol, ProxyEngineConfig, ProxyEngineDescriptor,
    ProxyEngineEvent, ProxyEngineKind, ProxyEngineLifecycleState, ProxyEngineService,
    ProxyEngineStatus, RouteAction, RuleSet,
};
use std::collections::BTreeSet;

pub const DEFAULT_NATIVE_ENGINE_ID: &str = "native";

pub const SOURCE_ENGINE_NATIVE_CONFIG: &str = "engine.native.config";
pub const SOURCE_ENGINE_NATIVE_LIFECYCLE: &str = "engine.native.lifecycle";

pub const ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE: &str =
    "engine.native.config.engine_id_unsupported";
pub const ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE: &str =
    "engine.native.config.listener_missing";
pub const ENGINE_NATIVE_CONFIG_LISTENER_ID_DUPLICATE_CODE: &str =
    "engine.native.config.listener_id_duplicate";
pub const ENGINE_NATIVE_CONFIG_LISTENER_BIND_INVALID_CODE: &str =
    "engine.native.config.listener_bind_invalid";
pub const ENGINE_NATIVE_CONFIG_LISTENER_KIND_UNSUPPORTED_CODE: &str =
    "engine.native.config.listener_kind_unsupported";
pub const ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE: &str = "engine.native.config.node_missing";
pub const ENGINE_NATIVE_CONFIG_NODE_ID_DUPLICATE_CODE: &str =
    "engine.native.config.node_id_duplicate";
pub const ENGINE_NATIVE_CONFIG_NODE_PROTOCOL_UNSUPPORTED_CODE: &str =
    "engine.native.config.node_protocol_unsupported";
pub const ENGINE_NATIVE_CONFIG_ROUTE_ID_DUPLICATE_CODE: &str =
    "engine.native.config.route_id_duplicate";
pub const ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE: &str =
    "engine.native.config.route_target_missing";
pub const ENGINE_NATIVE_CONFIG_ROUTE_EMPTY_CODE: &str = "engine.native.config.route_empty";
pub const ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE: &str =
    "engine.native.start.runtime_unavailable";

#[derive(Debug, Clone, Copy, Default)]
pub struct NativeProxyEngineService;

impl NativeProxyEngineService {
    pub const fn new() -> Self {
        Self
    }
}

impl ProxyEngineService for NativeProxyEngineService {
    fn list_engines(&self) -> Vec<ProxyEngineDescriptor> {
        vec![ProxyEngineDescriptor {
            id: DEFAULT_NATIVE_ENGINE_ID.to_string(),
            kind: ProxyEngineKind::Native,
            version: None,
            capabilities: Vec::new(),
        }]
    }

    fn validate_config(&self, engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        if engine_config.engine_id != DEFAULT_NATIVE_ENGINE_ID {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE,
                "native proxy engine only supports the native engine id",
                SOURCE_ENGINE_NATIVE_CONFIG,
            ));
        }

        validate_listeners(engine_config, &mut diagnostics);
        validate_nodes(engine_config, &mut diagnostics);
        validate_routes(engine_config, &mut diagnostics);

        diagnostics
    }

    fn start(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(&engine_config.engine_id)?;

        Err(domain_error(
            ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE,
            "native proxy runtime handle is not implemented yet",
        ))
    }

    fn reload(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(&engine_config.engine_id)?;

        Err(domain_error(
            ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE,
            "native proxy runtime handle is not implemented yet",
        ))
    }

    fn stop(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(engine_id)?;

        Ok(stopped_status(engine_id))
    }

    fn status(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(engine_id)?;

        Ok(stopped_status(engine_id))
    }

    fn events(&self, engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
        ensure_native_engine_id(engine_id)?;

        Ok(Vec::new())
    }
}

fn stopped_status(engine_id: &str) -> ProxyEngineStatus {
    ProxyEngineStatus {
        engine_id: engine_id.to_string(),
        state: ProxyEngineLifecycleState::Stopped,
        diagnostics: Vec::new(),
    }
}

fn validate_listeners(engine_config: &ProxyEngineConfig, diagnostics: &mut Vec<Diagnostic>) {
    let listeners = &engine_config.config.listeners;
    let enabled_listeners = enabled_listeners(listeners);

    if enabled_listeners.is_empty() {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE,
            "native proxy engine requires at least one enabled listener",
        ));
    }

    if has_duplicate_ids(listeners.iter().map(|listener| listener.id.as_str())) {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_LISTENER_ID_DUPLICATE_CODE,
            "native proxy listener ids must be unique",
        ));
    }

    if enabled_listeners.iter().any(|listener| {
        listener.bind.host.trim().is_empty() || listener.bind.port == 0
    }) {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_LISTENER_BIND_INVALID_CODE,
            "native proxy listener bind host and port must be explicit",
        ));
    }

    if enabled_listeners
        .iter()
        .any(|listener| !listener_kind_supported(&listener.kind))
    {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_LISTENER_KIND_UNSUPPORTED_CODE,
            "native proxy listener handlers are not implemented yet",
        ));
    }
}

fn validate_nodes(engine_config: &ProxyEngineConfig, diagnostics: &mut Vec<Diagnostic>) {
    let nodes = effective_nodes(engine_config);

    if nodes.is_empty() {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE,
            "native proxy engine requires at least one typed outbound node",
        ));
    }

    if has_duplicate_ids(nodes.iter().map(|node| node.id.as_str())) {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_NODE_ID_DUPLICATE_CODE,
            "native proxy node ids must be unique across config and runtime request nodes",
        ));
    }

    if nodes
        .iter()
        .any(|node| !node_protocol_supported(&node.protocol))
    {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_NODE_PROTOCOL_UNSUPPORTED_CODE,
            "native proxy outbound protocols are not implemented yet",
        ));
    }
}

fn validate_routes(engine_config: &ProxyEngineConfig, diagnostics: &mut Vec<Diagnostic>) {
    let route_sets = &engine_config.config.policies;
    let enabled_listeners = enabled_listeners(&engine_config.config.listeners);
    let node_ids = effective_node_ids(engine_config);
    let mut target_missing = false;
    let mut has_executable_proxy_route = false;

    if has_duplicate_ids(route_sets.iter().map(|route_set| route_set.id.as_str())) {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_ROUTE_ID_DUPLICATE_CODE,
            "native proxy route ids must be unique",
        ));
    }

    for listener in &enabled_listeners {
        match &listener.route {
            ListenerRoute::RuleSet { rule_set_id } => {
                let Some(route_set) = route_sets
                    .iter()
                    .find(|route_set| route_set.id == *rule_set_id)
                else {
                    target_missing = true;
                    continue;
                };
                let route_result = validate_route_set(route_set, &node_ids);
                target_missing |= route_result.target_missing;
                has_executable_proxy_route |= route_result.has_executable_proxy_route;
            }
            ListenerRoute::DefaultAction(action) => {
                let action_result = validate_route_action(action, &node_ids);
                target_missing |= action_result.target_missing;
                has_executable_proxy_route |= action_result.has_executable_proxy_route;
            }
        }
    }

    for route_set in route_sets {
        for rule in &route_set.rules {
            target_missing |= validate_route_action(&rule.action, &node_ids).target_missing;
        }
        target_missing |=
            validate_route_action(&route_set.default_action, &node_ids).target_missing;
    }

    if target_missing {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE,
            "native proxy routes must reference existing rule sets and nodes",
        ));
    }

    if !enabled_listeners.is_empty() && !has_executable_proxy_route {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_ROUTE_EMPTY_CODE,
            "native proxy listeners must have at least one proxy route to a typed node",
        ));
    }
}

fn ensure_native_engine_id(engine_id: &str) -> DomainResult<()> {
    if engine_id == DEFAULT_NATIVE_ENGINE_ID {
        return Ok(());
    }

    Err(domain_error(
        ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE,
        "native proxy engine only supports the native engine id",
    ))
}

#[derive(Debug, Clone, Copy, Default)]
struct RouteValidation {
    target_missing: bool,
    has_executable_proxy_route: bool,
}

fn validate_route_set(route_set: &RuleSet, node_ids: &BTreeSet<String>) -> RouteValidation {
    let mut validation = RouteValidation::default();

    for rule in &route_set.rules {
        validation = validation.combine(validate_route_action(&rule.action, node_ids));
    }

    validation.combine(validate_route_action(&route_set.default_action, node_ids))
}

fn validate_route_action(action: &RouteAction, node_ids: &BTreeSet<String>) -> RouteValidation {
    match action {
        RouteAction::Proxy { node_id } if node_ids.contains(node_id) => RouteValidation {
            target_missing: false,
            has_executable_proxy_route: true,
        },
        RouteAction::Proxy { .. } => RouteValidation {
            target_missing: true,
            has_executable_proxy_route: false,
        },
        RouteAction::Direct | RouteAction::Reject => RouteValidation::default(),
    }
}

impl RouteValidation {
    fn combine(self, other: Self) -> Self {
        Self {
            target_missing: self.target_missing || other.target_missing,
            has_executable_proxy_route: self.has_executable_proxy_route
                || other.has_executable_proxy_route,
        }
    }
}

fn enabled_listeners(listeners: &[ListenerDescriptor]) -> Vec<&ListenerDescriptor> {
    listeners
        .iter()
        .filter(|listener| listener.enabled)
        .collect()
}

fn effective_nodes(engine_config: &ProxyEngineConfig) -> Vec<&NodeDescriptor> {
    engine_config
        .config
        .nodes
        .iter()
        .chain(engine_config.nodes.iter())
        .collect()
}

fn effective_node_ids(engine_config: &ProxyEngineConfig) -> BTreeSet<String> {
    effective_nodes(engine_config)
        .into_iter()
        .map(|node| node.id.clone())
        .collect()
}

fn has_duplicate_ids<'a>(mut ids: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    ids.any(|id| !seen.insert(id))
}

fn listener_kind_supported(_kind: &ListenerKind) -> bool {
    false
}

fn node_protocol_supported(_protocol: &Protocol) -> bool {
    false
}

fn domain_error(code: impl Into<String>, message: impl Into<String>) -> DomainError {
    DomainError::new(code, message)
}

fn config_error(code: impl Into<String>, message: impl Into<String>) -> Diagnostic {
    engine_diagnostic(
        DiagnosticSeverity::Error,
        code,
        message,
        SOURCE_ENGINE_NATIVE_CONFIG,
    )
}

fn engine_diagnostic(
    severity: DiagnosticSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
    source: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(severity, code, message, Some(source.into()))
}
