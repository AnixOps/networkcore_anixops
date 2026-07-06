use control_domain::{
    ConfigSnapshot, Diagnostic, Endpoint, ListenerBind, ListenerDescriptor, ListenerKind,
    ListenerNetwork, ListenerRoute, MetadataEntry, NodeDescriptor, Protocol, ProxyEngineConfig,
    ProxyEngineKind, ProxyEngineLifecycleState, ProxyEngineService, RouteAction, RuleSet,
    SchemaVersion,
};
use engine_native::{
    NativeProxyEngineService, DEFAULT_NATIVE_ENGINE_ID,
    ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE,
    ENGINE_NATIVE_CONFIG_LISTENER_BIND_INVALID_CODE,
    ENGINE_NATIVE_CONFIG_LISTENER_ID_DUPLICATE_CODE,
    ENGINE_NATIVE_CONFIG_LISTENER_KIND_UNSUPPORTED_CODE, ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE,
    ENGINE_NATIVE_CONFIG_NODE_ID_DUPLICATE_CODE, ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE,
    ENGINE_NATIVE_CONFIG_NODE_PROTOCOL_UNSUPPORTED_CODE, ENGINE_NATIVE_CONFIG_ROUTE_EMPTY_CODE,
    ENGINE_NATIVE_CONFIG_ROUTE_ID_DUPLICATE_CODE, ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE,
    ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE,
};

#[test]
fn lists_native_descriptor_without_unimplemented_capabilities() {
    let service = NativeProxyEngineService::new();

    let descriptors = service.list_engines();

    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0].id, DEFAULT_NATIVE_ENGINE_ID);
    assert_eq!(descriptors[0].kind, ProxyEngineKind::Native);
    assert!(descriptors[0].version.is_none());
    assert!(descriptors[0].capabilities.is_empty());
}

#[test]
fn validate_config_rejects_unsupported_engine_id_with_stable_diagnostic() {
    let service = NativeProxyEngineService::new();
    let engine_config = config("external", Vec::new());

    let diagnostics = service.validate_config(&engine_config);

    assert_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE,
    );
    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE);
    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE);
}

#[test]
fn validate_config_does_not_leak_metadata_secret_values() {
    let service = NativeProxyEngineService::new();
    let mut engine_config = config(DEFAULT_NATIVE_ENGINE_ID, Vec::new());
    engine_config.metadata.push(MetadataEntry {
        key: "token".to_string(),
        value: "super-secret-token".to_string(),
    });

    let diagnostics = service.validate_config(&engine_config);

    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE);
    assert!(diagnostics.iter().all(|diagnostic| {
        !diagnostic.message.contains("super-secret-token") && !diagnostic.message.contains("token")
    }));
}

#[test]
fn validate_config_uses_config_snapshot_nodes_for_route_targets() {
    let service = NativeProxyEngineService::new();
    let engine_config = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        vec![node()],
        Vec::new(),
        vec![listener(
            "loopback-socks",
            ListenerRoute::RuleSet {
                rule_set_id: "default-route".to_string(),
            },
        )],
        vec![route_set(
            "default-route",
            RouteAction::Proxy {
                node_id: "node-1".to_string(),
            },
        )],
    );

    let diagnostics = service.validate_config(&engine_config);

    assert_no_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE);
    assert_no_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE);
    assert_no_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE);
    assert_no_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_ROUTE_EMPTY_CODE);
    assert_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_LISTENER_KIND_UNSUPPORTED_CODE,
    );
    assert_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_NODE_PROTOCOL_UNSUPPORTED_CODE,
    );
}

#[test]
fn validate_config_uses_runtime_request_nodes_for_route_targets() {
    let service = NativeProxyEngineService::new();
    let engine_config = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        Vec::new(),
        vec![node()],
        vec![listener(
            "loopback-socks",
            ListenerRoute::DefaultAction(RouteAction::Proxy {
                node_id: "node-1".to_string(),
            }),
        )],
        Vec::new(),
    );

    let diagnostics = service.validate_config(&engine_config);

    assert_no_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE);
    assert_no_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE);
    assert_no_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_ROUTE_EMPTY_CODE);
    assert_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_NODE_PROTOCOL_UNSUPPORTED_CODE,
    );
}

#[test]
fn validate_config_reports_duplicate_graph_ids() {
    let service = NativeProxyEngineService::new();
    let engine_config = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        vec![node()],
        vec![node()],
        vec![
            listener(
                "loopback-socks",
                ListenerRoute::RuleSet {
                    rule_set_id: "default-route".to_string(),
                },
            ),
            listener(
                "loopback-socks",
                ListenerRoute::RuleSet {
                    rule_set_id: "fallback-route".to_string(),
                },
            ),
        ],
        vec![
            route_set("default-route", RouteAction::Direct),
            route_set("default-route", RouteAction::Reject),
        ],
    );

    let diagnostics = service.validate_config(&engine_config);

    assert_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_LISTENER_ID_DUPLICATE_CODE,
    );
    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_NODE_ID_DUPLICATE_CODE);
    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_ROUTE_ID_DUPLICATE_CODE);
}

#[test]
fn validate_config_reports_missing_route_and_node_targets() {
    let service = NativeProxyEngineService::new();
    let engine_config = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        Vec::new(),
        Vec::new(),
        vec![
            listener(
                "missing-route",
                ListenerRoute::RuleSet {
                    rule_set_id: "absent-route".to_string(),
                },
            ),
            listener(
                "missing-node",
                ListenerRoute::DefaultAction(RouteAction::Proxy {
                    node_id: "absent-node".to_string(),
                }),
            ),
        ],
        Vec::new(),
    );

    let diagnostics = service.validate_config(&engine_config);

    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE);
    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE);
    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_ROUTE_EMPTY_CODE);
}

#[test]
fn validate_config_reports_disabled_and_invalid_listener_boundaries() {
    let service = NativeProxyEngineService::new();
    let disabled_only = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        vec![node()],
        Vec::new(),
        vec![disabled_listener("disabled-loopback")],
        Vec::new(),
    );

    let disabled_diagnostics = service.validate_config(&disabled_only);

    assert_diagnostic(
        &disabled_diagnostics,
        ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE,
    );

    let invalid_bind = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        vec![node()],
        Vec::new(),
        vec![listener_with_bind(
            "bad-bind",
            "",
            0,
            ListenerRoute::DefaultAction(RouteAction::Direct),
        )],
        Vec::new(),
    );

    let invalid_bind_diagnostics = service.validate_config(&invalid_bind);

    assert_diagnostic(
        &invalid_bind_diagnostics,
        ENGINE_NATIVE_CONFIG_LISTENER_BIND_INVALID_CODE,
    );
}

#[test]
fn start_rejects_until_real_runtime_handle_exists() {
    let service = NativeProxyEngineService::new();
    let engine_config = config(DEFAULT_NATIVE_ENGINE_ID, vec![node()]);

    let error = service
        .start(&engine_config)
        .expect_err("native runtime handle is intentionally unavailable");

    assert_eq!(error.code, ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE);
}

#[test]
fn status_and_stop_remain_stopped_without_runtime_handle() {
    let service = NativeProxyEngineService::new();

    let status = service
        .status(DEFAULT_NATIVE_ENGINE_ID)
        .expect("native status should be inspectable");
    let stopped = service
        .stop(DEFAULT_NATIVE_ENGINE_ID)
        .expect("native stop should be idempotent before runtime exists");

    assert_eq!(status.state, ProxyEngineLifecycleState::Stopped);
    assert_eq!(stopped.state, ProxyEngineLifecycleState::Stopped);
    assert!(status.diagnostics.is_empty());
    assert!(stopped.diagnostics.is_empty());
}

#[test]
fn events_are_empty_until_runtime_handle_exists() {
    let service = NativeProxyEngineService::new();

    let events = service
        .events(DEFAULT_NATIVE_ENGINE_ID)
        .expect("native events should be inspectable");

    assert!(events.is_empty());
}

#[test]
fn unsupported_engine_id_rejects_lifecycle_calls() {
    let service = NativeProxyEngineService::new();

    let error = service
        .status("external")
        .expect_err("unsupported engine id should fail lifecycle calls");

    assert_eq!(error.code, ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE);
}

fn config(engine_id: &str, request_nodes: Vec<NodeDescriptor>) -> ProxyEngineConfig {
    graph_config(
        engine_id,
        Vec::new(),
        request_nodes,
        Vec::new(),
        Vec::new(),
    )
}

fn graph_config(
    engine_id: &str,
    config_nodes: Vec<NodeDescriptor>,
    request_nodes: Vec<NodeDescriptor>,
    listeners: Vec<ListenerDescriptor>,
    policies: Vec<RuleSet>,
) -> ProxyEngineConfig {
    ProxyEngineConfig {
        engine_id: engine_id.to_string(),
        config: ConfigSnapshot {
            version: SchemaVersion::new(1),
            profiles: vec!["default".to_string()],
            listeners,
            nodes: config_nodes,
            policies,
            dns: Vec::new(),
            plugins: Vec::new(),
        },
        nodes: request_nodes,
        metadata: Vec::new(),
    }
}

fn listener(id: &str, route: ListenerRoute) -> ListenerDescriptor {
    listener_with_bind(id, "127.0.0.1", 1080, route)
}

fn disabled_listener(id: &str) -> ListenerDescriptor {
    ListenerDescriptor {
        enabled: false,
        ..listener(id, ListenerRoute::DefaultAction(RouteAction::Direct))
    }
}

fn listener_with_bind(id: &str, host: &str, port: u16, route: ListenerRoute) -> ListenerDescriptor {
    ListenerDescriptor {
        id: id.to_string(),
        enabled: true,
        kind: ListenerKind::Socks,
        bind: ListenerBind {
            host: host.to_string(),
            port,
        },
        network: ListenerNetwork::Tcp,
        route,
        tags: Vec::new(),
        metadata: Vec::new(),
    }
}

fn route_set(id: &str, default_action: RouteAction) -> RuleSet {
    RuleSet {
        id: id.to_string(),
        rules: Vec::new(),
        default_action,
    }
}

fn node() -> NodeDescriptor {
    NodeDescriptor {
        id: "node-1".to_string(),
        name: "node 1".to_string(),
        protocol: Protocol::Socks,
        endpoint: Endpoint {
            host: "127.0.0.1".to_string(),
            port: 1080,
        },
        tags: Vec::new(),
    }
}

fn assert_diagnostic(diagnostics: &[Diagnostic], code: &str) {
    assert!(
        diagnostics.iter().any(|diagnostic| diagnostic.code == code),
        "missing diagnostic {code}: {diagnostics:?}"
    );
}

fn assert_no_diagnostic(diagnostics: &[Diagnostic], code: &str) {
    assert!(
        diagnostics.iter().all(|diagnostic| diagnostic.code != code),
        "unexpected diagnostic {code}: {diagnostics:?}"
    );
}
