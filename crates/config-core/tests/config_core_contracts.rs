use config_core::{
    parse_config_document, CoreConfigurationService, CONFIG_LISTENER_BIND_PORT_INVALID_CODE,
    CONFIG_LISTENER_NETWORK_UNSUPPORTED_CODE, CONFIG_LISTENER_ROUTE_CONFLICT_CODE,
    CONFIG_LISTENER_ROUTE_MISSING_CODE, CONFIG_MIGRATION_UNSUPPORTED_CODE,
    CONFIG_NODE_HOST_EMPTY_CODE, CONFIG_NODE_PORT_INVALID_CODE, CONFIG_PARSE_FAILED_CODE,
    CONFIG_PROFILE_CONFLICT_CODE, CONFIG_PROFILE_EMPTY_CODE, CONFIG_PROFILE_MISSING_CODE,
    CONFIG_ROUTE_PROXY_NODE_MISSING_CODE, CONFIG_SCHEMA_UNSUPPORTED_CODE, CURRENT_SCHEMA_VERSION,
};
use control_domain::{
    ConfigurationService, Diagnostic, ListenerKind, ListenerNetwork, ListenerRoute,
    OperatingSystem, PlatformCapabilities, Protocol, RouteAction, SchemaVersion,
};

#[test]
fn normalizes_profile_list_from_minimal_toml() {
    let service = CoreConfigurationService::new();
    let snapshot = service
        .normalize(
            r#"
schema_version = 1
profiles = ["default", "work"]
"#,
            &capabilities(),
        )
        .expect("minimal config should normalize");

    assert_eq!(snapshot.version, SchemaVersion::new(CURRENT_SCHEMA_VERSION));
    assert_eq!(
        snapshot.profiles,
        vec!["default".to_string(), "work".to_string()]
    );
    assert!(snapshot.listeners.is_empty());
    assert!(snapshot.nodes.is_empty());
    assert!(snapshot.policies.is_empty());
    assert!(snapshot.dns.is_empty());
    assert!(snapshot.plugins.is_empty());
}

#[test]
fn normalizes_listener_node_and_route_subset_from_toml() {
    let service = CoreConfigurationService::new();
    let snapshot = service
        .normalize(
            r#"
schema_version = 1
profile = "default"

[[nodes]]
id = "node-1"
name = "Local SOCKS"
protocol = "socks"
host = "127.0.0.1"
port = 1081
tags = ["local", "  dev  ", ""]

[[routes]]
id = "default-route"
default_action = "proxy"
default_node = "node-1"

[[listeners]]
id = "loopback-socks"
enabled = true
kind = "socks"
bind_host = "127.0.0.1"
bind_port = 1080
network = "tcp"
route = "default-route"
tags = ["local"]
metadata = { owner = "user" }
"#,
            &capabilities(),
        )
        .expect("listener/node/route config should normalize");

    assert_eq!(snapshot.listeners.len(), 1);
    let listener = &snapshot.listeners[0];
    assert_eq!(listener.id, "loopback-socks");
    assert!(listener.enabled);
    assert_eq!(listener.kind, ListenerKind::Socks);
    assert_eq!(listener.bind.host, "127.0.0.1");
    assert_eq!(listener.bind.port, 1080);
    assert_eq!(listener.network, ListenerNetwork::Tcp);
    assert_eq!(
        listener.route,
        ListenerRoute::RuleSet {
            rule_set_id: "default-route".to_string()
        }
    );
    assert_eq!(listener.metadata[0].key, "owner");

    assert_eq!(snapshot.nodes.len(), 1);
    let node = &snapshot.nodes[0];
    assert_eq!(node.id, "node-1");
    assert_eq!(node.name, "Local SOCKS");
    assert_eq!(node.protocol, Protocol::Socks);
    assert_eq!(node.endpoint.host, "127.0.0.1");
    assert_eq!(node.endpoint.port, 1081);
    assert_eq!(node.tags, vec!["local".to_string(), "dev".to_string()]);

    assert_eq!(snapshot.policies.len(), 1);
    assert_eq!(snapshot.policies[0].id, "default-route");
    assert!(snapshot.policies[0].rules.is_empty());
    assert_eq!(
        snapshot.policies[0].default_action,
        RouteAction::Proxy {
            node_id: "node-1".to_string()
        }
    );
}

#[test]
fn listener_can_embed_default_route_action() {
    let service = CoreConfigurationService::new();
    let snapshot = service
        .normalize(
            r#"
profiles = ["default"]

[[listeners]]
id = "direct-loopback"
enabled = false
kind = "local_tcp"
bind_host = "::1"
bind_port = 8080
network = "tcp_udp"
route_action = "direct"
"#,
            &capabilities(),
        )
        .expect("listener default action should normalize");

    assert_eq!(snapshot.listeners.len(), 1);
    assert!(!snapshot.listeners[0].enabled);
    assert_eq!(snapshot.listeners[0].kind, ListenerKind::LocalTcp);
    assert_eq!(snapshot.listeners[0].network, ListenerNetwork::TcpUdp);
    assert_eq!(
        snapshot.listeners[0].route,
        ListenerRoute::DefaultAction(RouteAction::Direct)
    );
}

#[test]
fn accepts_singular_profile_shortcut() {
    let document = parse_config_document(
        r#"
schema_version = 1
profile = "default"
"#,
    )
    .expect("singular profile should parse");

    assert_eq!(document.profiles, vec!["default".to_string()]);
    assert!(document.listeners.is_empty());
    assert!(document.nodes.is_empty());
    assert!(document.routes.is_empty());
}

#[test]
fn missing_profile_returns_stable_diagnostic() {
    let service = CoreConfigurationService::new();

    let diagnostics = service.validate("schema_version = 1", &capabilities());

    assert_diagnostic(&diagnostics, CONFIG_PROFILE_MISSING_CODE);
}

#[test]
fn empty_profile_returns_stable_diagnostic() {
    let service = CoreConfigurationService::new();

    let diagnostics = service.validate("profiles = [\"default\", \"   \"]", &capabilities());

    assert_diagnostic(&diagnostics, CONFIG_PROFILE_EMPTY_CODE);
}

#[test]
fn conflicting_profile_shapes_return_stable_diagnostic() {
    let service = CoreConfigurationService::new();
    let diagnostics = service.validate(
        r#"
profile = "default"
profiles = ["work"]
"#,
        &capabilities(),
    );

    assert_diagnostic(&diagnostics, CONFIG_PROFILE_CONFLICT_CODE);
}

#[test]
fn unsupported_schema_version_returns_domain_error() {
    let service = CoreConfigurationService::new();

    let error = service
        .normalize(
            r#"
schema_version = 2
profiles = ["default"]
"#,
            &capabilities(),
        )
        .expect_err("unsupported schema should fail");

    assert_eq!(error.code, CONFIG_SCHEMA_UNSUPPORTED_CODE);
}

#[test]
fn invalid_listener_network_returns_stable_diagnostic() {
    let service = CoreConfigurationService::new();
    let diagnostics = service.validate(
        r#"
profiles = ["default"]

[[listeners]]
id = "bad-listener"
kind = "socks"
bind_host = "127.0.0.1"
bind_port = 1080
network = "quic"
route_action = "direct"
"#,
        &capabilities(),
    );

    assert_diagnostic(&diagnostics, CONFIG_LISTENER_NETWORK_UNSUPPORTED_CODE);
}

#[test]
fn listener_route_shape_errors_return_stable_diagnostics() {
    let service = CoreConfigurationService::new();
    let missing = service.validate(
        r#"
profiles = ["default"]

[[listeners]]
id = "missing-route"
kind = "socks"
bind_host = "127.0.0.1"
bind_port = 1080
network = "tcp"
"#,
        &capabilities(),
    );
    assert_diagnostic(&missing, CONFIG_LISTENER_ROUTE_MISSING_CODE);

    let conflict = service.validate(
        r#"
profiles = ["default"]

[[listeners]]
id = "conflicting-route"
kind = "socks"
bind_host = "127.0.0.1"
bind_port = 1080
network = "tcp"
route = "default"
route_action = "direct"
"#,
        &capabilities(),
    );
    assert_diagnostic(&conflict, CONFIG_LISTENER_ROUTE_CONFLICT_CODE);
}

#[test]
fn invalid_ports_and_empty_node_host_return_stable_diagnostics() {
    let service = CoreConfigurationService::new();
    let invalid_listener_port = service.validate(
        r#"
profiles = ["default"]

[[listeners]]
id = "bad-port"
kind = "socks"
bind_host = "127.0.0.1"
bind_port = 65536
network = "tcp"
route_action = "direct"
"#,
        &capabilities(),
    );
    assert_diagnostic(
        &invalid_listener_port,
        CONFIG_LISTENER_BIND_PORT_INVALID_CODE,
    );

    let empty_node_host = service.validate(
        r#"
profiles = ["default"]

[[nodes]]
id = "node-1"
protocol = "socks"
host = "   "
port = 1081
"#,
        &capabilities(),
    );
    assert_diagnostic(&empty_node_host, CONFIG_NODE_HOST_EMPTY_CODE);

    let invalid_node_port = service.validate(
        r#"
profiles = ["default"]

[[nodes]]
id = "node-1"
protocol = "socks"
host = "127.0.0.1"
port = 0
"#,
        &capabilities(),
    );
    assert_diagnostic(&invalid_node_port, CONFIG_NODE_PORT_INVALID_CODE);
}

#[test]
fn proxy_route_without_node_returns_stable_diagnostic() {
    let service = CoreConfigurationService::new();
    let diagnostics = service.validate(
        r#"
profiles = ["default"]

[[routes]]
id = "default"
default_action = "proxy"
"#,
        &capabilities(),
    );

    assert_diagnostic(&diagnostics, CONFIG_ROUTE_PROXY_NODE_MISSING_CODE);
}

#[test]
fn parse_failure_diagnostic_does_not_leak_secret_values() {
    let service = CoreConfigurationService::new();
    let diagnostics = service.validate(
        r#"
token = "super-secret-token"
profiles = [
"#,
        &capabilities(),
    );

    assert_diagnostic(&diagnostics, CONFIG_PARSE_FAILED_CODE);
    assert!(diagnostics.iter().all(|diagnostic| {
        !diagnostic.message.contains("super-secret-token")
            && !diagnostic.message.contains("token =")
    }));
}

#[test]
fn migrate_preserves_same_version_and_rejects_cross_version() {
    let service = CoreConfigurationService::new();
    let raw_config = "profiles = [\"default\"]";

    let unchanged = service
        .migrate(
            raw_config,
            SchemaVersion::new(CURRENT_SCHEMA_VERSION),
            SchemaVersion::new(CURRENT_SCHEMA_VERSION),
        )
        .expect("same version migration should be identity");

    assert_eq!(unchanged, raw_config);

    let error = service
        .migrate(
            raw_config,
            SchemaVersion::new(CURRENT_SCHEMA_VERSION),
            SchemaVersion::new(CURRENT_SCHEMA_VERSION + 1),
        )
        .expect_err("cross-version migration should be explicit");

    assert_eq!(error.code, CONFIG_MIGRATION_UNSUPPORTED_CODE);
}

fn capabilities() -> PlatformCapabilities {
    PlatformCapabilities {
        os: OperatingSystem::Linux,
        supports_tunnel: true,
        supports_mitm: true,
        supports_embedded_runtime: true,
    }
}

fn assert_diagnostic(diagnostics: &[Diagnostic], code: &str) {
    assert!(
        diagnostics.iter().any(|diagnostic| diagnostic.code == code),
        "missing diagnostic {code}: {diagnostics:?}"
    );
}
