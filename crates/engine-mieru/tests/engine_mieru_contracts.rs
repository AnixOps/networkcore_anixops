use engine_mieru::{
    parse_mieru_share_link, render_mieru_client_config, verify_local_mieru_binary,
    MieruClientConfigRequest, MieruManagedProcessState, MieruManagedProcessSupervisor,
    MIERU_BINARY_DIGEST_MISSING_CODE, MIERU_CONFIG_TRAFFIC_PATTERN_DEFERRED_CODE,
    MIERU_LISTENER_NOT_READY_CODE, MIERU_RUNTIME_UNWIRED_CODE,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

#[test]
fn mieru_share_link_retains_credentials_and_runtime_options() {
    let node = parse_mieru_share_link(
        "mierus://alice:secret@example.com:3010?ports=3010-3020&mtu=1400&multiplexing=true&handshake=fast&traffic=balanced#office",
    )
    .expect("Mieru share link should parse");

    assert_eq!(node.username, "alice");
    assert_eq!(node.password, "secret");
    assert_eq!(node.server, "example.com");
    assert_eq!(node.port, 3010);
    assert_eq!(node.port_range.as_deref(), Some("3010-3020"));
    assert_eq!(node.mtu, Some(1400));
    assert_eq!(node.multiplexing, Some(true));
    assert_eq!(node.handshake_mode.as_deref(), Some("fast"));
    assert_eq!(node.traffic_pattern.as_deref(), Some("balanced"));

    let descriptor = node.to_node_descriptor();
    assert_eq!(descriptor.protocol, control_domain::Protocol::Mieru);
    assert!(descriptor
        .metadata
        .iter()
        .any(|entry| entry.key == "mieru.password" && entry.value == "secret"));
}

#[test]
fn local_binary_verification_requires_explicit_digest_and_never_logs_credentials() {
    let root = temporary_root("binary");
    fs::create_dir_all(&root).expect("fixture directory should be created");
    let binary = root.join("mieru");
    fs::write(&binary, b"operator supplied binary").expect("fixture binary should be written");

    let error = verify_local_mieru_binary(&binary, None).expect_err("digest is mandatory");
    assert_eq!(error.code, MIERU_BINARY_DIGEST_MISSING_CODE);

    let digest = format!("{:x}", Sha256::digest(b"operator supplied binary"));
    let report =
        verify_local_mieru_binary(&binary, Some(&digest)).expect("explicit digest should verify");
    assert!(report.verified);
    let debug = format!(
        "{:?}",
        parse_mieru_share_link("mierus://alice:secret@example.com:3010")
    );
    assert!(!debug.contains("secret"));
}

#[test]
fn managed_supervisor_starts_stopped_and_service_stays_explicitly_unwired() {
    let mut supervisor = MieruManagedProcessSupervisor::default();
    assert_eq!(
        supervisor
            .status()
            .expect("status should be readable")
            .state,
        MieruManagedProcessState::Stopped
    );

    let service = engine_mieru::MieruProxyEngineService;
    let diagnostics = control_domain::ProxyEngineService::validate_config(
        &service,
        &control_domain::ProxyEngineConfig {
            engine_id: "mieru".to_string(),
            config: control_domain::ConfigSnapshot {
                version: control_domain::SchemaVersion::new(1),
                profiles: vec!["default".to_string()],
                listeners: Vec::new(),
                nodes: Vec::new(),
                policies: Vec::new(),
                dns: Vec::new(),
                plugins: Vec::new(),
            },
            nodes: Vec::new(),
            metadata: Vec::new(),
        },
    );
    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == MIERU_RUNTIME_UNWIRED_CODE));
}

#[test]
fn renders_official_shape_with_loopback_socks5_and_defers_traffic_pattern() {
    let node = parse_mieru_share_link(
        "mierus://alice:secret@example.com:3010?ports=3010-3020&mtu=1400&multiplexing=true&handshake=HANDSHAKE_STANDARD&traffic=encoded-pattern#office",
    )
    .expect("Mieru share link should parse");
    let report = render_mieru_client_config(&MieruClientConfigRequest {
        node,
        socks5_host: "127.0.0.1".to_string(),
        socks5_port: 1080,
    })
    .expect("Mieru client config should render");

    let json: serde_json::Value =
        serde_json::from_str(&report.content).expect("rendered Mieru config should be JSON");
    assert_eq!(json["activeProfile"], "default");
    assert_eq!(json["socks5Port"], 1080);
    assert_eq!(json["profiles"][0]["user"]["name"], "alice");
    assert_eq!(
        json["profiles"][0]["servers"][0]["portBindings"][0]["portRange"],
        "3010-3020"
    );
    assert!(report.traffic_pattern_deferred);
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == MIERU_CONFIG_TRAFFIC_PATTERN_DEFERRED_CODE));
    assert!(!format!("{:?}", report).contains("secret"));
}

#[test]
fn readiness_does_not_promote_a_stopped_process_from_pid_absence() {
    let mut supervisor = MieruManagedProcessSupervisor::default();
    let report = supervisor
        .readiness("127.0.0.1", 1080, std::time::Duration::from_millis(10))
        .expect("stopped supervisor readiness should be reportable");

    assert!(!report.listener_reachable);
    assert!(!report.ready);
    assert!(report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == MIERU_LISTENER_NOT_READY_CODE));
}

fn temporary_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("networkcore-engine-mieru-{label}"))
}
