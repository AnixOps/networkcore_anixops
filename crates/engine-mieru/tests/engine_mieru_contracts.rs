use engine_mieru::{
    parse_mieru_share_link, verify_local_mieru_binary, MieruManagedProcessState,
    MieruManagedProcessSupervisor, MIERU_BINARY_DIGEST_MISSING_CODE, MIERU_RUNTIME_UNWIRED_CODE,
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

fn temporary_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("networkcore-engine-mieru-{label}"))
}
