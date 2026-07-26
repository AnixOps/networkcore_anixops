use engine_mieru::{
    apply_and_start_mieru_client, parse_mieru_share_link, render_mieru_client_config,
    stop_mieru_client, verify_local_mieru_binary, write_mieru_client_config,
    MieruClientConfigRequest, MieruClientConfigWriteRequest, MieruClientControlRequest,
    MieruCommandReport, MieruCommandRunner, MieruManagedProcessState,
    MieruManagedProcessSupervisor, MIERU_BINARY_DIGEST_MISSING_CODE,
    MIERU_CONFIG_TRAFFIC_PATTERN_DEFERRED_CODE, MIERU_LISTENER_NOT_READY_CODE,
    MIERU_RUNTIME_UNWIRED_CODE,
};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

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
fn parses_official_simple_link_query_ports_without_authority_port() {
    let node = parse_mieru_share_link(
        "mierus://alice:secret@example.com?port=3010&port=3011&protocol=TCP&protocol=TCP&profile=default",
    )
    .expect("official simple Mieru link should parse");

    assert_eq!(node.port, 3010);
    assert_eq!(node.additional_ports, vec![3011]);
    assert_eq!(node.port_range, None);
}

#[test]
fn rejects_udp_binding_until_real_udp_contract_exists() {
    let error = parse_mieru_share_link("mierus://alice:secret@example.com?port=3010&protocol=UDP")
        .expect_err("UDP must not be claimed by the TCP-only adapter");
    assert_eq!(error.code, engine_mieru::MIERU_SHARE_LINK_INVALID_CODE);
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

#[test]
fn official_client_control_commands_are_explicit_and_redact_process_output() {
    let root = temporary_root("control");
    fs::create_dir_all(&root).expect("fixture directory should be created");
    let binary = root.join("mieru");
    fs::write(&binary, b"operator supplied binary").expect("fixture binary should be written");
    let digest = format!("{:x}", Sha256::digest(b"operator supplied binary"));
    let calls = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let runner = RecordingMieruRunner {
        calls: calls.clone(),
    };
    let request = MieruClientControlRequest {
        executable_path: binary,
        expected_sha256: digest,
        config_path: root.join("client_config.json"),
    };

    let started = apply_and_start_mieru_client(&runner, &request)
        .expect("official apply/start commands should succeed");
    let stopped =
        stop_mieru_client(&runner, &request).expect("official stop command should succeed");

    assert!(started.applied);
    assert!(started.started);
    assert!(stopped.stopped);
    assert_eq!(
        calls.lock().unwrap().as_slice(),
        [
            vec![
                "apply".to_string(),
                "config".to_string(),
                root.join("client_config.json").display().to_string()
            ],
            vec!["start".to_string()],
            vec!["stop".to_string()],
        ]
    );
    assert!(started
        .diagnostics
        .iter()
        .all(|diagnostic| !diagnostic.message.contains("secret")));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn config_write_snapshots_existing_credentials_and_sets_private_permissions() {
    let root = temporary_root("config-write");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("fixture directory should be created");
    let config_path = root.join("client_config.json");
    let snapshot_path = root.join("client_config.snapshot.json");
    fs::write(&config_path, b"old secret config").expect("old config should be written");

    let report = write_mieru_client_config(&MieruClientConfigWriteRequest {
        config_path: config_path.clone(),
        snapshot_path: snapshot_path.clone(),
        content: "{\"profiles\":[]}".to_string(),
    })
    .expect("Mieru config should be written");

    assert!(report.snapshot_written);
    assert!(report.verified);
    assert_eq!(
        fs::read_to_string(&snapshot_path).unwrap(),
        "old secret config"
    );
    assert_eq!(
        fs::read_to_string(&config_path).unwrap(),
        "{\"profiles\":[]}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&config_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&snapshot_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let _ = fs::remove_dir_all(&root);
}

struct RecordingMieruRunner {
    calls: Arc<Mutex<Vec<Vec<String>>>>,
}

impl MieruCommandRunner for RecordingMieruRunner {
    fn run(
        &self,
        _executable_path: &std::path::Path,
        arguments: &[String],
    ) -> control_domain::DomainResult<MieruCommandReport> {
        self.calls.lock().unwrap().push(arguments.to_vec());
        Ok(MieruCommandReport {
            exit_code: Some(0),
            succeeded: true,
            diagnostics: Vec::new(),
        })
    }
}

fn temporary_root(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("networkcore-engine-mieru-{label}"))
}
