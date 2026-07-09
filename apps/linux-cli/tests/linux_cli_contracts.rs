use config_core::CoreConfigurationService;
use control_domain::{
    CertificateTrustState, ConfigSnapshot, ConfigurationService, Diagnostic, DiagnosticSeverity,
    DomainError, DomainResult, PlatformCapabilities, PlatformFeatureState, ProxyEngineConfig,
    ProxyEngineDescriptor, ProxyEngineEvent, ProxyEngineLifecycleState, ProxyEngineService,
    ProxyEngineStatus, SchemaVersion, SubscriptionSource,
};
use control_runtime::{RuntimeOperationResult, RuntimeOrchestrator};
use engine_native::{
    NativeProxyEngineService, ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_READY_CODE,
    ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_STOPPED_CODE,
    ENGINE_NATIVE_RUNTIME_FOREGROUND_HANDOFF_READY_CODE, ENGINE_NATIVE_RUNTIME_RELEASED_CODE,
    ENGINE_NATIVE_START_RUNNING_CODE,
};
use engine_singbox::{
    SingBoxInstallReport, SingBoxInstallRequest, SingBoxProcessRunReport, SingBoxProcessRunRequest,
    SingBoxProcessRunner, SingBoxReleaseInstaller, ENGINE_SINGBOX_DOWNLOAD_BINARY_READY_CODE,
    ENGINE_SINGBOX_PROCESS_EXITED_CODE,
};
use networkcore_linux::{
    cli_help_text, handle_capabilities, handle_entrypoint,
    handle_entrypoint_with_browser_capture_all_io, handle_entrypoint_with_browser_capture_io,
    handle_entrypoint_with_browser_capture_runner, handle_entrypoint_with_certificate_lifecycle_io,
    handle_entrypoint_with_runtime, handle_entrypoint_with_runtime_and_lifecycle,
    handle_entrypoint_with_runtime_lifecycle_and_sing_box, handle_foreground_lifecycle,
    handle_foreground_lifecycle_with_runtime_stop, handle_install_sing_box,
    handle_mitm_browser_capture_apply, handle_mitm_browser_capture_apply_with_store,
    handle_mitm_browser_capture_apply_with_store_and_profile_prefs_and_proxy_scheme,
    handle_mitm_browser_capture_apply_with_store_and_proxy_scheme,
    handle_mitm_browser_capture_launch, handle_mitm_browser_capture_launch_plan,
    handle_mitm_browser_capture_launch_with_proxy_scheme, handle_mitm_browser_capture_plan,
    handle_mitm_browser_capture_rollback, handle_mitm_browser_capture_rollback_with_store,
    handle_mitm_browser_capture_session_plan,
    handle_mitm_browser_capture_session_plan_with_proxy_scheme,
    handle_mitm_browser_capture_traffic_proof,
    handle_mitm_browser_capture_traffic_proof_with_probe,
    handle_mitm_browser_capture_traffic_proof_with_probe_and_proxy_scheme,
    handle_mitm_browser_capture_verify, handle_mitm_browser_capture_verify_with_probe,
    handle_mitm_browser_plan, handle_mitm_certificate_apply,
    handle_mitm_certificate_apply_with_store, handle_mitm_certificate_plan,
    handle_mitm_certificate_rollback, handle_mitm_certificate_rollback_with_store,
    handle_mitm_http_rewrite_plan, handle_mitm_http_rewrite_preview, handle_mitm_status,
    handle_parse_error, handle_prepare_config, handle_run_url_with_sing_box, handle_start,
    handle_status, handle_stop, native_proxy_engine_service_with_builtin_mitm_plugin, parse_args,
    render_response, BrowserCaptureEndpointProbe, BrowserCapturePacFileStore,
    BrowserCaptureProcessRunner, BrowserCaptureTrafficProofProbe,
    CommandBrowserCaptureEndpointProbe, CommandBrowserCaptureTrafficProofProbe,
    CommandSubscriptionCatalogStore, ConfigReadError, ConfigReader,
    CurrentProcessForegroundLifecycleHost, ForegroundLifecycleHost,
    ForegroundLifecycleInterruption, ForegroundLifecycleInterruptionSource,
    ForegroundLifecycleOutcome, ForegroundLifecycleRequest, LinuxBrowserCaptureLaunchOutcome,
    LinuxBrowserCaptureLaunchRequest, LinuxBrowserCapturePacApplyOutcome,
    LinuxBrowserCapturePacRequest, LinuxBrowserCapturePacRollbackOutcome,
    LinuxBrowserCaptureTrafficProofOutcome, LinuxBrowserCaptureTrafficProofRequest,
    LinuxBrowserCaptureVerifyOutcome, LinuxBrowserCaptureVerifyRequest, LinuxCliCommand,
    LinuxCliExitCode, LinuxMitmCertificateArtifactApplyOutcome,
    LinuxMitmCertificateArtifactRequest, LinuxMitmCertificateArtifactRollbackOutcome,
    MitmCertificateArtifactStore, MitmCertificateRollbackSnapshot, OutputFormat,
    SubscriptionCatalogAddRequest, SubscriptionCatalogListRequest, SubscriptionCatalogRemoveRequest,
    UnavailableForegroundLifecycleHost, UnavailableProxyEngineService, CLI_CONFIG_EMPTY_CODE,
    CLI_CONFIG_PATH_MISSING_CODE, CLI_CONFIG_READ_FAILED_CODE,
    CLI_MITM_BROWSER_CAPTURE_APPLY_BLOCKED_CODE,
    CLI_MITM_BROWSER_CAPTURE_APPLY_CONFIG_MISSING_CODE, CLI_MITM_BROWSER_CAPTURE_APPLY_READY_CODE,
    CLI_MITM_BROWSER_CAPTURE_AUTHORIZATION_REQUIRED_CODE,
    CLI_MITM_BROWSER_CAPTURE_LAUNCH_AUTHORIZATION_REQUIRED_CODE,
    CLI_MITM_BROWSER_CAPTURE_LAUNCH_FAILED_CODE, CLI_MITM_BROWSER_CAPTURE_LAUNCH_PLAN_READY_CODE,
    CLI_MITM_BROWSER_CAPTURE_LAUNCH_STARTED_CODE, CLI_MITM_BROWSER_CAPTURE_MUTATION_BLOCKED_CODE,
    CLI_MITM_BROWSER_CAPTURE_ROLLBACK_BLOCKED_CODE, CLI_MITM_BROWSER_CAPTURE_ROLLBACK_READY_CODE,
    CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_READY_CODE,
    CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_AUTHORIZATION_REQUIRED_CODE,
    CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BINDING_MISMATCH_CODE,
    CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BLOCKED_CODE,
    CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_MISSING_CODE,
    CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_OBSERVED_CODE,
    CLI_MITM_BROWSER_CAPTURE_VERIFY_AUTHORIZATION_REQUIRED_CODE,
    CLI_MITM_BROWSER_CAPTURE_VERIFY_BLOCKED_CODE,
    CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_REACHABLE_CODE,
    CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
    CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
    CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_REACHABLE_CODE, CLI_MITM_BROWSER_HIJACK_DEFERRED_CODE,
    CLI_MITM_BROWSER_PLAN_READY_CODE, CLI_MITM_CERTIFICATE_APPLY_CONFIG_MISSING_CODE,
    CLI_MITM_CERTIFICATE_APPLY_READY_CODE, CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
    CLI_MITM_CERTIFICATE_AUTHORIZATION_REQUIRED_CODE, CLI_MITM_CERTIFICATE_GATE_DEFERRED_CODE,
    CLI_MITM_CERTIFICATE_MUTATION_BLOCKED_CODE, CLI_MITM_CERTIFICATE_PLAN_READY_CODE,
    CLI_MITM_CERTIFICATE_ROLLBACK_BLOCKED_CODE, CLI_MITM_CERTIFICATE_ROLLBACK_READY_CODE,
    CLI_MITM_CLI_GATE_PARTIAL_CODE, CLI_MITM_DATA_PLANE_GATE_DEFERRED_CODE,
    CLI_MITM_HTTP_REWRITE_APPLY_READY_CODE, CLI_MITM_HTTP_REWRITE_AUTHORIZATION_REQUIRED_CODE,
    CLI_MITM_HTTP_REWRITE_PLAN_READY_CODE, CLI_MITM_HTTP_REWRITE_TLS_BLOCKED_CODE,
    CLI_MITM_POLICY_READY_CODE, CLI_RUNTIME_UNWIRED_CODE, CLI_START_FOREGROUND_ONLY_CODE,
    CLI_START_LIFECYCLE_FAILED_CODE, CLI_START_LIFECYCLE_HOST_MISSING_CODE,
    CLI_START_LIFECYCLE_INTERRUPTED_CODE, CLI_START_PLATFORM_DENIED_CODE,
    CLI_START_RUNTIME_STOP_FAILED_CODE, CLI_STATUS_NO_RUNTIME_CONTEXT_CODE,
    CLI_STATUS_PLATFORM_ONLY_CODE, CLI_STOP_UNAVAILABLE_WITHOUT_DAEMON_CODE, DEFAULT_ENGINE_ID,
    MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR, MITM_BROWSER_CAPTURE_DEFAULT_PROOF_LOG_PATH,
    MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME, MITM_BROWSER_CAPTURE_GATE,
    MITM_BROWSER_CAPTURE_GATE_STATUS, MITM_BROWSER_CAPTURE_MODE,
    MITM_BROWSER_CAPTURE_MUTATION_READY, MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME,
    MITM_BROWSER_CAPTURE_PROOF_QUERY_PARAM, MITM_BROWSER_CAPTURE_PROXY_HOST,
    MITM_BROWSER_CAPTURE_PROXY_PORT, MITM_BROWSER_CAPTURE_SOURCE_CONTRACT_STATUS,
    MITM_BROWSER_HIJACK_STATUS, MITM_BROWSER_PLAN_STATUS, MITM_CERTIFICATE_ARTIFACT_SUBJECT,
    MITM_CERTIFICATE_LIFECYCLE_GATE, MITM_CERTIFICATE_LIFECYCLE_GATE_STATUS,
    MITM_CERTIFICATE_LIFECYCLE_SOURCE_CONTRACT_STATUS, MITM_CERTIFICATE_MUTATION_READY,
    MITM_CERTIFICATE_PLAN_STATUS, MITM_CLI_COMMAND_GATE, MITM_CLI_COMMAND_GATE_STATUS,
    MITM_HTTP_REWRITE_CONTROLLED_TLS_TERMINATION_PLAN_READY,
    MITM_HTTP_REWRITE_DOWNSTREAM_TLS_TERMINATION_PLAN_READY,
    MITM_HTTP_REWRITE_HTTPS_REQUEST_REWRITE_PREVIEW_READY,
    MITM_HTTP_REWRITE_HTTPS_RESPONSE_REWRITE_PREVIEW_READY,
    MITM_HTTP_REWRITE_HTTPS_RESPONSE_REWRITE_READY, MITM_HTTP_REWRITE_LIVE_TRAFFIC_READY,
    MITM_HTTP_REWRITE_MUTATION_READY, MITM_HTTP_REWRITE_SCRIPT_DISPATCH_READY,
    MITM_HTTP_REWRITE_SOURCE_CONTRACT_STATUS, MITM_HTTP_REWRITE_TLS_DECRYPTION_READY,
    MITM_HTTP_REWRITE_UPSTREAM_TLS_FORWARDING_READY, MITM_HTTP_TLS_DATA_PLANE_GATE,
    MITM_HTTP_TLS_DATA_PLANE_GATE_STATUS, MITM_USER_FACING_STAGE,
};
#[cfg(unix)]
use networkcore_linux::{
    OsSignalForegroundLifecycleInterruptionSource, CLI_START_SIGNAL_RECEIVED_CODE,
};
use platform_linux::{
    linux_diagnostic, LinuxCertificateProbe, LinuxDnsManagerState, LinuxFeatureProbe,
    LinuxPlatformSnapshot, LinuxPrivilegeProbe, LinuxReadOnlyProbe, LinuxReadOnlyProbeSnapshot,
    LinuxServiceManagerState, LinuxTunDeviceState, ReadOnlyLinuxPlatformCapabilityService,
    StaticLinuxPlatformCapabilityService, DNS_MANAGER_DETECTED_CODE, DNS_MANAGER_UNKNOWN_CODE,
    PERMISSION_CAPABILITY_MISSING_CODE, PERMISSION_ELEVATION_REQUIRED_CODE,
    SERVICE_UNSUPPORTED_ENVIRONMENT_CODE, SOURCE_DNS,
};
#[cfg(unix)]
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use std::net::TcpListener;

#[test]
fn parses_prepare_config_with_explicit_path_and_json_format() {
    let command = parse_args([
        "prepare-config",
        "--config",
        "/tmp/networkcore.toml",
        "--format",
        "json",
    ])
    .expect("command should parse");

    assert_eq!(
        command,
        LinuxCliCommand::PrepareConfig {
            config_path: Some("/tmp/networkcore.toml".to_string()),
            format: OutputFormat::Json
        }
    );
}

#[test]
fn parses_help_command_and_renders_command_table() {
    let command = parse_args(["help"]).expect("help should parse");

    assert_eq!(
        command,
        LinuxCliCommand::Help {
            format: OutputFormat::Text
        }
    );

    let rendered = render_response(&networkcore_linux::handle_help(), OutputFormat::Text);
    assert!(rendered.contains("NetworkCore Linux CLI"));
    assert!(rendered.contains("install-sing-box"));
    assert!(rendered.contains("run-url"));
    assert!(rendered.contains("mitm [status|diagnostics|certificate-plan|browser-plan]"));
    assert!(rendered.contains("mitm certificate [plan|apply|rollback]"));
    assert!(rendered.contains("--cert-file <path>"));
    assert!(rendered.contains("--key-file <path>"));
    assert!(rendered.contains("--profile-trust-file <path>"));
    assert!(rendered.contains(
        "mitm browser-capture [plan|launch-plan|session-plan|launch|apply|rollback|verify|traffic-proof]"
    ));
    assert!(rendered.contains("mitm http-rewrite [plan|preview]"));
    assert!(rendered.contains("--url <url>"));
    assert!(rendered.contains("--phase request|response"));
    assert!(rendered.contains("--proof-token <token>"));
    assert!(rendered.contains("--proof-log <path>"));
    assert!(rendered.contains("sing-box install"));
}

#[test]
fn subscription_catalog_add_persists_source_snapshot_and_redacts_location() {
    let root = std::env::temp_dir().join(format!(
        "networkcore-subscription-catalog-contract-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("catalog test directory should be created");
    let catalog_path = root.join("catalog.json");
    let snapshot_path = root.join("catalog.snapshot.json");
    let secret_location = "inline:secret-subscription-payload";
    let store = CommandSubscriptionCatalogStore::new();

    let report = store
        .add_source(&SubscriptionCatalogAddRequest {
            catalog_path: catalog_path.display().to_string(),
            snapshot_path: snapshot_path.display().to_string(),
            source: SubscriptionSource {
                id: " work ".to_string(),
                location: format!(" {secret_location} "),
            },
        })
        .expect("catalog add should persist a source");

    assert_eq!(report.source_id, "work");
    assert_eq!(report.source_count, 1);
    assert_eq!(report.location_kind, "inline");
    assert!(report.location_redacted);
    assert!(!format!("{report:?}").contains(secret_location));

    let catalog: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&catalog_path).expect("catalog file should be readable"),
    )
    .expect("catalog file should be valid JSON");
    assert_eq!(catalog["schema_version"], 1);
    assert_eq!(catalog["sources"][0]["id"], "work");
    assert_eq!(catalog["sources"][0]["location"], secret_location);

    let snapshot: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&snapshot_path).expect("snapshot file should be readable"),
    )
    .expect("snapshot file should be valid JSON");
    assert_eq!(snapshot["schema_version"], 1);
    assert!(snapshot["sources"]
        .as_array()
        .expect("sources array")
        .is_empty());

    let duplicate = store
        .add_source(&SubscriptionCatalogAddRequest {
            catalog_path: catalog_path.display().to_string(),
            snapshot_path: root.join("duplicate.snapshot.json").display().to_string(),
            source: SubscriptionSource {
                id: "work".to_string(),
                location: "https://secret.example/next?token=redacted".to_string(),
            },
        })
        .expect_err("duplicate source id should be rejected");
    assert_eq!(
        duplicate.code,
        "cli.linux.subscription_catalog.duplicate_source_id"
    );
    let catalog_after_duplicate: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&catalog_path).expect("catalog should remain readable"),
    )
    .expect("catalog should remain valid JSON");
    assert_eq!(catalog_after_duplicate, catalog);

    std::fs::remove_dir_all(&root).expect("catalog test directory should be removed");
}

#[test]
fn subscription_catalog_list_reads_and_redacts_sources() {
    let root = std::env::temp_dir().join(format!(
        "networkcore-subscription-catalog-list-contract-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("catalog list test directory should be created");
    let catalog_path = root.join("catalog.json");
    let catalog_json = r#"{
  "schema_version": 1,
  "sources": [
    {"id": " work ", "location": "inline:secret-subscription-payload"},
    {"id": "remote", "location": "https://example.test/sub?token=secret-token"}
  ]
}"#;
    std::fs::write(&catalog_path, catalog_json).expect("catalog should be written");
    let before = std::fs::read_to_string(&catalog_path).expect("catalog should be readable");

    let report = CommandSubscriptionCatalogStore::new()
        .list_sources(&SubscriptionCatalogListRequest {
            catalog_path: catalog_path.display().to_string(),
        })
        .expect("catalog list should read sources");

    assert_eq!(report.source_count, 2);
    assert_eq!(report.sources[0].source_id, "work");
    assert_eq!(report.sources[0].location_kind, "inline");
    assert!(report.sources[0].location_redacted);
    assert_eq!(report.sources[1].source_id, "remote");
    assert_eq!(report.sources[1].location_kind, "remote");
    assert!(report.sources[1].location_redacted);
    let debug_report = format!("{report:?}");
    assert!(!debug_report.contains("secret-subscription-payload"));
    assert!(!debug_report.contains("secret-token"));
    assert_eq!(
        std::fs::read_to_string(&catalog_path).expect("catalog should remain readable"),
        before
    );

    std::fs::remove_dir_all(&root).expect("catalog list test directory should be removed");
}

#[test]
fn subscription_catalog_remove_persists_snapshot_and_redacts_location() {
    let root = std::env::temp_dir().join(format!(
        "networkcore-subscription-catalog-remove-contract-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("catalog remove test directory should be created");
    let catalog_path = root.join("catalog.json");
    let snapshot_path = root.join("catalog.snapshot.json");
    let catalog_json = r#"{
  "schema_version": 1,
  "sources": [
    {"id": "work", "location": "inline:secret-subscription-payload"},
    {"id": "remote", "location": "https://example.test/sub?token=secret-token"}
  ]
}"#;
    std::fs::write(&catalog_path, catalog_json).expect("catalog should be written");

    let report = CommandSubscriptionCatalogStore::new()
        .remove_source(&SubscriptionCatalogRemoveRequest {
            catalog_path: catalog_path.display().to_string(),
            snapshot_path: snapshot_path.display().to_string(),
            source_id: " work ".to_string(),
        })
        .expect("catalog remove should persist the updated catalog");

    assert_eq!(report.source_id, "work");
    assert_eq!(report.source_count, 1);
    let debug_report = format!("{report:?}");
    assert!(!debug_report.contains("secret-subscription-payload"));
    assert!(!debug_report.contains("secret-token"));

    let catalog: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&catalog_path).expect("catalog should be readable"),
    )
    .expect("catalog should be valid JSON");
    assert_eq!(catalog["sources"].as_array().expect("sources array").len(), 1);
    assert_eq!(catalog["sources"][0]["id"], "remote");

    let snapshot: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&snapshot_path).expect("snapshot should be readable"),
    )
    .expect("snapshot should be valid JSON");
    assert_eq!(snapshot["schema_version"], 1);
    assert_eq!(snapshot["sources"].as_array().expect("sources array").len(), 2);
    assert_eq!(snapshot["sources"][0]["location"], "inline:secret-subscription-payload");

    let catalog_before_missing =
        std::fs::read_to_string(&catalog_path).expect("catalog should remain readable");
    let missing = CommandSubscriptionCatalogStore::new()
        .remove_source(&SubscriptionCatalogRemoveRequest {
            catalog_path: catalog_path.display().to_string(),
            snapshot_path: root.join("missing.snapshot.json").display().to_string(),
            source_id: "missing".to_string(),
        })
        .expect_err("missing source id should be rejected");
    assert_eq!(
        missing.code,
        "cli.linux.subscription_catalog.source_not_found"
    );
    assert_eq!(
        std::fs::read_to_string(&catalog_path).expect("catalog should remain readable"),
        catalog_before_missing
    );
    assert!(!root.join("missing.snapshot.json").exists());

    std::fs::remove_dir_all(&root).expect("catalog remove test directory should be removed");
}

#[test]
fn native_engine_factory_enables_builtin_mitm_plugin_hook_for_start_path() {
    let service = native_proxy_engine_service_with_builtin_mitm_plugin()
        .expect("built-in MITM plugin hook should load for native start path");

    assert!(service.http_mitm_hook_enabled());
}

#[test]
fn parses_mitm_status_and_diagnostics_commands() {
    let default_status = parse_args(["mitm"]).expect("mitm should default to status");
    let status =
        parse_args(["mitm", "status", "--format", "json"]).expect("mitm status should parse");
    let status_options =
        parse_args(["mitm", "--format", "json"]).expect("mitm options should imply status");
    let diagnostics = parse_args(["mitm", "diagnostics"]).expect("mitm diagnostics should parse");
    let certificate_plan = parse_args(["mitm", "certificate-plan", "--format", "json"])
        .expect("mitm certificate plan should parse");
    let cert_plan_alias =
        parse_args(["mitm", "cert-plan"]).expect("mitm cert-plan alias should parse");
    let certificate_apply = parse_args([
        "mitm",
        "certificate",
        "apply",
        "--confirm",
        "--cert-file",
        "/tmp/networkcore-mitm-ca.crt",
        "--key-file",
        "/tmp/networkcore-mitm-ca.key",
        "--profile-trust-file",
        "/tmp/networkcore-profile-trust.pem",
        "--snapshot",
        "/tmp/networkcore-mitm-ca.snapshot.json",
        "--format",
        "json",
    ])
    .expect("mitm certificate apply should parse");
    let certificate_rollback = parse_args([
        "mitm",
        "certificate",
        "rollback",
        "--snapshot",
        "/tmp/networkcore-mitm-ca.snapshot.json",
    ])
    .expect("mitm certificate rollback should parse");
    let browser_plan = parse_args(["mitm", "browser-plan", "--format", "json"])
        .expect("mitm browser plan should parse");
    let browser_capture_plan_alias = parse_args(["mitm", "browser-capture-plan"])
        .expect("mitm browser-capture-plan alias should parse");
    let hijack_plan_alias =
        parse_args(["mitm", "hijack-plan"]).expect("mitm hijack-plan alias should parse");
    let browser_capture_default =
        parse_args(["mitm", "browser-capture"]).expect("mitm browser-capture should parse");
    let browser_capture_plan = parse_args(["mitm", "browser-capture", "plan", "--format", "json"])
        .expect("mitm browser-capture plan should parse");
    let browser_capture_launch_plan = parse_args([
        "mitm",
        "browser-capture",
        "launch-plan",
        "--proxy-scheme",
        "socks5",
        "--format",
        "json",
    ])
    .expect("mitm browser-capture launch-plan should parse");
    let browser_capture_session_plan = parse_args([
        "mitm",
        "browser-capture",
        "session-plan",
        "ss://YWVzLTI1Ni1nY206ZjQzYzBlZWUtMTNiOS00ZjA3LWJlYzktZDRiNzQ0MTQxNTAz@82.47.34.99:11111#%E9%A6%99%E6%B8%AF",
        "--browser",
        "google-chrome",
        "--profile-dir",
        "/tmp/networkcore-browser-capture-profile",
        "--target-url",
        "https://example.com/capture",
        "--proof-token",
        "browser-proof-123",
        "--proof-log",
        "/tmp/networkcore-browser-proof.log",
        "--proxy-scheme",
        "socks5",
        "--listen-host",
        "127.0.0.1",
        "--listen-port",
        "7891",
        "--format",
        "json",
    ])
    .expect("mitm browser-capture session-plan should parse");
    let browser_capture_launch = parse_args([
        "mitm",
        "browser-capture",
        "launch",
        "--browser",
        "google-chrome",
        "--profile-dir",
        "/tmp/networkcore-browser-capture-profile",
        "--target-url",
        "https://example.com/capture",
        "--proof-token",
        "browser-proof-123",
        "--proof-log",
        "/tmp/networkcore-browser-proof.log",
        "--confirm",
        "--format",
        "json",
    ])
    .expect("mitm browser-capture launch should parse");
    let browser_capture_apply = parse_args(["mitm", "browser-capture", "apply", "--confirm"])
        .expect("mitm browser-capture apply should parse");
    let browser_capture_apply_pac = parse_args([
        "mitm",
        "browser-capture",
        "apply",
        "--confirm",
        "--pac-file",
        "/tmp/networkcore-browser-capture.pac",
        "--policy-file",
        "/tmp/networkcore-browser-capture-policy.json",
        "--profile-prefs-file",
        "/tmp/networkcore-browser-capture-profile/user.js",
        "--snapshot",
        "/tmp/networkcore-browser-capture.snapshot.json",
        "--format",
        "json",
    ])
    .expect("mitm browser-capture apply with PAC file should parse");
    let browser_capture_rollback = parse_args([
        "mitm",
        "browser-capture",
        "rollback",
        "--snapshot",
        "/tmp/networkcore-browser-capture.snapshot.json",
    ])
    .expect("mitm browser-capture rollback should parse");
    let browser_capture_verify = parse_args([
        "mitm",
        "browser-capture",
        "verify",
        "--confirm",
        "--target-url",
        "https://example.com/capture",
    ])
    .expect("mitm browser-capture verify should parse");
    let browser_capture_traffic_proof = parse_args([
        "mitm",
        "browser-capture",
        "traffic-proof",
        "--confirm",
        "--target-url",
        "https://example.com/capture",
        "--proof-token",
        "browser-proof-123",
        "--proof-log",
        "/tmp/networkcore-browser-proof.log",
        "--proxy-scheme",
        "socks5",
        "--format",
        "json",
    ])
    .expect("mitm browser-capture traffic-proof should parse");
    let browser_capture_traffic_proof_defaults = parse_args([
        "mitm",
        "browser-capture",
        "traffic-proof",
        "--confirm",
        "--target-url",
        "https://example.com/capture",
    ])
    .expect("mitm browser-capture traffic-proof default proof binding should parse");
    let http_rewrite_plan = parse_args(["mitm", "http-rewrite", "plan", "--format", "json"])
        .expect("mitm http-rewrite plan should parse");
    let http_rewrite_preview = parse_args([
        "mitm",
        "http-rewrite",
        "preview",
        "--url",
        "https://pubads.g.doubleclick.net/pagead/id",
        "--method",
        "get",
        "--phase",
        "request",
        "--header",
        "Accept: */*",
        "--body",
        "from=1",
        "--confirm",
        "--format",
        "json",
    ])
    .expect("mitm http-rewrite preview should parse");

    assert_eq!(
        default_status,
        LinuxCliCommand::MitmStatus {
            format: OutputFormat::Text
        }
    );
    assert_eq!(
        status,
        LinuxCliCommand::MitmStatus {
            format: OutputFormat::Json
        }
    );
    assert_eq!(
        status_options,
        LinuxCliCommand::MitmStatus {
            format: OutputFormat::Json
        }
    );
    assert_eq!(
        diagnostics,
        LinuxCliCommand::MitmDiagnostics {
            format: OutputFormat::Text
        }
    );
    assert_eq!(
        certificate_plan,
        LinuxCliCommand::MitmCertificatePlan {
            format: OutputFormat::Json
        }
    );
    assert_eq!(
        cert_plan_alias,
        LinuxCliCommand::MitmCertificatePlan {
            format: OutputFormat::Text
        }
    );
    assert_eq!(
        certificate_apply,
        LinuxCliCommand::MitmCertificateApply {
            cert_file_path: Some("/tmp/networkcore-mitm-ca.crt".to_string()),
            key_file_path: Some("/tmp/networkcore-mitm-ca.key".to_string()),
            profile_trust_file_path: Some("/tmp/networkcore-profile-trust.pem".to_string()),
            snapshot_path: Some("/tmp/networkcore-mitm-ca.snapshot.json".to_string()),
            confirm: true,
            format: OutputFormat::Json
        }
    );
    assert_eq!(
        certificate_rollback,
        LinuxCliCommand::MitmCertificateRollback {
            snapshot_path: Some("/tmp/networkcore-mitm-ca.snapshot.json".to_string()),
            format: OutputFormat::Text
        }
    );
    assert_eq!(
        browser_plan,
        LinuxCliCommand::MitmBrowserPlan {
            format: OutputFormat::Json
        }
    );
    assert_eq!(
        browser_capture_plan_alias,
        LinuxCliCommand::MitmBrowserPlan {
            format: OutputFormat::Text
        }
    );
    assert_eq!(
        hijack_plan_alias,
        LinuxCliCommand::MitmBrowserPlan {
            format: OutputFormat::Text
        }
    );
    assert_eq!(
        browser_capture_default,
        LinuxCliCommand::MitmBrowserCapturePlan {
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            format: OutputFormat::Text
        }
    );
    assert_eq!(
        browser_capture_plan,
        LinuxCliCommand::MitmBrowserCapturePlan {
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            format: OutputFormat::Json
        }
    );
    assert_eq!(
        browser_capture_launch_plan,
        LinuxCliCommand::MitmBrowserCaptureLaunchPlan {
            proxy_scheme: MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME.to_string(),
            format: OutputFormat::Json
        }
    );
    assert_eq!(
        browser_capture_session_plan,
        LinuxCliCommand::MitmBrowserCaptureSessionPlan {
            url: "ss://YWVzLTI1Ni1nY206ZjQzYzBlZWUtMTNiOS00ZjA3LWJlYzktZDRiNzQ0MTQxNTAz@82.47.34.99:11111#%E9%A6%99%E6%B8%AF".to_string(),
            browser: "google-chrome".to_string(),
            profile_dir: "/tmp/networkcore-browser-capture-profile".to_string(),
            target_url: Some("https://example.com/capture".to_string()),
            proof_token: Some("browser-proof-123".to_string()),
            proof_log_path: Some("/tmp/networkcore-browser-proof.log".to_string()),
            proxy_scheme: MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME.to_string(),
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7891,
            format: OutputFormat::Json
        }
    );
    assert_eq!(
        browser_capture_launch,
        LinuxCliCommand::MitmBrowserCaptureLaunch {
            browser: "google-chrome".to_string(),
            profile_dir: "/tmp/networkcore-browser-capture-profile".to_string(),
            target_url: Some("https://example.com/capture".to_string()),
            proof_token: Some("browser-proof-123".to_string()),
            proof_log_path: Some("/tmp/networkcore-browser-proof.log".to_string()),
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            confirm: true,
            format: OutputFormat::Json
        }
    );
    assert_eq!(
        browser_capture_apply,
        LinuxCliCommand::MitmBrowserCaptureApply {
            pac_file_path: None,
            policy_file_path: None,
            profile_prefs_file_path: None,
            snapshot_path: None,
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            confirm: true,
            format: OutputFormat::Text
        }
    );
    assert_eq!(
        browser_capture_apply_pac,
        LinuxCliCommand::MitmBrowserCaptureApply {
            pac_file_path: Some("/tmp/networkcore-browser-capture.pac".to_string()),
            policy_file_path: Some("/tmp/networkcore-browser-capture-policy.json".to_string()),
            profile_prefs_file_path: Some(
                "/tmp/networkcore-browser-capture-profile/user.js".to_string()
            ),
            snapshot_path: Some("/tmp/networkcore-browser-capture.snapshot.json".to_string()),
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            confirm: true,
            format: OutputFormat::Json
        }
    );
    assert_eq!(
        browser_capture_rollback,
        LinuxCliCommand::MitmBrowserCaptureRollback {
            snapshot_path: Some("/tmp/networkcore-browser-capture.snapshot.json".to_string()),
            format: OutputFormat::Text
        }
    );
    assert_eq!(
        browser_capture_verify,
        LinuxCliCommand::MitmBrowserCaptureVerify {
            target_url: Some("https://example.com/capture".to_string()),
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            confirm: true,
            format: OutputFormat::Text
        }
    );
    assert_eq!(
        browser_capture_traffic_proof,
        LinuxCliCommand::MitmBrowserCaptureTrafficProof {
            target_url: Some("https://example.com/capture".to_string()),
            proof_token: Some("browser-proof-123".to_string()),
            proof_log_path: Some("/tmp/networkcore-browser-proof.log".to_string()),
            proxy_scheme: MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME.to_string(),
            confirm: true,
            format: OutputFormat::Json
        }
    );
    assert_eq!(
        browser_capture_traffic_proof_defaults,
        LinuxCliCommand::MitmBrowserCaptureTrafficProof {
            target_url: Some("https://example.com/capture".to_string()),
            proof_token: None,
            proof_log_path: None,
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            confirm: true,
            format: OutputFormat::Text
        }
    );
    assert_eq!(
        http_rewrite_plan,
        LinuxCliCommand::MitmHttpRewritePlan {
            format: OutputFormat::Json
        }
    );
    assert_eq!(
        http_rewrite_preview,
        LinuxCliCommand::MitmHttpRewritePreview {
            url: Some("https://pubads.g.doubleclick.net/pagead/id".to_string()),
            method: "GET".to_string(),
            phase: "request".to_string(),
            status_code: None,
            headers: vec!["Accept: */*".to_string()],
            body: Some("from=1".to_string()),
            confirm: true,
            format: OutputFormat::Json
        }
    );
}

#[test]
fn missing_command_response_includes_help_table() {
    let diagnostic = parse_args(Vec::<&str>::new())
        .expect_err("missing command should stay a parse error")
        .into_diagnostic();

    let response = handle_parse_error(diagnostic);
    let rendered = render_response(&response, OutputFormat::Text);

    assert!(!response.ok);
    assert_eq!(response.exit_code, LinuxCliExitCode::ArgumentOrConfig);
    assert!(rendered.contains("missing linux CLI command"));
    assert!(rendered.contains(cli_help_text()));
}

#[test]
fn parses_install_sing_box_command_and_alias() {
    let command = parse_args([
        "install-sing-box",
        "--install-dir",
        "/tmp/networkcore-engines",
        "--force",
        "--format",
        "json",
    ])
    .expect("install-sing-box should parse");
    let alias = parse_args([
        "sing-box",
        "install",
        "--install-dir",
        "/tmp/networkcore-engines",
    ])
    .expect("sing-box install alias should parse");

    assert_eq!(
        command,
        LinuxCliCommand::InstallSingBox {
            install_dir: Some("/tmp/networkcore-engines".to_string()),
            force: true,
            format: OutputFormat::Json
        }
    );
    assert_eq!(
        alias,
        LinuxCliCommand::InstallSingBox {
            install_dir: Some("/tmp/networkcore-engines".to_string()),
            force: false,
            format: OutputFormat::Text
        }
    );
}

#[test]
fn parses_run_url_command_with_local_proxy_options() {
    let command = parse_args([
        "run-url",
        "ss://YWVzLTI1Ni1nY206ZjQzYzBlZWUtMTNiOS00ZjA3LWJlYzktZDRiNzQ0MTQxNTAz@82.47.34.99:11111#%E9%A6%99%E6%B8%AF",
        "--listen-host",
        "127.0.0.1",
        "--listen-port",
        "7891",
        "--install-dir",
        "/tmp/networkcore-engines",
        "--format",
        "json",
    ])
    .expect("run-url should parse");

    assert_eq!(
        command,
        LinuxCliCommand::RunUrl {
            url: "ss://YWVzLTI1Ni1nY206ZjQzYzBlZWUtMTNiOS00ZjA3LWJlYzktZDRiNzQ0MTQxNTAz@82.47.34.99:11111#%E9%A6%99%E6%B8%AF".to_string(),
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7891,
            install_dir: Some("/tmp/networkcore-engines".to_string()),
            force: false,
            format: OutputFormat::Json,
        }
    );
}

#[test]
fn missing_config_path_returns_stable_diagnostic() {
    let orchestrator = available_orchestrator();
    let reader = MemoryConfigReader::ok("profile = default");

    let response = handle_prepare_config(&orchestrator, &reader, None);

    assert!(!response.ok);
    assert_eq!(response.exit_code, LinuxCliExitCode::ArgumentOrConfig);
    assert_diagnostic(&response.diagnostics, CLI_CONFIG_PATH_MISSING_CODE);
}

#[test]
fn empty_config_returns_cli_config_diagnostic_before_runtime_validation() {
    let orchestrator = available_orchestrator();
    let reader = MemoryConfigReader::ok("   ");

    let response = handle_prepare_config(&orchestrator, &reader, Some("config.toml"));

    assert!(!response.ok);
    assert_eq!(response.exit_code, LinuxCliExitCode::ArgumentOrConfig);
    assert_diagnostic(&response.diagnostics, CLI_CONFIG_EMPTY_CODE);
}

#[test]
fn config_read_failure_returns_stable_cli_diagnostic() {
    let orchestrator = available_orchestrator();
    let reader = MemoryConfigReader::err("permission denied");

    let response = handle_prepare_config(&orchestrator, &reader, Some("config.toml"));

    assert!(!response.ok);
    assert_eq!(response.exit_code, LinuxCliExitCode::ArgumentOrConfig);
    assert_diagnostic(&response.diagnostics, CLI_CONFIG_READ_FAILED_CODE);
}

#[test]
fn prepare_config_uses_reader_and_runtime_orchestrator() {
    let orchestrator = available_orchestrator();
    let reader = MemoryConfigReader::ok("profile = default");

    let response = handle_prepare_config(&orchestrator, &reader, Some("config.toml"));

    assert!(response.ok);
    assert_eq!(response.exit_code, LinuxCliExitCode::Success);
    assert_eq!(response.config_profiles, vec!["default".to_string()]);
    assert!(response.platform.is_some());
}

#[test]
fn start_maps_platform_denial_to_cli_diagnostic() {
    let orchestrator = RuntimeOrchestrator::new(
        TestConfigurationService,
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot {
            tunnel: LinuxFeatureProbe {
                state: PlatformFeatureState::unavailable("linux TUN is unavailable"),
                diagnostics: Vec::new(),
            },
            ..LinuxPlatformSnapshot::available_for_tests()
        }),
        TestProxyEngineService,
    );
    let reader = MemoryConfigReader::ok("profile = default");

    let response = handle_start(&orchestrator, &reader, Some("config.toml"));

    assert!(!response.ok);
    assert_eq!(response.exit_code, LinuxCliExitCode::PlatformDenied);
    assert_diagnostic(&response.diagnostics, CLI_START_PLATFORM_DENIED_CODE);
}

#[test]
fn stop_without_daemon_is_stable_unavailable() {
    let response = handle_stop();

    assert!(!response.ok);
    assert_eq!(response.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &response.diagnostics,
        CLI_STOP_UNAVAILABLE_WITHOUT_DAEMON_CODE,
    );
}

#[test]
fn status_without_runtime_context_reports_platform_only_diagnostics() {
    let platform = StaticLinuxPlatformCapabilityService::new(
        LinuxPlatformSnapshot::available_for_tests().with_diagnostic(linux_diagnostic(
            DiagnosticSeverity::Warning,
            DNS_MANAGER_UNKNOWN_CODE,
            "linux DNS manager could not be identified",
            SOURCE_DNS,
        )),
    );

    let response = handle_status(&platform);

    assert!(response.ok);
    assert!(response.platform.is_some());
    assert_diagnostic(&response.diagnostics, DNS_MANAGER_UNKNOWN_CODE);
    assert_diagnostic(&response.diagnostics, CLI_STATUS_NO_RUNTIME_CONTEXT_CODE);
    assert_diagnostic(&response.diagnostics, CLI_STATUS_PLATFORM_ONLY_CODE);
}

#[test]
fn mitm_status_loads_builtin_policy_and_reports_deferred_gates() {
    let platform = StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot {
        mitm_certificate: LinuxCertificateProbe::new(CertificateTrustState::NotInstalled),
        ..LinuxPlatformSnapshot::available_for_tests()
    });

    let response = handle_mitm_status(&platform);

    assert!(response.ok);
    assert_eq!(response.command, "mitm status");
    assert_eq!(response.exit_code, LinuxCliExitCode::Success);
    assert!(response.platform.is_some());
    assert_diagnostic(&response.diagnostics, CLI_MITM_POLICY_READY_CODE);
    assert_diagnostic(&response.diagnostics, CLI_MITM_CLI_GATE_PARTIAL_CODE);
    assert_diagnostic(&response.diagnostics, CLI_MITM_CERTIFICATE_PLAN_READY_CODE);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_CERTIFICATE_GATE_DEFERRED_CODE,
    );
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_CERTIFICATE_MUTATION_BLOCKED_CODE,
    );
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_DATA_PLANE_GATE_DEFERRED_CODE,
    );
    assert_diagnostic(&response.diagnostics, CLI_MITM_BROWSER_PLAN_READY_CODE);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_MUTATION_BLOCKED_CODE,
    );
    assert_diagnostic(&response.diagnostics, CLI_MITM_BROWSER_HIJACK_DEFERRED_CODE);

    let mitm = response
        .mitm_status
        .as_ref()
        .expect("mitm status response should include machine fields");
    assert_eq!(mitm.stage, MITM_USER_FACING_STAGE);
    assert!(!mitm.user_facing_ready);
    assert_eq!(mitm.browser_hijack, MITM_BROWSER_HIJACK_STATUS);
    assert!(!mitm.platform_mitm_available);
    assert_eq!(mitm.certificate_state, "not_installed");
    assert_eq!(mitm.certificate_plan.status, MITM_CERTIFICATE_PLAN_STATUS);
    assert_eq!(
        mitm.certificate_plan.mutation_ready,
        MITM_CERTIFICATE_MUTATION_READY
    );
    assert_eq!(mitm.certificate_plan.current_state, "not_installed");
    assert!(mitm
        .certificate_plan
        .required_steps
        .iter()
        .any(|step| step.id == "write-local-ca-artifact" && step.status == "active"));
    let has_profile_trust_step =
        mitm.certificate_plan.required_steps.iter().any(|step| {
            step.id == "write-dedicated-profile-trust-artifact" && step.status == "active"
        });
    assert!(has_profile_trust_step);
    assert!(mitm
        .certificate_plan
        .required_steps
        .iter()
        .any(|step| step.id == "rollback-ca-artifact" && step.status == "active"));
    assert!(mitm
        .certificate_plan
        .blocked_operations
        .iter()
        .any(|operation| operation == "configure-browser-proxy"));
    assert_eq!(mitm.browser_plan.status, MITM_BROWSER_PLAN_STATUS);
    assert_eq!(
        mitm.browser_plan.mutation_ready,
        MITM_BROWSER_CAPTURE_MUTATION_READY
    );
    assert_eq!(mitm.browser_plan.current_capture, "not_configured");
    assert_eq!(
        mitm.browser_plan.planned_capture_mode,
        MITM_BROWSER_CAPTURE_MODE
    );
    assert_eq!(
        mitm.browser_plan.planned_proxy_host,
        MITM_BROWSER_CAPTURE_PROXY_HOST
    );
    assert_eq!(
        mitm.browser_plan.planned_proxy_port,
        MITM_BROWSER_CAPTURE_PROXY_PORT
    );
    assert!(mitm
        .browser_plan
        .required_steps
        .iter()
        .any(|step| step.id == "configure-browser-explicit-proxy" && step.status == "blocked"));
    assert!(mitm
        .browser_plan
        .blocked_operations
        .iter()
        .any(|operation| operation == "install-browser-policy"));
    assert_eq!(
        mitm.policy.plugin_id,
        mitm_policy::MITM_POLICY_AD_BLOCK_PLUGIN_ID
    );
    assert!(mitm.policy.plugin_loaded);
    assert!(mitm.policy.rewrite_rule_count >= 5);
    assert!(mitm.policy.mitm_pattern_count >= 5);
    assert_gate(
        &mitm.gates,
        MITM_CLI_COMMAND_GATE,
        MITM_CLI_COMMAND_GATE_STATUS,
    );
    assert_gate(
        &mitm.gates,
        MITM_CERTIFICATE_LIFECYCLE_GATE,
        MITM_CERTIFICATE_LIFECYCLE_GATE_STATUS,
    );
    assert_gate(
        &mitm.gates,
        MITM_HTTP_TLS_DATA_PLANE_GATE,
        MITM_HTTP_TLS_DATA_PLANE_GATE_STATUS,
    );
    assert_gate(
        &mitm.gates,
        MITM_BROWSER_CAPTURE_GATE,
        MITM_BROWSER_CAPTURE_GATE_STATUS,
    );

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered.contains("mitm stage: policy-only"));
    assert!(rendered.contains("browser hijack: deferred"));
    assert!(rendered.contains("certificate plan: artifact-lifecycle-active mutation_ready=false"));
    assert!(rendered.contains("certificate step write-local-ca-artifact: active"));
    assert!(rendered.contains("browser plan: plan-only mutation_ready=false"));
    assert!(rendered.contains("browser step configure-browser-explicit-proxy: blocked"));
    assert!(rendered.contains("gate MITM_CLI_COMMAND_GATE: partial-active"));
}

#[test]
fn mitm_http_rewrite_plan_reports_live_plain_http_data_plane_without_tls_decryption() {
    let platform = StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot {
        mitm_certificate: LinuxCertificateProbe::new(CertificateTrustState::InstalledUntrusted),
        ..LinuxPlatformSnapshot::available_for_tests()
    });

    let response = handle_mitm_http_rewrite_plan(&platform);

    assert!(response.ok);
    assert_eq!(response.command, "mitm http-rewrite plan");
    assert_diagnostic(&response.diagnostics, CLI_MITM_HTTP_REWRITE_PLAN_READY_CODE);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_HTTP_REWRITE_TLS_BLOCKED_CODE,
    );
    let report = response
        .http_rewrite
        .as_ref()
        .expect("http rewrite plan should include machine report");
    assert_eq!(
        report.source_contract_status,
        MITM_HTTP_REWRITE_SOURCE_CONTRACT_STATUS
    );
    assert_eq!(report.gate, MITM_HTTP_TLS_DATA_PLANE_GATE);
    assert_eq!(report.gate_status, MITM_HTTP_TLS_DATA_PLANE_GATE_STATUS);
    assert_eq!(report.mutation_ready, MITM_HTTP_REWRITE_MUTATION_READY);
    assert_eq!(
        report.live_traffic_ready,
        MITM_HTTP_REWRITE_LIVE_TRAFFIC_READY
    );
    assert_eq!(
        report.tls_decryption_ready,
        MITM_HTTP_REWRITE_TLS_DECRYPTION_READY
    );
    assert_eq!(
        report.controlled_tls_termination_plan_ready,
        MITM_HTTP_REWRITE_CONTROLLED_TLS_TERMINATION_PLAN_READY
    );
    assert_eq!(
        report.downstream_tls_termination_plan_ready,
        MITM_HTTP_REWRITE_DOWNSTREAM_TLS_TERMINATION_PLAN_READY
    );
    assert_eq!(
        report.upstream_tls_forwarding_ready,
        MITM_HTTP_REWRITE_UPSTREAM_TLS_FORWARDING_READY
    );
    assert!(report
        .blocked_operations
        .iter()
        .any(|operation| operation == "decrypt-https"));

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered
        .contains("http rewrite plan: plain-http-live-data-plane-active/tls-decryption-blocked"));
    assert!(rendered.contains("http rewrite blocked operation: decrypt-https"));
}

#[test]
fn mitm_http_rewrite_plan_reports_controlled_tls_termination_plan_without_decryption() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_mitm_http_rewrite_plan(&platform);

    let report = response
        .http_rewrite
        .as_ref()
        .expect("http rewrite plan should include machine report");
    assert_eq!(
        report.controlled_tls_termination_plan_ready,
        MITM_HTTP_REWRITE_CONTROLLED_TLS_TERMINATION_PLAN_READY
    );
    assert_eq!(
        report.downstream_tls_termination_plan_ready,
        MITM_HTTP_REWRITE_DOWNSTREAM_TLS_TERMINATION_PLAN_READY
    );
    assert_eq!(
        report.upstream_tls_forwarding_ready,
        MITM_HTTP_REWRITE_UPSTREAM_TLS_FORWARDING_READY
    );
    assert_eq!(
        report.tls_decryption_ready,
        MITM_HTTP_REWRITE_TLS_DECRYPTION_READY
    );

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered.contains("controlled_tls_termination_plan_ready=true"));
    assert!(rendered.contains("downstream_tls_termination_plan_ready=true"));
    assert!(rendered.contains("upstream_tls_forwarding_ready=true"));
    assert!(rendered.contains("tls_decryption_ready=false"));
}

#[test]
fn mitm_http_rewrite_preview_requires_authorization_before_applying_outcome() {
    let platform = StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot {
        mitm_certificate: LinuxCertificateProbe::new(CertificateTrustState::InstalledUntrusted),
        ..LinuxPlatformSnapshot::available_for_tests()
    });

    let response = handle_mitm_http_rewrite_preview(
        &platform,
        Some("https://pubads.g.doubleclick.net/pagead/id"),
        "GET",
        "request",
        None,
        &[],
        None,
        false,
    );

    assert!(!response.ok);
    assert_eq!(response.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_HTTP_REWRITE_AUTHORIZATION_REQUIRED_CODE,
    );
    let report = response
        .http_rewrite
        .as_ref()
        .expect("authorization failure should include http rewrite report");
    assert!(report.outcome.is_none());
    assert!(
        !report
            .request
            .authorization
            .as_ref()
            .expect("authorization should be present")
            .confirmed
    );
}

#[test]
fn mitm_http_rewrite_preview_reports_https_request_preview_without_live_tls_or_script() {
    let platform = StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot {
        mitm_certificate: LinuxCertificateProbe::new(CertificateTrustState::InstalledUntrusted),
        ..LinuxPlatformSnapshot::available_for_tests()
    });
    let headers = vec!["Accept: */*".to_string()];

    let response = handle_mitm_http_rewrite_preview(
        &platform,
        Some("https://pubads.g.doubleclick.net/pagead/id"),
        "GET",
        "request",
        None,
        &headers,
        Some("from=1"),
        true,
    );

    assert!(response.ok);
    assert_eq!(response.command, "mitm http-rewrite preview");
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_HTTP_REWRITE_APPLY_READY_CODE,
    );
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_HTTP_REWRITE_TLS_BLOCKED_CODE,
    );
    let report = response
        .http_rewrite
        .as_ref()
        .expect("preview should include http rewrite report");
    assert!(report.https_request_rewrite_preview_ready);
    assert!(report.https_response_rewrite_preview_ready);
    assert!(!report.https_response_rewrite_ready);
    assert!(!report.script_dispatch_ready);
    assert!(!report.tls_decryption_ready);
    assert!(report
        .blocked_operations
        .iter()
        .any(|operation| operation == "decrypt-https"));
    assert!(report
        .blocked_operations
        .iter()
        .any(|operation| operation == "mutate-live-https-traffic"));
    let outcome = report
        .outcome
        .as_ref()
        .expect("preview should include outcome report");
    assert!(outcome.planned);
    assert!(outcome.applied);
    assert_eq!(outcome.action, "reject");
    assert_eq!(outcome.terminal_action.as_deref(), Some("reject"));
    assert_eq!(outcome.final_status_code, Some(403));
    assert_eq!(outcome.header_mutation_count, 0);
    assert!(!outcome.body_mutated);
    assert!(!outcome.script_dispatch_deferred);
    assert_eq!(
        outcome
            .output_headers
            .iter()
            .find(|header| header.name == "Content-Length")
            .map(|header| header.value.as_str()),
        Some("0")
    );
    assert!(
        report
            .request
            .authorization
            .as_ref()
            .expect("authorization should be recorded")
            .confirmed
    );
}

#[test]
fn mitm_certificate_plan_reports_artifact_lifecycle_without_trust_mutation() {
    let platform = StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot {
        mitm_certificate: LinuxCertificateProbe::new(CertificateTrustState::InstalledUntrusted)
            .with_subject("NetworkCore Test CA")
            .with_fingerprint_sha256(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
        ..LinuxPlatformSnapshot::available_for_tests()
    });

    let response = handle_mitm_certificate_plan(&platform);

    assert!(response.ok);
    assert_eq!(response.command, "mitm certificate-plan");
    assert_eq!(response.exit_code, LinuxCliExitCode::Success);
    assert_diagnostic(&response.diagnostics, CLI_MITM_CERTIFICATE_PLAN_READY_CODE);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_CERTIFICATE_MUTATION_BLOCKED_CODE,
    );
    let mitm = response
        .mitm_status
        .as_ref()
        .expect("certificate plan response should include mitm status");
    assert_eq!(mitm.certificate_state, "installed_untrusted");
    assert_eq!(mitm.certificate_plan.status, MITM_CERTIFICATE_PLAN_STATUS);
    assert!(!mitm.certificate_plan.mutation_ready);
    assert_eq!(
        mitm.certificate_plan.subject.as_deref(),
        Some("NetworkCore Test CA")
    );
    assert_eq!(
        mitm.certificate_plan.fingerprint_sha256.as_deref(),
        Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    );
    assert!(mitm
        .certificate_plan
        .required_steps
        .iter()
        .any(|step| step.id == "probe-certificate-state" && step.status == "active"));
    assert!(mitm
        .certificate_plan
        .required_steps
        .iter()
        .any(|step| step.id == "write-local-ca-artifact" && step.status == "active"));
    assert!(mitm
        .certificate_plan
        .required_steps
        .iter()
        .any(|step| step.id == "install-user-trust" && step.status == "blocked"));
    assert!(mitm
        .certificate_plan
        .blocked_operations
        .iter()
        .any(|operation| operation == "trust-ca"));

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered.contains("certificate subject: NetworkCore Test CA"));
    assert!(rendered.contains("certificate blocked operation: trust-ca"));
}

#[test]
fn mitm_certificate_apply_requires_authorization_and_config() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let missing_confirm = handle_mitm_certificate_apply(&platform, false);

    assert!(!missing_confirm.ok);
    assert_eq!(missing_confirm.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &missing_confirm.diagnostics,
        CLI_MITM_CERTIFICATE_AUTHORIZATION_REQUIRED_CODE,
    );
    let lifecycle = missing_confirm
        .certificate_lifecycle
        .as_ref()
        .expect("certificate response should include lifecycle report");
    let apply = lifecycle
        .apply_report
        .as_ref()
        .expect("certificate response should include apply report");
    assert_eq!(lifecycle.action, "apply");
    assert_eq!(
        lifecycle.gate_status,
        MITM_CERTIFICATE_LIFECYCLE_GATE_STATUS
    );
    assert_eq!(apply.status, "authorization_required");
    assert!(!apply.applied);
    assert!(!apply.authorization.confirmed);

    let config_missing = handle_mitm_certificate_apply_with_store(
        &platform,
        &TestMitmCertificateArtifactStore,
        None,
        None,
        None,
        None,
        true,
    );

    assert!(!config_missing.ok);
    assert_eq!(config_missing.exit_code, LinuxCliExitCode::ArgumentOrConfig);
    assert_diagnostic(
        &config_missing.diagnostics,
        CLI_MITM_CERTIFICATE_APPLY_CONFIG_MISSING_CODE,
    );
    let lifecycle = config_missing
        .certificate_lifecycle
        .as_ref()
        .expect("config missing response should include lifecycle report");
    let apply = lifecycle
        .apply_report
        .as_ref()
        .expect("config missing response should include apply report");
    assert_eq!(apply.status, "config_missing");
    assert!(!apply.applied);
    assert!(apply.authorization.confirmed);
}

#[test]
fn mitm_certificate_apply_with_store_writes_artifact_report() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_mitm_certificate_apply_with_store(
        &platform,
        &TestMitmCertificateArtifactStore,
        Some("/tmp/networkcore-mitm-ca.crt"),
        Some("/tmp/networkcore-mitm-ca.key"),
        None,
        Some("/tmp/networkcore-mitm-ca.snapshot.json"),
        true,
    );

    assert!(response.ok);
    assert_eq!(response.command, "mitm certificate apply");
    assert_diagnostic(&response.diagnostics, CLI_MITM_CERTIFICATE_APPLY_READY_CODE);
    let lifecycle = response
        .certificate_lifecycle
        .as_ref()
        .expect("apply response should include certificate lifecycle report");
    assert_eq!(lifecycle.action, "apply");
    assert_eq!(
        lifecycle.source_contract_status,
        MITM_CERTIFICATE_LIFECYCLE_SOURCE_CONTRACT_STATUS
    );
    assert_eq!(lifecycle.gate, MITM_CERTIFICATE_LIFECYCLE_GATE);
    assert_eq!(
        lifecycle.gate_status,
        MITM_CERTIFICATE_LIFECYCLE_GATE_STATUS
    );
    assert!(!lifecycle.mutation_ready);
    assert_eq!(lifecycle.trust_plan.status, "trust-mutation-blocked");
    let artifact = lifecycle
        .request
        .artifact
        .as_ref()
        .expect("apply response should include artifact request");
    assert_eq!(artifact.cert_file_path, "/tmp/networkcore-mitm-ca.crt");
    assert_eq!(artifact.key_file_path, "/tmp/networkcore-mitm-ca.key");
    assert_eq!(
        artifact.snapshot_path,
        "/tmp/networkcore-mitm-ca.snapshot.json"
    );
    assert_eq!(artifact.subject, MITM_CERTIFICATE_ARTIFACT_SUBJECT);
    assert!(artifact
        .cert_content
        .contains("-----BEGIN CERTIFICATE-----"));
    assert!(artifact.key_content.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(!artifact.cert_content.contains("NETWORKCORE MITM CA"));
    assert!(!artifact.key_content.contains("NETWORKCORE MITM CA"));
    let apply = lifecycle
        .apply_report
        .as_ref()
        .expect("apply response should include apply report");
    assert_eq!(apply.status, "applied");
    assert!(apply.applied);
    assert_eq!(
        apply.cert_file_path.as_deref(),
        Some("/tmp/networkcore-mitm-ca.crt")
    );
    assert_eq!(
        apply.key_file_path.as_deref(),
        Some("/tmp/networkcore-mitm-ca.key")
    );
    assert_eq!(
        apply
            .rollback_snapshot
            .as_ref()
            .expect("apply report should include rollback snapshot")
            .status,
        "networkcore-created"
    );

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered.contains("certificate lifecycle apply"));
    assert!(rendered.contains("certificate artifact file: /tmp/networkcore-mitm-ca.crt"));
    assert!(rendered.contains("certificate trust blocked operation: trust-ca"));
}

#[test]
fn mitm_certificate_command_store_writes_and_rolls_back_artifacts() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("networkcore-mitm-ca-artifact-{unique}"));
    let cert_path = root.join("networkcore-mitm-ca.crt");
    let key_path = root.join("networkcore-mitm-ca.key");
    let snapshot_path = root.join("networkcore-mitm-ca.snapshot.json");

    let apply = handle_mitm_certificate_apply_with_store(
        &platform,
        &networkcore_linux::CommandMitmCertificateArtifactStore::new(),
        Some(cert_path.to_str().expect("cert path should be UTF-8")),
        Some(key_path.to_str().expect("key path should be UTF-8")),
        None,
        Some(
            snapshot_path
                .to_str()
                .expect("snapshot path should be UTF-8"),
        ),
        true,
    );

    assert!(apply.ok);
    assert_diagnostic(&apply.diagnostics, CLI_MITM_CERTIFICATE_APPLY_READY_CODE);
    let cert_content =
        std::fs::read_to_string(&cert_path).expect("cert artifact should be written");
    let key_content = std::fs::read_to_string(&key_path).expect("key artifact should be written");
    assert!(cert_content.contains("-----BEGIN CERTIFICATE-----"));
    assert!(cert_content.contains("-----END CERTIFICATE-----"));
    assert!(key_content.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(key_content.contains("-----END PRIVATE KEY-----"));
    assert!(!cert_content.contains("trust-store-mutation: blocked"));
    assert!(!key_content.contains("https-rewrite: blocked"));
    assert!(snapshot_path.exists());

    let rollback = handle_mitm_certificate_rollback_with_store(
        &platform,
        &networkcore_linux::CommandMitmCertificateArtifactStore::new(),
        Some(
            snapshot_path
                .to_str()
                .expect("snapshot path should be UTF-8")
                .to_string(),
        ),
    );

    assert!(rollback.ok);
    assert_diagnostic(
        &rollback.diagnostics,
        CLI_MITM_CERTIFICATE_ROLLBACK_READY_CODE,
    );
    assert!(!cert_path.exists());
    assert!(!key_path.exists());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn mitm_certificate_command_store_writes_and_rolls_back_profile_trust_artifact() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let root =
        std::env::temp_dir().join(format!("networkcore-mitm-profile-trust-artifact-{unique}"));
    let cert_path = root.join("networkcore-mitm-ca.crt");
    let key_path = root.join("networkcore-mitm-ca.key");
    let profile_trust_path = root.join("dedicated-profile-ca-trust.pem");
    let snapshot_path = root.join("networkcore-mitm-ca.snapshot.json");

    let apply = handle_mitm_certificate_apply_with_store(
        &platform,
        &networkcore_linux::CommandMitmCertificateArtifactStore::new(),
        Some(cert_path.to_str().expect("cert path should be UTF-8")),
        Some(key_path.to_str().expect("key path should be UTF-8")),
        Some(
            profile_trust_path
                .to_str()
                .expect("profile trust path should be UTF-8"),
        ),
        Some(
            snapshot_path
                .to_str()
                .expect("snapshot path should be UTF-8"),
        ),
        true,
    );

    assert!(apply.ok);
    assert_diagnostic(&apply.diagnostics, CLI_MITM_CERTIFICATE_APPLY_READY_CODE);
    let lifecycle = apply
        .certificate_lifecycle
        .as_ref()
        .expect("apply response should include certificate lifecycle");
    let artifact = lifecycle
        .request
        .artifact
        .as_ref()
        .expect("apply request should include certificate artifact");
    assert_eq!(
        artifact.profile_trust_file_path.as_deref(),
        Some(
            profile_trust_path
                .to_str()
                .expect("profile trust path should be UTF-8")
        )
    );
    assert!(artifact
        .profile_trust_content
        .as_ref()
        .expect("profile trust content should be recorded")
        .contains("-----BEGIN CERTIFICATE-----"));
    assert_eq!(
        artifact.profile_trust_content.as_deref(),
        Some(artifact.cert_content.as_str())
    );
    assert_eq!(
        artifact.profile_trust_fingerprint.as_deref(),
        Some(artifact.cert_fingerprint.as_str())
    );
    assert_ne!(
        artifact.profile_trust_fingerprint.as_deref(),
        Some(artifact.key_fingerprint.as_str())
    );
    assert!(artifact.profile_trust_fingerprint.is_some());
    let apply_report = lifecycle
        .apply_report
        .as_ref()
        .expect("apply response should include apply report");
    assert_eq!(
        apply_report.profile_trust_file_path.as_deref(),
        Some(
            profile_trust_path
                .to_str()
                .expect("profile trust path should be UTF-8")
        )
    );

    let profile_trust_content = std::fs::read_to_string(&profile_trust_path)
        .expect("profile trust artifact should be written");
    let cert_content =
        std::fs::read_to_string(&cert_path).expect("cert artifact should be written");
    let key_content = std::fs::read_to_string(&key_path).expect("key artifact should be written");
    assert_eq!(profile_trust_content, cert_content);
    assert!(profile_trust_content.contains("-----BEGIN CERTIFICATE-----"));
    assert!(!profile_trust_content.contains("-----BEGIN PRIVATE KEY-----"));
    assert_ne!(profile_trust_content, key_content);
    assert!(snapshot_path.exists());

    let rendered = render_response(&apply, OutputFormat::Text);
    assert!(rendered.contains("certificate dedicated profile trust artifact file:"));

    let rollback = handle_mitm_certificate_rollback_with_store(
        &platform,
        &networkcore_linux::CommandMitmCertificateArtifactStore::new(),
        Some(
            snapshot_path
                .to_str()
                .expect("snapshot path should be UTF-8")
                .to_string(),
        ),
    );

    assert!(rollback.ok);
    assert_diagnostic(
        &rollback.diagnostics,
        CLI_MITM_CERTIFICATE_ROLLBACK_READY_CODE,
    );
    let rollback_lifecycle = rollback
        .certificate_lifecycle
        .as_ref()
        .expect("rollback response should include certificate lifecycle");
    let rollback_report = rollback_lifecycle
        .rollback_report
        .as_ref()
        .expect("rollback response should include rollback report");
    assert_eq!(
        rollback_report.profile_trust_file_path.as_deref(),
        Some(
            profile_trust_path
                .to_str()
                .expect("profile trust path should be UTF-8")
        )
    );
    assert!(!cert_path.exists());
    assert!(!key_path.exists());
    assert!(!profile_trust_path.exists());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn mitm_certificate_apply_writes_tls_usable_ca_pem_without_trust_store_mutation() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("networkcore-mitm-ca-pem-{unique}"));
    let cert_path = root.join("networkcore-mitm-ca.pem");
    let key_path = root.join("networkcore-mitm-ca.key.pem");
    let profile_trust_path = root.join("dedicated-profile-ca.pem");
    let snapshot_path = root.join("networkcore-mitm-ca.snapshot.json");

    let response = handle_mitm_certificate_apply_with_store(
        &platform,
        &networkcore_linux::CommandMitmCertificateArtifactStore::new(),
        Some(cert_path.to_str().expect("cert path should be UTF-8")),
        Some(key_path.to_str().expect("key path should be UTF-8")),
        Some(
            profile_trust_path
                .to_str()
                .expect("profile trust path should be UTF-8"),
        ),
        Some(
            snapshot_path
                .to_str()
                .expect("snapshot path should be UTF-8"),
        ),
        true,
    );

    assert!(response.ok);
    let lifecycle = response
        .certificate_lifecycle
        .as_ref()
        .expect("apply response should include certificate lifecycle");
    assert_eq!(lifecycle.trust_plan.status, "trust-mutation-blocked");
    assert!(!lifecycle.trust_plan.mutation_ready);
    assert!(lifecycle
        .trust_plan
        .blocked_operations
        .iter()
        .any(|operation| operation == "update-ca-certificates"));
    assert!(lifecycle
        .trust_plan
        .blocked_operations
        .iter()
        .any(|operation| operation == "mutate-firefox-trust-store"));
    let artifact = lifecycle
        .request
        .artifact
        .as_ref()
        .expect("apply request should include certificate artifact");
    assert_eq!(artifact.artifact_version, 2);
    assert!(artifact
        .cert_content
        .contains("-----BEGIN CERTIFICATE-----"));
    assert!(artifact.cert_content.contains("-----END CERTIFICATE-----"));
    assert!(artifact.key_content.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(artifact.key_content.contains("-----END PRIVATE KEY-----"));
    assert!(!artifact.cert_content.contains("NETWORKCORE MITM CA"));
    assert!(!artifact.key_content.contains("NETWORKCORE MITM CA"));
    assert!(!artifact.cert_content.contains("trust-store-mutation:"));
    assert!(!artifact.key_content.contains("https-rewrite:"));
    assert_eq!(
        artifact.profile_trust_content.as_deref(),
        Some(artifact.cert_content.as_str())
    );
    assert_eq!(
        artifact.profile_trust_fingerprint.as_deref(),
        Some(artifact.cert_fingerprint.as_str())
    );
    assert_ne!(
        artifact.profile_trust_fingerprint.as_deref(),
        Some(artifact.key_fingerprint.as_str())
    );

    let cert_content =
        std::fs::read_to_string(&cert_path).expect("CA certificate PEM should be written");
    let key_content =
        std::fs::read_to_string(&key_path).expect("CA private key PEM should be written");
    let profile_trust_content = std::fs::read_to_string(&profile_trust_path)
        .expect("profile trust CA PEM copy should be written");
    assert_eq!(cert_content, artifact.cert_content);
    assert_eq!(key_content, artifact.key_content);
    assert_eq!(profile_trust_content, cert_content);
    assert!(!profile_trust_content.contains("-----BEGIN PRIVATE KEY-----"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn mitm_certificate_command_store_rejects_profile_trust_private_key_material() {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("networkcore-mitm-profile-invariant-{unique}"));
    let cert_path = root.join("networkcore-mitm-ca.pem");
    let key_path = root.join("networkcore-mitm-ca.key.pem");
    let profile_trust_path = root.join("dedicated-profile-ca.pem");
    let snapshot_path = root.join("networkcore-mitm-ca.snapshot.json");
    let cert_content =
        "-----BEGIN CERTIFICATE-----\nnetworkcore-test-ca\n-----END CERTIFICATE-----\n".to_string();
    let key_content =
        "-----BEGIN PRIVATE KEY-----\nnetworkcore-test-key\n-----END PRIVATE KEY-----\n"
            .to_string();
    let request = LinuxMitmCertificateArtifactRequest {
        cert_file_path: cert_path
            .to_str()
            .expect("cert path should be UTF-8")
            .to_string(),
        key_file_path: key_path
            .to_str()
            .expect("key path should be UTF-8")
            .to_string(),
        profile_trust_file_path: Some(
            profile_trust_path
                .to_str()
                .expect("profile trust path should be UTF-8")
                .to_string(),
        ),
        snapshot_path: snapshot_path
            .to_str()
            .expect("snapshot path should be UTF-8")
            .to_string(),
        subject: MITM_CERTIFICATE_ARTIFACT_SUBJECT.to_string(),
        artifact_version: 2,
        cert_content: cert_content.clone(),
        key_content: key_content.clone(),
        profile_trust_content: Some(format!("{cert_content}{key_content}")),
        cert_fingerprint: "cert-fingerprint".to_string(),
        key_fingerprint: "key-fingerprint".to_string(),
        profile_trust_fingerprint: Some("cert-fingerprint".to_string()),
    };

    let error = networkcore_linux::CommandMitmCertificateArtifactStore::new()
        .apply_certificate_artifact(&request)
        .expect_err("profile trust CA PEM copy must reject private key material");

    assert_eq!(error.code, CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE);
    assert!(error
        .message
        .contains("must not contain private key material"));
    assert!(!cert_path.exists());
    assert!(!key_path.exists());
    assert!(!profile_trust_path.exists());
    assert!(!snapshot_path.exists());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn mitm_certificate_rollback_with_store_restores_artifact_report() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_mitm_certificate_rollback_with_store(
        &platform,
        &TestMitmCertificateArtifactStore,
        Some("/tmp/networkcore-mitm-ca.snapshot.json".to_string()),
    );

    assert!(response.ok);
    assert_eq!(response.command, "mitm certificate rollback");
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_CERTIFICATE_ROLLBACK_READY_CODE,
    );
    let lifecycle = response
        .certificate_lifecycle
        .as_ref()
        .expect("rollback response should include lifecycle report");
    let rollback = lifecycle
        .rollback_report
        .as_ref()
        .expect("rollback response should include rollback report");
    assert_eq!(lifecycle.action, "rollback");
    assert_eq!(rollback.status, "rolled_back");
    assert!(rollback.rolled_back);
    assert_eq!(
        rollback.cert_file_path.as_deref(),
        Some("/tmp/networkcore-mitm-ca.crt")
    );
    assert_eq!(
        rollback.key_file_path.as_deref(),
        Some("/tmp/networkcore-mitm-ca.key")
    );
    assert_eq!(
        rollback
            .rollback_snapshot
            .as_ref()
            .expect("rollback report should include snapshot")
            .status,
        "networkcore-restored"
    );

    let blocked = handle_mitm_certificate_rollback(&platform, None);
    assert!(!blocked.ok);
    assert_eq!(blocked.exit_code, LinuxCliExitCode::ArgumentOrConfig);
    assert_diagnostic(
        &blocked.diagnostics,
        CLI_MITM_CERTIFICATE_ROLLBACK_BLOCKED_CODE,
    );
}

#[test]
fn mitm_browser_plan_reports_capture_plan_without_mutation() {
    let platform = StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot {
        mitm_certificate: LinuxCertificateProbe::new(CertificateTrustState::Trusted),
        ..LinuxPlatformSnapshot::available_for_tests()
    });

    let response = handle_mitm_browser_plan(&platform);

    assert!(response.ok);
    assert_eq!(response.command, "mitm browser-plan");
    assert_eq!(response.exit_code, LinuxCliExitCode::Success);
    assert_diagnostic(&response.diagnostics, CLI_MITM_BROWSER_PLAN_READY_CODE);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_MUTATION_BLOCKED_CODE,
    );
    let mitm = response
        .mitm_status
        .as_ref()
        .expect("browser plan response should include mitm status");
    assert_eq!(mitm.browser_plan.status, MITM_BROWSER_PLAN_STATUS);
    assert!(!mitm.browser_plan.mutation_ready);
    assert_eq!(mitm.browser_plan.current_capture, "not_configured");
    assert_eq!(
        mitm.browser_plan.planned_capture_mode,
        MITM_BROWSER_CAPTURE_MODE
    );
    assert_eq!(
        mitm.browser_plan.planned_proxy_host,
        MITM_BROWSER_CAPTURE_PROXY_HOST
    );
    assert_eq!(
        mitm.browser_plan.planned_proxy_port,
        MITM_BROWSER_CAPTURE_PROXY_PORT
    );
    assert!(mitm
        .browser_plan
        .required_steps
        .iter()
        .any(|step| step.id == "verify-certificate-trust" && step.status == "satisfied"));
    assert!(mitm
        .browser_plan
        .required_steps
        .iter()
        .any(|step| step.id == "start-http-tls-mitm-proxy" && step.status == "blocked"));
    assert!(mitm
        .browser_plan
        .blocked_operations
        .iter()
        .any(|operation| operation == "write-system-proxy"));

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered.contains("browser planned proxy: 127.0.0.1:7890"));
    assert!(rendered.contains("browser blocked operation: write-system-proxy"));
}

#[test]
fn mitm_browser_capture_plan_outputs_source_contract_report_without_mutation() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_mitm_browser_capture_plan(&platform);

    assert!(response.ok);
    assert_eq!(response.command, "mitm browser-capture plan");
    assert_eq!(response.exit_code, LinuxCliExitCode::Success);
    assert_diagnostic(&response.diagnostics, CLI_MITM_BROWSER_PLAN_READY_CODE);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_MUTATION_BLOCKED_CODE,
    );

    let capture = response
        .browser_capture
        .as_ref()
        .expect("browser capture plan should include a report");
    assert_eq!(capture.action, "plan");
    assert_eq!(
        capture.source_contract_status,
        MITM_BROWSER_CAPTURE_SOURCE_CONTRACT_STATUS
    );
    assert_eq!(capture.gate, MITM_BROWSER_CAPTURE_GATE);
    assert_eq!(capture.gate_status, MITM_BROWSER_CAPTURE_GATE_STATUS);
    assert!(!capture.mutation_ready);
    assert_eq!(
        capture.plan.planned_proxy_host,
        MITM_BROWSER_CAPTURE_PROXY_HOST
    );
    assert_eq!(
        capture.plan.planned_proxy_port,
        MITM_BROWSER_CAPTURE_PROXY_PORT
    );
    assert!(capture.apply_report.is_none());
    assert!(capture.rollback_report.is_none());
    assert!(capture.verify_report.is_none());

    let rendered = render_response(&response, OutputFormat::Text);
    let expected_plan_line = format!("browser capture plan: {MITM_BROWSER_CAPTURE_GATE_STATUS}");
    assert!(rendered.contains(&expected_plan_line));
    assert!(rendered.contains("browser capture source contract: active"));
}

#[test]
fn mitm_browser_capture_launch_plan_outputs_manual_browser_commands_without_mutation() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_mitm_browser_capture_launch_plan(&platform);

    assert!(response.ok);
    assert_eq!(response.command, "mitm browser-capture launch-plan");
    assert_eq!(response.exit_code, LinuxCliExitCode::Success);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_LAUNCH_PLAN_READY_CODE,
    );
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_MUTATION_BLOCKED_CODE,
    );

    let capture = response
        .browser_capture
        .as_ref()
        .expect("launch-plan response should include browser capture report");
    assert_eq!(capture.action, "launch-plan");
    assert_eq!(
        capture.plan.manual_launch.status,
        "manual-launch-plan-ready"
    );
    assert_eq!(
        capture.plan.manual_launch.proxy_url,
        "http://127.0.0.1:7890"
    );
    assert_eq!(
        capture.plan.manual_launch.plugin_id,
        mitm_policy::MITM_POLICY_AD_BLOCK_PLUGIN_ID
    );
    assert!(capture
        .plan
        .manual_launch
        .browser_commands
        .iter()
        .any(|command| command.browser == "chromium"
            && command
                .command
                .contains("--proxy-server=http://127.0.0.1:7890")));
    assert!(capture.apply_report.is_none());
    assert!(capture.rollback_report.is_none());
    assert!(capture.verify_report.is_none());

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered.contains("browser capture manual launch: manual-launch-plan-ready"));
    assert!(rendered.contains("browser launch command chromium: chromium"));
}

#[test]
fn mitm_browser_capture_session_plan_links_proxy_browser_and_plugin_without_mutation() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_mitm_browser_capture_session_plan(
        &platform,
        "ss://YWVzLTI1Ni1nY206ZjQzYzBlZWUtMTNiOS00ZjA3LWJlYzktZDRiNzQ0MTQxNTAz@82.47.34.99:11111#%E9%A6%99%E6%B8%AF",
        "google-chrome",
        "/tmp/networkcore-browser-capture-contract-profile",
        Some("https://example.com/capture"),
        Some("browser-proof-123"),
        Some("/tmp/networkcore-browser-proof.log"),
        "127.0.0.1",
        7891,
    );

    assert!(response.ok);
    assert_eq!(response.command, "mitm browser-capture session-plan");
    assert_eq!(response.exit_code, LinuxCliExitCode::Success);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_READY_CODE,
    );
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_MUTATION_BLOCKED_CODE,
    );

    let capture = response
        .browser_capture
        .as_ref()
        .expect("session-plan response should include browser capture report");
    assert_eq!(capture.action, "session-plan");
    assert!(capture.apply_report.is_none());
    assert!(capture.rollback_report.is_none());
    assert!(capture.verify_report.is_none());
    assert_eq!(capture.plan.planned_proxy_host, "127.0.0.1");
    assert_eq!(capture.plan.planned_proxy_port, 7891);

    let request = capture
        .request
        .session
        .as_ref()
        .expect("session-plan request should be present");
    assert_eq!(request.url_source, "cli-argument-redacted");
    assert_eq!(request.browser, "google-chrome");
    assert_eq!(
        request.profile_dir,
        "/tmp/networkcore-browser-capture-contract-profile"
    );
    assert_eq!(
        request.target_url.as_deref(),
        Some("https://example.com/capture")
    );
    assert_eq!(
        request.proof_target_url.as_deref(),
        Some("https://example.com/capture?networkcore_proof_token=browser-proof-123")
    );
    assert_eq!(request.proof_token, "browser-proof-123");
    assert_eq!(request.proof_log_path, "/tmp/networkcore-browser-proof.log");
    assert_eq!(request.listen_port, 7891);
    assert!(capture.request.launch.is_some());
    assert!(capture.request.verify.is_some());
    assert!(capture.request.traffic_proof.is_some());

    let session = capture
        .session_plan
        .as_ref()
        .expect("session-plan report should be present");
    assert_eq!(session.status, "ready");
    assert_eq!(session.url_source, "cli-argument-redacted");
    assert_eq!(session.node_id, "ss-82-47-34-99-11111");
    assert_eq!(session.node_name, "香港");
    assert_eq!(session.proxy_url, "http://127.0.0.1:7891");
    assert!(session
        .run_command
        .contains("networkcore-linux run-url <subscription-url>"));
    assert_eq!(session.browser_command.executable, "google-chrome");
    assert_eq!(
        session.target_url.as_deref(),
        Some("https://example.com/capture")
    );
    assert_eq!(
        session.proof_target_url.as_deref(),
        Some("https://example.com/capture?networkcore_proof_token=browser-proof-123")
    );
    assert_eq!(session.proof_token, "browser-proof-123");
    assert_eq!(session.proof_log_path, "/tmp/networkcore-browser-proof.log");
    assert!(session
        .browser_command
        .args
        .contains(&"--proxy-server=http://127.0.0.1:7891".to_string()));
    assert!(session.browser_command.args.contains(
        &"https://example.com/capture?networkcore_proof_token=browser-proof-123".to_string()
    ));
    assert!(session
        .verify_command
        .contains("--target-url https://example.com/capture"));
    assert!(session
        .traffic_proof_command
        .contains("--proof-token browser-proof-123"));
    assert!(session
        .traffic_proof_command
        .contains("--proof-log /tmp/networkcore-browser-proof.log"));
    assert_eq!(
        capture
            .request
            .verify
            .as_ref()
            .expect("session-plan verify request should be present")
            .target_url
            .as_deref(),
        Some("https://example.com/capture")
    );
    assert_eq!(
        session.plugin_id,
        mitm_policy::MITM_POLICY_AD_BLOCK_PLUGIN_ID
    );
    assert!(session
        .required_steps
        .iter()
        .any(|step| step.contains("start the local proxy with run-url")));
    assert!(session
        .blocked_operations
        .iter()
        .any(|operation| operation == "write-system-proxy"));

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered.contains("browser capture session plan: ready node=香港"));
    assert!(rendered.contains("browser capture session local proxy: 127.0.0.1:7891"));
    assert!(rendered.contains("browser capture session target URL: https://example.com/capture"));
    assert!(rendered.contains(
        "browser capture session proof target URL: https://example.com/capture?networkcore_proof_token=browser-proof-123"
    ));
    assert!(rendered.contains("browser capture session traffic-proof command:"));
    assert!(rendered.contains("browser capture session browser command: google-chrome"));
}

#[test]
fn mitm_browser_capture_session_plan_can_target_native_socks5_mitm_hook() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_mitm_browser_capture_session_plan_with_proxy_scheme(
        &platform,
        "ss://YWVzLTI1Ni1nY206ZjQzYzBlZWUtMTNiOS00ZjA3LWJlYzktZDRiNzQ0MTQxNTAz@82.47.34.99:11111#%E9%A6%99%E6%B8%AF",
        "chromium",
        MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR,
        Some("https://example.com/capture"),
        Some("browser-proof-123"),
        Some("/tmp/networkcore-browser-proof.log"),
        MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME,
        "127.0.0.1",
        7890,
    );

    assert!(response.ok);
    let capture = response
        .browser_capture
        .as_ref()
        .expect("session-plan response should include browser capture report");
    assert_eq!(
        capture.plan.planned_proxy_scheme,
        MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME
    );
    let session = capture
        .session_plan
        .as_ref()
        .expect("session-plan report should be present");
    assert_eq!(
        session.proxy_scheme,
        MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME
    );
    assert_eq!(session.proxy_url, "socks5://127.0.0.1:7890");
    assert!(session
        .browser_command
        .args
        .contains(&"--proxy-server=socks5://127.0.0.1:7890".to_string()));
    assert!(session.verify_command.contains("--proxy-scheme socks5"));
    assert!(session
        .traffic_proof_command
        .contains("--proxy-scheme socks5"));

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered.contains("browser capture planned proxy scheme: socks5"));
    assert!(rendered.contains("browser capture session proxy scheme: socks5"));
    assert!(rendered.contains("--proxy-server=socks5://127.0.0.1:7890"));
}

#[test]
fn mitm_browser_capture_launch_requires_confirmation_before_starting_browser() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let runner = TestBrowserCaptureRunner;

    let response = handle_mitm_browser_capture_launch(
        &platform,
        &runner,
        "chromium",
        MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR,
        None,
        None,
        None,
        false,
    );

    assert!(!response.ok);
    assert_eq!(response.command, "mitm browser-capture launch");
    assert_eq!(response.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_LAUNCH_AUTHORIZATION_REQUIRED_CODE,
    );
    assert_no_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_LAUNCH_STARTED_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("launch response should include browser capture report");
    assert_eq!(capture.action, "launch");
    let launch = capture
        .launch_report
        .as_ref()
        .expect("launch response should include a launch report");
    assert_eq!(launch.status, "authorization_required");
    assert!(!launch.launched);
    assert_eq!(launch.request.browser, "chromium");
    assert_eq!(
        launch.request.profile_dir,
        MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR
    );
}

#[test]
fn mitm_browser_capture_launch_uses_injected_runner_with_dedicated_profile() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let runner = TestBrowserCaptureRunner;

    let response = handle_mitm_browser_capture_launch(
        &platform,
        &runner,
        "google-chrome",
        "/tmp/networkcore-browser-capture-contract-profile",
        Some("https://example.com/capture"),
        Some("browser-proof-123"),
        Some("/tmp/networkcore-browser-proof.log"),
        true,
    );

    assert!(response.ok);
    assert_eq!(response.command, "mitm browser-capture launch");
    assert_eq!(response.exit_code, LinuxCliExitCode::Success);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_LAUNCH_STARTED_CODE,
    );
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_MUTATION_BLOCKED_CODE,
    );

    let capture = response
        .browser_capture
        .as_ref()
        .expect("launch response should include browser capture report");
    assert_eq!(capture.action, "launch");
    let launch = capture
        .launch_report
        .as_ref()
        .expect("launch response should include a launch report");
    assert_eq!(launch.status, "started");
    assert!(launch.launched);
    assert_eq!(launch.pid, Some(4242));
    assert_eq!(launch.request.command.executable, "google-chrome");
    assert_eq!(
        launch.request.target_url.as_deref(),
        Some("https://example.com/capture")
    );
    assert_eq!(
        launch.request.proof_target_url.as_deref(),
        Some("https://example.com/capture?networkcore_proof_token=browser-proof-123")
    );
    assert_eq!(launch.request.proof_token, "browser-proof-123");
    assert_eq!(
        launch.request.proof_log_path,
        "/tmp/networkcore-browser-proof.log"
    );
    assert!(launch
        .request
        .traffic_proof_command
        .contains("--proof-token browser-proof-123"));
    assert!(launch.request.command.args.contains(
        &"--user-data-dir=/tmp/networkcore-browser-capture-contract-profile".to_string()
    ));
    assert!(launch
        .request
        .command
        .args
        .contains(&"--proxy-server=http://127.0.0.1:7890".to_string()));
    assert!(launch.request.command.args.contains(
        &"https://example.com/capture?networkcore_proof_token=browser-proof-123".to_string()
    ));
    assert_eq!(
        capture
            .request
            .traffic_proof
            .as_ref()
            .expect("launch response should include a traffic proof request")
            .proof_token,
        "browser-proof-123"
    );
    assert_eq!(
        launch.plugin_id,
        mitm_policy::MITM_POLICY_AD_BLOCK_PLUGIN_ID
    );

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered.contains("browser capture launch: started launched=true pid=4242"));
    assert!(rendered.contains("browser capture launch target URL: https://example.com/capture"));
    assert!(rendered.contains(
        "browser capture launch proof target URL: https://example.com/capture?networkcore_proof_token=browser-proof-123"
    ));
    assert!(rendered.contains("browser capture launch traffic-proof command:"));
    assert!(rendered.contains("browser capture launch command: google-chrome"));
}

#[test]
fn mitm_browser_capture_launch_can_use_native_socks5_proxy_scheme() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let runner = TestSocks5BrowserCaptureRunner;

    let response = handle_mitm_browser_capture_launch_with_proxy_scheme(
        &platform,
        &runner,
        "chromium",
        MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR,
        Some("https://example.com/capture"),
        Some("browser-proof-123"),
        Some("/tmp/networkcore-browser-proof.log"),
        MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME,
        true,
    );

    assert!(response.ok);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_LAUNCH_STARTED_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("launch response should include browser capture report");
    let launch = capture
        .launch_report
        .as_ref()
        .expect("launch response should include a launch report");
    assert_eq!(launch.pid, Some(5252));
    assert_eq!(
        launch.request.proxy_scheme,
        MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME
    );
    assert_eq!(launch.request.proxy_url, "socks5://127.0.0.1:7890");
    assert!(launch
        .request
        .command
        .args
        .contains(&"--proxy-server=socks5://127.0.0.1:7890".to_string()));
    assert!(launch
        .request
        .traffic_proof_command
        .contains("--proxy-scheme socks5"));
}

#[test]
fn mitm_browser_capture_verify_requires_confirmation_before_probe() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let probe = TestBrowserCaptureEndpointProbe { reachable: true };

    let response = handle_mitm_browser_capture_verify_with_probe(&platform, &probe, None, false);

    assert!(!response.ok);
    assert_eq!(response.command, "mitm browser-capture verify");
    assert_eq!(response.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_VERIFY_AUTHORIZATION_REQUIRED_CODE,
    );
    assert_no_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_REACHABLE_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("verify response should include browser capture report");
    let verify = capture
        .verify_report
        .as_ref()
        .expect("verify response should include verify report");
    assert_eq!(capture.action, "verify");
    assert_eq!(verify.status, "authorization_required");
    assert!(!verify.verified);
    assert_eq!(verify.request.proxy_url, "http://127.0.0.1:7890");
    assert_eq!(
        verify.plugin_id,
        mitm_policy::MITM_POLICY_AD_BLOCK_PLUGIN_ID
    );
}

#[test]
fn mitm_browser_capture_verify_uses_injected_endpoint_probe() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let probe = TestBrowserCaptureEndpointProbe { reachable: true };

    let response = handle_mitm_browser_capture_verify_with_probe(
        &platform,
        &probe,
        Some("https://example.com/capture"),
        true,
    );

    assert!(response.ok);
    assert_eq!(response.command, "mitm browser-capture verify");
    assert_eq!(response.exit_code, LinuxCliExitCode::Success);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_REACHABLE_CODE,
    );
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_MUTATION_BLOCKED_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("verify response should include browser capture report");
    let verify = capture
        .verify_report
        .as_ref()
        .expect("verify response should include verify report");
    assert_eq!(capture.action, "verify");
    assert_eq!(verify.status, "target_reachable");
    assert!(verify.verified);
    assert_eq!(verify.request.proxy_host, MITM_BROWSER_CAPTURE_PROXY_HOST);
    assert_eq!(verify.request.proxy_port, MITM_BROWSER_CAPTURE_PROXY_PORT);
    assert_eq!(
        verify.request.target_url.as_deref(),
        Some("https://example.com/capture")
    );
    assert_eq!(verify.request.probe, "http-connect-target");

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered.contains(
        "browser capture verify: target_reachable verified=true proxy=http://127.0.0.1:7890"
    ));
    assert!(rendered.contains("browser capture verify target URL: https://example.com/capture"));
}

#[test]
fn mitm_browser_capture_verify_rejects_invalid_target_url_before_proxy_probe() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let probe = CommandBrowserCaptureEndpointProbe::new();

    let response = handle_mitm_browser_capture_verify_with_probe(
        &platform,
        &probe,
        Some("ftp://example.com/capture"),
        true,
    );

    assert!(!response.ok);
    assert_eq!(response.command, "mitm browser-capture verify");
    assert_eq!(response.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
    );
    assert_no_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("verify response should include browser capture report");
    let verify = capture
        .verify_report
        .as_ref()
        .expect("verify response should include verify report");
    assert_eq!(verify.status, "target_invalid");
    assert!(!verify.verified);
    assert_eq!(verify.request.probe, "http-connect-target");
    assert_eq!(
        verify.request.target_url.as_deref(),
        Some("ftp://example.com/capture")
    );
}

#[test]
fn mitm_browser_capture_verify_reports_unreachable_proxy_endpoint() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let probe = TestBrowserCaptureEndpointProbe { reachable: false };

    let response = handle_mitm_browser_capture_verify_with_probe(&platform, &probe, None, true);

    assert!(!response.ok);
    assert_eq!(response.command, "mitm browser-capture verify");
    assert_eq!(response.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("verify response should include browser capture report");
    let verify = capture
        .verify_report
        .as_ref()
        .expect("verify response should include verify report");
    assert_eq!(verify.status, "proxy_unreachable");
    assert!(!verify.verified);
    assert_eq!(verify.request.proxy_url, "http://127.0.0.1:7890");
}

#[test]
fn mitm_browser_capture_traffic_proof_requires_confirmation_before_reading_evidence() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let probe = TestBrowserCaptureTrafficProofProbe { observed: true };

    let response = handle_mitm_browser_capture_traffic_proof_with_probe(
        &platform,
        &probe,
        None,
        Some("browser-proof-123"),
        Some("/tmp/networkcore-browser-proof.log"),
        false,
    );

    assert!(!response.ok);
    assert_eq!(response.command, "mitm browser-capture traffic-proof");
    assert_eq!(response.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_AUTHORIZATION_REQUIRED_CODE,
    );
    assert_no_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_OBSERVED_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("traffic-proof response should include browser capture report");
    assert_eq!(capture.action, "traffic-proof");
    let proof = capture
        .traffic_proof_report
        .as_ref()
        .expect("traffic-proof response should include proof report");
    assert_eq!(proof.status, "authorization_required");
    assert!(!proof.proven);
    assert_eq!(proof.request.proxy_url, "http://127.0.0.1:7890");
    assert_eq!(proof.request.proof_token, "browser-proof-123");
    assert_eq!(
        proof.request.proof_log_path,
        "/tmp/networkcore-browser-proof.log"
    );
    assert_eq!(proof.request.probe, "proof-log-token");
}

#[test]
fn mitm_browser_capture_traffic_proof_uses_injected_probe_for_observed_token() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let probe = TestBrowserCaptureTrafficProofProbe { observed: true };

    let response = handle_mitm_browser_capture_traffic_proof_with_probe(
        &platform,
        &probe,
        None,
        Some("browser-proof-123"),
        Some("/tmp/networkcore-browser-proof.log"),
        true,
    );

    assert!(response.ok);
    assert_eq!(response.command, "mitm browser-capture traffic-proof");
    assert_eq!(response.exit_code, LinuxCliExitCode::Success);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_OBSERVED_CODE,
    );
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_MUTATION_BLOCKED_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("traffic-proof response should include browser capture report");
    let proof = capture
        .traffic_proof_report
        .as_ref()
        .expect("traffic-proof response should include proof report");
    assert_eq!(capture.action, "traffic-proof");
    assert_eq!(proof.status, "observed");
    assert!(proof.proven);
    assert_eq!(proof.request.proxy_host, MITM_BROWSER_CAPTURE_PROXY_HOST);
    assert_eq!(proof.request.proxy_port, MITM_BROWSER_CAPTURE_PROXY_PORT);
    assert_eq!(proof.request.proxy_url, "http://127.0.0.1:7890");
    assert!(proof.request.target_url.is_none());
    assert!(proof.request.proof_target_url.is_none());
    assert_eq!(proof.request.probe, "proof-log-token");
    assert_eq!(proof.plugin_id, mitm_policy::MITM_POLICY_AD_BLOCK_PLUGIN_ID);

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered.contains(
        "browser capture traffic proof: observed proven=true proxy=http://127.0.0.1:7890"
    ));
    assert!(rendered.contains("proof_log=/tmp/networkcore-browser-proof.log"));
}

#[test]
fn mitm_browser_capture_traffic_proof_defaults_to_session_proof_binding() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let probe = TestBrowserCaptureTrafficProofProbe { observed: true };

    let response = handle_mitm_browser_capture_traffic_proof_with_probe(
        &platform,
        &probe,
        Some("https://example.com/capture"),
        None,
        None,
        true,
    );

    assert!(response.ok);
    assert_eq!(response.command, "mitm browser-capture traffic-proof");
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_OBSERVED_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("traffic-proof response should include browser capture report");
    let proof = capture
        .traffic_proof_report
        .as_ref()
        .expect("traffic-proof response should include proof report");
    assert_eq!(proof.status, "observed");
    assert!(proof.proven);
    assert_eq!(
        proof.request.target_url.as_deref(),
        Some("https://example.com/capture")
    );
    assert!(proof
        .request
        .proof_token
        .starts_with("networkcore-browser-proof-"));
    let expected_proof_url = format!(
        "https://example.com/capture?{}={}",
        MITM_BROWSER_CAPTURE_PROOF_QUERY_PARAM, proof.request.proof_token
    );
    assert_eq!(
        proof.request.proof_target_url.as_deref(),
        Some(expected_proof_url.as_str())
    );
    assert_eq!(
        proof.request.proof_log_path,
        MITM_BROWSER_CAPTURE_DEFAULT_PROOF_LOG_PATH
    );

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(
        rendered.contains("browser capture traffic proof target URL: https://example.com/capture")
    );
    assert!(rendered.contains(&format!(
        "browser capture traffic proof target proof URL: {expected_proof_url}"
    )));
    assert!(rendered.contains("browser capture traffic proof token: networkcore-browser-proof-"));
}

#[test]
fn mitm_browser_capture_traffic_proof_text_output_includes_connect_authority() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let probe = TestBrowserCaptureTrafficProofProbe { observed: true };

    let response = handle_mitm_browser_capture_traffic_proof_with_probe(
        &platform,
        &probe,
        Some("https://example.com/capture"),
        Some("browser-proof-123"),
        Some("/tmp/networkcore-browser-proof.log"),
        true,
    );

    assert!(response.ok);
    let capture = response
        .browser_capture
        .as_ref()
        .expect("traffic-proof response should include browser capture report");
    let proof = capture
        .traffic_proof_report
        .as_ref()
        .expect("traffic-proof response should include proof report");
    assert_eq!(
        proof.request.proof_connect_authority.as_deref(),
        Some("example.com:443")
    );

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered.contains("browser capture traffic proof CONNECT authority: example.com:443"));
}

#[test]
fn mitm_browser_capture_traffic_proof_requires_bound_proxy_and_connect_authority() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let probe = CommandBrowserCaptureTrafficProofProbe::new();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock should be available")
        .as_nanos();
    let valid_log = std::env::temp_dir().join(format!(
        "networkcore-browser-proof-bound-{}-{nonce}.log",
        std::process::id()
    ));
    let mismatch_log = std::env::temp_dir().join(format!(
        "networkcore-browser-proof-mismatch-{}-{nonce}.log",
        std::process::id()
    ));
    let valid_log_path = valid_log.to_string_lossy().to_string();
    let mismatch_log_path = mismatch_log.to_string_lossy().to_string();

    std::fs::write(
        &valid_log,
        "engine.native.runtime.http_mitm_connect_browser_proof_observed token browser-proof-123 target example.com:443 via socks5://127.0.0.1:7890\n",
    )
    .expect("valid proof log should be writable");
    std::fs::write(
        &mismatch_log,
        "engine.native.runtime.http_mitm_connect_browser_proof_observed token browser-proof-123 target example.org:443 via http://127.0.0.1:7890\n",
    )
    .expect("mismatch proof log should be writable");

    let observed = handle_mitm_browser_capture_traffic_proof_with_probe_and_proxy_scheme(
        &platform,
        &probe,
        Some("https://example.com/capture"),
        Some("browser-proof-123"),
        Some(&valid_log_path),
        MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME,
        true,
    );

    assert!(observed.ok);
    assert_eq!(observed.exit_code, LinuxCliExitCode::Success);
    assert_diagnostic(
        &observed.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_OBSERVED_CODE,
    );
    let observed_capture = observed
        .browser_capture
        .as_ref()
        .expect("traffic-proof response should include browser capture report");
    let observed_proof = observed_capture
        .traffic_proof_report
        .as_ref()
        .expect("traffic-proof response should include proof report");
    assert_eq!(observed_proof.status, "observed");
    assert!(observed_proof.proven);
    assert_eq!(observed_proof.request.proxy_url, "socks5://127.0.0.1:7890");
    assert_eq!(
        observed_proof.request.proof_connect_authority.as_deref(),
        Some("example.com:443")
    );

    let mismatch = handle_mitm_browser_capture_traffic_proof_with_probe_and_proxy_scheme(
        &platform,
        &probe,
        Some("https://example.com/capture"),
        Some("browser-proof-123"),
        Some(&mismatch_log_path),
        MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME,
        true,
    );

    assert!(!mismatch.ok);
    assert_eq!(mismatch.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &mismatch.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BINDING_MISMATCH_CODE,
    );
    assert_no_diagnostic(
        &mismatch.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_OBSERVED_CODE,
    );
    let mismatch_capture = mismatch
        .browser_capture
        .as_ref()
        .expect("traffic-proof response should include browser capture report");
    let mismatch_proof = mismatch_capture
        .traffic_proof_report
        .as_ref()
        .expect("traffic-proof response should include proof report");
    assert_eq!(mismatch_proof.status, "binding_mismatch");
    assert!(!mismatch_proof.proven);
    assert_eq!(
        mismatch_proof.request.proof_connect_authority.as_deref(),
        Some("example.com:443")
    );

    let _ = std::fs::remove_file(valid_log);
    let _ = std::fs::remove_file(mismatch_log);
}

#[test]
fn mitm_browser_capture_default_proof_token_tracks_connect_endpoint_not_url_path() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let probe = TestBrowserCaptureTrafficProofProbe { observed: true };

    let token_for_path = |target_url: &str| {
        let response = handle_mitm_browser_capture_traffic_proof_with_probe(
            &platform,
            &probe,
            Some(target_url),
            None,
            None,
            true,
        );
        response
            .browser_capture
            .as_ref()
            .expect("traffic-proof response should include browser capture report")
            .traffic_proof_report
            .as_ref()
            .expect("traffic-proof response should include proof report")
            .request
            .proof_token
            .clone()
    };

    let first_token = token_for_path("https://example.com/capture");
    let second_token = token_for_path("https://example.com/another-path");
    let different_endpoint_token = token_for_path("https://example.org/capture");

    assert!(first_token.starts_with("networkcore-browser-proof-"));
    assert_eq!(first_token, second_token);
    assert_ne!(first_token, different_endpoint_token);
}

#[test]
fn mitm_browser_capture_traffic_proof_reports_missing_token_without_live_mitm_claim() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let probe = TestBrowserCaptureTrafficProofProbe { observed: false };

    let response = handle_mitm_browser_capture_traffic_proof_with_probe(
        &platform,
        &probe,
        None,
        Some("browser-proof-123"),
        Some("/tmp/networkcore-browser-proof.log"),
        true,
    );

    assert!(!response.ok);
    assert_eq!(response.command, "mitm browser-capture traffic-proof");
    assert_eq!(response.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_MISSING_CODE,
    );
    assert_no_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_OBSERVED_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("traffic-proof response should include browser capture report");
    let proof = capture
        .traffic_proof_report
        .as_ref()
        .expect("traffic-proof response should include proof report");
    assert_eq!(proof.status, "missing");
    assert!(!proof.proven);
    assert!(proof
        .blocked_operations
        .iter()
        .any(|operation| operation == "verify-live-browser-capture"));
}

#[test]
fn mitm_browser_capture_traffic_proof_stays_blocked_without_probe_wiring() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_mitm_browser_capture_traffic_proof(
        &platform,
        None,
        Some("browser-proof-123"),
        Some("/tmp/networkcore-browser-proof.log"),
        true,
    );

    assert!(!response.ok);
    assert_eq!(response.command, "mitm browser-capture traffic-proof");
    assert_eq!(response.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BLOCKED_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("traffic-proof response should include browser capture report");
    let proof = capture
        .traffic_proof_report
        .as_ref()
        .expect("traffic-proof response should include proof report");
    assert_eq!(proof.status, "blocked");
    assert!(!proof.proven);
}

#[test]
fn mitm_browser_capture_apply_requires_authorization_and_stays_blocked() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let missing_confirm = handle_mitm_browser_capture_apply(&platform, false);

    assert!(!missing_confirm.ok);
    assert_eq!(missing_confirm.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &missing_confirm.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_AUTHORIZATION_REQUIRED_CODE,
    );
    assert_diagnostic(
        &missing_confirm.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_APPLY_BLOCKED_CODE,
    );
    let capture = missing_confirm
        .browser_capture
        .as_ref()
        .expect("apply response should include browser capture report");
    let apply = capture
        .apply_report
        .as_ref()
        .expect("apply response should include apply report");
    assert_eq!(capture.action, "apply");
    assert_eq!(apply.status, "authorization_required");
    assert!(!apply.applied);
    assert!(!apply.authorization.confirmed);

    let confirmed = handle_mitm_browser_capture_apply(&platform, true);

    assert!(!confirmed.ok);
    assert_eq!(confirmed.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &confirmed.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_APPLY_BLOCKED_CODE,
    );
    let confirmed_capture = confirmed
        .browser_capture
        .as_ref()
        .expect("confirmed apply response should include browser capture report");
    let confirmed_apply = confirmed_capture
        .apply_report
        .as_ref()
        .expect("confirmed apply response should include apply report");
    assert_eq!(confirmed_apply.status, "blocked");
    assert!(!confirmed_apply.applied);
    assert!(confirmed_apply.authorization.confirmed);
    assert!(confirmed_apply.pac_file_path.is_none());
    assert!(confirmed_apply.pac_url.is_none());
    assert!(confirmed_apply.rollback_snapshot.is_none());
}

#[test]
fn mitm_browser_capture_apply_with_store_requires_pac_file_and_snapshot() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_mitm_browser_capture_apply_with_store(
        &platform,
        &TestBrowserCapturePacFileStore,
        None,
        None,
        None,
        true,
    );

    assert!(!response.ok);
    assert_eq!(response.command, "mitm browser-capture apply");
    assert_eq!(response.exit_code, LinuxCliExitCode::ArgumentOrConfig);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_APPLY_CONFIG_MISSING_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("apply response should include browser capture report");
    let apply = capture
        .apply_report
        .as_ref()
        .expect("apply response should include apply report");
    assert_eq!(apply.status, "config_missing");
    assert!(!apply.applied);
    assert!(apply.authorization.confirmed);
}

#[test]
fn mitm_browser_capture_apply_with_store_writes_pac_file_artifact() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_mitm_browser_capture_apply_with_store(
        &platform,
        &TestBrowserCapturePacFileStore,
        Some("/tmp/networkcore-browser-capture.pac"),
        None,
        Some("/tmp/networkcore-browser-capture.snapshot.json"),
        true,
    );

    assert!(response.ok);
    assert_eq!(response.command, "mitm browser-capture apply");
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_APPLY_READY_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("apply response should include browser capture report");
    assert_eq!(capture.action, "apply");
    assert_eq!(capture.gate_status, MITM_BROWSER_CAPTURE_GATE_STATUS);
    let pac = capture
        .request
        .pac
        .as_ref()
        .expect("apply response should include PAC request");
    assert_eq!(pac.pac_file_path, "/tmp/networkcore-browser-capture.pac");
    assert_eq!(
        pac.snapshot_path,
        "/tmp/networkcore-browser-capture.snapshot.json"
    );
    assert_eq!(pac.pac_url, "file:///tmp/networkcore-browser-capture.pac");
    assert!(pac.pac_content.contains("PROXY 127.0.0.1:7890; DIRECT"));
    let apply = capture
        .apply_report
        .as_ref()
        .expect("apply response should include apply report");
    assert_eq!(apply.status, "applied");
    assert!(apply.applied);
    assert_eq!(
        apply.pac_file_path.as_deref(),
        Some("/tmp/networkcore-browser-capture.pac")
    );
    assert_eq!(
        apply.pac_url.as_deref(),
        Some("file:///tmp/networkcore-browser-capture.pac")
    );
    assert_eq!(
        apply
            .rollback_snapshot
            .as_ref()
            .expect("apply report should include rollback snapshot")
            .status,
        "networkcore-created"
    );
}

#[test]
fn mitm_browser_capture_apply_with_store_can_write_browser_policy_artifact() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_mitm_browser_capture_apply_with_store(
        &platform,
        &TestBrowserCapturePolicyFileStore,
        Some("/tmp/networkcore-browser-capture.pac"),
        Some("/tmp/networkcore-browser-capture-policy.json"),
        Some("/tmp/networkcore-browser-capture.snapshot.json"),
        true,
    );

    assert!(response.ok);
    assert_eq!(response.command, "mitm browser-capture apply");
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_APPLY_READY_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("apply response should include browser capture report");
    let pac = capture
        .request
        .pac
        .as_ref()
        .expect("apply response should include PAC request");
    assert_eq!(
        pac.policy_file_path.as_deref(),
        Some("/tmp/networkcore-browser-capture-policy.json")
    );
    assert_eq!(
        pac.policy_url.as_deref(),
        Some("file:///tmp/networkcore-browser-capture-policy.json")
    );
    let policy_content = pac
        .policy_content
        .as_ref()
        .expect("policy content should be present");
    assert!(policy_content.contains("\"ProxyMode\": \"fixed_servers\""));
    assert!(policy_content.contains("\"ProxyServer\": \"http://127.0.0.1:7890\""));
    assert!(policy_content.contains("\"ProxyBypassList\": \"<-loopback>\""));

    let apply = capture
        .apply_report
        .as_ref()
        .expect("apply response should include apply report");
    assert_eq!(apply.status, "applied");
    assert!(apply.applied);
    assert_eq!(
        apply.policy_file_path.as_deref(),
        Some("/tmp/networkcore-browser-capture-policy.json")
    );
    assert_eq!(
        apply.policy_url.as_deref(),
        Some("file:///tmp/networkcore-browser-capture-policy.json")
    );

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered.contains(
        "browser capture browser policy file: /tmp/networkcore-browser-capture-policy.json"
    ));
    assert!(rendered.contains(
        "browser capture browser policy URL: file:///tmp/networkcore-browser-capture-policy.json"
    ));
}

#[test]
fn mitm_browser_capture_apply_can_write_socks5_pac_artifact() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_mitm_browser_capture_apply_with_store_and_proxy_scheme(
        &platform,
        &TestSocks5BrowserCapturePacFileStore,
        Some("/tmp/networkcore-browser-capture.pac"),
        None,
        Some("/tmp/networkcore-browser-capture.snapshot.json"),
        MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME,
        true,
    );

    assert!(response.ok);
    let capture = response
        .browser_capture
        .as_ref()
        .expect("apply response should include browser capture report");
    let pac = capture
        .request
        .pac
        .as_ref()
        .expect("apply response should include PAC request");
    assert_eq!(
        pac.proxy_scheme,
        MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME
    );
    assert_eq!(pac.proxy_url, "socks5://127.0.0.1:7890");
    assert!(pac.pac_content.contains("SOCKS5 127.0.0.1:7890; DIRECT"));
}

#[test]
fn mitm_browser_capture_apply_can_restore_firefox_profile_prefs_file() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "networkcore-browser-capture-profile-prefs-{unique}"
    ));
    let profile_dir = root.join("firefox-profile");
    let prefs_path = profile_dir.join("user.js");
    let pac_path = root.join("capture.pac");
    let snapshot_path = root.join("capture.snapshot.json");
    let original_prefs = "user_pref(\"browser.startup.homepage\", \"about:blank\");\n";

    std::fs::create_dir_all(&profile_dir).expect("test profile dir should be created");
    std::fs::write(&prefs_path, original_prefs).expect("test profile prefs should be seeded");

    let response = handle_mitm_browser_capture_apply_with_store_and_profile_prefs_and_proxy_scheme(
        &platform,
        &networkcore_linux::CommandBrowserCapturePacFileStore::new(),
        Some(pac_path.to_str().expect("PAC path should be UTF-8")),
        None,
        Some(
            prefs_path
                .to_str()
                .expect("profile prefs path should be UTF-8"),
        ),
        Some(
            snapshot_path
                .to_str()
                .expect("snapshot path should be UTF-8"),
        ),
        MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME,
        true,
    );

    assert!(response.ok);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_APPLY_READY_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("apply response should include browser capture report");
    let pac = capture
        .request
        .pac
        .as_ref()
        .expect("apply response should include PAC request");
    assert_eq!(
        pac.profile_prefs_file_path.as_deref(),
        Some(
            prefs_path
                .to_str()
                .expect("profile prefs path should be UTF-8")
        )
    );
    let profile_prefs_content = pac
        .profile_prefs_content
        .as_ref()
        .expect("profile prefs content should be present");
    assert!(profile_prefs_content.contains("network.proxy.socks"));
    assert!(profile_prefs_content.contains("network.proxy.socks_remote_dns"));

    let written_prefs =
        std::fs::read_to_string(&prefs_path).expect("profile prefs should be written");
    assert_eq!(written_prefs, profile_prefs_content.as_str());
    let apply = capture
        .apply_report
        .as_ref()
        .expect("apply response should include apply report");
    assert_eq!(
        apply.profile_prefs_file_path.as_deref(),
        Some(
            prefs_path
                .to_str()
                .expect("profile prefs path should be UTF-8")
        )
    );

    let rollback = handle_mitm_browser_capture_rollback_with_store(
        &platform,
        &networkcore_linux::CommandBrowserCapturePacFileStore::new(),
        Some(
            snapshot_path
                .to_str()
                .expect("snapshot path should be UTF-8")
                .to_string(),
        ),
    );

    assert!(rollback.ok);
    assert_diagnostic(
        &rollback.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_ROLLBACK_READY_CODE,
    );
    let restored_prefs =
        std::fs::read_to_string(&prefs_path).expect("profile prefs should be restored");
    assert_eq!(restored_prefs, original_prefs);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn mitm_browser_capture_rollback_with_store_restores_pac_file_artifact() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_mitm_browser_capture_rollback_with_store(
        &platform,
        &TestBrowserCapturePacFileStore,
        Some("/tmp/networkcore-browser-capture.snapshot.json".to_string()),
    );

    assert!(response.ok);
    assert_eq!(response.command, "mitm browser-capture rollback");
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_ROLLBACK_READY_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("rollback response should include browser capture report");
    let rollback = capture
        .rollback_report
        .as_ref()
        .expect("rollback response should include rollback report");
    assert_eq!(rollback.status, "rolled_back");
    assert!(rollback.rolled_back);
    assert_eq!(
        rollback.pac_file_path.as_deref(),
        Some("/tmp/networkcore-browser-capture.pac")
    );
    assert_eq!(
        rollback
            .rollback_snapshot
            .as_ref()
            .expect("rollback report should include snapshot")
            .status,
        "networkcore-restored"
    );
}

#[test]
fn mitm_browser_capture_rollback_and_verify_stay_blocked_without_mutation() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let rollback = handle_mitm_browser_capture_rollback(
        &platform,
        Some("/tmp/networkcore-browser-capture.snapshot.json".to_string()),
    );

    assert!(!rollback.ok);
    assert_eq!(rollback.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &rollback.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_ROLLBACK_BLOCKED_CODE,
    );
    let rollback_capture = rollback
        .browser_capture
        .as_ref()
        .expect("rollback response should include browser capture report");
    let rollback_report = rollback_capture
        .rollback_report
        .as_ref()
        .expect("rollback response should include rollback report");
    assert_eq!(rollback_capture.action, "rollback");
    assert!(!rollback_report.rolled_back);
    assert_eq!(
        rollback_report
            .rollback_snapshot
            .as_ref()
            .expect("rollback snapshot should be preserved")
            .path,
        "/tmp/networkcore-browser-capture.snapshot.json"
    );

    let verify = handle_mitm_browser_capture_verify(&platform, None, true);

    assert!(!verify.ok);
    assert_eq!(verify.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &verify.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_VERIFY_BLOCKED_CODE,
    );
    let verify_capture = verify
        .browser_capture
        .as_ref()
        .expect("verify response should include browser capture report");
    let verify_report = verify_capture
        .verify_report
        .as_ref()
        .expect("verify response should include verify report");
    assert_eq!(verify_capture.action, "verify");
    assert!(!verify_report.verified);
}

#[test]
fn entrypoint_routes_read_only_platform_commands_to_injected_service() {
    let platform = StaticLinuxPlatformCapabilityService::new(
        LinuxPlatformSnapshot::available_for_tests().with_diagnostic(linux_diagnostic(
            DiagnosticSeverity::Warning,
            DNS_MANAGER_UNKNOWN_CODE,
            "linux DNS manager could not be identified",
            SOURCE_DNS,
        )),
    );

    let capabilities = handle_entrypoint(
        LinuxCliCommand::Capabilities {
            format: OutputFormat::Text,
        },
        &platform,
    );
    let status = handle_entrypoint(
        LinuxCliCommand::Status {
            format: OutputFormat::Text,
        },
        &platform,
    );
    let diagnostics = handle_entrypoint(
        LinuxCliCommand::Diagnostics {
            format: OutputFormat::Text,
        },
        &platform,
    );
    let mitm = handle_entrypoint(
        LinuxCliCommand::MitmStatus {
            format: OutputFormat::Text,
        },
        &platform,
    );
    let certificate_plan = handle_entrypoint(
        LinuxCliCommand::MitmCertificatePlan {
            format: OutputFormat::Text,
        },
        &platform,
    );
    let certificate_apply = handle_entrypoint(
        LinuxCliCommand::MitmCertificateApply {
            cert_file_path: Some("/tmp/networkcore-mitm-ca.crt".to_string()),
            key_file_path: Some("/tmp/networkcore-mitm-ca.key".to_string()),
            profile_trust_file_path: None,
            snapshot_path: Some("/tmp/networkcore-mitm-ca.snapshot.json".to_string()),
            confirm: true,
            format: OutputFormat::Text,
        },
        &platform,
    );
    let certificate_rollback = handle_entrypoint(
        LinuxCliCommand::MitmCertificateRollback {
            snapshot_path: Some("/tmp/networkcore-mitm-ca.snapshot.json".to_string()),
            format: OutputFormat::Text,
        },
        &platform,
    );
    let browser_plan = handle_entrypoint(
        LinuxCliCommand::MitmBrowserPlan {
            format: OutputFormat::Text,
        },
        &platform,
    );
    let browser_capture_plan = handle_entrypoint(
        LinuxCliCommand::MitmBrowserCapturePlan {
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            format: OutputFormat::Text,
        },
        &platform,
    );
    let browser_capture_launch_plan = handle_entrypoint(
        LinuxCliCommand::MitmBrowserCaptureLaunchPlan {
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            format: OutputFormat::Text,
        },
        &platform,
    );
    let browser_capture_session_plan = handle_entrypoint(
        LinuxCliCommand::MitmBrowserCaptureSessionPlan {
            url: "ss://YWVzLTI1Ni1nY206ZjQzYzBlZWUtMTNiOS00ZjA3LWJlYzktZDRiNzQ0MTQxNTAz@82.47.34.99:11111#%E9%A6%99%E6%B8%AF".to_string(),
            browser: "chromium".to_string(),
            profile_dir: MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR.to_string(),
            target_url: None,
            proof_token: None,
            proof_log_path: None,
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            listen_host: MITM_BROWSER_CAPTURE_PROXY_HOST.to_string(),
            listen_port: MITM_BROWSER_CAPTURE_PROXY_PORT,
            format: OutputFormat::Text,
        },
        &platform,
    );
    let browser_capture_apply = handle_entrypoint(
        LinuxCliCommand::MitmBrowserCaptureApply {
            pac_file_path: None,
            policy_file_path: None,
            profile_prefs_file_path: None,
            snapshot_path: None,
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            confirm: true,
            format: OutputFormat::Text,
        },
        &platform,
    );
    let browser_capture_rollback = handle_entrypoint(
        LinuxCliCommand::MitmBrowserCaptureRollback {
            snapshot_path: Some("/tmp/networkcore-browser-capture.snapshot.json".to_string()),
            format: OutputFormat::Text,
        },
        &platform,
    );
    let browser_capture_verify = handle_entrypoint(
        LinuxCliCommand::MitmBrowserCaptureVerify {
            target_url: None,
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            confirm: true,
            format: OutputFormat::Text,
        },
        &platform,
    );
    let browser_capture_traffic_proof = handle_entrypoint(
        LinuxCliCommand::MitmBrowserCaptureTrafficProof {
            target_url: None,
            proof_token: Some("browser-proof-123".to_string()),
            proof_log_path: Some("/tmp/networkcore-browser-proof.log".to_string()),
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            confirm: true,
            format: OutputFormat::Text,
        },
        &platform,
    );

    assert!(capabilities.ok);
    assert!(status.ok);
    assert!(diagnostics.ok);
    assert!(mitm.ok);
    assert!(certificate_plan.ok);
    assert!(!certificate_apply.ok);
    assert!(!certificate_rollback.ok);
    assert!(browser_plan.ok);
    assert!(browser_capture_plan.ok);
    assert!(browser_capture_launch_plan.ok);
    assert!(browser_capture_session_plan.ok);
    assert!(!browser_capture_apply.ok);
    assert!(!browser_capture_rollback.ok);
    assert!(!browser_capture_verify.ok);
    assert!(!browser_capture_traffic_proof.ok);
    assert_eq!(capabilities.command, "capabilities");
    assert_eq!(status.command, "status");
    assert_eq!(diagnostics.command, "diagnostics");
    assert_eq!(mitm.command, "mitm status");
    assert_eq!(certificate_plan.command, "mitm certificate-plan");
    assert_eq!(certificate_apply.command, "mitm certificate apply");
    assert_eq!(certificate_rollback.command, "mitm certificate rollback");
    assert_eq!(browser_plan.command, "mitm browser-plan");
    assert_eq!(browser_capture_plan.command, "mitm browser-capture plan");
    assert_eq!(
        browser_capture_launch_plan.command,
        "mitm browser-capture launch-plan"
    );
    assert_eq!(
        browser_capture_session_plan.command,
        "mitm browser-capture session-plan"
    );
    assert_eq!(browser_capture_apply.command, "mitm browser-capture apply");
    assert_eq!(
        browser_capture_rollback.command,
        "mitm browser-capture rollback"
    );
    assert_eq!(
        browser_capture_verify.command,
        "mitm browser-capture verify"
    );
    assert_eq!(
        browser_capture_traffic_proof.command,
        "mitm browser-capture traffic-proof"
    );
    assert_diagnostic(&capabilities.diagnostics, DNS_MANAGER_UNKNOWN_CODE);
    assert_diagnostic(&status.diagnostics, CLI_STATUS_NO_RUNTIME_CONTEXT_CODE);
    assert_diagnostic(&diagnostics.diagnostics, DNS_MANAGER_UNKNOWN_CODE);
    assert!(mitm.mitm_status.is_some());
    assert!(certificate_plan.mitm_status.is_some());
    assert!(certificate_apply.certificate_lifecycle.is_some());
    assert!(certificate_rollback.certificate_lifecycle.is_some());
    assert!(browser_plan.mitm_status.is_some());
    assert!(browser_capture_plan.browser_capture.is_some());
    assert!(browser_capture_launch_plan.browser_capture.is_some());
    assert!(browser_capture_session_plan.browser_capture.is_some());
    assert!(browser_capture_apply.browser_capture.is_some());
    assert!(browser_capture_rollback.browser_capture.is_some());
    assert!(browser_capture_verify.browser_capture.is_some());
    assert!(browser_capture_traffic_proof.browser_capture.is_some());
}

#[test]
fn entrypoint_accepts_read_only_linux_probe_for_host_diagnostic_mapping() {
    let platform = ReadOnlyLinuxPlatformCapabilityService::new(MemoryLinuxReadOnlyProbe::new(
        LinuxReadOnlyProbeSnapshot {
            tun_device: LinuxTunDeviceState::Available,
            privileges: LinuxPrivilegeProbe {
                effective_uid: Some(1000),
                cap_net_admin: Some(false),
            },
            dns_manager: LinuxDnsManagerState::NetworkManager,
            service_manager: LinuxServiceManagerState::Unsupported,
            mitm_certificate: LinuxCertificateProbe::new(CertificateTrustState::NotInstalled),
        },
    ));

    let response = handle_entrypoint(
        LinuxCliCommand::Capabilities {
            format: OutputFormat::Json,
        },
        &platform,
    );

    assert!(response.ok);
    assert!(!response
        .platform
        .as_ref()
        .expect("platform status")
        .tunnel
        .is_available());
    assert_diagnostic(&response.diagnostics, PERMISSION_CAPABILITY_MISSING_CODE);
    assert_diagnostic(&response.diagnostics, PERMISSION_ELEVATION_REQUIRED_CODE);
    assert_diagnostic(&response.diagnostics, DNS_MANAGER_DETECTED_CODE);
    assert_diagnostic(&response.diagnostics, SERVICE_UNSUPPORTED_ENVIRONMENT_CODE);
}

#[test]
fn runtime_entrypoint_routes_prepare_config_to_core_config_service() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let orchestrator = RuntimeOrchestrator::new(
        CoreConfigurationService::new(),
        platform.clone(),
        UnavailableProxyEngineService::new(),
    );
    let reader = MemoryConfigReader::ok(
        r#"
schema_version = 1
profiles = ["default", "work"]
"#,
    );

    let response = handle_entrypoint_with_runtime(
        LinuxCliCommand::PrepareConfig {
            config_path: Some("networkcore.toml".to_string()),
            format: OutputFormat::Json,
        },
        &platform,
        &orchestrator,
        &reader,
    );

    assert!(response.ok);
    assert_eq!(response.command, "prepare-config");
    assert_eq!(
        response.config_profiles,
        vec!["default".to_string(), "work".to_string()]
    );
    assert!(response.platform.is_some());
}

#[test]
fn entrypoint_keeps_runtime_mutation_commands_unwired() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_entrypoint(
        LinuxCliCommand::Start {
            config_path: Some("config.toml".to_string()),
            format: OutputFormat::Text,
        },
        &platform,
    );

    assert!(!response.ok);
    assert_eq!(response.command, "start");
    assert_eq!(response.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(&response.diagnostics, CLI_RUNTIME_UNWIRED_CODE);
}

#[test]
fn runtime_entrypoint_keeps_start_unwired_until_engine_adapter_exists() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let orchestrator = RuntimeOrchestrator::new(
        CoreConfigurationService::new(),
        platform.clone(),
        UnavailableProxyEngineService::new(),
    );
    let reader = MemoryConfigReader::ok(
        r#"
schema_version = 1
profile = "default"
"#,
    );

    let response = handle_entrypoint_with_runtime(
        LinuxCliCommand::Start {
            config_path: Some("networkcore.toml".to_string()),
            format: OutputFormat::Text,
        },
        &platform,
        &orchestrator,
        &reader,
    );

    assert!(!response.ok);
    assert_eq!(response.command, "start");
    assert_eq!(response.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(&response.diagnostics, CLI_RUNTIME_UNWIRED_CODE);
}

#[test]
fn runtime_entrypoint_wires_start_to_native_engine_and_foreground_lifecycle() {
    let port = unused_loopback_port();
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let orchestrator = RuntimeOrchestrator::new(
        CoreConfigurationService::new(),
        platform.clone(),
        NativeProxyEngineService::new(),
    );
    let reader = MemoryConfigReader::ok(format!(
        r#"
schema_version = 1
profile = "default"

[[nodes]]
id = "node-1"
protocol = "socks"
host = "127.0.0.1"
port = 1081

[[listeners]]
id = "loopback-socks"
enabled = true
kind = "socks"
bind_host = "127.0.0.1"
bind_port = {port}
network = "tcp"
route_action = "proxy"
route_node = "node-1"
"#
    ));

    let response = handle_entrypoint_with_runtime_and_lifecycle(
        LinuxCliCommand::Start {
            config_path: Some("networkcore.toml".to_string()),
            format: OutputFormat::Text,
        },
        &platform,
        &orchestrator,
        &reader,
        &TestForegroundLifecycleHost::success(Vec::new()),
    );

    assert!(response.ok);
    assert_eq!(response.command, "start");
    assert_eq!(response.exit_code, LinuxCliExitCode::Success);
    assert!(response.platform.is_some());
    assert_diagnostic(&response.diagnostics, ENGINE_NATIVE_START_RUNNING_CODE);
    assert_diagnostic(
        &response.diagnostics,
        ENGINE_NATIVE_RUNTIME_FOREGROUND_HANDOFF_READY_CODE,
    );
    assert_diagnostic(
        &response.diagnostics,
        ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_READY_CODE,
    );
    assert_diagnostic(&response.diagnostics, CLI_START_FOREGROUND_ONLY_CODE);
    assert_no_diagnostic(&response.diagnostics, CLI_RUNTIME_UNWIRED_CODE);
}

#[test]
fn install_sing_box_handler_uses_injected_latest_installer() {
    let response = handle_install_sing_box(
        &TestSingBoxInstaller,
        Some("/tmp/networkcore-engines"),
        true,
    );

    assert!(response.ok);
    assert_eq!(response.command, "install-sing-box");
    assert_eq!(response.exit_code, LinuxCliExitCode::Success);
    assert_diagnostic(
        &response.diagnostics,
        ENGINE_SINGBOX_DOWNLOAD_BINARY_READY_CODE,
    );
    let install = response
        .sing_box_install
        .as_ref()
        .expect("install response should include sing-box status");
    assert_eq!(install.version, "1.2.3");
    assert_eq!(install.asset_name, "sing-box-1.2.3-linux-amd64.tar.gz");
    assert!(install.downloaded);

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered.contains("sing-box version: 1.2.3"));
    assert!(rendered.contains("executable:"));
}

#[test]
fn runtime_lifecycle_entrypoint_routes_sing_box_install_to_injected_installer() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let orchestrator = RuntimeOrchestrator::new(
        CoreConfigurationService::new(),
        platform.clone(),
        UnavailableProxyEngineService::new(),
    );
    let reader = MemoryConfigReader::ok("profile = default");

    let response = handle_entrypoint_with_runtime_lifecycle_and_sing_box(
        LinuxCliCommand::InstallSingBox {
            install_dir: Some("/tmp/networkcore-engines".to_string()),
            force: false,
            format: OutputFormat::Json,
        },
        &platform,
        &orchestrator,
        &reader,
        &UnavailableForegroundLifecycleHost::new(),
        &TestSingBoxInstaller,
        &TestSingBoxRunner,
    );

    assert!(response.ok);
    assert_eq!(response.command, "install-sing-box");
    assert!(response.sing_box_install.is_some());
}

#[test]
fn browser_capture_entrypoint_routes_launch_to_injected_runner() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_entrypoint_with_browser_capture_runner(
        LinuxCliCommand::MitmBrowserCaptureLaunch {
            browser: "chromium".to_string(),
            profile_dir: MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR.to_string(),
            target_url: Some("https://example.com/capture".to_string()),
            proof_token: Some("browser-proof-123".to_string()),
            proof_log_path: Some("/tmp/networkcore-browser-proof.log".to_string()),
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            confirm: true,
            format: OutputFormat::Json,
        },
        &platform,
        &TestBrowserCaptureRunner,
    );

    assert!(response.ok);
    assert_eq!(response.command, "mitm browser-capture launch");
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_LAUNCH_STARTED_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("launch response should include browser capture report");
    let launch = capture
        .launch_report
        .as_ref()
        .expect("launch response should include launch report");
    assert_eq!(launch.pid, Some(4242));
    assert_eq!(
        launch.request.target_url.as_deref(),
        Some("https://example.com/capture")
    );
    assert_eq!(
        launch.request.proof_target_url.as_deref(),
        Some("https://example.com/capture?networkcore_proof_token=browser-proof-123")
    );
}

#[test]
fn browser_capture_entrypoint_routes_verify_to_injected_endpoint_probe() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let probe = TestBrowserCaptureEndpointProbe { reachable: true };

    let response = handle_entrypoint_with_browser_capture_io(
        LinuxCliCommand::MitmBrowserCaptureVerify {
            target_url: Some("https://example.com/capture".to_string()),
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            confirm: true,
            format: OutputFormat::Json,
        },
        &platform,
        &TestBrowserCaptureRunner,
        &probe,
    );

    assert!(response.ok);
    assert_eq!(response.command, "mitm browser-capture verify");
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_REACHABLE_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("verify response should include browser capture report");
    let verify = capture
        .verify_report
        .as_ref()
        .expect("verify response should include verify report");
    assert!(verify.verified);
    assert_eq!(verify.request.proxy_url, "http://127.0.0.1:7890");
    assert_eq!(
        verify.request.target_url.as_deref(),
        Some("https://example.com/capture")
    );
}

#[test]
fn browser_capture_entrypoint_routes_traffic_proof_to_injected_probe() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let endpoint_probe = TestBrowserCaptureEndpointProbe { reachable: true };
    let traffic_proof_probe = TestBrowserCaptureTrafficProofProbe { observed: true };
    let pac_store = TestBrowserCapturePacFileStore;

    let response = handle_entrypoint_with_browser_capture_all_io(
        LinuxCliCommand::MitmBrowserCaptureTrafficProof {
            target_url: Some("https://example.com/capture".to_string()),
            proof_token: Some("browser-proof-123".to_string()),
            proof_log_path: Some("/tmp/networkcore-browser-proof.log".to_string()),
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            confirm: true,
            format: OutputFormat::Json,
        },
        &platform,
        &TestBrowserCaptureRunner,
        &endpoint_probe,
        &traffic_proof_probe,
        &pac_store,
    );

    assert!(response.ok);
    assert_eq!(response.command, "mitm browser-capture traffic-proof");
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_OBSERVED_CODE,
    );
    let capture = response
        .browser_capture
        .as_ref()
        .expect("traffic-proof response should include browser capture report");
    let proof = capture
        .traffic_proof_report
        .as_ref()
        .expect("traffic-proof response should include proof report");
    assert!(proof.proven);
    assert_eq!(proof.request.probe, "proof-log-token");
}

#[test]
fn browser_capture_entrypoint_routes_apply_and_rollback_to_pac_store() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let endpoint_probe = TestBrowserCaptureEndpointProbe { reachable: true };
    let traffic_proof_probe = TestBrowserCaptureTrafficProofProbe { observed: true };
    let pac_store = TestBrowserCapturePacFileStore;

    let apply = handle_entrypoint_with_browser_capture_all_io(
        LinuxCliCommand::MitmBrowserCaptureApply {
            pac_file_path: Some("/tmp/networkcore-browser-capture.pac".to_string()),
            policy_file_path: None,
            profile_prefs_file_path: None,
            snapshot_path: Some("/tmp/networkcore-browser-capture.snapshot.json".to_string()),
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            confirm: true,
            format: OutputFormat::Json,
        },
        &platform,
        &TestBrowserCaptureRunner,
        &endpoint_probe,
        &traffic_proof_probe,
        &pac_store,
    );
    assert!(apply.ok);
    assert_eq!(apply.command, "mitm browser-capture apply");
    assert_diagnostic(
        &apply.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_APPLY_READY_CODE,
    );

    let rollback = handle_entrypoint_with_browser_capture_all_io(
        LinuxCliCommand::MitmBrowserCaptureRollback {
            snapshot_path: Some("/tmp/networkcore-browser-capture.snapshot.json".to_string()),
            format: OutputFormat::Json,
        },
        &platform,
        &TestBrowserCaptureRunner,
        &endpoint_probe,
        &traffic_proof_probe,
        &pac_store,
    );
    assert!(rollback.ok);
    assert_eq!(rollback.command, "mitm browser-capture rollback");
    assert_diagnostic(
        &rollback.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_ROLLBACK_READY_CODE,
    );
}

#[test]
fn certificate_lifecycle_entrypoint_routes_apply_and_rollback_to_artifact_store() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let certificate_store = TestMitmCertificateArtifactStore;

    let apply = handle_entrypoint_with_certificate_lifecycle_io(
        LinuxCliCommand::MitmCertificateApply {
            cert_file_path: Some("/tmp/networkcore-mitm-ca.crt".to_string()),
            key_file_path: Some("/tmp/networkcore-mitm-ca.key".to_string()),
            profile_trust_file_path: None,
            snapshot_path: Some("/tmp/networkcore-mitm-ca.snapshot.json".to_string()),
            confirm: true,
            format: OutputFormat::Json,
        },
        &platform,
        &certificate_store,
    );
    assert!(apply.ok);
    assert_eq!(apply.command, "mitm certificate apply");
    assert_diagnostic(&apply.diagnostics, CLI_MITM_CERTIFICATE_APPLY_READY_CODE);

    let rollback = handle_entrypoint_with_certificate_lifecycle_io(
        LinuxCliCommand::MitmCertificateRollback {
            snapshot_path: Some("/tmp/networkcore-mitm-ca.snapshot.json".to_string()),
            format: OutputFormat::Json,
        },
        &platform,
        &certificate_store,
    );
    assert!(rollback.ok);
    assert_eq!(rollback.command, "mitm certificate rollback");
    assert_diagnostic(
        &rollback.diagnostics,
        CLI_MITM_CERTIFICATE_ROLLBACK_READY_CODE,
    );
}

#[test]
fn read_only_entrypoint_does_not_launch_browser_without_runner() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let response = handle_entrypoint(
        LinuxCliCommand::MitmBrowserCaptureLaunch {
            browser: "chromium".to_string(),
            profile_dir: MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR.to_string(),
            target_url: None,
            proof_token: None,
            proof_log_path: None,
            proxy_scheme: MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string(),
            confirm: true,
            format: OutputFormat::Text,
        },
        &platform,
    );

    assert!(!response.ok);
    assert_eq!(response.command, "mitm browser-capture launch");
    assert_eq!(response.exit_code, LinuxCliExitCode::Unavailable);
    assert_diagnostic(
        &response.diagnostics,
        CLI_MITM_BROWSER_CAPTURE_LAUNCH_FAILED_CODE,
    );
}

#[test]
fn run_url_handler_parses_ss_url_writes_sing_box_config_and_uses_runner() {
    let install_dir = std::env::temp_dir().join(format!(
        "networkcore-linux-run-url-contract-{}",
        std::process::id()
    ));
    let engine_dir = install_dir.join("networkcore-engines");
    let _ = std::fs::remove_dir_all(&install_dir);

    let response = handle_run_url_with_sing_box(
        &TestSingBoxInstaller,
        &TestSingBoxRunner,
        "ss://YWVzLTI1Ni1nY206ZjQzYzBlZWUtMTNiOS00ZjA3LWJlYzktZDRiNzQ0MTQxNTAz@82.47.34.99:11111#%E9%A6%99%E6%B8%AF",
        "127.0.0.1",
        7890,
        Some(engine_dir.to_str().expect("temp path should be utf-8")),
        false,
    );

    assert!(response.ok);
    assert_eq!(response.command, "run-url");
    assert_eq!(response.exit_code, LinuxCliExitCode::Success);
    assert!(response.sing_box_install.is_some());
    let run = response
        .sing_box_run
        .as_ref()
        .expect("run-url response should include run status");
    assert_eq!(run.node_id, "ss-82-47-34-99-11111");
    assert_eq!(run.node_name, "香港");
    assert_eq!(run.listen_host, "127.0.0.1");
    assert_eq!(run.listen_port, 7890);
    assert_eq!(run.process_exit_code, Some(0));
    assert_diagnostic(&response.diagnostics, ENGINE_SINGBOX_PROCESS_EXITED_CODE);

    let rendered = render_response(&response, OutputFormat::Text);
    assert!(rendered.contains("local proxy: 127.0.0.1:7890"));
    assert!(rendered.contains("node: 香港 (ss-82-47-34-99-11111)"));

    let _ = std::fs::remove_dir_all(&install_dir);
}

#[test]
fn foreground_lifecycle_contract_reports_missing_host_without_start_wiring() {
    let response = handle_foreground_lifecycle(
        runtime_operation_result(
            ProxyEngineLifecycleState::Running,
            vec![Diagnostic::new(
                DiagnosticSeverity::Info,
                "engine.ready",
                "engine accepted foreground handoff",
                Some("engine".to_string()),
            )],
        ),
        &UnavailableForegroundLifecycleHost::new(),
    );

    assert!(!response.ok);
    assert_eq!(response.command, "start");
    assert_eq!(response.exit_code, LinuxCliExitCode::Unavailable);
    assert!(response.platform.is_some());
    assert_diagnostic(&response.diagnostics, "engine.ready");
    assert_diagnostic(&response.diagnostics, CLI_START_FOREGROUND_ONLY_CODE);
    assert_diagnostic(&response.diagnostics, CLI_START_LIFECYCLE_HOST_MISSING_CODE);
}

#[test]
fn foreground_lifecycle_contract_rejects_non_running_engine_status_before_host() {
    let response = handle_foreground_lifecycle(
        runtime_operation_result(ProxyEngineLifecycleState::Starting, Vec::new()),
        &TestForegroundLifecycleHost::success(vec![Diagnostic::new(
            DiagnosticSeverity::Info,
            "host.ran",
            "host should not run",
            Some("host".to_string()),
        )]),
    );

    assert!(!response.ok);
    assert_eq!(response.command, "start");
    assert_eq!(response.exit_code, LinuxCliExitCode::GeneralFailure);
    assert_diagnostic(&response.diagnostics, CLI_START_FOREGROUND_ONLY_CODE);
    assert_diagnostic(&response.diagnostics, CLI_START_LIFECYCLE_FAILED_CODE);
    assert_no_diagnostic(&response.diagnostics, "host.ran");
}

#[test]
fn foreground_lifecycle_contract_aggregates_success_diagnostics() {
    let response = handle_foreground_lifecycle(
        runtime_operation_result(ProxyEngineLifecycleState::Running, Vec::new()),
        &TestForegroundLifecycleHost::success(vec![Diagnostic::new(
            DiagnosticSeverity::Info,
            "host.foreground.ready",
            "foreground host accepted runtime",
            Some("host".to_string()),
        )]),
    );

    assert!(response.ok);
    assert_eq!(response.command, "start");
    assert_eq!(response.exit_code, LinuxCliExitCode::Success);
    assert!(response.platform.is_some());
    assert_diagnostic(&response.diagnostics, CLI_START_FOREGROUND_ONLY_CODE);
    assert_diagnostic(&response.diagnostics, "host.foreground.ready");
}

#[test]
fn current_process_lifecycle_host_maps_interruption_to_stable_exit_contract() {
    let host = CurrentProcessForegroundLifecycleHost::with_interruption_source(
        TestForegroundLifecycleInterruptionSource::new("sigint").with_diagnostics(vec![
            Diagnostic::new(
                DiagnosticSeverity::Info,
                "host.signal.received",
                "foreground host received interruption",
                Some("host.signal".to_string()),
            ),
        ]),
    );

    let response = handle_foreground_lifecycle(
        runtime_operation_result(ProxyEngineLifecycleState::Running, Vec::new()),
        &host,
    );

    assert!(!response.ok);
    assert_eq!(response.command, "start");
    assert_eq!(response.exit_code, LinuxCliExitCode::Interrupted);
    assert_eq!(response.exit_code.code(), 130);
    assert!(response.platform.is_some());
    assert_diagnostic(&response.diagnostics, CLI_START_FOREGROUND_ONLY_CODE);
    assert_diagnostic(&response.diagnostics, "host.signal.received");
    assert_diagnostic(&response.diagnostics, CLI_START_LIFECYCLE_INTERRUPTED_CODE);
}

#[test]
fn foreground_interruption_stops_native_runtime_and_aggregates_release_diagnostics() {
    let port = unused_loopback_port();
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let engine = NativeProxyEngineService::new();
    let orchestrator = RuntimeOrchestrator::new(
        CoreConfigurationService::new(),
        platform.clone(),
        engine.clone(),
    );
    let reader = MemoryConfigReader::ok(format!(
        r#"
schema_version = 1
profile = "default"

[[nodes]]
id = "node-1"
protocol = "socks"
host = "127.0.0.1"
port = 1081

[[listeners]]
id = "loopback-socks"
enabled = true
kind = "socks"
bind_host = "127.0.0.1"
bind_port = {port}
network = "tcp"
route_action = "proxy"
route_node = "node-1"
"#
    ));
    let host = CurrentProcessForegroundLifecycleHost::with_interruption_source(
        TestForegroundLifecycleInterruptionSource::new("sigterm"),
    );

    let response = handle_entrypoint_with_runtime_and_lifecycle(
        LinuxCliCommand::Start {
            config_path: Some("networkcore.toml".to_string()),
            format: OutputFormat::Text,
        },
        &platform,
        &orchestrator,
        &reader,
        &host,
    );

    assert!(!response.ok);
    assert_eq!(response.command, "start");
    assert_eq!(response.exit_code, LinuxCliExitCode::Interrupted);
    assert_diagnostic(&response.diagnostics, ENGINE_NATIVE_START_RUNNING_CODE);
    assert_diagnostic(&response.diagnostics, CLI_START_FOREGROUND_ONLY_CODE);
    assert_diagnostic(&response.diagnostics, CLI_START_LIFECYCLE_INTERRUPTED_CODE);
    assert_diagnostic(
        &response.diagnostics,
        ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_STOPPED_CODE,
    );
    assert_diagnostic(&response.diagnostics, ENGINE_NATIVE_RUNTIME_RELEASED_CODE);

    let status = engine
        .status(DEFAULT_ENGINE_ID)
        .expect("interruption cleanup should leave native runtime inspectable");
    assert_eq!(status.state, ProxyEngineLifecycleState::Stopped);
    let rebound = TcpListener::bind(("127.0.0.1", port))
        .expect("interruption cleanup should release the loopback tcp port");
    drop(rebound);
}

#[test]
fn foreground_interruption_stop_failure_adds_stable_cli_diagnostic() {
    let orchestrator = RuntimeOrchestrator::new(
        TestConfigurationService,
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests()),
        StopFailingProxyEngineService,
    );
    let host = CurrentProcessForegroundLifecycleHost::with_interruption_source(
        TestForegroundLifecycleInterruptionSource::new("sigint"),
    );

    let response = handle_foreground_lifecycle_with_runtime_stop(
        runtime_operation_result(ProxyEngineLifecycleState::Running, Vec::new()),
        &orchestrator,
        &host,
    );

    assert!(!response.ok);
    assert_eq!(response.exit_code, LinuxCliExitCode::Interrupted);
    assert_diagnostic(&response.diagnostics, CLI_START_LIFECYCLE_INTERRUPTED_CODE);
    assert_diagnostic(&response.diagnostics, CLI_START_RUNTIME_STOP_FAILED_CODE);
}

#[cfg(unix)]
#[test]
fn os_signal_interruption_source_maps_unix_signals_to_stable_diagnostics() {
    let sigint = OsSignalForegroundLifecycleInterruptionSource::interruption_for_signal(SIGINT);
    let sigterm = OsSignalForegroundLifecycleInterruptionSource::interruption_for_signal(SIGTERM);

    assert_eq!(sigint.reason, "SIGINT");
    assert_eq!(sigterm.reason, "SIGTERM");
    assert_diagnostic(&sigint.diagnostics, CLI_START_SIGNAL_RECEIVED_CODE);
    assert_diagnostic(&sigterm.diagnostics, CLI_START_SIGNAL_RECEIVED_CODE);
}

#[test]
fn json_output_contains_required_top_level_fields() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let response = handle_capabilities(&platform);

    let rendered = render_response(&response, OutputFormat::Json);
    let json: serde_json::Value =
        serde_json::from_str(&rendered).expect("response should be valid JSON");

    assert_eq!(json["ok"].as_bool(), Some(true));
    assert_eq!(json["command"], "capabilities");
    assert_eq!(json["exit_code"], 0);
    assert!(json["diagnostics"].is_array());
    assert_eq!(json["platform"]["os"], "linux");
    assert_eq!(json["platform"]["tunnel"]["state"], "available");
}

#[test]
fn install_sing_box_json_output_contains_machine_fields() {
    let response = handle_install_sing_box(
        &TestSingBoxInstaller,
        Some("/tmp/networkcore-engines"),
        false,
    );

    let rendered = render_response(&response, OutputFormat::Json);
    let json: serde_json::Value =
        serde_json::from_str(&rendered).expect("install response should be valid JSON");

    assert_eq!(json["ok"].as_bool(), Some(true));
    assert_eq!(json["command"], "install-sing-box");
    assert_eq!(json["sing_box_install"]["version"], "1.2.3");
    assert!(json["sing_box_install"]["target"].as_str().is_some());
    assert_eq!(json["sing_box_install"]["downloaded"].as_bool(), Some(true));
}

#[test]
fn mitm_status_json_output_contains_machine_fields() {
    let platform = StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot {
        mitm_certificate: LinuxCertificateProbe::new(CertificateTrustState::Trusted)
            .with_subject("NetworkCore Test CA")
            .with_fingerprint_sha256(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ),
        ..LinuxPlatformSnapshot::available_for_tests()
    });
    let response = handle_mitm_status(&platform);

    let rendered = render_response(&response, OutputFormat::Json);
    let json: serde_json::Value =
        serde_json::from_str(&rendered).expect("mitm response should be valid JSON");

    assert_eq!(json["ok"].as_bool(), Some(true));
    assert_eq!(json["command"], "mitm status");
    assert_eq!(json["mitm_status"]["stage"], MITM_USER_FACING_STAGE);
    assert_eq!(
        json["mitm_status"]["user_facing_ready"].as_bool(),
        Some(false)
    );
    assert_eq!(
        json["mitm_status"]["browser_hijack"],
        MITM_BROWSER_HIJACK_STATUS
    );
    assert_eq!(
        json["mitm_status"]["certificate_plan"]["status"],
        MITM_CERTIFICATE_PLAN_STATUS
    );
    assert_eq!(
        json["mitm_status"]["certificate_plan"]["mutation_ready"].as_bool(),
        Some(MITM_CERTIFICATE_MUTATION_READY)
    );
    assert_eq!(
        json["mitm_status"]["certificate_plan"]["current_state"],
        "trusted"
    );
    assert_eq!(
        json["mitm_status"]["certificate_plan"]["subject"],
        "NetworkCore Test CA"
    );
    assert_eq!(
        json["mitm_status"]["certificate_plan"]["fingerprint_sha256"],
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    );
    assert_eq!(
        json["mitm_status"]["certificate_plan"]["required_steps"][0]["id"],
        "probe-certificate-state"
    );
    assert!(
        json["mitm_status"]["certificate_plan"]["blocked_operations"]
            .as_array()
            .expect("blocked operations should be an array")
            .iter()
            .any(|operation| operation.as_str() == Some("decrypt-https"))
    );
    assert_eq!(
        json["mitm_status"]["browser_plan"]["status"],
        MITM_BROWSER_PLAN_STATUS
    );
    assert_eq!(
        json["mitm_status"]["browser_plan"]["mutation_ready"].as_bool(),
        Some(MITM_BROWSER_CAPTURE_MUTATION_READY)
    );
    assert_eq!(
        json["mitm_status"]["browser_plan"]["current_capture"],
        "not_configured"
    );
    assert_eq!(
        json["mitm_status"]["browser_plan"]["planned_capture_mode"],
        MITM_BROWSER_CAPTURE_MODE
    );
    assert_eq!(
        json["mitm_status"]["browser_plan"]["planned_proxy_host"],
        MITM_BROWSER_CAPTURE_PROXY_HOST
    );
    assert_eq!(
        json["mitm_status"]["browser_plan"]["planned_proxy_port"].as_u64(),
        Some(u64::from(MITM_BROWSER_CAPTURE_PROXY_PORT))
    );
    assert_eq!(
        json["mitm_status"]["browser_plan"]["required_steps"][0]["id"],
        "load-mitm-policy"
    );
    assert!(json["mitm_status"]["browser_plan"]["blocked_operations"]
        .as_array()
        .expect("browser blocked operations should be an array")
        .iter()
        .any(|operation| operation.as_str() == Some("install-browser-policy")));
    assert_eq!(
        json["mitm_status"]["policy"]["plugin_id"],
        mitm_policy::MITM_POLICY_AD_BLOCK_PLUGIN_ID
    );
    assert_eq!(
        json["mitm_status"]["gates"][0]["gate"],
        MITM_CLI_COMMAND_GATE
    );
    assert_eq!(
        json["mitm_status"]["gates"][0]["status"],
        MITM_CLI_COMMAND_GATE_STATUS
    );
    assert_eq!(
        json["mitm_status"]["gates"][1]["gate"],
        MITM_CERTIFICATE_LIFECYCLE_GATE
    );
    assert_eq!(
        json["mitm_status"]["gates"][1]["status"],
        MITM_CERTIFICATE_LIFECYCLE_GATE_STATUS
    );
    assert_eq!(
        json["mitm_status"]["gates"][2]["gate"],
        MITM_HTTP_TLS_DATA_PLANE_GATE
    );
    assert_eq!(
        json["mitm_status"]["gates"][2]["status"],
        MITM_HTTP_TLS_DATA_PLANE_GATE_STATUS
    );
}

#[test]
fn http_rewrite_json_output_contains_live_plain_http_gate_fields() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let headers = vec!["Accept: */*".to_string()];
    let response = handle_mitm_http_rewrite_preview(
        &platform,
        Some("https://pubads.g.doubleclick.net/pagead/id"),
        "GET",
        "request",
        None,
        &headers,
        None,
        true,
    );

    let rendered = render_response(&response, OutputFormat::Json);
    let json: serde_json::Value =
        serde_json::from_str(&rendered).expect("http rewrite response should be valid JSON");

    assert_eq!(json["ok"].as_bool(), Some(true));
    assert_eq!(json["command"], "mitm http-rewrite preview");
    assert_eq!(json["http_rewrite"]["action"], "preview");
    assert_eq!(
        json["http_rewrite"]["source_contract_status"],
        MITM_HTTP_REWRITE_SOURCE_CONTRACT_STATUS
    );
    assert_eq!(json["http_rewrite"]["gate"], MITM_HTTP_TLS_DATA_PLANE_GATE);
    assert_eq!(
        json["http_rewrite"]["gate_status"],
        MITM_HTTP_TLS_DATA_PLANE_GATE_STATUS
    );
    assert_eq!(
        json["http_rewrite"]["mutation_ready"].as_bool(),
        Some(MITM_HTTP_REWRITE_MUTATION_READY)
    );
    assert_eq!(
        json["http_rewrite"]["live_traffic_ready"].as_bool(),
        Some(MITM_HTTP_REWRITE_LIVE_TRAFFIC_READY)
    );
    assert_eq!(
        json["http_rewrite"]["tls_decryption_ready"].as_bool(),
        Some(MITM_HTTP_REWRITE_TLS_DECRYPTION_READY)
    );
    assert_eq!(
        json["http_rewrite"]["controlled_tls_termination_plan_ready"].as_bool(),
        Some(MITM_HTTP_REWRITE_CONTROLLED_TLS_TERMINATION_PLAN_READY)
    );
    assert_eq!(
        json["http_rewrite"]["downstream_tls_termination_plan_ready"].as_bool(),
        Some(MITM_HTTP_REWRITE_DOWNSTREAM_TLS_TERMINATION_PLAN_READY)
    );
    assert_eq!(
        json["http_rewrite"]["upstream_tls_forwarding_ready"].as_bool(),
        Some(MITM_HTTP_REWRITE_UPSTREAM_TLS_FORWARDING_READY)
    );
    assert_eq!(
        json["http_rewrite"]["https_request_rewrite_preview_ready"].as_bool(),
        Some(MITM_HTTP_REWRITE_HTTPS_REQUEST_REWRITE_PREVIEW_READY)
    );
    assert_eq!(
        json["http_rewrite"]["https_response_rewrite_preview_ready"].as_bool(),
        Some(MITM_HTTP_REWRITE_HTTPS_RESPONSE_REWRITE_PREVIEW_READY)
    );
    assert_eq!(
        json["http_rewrite"]["https_response_rewrite_ready"].as_bool(),
        Some(MITM_HTTP_REWRITE_HTTPS_RESPONSE_REWRITE_READY)
    );
    assert_eq!(
        json["http_rewrite"]["script_dispatch_ready"].as_bool(),
        Some(MITM_HTTP_REWRITE_SCRIPT_DISPATCH_READY)
    );
    assert_eq!(
        json["http_rewrite"]["request"]["url"],
        "https://pubads.g.doubleclick.net/pagead/id"
    );
    assert_eq!(json["http_rewrite"]["request"]["method"], "GET");
    assert_eq!(json["http_rewrite"]["request"]["phase"], "request");
    assert_eq!(
        json["http_rewrite"]["request"]["authorization"]["confirmed"].as_bool(),
        Some(true)
    );
    assert_eq!(json["http_rewrite"]["outcome"]["terminal_action"], "reject");
    assert_eq!(
        json["http_rewrite"]["outcome"]["final_status_code"].as_u64(),
        Some(403)
    );
    assert!(json["http_rewrite"]["blocked_operations"]
        .as_array()
        .expect("blocked operations should be an array")
        .iter()
        .any(|operation| operation.as_str() == Some("decrypt-https")));
}

#[test]
fn certificate_lifecycle_json_output_contains_artifact_fields() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let response = handle_mitm_certificate_apply_with_store(
        &platform,
        &TestMitmCertificateArtifactStore,
        Some("/tmp/networkcore-mitm-ca.crt"),
        Some("/tmp/networkcore-mitm-ca.key"),
        None,
        Some("/tmp/networkcore-mitm-ca.snapshot.json"),
        true,
    );

    let rendered = render_response(&response, OutputFormat::Json);
    let json: serde_json::Value = serde_json::from_str(&rendered)
        .expect("certificate lifecycle response should be valid JSON");

    assert_eq!(json["ok"].as_bool(), Some(true));
    assert_eq!(json["command"], "mitm certificate apply");
    assert_eq!(json["certificate_lifecycle"]["action"], "apply");
    assert_eq!(
        json["certificate_lifecycle"]["source_contract_status"],
        MITM_CERTIFICATE_LIFECYCLE_SOURCE_CONTRACT_STATUS
    );
    assert_eq!(
        json["certificate_lifecycle"]["gate"],
        MITM_CERTIFICATE_LIFECYCLE_GATE
    );
    assert_eq!(
        json["certificate_lifecycle"]["gate_status"],
        MITM_CERTIFICATE_LIFECYCLE_GATE_STATUS
    );
    assert_eq!(
        json["certificate_lifecycle"]["mutation_ready"].as_bool(),
        Some(MITM_CERTIFICATE_MUTATION_READY)
    );
    assert_eq!(
        json["certificate_lifecycle"]["request"]["authorization"]["confirmed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        json["certificate_lifecycle"]["request"]["artifact"]["cert_file_path"],
        "/tmp/networkcore-mitm-ca.crt"
    );
    assert_eq!(
        json["certificate_lifecycle"]["request"]["artifact"]["key_file_path"],
        "/tmp/networkcore-mitm-ca.key"
    );
    assert_eq!(
        json["certificate_lifecycle"]["request"]["artifact"]["snapshot_path"],
        "/tmp/networkcore-mitm-ca.snapshot.json"
    );
    assert_eq!(
        json["certificate_lifecycle"]["request"]["artifact"]["subject"],
        MITM_CERTIFICATE_ARTIFACT_SUBJECT
    );
    assert!(
        json["certificate_lifecycle"]["request"]["artifact"]["cert_content"]
            .as_str()
            .expect("cert content should be a string")
            .contains("-----BEGIN CERTIFICATE-----")
    );
    assert_eq!(
        json["certificate_lifecycle"]["apply_report"]["status"],
        "applied"
    );
    assert_eq!(
        json["certificate_lifecycle"]["apply_report"]["applied"].as_bool(),
        Some(true)
    );
    assert_eq!(
        json["certificate_lifecycle"]["apply_report"]["rollback_snapshot"]["status"],
        "networkcore-created"
    );
    assert!(
        json["certificate_lifecycle"]["trust_plan"]["blocked_operations"]
            .as_array()
            .expect("trust blocked operations should be an array")
            .iter()
            .any(|operation| operation.as_str() == Some("update-ca-certificates"))
    );
}

#[test]
fn browser_capture_json_output_contains_machine_report_fields() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let response = handle_mitm_browser_capture_apply(&platform, true);

    let rendered = render_response(&response, OutputFormat::Json);
    let json: serde_json::Value =
        serde_json::from_str(&rendered).expect("browser capture response should be valid JSON");

    assert_eq!(json["ok"].as_bool(), Some(false));
    assert_eq!(json["command"], "mitm browser-capture apply");
    assert_eq!(json["browser_capture"]["action"], "apply");
    assert_eq!(
        json["browser_capture"]["source_contract_status"],
        MITM_BROWSER_CAPTURE_SOURCE_CONTRACT_STATUS
    );
    assert_eq!(json["browser_capture"]["gate"], MITM_BROWSER_CAPTURE_GATE);
    assert_eq!(
        json["browser_capture"]["gate_status"],
        MITM_BROWSER_CAPTURE_GATE_STATUS
    );
    assert_eq!(
        json["browser_capture"]["mutation_ready"].as_bool(),
        Some(MITM_BROWSER_CAPTURE_MUTATION_READY)
    );
    assert_eq!(
        json["browser_capture"]["request"]["authorization"]["confirmed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        json["browser_capture"]["plan"]["planned_proxy_host"],
        MITM_BROWSER_CAPTURE_PROXY_HOST
    );
    assert_eq!(
        json["browser_capture"]["plan"]["planned_proxy_scheme"],
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME
    );
    assert_eq!(
        json["browser_capture"]["plan"]["manual_launch"]["status"],
        "manual-launch-plan-ready"
    );
    assert_eq!(
        json["browser_capture"]["plan"]["manual_launch"]["proxy_url"],
        "http://127.0.0.1:7890"
    );
    assert_eq!(
        json["browser_capture"]["plan"]["manual_launch"]["plugin_id"],
        mitm_policy::MITM_POLICY_AD_BLOCK_PLUGIN_ID
    );
    assert!(
        json["browser_capture"]["plan"]["manual_launch"]["browser_commands"]
            .as_array()
            .expect("browser commands should be an array")
            .iter()
            .any(|command| command["browser"].as_str() == Some("chromium")
                && command["command"]
                    .as_str()
                    .expect("browser command should be a string")
                    .contains("--proxy-server=http://127.0.0.1:7890"))
    );
    assert_eq!(json["browser_capture"]["apply_report"]["status"], "blocked");
    assert_eq!(
        json["browser_capture"]["apply_report"]["applied"].as_bool(),
        Some(false)
    );
    assert!(
        json["browser_capture"]["apply_report"]["blocked_operations"]
            .as_array()
            .expect("blocked operations should be an array")
            .iter()
            .any(|operation| operation.as_str() == Some("write-system-proxy"))
    );
}

#[test]
fn browser_capture_pac_apply_json_output_contains_artifact_fields() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let response = handle_mitm_browser_capture_apply_with_store(
        &platform,
        &TestBrowserCapturePacFileStore,
        Some("/tmp/networkcore-browser-capture.pac"),
        None,
        Some("/tmp/networkcore-browser-capture.snapshot.json"),
        true,
    );

    let rendered = render_response(&response, OutputFormat::Json);
    let json: serde_json::Value = serde_json::from_str(&rendered)
        .expect("browser capture PAC apply response should be valid JSON");

    assert_eq!(json["ok"].as_bool(), Some(true));
    assert_eq!(json["command"], "mitm browser-capture apply");
    assert_eq!(json["browser_capture"]["action"], "apply");
    assert_eq!(
        json["browser_capture"]["request"]["pac"]["proxy_url"],
        "http://127.0.0.1:7890"
    );
    assert_eq!(
        json["browser_capture"]["request"]["pac"]["proxy_scheme"],
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME
    );
    assert_eq!(
        json["browser_capture"]["request"]["pac"]["pac_file_path"],
        "/tmp/networkcore-browser-capture.pac"
    );
    assert_eq!(
        json["browser_capture"]["request"]["pac"]["snapshot_path"],
        "/tmp/networkcore-browser-capture.snapshot.json"
    );
    assert_eq!(
        json["browser_capture"]["request"]["pac"]["pac_url"],
        "file:///tmp/networkcore-browser-capture.pac"
    );
    assert!(json["browser_capture"]["request"]["pac"]["policy_file_path"].is_null());
    assert!(json["browser_capture"]["request"]["pac"]["policy_url"].is_null());
    assert!(json["browser_capture"]["request"]["pac"]["policy_content"].is_null());
    assert_eq!(json["browser_capture"]["apply_report"]["status"], "applied");
    assert_eq!(
        json["browser_capture"]["apply_report"]["applied"].as_bool(),
        Some(true)
    );
    assert_eq!(
        json["browser_capture"]["apply_report"]["pac_file_path"],
        "/tmp/networkcore-browser-capture.pac"
    );
    assert_eq!(
        json["browser_capture"]["apply_report"]["pac_url"],
        "file:///tmp/networkcore-browser-capture.pac"
    );
    assert!(json["browser_capture"]["apply_report"]["policy_file_path"].is_null());
    assert!(json["browser_capture"]["apply_report"]["policy_url"].is_null());
    assert_eq!(
        json["browser_capture"]["apply_report"]["rollback_snapshot"]["status"],
        "networkcore-created"
    );
}

#[test]
fn browser_capture_launch_json_output_contains_process_report_fields() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let response = handle_mitm_browser_capture_launch(
        &platform,
        &TestBrowserCaptureRunner,
        "chromium",
        MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR,
        Some("https://example.com/capture"),
        Some("browser-proof-123"),
        Some("/tmp/networkcore-browser-proof.log"),
        true,
    );

    let rendered = render_response(&response, OutputFormat::Json);
    let json: serde_json::Value =
        serde_json::from_str(&rendered).expect("browser launch response should be valid JSON");

    assert_eq!(json["ok"].as_bool(), Some(true));
    assert_eq!(json["command"], "mitm browser-capture launch");
    assert_eq!(json["browser_capture"]["action"], "launch");
    assert_eq!(
        json["browser_capture"]["request"]["launch"]["browser"],
        "chromium"
    );
    assert_eq!(
        json["browser_capture"]["request"]["launch"]["profile_dir"],
        MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR
    );
    assert_eq!(
        json["browser_capture"]["request"]["launch"]["target_url"],
        "https://example.com/capture"
    );
    assert_eq!(
        json["browser_capture"]["request"]["launch"]["proof_target_url"],
        "https://example.com/capture?networkcore_proof_token=browser-proof-123"
    );
    assert_eq!(
        json["browser_capture"]["request"]["launch"]["proof_token"],
        "browser-proof-123"
    );
    assert_eq!(
        json["browser_capture"]["request"]["launch"]["proof_log_path"],
        "/tmp/networkcore-browser-proof.log"
    );
    assert_eq!(
        json["browser_capture"]["request"]["launch"]["proxy_scheme"],
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME
    );
    assert!(
        json["browser_capture"]["request"]["launch"]["traffic_proof_command"]
            .as_str()
            .expect("traffic proof command should be a string")
            .contains("--proof-token browser-proof-123")
    );
    assert_eq!(
        json["browser_capture"]["launch_report"]["status"],
        "started"
    );
    assert_eq!(
        json["browser_capture"]["launch_report"]["launched"].as_bool(),
        Some(true)
    );
    assert_eq!(
        json["browser_capture"]["launch_report"]["pid"].as_u64(),
        Some(4242)
    );
    assert_eq!(
        json["browser_capture"]["launch_report"]["request"]["command"]["executable"],
        "chromium"
    );
    assert!(
        json["browser_capture"]["launch_report"]["request"]["command"]["args"]
            .as_array()
            .expect("launch args should be an array")
            .iter()
            .any(|arg| arg.as_str() == Some("--proxy-server=http://127.0.0.1:7890"))
    );
    assert!(
        json["browser_capture"]["launch_report"]["request"]["command"]["args"]
            .as_array()
            .expect("launch args should be an array")
            .iter()
            .any(|arg| arg.as_str()
                == Some("https://example.com/capture?networkcore_proof_token=browser-proof-123"))
    );
    assert_eq!(
        json["browser_capture"]["launch_report"]["plugin_id"],
        mitm_policy::MITM_POLICY_AD_BLOCK_PLUGIN_ID
    );
}

#[test]
fn browser_capture_verify_json_output_contains_endpoint_probe_fields() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let probe = TestBrowserCaptureEndpointProbe { reachable: true };
    let response = handle_mitm_browser_capture_verify_with_probe(
        &platform,
        &probe,
        Some("https://example.com/capture"),
        true,
    );

    let rendered = render_response(&response, OutputFormat::Json);
    let json: serde_json::Value =
        serde_json::from_str(&rendered).expect("browser verify response should be valid JSON");

    assert_eq!(json["ok"].as_bool(), Some(true));
    assert_eq!(json["command"], "mitm browser-capture verify");
    assert_eq!(json["browser_capture"]["action"], "verify");
    assert_eq!(
        json["browser_capture"]["request"]["authorization"]["confirmed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        json["browser_capture"]["request"]["verify"]["proxy_url"],
        "http://127.0.0.1:7890"
    );
    assert_eq!(
        json["browser_capture"]["request"]["verify"]["proxy_scheme"],
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME
    );
    assert_eq!(
        json["browser_capture"]["request"]["verify"]["target_url"],
        "https://example.com/capture"
    );
    assert_eq!(
        json["browser_capture"]["verify_report"]["status"],
        "target_reachable"
    );
    assert_eq!(
        json["browser_capture"]["verify_report"]["verified"].as_bool(),
        Some(true)
    );
    assert_eq!(
        json["browser_capture"]["verify_report"]["request"]["probe"],
        "http-connect-target"
    );
    assert_eq!(
        json["browser_capture"]["verify_report"]["request"]["target_url"],
        "https://example.com/capture"
    );
    assert_eq!(
        json["browser_capture"]["verify_report"]["plugin_id"],
        mitm_policy::MITM_POLICY_AD_BLOCK_PLUGIN_ID
    );
}

#[test]
fn browser_capture_traffic_proof_json_output_contains_proof_fields() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let probe = TestBrowserCaptureTrafficProofProbe { observed: true };
    let response = handle_mitm_browser_capture_traffic_proof_with_probe(
        &platform,
        &probe,
        Some("https://example.com/capture"),
        Some("browser-proof-123"),
        Some("/tmp/networkcore-browser-proof.log"),
        true,
    );

    let rendered = render_response(&response, OutputFormat::Json);
    let json: serde_json::Value = serde_json::from_str(&rendered)
        .expect("browser traffic-proof response should be valid JSON");

    assert_eq!(json["ok"].as_bool(), Some(true));
    assert_eq!(json["command"], "mitm browser-capture traffic-proof");
    assert_eq!(json["browser_capture"]["action"], "traffic-proof");
    assert_eq!(
        json["browser_capture"]["request"]["authorization"]["confirmed"].as_bool(),
        Some(true)
    );
    assert_eq!(
        json["browser_capture"]["request"]["traffic_proof"]["proxy_url"],
        "http://127.0.0.1:7890"
    );
    assert_eq!(
        json["browser_capture"]["request"]["traffic_proof"]["proxy_scheme"],
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME
    );
    assert_eq!(
        json["browser_capture"]["request"]["traffic_proof"]["target_url"],
        "https://example.com/capture"
    );
    assert_eq!(
        json["browser_capture"]["request"]["traffic_proof"]["proof_connect_authority"],
        "example.com:443"
    );
    assert_eq!(
        json["browser_capture"]["request"]["traffic_proof"]["proof_target_url"],
        "https://example.com/capture?networkcore_proof_token=browser-proof-123"
    );
    assert_eq!(
        json["browser_capture"]["request"]["traffic_proof"]["proof_token"],
        "browser-proof-123"
    );
    assert_eq!(
        json["browser_capture"]["request"]["traffic_proof"]["proof_log_path"],
        "/tmp/networkcore-browser-proof.log"
    );
    assert_eq!(
        json["browser_capture"]["request"]["traffic_proof"]["probe"],
        "proof-log-token"
    );
    assert_eq!(
        json["browser_capture"]["traffic_proof_report"]["status"],
        "observed"
    );
    assert_eq!(
        json["browser_capture"]["traffic_proof_report"]["proven"].as_bool(),
        Some(true)
    );
    assert_eq!(
        json["browser_capture"]["traffic_proof_report"]["request"]["proof_log_path"],
        "/tmp/networkcore-browser-proof.log"
    );
    assert_eq!(
        json["browser_capture"]["traffic_proof_report"]["plugin_id"],
        mitm_policy::MITM_POLICY_AD_BLOCK_PLUGIN_ID
    );
}

#[test]
fn browser_capture_session_plan_json_output_contains_session_fields() {
    let platform =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());
    let response = handle_mitm_browser_capture_session_plan(
        &platform,
        "ss://YWVzLTI1Ni1nY206ZjQzYzBlZWUtMTNiOS00ZjA3LWJlYzktZDRiNzQ0MTQxNTAz@82.47.34.99:11111#%E9%A6%99%E6%B8%AF",
        "chromium",
        MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR,
        Some("https://example.com/capture"),
        Some("browser-proof-123"),
        Some("/tmp/networkcore-browser-proof.log"),
        "127.0.0.1",
        7890,
    );

    let rendered = render_response(&response, OutputFormat::Json);
    let json: serde_json::Value = serde_json::from_str(&rendered)
        .expect("browser session-plan response should be valid JSON");

    assert_eq!(json["ok"].as_bool(), Some(true));
    assert_eq!(json["command"], "mitm browser-capture session-plan");
    assert_eq!(json["browser_capture"]["action"], "session-plan");
    assert_eq!(
        json["browser_capture"]["request"]["session"]["url_source"],
        "cli-argument-redacted"
    );
    assert_eq!(
        json["browser_capture"]["request"]["session"]["browser"],
        "chromium"
    );
    assert_eq!(
        json["browser_capture"]["request"]["session"]["target_url"],
        "https://example.com/capture"
    );
    assert_eq!(
        json["browser_capture"]["request"]["session"]["proof_target_url"],
        "https://example.com/capture?networkcore_proof_token=browser-proof-123"
    );
    assert_eq!(
        json["browser_capture"]["request"]["session"]["proof_token"],
        "browser-proof-123"
    );
    assert_eq!(
        json["browser_capture"]["request"]["session"]["proof_log_path"],
        "/tmp/networkcore-browser-proof.log"
    );
    assert_eq!(
        json["browser_capture"]["request"]["launch"]["target_url"],
        "https://example.com/capture"
    );
    assert_eq!(
        json["browser_capture"]["request"]["launch"]["proof_target_url"],
        "https://example.com/capture?networkcore_proof_token=browser-proof-123"
    );
    assert_eq!(
        json["browser_capture"]["request"]["launch"]["proxy_url"],
        "http://127.0.0.1:7890"
    );
    assert_eq!(
        json["browser_capture"]["request"]["launch"]["proxy_scheme"],
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME
    );
    assert_eq!(
        json["browser_capture"]["request"]["verify"]["proxy_url"],
        "http://127.0.0.1:7890"
    );
    assert_eq!(
        json["browser_capture"]["request"]["verify"]["proxy_scheme"],
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME
    );
    assert_eq!(
        json["browser_capture"]["request"]["verify"]["target_url"],
        "https://example.com/capture"
    );
    assert_eq!(json["browser_capture"]["session_plan"]["status"], "ready");
    assert_eq!(
        json["browser_capture"]["session_plan"]["node_id"],
        "ss-82-47-34-99-11111"
    );
    assert_eq!(json["browser_capture"]["session_plan"]["node_name"], "香港");
    assert_eq!(
        json["browser_capture"]["session_plan"]["target_url"],
        "https://example.com/capture"
    );
    assert_eq!(
        json["browser_capture"]["session_plan"]["proof_target_url"],
        "https://example.com/capture?networkcore_proof_token=browser-proof-123"
    );
    assert_eq!(
        json["browser_capture"]["session_plan"]["proof_token"],
        "browser-proof-123"
    );
    assert_eq!(
        json["browser_capture"]["session_plan"]["proof_log_path"],
        "/tmp/networkcore-browser-proof.log"
    );
    assert_eq!(
        json["browser_capture"]["session_plan"]["proxy_url"],
        "http://127.0.0.1:7890"
    );
    assert_eq!(
        json["browser_capture"]["session_plan"]["proxy_scheme"],
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME
    );
    assert_eq!(
        json["browser_capture"]["session_plan"]["verify_command"],
        "networkcore-linux mitm browser-capture verify --confirm --target-url https://example.com/capture"
    );
    assert!(
        json["browser_capture"]["session_plan"]["traffic_proof_command"]
            .as_str()
            .expect("traffic proof command should be a string")
            .contains("--proof-token browser-proof-123")
    );
    assert_eq!(
        json["browser_capture"]["session_plan"]["browser_command"]["executable"],
        "chromium"
    );
    assert_eq!(
        json["browser_capture"]["session_plan"]["plugin_id"],
        mitm_policy::MITM_POLICY_AD_BLOCK_PLUGIN_ID
    );
    assert!(json["browser_capture"]["session_plan"]["required_steps"]
        .as_array()
        .expect("required steps should be an array")
        .iter()
        .any(|step| step
            .as_str()
            .expect("step should be a string")
            .contains("launch the dedicated browser profile")));
}

fn available_orchestrator() -> RuntimeOrchestrator<
    TestConfigurationService,
    StaticLinuxPlatformCapabilityService,
    TestProxyEngineService,
> {
    RuntimeOrchestrator::new(
        TestConfigurationService,
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests()),
        TestProxyEngineService,
    )
}

struct MemoryConfigReader {
    result: Result<String, String>,
}

impl MemoryConfigReader {
    fn ok(content: impl Into<String>) -> Self {
        Self {
            result: Ok(content.into()),
        }
    }

    fn err(message: impl Into<String>) -> Self {
        Self {
            result: Err(message.into()),
        }
    }
}

impl ConfigReader for MemoryConfigReader {
    fn read_config(&self, _path: &str) -> Result<String, ConfigReadError> {
        self.result.clone().map_err(ConfigReadError::new)
    }
}

struct MemoryLinuxReadOnlyProbe {
    snapshot: LinuxReadOnlyProbeSnapshot,
}

impl MemoryLinuxReadOnlyProbe {
    fn new(snapshot: LinuxReadOnlyProbeSnapshot) -> Self {
        Self { snapshot }
    }
}

impl LinuxReadOnlyProbe for MemoryLinuxReadOnlyProbe {
    fn snapshot(&self) -> LinuxReadOnlyProbeSnapshot {
        self.snapshot.clone()
    }
}

struct TestForegroundLifecycleHost {
    outcome: ForegroundLifecycleOutcome,
}

impl TestForegroundLifecycleHost {
    fn success(diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            outcome: ForegroundLifecycleOutcome::success(diagnostics),
        }
    }
}

impl ForegroundLifecycleHost for TestForegroundLifecycleHost {
    fn run_foreground(&self, request: &ForegroundLifecycleRequest) -> ForegroundLifecycleOutcome {
        assert_eq!(request.engine_status.engine_id.as_str(), DEFAULT_ENGINE_ID);
        self.outcome.clone()
    }
}

struct TestForegroundLifecycleInterruptionSource {
    reason: String,
    diagnostics: Vec<Diagnostic>,
}

struct TestSingBoxInstaller;

impl SingBoxReleaseInstaller for TestSingBoxInstaller {
    fn install_latest(
        &self,
        request: &SingBoxInstallRequest,
    ) -> DomainResult<SingBoxInstallReport> {
        assert!(request.install_root.ends_with("networkcore-engines"));
        Ok(SingBoxInstallReport {
            version: "1.2.3".to_string(),
            target: request.target,
            asset_name: "sing-box-1.2.3-linux-amd64.tar.gz".to_string(),
            asset_url: "https://example.invalid/sing-box.tar.gz".to_string(),
            asset_sha256: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            archive_path: request
                .install_root
                .join("1.2.3")
                .join(request.target.directory_name())
                .join("downloads")
                .join("sing-box-1.2.3-linux-amd64.tar.gz"),
            executable_path: request
                .install_root
                .join("1.2.3")
                .join(request.target.directory_name())
                .join("bin")
                .join(request.target.executable_name()),
            downloaded: true,
            diagnostics: vec![Diagnostic::new(
                DiagnosticSeverity::Info,
                ENGINE_SINGBOX_DOWNLOAD_BINARY_READY_CODE,
                "sing-box executable is ready",
                Some("engine.singbox.download".to_string()),
            )],
        })
    }
}

impl TestForegroundLifecycleInterruptionSource {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            diagnostics: Vec::new(),
        }
    }

    fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }
}

impl ForegroundLifecycleInterruptionSource for TestForegroundLifecycleInterruptionSource {
    fn wait_for_interruption(
        &self,
        request: &ForegroundLifecycleRequest,
    ) -> ForegroundLifecycleInterruption {
        assert_eq!(request.engine_status.engine_id.as_str(), DEFAULT_ENGINE_ID);
        ForegroundLifecycleInterruption::new(self.reason.clone())
            .with_diagnostics(self.diagnostics.clone())
    }
}

struct TestSingBoxRunner;

impl SingBoxProcessRunner for TestSingBoxRunner {
    fn run(&self, request: &SingBoxProcessRunRequest) -> DomainResult<SingBoxProcessRunReport> {
        let executable_name = request
            .executable_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("executable path should have a file name");
        assert!(matches!(executable_name, "sing-box" | "sing-box.exe"));
        let config = std::fs::read_to_string(&request.config_path)
            .expect("run-url should write a sing-box config before starting the runner");
        assert!(config.contains("\"type\": \"mixed\""));
        assert!(config.contains("\"listen_port\": 7890"));
        assert!(config.contains("\"type\": \"shadowsocks\""));
        assert!(config.contains("\"server\": \"82.47.34.99\""));
        assert!(config.contains("\"method\": \"aes-256-gcm\""));
        assert!(config.contains("\"password\": \"f43c0eee-13b9-4f07-bec9-d4b744141503\""));

        Ok(SingBoxProcessRunReport {
            exit_code: Some(0),
            diagnostics: vec![Diagnostic::new(
                DiagnosticSeverity::Info,
                ENGINE_SINGBOX_PROCESS_EXITED_CODE,
                "sing-box test runner exited",
                Some("engine.singbox.lifecycle".to_string()),
            )],
        })
    }
}

struct TestBrowserCaptureRunner;

impl BrowserCaptureProcessRunner for TestBrowserCaptureRunner {
    fn launch(
        &self,
        request: &LinuxBrowserCaptureLaunchRequest,
    ) -> DomainResult<LinuxBrowserCaptureLaunchOutcome> {
        assert_eq!(
            request.proxy_scheme,
            MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME
        );
        assert_eq!(request.proxy_url, "http://127.0.0.1:7890");
        assert!(request
            .command
            .args
            .iter()
            .any(|arg| arg.starts_with("--user-data-dir=")));
        assert!(request
            .command
            .args
            .iter()
            .any(|arg| arg == "--proxy-server=http://127.0.0.1:7890"));

        Ok(LinuxBrowserCaptureLaunchOutcome {
            pid: 4242,
            diagnostics: vec![Diagnostic::new(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_LAUNCH_STARTED_CODE,
                "browser capture test runner started",
                Some("cli.mitm".to_string()),
            )],
        })
    }
}

struct TestSocks5BrowserCaptureRunner;

impl BrowserCaptureProcessRunner for TestSocks5BrowserCaptureRunner {
    fn launch(
        &self,
        request: &LinuxBrowserCaptureLaunchRequest,
    ) -> DomainResult<LinuxBrowserCaptureLaunchOutcome> {
        assert_eq!(
            request.proxy_scheme,
            MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME
        );
        assert_eq!(request.proxy_url, "socks5://127.0.0.1:7890");
        assert!(request
            .command
            .args
            .iter()
            .any(|arg| arg == "--proxy-server=socks5://127.0.0.1:7890"));

        Ok(LinuxBrowserCaptureLaunchOutcome {
            pid: 5252,
            diagnostics: vec![Diagnostic::new(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_LAUNCH_STARTED_CODE,
                "browser capture socks5 test runner started",
                Some("cli.mitm".to_string()),
            )],
        })
    }
}

struct TestBrowserCaptureEndpointProbe {
    reachable: bool,
}

impl BrowserCaptureEndpointProbe for TestBrowserCaptureEndpointProbe {
    fn verify_proxy_endpoint(
        &self,
        request: &LinuxBrowserCaptureVerifyRequest,
    ) -> DomainResult<LinuxBrowserCaptureVerifyOutcome> {
        assert_eq!(request.proxy_host, "127.0.0.1");
        assert_eq!(request.proxy_port, 7890);
        assert_eq!(
            request.proxy_scheme,
            MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME
        );
        assert_eq!(request.proxy_url, "http://127.0.0.1:7890");
        if request.target_url.is_some() {
            assert_eq!(
                request.target_url.as_deref(),
                Some("https://example.com/capture")
            );
            assert_eq!(request.probe, "http-connect-target");
        } else {
            assert_eq!(request.probe, "tcp-connect-timeout");
        }

        if self.reachable {
            let code = if request.target_url.is_some() {
                CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_REACHABLE_CODE
            } else {
                CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_REACHABLE_CODE
            };
            Ok(LinuxBrowserCaptureVerifyOutcome {
                diagnostics: vec![Diagnostic::new(
                    DiagnosticSeverity::Info,
                    code,
                    "browser capture test proxy endpoint is reachable",
                    Some("cli.mitm".to_string()),
                )],
            })
        } else {
            Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                "browser capture test proxy endpoint is unreachable",
            ))
        }
    }
}

struct TestBrowserCaptureTrafficProofProbe {
    observed: bool,
}

impl BrowserCaptureTrafficProofProbe for TestBrowserCaptureTrafficProofProbe {
    fn verify_traffic_proof(
        &self,
        request: &LinuxBrowserCaptureTrafficProofRequest,
    ) -> DomainResult<LinuxBrowserCaptureTrafficProofOutcome> {
        assert_eq!(request.proxy_host, "127.0.0.1");
        assert_eq!(request.proxy_port, 7890);
        assert_eq!(
            request.proxy_scheme,
            MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME
        );
        assert_eq!(request.proxy_url, "http://127.0.0.1:7890");
        if request.proof_log_path == MITM_BROWSER_CAPTURE_DEFAULT_PROOF_LOG_PATH {
            assert!(request
                .proof_token
                .starts_with("networkcore-browser-proof-"));
        } else {
            assert_eq!(request.proof_token, "browser-proof-123");
            assert_eq!(request.proof_log_path, "/tmp/networkcore-browser-proof.log");
        }
        assert_eq!(request.probe, "proof-log-token");

        if self.observed {
            Ok(LinuxBrowserCaptureTrafficProofOutcome {
                diagnostics: vec![Diagnostic::new(
                    DiagnosticSeverity::Info,
                    CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_OBSERVED_CODE,
                    "browser capture proof token was observed by the test probe",
                    Some("cli.mitm".to_string()),
                )],
            })
        } else {
            Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_MISSING_CODE,
                "browser capture proof token was not observed by the test probe",
            ))
        }
    }
}

struct TestBrowserCapturePacFileStore;

struct TestMitmCertificateArtifactStore;

impl MitmCertificateArtifactStore for TestMitmCertificateArtifactStore {
    fn apply_certificate_artifact(
        &self,
        request: &LinuxMitmCertificateArtifactRequest,
    ) -> DomainResult<LinuxMitmCertificateArtifactApplyOutcome> {
        assert_eq!(request.cert_file_path, "/tmp/networkcore-mitm-ca.crt");
        assert_eq!(request.key_file_path, "/tmp/networkcore-mitm-ca.key");
        assert!(request.profile_trust_file_path.is_none());
        assert_eq!(
            request.snapshot_path,
            "/tmp/networkcore-mitm-ca.snapshot.json"
        );
        assert_eq!(request.subject, MITM_CERTIFICATE_ARTIFACT_SUBJECT);
        assert_eq!(request.artifact_version, 2);
        assert!(request.cert_content.contains("-----BEGIN CERTIFICATE-----"));
        assert!(request.key_content.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(!request.cert_content.contains("NETWORKCORE MITM CA"));
        assert!(!request.key_content.contains("NETWORKCORE MITM CA"));
        assert!(request.profile_trust_content.is_none());
        assert!(!request.cert_fingerprint.is_empty());
        assert!(!request.key_fingerprint.is_empty());
        assert!(request.profile_trust_fingerprint.is_none());

        Ok(LinuxMitmCertificateArtifactApplyOutcome {
            rollback_snapshot: MitmCertificateRollbackSnapshot {
                path: request.snapshot_path.clone(),
                status: "networkcore-created".to_string(),
            },
            diagnostics: vec![Diagnostic::new(
                DiagnosticSeverity::Info,
                CLI_MITM_CERTIFICATE_APPLY_READY_CODE,
                "MITM certificate artifacts were written by the test store",
                Some("cli.mitm".to_string()),
            )],
        })
    }

    fn rollback_certificate_artifact(
        &self,
        snapshot: &MitmCertificateRollbackSnapshot,
    ) -> DomainResult<LinuxMitmCertificateArtifactRollbackOutcome> {
        assert_eq!(snapshot.path, "/tmp/networkcore-mitm-ca.snapshot.json");

        Ok(LinuxMitmCertificateArtifactRollbackOutcome {
            cert_file_path: "/tmp/networkcore-mitm-ca.crt".to_string(),
            key_file_path: "/tmp/networkcore-mitm-ca.key".to_string(),
            profile_trust_file_path: None,
            diagnostics: vec![Diagnostic::new(
                DiagnosticSeverity::Info,
                CLI_MITM_CERTIFICATE_ROLLBACK_READY_CODE,
                "MITM certificate artifacts were removed by the test store",
                Some("cli.mitm".to_string()),
            )],
        })
    }
}

impl BrowserCapturePacFileStore for TestBrowserCapturePacFileStore {
    fn apply_pac_file(
        &self,
        request: &LinuxBrowserCapturePacRequest,
    ) -> DomainResult<LinuxBrowserCapturePacApplyOutcome> {
        assert_eq!(request.proxy_host, "127.0.0.1");
        assert_eq!(request.proxy_port, 7890);
        assert_eq!(
            request.proxy_scheme,
            MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME
        );
        assert_eq!(request.proxy_url, "http://127.0.0.1:7890");
        assert_eq!(
            request.pac_file_path,
            "/tmp/networkcore-browser-capture.pac"
        );
        assert_eq!(
            request.snapshot_path,
            "/tmp/networkcore-browser-capture.snapshot.json"
        );
        assert_eq!(
            request.pac_url,
            "file:///tmp/networkcore-browser-capture.pac"
        );
        assert!(request.pac_content.contains("PROXY 127.0.0.1:7890; DIRECT"));
        assert!(request.policy_file_path.is_none());
        assert!(request.policy_url.is_none());
        assert!(request.policy_content.is_none());

        Ok(LinuxBrowserCapturePacApplyOutcome {
            rollback_snapshot: networkcore_linux::BrowserCaptureRollbackSnapshot {
                path: request.snapshot_path.clone(),
                status: "networkcore-created".to_string(),
            },
            diagnostics: vec![Diagnostic::new(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_APPLY_READY_CODE,
                "browser capture PAC file was written by the test store",
                Some("cli.mitm".to_string()),
            )],
        })
    }

    fn rollback_pac_file(
        &self,
        snapshot: &networkcore_linux::BrowserCaptureRollbackSnapshot,
    ) -> DomainResult<LinuxBrowserCapturePacRollbackOutcome> {
        assert_eq!(
            snapshot.path,
            "/tmp/networkcore-browser-capture.snapshot.json"
        );

        Ok(LinuxBrowserCapturePacRollbackOutcome {
            pac_file_path: "/tmp/networkcore-browser-capture.pac".to_string(),
            policy_file_path: None,
            profile_prefs_file_path: None,
            diagnostics: vec![Diagnostic::new(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_ROLLBACK_READY_CODE,
                "browser capture PAC file was removed by the test store",
                Some("cli.mitm".to_string()),
            )],
        })
    }
}

struct TestBrowserCapturePolicyFileStore;

impl BrowserCapturePacFileStore for TestBrowserCapturePolicyFileStore {
    fn apply_pac_file(
        &self,
        request: &LinuxBrowserCapturePacRequest,
    ) -> DomainResult<LinuxBrowserCapturePacApplyOutcome> {
        assert_eq!(request.proxy_url, "http://127.0.0.1:7890");
        assert_eq!(
            request.pac_file_path,
            "/tmp/networkcore-browser-capture.pac"
        );
        assert_eq!(
            request.policy_file_path.as_deref(),
            Some("/tmp/networkcore-browser-capture-policy.json")
        );
        assert_eq!(
            request.policy_url.as_deref(),
            Some("file:///tmp/networkcore-browser-capture-policy.json")
        );
        let policy_content = request
            .policy_content
            .as_ref()
            .expect("policy content should be present for policy file apply");
        assert!(policy_content.contains("\"ProxyMode\": \"fixed_servers\""));
        assert!(policy_content.contains("\"ProxyServer\": \"http://127.0.0.1:7890\""));
        assert!(policy_content.contains("\"ProxyBypassList\": \"<-loopback>\""));

        Ok(LinuxBrowserCapturePacApplyOutcome {
            rollback_snapshot: networkcore_linux::BrowserCaptureRollbackSnapshot {
                path: request.snapshot_path.clone(),
                status: "networkcore-created".to_string(),
            },
            diagnostics: vec![Diagnostic::new(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_APPLY_READY_CODE,
                "browser capture PAC and policy files were written by the test store",
                Some("cli.mitm".to_string()),
            )],
        })
    }

    fn rollback_pac_file(
        &self,
        snapshot: &networkcore_linux::BrowserCaptureRollbackSnapshot,
    ) -> DomainResult<LinuxBrowserCapturePacRollbackOutcome> {
        assert_eq!(
            snapshot.path,
            "/tmp/networkcore-browser-capture.snapshot.json"
        );

        Ok(LinuxBrowserCapturePacRollbackOutcome {
            pac_file_path: "/tmp/networkcore-browser-capture.pac".to_string(),
            policy_file_path: Some("/tmp/networkcore-browser-capture-policy.json".to_string()),
            profile_prefs_file_path: None,
            diagnostics: Vec::new(),
        })
    }
}

struct TestSocks5BrowserCapturePacFileStore;

impl BrowserCapturePacFileStore for TestSocks5BrowserCapturePacFileStore {
    fn apply_pac_file(
        &self,
        request: &LinuxBrowserCapturePacRequest,
    ) -> DomainResult<LinuxBrowserCapturePacApplyOutcome> {
        assert_eq!(
            request.proxy_scheme,
            MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME
        );
        assert_eq!(request.proxy_url, "socks5://127.0.0.1:7890");
        assert!(request
            .pac_content
            .contains("SOCKS5 127.0.0.1:7890; DIRECT"));
        if let Some(policy_content) = &request.policy_content {
            assert!(policy_content.contains("\"ProxyMode\": \"fixed_servers\""));
            assert!(policy_content.contains("\"ProxyServer\": \"socks5://127.0.0.1:7890\""));
        }

        Ok(LinuxBrowserCapturePacApplyOutcome {
            rollback_snapshot: networkcore_linux::BrowserCaptureRollbackSnapshot {
                path: request.snapshot_path.clone(),
                status: "networkcore-created".to_string(),
            },
            diagnostics: vec![Diagnostic::new(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_APPLY_READY_CODE,
                "browser capture SOCKS5 PAC file was written by the test store",
                Some("cli.mitm".to_string()),
            )],
        })
    }

    fn rollback_pac_file(
        &self,
        _snapshot: &networkcore_linux::BrowserCaptureRollbackSnapshot,
    ) -> DomainResult<LinuxBrowserCapturePacRollbackOutcome> {
        Ok(LinuxBrowserCapturePacRollbackOutcome {
            pac_file_path: "/tmp/networkcore-browser-capture.pac".to_string(),
            policy_file_path: None,
            profile_prefs_file_path: None,
            diagnostics: Vec::new(),
        })
    }
}

struct TestConfigurationService;

impl ConfigurationService for TestConfigurationService {
    fn validate(&self, raw_config: &str, _capabilities: &PlatformCapabilities) -> Vec<Diagnostic> {
        if raw_config.contains("invalid") {
            vec![Diagnostic::new(
                DiagnosticSeverity::Error,
                "config.invalid",
                "configuration is invalid",
                Some("config".to_string()),
            )]
        } else {
            Vec::new()
        }
    }

    fn normalize(
        &self,
        _raw_config: &str,
        _capabilities: &PlatformCapabilities,
    ) -> DomainResult<ConfigSnapshot> {
        Ok(ConfigSnapshot {
            version: SchemaVersion::new(1),
            profiles: vec!["default".to_string()],
            listeners: Vec::new(),
            nodes: Vec::new(),
            policies: Vec::new(),
            dns: Vec::new(),
            plugins: Vec::new(),
        })
    }

    fn migrate(
        &self,
        raw_config: &str,
        _from_version: SchemaVersion,
        _to_version: SchemaVersion,
    ) -> DomainResult<String> {
        Ok(raw_config.to_string())
    }
}

struct TestProxyEngineService;

impl ProxyEngineService for TestProxyEngineService {
    fn list_engines(&self) -> Vec<ProxyEngineDescriptor> {
        Vec::new()
    }

    fn validate_config(&self, _engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
        Vec::new()
    }

    fn start(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        Ok(ProxyEngineStatus {
            engine_id: engine_config.engine_id.clone(),
            state: ProxyEngineLifecycleState::Running,
            diagnostics: Vec::new(),
        })
    }

    fn reload(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        Ok(ProxyEngineStatus {
            engine_id: engine_config.engine_id.clone(),
            state: ProxyEngineLifecycleState::Running,
            diagnostics: Vec::new(),
        })
    }

    fn stop(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        Ok(ProxyEngineStatus {
            engine_id: engine_id.to_string(),
            state: ProxyEngineLifecycleState::Stopped,
            diagnostics: Vec::new(),
        })
    }

    fn status(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        Ok(ProxyEngineStatus {
            engine_id: engine_id.to_string(),
            state: ProxyEngineLifecycleState::Stopped,
            diagnostics: Vec::new(),
        })
    }

    fn events(&self, _engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
        Ok(Vec::new())
    }
}

struct StopFailingProxyEngineService;

impl ProxyEngineService for StopFailingProxyEngineService {
    fn list_engines(&self) -> Vec<ProxyEngineDescriptor> {
        Vec::new()
    }

    fn validate_config(&self, _engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
        Vec::new()
    }

    fn start(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        Ok(ProxyEngineStatus {
            engine_id: engine_config.engine_id.clone(),
            state: ProxyEngineLifecycleState::Running,
            diagnostics: Vec::new(),
        })
    }

    fn reload(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        Ok(ProxyEngineStatus {
            engine_id: engine_config.engine_id.clone(),
            state: ProxyEngineLifecycleState::Running,
            diagnostics: Vec::new(),
        })
    }

    fn stop(&self, _engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        Err(DomainError::new(
            "engine.stop.failed",
            "engine stop failed during foreground interruption cleanup",
        ))
    }

    fn status(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        Ok(ProxyEngineStatus {
            engine_id: engine_id.to_string(),
            state: ProxyEngineLifecycleState::Running,
            diagnostics: Vec::new(),
        })
    }

    fn events(&self, _engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
        Ok(Vec::new())
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

fn assert_gate(gates: &[networkcore_linux::LinuxMitmGateStatus], gate: &str, status: &str) {
    assert!(
        gates
            .iter()
            .any(|candidate| candidate.gate == gate && candidate.status == status),
        "expected gate {gate}={status}, got {gates:?}"
    );
}

fn runtime_operation_result(
    state: ProxyEngineLifecycleState,
    diagnostics: Vec<Diagnostic>,
) -> RuntimeOperationResult {
    RuntimeOperationResult {
        platform: LinuxPlatformSnapshot::available_for_tests().into_status(),
        capabilities: PlatformCapabilities {
            os: control_domain::OperatingSystem::Linux,
            supports_tunnel: true,
            supports_mitm: true,
            supports_embedded_runtime: true,
        },
        engine_status: ProxyEngineStatus {
            engine_id: DEFAULT_ENGINE_ID.to_string(),
            state,
            diagnostics: Vec::new(),
        },
        diagnostics,
    }
}

fn unused_loopback_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .expect("test should reserve an ephemeral loopback tcp port");
    let port = listener
        .local_addr()
        .expect("reserved listener should expose its local address")
        .port();
    drop(listener);
    port
}
