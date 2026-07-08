use config_core::CoreConfigurationService;
use control_domain::{
    CertificateTrustState, ConfigSnapshot, ConfigurationService, Diagnostic, DiagnosticSeverity,
    DomainError, DomainResult, PlatformCapabilities, PlatformFeatureState, ProxyEngineConfig,
    ProxyEngineDescriptor, ProxyEngineEvent, ProxyEngineLifecycleState, ProxyEngineService,
    ProxyEngineStatus, SchemaVersion,
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
    cli_help_text, handle_capabilities, handle_entrypoint, handle_entrypoint_with_runtime,
    handle_entrypoint_with_runtime_and_lifecycle,
    handle_entrypoint_with_runtime_lifecycle_and_sing_box, handle_foreground_lifecycle,
    handle_foreground_lifecycle_with_runtime_stop, handle_install_sing_box,
    handle_mitm_browser_capture_apply, handle_mitm_browser_capture_plan,
    handle_mitm_browser_capture_rollback, handle_mitm_browser_capture_verify,
    handle_mitm_browser_plan, handle_mitm_certificate_plan, handle_mitm_status, handle_parse_error,
    handle_prepare_config, handle_run_url_with_sing_box, handle_start, handle_status, handle_stop,
    parse_args, render_response, ConfigReadError, ConfigReader,
    CurrentProcessForegroundLifecycleHost, ForegroundLifecycleHost,
    ForegroundLifecycleInterruption, ForegroundLifecycleInterruptionSource,
    ForegroundLifecycleOutcome, ForegroundLifecycleRequest, LinuxCliCommand, LinuxCliExitCode,
    OutputFormat, UnavailableForegroundLifecycleHost, UnavailableProxyEngineService,
    CLI_CONFIG_EMPTY_CODE, CLI_CONFIG_PATH_MISSING_CODE, CLI_CONFIG_READ_FAILED_CODE,
    CLI_MITM_BROWSER_CAPTURE_APPLY_BLOCKED_CODE,
    CLI_MITM_BROWSER_CAPTURE_AUTHORIZATION_REQUIRED_CODE,
    CLI_MITM_BROWSER_CAPTURE_MUTATION_BLOCKED_CODE, CLI_MITM_BROWSER_CAPTURE_ROLLBACK_BLOCKED_CODE,
    CLI_MITM_BROWSER_CAPTURE_VERIFY_BLOCKED_CODE, CLI_MITM_BROWSER_HIJACK_DEFERRED_CODE,
    CLI_MITM_BROWSER_PLAN_READY_CODE, CLI_MITM_CERTIFICATE_GATE_DEFERRED_CODE,
    CLI_MITM_CERTIFICATE_MUTATION_BLOCKED_CODE, CLI_MITM_CERTIFICATE_PLAN_READY_CODE,
    CLI_MITM_CLI_GATE_PARTIAL_CODE, CLI_MITM_DATA_PLANE_GATE_DEFERRED_CODE,
    CLI_MITM_POLICY_READY_CODE, CLI_RUNTIME_UNWIRED_CODE, CLI_START_FOREGROUND_ONLY_CODE,
    CLI_START_LIFECYCLE_FAILED_CODE, CLI_START_LIFECYCLE_HOST_MISSING_CODE,
    CLI_START_LIFECYCLE_INTERRUPTED_CODE, CLI_START_PLATFORM_DENIED_CODE,
    CLI_START_RUNTIME_STOP_FAILED_CODE, CLI_STATUS_NO_RUNTIME_CONTEXT_CODE,
    CLI_STATUS_PLATFORM_ONLY_CODE, CLI_STOP_UNAVAILABLE_WITHOUT_DAEMON_CODE, DEFAULT_ENGINE_ID,
    MITM_BROWSER_CAPTURE_GATE, MITM_BROWSER_CAPTURE_GATE_STATUS, MITM_BROWSER_CAPTURE_MODE,
    MITM_BROWSER_CAPTURE_MUTATION_READY, MITM_BROWSER_CAPTURE_PROXY_HOST,
    MITM_BROWSER_CAPTURE_PROXY_PORT, MITM_BROWSER_CAPTURE_SOURCE_CONTRACT_STATUS,
    MITM_BROWSER_HIJACK_STATUS, MITM_BROWSER_PLAN_STATUS, MITM_CERTIFICATE_LIFECYCLE_GATE,
    MITM_CERTIFICATE_LIFECYCLE_GATE_STATUS, MITM_CERTIFICATE_MUTATION_READY,
    MITM_CERTIFICATE_PLAN_STATUS, MITM_CLI_COMMAND_GATE, MITM_CLI_COMMAND_GATE_STATUS,
    MITM_HTTP_TLS_DATA_PLANE_GATE, MITM_HTTP_TLS_DATA_PLANE_GATE_STATUS, MITM_USER_FACING_STAGE,
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
    assert!(rendered.contains("mitm browser-capture [plan|apply|rollback|verify]"));
    assert!(rendered.contains("sing-box install"));
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
    let browser_capture_apply = parse_args(["mitm", "browser-capture", "apply", "--confirm"])
        .expect("mitm browser-capture apply should parse");
    let browser_capture_rollback = parse_args([
        "mitm",
        "browser-capture",
        "rollback",
        "--snapshot",
        "/tmp/networkcore-browser-capture.snapshot.json",
    ])
    .expect("mitm browser-capture rollback should parse");
    let browser_capture_verify = parse_args(["mitm", "browser-capture", "verify"])
        .expect("mitm browser-capture verify should parse");

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
            format: OutputFormat::Text
        }
    );
    assert_eq!(
        browser_capture_plan,
        LinuxCliCommand::MitmBrowserCapturePlan {
            format: OutputFormat::Json
        }
    );
    assert_eq!(
        browser_capture_apply,
        LinuxCliCommand::MitmBrowserCaptureApply {
            confirm: true,
            format: OutputFormat::Text
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
            format: OutputFormat::Text
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
        .any(|step| step.id == "generate-local-ca" && step.status == "blocked"));
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
        .any(|operation| operation == "write-browser-policy"));
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
    assert!(rendered.contains("certificate plan: plan-only mutation_ready=false"));
    assert!(rendered.contains("certificate step generate-local-ca: blocked"));
    assert!(rendered.contains("browser plan: plan-only mutation_ready=false"));
    assert!(rendered.contains("browser step configure-browser-explicit-proxy: blocked"));
    assert!(rendered.contains("gate MITM_CLI_COMMAND_GATE: partial-active"));
}

#[test]
fn mitm_certificate_plan_reports_plan_only_lifecycle_without_mutation() {
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
    assert_eq!(capture.gate_status, "plan-only/mutation-blocked");
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
    assert!(rendered.contains("browser capture plan: plan-only/mutation-blocked"));
    assert!(rendered.contains("browser capture source contract: active"));
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
    assert!(confirmed_apply.rollback_snapshot.is_none());
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

    let verify = handle_mitm_browser_capture_verify(&platform);

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
    let browser_plan = handle_entrypoint(
        LinuxCliCommand::MitmBrowserPlan {
            format: OutputFormat::Text,
        },
        &platform,
    );
    let browser_capture_plan = handle_entrypoint(
        LinuxCliCommand::MitmBrowserCapturePlan {
            format: OutputFormat::Text,
        },
        &platform,
    );
    let browser_capture_apply = handle_entrypoint(
        LinuxCliCommand::MitmBrowserCaptureApply {
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
            format: OutputFormat::Text,
        },
        &platform,
    );

    assert!(capabilities.ok);
    assert!(status.ok);
    assert!(diagnostics.ok);
    assert!(mitm.ok);
    assert!(certificate_plan.ok);
    assert!(browser_plan.ok);
    assert!(browser_capture_plan.ok);
    assert!(!browser_capture_apply.ok);
    assert!(!browser_capture_rollback.ok);
    assert!(!browser_capture_verify.ok);
    assert_eq!(capabilities.command, "capabilities");
    assert_eq!(status.command, "status");
    assert_eq!(diagnostics.command, "diagnostics");
    assert_eq!(mitm.command, "mitm status");
    assert_eq!(certificate_plan.command, "mitm certificate-plan");
    assert_eq!(browser_plan.command, "mitm browser-plan");
    assert_eq!(browser_capture_plan.command, "mitm browser-capture plan");
    assert_eq!(browser_capture_apply.command, "mitm browser-capture apply");
    assert_eq!(
        browser_capture_rollback.command,
        "mitm browser-capture rollback"
    );
    assert_eq!(
        browser_capture_verify.command,
        "mitm browser-capture verify"
    );
    assert_diagnostic(&capabilities.diagnostics, DNS_MANAGER_UNKNOWN_CODE);
    assert_diagnostic(&status.diagnostics, CLI_STATUS_NO_RUNTIME_CONTEXT_CODE);
    assert_diagnostic(&diagnostics.diagnostics, DNS_MANAGER_UNKNOWN_CODE);
    assert!(mitm.mitm_status.is_some());
    assert!(certificate_plan.mitm_status.is_some());
    assert!(browser_plan.mitm_status.is_some());
    assert!(browser_capture_plan.browser_capture.is_some());
    assert!(browser_capture_apply.browser_capture.is_some());
    assert!(browser_capture_rollback.browser_capture.is_some());
    assert!(browser_capture_verify.browser_capture.is_some());
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
        .any(|operation| operation.as_str() == Some("write-browser-policy")));
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
        json["mitm_status"]["gates"][2]["gate"],
        MITM_HTTP_TLS_DATA_PLANE_GATE
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
        "plan-only/mutation-blocked"
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
