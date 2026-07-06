use control_domain::{
    CertificateTrustState, ConfigSnapshot, ConfigurationService, Diagnostic, DiagnosticSeverity,
    DomainResult, PlatformCapabilities, PlatformFeatureState, ProxyEngineConfig,
    ProxyEngineDescriptor, ProxyEngineEvent, ProxyEngineLifecycleState, ProxyEngineService,
    ProxyEngineStatus, SchemaVersion,
};
use control_runtime::RuntimeOrchestrator;
use networkcore_linux::{
    handle_capabilities, handle_entrypoint, handle_prepare_config, handle_start, handle_status,
    handle_stop, parse_args, render_response, ConfigReadError, ConfigReader, LinuxCliCommand,
    LinuxCliExitCode, OutputFormat, CLI_CONFIG_EMPTY_CODE, CLI_CONFIG_PATH_MISSING_CODE,
    CLI_CONFIG_READ_FAILED_CODE, CLI_RUNTIME_UNWIRED_CODE, CLI_START_PLATFORM_DENIED_CODE,
    CLI_STATUS_NO_RUNTIME_CONTEXT_CODE, CLI_STATUS_PLATFORM_ONLY_CODE,
    CLI_STOP_UNAVAILABLE_WITHOUT_DAEMON_CODE,
};
use platform_linux::{
    linux_diagnostic, LinuxCertificateProbe, LinuxDnsManagerState, LinuxFeatureProbe,
    LinuxPlatformSnapshot, LinuxPrivilegeProbe, LinuxReadOnlyProbe, LinuxReadOnlyProbeSnapshot,
    LinuxServiceManagerState, LinuxTunDeviceState, ReadOnlyLinuxPlatformCapabilityService,
    StaticLinuxPlatformCapabilityService, DNS_MANAGER_DETECTED_CODE, DNS_MANAGER_UNKNOWN_CODE,
    PERMISSION_CAPABILITY_MISSING_CODE, PERMISSION_ELEVATION_REQUIRED_CODE, SOURCE_DNS,
    SERVICE_UNSUPPORTED_ENVIRONMENT_CODE,
};

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

    assert!(capabilities.ok);
    assert!(status.ok);
    assert!(diagnostics.ok);
    assert_eq!(capabilities.command, "capabilities");
    assert_eq!(status.command, "status");
    assert_eq!(diagnostics.command, "diagnostics");
    assert_diagnostic(&capabilities.diagnostics, DNS_MANAGER_UNKNOWN_CODE);
    assert_diagnostic(&status.diagnostics, CLI_STATUS_NO_RUNTIME_CONTEXT_CODE);
    assert_diagnostic(&diagnostics.diagnostics, DNS_MANAGER_UNKNOWN_CODE);
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

fn assert_diagnostic(diagnostics: &[Diagnostic], code: &str) {
    assert!(
        diagnostics.iter().any(|diagnostic| diagnostic.code == code),
        "missing diagnostic {code}: {diagnostics:?}"
    );
}
