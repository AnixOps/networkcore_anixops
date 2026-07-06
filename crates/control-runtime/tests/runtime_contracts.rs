use control_domain::{
    CertificateTrustState, ConfigSnapshot, ConfigurationService, Diagnostic, DomainError,
    DomainResult, MitmCertificateStatus, OperatingSystem, PlatformCapabilities,
    PlatformCapabilityService, PlatformCapabilityStatus, PlatformFeatureState, ProxyEngineConfig,
    ProxyEngineDescriptor, ProxyEngineEvent, ProxyEngineLifecycleState, ProxyEngineService,
    ProxyEngineStatus, SchemaVersion,
};
use control_runtime::{RuntimeConfigRequest, RuntimeOrchestrator};

struct NoopConfigurationService;

impl ConfigurationService for NoopConfigurationService {
    fn validate(&self, raw_config: &str, _capabilities: &PlatformCapabilities) -> Vec<Diagnostic> {
        if raw_config.trim().is_empty() {
            vec![Diagnostic::new(
                control_domain::DiagnosticSeverity::Error,
                "config.empty",
                "configuration is empty",
                None,
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

struct StaticPlatformCapabilityService {
    status: PlatformCapabilityStatus,
}

impl PlatformCapabilityService for StaticPlatformCapabilityService {
    fn status(&self) -> DomainResult<PlatformCapabilityStatus> {
        Ok(self.status.clone())
    }
}

struct FakeProxyEngineService {
    fail_start: bool,
}

impl ProxyEngineService for FakeProxyEngineService {
    fn list_engines(&self) -> Vec<ProxyEngineDescriptor> {
        Vec::new()
    }

    fn validate_config(&self, _engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
        Vec::new()
    }

    fn start(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        if self.fail_start {
            Err(DomainError::new(
                "engine.start_failed",
                "engine failed to start",
            ))
        } else {
            Ok(ProxyEngineStatus {
                engine_id: engine_config.engine_id.clone(),
                state: ProxyEngineLifecycleState::Running,
                diagnostics: Vec::new(),
            })
        }
    }

    fn reload(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        Ok(ProxyEngineStatus {
            engine_id: engine_config.engine_id.clone(),
            state: ProxyEngineLifecycleState::Reloading,
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
            state: ProxyEngineLifecycleState::Running,
            diagnostics: Vec::new(),
        })
    }

    fn events(&self, _engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
        Ok(Vec::new())
    }
}

#[test]
fn start_runtime_prepares_config_and_starts_engine() {
    let orchestrator = RuntimeOrchestrator::new(
        NoopConfigurationService,
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        FakeProxyEngineService { fail_start: false },
    );

    let result = orchestrator
        .start_runtime(RuntimeConfigRequest::new("native", "profile = default"))
        .expect("runtime should start");

    assert_eq!(result.engine_status.engine_id, "native");
    assert_eq!(
        result.engine_status.state,
        ProxyEngineLifecycleState::Running
    );
    assert!(result.capabilities.supports_tunnel);
    assert!(result.capabilities.supports_embedded_runtime);
}

#[test]
fn start_runtime_rejects_platform_tunnel_denial() {
    let orchestrator = RuntimeOrchestrator::new(
        NoopConfigurationService,
        StaticPlatformCapabilityService {
            status: platform_status_without_tunnel(),
        },
        FakeProxyEngineService { fail_start: false },
    );

    let error = orchestrator
        .start_runtime(RuntimeConfigRequest::new("native", "profile = default"))
        .expect_err("unavailable tunnel should reject start");

    assert_eq!(error.code, "runtime.platform.tunnel_unavailable");
    assert!(error.message.contains("network extension entitlement"));
}

#[test]
fn start_runtime_propagates_engine_start_error() {
    let orchestrator = RuntimeOrchestrator::new(
        NoopConfigurationService,
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        FakeProxyEngineService { fail_start: true },
    );

    let error = orchestrator
        .start_runtime(RuntimeConfigRequest::new("native", "profile = default"))
        .expect_err("engine start error should propagate");

    assert_eq!(error.code, "engine.start_failed");
}

fn available_platform_status() -> PlatformCapabilityStatus {
    PlatformCapabilityStatus {
        os: OperatingSystem::Ios,
        tunnel: PlatformFeatureState::available(),
        mitm: PlatformFeatureState::available(),
        embedded_runtime: PlatformFeatureState::available(),
        remote_script_execution: PlatformFeatureState::unavailable(
            "remote script execution is disabled on iOS",
        ),
        mitm_certificate: MitmCertificateStatus::new(CertificateTrustState::Trusted),
        diagnostics: Vec::new(),
    }
}

fn platform_status_without_tunnel() -> PlatformCapabilityStatus {
    PlatformCapabilityStatus {
        os: OperatingSystem::Ios,
        tunnel: PlatformFeatureState::unavailable("network extension entitlement is missing"),
        mitm: PlatformFeatureState::available(),
        embedded_runtime: PlatformFeatureState::available(),
        remote_script_execution: PlatformFeatureState::unavailable(
            "remote script execution is disabled on iOS",
        ),
        mitm_certificate: MitmCertificateStatus::new(CertificateTrustState::Trusted),
        diagnostics: Vec::new(),
    }
}
