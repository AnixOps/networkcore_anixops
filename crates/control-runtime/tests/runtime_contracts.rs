use control_domain::{
    AuditDecision, AuditEvent, CertificateTrustState, ConfigSnapshot, ConfigurationService,
    Diagnostic, DomainError, DomainResult, GrantedPermissions, HookPoint, HttpEvent,
    MitmCertificateStatus, MitmPluginService, OperatingSystem, PlatformCapabilities,
    PlatformCapabilityService, PlatformCapabilityStatus, PlatformFeatureState, PluginInstance,
    PluginManifest, PluginPackage, PluginPermission, PluginResult, ProxyEngineConfig,
    ProxyEngineDescriptor, ProxyEngineEvent, ProxyEngineLifecycleState, ProxyEngineService,
    ProxyEngineStatus, SchemaVersion,
};
use control_runtime::{
    MitmGateOrchestrator, MitmGateRequest, RuntimeConfigRequest, RuntimeOrchestrator,
};

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

struct FakeMitmPluginService;

impl MitmPluginService for FakeMitmPluginService {
    fn validate_manifest(&self, _plugin_manifest: &PluginManifest) -> Vec<Diagnostic> {
        Vec::new()
    }

    fn load(
        &self,
        plugin_package: &PluginPackage,
        _granted_permissions: &GrantedPermissions,
    ) -> DomainResult<PluginInstance> {
        Ok(PluginInstance {
            manifest: plugin_package.manifest.clone(),
        })
    }

    fn handle_http_event(
        &self,
        plugin_instance: &PluginInstance,
        _http_event: &HttpEvent,
    ) -> DomainResult<PluginResult> {
        Ok(PluginResult {
            audits: vec![AuditEvent {
                actor: plugin_instance.manifest.id.clone(),
                action: "handle_http_event".to_string(),
                decision: AuditDecision::Allowed,
                reason: None,
            }],
            diagnostics: Vec::new(),
        })
    }

    fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent> {
        plugin_result.audits.clone()
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

#[test]
fn mitm_gate_allows_trusted_certificate_and_granted_permissions() {
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        FakeMitmPluginService,
    );

    let decision = gate
        .mitm_gate(MitmGateRequest::new(
            sample_plugin_package(),
            granted_permissions(vec![
                PluginPermission::ReadRequest,
                PluginPermission::ModifyRequest,
            ]),
            sample_http_event(),
        ))
        .expect("mitm gate should evaluate");

    assert!(decision.is_allowed());
    assert_eq!(decision.decision, AuditDecision::Allowed);
    assert!(decision.plugin_result.is_some());
    assert!(decision
        .audits
        .iter()
        .any(|audit| audit.action == "mitm_gate"));
}

#[test]
fn mitm_gate_rejects_untrusted_certificate() {
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: platform_status_with_untrusted_certificate(),
        },
        FakeMitmPluginService,
    );

    let decision = gate
        .mitm_gate(MitmGateRequest::new(
            sample_plugin_package(),
            granted_permissions(vec![
                PluginPermission::ReadRequest,
                PluginPermission::ModifyRequest,
            ]),
            sample_http_event(),
        ))
        .expect("mitm gate should return a denial decision");

    assert!(!decision.is_allowed());
    assert_eq!(decision.decision, AuditDecision::Denied);
    assert!(decision.plugin_result.is_none());
    assert_eq!(
        decision.reason.as_deref(),
        Some("mitm certificate is installed but not trusted")
    );
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "runtime.mitm.certificate_untrusted"
            && diagnostic.severity == control_domain::DiagnosticSeverity::Error
    }));
}

#[test]
fn mitm_gate_rejects_ungranted_plugin_permission() {
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        FakeMitmPluginService,
    );

    let decision = gate
        .mitm_gate(MitmGateRequest::new(
            sample_plugin_package(),
            granted_permissions(vec![PluginPermission::ReadRequest]),
            sample_http_event(),
        ))
        .expect("mitm gate should return a denial decision");

    assert!(!decision.is_allowed());
    assert_eq!(decision.decision, AuditDecision::Denied);
    assert!(decision.plugin_result.is_none());
    assert_eq!(
        decision.reason.as_deref(),
        Some("plugin permission is not granted: modify_request")
    );
    assert!(decision
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "runtime.mitm.permission_denied"));
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

fn platform_status_with_untrusted_certificate() -> PlatformCapabilityStatus {
    PlatformCapabilityStatus {
        os: OperatingSystem::Ios,
        tunnel: PlatformFeatureState::available(),
        mitm: PlatformFeatureState::available(),
        embedded_runtime: PlatformFeatureState::available(),
        remote_script_execution: PlatformFeatureState::unavailable(
            "remote script execution is disabled on iOS",
        ),
        mitm_certificate: MitmCertificateStatus::new(CertificateTrustState::InstalledUntrusted),
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

fn sample_plugin_package() -> PluginPackage {
    PluginPackage {
        manifest: PluginManifest {
            id: "header-rewriter".to_string(),
            version: "1.0.0".to_string(),
            permissions: vec![
                PluginPermission::ReadRequest,
                PluginPermission::ModifyRequest,
            ],
            hooks: vec![HookPoint::Request],
        },
        source: "export default function rewrite(request) { return request; }".to_string(),
    }
}

fn granted_permissions(permissions: Vec<PluginPermission>) -> GrantedPermissions {
    GrantedPermissions { permissions }
}

fn sample_http_event() -> HttpEvent {
    HttpEvent {
        request_id: "request-1".to_string(),
        headers: Vec::new(),
        body: Vec::new(),
    }
}
