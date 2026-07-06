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

#[derive(Clone, Copy)]
enum MitmFailureMode {
    Load,
    Handle,
}

struct FakeMitmPluginService {
    failure: Option<MitmFailureMode>,
}

impl FakeMitmPluginService {
    const fn new() -> Self {
        Self { failure: None }
    }

    const fn fail_load() -> Self {
        Self {
            failure: Some(MitmFailureMode::Load),
        }
    }

    const fn fail_handle() -> Self {
        Self {
            failure: Some(MitmFailureMode::Handle),
        }
    }
}

impl MitmPluginService for FakeMitmPluginService {
    fn validate_manifest(&self, _plugin_manifest: &PluginManifest) -> Vec<Diagnostic> {
        Vec::new()
    }

    fn load(
        &self,
        plugin_package: &PluginPackage,
        _granted_permissions: &GrantedPermissions,
    ) -> DomainResult<PluginInstance> {
        if matches!(self.failure, Some(MitmFailureMode::Load)) {
            return Err(DomainError::new(
                "plugin.load_failed",
                "plugin failed to load",
            ));
        }

        Ok(PluginInstance {
            manifest: plugin_package.manifest.clone(),
        })
    }

    fn handle_http_event(
        &self,
        plugin_instance: &PluginInstance,
        _http_event: &HttpEvent,
    ) -> DomainResult<PluginResult> {
        if matches!(self.failure, Some(MitmFailureMode::Handle)) {
            return Err(DomainError::new(
                "plugin.handle_failed",
                "plugin failed to handle event",
            ));
        }

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

struct PanicMitmPluginService;

impl MitmPluginService for PanicMitmPluginService {
    fn validate_manifest(&self, _plugin_manifest: &PluginManifest) -> Vec<Diagnostic> {
        panic!("denied MITM gates should not validate plugin manifests")
    }

    fn load(
        &self,
        _plugin_package: &PluginPackage,
        _granted_permissions: &GrantedPermissions,
    ) -> DomainResult<PluginInstance> {
        panic!("denied MITM gates should not load plugins")
    }

    fn handle_http_event(
        &self,
        _plugin_instance: &PluginInstance,
        _http_event: &HttpEvent,
    ) -> DomainResult<PluginResult> {
        panic!("denied MITM gates should not handle HTTP events")
    }

    fn audit(&self, _plugin_result: &PluginResult) -> Vec<AuditEvent> {
        panic!("denied MITM gates should not audit plugin results")
    }
}

struct ManifestOnlyMitmPluginService;

impl MitmPluginService for ManifestOnlyMitmPluginService {
    fn validate_manifest(&self, _plugin_manifest: &PluginManifest) -> Vec<Diagnostic> {
        Vec::new()
    }

    fn load(
        &self,
        _plugin_package: &PluginPackage,
        _granted_permissions: &GrantedPermissions,
    ) -> DomainResult<PluginInstance> {
        panic!("permission-denied MITM gates should not load plugins")
    }

    fn handle_http_event(
        &self,
        _plugin_instance: &PluginInstance,
        _http_event: &HttpEvent,
    ) -> DomainResult<PluginResult> {
        panic!("permission-denied MITM gates should not handle events")
    }

    fn audit(&self, _plugin_result: &PluginResult) -> Vec<AuditEvent> {
        panic!("permission-denied MITM gates should not audit results")
    }
}

struct InvalidManifestMitmPluginService;

impl MitmPluginService for InvalidManifestMitmPluginService {
    fn validate_manifest(&self, _plugin_manifest: &PluginManifest) -> Vec<Diagnostic> {
        vec![Diagnostic::new(
            control_domain::DiagnosticSeverity::Error,
            "plugin.manifest.missing_hook",
            "plugin manifest must declare at least one hook",
            Some("manifest.hooks".to_string()),
        )]
    }

    fn load(
        &self,
        _plugin_package: &PluginPackage,
        _granted_permissions: &GrantedPermissions,
    ) -> DomainResult<PluginInstance> {
        panic!("invalid plugin manifests should not be loaded")
    }

    fn handle_http_event(
        &self,
        _plugin_instance: &PluginInstance,
        _http_event: &HttpEvent,
    ) -> DomainResult<PluginResult> {
        panic!("invalid plugin manifests should not handle HTTP events")
    }

    fn audit(&self, _plugin_result: &PluginResult) -> Vec<AuditEvent> {
        panic!("invalid plugin manifests should not audit plugin results")
    }
}

struct NonErrorManifestMitmPluginService;

impl MitmPluginService for NonErrorManifestMitmPluginService {
    fn validate_manifest(&self, _plugin_manifest: &PluginManifest) -> Vec<Diagnostic> {
        vec![
            Diagnostic::new(
                control_domain::DiagnosticSeverity::Warning,
                "plugin.manifest.deprecated_header_match",
                "plugin uses a deprecated header match hint",
                Some("manifest.hooks[0]".to_string()),
            ),
            Diagnostic::new(
                control_domain::DiagnosticSeverity::Info,
                "plugin.manifest.compatibility_note",
                "plugin manifest is compatible with request hooks",
                Some("manifest".to_string()),
            ),
        ]
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
                reason: Some("plugin executed after manifest diagnostics".to_string()),
            }],
            diagnostics: Vec::new(),
        })
    }

    fn audit(&self, _plugin_result: &PluginResult) -> Vec<AuditEvent> {
        Vec::new()
    }
}

struct DiagnosticResultMitmPluginService;

impl MitmPluginService for DiagnosticResultMitmPluginService {
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
            diagnostics: vec![
                Diagnostic::new(
                    control_domain::DiagnosticSeverity::Warning,
                    "plugin.result.header_skipped",
                    "plugin skipped an optional response header",
                    Some("plugin_result".to_string()),
                ),
                Diagnostic::new(
                    control_domain::DiagnosticSeverity::Info,
                    "plugin.result.rewrite_noop",
                    "plugin left the request unchanged",
                    Some("plugin_result".to_string()),
                ),
            ],
        })
    }

    fn audit(&self, _plugin_result: &PluginResult) -> Vec<AuditEvent> {
        Vec::new()
    }
}

struct AuditingMitmPluginService;

impl MitmPluginService for AuditingMitmPluginService {
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
                action: "plugin_result_audit".to_string(),
                decision: AuditDecision::Allowed,
                reason: Some("plugin handled HTTP event".to_string()),
            }],
            diagnostics: Vec::new(),
        })
    }

    fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent> {
        let actor = plugin_result
            .audits
            .first()
            .map(|audit| audit.actor.clone())
            .unwrap_or_else(|| "unknown-plugin".to_string());

        vec![AuditEvent {
            actor,
            action: "plugin_audit_port".to_string(),
            decision: AuditDecision::Allowed,
            reason: Some("plugin audit port evaluated result".to_string()),
        }]
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
        FakeMitmPluginService::new(),
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
fn mitm_gate_aggregates_gate_plugin_result_and_audit_port_events() {
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        AuditingMitmPluginService,
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

    let audit_actions = decision
        .audits
        .iter()
        .map(|audit| audit.action.as_str())
        .collect::<Vec<_>>();

    assert!(decision.is_allowed());
    assert_eq!(
        audit_actions,
        vec!["mitm_gate", "plugin_result_audit", "plugin_audit_port"]
    );
    assert_eq!(decision.audits.len(), 3);
    assert!(decision
        .audits
        .iter()
        .all(|audit| audit.actor == "header-rewriter"));
    assert!(decision
        .audits
        .iter()
        .all(|audit| audit.decision == AuditDecision::Allowed));
    assert_eq!(decision.audits[0].reason, None);
    assert_eq!(
        decision.audits[1].reason.as_deref(),
        Some("plugin handled HTTP event")
    );
    assert_eq!(
        decision.audits[2].reason.as_deref(),
        Some("plugin audit port evaluated result")
    );
}

#[test]
fn mitm_gate_rejects_unavailable_mitm_before_plugin_port() {
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: platform_status_without_mitm(),
        },
        PanicMitmPluginService,
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
    assert_eq!(
        decision.reason.as_deref(),
        Some("mitm is unavailable: mitm capability is disabled by platform policy")
    );
    assert!(decision.plugin_result.is_none());
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "runtime.mitm.unavailable"
            && diagnostic.severity == control_domain::DiagnosticSeverity::Error
    }));
    assert_eq!(decision.audits.len(), 1);
    assert_eq!(decision.audits[0].actor, "header-rewriter");
    assert_eq!(decision.audits[0].action, "mitm_gate");
    assert_eq!(decision.audits[0].decision, AuditDecision::Denied);
    assert_eq!(decision.audits[0].reason, decision.reason);
}

#[test]
fn mitm_gate_rejects_certificate_denial_matrix_before_plugin_port() {
    let cases = [
        (
            CertificateTrustState::NotInstalled,
            "mitm certificate is not installed",
        ),
        (
            CertificateTrustState::InstalledUntrusted,
            "mitm certificate is installed but not trusted",
        ),
        (
            CertificateTrustState::Revoked,
            "mitm certificate is revoked",
        ),
        (
            CertificateTrustState::Unknown,
            "mitm certificate trust state is unknown",
        ),
    ];

    for (state, expected_reason) in cases {
        let gate = MitmGateOrchestrator::new(
            StaticPlatformCapabilityService {
                status: platform_status_with_certificate_state(state),
            },
            PanicMitmPluginService,
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
        assert_eq!(decision.platform.mitm_certificate.state, state);
        assert_eq!(decision.reason.as_deref(), Some(expected_reason));
        assert!(decision.plugin_result.is_none());
        assert!(decision.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "runtime.mitm.certificate_untrusted"
                && diagnostic.message == expected_reason
                && diagnostic.severity == control_domain::DiagnosticSeverity::Error
        }));
        assert_eq!(decision.audits.len(), 1);
        assert_eq!(decision.audits[0].actor, "header-rewriter");
        assert_eq!(decision.audits[0].action, "mitm_gate");
        assert_eq!(decision.audits[0].decision, AuditDecision::Denied);
        assert_eq!(decision.audits[0].reason.as_deref(), Some(expected_reason));
    }
}

#[test]
fn mitm_gate_rejects_ungranted_plugin_permission() {
    let expected_reason = "plugin permission is not granted: modify_request";
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        ManifestOnlyMitmPluginService,
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
    assert_eq!(decision.reason.as_deref(), Some(expected_reason));
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "runtime.mitm.permission_denied"
            && diagnostic.message == expected_reason
            && diagnostic.severity == control_domain::DiagnosticSeverity::Error
    }));
    assert_eq!(decision.audits.len(), 1);
    assert_eq!(decision.audits[0].actor, "header-rewriter");
    assert_eq!(decision.audits[0].action, "mitm_gate");
    assert_eq!(decision.audits[0].decision, AuditDecision::Denied);
    assert_eq!(decision.audits[0].reason.as_deref(), Some(expected_reason));
}

#[test]
fn mitm_gate_rejects_manifest_error_diagnostics_before_loading_plugin() {
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        InvalidManifestMitmPluginService,
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
    assert_eq!(
        decision.reason.as_deref(),
        Some("plugin manifest validation failed")
    );
    assert!(decision.plugin_result.is_none());
    assert!(decision
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "plugin.manifest.missing_hook"));
    assert!(decision
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "runtime.mitm.manifest_invalid"));
}

#[test]
fn mitm_gate_allows_manifest_non_error_diagnostics() {
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        NonErrorManifestMitmPluginService,
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
    assert!(decision.reason.is_none());
    assert!(decision.plugin_result.is_some());
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "plugin.manifest.deprecated_header_match"
            && diagnostic.severity == control_domain::DiagnosticSeverity::Warning
    }));
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "plugin.manifest.compatibility_note"
            && diagnostic.severity == control_domain::DiagnosticSeverity::Info
    }));
    assert!(!decision
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "runtime.mitm.manifest_invalid"));
    assert!(decision.audits.iter().any(|audit| {
        audit.action == "handle_http_event"
            && audit.reason.as_deref() == Some("plugin executed after manifest diagnostics")
    }));
}

#[test]
fn mitm_gate_aggregates_plugin_result_diagnostics() {
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        DiagnosticResultMitmPluginService,
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
    assert!(decision.reason.is_none());
    assert!(decision.plugin_result.is_some());
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "plugin.result.header_skipped"
            && diagnostic.severity == control_domain::DiagnosticSeverity::Warning
    }));
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "plugin.result.rewrite_noop"
            && diagnostic.severity == control_domain::DiagnosticSeverity::Info
    }));
    assert!(!decision
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == control_domain::DiagnosticSeverity::Error));
    assert!(decision
        .audits
        .iter()
        .any(|audit| audit.action == "handle_http_event"));
}

#[test]
fn mitm_gate_aggregates_platform_diagnostics() {
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: platform_status_with_gate_diagnostics(),
        },
        FakeMitmPluginService::new(),
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
    assert!(decision.reason.is_none());
    assert!(decision.plugin_result.is_some());
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "platform.mitm.profile_scope"
            && diagnostic.severity == control_domain::DiagnosticSeverity::Warning
    }));
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "platform.mitm_certificate.cached_trust"
            && diagnostic.severity == control_domain::DiagnosticSeverity::Info
    }));
    assert!(!decision
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == control_domain::DiagnosticSeverity::Error));
    assert!(decision
        .audits
        .iter()
        .any(|audit| audit.action == "mitm_gate"));
}

#[test]
fn mitm_gate_rejects_disabled_remote_script_execution_before_plugin_port() {
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: platform_status_without_remote_scripts(),
        },
        PanicMitmPluginService,
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
    assert!(decision
        .reason
        .as_deref()
        .expect("denial reason should be present")
        .contains("remote script execution is disabled on iOS"));
    assert!(decision
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "runtime.mitm.remote_script_unavailable"));
}

#[test]
fn mitm_gate_rejects_unknown_remote_script_execution_before_plugin_port() {
    let expected_reason =
        "remote script execution is unavailable: platform feature availability is unknown";
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: platform_status_with_unknown_remote_scripts(),
        },
        PanicMitmPluginService,
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
    assert_eq!(
        decision.platform.remote_script_execution,
        PlatformFeatureState::Unknown
    );
    assert_eq!(decision.reason.as_deref(), Some(expected_reason));
    assert!(decision.plugin_result.is_none());
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "runtime.mitm.remote_script_unavailable"
            && diagnostic.message == expected_reason
            && diagnostic.severity == control_domain::DiagnosticSeverity::Error
    }));
    assert_eq!(decision.audits.len(), 1);
    assert_eq!(decision.audits[0].actor, "header-rewriter");
    assert_eq!(decision.audits[0].action, "mitm_gate");
    assert_eq!(decision.audits[0].decision, AuditDecision::Denied);
    assert_eq!(decision.audits[0].reason, decision.reason);
}

#[test]
fn mitm_gate_propagates_plugin_load_error() {
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        FakeMitmPluginService::fail_load(),
    );

    let error = gate
        .mitm_gate(MitmGateRequest::new(
            sample_plugin_package(),
            granted_permissions(vec![
                PluginPermission::ReadRequest,
                PluginPermission::ModifyRequest,
            ]),
            sample_http_event(),
        ))
        .expect_err("plugin load errors should propagate");

    assert_eq!(error.code, "plugin.load_failed");
}

#[test]
fn mitm_gate_propagates_plugin_handle_error() {
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        FakeMitmPluginService::fail_handle(),
    );

    let error = gate
        .mitm_gate(MitmGateRequest::new(
            sample_plugin_package(),
            granted_permissions(vec![
                PluginPermission::ReadRequest,
                PluginPermission::ModifyRequest,
            ]),
            sample_http_event(),
        ))
        .expect_err("plugin event errors should propagate");

    assert_eq!(error.code, "plugin.handle_failed");
}

fn available_platform_status() -> PlatformCapabilityStatus {
    PlatformCapabilityStatus {
        os: OperatingSystem::Ios,
        tunnel: PlatformFeatureState::available(),
        mitm: PlatformFeatureState::available(),
        embedded_runtime: PlatformFeatureState::available(),
        remote_script_execution: PlatformFeatureState::available(),
        mitm_certificate: MitmCertificateStatus::new(CertificateTrustState::Trusted),
        diagnostics: Vec::new(),
    }
}

fn platform_status_with_gate_diagnostics() -> PlatformCapabilityStatus {
    let mut status = available_platform_status();
    status.diagnostics = vec![Diagnostic::new(
        control_domain::DiagnosticSeverity::Warning,
        "platform.mitm.profile_scope",
        "mitm is limited to the selected profile",
        Some("platform.mitm".to_string()),
    )];
    status.mitm_certificate.diagnostics = vec![Diagnostic::new(
        control_domain::DiagnosticSeverity::Info,
        "platform.mitm_certificate.cached_trust",
        "mitm certificate trust state was served from cache",
        Some("platform.mitm_certificate".to_string()),
    )];
    status
}

fn platform_status_without_mitm() -> PlatformCapabilityStatus {
    PlatformCapabilityStatus {
        os: OperatingSystem::Ios,
        tunnel: PlatformFeatureState::available(),
        mitm: PlatformFeatureState::unavailable("mitm capability is disabled by platform policy"),
        embedded_runtime: PlatformFeatureState::available(),
        remote_script_execution: PlatformFeatureState::available(),
        mitm_certificate: MitmCertificateStatus::new(CertificateTrustState::Trusted),
        diagnostics: Vec::new(),
    }
}

fn platform_status_with_certificate_state(
    state: CertificateTrustState,
) -> PlatformCapabilityStatus {
    PlatformCapabilityStatus {
        os: OperatingSystem::Ios,
        tunnel: PlatformFeatureState::available(),
        mitm: PlatformFeatureState::available(),
        embedded_runtime: PlatformFeatureState::available(),
        remote_script_execution: PlatformFeatureState::available(),
        mitm_certificate: MitmCertificateStatus::new(state),
        diagnostics: Vec::new(),
    }
}

fn platform_status_without_remote_scripts() -> PlatformCapabilityStatus {
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

fn platform_status_with_unknown_remote_scripts() -> PlatformCapabilityStatus {
    PlatformCapabilityStatus {
        os: OperatingSystem::Ios,
        tunnel: PlatformFeatureState::available(),
        mitm: PlatformFeatureState::available(),
        embedded_runtime: PlatformFeatureState::available(),
        remote_script_execution: PlatformFeatureState::unknown(),
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
