use control_domain::{
    AuditDecision, AuditEvent, CertificateTrustState, ConfigSnapshot, ConfigurationService,
    Diagnostic, DomainError, DomainResult, Endpoint, GrantedPermissions, HookPoint, HttpEvent,
    MitmCertificateStatus, MitmPluginService, NodeCatalog, NodeDescriptor, OperatingSystem,
    PlatformCapabilities, PlatformCapabilityService, PlatformCapabilityStatus,
    PlatformFeatureState, PluginInstance, PluginManifest, PluginPackage, PluginPermission,
    PluginResult, Protocol, ProxyEngineConfig, ProxyEngineDescriptor, ProxyEngineEvent,
    ProxyEngineLifecycleState, ProxyEngineService, ProxyEngineStatus, RawSubscription, RouteAction,
    RouteRule, RuleSet, SchemaVersion, SubscriptionDocument, SubscriptionService,
    SubscriptionSource,
};
use control_runtime::{
    MitmGateOrchestrator, MitmGateRequest, RuntimeConfigRequest, RuntimeOrchestrator,
    RUNTIME_SUBSCRIPTION_CATALOG_EMPTY_CODE, RUNTIME_SUBSCRIPTION_CATALOG_READY_CODE,
    RUNTIME_SUBSCRIPTION_NODE_ID_DUPLICATE_CODE, RUNTIME_SUBSCRIPTION_RULES_DEFERRED_CODE,
    RUNTIME_SUBSCRIPTION_SOURCE_UNSUPPORTED_CODE,
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

struct StaticConfigurationService {
    nodes: Vec<NodeDescriptor>,
    policies: Vec<RuleSet>,
}

impl ConfigurationService for StaticConfigurationService {
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
            listeners: Vec::new(),
            nodes: self.nodes.clone(),
            policies: self.policies.clone(),
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

struct AssertingProxyEngineService {
    expected_node_ids: Vec<String>,
    expected_policy_ids: Vec<String>,
}

impl AssertingProxyEngineService {
    fn assert_engine_config(&self, engine_config: &ProxyEngineConfig) {
        let node_ids = engine_config
            .nodes
            .iter()
            .map(|node| node.id.clone())
            .collect::<Vec<_>>();
        let policy_ids = engine_config
            .config
            .policies
            .iter()
            .map(|policy| policy.id.clone())
            .collect::<Vec<_>>();

        assert_eq!(node_ids, self.expected_node_ids);
        assert_eq!(policy_ids, self.expected_policy_ids);
    }
}

impl ProxyEngineService for AssertingProxyEngineService {
    fn list_engines(&self) -> Vec<ProxyEngineDescriptor> {
        Vec::new()
    }

    fn validate_config(&self, engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
        self.assert_engine_config(engine_config);
        Vec::new()
    }

    fn start(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        self.assert_engine_config(engine_config);
        Ok(ProxyEngineStatus {
            engine_id: engine_config.engine_id.clone(),
            state: ProxyEngineLifecycleState::Running,
            diagnostics: Vec::new(),
        })
    }

    fn reload(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        self.assert_engine_config(engine_config);
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

struct StaticSubscriptionService {
    catalogs: Vec<(String, NodeCatalog)>,
}

impl StaticSubscriptionService {
    fn new(catalogs: Vec<(&str, NodeCatalog)>) -> Self {
        Self {
            catalogs: catalogs
                .into_iter()
                .map(|(source_id, catalog)| (source_id.to_string(), catalog))
                .collect(),
        }
    }
}

impl SubscriptionService for StaticSubscriptionService {
    fn fetch(&self, source: &SubscriptionSource) -> DomainResult<RawSubscription> {
        Ok(RawSubscription {
            source_id: source.id.clone(),
            content: "inline subscription payload is provided by the test service".to_string(),
        })
    }

    fn parse(&self, raw_subscription: &RawSubscription) -> DomainResult<SubscriptionDocument> {
        let Some((_, catalog)) = self
            .catalogs
            .iter()
            .find(|(source_id, _)| source_id == &raw_subscription.source_id)
        else {
            return Err(DomainError::new(
                "subscription.test.source_missing",
                "subscription test catalog source is missing",
            ));
        };

        Ok(SubscriptionDocument {
            nodes: catalog.nodes.clone(),
            rules: catalog.rules.clone(),
            diagnostics: Vec::new(),
        })
    }

    fn normalize(&self, document: &SubscriptionDocument) -> DomainResult<NodeCatalog> {
        Ok(NodeCatalog {
            nodes: document.nodes.clone(),
            rules: document.rules.clone(),
        })
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

struct DiagnosticManifestOnlyMitmPluginService;

impl MitmPluginService for DiagnosticManifestOnlyMitmPluginService {
    fn validate_manifest(&self, _plugin_manifest: &PluginManifest) -> Vec<Diagnostic> {
        non_error_manifest_diagnostics()
    }

    fn load(
        &self,
        _plugin_package: &PluginPackage,
        _granted_permissions: &GrantedPermissions,
    ) -> DomainResult<PluginInstance> {
        panic!("permission-denied MITM gates should not load diagnostic plugins")
    }

    fn handle_http_event(
        &self,
        _plugin_instance: &PluginInstance,
        _http_event: &HttpEvent,
    ) -> DomainResult<PluginResult> {
        panic!("permission-denied MITM gates should not handle diagnostic events")
    }

    fn audit(&self, _plugin_result: &PluginResult) -> Vec<AuditEvent> {
        panic!("permission-denied MITM gates should not audit diagnostic results")
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
        non_error_manifest_diagnostics()
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
fn subscription_catalog_nodes_enter_runtime_config_request_nodes() {
    let orchestrator = RuntimeOrchestrator::new(
        NoopConfigurationService,
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        FakeProxyEngineService { fail_start: false },
    );
    let subscription = StaticSubscriptionService::new(vec![(
        "inline-dev",
        subscription_catalog(vec![subscription_node("catalog-node")], Vec::new()),
    )]);

    let gate = orchestrator
        .prepare_runtime_request_with_subscription_catalogs(
            RuntimeConfigRequest::new("native", "profile = default"),
            &subscription,
            &[inline_subscription_source("inline-dev")],
        )
        .expect("subscription catalog should be applied to runtime request");

    assert_eq!(gate.request.nodes, vec![subscription_node("catalog-node")]);
    assert!(gate.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == RUNTIME_SUBSCRIPTION_CATALOG_READY_CODE
            && diagnostic.severity == control_domain::DiagnosticSeverity::Info
    }));
}

#[test]
fn subscription_catalog_rejects_config_snapshot_node_id_duplicate() {
    let orchestrator = RuntimeOrchestrator::new(
        StaticConfigurationService {
            nodes: vec![subscription_node("shared-node")],
            policies: Vec::new(),
        },
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        FakeProxyEngineService { fail_start: false },
    );
    let subscription = StaticSubscriptionService::new(vec![(
        "inline-dev",
        subscription_catalog(vec![subscription_node("shared-node")], Vec::new()),
    )]);

    let error = orchestrator
        .prepare_runtime_request_with_subscription_catalogs(
            RuntimeConfigRequest::new("native", "profile = default"),
            &subscription,
            &[inline_subscription_source("inline-dev")],
        )
        .expect_err("subscription catalog must not override local config nodes");

    assert_eq!(error.code, RUNTIME_SUBSCRIPTION_NODE_ID_DUPLICATE_CODE);
}

#[test]
fn subscription_catalog_rejects_duplicate_node_ids_across_catalogs() {
    let orchestrator = RuntimeOrchestrator::new(
        NoopConfigurationService,
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        FakeProxyEngineService { fail_start: false },
    );
    let subscription = StaticSubscriptionService::new(vec![
        (
            "catalog-a",
            subscription_catalog(vec![subscription_node("shared-node")], Vec::new()),
        ),
        (
            "catalog-b",
            subscription_catalog(vec![subscription_node("shared-node")], Vec::new()),
        ),
    ]);

    let error = orchestrator
        .reload_runtime_with_subscription_catalogs(
            RuntimeConfigRequest::new("native", "profile = default"),
            &subscription,
            &[
                inline_subscription_source("catalog-a"),
                inline_subscription_source("catalog-b"),
            ],
        )
        .expect_err("duplicate catalog nodes must reject reload before engine validation");

    assert_eq!(error.code, RUNTIME_SUBSCRIPTION_NODE_ID_DUPLICATE_CODE);
}

#[test]
fn subscription_catalog_rejects_duplicate_node_ids_within_catalog() {
    let orchestrator = RuntimeOrchestrator::new(
        NoopConfigurationService,
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        FakeProxyEngineService { fail_start: false },
    );
    let subscription = StaticSubscriptionService::new(vec![(
        "inline-dev",
        subscription_catalog(
            vec![
                subscription_node("shared-node"),
                subscription_node("shared-node"),
            ],
            Vec::new(),
        ),
    )]);

    let error = orchestrator
        .prepare_runtime_request_with_subscription_catalogs(
            RuntimeConfigRequest::new("native", "profile = default"),
            &subscription,
            &[inline_subscription_source("inline-dev")],
        )
        .expect_err("duplicate nodes inside one catalog must reject before engine validation");

    assert_eq!(error.code, RUNTIME_SUBSCRIPTION_NODE_ID_DUPLICATE_CODE);
}

#[test]
fn subscription_catalog_rejects_runtime_request_node_id_duplicate() {
    let orchestrator = RuntimeOrchestrator::new(
        NoopConfigurationService,
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        FakeProxyEngineService { fail_start: false },
    );
    let subscription = StaticSubscriptionService::new(vec![(
        "inline-dev",
        subscription_catalog(vec![subscription_node("request-node")], Vec::new()),
    )]);
    let mut request = RuntimeConfigRequest::new("native", "profile = default");
    request.nodes = vec![subscription_node("request-node")];

    let error = orchestrator
        .prepare_runtime_request_with_subscription_catalogs(
            request,
            &subscription,
            &[inline_subscription_source("inline-dev")],
        )
        .expect_err("subscription catalog must not override runtime request nodes");

    assert_eq!(error.code, RUNTIME_SUBSCRIPTION_NODE_ID_DUPLICATE_CODE);
}

#[test]
fn subscription_catalog_empty_reports_warning() {
    let orchestrator = RuntimeOrchestrator::new(
        NoopConfigurationService,
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        FakeProxyEngineService { fail_start: false },
    );
    let subscription = StaticSubscriptionService::new(vec![(
        "inline-empty",
        subscription_catalog(Vec::new(), Vec::new()),
    )]);

    let gate = orchestrator
        .prepare_runtime_request_with_subscription_catalogs(
            RuntimeConfigRequest::new("native", "profile = default"),
            &subscription,
            &[inline_subscription_source("inline-empty")],
        )
        .expect("empty subscription catalog should report a warning without adding nodes");

    assert!(gate.request.nodes.is_empty());
    assert!(gate.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == RUNTIME_SUBSCRIPTION_CATALOG_EMPTY_CODE
            && diagnostic.severity == control_domain::DiagnosticSeverity::Warning
    }));
}

#[test]
fn subscription_catalog_rules_are_deferred_without_mutating_config_policies() {
    let orchestrator = RuntimeOrchestrator::new(
        StaticConfigurationService {
            nodes: vec![subscription_node("local-node")],
            policies: vec![subscription_rule_set("local-policy", "local-node")],
        },
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        AssertingProxyEngineService {
            expected_node_ids: vec!["catalog-node".to_string()],
            expected_policy_ids: vec!["local-policy".to_string()],
        },
    );
    let subscription = StaticSubscriptionService::new(vec![(
        "inline-dev",
        subscription_catalog(
            vec![subscription_node("catalog-node")],
            vec![subscription_rule_set("subscription-policy", "catalog-node")],
        ),
    )]);

    let result = orchestrator
        .start_runtime_with_subscription_catalogs(
            RuntimeConfigRequest::new("native", "profile = default"),
            &subscription,
            &[inline_subscription_source("inline-dev")],
        )
        .expect("subscription rules should be deferred while catalog nodes start");

    assert_eq!(
        result.engine_status.state,
        ProxyEngineLifecycleState::Running
    );
    assert!(result.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == RUNTIME_SUBSCRIPTION_RULES_DEFERRED_CODE
            && diagnostic.severity == control_domain::DiagnosticSeverity::Info
    }));
    assert!(result.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == RUNTIME_SUBSCRIPTION_CATALOG_READY_CODE
            && diagnostic.severity == control_domain::DiagnosticSeverity::Info
    }));
}

#[test]
fn subscription_catalog_rejects_unsupported_remote_source_without_leaking_secret() {
    let orchestrator = RuntimeOrchestrator::new(
        NoopConfigurationService,
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        FakeProxyEngineService { fail_start: false },
    );
    let subscription = StaticSubscriptionService::new(Vec::new());
    let secret_location = "https://subscriptions.example.invalid/list?token=super-secret-token";

    let error = orchestrator
        .prepare_runtime_request_with_subscription_catalogs(
            RuntimeConfigRequest::new("native", "profile = default"),
            &subscription,
            &[SubscriptionSource {
                id: "remote-prod".to_string(),
                location: secret_location.to_string(),
            }],
        )
        .expect_err("remote subscription sources must stay blocked in the runtime gate");

    assert_eq!(error.code, RUNTIME_SUBSCRIPTION_SOURCE_UNSUPPORTED_CODE);
    assert!(!error.to_string().contains("super-secret-token"));
    assert!(!error.to_string().contains("subscriptions.example.invalid"));
}

#[test]
fn subscription_catalog_rejects_file_source_without_reading_path() {
    let orchestrator = RuntimeOrchestrator::new(
        NoopConfigurationService,
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        FakeProxyEngineService { fail_start: false },
    );
    let subscription = StaticSubscriptionService::new(Vec::new());
    let private_path = "file:///Users/example/Library/Application Support/secret-subscription.toml";

    let error = orchestrator
        .prepare_runtime_request_with_subscription_catalogs(
            RuntimeConfigRequest::new("native", "profile = default"),
            &subscription,
            &[SubscriptionSource {
                id: "file-prod".to_string(),
                location: private_path.to_string(),
            }],
        )
        .expect_err("file subscription sources must stay blocked in the runtime gate");

    assert_eq!(error.code, RUNTIME_SUBSCRIPTION_SOURCE_UNSUPPORTED_CODE);
    assert!(!error.to_string().contains("secret-subscription.toml"));
    assert!(!error.to_string().contains("/Users/example"));
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
fn mitm_gate_preserves_platform_diagnostics_on_platform_denial() {
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: platform_status_without_mitm_with_diagnostics(),
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

    let platform_diagnostic = decision
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "platform.mitm.entitlement_missing")
        .expect("platform diagnostic should be preserved");

    assert!(!decision.is_allowed());
    assert_eq!(decision.decision, AuditDecision::Denied);
    assert_eq!(
        decision.reason.as_deref(),
        Some("mitm is unavailable: mitm capability is disabled by platform policy")
    );
    assert!(decision.plugin_result.is_none());
    assert_eq!(
        platform_diagnostic.severity,
        control_domain::DiagnosticSeverity::Warning
    );
    assert_eq!(
        platform_diagnostic.message,
        "mitm entitlement is unavailable on the current profile"
    );
    assert_eq!(platform_diagnostic.source.as_deref(), Some("platform.mitm"));
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "runtime.mitm.unavailable"
            && diagnostic.severity == control_domain::DiagnosticSeverity::Error
    }));
    assert_eq!(decision.audits.len(), 1);
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
fn mitm_gate_preserves_certificate_diagnostics_on_certificate_denial() {
    let expected_reason = "mitm certificate is installed but not trusted";
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: platform_status_with_certificate_diagnostics(
                CertificateTrustState::InstalledUntrusted,
            ),
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

    let certificate_diagnostic = decision
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "platform.mitm_certificate.trust_pending")
        .expect("certificate diagnostic should be preserved");

    assert!(!decision.is_allowed());
    assert_eq!(decision.decision, AuditDecision::Denied);
    assert_eq!(decision.reason.as_deref(), Some(expected_reason));
    assert_eq!(
        decision.platform.mitm_certificate.state,
        CertificateTrustState::InstalledUntrusted
    );
    assert!(decision.plugin_result.is_none());
    assert_eq!(
        certificate_diagnostic.severity,
        control_domain::DiagnosticSeverity::Warning
    );
    assert_eq!(
        certificate_diagnostic.message,
        "mitm certificate is installed but still pending user trust"
    );
    assert_eq!(
        certificate_diagnostic.source.as_deref(),
        Some("platform.mitm_certificate")
    );
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "runtime.mitm.certificate_untrusted"
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
fn mitm_gate_preserves_manifest_diagnostics_on_permission_denial() {
    let expected_reason = "plugin permission is not granted: modify_request";
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        DiagnosticManifestOnlyMitmPluginService,
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
    assert_eq!(decision.reason.as_deref(), Some(expected_reason));
    assert!(decision.plugin_result.is_none());
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "plugin.manifest.deprecated_header_match"
            && diagnostic.severity == control_domain::DiagnosticSeverity::Warning
    }));
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "plugin.manifest.compatibility_note"
            && diagnostic.severity == control_domain::DiagnosticSeverity::Info
    }));
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "runtime.mitm.permission_denied"
            && diagnostic.message == expected_reason
            && diagnostic.severity == control_domain::DiagnosticSeverity::Error
    }));
    assert!(!decision
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "runtime.mitm.manifest_invalid"));
    assert_eq!(decision.audits.len(), 1);
    assert_eq!(decision.audits[0].action, "mitm_gate");
    assert_eq!(decision.audits[0].decision, AuditDecision::Denied);
    assert_eq!(decision.audits[0].reason, decision.reason);
}

#[test]
fn mitm_gate_orders_diagnostics_on_permission_denial() {
    let expected_reason = "plugin permission is not granted: modify_request";
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: platform_status_with_gate_diagnostics(),
        },
        DiagnosticManifestOnlyMitmPluginService,
    );

    let decision = gate
        .mitm_gate(MitmGateRequest::new(
            sample_plugin_package(),
            granted_permissions(vec![PluginPermission::ReadRequest]),
            sample_http_event(),
        ))
        .expect("mitm gate should return a denial decision");

    let diagnostic_codes = decision
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    let runtime_diagnostic = decision
        .diagnostics
        .last()
        .expect("runtime diagnostic should be appended");

    assert_eq!(
        diagnostic_codes,
        vec![
            "platform.mitm.profile_scope",
            "platform.mitm_certificate.cached_trust",
            "plugin.manifest.deprecated_header_match",
            "plugin.manifest.compatibility_note",
            "runtime.mitm.permission_denied",
        ]
    );
    assert!(!decision.is_allowed());
    assert_eq!(decision.decision, AuditDecision::Denied);
    assert_eq!(decision.reason.as_deref(), Some(expected_reason));
    assert!(decision.plugin_result.is_none());
    assert_eq!(
        runtime_diagnostic.code.as_str(),
        "runtime.mitm.permission_denied"
    );
    assert_eq!(runtime_diagnostic.message.as_str(), expected_reason);
    assert_eq!(decision.audits.len(), 1);
    assert_eq!(decision.audits[0].actor, "header-rewriter");
    assert_eq!(decision.audits[0].action, "mitm_gate");
    assert_eq!(decision.audits[0].decision, AuditDecision::Denied);
    assert_eq!(decision.audits[0].reason, decision.reason);
}

#[test]
fn mitm_gate_audits_manifest_error_denial_before_plugin_ports() {
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
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "runtime.mitm.manifest_invalid"
            && diagnostic.message == "plugin manifest validation failed"
            && diagnostic.severity == control_domain::DiagnosticSeverity::Error
    }));
    assert_eq!(decision.audits.len(), 1);
    assert_eq!(decision.audits[0].actor, "header-rewriter");
    assert_eq!(decision.audits[0].action, "mitm_gate");
    assert_eq!(decision.audits[0].decision, AuditDecision::Denied);
    assert_eq!(decision.audits[0].reason, decision.reason);
}

#[test]
fn mitm_gate_prefers_manifest_error_over_permission_denial() {
    let expected_reason = "plugin manifest validation failed";
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: available_platform_status(),
        },
        InvalidManifestMitmPluginService,
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
    assert_eq!(decision.reason.as_deref(), Some(expected_reason));
    assert!(decision.plugin_result.is_none());
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "plugin.manifest.missing_hook"
            && diagnostic.severity == control_domain::DiagnosticSeverity::Error
    }));
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "runtime.mitm.manifest_invalid"
            && diagnostic.message == expected_reason
            && diagnostic.severity == control_domain::DiagnosticSeverity::Error
    }));
    assert!(!decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "runtime.mitm.permission_denied"
            || diagnostic.message == "plugin permission is not granted: modify_request"
    }));
    assert_eq!(decision.audits.len(), 1);
    assert_eq!(decision.audits[0].actor, "header-rewriter");
    assert_eq!(decision.audits[0].action, "mitm_gate");
    assert_eq!(decision.audits[0].decision, AuditDecision::Denied);
    assert_eq!(decision.audits[0].reason, decision.reason);
}

#[test]
fn mitm_gate_preserves_platform_diagnostics_on_manifest_error_denial() {
    let expected_reason = "plugin manifest validation failed";
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: platform_status_with_gate_diagnostics(),
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

    let platform_diagnostic = decision
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "platform.mitm.profile_scope")
        .expect("platform diagnostic should be preserved");

    assert!(!decision.is_allowed());
    assert_eq!(decision.decision, AuditDecision::Denied);
    assert_eq!(decision.reason.as_deref(), Some(expected_reason));
    assert!(decision.plugin_result.is_none());
    assert_eq!(
        platform_diagnostic.severity,
        control_domain::DiagnosticSeverity::Warning
    );
    assert_eq!(
        platform_diagnostic.message,
        "mitm is limited to the selected profile"
    );
    assert_eq!(platform_diagnostic.source.as_deref(), Some("platform.mitm"));
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "plugin.manifest.missing_hook"
            && diagnostic.severity == control_domain::DiagnosticSeverity::Error
    }));
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "runtime.mitm.manifest_invalid"
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
fn mitm_gate_preserves_certificate_diagnostics_on_manifest_error_denial() {
    let expected_reason = "plugin manifest validation failed";
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: platform_status_with_gate_diagnostics(),
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

    let certificate_diagnostic = decision
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "platform.mitm_certificate.cached_trust")
        .expect("certificate diagnostic should be preserved");

    assert!(!decision.is_allowed());
    assert_eq!(decision.decision, AuditDecision::Denied);
    assert_eq!(decision.reason.as_deref(), Some(expected_reason));
    assert!(decision.plugin_result.is_none());
    assert_eq!(
        certificate_diagnostic.severity,
        control_domain::DiagnosticSeverity::Info
    );
    assert_eq!(
        certificate_diagnostic.message,
        "mitm certificate trust state was served from cache"
    );
    assert_eq!(
        certificate_diagnostic.source.as_deref(),
        Some("platform.mitm_certificate")
    );
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "plugin.manifest.missing_hook"
            && diagnostic.severity == control_domain::DiagnosticSeverity::Error
    }));
    assert!(decision.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "runtime.mitm.manifest_invalid"
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
fn mitm_gate_orders_diagnostics_on_manifest_error_denial() {
    let expected_reason = "plugin manifest validation failed";
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: platform_status_with_gate_diagnostics(),
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

    let diagnostic_codes = decision
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    let runtime_diagnostic = decision
        .diagnostics
        .last()
        .expect("runtime diagnostic should be appended");

    assert_eq!(
        diagnostic_codes,
        vec![
            "platform.mitm.profile_scope",
            "platform.mitm_certificate.cached_trust",
            "plugin.manifest.missing_hook",
            "runtime.mitm.manifest_invalid",
        ]
    );
    assert!(!decision.is_allowed());
    assert_eq!(decision.decision, AuditDecision::Denied);
    assert_eq!(decision.reason.as_deref(), Some(expected_reason));
    assert!(decision.plugin_result.is_none());
    assert_eq!(
        runtime_diagnostic.code.as_str(),
        "runtime.mitm.manifest_invalid"
    );
    assert_eq!(runtime_diagnostic.message.as_str(), expected_reason);
    assert_eq!(decision.audits.len(), 1);
    assert_eq!(decision.audits[0].decision, AuditDecision::Denied);
    assert_eq!(decision.audits[0].reason, decision.reason);
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
fn mitm_gate_preserves_platform_diagnostics_on_remote_script_denial() {
    let expected_reason =
        "remote script execution is unavailable: remote script execution is disabled on iOS";
    let gate = MitmGateOrchestrator::new(
        StaticPlatformCapabilityService {
            status: platform_status_without_remote_scripts_with_diagnostics(),
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

    let platform_diagnostic = decision
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "platform.remote_script_execution.disabled_by_policy")
        .expect("remote script diagnostic should be preserved");

    assert!(!decision.is_allowed());
    assert_eq!(decision.decision, AuditDecision::Denied);
    assert_eq!(decision.reason.as_deref(), Some(expected_reason));
    assert!(!decision.platform.remote_script_execution.is_available());
    assert!(decision.plugin_result.is_none());
    assert_eq!(
        platform_diagnostic.severity,
        control_domain::DiagnosticSeverity::Warning
    );
    assert_eq!(
        platform_diagnostic.message,
        "remote script execution is disabled by platform policy"
    );
    assert_eq!(
        platform_diagnostic.source.as_deref(),
        Some("platform.remote_script_execution")
    );
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

fn inline_subscription_source(id: &str) -> SubscriptionSource {
    SubscriptionSource {
        id: id.to_string(),
        location: "inline:[[nodes]]".to_string(),
    }
}

fn subscription_catalog(nodes: Vec<NodeDescriptor>, rules: Vec<RuleSet>) -> NodeCatalog {
    NodeCatalog { nodes, rules }
}

fn subscription_node(id: &str) -> NodeDescriptor {
    NodeDescriptor {
        id: id.to_string(),
        name: format!("Node {id}"),
        protocol: Protocol::Socks,
        endpoint: Endpoint {
            host: "127.0.0.1".to_string(),
            port: 1080,
        },
        tags: Vec::new(),
        metadata: Vec::new(),
    }
}

fn subscription_rule_set(id: &str, node_id: &str) -> RuleSet {
    RuleSet {
        id: id.to_string(),
        rules: vec![RouteRule {
            id: format!("{id}-proxy"),
            priority: 10,
            action: RouteAction::Proxy {
                node_id: node_id.to_string(),
            },
            metadata: Vec::new(),
        }],
        default_action: RouteAction::Reject,
    }
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

fn platform_status_without_mitm_with_diagnostics() -> PlatformCapabilityStatus {
    let mut status = platform_status_without_mitm();
    status.diagnostics = vec![Diagnostic::new(
        control_domain::DiagnosticSeverity::Warning,
        "platform.mitm.entitlement_missing",
        "mitm entitlement is unavailable on the current profile",
        Some("platform.mitm".to_string()),
    )];
    status
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

fn platform_status_with_certificate_diagnostics(
    state: CertificateTrustState,
) -> PlatformCapabilityStatus {
    let mut status = platform_status_with_certificate_state(state);
    status.mitm_certificate.diagnostics = vec![Diagnostic::new(
        control_domain::DiagnosticSeverity::Warning,
        "platform.mitm_certificate.trust_pending",
        "mitm certificate is installed but still pending user trust",
        Some("platform.mitm_certificate".to_string()),
    )];
    status
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

fn platform_status_without_remote_scripts_with_diagnostics() -> PlatformCapabilityStatus {
    let mut status = platform_status_without_remote_scripts();
    status.diagnostics = vec![Diagnostic::new(
        control_domain::DiagnosticSeverity::Warning,
        "platform.remote_script_execution.disabled_by_policy",
        "remote script execution is disabled by platform policy",
        Some("platform.remote_script_execution".to_string()),
    )];
    status
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

fn non_error_manifest_diagnostics() -> Vec<Diagnostic> {
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
