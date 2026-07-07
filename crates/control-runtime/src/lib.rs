//! Runtime orchestration use cases for the AnixOps network control kernel.
//!
//! This crate depends only on domain contracts. It coordinates domain ports but
//! does not perform platform probing, process management, file I/O, networking,
//! UI work, or transport-specific control API behavior.

use std::collections::BTreeSet;

use control_domain::{
    AuditDecision, AuditEvent, ConfigSnapshot, ConfigurationService, Diagnostic,
    DiagnosticSeverity, DomainError, DomainResult, GrantedPermissions, HttpEvent, Metadata,
    MitmPluginService, NodeCatalog, NodeDescriptor, PlatformCapabilities,
    PlatformCapabilityService, PlatformCapabilityStatus, PlatformFeatureState, PluginPackage,
    PluginPermission, PluginResult, ProxyEngineConfig, ProxyEngineEvent, ProxyEngineService,
    ProxyEngineStatus, SubscriptionService, SubscriptionSource,
};

pub const RUNTIME_SUBSCRIPTION_NODE_ID_DUPLICATE_CODE: &str =
    "runtime.subscription.node_id_duplicate";
pub const RUNTIME_SUBSCRIPTION_CATALOG_EMPTY_CODE: &str =
    "runtime.subscription.catalog_empty";
pub const RUNTIME_SUBSCRIPTION_RULES_DEFERRED_CODE: &str =
    "runtime.subscription.rules_deferred";
pub const RUNTIME_SUBSCRIPTION_CATALOG_READY_CODE: &str =
    "runtime.subscription.catalog_ready";
pub const RUNTIME_SUBSCRIPTION_SOURCE_UNSUPPORTED_CODE: &str =
    "runtime.subscription.source_unsupported";

/// Prepared configuration and platform context ready for runtime use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRuntimeConfig {
    pub platform: PlatformCapabilityStatus,
    pub capabilities: PlatformCapabilities,
    pub config: ConfigSnapshot,
    pub diagnostics: Vec<Diagnostic>,
}

/// Configuration-bearing runtime request used by start and reload use cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfigRequest {
    pub engine_id: String,
    pub raw_config: String,
    pub nodes: Vec<NodeDescriptor>,
    pub metadata: Metadata,
}

impl RuntimeConfigRequest {
    /// Creates a runtime config request with no nodes or metadata.
    pub fn new(engine_id: impl Into<String>, raw_config: impl Into<String>) -> Self {
        Self {
            engine_id: engine_id.into(),
            raw_config: raw_config.into(),
            nodes: Vec::new(),
            metadata: Vec::new(),
        }
    }
}

/// Result of applying subscription catalogs to a runtime config request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSubscriptionCatalogGateResult {
    pub request: RuntimeConfigRequest,
    pub diagnostics: Vec<Diagnostic>,
}

/// Runtime operation result with aggregated diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOperationResult {
    pub platform: PlatformCapabilityStatus,
    pub capabilities: PlatformCapabilities,
    pub engine_status: ProxyEngineStatus,
    pub diagnostics: Vec<Diagnostic>,
}

/// Runtime status snapshot with platform and engine state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStatusSnapshot {
    pub platform: PlatformCapabilityStatus,
    pub capabilities: PlatformCapabilities,
    pub engine_status: ProxyEngineStatus,
    pub diagnostics: Vec<Diagnostic>,
}

/// MITM plugin gate request for one HTTP event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmGateRequest {
    pub plugin_package: PluginPackage,
    pub granted_permissions: GrantedPermissions,
    pub http_event: HttpEvent,
}

impl MitmGateRequest {
    /// Creates a MITM gate request.
    pub fn new(
        plugin_package: PluginPackage,
        granted_permissions: GrantedPermissions,
        http_event: HttpEvent,
    ) -> Self {
        Self {
            plugin_package,
            granted_permissions,
            http_event,
        }
    }
}

/// MITM gate decision with diagnostics and audit events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmGateDecision {
    pub platform: PlatformCapabilityStatus,
    pub decision: AuditDecision,
    pub reason: Option<String>,
    pub plugin_result: Option<PluginResult>,
    pub audits: Vec<AuditEvent>,
    pub diagnostics: Vec<Diagnostic>,
}

impl MitmGateDecision {
    /// Returns whether the gate allowed plugin execution.
    pub fn is_allowed(&self) -> bool {
        self.decision == AuditDecision::Allowed
    }
}

/// Pure runtime use case orchestrator.
pub struct RuntimeOrchestrator<C, P, E> {
    configuration: C,
    platform: P,
    engine: E,
}

/// Pure MITM gate orchestrator.
pub struct MitmGateOrchestrator<P, M> {
    platform: P,
    mitm: M,
}

impl<C, P, E> RuntimeOrchestrator<C, P, E>
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
{
    /// Creates a runtime orchestrator from domain port implementations.
    pub const fn new(configuration: C, platform: P, engine: E) -> Self {
        Self {
            configuration,
            platform,
            engine,
        }
    }

    /// Validates and normalizes raw configuration against current platform capabilities.
    pub fn prepare_config(&self, raw_config: &str) -> DomainResult<PreparedRuntimeConfig> {
        let platform = self.platform.status()?;
        let capabilities = platform_capabilities_from_status(&platform);
        let mut diagnostics = platform_diagnostics(&platform);

        diagnostics.extend(self.configuration.validate(raw_config, &capabilities));
        reject_error_diagnostics(
            &diagnostics,
            "runtime.config.invalid",
            "configuration validation failed",
        )?;

        let config = self.configuration.normalize(raw_config, &capabilities)?;

        Ok(PreparedRuntimeConfig {
            platform,
            capabilities,
            config,
            diagnostics,
        })
    }

    /// Applies explicit subscription catalogs to runtime request nodes.
    pub fn prepare_runtime_request_with_subscription_catalogs<S>(
        &self,
        request: RuntimeConfigRequest,
        subscription: &S,
        sources: &[SubscriptionSource],
    ) -> DomainResult<RuntimeSubscriptionCatalogGateResult>
    where
        S: SubscriptionService,
    {
        let prepared = self.prepare_config(&request.raw_config)?;
        let gate =
            prepare_subscription_catalog_request(request, &prepared.config, subscription, sources)?;
        let mut diagnostics = prepared.diagnostics;
        diagnostics.extend(gate.diagnostics);

        Ok(RuntimeSubscriptionCatalogGateResult {
            request: gate.request,
            diagnostics,
        })
    }

    /// Starts a runtime engine after platform and engine configuration gates pass.
    pub fn start_runtime(
        &self,
        request: RuntimeConfigRequest,
    ) -> DomainResult<RuntimeOperationResult> {
        let (prepared, engine_config) = self.prepare_engine_config(&request)?;

        ensure_start_capabilities(&prepared.platform)?;
        let mut diagnostics = prepared.diagnostics.clone();
        diagnostics.extend(self.validate_engine_config(&engine_config)?);

        let engine_status = self.engine.start(&engine_config)?;
        diagnostics.extend(engine_status.diagnostics.clone());

        Ok(RuntimeOperationResult {
            platform: prepared.platform,
            capabilities: prepared.capabilities,
            engine_status,
            diagnostics,
        })
    }

    /// Starts a runtime engine with explicit subscription catalog node handoff.
    pub fn start_runtime_with_subscription_catalogs<S>(
        &self,
        request: RuntimeConfigRequest,
        subscription: &S,
        sources: &[SubscriptionSource],
    ) -> DomainResult<RuntimeOperationResult>
    where
        S: SubscriptionService,
    {
        let (prepared, engine_config, subscription_diagnostics) =
            self.prepare_engine_config_with_subscription_catalogs(&request, subscription, sources)?;

        ensure_start_capabilities(&prepared.platform)?;
        let mut diagnostics = prepared.diagnostics.clone();
        diagnostics.extend(subscription_diagnostics);
        diagnostics.extend(self.validate_engine_config(&engine_config)?);

        let engine_status = self.engine.start(&engine_config)?;
        diagnostics.extend(engine_status.diagnostics.clone());

        Ok(RuntimeOperationResult {
            platform: prepared.platform,
            capabilities: prepared.capabilities,
            engine_status,
            diagnostics,
        })
    }

    /// Reloads a runtime engine after platform and engine configuration gates pass.
    pub fn reload_runtime(
        &self,
        request: RuntimeConfigRequest,
    ) -> DomainResult<RuntimeOperationResult> {
        let (prepared, engine_config) = self.prepare_engine_config(&request)?;

        ensure_start_capabilities(&prepared.platform)?;
        let mut diagnostics = prepared.diagnostics.clone();
        diagnostics.extend(self.validate_engine_config(&engine_config)?);

        let engine_status = self.engine.reload(&engine_config)?;
        diagnostics.extend(engine_status.diagnostics.clone());

        Ok(RuntimeOperationResult {
            platform: prepared.platform,
            capabilities: prepared.capabilities,
            engine_status,
            diagnostics,
        })
    }

    /// Reloads a runtime engine with explicit subscription catalog node handoff.
    pub fn reload_runtime_with_subscription_catalogs<S>(
        &self,
        request: RuntimeConfigRequest,
        subscription: &S,
        sources: &[SubscriptionSource],
    ) -> DomainResult<RuntimeOperationResult>
    where
        S: SubscriptionService,
    {
        let (prepared, engine_config, subscription_diagnostics) =
            self.prepare_engine_config_with_subscription_catalogs(&request, subscription, sources)?;

        ensure_start_capabilities(&prepared.platform)?;
        let mut diagnostics = prepared.diagnostics.clone();
        diagnostics.extend(subscription_diagnostics);
        diagnostics.extend(self.validate_engine_config(&engine_config)?);

        let engine_status = self.engine.reload(&engine_config)?;
        diagnostics.extend(engine_status.diagnostics.clone());

        Ok(RuntimeOperationResult {
            platform: prepared.platform,
            capabilities: prepared.capabilities,
            engine_status,
            diagnostics,
        })
    }

    /// Stops a runtime engine through the proxy engine port.
    pub fn stop_runtime(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        self.engine.stop(engine_id)
    }

    /// Reads current platform and engine status.
    pub fn runtime_status(&self, engine_id: &str) -> DomainResult<RuntimeStatusSnapshot> {
        let platform = self.platform.status()?;
        let capabilities = platform_capabilities_from_status(&platform);
        let mut diagnostics = platform_diagnostics(&platform);
        let engine_status = self.engine.status(engine_id)?;

        diagnostics.extend(engine_status.diagnostics.clone());

        Ok(RuntimeStatusSnapshot {
            platform,
            capabilities,
            engine_status,
            diagnostics,
        })
    }

    /// Reads runtime events for an engine through the proxy engine port.
    pub fn runtime_events(&self, engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
        self.engine.events(engine_id)
    }

    fn prepare_engine_config(
        &self,
        request: &RuntimeConfigRequest,
    ) -> DomainResult<(PreparedRuntimeConfig, ProxyEngineConfig)> {
        let prepared = self.prepare_config(&request.raw_config)?;
        let engine_config = ProxyEngineConfig {
            engine_id: request.engine_id.clone(),
            config: prepared.config.clone(),
            nodes: request.nodes.clone(),
            metadata: request.metadata.clone(),
        };

        Ok((prepared, engine_config))
    }

    fn prepare_engine_config_with_subscription_catalogs<S>(
        &self,
        request: &RuntimeConfigRequest,
        subscription: &S,
        sources: &[SubscriptionSource],
    ) -> DomainResult<(PreparedRuntimeConfig, ProxyEngineConfig, Vec<Diagnostic>)>
    where
        S: SubscriptionService,
    {
        let prepared = self.prepare_config(&request.raw_config)?;
        let gate = prepare_subscription_catalog_request(
            request.clone(),
            &prepared.config,
            subscription,
            sources,
        )?;
        let engine_config = ProxyEngineConfig {
            engine_id: gate.request.engine_id,
            config: prepared.config.clone(),
            nodes: gate.request.nodes,
            metadata: gate.request.metadata,
        };

        Ok((prepared, engine_config, gate.diagnostics))
    }

    fn validate_engine_config(
        &self,
        engine_config: &ProxyEngineConfig,
    ) -> DomainResult<Vec<Diagnostic>> {
        let diagnostics = self.engine.validate_config(engine_config);
        reject_error_diagnostics(
            &diagnostics,
            "runtime.engine_config.invalid",
            "engine configuration validation failed",
        )?;
        Ok(diagnostics)
    }
}

fn prepare_subscription_catalog_request<S>(
    mut request: RuntimeConfigRequest,
    config: &ConfigSnapshot,
    subscription: &S,
    sources: &[SubscriptionSource],
) -> DomainResult<RuntimeSubscriptionCatalogGateResult>
where
    S: SubscriptionService,
{
    let mut known_node_ids = existing_runtime_node_ids(config, &request.nodes);
    let mut diagnostics = Vec::new();

    for source in sources {
        ensure_subscription_source_supported(source)?;
        let raw_subscription = subscription.fetch(source)?;
        let document = subscription.parse(&raw_subscription)?;
        diagnostics.extend(document.diagnostics.clone());
        let catalog = subscription.normalize(&document)?;
        append_subscription_catalog_nodes(
            &mut request.nodes,
            &catalog,
            &mut known_node_ids,
            source,
            &mut diagnostics,
        )?;
    }

    Ok(RuntimeSubscriptionCatalogGateResult {
        request,
        diagnostics,
    })
}

fn existing_runtime_node_ids(
    config: &ConfigSnapshot,
    request_nodes: &[NodeDescriptor],
) -> BTreeSet<String> {
    let mut node_ids = BTreeSet::new();
    node_ids.extend(config.nodes.iter().map(|node| node.id.clone()));
    node_ids.extend(request_nodes.iter().map(|node| node.id.clone()));
    node_ids
}

fn ensure_subscription_source_supported(source: &SubscriptionSource) -> DomainResult<()> {
    if source.location.trim().starts_with("inline:") {
        return Ok(());
    }

    Err(DomainError::new(
        RUNTIME_SUBSCRIPTION_SOURCE_UNSUPPORTED_CODE,
        "subscription source kind is unsupported by the runtime catalog gate",
    ))
}

fn append_subscription_catalog_nodes(
    request_nodes: &mut Vec<NodeDescriptor>,
    catalog: &NodeCatalog,
    known_node_ids: &mut BTreeSet<String>,
    source: &SubscriptionSource,
    diagnostics: &mut Vec<Diagnostic>,
) -> DomainResult<()> {
    let source_scope = subscription_source_scope(source);

    if catalog.nodes.is_empty() {
        diagnostics.push(Diagnostic::new(
            DiagnosticSeverity::Warning,
            RUNTIME_SUBSCRIPTION_CATALOG_EMPTY_CODE,
            "subscription catalog contains no runtime nodes",
            source_scope.clone(),
        ));
    }

    if !catalog.rules.is_empty() {
        diagnostics.push(Diagnostic::new(
            DiagnosticSeverity::Info,
            RUNTIME_SUBSCRIPTION_RULES_DEFERRED_CODE,
            "subscription catalog rules are deferred until policy routing is wired",
            source_scope.clone(),
        ));
    }

    for node in &catalog.nodes {
        if !known_node_ids.insert(node.id.clone()) {
            return Err(DomainError::new(
                RUNTIME_SUBSCRIPTION_NODE_ID_DUPLICATE_CODE,
                "subscription catalog node ids must be unique across config and runtime request nodes",
            ));
        }
    }

    if !catalog.nodes.is_empty() {
        request_nodes.extend(catalog.nodes.clone());
        diagnostics.push(Diagnostic::new(
            DiagnosticSeverity::Info,
            RUNTIME_SUBSCRIPTION_CATALOG_READY_CODE,
            "subscription catalog nodes are ready for RuntimeConfigRequest.nodes",
            source_scope,
        ));
    }

    Ok(())
}

fn subscription_source_scope(source: &SubscriptionSource) -> Option<String> {
    let source_id = source.id.trim();
    if source_id.is_empty() {
        None
    } else {
        Some(source_id.to_string())
    }
}

impl<P, M> MitmGateOrchestrator<P, M>
where
    P: PlatformCapabilityService,
    M: MitmPluginService,
{
    /// Creates a MITM gate orchestrator from domain port implementations.
    pub const fn new(platform: P, mitm: M) -> Self {
        Self { platform, mitm }
    }

    /// Evaluates platform and permission gates before handling a MITM HTTP event.
    pub fn mitm_gate(&self, request: MitmGateRequest) -> DomainResult<MitmGateDecision> {
        let platform = self.platform.status()?;
        let mut diagnostics = platform_diagnostics(&platform);
        let actor = request.plugin_package.manifest.id.clone();

        if !platform.mitm.is_available() {
            let reason = platform
                .mitm
                .denial_reason()
                .unwrap_or("mitm availability is unknown")
                .to_string();
            return Ok(denied_mitm_gate(
                platform,
                &actor,
                "runtime.mitm.unavailable",
                format!("mitm is unavailable: {reason}"),
                diagnostics,
            ));
        }

        if !platform.mitm_certificate.is_trusted() {
            let reason = platform
                .mitm_certificate
                .state
                .denial_reason()
                .unwrap_or("mitm certificate trust state is unknown");
            return Ok(denied_mitm_gate(
                platform,
                &actor,
                "runtime.mitm.certificate_untrusted",
                reason.to_string(),
                diagnostics,
            ));
        }

        if !platform.remote_script_execution.is_available() {
            let reason = platform
                .remote_script_execution
                .denial_reason()
                .unwrap_or("remote script execution availability is unknown")
                .to_string();
            return Ok(denied_mitm_gate(
                platform,
                &actor,
                "runtime.mitm.remote_script_unavailable",
                format!("remote script execution is unavailable: {reason}"),
                diagnostics,
            ));
        }

        let manifest_diagnostics = self
            .mitm
            .validate_manifest(&request.plugin_package.manifest);
        let manifest_invalid = has_error_diagnostics(&manifest_diagnostics);
        diagnostics.extend(manifest_diagnostics);
        if manifest_invalid {
            return Ok(denied_mitm_gate(
                platform,
                &actor,
                "runtime.mitm.manifest_invalid",
                "plugin manifest validation failed".to_string(),
                diagnostics,
            ));
        }

        if let Some(permission) = first_missing_permission(
            &request.plugin_package.manifest.permissions,
            &request.granted_permissions.permissions,
        ) {
            return Ok(denied_mitm_gate(
                platform,
                &actor,
                "runtime.mitm.permission_denied",
                format!(
                    "plugin permission is not granted: {}",
                    plugin_permission_name(permission)
                ),
                diagnostics,
            ));
        }

        let plugin_instance = self
            .mitm
            .load(&request.plugin_package, &request.granted_permissions)?;
        let plugin_result = self
            .mitm
            .handle_http_event(&plugin_instance, &request.http_event)?;
        let plugin_audits = self.mitm.audit(&plugin_result);

        diagnostics.extend(plugin_result.diagnostics.clone());
        let mut audits = vec![AuditEvent {
            actor,
            action: "mitm_gate".to_string(),
            decision: AuditDecision::Allowed,
            reason: None,
        }];
        audits.extend(plugin_result.audits.clone());
        audits.extend(plugin_audits);

        Ok(MitmGateDecision {
            platform,
            decision: AuditDecision::Allowed,
            reason: None,
            plugin_result: Some(plugin_result),
            audits,
            diagnostics,
        })
    }
}

/// Converts rich platform status into the current configuration capability input.
pub fn platform_capabilities_from_status(
    status: &PlatformCapabilityStatus,
) -> PlatformCapabilities {
    PlatformCapabilities {
        os: status.os,
        supports_tunnel: status.tunnel.is_available(),
        supports_mitm: status.mitm_available(),
        supports_embedded_runtime: status.embedded_runtime.is_available(),
    }
}

fn ensure_start_capabilities(status: &PlatformCapabilityStatus) -> DomainResult<()> {
    ensure_available(
        &status.tunnel,
        "runtime.platform.tunnel_unavailable",
        "runtime tunnel is unavailable",
    )?;
    ensure_available(
        &status.embedded_runtime,
        "runtime.platform.embedded_runtime_unavailable",
        "embedded runtime is unavailable",
    )
}

fn ensure_available(
    feature: &PlatformFeatureState,
    code: &'static str,
    message: &'static str,
) -> DomainResult<()> {
    if feature.is_available() {
        Ok(())
    } else {
        let reason = feature
            .denial_reason()
            .unwrap_or("platform feature availability is unknown");
        Err(DomainError::new(code, format!("{message}: {reason}")))
    }
}

fn reject_error_diagnostics(
    diagnostics: &[Diagnostic],
    code: &'static str,
    message: &'static str,
) -> DomainResult<()> {
    if has_error_diagnostics(diagnostics) {
        Err(DomainError::new(code, message))
    } else {
        Ok(())
    }
}

fn has_error_diagnostics(diagnostics: &[Diagnostic]) -> bool {
    diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
}

fn platform_diagnostics(status: &PlatformCapabilityStatus) -> Vec<Diagnostic> {
    let mut diagnostics = status.diagnostics.clone();
    diagnostics.extend(status.mitm_certificate.diagnostics.clone());
    diagnostics
}

fn denied_mitm_gate(
    platform: PlatformCapabilityStatus,
    actor: &str,
    code: &'static str,
    message: String,
    mut diagnostics: Vec<Diagnostic>,
) -> MitmGateDecision {
    diagnostics.push(Diagnostic::new(
        DiagnosticSeverity::Error,
        code,
        message.clone(),
        Some("mitm_gate".to_string()),
    ));

    MitmGateDecision {
        platform,
        decision: AuditDecision::Denied,
        reason: Some(message.clone()),
        plugin_result: None,
        audits: vec![AuditEvent {
            actor: actor.to_string(),
            action: "mitm_gate".to_string(),
            decision: AuditDecision::Denied,
            reason: Some(message),
        }],
        diagnostics,
    }
}

fn first_missing_permission<'a>(
    required_permissions: &'a [PluginPermission],
    granted_permissions: &[PluginPermission],
) -> Option<&'a PluginPermission> {
    required_permissions
        .iter()
        .find(|permission| !granted_permissions.contains(*permission))
}

fn plugin_permission_name(permission: &PluginPermission) -> &'static str {
    match permission {
        PluginPermission::ReadRequest => "read_request",
        PluginPermission::ModifyRequest => "modify_request",
        PluginPermission::ReadResponse => "read_response",
        PluginPermission::ModifyResponse => "modify_response",
        PluginPermission::NetworkAccess => "network_access",
        PluginPermission::PersistentStorage => "persistent_storage",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use control_domain::{
        CertificateTrustState, MitmCertificateStatus, OperatingSystem, PlatformFeatureState,
        ProxyEngineLifecycleState, SchemaVersion,
    };

    struct DiagnosticConfigService {
        diagnostics: Vec<Diagnostic>,
    }

    impl ConfigurationService for DiagnosticConfigService {
        fn validate(
            &self,
            _raw_config: &str,
            _capabilities: &PlatformCapabilities,
        ) -> Vec<Diagnostic> {
            self.diagnostics.clone()
        }

        fn normalize(
            &self,
            _raw_config: &str,
            _capabilities: &PlatformCapabilities,
        ) -> DomainResult<ConfigSnapshot> {
            Ok(empty_config())
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

    struct StaticPlatformService {
        status: PlatformCapabilityStatus,
    }

    impl PlatformCapabilityService for StaticPlatformService {
        fn status(&self) -> DomainResult<PlatformCapabilityStatus> {
            Ok(self.status.clone())
        }
    }

    struct StaticEngineService {
        config_diagnostics: Vec<Diagnostic>,
    }

    impl ProxyEngineService for StaticEngineService {
        fn list_engines(&self) -> Vec<control_domain::ProxyEngineDescriptor> {
            Vec::new()
        }

        fn validate_config(&self, _engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
            self.config_diagnostics.clone()
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
    fn platform_status_maps_to_configuration_capabilities() {
        let status = available_platform_status();
        let capabilities = platform_capabilities_from_status(&status);

        assert_eq!(capabilities.os, OperatingSystem::Ios);
        assert!(capabilities.supports_tunnel);
        assert!(capabilities.supports_mitm);
        assert!(capabilities.supports_embedded_runtime);
    }

    #[test]
    fn prepare_config_rejects_validation_errors() {
        let orchestrator = RuntimeOrchestrator::new(
            DiagnosticConfigService {
                diagnostics: vec![Diagnostic::new(
                    DiagnosticSeverity::Error,
                    "config.empty",
                    "configuration is empty",
                    None,
                )],
            },
            StaticPlatformService {
                status: available_platform_status(),
            },
            StaticEngineService {
                config_diagnostics: Vec::new(),
            },
        );

        let error = orchestrator
            .prepare_config("")
            .expect_err("validation errors should reject config");

        assert_eq!(error.code, "runtime.config.invalid");
    }

    #[test]
    fn start_runtime_rejects_engine_config_errors() {
        let orchestrator = RuntimeOrchestrator::new(
            DiagnosticConfigService {
                diagnostics: Vec::new(),
            },
            StaticPlatformService {
                status: available_platform_status(),
            },
            StaticEngineService {
                config_diagnostics: vec![Diagnostic::new(
                    DiagnosticSeverity::Error,
                    "engine.config.invalid",
                    "engine rejected config",
                    None,
                )],
            },
        );

        let error = orchestrator
            .start_runtime(RuntimeConfigRequest::new("native", "profile = default"))
            .expect_err("engine config errors should reject start");

        assert_eq!(error.code, "runtime.engine_config.invalid");
    }

    fn available_platform_status() -> PlatformCapabilityStatus {
        PlatformCapabilityStatus {
            os: OperatingSystem::Ios,
            tunnel: PlatformFeatureState::available(),
            mitm: PlatformFeatureState::available(),
            embedded_runtime: PlatformFeatureState::available(),
            remote_script_execution: PlatformFeatureState::unavailable(
                "remote scripts are disabled on iOS",
            ),
            mitm_certificate: MitmCertificateStatus::new(CertificateTrustState::Trusted),
            diagnostics: Vec::new(),
        }
    }

    fn empty_config() -> ConfigSnapshot {
        ConfigSnapshot {
            version: SchemaVersion::new(1),
            profiles: vec!["default".to_string()],
            listeners: Vec::new(),
            nodes: Vec::new(),
            policies: Vec::new(),
            dns: Vec::new(),
            plugins: Vec::new(),
        }
    }
}
