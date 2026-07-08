//! Domain contracts for the AnixOps network control kernel.
//!
//! This crate intentionally contains only pure domain types and port traits. It
//! must not depend on platform SDKs, proxy engine processes, UI code, or network
//! transports.

use std::error::Error;
use std::fmt::{Display, Formatter};

/// Result type used by domain ports.
pub type DomainResult<T> = Result<T, DomainError>;

/// Stable schema version for configuration documents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SchemaVersion(u32);

impl SchemaVersion {
    /// Creates a schema version.
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the numeric schema version.
    pub const fn value(self) -> u32 {
        self.0
    }
}

/// Error returned by domain ports when an operation cannot produce a valid value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainError {
    pub code: String,
    pub message: String,
}

impl DomainError {
    /// Creates a domain error with a stable code and human-readable message.
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl Display for DomainError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for DomainError {}

/// Diagnostic severity for validation, parsing, and runtime explanations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

/// Human- and machine-readable diagnostic message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub message: String,
    pub source: Option<String>,
}

impl Diagnostic {
    /// Creates a diagnostic message.
    pub fn new(
        severity: DiagnosticSeverity,
        code: impl Into<String>,
        message: impl Into<String>,
        source: Option<String>,
    ) -> Self {
        Self {
            severity,
            code: code.into(),
            message: message.into(),
            source,
        }
    }
}

/// Generic key/value metadata used by domain inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataEntry {
    pub key: String,
    pub value: String,
}

pub type Metadata = Vec<MetadataEntry>;

pub const NODE_METADATA_SHADOWSOCKS_METHOD: &str = "shadowsocks.method";
pub const NODE_METADATA_SHADOWSOCKS_PASSWORD: &str = "shadowsocks.password";
pub const NODE_METADATA_SOURCE_FORMAT: &str = "subscription.source_format";

/// Operating system capability target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperatingSystem {
    Linux,
    Macos,
    Windows,
    Ios,
    Unknown,
}

/// Platform capabilities visible to the domain layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformCapabilities {
    pub os: OperatingSystem,
    pub supports_tunnel: bool,
    pub supports_mitm: bool,
    pub supports_embedded_runtime: bool,
}

/// Availability of a platform feature after permissions and platform limits are considered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformFeatureState {
    Available,
    Unavailable { reason: String },
    Unknown,
}

impl PlatformFeatureState {
    /// Creates an available platform feature state.
    pub const fn available() -> Self {
        Self::Available
    }

    /// Creates an unavailable platform feature state with a stable denial reason.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }

    /// Creates an unknown platform feature state.
    pub const fn unknown() -> Self {
        Self::Unknown
    }

    /// Returns whether the feature is currently available.
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }

    /// Returns the reason a feature cannot be used yet.
    pub fn denial_reason(&self) -> Option<&str> {
        match self {
            Self::Available => None,
            Self::Unavailable { reason } => Some(reason.as_str()),
            Self::Unknown => Some("platform feature availability is unknown"),
        }
    }
}

/// Trust state of the MITM certificate visible to the domain layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertificateTrustState {
    NotInstalled,
    InstalledUntrusted,
    Trusted,
    Revoked,
    Unknown,
}

impl CertificateTrustState {
    /// Returns whether a certificate is present on the platform.
    pub fn is_installed(self) -> bool {
        matches!(
            self,
            Self::InstalledUntrusted | Self::Trusted | Self::Revoked
        )
    }

    /// Returns whether the platform currently trusts the MITM certificate.
    pub fn is_trusted(self) -> bool {
        self == Self::Trusted
    }

    /// Returns a denial reason when the certificate cannot be used for MITM.
    pub fn denial_reason(self) -> Option<&'static str> {
        match self {
            Self::Trusted => None,
            Self::NotInstalled => Some("mitm certificate is not installed"),
            Self::InstalledUntrusted => Some("mitm certificate is installed but not trusted"),
            Self::Revoked => Some("mitm certificate is revoked"),
            Self::Unknown => Some("mitm certificate trust state is unknown"),
        }
    }
}

/// MITM certificate status reported by a platform adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmCertificateStatus {
    pub state: CertificateTrustState,
    pub subject: Option<String>,
    pub fingerprint_sha256: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
}

impl MitmCertificateStatus {
    /// Creates MITM certificate status with no certificate metadata.
    pub fn new(state: CertificateTrustState) -> Self {
        Self {
            state,
            subject: None,
            fingerprint_sha256: None,
            diagnostics: Vec::new(),
        }
    }

    /// Returns whether the certificate is installed on the platform.
    pub fn is_installed(&self) -> bool {
        self.state.is_installed()
    }

    /// Returns whether the certificate is trusted by the platform.
    pub fn is_trusted(&self) -> bool {
        self.state.is_trusted()
    }
}

/// Rich platform capability status visible to domain services and clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformCapabilityStatus {
    pub os: OperatingSystem,
    pub tunnel: PlatformFeatureState,
    pub mitm: PlatformFeatureState,
    pub embedded_runtime: PlatformFeatureState,
    pub remote_script_execution: PlatformFeatureState,
    pub mitm_certificate: MitmCertificateStatus,
    pub diagnostics: Vec<Diagnostic>,
}

impl PlatformCapabilityStatus {
    /// Returns whether MITM can be used now, including certificate trust.
    pub fn mitm_available(&self) -> bool {
        self.mitm.is_available() && self.mitm_certificate.is_trusted()
    }

    /// Returns the first reason MITM cannot be used now.
    pub fn mitm_denied_reason(&self) -> Option<&str> {
        self.mitm
            .denial_reason()
            .or_else(|| self.mitm_certificate.state.denial_reason())
    }
}

/// Normalized configuration snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSnapshot {
    pub version: SchemaVersion,
    pub profiles: Vec<String>,
    pub listeners: Vec<ListenerDescriptor>,
    pub nodes: Vec<NodeDescriptor>,
    pub policies: Vec<RuleSet>,
    pub dns: Vec<DnsUpstream>,
    pub plugins: Vec<PluginManifest>,
}

/// Inbound listener protocol family.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ListenerKind {
    LocalTcp,
    Socks,
    Http,
    Tun,
    Other(String),
}

/// Listener bind address without socket ownership.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListenerBind {
    pub host: String,
    pub port: u16,
}

/// Transport network accepted by a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ListenerNetwork {
    Tcp,
    Udp,
    TcpUdp,
}

/// Route entry selected by a listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListenerRoute {
    RuleSet { rule_set_id: String },
    DefaultAction(RouteAction),
}

/// Normalized inbound listener description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerDescriptor {
    pub id: String,
    pub enabled: bool,
    pub kind: ListenerKind,
    pub bind: ListenerBind,
    pub network: ListenerNetwork,
    pub route: ListenerRoute,
    pub tags: Vec<String>,
    pub metadata: Metadata,
}

/// Proxy protocol family.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Protocol {
    Http,
    Socks,
    Shadowsocks,
    Vmess,
    Vless,
    Trojan,
    Hysteria,
    Other(String),
}

/// Network endpoint without transport ownership.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}

/// Normalized proxy node description.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDescriptor {
    pub id: String,
    pub name: String,
    pub protocol: Protocol,
    pub endpoint: Endpoint,
    pub tags: Vec<String>,
    pub metadata: Metadata,
}

/// Subscription source descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionSource {
    pub id: String,
    pub location: String,
}

/// Raw subscription payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSubscription {
    pub source_id: String,
    pub content: String,
}

/// Parsed subscription before normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionDocument {
    pub nodes: Vec<NodeDescriptor>,
    pub rules: Vec<RuleSet>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Normalized node and rule catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCatalog {
    pub nodes: Vec<NodeDescriptor>,
    pub rules: Vec<RuleSet>,
}

/// Route action selected by policy routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAction {
    Direct,
    Proxy { node_id: String },
    Reject,
}

/// Route matching rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRule {
    pub id: String,
    pub priority: u32,
    pub action: RouteAction,
    pub metadata: Metadata,
}

/// Policy routing rule set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSet {
    pub id: String,
    pub rules: Vec<RouteRule>,
    pub default_action: RouteAction,
}

/// Network family for route decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Tcp,
    Udp,
}

/// Route decision input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteContext {
    pub network: Network,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub metadata: Metadata,
}

/// Runtime health state for a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRuntimeState {
    pub node_id: String,
    pub healthy: bool,
}

/// Runtime state available to policy routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeState {
    pub nodes: Vec<NodeRuntimeState>,
}

/// Supported proxy engine family.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProxyEngineKind {
    Native,
    SingBox,
    XrayCore,
    Mihomo,
    Other(String),
}

/// Capability exposed by a proxy execution engine adapter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProxyEngineCapability {
    TcpProxy,
    UdpProxy,
    Tun,
    Dns,
    Mitm,
    HotReload,
    HealthCheck,
}

/// Available proxy execution engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEngineDescriptor {
    pub id: String,
    pub kind: ProxyEngineKind,
    pub version: Option<String>,
    pub capabilities: Vec<ProxyEngineCapability>,
}

/// Standardized engine configuration input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEngineConfig {
    pub engine_id: String,
    pub config: ConfigSnapshot,
    pub nodes: Vec<NodeDescriptor>,
    pub metadata: Metadata,
}

/// Proxy execution engine lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyEngineLifecycleState {
    Stopped,
    Starting,
    Running,
    Reloading,
    Stopping,
    Failed,
}

/// Proxy execution engine status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEngineStatus {
    pub engine_id: String,
    pub state: ProxyEngineLifecycleState,
    pub diagnostics: Vec<Diagnostic>,
}

/// Proxy execution engine event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyEngineEventKind {
    Started,
    Reloaded,
    Stopped,
    HealthChanged,
    Failed,
}

/// Proxy execution engine event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyEngineEvent {
    pub engine_id: String,
    pub kind: ProxyEngineEventKind,
    pub diagnostics: Vec<Diagnostic>,
}

/// Compiled routing rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRules {
    pub rule_set_id: String,
}

/// Route decision output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    pub action: RouteAction,
    pub reason: String,
    pub diagnostics: Vec<Diagnostic>,
}

/// DNS record type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsRecordType {
    A,
    Aaaa,
    Cname,
    Txt,
    Other,
}

/// DNS policy input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub name: String,
    pub record_type: DnsRecordType,
    pub client_context: Metadata,
}

/// DNS upstream descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsUpstream {
    pub id: String,
    pub endpoint: Endpoint,
}

/// DNS resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsStrategy {
    System,
    Remote,
    Direct,
}

/// DNS cache policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CachePolicy {
    UseCache,
    Refresh,
    Bypass,
}

/// DNS decision output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDecision {
    pub upstream: Option<DnsUpstream>,
    pub strategy: DnsStrategy,
    pub cache_policy: CachePolicy,
    pub diagnostics: Vec<Diagnostic>,
}

/// Cached DNS result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedDnsResult {
    pub query: DnsQuery,
    pub values: Vec<String>,
}

/// DNS cache update event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEvent {
    pub query: DnsQuery,
    pub values: Vec<String>,
    pub policy: CachePolicy,
}

/// Plugin permission declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PluginPermission {
    ReadRequest,
    ModifyRequest,
    ReadResponse,
    ModifyResponse,
    NetworkAccess,
    PersistentStorage,
}

/// Plugin hook declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HookPoint {
    Request,
    Response,
}

/// MITM plugin manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginManifest {
    pub id: String,
    pub version: String,
    pub permissions: Vec<PluginPermission>,
    pub hooks: Vec<HookPoint>,
}

/// Plugin package payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginPackage {
    pub manifest: PluginManifest,
    pub source: String,
}

/// Granted plugin permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantedPermissions {
    pub permissions: Vec<PluginPermission>,
}

/// Loaded plugin instance descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginInstance {
    pub manifest: PluginManifest,
    /// Optional loaded source snapshot for stateless adapters.
    ///
    /// This field is owned by the plugin service boundary and must not be
    /// surfaced in client status, diagnostics, release notes, or logs.
    pub loaded_source: Option<String>,
}

/// HTTP event visible to plugin logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEvent {
    pub request_id: String,
    pub headers: Metadata,
    pub body: Vec<u8>,
}

/// HTTP MITM phase used by plugin mutation planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMitmPhase {
    Request,
    Response,
}

/// Rich HTTP MITM event visible to mutation-capable plugin logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMitmEvent {
    pub request_id: String,
    pub url: String,
    pub method: Option<String>,
    pub phase: HttpMitmPhase,
    pub status_code: Option<u16>,
    pub headers: Metadata,
    pub body: Vec<u8>,
}

impl HttpMitmEvent {
    /// Converts this rich MITM event to the legacy read-only HTTP event shape.
    pub fn legacy_event(&self) -> HttpEvent {
        HttpEvent {
            request_id: self.request_id.clone(),
            headers: self.headers.clone(),
            body: self.body.clone(),
        }
    }
}

/// Terminal action selected by MITM plugin policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMitmAction {
    Continue,
    Redirect { status_code: u16, location: String },
    Reject { status_code: u16 },
}

/// Header mutation operation selected by plugin policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpHeaderMutationOperation {
    Add,
    Replace,
    Delete,
    Set,
}

/// Header mutation planned by plugin policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHeaderMutation {
    pub operation: HttpHeaderMutationOperation,
    pub name: String,
    pub value: Option<String>,
}

/// Body mutation planned by plugin policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpBodyMutation {
    pub body: Vec<u8>,
    pub truncated: bool,
}

/// Script dispatch phase planned by plugin policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpMitmScriptKind {
    Request,
    Response,
}

/// Script dispatch planned by plugin policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMitmScriptDispatch {
    pub kind: HttpMitmScriptKind,
    pub phase: HttpMitmPhase,
    pub requires_body: bool,
    pub timeout_ms: usize,
    pub max_size: usize,
    pub script_path: String,
    pub tag: String,
    pub argument: String,
}

/// MITM plugin mutation plan consumed by a future HTTP/TLS data plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpMitmOutcome {
    pub action: HttpMitmAction,
    pub header_mutations: Vec<HttpHeaderMutation>,
    pub body_mutation: Option<HttpBodyMutation>,
    pub script_dispatch: Option<HttpMitmScriptDispatch>,
    pub audits: Vec<AuditEvent>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Security audit decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditDecision {
    Allowed,
    Denied,
}

/// Security-sensitive audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    pub actor: String,
    pub action: String,
    pub decision: AuditDecision,
    pub reason: Option<String>,
}

/// MITM plugin operation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginResult {
    pub audits: Vec<AuditEvent>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Control API caller context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerContext {
    pub actor: String,
    pub permissions: Vec<String>,
}

/// Control API status query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusQuery {
    pub scope: String,
}

/// Control API status snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusSnapshot {
    pub status: String,
    pub diagnostics: Vec<Diagnostic>,
}

/// Control API operation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationResult {
    pub accepted: bool,
    pub diagnostics: Vec<Diagnostic>,
    pub audits: Vec<AuditEvent>,
}

/// Reload operation scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReloadScope {
    pub target: String,
}

/// Stop operation scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopScope {
    pub target: String,
}

/// Diagnostic query scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticScope {
    pub target: String,
}

/// Configuration domain port.
pub trait ConfigurationService {
    fn validate(&self, raw_config: &str, capabilities: &PlatformCapabilities) -> Vec<Diagnostic>;

    fn normalize(
        &self,
        raw_config: &str,
        capabilities: &PlatformCapabilities,
    ) -> DomainResult<ConfigSnapshot>;

    fn migrate(
        &self,
        raw_config: &str,
        from_version: SchemaVersion,
        to_version: SchemaVersion,
    ) -> DomainResult<String>;
}

/// Platform capability domain port.
pub trait PlatformCapabilityService {
    fn status(&self) -> DomainResult<PlatformCapabilityStatus>;
}

/// Subscription parsing domain port.
pub trait SubscriptionService {
    fn fetch(&self, source: &SubscriptionSource) -> DomainResult<RawSubscription>;

    fn parse(&self, raw_subscription: &RawSubscription) -> DomainResult<SubscriptionDocument>;

    fn normalize(&self, document: &SubscriptionDocument) -> DomainResult<NodeCatalog>;
}

/// Policy routing domain port.
pub trait PolicyRoutingService {
    fn compile(&self, rule_set: &RuleSet) -> DomainResult<CompiledRules>;

    fn decide(
        &self,
        route_context: &RouteContext,
        compiled_rules: &CompiledRules,
        runtime_state: &RuntimeState,
    ) -> DomainResult<RouteDecision>;

    fn explain(&self, route_decision: &RouteDecision) -> Vec<Diagnostic>;
}

/// Proxy execution engine adapter domain port.
pub trait ProxyEngineService {
    fn list_engines(&self) -> Vec<ProxyEngineDescriptor>;

    fn validate_config(&self, engine_config: &ProxyEngineConfig) -> Vec<Diagnostic>;

    fn start(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus>;

    fn reload(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus>;

    fn stop(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus>;

    fn status(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus>;

    fn events(&self, engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>>;
}

/// DNS policy domain port.
pub trait DnsPolicyService {
    fn plan(
        &self,
        dns_query: &DnsQuery,
        config: &ConfigSnapshot,
        route_context: &RouteContext,
    ) -> DomainResult<DnsDecision>;

    fn cache_lookup(&self, dns_query: &DnsQuery) -> Option<CachedDnsResult>;

    fn cache_update(
        &self,
        dns_query: &DnsQuery,
        values: Vec<String>,
        policy: CachePolicy,
    ) -> DomainResult<CacheEvent>;
}

/// MITM plugin domain port.
pub trait MitmPluginService {
    fn validate_manifest(&self, plugin_manifest: &PluginManifest) -> Vec<Diagnostic>;

    fn load(
        &self,
        plugin_package: &PluginPackage,
        granted_permissions: &GrantedPermissions,
    ) -> DomainResult<PluginInstance>;

    fn handle_http_event(
        &self,
        plugin_instance: &PluginInstance,
        http_event: &HttpEvent,
    ) -> DomainResult<PluginResult>;

    fn handle_http_mitm_event(
        &self,
        plugin_instance: &PluginInstance,
        http_event: &HttpMitmEvent,
    ) -> DomainResult<HttpMitmOutcome> {
        let result = self.handle_http_event(plugin_instance, &http_event.legacy_event())?;
        Ok(HttpMitmOutcome {
            action: HttpMitmAction::Continue,
            header_mutations: Vec::new(),
            body_mutation: None,
            script_dispatch: None,
            audits: result.audits,
            diagnostics: result.diagnostics,
        })
    }

    fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent>;
}

/// Control API domain port.
pub trait ControlApiService {
    fn status(
        &self,
        query: &StatusQuery,
        caller_context: &CallerContext,
    ) -> DomainResult<StatusSnapshot>;

    fn apply_config(
        &self,
        config_snapshot: &ConfigSnapshot,
        caller_context: &CallerContext,
    ) -> DomainResult<OperationResult>;

    fn reload(
        &self,
        scope: &ReloadScope,
        caller_context: &CallerContext,
    ) -> DomainResult<OperationResult>;

    fn stop(
        &self,
        scope: &StopScope,
        caller_context: &CallerContext,
    ) -> DomainResult<OperationResult>;

    fn diagnostics(
        &self,
        scope: &DiagnosticScope,
        caller_context: &CallerContext,
    ) -> DomainResult<Vec<Diagnostic>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_version_exposes_numeric_value() {
        let version = SchemaVersion::new(1);

        assert_eq!(version.value(), 1);
    }

    #[test]
    fn diagnostic_carries_structured_fields() {
        let diagnostic = Diagnostic::new(
            DiagnosticSeverity::Warning,
            "config.missing",
            "profile is missing",
            Some("profile.default".to_string()),
        );

        assert_eq!(diagnostic.severity, DiagnosticSeverity::Warning);
        assert_eq!(diagnostic.code, "config.missing");
        assert_eq!(diagnostic.source.as_deref(), Some("profile.default"));
    }

    #[test]
    fn domain_error_displays_code_and_message() {
        let error = DomainError::new("policy.invalid", "rule set is invalid");

        assert_eq!(error.to_string(), "policy.invalid: rule set is invalid");
    }

    #[test]
    fn proxy_engine_descriptor_preserves_adapter_identity() {
        let descriptor = ProxyEngineDescriptor {
            id: "sing-box".to_string(),
            kind: ProxyEngineKind::SingBox,
            version: Some("adapter-managed".to_string()),
            capabilities: vec![
                ProxyEngineCapability::TcpProxy,
                ProxyEngineCapability::UdpProxy,
                ProxyEngineCapability::HotReload,
            ],
        };

        assert_eq!(descriptor.kind, ProxyEngineKind::SingBox);
        assert!(descriptor
            .capabilities
            .contains(&ProxyEngineCapability::HotReload));
    }

    #[test]
    fn listener_descriptor_preserves_inbound_configuration_boundary() {
        let listener = ListenerDescriptor {
            id: "loopback-socks".to_string(),
            enabled: true,
            kind: ListenerKind::Socks,
            bind: ListenerBind {
                host: "127.0.0.1".to_string(),
                port: 1080,
            },
            network: ListenerNetwork::Tcp,
            route: ListenerRoute::RuleSet {
                rule_set_id: "default-route".to_string(),
            },
            tags: vec!["local".to_string()],
            metadata: vec![MetadataEntry {
                key: "owner".to_string(),
                value: "user".to_string(),
            }],
        };

        assert_eq!(listener.id, "loopback-socks");
        assert!(listener.enabled);
        assert_eq!(listener.kind, ListenerKind::Socks);
        assert_eq!(listener.bind.host, "127.0.0.1");
        assert_eq!(listener.bind.port, 1080);
        assert_eq!(listener.network, ListenerNetwork::Tcp);
        assert_eq!(
            listener.route,
            ListenerRoute::RuleSet {
                rule_set_id: "default-route".to_string()
            }
        );
        assert_eq!(listener.tags, vec!["local".to_string()]);
        assert_eq!(listener.metadata[0].key, "owner");
    }

    #[test]
    fn listener_route_can_embed_default_route_action() {
        let route = ListenerRoute::DefaultAction(RouteAction::Proxy {
            node_id: "node-1".to_string(),
        });

        assert_eq!(
            route,
            ListenerRoute::DefaultAction(RouteAction::Proxy {
                node_id: "node-1".to_string()
            })
        );
    }

    #[test]
    fn config_snapshot_carries_listener_descriptors() {
        let snapshot = ConfigSnapshot {
            version: SchemaVersion::new(1),
            profiles: vec!["default".to_string()],
            listeners: vec![ListenerDescriptor {
                id: "local-tcp".to_string(),
                enabled: true,
                kind: ListenerKind::LocalTcp,
                bind: ListenerBind {
                    host: "::1".to_string(),
                    port: 8080,
                },
                network: ListenerNetwork::TcpUdp,
                route: ListenerRoute::DefaultAction(RouteAction::Direct),
                tags: Vec::new(),
                metadata: Vec::new(),
            }],
            nodes: Vec::new(),
            policies: Vec::new(),
            dns: Vec::new(),
            plugins: Vec::new(),
        };

        assert_eq!(snapshot.listeners.len(), 1);
        assert_eq!(snapshot.listeners[0].id, "local-tcp");
        assert_eq!(snapshot.listeners[0].bind.host, "::1");
        assert_eq!(snapshot.listeners[0].network, ListenerNetwork::TcpUdp);
    }

    #[test]
    fn platform_feature_state_exposes_denial_reason() {
        let unavailable =
            PlatformFeatureState::unavailable("network extension entitlement is missing");

        assert!(!unavailable.is_available());
        assert_eq!(
            unavailable.denial_reason(),
            Some("network extension entitlement is missing")
        );
    }

    #[test]
    fn mitm_availability_requires_trusted_certificate() {
        let status = PlatformCapabilityStatus {
            os: OperatingSystem::Ios,
            tunnel: PlatformFeatureState::available(),
            mitm: PlatformFeatureState::available(),
            embedded_runtime: PlatformFeatureState::available(),
            remote_script_execution: PlatformFeatureState::unavailable(
                "remote scripts are disabled on iOS",
            ),
            mitm_certificate: MitmCertificateStatus::new(CertificateTrustState::InstalledUntrusted),
            diagnostics: Vec::new(),
        };

        assert!(status.mitm_certificate.is_installed());
        assert!(!status.mitm_available());
        assert_eq!(
            status.mitm_denied_reason(),
            Some("mitm certificate is installed but not trusted")
        );
    }

    struct LegacyOnlyMitmService;

    impl MitmPluginService for LegacyOnlyMitmService {
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
                loaded_source: None,
            })
        }

        fn handle_http_event(
            &self,
            plugin_instance: &PluginInstance,
            http_event: &HttpEvent,
        ) -> DomainResult<PluginResult> {
            Ok(PluginResult {
                audits: vec![AuditEvent {
                    actor: plugin_instance.manifest.id.clone(),
                    action: format!("legacy-http-event:{}", http_event.request_id),
                    decision: AuditDecision::Allowed,
                    reason: None,
                }],
                diagnostics: vec![Diagnostic::new(
                    DiagnosticSeverity::Info,
                    "plugin.legacy_handled",
                    "legacy handler processed the HTTP event",
                    None,
                )],
            })
        }

        fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent> {
            plugin_result.audits.clone()
        }
    }

    #[test]
    fn mitm_plugin_service_rich_event_defaults_to_legacy_result_without_mutation() {
        let service = LegacyOnlyMitmService;
        let package = PluginPackage {
            manifest: PluginManifest {
                id: "legacy-only".to_string(),
                version: "0.1.0".to_string(),
                permissions: vec![PluginPermission::ReadRequest],
                hooks: vec![HookPoint::Request],
            },
            source: "legacy-source".to_string(),
        };
        let instance = service
            .load(
                &package,
                &GrantedPermissions {
                    permissions: vec![PluginPermission::ReadRequest],
                },
            )
            .expect("legacy service should load plugin");

        let outcome = service
            .handle_http_mitm_event(
                &instance,
                &HttpMitmEvent {
                    request_id: "request-rich".to_string(),
                    url: "https://example.test/".to_string(),
                    method: Some("GET".to_string()),
                    phase: HttpMitmPhase::Request,
                    status_code: None,
                    headers: Vec::new(),
                    body: Vec::new(),
                },
            )
            .expect("default rich handler should delegate to legacy handler");

        assert_eq!(outcome.action, HttpMitmAction::Continue);
        assert!(outcome.header_mutations.is_empty());
        assert!(outcome.body_mutation.is_none());
        assert!(outcome.script_dispatch.is_none());
        assert_eq!(outcome.audits[0].action, "legacy-http-event:request-rich");
        assert_eq!(outcome.diagnostics[0].code, "plugin.legacy_handled");
    }
}
