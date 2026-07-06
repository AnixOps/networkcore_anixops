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

/// Normalized configuration snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigSnapshot {
    pub version: SchemaVersion,
    pub profiles: Vec<String>,
    pub policies: Vec<RuleSet>,
    pub dns: Vec<DnsUpstream>,
    pub plugins: Vec<PluginManifest>,
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
}

/// HTTP event visible to plugin logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpEvent {
    pub request_id: String,
    pub headers: Metadata,
    pub body: Vec<u8>,
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
}
