//! Runtime config envelope passed across the C ABI.
//!
//! The envelope is JSON. It carries either the one outbound the tunnel uses
//! or a `routing` section with named TCP outbounds, rules and policy groups.
//! Each outbound names its protocol with `type`; which types exist depends on
//! the cargo features this crate was built with (see [`crate::protocols`]).
//! Secrets (the Shadowsocks password, the VLESS uuid, the WireGuard private
//! and preshared keys) are read from the Keychain by the Swift side right
//! before the call and are never written back out by this crate (no `Debug`,
//! no status field).

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use config_core::routing::{PolicyGroupSpec, RoutingSpec};
use config_core::rule_set::RuleSet;
use engine_outbound::registry::{OutboundRegistry, Settings};
use engine_outbound::{Dialer, TcpOutbound};
use serde::Deserialize;

use crate::direct::DirectOutbound;
use crate::routing::RoutedOutbound;
#[cfg(feature = "wireguard")]
use crate::wireguard::{self, WireGuardSettings};
use crate::{RuntimeError, RuntimeErrorCode};

pub const CONFIG_SCHEMA_VERSION: u32 = 1;

const MIN_MTU: u16 = 1280;
const MAX_MTU: u16 = 9000;
const MAX_PROFILE_ID_LEN: usize = 128;
const MAX_ROUTED_OUTBOUNDS: usize = 64;
const MAX_ROUTING_RULES: usize = 4096;
const MAX_POLICY_GROUPS: usize = 64;
const MAX_RULE_SETS: usize = 16;
/// Room for the mainland China domain and network lists with headroom.
const MAX_RULE_SET_ENTRIES: usize = 500_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub schema_version: u32,
    pub profile_id: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Single outbound for every connection. Exactly one of `outbound` and
    /// `routing` is set.
    #[serde(default)]
    pub outbound: Option<OutboundConfig>,
    #[serde(default)]
    pub routing: Option<RoutingConfig>,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub limits: Limits,
}

/// One outbound: a `type` name looked up in the [`OutboundRegistry`] and the
/// protocol's own settings, which only its factory parses.
///
/// `wireguard` is not in the registry: it replaces the TCP/IP stack instead of
/// carrying its flows, so the runtime handles it itself.
#[derive(Deserialize)]
pub struct OutboundConfig {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(flatten)]
    pub settings: Settings,
}

/// What the runtime runs for a config.
pub enum TunnelMode {
    /// Userspace TCP/IP stack with flows through a TCP outbound.
    Stack(Arc<dyn TcpOutbound>),
    /// Packets sealed straight to a WireGuard peer.
    #[cfg(feature = "wireguard")]
    WireGuard(WireGuardSettings),
}

/// Rule-based routing: TCP outbounds keyed by node id, `config-core` rule lines
/// that must end with FINAL, and policy groups over those node ids.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    pub outbounds: BTreeMap<String, OutboundConfig>,
    pub rules: Vec<String>,
    #[serde(default)]
    pub groups: Vec<PolicyGroupConfig>,
    /// Lists named by `RULE-SET,<name>,<target>` rules.
    #[serde(default)]
    pub rule_sets: BTreeMap<String, RuleSetConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSetConfig {
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    /// Networks or bare addresses.
    #[serde(default)]
    pub ip_cidr: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyGroupConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub members: Vec<String>,
    #[serde(default)]
    pub default: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub interval_secs: Option<u32>,
    #[serde(default)]
    pub tolerance_ms: Option<u16>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// DNS server reached over TCP through the outbound.
    #[serde(default = "default_dns_upstream")]
    pub upstream: SocketAddr,
    #[serde(default = "default_dns_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            upstream: default_dns_upstream(),
            timeout_ms: default_dns_timeout_ms(),
        }
    }
}

/// Resource limits sized for the ~50 MB Network Extension budget.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_max_tcp_connections")]
    pub max_tcp_connections: usize,
    #[serde(default = "default_max_dns_in_flight")]
    pub max_dns_in_flight: usize,
    /// Per-socket userspace TCP window in each direction, in bytes.
    #[serde(default = "default_tcp_window_bytes")]
    pub tcp_window_bytes: u32,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_tcp_connections: default_max_tcp_connections(),
            max_dns_in_flight: default_max_dns_in_flight(),
            tcp_window_bytes: default_tcp_window_bytes(),
            idle_timeout_secs: default_idle_timeout_secs(),
            connect_timeout_secs: default_connect_timeout_secs(),
        }
    }
}

fn default_mtu() -> u16 {
    1500
}

fn default_dns_upstream() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(1, 1, 1, 1), 53))
}

fn default_dns_timeout_ms() -> u64 {
    5_000
}

fn default_max_tcp_connections() -> usize {
    128
}

fn default_max_dns_in_flight() -> usize {
    32
}

fn default_tcp_window_bytes() -> u32 {
    64 * 1024
}

fn default_idle_timeout_secs() -> u64 {
    300
}

fn default_connect_timeout_secs() -> u64 {
    10
}

impl RuntimeConfig {
    pub fn from_json(bytes: &[u8]) -> Result<Self, RuntimeError> {
        // Check the schema first so a newer envelope reports a schema mismatch,
        // not an unknown-field error.
        #[derive(Deserialize)]
        struct Probe {
            schema_version: u32,
        }
        let probe: Probe = serde_json::from_slice(bytes).map_err(|_| {
            RuntimeError::new(
                RuntimeErrorCode::ConfigRejected,
                "runtime config is not a valid JSON envelope",
            )
        })?;
        if probe.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(RuntimeError::new(
                RuntimeErrorCode::SchemaMismatch,
                "runtime config schema version is not supported",
            ));
        }
        let config: RuntimeConfig = serde_json::from_slice(bytes).map_err(|_| {
            RuntimeError::new(
                RuntimeErrorCode::ConfigRejected,
                "runtime config has missing or unknown fields",
            )
        })?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), RuntimeError> {
        let profile_id_ok = is_identifier(&self.profile_id);
        if !profile_id_ok {
            return Err(rejected(
                "profile_id must be 1-128 characters of [A-Za-z0-9._-]",
            ));
        }
        match (&self.outbound, &self.routing) {
            (Some(_), None) => {}
            (None, Some(routing)) => {
                let rule_set_entries: usize = routing
                    .rule_sets
                    .values()
                    .map(|set| set.domain_suffix.len() + set.ip_cidr.len())
                    .sum();
                if routing.outbounds.is_empty()
                    || routing.outbounds.len() > MAX_ROUTED_OUTBOUNDS
                    || routing.rules.len() > MAX_ROUTING_RULES
                    || routing.groups.len() > MAX_POLICY_GROUPS
                    || routing.rule_sets.len() > MAX_RULE_SETS
                    || rule_set_entries > MAX_RULE_SET_ENTRIES
                {
                    return Err(rejected("routing section size is out of range"));
                }
                if !routing.rule_sets.keys().all(|name| is_identifier(name)) {
                    return Err(rejected(
                        "rule set names must be 1-128 characters of [A-Za-z0-9._-]",
                    ));
                }
                if !routing.outbounds.keys().all(|id| is_identifier(id)) {
                    return Err(rejected(
                        "routing outbound ids must be 1-128 characters of [A-Za-z0-9._-]",
                    ));
                }
            }
            _ => return Err(rejected("exactly one of outbound and routing must be set")),
        }
        if !(MIN_MTU..=MAX_MTU).contains(&self.mtu) {
            return Err(rejected("mtu is out of range"));
        }
        let limits = &self.limits;
        if limits.max_tcp_connections == 0
            || limits.max_dns_in_flight == 0
            || limits.tcp_window_bytes < 4 * 1024
            || limits.tcp_window_bytes > 1024 * 1024
            || limits.idle_timeout_secs == 0
            || limits.connect_timeout_secs == 0
            || self.dns.timeout_ms == 0
        {
            return Err(rejected("resource limits are out of range"));
        }
        Ok(())
    }

    pub fn build_mode(
        &self,
        registry: &OutboundRegistry,
        dialer: Arc<dyn Dialer>,
    ) -> Result<TunnelMode, RuntimeError> {
        #[cfg(feature = "wireguard")]
        if let Some(outbound) = self
            .outbound
            .as_ref()
            .filter(|outbound| outbound.kind == wireguard::TYPE_NAME)
        {
            return wireguard::settings_from(&outbound.settings)
                .map(TunnelMode::WireGuard)
                .map_err(rejected);
        }
        self.build_outbound(registry, dialer).map(TunnelMode::Stack)
    }

    pub fn build_outbound(
        &self,
        registry: &OutboundRegistry,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, RuntimeError> {
        match (&self.outbound, &self.routing) {
            (Some(outbound), _) => build_single_outbound(registry, outbound, dialer),
            (None, Some(routing)) => {
                let mut nodes = BTreeMap::new();
                for (id, outbound) in &routing.outbounds {
                    nodes.insert(
                        id.clone(),
                        build_single_outbound(registry, outbound, dialer.clone())?,
                    );
                }
                let spec = RoutingSpec {
                    rules: routing.rules.clone(),
                    groups: routing
                        .groups
                        .iter()
                        .map(|group| PolicyGroupSpec {
                            id: group.id.clone(),
                            kind: group.kind.clone(),
                            members: group.members.clone(),
                            default: group.default.clone(),
                            url: group.url.clone(),
                            interval_secs: group.interval_secs,
                            tolerance_ms: group.tolerance_ms,
                        })
                        .collect(),
                };
                let rule_sets = routing
                    .rule_sets
                    .iter()
                    .map(|(name, set)| {
                        RuleSet::new(
                            set.domain_suffix.iter().map(String::as_str),
                            set.ip_cidr.iter().map(String::as_str),
                        )
                        .map(|set| (name.clone(), set))
                        .map_err(|_| rejected("rule set entries are invalid"))
                    })
                    .collect::<Result<BTreeMap<_, _>, _>>()?;
                let direct = Arc::new(DirectOutbound::new(dialer));
                Ok(Arc::new(RoutedOutbound::with_rule_sets(
                    &spec, direct, nodes, rule_sets,
                )?))
            }
            (None, None) => Err(rejected("exactly one of outbound and routing must be set")),
        }
    }
}

/// Builds one TCP outbound. WireGuard runs as a packet tunnel, so it cannot be
/// used here or as a routed node.
fn build_single_outbound(
    registry: &OutboundRegistry,
    outbound: &OutboundConfig,
    dialer: Arc<dyn Dialer>,
) -> Result<Arc<dyn TcpOutbound>, RuntimeError> {
    #[cfg(feature = "wireguard")]
    if outbound.kind == wireguard::TYPE_NAME {
        return Err(rejected("wireguard is a packet tunnel, not a TCP outbound"));
    }
    registry
        .build(&outbound.kind, &outbound.settings, dialer)
        .map_err(rejected)
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PROFILE_ID_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn rejected(message: &'static str) -> RuntimeError {
    RuntimeError::new(RuntimeErrorCode::ConfigRejected, message)
}
