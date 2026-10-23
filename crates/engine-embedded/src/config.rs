//! Runtime config envelope passed across the C ABI.
//!
//! The envelope is JSON. It carries either the one outbound the tunnel uses
//! or a `routing` section with named TCP outbounds, rules and policy groups.
//! Secrets (the Shadowsocks password, the VLESS uuid, the WireGuard private
//! and preshared keys) are read from the Keychain by the Swift side right
//! before the call and are never written back out by this crate (no `Debug`,
//! no status field).

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use config_core::routing::{PolicyGroupSpec, RoutingSpec};
use engine_outbound::{Dialer, TcpOutbound};
use outbound_vless::{
    parse_public_key, parse_short_id, parse_uuid, Flow, RealityConfig, VlessRealityConfig,
    VlessRealityOutbound,
};
use serde::Deserialize;
use tls_mimic::Fingerprint;

use crate::direct::DirectOutbound;
use crate::routing::RoutedOutbound;
use crate::shadowsocks::{Method, Ss2022Outbound};
use crate::wireguard::{decode_key, WireGuardSettings};
use crate::{RuntimeError, RuntimeErrorCode};

pub const CONFIG_SCHEMA_VERSION: u32 = 1;

const MIN_MTU: u16 = 1280;
const MAX_MTU: u16 = 9000;
const MAX_PROFILE_ID_LEN: usize = 128;
const MAX_ROUTED_OUTBOUNDS: usize = 64;
const MAX_ROUTING_RULES: usize = 4096;
const MAX_POLICY_GROUPS: usize = 64;

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

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum OutboundConfig {
    Shadowsocks {
        server: String,
        port: u16,
        method: String,
        password: String,
    },
    /// VLESS over REALITY, optionally with the `xtls-rprx-vision` flow.
    Vless {
        server: String,
        port: u16,
        uuid: String,
        #[serde(default)]
        flow: String,
        reality: RealityOutboundConfig,
    },
    Direct,
    /// One WireGuard peer. Keys are standard base64, as in a `wg-quick` file;
    /// the private and preshared keys are injected from the Keychain.
    Wireguard {
        private_key: String,
        peer_public_key: String,
        #[serde(default)]
        preshared_key: Option<String>,
        server: String,
        port: u16,
        #[serde(default)]
        persistent_keepalive_secs: Option<u16>,
    },
}

/// What the runtime runs for a config.
pub enum TunnelMode {
    /// Userspace TCP/IP stack with flows through a TCP outbound.
    Stack(Arc<dyn TcpOutbound>),
    /// Packets sealed straight to a WireGuard peer.
    WireGuard(WireGuardSettings),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealityOutboundConfig {
    pub server_name: String,
    pub public_key: String,
    #[serde(default)]
    pub short_id: String,
    #[serde(default = "default_fingerprint")]
    pub fingerprint: String,
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

fn default_fingerprint() -> String {
    "chrome".to_owned()
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
                if routing.outbounds.is_empty()
                    || routing.outbounds.len() > MAX_ROUTED_OUTBOUNDS
                    || routing.rules.len() > MAX_ROUTING_RULES
                    || routing.groups.len() > MAX_POLICY_GROUPS
                {
                    return Err(rejected("routing section size is out of range"));
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

    pub fn build_mode(&self, dialer: Arc<dyn Dialer>) -> Result<TunnelMode, RuntimeError> {
        match &self.outbound {
            Some(OutboundConfig::Wireguard {
                private_key,
                peer_public_key,
                preshared_key,
                server,
                port,
                persistent_keepalive_secs,
            }) => {
                let private_key = decode_key(private_key)
                    .ok_or_else(|| rejected("wireguard private key must be 32 bytes of base64"))?;
                let peer_public_key = decode_key(peer_public_key).ok_or_else(|| {
                    rejected("wireguard peer public key must be 32 bytes of base64")
                })?;
                let preshared_key = match preshared_key.as_deref() {
                    None | Some("") => None,
                    Some(key) => Some(decode_key(key).ok_or_else(|| {
                        rejected("wireguard preshared key must be 32 bytes of base64")
                    })?),
                };
                if server.trim().is_empty() || *port == 0 {
                    return Err(rejected("wireguard endpoint is invalid"));
                }
                Ok(TunnelMode::WireGuard(WireGuardSettings {
                    private_key,
                    peer_public_key,
                    preshared_key,
                    server: server.trim().to_owned(),
                    port: *port,
                    persistent_keepalive_secs: *persistent_keepalive_secs,
                }))
            }
            _ => self.build_outbound(dialer).map(TunnelMode::Stack),
        }
    }

    pub fn build_outbound(
        &self,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, RuntimeError> {
        match (&self.outbound, &self.routing) {
            (Some(outbound), _) => build_single_outbound(outbound, dialer),
            (None, Some(routing)) => {
                let mut nodes = BTreeMap::new();
                for (id, outbound) in &routing.outbounds {
                    nodes.insert(id.clone(), build_single_outbound(outbound, dialer.clone())?);
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
                let direct = Arc::new(DirectOutbound::new(dialer));
                Ok(Arc::new(RoutedOutbound::new(&spec, direct, nodes)?))
            }
            (None, None) => Err(rejected("exactly one of outbound and routing must be set")),
        }
    }
}

fn vless_config(
    server: &str,
    port: u16,
    uuid: &str,
    flow: &str,
    reality: &RealityOutboundConfig,
) -> Result<VlessRealityConfig, RuntimeError> {
    if server.is_empty() || port == 0 {
        return Err(rejected("vless server address is invalid"));
    }
    let uuid = parse_uuid(uuid).map_err(|_| rejected("vless uuid is invalid"))?;
    let flow = Flow::from_name(flow).ok_or_else(|| rejected("unsupported vless flow"))?;
    if reality.server_name.is_empty() {
        return Err(rejected("reality server_name is required"));
    }
    let public_key = parse_public_key(&reality.public_key)
        .map_err(|_| rejected("reality public_key is invalid"))?;
    let short_id =
        parse_short_id(&reality.short_id).map_err(|_| rejected("reality short_id is invalid"))?;
    let fingerprint = Fingerprint::from_name(&reality.fingerprint)
        .ok_or_else(|| rejected("unsupported reality fingerprint"))?;
    let mut reality_config = RealityConfig::new(reality.server_name.clone(), public_key, short_id);
    reality_config.fingerprint = fingerprint;
    Ok(VlessRealityConfig {
        server: server.to_owned(),
        port,
        uuid,
        flow,
        reality: reality_config,
    })
}

/// Builds one TCP outbound. WireGuard runs as a packet tunnel, so it cannot be
/// used here or as a routed node.
fn build_single_outbound(
    outbound: &OutboundConfig,
    dialer: Arc<dyn Dialer>,
) -> Result<Arc<dyn TcpOutbound>, RuntimeError> {
    match outbound {
        OutboundConfig::Wireguard { .. } => {
            Err(rejected("wireguard is a packet tunnel, not a TCP outbound"))
        }
        OutboundConfig::Shadowsocks {
            server,
            port,
            method,
            password,
        } => {
            let method =
                Method::parse(method).map_err(|_| rejected("unsupported shadowsocks method"))?;
            let outbound = Ss2022Outbound::new(server.clone(), *port, method, password, dialer)
                .map_err(|err| {
                    RuntimeError::new(RuntimeErrorCode::ConfigRejected, safe_io_message(&err))
                })?;
            Ok(Arc::new(outbound))
        }
        OutboundConfig::Vless {
            server,
            port,
            uuid,
            flow,
            reality,
        } => {
            let config = vless_config(server, *port, uuid, flow, reality)?;
            Ok(Arc::new(VlessRealityOutbound::new(config, dialer)))
        }
        OutboundConfig::Direct => Ok(Arc::new(DirectOutbound::new(dialer))),
    }
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

/// Outbound constructors only use fixed messages; anything else is replaced.
fn safe_io_message(err: &std::io::Error) -> &'static str {
    match err.kind() {
        std::io::ErrorKind::InvalidInput => "shadowsocks outbound settings are invalid",
        _ => "outbound could not be created",
    }
}
