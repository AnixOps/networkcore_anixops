//! Runtime config envelope passed across the C ABI.
//!
//! The envelope is JSON. It carries the one outbound the tunnel uses; the
//! password is read from the Keychain by the Swift side right before the call
//! and is never written back out by this crate (no `Debug`, no status field).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use engine_outbound::{Dialer, TcpOutbound};
use serde::Deserialize;

use crate::direct::DirectOutbound;
use crate::shadowsocks::{Method, Ss2022Outbound};
use crate::{RuntimeError, RuntimeErrorCode};

pub const CONFIG_SCHEMA_VERSION: u32 = 1;

const MIN_MTU: u16 = 1280;
const MAX_MTU: u16 = 9000;
const MAX_PROFILE_ID_LEN: usize = 128;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfig {
    pub schema_version: u32,
    pub profile_id: String,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    pub outbound: OutboundConfig,
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
    Direct,
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
        let profile_id_ok = !self.profile_id.is_empty()
            && self.profile_id.len() <= MAX_PROFILE_ID_LEN
            && self
                .profile_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        if !profile_id_ok {
            return Err(rejected(
                "profile_id must be 1-128 characters of [A-Za-z0-9._-]",
            ));
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

    pub fn build_outbound(
        &self,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, RuntimeError> {
        match &self.outbound {
            OutboundConfig::Shadowsocks {
                server,
                port,
                method,
                password,
            } => {
                let method = Method::parse(method)
                    .map_err(|_| rejected("unsupported shadowsocks method"))?;
                let outbound = Ss2022Outbound::new(server.clone(), *port, method, password, dialer)
                    .map_err(|err| {
                        RuntimeError::new(RuntimeErrorCode::ConfigRejected, safe_io_message(&err))
                    })?;
                Ok(Arc::new(outbound))
            }
            OutboundConfig::Direct => Ok(Arc::new(DirectOutbound::new(dialer))),
        }
    }
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
