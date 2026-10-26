//! Embedded engine for the iOS Network Extension.
//!
//! Layers, from the C ABI inward:
//!
//! - [`ffi`]: the `networkcore_ios_*` C ABI that the Swift packet tunnel calls.
//! - [`EmbeddedRuntime`]: validated config, outbound selection and lifecycle.
//! - [`tunnel`]: userspace TCP/IP (smoltcp) that turns packets into flows,
//!   with [`sniff`] reading the host name of each TCP flow.
//! - [`connections`]: the dispatcher every flow goes through, which routes
//!   it and keeps the connection list and traffic counters that [`control`]
//!   requests read.
//! - Outbounds implementing [`engine_outbound::TcpOutbound`], looked up by
//!   config `type` in the registry from [`protocols`]: Shadowsocks-2022
//!   (`outbound-shadowsocks`), VLESS + REALITY (`outbound-vless`) and direct
//!   ([`direct`]). Each protocol is a cargo feature, so it can be added or
//!   left out without touching the tunnel. [`routing`] wraps several of them
//!   behind the shared `config-core` rules and policy groups.
//! - `local_proxy` (feature `local-proxy`): the desktop mode, the same
//!   outbounds behind a SOCKS5/HTTP listener from `inbound-mixed`, and
//!   `delay`, URL delay tests of a node's outbound.
//! - `wireguard` (feature `wireguard`): an IP-level tunnel that bypasses the
//!   TCP/IP stack and seals packets straight to one peer.
//! - `mitm` (feature `mitm`): HTTPS decryption for the policy's MITM host
//!   list, offered every new TCP flow through [`tunnel::FlowInterceptor`].
//!
//! The runtime never starts a process, never touches Apple SDK objects and
//! never puts credentials or traffic into errors, status or logs.

pub mod config;
pub mod connections;
pub mod control;
#[cfg(feature = "local-proxy")]
pub mod delay;
pub mod direct;
pub mod dns;
pub mod dns_policy;
#[cfg(feature = "local-proxy")]
pub mod fetch;
pub mod ffi;
#[cfg(any(feature = "local-proxy", feature = "dns-tls"))]
pub mod http1;
#[cfg(feature = "local-proxy")]
pub mod local_proxy;
#[cfg(feature = "mitm")]
pub mod mitm;
pub mod nodes;
pub mod profile;
pub mod protocols;
pub mod routing;
pub mod rule_sets;
pub mod sniff;
pub mod tunnel;
#[cfg(feature = "wireguard")]
pub mod wireguard;

#[cfg(feature = "shadowsocks")]
pub use outbound_shadowsocks as shadowsocks;

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use engine_outbound::registry::OutboundRegistry;
use engine_outbound::{Dialer, TcpDialer, TcpOutbound};
use serde::Serialize;

use crate::config::{RuntimeConfig, TunnelMode};
use crate::connections::Dispatcher;
use crate::dns_policy::DnsPolicy;
use crate::routing::RoutedOutbound;
use crate::tunnel::{FlowInterceptor, PacketSink, Tunnel, TunnelSettings, TunnelStatsSnapshot};
#[cfg(feature = "wireguard")]
use crate::wireguard::WireGuardSettings;

/// Stable error categories. They map one-to-one onto the FFI error codes and
/// the `platform.ios.embedded_runtime.*` diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeErrorCode {
    InvalidArgument,
    SchemaMismatch,
    ConfigRejected,
    ResourceExhausted,
    PanicCaught,
    InternalError,
}

impl RuntimeErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeErrorCode::InvalidArgument => "invalid_argument",
            RuntimeErrorCode::SchemaMismatch => "schema_mismatch",
            RuntimeErrorCode::ConfigRejected => "config_rejected",
            RuntimeErrorCode::ResourceExhausted => "resource_exhausted",
            RuntimeErrorCode::PanicCaught => "panic_caught",
            RuntimeErrorCode::InternalError => "internal_error",
        }
    }
}

/// An error with a fixed, credential-free message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeError {
    pub code: RuntimeErrorCode,
    pub message: &'static str,
}

impl RuntimeError {
    pub fn new(code: RuntimeErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for RuntimeError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    Initialized,
    Running,
    Stopped,
}

/// Sanitized status: identifiers, state and counters only.
#[derive(Clone, Debug, Serialize)]
pub struct RuntimeStatus {
    pub abi_version: u32,
    pub schema_version: u32,
    pub profile_id: String,
    pub outbound: &'static str,
    pub state: RuntimeState,
    pub last_error: Option<&'static str>,
    pub stats: TunnelStatsSnapshot,
}

/// What carries the traffic: a TCP outbound behind the userspace stack, or a
/// WireGuard peer that takes IP packets directly.
enum Engine {
    Stack(Arc<Dispatcher>),
    #[cfg(feature = "wireguard")]
    WireGuard(WireGuardSettings),
}

pub struct EmbeddedRuntime {
    config: RuntimeConfig,
    engine: Engine,
    /// The rule-based outbound of a `routing` config, kept to run its url-test
    /// and fallback health checks while the tunnel runs.
    routed: Option<Arc<RoutedOutbound>>,
    interceptor: Option<Arc<dyn FlowInterceptor>>,
    tunnel: Option<Tunnel>,
    state: RuntimeState,
    last_error: Option<RuntimeErrorCode>,
    last_stats: TunnelStatsSnapshot,
}

impl EmbeddedRuntime {
    pub fn from_json(bytes: &[u8]) -> Result<Self, RuntimeError> {
        Self::with_dialer(bytes, Arc::new(TcpDialer))
    }

    pub fn with_dialer(bytes: &[u8], dialer: Arc<dyn Dialer>) -> Result<Self, RuntimeError> {
        Self::with_registry(bytes, &protocols::default_registry(), dialer)
    }

    /// Builds outbounds from `registry` instead of the feature-selected one,
    /// e.g. to add a protocol crate that lives outside this repository.
    pub fn with_registry(
        bytes: &[u8],
        registry: &OutboundRegistry,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Self, RuntimeError> {
        let config = RuntimeConfig::from_json(bytes)?;
        let interceptor = build_interceptor(&config)?;
        let routed = config.build_routed(registry, dialer.clone())?;
        let engine = match &routed {
            Some(routed) => Engine::Stack(Arc::new(config.build_dispatcher(
                Some(routed.clone()),
                registry,
                dialer,
            )?)),
            None => match config.build_mode(registry, dialer.clone())? {
                TunnelMode::Stack(outbound) => {
                    let dispatcher = Dispatcher::single(outbound)
                        .with_direct(Arc::new(direct::DirectOutbound::new(dialer)));
                    dispatcher.set_mode(config.mode);
                    Engine::Stack(Arc::new(dispatcher))
                }
                #[cfg(feature = "wireguard")]
                TunnelMode::WireGuard(settings) => Engine::WireGuard(settings),
            },
        };
        let mut runtime = Self::with_engine(config, engine);
        runtime.interceptor = interceptor;
        runtime.routed = routed;
        Ok(runtime)
    }

    /// Uses a caller-provided outbound, for tests and future protocol crates.
    pub fn with_outbound(config: RuntimeConfig, outbound: Arc<dyn TcpOutbound>) -> Self {
        Self::with_engine(
            config,
            Engine::Stack(Arc::new(Dispatcher::single(outbound))),
        )
    }

    fn with_engine(config: RuntimeConfig, engine: Engine) -> Self {
        Self {
            config,
            engine,
            routed: None,
            interceptor: None,
            tunnel: None,
            state: RuntimeState::Initialized,
            last_error: None,
            last_stats: TunnelStatsSnapshot::default(),
        }
    }

    pub fn start(&mut self, sink: PacketSink) -> Result<(), RuntimeError> {
        if self.tunnel.is_some() {
            return Err(self.fail(RuntimeError::new(
                RuntimeErrorCode::InvalidArgument,
                "tunnel is already running",
            )));
        }
        let dns = match DnsPolicy::from_config(&self.config.dns) {
            Ok(policy) => policy,
            Err(message) => {
                return Err(self.fail(RuntimeError::new(RuntimeErrorCode::ConfigRejected, message)))
            }
        };
        let limits = &self.config.limits;
        let settings = TunnelSettings {
            mtu: self.config.mtu,
            tcp_window_bytes: limits.tcp_window_bytes,
            max_tcp_connections: limits.max_tcp_connections,
            max_dns_in_flight: limits.max_dns_in_flight,
            idle_timeout: Duration::from_secs(limits.idle_timeout_secs),
            connect_timeout: Duration::from_secs(limits.connect_timeout_secs),
            dns: Arc::new(dns),
        };
        let started = match &self.engine {
            Engine::Stack(dispatcher) => Tunnel::start_with_dispatcher(
                settings,
                dispatcher.clone(),
                self.interceptor.clone(),
                self.health_checks(),
                sink,
            ),
            #[cfg(feature = "wireguard")]
            Engine::WireGuard(wireguard) => Tunnel::start_wireguard(wireguard.clone(), sink),
        };
        match started {
            Ok(tunnel) => {
                self.tunnel = Some(tunnel);
                self.state = RuntimeState::Running;
                Ok(())
            }
            Err(_) => Err(self.fail(RuntimeError::new(
                RuntimeErrorCode::ResourceExhausted,
                "tunnel could not start",
            ))),
        }
    }

    /// The url-test and fallback health checks and the remote rule set
    /// updates of a routed config. They go through the outbounds like the
    /// delay test, which the `local-proxy` feature builds.
    #[cfg(feature = "local-proxy")]
    fn health_checks(&self) -> Option<engine_outbound::BoxFuture<'static, ()>> {
        let routed = self.routed.clone()?;
        Some(Box::pin(async move {
            tokio::join!(
                routed.clone().run_health_checks(),
                routed.run_rule_set_updates()
            );
        }))
    }

    #[cfg(not(feature = "local-proxy"))]
    fn health_checks(&self) -> Option<engine_outbound::BoxFuture<'static, ()>> {
        None
    }

    /// Returns `false` when the packet was dropped.
    pub fn input_packet(&self, packet: &[u8]) -> bool {
        match &self.tunnel {
            Some(tunnel) => tunnel.input_packet(packet),
            None => false,
        }
    }

    /// Idempotent.
    pub fn stop(&mut self) {
        if let Some(mut tunnel) = self.tunnel.take() {
            tunnel.stop();
            self.last_stats = tunnel.stats();
            self.state = RuntimeState::Stopped;
        }
    }

    pub fn status(&self) -> RuntimeStatus {
        RuntimeStatus {
            abi_version: ffi::NETWORKCORE_IOS_ABI_VERSION,
            schema_version: config::CONFIG_SCHEMA_VERSION,
            profile_id: self.config.profile_id.clone(),
            outbound: match &self.engine {
                Engine::Stack(dispatcher) => dispatcher.protocol(),
                #[cfg(feature = "wireguard")]
                Engine::WireGuard(_) => wireguard::PROTOCOL,
            },
            state: self.state,
            last_error: self.last_error.map(RuntimeErrorCode::as_str),
            stats: match &self.tunnel {
                Some(tunnel) => tunnel.stats(),
                None => self.last_stats.clone(),
            },
        }
    }

    /// Answers one [`control`] request, such as the connection list. A
    /// WireGuard tunnel has no flows to control and rejects every request.
    pub fn control_json(&self, request: &[u8]) -> Result<Vec<u8>, RuntimeError> {
        match &self.engine {
            Engine::Stack(dispatcher) => control::handle(dispatcher, request),
            #[cfg(feature = "wireguard")]
            Engine::WireGuard(_) => {
                let _ = request;
                Err(control::unavailable())
            }
        }
    }

    fn fail(&mut self, err: RuntimeError) -> RuntimeError {
        self.last_error = Some(err.code);
        err
    }
}

/// The HTTPS decryption interceptor for the config's `mitm` section.
fn build_interceptor(
    config: &RuntimeConfig,
) -> Result<Option<Arc<dyn FlowInterceptor>>, RuntimeError> {
    let Some(mitm) = config.mitm.as_ref() else {
        return Ok(None);
    };
    #[cfg(feature = "mitm")]
    {
        let engine = mitm::MitmEngine::new(mitm)
            .map_err(|message| RuntimeError::new(RuntimeErrorCode::ConfigRejected, message))?;
        Ok(Some(Arc::new(engine)))
    }
    #[cfg(not(feature = "mitm"))]
    {
        let _ = mitm;
        Err(RuntimeError::new(
            RuntimeErrorCode::ConfigRejected,
            "mitm is not supported by this build",
        ))
    }
}

impl Drop for EmbeddedRuntime {
    fn drop(&mut self) {
        self.stop();
    }
}
