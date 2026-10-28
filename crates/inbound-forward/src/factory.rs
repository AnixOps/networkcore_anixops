//! Registry entry for `"type": "forward"` inbound config entries.

use std::sync::Arc;
use std::time::Duration;

use engine_inbound::registry::{parse_settings, BuildError, InboundFactory, Settings};
use engine_inbound::StreamInbound;
use engine_outbound::TargetAddr;
use serde::Deserialize;

use crate::balance::{Health, Strategy, Target};
use crate::proxy::ProxyProtocol;
use crate::{ForwardInbound, Limits, Network};

pub const TYPE_NAME: &str = "forward";

/// One target: `{"server": "203.0.113.7", "server_port": 443}`, or several
/// in `targets` with a policy:
///
/// ```json
/// {"targets": [{"server": "a.example", "server_port": 443, "weight": 2},
///              {"server": "203.0.113.8", "server_port": 443, "priority": 1}],
///  "balance": "least_conn",
///  "health": {"interval_ms": 5000, "timeout_ms": 2000, "disabled": false},
///  "circuit_breaker": {"failure_threshold": 3, "open_ms": 30000},
///  "bandwidth_bps": 100000000, "max_conns": 2000, "proxy_protocol": "v2",
///  "network": "tcp,udp"}
/// ```
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardInboundSettings {
    /// Target host: an IP address or a name, resolved per connection.
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    server_port: Option<u16>,
    #[serde(default)]
    targets: Vec<TargetSettings>,
    /// `tcp`, `udp` or `tcp,udp` (when absent).
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    balance: Option<String>,
    #[serde(default)]
    health: HealthSettings,
    #[serde(default)]
    circuit_breaker: BreakerSettings,
    #[serde(default)]
    bandwidth_bps: u64,
    #[serde(default)]
    max_conns: u32,
    #[serde(default)]
    proxy_protocol: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetSettings {
    server: String,
    server_port: u16,
    #[serde(default)]
    weight: u32,
    #[serde(default)]
    priority: u32,
}

/// forward.v1 `HealthCheck`: 0 takes the default.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct HealthSettings {
    #[serde(default)]
    interval_ms: u32,
    #[serde(default)]
    timeout_ms: u32,
    #[serde(default)]
    disabled: bool,
}

/// forward.v1 `CircuitBreaker`: 0 takes the default.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct BreakerSettings {
    #[serde(default)]
    failure_threshold: u32,
    #[serde(default)]
    open_ms: u32,
}

pub struct ForwardInboundFactory;

fn target(server: &str, port: u16) -> Result<TargetAddr, BuildError> {
    let server = server.trim();
    if server.is_empty() {
        return Err("forward server is missing");
    }
    if port == 0 {
        return Err("forward server_port must not be 0");
    }
    Ok(TargetAddr::from_host(server, port))
}

fn or_default(ms: u32, default: Duration) -> Duration {
    match ms {
        0 => default,
        ms => Duration::from_millis(u64::from(ms)),
    }
}

impl InboundFactory for ForwardInboundFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(&self, settings: &Settings) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let settings: ForwardInboundSettings =
            parse_settings(settings, "forward inbound settings are missing or invalid")?;
        let targets = match (
            &settings.server,
            settings.server_port,
            settings.targets.len(),
        ) {
            (Some(server), Some(port), 0) => vec![Target {
                addr: target(server, port)?,
                weight: 1,
                priority: 0,
            }],
            (None, None, 1..) => settings
                .targets
                .iter()
                .map(|t| {
                    Ok(Target {
                        addr: target(&t.server, t.server_port)?,
                        weight: t.weight.max(1),
                        priority: t.priority,
                    })
                })
                .collect::<Result<_, BuildError>>()?,
            (None, None, 0) | (Some(_), None, 0) | (None, Some(_), 0) => {
                return Err("forward server is missing")
            }
            _ => return Err("forward takes server and server_port, or targets"),
        };
        let network = match settings.network.as_deref() {
            None => Network::BOTH,
            Some(value) => {
                Network::parse(value).ok_or("forward network must be tcp, udp or tcp,udp")?
            }
        };
        let strategy = match settings.balance.as_deref() {
            None => Strategy::default(),
            Some(value) => Strategy::parse(value).ok_or(
                "forward balance must be round_robin, random, ip_hash, least_conn or failover",
            )?,
        };
        let proxy_protocol = match settings.proxy_protocol.as_deref() {
            None => ProxyProtocol::Off,
            Some(value) => {
                ProxyProtocol::parse(value).ok_or("forward proxy_protocol must be off, v1 or v2")?
            }
        };
        let defaults = Health::default();
        let health = Health {
            active: !settings.health.disabled,
            interval: or_default(settings.health.interval_ms, defaults.interval),
            timeout: or_default(settings.health.timeout_ms, defaults.timeout),
            failure_threshold: match settings.circuit_breaker.failure_threshold {
                0 => defaults.failure_threshold,
                n => n,
            },
            open: or_default(settings.circuit_breaker.open_ms, defaults.open),
        };
        Ok(Arc::new(
            ForwardInbound::with_targets(targets, strategy, health, network)
                .with_limits(Limits {
                    bandwidth_bps: settings.bandwidth_bps,
                    max_conns: settings.max_conns,
                })
                .with_proxy_protocol(proxy_protocol),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(json: &str) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let settings: Settings = serde_json::from_str(json).unwrap();
        ForwardInboundFactory.build(&settings)
    }

    #[test]
    fn builds_forwards() {
        let inbound = build(r#"{"server":"203.0.113.7","server_port":443}"#).unwrap();
        assert_eq!(inbound.protocol(), "forward");
        assert!(inbound.datagram().is_some());
        let tcp = build(r#"{"server":"example.com","server_port":80,"network":"tcp"}"#).unwrap();
        assert!(tcp.datagram().is_none());
        build(r#"{"server":"2001:db8::1","server_port":53,"network":"udp"}"#).unwrap();
    }

    #[test]
    fn rejects_invalid_settings() {
        assert!(build(r#"{"server":"","server_port":443}"#).is_err());
        assert!(build(r#"{"server":"203.0.113.7","server_port":0}"#).is_err());
        assert!(build(r#"{"server":"203.0.113.7"}"#).is_err());
        assert!(build(r#"{"server":"203.0.113.7","server_port":443,"network":"sctp"}"#).is_err());
        assert!(build(r#"{"server":"203.0.113.7","server_port":443,"users":[]}"#).is_err());
        assert!(build(r#"{"targets":[]}"#).is_err());
        assert!(build(
            r#"{"server":"a","server_port":1,"targets":[{"server":"b","server_port":2}]}"#
        )
        .is_err());
        assert!(build(r#"{"targets":[{"server":"b","server_port":0}]}"#).is_err());
        assert!(
            build(r#"{"targets":[{"server":"b","server_port":2}],"balance":"sticky"}"#).is_err()
        );
        assert!(
            build(r#"{"targets":[{"server":"b","server_port":2}],"proxy_protocol":"v3"}"#).is_err()
        );
    }

    #[test]
    fn builds_policies() {
        let inbound = build(
            r#"{"targets":[{"server":"203.0.113.7","server_port":443,"weight":2},
                           {"server":"b.example","server_port":443,"priority":1}],
                "balance":"BALANCE_STRATEGY_FAILOVER",
                "health":{"interval_ms":1000},"circuit_breaker":{"open_ms":5000},
                "bandwidth_bps":8000000,"max_conns":10,"proxy_protocol":"PROXY_PROTOCOL_V2"}"#,
        )
        .unwrap();
        assert!(inbound.serves_connections());
        assert!(inbound.datagram().is_some());
    }
}
