//! Registry entry for `"type": "forward"` inbound config entries.

use std::sync::Arc;

use engine_inbound::registry::{parse_settings, BuildError, InboundFactory, Settings};
use engine_inbound::StreamInbound;
use engine_outbound::TargetAddr;
use serde::Deserialize;

use crate::{ForwardInbound, Network};

pub const TYPE_NAME: &str = "forward";

/// `{"server": "203.0.113.7", "server_port": 443, "network": "tcp,udp"}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardInboundSettings {
    /// Target host: an IP address or a name, resolved per connection.
    server: String,
    server_port: u16,
    /// `tcp`, `udp` or `tcp,udp` (when absent).
    #[serde(default)]
    network: Option<String>,
}

pub struct ForwardInboundFactory;

impl InboundFactory for ForwardInboundFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(&self, settings: &Settings) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let settings: ForwardInboundSettings =
            parse_settings(settings, "forward inbound settings are missing or invalid")?;
        let server = settings.server.trim();
        if server.is_empty() {
            return Err("forward server is missing");
        }
        if settings.server_port == 0 {
            return Err("forward server_port must not be 0");
        }
        let network = match settings.network.as_deref() {
            None => Network::BOTH,
            Some(value) => {
                Network::parse(value).ok_or("forward network must be tcp, udp or tcp,udp")?
            }
        };
        Ok(Arc::new(ForwardInbound::new(
            TargetAddr::from_host(server, settings.server_port),
            network,
        )))
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
    }
}
