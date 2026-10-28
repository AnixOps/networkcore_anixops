//! The `anixcore` configuration file.
//!
//! ```json
//! {
//!   "management": {"listen": "127.0.0.1:10085", "token": "..."},
//!   "allow_private_targets": false,
//!   "inbounds": [
//!     {"tag": "ss", "type": "shadowsocks", "listen": "::", "listen_port": 8388,
//!      "method": "2022-blake3-aes-128-gcm", "password": "...", "users": []}
//!   ],
//!   "egress": {"routes": [], "relays": []},
//!   "network": {"generation": 1, "egresses": [], "ingresses": [], "paths": []}
//! }
//! ```
//!
//! Every inbound key other than `tag`, `type`, `listen`, `listen_port`,
//! `outbound` and `ingress` is passed to the protocol factory as its
//! settings. `egress` is optional and has the format of `PUT /v1/egress`
//! ([`crate::egress::EgressConfig`]); `network` is optional and has the
//! format of `PUT /v1/network` ([`crate::network::NetworkPlan`]).
//!
//! `outbound` (on an inbound) and `default_outbound` (for all inbounds)
//! name the base outbound traffic leaves through: `"direct"` (the default),
//! `"egress:<id>"` (an egress of the network plan) or one the binary
//! registered ([`crate::Node::with_outbound`]); plain `anixcore` registers
//! none. `ingress` (instead of `outbound`) puts the inbound in an ingress
//! of the network plan: it takes that ingress's active path.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use engine_inbound::registry::Settings;
use engine_inbound::FallbackSettings;
use engine_outbound::TargetAddr;
use serde::Deserialize;

use crate::egress::EgressConfig;
use crate::network::NetworkPlan;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    #[serde(default)]
    pub management: Option<ManagementSettings>,
    #[serde(default)]
    pub allow_private_targets: bool,
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    #[serde(default)]
    pub egress: Option<EgressConfig>,
    #[serde(default)]
    pub default_outbound: Option<String>,
    #[serde(default)]
    pub network: Option<NetworkPlan>,
}

/// Has no `Debug`: `token` is a credential.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementSettings {
    pub listen: SocketAddr,
    /// Bearer token every request must carry.
    pub token: String,
}

/// One inbound. Has no `Debug`: settings carry passwords.
#[derive(Clone, Deserialize)]
pub struct InboundConfig {
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default = "any_address")]
    pub listen: IpAddr,
    pub listen_port: u16,
    /// The base outbound's name; `None` takes the node's default.
    #[serde(default)]
    pub outbound: Option<String>,
    /// The network-model ingress; excludes `outbound`.
    #[serde(default)]
    pub ingress: Option<String>,
    #[serde(flatten)]
    pub settings: Settings,
}

fn any_address() -> IpAddr {
    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
}

impl InboundConfig {
    /// Targets this inbound relays to by design (`fallback`, REALITY
    /// `handshake`, a forward's `server` or `targets`), which the private-target filter
    /// lets through.
    pub fn allowed_targets(&self) -> Vec<(String, u16)> {
        let fallback = self.settings.get("fallback");
        let handshake = self
            .settings
            .get("reality")
            .and_then(|reality| reality.get("handshake"));
        let mut allowed: Vec<(String, u16)> = [fallback, handshake]
            .into_iter()
            .flatten()
            .filter_map(|value| serde_json::from_value::<FallbackSettings>(value.clone()).ok())
            .map(|target| (target.server, target.server_port))
            .collect();
        if self.kind == crate::FORWARD_TYPE {
            let targets = self
                .settings
                .get("targets")
                .and_then(|value| value.as_array());
            let own = std::iter::once(&self.settings).filter_map(|settings| {
                settings
                    .get("server")
                    .map(|server| (server, settings.get("server_port")))
            });
            let listed = targets.into_iter().flatten().filter_map(|target| {
                target
                    .get("server")
                    .map(|server| (server, target.get("server_port")))
            });
            for (server, port) in own.chain(listed) {
                let server = server.as_str();
                let port = port
                    .and_then(|value| value.as_u64())
                    .and_then(|port| u16::try_from(port).ok());
                if let (Some(server), Some(port)) = (server, port) {
                    // As the forward sends it: IP literals in canonical form.
                    let target = TargetAddr::from_host(server.trim(), port);
                    allowed.push((target.host(), port));
                }
            }
        }
        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_inbound_keys_from_protocol_settings() {
        let config: NodeConfig = serde_json::from_value(serde_json::json!({
            "inbounds": [{
                "tag": "vless", "type": "vless", "listen_port": 443,
                "outbound": "direct",
                "users": [],
                "fallback": {"server": "127.0.0.1", "server_port": 8080},
                "reality": {"handshake": {"server": "www.example.com", "server_port": 443}}
            }]
        }))
        .unwrap();
        let inbound = &config.inbounds[0];
        assert_eq!(inbound.listen, any_address());
        assert!(!inbound.settings.contains_key("tag"));
        assert!(!inbound.settings.contains_key("listen_port"));
        assert_eq!(inbound.outbound.as_deref(), Some("direct"));
        assert!(!inbound.settings.contains_key("outbound"));
        assert!(inbound.settings.contains_key("users"));
        assert_eq!(
            inbound.allowed_targets(),
            vec![
                ("127.0.0.1".to_owned(), 8080),
                ("www.example.com".to_owned(), 443)
            ]
        );
    }

    #[test]
    fn allows_the_forward_target() {
        let config: NodeConfig = serde_json::from_value(serde_json::json!({
            "inbounds": [
                {"tag": "f", "type": "forward", "listen_port": 10001,
                 "server": "[fd00::0:7]", "server_port": 22},
                {"tag": "ss", "type": "shadowsocks", "listen_port": 8388,
                 "server": "10.0.0.1", "server_port": 22}
            ]
        }))
        .unwrap();
        assert_eq!(
            config.inbounds[0].allowed_targets(),
            vec![("fd00::7".to_owned(), 22)]
        );
        assert!(config.inbounds[1].allowed_targets().is_empty());
        let config: NodeConfig = serde_json::from_value(serde_json::json!({
            "inbounds": [
                {"tag": "f", "type": "forward", "listen_port": 10001,
                 "targets": [{"server": "10.0.0.1", "server_port": 22},
                             {"server": "b.example", "server_port": 80}]}
            ]
        }))
        .unwrap();
        assert_eq!(
            config.inbounds[0].allowed_targets(),
            vec![("10.0.0.1".to_owned(), 22), ("b.example".to_owned(), 80)]
        );
    }
}
