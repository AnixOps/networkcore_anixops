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
//!   "egress": {"routes": [], "relays": []}
//! }
//! ```
//!
//! Every inbound key other than `tag`, `type`, `listen`, `listen_port` and
//! `outbound` is passed to the protocol factory as its settings. `egress` is
//! optional and has the format of `PUT /v1/egress`
//! ([`crate::egress::EgressConfig`]).
//!
//! `outbound` (on an inbound) and `default_outbound` (for all inbounds)
//! name the base outbound traffic leaves through: `"direct"` (the default)
//! or one the binary registered ([`crate::Node::with_outbound`]); plain
//! `anixcore` registers none.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use engine_inbound::registry::Settings;
use engine_inbound::FallbackSettings;
use serde::Deserialize;

use crate::egress::EgressConfig;

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
    #[serde(flatten)]
    pub settings: Settings,
}

fn any_address() -> IpAddr {
    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
}

impl InboundConfig {
    /// Targets this inbound relays to by design (`fallback`, REALITY
    /// `handshake`), which the private-target filter lets through.
    pub fn allowed_targets(&self) -> Vec<(String, u16)> {
        let fallback = self.settings.get("fallback");
        let handshake = self
            .settings
            .get("reality")
            .and_then(|reality| reality.get("handshake"));
        [fallback, handshake]
            .into_iter()
            .flatten()
            .filter_map(|value| serde_json::from_value::<FallbackSettings>(value.clone()).ok())
            .map(|target| (target.server, target.server_port))
            .collect()
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
}
