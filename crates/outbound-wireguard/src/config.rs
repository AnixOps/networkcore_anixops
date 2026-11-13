//! The `"type": "wireguard"` outbound settings.
//!
//! ```json
//! {
//!   "type": "wireguard",
//!   "server": "wg.example.com",
//!   "port": 51820,
//!   "private_key": "<base64>",
//!   "peer_public_key": "<base64>",
//!   "preshared_key": "<base64>",
//!   "local_address": ["10.7.0.2/32", "fd00:7::2/128"],
//!   "allowed_ips": ["10.0.0.0/8", "fd00::/8"],
//!   "dns": ["10.7.0.1"],
//!   "mtu": 1420,
//!   "persistent_keepalive_secs": 25,
//!   "reserved": [0, 0, 0]
//! }
//! ```
//!
//! `allowed_ips` is the peer's AllowedIPs in the WireGuard sense: a
//! connection or UDP flow may only go to an address inside it, and a packet
//! that comes out of the tunnel is dropped unless its source is inside it.
//! It defaults to everything (`0.0.0.0/0`, `::/0`).

use std::net::IpAddr;

use base64::Engine;
use engine_outbound::registry::BuildError;
use serde::Deserialize;

use crate::allowed::{AllowedIps, IpNet};

pub const DEFAULT_MTU: u16 = 1420;
/// IPv6 needs 1280; 576 is the IPv4 floor for a v4-only node.
pub const MIN_MTU: u16 = 576;
pub const MAX_MTU: u16 = 9000;
pub const DEFAULT_TCP_BUFFER: u32 = 64 * 1024;
pub const MIN_TCP_BUFFER: u32 = 4 * 1024;
pub const MAX_TCP_BUFFER: u32 = 1024 * 1024;
const MAX_ADDRESSES: usize = 16;
const MAX_ALLOWED_IPS: usize = 256;
const MAX_DNS: usize = 4;

/// The settings as written in the config. Keys are standard base64, as in a
/// `wg-quick` file. Holds key material, so it has no `Debug`.
#[derive(Deserialize)]
pub struct WireGuardConfig {
    pub server: String,
    pub port: u16,
    pub private_key: String,
    pub peer_public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    /// The interface addresses (wg-quick `Address`), with or without a
    /// prefix length.
    #[serde(default)]
    pub local_address: Vec<String>,
    /// The peer's AllowedIPs; empty means everything.
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    /// DNS servers inside the tunnel (wg-quick `DNS`) for domain targets.
    /// Without them, names resolve with the system resolver.
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub persistent_keepalive_secs: Option<u16>,
    /// Bytes 1..4 of every message, which some services (Cloudflare WARP)
    /// use as a client id; zero in plain WireGuard.
    #[serde(default)]
    pub reserved: Option<[u8; 3]>,
    #[serde(default = "default_tcp_buffer")]
    pub tcp_buffer_bytes: u32,
}

fn default_mtu() -> u16 {
    DEFAULT_MTU
}

fn default_tcp_buffer() -> u32 {
    DEFAULT_TCP_BUFFER
}

/// Validated settings. Holds key material, so it has no `Debug`.
#[derive(Clone)]
pub struct WireGuardSettings {
    pub server: String,
    pub port: u16,
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// At most one address of each family; extra ones are ignored.
    pub local_v4: Option<std::net::Ipv4Addr>,
    pub local_v6: Option<std::net::Ipv6Addr>,
    pub allowed_ips: AllowedIps,
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
    pub persistent_keepalive_secs: Option<u16>,
    pub reserved: Option<[u8; 3]>,
    pub tcp_buffer_bytes: u32,
}

impl WireGuardConfig {
    pub fn validate(self) -> Result<WireGuardSettings, BuildError> {
        let server = self.server.trim();
        if server.is_empty() || self.port == 0 {
            return Err("wireguard endpoint is invalid");
        }
        let private_key = decode_key(&self.private_key)
            .ok_or("wireguard private key must be 32 bytes of base64")?;
        let peer_public_key = decode_key(&self.peer_public_key)
            .ok_or("wireguard peer public key must be 32 bytes of base64")?;
        let preshared_key = match self.preshared_key.as_deref().map(str::trim) {
            None | Some("") => None,
            Some(key) => {
                Some(decode_key(key).ok_or("wireguard preshared key must be 32 bytes of base64")?)
            }
        };

        if self.local_address.is_empty() {
            return Err("wireguard local_address is required");
        }
        if self.local_address.len() > MAX_ADDRESSES {
            return Err("wireguard has too many local addresses");
        }
        let mut local_v4 = None;
        let mut local_v6 = None;
        for address in &self.local_address {
            let net = IpNet::parse(address).ok_or("wireguard local_address is invalid")?;
            match net.address() {
                IpAddr::V4(v4) => {
                    if v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast() {
                        return Err("wireguard local_address is invalid");
                    }
                    local_v4.get_or_insert(v4);
                }
                IpAddr::V6(v6) => {
                    if v6.is_unspecified() || v6.is_multicast() {
                        return Err("wireguard local_address is invalid");
                    }
                    local_v6.get_or_insert(v6);
                }
            }
        }

        if self.allowed_ips.len() > MAX_ALLOWED_IPS {
            return Err("wireguard has too many allowed_ips");
        }
        let allowed_ips = if self.allowed_ips.is_empty() {
            AllowedIps::everything()
        } else {
            let mut nets = Vec::with_capacity(self.allowed_ips.len());
            for entry in &self.allowed_ips {
                // wg-quick writes one comma-separated line.
                for part in entry
                    .split(',')
                    .map(str::trim)
                    .filter(|part| !part.is_empty())
                {
                    nets.push(IpNet::parse(part).ok_or("wireguard allowed_ips is invalid")?);
                }
            }
            if nets.is_empty() {
                return Err("wireguard allowed_ips is invalid");
            }
            AllowedIps::new(nets)
        };

        if self.dns.len() > MAX_DNS {
            return Err("wireguard has too many dns servers");
        }
        let mut dns = Vec::with_capacity(self.dns.len());
        for server in &self.dns {
            let address: IpAddr = server
                .trim()
                .parse()
                .map_err(|_| "wireguard dns must be IP addresses")?;
            if !allowed_ips.contains(address) {
                return Err("wireguard dns server is outside allowed_ips");
            }
            let reachable = match address {
                IpAddr::V4(_) => local_v4.is_some(),
                IpAddr::V6(_) => local_v6.is_some(),
            };
            if !reachable {
                return Err("wireguard dns server has no local address of its family");
            }
            dns.push(address);
        }

        if !(MIN_MTU..=MAX_MTU).contains(&self.mtu) {
            return Err("wireguard mtu is out of range");
        }
        if local_v6.is_some() && self.mtu < 1280 {
            return Err("wireguard mtu must be at least 1280 with an IPv6 address");
        }
        if !(MIN_TCP_BUFFER..=MAX_TCP_BUFFER).contains(&self.tcp_buffer_bytes) {
            return Err("wireguard tcp_buffer_bytes is out of range");
        }
        Ok(WireGuardSettings {
            server: server
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned(),
            port: self.port,
            private_key,
            peer_public_key,
            preshared_key,
            local_v4,
            local_v6,
            allowed_ips,
            dns,
            mtu: self.mtu,
            persistent_keepalive_secs: self.persistent_keepalive_secs.filter(|secs| *secs > 0),
            reserved: self.reserved.filter(|bytes| *bytes != [0; 3]),
            tcp_buffer_bytes: self.tcp_buffer_bytes,
        })
    }
}

/// Decodes a standard base64 WireGuard key.
pub fn decode_key(encoded: &str) -> Option<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    fn config(extra: serde_json::Value) -> Result<WireGuardSettings, BuildError> {
        let mut value = serde_json::json!({
            "server": "wg.example.test",
            "port": 51820,
            "private_key": KEY,
            "peer_public_key": KEY,
            "local_address": ["10.7.0.2/32"],
        });
        for (key, field) in extra.as_object().unwrap() {
            value[key] = field.clone();
        }
        serde_json::from_value::<WireGuardConfig>(value)
            .map_err(|_| "parse")?
            .validate()
    }

    #[test]
    fn defaults_allow_everything() {
        let settings = config(serde_json::json!({})).ok().unwrap();
        assert_eq!(settings.mtu, DEFAULT_MTU);
        assert_eq!(settings.local_v4, Some("10.7.0.2".parse().unwrap()));
        assert_eq!(settings.local_v6, None);
        assert!(settings.allowed_ips.contains("8.8.8.8".parse().unwrap()));
        assert!(settings
            .allowed_ips
            .contains("2001:db8::1".parse().unwrap()));
        assert!(settings.reserved.is_none());
    }

    #[test]
    fn allowed_ips_accept_wg_quick_lines() {
        let settings = config(serde_json::json!({
            "local_address": ["10.7.0.2/32", "fd00:7::2/128"],
            "allowed_ips": ["10.7.0.0/24, 192.168.1.1", "fd00:7::/64"],
            "dns": ["10.7.0.1"],
            "reserved": [1, 2, 3],
        }))
        .ok()
        .unwrap();
        let allowed = &settings.allowed_ips;
        assert!(allowed.contains("10.7.0.9".parse().unwrap()));
        assert!(allowed.contains("192.168.1.1".parse().unwrap()));
        assert!(!allowed.contains("192.168.1.2".parse().unwrap()));
        assert!(allowed.contains("fd00:7::99".parse().unwrap()));
        assert!(!allowed.contains("fd00:8::1".parse().unwrap()));
        assert_eq!(settings.reserved, Some([1, 2, 3]));
    }

    #[test]
    fn invalid_settings_are_rejected() {
        for extra in [
            serde_json::json!({"local_address": []}),
            serde_json::json!({"local_address": ["nope"]}),
            serde_json::json!({"allowed_ips": ["10.0.0.0/33"]}),
            serde_json::json!({"allowed_ips": [","]}),
            serde_json::json!({"dns": ["10.7.0.1"], "allowed_ips": ["192.168.0.0/16"]}),
            serde_json::json!({"dns": ["fd00::1"]}),
            serde_json::json!({"mtu": 100}),
            serde_json::json!({"local_address": ["fd00::2"], "mtu": 1200}),
            serde_json::json!({"private_key": "c2hvcnQ="}),
            serde_json::json!({"port": 0}),
            serde_json::json!({"tcp_buffer_bytes": 1}),
        ] {
            assert!(config(extra.clone()).is_err(), "{extra}");
        }
    }
}
