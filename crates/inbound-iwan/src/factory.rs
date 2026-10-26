//! Registry entry for `"type": "iwan"` inbound config entries (spec §12.4).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use engine_inbound::registry::{parse_settings, BuildError, PacketInboundFactory, Settings};
use engine_inbound::{PacketInbound, User};
use serde::Deserialize;

use crate::{IwanInbound, IwanInboundConfig, Network};

pub const TYPE_NAME: &str = "iwan";

const DEFAULT_MTU: u16 = 1400;
/// The node's MTU bounds the MSS of every tunnelled TCP connection, so it is
/// kept at a size TCP works well with.
const MIN_MTU: u16 = 576;
const MAX_MTU: u16 = 1600;
const DNS_PORT: u16 = 53;
const DEFAULT_DNS_UPSTREAM: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), DNS_PORT);

/// Has no `Debug`: users carry passwords.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IwanInboundSettings {
    #[serde(default = "default_mtu")]
    mtu: u16,
    /// IPv4 network, e.g. `10.66.0.0/16`.
    pool: String,
    /// `1.1.1.1` or `1.1.1.1:53`.
    #[serde(default)]
    dns_upstream: Option<String>,
    #[serde(default)]
    allow_client_to_client: bool,
    #[serde(default = "default_allow_encrypt")]
    allow_encrypt: bool,
    #[serde(default)]
    users: Vec<User>,
}

fn default_mtu() -> u16 {
    DEFAULT_MTU
}

fn default_allow_encrypt() -> bool {
    true
}

fn parse_upstream(text: &str) -> Option<SocketAddr> {
    let text = text.trim();
    text.parse::<SocketAddr>()
        .ok()
        .or_else(|| {
            text.parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, DNS_PORT))
        })
        .filter(|address| address.port() != 0 && !address.ip().is_unspecified())
}

pub struct IwanInboundFactory;

impl PacketInboundFactory for IwanInboundFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(&self, settings: &Settings) -> Result<Arc<dyn PacketInbound>, BuildError> {
        let settings: IwanInboundSettings =
            parse_settings(settings, "iwan inbound settings are missing or invalid")?;
        if !(MIN_MTU..=MAX_MTU).contains(&settings.mtu) {
            return Err("iwan inbound mtu must be between 576 and 1600");
        }
        let pool = Network::parse(&settings.pool)
            .ok_or("iwan pool must be an IPv4 network from /8 to /30")?;
        let dns_upstream = match settings.dns_upstream.as_deref() {
            None => DEFAULT_DNS_UPSTREAM,
            Some(text) => parse_upstream(text).ok_or("iwan dns_upstream must be an IP address")?,
        };
        let inbound = IwanInbound::new(IwanInboundConfig {
            mtu: settings.mtu,
            pool,
            dns_upstream,
            allow_client_to_client: settings.allow_client_to_client,
            allow_encrypt: settings.allow_encrypt,
        });
        inbound.users().add_all(settings.users)?;
        Ok(Arc::new(inbound))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(json: &str) -> Result<Arc<dyn PacketInbound>, BuildError> {
        let settings: Settings = serde_json::from_str(json).unwrap();
        IwanInboundFactory.build(&settings)
    }

    #[test]
    fn builds_with_defaults_and_users() {
        let inbound = build(
            r#"{"pool":"10.66.0.0/16","users":[
                {"name":"1001","username":"alice","password":"secret"},
                {"name":"1002","password":"0123456789abcdef","address":"10.66.3.4"}]}"#,
        )
        .unwrap();
        assert_eq!(inbound.protocol(), "iwan");
        assert!(inbound.users().contains("1001"));
        assert!(inbound.users().contains("1002"));
        assert_eq!(
            parse_upstream("9.9.9.9"),
            Some("9.9.9.9:53".parse().unwrap())
        );
        assert_eq!(
            parse_upstream("[2001:db8::1]:5353"),
            Some("[2001:db8::1]:5353".parse().unwrap())
        );
        build(
            r#"{"pool":"10.66.0.0/24","mtu":1300,"dns_upstream":"8.8.8.8:53",
                "allow_client_to_client":true,"allow_encrypt":false}"#,
        )
        .unwrap();
    }

    #[test]
    fn rejects_invalid_settings() {
        for json in [
            r#"{}"#,
            r#"{"pool":"10.66.0.0"}"#,
            r#"{"pool":"10.66.0.0/31"}"#,
            r#"{"pool":"10.66.0.0/16","mtu":500}"#,
            r#"{"pool":"10.66.0.0/16","mtu":1601}"#,
            r#"{"pool":"10.66.0.0/16","dns_upstream":"dns.google"}"#,
            r#"{"pool":"10.66.0.0/16","dns_upstream":"0.0.0.0"}"#,
            r#"{"pool":"10.66.0.0/16","listen":"0.0.0.0"}"#,
            r#"{"pool":"10.66.0.0/16","users":[{"name":"a"}]}"#,
            r#"{"pool":"10.66.0.0/16","users":[{"name":"a","password":""}]}"#,
            r#"{"pool":"10.66.0.0/16","users":[{"name":"a","password":"0123456789abcdefg"}]}"#,
            r#"{"pool":"10.66.0.0/16","users":[{"name":"a","username":"","password":"x"}]}"#,
            r#"{"pool":"10.66.0.0/16","users":[{"name":"a","password":"x","address":"10.66.0.1"}]}"#,
            r#"{"pool":"10.66.0.0/16","users":[{"name":"a","password":"x","address":"10.67.0.2"}]}"#,
            r#"{"pool":"10.66.0.0/16","users":[{"name":"a","password":"x","address":"::1"}]}"#,
        ] {
            assert!(build(json).is_err(), "{json}");
        }
    }
}
