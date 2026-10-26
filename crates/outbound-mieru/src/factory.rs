//! Registry entry for `"type": "mieru"` config entries.

use std::io;
use std::sync::Arc;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{Dialer, TcpOutbound};
use serde::Deserialize;

use crate::client::{MieruOptions, MieruOutbound};

pub const TYPE_NAME: &str = "mieru";

/// Has no `Debug`: the password is a secret.
#[derive(Deserialize)]
struct MieruSettings {
    server: String,
    port: u16,
    username: String,
    password: String,
    /// `"low-high"`; each connection picks a port from it.
    #[serde(default)]
    port_range: Option<String>,
    /// `TCP` (default); `UDP` is not implemented.
    #[serde(default)]
    transport: Option<String>,
}

fn parse_port_range(raw: &str) -> Option<(u16, u16)> {
    let (low, high) = raw.trim().split_once('-')?;
    let low: u16 = low.trim().parse().ok()?;
    let high: u16 = high.trim().parse().ok()?;
    (low != 0 && low <= high).then_some((low, high))
}

pub struct MieruFactory;

impl OutboundFactory for MieruFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(
        &self,
        settings: &Settings,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let settings: MieruSettings =
            parse_settings(settings, "mieru settings are missing or invalid")?;
        match settings.transport.as_deref() {
            None | Some("") => {}
            Some(transport) if transport.eq_ignore_ascii_case("tcp") => {}
            Some(transport) if transport.eq_ignore_ascii_case("udp") => {
                return Err("mieru udp transport is not implemented yet")
            }
            Some(_) => return Err("unsupported mieru transport"),
        }
        let port_range = match settings.port_range.as_deref() {
            None | Some("") => None,
            Some(raw) => Some(parse_port_range(raw).ok_or("mieru port range is invalid")?),
        };
        let options = MieruOptions {
            username: settings.username,
            password: settings.password,
            port_range,
        };
        let invalid = |err: io::Error| match err.kind() {
            io::ErrorKind::InvalidInput => "mieru outbound settings are invalid",
            _ => "outbound could not be created",
        };
        let outbound =
            MieruOutbound::new(settings.server, settings.port, options, dialer).map_err(invalid)?;
        Ok(Arc::new(outbound))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_outbound::TcpDialer;

    fn build(json: &str) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let settings: Settings = serde_json::from_str(json).unwrap();
        MieruFactory.build(&settings, Arc::new(TcpDialer))
    }

    #[test]
    fn builds_tcp_outbounds_with_and_without_a_port_range() {
        for json in [
            r#"{"server":"example.com","port":2027,"username":"alice","password":"hunter2"}"#,
            r#"{"server":"example.com","port":2012,"username":"alice","password":"hunter2","port_range":"2012-2022","transport":"TCP"}"#,
        ] {
            assert_eq!(build(json).unwrap().protocol(), "mieru");
        }
    }

    #[test]
    fn rejects_invalid_settings_without_echoing_secrets() {
        for (json, reason) in [
            (
                r#"{"server":"example.com","port":2027,"username":"alice","password":"hunter2","transport":"UDP"}"#,
                "mieru udp transport is not implemented yet",
            ),
            (
                r#"{"server":"example.com","port":2027,"username":"alice","password":"hunter2","transport":"quic"}"#,
                "unsupported mieru transport",
            ),
            (
                r#"{"server":"example.com","port":2027,"username":"alice","password":"hunter2","port_range":"2022-2012"}"#,
                "mieru port range is invalid",
            ),
            (
                r#"{"server":"example.com","port":2027,"username":"","password":"hunter2"}"#,
                "mieru outbound settings are invalid",
            ),
            (
                r#"{"server":"example.com","port":2027,"password":"hunter2"}"#,
                "mieru settings are missing or invalid",
            ),
        ] {
            let err = build(json).err().unwrap();
            assert_eq!(err, reason);
            assert!(!err.contains("hunter2"));
        }
    }

    #[test]
    fn parses_port_ranges() {
        assert_eq!(parse_port_range("2012-2022"), Some((2012, 2022)));
        assert_eq!(parse_port_range(" 7 - 7 "), Some((7, 7)));
        assert_eq!(parse_port_range("0-5"), None);
        assert_eq!(parse_port_range("2012"), None);
    }
}
