//! Registry entry for `"type": "snell"` config entries.

use std::io;
use std::sync::Arc;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{Dialer, TcpOutbound};
use serde::Deserialize;

use crate::client::{HttpObfsSettings, SnellOptions, SnellOutbound};
use crate::codec::V6Mode;
use crate::obfs::{DEFAULT_HTTP_HOST, DEFAULT_HTTP_URI};

pub const TYPE_NAME: &str = "snell";

/// Has no `Debug`: the PSK is a key.
#[derive(Deserialize)]
struct SnellSettings {
    server: String,
    port: u16,
    psk: String,
    version: u8,
    #[serde(default)]
    mode: Option<String>,
    /// `http` (v1–v4); `tls` is not implemented.
    #[serde(default)]
    obfs: Option<String>,
    #[serde(default)]
    obfs_host: Option<String>,
    #[serde(default)]
    obfs_uri: Option<String>,
    #[serde(default)]
    reuse: bool,
    #[serde(default)]
    userkey: Option<String>,
}

pub struct SnellFactory;

impl OutboundFactory for SnellFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(
        &self,
        settings: &Settings,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let settings: SnellSettings =
            parse_settings(settings, "snell settings are missing or invalid")?;
        let mode = match settings.mode.as_deref() {
            None | Some("") => V6Mode::Default,
            Some(name) => V6Mode::parse(name).ok_or("unsupported snell mode")?,
        };
        if settings.mode.is_some() && settings.version != 6 && mode != V6Mode::Default {
            return Err("snell mode needs version 6");
        }
        let obfs = match settings.obfs.as_deref() {
            None | Some("") | Some("none") | Some("off") => None,
            Some("http") => Some(HttpObfsSettings {
                host: settings
                    .obfs_host
                    .filter(|host| !host.is_empty())
                    .unwrap_or_else(|| DEFAULT_HTTP_HOST.to_owned()),
                uri: settings
                    .obfs_uri
                    .filter(|uri| !uri.is_empty())
                    .unwrap_or_else(|| DEFAULT_HTTP_URI.to_owned()),
            }),
            Some("tls") => return Err("snell tls obfs is not implemented yet"),
            Some(_) => return Err("unsupported snell obfs"),
        };
        let options = SnellOptions {
            version: settings.version,
            mode,
            psk: settings.psk.into_bytes(),
            obfs,
            reuse: settings.reuse,
            user_key: settings.userkey.unwrap_or_default().into_bytes(),
        };
        let invalid = |err: io::Error| match err.kind() {
            io::ErrorKind::InvalidInput => "snell outbound settings are invalid",
            _ => "outbound could not be created",
        };
        let outbound =
            SnellOutbound::new(settings.server, settings.port, options, dialer).map_err(invalid)?;
        Ok(Arc::new(outbound))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_outbound::TcpDialer;

    fn build(json: &str) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let settings: Settings = serde_json::from_str(json).unwrap();
        SnellFactory.build(&settings, Arc::new(TcpDialer))
    }

    #[test]
    fn builds_every_version_and_mode() {
        for version in 1..=6 {
            let json = format!(
                r#"{{"server":"example.com","port":443,"psk":"0123456789abcdef","version":{version}}}"#
            );
            assert_eq!(build(&json).unwrap().protocol(), "snell");
        }
        for mode in ["default", "unshaped", "unsafe-raw"] {
            let json = format!(
                r#"{{"server":"example.com","port":443,"psk":"0123456789abcdef","version":6,"mode":"{mode}","reuse":true}}"#
            );
            assert!(build(&json).is_ok());
        }
        assert!(build(
            r#"{"server":"example.com","port":443,"psk":"k","version":4,"obfs":"http","obfs_host":"cdn.example"}"#
        )
        .is_ok());
    }

    #[test]
    fn rejects_invalid_settings_without_echoing_secrets() {
        for (json, reason) in [
            (
                r#"{"server":"example.com","port":443,"psk":"hunter2","version":7}"#,
                "snell outbound settings are invalid",
            ),
            (
                r#"{"server":"example.com","port":443,"psk":"","version":4}"#,
                "snell outbound settings are invalid",
            ),
            (
                r#"{"server":"example.com","port":443,"psk":"hunter2","version":6,"obfs":"http"}"#,
                "snell outbound settings are invalid",
            ),
            (
                r#"{"server":"example.com","port":443,"psk":"hunter2","version":3,"obfs":"tls"}"#,
                "snell tls obfs is not implemented yet",
            ),
            (
                r#"{"server":"example.com","port":443,"psk":"hunter2","version":6,"mode":"fast"}"#,
                "unsupported snell mode",
            ),
            (
                r#"{"server":"example.com","port":443,"version":6}"#,
                "snell settings are missing or invalid",
            ),
        ] {
            let err = build(json).err().unwrap();
            assert_eq!(err, reason);
            assert!(!err.contains("hunter2"));
        }
    }
}
