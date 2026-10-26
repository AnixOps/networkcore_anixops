//! Registry entry for `"type": "snell"` inbound config entries.

use std::sync::Arc;

use engine_inbound::registry::{parse_settings, BuildError, InboundFactory, Settings};
use engine_inbound::{StreamInbound, User};
use outbound_snell::V6Mode;
use serde::Deserialize;

use crate::{SnellInbound, SnellInboundOptions};

pub const TYPE_NAME: &str = "snell";

/// Has no `Debug`: `psk` and the user keys are keys.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnellInboundSettings {
    psk: String,
    version: u8,
    /// v6: `default` (when absent), `unshaped` or `unsafe-raw`.
    #[serde(default)]
    mode: Option<String>,
    /// v1–v4: `http` or `none`.
    #[serde(default)]
    obfs: Option<String>,
    /// Users by user key (`password`); empty for a single-user server.
    #[serde(default)]
    users: Vec<User>,
}

pub struct SnellInboundFactory;

impl InboundFactory for SnellInboundFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(&self, settings: &Settings) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let settings: SnellInboundSettings =
            parse_settings(settings, "snell inbound settings are missing or invalid")?;
        if !(1..=6).contains(&settings.version) {
            return Err("snell version must be between 1 and 6");
        }
        if settings.psk.is_empty() {
            return Err("snell psk is missing");
        }
        let mode = match settings.mode.as_deref() {
            None => V6Mode::Default,
            Some(_) if settings.version != 6 => return Err("snell mode applies to version 6 only"),
            Some(name) => V6Mode::parse(name).ok_or("unknown snell v6 mode")?,
        };
        let http_obfs = match settings.obfs.as_deref() {
            None | Some("none") | Some("off") => false,
            Some("http") if settings.version <= 4 => true,
            Some("http") => return Err("snell obfs is only defined for versions 1 to 4"),
            Some("tls") => return Err("snell tls obfs is not implemented yet"),
            Some(_) => return Err("unknown snell obfs"),
        };
        let inbound = SnellInbound::new(SnellInboundOptions {
            version: settings.version,
            mode,
            psk: settings.psk.into_bytes(),
            http_obfs,
        })
        .map_err(|_| "snell inbound settings are invalid")?;
        inbound.users().add_all(settings.users)?;
        Ok(Arc::new(inbound))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(json: &str) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let settings: Settings = serde_json::from_str(json).unwrap();
        SnellInboundFactory.build(&settings)
    }

    #[test]
    fn builds_every_version_and_mode() {
        for version in 1..=6 {
            let inbound = build(&format!(r#"{{"psk":"secret","version":{version}}}"#)).unwrap();
            assert_eq!(inbound.protocol(), "snell");
        }
        for mode in ["default", "unshaped", "unsafe-raw"] {
            build(&format!(
                r#"{{"psk":"secret","version":6,"mode":"{mode}"}}"#
            ))
            .unwrap();
        }
        build(r#"{"psk":"secret","version":4,"obfs":"http"}"#).unwrap();
        let inbound =
            build(r#"{"psk":"secret","version":4,"users":[{"name":"a","password":"key-a"}]}"#)
                .unwrap();
        assert!(inbound.users().contains("a"));
    }

    #[test]
    fn rejects_invalid_settings() {
        assert!(build(r#"{"psk":"secret","version":7}"#).is_err());
        assert!(build(r#"{"psk":"","version":4}"#).is_err());
        assert!(build(r#"{"psk":"secret","version":4,"mode":"default"}"#).is_err());
        assert!(build(r#"{"psk":"secret","version":6,"mode":"fast"}"#).is_err());
        assert!(build(r#"{"psk":"secret","version":6,"obfs":"http"}"#).is_err());
        assert!(build(r#"{"psk":"secret","version":3,"obfs":"tls"}"#).is_err());
        assert!(build(r#"{"psk":"secret","version":4,"users":[{"name":"a"}]}"#).is_err());
        assert!(build(r#"{"version":4}"#).is_err());
    }
}
