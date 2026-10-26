//! Registry entry for `"type": "shadowsocks"` inbound config entries.

use std::io;
use std::sync::Arc;

use engine_inbound::registry::{parse_settings, BuildError, InboundFactory, Settings};
use engine_inbound::{StreamInbound, User};
use serde::Deserialize;

use crate::{Method, Ss2022Inbound};

pub const TYPE_NAME: &str = "shadowsocks";

/// Has no `Debug`: the password is a key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowsocksInboundSettings {
    method: String,
    /// Server key; the identity key when `users` is not empty.
    password: String,
    #[serde(default)]
    users: Vec<User>,
}

/// Builds Shadowsocks-2022 inbounds. Without `users` the inbound is
/// single-key; with `users` it is multi-user and needs an AES method.
pub struct ShadowsocksInboundFactory;

impl InboundFactory for ShadowsocksInboundFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(&self, settings: &Settings) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let settings: ShadowsocksInboundSettings = parse_settings(
            settings,
            "shadowsocks inbound settings are missing or invalid",
        )?;
        if !settings.method.starts_with("2022-") {
            return Err("shadowsocks inbound supports only 2022 methods");
        }
        let method =
            Method::parse(&settings.method).map_err(|_| "unsupported shadowsocks method")?;
        let multi_user = !settings.users.is_empty();
        let inbound =
            Ss2022Inbound::new(method, &settings.password, multi_user).map_err(|err| match err
                .kind()
            {
                io::ErrorKind::InvalidInput => "shadowsocks inbound settings are invalid",
                _ => "inbound could not be created",
            })?;
        inbound.users().add_all(settings.users)?;
        Ok(Arc::new(inbound))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(json: &str) -> Result<Arc<dyn StreamInbound>, BuildError> {
        ShadowsocksInboundFactory.build(&serde_json::from_str(json).unwrap())
    }

    #[test]
    fn builds_single_key_and_multi_user_inbounds() {
        let single =
            build(r#"{"method":"2022-blake3-aes-128-gcm","password":"AAECAwQFBgcICQoLDA0ODw=="}"#)
                .unwrap();
        assert!(single.users().is_empty());

        let multi = build(
            r#"{"method":"2022-blake3-aes-128-gcm","password":"AAECAwQFBgcICQoLDA0ODw==",
                "users":[{"name":"a","password":"EBESExQVFhcYGRobHB0eHw=="}]}"#,
        )
        .unwrap();
        assert_eq!(multi.users().names(), ["a"]);
    }

    #[test]
    fn rejects_bad_settings_without_echoing_keys() {
        assert!(build(r#"{"method":"aes-128-gcm","password":"x"}"#).is_err());
        let err = build(r#"{"method":"2022-blake3-aes-128-gcm","password":"c2hvcnQ="}"#)
            .err()
            .unwrap();
        assert!(!err.contains("c2hvcnQ"));
        // Multi-user with ChaCha20 is not defined by SIP022.
        assert!(build(
            r#"{"method":"2022-blake3-chacha20-poly1305",
                "password":"AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKCwwNDg8=",
                "users":[{"name":"a","password":"AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKCwwNDg8="}]}"#
        )
        .is_err());
        assert!(build(r#"{"method":"2022-blake3-aes-128-gcm","password":"AAECAwQFBgcICQoLDA0ODw==","extra":1}"#).is_err());
    }
}
