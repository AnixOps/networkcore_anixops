//! Registry entry for `"type": "shadowsocks"` inbound config entries.

use std::io;
use std::sync::Arc;

use engine_inbound::registry::{parse_settings, BuildError, InboundFactory, Settings};
use engine_inbound::{StreamInbound, User};
use serde::Deserialize;

use crate::{aead, AeadInbound, Method, Ss2022Inbound};

pub const TYPE_NAME: &str = "shadowsocks";

/// Has no `Debug`: the password is a key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShadowsocksInboundSettings {
    method: String,
    /// 2022 methods: the server key, the identity key when `users` is not
    /// empty. AEAD methods: an optional key for clients that are no user.
    #[serde(default)]
    password: String,
    #[serde(default)]
    users: Vec<User>,
}

/// Builds Shadowsocks inbounds. A 2022 method makes a Shadowsocks-2022
/// inbound: without `users` it is single-key, with `users` multi-user (AES
/// methods only). An AEAD method (`aes-128-gcm`, `aes-256-gcm`,
/// `chacha20-ietf-poly1305`) makes a SIP004 inbound that always takes users
/// and adds users at runtime, with or without `users` at creation.
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
            let method = aead::parse_method(&settings.method)
                .map_err(|_| "unsupported shadowsocks method")?;
            let inbound = AeadInbound::new(method, &settings.password)
                .map_err(|_| "inbound could not be created")?;
            inbound.users().add_all(settings.users)?;
            return Ok(Arc::new(inbound));
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
    fn builds_aead_inbounds_with_and_without_users() {
        for method in ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"] {
            let open = build(&format!(r#"{{"method":"{method}"}}"#)).unwrap();
            assert!(open.users().is_empty());
            assert_eq!(open.protocol(), "shadowsocks");
            let users = build(&format!(
                r#"{{"method":"{method}","password":"anon","users":[{{"name":"1","password":"p1"}}]}}"#
            ))
            .unwrap();
            assert_eq!(users.users().names(), ["1"]);
        }
        assert!(build(r#"{"method":"aes-128-gcm","users":[{"name":"1"}]}"#).is_err());
    }

    #[test]
    fn rejects_bad_settings_without_echoing_keys() {
        assert!(build(r#"{"method":"aes-128-cfb","password":"x"}"#).is_err());
        assert!(build(r#"{"method":"2022-blake3-aes-128-gcm"}"#).is_err());
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
