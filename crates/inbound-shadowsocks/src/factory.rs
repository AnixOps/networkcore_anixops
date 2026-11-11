//! Registry entry for `"type": "shadowsocks"` inbound config entries.

use std::io;
use std::sync::Arc;

use engine_inbound::registry::{parse_settings, BuildError, InboundFactory, Settings};
use engine_inbound::shadow_tls::{self, ShadowTlsSettings};
use engine_inbound::{StreamInbound, User};
use inbound_transport::{TlsServerSettings, TransportSettings};
use serde::Deserialize;

use crate::obfs::{ObfsInbound, ObfsSettings};
use crate::{sip004, AeadInbound, Method, Ss2022Inbound};

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
    /// A ShadowTLS v3 server in front of the TCP side.
    #[serde(default)]
    shadow_tls: Option<ShadowTlsSettings>,
    /// simple-obfs (`obfs-local` clients) in front of the protocol:
    /// `{"type": "http" | "tls", "host": "..."}`. Not with `tls` or
    /// `transport`.
    #[serde(default)]
    obfs: Option<ObfsSettings>,
    /// TLS in front of the `ws` transport, v2ray-plugin's `tls` option; not
    /// without that transport.
    #[serde(default)]
    tls: Option<TlsServerSettings>,
    /// `{"type": "ws", "path": ..., "host": ...}`: v2ray-plugin's
    /// `websocket` mode without its multiplexing (`mux=0`).
    #[serde(default)]
    transport: Option<TransportSettings>,
}

/// Builds Shadowsocks inbounds. A 2022 method makes a Shadowsocks-2022
/// inbound: without `users` it is single-key, with `users` multi-user (AES
/// methods only). An AEAD method (`aes-128-gcm`, `aes-256-gcm`,
/// `chacha20-ietf-poly1305`) makes a SIP004 inbound that always takes users
/// and adds users at runtime, with or without `users` at creation. Either
/// may sit behind what the SIP003 plugins simple-obfs (`obfs`) and
/// v2ray-plugin (`transport`, `tls`) put on the TCP connection, or, with
/// `shadow_tls`, behind ShadowTLS v3 ([`engine_inbound::shadow_tls`]); the
/// two do not combine.
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
        let inbound = protocol(&settings.method, &settings.password, settings.users)?;
        let tls = settings.tls.as_ref();
        // `tcp` is no transport.
        let transport = settings.transport.as_ref();
        let transport = transport.filter(|kind| !matches!(kind, TransportSettings::Tcp));
        let plugin = settings.obfs.is_some() || tls.is_some() || transport.is_some();
        match (&settings.obfs, transport) {
            _ if settings.shadow_tls.is_some() && plugin => {
                Err("shadowsocks shadow_tls does not combine with obfs, tls or transport")
            }
            (Some(_), _) if tls.is_some() || transport.is_some() => {
                Err("shadowsocks obfs does not combine with tls or transport")
            }
            (Some(obfs), _) => Ok(Arc::new(ObfsInbound::new(inbound, obfs))),
            // v2ray-plugin has no TLS without its websocket.
            (None, None) if tls.is_some() => Err("shadowsocks tls needs the ws transport"),
            (None, None | Some(TransportSettings::Ws { .. })) => {
                let inbound = inbound_transport::wrap_all(inbound, transport, tls)?;
                shadow_tls::wrap(inbound, settings.shadow_tls.as_ref())
            }
            (None, Some(_)) => Err("shadowsocks takes the ws transport only"),
        }
    }
}

/// The inbound of the protocol that `method` names.
fn protocol(
    method: &str,
    password: &str,
    users: Vec<User>,
) -> Result<Arc<dyn StreamInbound>, BuildError> {
    if !method.starts_with("2022-") {
        let method = sip004::parse_method(method).map_err(|_| "unsupported shadowsocks method")?;
        let inbound =
            AeadInbound::new(method, password).map_err(|_| "inbound could not be created")?;
        inbound.users().add_all(users)?;
        return Ok(Arc::new(inbound));
    }
    let method = Method::parse(method).map_err(|_| "unsupported shadowsocks method")?;
    let inbound =
        Ss2022Inbound::new(method, password, !users.is_empty()).map_err(|err| {
            match err.kind() {
                io::ErrorKind::InvalidInput => "shadowsocks inbound settings are invalid",
                _ => "inbound could not be created",
            }
        })?;
    inbound.users().add_all(users)?;
    Ok(Arc::new(inbound))
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
    fn builds_inbounds_behind_shadow_tls() {
        let key = r#""method":"2022-blake3-aes-128-gcm","password":"AAECAwQFBgcICQoLDA0ODw==""#;
        let user = r#"{"name":"a","password":"EBESExQVFhcYGRobHB0eHw=="}"#;
        let front = r#"{"name":"b","password":"front"}"#;
        let handshake = r#""handshake":{"server":"www.example.com","server_port":443}"#;

        // A shared ShadowTLS password: the users are the protocol's.
        let shared = build(&format!(
            r#"{{{key},"users":[{user}],"shadow_tls":{{"password":"front",{handshake}}}}}"#
        ))
        .unwrap();
        assert_eq!(shared.protocol(), "shadowsocks-2022");
        assert!(shared.serves_connections());
        assert_eq!(shared.users().names(), ["a"]);
        assert!(shared.datagram().is_some());

        // ShadowTLS users on a single-key inbound: the users are theirs, and
        // the UDP port, which could not tell them apart, stays closed.
        let users = build(&format!(
            r#"{{{key},"shadow_tls":{{"version":3,"strict_mode":true,"users":[{front}],{handshake}}}}}"#
        ))
        .unwrap();
        assert_eq!(users.users().names(), ["b"]);
        assert!(users.datagram().is_none());
        assert!(users.users().add(User::with_password("c", "")).is_err());

        for shadow_tls in [
            // No password and no users, another version, no handshake site.
            format!("{{{handshake}}}"),
            format!(r#"{{"version":2,"password":"front",{handshake}}}"#),
            r#"{"password":"front"}"#.to_owned(),
        ] {
            assert!(build(&format!(r#"{{{key},"shadow_tls":{shadow_tls}}}"#)).is_err());
        }
        // Two user tables.
        assert!(build(&format!(
            r#"{{{key},"users":[{user}],"shadow_tls":{{"users":[{front}],{handshake}}}}}"#
        ))
        .is_err());
        // ShadowTLS and a plugin layer on one inbound.
        for layer in [
            r#""obfs":{"type":"http"}"#,
            r#""transport":{"type":"ws","path":"/ss"}"#,
        ] {
            assert!(build(&format!(
                r#"{{{key},{layer},"shadow_tls":{{"password":"front",{handshake}}}}}"#
            ))
            .is_err());
        }
        // The `tcp` transport is no layer.
        let tcp = build(&format!(
            r#"{{{key},"transport":{{"type":"tcp"}},"shadow_tls":{{"password":"front",{handshake}}}}}"#
        ))
        .unwrap();
        assert!(tcp.serves_connections());
    }

    #[test]
    fn builds_plugin_layers_and_refuses_to_mix_them() {
        let protocol = r#""method":"aes-128-gcm","password":"p""#;
        for layer in [
            r#""obfs":{"type":"http"}"#,
            r#""obfs":{"type":"tls","host":"cdn.example"}"#,
            r#""transport":{"type":"ws","path":"/ss","host":"cdn.example"}"#,
            r#""transport":{"type":"tcp"}"#,
            r#""obfs":{"type":"http"},"transport":{"type":"tcp"}"#,
        ] {
            let inbound = build(&format!("{{{protocol},{layer}}}")).unwrap();
            assert_eq!(inbound.protocol(), "shadowsocks");
            assert!(inbound.datagram().is_some());
        }
        for layers in [
            r#""obfs":{"type":"quic"}"#,
            r#""obfs":{"type":"http","hots":"cdn.example"}"#,
            r#""obfs":{"type":"http"},"transport":{"type":"ws"}"#,
            r#""obfs":{"type":"tls"},"tls":{"certificate":"c","key":"k"}"#,
            r#""transport":{"type":"grpc","service_name":"ss"}"#,
            r#""transport":{"type":"ws","path":"ss"}"#,
        ] {
            assert!(build(&format!("{{{protocol},{layers}}}")).is_err());
        }
        // TLS is v2ray-plugin's, in front of its websocket only.
        for transport in ["", r#","transport":{"type":"tcp"}"#] {
            let tls = r#""tls":{"certificate":"c","key":"k"}"#;
            assert_eq!(
                build(&format!("{{{protocol},{tls}{transport}}}")).err(),
                Some("shadowsocks tls needs the ws transport")
            );
        }
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
