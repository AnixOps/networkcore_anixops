//! REALITY server transport (Xray `transport/internet/reality`).
//!
//! The server reads the ClientHello and checks the encrypted marker in its
//! session id (see `outbound_vless::reality`): the X25519 shared secret
//! between the client's key share and the server private key gives the
//! auth key, which must open the session id to a known short id and a
//! timestamp inside the allowed window. An authenticated client gets a TLS
//! 1.3 handshake with a temporary Ed25519 certificate whose signature field
//! is `HMAC-SHA512(auth_key, public_key)`; everything else, including
//! non-TLS probes, is relayed unchanged to the `handshake` site, so a prober
//! sees that site's real certificate.
//!
//! Not yet: mirroring the handshake site's ServerHello and record sizes, and
//! the ML-KEM part of hybrid key shares (the X25519 half is used).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use engine_inbound::registry::BuildError;
use engine_inbound::{
    fallback_or_hold, Accepted, FallbackSettings, Rejected, StreamInbound, UserStore,
};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use outbound_vless::reality::derive_auth_key;
use outbound_vless::{parse_public_key, parse_short_id};
use ring::signature::{Ed25519KeyPair, KeyPair};
use ring::{aead, hmac};
use serde::Deserialize;
use tls_mimic::server::{
    accept, ed25519_certificate_template, parse_client_hello, read_client_hello, ClientHelloInfo,
    ServerIdentity,
};
use tls_mimic::SESSION_ID_OFFSET;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::VlessInbound;

/// `"reality"` in inbound settings. Has no `Debug`: holds the private key.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealitySettings {
    /// X25519 private key, base64 as printed by `xray x25519` or `sing-box
    /// generate reality-keypair`.
    pub private_key: String,
    /// Accepted short ids (hex, up to 16 digits; `""` is the all-zero id).
    pub short_ids: Vec<String>,
    /// Accepted SNI values.
    pub server_names: Vec<String>,
    /// The real site that unauthenticated clients are relayed to.
    pub handshake: FallbackSettings,
    /// Largest accepted clock difference; unchecked when absent.
    #[serde(default)]
    pub max_time_difference_secs: Option<u64>,
}

/// ALPN offered to authenticated clients, like a typical web server.
const ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

/// The VLESS inbound behind a REALITY server handshake.
pub struct RealityInbound {
    inner: Arc<VlessInbound>,
    private_key: StaticSecret,
    short_ids: HashSet<[u8; 8]>,
    server_names: HashSet<String>,
    handshake: TargetAddr,
    max_time_difference: Option<u64>,
    signer: Ed25519KeyPair,
    certificate: Vec<u8>,
    alpn: Vec<Vec<u8>>,
}

impl RealityInbound {
    pub fn new(inner: Arc<VlessInbound>, settings: &RealitySettings) -> Result<Self, BuildError> {
        let private_key = parse_public_key(&settings.private_key)
            .map_err(|_| "reality private_key is invalid")?;
        if settings.short_ids.is_empty() {
            return Err("reality short_ids are missing");
        }
        let short_ids = settings
            .short_ids
            .iter()
            .map(|id| parse_short_id(id).map_err(|_| "reality short_id is invalid"))
            .collect::<Result<HashSet<_>, _>>()?;
        if settings.server_names.is_empty() {
            return Err("reality server_names are missing");
        }
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| "reality certificate key generation failed")?;
        let signer = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| "reality certificate key generation failed")?;
        let public: [u8; 32] = signer
            .public_key()
            .as_ref()
            .try_into()
            .map_err(|_| "reality certificate key generation failed")?;
        Ok(Self {
            inner,
            private_key: StaticSecret::from(private_key),
            short_ids,
            server_names: settings.server_names.iter().cloned().collect(),
            handshake: settings.handshake.target(),
            max_time_difference: settings.max_time_difference_secs,
            certificate: ed25519_certificate_template(&public),
            signer,
            alpn: ALPN.iter().map(|protocol| protocol.to_vec()).collect(),
        })
    }

    /// The X25519 public key clients configure (`publicKey` / `pbk`).
    pub fn public_key(&self) -> [u8; 32] {
        PublicKey::from(&self.private_key).to_bytes()
    }

    /// Returns the parsed ClientHello and auth key when `message` carries a
    /// valid REALITY marker.
    fn authenticate(&self, message: &[u8]) -> Option<(ClientHelloInfo, [u8; 32])> {
        let hello = parse_client_hello(message).ok()?;
        if !hello.tls13 || hello.session_id.len() != 32 {
            return None;
        }
        if !self.server_names.contains(hello.server_name.as_deref()?) {
            return None;
        }
        let shared = self
            .private_key
            .diffie_hellman(&PublicKey::from(hello.x25519_share?))
            .to_bytes();
        if shared.iter().all(|byte| *byte == 0) {
            return None;
        }
        let auth_key = derive_auth_key(&shared, &hello.random);
        let mut aad = message.to_vec();
        aad.get_mut(SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32)?
            .fill(0);
        let key =
            aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, &auth_key).ok()?);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&hello.random[20..32]);
        let mut sealed = hello.session_id.clone();
        let plaintext = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad.as_slice()),
                &mut sealed,
            )
            .ok()?;
        let short_id: [u8; 8] = plaintext[8..16].try_into().ok()?;
        if !self.short_ids.contains(&short_id) {
            return None;
        }
        if let Some(max) = self.max_time_difference {
            let client_time = u32::from_be_bytes(plaintext[4..8].try_into().ok()?) as u64;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs())
                .unwrap_or(0);
            if now.abs_diff(client_time) > max {
                return None;
            }
        }
        Some((hello, auth_key))
    }

    /// The temporary certificate bound to `auth_key`.
    fn certificate(&self, auth_key: &[u8; 32]) -> Vec<u8> {
        let mut certificate = self.certificate.clone();
        let mac = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA512, auth_key),
            self.signer.public_key().as_ref(),
        );
        let start = certificate.len() - 64;
        certificate[start..].copy_from_slice(mac.as_ref());
        certificate
    }
}

impl StreamInbound for RealityInbound {
    fn protocol(&self) -> &'static str {
        self.inner.protocol()
    }

    fn users(&self) -> &Arc<UserStore> {
        self.inner.users()
    }

    fn accept<'a>(
        &'a self,
        mut stream: BoxStream,
        _peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(async move {
            let mut consumed = Vec::new();
            let message = match read_client_hello(&mut stream, &mut consumed).await {
                Ok(message) => message,
                Err(_) => {
                    return fallback_or_hold(
                        Some(&self.handshake),
                        consumed,
                        stream,
                        "not a reality client",
                    )
                }
            };
            let Some((hello, auth_key)) = self.authenticate(&message) else {
                return fallback_or_hold(
                    Some(&self.handshake),
                    consumed,
                    stream,
                    "reality authentication failed",
                );
            };
            let chain = [self.certificate(&auth_key)];
            let identity = ServerIdentity {
                certificate_chain: &chain,
                signer: &self.signer,
                alpn: &self.alpn,
            };
            let tls = match accept(stream, &hello, &identity).await {
                Ok(tls) => tls,
                Err(_) => return Err(Rejected::close("reality tls handshake failed")),
            };
            self.inner.handshake_reality(tls).await
        })
    }
}
