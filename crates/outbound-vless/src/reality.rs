//! REALITY client authentication (Xray `transport/internet/reality`).
//!
//! The client hides an authenticated, encrypted marker in the ClientHello
//! session id:
//!
//! * `auth_key = HKDF-SHA256(ikm = X25519(client_ephemeral, server_public),
//!   salt = random[0..20], info = "REALITY")`
//! * session id plaintext = version (3 bytes), 0, unix time (u32 BE),
//!   short id (8 bytes)
//! * session id = AES-256-GCM(auth_key, nonce = random[20..32],
//!   aad = ClientHello with a zeroed session id)
//!
//! An authenticated server answers with a temporary Ed25519 certificate whose
//! signature field is `HMAC-SHA512(auth_key, ed25519_public_key)`. Any other
//! certificate means the connection was forwarded to the camouflage target,
//! and the client must not send proxy traffic.

use std::fmt;
use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use ring::{aead, hmac};
use tls_mimic::cert::{parse_leaf, OID_ED25519};
use tls_mimic::{Fingerprint, HandshakeHooks, HashAlg, HelloContext, SESSION_ID_OFFSET};

/// REALITY client parameters.
#[derive(Clone, PartialEq, Eq)]
pub struct RealityConfig {
    /// SNI; must be one of the server's `serverNames`.
    pub server_name: String,
    /// Server X25519 public key (`publicKey` / `pbk`).
    pub public_key: [u8; 32],
    /// Short id (`shortId` / `sid`), zero padded to 8 bytes.
    pub short_id: [u8; 8],
    pub fingerprint: Fingerprint,
    /// Client version reported to the server (Xray `x.y.z`).
    pub client_version: [u8; 3],
}

/// Version reported when the caller does not choose one.
pub const DEFAULT_CLIENT_VERSION: [u8; 3] = [25, 10, 15];

impl RealityConfig {
    pub fn new(server_name: impl Into<String>, public_key: [u8; 32], short_id: [u8; 8]) -> Self {
        Self {
            server_name: server_name.into(),
            public_key,
            short_id,
            fingerprint: Fingerprint::Chrome,
            client_version: DEFAULT_CLIENT_VERSION,
        }
    }
}

impl fmt::Debug for RealityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RealityConfig")
            .field("server_name", &self.server_name)
            .field("public_key", &"<set>")
            .field("short_id", &"<redacted>")
            .field("fingerprint", &self.fingerprint)
            .field("client_version", &self.client_version)
            .finish()
    }
}

/// Handshake hooks implementing the REALITY client side.
pub struct RealityHooks {
    public_key: [u8; 32],
    short_id: [u8; 8],
    client_version: [u8; 3],
    unix_time: Option<u32>,
    auth_key: Option<[u8; 32]>,
}

impl RealityHooks {
    pub fn new(config: &RealityConfig) -> Self {
        Self {
            public_key: config.public_key,
            short_id: config.short_id,
            client_version: config.client_version,
            unix_time: None,
            auth_key: None,
        }
    }

    /// Fixes the timestamp placed in the session id (tests only need this).
    pub fn with_unix_time(mut self, unix_time: u32) -> Self {
        self.unix_time = Some(unix_time);
        self
    }

    /// The derived authentication key, available after the ClientHello was
    /// built.
    pub fn auth_key(&self) -> Option<&[u8; 32]> {
        self.auth_key.as_ref()
    }
}

/// `HKDF-SHA256(shared, salt = random[..20], info = "REALITY")`.
pub fn derive_auth_key(shared: &[u8; 32], random: &[u8; 32]) -> [u8; 32] {
    let hash = HashAlg::Sha256;
    let prk = hash.hkdf_extract(&random[..20], shared);
    let okm = hash.hkdf_expand(&prk, b"REALITY", 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    key
}

/// Encrypts the 16-byte session id plaintext in place of bytes `39..71` of
/// the ClientHello handshake message.
pub fn seal_session_id(
    auth_key: &[u8; 32],
    random: &[u8; 32],
    plaintext: &[u8; 16],
    client_hello: &mut [u8],
) -> io::Result<()> {
    if client_hello.len() < SESSION_ID_OFFSET + 32 || client_hello[SESSION_ID_OFFSET - 1] != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ClientHello has no 32-byte session id",
        ));
    }
    client_hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].fill(0);
    let aad = client_hello.to_vec();
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, auth_key)
            .map_err(|_| io::Error::other("invalid REALITY auth key"))?,
    );
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&random[20..32]);
    let mut sealed = plaintext.to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::from(aad.as_slice()),
        &mut sealed,
    )
    .map_err(|_| io::Error::other("REALITY session id encryption failed"))?;
    client_hello[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32].copy_from_slice(&sealed);
    Ok(())
}

/// Checks the REALITY temporary certificate binding.
pub fn verify_temporary_certificate(auth_key: &[u8; 32], leaf_der: &[u8]) -> bool {
    let Some(leaf) = parse_leaf(leaf_der) else {
        return false;
    };
    if leaf.public_key_algorithm != OID_ED25519 || leaf.public_key.len() != 32 {
        return false;
    }
    let key = hmac::Key::new(hmac::HMAC_SHA512, auth_key);
    hmac::verify(&key, leaf.public_key, leaf.signature).is_ok()
}

impl HandshakeHooks for RealityHooks {
    fn edit_client_hello(&mut self, ctx: &HelloContext<'_>, message: &mut [u8]) -> io::Result<()> {
        let shared = ctx.x25519_shared(&self.public_key)?;
        let auth_key = derive_auth_key(&shared, ctx.random);
        let unix_time = self.unix_time.unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|elapsed| elapsed.as_secs() as u32)
                .unwrap_or(0)
        });
        let mut plaintext = [0u8; 16];
        plaintext[..3].copy_from_slice(&self.client_version);
        plaintext[4..8].copy_from_slice(&unix_time.to_be_bytes());
        plaintext[8..].copy_from_slice(&self.short_id);
        seal_session_id(&auth_key, ctx.random, &plaintext, message)?;
        self.auth_key = Some(auth_key);
        Ok(())
    }

    fn verify_server_certificates(
        &mut self,
        _server_name: &str,
        chain: &[Vec<u8>],
    ) -> io::Result<()> {
        let auth_key = self
            .auth_key
            .ok_or_else(|| io::Error::other("REALITY auth key missing"))?;
        match chain.first() {
            Some(leaf) if verify_temporary_certificate(&auth_key, leaf) => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "REALITY server authentication failed",
            )),
        }
    }
}
