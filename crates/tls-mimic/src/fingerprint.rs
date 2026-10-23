//! Browser-shaped ClientHello construction (uTLS-like).
//!
//! A [`Fingerprint`] expands to a [`ClientHelloSpec`]: cipher suites, the
//! ordered extension list and which parts are randomized per connection
//! (GREASE values, extension permutation, ECH GREASE payload). The encoder
//! then produces the exact handshake message bytes.

use std::io;

use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{fill_random, invalid_data, random_u32};

pub const GROUP_X25519: u16 = 0x001d;
pub const GROUP_SECP256R1: u16 = 0x0017;
pub const GROUP_SECP384R1: u16 = 0x0018;
pub const GROUP_X25519_MLKEM768: u16 = 0x11ec;

const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1184;

/// Offset of the 32-byte legacy session id inside the encoded ClientHello
/// handshake message (4-byte header, version, random, length octet).
pub const SESSION_ID_OFFSET: usize = 39;

/// Supported browser fingerprints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Fingerprint {
    /// Current desktop Chrome: GREASE, permuted extensions, X25519MLKEM768 +
    /// X25519 key shares, ECH GREASE and the new ALPS code point.
    #[default]
    Chrome,
    /// The same Chrome shape without the post-quantum hybrid group, for
    /// servers or middleboxes that cannot handle a large ClientHello.
    ChromeNoPq,
}

impl Fingerprint {
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "chrome" | "chrome-pq" => Some(Fingerprint::Chrome),
            "chrome-nopq" | "chrome-no-pq" | "chrome120" => Some(Fingerprint::ChromeNoPq),
            _ => None,
        }
    }

    pub fn spec(self) -> ClientHelloSpec {
        let post_quantum = matches!(self, Fingerprint::Chrome);
        let mut groups = vec![NamedGroup::Grease];
        if post_quantum {
            groups.push(NamedGroup::Named(GROUP_X25519_MLKEM768));
        }
        groups.extend([
            NamedGroup::Named(GROUP_X25519),
            NamedGroup::Named(GROUP_SECP256R1),
            NamedGroup::Named(GROUP_SECP384R1),
        ]);
        let mut key_shares = vec![NamedGroup::Grease];
        if post_quantum {
            key_shares.push(NamedGroup::Named(GROUP_X25519_MLKEM768));
        }
        key_shares.push(NamedGroup::Named(GROUP_X25519));

        ClientHelloSpec {
            cipher_suites: vec![
                CipherSuiteEntry::Grease,
                CipherSuiteEntry::Id(0x1301),
                CipherSuiteEntry::Id(0x1302),
                CipherSuiteEntry::Id(0x1303),
                CipherSuiteEntry::Id(0xc02b),
                CipherSuiteEntry::Id(0xc02f),
                CipherSuiteEntry::Id(0xc02c),
                CipherSuiteEntry::Id(0xc030),
                CipherSuiteEntry::Id(0xcca9),
                CipherSuiteEntry::Id(0xcca8),
                CipherSuiteEntry::Id(0xc013),
                CipherSuiteEntry::Id(0xc014),
                CipherSuiteEntry::Id(0x009c),
                CipherSuiteEntry::Id(0x009d),
                CipherSuiteEntry::Id(0x002f),
                CipherSuiteEntry::Id(0x0035),
            ],
            extensions: vec![
                Extension::Grease,
                Extension::ServerName,
                Extension::ExtendedMasterSecret,
                Extension::RenegotiationInfo,
                Extension::SupportedGroups(groups),
                Extension::EcPointFormats,
                Extension::SessionTicket,
                Extension::Alpn,
                Extension::StatusRequest,
                Extension::SignatureAlgorithms(vec![
                    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
                ]),
                Extension::SignedCertificateTimestamp,
                Extension::KeyShare(key_shares),
                Extension::PskKeyExchangeModes,
                Extension::SupportedVersions,
                Extension::CompressCertificate,
                Extension::ApplicationSettings(0x44cd),
                Extension::EchGrease,
                Extension::GreaseOneByte,
            ],
            permute_extensions: true,
            default_alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CipherSuiteEntry {
    Grease,
    Id(u16),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamedGroup {
    Grease,
    Named(u16),
}

/// ClientHello extensions in the order a fingerprint lists them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Extension {
    /// Empty GREASE extension (BoringSSL's first GREASE extension).
    Grease,
    /// GREASE extension with one zero byte (BoringSSL's last GREASE extension).
    GreaseOneByte,
    ServerName,
    ExtendedMasterSecret,
    RenegotiationInfo,
    SupportedGroups(Vec<NamedGroup>),
    EcPointFormats,
    SessionTicket,
    Alpn,
    StatusRequest,
    SignatureAlgorithms(Vec<u16>),
    SignedCertificateTimestamp,
    KeyShare(Vec<NamedGroup>),
    PskKeyExchangeModes,
    SupportedVersions,
    CompressCertificate,
    /// ALPS with the given extension code point (0x4469 old, 0x44cd new).
    ApplicationSettings(u16),
    EchGrease,
}

impl Extension {
    fn is_grease(&self) -> bool {
        matches!(self, Extension::Grease | Extension::GreaseOneByte)
    }
}

#[derive(Clone, Debug)]
pub struct ClientHelloSpec {
    pub cipher_suites: Vec<CipherSuiteEntry>,
    pub extensions: Vec<Extension>,
    /// Chrome permutes all non-GREASE extensions on every connection.
    pub permute_extensions: bool,
    pub default_alpn: Vec<Vec<u8>>,
}

/// Ephemeral key material behind the key_share extension.
pub struct KeyShareSecrets {
    pub(crate) x25519: StaticSecret,
    pub(crate) mlkem768: Option<MlKemShare>,
}

pub(crate) struct MlKemShare {
    pub(crate) decapsulation: <MlKem768 as KemCore>::DecapsulationKey,
    pub(crate) encapsulation: Vec<u8>,
}

impl KeyShareSecrets {
    fn generate(with_mlkem: bool) -> Self {
        let mut rng = rand_core::OsRng;
        let x25519 = StaticSecret::random_from_rng(rng);
        let mlkem768 = with_mlkem.then(|| {
            let (decapsulation, encapsulation) = MlKem768::generate(&mut rng);
            MlKemShare {
                decapsulation,
                encapsulation: encapsulation.as_bytes().as_slice().to_vec(),
            }
        });
        Self { x25519, mlkem768 }
    }

    pub fn x25519_public(&self) -> [u8; 32] {
        PublicKey::from(&self.x25519).to_bytes()
    }

    /// X25519 with the client's ephemeral key. Fails on an all-zero output.
    pub fn x25519_shared(&self, peer_public: &[u8; 32]) -> io::Result<[u8; 32]> {
        let shared = self
            .x25519
            .diffie_hellman(&PublicKey::from(*peer_public))
            .to_bytes();
        if shared.iter().all(|byte| *byte == 0) {
            return Err(invalid_data(
                "X25519 produced a non-contributory shared secret",
            ));
        }
        Ok(shared)
    }
}

/// An encoded ClientHello plus the secrets needed to finish the handshake.
pub struct ClientHello {
    /// Handshake message bytes (type, 24-bit length, body).
    pub message: Vec<u8>,
    pub random: [u8; 32],
    pub secrets: KeyShareSecrets,
    /// ALPN protocols that were offered, in order.
    pub alpn: Vec<Vec<u8>>,
}

struct GreaseValues {
    cipher: u16,
    group: u16,
    extension_first: u16,
    extension_last: u16,
    version: u16,
}

fn grease_value(seed: u32) -> u16 {
    let nibble = (seed % 16) as u16;
    (nibble << 12) | 0x0a00 | (nibble << 4) | 0x0a
}

impl GreaseValues {
    fn generate() -> io::Result<Self> {
        let mut seeds = [0u8; 5];
        fill_random(&mut seeds)?;
        let extension_first = grease_value(seeds[2] as u32);
        let mut extension_last = grease_value(seeds[3] as u32);
        if extension_last == extension_first {
            extension_last ^= 0x1010;
        }
        Ok(Self {
            cipher: grease_value(seeds[0] as u32),
            group: grease_value(seeds[1] as u32),
            extension_first,
            extension_last,
            version: grease_value(seeds[4] as u32),
        })
    }
}

/// Builds a ClientHello for `server_name` with the given fingerprint.
///
/// `server_name` is sent as SNI unless it is an IP literal. `alpn` overrides
/// the fingerprint's default ALPN list when present.
pub fn build_client_hello(
    fingerprint: Fingerprint,
    server_name: &str,
    alpn: Option<&[Vec<u8>]>,
) -> io::Result<ClientHello> {
    let spec = fingerprint.spec();
    build_from_spec(&spec, server_name, alpn)
}

pub fn build_from_spec(
    spec: &ClientHelloSpec,
    server_name: &str,
    alpn: Option<&[Vec<u8>]>,
) -> io::Result<ClientHello> {
    let grease = GreaseValues::generate()?;
    let with_mlkem = spec.extensions.iter().any(|extension| {
        matches!(extension, Extension::KeyShare(groups)
            if groups.contains(&NamedGroup::Named(GROUP_X25519_MLKEM768)))
    });
    let secrets = KeyShareSecrets::generate(with_mlkem);
    let alpn: Vec<Vec<u8>> = alpn
        .map(|protocols| protocols.to_vec())
        .unwrap_or_else(|| spec.default_alpn.clone());

    let mut random = [0u8; 32];
    fill_random(&mut random)?;
    let mut session_id = [0u8; 32];
    fill_random(&mut session_id)?;

    let mut extensions = spec.extensions.clone();
    if spec.permute_extensions {
        permute_middle(&mut extensions)?;
    }
    let sni_allowed = server_name.parse::<std::net::IpAddr>().is_err() && !server_name.is_empty();

    let mut encoded_extensions = Vec::with_capacity(2048);
    let mut first_grease_used = false;
    for extension in &extensions {
        if matches!(extension, Extension::ServerName) && !sni_allowed {
            continue;
        }
        if matches!(extension, Extension::Alpn) && alpn.is_empty() {
            continue;
        }
        let ext_type = match extension {
            Extension::Grease | Extension::GreaseOneByte => {
                if first_grease_used {
                    grease.extension_last
                } else {
                    first_grease_used = true;
                    grease.extension_first
                }
            }
            other => extension_type(other),
        };
        let body = encode_extension(extension, &grease, &secrets, server_name, &alpn)?;
        put_u16(&mut encoded_extensions, ext_type);
        put_u16(&mut encoded_extensions, body.len() as u16);
        encoded_extensions.extend_from_slice(&body);
    }

    let mut body = Vec::with_capacity(512 + encoded_extensions.len());
    put_u16(&mut body, 0x0303);
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(&session_id);
    let suites: Vec<u16> = spec
        .cipher_suites
        .iter()
        .map(|entry| match entry {
            CipherSuiteEntry::Grease => grease.cipher,
            CipherSuiteEntry::Id(id) => *id,
        })
        .collect();
    put_u16(&mut body, (suites.len() * 2) as u16);
    for suite in suites {
        put_u16(&mut body, suite);
    }
    body.extend_from_slice(&[1, 0]);
    put_u16(&mut body, encoded_extensions.len() as u16);
    body.extend_from_slice(&encoded_extensions);

    let mut message = Vec::with_capacity(4 + body.len());
    message.push(1);
    put_u24(&mut message, body.len());
    message.extend_from_slice(&body);

    Ok(ClientHello {
        message,
        random,
        secrets,
        alpn,
    })
}

/// Fisher-Yates shuffle of every extension except the GREASE bookends.
fn permute_middle(extensions: &mut [Extension]) -> io::Result<()> {
    let movable: Vec<usize> = extensions
        .iter()
        .enumerate()
        .filter(|(_, extension)| !extension.is_grease())
        .map(|(index, _)| index)
        .collect();
    let mut items: Vec<Extension> = movable.iter().map(|&i| extensions[i].clone()).collect();
    for i in (1..items.len()).rev() {
        let j = (random_u32()? as usize) % (i + 1);
        items.swap(i, j);
    }
    for (slot, item) in movable.into_iter().zip(items) {
        extensions[slot] = item;
    }
    Ok(())
}

fn extension_type(extension: &Extension) -> u16 {
    match extension {
        Extension::Grease | Extension::GreaseOneByte => 0,
        Extension::ServerName => 0x0000,
        Extension::ExtendedMasterSecret => 0x0017,
        Extension::RenegotiationInfo => 0xff01,
        Extension::SupportedGroups(_) => 0x000a,
        Extension::EcPointFormats => 0x000b,
        Extension::SessionTicket => 0x0023,
        Extension::Alpn => 0x0010,
        Extension::StatusRequest => 0x0005,
        Extension::SignatureAlgorithms(_) => 0x000d,
        Extension::SignedCertificateTimestamp => 0x0012,
        Extension::KeyShare(_) => 0x0033,
        Extension::PskKeyExchangeModes => 0x002d,
        Extension::SupportedVersions => 0x002b,
        Extension::CompressCertificate => 0x001b,
        Extension::ApplicationSettings(code_point) => *code_point,
        Extension::EchGrease => 0xfe0d,
    }
}

fn encode_extension(
    extension: &Extension,
    grease: &GreaseValues,
    secrets: &KeyShareSecrets,
    server_name: &str,
    alpn: &[Vec<u8>],
) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    match extension {
        Extension::Grease
        | Extension::ExtendedMasterSecret
        | Extension::SessionTicket
        | Extension::SignedCertificateTimestamp => {}
        Extension::GreaseOneByte => out.push(0),
        Extension::ServerName => {
            let name = server_name.as_bytes();
            put_u16(&mut out, (name.len() + 3) as u16);
            out.push(0);
            put_u16(&mut out, name.len() as u16);
            out.extend_from_slice(name);
        }
        Extension::RenegotiationInfo => out.push(0),
        Extension::SupportedGroups(groups) => {
            put_u16(&mut out, (groups.len() * 2) as u16);
            for group in groups {
                put_u16(&mut out, resolve_group(group, grease));
            }
        }
        Extension::EcPointFormats => out.extend_from_slice(&[1, 0]),
        Extension::Alpn => {
            let mut list = Vec::new();
            for protocol in alpn {
                if protocol.is_empty() || protocol.len() > 255 {
                    return Err(invalid_data("invalid ALPN protocol name"));
                }
                list.push(protocol.len() as u8);
                list.extend_from_slice(protocol);
            }
            put_u16(&mut out, list.len() as u16);
            out.extend_from_slice(&list);
        }
        Extension::StatusRequest => out.extend_from_slice(&[1, 0, 0, 0, 0]),
        Extension::SignatureAlgorithms(schemes) => {
            put_u16(&mut out, (schemes.len() * 2) as u16);
            for scheme in schemes {
                put_u16(&mut out, *scheme);
            }
        }
        Extension::KeyShare(groups) => {
            let mut shares = Vec::new();
            for group in groups {
                let id = resolve_group(group, grease);
                let data: Vec<u8> = match group {
                    NamedGroup::Grease => vec![0],
                    NamedGroup::Named(GROUP_X25519) => secrets.x25519_public().to_vec(),
                    NamedGroup::Named(GROUP_X25519_MLKEM768) => {
                        let share = secrets
                            .mlkem768
                            .as_ref()
                            .ok_or_else(|| invalid_data("missing ML-KEM key"))?;
                        if share.encapsulation.len() != MLKEM768_ENCAPSULATION_KEY_LEN {
                            return Err(invalid_data("unexpected ML-KEM-768 key length"));
                        }
                        let mut data = Vec::with_capacity(MLKEM768_ENCAPSULATION_KEY_LEN + 32);
                        data.extend_from_slice(&share.encapsulation);
                        data.extend_from_slice(&secrets.x25519_public());
                        data
                    }
                    NamedGroup::Named(_) => {
                        return Err(invalid_data("unsupported key share group in fingerprint"))
                    }
                };
                put_u16(&mut shares, id);
                put_u16(&mut shares, data.len() as u16);
                shares.extend_from_slice(&data);
            }
            put_u16(&mut out, shares.len() as u16);
            out.extend_from_slice(&shares);
        }
        Extension::PskKeyExchangeModes => out.extend_from_slice(&[1, 1]),
        Extension::SupportedVersions => {
            out.push(6);
            put_u16(&mut out, grease.version);
            put_u16(&mut out, 0x0304);
            put_u16(&mut out, 0x0303);
        }
        Extension::CompressCertificate => out.extend_from_slice(&[2, 0, 2]),
        Extension::ApplicationSettings(_) => out.extend_from_slice(&[0, 3, 2, b'h', b'2']),
        Extension::EchGrease => {
            // ECHClientHello(outer) with HPKE X25519/HKDF-SHA256/AES-128-GCM
            // and a random config id, encapsulated key and payload, matching
            // BoringSSL's GREASE ECH.
            const PAYLOAD_LENS: [usize; 4] = [144, 176, 208, 240];
            let mut seed = [0u8; 2];
            fill_random(&mut seed)?;
            let payload_len = PAYLOAD_LENS[(seed[1] % 4) as usize];
            out.push(0);
            put_u16(&mut out, 0x0001);
            put_u16(&mut out, 0x0001);
            out.push(seed[0]);
            let mut enc = [0u8; 32];
            fill_random(&mut enc)?;
            put_u16(&mut out, 32);
            out.extend_from_slice(&enc);
            let mut payload = vec![0u8; payload_len];
            fill_random(&mut payload)?;
            put_u16(&mut out, payload_len as u16);
            out.extend_from_slice(&payload);
        }
    }
    Ok(out)
}

fn resolve_group(group: &NamedGroup, grease: &GreaseValues) -> u16 {
    match group {
        NamedGroup::Grease => grease.group,
        NamedGroup::Named(id) => *id,
    }
}

pub(crate) fn put_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_u24(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&[(value >> 16) as u8, (value >> 8) as u8, value as u8]);
}

/// True for the sixteen reserved GREASE code points (RFC 8701).
pub fn is_grease(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a && (value >> 8) == (value & 0xff)
}
