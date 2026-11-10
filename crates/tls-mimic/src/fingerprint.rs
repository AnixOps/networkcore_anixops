//! Browser-shaped ClientHello construction (uTLS-like).
//!
//! A [`Fingerprint`] names a [`ClientHelloSpec`]: cipher suites, the ordered
//! extension list and which parts are randomized per connection (GREASE
//! values, extension permutation, ECH GREASE payload). The encoder then
//! produces the exact handshake message bytes.
//!
//! The specs are data. The built-in ones are the JSON files under
//! `fingerprints/` (format in [`crate::profile`]); [`install_profiles`]
//! replaces them at run time with a delivered bundle, so following a new
//! browser release does not need a new build.

use std::io;
use std::sync::{Arc, OnceLock, RwLock};

use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{fill_random, invalid_data, random_u32};
use crate::profile;

pub const GROUP_X25519: u16 = 0x001d;
pub const GROUP_SECP256R1: u16 = 0x0017;
pub const GROUP_SECP384R1: u16 = 0x0018;
pub const GROUP_X25519_MLKEM768: u16 = 0x11ec;

const MLKEM768_ENCAPSULATION_KEY_LEN: usize = 1184;

const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_SCT: u16 = 0x0012;
const EXT_PADDING: u16 = 0x0015;
const EXT_EXTENDED_MASTER_SECRET: u16 = 0x0017;
const EXT_COMPRESS_CERTIFICATE: u16 = 0x001b;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_ECH: u16 = 0xfe0d;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// Offset of the 32-byte legacy session id inside the encoded ClientHello
/// handshake message (4-byte header, version, random, length octet).
pub const SESSION_ID_OFFSET: usize = 39;

/// Supported browser fingerprints.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Fingerprint {
    /// Current desktop Chrome: GREASE, permuted extensions, X25519MLKEM768 +
    /// X25519 key shares, ECH GREASE, the new ALPS code point, and (Chrome 157,
    /// checked against Chrome for Testing 157.0.8103.38) a GREASE signature
    /// scheme followed by ML-DSA-44/65/87 at the front of signature_algorithms.
    #[default]
    Chrome,
    /// The same Chrome shape without the post-quantum hybrid group, for
    /// servers or middleboxes that cannot handle a large ClientHello.
    ChromeNoPq,
    /// Safari and every other client of Apple's network stack (NSURLSession)
    /// on iOS and macOS: fixed extension order, X25519MLKEM768 + X25519 key
    /// shares, zlib certificate compression, no ALPS, no ECH GREASE. Captured
    /// from Safari 26.6.2 on macOS 26.7.2.
    Safari,
}

impl Fingerprint {
    pub const ALL: [Fingerprint; 3] = [
        Fingerprint::Chrome,
        Fingerprint::ChromeNoPq,
        Fingerprint::Safari,
    ];

    /// Resolves a configured name. `auto` is [`Fingerprint::platform_default`].
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "chrome" | "chrome-pq" => Some(Fingerprint::Chrome),
            "chrome-nopq" | "chrome-no-pq" | "chrome120" => Some(Fingerprint::ChromeNoPq),
            "safari" | "ios" | "apple" => Some(Fingerprint::Safari),
            "auto" => Some(Fingerprint::platform_default()),
            _ => None,
        }
    }

    /// The canonical name, also the key of this fingerprint in a bundle.
    pub fn name(self) -> &'static str {
        match self {
            Fingerprint::Chrome => "chrome",
            Fingerprint::ChromeNoPq => "chrome-nopq",
            Fingerprint::Safari => "safari",
        }
    }

    /// The fingerprint that fits the platform this build runs on: on iOS and
    /// macOS the system network stack speaks the Safari shape, so a Chrome
    /// ClientHello from a device whose TCP/IP stack is Apple's stands out;
    /// everywhere else Chrome is the common browser.
    pub fn platform_default() -> Self {
        if cfg!(target_vendor = "apple") {
            Fingerprint::Safari
        } else {
            Fingerprint::Chrome
        }
    }

    fn index(self) -> usize {
        match self {
            Fingerprint::Chrome => 0,
            Fingerprint::ChromeNoPq => 1,
            Fingerprint::Safari => 2,
        }
    }

    fn builtin_json(self) -> &'static str {
        match self {
            Fingerprint::Chrome => include_str!("../fingerprints/chrome.json"),
            Fingerprint::ChromeNoPq => include_str!("../fingerprints/chrome-nopq.json"),
            Fingerprint::Safari => include_str!("../fingerprints/safari.json"),
        }
    }

    /// The spec compiled into this build.
    pub fn builtin_spec(self) -> io::Result<Arc<ClientHelloSpec>> {
        static BUILTIN: [OnceLock<Arc<ClientHelloSpec>>; 3] =
            [OnceLock::new(), OnceLock::new(), OnceLock::new()];
        let slot = &BUILTIN[self.index()];
        if let Some(spec) = slot.get() {
            return Ok(spec.clone());
        }
        let spec = Arc::new(ClientHelloSpec::from_json(self.builtin_json())?);
        Ok(slot.get_or_init(|| spec).clone())
    }

    /// The spec in effect: the installed profile if a bundle replaced this
    /// fingerprint, the built-in one otherwise.
    pub fn spec(self) -> io::Result<Arc<ClientHelloSpec>> {
        let installed = {
            let overrides = OVERRIDES
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            overrides.specs[self.index()].clone()
        };
        match installed {
            Some(spec) => Ok(spec),
            None => self.builtin_spec(),
        }
    }
}

/// The installed bundle: one slot per fingerprint, `None` = built-in.
struct Overrides {
    revision: String,
    specs: [Option<Arc<ClientHelloSpec>>; 3],
}

static OVERRIDES: RwLock<Overrides> = RwLock::new(Overrides {
    revision: String::new(),
    specs: [None, None, None],
});

/// What [`install_profiles`] did with a bundle.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InstalledProfiles {
    /// The bundle's `revision` string (empty if it has none).
    pub revision: String,
    /// Fingerprints now served from the bundle.
    pub replaced: Vec<Fingerprint>,
    /// Profile names this build does not know; they are skipped so a bundle
    /// can carry profiles for newer builds.
    pub ignored: Vec<String>,
}

/// Installs a fingerprint bundle for this process:
///
/// ```json
/// { "format": 1, "revision": "2026-11-10", "profiles": { "chrome": { ... }, "safari": { ... } } }
/// ```
///
/// Each profile has the layout of the files under `fingerprints/`. The bundle
/// is the whole override state: fingerprints it does not name go back to
/// their built-in spec. Nothing changes unless every known profile in the
/// bundle parses and validates, so a bad bundle leaves the previous state in
/// place. Connections opened afterwards use the new specs.
pub fn install_profiles(json: &str) -> io::Result<InstalledProfiles> {
    let bundle = profile::parse_bundle(json)?;
    let mut table: [Option<Arc<ClientHelloSpec>>; 3] = [None, None, None];
    let mut report = InstalledProfiles {
        revision: bundle.revision,
        ..InstalledProfiles::default()
    };
    for (name, value) in &bundle.profiles {
        let known = Fingerprint::ALL
            .into_iter()
            .find(|fingerprint| fingerprint.name() == name.as_str());
        match known {
            Some(fingerprint) => {
                let spec = profile::spec_from_value(value).map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("profile {name}: {error}"),
                    )
                })?;
                table[fingerprint.index()] = Some(Arc::new(spec));
                report.replaced.push(fingerprint);
            }
            None => report.ignored.push(name.clone()),
        }
    }
    *OVERRIDES
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Overrides {
        revision: report.revision.clone(),
        specs: table,
    };
    Ok(report)
}

/// The bundle in effect: its revision and the fingerprints it replaces
/// (`ignored` is always empty here).
pub fn installed_profiles() -> InstalledProfiles {
    let overrides = OVERRIDES
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    InstalledProfiles {
        revision: overrides.revision.clone(),
        replaced: Fingerprint::ALL
            .into_iter()
            .filter(|fingerprint| overrides.specs[fingerprint.index()].is_some())
            .collect(),
        ignored: Vec::new(),
    }
}

/// Drops every installed profile; all fingerprints use their built-in spec.
pub fn clear_profiles() {
    *OVERRIDES
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Overrides {
        revision: String::new(),
        specs: [None, None, None],
    };
}

/// A list entry that is either a fixed code point or a GREASE value drawn
/// per connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code {
    Grease,
    Value(u16),
}

/// ClientHello extensions in the order a fingerprint lists them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Extension {
    /// GREASE extension with the given body (BoringSSL: the first one is
    /// empty, the last one carries a single zero byte).
    Grease {
        body: Vec<u8>,
    },
    ServerName,
    ExtendedMasterSecret,
    RenegotiationInfo,
    SupportedGroups(Vec<Code>),
    EcPointFormats(Vec<u8>),
    SessionTicket,
    Alpn,
    StatusRequest,
    SignatureAlgorithms(Vec<Code>),
    SignedCertificateTimestamp,
    KeyShare(Vec<Code>),
    PskKeyExchangeModes(Vec<u8>),
    SupportedVersions(Vec<Code>),
    /// Certificate compression algorithms (1 zlib, 2 brotli, 3 zstd).
    CompressCertificate(Vec<u16>),
    /// ALPS with the given extension code point (0x4469 old, 0x44cd new).
    ApplicationSettings {
        code_point: u16,
        protocols: Vec<Vec<u8>>,
    },
    EchGrease,
    /// BoringSSL-style padding: present only when the ClientHello would
    /// otherwise be 256 to 511 bytes long, and then pads it to 512.
    Padding,
    /// Any other extension with a fixed body.
    Raw {
        id: u16,
        body: Vec<u8>,
    },
}

impl Extension {
    /// Extensions that stay in place when the others are permuted.
    fn is_pinned(&self) -> bool {
        matches!(self, Extension::Grease { .. } | Extension::Padding)
    }

    /// The code point on the wire; `None` for GREASE, which gets a fresh one.
    fn wire_type(&self) -> Option<u16> {
        Some(match self {
            Extension::Grease { .. } => return None,
            Extension::ServerName => EXT_SERVER_NAME,
            Extension::ExtendedMasterSecret => EXT_EXTENDED_MASTER_SECRET,
            Extension::RenegotiationInfo => EXT_RENEGOTIATION_INFO,
            Extension::SupportedGroups(_) => EXT_SUPPORTED_GROUPS,
            Extension::EcPointFormats(_) => EXT_EC_POINT_FORMATS,
            Extension::SessionTicket => EXT_SESSION_TICKET,
            Extension::Alpn => EXT_ALPN,
            Extension::StatusRequest => EXT_STATUS_REQUEST,
            Extension::SignatureAlgorithms(_) => EXT_SIGNATURE_ALGORITHMS,
            Extension::SignedCertificateTimestamp => EXT_SCT,
            Extension::KeyShare(_) => EXT_KEY_SHARE,
            Extension::PskKeyExchangeModes(_) => EXT_PSK_KEY_EXCHANGE_MODES,
            Extension::SupportedVersions(_) => EXT_SUPPORTED_VERSIONS,
            Extension::CompressCertificate(_) => EXT_COMPRESS_CERTIFICATE,
            Extension::ApplicationSettings { code_point, .. } => *code_point,
            Extension::EchGrease => EXT_ECH,
            Extension::Padding => EXT_PADDING,
            Extension::Raw { id, .. } => *id,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHelloSpec {
    pub cipher_suites: Vec<Code>,
    pub extensions: Vec<Extension>,
    /// Chrome permutes all non-GREASE extensions on every connection.
    pub permute_extensions: bool,
    pub default_alpn: Vec<Vec<u8>>,
}

impl ClientHelloSpec {
    /// Parses one profile (the layout of the files under `fingerprints/`)
    /// and validates it.
    pub fn from_json(json: &str) -> io::Result<Self> {
        profile::spec_from_value(&profile::parse_document(json)?)
    }

    /// The profile as JSON; [`ClientHelloSpec::from_json`] reads it back.
    pub fn to_json(&self) -> String {
        profile::spec_to_value(self).to_string()
    }

    /// Whether the spec offers `psk_dhe_ke`, the only PSK mode this client
    /// resumes with.
    pub fn offers_psk_dhe_ke(&self) -> bool {
        self.extensions.iter().any(|extension| {
            matches!(extension, Extension::PskKeyExchangeModes(modes) if modes.contains(&1))
        })
    }

    fn key_share_groups(&self) -> &[Code] {
        self.extensions
            .iter()
            .find_map(|extension| match extension {
                Extension::KeyShare(groups) => Some(groups.as_slice()),
                _ => None,
            })
            .unwrap_or(&[])
    }

    /// Checks that this client can send the spec and finish a handshake that
    /// starts with it: a TLS 1.3 offer with a suite and an X25519 key share
    /// this crate implements, and no extension listed twice.
    pub fn validate(&self) -> io::Result<()> {
        if self.cipher_suites.is_empty() {
            return Err(invalid_data("fingerprint lists no cipher suites"));
        }
        if !self
            .cipher_suites
            .iter()
            .any(|suite| matches!(suite, Code::Value(0x1301..=0x1303)))
        {
            return Err(invalid_data(
                "fingerprint offers no TLS 1.3 cipher suite this client implements",
            ));
        }
        let mut seen: Vec<u16> = Vec::new();
        let mut groups: &[Code] = &[];
        let mut versions: &[Code] = &[];
        let mut has_signature_algorithms = false;
        for extension in &self.extensions {
            let Some(wire_type) = extension.wire_type() else {
                continue;
            };
            if is_grease(wire_type) {
                return Err(invalid_data(
                    "fingerprint uses a GREASE code point as a fixed extension",
                ));
            }
            if seen.contains(&wire_type) {
                return Err(invalid_data("fingerprint lists an extension twice"));
            }
            seen.push(wire_type);
            match extension {
                Extension::SupportedGroups(list) => groups = list,
                Extension::SupportedVersions(list) => versions = list,
                Extension::SignatureAlgorithms(list) => has_signature_algorithms = !list.is_empty(),
                Extension::ApplicationSettings { protocols, .. } if protocols.is_empty() => {
                    return Err(invalid_data("fingerprint has ALPS without protocols"));
                }
                _ => {}
            }
        }
        if !versions.contains(&Code::Value(0x0304)) {
            return Err(invalid_data("fingerprint does not offer TLS 1.3"));
        }
        if !has_signature_algorithms {
            return Err(invalid_data("fingerprint lists no signature algorithms"));
        }
        let shares = self.key_share_groups();
        if !shares.contains(&Code::Value(GROUP_X25519)) {
            return Err(invalid_data("fingerprint has no X25519 key share"));
        }
        for share in shares {
            match share {
                Code::Grease | Code::Value(GROUP_X25519 | GROUP_X25519_MLKEM768) => {}
                Code::Value(_) => {
                    return Err(invalid_data(
                        "fingerprint has a key share for a group this client does not implement",
                    ))
                }
            }
            if !groups.contains(share) {
                return Err(invalid_data(
                    "fingerprint has a key share for a group missing from supported_groups",
                ));
            }
        }
        if self
            .default_alpn
            .iter()
            .any(|protocol| protocol.is_empty() || protocol.len() > 255)
        {
            return Err(invalid_data("invalid ALPN protocol name"));
        }
        Ok(())
    }
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
    /// Length of the PSK binders list at the very end of `message` (its
    /// two-byte length included); 0 when no pre_shared_key is offered. The
    /// binders are zero until the handshake fills them in.
    pub psk_binders_len: usize,
}

/// The pre_shared_key extension to add to a ClientHello: one identity with
/// its obfuscated age and room for one binder of `binder_len` bytes.
#[derive(Clone, Copy, Debug)]
pub struct PskShape<'a> {
    pub identity: &'a [u8],
    pub obfuscated_age: u32,
    pub binder_len: usize,
}

struct GreaseValues {
    cipher: u16,
    group: u16,
    extension_first: u16,
    extension_last: u16,
    version: u16,
    signature: u16,
}

fn grease_value(seed: u32) -> u16 {
    let nibble = (seed % 16) as u16;
    (nibble << 12) | 0x0a00 | (nibble << 4) | 0x0a
}

impl GreaseValues {
    fn generate() -> io::Result<Self> {
        let mut seeds = [0u8; 6];
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
            signature: grease_value(seeds[5] as u32),
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
    let spec = fingerprint.spec()?;
    build_from_spec(&spec, server_name, alpn)
}

pub fn build_from_spec(
    spec: &ClientHelloSpec,
    server_name: &str,
    alpn: Option<&[Vec<u8>]>,
) -> io::Result<ClientHello> {
    build_from_spec_with_psk(spec, server_name, alpn, None)
}

/// [`build_from_spec`] with an optional pre_shared_key extension. It is
/// always the last extension (RFC 8446 §4.2.11), after GREASE and padding,
/// and counts towards the length padding looks at, as in BoringSSL. The
/// binder is left zero: it covers the rest of the message, so it is computed
/// once nothing else changes.
pub fn build_from_spec_with_psk(
    spec: &ClientHelloSpec,
    server_name: &str,
    alpn: Option<&[Vec<u8>]>,
    psk: Option<PskShape<'_>>,
) -> io::Result<ClientHello> {
    spec.validate()?;
    let psk_body = psk
        .map(|psk| encode_pre_shared_key(spec, psk))
        .transpose()?;
    let psk_binders_len = psk.map_or(0, |psk| psk.binder_len + 3);
    let grease = GreaseValues::generate()?;
    let with_mlkem = spec
        .key_share_groups()
        .contains(&Code::Value(GROUP_X25519_MLKEM768));
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

    // Everything except padding is encoded first; padding depends on the
    // length of the rest and goes back into the slot the spec gives it.
    let mut encoded: Vec<(u16, Vec<u8>)> = Vec::with_capacity(extensions.len());
    let mut padding_slot = None;
    let mut first_grease_used = false;
    for extension in &extensions {
        match extension {
            Extension::ServerName if !sni_allowed => continue,
            Extension::Alpn if alpn.is_empty() => continue,
            Extension::Padding => {
                padding_slot = Some(encoded.len());
                continue;
            }
            _ => {}
        }
        let ext_type = match extension.wire_type() {
            Some(wire_type) => wire_type,
            None if first_grease_used => grease.extension_last,
            None => {
                first_grease_used = true;
                grease.extension_first
            }
        };
        let body = encode_extension(extension, &grease, &secrets, server_name, &alpn)?;
        if body.len() > usize::from(u16::MAX) {
            return Err(invalid_data("ClientHello extension too large"));
        }
        encoded.push((ext_type, body));
    }

    let suites: Vec<u16> = spec
        .cipher_suites
        .iter()
        .map(|entry| match entry {
            Code::Grease => grease.cipher,
            Code::Value(id) => *id,
        })
        .collect();

    if let Some(slot) = padding_slot {
        // Handshake header, version, random, session id, suites, compression
        // methods and the extensions length field, then the extensions.
        let extensions_len: usize = encoded
            .iter()
            .map(|(_, body)| 4 + body.len())
            .sum::<usize>()
            + psk_body.as_ref().map_or(0, |body| 4 + body.len());
        let unpadded = 4 + 2 + 32 + 1 + 32 + 2 + suites.len() * 2 + 2 + 2 + extensions_len;
        if unpadded > 0xff && unpadded < 0x200 {
            // BoringSSL: pad to 512 bytes; the extension header takes four of
            // them and the body is at least one byte.
            let room = 0x200 - unpadded;
            let padding = if room >= 5 { room - 4 } else { 1 };
            encoded.insert(slot, (EXT_PADDING, vec![0u8; padding]));
        }
    }

    if let Some(body) = psk_body {
        encoded.push((EXT_PRE_SHARED_KEY, body));
    }

    let mut encoded_extensions = Vec::with_capacity(2048);
    for (ext_type, body) in &encoded {
        put_u16(&mut encoded_extensions, *ext_type);
        put_u16(&mut encoded_extensions, body.len() as u16);
        encoded_extensions.extend_from_slice(body);
    }
    if encoded_extensions.len() > usize::from(u16::MAX) {
        return Err(invalid_data("ClientHello extensions too large"));
    }

    let mut body = Vec::with_capacity(512 + encoded_extensions.len());
    put_u16(&mut body, 0x0303);
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(&session_id);
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
        psk_binders_len,
    })
}

/// Body of a pre_shared_key extension with one identity and a zero binder.
fn encode_pre_shared_key(spec: &ClientHelloSpec, psk: PskShape<'_>) -> io::Result<Vec<u8>> {
    if psk.identity.is_empty()
        || psk.identity.len() > usize::from(u16::MAX) - 64
        || psk.binder_len < 32
        || psk.binder_len > 255
    {
        return Err(invalid_data("invalid pre-shared key offer"));
    }
    if !spec.offers_psk_dhe_ke() {
        return Err(invalid_data("fingerprint does not offer psk_dhe_ke"));
    }
    let mut body = Vec::with_capacity(psk.identity.len() + psk.binder_len + 11);
    put_u16(&mut body, (psk.identity.len() + 6) as u16);
    put_u16(&mut body, psk.identity.len() as u16);
    body.extend_from_slice(psk.identity);
    body.extend_from_slice(&psk.obfuscated_age.to_be_bytes());
    put_u16(&mut body, (psk.binder_len + 1) as u16);
    body.push(psk.binder_len as u8);
    body.resize(body.len() + psk.binder_len, 0);
    Ok(body)
}

/// Fisher-Yates shuffle of every extension except GREASE and padding, which
/// keep their places.
fn permute_middle(extensions: &mut [Extension]) -> io::Result<()> {
    let movable: Vec<usize> = extensions
        .iter()
        .enumerate()
        .filter(|(_, extension)| !extension.is_pinned())
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

fn put_codes(out: &mut Vec<u8>, codes: &[Code], grease: u16) {
    for code in codes {
        put_u16(
            out,
            match code {
                Code::Grease => grease,
                Code::Value(value) => *value,
            },
        );
    }
}

fn put_protocols(out: &mut Vec<u8>, protocols: &[Vec<u8>]) -> io::Result<()> {
    let mut list = Vec::new();
    for protocol in protocols {
        if protocol.is_empty() || protocol.len() > 255 {
            return Err(invalid_data("invalid ALPN protocol name"));
        }
        list.push(protocol.len() as u8);
        list.extend_from_slice(protocol);
    }
    put_u16(out, list.len() as u16);
    out.extend_from_slice(&list);
    Ok(())
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
        Extension::ExtendedMasterSecret
        | Extension::SessionTicket
        | Extension::SignedCertificateTimestamp
        | Extension::Padding => {}
        Extension::Grease { body } | Extension::Raw { body, .. } => out.extend_from_slice(body),
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
            put_codes(&mut out, groups, grease.group);
        }
        Extension::EcPointFormats(formats) => {
            out.push(formats.len() as u8);
            out.extend_from_slice(formats);
        }
        Extension::Alpn => put_protocols(&mut out, alpn)?,
        Extension::StatusRequest => out.extend_from_slice(&[1, 0, 0, 0, 0]),
        Extension::SignatureAlgorithms(schemes) => {
            put_u16(&mut out, (schemes.len() * 2) as u16);
            put_codes(&mut out, schemes, grease.signature);
        }
        Extension::KeyShare(groups) => {
            let mut shares = Vec::new();
            for group in groups {
                let (id, data): (u16, Vec<u8>) = match group {
                    Code::Grease => (grease.group, vec![0]),
                    Code::Value(GROUP_X25519) => (GROUP_X25519, secrets.x25519_public().to_vec()),
                    Code::Value(GROUP_X25519_MLKEM768) => {
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
                        (GROUP_X25519_MLKEM768, data)
                    }
                    Code::Value(_) => {
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
        Extension::PskKeyExchangeModes(modes) => {
            out.push(modes.len() as u8);
            out.extend_from_slice(modes);
        }
        Extension::SupportedVersions(versions) => {
            out.push((versions.len() * 2) as u8);
            put_codes(&mut out, versions, grease.version);
        }
        Extension::CompressCertificate(algorithms) => {
            out.push((algorithms.len() * 2) as u8);
            for algorithm in algorithms {
                put_u16(&mut out, *algorithm);
            }
        }
        Extension::ApplicationSettings { protocols, .. } => put_protocols(&mut out, protocols)?,
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
