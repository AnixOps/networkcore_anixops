//! JSON form of [`ClientHelloSpec`] and of fingerprint bundles.
//!
//! A fingerprint is data: the built-in ones are the JSON files under
//! `fingerprints/`, and a bundle delivered at run time (see
//! [`crate::fingerprint::install_profiles`]) replaces them without a new
//! build. The format is strict: unknown keys and unknown extension types are
//! errors, so a profile this build cannot reproduce exactly is rejected as a
//! whole instead of being sent half right.
//!
//! ```json
//! {
//!   "note": "free text, ignored",
//!   "cipher_suites": ["grease", "0x1301"],
//!   "extensions": [
//!     "grease",
//!     "server_name",
//!     { "type": "supported_groups", "groups": ["grease", "0x001d"] },
//!     { "type": "raw", "id": "0x1234", "body": "00ff" }
//!   ],
//!   "permute_extensions": false,
//!   "alpn": ["h2", "http/1.1"]
//! }
//! ```
//!
//! 16-bit code points are `"0x…"` strings (plain JSON numbers are accepted
//! too); `"grease"` in a list is replaced by a GREASE value on every
//! connection. Extensions without parameters may be written as a bare string.

use std::io;

use serde_json::{json, Map, Value};

use crate::fingerprint::{ClientHelloSpec, Code, Extension};

/// Largest profile or bundle document accepted.
pub const MAX_DOCUMENT_BYTES: usize = 256 * 1024;
/// The bundle layout this build reads.
pub const BUNDLE_FORMAT: u64 = 1;

const MAX_LIST: usize = 64;
const MAX_RAW_BODY: usize = 4096;

fn bad(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// A parsed bundle: profiles by name, in document order.
pub(crate) struct Bundle {
    pub(crate) revision: String,
    pub(crate) profiles: Vec<(String, Value)>,
}

pub(crate) fn parse_document(text: &str) -> io::Result<Value> {
    if text.len() > MAX_DOCUMENT_BYTES {
        return Err(bad("fingerprint document is too large"));
    }
    serde_json::from_str(text).map_err(|error| bad(format!("fingerprint JSON: {error}")))
}

pub(crate) fn parse_bundle(text: &str) -> io::Result<Bundle> {
    let document = parse_document(text)?;
    let mut fields = Fields::new(&document, "bundle")?;
    let format = fields
        .take("format")
        .and_then(Value::as_u64)
        .ok_or_else(|| bad("bundle: format must be a number"))?;
    if format != BUNDLE_FORMAT {
        return Err(bad(format!("bundle: unsupported format {format}")));
    }
    let revision = match fields.take("revision") {
        None => String::new(),
        Some(Value::String(revision)) if revision.len() <= 64 => revision.clone(),
        Some(_) => return Err(bad("bundle: revision must be a short string")),
    };
    let profiles = fields
        .take("profiles")
        .and_then(Value::as_object)
        .ok_or_else(|| bad("bundle: profiles must be an object"))?;
    fields.finish()?;
    Ok(Bundle {
        revision,
        profiles: profiles
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect(),
    })
}

/// Object reader that rejects keys nobody asked for.
struct Fields<'a> {
    map: &'a Map<String, Value>,
    what: &'a str,
    taken: Vec<&'static str>,
}

impl<'a> Fields<'a> {
    fn new(value: &'a Value, what: &'a str) -> io::Result<Self> {
        let map = value
            .as_object()
            .ok_or_else(|| bad(format!("{what}: expected an object")))?;
        Ok(Self {
            map,
            what,
            taken: Vec::new(),
        })
    }

    fn take(&mut self, key: &'static str) -> Option<&'a Value> {
        self.taken.push(key);
        self.map.get(key)
    }

    fn require(&mut self, key: &'static str) -> io::Result<&'a Value> {
        let what = self.what;
        self.take(key)
            .ok_or_else(|| bad(format!("{what}: {key} is missing")))
    }

    fn finish(self) -> io::Result<()> {
        match self
            .map
            .keys()
            .find(|key| !self.taken.contains(&key.as_str()))
        {
            Some(key) => Err(bad(format!("{}: unknown key {key}", self.what))),
            None => Ok(()),
        }
    }
}

fn parse_u16(value: &Value, what: &str) -> io::Result<u16> {
    let parsed = match value {
        Value::Number(number) => number.as_u64().and_then(|n| u16::try_from(n).ok()),
        Value::String(text) => match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
            Some(hex) if !hex.is_empty() && hex.len() <= 4 => u16::from_str_radix(hex, 16).ok(),
            Some(_) => None,
            None => text.parse::<u16>().ok(),
        },
        _ => None,
    };
    parsed.ok_or_else(|| bad(format!("{what}: expected a 16-bit code point, got {value}")))
}

fn parse_code(value: &Value, what: &str) -> io::Result<Code> {
    match value {
        Value::String(text) if text.eq_ignore_ascii_case("grease") => Ok(Code::Grease),
        other => parse_u16(other, what).map(Code::Value),
    }
}

fn parse_list<'a>(value: &'a Value, what: &str) -> io::Result<&'a Vec<Value>> {
    let list = value
        .as_array()
        .ok_or_else(|| bad(format!("{what}: expected a list")))?;
    if list.len() > MAX_LIST {
        return Err(bad(format!("{what}: too many entries")));
    }
    Ok(list)
}

fn parse_codes(value: &Value, what: &str) -> io::Result<Vec<Code>> {
    parse_list(value, what)?
        .iter()
        .map(|entry| parse_code(entry, what))
        .collect()
}

fn parse_u16s(value: &Value, what: &str) -> io::Result<Vec<u16>> {
    parse_list(value, what)?
        .iter()
        .map(|entry| parse_u16(entry, what))
        .collect()
}

fn parse_u8s(value: &Value, what: &str) -> io::Result<Vec<u8>> {
    parse_list(value, what)?
        .iter()
        .map(|entry| {
            parse_u16(entry, what)
                .ok()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or_else(|| bad(format!("{what}: expected a byte, got {entry}")))
        })
        .collect()
}

fn parse_names(value: &Value, what: &str) -> io::Result<Vec<Vec<u8>>> {
    parse_list(value, what)?
        .iter()
        .map(|entry| match entry.as_str() {
            Some(name) if !name.is_empty() && name.len() <= 255 => Ok(name.as_bytes().to_vec()),
            _ => Err(bad(format!(
                "{what}: expected a protocol name, got {entry}"
            ))),
        })
        .collect()
}

fn parse_hex(value: &Value, what: &str) -> io::Result<Vec<u8>> {
    let text = value
        .as_str()
        .ok_or_else(|| bad(format!("{what}: expected a hex string")))?;
    let digits = text.as_bytes();
    if !digits.len().is_multiple_of(2) || digits.len() > MAX_RAW_BODY * 2 {
        return Err(bad(format!("{what}: bad hex length")));
    }
    digits
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| bad(format!("{what}: not hex")))
        })
        .collect()
}

/// Looks up one parameter of an extension; a bare string has none.
fn param<'a>(
    fields: &mut Option<Fields<'a>>,
    what: &str,
    key: &'static str,
) -> io::Result<&'a Value> {
    fields
        .as_mut()
        .and_then(|fields| fields.take(key))
        .ok_or_else(|| bad(format!("{what}: {key} is missing")))
}

fn parse_extension(value: &Value) -> io::Result<Extension> {
    let (name, mut fields) = match value {
        Value::String(name) => (name.as_str(), None),
        Value::Object(_) => {
            let mut fields = Fields::new(value, "extension")?;
            let name = fields
                .require("type")?
                .as_str()
                .ok_or_else(|| bad("extension: type must be a string"))?;
            (name, Some(fields))
        }
        _ => return Err(bad("extension: expected a name or an object")),
    };
    let what = format!("extension {name}");
    let extension = match name {
        "grease" => Extension::Grease {
            body: match param(&mut fields, &what, "body") {
                Ok(body) => parse_hex(body, &what)?,
                Err(_) => Vec::new(),
            },
        },
        "server_name" => Extension::ServerName,
        "extended_master_secret" => Extension::ExtendedMasterSecret,
        "renegotiation_info" => Extension::RenegotiationInfo,
        "supported_groups" => {
            Extension::SupportedGroups(parse_codes(param(&mut fields, &what, "groups")?, &what)?)
        }
        "ec_point_formats" => {
            Extension::EcPointFormats(parse_u8s(param(&mut fields, &what, "formats")?, &what)?)
        }
        "session_ticket" => Extension::SessionTicket,
        "alpn" => Extension::Alpn,
        "status_request" => Extension::StatusRequest,
        "signature_algorithms" => Extension::SignatureAlgorithms(parse_codes(
            param(&mut fields, &what, "schemes")?,
            &what,
        )?),
        "signed_certificate_timestamp" => Extension::SignedCertificateTimestamp,
        "key_share" => {
            Extension::KeyShare(parse_codes(param(&mut fields, &what, "groups")?, &what)?)
        }
        "psk_key_exchange_modes" => {
            Extension::PskKeyExchangeModes(parse_u8s(param(&mut fields, &what, "modes")?, &what)?)
        }
        "supported_versions" => Extension::SupportedVersions(parse_codes(
            param(&mut fields, &what, "versions")?,
            &what,
        )?),
        "compress_certificate" => Extension::CompressCertificate(parse_u16s(
            param(&mut fields, &what, "algorithms")?,
            &what,
        )?),
        "application_settings" => Extension::ApplicationSettings {
            code_point: parse_u16(param(&mut fields, &what, "code_point")?, &what)?,
            protocols: parse_names(param(&mut fields, &what, "protocols")?, &what)?,
        },
        "ech_grease" => Extension::EchGrease,
        "padding" => Extension::Padding,
        "raw" => Extension::Raw {
            id: parse_u16(param(&mut fields, &what, "id")?, &what)?,
            body: parse_hex(param(&mut fields, &what, "body")?, &what)?,
        },
        other => return Err(bad(format!("unknown extension type {other}"))),
    };
    if let Some(fields) = fields {
        fields.finish()?;
    }
    Ok(extension)
}

pub(crate) fn spec_from_value(value: &Value) -> io::Result<ClientHelloSpec> {
    let mut fields = Fields::new(value, "fingerprint")?;
    if let Some(note) = fields.take("note") {
        if !note.is_string() {
            return Err(bad("fingerprint: note must be a string"));
        }
    }
    let cipher_suites = parse_codes(fields.require("cipher_suites")?, "cipher_suites")?;
    let extensions = parse_list(fields.require("extensions")?, "extensions")?
        .iter()
        .map(parse_extension)
        .collect::<io::Result<Vec<_>>>()?;
    let permute_extensions = match fields.take("permute_extensions") {
        None => false,
        Some(Value::Bool(permute)) => *permute,
        Some(_) => return Err(bad("fingerprint: permute_extensions must be a boolean")),
    };
    let default_alpn = match fields.take("alpn") {
        None => Vec::new(),
        Some(alpn) => parse_names(alpn, "alpn")?,
    };
    fields.finish()?;
    let spec = ClientHelloSpec {
        cipher_suites,
        extensions,
        permute_extensions,
        default_alpn,
    };
    spec.validate()?;
    Ok(spec)
}

fn u16_json(value: u16) -> Value {
    Value::String(format!("0x{value:04x}"))
}

fn code_json(code: &Code) -> Value {
    match code {
        Code::Grease => Value::String("grease".to_owned()),
        Code::Value(value) => u16_json(*value),
    }
}

fn codes_json(codes: &[Code]) -> Value {
    Value::Array(codes.iter().map(code_json).collect())
}

fn hex_json(bytes: &[u8]) -> Value {
    Value::String(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn names_json(names: &[Vec<u8>]) -> Value {
    Value::Array(
        names
            .iter()
            .map(|name| Value::String(String::from_utf8_lossy(name).into_owned()))
            .collect(),
    )
}

fn extension_json(extension: &Extension) -> Value {
    let bare = |name: &str| Value::String(name.to_owned());
    match extension {
        Extension::Grease { body } if body.is_empty() => bare("grease"),
        Extension::Grease { body } => json!({ "type": "grease", "body": hex_json(body) }),
        Extension::ServerName => bare("server_name"),
        Extension::ExtendedMasterSecret => bare("extended_master_secret"),
        Extension::RenegotiationInfo => bare("renegotiation_info"),
        Extension::SupportedGroups(groups) => {
            json!({ "type": "supported_groups", "groups": codes_json(groups) })
        }
        Extension::EcPointFormats(formats) => {
            json!({ "type": "ec_point_formats", "formats": formats })
        }
        Extension::SessionTicket => bare("session_ticket"),
        Extension::Alpn => bare("alpn"),
        Extension::StatusRequest => bare("status_request"),
        Extension::SignatureAlgorithms(schemes) => {
            json!({ "type": "signature_algorithms", "schemes": codes_json(schemes) })
        }
        Extension::SignedCertificateTimestamp => bare("signed_certificate_timestamp"),
        Extension::KeyShare(groups) => json!({ "type": "key_share", "groups": codes_json(groups) }),
        Extension::PskKeyExchangeModes(modes) => {
            json!({ "type": "psk_key_exchange_modes", "modes": modes })
        }
        Extension::SupportedVersions(versions) => {
            json!({ "type": "supported_versions", "versions": codes_json(versions) })
        }
        Extension::CompressCertificate(algorithms) => json!({
            "type": "compress_certificate",
            "algorithms": Value::Array(algorithms.iter().map(|a| u16_json(*a)).collect()),
        }),
        Extension::ApplicationSettings {
            code_point,
            protocols,
        } => json!({
            "type": "application_settings",
            "code_point": u16_json(*code_point),
            "protocols": names_json(protocols),
        }),
        Extension::EchGrease => bare("ech_grease"),
        Extension::Padding => bare("padding"),
        Extension::Raw { id, body } => {
            json!({ "type": "raw", "id": u16_json(*id), "body": hex_json(body) })
        }
    }
}

pub(crate) fn spec_to_value(spec: &ClientHelloSpec) -> Value {
    json!({
        "cipher_suites": codes_json(&spec.cipher_suites),
        "extensions": Value::Array(spec.extensions.iter().map(extension_json).collect()),
        "permute_extensions": spec.permute_extensions,
        "alpn": names_json(&spec.default_alpn),
    })
}
