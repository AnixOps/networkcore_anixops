//! ClientHello parsing, JA3 / JA4 fingerprints, and profiles derived from a
//! captured ClientHello.
//!
//! This is how a fingerprint is checked against its target: capture the real
//! browser's first flight, build ours for the same server name and ALPN, and
//! compare their JA4 and JA3 (`.github/workflows/browser-fingerprints.yml`
//! does it for every browser it can run). [`spec_from_hello`] turns a capture
//! into a profile, which is how a new browser release is followed.
//!
//! - JA3: `version,ciphers,extensions,groups,point_formats` in decimal, GREASE
//!   removed, MD5. Chrome permutes its extensions, so its JA3 changes on every
//!   connection; [`Hello::ja3n`] sorts the extensions first (often called
//!   JA3N) and is stable.
//! - JA4 (FoxIO, TLS client part): `t13d1516h2_<ciphers>_<extensions>`, where
//!   the hashes are the first 12 hex digits of SHA-256 over the sorted cipher
//!   list and over the sorted extension list (without SNI and ALPN) followed
//!   by the signature algorithms in order. Order-independent by design.

use std::io;

use ring::digest;

use crate::crypto::invalid_data;
use crate::fingerprint::{is_grease, ClientHelloSpec, Code, Extension};

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
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_ALPS_OLD: u16 = 0x4469;
const EXT_ALPS_NEW: u16 = 0x44cd;
const EXT_ECH: u16 = 0xfe0d;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;

/// The fields of a ClientHello that fingerprints look at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub legacy_version: u16,
    pub cipher_suites: Vec<u16>,
    /// Extensions in wire order with their bodies.
    pub extensions: Vec<(u16, Vec<u8>)>,
}

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        if self.data.len() < len {
            return Err(invalid_data("truncated ClientHello"));
        }
        let (head, rest) = self.data.split_at(len);
        self.data = rest;
        Ok(head)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> io::Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

/// Parses a ClientHello given as a handshake message (`01 …`) or as TLS
/// records (`16 03 01 …`, possibly several carrying one message).
pub fn parse_client_hello(bytes: &[u8]) -> io::Result<Hello> {
    let message = if bytes.first() == Some(&0x16) {
        let mut message = Vec::new();
        let mut records = Reader { data: bytes };
        while !records.data.is_empty() {
            let header = records.take(5)?;
            if header[0] != 0x16 {
                break;
            }
            let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            message.extend_from_slice(records.take(len)?);
        }
        message
    } else {
        bytes.to_vec()
    };
    let mut reader = Reader { data: &message };
    if reader.u8()? != 1 {
        return Err(invalid_data("not a ClientHello"));
    }
    let len = reader.take(3)?;
    let len = (usize::from(len[0]) << 16) | (usize::from(len[1]) << 8) | usize::from(len[2]);
    let mut body = Reader {
        data: reader.take(len)?,
    };
    let legacy_version = body.u16()?;
    body.take(32)?;
    let session_id = usize::from(body.u8()?);
    body.take(session_id)?;
    let suites_len = usize::from(body.u16()?);
    let mut suites = Reader {
        data: body.take(suites_len)?,
    };
    let mut cipher_suites = Vec::with_capacity(suites_len / 2);
    while !suites.data.is_empty() {
        cipher_suites.push(suites.u16()?);
    }
    let compression = usize::from(body.u8()?);
    body.take(compression)?;
    let mut extensions = Vec::new();
    if !body.data.is_empty() {
        let extensions_len = usize::from(body.u16()?);
        let mut list = Reader {
            data: body.take(extensions_len)?,
        };
        while !list.data.is_empty() {
            let ext_type = list.u16()?;
            let ext_len = usize::from(list.u16()?);
            extensions.push((ext_type, list.take(ext_len)?.to_vec()));
        }
    }
    Ok(Hello {
        legacy_version,
        cipher_suites,
        extensions,
    })
}

/// Decodes hex, ignoring whitespace (the format of `tests/data/*.hex`).
pub fn decode_hex(text: &str) -> io::Result<Vec<u8>> {
    let digits: Vec<u8> = text
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if !digits.len().is_multiple_of(2) {
        return Err(invalid_data("odd hex length"));
    }
    digits
        .chunks(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| invalid_data("not hex"))
        })
        .collect()
}

fn u16_list(body: &[u8], skip: usize) -> Vec<u16> {
    body.get(skip..)
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_be_bytes(*pair))
        .collect()
}

fn join(values: impl Iterator<Item = String>, separator: &str) -> String {
    values.collect::<Vec<_>>().join(separator)
}

fn hex12(text: &str) -> String {
    let hash = digest::digest(&digest::SHA256, text.as_bytes());
    hash.as_ref()[..6]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl Hello {
    pub fn extension(&self, ext_type: u16) -> Option<&[u8]> {
        self.extensions
            .iter()
            .find(|(id, _)| *id == ext_type)
            .map(|(_, body)| body.as_slice())
    }

    /// The SNI host name, if one is sent.
    pub fn server_name(&self) -> Option<String> {
        let body = self.extension(EXT_SERVER_NAME)?;
        // list length (2), type (1), name length (2), name
        let name = body.get(5..)?;
        String::from_utf8(name.to_vec()).ok()
    }

    /// The offered ALPN protocols, in order.
    pub fn alpn(&self) -> Vec<Vec<u8>> {
        let Some(body) = self.extension(EXT_ALPN) else {
            return Vec::new();
        };
        let mut protocols = Vec::new();
        let mut at = 2;
        while let Some(&len) = body.get(at) {
            let Some(protocol) = body.get(at + 1..at + 1 + usize::from(len)) else {
                break;
            };
            protocols.push(protocol.to_vec());
            at += 1 + usize::from(len);
        }
        protocols
    }

    fn groups(&self) -> Vec<u16> {
        self.extension(EXT_SUPPORTED_GROUPS)
            .map(|body| u16_list(body, 2))
            .unwrap_or_default()
    }

    fn point_formats(&self) -> Vec<u8> {
        self.extension(EXT_EC_POINT_FORMATS)
            .and_then(|body| body.get(1..))
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    }

    fn signature_algorithms(&self) -> Vec<u16> {
        self.extension(EXT_SIGNATURE_ALGORITHMS)
            .map(|body| u16_list(body, 2))
            .unwrap_or_default()
    }

    fn ja3_with(&self, sort_extensions: bool) -> String {
        let decimal = |values: &[u16]| {
            join(
                values
                    .iter()
                    .filter(|value| !is_grease(**value))
                    .map(u16::to_string),
                "-",
            )
        };
        let mut extensions: Vec<u16> = self.extensions.iter().map(|(id, _)| *id).collect();
        if sort_extensions {
            extensions.sort_unstable();
        }
        format!(
            "{},{},{},{},{}",
            self.legacy_version,
            decimal(&self.cipher_suites),
            decimal(&extensions),
            decimal(&self.groups()),
            join(self.point_formats().iter().map(u8::to_string), "-"),
        )
    }

    /// The JA3 string (before hashing).
    pub fn ja3_string(&self) -> String {
        self.ja3_with(false)
    }

    /// JA3: MD5 of [`Hello::ja3_string`].
    pub fn ja3(&self) -> String {
        md5_hex(self.ja3_string().as_bytes())
    }

    /// JA3 with the extensions sorted, stable across Chrome's permutation.
    pub fn ja3n(&self) -> String {
        md5_hex(self.ja3_with(true).as_bytes())
    }

    /// JA4 (TLS over TCP).
    pub fn ja4(&self) -> String {
        let version = self
            .extension(EXT_SUPPORTED_VERSIONS)
            .map(|body| u16_list(body, 1))
            .and_then(|versions| {
                versions
                    .into_iter()
                    .filter(|version| !is_grease(*version))
                    .max()
            })
            .unwrap_or(self.legacy_version);
        let version = match version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            0x0300 => "s3",
            _ => "00",
        };
        let sni = if self.extension(EXT_SERVER_NAME).is_some() {
            'd'
        } else {
            'i'
        };
        let ciphers: Vec<u16> = self
            .cipher_suites
            .iter()
            .copied()
            .filter(|suite| !is_grease(*suite))
            .collect();
        let extensions: Vec<u16> = self
            .extensions
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| !is_grease(*id))
            .collect();
        let alpn = match self.alpn().first() {
            None => "00".to_owned(),
            Some(first) if first.is_empty() => "00".to_owned(),
            Some(first) => {
                let (head, tail) = (first[0], first[first.len() - 1]);
                if head.is_ascii_alphanumeric() && tail.is_ascii_alphanumeric() {
                    format!("{}{}", head as char, tail as char)
                } else {
                    let head = format!("{head:02x}");
                    let tail = format!("{tail:02x}");
                    format!("{}{}", &head[..1], &tail[1..])
                }
            }
        };
        let a = format!(
            "t{version}{sni}{:02}{:02}{alpn}",
            ciphers.len().min(99),
            extensions.len().min(99)
        );

        let mut sorted_ciphers = ciphers;
        sorted_ciphers.sort_unstable();
        let b = if sorted_ciphers.is_empty() {
            "000000000000".to_owned()
        } else {
            hex12(&join(
                sorted_ciphers.iter().map(|id| format!("{id:04x}")),
                ",",
            ))
        };

        let mut sorted_extensions: Vec<u16> = extensions
            .into_iter()
            .filter(|id| *id != EXT_SERVER_NAME && *id != EXT_ALPN)
            .collect();
        sorted_extensions.sort_unstable();
        let signatures: Vec<u16> = self
            .signature_algorithms()
            .into_iter()
            .filter(|id| !is_grease(*id))
            .collect();
        let c = if sorted_extensions.is_empty() {
            "000000000000".to_owned()
        } else {
            let mut text = join(sorted_extensions.iter().map(|id| format!("{id:04x}")), ",");
            if !signatures.is_empty() {
                text.push('_');
                text.push_str(&join(signatures.iter().map(|id| format!("{id:04x}")), ","));
            }
            hex12(&text)
        };
        format!("{a}_{b}_{c}")
    }
}

fn code(value: u16) -> Code {
    if is_grease(value) {
        Code::Grease
    } else {
        Code::Value(value)
    }
}

fn codes(values: &[u16]) -> Vec<Code> {
    values.iter().map(|value| code(*value)).collect()
}

/// A profile that reproduces a captured ClientHello: GREASE values become
/// `"grease"`, key shares keep only their groups, the server name and ALPN
/// come from the connection, ECH and padding become the generated
/// extensions, a pre_shared_key (resumption) is dropped, and any extension
/// this crate has no name for is kept as `raw`. Whether the browser permutes
/// its extensions cannot be seen in one capture, so the caller says.
pub fn spec_from_hello(hello: &Hello, permute_extensions: bool) -> io::Result<ClientHelloSpec> {
    let mut extensions = Vec::with_capacity(hello.extensions.len());
    for (ext_type, body) in &hello.extensions {
        let extension = match *ext_type {
            id if is_grease(id) => Extension::Grease { body: body.clone() },
            EXT_SERVER_NAME => Extension::ServerName,
            EXT_EXTENDED_MASTER_SECRET if body.is_empty() => Extension::ExtendedMasterSecret,
            EXT_RENEGOTIATION_INFO if body.as_slice() == [0] => Extension::RenegotiationInfo,
            EXT_SUPPORTED_GROUPS => Extension::SupportedGroups(codes(&u16_list(body, 2))),
            EXT_EC_POINT_FORMATS => {
                Extension::EcPointFormats(body.get(1..).unwrap_or_default().to_vec())
            }
            EXT_SESSION_TICKET if body.is_empty() => Extension::SessionTicket,
            EXT_ALPN => Extension::Alpn,
            EXT_STATUS_REQUEST if body.as_slice() == [1, 0, 0, 0, 0] => Extension::StatusRequest,
            EXT_SIGNATURE_ALGORITHMS => Extension::SignatureAlgorithms(codes(&u16_list(body, 2))),
            EXT_SCT if body.is_empty() => Extension::SignedCertificateTimestamp,
            EXT_KEY_SHARE => {
                let mut groups = Vec::new();
                let mut at = 2;
                while let Some(header) = body.get(at..at + 4) {
                    groups.push(code(u16::from_be_bytes([header[0], header[1]])));
                    at += 4 + usize::from(u16::from_be_bytes([header[2], header[3]]));
                }
                Extension::KeyShare(groups)
            }
            EXT_PSK_KEY_EXCHANGE_MODES => {
                Extension::PskKeyExchangeModes(body.get(1..).unwrap_or_default().to_vec())
            }
            EXT_SUPPORTED_VERSIONS => Extension::SupportedVersions(codes(&u16_list(body, 1))),
            EXT_COMPRESS_CERTIFICATE => Extension::CompressCertificate(u16_list(body, 1)),
            EXT_ALPS_OLD | EXT_ALPS_NEW => {
                let mut protocols = Vec::new();
                let mut at = 2;
                while let Some(&len) = body.get(at) {
                    let Some(protocol) = body.get(at + 1..at + 1 + usize::from(len)) else {
                        break;
                    };
                    protocols.push(protocol.to_vec());
                    at += 1 + usize::from(len);
                }
                Extension::ApplicationSettings {
                    code_point: *ext_type,
                    protocols,
                }
            }
            EXT_ECH => Extension::EchGrease,
            EXT_PADDING => Extension::Padding,
            EXT_PRE_SHARED_KEY => continue,
            id => Extension::Raw {
                id,
                body: body.clone(),
            },
        };
        extensions.push(extension);
    }
    let spec = ClientHelloSpec {
        cipher_suites: codes(&hello.cipher_suites),
        extensions,
        permute_extensions,
        default_alpn: hello.alpn(),
    };
    spec.validate()?;
    Ok(spec)
}

/// MD5 (RFC 1321), only for JA3; nothing here depends on its security.
fn md5_hex(input: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: Vec<u32> = (0..64)
        .map(|i| ((i as f64 + 1.0).sin().abs() * 4_294_967_296.0) as u32)
        .collect();
    let mut state: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    let mut message = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_len.to_le_bytes());
    for block in message.as_chunks::<64>().0 {
        let words: Vec<u32> = block
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect();
        let [mut a, mut b, mut c, mut d] = state;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            let rotated = a
                .wrapping_add(f)
                .wrapping_add(k[i])
                .wrapping_add(words[g])
                .rotate_left(S[i]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(rotated);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
    }
    state
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_matches_rfc1321_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    /// The ClientHello of the JA4 reference implementation's README example
    /// is not public as bytes, so this builds one with the documented fields
    /// and checks every part of the fingerprint by hand.
    #[test]
    fn ja3_and_ja4_of_a_known_hello() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        // GREASE, 0x1301, 0xc02b
        body.extend_from_slice(&[0, 6, 0x0a, 0x0a, 0x13, 0x01, 0xc0, 0x2b]);
        body.extend_from_slice(&[1, 0]);
        let mut extensions = Vec::new();
        let mut push = |id: u16, data: &[u8]| {
            extensions.extend_from_slice(&id.to_be_bytes());
            extensions.extend_from_slice(&(data.len() as u16).to_be_bytes());
            extensions.extend_from_slice(data);
        };
        push(0x0a0a, &[]);
        push(0x0000, &[0, 6, 0, 0, 3, b'a', b'.', b'b']);
        push(0x000a, &[0, 4, 0x1a, 0x1a, 0x00, 0x1d]);
        push(0x000b, &[1, 0]);
        push(0x0010, &[0, 3, 2, b'h', b'2']);
        push(0x000d, &[0, 4, 0x04, 0x03, 0x08, 0x04]);
        push(0x002b, &[4, 0x2a, 0x2a, 0x03, 0x04]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut message = vec![1, 0, 0, body.len() as u8];
        message.extend_from_slice(&body);

        let hello = parse_client_hello(&message).unwrap();
        assert_eq!(hello.server_name().as_deref(), Some("a.b"));
        assert_eq!(hello.alpn(), vec![b"h2".to_vec()]);
        assert_eq!(hello.ja3_string(), "771,4865-49195,0-10-11-16-13-43,29,0");
        assert_eq!(
            hello.ja3(),
            md5_hex(b"771,4865-49195,0-10-11-16-13-43,29,0")
        );
        assert_eq!(
            hello.ja3n(),
            md5_hex(b"771,4865-49195,0-10-11-13-16-43,29,0")
        );
        let ja4 = hello.ja4();
        assert!(ja4.starts_with("t13d0206h2_"), "{ja4}");
        assert_eq!(&ja4[11..23], hex12("1301,c02b"));
        assert_eq!(&ja4[24..], hex12("000a,000b,000d,002b_0403,0804"));

        // As TLS records, split over two of them.
        let mut records = Vec::new();
        let (first, second) = message.split_at(10);
        for part in [first, second] {
            records.extend_from_slice(&[0x16, 0x03, 0x01]);
            records.extend_from_slice(&(part.len() as u16).to_be_bytes());
            records.extend_from_slice(part);
        }
        assert_eq!(parse_client_hello(&records).unwrap(), hello);
    }
}
