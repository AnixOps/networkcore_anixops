//! VLESS request/response headers (version 0).

use std::io;
use std::net::SocketAddr;

use engine_outbound::TargetAddr;

pub const FLOW_VISION: &str = "xtls-rprx-vision";
const COMMAND_TCP: u8 = 1;
const COMMAND_UDP: u8 = 2;

/// VLESS flow control.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Flow {
    /// Plain VLESS inside the outer TLS.
    #[default]
    None,
    /// `xtls-rprx-vision`.
    Vision,
}

impl Flow {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "" | "none" => Some(Flow::None),
            FLOW_VISION => Some(Flow::Vision),
            _ => None,
        }
    }
}

/// Encodes the request header for a TCP connection to `target`.
pub fn encode_request_header(
    uuid: &[u8; 16],
    flow: Flow,
    target: &TargetAddr,
) -> io::Result<Vec<u8>> {
    encode_header(uuid, flow, COMMAND_TCP, target)
}

/// Encodes the request header for a UDP flow to `target`. UDP never takes a
/// flow, also for Vision users, as in Xray.
pub fn encode_udp_request_header(uuid: &[u8; 16], target: &TargetAddr) -> io::Result<Vec<u8>> {
    encode_header(uuid, Flow::None, COMMAND_UDP, target)
}

fn encode_header(
    uuid: &[u8; 16],
    flow: Flow,
    command: u8,
    target: &TargetAddr,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(64);
    out.push(0);
    out.extend_from_slice(uuid);
    match flow {
        Flow::None => out.push(0),
        Flow::Vision => {
            // Addons protobuf: field 1 (Flow), wire type 2.
            out.push(2 + FLOW_VISION.len() as u8);
            out.push(0x0a);
            out.push(FLOW_VISION.len() as u8);
            out.extend_from_slice(FLOW_VISION.as_bytes());
        }
    }
    out.push(command);
    out.extend_from_slice(&target.port().to_be_bytes());
    match target {
        TargetAddr::Ip(SocketAddr::V4(addr)) => {
            out.push(1);
            out.extend_from_slice(&addr.ip().octets());
        }
        TargetAddr::Ip(SocketAddr::V6(addr)) => {
            out.push(3);
            out.extend_from_slice(&addr.ip().octets());
        }
        TargetAddr::Domain(domain, _) => {
            if domain.is_empty() || domain.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "VLESS target domain must be 1..=255 bytes",
                ));
            }
            out.push(2);
            out.push(domain.len() as u8);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(out)
}

/// Parses a UUID in the usual hyphenated (or plain 32 hex digit) form.
pub fn parse_uuid(text: &str) -> io::Result<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    let bytes = decode_hex(&hex).filter(|bytes| bytes.len() == 16);
    let bytes =
        bytes.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid VLESS UUID"))?;
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes);
    Ok(uuid)
}

/// Parses a REALITY short id (0 to 16 hex digits, even length).
pub fn parse_short_id(text: &str) -> io::Result<[u8; 8]> {
    let bytes = decode_hex(text)
        .filter(|bytes| bytes.len() <= 8)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid REALITY short id"))?;
    let mut short_id = [0u8; 8];
    short_id[..bytes.len()].copy_from_slice(&bytes);
    Ok(short_id)
}

/// Decodes a REALITY public key (base64url or standard base64, padding
/// optional), as printed by `xray x25519` and `sing-box generate
/// reality-keypair`.
pub fn parse_public_key(text: &str) -> io::Result<[u8; 32]> {
    let bytes = decode_base64(text.trim())
        .filter(|bytes| bytes.len() == 32)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid REALITY public key"))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| {
            text.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect()
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in text.trim_end_matches('=').bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}
