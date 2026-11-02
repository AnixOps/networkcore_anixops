//! The TLS SNI of a QUIC client's Initial packets (RFC 9001 section 5,
//! RFC 9369 for QUIC v2), for the destination statistics of UDP flows to an
//! address.
//!
//! Initial packets are encrypted with keys derived from the client's
//! Destination Connection ID only, so anyone on the path can read them. A
//! ClientHello may span several Initial packets, and browsers spread it over
//! CRYPTO frames out of order; [`QuicHello`] reassembles the CRYPTO stream
//! of the first few datagrams until the SNI shows.

use engine_outbound::sniff;
#[cfg(test)]
use engine_outbound::TargetAddr;
use ring::aead::{self, quic, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;

const V1: u32 = 0x0000_0001;
const V2: u32 = 0x6b33_43cf;
const V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const V2_SALT: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
/// Client datagrams looked at before giving up on a name.
const MAX_DATAGRAMS: u8 = 4;
/// CRYPTO bytes kept; a ClientHello with post-quantum key shares is ~2 KB.
const MAX_CRYPTO: u64 = 16 * 1024;

/// Whether `datagram` starts with a QUIC v1 or v2 Initial packet.
pub(crate) fn is_initial(datagram: &[u8]) -> bool {
    initial_version(datagram).is_some()
}

fn initial_version(datagram: &[u8]) -> Option<u32> {
    let first = *datagram.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(datagram.get(1..5)?.try_into().ok()?);
    let kind = (first >> 4) & 0x03;
    match (version, kind) {
        (V1, 0) | (V2, 1) => Some(version),
        _ => None,
    }
}

/// The CRYPTO stream of a QUIC client's first Initial packets.
#[derive(Default)]
pub(crate) struct QuicHello {
    chunks: Vec<(u64, Vec<u8>)>,
    datagrams: u8,
}

/// What [`QuicHello::push`] learnt.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Sniffed {
    /// The ClientHello's server name.
    Name(String),
    /// More Initial packets may still show it.
    Pending,
    /// No name will show: not QUIC, no SNI, or too many datagrams.
    None,
}

impl QuicHello {
    /// Looks at one client datagram.
    pub(crate) fn push(&mut self, datagram: &[u8]) -> Sniffed {
        self.datagrams = self.datagrams.saturating_add(1);
        if self.datagrams > MAX_DATAGRAMS {
            return Sniffed::None;
        }
        let Some(frames) = initial_payload(datagram) else {
            // A later datagram may be a short-header packet; keep trying
            // until the limit only while Initials come.
            return if self.chunks.is_empty() {
                Sniffed::None
            } else {
                Sniffed::Pending
            };
        };
        for (offset, data) in crypto_frames(&frames) {
            if offset + (data.len() as u64) <= MAX_CRYPTO {
                self.chunks.push((offset, data.to_vec()));
            }
        }
        let hello = self.contiguous();
        if hello.is_empty() {
            return Sniffed::Pending;
        }
        let mut record = vec![0x16, 0x03, 0x03];
        let len = hello.len().min(usize::from(u16::MAX));
        record.extend_from_slice(&(len as u16).to_be_bytes());
        record.extend_from_slice(&hello[..len]);
        if let Some(name) = sniff::client_hello_server_name(&record) {
            return Sniffed::Name(name);
        }
        // The whole ClientHello is here and has no name.
        let complete = hello.len() >= 4 && {
            let body = u32::from_be_bytes([0, hello[1], hello[2], hello[3]]) as usize;
            hello.len() >= 4 + body
        };
        if complete || hello.first() != Some(&0x01) {
            Sniffed::None
        } else {
            Sniffed::Pending
        }
    }

    /// The CRYPTO bytes from offset 0 up to the first gap.
    fn contiguous(&mut self) -> Vec<u8> {
        self.chunks.sort_by_key(|(offset, _)| *offset);
        let mut out: Vec<u8> = Vec::new();
        for (offset, data) in &self.chunks {
            let offset = *offset as usize;
            if offset > out.len() {
                break;
            }
            let end = offset + data.len();
            if end > out.len() {
                out.extend_from_slice(&data[out.len() - offset..]);
            }
        }
        out
    }
}

/// The decrypted payload of the Initial packet `datagram` starts with.
fn initial_payload(datagram: &[u8]) -> Option<Vec<u8>> {
    let version = initial_version(datagram)?;
    let mut at = 5;
    let dcid_len = usize::from(*datagram.get(at)?);
    if dcid_len > 20 {
        return None;
    }
    let dcid = datagram.get(at + 1..at + 1 + dcid_len)?;
    at += 1 + dcid_len;
    let scid_len = usize::from(*datagram.get(at)?);
    if scid_len > 20 {
        return None;
    }
    at += 1 + scid_len;
    let token_len = varint(datagram, &mut at)? as usize;
    at = at.checked_add(token_len)?;
    let length = varint(datagram, &mut at)? as usize;
    let pn_offset = at;
    let end = pn_offset.checked_add(length)?;
    if end > datagram.len() || length < 20 {
        return None;
    }

    let (salt, prefix) = if version == V2 {
        (&V2_SALT, "quicv2 ")
    } else {
        (&V1_SALT, "quic ")
    };
    let initial = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dcid);
    let mut client = [0u8; 32];
    expand_label(&initial, "client in", &mut client)?;
    let client = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client);
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    let mut hp = [0u8; 16];
    expand_label(&client, &format!("{prefix}key"), &mut key)?;
    expand_label(&client, &format!("{prefix}iv"), &mut iv)?;
    expand_label(&client, &format!("{prefix}hp"), &mut hp)?;

    let sample = datagram.get(pn_offset + 4..pn_offset + 20)?;
    let mask = quic::HeaderProtectionKey::new(&quic::AES_128, &hp)
        .ok()?
        .new_mask(sample)
        .ok()?;
    let mut header = datagram[..pn_offset + 4].to_vec();
    header[0] ^= mask[0] & 0x0f;
    let pn_len = usize::from(header[0] & 0x03) + 1;
    header.truncate(pn_offset + pn_len);
    for (byte, mask) in header[pn_offset..].iter_mut().zip(&mask[1..]) {
        *byte ^= mask;
    }
    let mut nonce = iv;
    for (byte, pn) in nonce[12 - pn_len..].iter_mut().zip(&header[pn_offset..]) {
        *byte ^= pn;
    }
    let mut payload = datagram[pn_offset + pn_len..end].to_vec();
    let key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).ok()?);
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&header[..]),
            &mut payload,
        )
        .ok()?;
    Some(plain.to_vec())
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-Expand-Label of TLS 1.3 with an empty context.
fn expand_label(secret: &hkdf::Prk, label: &str, out: &mut [u8]) -> Option<()> {
    let mut info = Vec::with_capacity(4 + 6 + label.len());
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    let info = [info.as_slice()];
    secret.expand(&info, Len(out.len())).ok()?.fill(out).ok()
}

/// The CRYPTO frames of a decrypted Initial payload, up to the first frame
/// that is not PADDING, PING, ACK or CRYPTO.
fn crypto_frames(payload: &[u8]) -> Vec<(u64, &[u8])> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < payload.len() {
        let Some(kind) = varint(payload, &mut at) else {
            break;
        };
        match kind {
            0x00 | 0x01 => {}
            0x02 | 0x03 => {
                if skip_ack(payload, &mut at, kind == 0x03).is_none() {
                    break;
                }
            }
            0x06 => {
                let (Some(offset), Some(len)) =
                    (varint(payload, &mut at), varint(payload, &mut at))
                else {
                    break;
                };
                let Some(data) = payload.get(at..at.saturating_add(len as usize)) else {
                    break;
                };
                at += data.len();
                out.push((offset, data));
            }
            _ => break,
        }
    }
    out
}

/// Skips the fields of an ACK frame (with ECN counts for type 0x03).
fn skip_ack(payload: &[u8], at: &mut usize, ecn: bool) -> Option<()> {
    varint(payload, at)?;
    varint(payload, at)?;
    let ranges = varint(payload, at)?;
    varint(payload, at)?;
    for _ in 0..ranges {
        varint(payload, at)?;
        varint(payload, at)?;
    }
    if ecn {
        for _ in 0..3 {
            varint(payload, at)?;
        }
    }
    Some(())
}

/// A QUIC variable-length integer at `*at`.
fn varint(bytes: &[u8], at: &mut usize) -> Option<u64> {
    let first = *bytes.get(*at)?;
    let len = 1usize << (first >> 6);
    let raw = bytes.get(*at..*at + len)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &raw[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    *at += len;
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(|b| b.is_ascii_hexdigit())
            .map(|b| (b as char).to_digit(16).unwrap() as u8)
            .collect();
        digits
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect()
    }

    /// Seals `frames` as a client Initial of `version` the way a client
    /// does, padded to 1200 bytes.
    fn initial(version: u32, dcid: &[u8], frames: &[u8]) -> Vec<u8> {
        let (salt, prefix, kind) = if version == V2 {
            (&V2_SALT, "quicv2 ", 1u8)
        } else {
            (&V1_SALT, "quic ", 0u8)
        };
        let secret = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dcid);
        let mut client = [0u8; 32];
        expand_label(&secret, "client in", &mut client).unwrap();
        let client = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client);
        let (mut key, mut iv, mut hp) = ([0u8; 16], [0u8; 12], [0u8; 16]);
        expand_label(&client, &format!("{prefix}key"), &mut key).unwrap();
        expand_label(&client, &format!("{prefix}iv"), &mut iv).unwrap();
        expand_label(&client, &format!("{prefix}hp"), &mut hp).unwrap();

        let pn: u32 = 2;
        let mut plain = frames.to_vec();
        let header_len = 1 + 4 + 1 + dcid.len() + 1 + 1 + 2 + 4;
        plain.resize(1200 - header_len - 16, 0);
        let length = 4 + plain.len() + 16;
        let mut header = vec![0xc0 | (kind << 4) | 0x03];
        header.extend_from_slice(&version.to_be_bytes());
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0);
        header.push(0);
        header.extend_from_slice(&(0x4000u16 | length as u16).to_be_bytes());
        let pn_offset = header.len();
        header.extend_from_slice(&pn.to_be_bytes());
        let mut nonce = iv;
        for (i, byte) in pn.to_be_bytes().iter().enumerate() {
            nonce[8 + i] ^= byte;
        }
        let key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&header[..]),
            &mut plain,
        )
        .unwrap();
        let mut packet = header;
        packet.extend_from_slice(&plain);
        let mask = quic::HeaderProtectionKey::new(&quic::AES_128, &hp)
            .unwrap()
            .new_mask(&packet[pn_offset + 4..pn_offset + 20])
            .unwrap();
        packet[0] ^= mask[0] & 0x0f;
        for (byte, mask) in packet[pn_offset..pn_offset + 4].iter_mut().zip(&mask[1..]) {
            *byte ^= mask;
        }
        packet
    }

    fn client_hello(name: &str) -> Vec<u8> {
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name.as_bytes());
        // A large first extension, as post-quantum key shares make.
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0033u16.to_be_bytes());
        extensions.extend_from_slice(&1500u16.to_be_bytes());
        extensions.extend_from_slice(&[7u8; 1500]);
        extensions.extend_from_slice(&0u16.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut hello = vec![0x01];
        hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hello.extend_from_slice(&body);
        hello
    }

    fn crypto(offset: u64, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x06];
        frame.extend_from_slice(&(0x8000_0000u32 | offset as u32).to_be_bytes());
        frame.extend_from_slice(&(0x4000u16 | data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        frame
    }

    #[test]
    fn derives_the_rfc_9001_client_keys() {
        // RFC 9001 appendix A.1.
        let dcid = hex("8394c8f03e515708");
        let initial = hkdf::Salt::new(hkdf::HKDF_SHA256, &V1_SALT).extract(&dcid);
        let mut client = [0u8; 32];
        expand_label(&initial, "client in", &mut client).unwrap();
        assert_eq!(
            client.to_vec(),
            hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
        let client = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client);
        let mut key = [0u8; 16];
        expand_label(&client, "quic key", &mut key).unwrap();
        assert_eq!(key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        let mut hp = [0u8; 16];
        expand_label(&client, "quic hp", &mut hp).unwrap();
        assert_eq!(hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn finds_the_name_across_packets_and_out_of_order_frames() {
        let hello = client_hello("video.example.com");
        let dcid = hex("8394c8f03e515708");
        let split = 1000;
        // First datagram: the tail of its share before the head, as
        // Chrome sends.
        let mut first = crypto(600, &hello[600..split]);
        first.extend(crypto(0, &hello[..600]));
        let second = crypto(split as u64, &hello[split..]);

        for version in [V1, V2] {
            let mut sniffing = QuicHello::default();
            let one = initial(version, &dcid, &first);
            assert!(is_initial(&one));
            assert_eq!(sniffing.push(&one), Sniffed::Pending);
            let two = initial(version, &dcid, &second);
            assert_eq!(
                sniffing.push(&two),
                Sniffed::Name("video.example.com".into())
            );
        }
    }

    #[test]
    fn gives_up_on_other_traffic() {
        assert!(!is_initial(b"\x40short header"));
        let mut sniffing = QuicHello::default();
        assert_eq!(sniffing.push(b"not quic at all"), Sniffed::None);
        let mut corrupt = initial(V1, &[1, 2, 3, 4], &crypto(0, &[1, 2, 3]));
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert_eq!(QuicHello::default().push(&corrupt), Sniffed::None);
    }

    #[test]
    fn udp_flows_count_by_target_and_quic_name() {
        use crate::destinations::UdpDestinations;
        use crate::{User, UserStore};
        use std::net::SocketAddr;

        let store = UserStore::default();
        store.add(User::with_password("7", "secret")).unwrap();
        let mut flows = UdpDestinations::new(store.get("7"));

        let dns = TargetAddr::Domain("Dns.Example".into(), 53);
        flows.up(&dns, &[0u8; 30]);
        flows.down("198.51.100.53:53".parse().unwrap(), 70);

        let server: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let quic_target = TargetAddr::Ip(server);
        let hello = client_hello("video.example.com");
        let dcid = hex("0011223344556677");
        let one = initial(V1, &dcid, &crypto(0, &hello[..900]));
        let two = initial(V1, &dcid, &crypto(900, &hello[900..]));
        flows.up(&quic_target, &one);
        // A reply before the name shows waits with the flow.
        flows.down(server, 1000);
        flows.up(&quic_target, &two);
        flows.down(server, 5);

        let game = TargetAddr::Ip("192.0.2.1:27015".parse().unwrap());
        flows.up(&game, b"ping");
        flows.down("192.0.2.1:27015".parse().unwrap(), 6);

        let got: Vec<_> = store
            .destinations(true)
            .into_iter()
            .map(|entry| {
                (
                    entry.host,
                    entry.protocol,
                    entry.up,
                    entry.down,
                    entry.connections,
                )
            })
            .collect();
        assert_eq!(
            got,
            vec![
                ("192.0.2.1".into(), "udp".into(), 4, 6, 1),
                ("dns.example".into(), "udp".into(), 30, 70, 1),
                (
                    "video.example.com".into(),
                    "quic".into(),
                    (one.len() + two.len()) as u64,
                    1005,
                    1
                ),
            ]
        );
    }
}
