//! Wire format: the 8-byte header, the header signature, TLVs and every
//! packet the client sends or reads (spec §3, §4, §6, §7, §8).

use std::net::Ipv4Addr;

use crate::crypto::{self, XorKey, PASSWORD_BLOCK};

pub const HEADER_LEN: usize = 8;
pub const SIGNATURE_LEN: usize = 16;
/// Header plus signature; control payloads start here.
pub const SIGNED_LEN: usize = HEADER_LEN + SIGNATURE_LEN;
/// Largest datagram the client handles (spec §6.1).
pub const MAX_DATAGRAM: usize = 2048;
/// ECHOREQ payload length (spec §6.4).
pub const ECHO_PAYLOAD_LEN: usize = 36;
/// Longest username a TLV can carry.
pub const MAX_USERNAME_LEN: usize = 253;

/// Packet type byte (spec §3.3).
pub mod kind {
    pub const OPENREJ: u8 = 0x11;
    pub const OPENACK: u8 = 0x12;
    pub const OPEN: u8 = 0x13;
    pub const DATA: u8 = 0x14;
    pub const ECHOREQ: u8 = 0x15;
    pub const ECHORESP: u8 = 0x16;
    pub const CLOSE: u8 = 0x17;
    pub const DATA_ENC: u8 = 0x18;
    pub const IPFRAG: u8 = 0x21;
    pub const SR_IPFRAG: u8 = 0x22;
    pub const SEGRT: u8 = 0x27;
}

/// OPENREJ reasons seen from Panabit servers.
pub mod reject {
    /// Wrong user name or password.
    pub const INVALID_PASSWORD: &str = "INVPASS";
    /// The login was accepted but the server's address pool is exhausted.
    pub const NO_FREE_ADDRESS: &str = "NO_FREEIP_INPOOL";
}

/// Longest OPENREJ reason kept.
const MAX_REJECT_REASON: usize = 64;

/// TLV types of OPEN and OPENACK (spec §4.1, §4.3).
pub mod tlv {
    pub const USERNAME: u8 = 1;
    pub const PASSWORD: u8 = 2;
    pub const MTU: u8 = 3;
    pub const ADDRESS: u8 = 4;
    pub const DNS0: u8 = 5;
    pub const DNS_PAIR: u8 = 6;
    pub const PEER_DUP: u8 = 7;
    pub const ENCRYPT: u8 = 8;
    pub const PIPE: u8 = 0x0A;
}

/// The session identifiers the server hands out in OPENACK. The client echoes
/// them and never interprets their values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Session {
    pub token: [u8; 2],
    pub id: [u8; 4],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u8,
    /// Encryption mode in OPEN, OPENACK and DATA_ENC; 0 elsewhere.
    pub flags: u8,
    pub session: Session,
}

impl Header {
    pub fn new(kind: u8, flags: u8, session: Session) -> Self {
        Self {
            kind,
            flags,
            session,
        }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = self.kind;
        out[1] = self.flags;
        out[2..4].copy_from_slice(&self.session.token);
        out[4..8].copy_from_slice(&self.session.id);
        out
    }

    pub fn decode(datagram: &[u8]) -> Option<Self> {
        let bytes = datagram.get(..HEADER_LEN)?;
        let mut token = [0u8; 2];
        token.copy_from_slice(&bytes[2..4]);
        let mut id = [0u8; 4];
        id.copy_from_slice(&bytes[4..8]);
        Some(Self {
            kind: bytes[0],
            flags: bytes[1],
            session: Session { token, id },
        })
    }
}

/// `MD5(header ‖ "mw")` (spec §3.2). Covers the header only and has no key.
pub fn signature(header: &[u8; HEADER_LEN]) -> [u8; SIGNATURE_LEN] {
    crypto::md5(&[header, b"mw"])
}

/// A control packet: header, signature, then `payload`.
pub fn signed(header: Header, payload: &[u8]) -> Vec<u8> {
    let header = header.encode();
    let mut out = Vec::with_capacity(SIGNED_LEN + payload.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&signature(&header));
    out.extend_from_slice(payload);
    out
}

/// Checks the signature of a control packet and returns its header and
/// payload, or `None` when it is shorter than 24 bytes or the signature differs.
pub fn verify_signed(datagram: &[u8]) -> Option<(Header, &[u8])> {
    if datagram.len() < SIGNED_LEN {
        return None;
    }
    let mut header = [0u8; HEADER_LEN];
    header.copy_from_slice(&datagram[..HEADER_LEN]);
    if signature(&header) != datagram[HEADER_LEN..SIGNED_LEN] {
        return None;
    }
    Some((Header::decode(&header)?, &datagram[SIGNED_LEN..]))
}

/// Appends one TLV. The 1-byte length counts the 2-byte TLV header, so a
/// value is at most 253 bytes.
pub fn push_tlv(out: &mut Vec<u8>, kind: u8, value: &[u8]) {
    assert!(value.len() <= MAX_USERNAME_LEN, "TLV value too long");
    out.push(kind);
    out.push((value.len() + 2) as u8);
    out.extend_from_slice(value);
}

/// TLVs of a payload, in order. Parsing stops at the first malformed entry;
/// the entries before it are kept (spec §3.4).
pub struct Tlvs<'a> {
    rest: &'a [u8],
    malformed: bool,
}

impl<'a> Tlvs<'a> {
    pub fn new(payload: &'a [u8]) -> Self {
        Self {
            rest: payload,
            malformed: false,
        }
    }

    /// Whether parsing stopped at a malformed entry.
    pub fn malformed(&self) -> bool {
        self.malformed
    }
}

impl<'a> Iterator for Tlvs<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() || self.malformed {
            return None;
        }
        let total = match self.rest {
            [_, total, ..] => *total as usize,
            _ => 0,
        };
        if total < 2 || total > self.rest.len() {
            self.malformed = true;
            return None;
        }
        let kind = self.rest[0];
        let value = &self.rest[2..total];
        self.rest = &self.rest[total..];
        Some((kind, value))
    }
}

/// What the client puts in OPEN (spec §4.1).
pub struct OpenRequest<'a> {
    pub username: &'a [u8],
    pub password: &'a [u8],
    pub mtu: u16,
    pub encrypt: bool,
    pub pipe_id: u16,
    pub pipe_idx: u8,
}

/// OPEN: zero session, flags = encryption mode, TLVs MTU, username, password
/// block, then encryption mode and pipe only when set.
pub fn encode_open(request: &OpenRequest<'_>) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64 + request.username.len());
    push_tlv(&mut payload, tlv::MTU, &request.mtu.to_be_bytes());
    push_tlv(&mut payload, tlv::USERNAME, request.username);
    push_tlv(
        &mut payload,
        tlv::PASSWORD,
        &crypto::encrypt_password(request.username, request.password),
    );
    if request.encrypt {
        push_tlv(&mut payload, tlv::ENCRYPT, &[1]);
    }
    if request.pipe_id != 0 || request.pipe_idx != 0 {
        let pipe = request.pipe_id | (u16::from(request.pipe_idx) << 15);
        push_tlv(&mut payload, tlv::PIPE, &pipe.to_be_bytes());
    }
    let header = Header::new(kind::OPEN, u8::from(request.encrypt), Session::default());
    signed(header, &payload)
}

/// The fields of an OPEN as a server reads them; used by `inbound-iwan` and tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpenFields {
    pub flags: u8,
    pub mtu: Option<u16>,
    pub username: Option<Vec<u8>>,
    pub password_block: Option<[u8; PASSWORD_BLOCK]>,
    pub encrypt: Option<u8>,
    pub pipe: Option<u16>,
}

/// Parses a signed OPEN.
pub fn decode_open(datagram: &[u8]) -> Option<OpenFields> {
    let (header, payload) = verify_signed(datagram)?;
    if header.kind != kind::OPEN {
        return None;
    }
    let mut fields = OpenFields {
        flags: header.flags,
        ..OpenFields::default()
    };
    let mut tlvs = Tlvs::new(payload);
    for (kind, value) in &mut tlvs {
        match kind {
            tlv::MTU => fields.mtu = be_u16(value),
            tlv::USERNAME => fields.username = Some(value.to_vec()),
            tlv::PASSWORD => fields.password_block = value.try_into().ok(),
            tlv::ENCRYPT => fields.encrypt = value.first().copied(),
            tlv::PIPE => fields.pipe = be_u16(value),
            _ => {}
        }
    }
    if tlvs.malformed() {
        return None;
    }
    Some(fields)
}

/// The session parameters of an OPENACK (spec §4.3).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpenAck {
    pub session: Session,
    pub flags: u8,
    pub server_mtu: Option<u16>,
    pub address: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub peer_dup: Option<u8>,
    /// Negotiated data-plane mode; 0 without the TLV.
    pub encrypt: u8,
}

/// Parses a signed OPENACK. TLVs whose value is too short are ignored; a
/// malformed TLV ends parsing and keeps what came before.
pub fn decode_open_ack(datagram: &[u8]) -> Option<OpenAck> {
    let (header, payload) = verify_signed(datagram)?;
    if header.kind != kind::OPENACK {
        return None;
    }
    let mut ack = OpenAck {
        session: header.session,
        flags: header.flags,
        ..OpenAck::default()
    };
    let mut dns0 = None;
    let mut dns1 = None;
    for (kind, value) in Tlvs::new(payload) {
        match kind {
            tlv::MTU => {
                if let Some(mtu) = be_u16(value) {
                    ack.server_mtu = Some(mtu);
                }
            }
            tlv::ADDRESS => {
                if let Some(address) = ipv4(value) {
                    ack.address = Some(address);
                }
            }
            tlv::DNS0 => {
                if let Some(address) = ipv4(value) {
                    dns0 = Some(address);
                }
            }
            tlv::DNS_PAIR => {
                if let Some(address) = ipv4(value) {
                    dns0 = Some(address);
                    dns1 = value.get(4..).and_then(ipv4);
                }
            }
            tlv::PEER_DUP => {
                if let Some(flag) = value.first() {
                    ack.peer_dup = Some(*flag);
                }
            }
            tlv::ENCRYPT => {
                if let Some(mode) = value.first() {
                    ack.encrypt = *mode;
                }
            }
            _ => {}
        }
    }
    ack.dns = [dns0, dns1]
        .into_iter()
        .flatten()
        .filter(|address| !address.is_unspecified())
        .collect();
    Some(ack)
}

/// OPENACK as a server sends it; used by `inbound-iwan` and tests.
pub fn encode_open_ack(session: Session, encrypt: u8, tlvs: &[(u8, &[u8])]) -> Vec<u8> {
    let mut payload = Vec::new();
    for (kind, value) in tlvs {
        push_tlv(&mut payload, *kind, value);
    }
    signed(Header::new(kind::OPENACK, encrypt, session), &payload)
}

/// OPENREJ: header and signature, zero session, no reason.
pub fn encode_open_rej() -> Vec<u8> {
    encode_open_rej_with(&[])
}

/// OPENREJ with an ASCII reason after the signature, as Panabit sends.
pub fn encode_open_rej_with(reason: &[u8]) -> Vec<u8> {
    signed(Header::new(kind::OPENREJ, 0, Session::default()), reason)
}

/// The reason text of an OPENREJ: printable ASCII after the signature, up
/// to the first NUL; `None` when there is none.
pub fn open_rej_reason(datagram: &[u8]) -> Option<String> {
    let text = datagram.get(SIGNED_LEN..)?;
    let text = text.split(|byte| *byte == 0).next().unwrap_or_default();
    let text = &text[..text.len().min(MAX_REJECT_REASON)];
    if text.is_empty()
        || !text
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        return None;
    }
    String::from_utf8(text.to_vec()).ok()
}

/// DATA (0x14) or, when `xor` is set, DATA_ENC (0x18) with the masked packet.
pub fn encode_data(session: Session, xor: Option<&XorKey>, ip: &[u8]) -> Vec<u8> {
    let (kind, flags) = match xor {
        Some(_) => (kind::DATA_ENC, 1),
        None => (kind::DATA, 0),
    };
    let mut out = Vec::with_capacity(HEADER_LEN + ip.len());
    out.extend_from_slice(&Header::new(kind, flags, session).encode());
    out.extend_from_slice(ip);
    if let Some(xor) = xor {
        xor.apply(&mut out[HEADER_LEN..]);
    }
    out
}

/// CLOSE: header and signature, no payload.
pub fn encode_close(session: Session) -> Vec<u8> {
    signed(Header::new(kind::CLOSE, 0, session), &[])
}

/// The latency fields of an ECHOREQ, in microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EchoRequest {
    pub sent_us: u64,
    pub current_us: u32,
    pub min_us: u32,
    pub max_us: u32,
    pub route_magic: u32,
}

/// ECHOREQ: 60 bytes, little-endian latency fields, "TDR\0" marker,
/// big-endian route magic (spec §6.4).
pub fn encode_echo_request(session: Session, echo: &EchoRequest) -> Vec<u8> {
    let mut payload = [0u8; ECHO_PAYLOAD_LEN];
    payload[0..8].copy_from_slice(&echo.sent_us.to_le_bytes());
    payload[8..12].copy_from_slice(&echo.current_us.to_le_bytes());
    payload[12..16].copy_from_slice(&echo.min_us.to_le_bytes());
    payload[16..20].copy_from_slice(&echo.max_us.to_le_bytes());
    payload[24..28].copy_from_slice(b"TDR\0");
    payload[28..32].copy_from_slice(&echo.route_magic.to_be_bytes());
    signed(Header::new(kind::ECHOREQ, 0, session), &payload)
}

/// The send time of a signed ECHORESP, from the first 8 echoed bytes.
pub fn decode_echo_response(datagram: &[u8]) -> Option<u64> {
    let (header, payload) = verify_signed(datagram)?;
    if header.kind != kind::ECHORESP {
        return None;
    }
    let sent: [u8; 8] = payload.get(..8)?.try_into().ok()?;
    Some(u64::from_le_bytes(sent))
}

/// One IPFRAG piece (spec §7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub group: [u8; 4],
    pub offset: usize,
    pub last: bool,
    pub data: &'a [u8],
}

/// IPFRAG bitfield, little-endian: bit 0 last, bits 2-14 offset, bits 15-25 length.
pub fn fragment_bits(offset: usize, len: usize, last: bool) -> u32 {
    u32::from(last) | ((offset as u32 & 0x1FFF) << 2) | ((len as u32 & 0x7FF) << 15)
}

/// Parses an IPFRAG datagram. The datagram must be exactly 24 bytes plus the
/// piece length, and the piece must not be empty.
pub fn decode_fragment(datagram: &[u8]) -> Option<Fragment<'_>> {
    if datagram.len() < SIGNED_LEN {
        return None;
    }
    let group: [u8; 4] = datagram[16..20].try_into().ok()?;
    let bits = u32::from_le_bytes(datagram[20..24].try_into().ok()?);
    let last = bits & 1 == 1;
    let offset = ((bits >> 2) & 0x1FFF) as usize;
    let len = ((bits >> 15) & 0x7FF) as usize;
    if len == 0 || datagram.len() != SIGNED_LEN + len {
        return None;
    }
    Some(Fragment {
        group,
        offset,
        last,
        data: &datagram[SIGNED_LEN..],
    })
}

/// The inner DATA or DATA_ENC packet of an unencrypted SEGRT (spec §8), or
/// `None` for anything the first version does not handle.
pub fn segrt_inner(datagram: &[u8]) -> Option<&[u8]> {
    let route = datagram.get(HEADER_LEN..HEADER_LEN + 4)?;
    let links = usize::from(route[1]);
    let algorithm = route[2] & 0x07;
    if algorithm != 0 {
        return None;
    }
    let inner = datagram.get(HEADER_LEN + 4 + links * 4..)?;
    match inner.first() {
        Some(&kind::DATA) | Some(&kind::DATA_ENC) => Some(inner),
        _ => None,
    }
}

fn be_u16(value: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(value.get(..2)?.try_into().ok()?))
}

fn ipv4(value: &[u8]) -> Option<Ipv4Addr> {
    let octets: [u8; 4] = value.get(..4)?.try_into().ok()?;
    Some(Ipv4Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    const SESSION: Session = Session {
        token: [0xAB, 0xCD],
        id: [1, 2, 3, 4],
    };

    #[test]
    fn signature_vectors() {
        assert_eq!(
            hex(&signature(&[0x13, 0, 0, 0, 0, 0, 0, 0])),
            "39c6b588392392701064efe9e0dd4e98"
        );
        let close = encode_close(SESSION);
        assert_eq!(close.len(), 24);
        assert_eq!(hex(&close[..8]), "1700abcd01020304");
        assert_eq!(hex(&close[8..]), "1aa88885639088ec0792b6a48ba62c69");
    }

    #[test]
    fn open_rej_reasons() {
        assert_eq!(open_rej_reason(&encode_open_rej()), None);
        let rej = encode_open_rej_with(reject::NO_FREE_ADDRESS.as_bytes());
        assert_eq!(rej[0], kind::OPENREJ);
        assert!(verify_signed(&rej).is_some());
        assert_eq!(open_rej_reason(&rej).as_deref(), Some("NO_FREEIP_INPOOL"));
        let padded = encode_open_rej_with(b"INVPASS\0\0\0");
        assert_eq!(open_rej_reason(&padded).as_deref(), Some("INVPASS"));
        assert_eq!(open_rej_reason(&encode_open_rej_with(&[0xff, b'x'])), None);
        assert_eq!(open_rej_reason(&rej[..8]), None);
    }

    #[test]
    fn verify_rejects_short_or_tampered_packets() {
        let close = encode_close(SESSION);
        assert!(verify_signed(&close).is_some());
        assert!(verify_signed(&close[..23]).is_none());
        let mut tampered = close.clone();
        tampered[3] ^= 1;
        assert!(verify_signed(&tampered).is_none());
        // The signature does not cover the payload.
        let mut extended = close;
        extended.push(9);
        assert_eq!(verify_signed(&extended).unwrap().1, &[9]);
    }

    #[test]
    fn open_layout_without_optional_tlvs() {
        let open = encode_open(&OpenRequest {
            username: b"alice",
            password: b"secret",
            mtu: 1400,
            encrypt: false,
            pipe_id: 0,
            pipe_idx: 0,
        });
        assert_eq!(hex(&open[..8]), "1300000000000000");
        assert_eq!(hex(&open[8..24]), "39c6b588392392701064efe9e0dd4e98");
        assert_eq!(
            hex(&open[24..]),
            concat!(
                "03040578",
                "0107616c696365",
                "0212567e3c4f58d08532529f8191a0ae0d9d"
            )
        );
    }

    #[test]
    fn open_with_encryption_and_pipe() {
        let open = encode_open(&OpenRequest {
            username: b"alice",
            password: b"secret",
            mtu: 1300,
            encrypt: true,
            pipe_id: 5,
            pipe_idx: 1,
        });
        assert_eq!(open[1], 1);
        // Encryption mode TLV, then pipe 5 | (1 << 15).
        assert!(hex(&open).ends_with("0803010a048005"));
        let fields = decode_open(&open).unwrap();
        assert_eq!(fields.flags, 1);
        assert_eq!(fields.mtu, Some(1300));
        assert_eq!(fields.username.as_deref(), Some(&b"alice"[..]));
        assert_eq!(
            fields.password_block,
            Some(crypto::encrypt_password(b"alice", b"secret"))
        );
        assert_eq!(fields.encrypt, Some(1));
        assert_eq!(fields.pipe, Some(0x8005));
    }

    #[test]
    fn tlv_parsing_stops_at_malformed_entry() {
        let mut tlvs = Tlvs::new(&[1, 3, 7, 2, 1, 9]);
        assert_eq!(tlvs.next(), Some((1, &[7][..])));
        assert_eq!(tlvs.next(), None);
        assert!(tlvs.malformed());
        let mut tlvs = Tlvs::new(&[1, 5, 7]);
        assert_eq!(tlvs.next(), None);
        assert!(tlvs.malformed());
        let mut tlvs = Tlvs::new(&[1]);
        assert_eq!(tlvs.next(), None);
        assert!(tlvs.malformed());
        let mut tlvs = Tlvs::new(&[9, 2]);
        assert_eq!(tlvs.next(), Some((9, &[][..])));
        assert_eq!(tlvs.next(), None);
        assert!(!tlvs.malformed());
    }

    #[test]
    fn open_ack_fields() {
        let ack = encode_open_ack(
            SESSION,
            1,
            &[
                (tlv::MTU, &1380u16.to_be_bytes()),
                (tlv::ADDRESS, &[10, 20, 30, 10]),
                (tlv::DNS_PAIR, &[1, 1, 1, 1, 8, 8, 8, 8]),
                (tlv::PEER_DUP, &[1]),
                (tlv::ENCRYPT, &[1]),
                (0x55, &[1, 2, 3]),
            ],
        );
        let ack = decode_open_ack(&ack).unwrap();
        assert_eq!(ack.session, SESSION);
        assert_eq!(ack.server_mtu, Some(1380));
        assert_eq!(ack.address, Some(Ipv4Addr::new(10, 20, 30, 10)));
        assert_eq!(
            ack.dns,
            vec![Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8)]
        );
        assert_eq!(ack.peer_dup, Some(1));
        assert_eq!(ack.encrypt, 1);
    }

    #[test]
    fn open_ack_short_values_and_malformed_tail() {
        let mut payload = Vec::new();
        push_tlv(&mut payload, tlv::ADDRESS, &[10, 0, 0, 2]);
        push_tlv(&mut payload, tlv::DNS0, &[9, 9]);
        push_tlv(&mut payload, tlv::DNS_PAIR, &[1, 0, 0, 1, 2]);
        payload.extend_from_slice(&[tlv::ENCRYPT, 9, 1]);
        let datagram = signed(Header::new(kind::OPENACK, 0, SESSION), &payload);
        let ack = decode_open_ack(&datagram).unwrap();
        assert_eq!(ack.address, Some(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(ack.dns, vec![Ipv4Addr::new(1, 0, 0, 1)]);
        assert_eq!(ack.encrypt, 0);
        assert_eq!(ack.server_mtu, None);
    }

    #[test]
    fn data_types_follow_the_mode() {
        let key = XorKey::new(b"alice", b"secret");
        let plain = encode_data(SESSION, None, &[1, 2, 3]);
        assert_eq!(hex(&plain), "1400abcd01020304010203");
        let masked = encode_data(SESSION, Some(&key), &[0, 0, 0]);
        assert_eq!(hex(&masked), "1801abcd01020304c4e313");
    }

    #[test]
    fn echo_request_layout_and_response() {
        let echo = EchoRequest {
            sent_us: 0x0102_0304_0506_0708,
            current_us: 1000,
            min_us: 5_000_000,
            max_us: 0,
            route_magic: 0,
        };
        let request = encode_echo_request(SESSION, &echo);
        assert_eq!(request.len(), 60);
        assert_eq!(hex(&request[24..32]), "0807060504030201");
        assert_eq!(hex(&request[32..36]), "e8030000");
        assert_eq!(hex(&request[36..40]), "404b4c00");
        assert_eq!(&request[48..52], b"TDR\0");
        assert_eq!(&request[52..60], &[0u8; 8]);
        let mut response = request.clone();
        let header = Header::new(kind::ECHORESP, 0, SESSION).encode();
        response[..8].copy_from_slice(&header);
        response[8..24].copy_from_slice(&signature(&header));
        assert_eq!(decode_echo_response(&response), Some(echo.sent_us));
        assert_eq!(decode_echo_response(&request), None);
    }

    #[test]
    fn fragment_bitfield() {
        let mut datagram = vec![kind::IPFRAG, 0, 0, 0, 0, 0, 0, 0];
        datagram.extend_from_slice(&[0; 8]);
        datagram.extend_from_slice(&[7, 7, 7, 7]);
        datagram.extend_from_slice(&fragment_bits(1200, 3, true).to_le_bytes());
        datagram.extend_from_slice(&[1, 2, 3]);
        let fragment = decode_fragment(&datagram).unwrap();
        assert_eq!(fragment.group, [7; 4]);
        assert_eq!(fragment.offset, 1200);
        assert!(fragment.last);
        assert_eq!(fragment.data, &[1, 2, 3]);
        // Length must match the datagram exactly.
        datagram.push(4);
        assert!(decode_fragment(&datagram).is_none());
    }

    #[test]
    fn segrt_without_encryption_yields_inner_data() {
        let inner = encode_data(SESSION, None, &[0x45, 0, 0, 20]);
        let mut datagram = Header::new(kind::SEGRT, 0, SESSION).encode().to_vec();
        datagram.extend_from_slice(&[0, 2, 0, 0]);
        datagram.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        datagram.extend_from_slice(&inner);
        assert_eq!(segrt_inner(&datagram), Some(&inner[..]));
        datagram[HEADER_LEN + 2] = 1;
        assert_eq!(segrt_inner(&datagram), None);
    }
}
