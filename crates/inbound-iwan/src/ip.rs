//! The few IPv4 operations the server does itself: header fields, gateway
//! ping replies and fragmentation to a session's MTU.

use std::net::Ipv4Addr;

pub const ICMP: u8 = 1;
pub const TCP: u8 = 6;
pub const UDP: u8 = 17;

const MORE_FRAGMENTS: u16 = 0x2000;
const OFFSET_MASK: u16 = 0x1fff;

/// The header fields of an IPv4 packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4 {
    pub header_len: usize,
    /// From the header, at most the packet length.
    pub total_len: usize,
    pub protocol: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl Ipv4 {
    pub fn parse(packet: &[u8]) -> Option<Self> {
        let first = *packet.first()?;
        if first >> 4 != 4 {
            return None;
        }
        let header_len = usize::from(first & 0x0f) * 4;
        if header_len < 20 || packet.len() < header_len {
            return None;
        }
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if total_len < header_len {
            return None;
        }
        Some(Self {
            header_len,
            total_len: total_len.min(packet.len()),
            protocol: packet[9],
            src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
            dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        })
    }
}

/// The Internet checksum of `data`.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let (pairs, rest) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let [last] = rest {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn set_header_checksum(packet: &mut [u8], header_len: usize) {
    packet[10..12].fill(0);
    let sum = checksum(&packet[..header_len]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
}

/// The reply to an unfragmented ICMP echo request, or `None` for any other
/// packet.
pub fn echo_reply(packet: &[u8]) -> Option<Vec<u8>> {
    let header = Ipv4::parse(packet)?;
    let flags = u16::from_be_bytes([packet[6], packet[7]]);
    if header.protocol != ICMP
        || flags & (MORE_FRAGMENTS | OFFSET_MASK) != 0
        || header.total_len < header.header_len + 8
    {
        return None;
    }
    let icmp = &packet[header.header_len..header.total_len];
    if icmp[0] != 8 || icmp[1] != 0 || checksum(icmp) != 0 {
        return None;
    }
    let mut reply = packet[..header.total_len].to_vec();
    reply[8] = 64;
    reply[12..16].copy_from_slice(&header.dst.octets());
    reply[16..20].copy_from_slice(&header.src.octets());
    set_header_checksum(&mut reply, header.header_len);
    let icmp = &mut reply[header.header_len..];
    icmp[0] = 0;
    icmp[2..4].fill(0);
    let sum = checksum(icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    Some(reply)
}

/// Splits `packet` into fragments of at most `mtu` bytes. A packet that fits
/// is returned whole; one whose header leaves no room is dropped (empty).
pub fn fragment(packet: &[u8], mtu: usize) -> Vec<Vec<u8>> {
    if packet.len() <= mtu {
        return vec![packet.to_vec()];
    }
    let Some(header) = Ipv4::parse(packet) else {
        return Vec::new();
    };
    let room = mtu.saturating_sub(header.header_len) / 8 * 8;
    if room == 0 {
        return Vec::new();
    }
    let flags = u16::from_be_bytes([packet[6], packet[7]]);
    let first_offset = usize::from(flags & OFFSET_MASK) * 8;
    let more_after = flags & MORE_FRAGMENTS != 0;
    let payload = &packet[header.header_len..header.total_len];
    let count = payload.len().div_ceil(room);
    let mut out = Vec::with_capacity(count);
    for (index, piece) in payload.chunks(room).enumerate() {
        let offset = first_offset + index * room;
        let more = more_after || index + 1 < count;
        let mut fragment = Vec::with_capacity(header.header_len + piece.len());
        fragment.extend_from_slice(&packet[..header.header_len]);
        fragment.extend_from_slice(piece);
        let total = (header.header_len + piece.len()) as u16;
        fragment[2..4].copy_from_slice(&total.to_be_bytes());
        // Don't Fragment is dropped: the session MTU is the only limit here.
        let mut field = (offset / 8) as u16 & OFFSET_MASK;
        if more {
            field |= MORE_FRAGMENTS;
        }
        fragment[6..8].copy_from_slice(&field.to_be_bytes());
        set_header_checksum(&mut fragment, header.header_len);
        out.push(fragment);
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An IPv4 packet with a valid header checksum.
    pub(crate) fn packet(protocol: u8, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0x45, 0, 0, 0, 0x12, 0x34, 0x40, 0, 64, protocol, 0, 0];
        out.extend_from_slice(&src.octets());
        out.extend_from_slice(&dst.octets());
        out.extend_from_slice(payload);
        let total = out.len() as u16;
        out[2..4].copy_from_slice(&total.to_be_bytes());
        set_header_checksum(&mut out, 20);
        out
    }

    pub(crate) fn echo_request(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut icmp = vec![8, 0, 0, 0, 0xab, 0xcd, 0, 1, b'p', b'i', b'n', b'g'];
        let sum = checksum(&icmp);
        icmp[2..4].copy_from_slice(&sum.to_be_bytes());
        packet(ICMP, src, dst, &icmp)
    }

    const A: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);
    const B: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);

    #[test]
    fn parses_headers() {
        let ip = packet(UDP, A, B, b"payload");
        let header = Ipv4::parse(&ip).unwrap();
        assert_eq!((header.header_len, header.total_len), (20, 27));
        assert_eq!((header.protocol, header.src, header.dst), (UDP, A, B));
        assert_eq!(checksum(&ip[..20]), 0);
        assert!(Ipv4::parse(&ip[..19]).is_none());
        let mut v6 = ip.clone();
        v6[0] = 0x60;
        assert!(Ipv4::parse(&v6).is_none());
    }

    #[test]
    fn answers_echo_requests_only() {
        let request = echo_request(A, B);
        let reply = echo_reply(&request).unwrap();
        let header = Ipv4::parse(&reply).unwrap();
        assert_eq!((header.src, header.dst), (B, A));
        assert_eq!(checksum(&reply[..20]), 0);
        assert_eq!(reply[20], 0);
        assert_eq!(checksum(&reply[20..]), 0);
        assert_eq!(&reply[24..], &request[24..]);
        assert!(echo_reply(&reply).is_none());
        assert!(echo_reply(&packet(UDP, A, B, &[8, 0, 0, 0, 0, 0, 0, 0])).is_none());
    }

    #[test]
    fn fragments_to_the_mtu() {
        let payload: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let ip = packet(UDP, A, B, &payload);
        assert_eq!(fragment(&ip, 1500), vec![ip.clone()]);
        let pieces = fragment(&ip, 420);
        assert_eq!(pieces.len(), 3);
        let mut joined = Vec::new();
        for (index, piece) in pieces.iter().enumerate() {
            assert!(piece.len() <= 420);
            assert_eq!(checksum(&piece[..20]), 0);
            let field = u16::from_be_bytes([piece[6], piece[7]]);
            assert_eq!(usize::from(field & OFFSET_MASK) * 8, joined.len());
            assert_eq!(field & MORE_FRAGMENTS != 0, index < 2);
            assert_eq!(Ipv4::parse(piece).unwrap().total_len, piece.len());
            joined.extend_from_slice(&piece[20..]);
        }
        assert_eq!(joined, payload);
        assert!(fragment(&ip, 24).is_empty());
    }
}
