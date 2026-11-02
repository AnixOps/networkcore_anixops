//! ICMP "port unreachable" for UDP datagrams the tunnel cannot carry.
//!
//! An outbound without UDP (ANX-A, Trojan, plain HTTP proxies, …) used to
//! drop QUIC silently, so a browser or the YouTube app waited for its QUIC
//! handshake to time out before falling back to TCP, which delays page loads
//! and video start. A port unreachable for the dropped datagram makes the
//! app's connected UDP socket fail at once (`ECONNREFUSED`), and QUIC
//! clients then go straight to TCP.

use std::net::{IpAddr, SocketAddr};

const IPV4_HEADER: usize = 20;
const UDP_HEADER: usize = 8;
const TTL: u8 = 64;

/// The IP packet that tells `app` its datagram of `payload_len` bytes to
/// `destination` was refused, as if sent by `destination`; `None` when the
/// two addresses are of different families.
pub fn port_unreachable(
    app: SocketAddr,
    destination: SocketAddr,
    payload_len: usize,
) -> Option<Vec<u8>> {
    let udp_len = u16::try_from(UDP_HEADER + payload_len).unwrap_or(u16::MAX);
    match (app.ip(), destination.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            // The quoted datagram: its IPv4 header and UDP header.
            let mut quoted = ipv4_header(
                src.octets(),
                dst.octets(),
                17,
                udp_len.saturating_add(IPV4_HEADER as u16),
            );
            quoted.extend_from_slice(&udp_header(app.port(), destination.port(), udp_len));
            let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(&quoted);
            let sum = checksum(&[&icmp]);
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            let mut packet = ipv4_header(
                dst.octets(),
                src.octets(),
                1,
                (IPV4_HEADER + icmp.len()) as u16,
            );
            packet.extend_from_slice(&icmp);
            Some(packet)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut quoted = ipv6_header(src.octets(), dst.octets(), 17, udp_len);
            quoted.extend_from_slice(&udp_header(app.port(), destination.port(), udp_len));
            let mut icmp = vec![1, 4, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(&quoted);
            let length = (icmp.len() as u32).to_be_bytes();
            let pseudo_tail = [0, 0, 0, 58];
            let sum = checksum(&[&dst.octets(), &src.octets(), &length, &pseudo_tail, &icmp]);
            icmp[2..4].copy_from_slice(&sum.to_be_bytes());
            let mut packet = ipv6_header(dst.octets(), src.octets(), 58, icmp.len() as u16);
            packet.extend_from_slice(&icmp);
            Some(packet)
        }
        _ => None,
    }
}

fn ipv4_header(src: [u8; 4], dst: [u8; 4], protocol: u8, total_len: u16) -> Vec<u8> {
    let mut header = vec![0x45, 0];
    header.extend_from_slice(&total_len.to_be_bytes());
    header.extend_from_slice(&[0, 0, 0x40, 0, TTL, protocol, 0, 0]);
    header.extend_from_slice(&src);
    header.extend_from_slice(&dst);
    let sum = checksum(&[&header]);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    header
}

fn ipv6_header(src: [u8; 16], dst: [u8; 16], next: u8, payload_len: u16) -> Vec<u8> {
    let mut header = vec![0x60, 0, 0, 0];
    header.extend_from_slice(&payload_len.to_be_bytes());
    header.extend_from_slice(&[next, TTL]);
    header.extend_from_slice(&src);
    header.extend_from_slice(&dst);
    header
}

/// A UDP header without checksum (the quoted copy only has to name the flow).
fn udp_header(src_port: u16, dst_port: u16, len: u16) -> [u8; 8] {
    let [a, b] = src_port.to_be_bytes();
    let [c, d] = dst_port.to_be_bytes();
    let [e, f] = len.to_be_bytes();
    [a, b, c, d, e, f, 0, 0]
}

/// The Internet checksum over `parts` taken as one byte string.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut odd: Option<u8> = None;
    for part in parts {
        for &byte in *part {
            match odd.take() {
                Some(high) => sum += u32::from(u16::from_be_bytes([high, byte])),
                None => odd = Some(byte),
            }
        }
    }
    if let Some(high) = odd {
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_port_unreachable_quotes_the_datagram() {
        let app: SocketAddr = "10.0.0.2:51000".parse().unwrap();
        let dst: SocketAddr = "142.250.1.1:443".parse().unwrap();
        let packet = port_unreachable(app, dst, 1200).unwrap();
        assert_eq!(packet.len(), 20 + 8 + 20 + 8);
        assert_eq!(&packet[12..16], &[142, 250, 1, 1], "from the destination");
        assert_eq!(&packet[16..20], &[10, 0, 0, 2], "to the app");
        assert_eq!(packet[9], 1, "ICMP");
        assert_eq!(checksum(&[&packet[..20]]), 0, "IP header checksum");
        let icmp = &packet[20..];
        assert_eq!(&icmp[..2], &[3, 3], "port unreachable");
        assert_eq!(checksum(&[icmp]), 0, "ICMP checksum");
        let quoted = &icmp[8..];
        assert_eq!(&quoted[12..16], &[10, 0, 0, 2]);
        assert_eq!(&quoted[16..20], &[142, 250, 1, 1]);
        assert_eq!(&quoted[20..22], &51000u16.to_be_bytes());
        assert_eq!(&quoted[22..24], &443u16.to_be_bytes());
        assert_eq!(&quoted[24..26], &1208u16.to_be_bytes());
    }

    #[test]
    fn ipv6_port_unreachable_has_a_valid_checksum() {
        let app: SocketAddr = "[fd00::2]:51000".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let packet = port_unreachable(app, dst, 1200).unwrap();
        assert_eq!(packet.len(), 40 + 8 + 40 + 8);
        assert_eq!(packet[6], 58, "ICMPv6");
        let icmp = &packet[40..];
        assert_eq!(&icmp[..2], &[1, 4], "port unreachable");
        let length = (icmp.len() as u32).to_be_bytes();
        assert_eq!(
            checksum(&[
                &packet[8..24],
                &packet[24..40],
                &length,
                &[0, 0, 0, 58],
                icmp
            ]),
            0
        );
        assert_eq!(&icmp[8 + 40 + 2..8 + 40 + 4], &443u16.to_be_bytes());
        assert!(port_unreachable(app, "1.1.1.1:443".parse().unwrap(), 10).is_none());
    }
}
