//! PROXY protocol headers (HAProxy, versions 1 and 2) that a forward
//! writes to the target before the client's bytes, carrying the client's
//! address. Relays in between pass them on untouched, so the header is
//! written once, at the entry.

use std::net::{IpAddr, SocketAddr};

/// Which header, if any.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProxyProtocol {
    #[default]
    Off,
    V1,
    V2,
}

impl ProxyProtocol {
    /// `off`, `v1` or `v2`; the forward.v1 enum names
    /// (`PROXY_PROTOCOL_V2`) are accepted too, and `UNSPECIFIED` is off.
    pub fn parse(value: &str) -> Option<ProxyProtocol> {
        let value = value.trim();
        let name = value
            .strip_prefix("PROXY_PROTOCOL_")
            .unwrap_or(value)
            .to_ascii_lowercase();
        Some(match name.as_str() {
            "off" | "unspecified" => ProxyProtocol::Off,
            "v1" => ProxyProtocol::V1,
            "v2" => ProxyProtocol::V2,
            _ => return None,
        })
    }

    /// The header for a TCP connection from `source` (the client) to
    /// `destination` (the address it reached); empty when off.
    pub fn header(self, source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
        let (source, destination) = same_family(source, destination);
        match self {
            ProxyProtocol::Off => Vec::new(),
            ProxyProtocol::V1 => {
                let family = if source.is_ipv4() { "TCP4" } else { "TCP6" };
                format!(
                    "PROXY {family} {} {} {} {}\r\n",
                    source.ip(),
                    destination.ip(),
                    source.port(),
                    destination.port()
                )
                .into_bytes()
            }
            ProxyProtocol::V2 => {
                let mut header = SIGNATURE.to_vec();
                // Version 2, PROXY command.
                header.push(0x21);
                let mut addresses = Vec::with_capacity(36);
                match (source.ip(), destination.ip()) {
                    (IpAddr::V4(from), IpAddr::V4(to)) => {
                        // AF_INET, STREAM.
                        header.push(0x11);
                        addresses.extend_from_slice(&from.octets());
                        addresses.extend_from_slice(&to.octets());
                    }
                    (from, to) => {
                        // AF_INET6, STREAM.
                        header.push(0x21);
                        addresses.extend_from_slice(&v6(from).octets());
                        addresses.extend_from_slice(&v6(to).octets());
                    }
                }
                addresses.extend_from_slice(&source.port().to_be_bytes());
                addresses.extend_from_slice(&destination.port().to_be_bytes());
                header.extend_from_slice(&(addresses.len() as u16).to_be_bytes());
                header.extend_from_slice(&addresses);
                header
            }
        }
    }
}

const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";

fn v6(ip: IpAddr) -> std::net::Ipv6Addr {
    match ip {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    }
}

/// Unmaps IPv4-mapped addresses, then puts both in IPv6 if they still
/// differ in family.
fn same_family(source: SocketAddr, destination: SocketAddr) -> (SocketAddr, SocketAddr) {
    let canonical = |addr: SocketAddr| SocketAddr::new(addr.ip().to_canonical(), addr.port());
    let (source, destination) = (canonical(source), canonical(destination));
    if source.is_ipv4() == destination.is_ipv4() {
        return (source, destination);
    }
    let widen = |addr: SocketAddr| SocketAddr::new(IpAddr::V6(v6(addr.ip())), addr.port());
    (widen(source), widen(destination))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_settings() {
        assert_eq!(ProxyProtocol::parse("v1"), Some(ProxyProtocol::V1));
        assert_eq!(
            ProxyProtocol::parse("PROXY_PROTOCOL_V2"),
            Some(ProxyProtocol::V2)
        );
        assert_eq!(
            ProxyProtocol::parse("PROXY_PROTOCOL_UNSPECIFIED"),
            Some(ProxyProtocol::Off)
        );
        assert_eq!(ProxyProtocol::parse("v3"), None);
    }

    #[test]
    fn writes_version_1() {
        let header = ProxyProtocol::V1.header(
            "[::ffff:198.51.100.7]:50000".parse().unwrap(),
            "203.0.113.1:443".parse().unwrap(),
        );
        assert_eq!(header, b"PROXY TCP4 198.51.100.7 203.0.113.1 50000 443\r\n");
        let header = ProxyProtocol::V1.header(
            "[2001:db8::7]:50000".parse().unwrap(),
            "203.0.113.1:443".parse().unwrap(),
        );
        assert_eq!(
            header,
            b"PROXY TCP6 2001:db8::7 ::ffff:203.0.113.1 50000 443\r\n"
        );
        assert!(ProxyProtocol::Off
            .header(
                "198.51.100.7:1".parse().unwrap(),
                "203.0.113.1:2".parse().unwrap()
            )
            .is_empty());
    }

    #[test]
    fn writes_version_2() {
        let header = ProxyProtocol::V2.header(
            "198.51.100.7:50000".parse().unwrap(),
            "203.0.113.1:443".parse().unwrap(),
        );
        let mut expected = SIGNATURE.to_vec();
        expected.extend_from_slice(&[0x21, 0x11, 0, 12]);
        expected.extend_from_slice(&[198, 51, 100, 7, 203, 0, 113, 1]);
        expected.extend_from_slice(&[0xc3, 0x50, 0x01, 0xbb]);
        assert_eq!(header, expected);
        let header = ProxyProtocol::V2.header(
            "[2001:db8::7]:1".parse().unwrap(),
            "[2001:db8::1]:2".parse().unwrap(),
        );
        assert_eq!(header.len(), 16 + 36);
        assert_eq!(&header[12..16], &[0x21, 0x21, 0, 36]);
    }
}
