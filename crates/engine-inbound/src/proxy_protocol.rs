//! PROXY protocol headers (HAProxy, versions 1 and 2), which carry a
//! client's address past a relay.
//!
//! A forward writes one to the target before the client's bytes
//! ([`ProxyProtocol::header`]); relays in between pass it on untouched, so
//! the header is written once, at the entry. A listener behind such a relay
//! or a load balancer reads it ahead of everything else ([`read_header`])
//! and takes the client's address from it.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

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
/// Longest version 1 header, with its CRLF.
const V1_MAX: usize = 107;

/// The client's address and the address it reached.
pub type Endpoints = (SocketAddr, SocketAddr);

/// Reads the header a relay in front sent ahead of the client's bytes, in
/// either version, and nothing behind it. `None` when the header names no
/// addresses (version 1 `UNKNOWN`, version 2 `LOCAL` or a family other
/// than IPv4 and IPv6): the connection is the relay's own, such as a health
/// check. Fails when the stream does not start with a valid header.
pub async fn read_header<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<Endpoints>> {
    // Every header is longer than the version 2 signature.
    let mut start = [0u8; 12];
    reader.read_exact(&mut start).await?;
    if start == SIGNATURE {
        return read_v2(reader).await;
    }
    if !start.starts_with(b"PROXY ") {
        return Err(invalid());
    }
    let mut line = start.to_vec();
    while !line.ends_with(b"\r\n") {
        if line.len() == V1_MAX {
            return Err(invalid());
        }
        line.push(reader.read_u8().await?);
    }
    parse_v1(&line[6..line.len() - 2]).ok_or_else(invalid)
}

/// `TCP4 <source> <destination> <source port> <destination port>`, `TCP6`
/// likewise, or `UNKNOWN` and anything.
fn parse_v1(line: &[u8]) -> Option<Option<Endpoints>> {
    let fields: Vec<&str> = std::str::from_utf8(line).ok()?.split(' ').collect();
    match fields[..] {
        ["UNKNOWN", ..] => Some(None),
        [family @ ("TCP4" | "TCP6"), source, destination, source_port, destination_port] => {
            let endpoint = |ip: &str, port: &str| -> Option<SocketAddr> {
                let ip: IpAddr = ip.parse().ok()?;
                (ip.is_ipv4() == (family == "TCP4"))
                    .then_some(SocketAddr::new(ip, port.parse().ok()?))
            };
            Some(Some((
                endpoint(source, source_port)?,
                endpoint(destination, destination_port)?,
            )))
        }
        _ => None,
    }
}

/// What follows the version 2 signature: version and command, family and
/// transport, the length of the rest, then the addresses, the ports and
/// any TLVs.
async fn read_v2<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<Endpoints>> {
    let mut head = [0u8; 4];
    reader.read_exact(&mut head).await?;
    let mut rest = vec![0u8; usize::from(u16::from_be_bytes([head[2], head[3]]))];
    reader.read_exact(&mut rest).await?;
    let mut rest = rest.as_slice();
    let (source, destination): (IpAddr, IpAddr) = match (head[0], head[1] >> 4) {
        // LOCAL, or PROXY without an IP family.
        (0x20, _) | (0x21, 0 | 3) => return Ok(None),
        (0x21, 1) => {
            let mut raw = [[0u8; 4]; 2];
            rest.read_exact(&mut raw[0]).await?;
            rest.read_exact(&mut raw[1]).await?;
            (raw[0].into(), raw[1].into())
        }
        (0x21, 2) => {
            let mut raw = [[0u8; 16]; 2];
            rest.read_exact(&mut raw[0]).await?;
            rest.read_exact(&mut raw[1]).await?;
            (raw[0].into(), raw[1].into())
        }
        _ => return Err(invalid()),
    };
    let (source_port, destination_port) = (rest.read_u16().await?, rest.read_u16().await?);
    Ok(Some((
        SocketAddr::new(source, source_port),
        SocketAddr::new(destination, destination_port),
    )))
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "PROXY protocol header is invalid",
    )
}

fn v6(ip: IpAddr) -> Ipv6Addr {
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

    async fn read(mut bytes: &[u8]) -> io::Result<(Option<Endpoints>, usize)> {
        let header = read_header(&mut bytes).await?;
        Ok((header, bytes.len()))
    }

    fn endpoints(source: &str, destination: &str) -> Option<Endpoints> {
        Some((source.parse().unwrap(), destination.parse().unwrap()))
    }

    fn v2(command: u8, family: u8, rest: &[u8]) -> Vec<u8> {
        let mut header = SIGNATURE.to_vec();
        header.extend_from_slice(&[command, family]);
        header.extend_from_slice(&(rest.len() as u16).to_be_bytes());
        header.extend_from_slice(rest);
        header
    }

    #[tokio::test]
    async fn reads_version_1() {
        // The client's bytes behind the header stay unread.
        let (header, left) = read(b"PROXY TCP4 198.51.100.7 203.0.113.1 50000 443\r\nGET /")
            .await
            .unwrap();
        assert_eq!(header, endpoints("198.51.100.7:50000", "203.0.113.1:443"));
        assert_eq!(left, 5);
        let (header, _) = read(b"PROXY TCP6 2001:db8::7 ::ffff:203.0.113.1 50000 443\r\n")
            .await
            .unwrap();
        assert_eq!(
            header,
            endpoints("[2001:db8::7]:50000", "[::ffff:203.0.113.1]:443")
        );
        assert_eq!(read(b"PROXY UNKNOWN\r\n").await.unwrap(), (None, 0));
        let unknown = read(b"PROXY UNKNOWN ffff::1 ::1 1 2\r\nx").await.unwrap();
        assert_eq!(unknown, (None, 1));
    }

    #[tokio::test]
    async fn reads_version_2() {
        let v4 = [198, 51, 100, 7, 203, 0, 113, 1, 0xc3, 0x50, 0x01, 0xbb];
        let mut bytes = v2(0x21, 0x11, &v4);
        bytes.extend_from_slice(b"payload");
        let (header, left) = read(&bytes).await.unwrap();
        assert_eq!(header, endpoints("198.51.100.7:50000", "203.0.113.1:443"));
        assert_eq!(left, 7);
        // What the forward writes reads back, and TLVs behind the addresses
        // are skipped.
        let (source, destination) = ("[2001:db8::7]:1", "[2001:db8::1]:2");
        let mut bytes =
            ProxyProtocol::V2.header(source.parse().unwrap(), destination.parse().unwrap());
        bytes[15] += 7;
        bytes.extend_from_slice(&[0x04, 0, 4, 1, 2, 3, 4, b'x']);
        let (header, left) = read(&bytes).await.unwrap();
        assert_eq!(header, endpoints(source, destination));
        assert_eq!(left, 1);
        // LOCAL and families without an IP address name no client.
        for (command, family, rest) in [
            (0x20, 0x00, &[][..]),
            (0x20, 0x11, &v4[..]),
            (0x21, 0x00, &[9, 9][..]),
            (0x21, 0x31, &[0u8; 216][..]),
        ] {
            let (header, left) = read(&v2(command, family, rest)).await.unwrap();
            assert_eq!((header, left), (None, 0));
        }
    }

    #[tokio::test]
    async fn refuses_malformed_headers() {
        let long = format!("PROXY UNKNOWN {}\r\n", "x".repeat(100));
        for bad in [
            &b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"[..],
            b"PROXY TCP4 198.51.100.7 203.0.113.1 50000\r\n",
            b"PROXY TCP4 2001:db8::7 203.0.113.1 50000 443\r\n",
            b"PROXY TCP6 2001:db8::7 2001:db8::1 50000 70000\r\n",
            b"PROXY UDP4 198.51.100.7 203.0.113.1 50000 443\r\n",
            b"PROXY TCP4 198.51.100.7 203.0.113.1 50000 443\n",
            long.as_bytes(),
            b"PROXY UNK",
            // Version 3, an unknown command, and addresses cut short.
            &v2(0x31, 0x11, &[0; 12]),
            &v2(0x22, 0x11, &[0; 12]),
            &v2(0x21, 0x11, &[0; 11]),
            &v2(0x21, 0x21, &[0; 12]),
            &v2(0x21, 0x11, &[0; 12])[..20],
        ] {
            assert!(read(bad).await.is_err(), "{bad:?}");
        }
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
