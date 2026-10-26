//! Destination address encodings shared by several protocols.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use engine_outbound::TargetAddr;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Address type codes of one protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AddrCodes {
    pub ipv4: u8,
    pub domain: u8,
    pub ipv6: u8,
}

/// SOCKS5 codes, used by Shadowsocks and Trojan.
pub const SOCKS: AddrCodes = AddrCodes {
    ipv4: 1,
    domain: 3,
    ipv6: 4,
};

/// VLESS and VMess codes.
pub const VMESS: AddrCodes = AddrCodes {
    ipv4: 1,
    domain: 2,
    ipv6: 3,
};

/// Reads `ATYP ADDR PORT` (SOCKS order).
pub async fn read_addr_port<R: AsyncRead + Unpin>(
    reader: &mut R,
    codes: AddrCodes,
) -> io::Result<TargetAddr> {
    let host = read_host(reader, codes).await?;
    let port = reader.read_u16().await?;
    Ok(host.with_port(port))
}

/// Reads `PORT ATYP ADDR` (VLESS and VMess order).
pub async fn read_port_addr<R: AsyncRead + Unpin>(
    reader: &mut R,
    codes: AddrCodes,
) -> io::Result<TargetAddr> {
    let port = reader.read_u16().await?;
    let host = read_host(reader, codes).await?;
    Ok(host.with_port(port))
}

enum Host {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Domain(String),
}

impl Host {
    fn with_port(self, port: u16) -> TargetAddr {
        match self {
            Host::V4(ip) => TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(ip, port))),
            Host::V6(ip) => TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))),
            Host::Domain(domain) => TargetAddr::Domain(domain, port),
        }
    }
}

async fn read_host<R: AsyncRead + Unpin>(reader: &mut R, codes: AddrCodes) -> io::Result<Host> {
    let atyp = reader.read_u8().await?;
    if atyp == codes.ipv4 {
        let mut raw = [0u8; 4];
        reader.read_exact(&mut raw).await?;
        Ok(Host::V4(Ipv4Addr::from(raw)))
    } else if atyp == codes.ipv6 {
        let mut raw = [0u8; 16];
        reader.read_exact(&mut raw).await?;
        Ok(Host::V6(Ipv6Addr::from(raw)))
    } else if atyp == codes.domain {
        let len = usize::from(reader.read_u8().await?);
        let mut raw = vec![0u8; len];
        reader.read_exact(&mut raw).await?;
        let domain = String::from_utf8(raw).map_err(|_| invalid("target domain is not UTF-8"))?;
        if domain.is_empty() {
            return Err(invalid("target domain is empty"));
        }
        Ok(Host::Domain(domain))
    } else {
        Err(invalid("target address type is invalid"))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_both_orders() {
        let mut socks: &[u8] = &[3, 3, b'a', b'.', b'b', 0, 80];
        assert_eq!(
            read_addr_port(&mut socks, SOCKS).await.unwrap(),
            TargetAddr::Domain("a.b".into(), 80)
        );
        let mut vless: &[u8] = &[1, 187, 1, 10, 0, 0, 1];
        assert_eq!(
            read_port_addr(&mut vless, VMESS).await.unwrap(),
            TargetAddr::Ip("10.0.0.1:443".parse().unwrap())
        );
        let mut v6: &[u8] = &[0, 53, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            read_port_addr(&mut v6, VMESS).await.unwrap(),
            TargetAddr::Ip("[::1]:53".parse().unwrap())
        );
        let mut bad: &[u8] = &[9, 0, 0];
        assert!(read_addr_port(&mut bad, SOCKS).await.is_err());
        let mut empty: &[u8] = &[3, 0, 0, 80];
        assert!(read_addr_port(&mut empty, SOCKS).await.is_err());
    }
}
