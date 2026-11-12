//! AllowedIPs: the networks a peer may carry, used in both directions as
//! WireGuard's cryptokey routing does.

use std::net::IpAddr;

/// One network, `address/prefix`; a bare address is a host route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpNet {
    address: IpAddr,
    prefix: u8,
}

impl IpNet {
    pub fn new(address: IpAddr, prefix: u8) -> Option<Self> {
        let max = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        (prefix <= max).then_some(Self { address, prefix })
    }

    /// Parses `10.0.0.0/8`, `fd00::/8`, `10.0.0.1` or `[fd00::1]`.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix.trim())),
            None => (text, None),
        };
        let address: IpAddr = address
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .ok()?;
        let prefix = match prefix {
            Some(prefix) => prefix.parse().ok()?,
            None => match address {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            },
        };
        Self::new(address, prefix)
    }

    pub fn address(&self) -> IpAddr {
        self.address
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(net), IpAddr::V4(address)) => {
                let mask = mask32(self.prefix);
                u32::from(net) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(address)) => {
                let mask = mask128(self.prefix);
                u128::from(net) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

fn mask32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn mask128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

/// A peer's AllowedIPs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowedIps {
    nets: Vec<IpNet>,
}

impl AllowedIps {
    pub fn new(nets: Vec<IpNet>) -> Self {
        Self { nets }
    }

    /// `0.0.0.0/0, ::/0`.
    pub fn everything() -> Self {
        Self::new(vec![
            IpNet {
                address: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                prefix: 0,
            },
            IpNet {
                address: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                prefix: 0,
            },
        ])
    }

    pub fn nets(&self) -> &[IpNet] {
        &self.nets
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        // An IPv4-mapped IPv6 address is matched as the IPv4 address it is.
        let address = match address {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        self.nets.iter().any(|net| net.contains(address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks_parse_and_match() {
        let net = IpNet::parse("10.7.0.0/24").unwrap();
        assert!(net.contains("10.7.0.200".parse().unwrap()));
        assert!(!net.contains("10.7.1.1".parse().unwrap()));
        assert!(!net.contains("fd00::1".parse().unwrap()));

        let host = IpNet::parse("[fd00:7::1]").unwrap();
        assert_eq!(host.prefix(), 128);
        assert!(host.contains("fd00:7::1".parse().unwrap()));
        assert!(!host.contains("fd00:7::2".parse().unwrap()));

        assert!(IpNet::parse("0.0.0.0/0")
            .unwrap()
            .contains("1.2.3.4".parse().unwrap()));
        assert!(IpNet::parse("10.0.0.0/33").is_none());
        assert!(IpNet::parse("fd00::/129").is_none());
        assert!(IpNet::parse("example.com/8").is_none());
    }

    #[test]
    fn allowed_ips_match_any_network() {
        let allowed = AllowedIps::new(vec![
            IpNet::parse("10.0.0.0/8").unwrap(),
            IpNet::parse("fd00::/8").unwrap(),
        ]);
        assert!(allowed.contains("10.1.2.3".parse().unwrap()));
        assert!(allowed.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert!(allowed.contains("fd12::1".parse().unwrap()));
        assert!(!allowed.contains("11.0.0.1".parse().unwrap()));
        assert!(!allowed.contains("2001:db8::1".parse().unwrap()));
        assert!(AllowedIps::everything().contains("2001:db8::1".parse().unwrap()));
    }
}
