//! Large domain and IP lists referenced by `RULE-SET,<name>,<target>` rules.
//!
//! A rule set is matched as one rule: a hash lookup per domain label suffix
//! and a binary search over merged address ranges, so lists with hundreds of
//! thousands of entries (for example mainland China domains and networks) cost
//! the same per connection as a short one. Like a sing-box `rule_set` without
//! a `resolve` action, the IP part matches only a destination that is already
//! an address; domains are never resolved for it.

use control_domain::DomainResult;
use std::collections::HashSet;
use std::net::IpAddr;

use crate::routing::{
    normalize_rule_domain, routing_error, IpCidr, ROUTING_RULE_VALUE_INVALID_CODE,
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSet {
    /// Each entry matches the domain itself and every subdomain.
    domain_suffixes: HashSet<String>,
    /// Sorted, non-overlapping inclusive ranges.
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl RuleSet {
    pub fn new<'a>(
        domain_suffixes: impl IntoIterator<Item = &'a str>,
        ip_cidrs: impl IntoIterator<Item = &'a str>,
    ) -> DomainResult<Self> {
        let domain_suffixes = domain_suffixes
            .into_iter()
            .map(|suffix| normalize_rule_domain(suffix.trim().trim_start_matches('.')))
            .collect::<DomainResult<HashSet<_>>>()?;
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for value in ip_cidrs {
            let value = value.trim();
            // Lists often carry bare addresses next to networks.
            let cidr = match value.parse::<IpAddr>() {
                Ok(IpAddr::V4(address)) => IpCidr::parse(&format!("{address}/32")),
                Ok(IpAddr::V6(address)) => IpCidr::parse(&format!("{address}/128")),
                Err(_) => IpCidr::parse(value),
            }
            .ok_or_else(|| {
                routing_error(
                    ROUTING_RULE_VALUE_INVALID_CODE,
                    "rule set address must be an IP address or network",
                )
            })?;
            match cidr.network() {
                IpAddr::V4(network) => {
                    let start = u32::from(network);
                    let host_bits = 32 - u32::from(cidr.prefix_len());
                    let size = 1u64 << host_bits;
                    v4.push((start, (u64::from(start) + size - 1) as u32));
                }
                IpAddr::V6(network) => {
                    let start = u128::from(network);
                    let host_bits = 128 - u32::from(cidr.prefix_len());
                    let span = u128::MAX.checked_shr(128 - host_bits).unwrap_or(0);
                    v6.push((start, start + span));
                }
            }
        }
        Ok(Self {
            domain_suffixes,
            v4: merge_ranges(v4),
            v6: merge_ranges(v6),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.domain_suffixes.is_empty() && self.v4.is_empty() && self.v6.is_empty()
    }

    /// `domain` is lower case without a trailing dot, as
    /// [`crate::routing::RoutingModel::decide`] passes it.
    pub fn matches(&self, domain: Option<&str>, ip: Option<IpAddr>) -> bool {
        if let Some(domain) = domain {
            let mut rest = domain;
            loop {
                if self.domain_suffixes.contains(rest) {
                    return true;
                }
                match rest.split_once('.') {
                    Some((_, parent)) => rest = parent,
                    None => break,
                }
            }
        }
        match ip {
            Some(IpAddr::V4(address)) => in_ranges(&self.v4, u32::from(address)),
            Some(IpAddr::V6(address)) => in_ranges(&self.v6, u128::from(address)),
            None => false,
        }
    }
}

fn merge_ranges<T: Ord + Copy + num::Successor>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut merged: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if last.1.successor().is_none_or(|next| start <= next) => {
                if end > last.1 {
                    last.1 = end;
                }
            }
            _ => merged.push((start, end)),
        }
    }
    merged
}

fn in_ranges<T: Ord + Copy>(ranges: &[(T, T)], value: T) -> bool {
    let index = ranges.partition_point(|(start, _)| *start <= value);
    index > 0 && value <= ranges[index - 1].1
}

mod num {
    /// The next value, or `None` at the maximum.
    pub trait Successor: Sized {
        fn successor(self) -> Option<Self>;
    }

    impl Successor for u32 {
        fn successor(self) -> Option<Self> {
            self.checked_add(1)
        }
    }

    impl Successor for u128 {
        fn successor(self) -> Option<Self> {
            self.checked_add(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: [&str; 0] = [];

    #[test]
    fn domains_match_themselves_and_subdomains_only() {
        let set = RuleSet::new(["cn", ".Example.COM"], NONE).unwrap();
        assert!(set.matches(Some("cn"), None));
        assert!(set.matches(Some("www.baidu.cn"), None));
        assert!(set.matches(Some("example.com"), None));
        assert!(set.matches(Some("a.b.example.com"), None));
        assert!(!set.matches(Some("notexample.com"), None));
        assert!(!set.matches(Some("example.org"), None));
        assert!(!set.matches(None, None));
    }

    #[test]
    fn networks_merge_and_match_by_range() {
        let set = RuleSet::new(
            NONE,
            [
                "10.0.0.0/9",
                "10.128.0.0/9",
                "192.0.2.7",
                "0.0.0.0/0",
                "2001:db8::/32",
            ],
        )
        .unwrap();
        assert_eq!(set.v4, vec![(0, u32::MAX)]);
        assert!(set.matches(None, Some("203.0.113.1".parse().unwrap())));
        assert!(set.matches(None, Some("2001:db8:1::1".parse().unwrap())));
        assert!(!set.matches(None, Some("2001:db9::1".parse().unwrap())));

        let set = RuleSet::new(NONE, ["10.0.0.0/8", "10.1.0.0/16", "192.0.2.7", "::/0"]).unwrap();
        assert_eq!(set.v4.len(), 2);
        assert!(set.matches(None, Some("10.200.0.1".parse().unwrap())));
        assert!(set.matches(None, Some("192.0.2.7".parse().unwrap())));
        assert!(!set.matches(None, Some("192.0.2.8".parse().unwrap())));
        assert!(!set.matches(None, Some("11.0.0.0".parse().unwrap())));
        assert!(set.matches(None, Some("::1".parse().unwrap())));
        // A domain destination is never resolved for the IP part.
        assert!(!set.matches(Some("10.example"), None));
    }

    #[test]
    fn invalid_entries_are_rejected() {
        assert!(RuleSet::new(["bad domain"], NONE).is_err());
        assert!(RuleSet::new(NONE, ["10.0.0.0/33"]).is_err());
        assert!(RuleSet::new(NONE, ["not-an-ip"]).is_err());
        assert!(RuleSet::new(NONE, NONE).unwrap().is_empty());
    }
}
