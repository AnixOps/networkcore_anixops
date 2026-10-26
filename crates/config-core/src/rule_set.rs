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

/// Most entries a configured or downloaded set may hold: room for the
/// mainland China domain and network lists with headroom.
pub const MAX_RULE_SET_ENTRIES: usize = 500_000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSet {
    /// Exact domains.
    domains: HashSet<String>,
    /// Each entry matches the domain itself and every subdomain.
    domain_suffixes: HashSet<String>,
    /// Substrings of the domain; checked one by one, so lists keep few.
    domain_keywords: Vec<String>,
    /// Sorted, non-overlapping inclusive ranges.
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

impl RuleSet {
    pub fn new<'a>(
        domain_suffixes: impl IntoIterator<Item = &'a str>,
        ip_cidrs: impl IntoIterator<Item = &'a str>,
    ) -> DomainResult<Self> {
        Self::from_entries(&RuleSetEntries {
            domain_suffix: domain_suffixes.into_iter().map(str::to_string).collect(),
            ip_cidr: ip_cidrs.into_iter().map(str::to_string).collect(),
            ..RuleSetEntries::default()
        })
    }

    pub fn from_entries(entries: &RuleSetEntries) -> DomainResult<Self> {
        let domains = entries
            .domain
            .iter()
            .map(|domain| normalize_rule_domain(domain.trim()))
            .collect::<DomainResult<HashSet<_>>>()?;
        let domain_keywords = entries
            .domain_keyword
            .iter()
            .map(|keyword| normalize_rule_domain(keyword.trim()))
            .collect::<DomainResult<Vec<_>>>()?;
        let domain_suffixes = entries
            .domain_suffix
            .iter()
            .map(|suffix| normalize_rule_domain(suffix.trim().trim_start_matches('.')))
            .collect::<DomainResult<HashSet<_>>>()?;
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for value in &entries.ip_cidr {
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
            domains,
            domain_suffixes,
            domain_keywords,
            v4: merge_ranges(v4),
            v6: merge_ranges(v6),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Entries held, counting each merged address range once.
    pub fn len(&self) -> usize {
        self.domains.len()
            + self.domain_suffixes.len()
            + self.domain_keywords.len()
            + self.v4.len()
            + self.v6.len()
    }

    /// `domain` is lower case without a trailing dot, as
    /// [`crate::routing::RoutingModel::decide`] passes it.
    pub fn matches(&self, domain: Option<&str>, ip: Option<IpAddr>) -> bool {
        if let Some(domain) = domain {
            if self.domains.contains(domain)
                || self
                    .domain_keywords
                    .iter()
                    .any(|keyword| domain.contains(keyword.as_str()))
            {
                return true;
            }
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

/// Unvalidated rule set entries, as a config lists them or a downloaded list
/// yields them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleSetEntries {
    pub domain: Vec<String>,
    pub domain_suffix: Vec<String>,
    pub domain_keyword: Vec<String>,
    /// Networks or bare addresses.
    pub ip_cidr: Vec<String>,
}

/// How a downloaded list writes a bare domain line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BareDomain {
    /// The domain and its subdomains, as plain domain lists (and the
    /// v2ray-rules-dat text lists) mean it.
    #[default]
    Suffix,
    /// That domain only, as Clash `behavior: domain` lists mean it; `+.` and
    /// `.` prefixes mark suffixes.
    Exact,
}

impl RuleSetEntries {
    pub fn len(&self) -> usize {
        self.domain.len()
            + self.domain_suffix.len()
            + self.domain_keyword.len()
            + self.ip_cidr.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reads a downloaded list: one entry per line, either `TYPE,value`
    /// (Surge, Loon, Clash classical; DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD,
    /// IP-CIDR, IP-CIDR6) or a bare domain, `+.`/`.`/`*.` suffix, address or
    /// network. Clash YAML `payload:` lists, quotes and `#`, `//` or `;`
    /// comments are accepted. Returns the entries and how many lines were
    /// skipped (other rule types, malformed values).
    pub fn parse_list(text: &str, bare: BareDomain) -> (Self, usize) {
        let mut entries = Self::default();
        let mut skipped = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty()
                || line.starts_with('#')
                || line.starts_with("//")
                || line.starts_with(';')
                || line == "payload:"
            {
                continue;
            }
            let line = line.strip_prefix("- ").unwrap_or(line).trim();
            let line = line.trim_matches(|c| c == '\'' || c == '"').trim();
            if !entries.push_line(line, bare) {
                skipped += 1;
            }
        }
        (entries, skipped)
    }

    fn push_line(&mut self, line: &str, bare: BareDomain) -> bool {
        if let Some((kind, rest)) = line.split_once(',') {
            let value = rest.split(',').next().unwrap_or_default().trim();
            let kind = kind.trim().to_ascii_uppercase();
            let (list, valid) = match kind.as_str() {
                "DOMAIN" => (&mut self.domain, is_domain(value)),
                "DOMAIN-SUFFIX" => (
                    &mut self.domain_suffix,
                    is_domain(value.trim_start_matches('.')),
                ),
                "DOMAIN-KEYWORD" => (&mut self.domain_keyword, is_domain(value)),
                "IP-CIDR" | "IP-CIDR6" => (&mut self.ip_cidr, is_network(value)),
                _ => return false,
            };
            if valid {
                list.push(value.to_string());
            }
            return valid;
        }
        if is_network(line) {
            self.ip_cidr.push(line.to_string());
            return true;
        }
        let suffix = line
            .strip_prefix("+.")
            .or_else(|| line.strip_prefix("*."))
            .or_else(|| line.strip_prefix('.'));
        let (list, name) = match (suffix, bare) {
            (Some(name), _) => (&mut self.domain_suffix, name),
            (None, BareDomain::Suffix) => (&mut self.domain_suffix, line),
            (None, BareDomain::Exact) => (&mut self.domain, line),
        };
        if !is_domain(name) {
            return false;
        }
        list.push(name.to_string());
        true
    }
}

fn is_domain(value: &str) -> bool {
    normalize_rule_domain(value).is_ok()
}

fn is_network(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok() || IpCidr::parse(value).is_some()
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
    fn exact_domains_and_keywords_match() {
        let set = RuleSet::from_entries(&RuleSetEntries {
            domain: vec!["Exact.example".to_string()],
            domain_keyword: vec!["track".to_string()],
            ..RuleSetEntries::default()
        })
        .unwrap();
        assert!(set.matches(Some("exact.example"), None));
        assert!(!set.matches(Some("www.exact.example"), None));
        assert!(set.matches(Some("ads.tracker.test"), None));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn downloaded_lists_are_parsed_in_every_common_shape() {
        let text =
            "# comment\npayload:\n  - '+.google.com'\n  - \"exact.example\"\n.suffix.example\n\
            DOMAIN-SUFFIX,classic.example\nDOMAIN-KEYWORD,adtrack\nIP-CIDR,10.0.0.0/8,no-resolve\n\
            IP-CIDR6,2001:db8::/32\n192.0.2.1\nUSER-AGENT,curl*\nnot a domain\n// note\n";
        let (entries, skipped) = RuleSetEntries::parse_list(text, BareDomain::Exact);
        assert_eq!(entries.domain, ["exact.example"]);
        assert_eq!(
            entries.domain_suffix,
            ["google.com", "suffix.example", "classic.example"]
        );
        assert_eq!(entries.domain_keyword, ["adtrack"]);
        assert_eq!(
            entries.ip_cidr,
            ["10.0.0.0/8", "2001:db8::/32", "192.0.2.1"]
        );
        assert_eq!(skipped, 2);

        let (entries, _) = RuleSetEntries::parse_list("baidu.com\n", BareDomain::Suffix);
        assert_eq!(entries.domain_suffix, ["baidu.com"]);
        assert!(RuleSet::from_entries(&entries)
            .unwrap()
            .matches(Some("www.baidu.com"), None));
    }

    #[test]
    fn invalid_entries_are_rejected() {
        assert!(RuleSet::new(["bad domain"], NONE).is_err());
        assert!(RuleSet::new(NONE, ["10.0.0.0/33"]).is_err());
        assert!(RuleSet::new(NONE, ["not-an-ip"]).is_err());
        assert!(RuleSet::new(NONE, NONE).unwrap().is_empty());
    }
}
