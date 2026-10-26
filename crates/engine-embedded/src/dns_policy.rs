//! Which upstream answers a DNS name: the `dns` section's hosts, per-domain
//! rules and servers.
//!
//! A query is answered locally when its name is in `hosts` (exact, or a
//! subdomain of a `*.` entry). Otherwise the first rule whose domains, suffixes,
//! keywords or rule set match picks the server, and names no rule picks go to
//! the default server. Each server is reached through the proxy (the config's
//! outbound or rules, and the direct outbound in the direct mode) or directly.
//! A config without `servers` keeps the single `upstream` over TCP through the
//! proxy.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use engine_outbound::TargetAddr;
use serde::Serialize;

use crate::config::{DnsConfig, DnsRuleConfig, DnsVia};
use crate::dns::{self, Upstream, UpstreamError};
use crate::rule_sets::RuleSetStore;

pub const MAX_DNS_SERVERS: usize = 16;
pub const MAX_DNS_RULES: usize = 64;
/// Domains, suffixes and keywords over every rule.
pub const MAX_DNS_RULE_DOMAINS: usize = 4096;
pub const MAX_HOSTS: usize = 1024;
pub const MAX_HOST_ADDRESSES: usize = 8;

/// One configured upstream.
#[derive(Clone)]
pub struct DnsServer {
    pub name: String,
    pub upstream: Upstream,
    pub via: DnsVia,
}

/// What to do with one query.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// Reply with this message without asking anyone.
    Local(Vec<u8>),
    /// Forward to the server at this index of [`DnsPolicy::servers`].
    Forward(usize),
}

/// One server as the client's DNS page shows it; no URL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsServerView {
    pub name: String,
    /// `tcp`, `tls` or `https`.
    pub scheme: &'static str,
    /// `proxy` or `direct`.
    pub via: &'static str,
    pub default: bool,
}

struct DnsRule {
    domains: HashSet<String>,
    suffixes: Vec<String>,
    keywords: Vec<String>,
    rule_set: Option<String>,
    server: usize,
}

impl DnsRule {
    fn matches(&self, name: &str, rule_sets: Option<&RuleSetStore>) -> bool {
        self.domains.contains(name)
            || self.suffixes.iter().any(|suffix| is_within(name, suffix))
            || self
                .keywords
                .iter()
                .any(|keyword| name.contains(keyword.as_str()))
            || self.rule_set.as_ref().is_some_and(|set| {
                rule_sets.is_some_and(|store| {
                    store
                        .read()
                        .get(set)
                        .is_some_and(|set| set.matches(Some(name), None))
                })
            })
    }
}

pub struct DnsPolicy {
    servers: Vec<DnsServer>,
    default: usize,
    hosts: HashMap<String, Vec<IpAddr>>,
    /// `*.suffix` hosts, by suffix.
    wildcard_hosts: Vec<(String, Vec<IpAddr>)>,
    rules: Vec<DnsRule>,
    timeout: Duration,
}

impl fmt::Debug for DnsPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsPolicy")
            .field("servers", &self.servers.len())
            .field("hosts", &(self.hosts.len() + self.wildcard_hosts.len()))
            .field("rules", &self.rules.len())
            .finish()
    }
}

impl DnsPolicy {
    /// Every query to `upstream` over TCP through the proxy.
    pub fn tcp(upstream: SocketAddr, timeout: Duration) -> Self {
        Self {
            servers: vec![DnsServer {
                name: "default".to_string(),
                upstream: Upstream::Tcp(TargetAddr::Ip(upstream)),
                via: DnsVia::Proxy,
            }],
            default: 0,
            hosts: HashMap::new(),
            wildcard_hosts: Vec::new(),
            rules: Vec::new(),
            timeout,
        }
    }

    /// The policy of a `dns` section, or why it is refused (a fixed message
    /// without names or URLs).
    pub fn from_config(config: &DnsConfig) -> Result<Self, &'static str> {
        let timeout = Duration::from_millis(config.timeout_ms);
        let mut policy = if config.servers.is_empty() {
            if config.default.is_some() || !config.rules.is_empty() {
                return Err("dns rules and default need servers");
            }
            Self::tcp(config.upstream, timeout)
        } else {
            if config.servers.len() > MAX_DNS_SERVERS {
                return Err("dns has too many servers");
            }
            let mut servers: Vec<DnsServer> = Vec::with_capacity(config.servers.len());
            for server in &config.servers {
                if !crate::config::is_identifier(&server.name) {
                    return Err("dns server names must be 1-128 characters of [A-Za-z0-9._-]");
                }
                if servers.iter().any(|known| known.name == server.name) {
                    return Err("dns server names must be unique");
                }
                let upstream = Upstream::parse(&server.url, server.server_name.as_deref())
                    .map_err(|error| match error {
                        UpstreamError::Invalid => "dns server url is invalid",
                        UpstreamError::Unsupported => {
                            "dns over tls and https need the dns-tls feature"
                        }
                    })?;
                servers.push(DnsServer {
                    name: server.name.clone(),
                    upstream,
                    via: server.via,
                });
            }
            let index_of = |name: &str| servers.iter().position(|server| server.name == name);
            let default = match &config.default {
                Some(name) => index_of(name).ok_or("dns default names no server")?,
                None => 0,
            };
            if config.rules.len() > MAX_DNS_RULES {
                return Err("dns has too many rules");
            }
            let domains: usize = config.rules.iter().map(DnsRuleConfig::entry_count).sum();
            if domains > MAX_DNS_RULE_DOMAINS {
                return Err("dns rules have too many domains");
            }
            let mut rules = Vec::with_capacity(config.rules.len());
            for rule in &config.rules {
                let server = index_of(&rule.server).ok_or("dns rule names no server")?;
                if rule.entry_count() == 0 && rule.rule_set.is_none() {
                    return Err("dns rule matches nothing");
                }
                rules.push(DnsRule {
                    domains: names(&rule.domain)?.into_iter().collect(),
                    suffixes: names(&rule.domain_suffix)?,
                    keywords: rule
                        .domain_keyword
                        .iter()
                        .map(|keyword| keyword.trim().to_ascii_lowercase())
                        .filter(|keyword| !keyword.is_empty())
                        .collect(),
                    rule_set: rule.rule_set.clone(),
                    server,
                });
            }
            Self {
                servers,
                default,
                hosts: HashMap::new(),
                wildcard_hosts: Vec::new(),
                rules,
                timeout,
            }
        };
        policy.set_hosts(&config.hosts)?;
        Ok(policy)
    }

    fn set_hosts(&mut self, hosts: &BTreeMap<String, Vec<IpAddr>>) -> Result<(), &'static str> {
        if hosts.len() > MAX_HOSTS {
            return Err("dns has too many hosts");
        }
        for (name, addresses) in hosts {
            if addresses.is_empty() || addresses.len() > MAX_HOST_ADDRESSES {
                return Err("dns hosts need 1-8 addresses each");
            }
            match name.strip_prefix("*.") {
                Some(suffix) => self
                    .wildcard_hosts
                    .push((normalize(suffix)?, addresses.clone())),
                None => {
                    self.hosts.insert(normalize(name)?, addresses.clone());
                }
            }
        }
        Ok(())
    }

    pub fn servers(&self) -> &[DnsServer] {
        &self.servers
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// The servers without their URLs, for status.
    pub fn view(&self) -> Vec<DnsServerView> {
        self.servers
            .iter()
            .enumerate()
            .map(|(index, server)| DnsServerView {
                name: server.name.clone(),
                scheme: server.upstream.scheme(),
                via: server.via.as_str(),
                default: index == self.default,
            })
            .collect()
    }

    /// Decides how to answer `query`. A query whose question does not parse
    /// goes to the default server unchanged.
    pub fn plan(&self, query: &[u8], rule_sets: Option<&RuleSetStore>) -> Plan {
        let Some(question) = dns::question(query) else {
            return Plan::Forward(self.default);
        };
        if let Some(addresses) = self.host(&question.name) {
            return Plan::Local(dns::local_answer(query, &question, addresses));
        }
        Plan::Forward(self.server_for(&question.name, rule_sets))
    }

    /// The index of the server for `name`.
    pub fn server_for(&self, name: &str, rule_sets: Option<&RuleSetStore>) -> usize {
        self.rules
            .iter()
            .find(|rule| rule.matches(name, rule_sets))
            .map_or(self.default, |rule| rule.server)
    }

    fn host(&self, name: &str) -> Option<&[IpAddr]> {
        if let Some(addresses) = self.hosts.get(name) {
            return Some(addresses);
        }
        self.wildcard_hosts
            .iter()
            .find(|(suffix, _)| name.len() > suffix.len() && is_within(name, suffix))
            .map(|(_, addresses)| addresses.as_slice())
    }
}

/// Whether `name` is `suffix` or one of its subdomains.
fn is_within(name: &str, suffix: &str) -> bool {
    name.strip_suffix(suffix)
        .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
}

/// A configured name in lower case without a leading `.`/`+.` or final dot.
fn normalize(name: &str) -> Result<String, &'static str> {
    let name = name.trim();
    let name = name
        .strip_prefix("+.")
        .or_else(|| name.strip_prefix('.'))
        .unwrap_or(name);
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 253
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err("dns domain is invalid");
    }
    Ok(name)
}

fn names(list: &[String]) -> Result<Vec<String>, &'static str> {
    list.iter().map(|name| normalize(name)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DnsServerConfig;

    fn query(name: &[u8]) -> Vec<u8> {
        let mut query = vec![0x00, 0x01, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(name);
        query.extend_from_slice(&[0, 1, 0, 1]);
        query
    }

    fn server(name: &str, url: &str, via: DnsVia) -> DnsServerConfig {
        DnsServerConfig {
            name: name.to_string(),
            url: url.to_string(),
            server_name: None,
            via,
        }
    }

    fn config() -> DnsConfig {
        DnsConfig {
            servers: vec![
                server("remote", "tcp://8.8.8.8", DnsVia::Proxy),
                server("local", "223.5.5.5:53", DnsVia::Direct),
            ],
            hosts: BTreeMap::from([
                (
                    "router.lan".to_string(),
                    vec!["192.168.1.1".parse().unwrap()],
                ),
                (
                    "*.corp.example".to_string(),
                    vec!["10.0.0.1".parse().unwrap()],
                ),
            ]),
            rules: vec![
                DnsRuleConfig {
                    domain_suffix: vec!["cn".into(), "+.Baidu.com".into()],
                    server: "local".into(),
                    ..DnsRuleConfig::default()
                },
                DnsRuleConfig {
                    domain_keyword: vec!["taobao".into()],
                    server: "local".into(),
                    ..DnsRuleConfig::default()
                },
            ],
            ..DnsConfig::default()
        }
    }

    #[test]
    fn names_pick_their_server() {
        let policy = DnsPolicy::from_config(&config()).unwrap();
        assert_eq!(policy.server_for("www.baidu.com", None), 1);
        assert_eq!(policy.server_for("baidu.com", None), 1);
        assert_eq!(policy.server_for("notbaidu.com", None), 0);
        assert_eq!(policy.server_for("gov.cn", None), 1);
        assert_eq!(policy.server_for("world.taobao.com", None), 1);
        assert_eq!(policy.server_for("example.com", None), 0);
        assert_eq!(
            policy.plan(&query(b"\x03www\x05baidu\x03com\x00"), None),
            Plan::Forward(1)
        );
        assert_eq!(policy.plan(b"not dns", None), Plan::Forward(0));
        let views = policy.view();
        assert_eq!(views[1].via, "direct");
        assert_eq!(views[1].scheme, "tcp");
        assert!(views[0].default);
    }

    #[test]
    fn hosts_are_answered_locally() {
        let policy = DnsPolicy::from_config(&config()).unwrap();
        let Plan::Local(answer) = policy.plan(&query(b"\x06Router\x03lan\x00"), None) else {
            panic!("hosts entry should answer locally");
        };
        assert!(answer.ends_with(&[192, 168, 1, 1]));
        let Plan::Local(answer) = policy.plan(&query(b"\x03git\x04corp\x07example\x00"), None)
        else {
            panic!("wildcard hosts entry should answer locally");
        };
        assert!(answer.ends_with(&[10, 0, 0, 1]));
        // The wildcard covers subdomains only.
        assert_eq!(
            policy.plan(&query(b"\x04corp\x07example\x00"), None),
            Plan::Forward(0)
        );
    }

    #[test]
    fn rule_sets_back_dns_rules() {
        use config_core::rule_set::{BareDomain, RuleSet, RuleSetEntries};

        let mut config = config();
        config.rules = vec![DnsRuleConfig {
            rule_set: Some("geosite-cn".into()),
            server: "local".into(),
            ..DnsRuleConfig::default()
        }];
        let policy = DnsPolicy::from_config(&config).unwrap();
        let (entries, _) = RuleSetEntries::parse_list("qq.com\n", BareDomain::Suffix);
        let store = RuleSetStore::new(
            BTreeMap::from([(
                "geosite-cn".to_string(),
                RuleSet::from_entries(&entries).unwrap(),
            )]),
            Vec::new(),
        );
        assert_eq!(policy.server_for("im.qq.com", Some(&store)), 1);
        assert_eq!(policy.server_for("im.qq.com", None), 0);
        assert_eq!(policy.server_for("example.com", Some(&store)), 0);
    }

    #[test]
    fn bad_sections_are_refused() {
        let legacy = DnsPolicy::from_config(&DnsConfig::default()).unwrap();
        assert_eq!(legacy.servers().len(), 1);

        let mut unknown = config();
        unknown.rules[0].server = "nowhere".into();
        let mut duplicate = config();
        duplicate.servers[1].name = "remote".into();
        let mut bad_url = config();
        bad_url.servers[0].url = "udp://8.8.8.8".into();
        let mut empty_rule = config();
        empty_rule.rules.push(DnsRuleConfig {
            server: "local".into(),
            ..DnsRuleConfig::default()
        });
        let mut bad_host = config();
        bad_host
            .hosts
            .insert("a b".into(), vec!["1.1.1.1".parse().unwrap()]);
        let mut no_address = config();
        no_address.hosts.insert("x.lan".into(), Vec::new());
        let mut rules_without_servers = config();
        rules_without_servers.servers.clear();
        for config in [
            unknown,
            duplicate,
            bad_url,
            empty_rule,
            bad_host,
            no_address,
            rules_without_servers,
        ] {
            assert!(DnsPolicy::from_config(&config).is_err());
        }
    }
}
