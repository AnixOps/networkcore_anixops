//! Destination rewrites: send matching connections to another address.
//!
//! A redirect line is a routing rule whose target is a new destination
//! instead of a policy, for example
//!
//! ```text
//! IP-CIDR,203.0.113.10/32,10.8.0.5
//! AND,((DOMAIN-SUFFIX,game.example.com),(PROTOCOL,UDP)),10.8.0.5:7000
//! DST-PORT,7000-7100,dev.example.com
//! IP-CIDR,203.0.113.10/32,:9000
//! ```
//!
//! The new destination is `host`, `host:port`, `[v6]:port` or `:port`; a
//! missing port keeps the original one and `:port` keeps the original host.
//! Lines are tried in order and the first match wins. Matching never
//! resolves a domain: IP rules match only a connection to an address.
//! `GEOIP`, `GEOSITE` and `RULE-SET` need data that only routing loads, so
//! they are refused here. The engine applies the rewrite before routing, so
//! the routing rules then see the new destination.

use control_domain::{DomainError, DomainResult};
use std::fmt;
use std::net::IpAddr;

use crate::routing::{
    normalize_rule_domain, parse_rule_line, RouteQuery, RuleLine, RuleMatcher,
    StaticRoutingEnvironment,
};

pub const REDIRECT_LINE_INVALID_CODE: &str = "config.core.redirect_line_invalid";
pub const REDIRECT_MATCHER_UNSUPPORTED_CODE: &str = "config.core.redirect_matcher_unsupported";
pub const REDIRECT_TARGET_INVALID_CODE: &str = "config.core.redirect_target_invalid";
pub const REDIRECT_TOO_MANY_CODE: &str = "config.core.redirect_too_many";

/// Most redirect lines one config may hold.
pub const MAX_REDIRECTS: usize = 256;

/// Host of a new destination.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RedirectHost {
    Ip(IpAddr),
    /// Lower-case domain, resolved by the outbound that carries the flow.
    Domain(String),
    /// The original host; only the port changes.
    Keep,
}

/// Where a matching connection goes instead.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RedirectTo {
    pub host: RedirectHost,
    /// `None` keeps the original port.
    pub port: Option<u16>,
}

impl fmt::Display for RedirectTo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.host, self.port) {
            (RedirectHost::Ip(IpAddr::V6(ip)), Some(port)) => write!(formatter, "[{ip}]:{port}"),
            (RedirectHost::Ip(ip), Some(port)) => write!(formatter, "{ip}:{port}"),
            (RedirectHost::Ip(ip), None) => write!(formatter, "{ip}"),
            (RedirectHost::Domain(domain), Some(port)) => write!(formatter, "{domain}:{port}"),
            (RedirectHost::Domain(domain), None) => formatter.write_str(domain),
            (RedirectHost::Keep, Some(port)) => write!(formatter, ":{port}"),
            (RedirectHost::Keep, None) => formatter.write_str(":"),
        }
    }
}

/// One redirect line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectRule {
    pub matcher: RuleMatcher,
    pub to: RedirectTo,
}

impl fmt::Display for RedirectRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{},{}", self.matcher, self.to)
    }
}

/// Ordered redirect lines; the first match wins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedirectTable {
    rules: Vec<RedirectRule>,
}

impl RedirectTable {
    /// Parses `lines` in order. Blank lines and lines starting with `#` or
    /// `;` are skipped.
    pub fn parse<S: AsRef<str>>(lines: &[S]) -> DomainResult<Self> {
        let mut rules = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            let line = line.as_ref().trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if rules.len() == MAX_REDIRECTS {
                return Err(DomainError::new(
                    REDIRECT_TOO_MANY_CODE,
                    format!("at most {MAX_REDIRECTS} redirect lines are supported"),
                ));
            }
            let rule = parse_redirect_line(line).map_err(|error| {
                DomainError::new(error.code, format!("redirect {index}: {}", error.message))
            })?;
            rules.push(rule);
        }
        Ok(Self { rules })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn rules(&self) -> &[RedirectRule] {
        &self.rules
    }

    /// The first rule matching `query`, if any.
    pub fn find(&self, query: &RouteQuery) -> Option<&RedirectRule> {
        self.rules
            .iter()
            .find(|rule| rule.matcher.matches(query, &StaticRoutingEnvironment))
    }
}

/// Parses one redirect line: a routing rule whose target is the new
/// destination.
pub fn parse_redirect_line(line: &str) -> DomainResult<RedirectRule> {
    let (matcher, target) = match parse_rule_line(line)? {
        RuleLine::Rule {
            matcher, target, ..
        } => (matcher, target),
        RuleLine::Final { .. } => {
            return Err(DomainError::new(
                REDIRECT_LINE_INVALID_CODE,
                "a redirect needs a rule; FINAL is not one",
            ))
        }
    };
    check_matcher(&matcher)?;
    Ok(RedirectRule {
        matcher,
        to: parse_redirect_target(&target)?,
    })
}

fn check_matcher(matcher: &RuleMatcher) -> DomainResult<()> {
    match matcher {
        RuleMatcher::GeoIp(_) | RuleMatcher::GeoSite(_) | RuleMatcher::RuleSet(_) => {
            Err(DomainError::new(
                REDIRECT_MATCHER_UNSUPPORTED_CODE,
                "GEOIP, GEOSITE and RULE-SET cannot select a redirect",
            ))
        }
        RuleMatcher::And(rules) | RuleMatcher::Or(rules) => {
            rules.iter().try_for_each(check_matcher)
        }
        RuleMatcher::Not(rule) => check_matcher(rule),
        _ => Ok(()),
    }
}

/// Parses `host`, `host:port`, `[v6]:port`, a bare IPv6 address, or
/// `:port`.
pub fn parse_redirect_target(value: &str) -> DomainResult<RedirectTo> {
    let invalid = |message: &str| DomainError::new(REDIRECT_TARGET_INVALID_CODE, message);
    let value = value.trim();
    if value.is_empty() {
        return Err(invalid("redirect target must not be empty"));
    }
    let port = |text: &str| match text.parse::<u16>() {
        Ok(port) if port != 0 => Ok(port),
        _ => Err(invalid("redirect port must be 1-65535")),
    };
    if let Some(rest) = value.strip_prefix(':') {
        if !rest.contains(':') {
            return Ok(RedirectTo {
                host: RedirectHost::Keep,
                port: Some(port(rest)?),
            });
        }
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(RedirectTo {
            host: RedirectHost::Ip(ip),
            port: None,
        });
    }
    if let Some(rest) = value.strip_prefix('[') {
        let (address, after) = rest
            .split_once(']')
            .ok_or_else(|| invalid("redirect IPv6 target must close its bracket"))?;
        let ip = address
            .parse::<IpAddr>()
            .ok()
            .filter(IpAddr::is_ipv6)
            .ok_or_else(|| invalid("redirect target in brackets must be an IPv6 address"))?;
        let port = match after {
            "" => None,
            _ => Some(port(after.strip_prefix(':').ok_or_else(|| {
                invalid("redirect IPv6 target must be [address] or [address]:port")
            })?)?),
        };
        return Ok(RedirectTo {
            host: RedirectHost::Ip(ip),
            port,
        });
    }
    let (host, port) = match value.rsplit_once(':') {
        Some((host, text)) => (host, Some(port(text)?)),
        None => (value, None),
    };
    let host = match host.parse::<IpAddr>() {
        Ok(ip @ IpAddr::V4(_)) => RedirectHost::Ip(ip),
        Ok(IpAddr::V6(_)) => {
            return Err(invalid("redirect IPv6 target with a port needs brackets"))
        }
        Err(_) => RedirectHost::Domain(
            normalize_rule_domain(host)
                .map_err(|_| invalid("redirect target must be an address or a domain"))?,
        ),
    };
    Ok(RedirectTo { host, port })
}
