//! First-class routing rules and policy groups.
//!
//! This module owns the platform-neutral routing model: ordered
//! DOMAIN/DOMAIN-SUFFIX/DOMAIN-KEYWORD/IP-CIDR/GEOIP/GEOSITE/DST-PORT/
//! PROCESS-NAME/RULE-SET rules and AND/OR/NOT combinations of them, a
//! mandatory FINAL target, and
//! select/url-test/fallback policy groups. In-process engines call
//! [`RoutingModel::decide`] directly, and snapshot tests pin its results. The module performs no DNS, GeoIP database, health check,
//! or network work; those inputs come from a [`RoutingEnvironment`].

use control_domain::{DomainError, DomainResult};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const ROUTING_RULE_LINE_INVALID_CODE: &str = "config.core.routing_rule_line_invalid";
pub const ROUTING_RULE_TYPE_UNSUPPORTED_CODE: &str = "config.core.routing_rule_type_unsupported";
pub const ROUTING_RULE_VALUE_INVALID_CODE: &str = "config.core.routing_rule_value_invalid";
pub const ROUTING_RULE_OPTION_UNSUPPORTED_CODE: &str =
    "config.core.routing_rule_option_unsupported";
pub const ROUTING_TARGET_UNKNOWN_CODE: &str = "config.core.routing_target_unknown";
pub const ROUTING_FINAL_MISSING_CODE: &str = "config.core.routing_final_missing";
pub const ROUTING_FINAL_NOT_LAST_CODE: &str = "config.core.routing_final_not_last";
pub const ROUTING_GROUP_ID_INVALID_CODE: &str = "config.core.routing_group_id_invalid";
pub const ROUTING_GROUP_ID_CONFLICT_CODE: &str = "config.core.routing_group_id_conflict";
pub const ROUTING_GROUP_TYPE_UNSUPPORTED_CODE: &str = "config.core.routing_group_type_unsupported";
pub const ROUTING_GROUP_MEMBERS_EMPTY_CODE: &str = "config.core.routing_group_members_empty";
pub const ROUTING_GROUP_MEMBER_UNSUPPORTED_CODE: &str =
    "config.core.routing_group_member_unsupported";
pub const ROUTING_GROUP_DEFAULT_INVALID_CODE: &str = "config.core.routing_group_default_invalid";
pub const ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE: &str =
    "config.core.routing_group_health_check_invalid";
pub const ROUTING_GROUP_CYCLE_CODE: &str = "config.core.routing_group_cycle";

pub const DEFAULT_HEALTH_CHECK_URL: &str = "https://www.gstatic.com/generate_204";
pub const DEFAULT_HEALTH_CHECK_INTERVAL_SECS: u32 = 300;
pub const DEFAULT_URL_TEST_TOLERANCE_MS: u16 = 50;

const RESERVED_DIRECT: &str = "DIRECT";
const RESERVED_REJECT: &str = "REJECT";
const RESERVED_NAMES: [&str; 3] = [RESERVED_DIRECT, RESERVED_REJECT, "FINAL"];

/// Unvalidated routing input: Loon-style rule lines and policy group specs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutingSpec {
    pub rules: Vec<String>,
    pub groups: Vec<PolicyGroupSpec>,
}

/// Unvalidated policy group input. Targets are referenced by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyGroupSpec {
    pub id: String,
    pub kind: String,
    pub members: Vec<String>,
    pub default: Option<String>,
    pub url: Option<String>,
    pub interval_secs: Option<u32>,
    pub tolerance_ms: Option<u16>,
}

/// Where a rule, FINAL, or group member sends a connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PolicyTarget {
    Direct,
    Reject,
    Node(String),
    Group(String),
}

impl PolicyTarget {
    /// Returns the configuration name used to reference this target.
    pub fn name(&self) -> &str {
        match self {
            Self::Direct => RESERVED_DIRECT,
            Self::Reject => RESERVED_REJECT,
            Self::Node(id) | Self::Group(id) => id,
        }
    }
}

/// IPv4 or IPv6 network in CIDR notation, normalized to its network address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    pub fn parse(value: &str) -> Option<Self> {
        let (address, prefix) = value.trim().split_once('/')?;
        let address = address.trim().parse::<IpAddr>().ok()?;
        let prefix_len = prefix.trim().parse::<u8>().ok()?;
        let max_prefix = if address.is_ipv4() { 32 } else { 128 };
        if prefix_len > max_prefix {
            return None;
        }
        Some(Self {
            network: mask_ip(address, prefix_len),
            prefix_len,
        })
    }

    pub fn network(&self) -> IpAddr {
        self.network
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        self.network.is_ipv4() == ip.is_ipv4() && mask_ip(ip, self.prefix_len) == self.network
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.prefix_len)
    }
}

fn mask_ip(address: IpAddr, prefix_len: u8) -> IpAddr {
    match address {
        IpAddr::V4(address) => {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(prefix_len))
                .unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
        }
        IpAddr::V6(address) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(prefix_len))
                .unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
        }
    }
}

/// Connection property a rule matches against.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RuleMatcher {
    /// Exact, case-insensitive domain.
    Domain(String),
    /// The domain itself and every subdomain.
    DomainSuffix(String),
    /// Lower-case substring of the domain.
    DomainKeyword(String),
    IpCidr(IpCidr),
    /// Upper-case ISO 3166-1 alpha-2 country code.
    GeoIp(String),
    /// Name of a [`crate::rule_set::RuleSet`] the environment supplies.
    RuleSet(String),
    /// Lower-case GeoSite category (such as `cn` or `google`) whose domains
    /// the environment supplies.
    GeoSite(String),
    /// Destination port within an inclusive range.
    DstPort(u16, u16),
    /// Lower-case name of the local process that opened the connection,
    /// when the platform can tell.
    ProcessName(String),
    /// Every rule matches.
    And(Vec<RuleMatcher>),
    /// Any rule matches.
    Or(Vec<RuleMatcher>),
    /// The rule does not match.
    Not(Box<RuleMatcher>),
}

/// Deepest nesting of AND/OR/NOT accepted.
const MAX_LOGICAL_DEPTH: usize = 8;

impl RuleMatcher {
    /// Whether matching needs a destination address: an IP rule, or a
    /// logical rule containing one.
    pub fn matches_ip(&self) -> bool {
        match self {
            Self::IpCidr(_) | Self::GeoIp(_) => true,
            Self::And(rules) | Self::Or(rules) => rules.iter().any(Self::matches_ip),
            Self::Not(rule) => rule.matches_ip(),
            _ => false,
        }
    }
}

/// The rule as a line without its target, such as `DOMAIN-SUFFIX,example.com`,
/// for connection lists.
impl fmt::Display for RuleMatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Domain(domain) => write!(formatter, "DOMAIN,{domain}"),
            Self::DomainSuffix(suffix) => write!(formatter, "DOMAIN-SUFFIX,{suffix}"),
            Self::DomainKeyword(keyword) => write!(formatter, "DOMAIN-KEYWORD,{keyword}"),
            Self::IpCidr(cidr) if cidr.network().is_ipv6() => write!(formatter, "IP-CIDR6,{cidr}"),
            Self::IpCidr(cidr) => write!(formatter, "IP-CIDR,{cidr}"),
            Self::GeoIp(country) => write!(formatter, "GEOIP,{country}"),
            Self::RuleSet(name) => write!(formatter, "RULE-SET,{name}"),
            Self::GeoSite(category) => write!(formatter, "GEOSITE,{category}"),
            Self::DstPort(start, end) if start == end => write!(formatter, "DST-PORT,{start}"),
            Self::DstPort(start, end) => write!(formatter, "DST-PORT,{start}-{end}"),
            Self::ProcessName(name) => write!(formatter, "PROCESS-NAME,{name}"),
            Self::And(rules) => write_logical(formatter, "AND", rules),
            Self::Or(rules) => write_logical(formatter, "OR", rules),
            Self::Not(rule) => write_logical(formatter, "NOT", std::slice::from_ref(rule)),
        }
    }
}

fn write_logical(
    formatter: &mut fmt::Formatter<'_>,
    kind: &str,
    rules: &[RuleMatcher],
) -> fmt::Result {
    write!(formatter, "{kind},(")?;
    for (index, rule) in rules.iter().enumerate() {
        if index > 0 {
            formatter.write_str(",")?;
        }
        write!(formatter, "({rule})")?;
    }
    formatter.write_str(")")
}

/// One ordered routing rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingRule {
    pub matcher: RuleMatcher,
    pub target: PolicyTarget,
    /// For IP rules: never resolve a domain destination to match this rule.
    pub no_resolve: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyGroupKind {
    /// Manually selected member.
    Select,
    /// Lowest measured latency member.
    UrlTest,
    /// First healthy member in declaration order.
    Fallback,
}

impl PolicyGroupKind {
    /// The configuration name: `select`, `url-test` or `fallback`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::UrlTest => "url-test",
            Self::Fallback => "fallback",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCheck {
    pub url: String,
    pub interval_secs: u32,
    /// Latency difference below which url-test keeps its current member.
    pub tolerance_ms: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyGroup {
    pub id: String,
    pub kind: PolicyGroupKind,
    pub members: Vec<PolicyTarget>,
    /// Initial member for select groups.
    pub default: Option<PolicyTarget>,
    /// Present for url-test and fallback groups.
    pub health_check: Option<HealthCheck>,
}

/// Validated routing model shared by every execution engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingModel {
    pub rules: Vec<RoutingRule>,
    pub final_target: PolicyTarget,
    pub groups: Vec<PolicyGroup>,
}

/// Rule line parsed without resolving its target name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleLine {
    Rule {
        matcher: RuleMatcher,
        target: String,
        no_resolve: bool,
    },
    Final {
        target: String,
    },
}

/// Parses one Loon-style rule line such as `DOMAIN-SUFFIX,example.com,Proxy`
/// or a Surge-style logical rule such as
/// `AND,((DOMAIN-SUFFIX,example.com),(DST-PORT,443)),Proxy`.
pub fn parse_rule_line(line: &str) -> DomainResult<RuleLine> {
    let line = line.trim();
    let (head, rest) = line.split_once(',').unwrap_or((line, ""));
    let head = head.trim().to_ascii_uppercase();
    if is_logical(&head) {
        let (inner, after) = split_parenthesized(rest)?;
        let matcher = parse_logical(&head, inner, 1)?;
        let after = after.trim_start();
        let tail = after.strip_prefix(',').ok_or_else(|| {
            routing_error(
                ROUTING_RULE_LINE_INVALID_CODE,
                "logical rule must be followed by a target",
            )
        })?;
        let parts = tail.split(',').map(str::trim).collect::<Vec<_>>();
        if parts[0].is_empty() {
            return Err(routing_error(
                ROUTING_RULE_LINE_INVALID_CODE,
                "logical rule must be followed by a target",
            ));
        }
        let no_resolve = parse_options(&parts[1..], &matcher)?;
        return Ok(RuleLine::Rule {
            matcher,
            target: parts[0].to_string(),
            no_resolve,
        });
    }

    let parts = line.split(',').map(str::trim).collect::<Vec<_>>();
    let kind = parts[0].to_ascii_uppercase();
    if kind == "FINAL" {
        return match parts.as_slice() {
            [_, target] if !target.is_empty() => Ok(RuleLine::Final {
                target: (*target).to_string(),
            }),
            _ => Err(routing_error(
                ROUTING_RULE_LINE_INVALID_CODE,
                "FINAL rule must have exactly one target",
            )),
        };
    }

    if parts.len() < 3 || parts[1].is_empty() || parts[2].is_empty() {
        return Err(routing_error(
            ROUTING_RULE_LINE_INVALID_CODE,
            "routing rule must have a type, a value, and a target",
        ));
    }
    let matcher = parse_matcher(&kind, parts[1])?;
    let no_resolve = parse_options(&parts[3..], &matcher)?;
    Ok(RuleLine::Rule {
        matcher,
        target: parts[2].to_string(),
        no_resolve,
    })
}

fn parse_options(options: &[&str], matcher: &RuleMatcher) -> DomainResult<bool> {
    let mut no_resolve = false;
    for option in options {
        if option.eq_ignore_ascii_case("no-resolve") && matcher.matches_ip() {
            no_resolve = true;
        } else {
            return Err(routing_error(
                ROUTING_RULE_OPTION_UNSUPPORTED_CODE,
                "routing rule option is unsupported; only IP rules accept no-resolve",
            ));
        }
    }
    Ok(no_resolve)
}

fn is_logical(kind: &str) -> bool {
    matches!(kind, "AND" | "OR" | "NOT")
}

/// Splits `(inner)rest` at the parenthesis matching the first one.
fn split_parenthesized(text: &str) -> DomainResult<(&str, &str)> {
    let invalid = || {
        routing_error(
            ROUTING_RULE_LINE_INVALID_CODE,
            "logical rule needs balanced parentheses, as in AND,((DOMAIN,a.com),(DST-PORT,443))",
        )
    };
    let text = text.trim_start();
    if !text.starts_with('(') {
        return Err(invalid());
    }
    let mut depth = 0usize;
    for (index, character) in text.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok((&text[1..index], &text[index + 1..]));
                }
            }
            _ => {}
        }
    }
    Err(invalid())
}

/// Parses the parenthesized rules inside a logical rule, `(A,a),(B,b)`.
fn parse_logical(kind: &str, inner: &str, depth: usize) -> DomainResult<RuleMatcher> {
    if depth > MAX_LOGICAL_DEPTH {
        return Err(routing_error(
            ROUTING_RULE_LINE_INVALID_CODE,
            "logical rules are nested too deeply",
        ));
    }
    let mut rules = Vec::new();
    let mut rest = inner.trim();
    while !rest.is_empty() {
        let (item, after) = split_parenthesized(rest)?;
        rules.push(parse_sub_rule(item, depth)?);
        let after = after.trim_start();
        rest = match after.strip_prefix(',') {
            Some(next) => next.trim_start(),
            None if after.is_empty() => after,
            None => {
                return Err(routing_error(
                    ROUTING_RULE_LINE_INVALID_CODE,
                    "rules inside a logical rule must be separated by commas",
                ))
            }
        };
    }
    match (kind, rules.len()) {
        (_, 0) => Err(routing_error(
            ROUTING_RULE_LINE_INVALID_CODE,
            "logical rule must contain at least one rule",
        )),
        ("NOT", 1) => Ok(RuleMatcher::Not(Box::new(rules.remove(0)))),
        ("NOT", _) => Err(routing_error(
            ROUTING_RULE_LINE_INVALID_CODE,
            "NOT rule must contain exactly one rule",
        )),
        ("AND", _) => Ok(RuleMatcher::And(rules)),
        _ => Ok(RuleMatcher::Or(rules)),
    }
}

/// One rule inside a logical rule: a type and a value, or another logical
/// rule, without a target.
fn parse_sub_rule(text: &str, depth: usize) -> DomainResult<RuleMatcher> {
    let (kind, value) = text.split_once(',').ok_or_else(|| {
        routing_error(
            ROUTING_RULE_LINE_INVALID_CODE,
            "rule inside a logical rule must have a type and a value",
        )
    })?;
    let kind = kind.trim().to_ascii_uppercase();
    if is_logical(&kind) {
        let (inner, after) = split_parenthesized(value)?;
        if !after.trim().is_empty() {
            return Err(routing_error(
                ROUTING_RULE_LINE_INVALID_CODE,
                "rule inside a logical rule has no target",
            ));
        }
        return parse_logical(&kind, inner, depth + 1);
    }
    let mut parts = value.split(',').map(str::trim);
    let value = parts.next().unwrap_or_default();
    // `no-resolve` is accepted for compatibility; a logical rule resolves as
    // its own options say.
    if parts.any(|option| !option.eq_ignore_ascii_case("no-resolve")) || value.is_empty() {
        return Err(routing_error(
            ROUTING_RULE_LINE_INVALID_CODE,
            "rule inside a logical rule must have a type and a value",
        ));
    }
    parse_matcher(&kind, value)
}

/// The matcher of a rule type and its value.
fn parse_matcher(kind: &str, value: &str) -> DomainResult<RuleMatcher> {
    Ok(match kind {
        "DOMAIN" => RuleMatcher::Domain(normalize_rule_domain(value)?),
        "DOMAIN-SUFFIX" => {
            RuleMatcher::DomainSuffix(normalize_rule_domain(value.trim_start_matches('.'))?)
        }
        "DOMAIN-KEYWORD" => RuleMatcher::DomainKeyword(normalize_rule_domain(value)?),
        "IP-CIDR" | "IP-CIDR6" => RuleMatcher::IpCidr(IpCidr::parse(value).ok_or_else(|| {
            routing_error(
                ROUTING_RULE_VALUE_INVALID_CODE,
                "IP-CIDR rule value must be an address with a prefix length",
            )
        })?),
        "GEOIP" => RuleMatcher::GeoIp(normalize_country_code(value)?),
        "RULE-SET" => RuleMatcher::RuleSet(value.to_string()),
        "GEOSITE" => RuleMatcher::GeoSite(normalize_category(value)?),
        "DST-PORT" | "DEST-PORT" => {
            let (start, end) = parse_port_range(value)?;
            RuleMatcher::DstPort(start, end)
        }
        "PROCESS-NAME" => RuleMatcher::ProcessName(value.trim().to_lowercase()),
        _ => return Err(routing_error(
            ROUTING_RULE_TYPE_UNSUPPORTED_CODE,
            "routing rule type must be DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, IP-CIDR6, GEOIP, GEOSITE, DST-PORT, PROCESS-NAME, RULE-SET, AND, OR, NOT, or FINAL",
        )),
    })
}

/// A port or an inclusive `start-end` range.
fn parse_port_range(value: &str) -> DomainResult<(u16, u16)> {
    let invalid = || {
        routing_error(
            ROUTING_RULE_VALUE_INVALID_CODE,
            "DST-PORT rule value must be a port or a start-end range",
        )
    };
    let port = |text: &str| text.trim().parse::<u16>().map_err(|_| invalid());
    let (start, end) = match value.split_once('-') {
        Some((start, end)) => (port(start)?, port(end)?),
        None => {
            let port = port(value)?;
            (port, port)
        }
    };
    if start > end {
        return Err(invalid());
    }
    Ok((start, end))
}

fn normalize_category(value: &str) -> DomainResult<String> {
    let category = value.trim().to_ascii_lowercase();
    let valid = !category.is_empty()
        && category.len() <= 64
        && category
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'!' | b'@' | b'.'));
    if valid {
        Ok(category)
    } else {
        Err(routing_error(
            ROUTING_RULE_VALUE_INVALID_CODE,
            "GEOSITE rule value must be a category name such as cn or google",
        ))
    }
}

impl RoutingModel {
    /// Validates a routing spec against the node ids that can be referenced.
    pub fn from_spec(spec: &RoutingSpec, node_ids: &BTreeSet<String>) -> DomainResult<Self> {
        let names = TargetNames::collect(&spec.groups, node_ids)?;
        let groups = spec
            .groups
            .iter()
            .map(|group| normalize_group(group, &names))
            .collect::<DomainResult<Vec<_>>>()?;
        reject_group_cycles(&groups)?;

        let mut rules = Vec::with_capacity(spec.rules.len());
        let mut final_target = None;
        for (index, line) in spec.rules.iter().enumerate() {
            if final_target.is_some() {
                return Err(routing_error(
                    ROUTING_FINAL_NOT_LAST_CODE,
                    format!("routing rule {index} follows the FINAL rule"),
                ));
            }
            match parse_rule_line(line).map_err(|error| with_rule_index(error, index))? {
                RuleLine::Rule {
                    matcher,
                    target,
                    no_resolve,
                } => rules.push(RoutingRule {
                    matcher,
                    target: names
                        .resolve(&target)
                        .map_err(|error| with_rule_index(error, index))?,
                    no_resolve,
                }),
                RuleLine::Final { target } => {
                    final_target = Some(
                        names
                            .resolve(&target)
                            .map_err(|error| with_rule_index(error, index))?,
                    );
                }
            }
        }

        let final_target = final_target.ok_or_else(|| {
            routing_error(
                ROUTING_FINAL_MISSING_CODE,
                "routing rules must end with a FINAL rule",
            )
        })?;
        Ok(Self {
            rules,
            final_target,
            groups,
        })
    }

    pub fn group(&self, id: &str) -> Option<&PolicyGroup> {
        self.groups.iter().find(|group| group.id == id)
    }

    /// Decides where a connection goes, resolving policy groups to a node.
    ///
    /// Rules are evaluated in order. The first IP rule without `no-resolve`
    /// asks the environment to resolve a domain-only destination once; like a
    /// sing-box `resolve` action, the resolved address is then used by every
    /// later IP rule and is reported in the result. As in sing-box, a failed
    /// resolution rejects the connection instead of falling through to FINAL.
    pub fn decide(
        &self,
        query: &RouteQuery,
        environment: &dyn RoutingEnvironment,
    ) -> RouteResolution {
        let domain = query.domain.as_deref().map(normalize_query_domain);
        let process = query.process.as_deref().map(str::to_lowercase);
        let mut ip = query.ip;
        let mut resolved_ip = None;
        let mut resolve_attempted = false;

        for (index, rule) in self.rules.iter().enumerate() {
            if rule.matcher.matches_ip() && ip.is_none() && !rule.no_resolve && !resolve_attempted {
                resolve_attempted = true;
                if let Some(domain) = domain.as_deref() {
                    resolved_ip = environment.resolve(domain);
                    if resolved_ip.is_none() {
                        return RouteResolution {
                            matched: RouteMatch::ResolveFailed(index),
                            target: PolicyTarget::Reject,
                            group_path: Vec::new(),
                            outcome: RouteOutcome::Reject,
                            resolved_ip: None,
                        };
                    }
                    ip = resolved_ip;
                }
            }
            let input = MatchInput {
                domain: domain.as_deref(),
                ip,
                port: query.port,
                process: process.as_deref(),
            };
            if rule_matches(&rule.matcher, &input, environment) {
                return self.resolution(
                    RouteMatch::Rule(index),
                    &rule.target,
                    resolved_ip,
                    environment,
                );
            }
        }

        self.resolution(
            RouteMatch::Final,
            &self.final_target,
            resolved_ip,
            environment,
        )
    }

    /// Sends a connection straight to `target`, skipping the rules, as a
    /// global mode does. The result reports [`RouteMatch::Final`].
    pub fn route_to(
        &self,
        target: &PolicyTarget,
        environment: &dyn RoutingEnvironment,
    ) -> RouteResolution {
        self.resolution(RouteMatch::Final, target, None, environment)
    }

    /// The member a group currently picks: the selected or default member of
    /// a select group, the fastest of a url-test group, the first healthy
    /// member of a fallback group.
    pub fn group_member(
        &self,
        group_id: &str,
        environment: &dyn RoutingEnvironment,
    ) -> Option<PolicyTarget> {
        self.group(group_id)
            .map(|group| select_group_member(group, environment))
    }

    /// Looks up a configuration name the way rule targets are resolved:
    /// DIRECT, REJECT, a policy group id or a node id.
    pub fn target_named(&self, name: &str, node_ids: &BTreeSet<String>) -> Option<PolicyTarget> {
        let name = name.trim();
        if name.eq_ignore_ascii_case(RESERVED_DIRECT) {
            Some(PolicyTarget::Direct)
        } else if name.eq_ignore_ascii_case(RESERVED_REJECT) {
            Some(PolicyTarget::Reject)
        } else if self.group(name).is_some() {
            Some(PolicyTarget::Group(name.to_string()))
        } else if node_ids.contains(name) {
            Some(PolicyTarget::Node(name.to_string()))
        } else {
            None
        }
    }

    fn resolution(
        &self,
        matched: RouteMatch,
        target: &PolicyTarget,
        resolved_ip: Option<IpAddr>,
        environment: &dyn RoutingEnvironment,
    ) -> RouteResolution {
        let mut group_path = Vec::new();
        let mut current = target.clone();
        while let PolicyTarget::Group(id) = &current {
            let Some(group) = self.group(id) else { break };
            if group_path.contains(&group.id) {
                break;
            }
            group_path.push(group.id.clone());
            current = select_group_member(group, environment);
        }

        let outcome = match current {
            PolicyTarget::Direct | PolicyTarget::Group(_) => RouteOutcome::Direct,
            PolicyTarget::Reject => RouteOutcome::Reject,
            PolicyTarget::Node(id) => RouteOutcome::Node(id),
        };
        RouteResolution {
            matched,
            target: target.clone(),
            group_path,
            outcome,
            resolved_ip,
        }
    }
}

/// Destination of a connection being routed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteQuery {
    /// Destination domain, when known (for example from FakeIP or sniffing).
    pub domain: Option<String>,
    /// Destination address, when the connection targets an IP.
    pub ip: Option<IpAddr>,
    /// Destination port, for DST-PORT rules.
    pub port: Option<u16>,
    /// Name of the local process that opened the connection, for
    /// PROCESS-NAME rules, when the platform can tell.
    pub process: Option<String>,
}

impl RouteQuery {
    pub fn domain(domain: impl Into<String>) -> Self {
        Self {
            domain: Some(domain.into()),
            ..Self::default()
        }
    }

    pub fn ip(ip: IpAddr) -> Self {
        Self {
            ip: Some(ip),
            ..Self::default()
        }
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }
}

/// Runtime inputs an execution engine supplies to [`RoutingModel::decide`].
///
/// Every method has a conservative default so a static environment is enough
/// for snapshot tests: no DNS, no GeoIP database, and no health results.
pub trait RoutingEnvironment {
    /// Country code for an address, compared case-insensitively.
    fn geoip_country(&self, _ip: IpAddr) -> Option<String> {
        None
    }

    /// Whether `ip` is in the upper-case `country`; by default it compares
    /// [`RoutingEnvironment::geoip_country`].
    fn geoip_matches(&self, country: &str, ip: IpAddr) -> bool {
        self.geoip_country(ip)
            .is_some_and(|found| found.eq_ignore_ascii_case(country))
    }

    /// Whether the lower-case GeoSite `category` holds `domain` (lower case,
    /// no trailing dot); an unknown category matches nothing.
    fn geosite_matches(&self, _category: &str, _domain: &str) -> bool {
        false
    }

    /// Resolves a domain for IP rules that allow resolution; `None` means the
    /// lookup failed and the connection is rejected.
    fn resolve(&self, _domain: &str) -> Option<IpAddr> {
        None
    }

    /// Member name currently chosen in a select group.
    fn selected_member(&self, _group_id: &str) -> Option<String> {
        None
    }

    /// Last measured latency of a url-test or fallback member; `None` means
    /// untested or failed.
    fn member_latency_ms(&self, _group_id: &str, _member: &PolicyTarget) -> Option<u32> {
        None
    }

    /// Whether the named rule set holds the destination; an unknown set
    /// matches nothing.
    fn rule_set_matches(&self, _name: &str, _domain: Option<&str>, _ip: Option<IpAddr>) -> bool {
        false
    }
}

/// Environment with no runtime state: select groups use their default and
/// health-checked groups use their first member.
#[derive(Debug, Clone, Copy, Default)]
pub struct StaticRoutingEnvironment;

impl RoutingEnvironment for StaticRoutingEnvironment {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMatch {
    /// Index into [`RoutingModel::rules`].
    Rule(usize),
    /// Resolving the domain for the IP rule at this index failed.
    ResolveFailed(usize),
    Final,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOutcome {
    Direct,
    Reject,
    Node(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteResolution {
    pub matched: RouteMatch,
    /// Target named by the matched rule or FINAL.
    pub target: PolicyTarget,
    /// Groups traversed from `target` to `outcome`, outermost first.
    pub group_path: Vec<String>,
    pub outcome: RouteOutcome,
    /// Address obtained by resolving the domain for an IP rule.
    pub resolved_ip: Option<IpAddr>,
}

/// What one connection offers the rules, normalized.
struct MatchInput<'a> {
    domain: Option<&'a str>,
    ip: Option<IpAddr>,
    port: Option<u16>,
    process: Option<&'a str>,
}

fn rule_matches(
    matcher: &RuleMatcher,
    input: &MatchInput<'_>,
    environment: &dyn RoutingEnvironment,
) -> bool {
    let (domain, ip) = (input.domain, input.ip);
    match matcher {
        RuleMatcher::Domain(expected) => domain == Some(expected.as_str()),
        RuleMatcher::DomainKeyword(keyword) => {
            domain.is_some_and(|domain| domain.contains(keyword.as_str()))
        }
        RuleMatcher::DomainSuffix(suffix) => domain.is_some_and(|domain| {
            domain == suffix
                || domain
                    .strip_suffix(suffix.as_str())
                    .is_some_and(|prefix| prefix.ends_with('.'))
        }),
        RuleMatcher::IpCidr(cidr) => ip.is_some_and(|ip| cidr.contains(ip)),
        RuleMatcher::GeoIp(country) => ip.is_some_and(|ip| environment.geoip_matches(country, ip)),
        RuleMatcher::RuleSet(name) => environment.rule_set_matches(name, domain, ip),
        RuleMatcher::GeoSite(category) => {
            domain.is_some_and(|domain| environment.geosite_matches(category, domain))
        }
        RuleMatcher::DstPort(start, end) => input
            .port
            .is_some_and(|port| (*start..=*end).contains(&port)),
        RuleMatcher::ProcessName(name) => input.process == Some(name.as_str()),
        RuleMatcher::And(rules) => rules
            .iter()
            .all(|rule| rule_matches(rule, input, environment)),
        RuleMatcher::Or(rules) => rules
            .iter()
            .any(|rule| rule_matches(rule, input, environment)),
        RuleMatcher::Not(rule) => !rule_matches(rule, input, environment),
    }
}

fn select_group_member(group: &PolicyGroup, environment: &dyn RoutingEnvironment) -> PolicyTarget {
    let first = group.members[0].clone();
    match group.kind {
        PolicyGroupKind::Select => environment
            .selected_member(&group.id)
            .and_then(|name| {
                group
                    .members
                    .iter()
                    .find(|member| member.name() == name)
                    .cloned()
            })
            .or_else(|| group.default.clone())
            .unwrap_or(first),
        PolicyGroupKind::UrlTest => group
            .members
            .iter()
            .filter_map(|member| {
                environment
                    .member_latency_ms(&group.id, member)
                    .map(|latency| (latency, member))
            })
            .min_by_key(|(latency, _)| *latency)
            .map(|(_, member)| member.clone())
            .unwrap_or(first),
        PolicyGroupKind::Fallback => group
            .members
            .iter()
            .find(|member| environment.member_latency_ms(&group.id, member).is_some())
            .cloned()
            .unwrap_or(first),
    }
}

struct TargetNames<'a> {
    groups: BTreeSet<&'a str>,
    node_ids: &'a BTreeSet<String>,
}

impl<'a> TargetNames<'a> {
    fn collect(
        groups: &'a [PolicyGroupSpec],
        node_ids: &'a BTreeSet<String>,
    ) -> DomainResult<Self> {
        let mut names = BTreeSet::new();
        for group in groups {
            let id = group.id.trim();
            if id.is_empty() || id.contains(',') || is_reserved_name(id) {
                return Err(routing_error(
                    ROUTING_GROUP_ID_INVALID_CODE,
                    "policy group id must be non-empty, comma-free, and not DIRECT, REJECT, or FINAL",
                ));
            }
            if node_ids.contains(id) || !names.insert(id) {
                return Err(routing_error(
                    ROUTING_GROUP_ID_CONFLICT_CODE,
                    format!("policy group id {id} duplicates another group or node id"),
                ));
            }
        }
        Ok(Self {
            groups: names,
            node_ids,
        })
    }

    fn resolve(&self, name: &str) -> DomainResult<PolicyTarget> {
        let name = name.trim();
        if name.eq_ignore_ascii_case(RESERVED_DIRECT) {
            Ok(PolicyTarget::Direct)
        } else if name.eq_ignore_ascii_case(RESERVED_REJECT) {
            Ok(PolicyTarget::Reject)
        } else if self.groups.contains(name) {
            Ok(PolicyTarget::Group(name.to_string()))
        } else if self.node_ids.contains(name) {
            Ok(PolicyTarget::Node(name.to_string()))
        } else {
            Err(routing_error(
                ROUTING_TARGET_UNKNOWN_CODE,
                format!("routing target {name} is not DIRECT, REJECT, a policy group, or a node"),
            ))
        }
    }
}

fn normalize_group(spec: &PolicyGroupSpec, names: &TargetNames) -> DomainResult<PolicyGroup> {
    let id = spec.id.trim().to_string();
    let kind = match spec
        .kind
        .trim()
        .to_ascii_lowercase()
        .replace('_', "-")
        .as_str()
    {
        "select" => PolicyGroupKind::Select,
        "url-test" | "urltest" => PolicyGroupKind::UrlTest,
        "fallback" => PolicyGroupKind::Fallback,
        _ => {
            return Err(routing_error(
                ROUTING_GROUP_TYPE_UNSUPPORTED_CODE,
                format!("policy group {id} type must be select, url-test, or fallback"),
            ))
        }
    };
    if spec.members.is_empty() {
        return Err(routing_error(
            ROUTING_GROUP_MEMBERS_EMPTY_CODE,
            format!("policy group {id} must have at least one member"),
        ));
    }

    let mut members = Vec::with_capacity(spec.members.len());
    for member in &spec.members {
        let member = names.resolve(member)?;
        let supported = match (&member, kind) {
            (PolicyTarget::Reject, _) => false,
            (PolicyTarget::Group(_), PolicyGroupKind::Select) => true,
            (PolicyTarget::Group(_), _) => false,
            (PolicyTarget::Direct | PolicyTarget::Node(_), _) => true,
        };
        if !supported {
            return Err(routing_error(
                ROUTING_GROUP_MEMBER_UNSUPPORTED_CODE,
                format!(
                    "policy group {id} cannot contain {}; groups never contain REJECT and only select groups contain other groups",
                    member.name()
                ),
            ));
        }
        if !members.contains(&member) {
            members.push(member);
        }
    }

    let default = match (&spec.default, kind) {
        (None, _) => None,
        (Some(name), PolicyGroupKind::Select) => {
            let target = names.resolve(name)?;
            if !members.contains(&target) {
                return Err(routing_error(
                    ROUTING_GROUP_DEFAULT_INVALID_CODE,
                    format!("policy group {id} default must be one of its members"),
                ));
            }
            Some(target)
        }
        (Some(_), _) => {
            return Err(routing_error(
                ROUTING_GROUP_DEFAULT_INVALID_CODE,
                format!("policy group {id} default is only supported for select groups"),
            ))
        }
    };

    let health_check = match kind {
        PolicyGroupKind::Select => {
            if spec.url.is_some() || spec.interval_secs.is_some() || spec.tolerance_ms.is_some() {
                return Err(routing_error(
                    ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE,
                    format!("policy group {id} is select and cannot have health check fields"),
                ));
            }
            None
        }
        PolicyGroupKind::UrlTest | PolicyGroupKind::Fallback => {
            if kind == PolicyGroupKind::Fallback && spec.tolerance_ms.is_some() {
                return Err(routing_error(
                    ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE,
                    format!("policy group {id} is fallback and cannot have a tolerance"),
                ));
            }
            let url = spec
                .url
                .as_deref()
                .map(str::trim)
                .unwrap_or(DEFAULT_HEALTH_CHECK_URL)
                .to_string();
            let interval_secs = spec
                .interval_secs
                .unwrap_or(DEFAULT_HEALTH_CHECK_INTERVAL_SECS);
            if !(url.starts_with("http://") || url.starts_with("https://")) || interval_secs == 0 {
                return Err(routing_error(
                    ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE,
                    format!(
                        "policy group {id} health check needs an http(s) url and a positive interval"
                    ),
                ));
            }
            Some(HealthCheck {
                url,
                interval_secs,
                tolerance_ms: spec.tolerance_ms.unwrap_or(DEFAULT_URL_TEST_TOLERANCE_MS),
            })
        }
    };

    Ok(PolicyGroup {
        id,
        kind,
        members,
        default,
        health_check,
    })
}

fn reject_group_cycles(groups: &[PolicyGroup]) -> DomainResult<()> {
    let edges = groups
        .iter()
        .map(|group| {
            let children = group
                .members
                .iter()
                .filter_map(|member| match member {
                    PolicyTarget::Group(id) => Some(id.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>();
            (group.id.as_str(), children)
        })
        .collect::<BTreeMap<_, _>>();

    // 0 = unvisited, 1 = on the current path, 2 = done.
    fn visit<'a>(
        id: &'a str,
        edges: &BTreeMap<&'a str, Vec<&'a str>>,
        state: &mut BTreeMap<&'a str, u8>,
    ) -> DomainResult<()> {
        match state.get(id).copied().unwrap_or(0) {
            1 => {
                return Err(routing_error(
                    ROUTING_GROUP_CYCLE_CODE,
                    format!("policy group {id} is part of a group cycle"),
                ))
            }
            2 => return Ok(()),
            _ => {}
        }
        state.insert(id, 1);
        for child in edges.get(id).into_iter().flatten().copied() {
            visit(child, edges, state)?;
        }
        state.insert(id, 2);
        Ok(())
    }

    let mut state = BTreeMap::new();
    for id in edges.keys().copied() {
        visit(id, &edges, &mut state)?;
    }
    Ok(())
}

pub(crate) fn normalize_rule_domain(value: &str) -> DomainResult<String> {
    let domain = normalize_query_domain(value);
    let valid = !domain.is_empty()
        && domain
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-._".contains(character))
        && !domain.starts_with('.')
        && !domain.contains("..");
    if valid {
        Ok(domain)
    } else {
        Err(routing_error(
            ROUTING_RULE_VALUE_INVALID_CODE,
            "domain rule value must be an ASCII domain name",
        ))
    }
}

fn normalize_query_domain(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_country_code(value: &str) -> DomainResult<String> {
    if value.len() == 2
        && value
            .chars()
            .all(|character| character.is_ascii_alphabetic())
    {
        Ok(value.to_ascii_uppercase())
    } else {
        Err(routing_error(
            ROUTING_RULE_VALUE_INVALID_CODE,
            "GEOIP rule value must be a two-letter country code",
        ))
    }
}

fn is_reserved_name(name: &str) -> bool {
    RESERVED_NAMES
        .iter()
        .any(|reserved| reserved.eq_ignore_ascii_case(name))
}

fn with_rule_index(error: DomainError, index: usize) -> DomainError {
    DomainError::new(
        error.code,
        format!("routing rule {index}: {}", error.message),
    )
}

pub(crate) fn routing_error(code: &'static str, message: impl Into<String>) -> DomainError {
    DomainError::new(code, message)
}
