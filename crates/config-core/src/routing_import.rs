//! Import of rules and policy groups from Surge/Loon profiles and Clash YAML.
//!
//! Subscription parsing keeps returning only nodes. This module reads the
//! same payload a second time for `[Proxy Group]`/`[Rule]` sections or Clash
//! `proxy-groups`/`rules`, maps proxy names to the parsed node ids, and builds
//! a [`RoutingModel`]. `RULE-SET`/`DOMAIN-SET` URLs, Loon `[Remote Rule]`
//! lines, and Clash `rule-providers` become [`ImportedRuleSet`]s that the
//! rewritten rules reference by id. Rules, group members, and groups the
//! model cannot express are skipped with a warning. When the remaining input still fails
//! validation (for example no FINAL rule or a group cycle), no routing is
//! returned and the caller keeps its single-node behavior.

use crate::routing::{parse_rule_line, PolicyGroupSpec, RoutingModel, RoutingSpec};
use control_domain::{Diagnostic, DiagnosticSeverity, NodeDescriptor};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

pub const SOURCE_ROUTING_IMPORT: &str = "config.core.routing_import";
pub const ROUTING_IMPORT_READY_CODE: &str = "config.core.routing_import.ready";
pub const ROUTING_IMPORT_RULE_SKIPPED_CODE: &str = "config.core.routing_import.rule_skipped";
pub const ROUTING_IMPORT_GROUP_SKIPPED_CODE: &str = "config.core.routing_import.group_skipped";
pub const ROUTING_IMPORT_MEMBER_SKIPPED_CODE: &str = "config.core.routing_import.member_skipped";
pub const ROUTING_IMPORT_OPTION_IGNORED_CODE: &str = "config.core.routing_import.option_ignored";
pub const ROUTING_IMPORT_INVALID_CODE: &str = "config.core.routing_import.invalid";

const SUPPORTED_RULE_TYPES: [&str; 10] = [
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "GEOSITE",
    "DST-PORT",
    "DEST-PORT",
    "PROCESS-NAME",
];
const LOGICAL_RULE_TYPES: [&str; 3] = ["AND", "OR", "NOT"];
/// Most rule sets one import creates; the embedded engine accepts 32.
pub const MAX_IMPORTED_RULE_SETS: usize = 32;
/// The embedded engine refreshes a remote set at most this often.
const MIN_RULE_SET_INTERVAL_SECS: u32 = 600;
const MAX_RULE_SET_URL_LEN: usize = 2048;
const MAX_RULE_SET_ID_LEN: usize = 64;
const HEALTH_CHECK_OPTIONS: [&str; 3] = ["url", "interval", "tolerance"];
/// How a load-balance group spreads connections: Clash `strategy`, Loon
/// `algorithm`.
const BALANCE_OPTIONS: [&str; 2] = ["strategy", "algorithm"];
/// Longest node name filter accepted.
const MAX_FILTER_LEN: usize = 1024;

/// Routing found in a subscription payload, with import diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedRouting {
    /// `None` when the payload has no rules or the imported rules are invalid.
    pub routing: Option<RoutingModel>,
    /// The rule lines and groups `routing` was built from, for engines that
    /// take the spec form (the embedded engine's config envelope).
    pub spec: Option<RoutingSpec>,
    /// Remote rule sets that `spec` rules reference as `RULE-SET,<id>`, in
    /// first-use order. Empty when `spec` is `None`.
    pub rule_sets: Vec<ImportedRuleSet>,
    pub diagnostics: Vec<Diagnostic>,
}

/// A remote rule list found in the payload, in the embedded engine's
/// `routing.rule_sets` shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedRuleSet {
    /// `[A-Za-z0-9._-]`, unique within one import.
    pub id: String,
    pub url: String,
    /// `Some("domain")` when bare lines match one domain only (Surge
    /// `DOMAIN-SET`, Clash `behavior: domain`); `None` keeps the engine's
    /// suffix default.
    pub format: Option<&'static str>,
    /// At least 600 seconds when present.
    pub interval_secs: Option<u32>,
    /// The policy group or node the download goes through (Clash `proxy`).
    pub via: Option<String>,
}

/// Imports rules and policy groups from a Surge/Loon profile or Clash YAML.
///
/// `nodes` are the nodes parsed from the same payload; rule and group targets
/// refer to them by proxy name and are rewritten to node ids.
pub fn import_subscription_routing(content: &str, nodes: &[NodeDescriptor]) -> ImportedRouting {
    let source = if has_ini_routing_sections(content) {
        parse_ini_routing(content)
    } else {
        parse_clash_routing(content)
    };
    let Some(source) = source else {
        return ImportedRouting {
            routing: None,
            spec: None,
            rule_sets: Vec::new(),
            diagnostics: Vec::new(),
        };
    };
    build_routing(source, nodes)
}

#[derive(Debug, Default)]
struct RoutingSource {
    format: &'static str,
    rules: Vec<String>,
    /// Loon `[Remote Rule]` entries as `RULE-SET,<url>,<policy>` lines;
    /// they are matched after the local rules, before FINAL.
    remote_rules: Vec<String>,
    groups: Vec<SourceGroup>,
    /// Clash `rule-providers` by name.
    providers: BTreeMap<String, RuleProvider>,
}

#[derive(Debug, Default)]
struct RuleProvider {
    kind: Option<String>,
    behavior: Option<String>,
    format: Option<String>,
    url: Option<String>,
    interval: Option<String>,
    proxy: Option<String>,
}

#[derive(Debug)]
struct SourceGroup {
    name: String,
    kind: String,
    members: Vec<String>,
    options: BTreeMap<String, String>,
}

fn has_ini_routing_sections(content: &str) -> bool {
    content
        .lines()
        .filter_map(ini_section)
        .any(|section| section == "rule" || section == "proxy group" || section == "remote rule")
}

fn ini_section(line: &str) -> Option<String> {
    let line = line.trim();
    let section = line.strip_prefix('[')?.strip_suffix(']')?;
    Some(section.trim().to_ascii_lowercase())
}

fn parse_ini_routing(content: &str) -> Option<RoutingSource> {
    let mut source = RoutingSource {
        format: "surge/loon",
        ..RoutingSource::default()
    };
    let mut section = String::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with("//")
            || line.starts_with(';')
        {
            continue;
        }
        if let Some(name) = ini_section(line) {
            section = name;
            continue;
        }
        match section.as_str() {
            "rule" => source.rules.push(line.to_string()),
            "remote rule" => source.remote_rules.extend(parse_remote_rule_line(line)),
            "proxy group" => {
                if let Some(group) = parse_ini_group_line(line) {
                    source.groups.push(group);
                }
            }
            _ => {}
        }
    }
    (!source.rules.is_empty() || !source.remote_rules.is_empty()).then_some(source)
}

/// Parses Loon `url, policy=Name, tag=Name, enabled=true` into a
/// `RULE-SET,url,policy` line; disabled entries are dropped.
fn parse_remote_rule_line(line: &str) -> Option<String> {
    let mut parts = line.split(',').map(str::trim);
    let url = parts.next()?;
    let mut policy = None;
    for part in parts {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "policy" => policy = Some(strip_quotes(value.trim())),
            "enabled" if value.trim().eq_ignore_ascii_case("false") => return None,
            _ => {}
        }
    }
    Some(format!("RULE-SET,{url},{}", policy?))
}

/// Parses `Name = type, member, member, key=value`.
fn parse_ini_group_line(line: &str) -> Option<SourceGroup> {
    let (name, definition) = line.split_once('=')?;
    let mut parts = definition.split(',').map(str::trim);
    let kind = parts.next()?.to_string();
    let mut members = Vec::new();
    let mut options = BTreeMap::new();
    for part in parts.filter(|part| !part.is_empty()) {
        match part.split_once('=') {
            Some((key, value)) => {
                options.insert(key.trim().to_ascii_lowercase(), value.trim().to_string());
            }
            None => members.push(strip_quotes(part).to_string()),
        }
    }
    Some(SourceGroup {
        name: strip_quotes(name.trim()).to_string(),
        kind,
        members,
        options,
    })
}

fn strip_quotes(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
}

#[derive(Debug, Deserialize)]
struct RawClashRoutingDocument {
    rules: Option<Vec<String>>,
    #[serde(rename = "proxy-groups")]
    proxy_groups: Option<Vec<RawClashProxyGroup>>,
    #[serde(rename = "rule-providers")]
    rule_providers: Option<BTreeMap<String, RawClashRuleProvider>>,
}

#[derive(Debug, Deserialize)]
struct RawClashRuleProvider {
    #[serde(rename = "type")]
    kind: Option<String>,
    behavior: Option<String>,
    format: Option<String>,
    url: Option<String>,
    interval: Option<RawScalar>,
    proxy: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawClashProxyGroup {
    name: Option<RawScalar>,
    #[serde(rename = "type")]
    kind: Option<String>,
    proxies: Option<Vec<RawScalar>>,
    url: Option<String>,
    interval: Option<RawScalar>,
    tolerance: Option<RawScalar>,
    strategy: Option<String>,
    filter: Option<String>,
    #[serde(rename = "exclude-filter")]
    exclude_filter: Option<String>,
    #[serde(rename = "include-all")]
    include_all: Option<RawScalar>,
    #[serde(rename = "include-all-proxies")]
    include_all_proxies: Option<RawScalar>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawScalar {
    Text(String),
    Integer(i64),
    Bool(bool),
}

impl RawScalar {
    fn into_text(self) -> String {
        match self {
            Self::Text(value) => value,
            Self::Integer(value) => value.to_string(),
            Self::Bool(value) => value.to_string(),
        }
    }
}

fn parse_clash_routing(content: &str) -> Option<RoutingSource> {
    let raw = serde_saphyr::from_str::<RawClashRoutingDocument>(content.trim()).ok()?;
    let rules = raw.rules.filter(|rules| !rules.is_empty())?;
    let groups = raw
        .proxy_groups
        .unwrap_or_default()
        .into_iter()
        .filter_map(|group| {
            let mut options = BTreeMap::new();
            if let Some(url) = group.url {
                options.insert("url".to_string(), url);
            }
            if let Some(interval) = group.interval {
                options.insert("interval".to_string(), interval.into_text());
            }
            if let Some(tolerance) = group.tolerance {
                options.insert("tolerance".to_string(), tolerance.into_text());
            }
            let text_options = [
                ("strategy", group.strategy),
                ("filter", group.filter),
                ("exclude-filter", group.exclude_filter),
                ("include-all", group.include_all.map(RawScalar::into_text)),
                (
                    "include-all-proxies",
                    group.include_all_proxies.map(RawScalar::into_text),
                ),
            ];
            for (key, value) in text_options {
                if let Some(value) = value {
                    options.insert(key.to_string(), value);
                }
            }
            Some(SourceGroup {
                name: group.name?.into_text().trim().to_string(),
                kind: group.kind.unwrap_or_default(),
                members: group
                    .proxies
                    .unwrap_or_default()
                    .into_iter()
                    .map(RawScalar::into_text)
                    .collect(),
                options,
            })
        })
        .collect();
    let providers = raw
        .rule_providers
        .unwrap_or_default()
        .into_iter()
        .map(|(name, provider)| {
            (
                name,
                RuleProvider {
                    kind: provider.kind,
                    behavior: provider.behavior,
                    format: provider.format,
                    url: provider.url,
                    interval: provider.interval.map(RawScalar::into_text),
                    proxy: provider.proxy,
                },
            )
        })
        .collect();
    Some(RoutingSource {
        format: "clash",
        rules,
        remote_rules: Vec::new(),
        groups,
        providers,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupKind {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
    RoundRobin,
}

impl GroupKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::UrlTest => "url-test",
            Self::Fallback => "fallback",
            Self::LoadBalance => "load-balance",
            Self::RoundRobin => "round-robin",
        }
    }

    /// Whether `key` is an option this kind of group uses.
    fn uses_option(self, key: &str) -> bool {
        match self {
            Self::Select => false,
            Self::UrlTest | Self::Fallback => HEALTH_CHECK_OPTIONS.contains(&key),
            Self::LoadBalance | Self::RoundRobin => {
                HEALTH_CHECK_OPTIONS.contains(&key) || BALANCE_OPTIONS.contains(&key)
            }
        }
    }
}

/// The kind of a source group. A load-balance group whose `strategy` or
/// `algorithm` is `round-robin` (or `random`) takes members in turn; every
/// other strategy (`consistent-hashing`, `sticky-sessions`, Loon `pcc`)
/// keeps one member per destination host.
fn group_kind(group: &SourceGroup) -> Option<GroupKind> {
    match group.kind.trim().to_ascii_lowercase().as_str() {
        "select" => Some(GroupKind::Select),
        "url-test" => Some(GroupKind::UrlTest),
        "fallback" => Some(GroupKind::Fallback),
        "load-balance" => {
            let strategy = BALANCE_OPTIONS
                .iter()
                .find_map(|key| group.options.get(*key))
                .map(|value| value.trim().to_ascii_lowercase());
            match strategy.as_deref() {
                Some("round-robin" | "random") => Some(GroupKind::RoundRobin),
                _ => Some(GroupKind::LoadBalance),
            }
        }
        _ => None,
    }
}

/// Adds to each group the imported nodes its name filter picks.
///
/// Surge `include-all-proxies` and Clash `include-all`/`include-all-proxies`
/// take every node; Surge `policy-regex-filter` and Clash `filter` keep the
/// names that match (Clash may list several patterns separated by a
/// backtick) and Clash `exclude-filter` drops names that match. Both
/// clients apply filters to external lists or providers, which are not
/// imported, so a filter on a group without members picks from every node;
/// a filter on a group with members and without `include-all` is ignored.
fn expand_filters(importer: &mut Importer, groups: &mut [SourceGroup], nodes: &[NodeDescriptor]) {
    for group in groups.iter_mut() {
        let include_all = [
            take_option(&mut group.options, "include-all"),
            take_option(&mut group.options, "include-all-proxies"),
        ]
        .into_iter()
        .flatten()
        .any(|value| is_truthy(&value));
        let filter = [
            take_option(&mut group.options, "policy-regex-filter"),
            take_option(&mut group.options, "filter"),
        ]
        .into_iter()
        .flatten()
        .next();
        let exclude = take_option(&mut group.options, "exclude-filter");
        let filtered = filter.is_some() || exclude.is_some();
        if !include_all && !(filtered && group.members.is_empty()) {
            if filtered {
                importer.warn(
                    ROUTING_IMPORT_OPTION_IGNORED_CODE,
                    format!(
                        "policy group {} name filter was ignored: it only applies with include-all or to a group without members",
                        group.name
                    ),
                );
            }
            continue;
        }
        let (Some(keep), Some(drop)) = (name_filter(filter), name_filter(exclude)) else {
            importer.warn(
                ROUTING_IMPORT_OPTION_IGNORED_CODE,
                format!(
                    "policy group {} name filter is not a supported regular expression; no nodes were added",
                    group.name
                ),
            );
            continue;
        };
        for node in nodes {
            let name = node.name.trim();
            let kept = keep
                .as_ref()
                .is_none_or(|patterns| matches_any(patterns, name));
            let dropped = drop
                .as_ref()
                .is_some_and(|patterns| matches_any(patterns, name));
            if kept && !dropped && !group.members.iter().any(|member| member.trim() == name) {
                group.members.push(name.to_string());
            }
        }
    }
}

fn take_option(options: &mut BTreeMap<String, String>, key: &str) -> Option<String> {
    options.remove(key)
}

fn is_truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// `Some(None)` without a filter, `Some(patterns)` for a valid one, `None`
/// for one that does not compile.
fn name_filter(filter: Option<String>) -> Option<Option<Vec<regex::Regex>>> {
    let Some(filter) = filter else {
        return Some(None);
    };
    let filter = strip_quotes(filter.trim());
    if filter.is_empty() || filter.len() > MAX_FILTER_LEN {
        return None;
    }
    filter
        .split('`')
        .filter(|pattern| !pattern.is_empty())
        .map(|pattern| {
            regex::RegexBuilder::new(pattern)
                .size_limit(1 << 20)
                .build()
                .ok()
        })
        .collect::<Option<Vec<_>>>()
        .map(Some)
}

fn matches_any(patterns: &[regex::Regex], name: &str) -> bool {
    patterns.iter().any(|pattern| pattern.is_match(name))
}

fn is_reject_policy(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    name == "REJECT" || name.starts_with("REJECT-")
}

struct Importer<'a> {
    nodes_by_name: BTreeMap<&'a str, &'a str>,
    diagnostics: Vec<Diagnostic>,
}

impl Importer<'_> {
    fn warn(&mut self, code: &'static str, message: String) {
        self.diagnostics.push(Diagnostic::new(
            DiagnosticSeverity::Warning,
            code,
            message,
            Some(SOURCE_ROUTING_IMPORT.to_string()),
        ));
    }
}

fn build_routing(source: RoutingSource, nodes: &[NodeDescriptor]) -> ImportedRouting {
    let mut nodes_by_name = BTreeMap::new();
    for node in nodes {
        nodes_by_name
            .entry(node.name.trim())
            .or_insert(node.id.as_str());
    }
    let mut importer = Importer {
        nodes_by_name,
        diagnostics: Vec::new(),
    };

    let mut source_groups = source.groups;
    expand_filters(&mut importer, &mut source_groups, nodes);
    let groups = import_groups(&mut importer, source_groups);
    let group_ids = groups
        .iter()
        .map(|group| group.id.clone())
        .collect::<BTreeSet<_>>();
    let mut source_rules = source.rules;
    let final_index = source_rules
        .iter()
        .position(|line| {
            let kind = line.split(',').next().unwrap_or_default().trim();
            kind.eq_ignore_ascii_case("FINAL") || kind.eq_ignore_ascii_case("MATCH")
        })
        .unwrap_or(source_rules.len());
    source_rules.splice(final_index..final_index, source.remote_rules);
    let mut rule_sets = RuleSetCollector::new(&source.providers);
    let rules = import_rules(&mut importer, source_rules, &group_ids, &mut rule_sets);

    let spec = RoutingSpec { rules, groups };
    let node_ids = nodes
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    match RoutingModel::from_spec(&spec, &node_ids) {
        Ok(model) => {
            importer.diagnostics.push(Diagnostic::new(
                DiagnosticSeverity::Info,
                ROUTING_IMPORT_READY_CODE,
                format!(
                    "imported {} {} rules and {} policy groups",
                    model.rules.len() + 1,
                    source.format,
                    model.groups.len()
                ),
                Some(SOURCE_ROUTING_IMPORT.to_string()),
            ));
            ImportedRouting {
                routing: Some(model),
                spec: Some(spec),
                rule_sets: rule_sets.sets,
                diagnostics: importer.diagnostics,
            }
        }
        Err(error) => {
            importer.warn(
                ROUTING_IMPORT_INVALID_CODE,
                format!(
                    "{} rules were not imported and routing falls back to one node: {}",
                    source.format, error.message
                ),
            );
            ImportedRouting {
                routing: None,
                spec: None,
                rule_sets: Vec::new(),
                diagnostics: importer.diagnostics,
            }
        }
    }
}

/// Keeps supported groups and members. Groups that end up empty are dropped,
/// which can empty groups that referenced them, so this repeats until stable.
fn import_groups(importer: &mut Importer, groups: Vec<SourceGroup>) -> Vec<PolicyGroupSpec> {
    let mut candidates = Vec::new();
    for group in groups {
        if group.name.is_empty() {
            continue;
        }
        match group_kind(&group) {
            Some(kind) => candidates.push((group, kind)),
            None => importer.warn(
                ROUTING_IMPORT_GROUP_SKIPPED_CODE,
                format!(
                    "policy group {} was skipped: type {} is unsupported",
                    group.name, group.kind
                ),
            ),
        }
    }

    let mut kept = candidates
        .iter()
        .map(|(group, kind)| (group.name.clone(), *kind))
        .collect::<BTreeMap<_, _>>();
    loop {
        let emptied = candidates
            .iter()
            .filter(|(group, kind)| {
                kept.contains_key(&group.name) && {
                    !group.members.iter().any(|member| {
                        resolve_member(&importer.nodes_by_name, &kept, *kind, member).is_ok()
                    })
                }
            })
            .map(|(group, _)| group.name.clone())
            .collect::<Vec<_>>();
        if emptied.is_empty() {
            break;
        }
        for name in emptied {
            kept.remove(&name);
            importer.warn(
                ROUTING_IMPORT_GROUP_SKIPPED_CODE,
                format!("policy group {name} was skipped: none of its members can be imported"),
            );
        }
    }

    let mut specs = Vec::new();
    for (group, kind) in candidates {
        if !kept.contains_key(&group.name) {
            continue;
        }
        let mut members = Vec::new();
        for member in &group.members {
            match resolve_member(&importer.nodes_by_name, &kept, kind, member) {
                Ok(target) => members.push(target),
                Err(reason) => importer.warn(
                    ROUTING_IMPORT_MEMBER_SKIPPED_CODE,
                    format!(
                        "policy group {} member {member} was skipped: {reason}",
                        group.name
                    ),
                ),
            }
        }

        let ignored = group
            .options
            .keys()
            .filter(|key| !kind.uses_option(key))
            .cloned()
            .collect::<Vec<_>>();
        if !ignored.is_empty() {
            importer.warn(
                ROUTING_IMPORT_OPTION_IGNORED_CODE,
                format!(
                    "policy group {} options were ignored: {}",
                    group.name,
                    ignored.join(", ")
                ),
            );
        }
        let health_check = kind != GroupKind::Select;
        specs.push(PolicyGroupSpec {
            id: group.name.clone(),
            kind: kind.as_str().to_string(),
            members,
            default: None,
            url: group.options.get("url").filter(|_| health_check).cloned(),
            interval_secs: group
                .options
                .get("interval")
                .filter(|_| health_check)
                .and_then(|value| value.parse().ok()),
            tolerance_ms: group
                .options
                .get("tolerance")
                .filter(|_| kind == GroupKind::UrlTest)
                .and_then(|value| value.parse().ok()),
        });
    }
    specs
}

fn resolve_member(
    nodes_by_name: &BTreeMap<&str, &str>,
    groups: &BTreeMap<String, GroupKind>,
    kind: GroupKind,
    member: &str,
) -> Result<String, &'static str> {
    let member = member.trim();
    if member.eq_ignore_ascii_case("DIRECT") {
        return Ok("DIRECT".to_string());
    }
    if is_reject_policy(member) {
        return Err("policy groups cannot contain REJECT");
    }
    if groups.contains_key(member) {
        return if kind == GroupKind::Select {
            Ok(member.to_string())
        } else {
            Err("only select groups can contain other groups")
        };
    }
    nodes_by_name
        .get(member)
        .map(|id| (*id).to_string())
        .ok_or("no imported node or group has this name")
}

/// Rewrites rule targets to model names and keeps only supported rules up to
/// and including the first FINAL (Clash `MATCH`).
fn import_rules(
    importer: &mut Importer,
    rules: Vec<String>,
    group_ids: &BTreeSet<String>,
    rule_sets: &mut RuleSetCollector,
) -> Vec<String> {
    let mut imported = Vec::new();
    let mut skipped = BTreeMap::<String, usize>::new();
    for (index, line) in rules.iter().enumerate() {
        let parts = line.split(',').map(str::trim).collect::<Vec<_>>();
        let kind = parts[0].to_ascii_uppercase();
        if kind == "FINAL" || kind == "MATCH" {
            let Some(target) = parts.get(1) else {
                importer.warn(
                    ROUTING_IMPORT_RULE_SKIPPED_CODE,
                    format!("rule {index} was skipped: {kind} has no target"),
                );
                continue;
            };
            match resolve_rule_target(importer, group_ids, target) {
                Some(target) => imported.push(format!("FINAL,{target}")),
                None => importer.warn(
                    ROUTING_IMPORT_RULE_SKIPPED_CODE,
                    format!("rule {index} was skipped: target {target} was not imported"),
                ),
            }
            if index + 1 < rules.len() {
                importer.warn(
                    ROUTING_IMPORT_RULE_SKIPPED_CODE,
                    format!("{} rules after FINAL were skipped", rules.len() - index - 1),
                );
            }
            break;
        }

        let result = if LOGICAL_RULE_TYPES.contains(&kind.as_str()) {
            import_logical_rule(importer, group_ids, rule_sets, &kind, line)
        } else if kind == "RULE-SET" || kind == "DOMAIN-SET" {
            import_rule_set_rule(importer, group_ids, rule_sets, &kind, &parts)
        } else if SUPPORTED_RULE_TYPES.contains(&kind.as_str()) {
            import_plain_rule(importer, group_ids, &kind, &parts)
        } else {
            *skipped.entry(kind).or_default() += 1;
            continue;
        };
        match result {
            Ok(rule) => imported.push(rule),
            Err(reason) => importer.warn(
                ROUTING_IMPORT_RULE_SKIPPED_CODE,
                format!("rule {index} was skipped: {reason}"),
            ),
        }
    }

    if !skipped.is_empty() {
        let summary = skipped
            .iter()
            .map(|(kind, count)| format!("{kind} x{count}"))
            .collect::<Vec<_>>()
            .join(", ");
        importer.warn(
            ROUTING_IMPORT_RULE_SKIPPED_CODE,
            format!("unsupported rule types were skipped: {summary}"),
        );
    }
    imported
}

/// `TYPE,value,target[,no-resolve]`.
fn import_plain_rule(
    importer: &Importer,
    group_ids: &BTreeSet<String>,
    kind: &str,
    parts: &[&str],
) -> Result<String, String> {
    if parts.len() < 3 {
        return Err(format!("{kind} needs a value and a target"));
    }
    let target = resolve_rule_target(importer, group_ids, parts[2])
        .ok_or_else(|| format!("target {} was not imported", parts[2]))?;
    let no_resolve = parts[3..]
        .iter()
        .any(|option| option.eq_ignore_ascii_case("no-resolve"))
        && matches!(kind, "IP-CIDR" | "IP-CIDR6" | "GEOIP");
    let rewritten = format!(
        "{kind},{},{target}{}",
        parts[1],
        if no_resolve { ",no-resolve" } else { "" }
    );
    parse_rule_line(&rewritten)
        .map(|_| rewritten)
        .map_err(|error| error.message)
}

/// `RULE-SET,<url or provider>,target` and Surge `DOMAIN-SET,<url>,target`,
/// rewritten to `RULE-SET,<id>,target`.
fn import_rule_set_rule(
    importer: &Importer,
    group_ids: &BTreeSet<String>,
    rule_sets: &mut RuleSetCollector,
    kind: &str,
    parts: &[&str],
) -> Result<String, String> {
    if parts.len() < 3 {
        return Err(format!("{kind} needs a list and a target"));
    }
    let target = resolve_rule_target(importer, group_ids, parts[2])
        .ok_or_else(|| format!("target {} was not imported", parts[2]))?;
    let checkpoint = rule_sets.checkpoint();
    let id = rule_sets.reference(importer, group_ids, kind, parts[1], &parts[3..])?;
    let rewritten = format!("RULE-SET,{id},{target}");
    parse_rule_line(&rewritten)
        .map(|_| rewritten)
        .map_err(|error| {
            rule_sets.rollback(checkpoint);
            error.message
        })
}

/// `AND|OR|NOT,((TYPE,value),...),target[,no-resolve]`. Rule sets inside are
/// rewritten to ids like top-level ones.
fn import_logical_rule(
    importer: &Importer,
    group_ids: &BTreeSet<String>,
    rule_sets: &mut RuleSetCollector,
    kind: &str,
    line: &str,
) -> Result<String, String> {
    let shape = || format!("{kind} rule needs parenthesized rules and a target");
    let (_, rest) = line.split_once(',').ok_or_else(shape)?;
    let (body, after) = split_logical_body(rest).ok_or_else(shape)?;
    let after = after.trim_start().strip_prefix(',').ok_or_else(shape)?;
    let mut options = after.split(',').map(str::trim);
    let target_name = options
        .next()
        .filter(|target| !target.is_empty())
        .ok_or_else(shape)?;
    let target = resolve_rule_target(importer, group_ids, target_name)
        .ok_or_else(|| format!("target {target_name} was not imported"))?;
    let no_resolve = options.any(|option| option.eq_ignore_ascii_case("no-resolve"));

    let checkpoint = rule_sets.checkpoint();
    let body = match rewrite_rule_set_references(importer, group_ids, rule_sets, body) {
        Ok(body) => body,
        Err(reason) => {
            rule_sets.rollback(checkpoint);
            return Err(reason);
        }
    };
    let rewritten = format!("{kind},{body},{target}");
    // `no-resolve` is kept only where the rule has an IP part to apply it to.
    if no_resolve {
        let with_option = format!("{rewritten},no-resolve");
        if parse_rule_line(&with_option).is_ok() {
            return Ok(with_option);
        }
    }
    parse_rule_line(&rewritten)
        .map(|_| rewritten)
        .map_err(|error| {
            rule_sets.rollback(checkpoint);
            error.message
        })
}

/// Splits `(...)rest` after the parenthesis matching the first one, keeping
/// the parentheses in the body.
fn split_logical_body(text: &str) -> Option<(&str, &str)> {
    let text = text.trim_start();
    if !text.starts_with('(') {
        return None;
    }
    let mut depth = 0usize;
    for (index, character) in text.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some((&text[..=index], &text[index + 1..]));
                }
            }
            _ => {}
        }
    }
    None
}

/// Replaces `(RULE-SET,<list>` and `(DOMAIN-SET,<list>` inside a logical
/// rule with `(RULE-SET,<id>`.
fn rewrite_rule_set_references(
    importer: &Importer,
    group_ids: &BTreeSet<String>,
    rule_sets: &mut RuleSetCollector,
    body: &str,
) -> Result<String, String> {
    const PREFIXES: [&str; 2] = ["(RULE-SET,", "(DOMAIN-SET,"];
    let mut rewritten = String::with_capacity(body.len());
    let mut rest = body;
    loop {
        // ASCII uppercasing keeps byte offsets.
        let upper = rest.to_ascii_uppercase();
        let found = PREFIXES
            .iter()
            .filter_map(|prefix| upper.find(prefix).map(|start| (start, *prefix)))
            .min();
        let Some((start, prefix)) = found else {
            rewritten.push_str(rest);
            return Ok(rewritten);
        };
        let value_start = start + prefix.len();
        let value_end = rest[value_start..]
            .find([',', ')'])
            .map(|offset| value_start + offset)
            .ok_or_else(|| "logical rule needs balanced parentheses".to_string())?;
        let kind = &prefix[1..prefix.len() - 1];
        let id = rule_sets.reference(
            importer,
            group_ids,
            kind,
            &rest[value_start..value_end],
            &[],
        )?;
        rewritten.push_str(&rest[..start]);
        rewritten.push_str("(RULE-SET,");
        rewritten.push_str(&id);
        rest = &rest[value_end..];
    }
}

/// The rule sets referenced by imported rules, one per distinct list.
struct RuleSetCollector<'a> {
    providers: &'a BTreeMap<String, RuleProvider>,
    /// `RULE-SET:<url>`, `DOMAIN-SET:<url>`, or `provider:<name>` to id.
    ids: BTreeMap<String, String>,
    sets: Vec<ImportedRuleSet>,
}

impl<'a> RuleSetCollector<'a> {
    fn new(providers: &'a BTreeMap<String, RuleProvider>) -> Self {
        Self {
            providers,
            ids: BTreeMap::new(),
            sets: Vec::new(),
        }
    }

    fn checkpoint(&self) -> usize {
        self.sets.len()
    }

    /// Forgets the sets added after `checkpoint`, for a rule that was skipped
    /// after its sets were registered.
    fn rollback(&mut self, checkpoint: usize) {
        for set in self.sets.drain(checkpoint..) {
            self.ids.retain(|_, id| *id != set.id);
        }
    }

    /// The id of the set for `value`, a URL or a Clash provider name,
    /// registering it on first use. Errors never contain the URL, which can
    /// carry a subscription token.
    fn reference(
        &mut self,
        importer: &Importer,
        group_ids: &BTreeSet<String>,
        kind: &str,
        value: &str,
        options: &[&str],
    ) -> Result<String, String> {
        let value = strip_quotes(value.trim());
        let is_url = value.starts_with("https://") || value.starts_with("http://");
        let key = if is_url {
            format!("{kind}:{value}")
        } else {
            format!("provider:{value}")
        };
        if let Some(id) = self.ids.get(&key) {
            return Ok(id.clone());
        }
        let (hint, mut set) = if is_url {
            (url_hint(value), url_rule_set(kind, value, options)?)
        } else {
            let provider = self
                .providers
                .get(value)
                .ok_or_else(|| format!("rule set {value} is not a URL or a rule provider"))?;
            (
                value.to_string(),
                provider_rule_set(importer, group_ids, value, provider)?,
            )
        };
        if self.sets.len() >= MAX_IMPORTED_RULE_SETS {
            return Err(format!(
                "more than {MAX_IMPORTED_RULE_SETS} rule sets are referenced"
            ));
        }
        let id = self.unique_id(&hint);
        set.id = id.clone();
        self.ids.insert(key, id.clone());
        self.sets.push(set);
        Ok(id)
    }

    /// `hint` reduced to `[A-Za-z0-9._-]`, numbered when already taken.
    fn unique_id(&self, hint: &str) -> String {
        let mut base = String::new();
        for character in hint.chars() {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                base.push(character);
            } else if !base.ends_with('-') {
                base.push('-');
            }
        }
        base.truncate(MAX_RULE_SET_ID_LEN);
        let base = base.trim_matches(|c| c == '-' || c == '.');
        let base = if base.is_empty() { "rule-set" } else { base };
        let taken = |id: &str| self.sets.iter().any(|set| set.id == id);
        if !taken(base) {
            return base.to_string();
        }
        (2..)
            .map(|number| format!("{base}-{number}"))
            .find(|id| !taken(id))
            .expect("some numbered id is free")
    }
}

/// A set downloaded from a Surge/Loon `RULE-SET`/`DOMAIN-SET` URL.
fn url_rule_set(kind: &str, url: &str, options: &[&str]) -> Result<ImportedRuleSet, String> {
    if url.len() > MAX_RULE_SET_URL_LEN {
        return Err(format!("{kind} URL is too long"));
    }
    let interval_secs = options.iter().find_map(|option| {
        let (key, value) = option.split_once('=')?;
        if key.trim().eq_ignore_ascii_case("update-interval") {
            value.trim().parse::<u32>().ok()
        } else {
            None
        }
    });
    Ok(ImportedRuleSet {
        id: String::new(),
        url: url.to_string(),
        format: (kind == "DOMAIN-SET").then_some("domain"),
        interval_secs: interval_secs.map(|secs| secs.max(MIN_RULE_SET_INTERVAL_SECS)),
        via: None,
    })
}

/// A set from a Clash `rule-providers` entry.
fn provider_rule_set(
    importer: &Importer,
    group_ids: &BTreeSet<String>,
    name: &str,
    provider: &RuleProvider,
) -> Result<ImportedRuleSet, String> {
    if let Some(kind) = provider.kind.as_deref() {
        if !kind.eq_ignore_ascii_case("http") {
            return Err(format!("rule provider {name} type {kind} is unsupported"));
        }
    }
    if let Some(format) = provider.format.as_deref() {
        if !matches!(format.to_ascii_lowercase().as_str(), "yaml" | "text") {
            return Err(format!(
                "rule provider {name} format {format} is unsupported"
            ));
        }
    }
    let format = match provider.behavior.as_deref().map(str::to_ascii_lowercase) {
        Some(behavior) if behavior == "domain" => Some("domain"),
        None => None,
        Some(behavior) if behavior == "ipcidr" || behavior == "classical" => None,
        Some(behavior) => {
            return Err(format!(
                "rule provider {name} behavior {behavior} is unsupported"
            ))
        }
    };
    let url = provider
        .url
        .as_deref()
        .map(str::trim)
        .filter(|url| url.starts_with("https://") || url.starts_with("http://"))
        .ok_or_else(|| format!("rule provider {name} has no http or https url"))?;
    if url.len() > MAX_RULE_SET_URL_LEN {
        return Err(format!("rule provider {name} url is too long"));
    }
    let via = provider
        .proxy
        .as_deref()
        .and_then(|proxy| resolve_rule_target(importer, group_ids, proxy))
        .filter(|target| target != "REJECT");
    Ok(ImportedRuleSet {
        id: String::new(),
        url: url.to_string(),
        format,
        interval_secs: provider
            .interval
            .as_deref()
            .and_then(|interval| interval.trim().parse::<u32>().ok())
            .map(|secs| secs.max(MIN_RULE_SET_INTERVAL_SECS)),
        via,
    })
}

/// The last path segment of `url` without its extension, as an id hint.
fn url_hint(url: &str) -> String {
    let path = url.split(['?', '#']).next().unwrap_or_default();
    let segment = path
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or_default();
    let stem = segment.rsplit_once('.').map_or(segment, |(stem, _)| stem);
    stem.to_string()
}

fn resolve_rule_target(
    importer: &Importer,
    group_ids: &BTreeSet<String>,
    target: &str,
) -> Option<String> {
    let target = target.trim();
    if target.eq_ignore_ascii_case("DIRECT") {
        Some("DIRECT".to_string())
    } else if is_reject_policy(target) {
        Some("REJECT".to_string())
    } else if group_ids.contains(target) {
        Some(target.to_string())
    } else {
        importer
            .nodes_by_name
            .get(target)
            .map(|id| (*id).to_string())
    }
}
