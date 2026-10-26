//! Import of rules and policy groups from Surge/Loon profiles and Clash YAML.
//!
//! Subscription parsing keeps returning only nodes. This module reads the
//! same payload a second time for `[Proxy Group]`/`[Rule]` sections or Clash
//! `proxy-groups`/`rules`, maps proxy names to the parsed node ids, and builds
//! a [`RoutingModel`]. Rules, group members, and groups the model cannot
//! express are skipped with a warning. When the remaining input still fails
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

const SUPPORTED_RULE_TYPES: [&str; 8] = [
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "DST-PORT",
    "DEST-PORT",
];
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
    pub diagnostics: Vec<Diagnostic>,
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
            diagnostics: Vec::new(),
        };
    };
    build_routing(source, nodes)
}

#[derive(Debug, Default)]
struct RoutingSource {
    format: &'static str,
    rules: Vec<String>,
    groups: Vec<SourceGroup>,
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
        .any(|section| section == "rule" || section == "proxy group")
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
            "proxy group" => {
                if let Some(group) = parse_ini_group_line(line) {
                    source.groups.push(group);
                }
            }
            _ => {}
        }
    }
    (!source.rules.is_empty()).then_some(source)
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
    Some(RoutingSource {
        format: "clash",
        rules,
        groups,
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
    let rules = import_rules(&mut importer, source.rules, &group_ids);

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

        if !SUPPORTED_RULE_TYPES.contains(&kind.as_str()) {
            *skipped.entry(kind).or_default() += 1;
            continue;
        }
        if parts.len() < 3 {
            importer.warn(
                ROUTING_IMPORT_RULE_SKIPPED_CODE,
                format!("rule {index} was skipped: {kind} needs a value and a target"),
            );
            continue;
        }
        let Some(target) = resolve_rule_target(importer, group_ids, parts[2]) else {
            importer.warn(
                ROUTING_IMPORT_RULE_SKIPPED_CODE,
                format!(
                    "rule {index} was skipped: target {} was not imported",
                    parts[2]
                ),
            );
            continue;
        };
        let no_resolve = parts[3..]
            .iter()
            .any(|option| option.eq_ignore_ascii_case("no-resolve"))
            && (kind == "IP-CIDR" || kind == "IP-CIDR6" || kind == "GEOIP");
        let rewritten = format!(
            "{kind},{},{target}{}",
            parts[1],
            if no_resolve { ",no-resolve" } else { "" }
        );
        match parse_rule_line(&rewritten) {
            Ok(_) => imported.push(rewritten),
            Err(error) => importer.warn(
                ROUTING_IMPORT_RULE_SKIPPED_CODE,
                format!("rule {index} was skipped: {}", error.message),
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
