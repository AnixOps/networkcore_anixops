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

const SUPPORTED_RULE_TYPES: [&str; 6] = [
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
];
const HEALTH_CHECK_OPTIONS: [&str; 3] = ["url", "interval", "tolerance"];

/// Routing found in a subscription payload, with import diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedRouting {
    /// `None` when the payload has no rules or the imported rules are invalid.
    pub routing: Option<RoutingModel>,
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
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawScalar {
    Text(String),
    Integer(i64),
}

impl RawScalar {
    fn into_text(self) -> String {
        match self {
            Self::Text(value) => value,
            Self::Integer(value) => value.to_string(),
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
}

fn group_kind(kind: &str) -> Option<GroupKind> {
    match kind.trim().to_ascii_lowercase().as_str() {
        "select" => Some(GroupKind::Select),
        "url-test" => Some(GroupKind::UrlTest),
        "fallback" => Some(GroupKind::Fallback),
        _ => None,
    }
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

    let groups = import_groups(&mut importer, source.groups);
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
        match group_kind(&group.kind) {
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
            .filter(|key| {
                kind == GroupKind::Select || !HEALTH_CHECK_OPTIONS.contains(&key.as_str())
            })
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
            kind: match kind {
                GroupKind::Select => "select",
                GroupKind::UrlTest => "url-test",
                GroupKind::Fallback => "fallback",
            }
            .to_string(),
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
