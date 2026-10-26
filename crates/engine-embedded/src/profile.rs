//! Desktop routing over an imported profile: the envelope an import produced
//! (one outbound, or every node with the subscription's rules and policy
//! groups) turned into the envelope for a routing mode, and the policy group
//! choices a client shows and switches. Pure JSON work, no files or network:
//! clients download and cache the public rule lists themselves.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::RuntimeConfig;

/// The routed outbound a single-node profile gets when a mode adds rules.
pub const PROXY_OUTBOUND: &str = "proxy";

/// How traffic is split, as the desktop clients name the modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    /// Mainland China sites direct, everything else through the proxy.
    BypassChina,
    /// Only sites on the GFW list through the proxy.
    GfwList,
    /// Mainland China sites through the proxy, everything else direct.
    ReturnChina,
    /// Everything direct.
    Direct,
    /// The subscription's own rules and policy groups; a single-node profile
    /// sends everything through its node.
    #[default]
    Rule,
}

impl RoutingMode {
    pub fn as_str(self) -> &'static str {
        match self {
            RoutingMode::BypassChina => "bypass_china",
            RoutingMode::GfwList => "gfw_list",
            RoutingMode::ReturnChina => "return_china",
            RoutingMode::Direct => "direct",
            RoutingMode::Rule => "rule",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        [
            RoutingMode::BypassChina,
            RoutingMode::GfwList,
            RoutingMode::ReturnChina,
            RoutingMode::Direct,
            RoutingMode::Rule,
        ]
        .into_iter()
        .find(|mode| mode.as_str() == value)
    }

    /// The public lists this mode's rules are built from.
    pub fn rule_lists(self) -> &'static [RuleList] {
        match self {
            RoutingMode::BypassChina | RoutingMode::ReturnChina => {
                &[RuleList::ChinaDomains, RuleList::ChinaIps]
            }
            RoutingMode::GfwList => &[RuleList::GfwDomains],
            RoutingMode::Direct | RoutingMode::Rule => &[],
        }
    }
}

/// A public domain or network list the routing modes use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleList {
    ChinaDomains,
    ChinaIps,
    GfwDomains,
}

impl RuleList {
    pub fn url(self) -> &'static str {
        match self {
            RuleList::ChinaDomains => {
                "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/china-list.txt"
            }
            RuleList::ChinaIps => {
                "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt"
            }
            RuleList::GfwDomains => {
                "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt"
            }
        }
    }

    /// The cache file name a client keeps the parsed entries under.
    pub fn file_name(self) -> &'static str {
        match self {
            RuleList::ChinaDomains => "china-domains.txt",
            RuleList::ChinaIps => "china-ips.txt",
            RuleList::GfwDomains => "gfw-domains.txt",
        }
    }

    pub fn is_networks(self) -> bool {
        self == RuleList::ChinaIps
    }

    /// The entries of a downloaded list: one domain suffix or network per
    /// line, comments and anything else skipped.
    pub fn parse(self, content: &str) -> Vec<String> {
        content
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .filter_map(|line| line.split_whitespace().next())
            .filter(|entry| {
                if self.is_networks() {
                    entry.parse::<std::net::IpAddr>().is_ok() || entry.contains('/')
                } else {
                    entry.contains('.') && !entry.contains('/')
                }
            })
            .map(str::to_string)
            .collect()
    }
}

/// The envelope `profile` runs with in `mode`. The rule modes replace the
/// profile's rules with the lists' (`list` returns a list's entries) and send
/// the proxied part to the profile's FINAL target, or to its one outbound.
pub fn envelope_for_mode(
    profile: &str,
    mode: RoutingMode,
    list: impl Fn(RuleList) -> Result<Vec<String>, String>,
) -> Result<String, String> {
    if mode == RoutingMode::Rule {
        validate(profile)?;
        return Ok(profile.to_string());
    }
    let mut envelope: Value = serde_json::from_str(profile).map_err(|error| error.to_string())?;
    let object = envelope
        .as_object_mut()
        .ok_or("the profile must be a JSON object")?;
    let (mut routing, proxy) = match (object.remove("outbound"), object.remove("routing")) {
        (Some(outbound), None) => (
            json!({ "outbounds": { PROXY_OUTBOUND: outbound } }),
            PROXY_OUTBOUND.to_string(),
        ),
        (None, Some(routing)) => {
            let proxy = final_target(&routing).ok_or("the profile's rules must end with FINAL")?;
            (routing, proxy)
        }
        _ => return Err("the profile must carry one outbound or routing".to_string()),
    };
    let (rules, rule_sets) = match mode {
        RoutingMode::BypassChina | RoutingMode::ReturnChina => {
            let (china, rest) = if mode == RoutingMode::BypassChina {
                ("DIRECT".to_string(), proxy)
            } else {
                (proxy, "DIRECT".to_string())
            };
            (
                vec![format!("RULE-SET,china,{china}"), format!("FINAL,{rest}")],
                json!({ "china": {
                    "domain_suffix": list(RuleList::ChinaDomains)?,
                    "ip_cidr": list(RuleList::ChinaIps)?,
                } }),
            )
        }
        RoutingMode::GfwList => (
            vec![format!("RULE-SET,gfw,{proxy}"), "FINAL,DIRECT".to_string()],
            json!({ "gfw": { "domain_suffix": list(RuleList::GfwDomains)?, "ip_cidr": [] } }),
        ),
        RoutingMode::Direct => (vec!["FINAL,DIRECT".to_string()], json!({})),
        RoutingMode::Rule => unreachable!("rule mode returns the profile above"),
    };
    let routing_object = routing
        .as_object_mut()
        .ok_or("the profile's routing must be a JSON object")?;
    routing_object.insert("rules".to_string(), json!(rules));
    routing_object.insert("rule_sets".to_string(), rule_sets);
    object.insert("routing".to_string(), routing);
    let rendered = envelope.to_string();
    validate(&rendered)?;
    Ok(rendered)
}

fn validate(envelope: &str) -> Result<(), String> {
    RuntimeConfig::from_json(envelope.as_bytes())
        .map(|_| ())
        .map_err(|error| format!("the engine rejected the profile: {}", error.message))
}

/// A policy group as a client lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupView {
    pub id: String,
    /// `select`, `url-test` or `fallback`.
    pub kind: String,
    pub members: Vec<String>,
    /// What the group routes to before any health check: a select group's
    /// default, otherwise its first member.
    pub choice: Option<String>,
}

/// The routed profile's policy groups; none for a single-node profile.
pub fn groups(profile: &Value) -> Vec<GroupView> {
    raw_groups(profile)
        .iter()
        .filter_map(|group| {
            Some(GroupView {
                id: group.get("id")?.as_str()?.to_string(),
                kind: group.get("type")?.as_str()?.to_string(),
                members: members(group),
                choice: choice(group),
            })
        })
        .collect()
}

/// Makes `member` the default of the select group `group_id`.
pub fn set_group_default(profile: &mut Value, group_id: &str, member: &str) -> Result<(), String> {
    let group = profile
        .pointer_mut("/routing/groups")
        .and_then(Value::as_array_mut)
        .and_then(|groups| {
            groups
                .iter_mut()
                .find(|group| group.get("id").and_then(Value::as_str) == Some(group_id))
        })
        .ok_or_else(|| format!("policy group {group_id} is not in the profile"))?;
    if group.get("type").and_then(Value::as_str) != Some("select") {
        return Err(format!(
            "policy group {group_id} chooses by itself; only select groups can be switched"
        ));
    }
    if !members(group).iter().any(|candidate| candidate == member) {
        return Err(format!(
            "{member} is not a member of policy group {group_id}"
        ));
    }
    group
        .as_object_mut()
        .ok_or("a policy group must be a JSON object")?
        .insert("default".to_string(), Value::String(member.to_string()));
    Ok(())
}

/// The node FINAL ends at, following each group's choice, if it ends at a node.
pub fn selected_node(profile: &Value) -> Option<String> {
    let (_, target) = final_chain(profile);
    target.filter(|id| {
        profile
            .pointer("/routing/outbounds")
            .and_then(Value::as_object)
            .is_some_and(|outbounds| outbounds.contains_key(id))
    })
}

/// The first select group on FINAL's route with `node_id` as a member: the
/// group a node switch changes.
pub fn switch_group_for_node(profile: &Value, node_id: &str) -> Option<String> {
    let (chain, _) = final_chain(profile);
    chain.into_iter().find(|id| {
        group(profile, id).is_some_and(|group| {
            group.get("type").and_then(Value::as_str) == Some("select")
                && members(group).iter().any(|member| member == node_id)
        })
    })
}

fn raw_groups(profile: &Value) -> &[Value] {
    profile
        .pointer("/routing/groups")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn group<'a>(profile: &'a Value, id: &str) -> Option<&'a Value> {
    raw_groups(profile)
        .iter()
        .find(|group| group.get("id").and_then(Value::as_str) == Some(id))
}

fn members(group: &Value) -> Vec<String> {
    group
        .get("members")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn choice(group: &Value) -> Option<String> {
    let members = members(group);
    group
        .get("default")
        .and_then(Value::as_str)
        .filter(|_| group.get("type").and_then(Value::as_str) == Some("select"))
        .filter(|default| members.iter().any(|member| member == default))
        .map(str::to_string)
        .or_else(|| members.into_iter().next())
}

fn final_target(routing: &Value) -> Option<String> {
    routing
        .get("rules")
        .and_then(Value::as_array)
        .and_then(|rules| rules.last())
        .and_then(Value::as_str)
        .and_then(|rule| rule.strip_prefix("FINAL,"))
        .map(|target| target.trim().to_string())
}

/// The groups FINAL passes through and the target it ends at.
fn final_chain(profile: &Value) -> (Vec<String>, Option<String>) {
    let mut target = profile.get("routing").and_then(final_target);
    let mut chain = Vec::new();
    while let Some(id) = target.clone() {
        if chain.contains(&id) {
            break;
        }
        let Some(group) = group(profile, &id) else {
            break;
        };
        chain.push(id);
        target = choice(group);
    }
    (chain, target)
}
