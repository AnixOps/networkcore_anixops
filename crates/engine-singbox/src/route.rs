//! Translation of the `config-core` routing model into a sing-box `route`.
//!
//! The fragment contains the policy group outbounds and the `route` object.
//! Callers add the node outbounds (tagged by node id) and a `direct` outbound,
//! as the local proxy renderers already do.

use config_core::routing::{PolicyGroupKind, PolicyTarget, RoutingModel, RuleMatcher};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub const SING_BOX_DIRECT_OUTBOUND_TAG: &str = "direct";
pub const SING_BOX_GEOIP_RULE_SET_URL_PREFIX: &str =
    "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/";
/// sing-box has no ordered fallback group. Fallback groups render as
/// `urltest` with the largest tolerance, so the chosen member only changes
/// when it fails its health check.
pub const SING_BOX_FALLBACK_URLTEST_TOLERANCE_MS: u16 = u16::MAX;

#[derive(Debug, Clone, PartialEq)]
pub struct SingBoxRouteFragment {
    /// One `selector` or `urltest` outbound per policy group, in model order.
    pub outbounds: Vec<Value>,
    pub route: Value,
}

impl SingBoxRouteFragment {
    pub fn to_value(&self) -> Value {
        json!({
            "outbounds": self.outbounds,
            "route": self.route,
        })
    }
}

/// Renders rules, FINAL, and policy groups. Rules keep model order one to one;
/// the first IP rule without `no-resolve` is preceded by a `resolve` action.
pub fn render_sing_box_route(model: &RoutingModel) -> SingBoxRouteFragment {
    let mut rules = Vec::with_capacity(model.rules.len() + 2);
    let mut rule_sets = Vec::new();
    let mut rule_set_tags = BTreeSet::new();
    let mut resolve_rendered = false;

    for rule in &model.rules {
        if rule.matcher.matches_ip() && !rule.no_resolve && !resolve_rendered {
            rules.push(json!({ "action": "resolve" }));
            resolve_rendered = true;
        }
        let mut rendered = match &rule.matcher {
            RuleMatcher::Domain(domain) => json!({ "domain": [domain] }),
            RuleMatcher::DomainSuffix(suffix) => json!({ "domain_suffix": [suffix] }),
            RuleMatcher::DomainKeyword(keyword) => json!({ "domain_keyword": [keyword] }),
            RuleMatcher::IpCidr(cidr) => json!({ "ip_cidr": [cidr.to_string()] }),
            RuleMatcher::GeoIp(country) => {
                let tag = format!("geoip-{}", country.to_ascii_lowercase());
                if rule_set_tags.insert(tag.clone()) {
                    rule_sets.push(json!({
                        "type": "remote",
                        "tag": tag,
                        "format": "binary",
                        "url": format!("{SING_BOX_GEOIP_RULE_SET_URL_PREFIX}{tag}.srs"),
                        "download_detour": SING_BOX_DIRECT_OUTBOUND_TAG,
                    }));
                }
                json!({ "rule_set": [tag] })
            }
            // The caller defines the rule set under the same tag.
            RuleMatcher::RuleSet(name) => json!({ "rule_set": [name] }),
        };
        apply_rule_target(&mut rendered, &rule.target);
        rules.push(rendered);
    }

    let route_final = match &model.final_target {
        PolicyTarget::Reject => {
            rules.push(json!({ "action": "reject" }));
            SING_BOX_DIRECT_OUTBOUND_TAG
        }
        target => target_tag(target),
    };

    let mut route = json!({
        "rules": rules,
        "final": route_final,
    });
    if !rule_sets.is_empty() {
        route["rule_set"] = Value::Array(rule_sets);
    }

    let outbounds = model
        .groups
        .iter()
        .map(|group| {
            let members = group.members.iter().map(target_tag).collect::<Vec<_>>();
            let mut outbound = match group.kind {
                PolicyGroupKind::Select => json!({
                    "type": "selector",
                    "tag": group.id,
                    "outbounds": members,
                }),
                PolicyGroupKind::UrlTest | PolicyGroupKind::Fallback => {
                    let health_check = group
                        .health_check
                        .as_ref()
                        .expect("validated url-test and fallback groups have a health check");
                    let tolerance = if group.kind == PolicyGroupKind::Fallback {
                        SING_BOX_FALLBACK_URLTEST_TOLERANCE_MS
                    } else {
                        health_check.tolerance_ms
                    };
                    json!({
                        "type": "urltest",
                        "tag": group.id,
                        "outbounds": members,
                        "url": health_check.url,
                        "interval": format!("{}s", health_check.interval_secs),
                        "tolerance": tolerance,
                    })
                }
            };
            if let Some(default) = &group.default {
                outbound["default"] = Value::String(target_tag(default).to_string());
            }
            outbound["interrupt_exist_connections"] = Value::Bool(false);
            outbound
        })
        .collect();

    SingBoxRouteFragment { outbounds, route }
}

fn apply_rule_target(rule: &mut Value, target: &PolicyTarget) {
    if *target == PolicyTarget::Reject {
        rule["action"] = Value::String("reject".to_string());
    } else {
        rule["action"] = Value::String("route".to_string());
        rule["outbound"] = Value::String(target_tag(target).to_string());
    }
}

fn target_tag(target: &PolicyTarget) -> &str {
    match target {
        PolicyTarget::Direct | PolicyTarget::Reject => SING_BOX_DIRECT_OUTBOUND_TAG,
        PolicyTarget::Node(id) | PolicyTarget::Group(id) => id,
    }
}
