use config_core::parse_config_document;
use config_core::routing::{
    parse_rule_line, IpCidr, PolicyGroupKind, PolicyGroupSpec, PolicyTarget, RouteMatch,
    RouteOutcome, RouteQuery, RouteResolution, RoutingEnvironment, RoutingModel, RoutingSpec,
    RuleLine, RuleMatcher, StaticRoutingEnvironment, ROUTING_FINAL_MISSING_CODE,
    ROUTING_FINAL_NOT_LAST_CODE, ROUTING_GROUP_CYCLE_CODE, ROUTING_GROUP_DEFAULT_INVALID_CODE,
    ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE, ROUTING_GROUP_ID_CONFLICT_CODE,
    ROUTING_GROUP_ID_INVALID_CODE, ROUTING_GROUP_MEMBERS_EMPTY_CODE,
    ROUTING_GROUP_MEMBER_UNSUPPORTED_CODE, ROUTING_GROUP_TYPE_UNSUPPORTED_CODE,
    ROUTING_RULE_LINE_INVALID_CODE, ROUTING_RULE_OPTION_UNSUPPORTED_CODE,
    ROUTING_RULE_TYPE_UNSUPPORTED_CODE, ROUTING_RULE_VALUE_INVALID_CODE,
    ROUTING_TARGET_UNKNOWN_CODE,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

const SNAPSHOT_CONFIG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/routing-snapshot/config.toml"
));
const SNAPSHOT_DECISIONS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/routing-snapshot/decisions.json"
));

#[derive(Default)]
struct FixtureEnvironment {
    geoip: BTreeMap<IpAddr, String>,
    dns: BTreeMap<String, IpAddr>,
    selected: BTreeMap<String, String>,
    latency_ms: BTreeMap<(String, String), u32>,
}

impl RoutingEnvironment for FixtureEnvironment {
    fn geoip_country(&self, ip: IpAddr) -> Option<String> {
        self.geoip.get(&ip).cloned()
    }

    fn resolve(&self, domain: &str) -> Option<IpAddr> {
        self.dns.get(domain).copied()
    }

    fn selected_member(&self, group_id: &str) -> Option<String> {
        self.selected.get(group_id).cloned()
    }

    fn member_latency_ms(&self, group_id: &str, member: &PolicyTarget) -> Option<u32> {
        self.latency_ms
            .get(&(group_id.to_string(), member.name().to_string()))
            .copied()
    }
}

fn fixture_environments(snapshot: &Value) -> (FixtureEnvironment, FixtureEnvironment) {
    let environment = &snapshot["environment"];
    let string_map = |value: &Value| {
        value
            .as_object()
            .unwrap()
            .iter()
            .map(|(key, value)| (key.clone(), value.as_str().unwrap().to_string()))
            .collect::<BTreeMap<_, _>>()
    };
    let geoip = string_map(&environment["geoip"])
        .into_iter()
        .map(|(ip, country)| (ip.parse::<IpAddr>().unwrap(), country))
        .collect::<BTreeMap<_, _>>();
    let dns = string_map(&environment["dns"])
        .into_iter()
        .map(|(domain, ip)| (domain, ip.parse::<IpAddr>().unwrap()))
        .collect::<BTreeMap<_, _>>();
    let mut latency_ms = BTreeMap::new();
    for (group, members) in environment["live_latency_ms"].as_object().unwrap() {
        for (member, latency) in members.as_object().unwrap() {
            latency_ms.insert(
                (group.clone(), member.clone()),
                latency.as_u64().unwrap() as u32,
            );
        }
    }

    let static_environment = FixtureEnvironment {
        geoip: geoip.clone(),
        dns: dns.clone(),
        ..FixtureEnvironment::default()
    };
    let live_environment = FixtureEnvironment {
        geoip,
        dns,
        selected: string_map(&environment["live_selected"]),
        latency_ms,
    };
    (static_environment, live_environment)
}

fn resolution_snapshot(resolution: &RouteResolution) -> Value {
    serde_json::json!({
        "matched": match resolution.matched {
            RouteMatch::Rule(index) => format!("rule:{index}"),
            RouteMatch::ResolveFailed(index) => format!("resolve_failed:{index}"),
            RouteMatch::Final => "final".to_string(),
        },
        "target": resolution.target.name(),
        "group_path": resolution.group_path,
        "outcome": match &resolution.outcome {
            RouteOutcome::Direct => "direct".to_string(),
            RouteOutcome::Reject => "reject".to_string(),
            RouteOutcome::Node(id) => format!("node:{id}"),
        },
        "resolved_ip": resolution.resolved_ip.map(|ip| ip.to_string()),
    })
}

fn snapshot_model() -> RoutingModel {
    parse_config_document(SNAPSHOT_CONFIG)
        .unwrap()
        .routing
        .expect("snapshot config defines routing")
}

#[test]
fn routing_snapshot_decisions_match_fixture() {
    let model = snapshot_model();
    let snapshot = serde_json::from_str::<Value>(SNAPSHOT_DECISIONS).unwrap();
    let (static_environment, live_environment) = fixture_environments(&snapshot);

    for case in snapshot["cases"].as_array().unwrap() {
        let query = RouteQuery {
            domain: case["domain"].as_str().map(str::to_string),
            ip: case["ip"].as_str().map(|ip| ip.parse::<IpAddr>().unwrap()),
            ..RouteQuery::default()
        };
        let environment: &dyn RoutingEnvironment = if case["live"].as_bool().unwrap_or(false) {
            &live_environment
        } else {
            &static_environment
        };
        let actual = resolution_snapshot(&model.decide(&query, environment));
        assert_eq!(
            actual, case["expected"],
            "routing snapshot case {}",
            case["name"]
        );
    }
}

#[test]
fn routing_snapshot_config_normalizes_rules_and_groups() {
    let model = snapshot_model();

    assert_eq!(model.rules.len(), 9);
    assert_eq!(
        model.rules[4].matcher,
        RuleMatcher::DomainKeyword("tracker".to_string())
    );
    assert_eq!(
        model.rules[2].matcher,
        RuleMatcher::DomainSuffix("netflix.com".to_string())
    );
    assert_eq!(
        model.rules[5].matcher,
        RuleMatcher::Domain("router.lan".to_string())
    );
    assert!(model.rules[6].no_resolve);
    assert_eq!(
        model.rules[7].matcher,
        RuleMatcher::IpCidr(IpCidr::parse("2001:db8::/32").unwrap())
    );
    assert_eq!(model.rules[8].matcher, RuleMatcher::GeoIp("CN".to_string()));
    assert_eq!(model.final_target, PolicyTarget::Group("Proxy".to_string()));

    let proxy = model.group("Proxy").unwrap();
    assert_eq!(proxy.kind, PolicyGroupKind::Select);
    assert_eq!(
        proxy.members,
        vec![
            PolicyTarget::Group("Auto".to_string()),
            PolicyTarget::Node("hk-1".to_string()),
            PolicyTarget::Node("jp-1".to_string()),
            PolicyTarget::Direct,
        ]
    );
    assert_eq!(proxy.default, Some(PolicyTarget::Group("Auto".to_string())));
    assert!(proxy.health_check.is_none());

    let auto = model.group("Auto").unwrap().health_check.as_ref().unwrap();
    assert_eq!(auto.url, "https://www.gstatic.com/generate_204");
    assert_eq!(auto.interval_secs, 600);
    assert_eq!(auto.tolerance_ms, 80);

    let streaming = model.group("Streaming").unwrap();
    assert_eq!(streaming.kind, PolicyGroupKind::Fallback);
    assert_eq!(
        streaming.health_check.as_ref().unwrap().url,
        "https://cp.cloudflare.com/generate_204"
    );
}

#[test]
fn config_without_rules_has_no_routing_model() {
    let document = parse_config_document(
        r#"
profile = "default"
"#,
    )
    .unwrap();

    assert!(document.routing.is_none());
}

#[test]
fn parses_rule_lines() {
    assert_eq!(
        parse_rule_line(" domain-suffix , Example.COM , Proxy ").unwrap(),
        RuleLine::Rule {
            matcher: RuleMatcher::DomainSuffix("example.com".to_string()),
            target: "Proxy".to_string(),
            no_resolve: false,
        }
    );
    assert_eq!(
        parse_rule_line("IP-CIDR,10.1.2.3/8,DIRECT,no-resolve").unwrap(),
        RuleLine::Rule {
            matcher: RuleMatcher::IpCidr(IpCidr::parse("10.0.0.0/8").unwrap()),
            target: "DIRECT".to_string(),
            no_resolve: true,
        }
    );
    assert_eq!(
        parse_rule_line("FINAL,Proxy").unwrap(),
        RuleLine::Final {
            target: "Proxy".to_string()
        }
    );

    for (line, code) in [
        ("DOMAIN,example.com", ROUTING_RULE_LINE_INVALID_CODE),
        ("FINAL", ROUTING_RULE_LINE_INVALID_CODE),
        ("FINAL,Proxy,extra", ROUTING_RULE_LINE_INVALID_CODE),
        (
            "USER-AGENT,curl*,DIRECT",
            ROUTING_RULE_TYPE_UNSUPPORTED_CODE,
        ),
        (
            "DOMAIN,exa mple.com,DIRECT",
            ROUTING_RULE_VALUE_INVALID_CODE,
        ),
        (
            "DOMAIN,example..com,DIRECT",
            ROUTING_RULE_VALUE_INVALID_CODE,
        ),
        ("IP-CIDR,10.0.0.0,DIRECT", ROUTING_RULE_VALUE_INVALID_CODE),
        (
            "IP-CIDR,10.0.0.0/33,DIRECT",
            ROUTING_RULE_VALUE_INVALID_CODE,
        ),
        ("GEOIP,CHN,DIRECT", ROUTING_RULE_VALUE_INVALID_CODE),
        (
            "DOMAIN,example.com,DIRECT,no-resolve",
            ROUTING_RULE_OPTION_UNSUPPORTED_CODE,
        ),
        (
            "IP-CIDR,10.0.0.0/8,DIRECT,force-remote-dns",
            ROUTING_RULE_OPTION_UNSUPPORTED_CODE,
        ),
    ] {
        assert_eq!(parse_rule_line(line).unwrap_err().code, code, "{line}");
    }
}

#[test]
fn ip_cidr_matches_by_family_and_prefix() {
    let v4 = IpCidr::parse("172.16.5.4/12").unwrap();
    assert_eq!(v4.to_string(), "172.16.0.0/12");
    assert!(v4.contains("172.31.255.255".parse().unwrap()));
    assert!(!v4.contains("172.32.0.1".parse().unwrap()));
    assert!(!v4.contains("::ffff:172.16.0.1".parse().unwrap()));

    let everything = IpCidr::parse("0.0.0.0/0").unwrap();
    assert!(everything.contains("203.0.113.9".parse().unwrap()));

    let host = IpCidr::parse("2001:db8::1/128").unwrap();
    assert!(host.contains("2001:db8::1".parse().unwrap()));
    assert!(!host.contains("2001:db8::2".parse().unwrap()));
}

fn node_ids() -> BTreeSet<String> {
    ["hk-1", "jp-1"].into_iter().map(str::to_string).collect()
}

fn group(id: &str, kind: &str, members: &[&str]) -> PolicyGroupSpec {
    PolicyGroupSpec {
        id: id.to_string(),
        kind: kind.to_string(),
        members: members.iter().map(|member| member.to_string()).collect(),
        default: None,
        url: None,
        interval_secs: None,
        tolerance_ms: None,
    }
}

fn spec(rules: &[&str], groups: Vec<PolicyGroupSpec>) -> RoutingSpec {
    RoutingSpec {
        rules: rules.iter().map(|rule| rule.to_string()).collect(),
        groups,
    }
}

fn model_error(spec: &RoutingSpec) -> String {
    RoutingModel::from_spec(spec, &node_ids()).unwrap_err().code
}

#[test]
fn rejects_invalid_rule_structure() {
    assert_eq!(
        model_error(&spec(&["DOMAIN,example.com,DIRECT"], vec![])),
        ROUTING_FINAL_MISSING_CODE
    );
    assert_eq!(
        model_error(&spec(
            &["FINAL,DIRECT", "DOMAIN,example.com,DIRECT"],
            vec![]
        )),
        ROUTING_FINAL_NOT_LAST_CODE
    );
    assert_eq!(
        model_error(&spec(
            &["DOMAIN,example.com,Missing", "FINAL,DIRECT"],
            vec![]
        )),
        ROUTING_TARGET_UNKNOWN_CODE
    );

    let error = RoutingModel::from_spec(
        &spec(&["FINAL,DIRECT", "GEOIP,XX1,DIRECT"], vec![]),
        &node_ids(),
    )
    .unwrap_err();
    assert_eq!(error.code, ROUTING_FINAL_NOT_LAST_CODE);
    assert!(error.message.starts_with("routing rule 1"));
}

#[test]
fn final_reject_and_reserved_names_are_case_insensitive() {
    let model = RoutingModel::from_spec(
        &spec(&["DOMAIN,example.com,direct", "FINAL,reject"], vec![]),
        &node_ids(),
    )
    .unwrap();

    assert_eq!(model.rules[0].target, PolicyTarget::Direct);
    assert_eq!(model.final_target, PolicyTarget::Reject);
    let resolution = model.decide(&RouteQuery::domain("other.test"), &StaticRoutingEnvironment);
    assert_eq!(resolution.matched, RouteMatch::Final);
    assert_eq!(resolution.outcome, RouteOutcome::Reject);
}

#[test]
fn rejects_invalid_policy_groups() {
    let final_only = ["FINAL,DIRECT"];
    let cases = vec![
        (
            group("", "select", &["hk-1"]),
            ROUTING_GROUP_ID_INVALID_CODE,
        ),
        (
            group("direct", "select", &["hk-1"]),
            ROUTING_GROUP_ID_INVALID_CODE,
        ),
        (
            group("hk-1", "select", &["jp-1"]),
            ROUTING_GROUP_ID_CONFLICT_CODE,
        ),
        (
            group("Proxy", "relay", &["hk-1"]),
            ROUTING_GROUP_TYPE_UNSUPPORTED_CODE,
        ),
        (
            group("Proxy", "select", &[]),
            ROUTING_GROUP_MEMBERS_EMPTY_CODE,
        ),
        (
            group("Proxy", "select", &["REJECT"]),
            ROUTING_GROUP_MEMBER_UNSUPPORTED_CODE,
        ),
        (
            group("Proxy", "select", &["missing"]),
            ROUTING_TARGET_UNKNOWN_CODE,
        ),
        (
            PolicyGroupSpec {
                default: Some("jp-1".to_string()),
                ..group("Proxy", "select", &["hk-1"])
            },
            ROUTING_GROUP_DEFAULT_INVALID_CODE,
        ),
        (
            PolicyGroupSpec {
                default: Some("hk-1".to_string()),
                ..group("Auto", "url-test", &["hk-1"])
            },
            ROUTING_GROUP_DEFAULT_INVALID_CODE,
        ),
        (
            PolicyGroupSpec {
                url: Some("https://example.com/".to_string()),
                ..group("Proxy", "select", &["hk-1"])
            },
            ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE,
        ),
        (
            PolicyGroupSpec {
                url: Some("ftp://example.com/".to_string()),
                ..group("Auto", "url-test", &["hk-1"])
            },
            ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE,
        ),
        (
            PolicyGroupSpec {
                interval_secs: Some(0),
                ..group("Auto", "url-test", &["hk-1"])
            },
            ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE,
        ),
        (
            PolicyGroupSpec {
                tolerance_ms: Some(10),
                ..group("Backup", "fallback", &["hk-1"])
            },
            ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE,
        ),
    ];
    for (group_spec, code) in cases {
        let id = group_spec.id.clone();
        assert_eq!(
            model_error(&spec(&final_only, vec![group_spec])),
            code,
            "group {id}"
        );
    }

    assert_eq!(
        model_error(&spec(
            &final_only,
            vec![
                group("Proxy", "select", &["hk-1"]),
                group("Proxy", "select", &["jp-1"]),
            ]
        )),
        ROUTING_GROUP_ID_CONFLICT_CODE
    );
    assert_eq!(
        model_error(&spec(
            &final_only,
            vec![
                group("Proxy", "select", &["hk-1"]),
                group("Auto", "url-test", &["Proxy"]),
            ]
        )),
        ROUTING_GROUP_MEMBER_UNSUPPORTED_CODE
    );
    assert_eq!(
        model_error(&spec(
            &final_only,
            vec![
                group("A", "select", &["B"]),
                group("B", "select", &["C", "hk-1"]),
                group("C", "select", &["A"]),
            ]
        )),
        ROUTING_GROUP_CYCLE_CODE
    );
}

#[test]
fn nested_select_groups_resolve_to_a_node_and_skip_unknown_selection() {
    struct Selection;
    impl RoutingEnvironment for Selection {
        fn selected_member(&self, group_id: &str) -> Option<String> {
            match group_id {
                "Outer" => Some("Inner".to_string()),
                "Inner" => Some("not-a-member".to_string()),
                _ => None,
            }
        }
    }

    let model = RoutingModel::from_spec(
        &spec(
            &["FINAL,Outer"],
            vec![
                group("Outer", "select", &["hk-1", "Inner"]),
                PolicyGroupSpec {
                    default: Some("jp-1".to_string()),
                    ..group("Inner", "select", &["hk-1", "jp-1", "jp-1"])
                },
            ],
        ),
        &node_ids(),
    )
    .unwrap();

    assert_eq!(model.group("Inner").unwrap().members.len(), 2);
    let resolution = model.decide(&RouteQuery::default(), &Selection);
    assert_eq!(resolution.group_path, vec!["Outer", "Inner"]);
    assert_eq!(resolution.outcome, RouteOutcome::Node("jp-1".to_string()));
}

#[test]
fn ip_rules_resolve_once_and_no_resolve_rules_skip_domains() {
    struct Dns;
    impl RoutingEnvironment for Dns {
        fn resolve(&self, domain: &str) -> Option<IpAddr> {
            (domain == "intranet.test").then(|| "10.1.1.1".parse().unwrap())
        }
    }

    let model = RoutingModel::from_spec(
        &spec(
            &[
                "IP-CIDR,10.0.0.0/8,REJECT,no-resolve",
                "IP-CIDR,10.0.0.0/8,hk-1",
                "FINAL,DIRECT",
            ],
            vec![],
        ),
        &node_ids(),
    )
    .unwrap();

    let resolution = model.decide(&RouteQuery::domain("intranet.test"), &Dns);
    assert_eq!(resolution.matched, RouteMatch::Rule(1));
    assert_eq!(resolution.outcome, RouteOutcome::Node("hk-1".to_string()));
    assert_eq!(
        resolution.resolved_ip,
        Some("10.1.1.1".parse::<IpAddr>().unwrap())
    );

    let direct_ip = model.decide(
        &RouteQuery::ip("10.2.2.2".parse().unwrap()),
        &StaticRoutingEnvironment,
    );
    assert_eq!(direct_ip.matched, RouteMatch::Rule(0));
    assert_eq!(direct_ip.outcome, RouteOutcome::Reject);
}

#[test]
fn routing_toml_rejects_unknown_group_fields() {
    let error = parse_config_document(
        r#"
profile = "default"
rules = ["FINAL,DIRECT"]

[[policy_groups]]
id = "Proxy"
type = "select"
members = ["DIRECT"]
strategy = "round-robin"
"#,
    )
    .unwrap_err();

    assert_eq!(error.code, config_core::CONFIG_PARSE_FAILED_CODE);
}

/// Answers GeoSite lookups from a fixed table and a fixed address.
struct GeoEnvironment;

impl RoutingEnvironment for GeoEnvironment {
    fn geosite_matches(&self, category: &str, domain: &str) -> bool {
        category == "google" && (domain == "google.com" || domain.ends_with(".google.com"))
    }

    fn resolve(&self, _domain: &str) -> Option<IpAddr> {
        Some("203.0.113.9".parse().unwrap())
    }
}

#[test]
fn port_process_geosite_and_logical_rules_route() {
    let spec = RoutingSpec {
        rules: vec![
            "AND,((DOMAIN-SUFFIX,example.com),(DST-PORT,443)),hk".to_string(),
            "OR,((DOMAIN-KEYWORD,ads),(NOT,((DST-PORT,1-1024)))),REJECT".to_string(),
            "GEOSITE,Google,hk".to_string(),
            "PROCESS-NAME,Telegram.exe,hk".to_string(),
            "DEST-PORT,53,DIRECT".to_string(),
            "AND,((IP-CIDR,203.0.113.0/24),(DST-PORT,80)),hk,no-resolve".to_string(),
            "FINAL,DIRECT".to_string(),
        ],
        groups: Vec::new(),
    };
    let model = RoutingModel::from_spec(&spec, &BTreeSet::from(["hk".to_string()])).unwrap();
    let route = |query: RouteQuery| model.decide(&query, &GeoEnvironment);
    let hk = RouteOutcome::Node("hk".to_string());

    let secure = route(RouteQuery::domain("www.example.com").with_port(443));
    assert_eq!(
        (secure.matched, secure.outcome),
        (RouteMatch::Rule(0), hk.clone())
    );
    let plain = route(RouteQuery::domain("www.example.com").with_port(80));
    assert_eq!(plain.matched, RouteMatch::Final);
    assert_eq!(
        route(RouteQuery::domain("ads.test").with_port(80)).outcome,
        RouteOutcome::Reject
    );
    assert_eq!(
        route(RouteQuery::domain("other.test").with_port(8443)).matched,
        RouteMatch::Rule(1)
    );
    assert_eq!(
        route(RouteQuery::domain("mail.google.com").with_port(443)).matched,
        RouteMatch::Rule(2)
    );
    let mut telegram = RouteQuery::ip("192.0.2.1".parse().unwrap()).with_port(443);
    telegram.process = Some("telegram.EXE".to_string());
    assert_eq!(route(telegram).matched, RouteMatch::Rule(3));
    assert_eq!(
        route(RouteQuery::ip("192.0.2.1".parse().unwrap()).with_port(53)).matched,
        RouteMatch::Rule(4)
    );
    // no-resolve on the logical rule: a domain is not resolved for it.
    let named = route(RouteQuery::domain("site.test").with_port(80));
    assert_eq!(
        (named.matched, named.resolved_ip),
        (RouteMatch::Final, None)
    );
    assert_eq!(
        route(RouteQuery::ip("203.0.113.5".parse().unwrap()).with_port(80)).matched,
        RouteMatch::Rule(5)
    );

    let texts = model
        .rules
        .iter()
        .map(|rule| rule.matcher.to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        texts,
        [
            "AND,((DOMAIN-SUFFIX,example.com),(DST-PORT,443))",
            "OR,((DOMAIN-KEYWORD,ads),(NOT,((DST-PORT,1-1024))))",
            "GEOSITE,google",
            "PROCESS-NAME,telegram.exe",
            "DST-PORT,53",
            "AND,((IP-CIDR,203.0.113.0/24),(DST-PORT,80))",
        ]
    );
    for text in &texts {
        let line = format!("{text},DIRECT");
        let RuleLine::Rule { matcher, .. } = parse_rule_line(&line).unwrap() else {
            panic!("{line} should parse as a rule");
        };
        assert_eq!(&matcher.to_string(), text);
    }
}

#[test]
fn malformed_logical_and_port_rules_are_rejected() {
    for line in [
        "AND,(DOMAIN,a.com),DIRECT",
        "AND,((DOMAIN,a.com),DIRECT",
        "AND,((DOMAIN,a.com))",
        "NOT,((DOMAIN,a.com),(DOMAIN,b.com)),DIRECT",
        "OR,(),DIRECT",
        "AND,((DOMAIN,a.com)(DOMAIN,b.com)),DIRECT",
        "AND,((DOMAIN,a.com,DIRECT)),DIRECT",
        "AND,((DOMAIN)),DIRECT",
        "AND,((USER-AGENT,curl)),DIRECT",
        "DST-PORT,99999,DIRECT",
        "DST-PORT,500-400,DIRECT",
        "GEOSITE,bad category,DIRECT",
        "DST-PORT,443,DIRECT,no-resolve",
        "AND,((((((((((((((((((DOMAIN,a.com)))))))))))))))))),DIRECT",
    ] {
        assert!(parse_rule_line(line).is_err(), "{line}");
    }
    let nested = "AND,((NOT,((AND,((DOMAIN,a.com),(DST-PORT,1)))))),DIRECT";
    assert!(parse_rule_line(nested).is_ok());
    let nest = |levels: usize| {
        format!(
            "{}DOMAIN,a.com{},DIRECT",
            "NOT,((".repeat(levels),
            "))".repeat(levels)
        )
    };
    assert!(parse_rule_line(&nest(8)).is_ok());
    assert!(parse_rule_line(&nest(9)).is_err());
}

/// Every member healthy, with a counter for round-robin groups.
#[derive(Default)]
struct BalanceEnvironment {
    down: Vec<&'static str>,
    turns: std::cell::Cell<usize>,
}

impl RoutingEnvironment for BalanceEnvironment {
    fn member_latency_ms(&self, _group_id: &str, member: &PolicyTarget) -> Option<u32> {
        (!self.down.iter().any(|down| *down == member.name())).then_some(50)
    }

    fn round_robin(&self, _group_id: &str) -> usize {
        let turn = self.turns.get();
        self.turns.set(turn + 1);
        turn
    }
}

#[test]
fn load_balance_groups_spread_hosts_over_healthy_members() {
    let nodes = BTreeSet::from(["a".to_string(), "b".to_string(), "c".to_string()]);
    let spec = spec(
        &["DOMAIN-SUFFIX,rr.example,RR", "FINAL,LB"],
        vec![
            group("LB", "load-balance", &["a", "b", "c"]),
            group("RR", "round-robin", &["a", "b", "c"]),
        ],
    );
    let model = RoutingModel::from_spec(&spec, &nodes).unwrap();
    assert_eq!(
        model.group("LB").unwrap().kind,
        PolicyGroupKind::LoadBalance
    );
    assert_eq!(model.group("RR").unwrap().kind, PolicyGroupKind::RoundRobin);
    assert!(model.group("LB").unwrap().health_check.is_some());

    let node = |resolution: RouteResolution| match resolution.outcome {
        RouteOutcome::Node(id) => id,
        other => panic!("expected a node, got {other:?}"),
    };
    let all_up = BalanceEnvironment::default();
    // One host always gets the same member; many hosts use several members.
    let first = node(model.decide(&RouteQuery::domain("www.example.com"), &all_up));
    for _ in 0..3 {
        assert_eq!(
            node(model.decide(&RouteQuery::domain("www.example.com"), &all_up)),
            first
        );
    }
    let used: BTreeSet<String> = (0..32)
        .map(|index| {
            node(model.decide(&RouteQuery::domain(format!("site{index}.example")), &all_up))
        })
        .collect();
    assert!(used.len() > 1, "hashing should use more than one member");

    // A host whose member goes down moves; the others stay.
    let down = BalanceEnvironment {
        down: vec!["a"],
        ..BalanceEnvironment::default()
    };
    for index in 0..32 {
        let query = RouteQuery::domain(format!("site{index}.example"));
        let before = node(model.decide(&query, &all_up));
        let after = node(model.decide(&query, &down));
        assert_ne!(after, "a");
        if before != "a" {
            assert_eq!(after, before);
        }
    }

    // Round-robin takes the members in turn.
    let turns: Vec<String> = (0..4)
        .map(|_| node(model.decide(&RouteQuery::domain("x.rr.example"), &all_up)))
        .collect();
    assert_eq!(turns, vec!["a", "b", "c", "a"]);
    // Without a connection the group reports its first healthy member.
    assert_eq!(
        model.group_member("RR", &down),
        Some(PolicyTarget::Node("b".to_string()))
    );
    assert_eq!(
        model_error(&spec_with_tolerance()),
        ROUTING_GROUP_HEALTH_CHECK_INVALID_CODE
    );
}

fn spec_with_tolerance() -> RoutingSpec {
    spec(
        &["FINAL,LB"],
        vec![PolicyGroupSpec {
            tolerance_ms: Some(10),
            ..group("LB", "load-balance", &["hk-1", "jp-1"])
        }],
    )
}
