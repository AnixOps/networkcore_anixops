//! `RoutingModel::decide_indexed` must decide exactly as `decide`.

use config_core::routing::{
    PolicyGroupSpec, RouteMatch, RouteQuery, RoutingEnvironment, RoutingModel, RoutingSpec,
    RuleIndex,
};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

/// Resolves names under `ok.test` and fails the rest, so a decision can
/// end in `ResolveFailed` at an IP rule before or after a domain rule.
struct Environment;

impl RoutingEnvironment for Environment {
    fn resolve(&self, domain: &str) -> Option<IpAddr> {
        domain
            .ends_with("ok.test")
            .then_some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, domain.len() as u8)))
    }

    fn geoip_country(&self, ip: IpAddr) -> Option<String> {
        matches!(ip, IpAddr::V4(v4) if v4.octets()[1] == 1).then(|| "CN".to_string())
    }
}

fn model(rules: &[&str]) -> RoutingModel {
    let nodes = BTreeSet::from(["hk".to_string(), "jp".to_string()]);
    let spec = RoutingSpec {
        rules: rules.iter().map(|rule| rule.to_string()).collect(),
        groups: vec![PolicyGroupSpec {
            id: "Proxy".to_string(),
            kind: "select".to_string(),
            members: vec!["hk".to_string(), "jp".to_string()],
            default: None,
            url: None,
            interval_secs: None,
            tolerance_ms: None,
        }],
    };
    RoutingModel::from_spec(&spec, &nodes).unwrap()
}

const RULES: &[&str] = &[
    "DOMAIN-KEYWORD,tracker,REJECT",
    "DOMAIN-SUFFIX,b.example.com,hk",
    "DOMAIN,exact.example.com,jp",
    "IP-CIDR,192.0.2.0/24,REJECT,no-resolve",
    "DOMAIN-SUFFIX,example.com,Proxy",
    "DOMAIN,b.example.com,REJECT",
    "DOMAIN-WILDCARD,*.wild.example.net,jp",
    "DST-PORT,8443,hk",
    "AND,((DOMAIN-SUFFIX,and.test),(DST-PORT,443)),jp",
    "DOMAIN-SUFFIX,example.net,DIRECT",
    "IP-CIDR,10.1.0.0/16,hk",
    "DOMAIN-SUFFIX,later.ok.test,jp",
    "DOMAIN-SUFFIX,c.example.com,REJECT",
    "DOMAIN-SUFFIX,example.org,hk",
    "GEOIP,CN,DIRECT",
    "DOMAIN-SUFFIX,after.fail.test,hk",
    "DOMAIN,after-geoip.ok.test,REJECT",
    "FINAL,Proxy",
];

fn queries() -> Vec<RouteQuery> {
    let mut queries: Vec<RouteQuery> = [
        "exact.example.com",
        "EXACT.example.com.",
        "b.example.com",
        "x.b.example.com",
        "c.example.com",
        "a.c.example.com",
        "example.com",
        "notexample.com",
        "tracker.example.com",
        "x.wild.example.net",
        "example.net",
        "www.example.org",
        "and.test",
        "x.and.test",
        "later.ok.test",
        "x.later.ok.test",
        "after-geoip.ok.test",
        "after.fail.test",
        "y.after.fail.test",
        "unknown.ok.test",
        "unknown.fail.test",
        "a..example.com",
        "",
        "com",
    ]
    .iter()
    .flat_map(|domain| {
        [
            RouteQuery::domain(*domain),
            RouteQuery::domain(*domain).with_port(443),
            RouteQuery::domain(*domain).with_port(8443),
        ]
    })
    .collect();
    for ip in ["192.0.2.7", "10.1.9.9", "203.0.113.1"] {
        let ip: IpAddr = ip.parse().unwrap();
        queries.push(RouteQuery::ip(ip));
        queries.push(RouteQuery::ip(ip).with_port(8443));
        let mut both = RouteQuery::domain("b.example.com");
        both.ip = Some(ip);
        queries.push(both);
    }
    queries
}

#[test]
fn indexed_decisions_match_linear_decisions() {
    let model = model(RULES);
    let index = RuleIndex::new(&model);
    assert!(index.fits(&model));
    assert!(index.unindexed_len() < model.rules.len());
    for query in queries() {
        assert_eq!(
            model.decide_indexed(&index, &query, &Environment),
            model.decide(&query, &Environment),
            "{query:?}"
        );
    }
}

#[test]
fn the_first_matching_rule_wins_over_a_later_indexed_one() {
    let model = model(RULES);
    let index = RuleIndex::new(&model);
    let decide = |domain: &str| {
        model
            .decide_indexed(&index, &RouteQuery::domain(domain), &Environment)
            .matched
    };
    // The suffix rule at 1 comes before the exact rule at 5.
    assert_eq!(decide("b.example.com"), RouteMatch::Rule(1));
    // The keyword at 0 comes before every domain rule.
    assert_eq!(decide("tracker.example.com"), RouteMatch::Rule(0));
    // c.example.com: the broader suffix at 4 comes before the one at 12.
    assert_eq!(decide("a.c.example.com"), RouteMatch::Rule(4));
    // IP-CIDR at 10 resolves the name before the suffix at 11 is reached.
    assert_eq!(decide("later.ok.test"), RouteMatch::Rule(10));
    // Resolving fails at the first IP rule that may resolve.
    assert_eq!(decide("after.fail.test"), RouteMatch::ResolveFailed(10));
}

#[test]
fn an_index_for_other_rules_is_ignored() {
    let routing = model(RULES);
    let stale = RuleIndex::new(&model(&["DOMAIN,b.example.com,REJECT", "FINAL,DIRECT"]));
    assert!(!stale.fits(&routing));
    for query in queries() {
        assert_eq!(
            routing.decide_indexed(&stale, &query, &Environment),
            routing.decide(&query, &Environment)
        );
    }
}

/// Many generated rules and queries, as the benchmark uses.
#[test]
fn generated_lists_decide_the_same_way() {
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let mut next = move |n: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % n
    };
    let labels = ["a", "b", "c", "cdn", "api", "ok", "x1", "y"];
    let tlds = ["com", "net", "test"];
    let mut rules = Vec::new();
    for _ in 0..600 {
        let name = format!(
            "{}.{}",
            labels[next(labels.len() as u64) as usize],
            tlds[next(tlds.len() as u64) as usize]
        );
        let target = ["hk", "jp", "DIRECT", "REJECT", "Proxy"][next(5) as usize];
        rules.push(match next(8) {
            0 | 1 | 2 => format!("DOMAIN-SUFFIX,{name},{target}"),
            3 => format!("DOMAIN,{}.{name},{target}", labels[next(8) as usize]),
            4 => format!("DOMAIN-KEYWORD,{},{target}", labels[next(8) as usize]),
            5 => format!("IP-CIDR,10.{}.0.0/16,{target},no-resolve", next(4)),
            6 => format!("IP-CIDR,10.{}.0.0/16,{target}", next(4)),
            _ => format!("DST-PORT,{},{target}", 440 + next(8)),
        });
    }
    rules.push("FINAL,Proxy".to_string());
    let lines: Vec<&str> = rules.iter().map(String::as_str).collect();
    let model = model(&lines);
    let index = RuleIndex::new(&model);
    for _ in 0..5000 {
        let domain = format!(
            "{}.{}.{}",
            labels[next(8) as usize],
            labels[next(8) as usize],
            tlds[next(3) as usize]
        );
        let query = RouteQuery::domain(domain).with_port(440 + next(10) as u16);
        assert_eq!(
            model.decide_indexed(&index, &query, &Environment),
            model.decide(&query, &Environment),
            "{query:?}"
        );
    }
}
