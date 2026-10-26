use config_core::routing::{
    PolicyGroupKind, PolicyTarget, RouteOutcome, RouteQuery, RuleMatcher, StaticRoutingEnvironment,
};
use config_core::routing_import::{
    import_subscription_routing, ImportedRouting, ImportedRuleSet,
    ROUTING_IMPORT_GROUP_SKIPPED_CODE, ROUTING_IMPORT_INVALID_CODE,
    ROUTING_IMPORT_MEMBER_SKIPPED_CODE, ROUTING_IMPORT_READY_CODE,
    ROUTING_IMPORT_RULE_SKIPPED_CODE,
};
use config_core::CoreSubscriptionService;
use control_domain::{NodeDescriptor, RawSubscription, SubscriptionService};

const SURGE_PROFILE: &str = r#"
[General]
loglevel = notify

[Proxy]
HK = ss, 82.47.34.99, 11111, encrypt-method=aes-256-gcm, password=f43c0eee-13b9-4f07-bec9-d4b744141503
JP = ss, 82.47.34.100, 11112, encrypt-method=aes-256-gcm, password=f43c0eee-13b9-4f07-bec9-d4b744141504

[Proxy Group]
Proxy = select, Auto, HK, JP, DIRECT
Auto = url-test, HK, JP, url=http://www.gstatic.com/generate_204, interval=600, tolerance=100
Backup = fallback, JP, HK, Auto, interval=120
Balance = load-balance, HK, JP
Blocked = select, REJECT, Missing

[Rule]
DOMAIN,ads.example.com,REJECT-TINYGIF
DOMAIN-SUFFIX,google.com,Proxy
DOMAIN-KEYWORD,tracker,REJECT
PROCESS-NAME,curl,DIRECT
URL-REGEX,^https?://example\.com/ad,REJECT
DOMAIN-SUFFIX,balance.example,Balance
IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
GEOIP,CN,DIRECT
FINAL,Proxy,dns-failed
"#;

const CLASH_PROFILE: &str = r#"
proxies:
  - name: HK Clash
    type: ss
    server: 82.47.34.99
    port: 11111
    cipher: aes-256-gcm
    password: f43c0eee-13b9-4f07-bec9-d4b744141503
  - name: JP Clash
    type: ss
    server: 82.47.34.100
    port: 11112
    cipher: aes-256-gcm
    password: f43c0eee-13b9-4f07-bec9-d4b744141504
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - Auto
      - HK Clash
      - DIRECT
  - name: Auto
    type: url-test
    proxies:
      - HK Clash
      - JP Clash
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
rules:
  - DOMAIN-SUFFIX,google.com,Proxy
  - IP-CIDR6,2001:db8::/32,JP Clash,no-resolve
  - RULE-SET,private,DIRECT
  - MATCH,Proxy
"#;

fn parse_nodes(content: &str) -> Vec<NodeDescriptor> {
    let service = CoreSubscriptionService::new();
    let document = service
        .parse(&RawSubscription {
            source_id: "routing-import".to_string(),
            content: content.to_string(),
        })
        .expect("fixture subscription should parse");
    service.normalize(&document).unwrap().nodes
}

fn node_id(nodes: &[NodeDescriptor], name: &str) -> String {
    nodes
        .iter()
        .find(|node| node.name == name)
        .unwrap_or_else(|| panic!("fixture node {name} should exist"))
        .id
        .clone()
}

fn diagnostic_codes(imported: &ImportedRouting) -> Vec<&str> {
    imported
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect()
}

#[test]
fn surge_profile_imports_supported_rules_and_groups() {
    let nodes = parse_nodes(SURGE_PROFILE);
    let hk = node_id(&nodes, "HK");
    let jp = node_id(&nodes, "JP");

    let imported = import_subscription_routing(SURGE_PROFILE, &nodes);
    let model = imported
        .routing
        .clone()
        .expect("surge profile routing should import");

    assert_eq!(
        model
            .rules
            .iter()
            .map(|rule| (rule.matcher.clone(), rule.target.clone(), rule.no_resolve))
            .collect::<Vec<_>>(),
        vec![
            (
                RuleMatcher::Domain("ads.example.com".to_string()),
                PolicyTarget::Reject,
                false
            ),
            (
                RuleMatcher::DomainSuffix("google.com".to_string()),
                PolicyTarget::Group("Proxy".to_string()),
                false
            ),
            (
                RuleMatcher::DomainKeyword("tracker".to_string()),
                PolicyTarget::Reject,
                false
            ),
            (
                RuleMatcher::ProcessName("curl".to_string()),
                PolicyTarget::Direct,
                false
            ),
            (
                RuleMatcher::DomainSuffix("balance.example".to_string()),
                PolicyTarget::Group("Balance".to_string()),
                false
            ),
            (
                RuleMatcher::IpCidr(config_core::routing::IpCidr::parse("192.168.0.0/16").unwrap()),
                PolicyTarget::Direct,
                true
            ),
            (
                RuleMatcher::GeoIp("CN".to_string()),
                PolicyTarget::Direct,
                false
            ),
        ]
    );
    assert_eq!(model.final_target, PolicyTarget::Group("Proxy".to_string()));

    let ids = model
        .groups
        .iter()
        .map(|group| group.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, vec!["Proxy", "Auto", "Backup", "Balance"]);
    let balance = model.group("Balance").unwrap();
    assert_eq!(balance.kind, PolicyGroupKind::LoadBalance);
    assert_eq!(
        balance.members,
        vec![
            PolicyTarget::Node(hk.clone()),
            PolicyTarget::Node(jp.clone())
        ]
    );
    let proxy = model.group("Proxy").unwrap();
    assert_eq!(proxy.kind, PolicyGroupKind::Select);
    assert_eq!(
        proxy.members,
        vec![
            PolicyTarget::Group("Auto".to_string()),
            PolicyTarget::Node(hk.clone()),
            PolicyTarget::Node(jp.clone()),
            PolicyTarget::Direct,
        ]
    );
    let auto = model.group("Auto").unwrap();
    assert_eq!(auto.kind, PolicyGroupKind::UrlTest);
    let health_check = auto.health_check.as_ref().unwrap();
    assert_eq!(health_check.url, "http://www.gstatic.com/generate_204");
    assert_eq!(health_check.interval_secs, 600);
    assert_eq!(health_check.tolerance_ms, 100);
    let backup = model.group("Backup").unwrap();
    assert_eq!(backup.kind, PolicyGroupKind::Fallback);
    assert_eq!(
        backup.members,
        vec![PolicyTarget::Node(jp), PolicyTarget::Node(hk.clone())]
    );
    assert_eq!(backup.health_check.as_ref().unwrap().interval_secs, 120);

    let decision = model.decide(
        &RouteQuery::domain("www.google.com"),
        &StaticRoutingEnvironment,
    );
    assert_eq!(decision.group_path, vec!["Proxy", "Auto"]);
    assert_eq!(decision.outcome, RouteOutcome::Node(hk));

    let codes = diagnostic_codes(&imported);
    assert_eq!(codes.last(), Some(&ROUTING_IMPORT_READY_CODE));
    assert!(codes.contains(&ROUTING_IMPORT_GROUP_SKIPPED_CODE));
    assert!(codes.contains(&ROUTING_IMPORT_MEMBER_SKIPPED_CODE));
    assert!(codes.contains(&ROUTING_IMPORT_RULE_SKIPPED_CODE));
    let messages = imported
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(messages.contains("Blocked"));
    assert!(messages.contains("Backup member Auto was skipped"));
    assert!(messages.contains("URL-REGEX x1"));
    assert!(!messages.contains("f43c0eee"));
}

#[test]
fn clash_yaml_imports_rules_groups_and_match() {
    let nodes = parse_nodes(CLASH_PROFILE);
    let hk = node_id(&nodes, "HK Clash");
    let jp = node_id(&nodes, "JP Clash");

    let imported = import_subscription_routing(CLASH_PROFILE, &nodes);
    let model = imported
        .routing
        .clone()
        .expect("clash routing should import");

    assert_eq!(model.rules.len(), 2);
    assert_eq!(
        model.rules[0].target,
        PolicyTarget::Group("Proxy".to_string())
    );
    assert_eq!(model.rules[1].target, PolicyTarget::Node(jp.clone()));
    assert!(model.rules[1].no_resolve);
    assert_eq!(model.final_target, PolicyTarget::Group("Proxy".to_string()));
    assert_eq!(
        model.group("Proxy").unwrap().members,
        vec![
            PolicyTarget::Group("Auto".to_string()),
            PolicyTarget::Node(hk.clone()),
            PolicyTarget::Direct,
        ]
    );
    assert_eq!(
        model.group("Auto").unwrap().members,
        vec![PolicyTarget::Node(hk), PolicyTarget::Node(jp)]
    );
    assert!(imported
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("rule set private is not a URL")));
    assert!(imported.rule_sets.is_empty());
}

#[test]
fn profile_without_rules_imports_no_routing() {
    let content = r#"
[Proxy]
HK = ss, 82.47.34.99, 11111, encrypt-method=aes-256-gcm, password=f43c0eee-13b9-4f07-bec9-d4b744141503

[Proxy Group]
Proxy = select, HK
"#;
    let nodes = parse_nodes(content);
    let imported = import_subscription_routing(content, &nodes);
    assert_eq!(imported.routing, None);
    assert!(imported.diagnostics.is_empty());

    let links = "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@82.47.34.99:11111#HK";
    let imported = import_subscription_routing(links, &[]);
    assert_eq!(imported.routing, None);
    assert!(imported.diagnostics.is_empty());
}

#[test]
fn invalid_imported_routing_falls_back_with_warning() {
    let content = r#"
[Proxy]
HK = ss, 82.47.34.99, 11111, encrypt-method=aes-256-gcm, password=f43c0eee-13b9-4f07-bec9-d4b744141503

[Proxy Group]
A = select, B, HK
B = select, A, HK

[Rule]
DOMAIN-SUFFIX,google.com,A
"#;
    let nodes = parse_nodes(content);
    let imported = import_subscription_routing(content, &nodes);
    assert_eq!(imported.routing, None);
    let codes = diagnostic_codes(&imported);
    assert_eq!(codes, vec![ROUTING_IMPORT_INVALID_CODE]);
}

const FILTER_PROFILE: &str = r#"
[General]
loglevel = notify

[Proxy]
HK 01 = ss, 82.47.34.99, 11111, encrypt-method=aes-256-gcm, password=f43c0eee-13b9-4f07-bec9-d4b744141503
HK 02 = ss, 82.47.34.98, 11111, encrypt-method=aes-256-gcm, password=f43c0eee-13b9-4f07-bec9-d4b744141503
JP 01 = ss, 82.47.34.100, 11112, encrypt-method=aes-256-gcm, password=f43c0eee-13b9-4f07-bec9-d4b744141504
HK Expired = ss, 82.47.34.97, 11111, encrypt-method=aes-256-gcm, password=f43c0eee-13b9-4f07-bec9-d4b744141503

[Proxy Group]
HongKong = url-test, include-all-proxies=1, policy-regex-filter=^HK \d+$
Spread = load-balance, policy-regex-filter=HK|JP, url=http://www.gstatic.com/generate_204, algorithm=round-robin
Manual = select, JP 01, policy-regex-filter=HK
Broken = select, include-all-proxies=true, policy-regex-filter=(HK

[Rule]
FINAL,HongKong
"#;

#[test]
fn surge_name_filters_pick_group_members() {
    let nodes = parse_nodes(FILTER_PROFILE);
    let id = |name| PolicyTarget::Node(node_id(&nodes, name));
    let imported = import_subscription_routing(FILTER_PROFILE, &nodes);
    let model = imported
        .routing
        .clone()
        .expect("filter profile should import");

    assert_eq!(
        model.group("HongKong").unwrap().members,
        vec![id("HK 01"), id("HK 02")]
    );
    let spread = model.group("Spread").unwrap();
    assert_eq!(spread.kind, PolicyGroupKind::RoundRobin);
    assert_eq!(
        spread.members,
        vec![id("HK 01"), id("HK 02"), id("JP 01"), id("HK Expired")]
    );
    // A filter on a group with members and without include-all is ignored.
    assert_eq!(model.group("Manual").unwrap().members, vec![id("JP 01")]);
    // An invalid filter adds nothing, so the group is skipped.
    assert!(model.group("Broken").is_none());
    let messages = imported
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(messages.contains("Manual name filter was ignored"));
    assert!(messages.contains("Broken name filter is not a supported regular expression"));
}

#[test]
fn clash_filters_and_strategies_import() {
    let profile = r#"
proxies:
  - { name: HK 01, type: ss, server: 82.47.34.99, port: 11111, cipher: aes-256-gcm, password: f43c0eee-13b9-4f07-bec9-d4b744141503 }
  - { name: JP 01, type: ss, server: 82.47.34.100, port: 11112, cipher: aes-256-gcm, password: f43c0eee-13b9-4f07-bec9-d4b744141504 }
  - { name: US 01, type: ss, server: 82.47.34.101, port: 11113, cipher: aes-256-gcm, password: f43c0eee-13b9-4f07-bec9-d4b744141505 }
proxy-groups:
  - name: Asia
    type: load-balance
    strategy: consistent-hashing
    include-all: true
    filter: "HK`JP"
    exclude-filter: "JP"
  - name: Turns
    type: load-balance
    strategy: round-robin
    proxies: [US 01]
rules:
  - MATCH,Asia
"#;
    let nodes = parse_nodes(profile);
    let id = |name| PolicyTarget::Node(node_id(&nodes, name));
    let imported = import_subscription_routing(profile, &nodes);
    let model = imported
        .routing
        .clone()
        .expect("clash routing should import");
    let asia = model.group("Asia").unwrap();
    assert_eq!(asia.kind, PolicyGroupKind::LoadBalance);
    assert_eq!(asia.members, vec![id("HK 01")]);
    let turns = model.group("Turns").unwrap();
    assert_eq!(turns.kind, PolicyGroupKind::RoundRobin);
    assert_eq!(turns.members, vec![id("US 01")]);
    assert!(!imported
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("options were ignored")));
}

#[test]
fn clash_rule_providers_and_logical_rules_import() {
    let profile = r#"
proxies:
  - { name: HK 01, type: ss, server: 82.47.34.99, port: 11111, cipher: aes-256-gcm, password: f43c0eee-13b9-4f07-bec9-d4b744141503 }
proxy-groups:
  - { name: Proxy, type: select, proxies: [HK 01, DIRECT] }
rule-providers:
  reject:
    type: http
    behavior: domain
    url: https://rules.example/reject.txt?token=secret-token
    path: ./ruleset/reject.yaml
    interval: 86400
  cncidr:
    type: http
    behavior: ipcidr
    format: text
    url: https://rules.example/cncidr.txt
    interval: 60
    proxy: Proxy
  binary:
    type: http
    behavior: domain
    format: mrs
    url: https://rules.example/binary.mrs
  local:
    type: file
    behavior: classical
    path: ./local.yaml
rules:
  - RULE-SET,reject,REJECT
  - RULE-SET,cncidr,DIRECT,no-resolve
  - RULE-SET,binary,Proxy
  - RULE-SET,local,Proxy
  - GEOSITE,cn,DIRECT
  - PROCESS-NAME,Telegram,Proxy
  - AND,((RULE-SET,reject),(DST-PORT,443)),Proxy
  - OR,((DOMAIN,a.example),(IP-CIDR,10.0.0.0/8,no-resolve)),DIRECT,no-resolve
  - NOT,((DOMAIN-SUFFIX,example.org)),Proxy
  - MATCH,Proxy
"#;
    let nodes = parse_nodes(profile);
    let imported = import_subscription_routing(profile, &nodes);
    let spec = imported.spec.clone().expect("clash routing should import");
    assert_eq!(
        spec.rules,
        vec![
            "RULE-SET,reject,REJECT".to_string(),
            "RULE-SET,cncidr,DIRECT".to_string(),
            "GEOSITE,cn,DIRECT".to_string(),
            "PROCESS-NAME,Telegram,Proxy".to_string(),
            "AND,((RULE-SET,reject),(DST-PORT,443)),Proxy".to_string(),
            "OR,((DOMAIN,a.example),(IP-CIDR,10.0.0.0/8,no-resolve)),DIRECT,no-resolve".to_string(),
            "NOT,((DOMAIN-SUFFIX,example.org)),Proxy".to_string(),
            "FINAL,Proxy".to_string(),
        ]
    );
    assert_eq!(
        imported.rule_sets,
        vec![
            ImportedRuleSet {
                id: "reject".to_string(),
                url: "https://rules.example/reject.txt?token=secret-token".to_string(),
                format: Some("domain"),
                interval_secs: Some(86400),
                via: None,
            },
            ImportedRuleSet {
                id: "cncidr".to_string(),
                url: "https://rules.example/cncidr.txt".to_string(),
                format: None,
                interval_secs: Some(600),
                via: Some("Proxy".to_string()),
            },
        ]
    );
    let model = imported.routing.clone().unwrap();
    assert_eq!(model.rules.len(), 7);
    assert_eq!(
        model.rules[3].target,
        PolicyTarget::Group("Proxy".to_string())
    );
    let messages = imported
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(messages.contains("format mrs is unsupported"));
    assert!(messages.contains("type file is unsupported"));
    assert!(!messages.contains("secret-token"));
}

#[test]
fn surge_and_loon_rule_set_urls_import() {
    let profile = r#"
[Proxy]
HK = ss, 82.47.34.99, 11111, encrypt-method=aes-256-gcm, password=f43c0eee-13b9-4f07-bec9-d4b744141503

[Proxy Group]
Proxy = select, HK, DIRECT

[Rule]
RULE-SET,https://rules.example/surge/Apple.list,DIRECT,update-interval=7200
DOMAIN-SET,https://rules.example/surge/reject.txt,REJECT
RULE-SET,https://rules.example/surge/Apple.list,Proxy
RULE-SET,SYSTEM,DIRECT
RULE-SET,https://other.example/lists/Apple.list,Proxy
FINAL,Proxy

[Remote Rule]
https://rules.example/loon/Netflix.list, policy=Proxy, tag=Netflix, enabled=true
https://rules.example/loon/Off.list, policy=Proxy, tag=Off, enabled=false
"#;
    let nodes = parse_nodes(profile);
    let imported = import_subscription_routing(profile, &nodes);
    let spec = imported.spec.clone().expect("surge routing should import");
    assert_eq!(
        spec.rules,
        vec![
            "RULE-SET,Apple,DIRECT".to_string(),
            "RULE-SET,reject,REJECT".to_string(),
            "RULE-SET,Apple,Proxy".to_string(),
            "RULE-SET,Apple-2,Proxy".to_string(),
            "RULE-SET,Netflix,Proxy".to_string(),
            "FINAL,Proxy".to_string(),
        ]
    );
    let summary = imported
        .rule_sets
        .iter()
        .map(|set| (set.id.as_str(), set.format, set.interval_secs))
        .collect::<Vec<_>>();
    assert_eq!(
        summary,
        vec![
            ("Apple", None, Some(7200)),
            ("reject", Some("domain"), None),
            ("Apple-2", None, None),
            ("Netflix", None, None),
        ]
    );
    assert!(imported
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.message.contains("rule set SYSTEM is not a URL")));
}
