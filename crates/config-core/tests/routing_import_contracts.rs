use config_core::routing::{
    PolicyGroupKind, PolicyTarget, RouteOutcome, RouteQuery, RuleMatcher, StaticRoutingEnvironment,
};
use config_core::routing_import::{
    import_subscription_routing, ImportedRouting, ROUTING_IMPORT_GROUP_SKIPPED_CODE,
    ROUTING_IMPORT_INVALID_CODE, ROUTING_IMPORT_MEMBER_SKIPPED_CODE, ROUTING_IMPORT_READY_CODE,
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
Backup = fallback, JP, HK, interval=120
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
    assert_eq!(ids, vec!["Proxy", "Auto", "Backup"]);
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
    assert!(messages.contains("load-balance"));
    assert!(messages.contains("Blocked"));
    assert!(messages.contains("PROCESS-NAME x1"));
    assert!(messages.contains("URL-REGEX x1"));
    assert!(messages.contains("target Balance was not imported"));
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
        .any(|diagnostic| diagnostic.message.contains("RULE-SET x1")));
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
