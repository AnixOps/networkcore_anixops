//! Routing modes and policy group choices over imported profiles.

use engine_embedded::profile::{
    envelope_for_mode, groups, selected_node, set_group_default, switch_group_for_node,
    RoutingMode, RuleList, PROXY_OUTBOUND,
};
use serde_json::{json, Value};

fn ss(server: &str) -> Value {
    json!({
        "type": "shadowsocks",
        "server": server,
        "port": 443,
        "method": "2022-blake3-aes-128-gcm",
        "password": "AAECAwQFBgcICQoLDA0ODw==",
    })
}

fn single() -> Value {
    json!({ "schema_version": 1, "profile_id": "p", "outbound": ss("192.0.2.1") })
}

fn routed() -> Value {
    json!({
        "schema_version": 1,
        "profile_id": "p",
        "routing": {
            "outbounds": { "hk": ss("192.0.2.1"), "jp": ss("192.0.2.2") },
            "rules": ["DOMAIN-SUFFIX,example.org,DIRECT", "FINAL,Proxy"],
            "groups": [
                { "id": "Proxy", "type": "select", "members": ["Auto", "hk", "DIRECT"] },
                { "id": "Auto", "type": "url-test", "members": ["jp", "hk"],
                  "url": "http://www.gstatic.com/generate_204", "interval_secs": 300 },
            ],
        },
    })
}

fn lists(list: RuleList) -> Result<Vec<String>, String> {
    Ok(match list {
        RuleList::ChinaDomains => vec!["cn".to_string(), "baidu.com".to_string()],
        RuleList::ChinaIps => vec!["1.0.1.0/24".to_string()],
        RuleList::GfwDomains => vec!["google.com".to_string()],
    })
}

fn render(profile: &Value, mode: RoutingMode) -> Value {
    serde_json::from_str(&envelope_for_mode(&profile.to_string(), mode, lists).unwrap()).unwrap()
}

#[test]
fn modes_name_themselves_and_their_lists() {
    for mode in [
        RoutingMode::BypassChina,
        RoutingMode::GfwList,
        RoutingMode::ReturnChina,
        RoutingMode::Direct,
        RoutingMode::Rule,
    ] {
        assert_eq!(RoutingMode::parse(mode.as_str()), Some(mode));
        assert_eq!(
            serde_json::to_value(mode).unwrap(),
            Value::String(mode.as_str().to_string())
        );
    }
    assert_eq!(RoutingMode::parse("global"), None);
    assert_eq!(RoutingMode::default(), RoutingMode::Rule);
    assert_eq!(
        RoutingMode::BypassChina.rule_lists(),
        [RuleList::ChinaDomains, RuleList::ChinaIps]
    );
    assert!(RoutingMode::Rule.rule_lists().is_empty());

    let text = "# comment\nexample.cn\n\nnot-a-domain\n1.0.1.0/24 extra\n";
    assert_eq!(RuleList::ChinaDomains.parse(text), ["example.cn"]);
    assert_eq!(RuleList::ChinaIps.parse(text), ["1.0.1.0/24"]);
}

#[test]
fn rule_mode_keeps_the_profile_and_list_modes_replace_its_rules() {
    let profile = routed();
    assert_eq!(render(&profile, RoutingMode::Rule), profile);

    let bypass = render(&profile, RoutingMode::BypassChina);
    assert_eq!(
        bypass["routing"]["rules"],
        json!(["RULE-SET,china,DIRECT", "FINAL,Proxy"])
    );
    assert_eq!(
        bypass["routing"]["rule_sets"]["china"]["ip_cidr"],
        json!(["1.0.1.0/24"])
    );
    // The groups stay, so the proxied part still follows them.
    assert_eq!(bypass["routing"]["groups"], profile["routing"]["groups"]);

    let back = render(&profile, RoutingMode::ReturnChina);
    assert_eq!(
        back["routing"]["rules"],
        json!(["RULE-SET,china,Proxy", "FINAL,DIRECT"])
    );

    let gfw = render(&single(), RoutingMode::GfwList);
    assert!(gfw.get("outbound").is_none());
    assert_eq!(
        gfw["routing"]["rules"],
        json!([format!("RULE-SET,gfw,{PROXY_OUTBOUND}"), "FINAL,DIRECT"])
    );
    assert!(gfw["routing"]["outbounds"][PROXY_OUTBOUND].is_object());

    let direct = render(&single(), RoutingMode::Direct);
    assert_eq!(direct["routing"]["rules"], json!(["FINAL,DIRECT"]));

    let failing = envelope_for_mode(&profile.to_string(), RoutingMode::GfwList, |_| {
        Err("offline".to_string())
    });
    assert_eq!(failing, Err("offline".to_string()));
}

#[test]
fn groups_report_their_choice_and_select_groups_switch() {
    let mut profile = routed();
    let listed = groups(&profile);
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].id, "Proxy");
    assert_eq!(listed[0].choice.as_deref(), Some("Auto"));
    assert_eq!(listed[1].kind, "url-test");
    assert!(groups(&single()).is_empty());

    // FINAL → Proxy → Auto → jp before any health check.
    assert_eq!(selected_node(&profile).as_deref(), Some("jp"));
    assert_eq!(
        switch_group_for_node(&profile, "hk").as_deref(),
        Some("Proxy")
    );
    assert_eq!(switch_group_for_node(&profile, "missing"), None);

    set_group_default(&mut profile, "Proxy", "hk").unwrap();
    assert_eq!(selected_node(&profile).as_deref(), Some("hk"));
    assert!(set_group_default(&mut profile, "Auto", "hk").is_err());
    assert!(set_group_default(&mut profile, "Proxy", "nope").is_err());
    assert!(set_group_default(&mut profile, "Missing", "hk").is_err());

    set_group_default(&mut profile, "Proxy", "DIRECT").unwrap();
    assert_eq!(selected_node(&profile), None);
}
