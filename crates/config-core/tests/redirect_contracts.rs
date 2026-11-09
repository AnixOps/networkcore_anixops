//! Destination rewrite lines: parsing, targets and first-match order.

use std::net::IpAddr;

use config_core::redirect::{
    parse_redirect_line, parse_redirect_target, RedirectHost, RedirectTable, RedirectTo,
    MAX_REDIRECTS, REDIRECT_LINE_INVALID_CODE, REDIRECT_MATCHER_UNSUPPORTED_CODE,
    REDIRECT_TARGET_INVALID_CODE, REDIRECT_TOO_MANY_CODE,
};
use config_core::routing::{RouteNetwork, RouteQuery};

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

#[test]
fn targets_take_every_documented_shape() {
    let cases = [
        ("10.8.0.5", RedirectHost::Ip(ip("10.8.0.5")), None),
        (
            "10.8.0.5:7000",
            RedirectHost::Ip(ip("10.8.0.5")),
            Some(7000),
        ),
        ("fd00::5", RedirectHost::Ip(ip("fd00::5")), None),
        ("[fd00::5]", RedirectHost::Ip(ip("fd00::5")), None),
        (
            "[fd00::5]:7000",
            RedirectHost::Ip(ip("fd00::5")),
            Some(7000),
        ),
        (
            "Dev.Example.com",
            RedirectHost::Domain("dev.example.com".to_string()),
            None,
        ),
        (
            "dev.example.com:9000",
            RedirectHost::Domain("dev.example.com".to_string()),
            Some(9000),
        ),
        (":9000", RedirectHost::Keep, Some(9000)),
    ];
    for (text, host, port) in cases {
        assert_eq!(
            parse_redirect_target(text).unwrap(),
            RedirectTo { host, port },
            "{text}"
        );
    }
}

#[test]
fn bad_targets_are_refused() {
    for text in [
        "",
        ":0",
        ":70000",
        "10.8.0.5:",
        "fd00::5:7000x",
        "[fd00::5",
        "[10.8.0.5]:7000",
        "[fd00::5]7000",
        "dev example.com",
        "dev.example.com:0",
    ] {
        let error = parse_redirect_target(text).unwrap_err();
        assert_eq!(error.code, REDIRECT_TARGET_INVALID_CODE, "{text}");
    }
}

#[test]
fn targets_print_back_as_written() {
    for text in [
        "10.8.0.5",
        "10.8.0.5:7000",
        "[fd00::5]:7000",
        "dev.example.com:9000",
        ":9000",
    ] {
        assert_eq!(parse_redirect_target(text).unwrap().to_string(), text);
    }
    let rule = parse_redirect_line("AND,((IP-CIDR,203.0.113.10/32),(PROTOCOL,UDP)),:9000").unwrap();
    assert_eq!(
        rule.to_string(),
        "AND,((IP-CIDR,203.0.113.10/32),(PROTOCOL,UDP)),:9000"
    );
}

#[test]
fn lines_need_a_rule_and_a_supported_matcher() {
    assert_eq!(
        parse_redirect_line("FINAL,10.8.0.5").unwrap_err().code,
        REDIRECT_LINE_INVALID_CODE
    );
    for line in [
        "GEOIP,CN,10.8.0.5",
        "GEOSITE,cn,10.8.0.5",
        "RULE-SET,games,10.8.0.5",
        "AND,((DST-PORT,7000),(NOT,((GEOIP,CN)))),10.8.0.5",
    ] {
        assert_eq!(
            parse_redirect_line(line).unwrap_err().code,
            REDIRECT_MATCHER_UNSUPPORTED_CODE,
            "{line}"
        );
    }
    assert!(parse_redirect_line("DOMAIN-SUFFIX,game.example.com").is_err());
}

#[test]
fn the_first_matching_line_wins_and_ip_rules_never_resolve() {
    let table = RedirectTable::parse(&[
        "# game servers",
        "",
        "AND,((DOMAIN-SUFFIX,game.example.com),(PROTOCOL,UDP)),10.8.0.5:7777",
        "DOMAIN-SUFFIX,game.example.com,10.8.0.5",
        "IP-CIDR,203.0.113.0/24,10.8.0.6",
        "DST-PORT,9000-9010,:19000",
    ])
    .unwrap();
    assert_eq!(table.rules().len(), 4);

    let udp = RouteQuery::domain("login.game.example.com")
        .with_port(7000)
        .with_network(RouteNetwork::Udp);
    assert_eq!(table.find(&udp).unwrap().to.to_string(), "10.8.0.5:7777");

    let tcp = RouteQuery::domain("login.game.example.com")
        .with_port(443)
        .with_network(RouteNetwork::Tcp);
    assert_eq!(table.find(&tcp).unwrap().to.to_string(), "10.8.0.5");

    let by_address = RouteQuery::ip(ip("203.0.113.9")).with_port(80);
    assert_eq!(table.find(&by_address).unwrap().to.to_string(), "10.8.0.6");

    // A domain is never resolved for an IP rule.
    let other_domain = RouteQuery::domain("cdn.example.org").with_port(80);
    assert!(table.find(&other_domain).is_none());

    let by_port = RouteQuery::ip(ip("198.51.100.1")).with_port(9005);
    assert_eq!(table.find(&by_port).unwrap().to.to_string(), ":19000");
}

#[test]
fn errors_name_the_line_and_the_count_is_capped() {
    let error = RedirectTable::parse(&["DST-PORT,80,:8080", "DST-PORT,81,nope nope"]).unwrap_err();
    assert_eq!(error.code, REDIRECT_TARGET_INVALID_CODE);
    assert!(
        error.message.starts_with("redirect 1:"),
        "{}",
        error.message
    );

    let many = vec!["DST-PORT,80,:8080"; MAX_REDIRECTS + 1];
    assert_eq!(
        RedirectTable::parse(&many).unwrap_err().code,
        REDIRECT_TOO_MANY_CODE
    );
    assert!(RedirectTable::parse(&many[..MAX_REDIRECTS]).is_ok());
}
