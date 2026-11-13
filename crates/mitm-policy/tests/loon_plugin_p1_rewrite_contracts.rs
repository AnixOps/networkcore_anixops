//! Loon P1 `[Map Local]` and `[Body Rewrite]`: grading, translation for the
//! policy core, and the outcomes the plugin service plans from them.

use control_domain::{
    GrantedPermissions, HookPoint, HttpMitmAction, HttpMitmEvent, HttpMitmOutcome, HttpMitmPhase,
    MetadataEntry, MitmHostnameDecision, MitmPluginService, PluginInstance, PluginManifest,
    PluginPackage, PluginPermission,
};
use mitm_policy::loon_map_local::{match_map_local, parse_map_local_line};
use mitm_policy::loon_plugin::{
    import_loon_plugin, import_loon_plugin_with_resources, merged_plugin_source, LoonLineHandler,
    LoonLineStatus, LoonPluginImport, LoonRemoteResource, LoonRemoteResourceKind, LoonSupportLevel,
};
use mitm_policy::{AnixOpsMitmPluginService, MITM_POLICY_HTTP_EVENT_MAP_LOCAL_CODE};
use std::collections::BTreeMap;

const FIXTURE: &str = include_str!("fixtures/loon-plugins/p1-map-local-body-rewrite.plugin");

fn load(plugin: &LoonPluginImport) -> (AnixOpsMitmPluginService, PluginInstance) {
    let package = plugin
        .plugin_package("user.p1-rewrite", "1.0.0")
        .expect("package should build");
    let service = AnixOpsMitmPluginService::new();
    let instance = service
        .load(
            &package,
            &GrantedPermissions {
                permissions: package.manifest.permissions.clone(),
            },
        )
        .expect("plugin should load");
    (service, instance)
}

fn event(phase: HttpMitmPhase, url: &str, body: &str) -> HttpMitmEvent {
    HttpMitmEvent {
        request_id: "p1-rewrite".to_string(),
        url: url.to_string(),
        method: Some("POST".to_string()),
        phase,
        status_code: (phase == HttpMitmPhase::Response).then_some(200),
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
    }
}

fn plan(plugin: &LoonPluginImport, event: &HttpMitmEvent) -> HttpMitmOutcome {
    let (service, instance) = load(plugin);
    service
        .handle_http_mitm_event(&instance, event)
        .expect("event should plan")
}

fn header<'a>(headers: &'a [MetadataEntry], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.key.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

#[test]
fn map_local_and_body_rewrite_fixture_is_fully_supported() {
    let plugin = import_loon_plugin(FIXTURE).expect("fixture should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("p1-map-local-body-rewrite")
    );
    let graded = plugin
        .report
        .lines
        .iter()
        .filter(|line| line.status != LoonLineStatus::Ignored)
        .map(|line| (line.line, line.reason.as_str(), line.handler))
        .collect::<Vec<_>>();
    assert_eq!(
        graded,
        vec![
            (5, "map_local.response", LoonLineHandler::MapLocal),
            (6, "map_local.response", LoonLineHandler::MapLocal),
            (9, "map_local.response", LoonLineHandler::MapLocal),
            (
                12,
                "body_rewrite.http_response",
                LoonLineHandler::PolicyEngine
            ),
            (
                13,
                "body_rewrite.http_request",
                LoonLineHandler::PolicyEngine
            ),
            (16, "mitm.hostname", LoonLineHandler::MitmHostnames),
        ]
    );
    let package = plugin.plugin_package("user.p1", "1.0.0").unwrap();
    assert_eq!(
        package.manifest.hooks,
        vec![HookPoint::Request, HookPoint::Response]
    );
}

#[test]
fn body_rewrite_lines_are_translated_to_url_first_rules_on_the_same_line() {
    let plugin = import_loon_plugin(FIXTURE).expect("fixture should import");
    let source = plugin.source().lines().collect::<Vec<_>>();
    assert_eq!(
        source[11],
        r#"^https?://api\.example\.com/v1/feed response-body-replace-regex "\"ad\":true" "\"ad\":false""#
    );
    assert_eq!(
        source[12],
        r"^https?://api\.example\.com/v1/report request-body-replace-regex tracking=1 tracking=0"
    );
    assert!(
        source[8].starts_with("# "),
        "mock line is moved: {}",
        source[8]
    );
    let appended = &source[FIXTURE.lines().count()..];
    assert_eq!(
        appended,
        [
            "[Map Local]",
            r#"^https?://api\.example\.com/v1/splash data-type=text data="no splash" status-code=202"#,
            "[Body Rewrite]",
            r"^https?://api\.example\.com/v1/feed response-body-replace-regex promo plain",
        ]
    );
}

#[test]
fn map_local_answers_requests_without_the_origin() {
    let plugin = import_loon_plugin(FIXTURE).expect("fixture should import");

    let outcome = plan(
        &plugin,
        &event(
            HttpMitmPhase::Request,
            "https://api.example.com/v1/ads?slot=1",
            "",
        ),
    );
    let HttpMitmAction::Respond {
        status_code,
        headers,
        body,
    } = &outcome.action
    else {
        panic!("expected a local response, got {:?}", outcome.action);
    };
    assert_eq!(*status_code, 200);
    assert_eq!(body, br#"{"ads":[]}"#);
    assert_eq!(
        header(headers, "Content-Type"),
        Some("application/json; charset=utf-8")
    );
    assert_eq!(header(headers, "Cache-Control"), Some("no-store"));
    assert!(outcome
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == MITM_POLICY_HTTP_EVENT_MAP_LOCAL_CODE));

    let pixel = plan(
        &plugin,
        &event(
            HttpMitmPhase::Request,
            "https://api.example.com/v1/pixel",
            "",
        ),
    );
    let HttpMitmAction::Respond { headers, body, .. } = &pixel.action else {
        panic!("expected a local GIF");
    };
    assert_eq!(header(headers, "Content-Type"), Some("image/gif"));
    assert!(body.starts_with(b"GIF89a"));

    let splash = plan(
        &plugin,
        &event(
            HttpMitmPhase::Request,
            "https://api.example.com/v1/splash",
            "",
        ),
    );
    assert_eq!(
        splash.action,
        HttpMitmAction::Respond {
            status_code: 202,
            headers: vec![MetadataEntry {
                key: "Content-Type".to_string(),
                value: "text/plain; charset=utf-8".to_string(),
            }],
            body: b"no splash".to_vec(),
        }
    );

    let other = plan(
        &plugin,
        &event(
            HttpMitmPhase::Request,
            "https://api.example.com/v1/feed",
            "",
        ),
    );
    assert_eq!(other.action, HttpMitmAction::Continue);
}

#[test]
fn every_replacement_pair_of_a_body_rewrite_line_applies() {
    let plugin = import_loon_plugin(FIXTURE).expect("fixture should import");

    let response = plan(
        &plugin,
        &event(
            HttpMitmPhase::Response,
            "https://api.example.com/v1/feed",
            r#"{"items":[{"ad":true,"kind":"promo"}]}"#,
        ),
    );
    assert_eq!(response.action, HttpMitmAction::Continue);
    assert_eq!(
        String::from_utf8(response.body_mutation.expect("body rewritten").body).unwrap(),
        r#"{"items":[{"ad":false,"kind":"plain"}]}"#
    );

    let request = plan(
        &plugin,
        &event(
            HttpMitmPhase::Request,
            "https://api.example.com/v1/report",
            "id=7&tracking=1",
        ),
    );
    assert_eq!(
        String::from_utf8(request.body_mutation.expect("body rewritten").body).unwrap(),
        "id=7&tracking=0"
    );
}

#[test]
fn unsupported_map_local_and_body_rewrite_lines_are_graded() {
    let plugin = import_loon_plugin(concat!(
        "#!name = P1 Edge Cases\n",
        "[Map Local]\n",
        "^https?://a\\.example\\.com/remote data=\"https://cdn.example.com/x.json\"\n",
        "^https?://a\\.example\\.com/bad data-type=base64 data=\"@@\"\n",
        "^https?://a\\.example\\.com/status status-code=99\n",
        "^https?://a\\.example\\.com/kind data-type=file data=\"x.json\"\n",
        "[Body Rewrite]\n",
        "http-response-jq ^https?://a\\.example\\.com/jq 'del(.ad)'\n",
        "http-response ^https?://a\\.example\\.com/short\n",
        "http-response-json-del ^https?://a\\.example\\.com/x ad\n",
        "^https?://a\\.example\\.com/url-first response-body-replace-regex a b\n",
        "[MITM]\n",
        "hostname = a.example.com\n",
    ))
    .expect("edge cases should import");
    let graded = plugin
        .report
        .lines
        .iter()
        .filter(|line| line.status != LoonLineStatus::Ignored)
        .map(|line| (line.reason.as_str(), line.status))
        .collect::<Vec<_>>();
    assert_eq!(
        graded,
        vec![
            ("map_local.remote_data_missing", LoonLineStatus::Unsupported),
            ("map_local.base64_invalid", LoonLineStatus::Unsupported),
            ("map_local.status_invalid", LoonLineStatus::Unsupported),
            (
                "map_local.data_type_unsupported",
                LoonLineStatus::Unsupported
            ),
            ("rewrite.jq", LoonLineStatus::Supported),
            ("body_rewrite.invalid", LoonLineStatus::Unsupported),
            ("rewrite.jq", LoonLineStatus::Supported),
            ("rewrite.response_body", LoonLineStatus::Supported),
            ("mitm.hostname", LoonLineStatus::Supported),
        ]
    );
    assert_eq!(plugin.report.level, LoonSupportLevel::Partial);
}

#[test]
fn map_local_matching_survives_a_pattern_the_core_refuses() {
    let source = concat!(
        "[Map Local]\n",
        "^https?://(unclosed data=\"broken\"\n",
        "^https?://b\\.example\\.com/ok data=\"ok\"\n",
    );
    let rule = match_map_local(source, "https://b.example.com/ok")
        .expect("matching should not fail")
        .expect("valid rule should still match");
    assert_eq!(rule.body, b"ok");
    assert!(match_map_local(source, "https://b.example.com/other")
        .unwrap()
        .is_none());
}

#[test]
fn map_local_base64_and_custom_content_type() {
    let rule = parse_map_local_line(
        "^https?://c\\.example\\.com/ data-type=base64 data=\"aGk=\" header=\"Content-Type:text/x-test\"",
    )
    .unwrap();
    assert_eq!(rule.body, b"hi");
    assert_eq!(
        rule.headers,
        vec![MetadataEntry {
            key: "Content-Type".to_string(),
            value: "text/x-test".to_string(),
        }]
    );
}

const REMOTE_RESOURCE_PLUGIN: &str = concat!(
    "#!name = Remote Resources\n",
    "[Map Local]\n",
    "^https?://a\\.example\\.com/ad data-type=json data=\"https://cdn.example.com/empty.json\"\n",
    "[Rewrite]\n",
    "^https?://a\\.example\\.com/q url echo-response text/html echo-response https://cdn.example.com/page.html\n",
    "[Script]\n",
    "http-response ^https?://a\\.example\\.com/s script-path=https://cdn.example.com/s.js, requires-body=true, tag=s\n",
    "[MITM]\n",
    "hostname = a.example.com\n",
);

#[test]
fn remote_resources_are_listed_and_map_local_data_is_inlined_when_supplied() {
    let missing = import_loon_plugin(REMOTE_RESOURCE_PLUGIN).expect("plugin should import");
    assert_eq!(
        missing.remote_resources,
        vec![
            LoonRemoteResource {
                url: "https://cdn.example.com/empty.json".to_string(),
                kind: LoonRemoteResourceKind::MapLocalData,
                line: 3,
            },
            LoonRemoteResource {
                url: "https://cdn.example.com/page.html".to_string(),
                kind: LoonRemoteResourceKind::MapLocalData,
                line: 5,
            },
            LoonRemoteResource {
                url: "https://cdn.example.com/s.js".to_string(),
                kind: LoonRemoteResourceKind::Script,
                line: 7,
            },
        ]
    );
    assert_eq!(missing.report.level, LoonSupportLevel::Partial);
    let source = merged_plugin_source("Remote", &[&missing]);
    assert!(match_map_local(&source, "https://a.example.com/ad")
        .unwrap()
        .is_none());

    let resources = BTreeMap::from([
        (
            "https://cdn.example.com/empty.json".to_string(),
            br#"{"ads":[]}"#.to_vec(),
        ),
        (
            "https://cdn.example.com/page.html".to_string(),
            b"<p>hi</p>".to_vec(),
        ),
    ]);
    let plugin = import_loon_plugin_with_resources(REMOTE_RESOURCE_PLUGIN, &resources)
        .expect("plugin should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("remote")
    );
    assert_eq!(plugin.remote_resources, missing.remote_resources);
    let source = merged_plugin_source("Remote", &[&plugin]);
    assert!(!source.contains("https://cdn.example.com/empty.json"));

    let json = match_map_local(&source, "https://a.example.com/ad")
        .unwrap()
        .expect("inlined JSON should answer");
    assert_eq!(json.body, br#"{"ads":[]}"#);
    assert!(json.headers.contains(&MetadataEntry {
        key: "Content-Type".to_string(),
        value: "application/json; charset=utf-8".to_string(),
    }));
    let html = match_map_local(&source, "https://a.example.com/q")
        .unwrap()
        .expect("QX echo-response should answer");
    assert_eq!(html.body, b"<p>hi</p>");
    assert!(html.headers.contains(&MetadataEntry {
        key: "Content-Type".to_string(),
        value: "text/html".to_string(),
    }));
}

#[test]
fn jq_body_rewrites_of_every_dialect_run_with_jaq() {
    let plugin = import_loon_plugin(concat!(
        "#!name = jq\n",
        "[Body Rewrite]\n",
        "http-response-jq ^https?://a\\.example\\.com/surge 'del(.ad) | .data.items |= map(select(.type != \"AD\"))'\n",
        "[Rewrite]\n",
        "^https?://a\\.example\\.com/loon response-body-json-jq '.vip.status = 1'\n",
        "^https?://a\\.example\\.com/qx url jsonjq-response-body '.dt = []'\n",
        "[MITM]\n",
        "hostname = a.example.com\n",
    ))
    .expect("jq rewrites should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("jq")
    );

    let cases = [
        (
            "https://a.example.com/surge",
            r#"{"ad":1,"data":{"items":[{"type":"AD"},{"type":"post"}]}}"#,
            r#"{"data":{"items":[{"type":"post"}]}}"#,
        ),
        (
            "https://a.example.com/loon",
            r#"{"vip":{"status":0}}"#,
            r#"{"vip":{"status":1}}"#,
        ),
        (
            "https://a.example.com/qx?x=1",
            r#"{"dt":[1,2],"ok":true}"#,
            r#"{"dt":[],"ok":true}"#,
        ),
    ];
    for (url, body, expected) in cases {
        let outcome = plan(&plugin, &event(HttpMitmPhase::Response, url, body));
        assert_eq!(
            String::from_utf8(
                outcome
                    .body_mutation
                    .unwrap_or_else(|| panic!("{url} should be rewritten"))
                    .body
            )
            .unwrap(),
            expected,
            "{url}"
        );
    }

    // Loon JSON edits become jq too.
    let edits = import_loon_plugin(concat!(
        "#!name = json edits\n",
        "[Rewrite]\n",
        "^https?://a\\.example\\.com/del response-body-json-del data.ad blocks[1]\n",
        "[Body Rewrite]\n",
        "http-response-json-add ^https?://a\\.example\\.com/add vip.status 1 vip.name VIP\n",
        "http-response-json-replace ^https?://a\\.example\\.com/replace a 2 missing 3\n",
        "[MITM]\n",
        "hostname = a.example.com\n",
    ))
    .expect("json edits should import");
    assert_eq!(
        edits.report.level,
        LoonSupportLevel::Full,
        "{}",
        edits.report.render_text("edits")
    );
    let cases = [
        (
            "https://a.example.com/del",
            r#"{"data":{"ad":1,"x":2},"blocks":[0,1,2]}"#,
            r#"{"data":{"x":2},"blocks":[0,2]}"#,
        ),
        (
            "https://a.example.com/add",
            r#"{"vip":{"status":0}}"#,
            r#"{"vip":{"status":1,"name":"VIP"}}"#,
        ),
        ("https://a.example.com/replace", r#"{"a":1}"#, r#"{"a":2}"#),
    ];
    for (url, body, expected) in cases {
        let outcome = plan(&edits, &event(HttpMitmPhase::Response, url, body));
        assert_eq!(
            String::from_utf8(
                outcome
                    .body_mutation
                    .unwrap_or_else(|| panic!("{url} should be rewritten"))
                    .body
            )
            .unwrap(),
            expected,
            "{url}"
        );
    }

    // Not JSON: left alone.
    let outcome = plan(
        &plugin,
        &event(
            HttpMitmPhase::Response,
            "https://a.example.com/loon",
            "<html>",
        ),
    );
    assert!(outcome.body_mutation.is_none());
}

#[test]
fn quantumult_x_header_block_rewrites_edit_headers_or_move_the_request() {
    let plugin = import_loon_plugin(concat!(
        "[rewrite_local]\n",
        "^https?://a\\.example\\.com/ua url request-header (\\r\\n)User-Agent:.+(\\r\\n) request-header $1User-Agent: Quantumult$2\n",
        "^https?://a\\.example\\.com/etag url request-header (\\r\\n)If-None-Match:.+(\\r\\n) request-header $1\n",
        "^https?://a\\.example\\.com/jda? url request-header ^(.+?\\s).+?(\\s[\\s\\S]+?Host:).+?(\\r\\n) request-header $1/jda?adblock=$2b.example.com$3\n",
        "[mitm]\n",
        "hostname = a.example.com\n",
    ))
    .expect("header-block rewrites should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("header-block")
    );
    let merged = merged_plugin_source("QX", &[&plugin]);
    assert!(merged.contains("[AnixOps Header Block]"), "{merged}");

    let request = |url: &str| HttpMitmEvent {
        headers: vec![
            MetadataEntry {
                key: "Host".to_string(),
                value: "a.example.com".to_string(),
            },
            MetadataEntry {
                key: "User-Agent".to_string(),
                value: "App/1.0".to_string(),
            },
            MetadataEntry {
                key: "If-None-Match".to_string(),
                value: "\"abc\"".to_string(),
            },
        ],
        method: Some("GET".to_string()),
        ..event(HttpMitmPhase::Request, url, "")
    };

    let ua = plan(&plugin, &request("https://a.example.com/ua"));
    let mut headers = request("https://a.example.com/ua").headers;
    for mutation in &ua.header_mutations {
        match mutation.value.as_ref() {
            Some(value) => headers.push(MetadataEntry {
                key: mutation.name.clone(),
                value: value.clone(),
            }),
            None => headers.retain(|header| !header.key.eq_ignore_ascii_case(&mutation.name)),
        }
    }
    assert_eq!(header(&headers, "User-Agent"), Some("Quantumult"));
    assert_eq!(header(&headers, "If-None-Match"), Some("\"abc\""));

    let etag = plan(&plugin, &request("https://a.example.com/etag"));
    assert!(
        etag.header_mutations
            .iter()
            .any(|mutation| mutation.name == "If-None-Match" && mutation.value.is_none()),
        "{:?}",
        etag.header_mutations
    );

    let moved = plan(&plugin, &request("https://a.example.com/jda?e=1"));
    assert_eq!(
        moved.action,
        HttpMitmAction::Redirect {
            status_code: 302,
            location: "https://b.example.com/jda?adblock=".to_string(),
        }
    );

    let untouched = plan(&plugin, &request("https://a.example.com/other"));
    assert!(untouched.header_mutations.is_empty());
    assert_eq!(untouched.action, HttpMitmAction::Continue);
}

#[test]
fn reused_engines_follow_the_policy_of_each_instance() {
    let first = import_loon_plugin(
        "#!name = First\n[Rewrite]\n^https://a\\.example\\.test/ads reject\n[MITM]\nhostname = a.example.test\n",
    )
    .expect("first plugin imports");
    let second = import_loon_plugin(
        "#!name = Second\n[Rewrite]\n^https://a\\.example\\.test/feed reject\n[MITM]\nhostname = a.example.test\n",
    )
    .expect("second plugin imports");
    let (service, first) = load(&first);
    let (_, second) = load(&second);
    let ads = event(HttpMitmPhase::Request, "https://a.example.test/ads", "");
    let feed = event(HttpMitmPhase::Request, "https://a.example.test/feed", "");

    // Alternating between two loaded policies, each plan sees only its own.
    for _ in 0..3 {
        let plan = |instance: &PluginInstance, event: &HttpMitmEvent| {
            service
                .handle_http_mitm_event(instance, event)
                .expect("event should plan")
                .action
        };
        assert_ne!(plan(&first, &ads), HttpMitmAction::Continue);
        assert_eq!(plan(&first, &feed), HttpMitmAction::Continue);
        assert_eq!(plan(&second, &ads), HttpMitmAction::Continue);
        assert!(matches!(
            plan(&second, &feed),
            HttpMitmAction::Reject { .. }
        ));
    }
}

/// The ipleak.net demo handed to users: the page shows the address from its
/// own HTML and from `ipv4|ipv6.ipleak.net/?mode=ajax` HTML fragments (bodies
/// below as the site served them on 2026-11-13, with a documentation address),
/// not from `/json/`, so a `/json`-only rule never changed what the page shows.
#[test]
fn ipleak_demo_rewrites_the_address_the_page_shows() {
    let plugin = import_loon_plugin(include_str!("fixtures/loon-plugins/ipleak-demo.sgmodule"))
        .expect("ipleak demo should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("ipleak-demo")
    );
    assert_eq!(
        plugin.mitm_hostnames.include,
        vec!["ipleak.net".to_string(), "*.ipleak.net".to_string()]
    );

    // Load it the way the packet tunnel does: merged, with `[MITM] enable = true`.
    let package = PluginPackage {
        manifest: PluginManifest {
            id: "user.ipleak-demo".to_string(),
            version: "1".to_string(),
            permissions: vec![
                PluginPermission::ReadRequest,
                PluginPermission::ModifyRequest,
                PluginPermission::ReadResponse,
                PluginPermission::ModifyResponse,
            ],
            hooks: vec![HookPoint::Request, HookPoint::Response],
        },
        source: merged_plugin_source("ipleak demo", &[&plugin]),
    };
    let service = AnixOpsMitmPluginService::new();
    let instance = service
        .load(
            &package,
            &GrantedPermissions {
                permissions: package.manifest.permissions.clone(),
            },
        )
        .expect("merged policy should load");
    for host in ["ipleak.net", "ipv4.ipleak.net", "ipv6.ipleak.net"] {
        assert_eq!(
            service
                .evaluate_mitm_hostname(&instance, host, false)
                .expect("hostname should evaluate"),
            MitmHostnameDecision::Intercept,
            "{host}"
        );
    }

    let rewrite = |url: &str, body: &str| -> Option<String> {
        let mut response = event(HttpMitmPhase::Response, url, body);
        response.method = Some("GET".to_string());
        let outcome = service
            .handle_http_mitm_event(&instance, &response)
            .expect("event should plan");
        outcome
            .body_mutation
            .map(|mutation| String::from_utf8(mutation.body).unwrap())
    };

    let fragment = "<div class='ip_box ipv4_box' data-h='ipv4' data-i='203_0_113_7'><div><a data-tooltip='Click for more details about this IP' class='ip' rel='nofollow' href='/203.0.113.7'>203.0.113.7</a></div><div class='ip_stats'></div></div>";
    let rewritten = rewrite("https://ipv4.ipleak.net/?mode=ajax&_=1794586992", fragment)
        .expect("ajax fragment should be rewritten");
    assert!(rewritten.contains(">233.333.333.333</a>"), "{rewritten}");
    assert!(!rewritten.contains("203.0.113.7"), "{rewritten}");

    let page = "<script src=\"/static/js/jquery-4.0.0.min.js\"></script><div id='jsonData' data-json='{&quot;ip&quot;:&quot;203.0.113.7&quot;,&quot;latitude&quot;:37.751}'></div><table class='properties details'><tr data-tooltip=''><td>IP: </td><td>203.0.113.7</td></tr></table>";
    let rewritten = rewrite("https://ipleak.net/", page).expect("main page should be rewritten");
    assert!(
        rewritten.contains("<td>IP: </td><td>233.333.333.333</td>"),
        "{rewritten}"
    );
    assert!(
        rewritten.contains("&quot;ip&quot;:&quot;233.333.333.333&quot;"),
        "{rewritten}"
    );
    assert!(rewritten.contains("jquery-4.0.0.min.js"), "{rewritten}");
    assert!(rewritten.contains("37.751"), "{rewritten}");

    let json = rewrite(
        "https://ipleak.net/json/",
        r#"{"country_code":"US","ip":"203.0.113.7"}"#,
    )
    .expect("json should be rewritten");
    assert_eq!(json, r#"{"country_code":"US","ip":"233.333.333.333"}"#);

    // Scripts and lookups of other addresses are left alone.
    assert_eq!(
        rewrite(
            "https://ipleak.net/static/js/index.js",
            "var a = '1.2.3.4';"
        ),
        None
    );
    assert_eq!(
        rewrite("https://ipleak.net/json/8.8.8.8", r#"{"ip":"8.8.8.8"}"#),
        None
    );
}
