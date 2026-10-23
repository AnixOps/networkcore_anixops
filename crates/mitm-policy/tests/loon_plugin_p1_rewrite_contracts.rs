//! Loon P1 `[Map Local]` and `[Body Rewrite]`: grading, translation for the
//! policy core, and the outcomes the plugin service plans from them.

use control_domain::{
    GrantedPermissions, HookPoint, HttpMitmAction, HttpMitmEvent, HttpMitmOutcome, HttpMitmPhase,
    MetadataEntry, MitmPluginService, PluginInstance,
};
use mitm_policy::loon_map_local::{match_map_local, parse_map_local_line};
use mitm_policy::loon_plugin::{
    import_loon_plugin, LoonLineHandler, LoonLineStatus, LoonPluginImport, LoonSupportLevel,
};
use mitm_policy::{AnixOpsMitmPluginService, MITM_POLICY_HTTP_EVENT_MAP_LOCAL_CODE};

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
            (
                "map_local.remote_data_unsupported",
                LoonLineStatus::Unsupported
            ),
            ("map_local.base64_invalid", LoonLineStatus::Unsupported),
            ("map_local.status_invalid", LoonLineStatus::Unsupported),
            (
                "map_local.data_type_unsupported",
                LoonLineStatus::Unsupported
            ),
            ("body_rewrite.jq_unavailable", LoonLineStatus::Unsupported),
            ("body_rewrite.invalid", LoonLineStatus::Unsupported),
            ("body_rewrite.type_unsupported", LoonLineStatus::Unsupported),
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
