use config_core::routing::{
    PolicyTarget, RouteOutcome, RouteQuery, RoutingModel, RoutingSpec, RuleMatcher,
    StaticRoutingEnvironment,
};
use control_domain::{
    CertificateTrustState, GrantedPermissions, HookPoint, MitmPluginService, PluginPermission,
};
use mitm_policy::loon_plugin::{
    import_loon_plugin, merged_plugin_source, routing_model_with_plugin_rules, LoonLineHandler,
    LoonLineStatus, LoonSupportLevel, LOON_PLUGIN_EMPTY_CODE, LOON_PLUGIN_ID_INVALID_CODE,
    LOON_PLUGIN_MAX_BYTES, LOON_PLUGIN_TOO_LARGE_CODE,
};
use mitm_policy::{
    AnixOpsMitmPluginService, AnixOpsMitmPolicyEngine, MitmPolicyMitmDecisionType, MitmPolicyPhase,
    MitmPolicyRewriteAction,
};
use std::collections::BTreeSet;
use std::path::Path;

const FULL_FIXTURE: &str = include_str!("fixtures/loon-plugins/p0-full-ad-block.plugin");
const PARTIAL_FIXTURE: &str = include_str!("fixtures/loon-plugins/p0-partial-mixed.plugin");
const SCRIPT_ONLY_FIXTURE: &str = include_str!("fixtures/loon-plugins/p1-script-only.plugin");

#[test]
fn full_p0_plugin_imports_metadata_hostnames_rules_and_rewrites() {
    let plugin = import_loon_plugin(FULL_FIXTURE).expect("P0 plugin should import");

    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("p0-full-ad-block")
    );
    assert_eq!(plugin.report.policy_load_error, None);
    assert_eq!(plugin.metadata.name.as_deref(), Some("Example Ad Block"));
    assert_eq!(
        plugin.metadata.desc.as_deref(),
        Some("Rejects ad endpoints on example hosts")
    );
    assert_eq!(plugin.metadata.author.as_deref(), Some("NetworkCore"));
    assert_eq!(plugin.metadata.category.as_deref(), Some("Ad Block"));
    assert_eq!(
        plugin.metadata.arguments,
        vec![("Mode".to_string(), "strict".to_string())]
    );

    assert_eq!(
        plugin.mitm_hostnames.include,
        vec!["api.example.com".to_string(), "old.example.com".to_string()]
    );
    assert_eq!(
        plugin.mitm_hostnames.exclude,
        vec!["login.example.com".to_string()]
    );

    let rules = plugin.routing_rules();
    assert_eq!(rules.len(), 4);
    assert_eq!(
        rules[0].matcher,
        RuleMatcher::Domain("ads.example.com".to_string())
    );
    assert_eq!(rules[0].target, PolicyTarget::Reject);
    assert_eq!(
        rules[1].matcher,
        RuleMatcher::DomainSuffix("tracker.example.net".to_string())
    );
    assert_eq!(rules[1].target, PolicyTarget::Reject);
    assert!(matches!(rules[2].matcher, RuleMatcher::IpCidr(_)));
    assert_eq!(rules[2].target, PolicyTarget::Reject);
    assert!(rules[2].no_resolve);
    assert_eq!(rules[3].target, PolicyTarget::Direct);
}

#[test]
fn full_p0_plugin_rewrites_evaluate_through_the_policy_core() {
    let plugin = import_loon_plugin(FULL_FIXTURE).expect("P0 plugin should import");
    let mut engine = AnixOpsMitmPolicyEngine::new().expect("policy engine should allocate");
    engine
        .load_config(plugin.source())
        .expect("imported plugin source should load");

    let reject = engine
        .evaluate_url_rewrite("https://api.example.com/v1/ad", MitmPolicyPhase::Request)
        .expect("reject rewrite should evaluate");
    assert_eq!(reject.action, MitmPolicyRewriteAction::Reject);

    let redirect = engine
        .evaluate_url_rewrite("https://old.example.com/path", MitmPolicyPhase::Request)
        .expect("redirect rewrite should evaluate");
    assert_eq!(redirect.action, MitmPolicyRewriteAction::Redirect);
    assert_eq!(redirect.status_code, 302);
    assert_eq!(redirect.value, "https://new.example.com/path");
}

#[test]
fn imported_plugin_package_declares_only_the_phases_it_rewrites_and_loads() {
    let full = import_loon_plugin(FULL_FIXTURE).expect("P0 plugin should import");
    let package = full
        .plugin_package("user.example-ad-block", "1.0.0")
        .expect("package should build");
    assert_eq!(package.manifest.id, "user.example-ad-block");
    assert_eq!(
        package.manifest.hooks,
        vec![HookPoint::Request, HookPoint::Response]
    );
    let instance = AnixOpsMitmPluginService::new()
        .load(
            &package,
            &GrantedPermissions {
                permissions: package.manifest.permissions.clone(),
            },
        )
        .expect("imported plugin should load through the plugin service");
    assert_eq!(instance.manifest.id, "user.example-ad-block");

    let request_only = import_loon_plugin(concat!(
        "#!name = Request Only\n",
        "[Rewrite]\n",
        "^https?://api\\.example\\.com/ad reject\n",
        "[MITM]\n",
        "hostname = api.example.com\n",
    ))
    .expect("request-only plugin should import");
    let package = request_only
        .plugin_package("user.request-only", "1.0.0")
        .expect("package should build");
    assert_eq!(package.manifest.hooks, vec![HookPoint::Request]);
    assert_eq!(
        package.manifest.permissions,
        vec![
            PluginPermission::ReadRequest,
            PluginPermission::ModifyRequest
        ]
    );

    for invalid in ["", "  ", "user plugin", "user/plugin"] {
        let error = request_only
            .plugin_package(invalid, "1.0.0")
            .expect_err("invalid plugin id should be refused");
        assert_eq!(error.code, LOON_PLUGIN_ID_INVALID_CODE);
    }
}

#[test]
fn plugin_hostnames_append_to_the_existing_list_and_keep_exclusions() {
    let plugin = import_loon_plugin(FULL_FIXTURE).expect("P0 plugin should import");
    let merged = plugin.mitm_hostnames.apply(&[
        "login.example.com".to_string(),
        "user.example.com".to_string(),
        "API.example.com".to_string(),
    ]);
    assert_eq!(
        merged,
        vec![
            "user.example.com".to_string(),
            "API.example.com".to_string(),
            "old.example.com".to_string(),
            "-login.example.com".to_string(),
        ]
    );
}

#[test]
fn plugin_rules_run_before_user_rules_in_the_routing_model() {
    let plugin = import_loon_plugin(FULL_FIXTURE).expect("P0 plugin should import");
    let model = RoutingModel::from_spec(
        &RoutingSpec {
            rules: vec![
                "DOMAIN-SUFFIX,example.com,node-a".to_string(),
                "FINAL,DIRECT".to_string(),
            ],
            groups: Vec::new(),
        },
        &BTreeSet::from(["node-a".to_string()]),
    )
    .expect("user routing should validate");

    let merged = routing_model_with_plugin_rules(&model, &[&plugin]);
    assert_eq!(merged.rules.len(), model.rules.len() + 4);
    assert_eq!(merged.final_target, model.final_target);

    let environment = StaticRoutingEnvironment;
    let blocked = merged.decide(&RouteQuery::domain("ads.example.com"), &environment);
    assert_eq!(blocked.outcome, RouteOutcome::Reject);
    let user = merged.decide(&RouteQuery::domain("www.example.com"), &environment);
    assert_eq!(user.outcome, RouteOutcome::Node("node-a".to_string()));
    let blocked_ip = merged.decide(
        &RouteQuery::ip("203.0.113.9".parse().expect("test address should parse")),
        &environment,
    );
    assert_eq!(blocked_ip.outcome, RouteOutcome::Reject);
}

#[test]
fn mixed_plugin_reports_partial_deferred_and_unsupported_lines() {
    let plugin = import_loon_plugin(PARTIAL_FIXTURE).expect("mixed plugin should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Partial,
        "{}",
        plugin.report.render_text("p0-partial-mixed")
    );

    let status_of = |reason: &str| {
        plugin
            .report
            .lines
            .iter()
            .find(|line| line.reason == reason)
            .map(|line| line.status)
    };
    assert_eq!(status_of("rule.routing"), Some(LoonLineStatus::Supported));
    assert_eq!(
        status_of("rule.policy_unsupported"),
        Some(LoonLineStatus::Unsupported)
    );
    assert_eq!(status_of("rewrite.reject"), Some(LoonLineStatus::Supported));
    assert_eq!(
        status_of("rewrite.response_body"),
        Some(LoonLineStatus::Supported)
    );
    assert_eq!(
        status_of("script.http_response"),
        Some(LoonLineStatus::Supported)
    );
    assert_eq!(
        status_of("mitm.skip_server_cert_verify_refused"),
        Some(LoonLineStatus::Unsupported)
    );
    let rules = plugin.routing_rules();
    assert_eq!(
        rules.len(),
        1,
        "PROXY rules must not enter the routing model"
    );
    assert_eq!(
        rules[0].matcher,
        RuleMatcher::DomainKeyword("adtrack".to_string())
    );
    assert_eq!(rules[0].target, PolicyTarget::Reject);

    let text = plugin.report.render_text("p0-partial-mixed");
    assert!(text.starts_with("p0-partial-mixed: partial"));
    assert!(text.contains("rule.policy_unsupported"));
}

#[test]
fn script_only_plugin_is_supported_by_the_p1_script_runtime() {
    let plugin = import_loon_plugin(SCRIPT_ONLY_FIXTURE).expect("script plugin should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("p1-script-only")
    );
    let script = plugin
        .report
        .lines
        .iter()
        .find(|line| line.reason == "script.http_request")
        .expect("http-request script line should be graded");
    assert_eq!(script.handler, LoonLineHandler::ScriptRuntime);

    let package = plugin
        .plugin_package("example.sign", "1.0.0")
        .expect("script plugin should build a package");
    assert_eq!(package.manifest.hooks, vec![HookPoint::Request]);
}

#[test]
fn script_lines_without_an_http_runtime_are_graded() {
    let plugin = import_loon_plugin(concat!(
        "#!name = Script Kinds\n",
        "[Script]\n",
        "http-response ^https?://api\\.example\\.com/feed script-path=https://scripts.example.com/feed.js, requires-body=true, binary-body-mode=true, tag=feed\n",
        "cron \"0 8 * * *\" script-path=https://scripts.example.com/checkin.js, tag=checkin\n",
        "http-request ^https?://api\\.example\\.com/sign tag=missing-path\n",
        "[MITM]\n",
        "hostname = api.example.com\n",
    ))
    .expect("script kinds should import");
    let reasons = plugin
        .report
        .lines
        .iter()
        .filter(|line| line.section == "Script")
        .map(|line| (line.reason.as_str(), line.status))
        .collect::<Vec<_>>();
    assert_eq!(
        reasons,
        vec![
            ("script.binary_body_unsupported", LoonLineStatus::Partial),
            ("script.type_unsupported", LoonLineStatus::Unsupported),
            ("script.path_missing", LoonLineStatus::Unsupported),
        ]
    );
    assert_eq!(plugin.report.level, LoonSupportLevel::Partial);
}

#[test]
fn plugin_refused_by_the_policy_core_is_unsupported_as_a_whole() {
    let plugin = import_loon_plugin(concat!(
        "#!name = Broken Regex\n",
        "[Rewrite]\n",
        "^https?://(unclosed reject\n",
        "[MITM]\n",
        "hostname = api.example.com\n",
    ))
    .expect("import reports refusal instead of failing");
    assert_eq!(plugin.report.level, LoonSupportLevel::Unsupported);
    assert!(plugin.report.policy_load_error.is_some());
    assert!(plugin
        .report
        .render_text("broken")
        .contains("policy core refused the plugin"));
}

#[test]
fn empty_and_oversized_plugins_are_refused() {
    let error = import_loon_plugin(" \n\n").expect_err("empty plugin should be refused");
    assert_eq!(error.code, LOON_PLUGIN_EMPTY_CODE);

    let oversized = format!("#!name = Big\n{}", "#".repeat(LOON_PLUGIN_MAX_BYTES));
    let error = import_loon_plugin(&oversized).expect_err("oversized plugin should be refused");
    assert_eq!(error.code, LOON_PLUGIN_TOO_LARGE_CODE);
}

/// Grades every plugin in the corpus and prints the report to the CI log.
#[test]
fn loon_plugin_corpus_matches_expected_support_levels() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/loon-plugins");
    let expected = std::fs::read_to_string(corpus.join("expected-levels.txt"))
        .expect("corpus expectations should be readable");

    let mut graded = 0;
    for line in expected.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (file, level) = line
            .split_once(' ')
            .expect("expectation lines are `file level`");
        let text = std::fs::read_to_string(corpus.join(file)).expect("corpus plugin should read");
        let plugin = import_loon_plugin(&text).expect("corpus plugin should import");
        println!("{}", plugin.report.render_text(file));
        assert_eq!(
            plugin.report.level.as_str(),
            level.trim(),
            "{}",
            plugin.report.render_text(file)
        );
        graded += 1;
    }

    let plugin_files = std::fs::read_dir(&corpus)
        .expect("corpus directory should list")
        .filter_map(Result::ok)
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "plugin"))
        .count();
    assert_eq!(
        graded, plugin_files,
        "every corpus plugin needs an expected level"
    );
}

#[test]
fn merged_plugins_load_as_one_policy_with_combined_rewrites_and_hosts() {
    let full = import_loon_plugin(FULL_FIXTURE).expect("P0 plugin should import");
    let second = import_loon_plugin(
        "#!name = Second\n\
         [Rewrite]\n\
         ^https?://cdn\\.example\\.org/ads/ reject\n\
         [MITM]\n\
         hostname = cdn.example.org, login.example.com\n",
    )
    .expect("second plugin should import");
    let merged = merged_plugin_source("Merged", &[&full, &second]);

    assert_eq!(merged.matches("[Rewrite]").count(), 1, "{merged}");
    assert!(!merged.contains("[Rule]"), "{merged}");
    assert!(
        merged.contains(
            "hostname = api.example.com, old.example.com, -login.example.com, cdn.example.org"
        ),
        "a later plugin cannot re-enable an excluded host: {merged}"
    );

    let mut engine = AnixOpsMitmPolicyEngine::new().expect("policy engine should allocate");
    engine
        .load_config(&merged)
        .expect("merged source should load");
    for url in [
        "https://api.example.com/v1/ad",
        "https://cdn.example.org/ads/banner.js",
    ] {
        let result = engine
            .evaluate_url_rewrite(url, MitmPolicyPhase::Request)
            .expect("rewrite should evaluate");
        assert_eq!(result.action, MitmPolicyRewriteAction::Reject, "{url}");
    }
    engine.set_certificate_trust_state(CertificateTrustState::Trusted);
    for (host, expected) in [
        ("cdn.example.org", MitmPolicyMitmDecisionType::Intercept),
        ("api.example.com", MitmPolicyMitmDecisionType::Intercept),
        ("login.example.com", MitmPolicyMitmDecisionType::Bypass),
    ] {
        let decision = engine
            .evaluate_mitm(host, false)
            .expect("host decision should evaluate");
        assert_eq!(decision.decision, expected, "{host}");
    }

    let empty = merged_plugin_source("Nothing", &[]);
    assert!(!empty.contains("[MITM]"), "{empty}");
}
