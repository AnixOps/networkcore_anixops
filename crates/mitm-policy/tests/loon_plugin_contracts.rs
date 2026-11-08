use config_core::routing::{
    PolicyGroupSpec, PolicyTarget, RouteOutcome, RouteQuery, RoutingModel, RoutingSpec,
    RuleMatcher, StaticRoutingEnvironment,
};
use control_domain::{
    CertificateTrustState, GrantedPermissions, HookPoint, MitmPluginService, PluginPermission,
};
use mitm_policy::loon_plugin::{
    import_loon_plugin, merged_plugin_source, routing_model_with_plugin_rules, LoonLineHandler,
    LoonLineStatus, LoonScheduledTrigger, LoonSupportLevel, LOON_PLUGIN_EMPTY_CODE,
    LOON_PLUGIN_ID_INVALID_CODE, LOON_PLUGIN_MAX_BYTES, LOON_PLUGIN_TOO_LARGE_CODE,
};
use mitm_policy::{
    AnixOpsMitmPluginService, AnixOpsMitmPolicyEngine, MitmPolicyMitmDecisionType, MitmPolicyPhase,
    MitmPolicyRewriteAction, MitmPolicyScriptKind,
};
use std::collections::BTreeSet;
use std::path::Path;

const FULL_FIXTURE: &str = include_str!("fixtures/loon-plugins/p0-full-ad-block.plugin");
const PARTIAL_FIXTURE: &str = include_str!("fixtures/loon-plugins/p0-partial-mixed.plugin");
const SCRIPT_ONLY_FIXTURE: &str = include_str!("fixtures/loon-plugins/p1-script-only.plugin");
const QX_REWRITE_FIXTURE: &str = include_str!("fixtures/loon-plugins/qx-rewrite-local.snippet");
const QX_HEADERLESS_FIXTURE: &str = include_str!("fixtures/loon-plugins/qx-headerless.snippet");
const QX_MIXED_FIXTURE: &str = include_str!("fixtures/loon-plugins/qx-mixed.snippet");
const SURGE_MODULE_FIXTURE: &str = include_str!("fixtures/loon-plugins/surge-module.sgmodule");

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
        status_of("rule.routing_policy"),
        Some(LoonLineStatus::Supported)
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
    assert_eq!(rules.len(), 2);
    assert_eq!(
        rules[0].matcher,
        RuleMatcher::DomainKeyword("adtrack".to_string())
    );
    assert_eq!(rules[0].target, PolicyTarget::Reject);
    // PROXY names the user's proxy; it resolves when joining the model.
    assert_eq!(rules[1].target, PolicyTarget::Group("PROXY".to_string()));

    let text = plugin.report.render_text("p0-partial-mixed");
    assert!(text.starts_with("p0-partial-mixed: partial"));
    assert!(text.contains("mitm.skip_server_cert_verify_refused"));
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
            ("script.http_response", LoonLineStatus::Supported),
            ("script.type_unsupported", LoonLineStatus::Unsupported),
            ("script.path_missing", LoonLineStatus::Unsupported),
        ]
    );
    assert_eq!(plugin.report.level, LoonSupportLevel::Partial);

    let feed = loaded_engine(plugin.source())
        .evaluate_script("https://api.example.com/feed", MitmPolicyPhase::Response)
        .expect("binary script should evaluate");
    assert_eq!(feed.kind, MitmPolicyScriptKind::HttpResponse);
    assert!(feed.binary_body_mode);
    assert!(feed.requires_body);
}

#[test]
fn line_refused_by_the_policy_core_is_dropped_not_the_whole_plugin() {
    let plugin = import_loon_plugin(concat!(
        "#!name = Broken Regex\n",
        "[Rewrite]\n",
        "^https?://(unclosed reject\n",
        "^https?://ads\\.example\\.com/ reject\n",
        "[MITM]\n",
        "hostname = api.example.com\n",
    ))
    .expect("import reports refusal instead of failing");
    assert_eq!(plugin.report.policy_load_error, None);
    assert_eq!(plugin.report.level, LoonSupportLevel::Partial);
    let broken = plugin
        .report
        .lines
        .iter()
        .find(|line| line.line == 3)
        .expect("the refused line is reported");
    assert_eq!(broken.status, LoonLineStatus::Unsupported);
    assert!(plugin.source().contains("# ^https?://(unclosed reject"));
    assert!(plugin
        .source()
        .lines()
        .any(|line| line == "^https?://ads\\.example\\.com/ reject"));
    // The cleaned source loads as it is.
    AnixOpsMitmPolicyEngine::new()
        .expect("engine")
        .load_config(plugin.source())
        .expect("the source without the refused line loads");
}

#[test]
fn glob_hostnames_are_kept_and_malformed_ones_left_out() {
    let plugin = import_loon_plugin(concat!(
        "#!name = Glob Hosts\n",
        "[Rewrite]\n",
        "^https?://spclient\\.wg\\.spotify\\.com/ads reject\n",
        "[MITM]\n",
        "hostname = %APPEND% spclient.wg.spotify.com, *spclient.spotify.com, *.flyert.*, ad?.example.com, -redirector*.googlevideo.com\n",
    ))
    .expect("plugin imports");
    assert_eq!(plugin.report.policy_load_error, None);
    assert_eq!(
        plugin.mitm_hostnames.include,
        vec![
            "spclient.wg.spotify.com",
            "*spclient.spotify.com",
            "*.flyert.*",
            "ad?.example.com"
        ]
    );
    assert_eq!(
        plugin.mitm_hostnames.exclude,
        vec!["redirector*.googlevideo.com"]
    );
    let hostname = plugin
        .report
        .lines
        .iter()
        .find(|line| line.line == 5)
        .expect("hostname line is reported");
    assert_eq!(hostname.status, LoonLineStatus::Supported);
    assert_eq!(plugin.report.level, LoonSupportLevel::Full);
    // The policy core reads the glob hosts as they are.
    AnixOpsMitmPolicyEngine::new()
        .expect("engine")
        .load_config(plugin.source())
        .expect("glob hostnames load in the policy core");

    // Globs the core cannot read are left out of an include list.
    let malformed = import_loon_plugin(concat!(
        "[Rewrite]\n",
        "^https?://a\\.example\\.com/ads reject\n",
        "[MITM]\n",
        "hostname = a.example.com, **, a*..example.com, ad*.exa/mple.com, a-zA-Z0-9_-.admobile.top\n",
    ))
    .expect("plugin imports");
    assert_eq!(malformed.mitm_hostnames.include, vec!["a.example.com"]);
    let line = malformed
        .report
        .lines
        .iter()
        .find(|line| line.line == 4)
        .expect("hostname line is reported");
    assert_eq!(line.status, LoonLineStatus::Partial);
    assert_eq!(line.reason, "mitm.hostname_pattern_unsupported");
    assert!(malformed
        .source()
        .lines()
        .any(|line| line == "hostname = a.example.com"));

    // Items no host name can have lose nothing: the line stays supported.
    let dead = import_loon_plugin(concat!(
        "[Rewrite]\n",
        "^https?://a\\.example\\.com/ads reject\n",
        "[MITM]\n",
        "hostname = a.example.com, a-zA-Z0-9_-.admobile.top, cupid.51job*.comhostname = img.example.com\n",
    ))
    .expect("plugin imports");
    assert_eq!(dead.mitm_hostnames.include, vec!["a.example.com"]);
    assert_eq!(dead.report.level, LoonSupportLevel::Full);
    assert!(dead
        .report
        .lines
        .iter()
        .any(|line| line.reason == "mitm.hostname_dead_items_dropped"));

    // An exclusion the core cannot read would widen decryption: drop the line.
    let excluded = import_loon_plugin(concat!(
        "[Rewrite]\n",
        "^https?://a\\.example\\.com/ads reject\n",
        "[MITM]\n",
        "hostname = *.example.com, -**\n",
    ))
    .expect("plugin imports");
    assert!(excluded.mitm_hostnames.include.is_empty());
    let line = excluded
        .report
        .lines
        .iter()
        .find(|line| line.line == 4)
        .expect("hostname line is reported");
    assert_eq!(line.status, LoonLineStatus::Unsupported);
    assert!(excluded.source().contains("# hostname = *.example.com"));
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
        .filter(|entry| {
            entry.path().extension().is_some_and(|ext| {
                matches!(
                    ext.to_str(),
                    Some("plugin" | "sgmodule" | "snippet" | "conf")
                )
            })
        })
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

fn loaded_engine(source: &str) -> AnixOpsMitmPolicyEngine {
    let mut engine = AnixOpsMitmPolicyEngine::new().expect("policy engine should allocate");
    engine
        .load_config(source)
        .expect("translated plugin source should load");
    engine
}

#[test]
fn quantumult_x_rewrite_local_translates_to_core_rules_and_scripts() {
    let plugin = import_loon_plugin(QX_REWRITE_FIXTURE).expect("QX snippet should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("qx-rewrite-local")
    );
    assert_eq!(
        plugin.mitm_hostnames.include,
        vec!["api.qx.example.com", "old.qx.example.com"]
    );

    for source in [
        plugin.source().to_string(),
        merged_plugin_source("QX", &[&plugin]),
    ] {
        let engine = loaded_engine(&source);
        let reject = engine
            .evaluate_url_rewrite("https://api.qx.example.com/ad", MitmPolicyPhase::Request)
            .expect("reject should evaluate");
        assert_eq!(reject.action, MitmPolicyRewriteAction::Reject, "{source}");

        let redirect = engine
            .evaluate_url_rewrite("https://old.qx.example.com/a/b", MitmPolicyPhase::Request)
            .expect("redirect should evaluate");
        assert_eq!(
            redirect.action,
            MitmPolicyRewriteAction::Redirect,
            "{source}"
        );
        assert_eq!(redirect.value, "https://new.qx.example.com/a/b");

        let feed = engine
            .evaluate_script("https://api.qx.example.com/feed", MitmPolicyPhase::Response)
            .expect("response script should evaluate");
        assert_eq!(feed.kind, MitmPolicyScriptKind::HttpResponse, "{source}");
        assert!(feed.requires_body);
        assert_eq!(feed.script_path, "https://scripts.example.com/qx-feed.js");

        let sign = engine
            .evaluate_script("https://api.qx.example.com/sign", MitmPolicyPhase::Request)
            .expect("request script should evaluate");
        assert_eq!(sign.kind, MitmPolicyScriptKind::HttpRequest, "{source}");
        assert!(!sign.requires_body);

        let (body, _) = engine
            .apply_body_chain(
                "https://api.qx.example.com/config",
                MitmPolicyPhase::Response,
                "{ads_enabled=1}",
            )
            .expect("body rewrite should apply");
        assert_eq!(body, "{ads_enabled=0}", "{source}");
    }

    let package = plugin
        .plugin_package("qx.rewrite", "1")
        .expect("QX snippet should build a package");
    assert_eq!(
        package.manifest.hooks,
        vec![HookPoint::Request, HookPoint::Response]
    );
}

#[test]
fn quantumult_x_snippet_without_section_headers_is_read_as_rewrite_and_mitm() {
    let plugin =
        import_loon_plugin(QX_HEADERLESS_FIXTURE).expect("headerless snippet should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("qx-headerless")
    );
    assert_eq!(plugin.mitm_hostnames.include, vec!["m.qx.example.com"]);

    let engine = loaded_engine(&merged_plugin_source("QX", &[&plugin]));
    let reject = engine
        .evaluate_url_rewrite("https://m.qx.example.com/splash", MitmPolicyPhase::Request)
        .expect("reject should evaluate");
    assert_eq!(reject.action, MitmPolicyRewriteAction::Reject);
    let home = engine
        .evaluate_script("https://m.qx.example.com/home", MitmPolicyPhase::Response)
        .expect("script should evaluate");
    assert_eq!(home.kind, MitmPolicyScriptKind::HttpResponse);
    assert_eq!(home.script_path, "https://scripts.example.com/qx-home.js");
}

#[test]
fn quantumult_x_lines_are_graded_and_left_out_of_the_core() {
    let plugin = import_loon_plugin(QX_MIXED_FIXTURE).expect("mixed snippet should import");
    let reasons = plugin
        .report
        .lines
        .iter()
        .filter(|line| line.status != LoonLineStatus::Ignored)
        .map(|line| (line.reason.as_str(), line.status))
        .collect::<Vec<_>>();
    assert_eq!(
        reasons,
        vec![
            ("rewrite.reject", LoonLineStatus::Supported),
            ("map_local.remote_data_missing", LoonLineStatus::Unsupported),
            ("rewrite.header_block", LoonLineStatus::Supported),
            ("script.cron", LoonLineStatus::Supported),
            ("mitm.hostname", LoonLineStatus::Supported),
        ],
        "{}",
        plugin.report.render_text("qx-mixed")
    );
    assert_eq!(plugin.report.level, LoonSupportLevel::Partial);

    // The echo-response URL must never be served as a literal body.
    let engine = loaded_engine(plugin.source());
    let echo = engine
        .evaluate_url_rewrite("https://x.qx.example.com/b", MitmPolicyPhase::Request)
        .expect("echo line should evaluate");
    assert_eq!(echo.action, MitmPolicyRewriteAction::None);
}

#[test]
fn surge_module_rewrites_headers_and_scripts_are_supported() {
    let plugin = import_loon_plugin(SURGE_MODULE_FIXTURE).expect("Surge module should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("surge-module")
    );
    assert_eq!(
        plugin.metadata.arguments,
        vec![("mode".to_string(), "clean".to_string())]
    );
    let header_reasons = plugin
        .report
        .lines
        .iter()
        .filter(|line| line.section == "Header Rewrite")
        .map(|line| line.reason.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        header_reasons,
        vec!["rewrite.request_header", "rewrite.response_header"]
    );

    let engine = loaded_engine(&merged_plugin_source("Surge", &[&plugin]));
    let reject = engine
        .evaluate_url_rewrite("https://ad.surge.example.com/x", MitmPolicyPhase::Request)
        .expect("reject should evaluate");
    assert_eq!(reject.action, MitmPolicyRewriteAction::Reject);
    let redirect = engine
        .evaluate_url_rewrite("https://old.surge.example.com/p", MitmPolicyPhase::Request)
        .expect("redirect should evaluate");
    assert_eq!(redirect.action, MitmPolicyRewriteAction::Redirect);
    assert_eq!(redirect.status_code, 302);
    assert_eq!(redirect.value, "https://new.surge.example.com/p");
    let feed = engine
        .evaluate_script(
            "https://api.surge.example.com/feed",
            MitmPolicyPhase::Response,
        )
        .expect("script should evaluate");
    assert_eq!(feed.kind, MitmPolicyScriptKind::HttpResponse);
    assert!(feed.requires_body);
}

#[test]
fn plugin_policy_names_resolve_to_a_user_group_or_the_proxy_fallback() {
    let plugin = import_loon_plugin(concat!(
        "#!name = Policies\n",
        "[Rule]\n",
        "DOMAIN,proxied.example.com,PROXY\n",
        "DOMAIN,streaming.example.com,Streaming\n",
        "DOMAIN-SUFFIX,direct.example.com,DIRECT\n",
    ))
    .expect("policy rules should import");
    assert_eq!(plugin.report.level, LoonSupportLevel::Full);

    let spec = |rules: &[&str], groups: Vec<PolicyGroupSpec>| RoutingSpec {
        rules: rules.iter().map(|rule| rule.to_string()).collect(),
        groups,
    };
    let group = |id: &str| PolicyGroupSpec {
        id: id.to_string(),
        kind: "select".to_string(),
        members: vec!["node-a".to_string()],
        default: None,
        url: None,
        interval_secs: None,
        tolerance_ms: None,
    };
    let nodes = BTreeSet::from(["node-a".to_string()]);
    let environment = StaticRoutingEnvironment;

    let model = RoutingModel::from_spec(
        &spec(&["FINAL,Proxy"], vec![group("Proxy"), group("Streaming")]),
        &nodes,
    )
    .expect("user routing should validate");
    let merged = routing_model_with_plugin_rules(&model, &[&plugin]);
    assert_eq!(
        merged.rules[0].target,
        PolicyTarget::Group("Proxy".to_string())
    );
    assert_eq!(
        merged.rules[1].target,
        PolicyTarget::Group("Streaming".to_string())
    );
    assert_eq!(merged.rules[2].target, PolicyTarget::Direct);
    let direct = merged.decide(&RouteQuery::domain("a.direct.example.com"), &environment);
    assert_eq!(direct.outcome, RouteOutcome::Direct);

    // With a DIRECT FINAL and no groups there is no proxy to name.
    let bare = RoutingModel::from_spec(&spec(&["FINAL,DIRECT"], vec![]), &nodes)
        .expect("user routing should validate");
    let merged = routing_model_with_plugin_rules(&bare, &[&plugin]);
    assert_eq!(merged.rules.len(), 1, "{:?}", merged.rules);
    assert_eq!(merged.rules[0].target, PolicyTarget::Direct);
}

#[test]
fn surge_module_arguments_substitute_and_surge_rule_options_are_read() {
    let plugin = import_loon_plugin(concat!(
        "#!name = Arguments\n",
        "#!arguments=Policy:DIRECT,Block:DEST-PORT,Hosts:\"api.example.com,cdn.example.com\",Off:#\n",
        "[Rule]\n",
        "DOMAIN,bsbsb.top,{{{Policy}}}\n",
        "{{{Block}}},4480,REJECT-NO-DROP,pre-matching\n",
        "DOMAIN,dns.google,REJECT,pre-matching,extended-matching\n",
        "DOMAIN-SUFFIX,ad-cdn_core.example.com,REJECT\n",
        "DOMAIN-WILDCARD,*pcdn*.example.net,REJECT\n",
        "AND,((DOMAIN-SUFFIX,chat.example.com),(OR,((DOMAIN-KEYWORD,stun),(DOMAIN-KEYWORD,p2p)))),REJECT\n",
        "URL-REGEX,^https?://api\\.example\\.com/ads,REJECT-DROP\n",
        "{{{Off}}}DOMAIN,off.example.com,REJECT\n",
        "[MITM]\n",
        "hostname = {{{Hosts}}}\n",
    ))
    .expect("argument plugin should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("arguments")
    );
    let rules = plugin.routing_rules();
    assert_eq!(rules.len(), 6, "{rules:?}");
    assert_eq!(rules[0].target, PolicyTarget::Direct);
    assert_eq!(rules[1].matcher, RuleMatcher::DstPort(4480, 4480));
    assert_eq!(rules[1].target, PolicyTarget::Reject);
    assert_eq!(
        plugin.mitm_hostnames.include,
        vec!["api.example.com", "cdn.example.com"]
    );
    assert!(
        plugin.source().contains("# DOMAIN,bsbsb.top,DIRECT"),
        "{}",
        plugin.source()
    );
    assert!(
        !plugin.source().contains("REJECT-DROP"),
        "{}",
        plugin.source()
    );

    let merged = merged_plugin_source("Arguments", &[&plugin]);
    assert!(merged.contains("[Rule]\nURL-REGEX,"), "{merged}");
    assert!(!merged.contains("bsbsb.top"), "{merged}");
    let engine = loaded_engine(&merged);
    let ad = engine
        .evaluate_url_rewrite("https://api.example.com/ads", MitmPolicyPhase::Request)
        .expect("URL-REGEX reject should evaluate");
    assert_eq!(ad.action, MitmPolicyRewriteAction::Reject);
}

#[test]
fn surge_force_http_engine_hosts_and_quantumult_echo_scripts_are_supported() {
    let surge = import_loon_plugin(concat!(
        "#!name=BoxJs\n",
        "[General]\n",
        "force-http-engine-hosts = %APPEND% boxjs.com, *.boxjs.com, lzmh.example.com:5090\n",
        "skip-proxy = 192.168.0.0/16\n",
        "[Script]\n",
        "BoxJs = type=http-request,pattern=^https?:\\/\\/(.+\\.)?boxjs\\.com,script-path=https://example.com/box.js, requires-body=true, timeout=120\n",
        "[MITM]\n",
        "hostname = %APPEND% api.example.com\n",
    ))
    .expect("BoxJs module should import");
    assert_eq!(
        surge.report.level,
        LoonSupportLevel::Full,
        "{}",
        surge.report.render_text("boxjs")
    );
    for host in [
        "boxjs.com",
        "*.boxjs.com",
        "lzmh.example.com:5090",
        "api.example.com",
    ] {
        assert!(
            surge.mitm_hostnames.include.iter().any(|item| item == host),
            "{host}: {:?}",
            surge.mitm_hostnames
        );
    }
    assert!(
        !surge
            .source()
            .lines()
            .any(|line| line.starts_with("skip-proxy")),
        "{}",
        surge.source()
    );

    let quantumult = import_loon_plugin(concat!(
        "hostname = boxjs.com\n",
        "\n",
        "^https?:\\/\\/(.+\\.)?boxjs\\.com url script-analyze-echo-response https://example.com/chavy.boxjs.js\n",
        "^https?:\\/\\/sub\\.store url script-echo-response https://example.com/sub-store.min.js\n",
    ))
    .expect("QX echo snippet should import");
    assert_eq!(
        quantumult.report.level,
        LoonSupportLevel::Full,
        "{}",
        quantumult.report.render_text("echo")
    );
    let merged = merged_plugin_source("Echo", &[&quantumult]);
    assert!(merged.contains("[Script]\nhttp-request "), "{merged}");
    assert!(
        merged.contains("script-path=https://example.com/chavy.boxjs.js, requires-body=true"),
        "{merged}"
    );
    // The core must accept the translated scripts.
    let _engine = loaded_engine(&merged);
}

#[test]
fn loon_conditional_scripts_become_http_scripts() {
    let plugin = import_loon_plugin(concat!(
        "#!name=Script Hub\n",
        "[Script]\n",
        "request if ${url} ~= /^https?:\\/\\/script\\.hub\\/($|edit\\/|reload)/i then script(\"https://example.com/script-hub.js\") with tag=\"Script Hub: 前端\", timeout=300\n",
        "response if ${url} ~= /^https:\\/\\/api\\.example\\.com\\/feed/ then script(\"https://example.com/feed.js\") with requires-body=true\n",
        "[MITM]\n",
        "hostname = script.hub, api.example.com\n",
    ))
    .expect("conditional scripts should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("script-hub")
    );
    let source = plugin.source();
    assert!(
        source.contains(
            "http-request (?i)^https?:\\/\\/script\\.hub\\/($|edit\\/|reload) script-path=https://example.com/script-hub.js, tag=\"Script Hub: 前端\", timeout=300, requires-body=true"
        ),
        "{source}"
    );
    assert!(
        source.contains("http-response ^https:\\/\\/api\\.example\\.com\\/feed script-path=https://example.com/feed.js, requires-body=true"),
        "{source}"
    );
    let _engine = loaded_engine(&merged_plugin_source("Script Hub", &[&plugin]));
}

#[test]
fn policyless_rules_and_misfiled_lines_are_read() {
    let plugin = import_loon_plugin(concat!(
        "#!name = Misfiled\n",
        "[Rule]\n",
        "DOMAIN-SUFFIX,musical.ly\n",
        "AND,((PROTOCOL,QUIC),(DOMAIN-SUFFIX,example.com)),REJECT\n",
        "[Rewrite]\n",
        "http-response ^https?://a\\.example\\.com/feed script-path=https://example.com/feed.js, requires-body=true, tag=feed\n",
        "[Script]\n",
        "^https?://a\\.example\\.com/adplace reject-dict\n",
        "[MITM]\n",
        "hostname = a.example.com\n",
    ))
    .expect("misfiled plugin should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("misfiled")
    );
    let rules = plugin.routing_rules();
    assert_eq!(rules[0].target, PolicyTarget::Group("PROXY".to_string()));
    assert_eq!(rules[1].target, PolicyTarget::Reject);
    let merged = merged_plugin_source("Misfiled", &[&plugin]);
    assert!(
        merged.contains("http-response ^https?://a\\.example\\.com/feed"),
        "{merged}"
    );
    let engine = loaded_engine(&merged);
    let ad = engine
        .evaluate_url_rewrite("https://a.example.com/adplace", MitmPolicyPhase::Request)
        .expect("reject should evaluate");
    assert_eq!(ad.action, MitmPolicyRewriteAction::Reject);
}

#[test]
fn scheduled_scripts_of_every_dialect_are_read() {
    let loon = import_loon_plugin(concat!(
        "#!name = Tasks\n",
        "#!arguments = sync_cron:\"55 23 * * *\", notify:true\n",
        "[Script]\n",
        "cron \"0 9 * * *\" script-path=https://example.com/checkin.js, tag=checkin, timeout=120, argument=[{notify}]\n",
        "cron {sync_cron} script-path=https://example.com/sync.js, tag=sync\n",
        "network-changed script-path=https://example.com/net.js, tag=net\n",
        "generic script-path=https://example.com/panel.js, tag=panel\n",
        "cron \"0 1 * * *\" script-path=https://example.com/off.js, enable=false\n",
        "cron \"not a cron\" script-path=https://example.com/bad.js\n",
    ))
    .expect("loon tasks should import");
    let scripts = &loon.scheduled_scripts;
    assert_eq!(scripts.len(), 4, "{scripts:?}");
    assert_eq!(
        scripts[0].trigger,
        LoonScheduledTrigger::Cron("0 9 * * *".to_string())
    );
    assert_eq!(scripts[0].tag, "checkin");
    assert_eq!(scripts[0].timeout_secs, 120);
    assert_eq!(scripts[0].argument, "notify=true");
    assert_eq!(
        scripts[1].trigger,
        LoonScheduledTrigger::Cron("55 23 * * *".to_string())
    );
    assert_eq!(scripts[2].trigger, LoonScheduledTrigger::NetworkChanged);
    assert_eq!(scripts[2].script_url, "https://example.com/net.js");
    assert_eq!(scripts[2].tag, "net");
    assert_eq!(scripts[3].trigger, LoonScheduledTrigger::Generic);
    assert_eq!(scripts[3].timeout_secs, 60);
    let reasons = loon
        .report
        .lines
        .iter()
        .map(|line| (line.reason.as_str(), line.status))
        .collect::<Vec<_>>();
    assert!(reasons.contains(&("script.disabled", LoonLineStatus::Ignored)));
    assert!(reasons.contains(&("script.cron_invalid", LoonLineStatus::Unsupported)));
    assert!(!loon.source().contains("\ncron "), "{}", loon.source());

    let surge = import_loon_plugin(concat!(
        "#!name = Surge tasks\n",
        "[Script]\n",
        "Sub-Store Sync = type=cron, cronexp=\"55 23 * * *\", wake-system=1, timeout=120, script-path=https://example.com/cron-sync.js\n",
        "Net = type=event, event-name=network-changed, script-path=https://example.com/net.js\n",
        "Notify = type=event, event-name=notification, script-path=https://example.com/n.js\n",
    ))
    .expect("surge tasks should import");
    assert_eq!(surge.scheduled_scripts.len(), 2);
    assert_eq!(surge.scheduled_scripts[0].tag, "Sub-Store Sync");
    assert_eq!(
        surge.scheduled_scripts[1].trigger,
        LoonScheduledTrigger::NetworkChanged
    );
    assert!(surge
        .report
        .lines
        .iter()
        .any(|line| line.reason == "script.event_unsupported"));

    let qx = import_loon_plugin(concat!(
        "[task_local]\n",
        "0 8 * * * https://example.com/qx-checkin.js, tag=qx checkin, enabled=true\n",
        "event-network https://example.com/qx-net.js, tag=qx net\n",
    ))
    .expect("qx tasks should import");
    assert_eq!(qx.scheduled_scripts.len(), 2, "{:?}", qx.report.lines);
    assert_eq!(
        qx.scheduled_scripts[0].script_url,
        "https://example.com/qx-checkin.js"
    );
    assert_eq!(qx.scheduled_scripts[0].tag, "qx checkin");
    assert_eq!(
        qx.scheduled_scripts[1].trigger,
        LoonScheduledTrigger::NetworkChanged
    );
}

#[test]
fn patterns_longer_than_the_core_reads_are_split_on_their_alternation() {
    let hosts = (0..60)
        .map(|index| format!("site{index:02}\\.example\\.com"))
        .collect::<Vec<_>>();
    let pattern = format!("^https?:\\/\\/({})\\/player", hosts.join("|"));
    assert!(pattern.len() > 1000);
    let plugin = import_loon_plugin(&format!(
        "#!name=Long\n[Script]\nPlayer = type=http-response, pattern=\"{pattern}\", requires-body=1, script-path=https://scripts.example.com/player.js\nhttp-request {pattern} script-path=https://scripts.example.com/request.js\n[MITM]\nhostname = %APPEND% *.example.com\n"
    ))
    .expect("long patterns should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("long")
    );
    let merged = merged_plugin_source("Long", &[&plugin]);
    assert!(
        merged
            .lines()
            .all(|line| line.len() < 600 || line.starts_with("hostname")),
        "{merged}"
    );
    let engine = loaded_engine(&merged);
    for host in ["site00", "site31", "site59"] {
        let response = engine
            .evaluate_script(
                &format!("https://{host}.example.com/player"),
                MitmPolicyPhase::Response,
            )
            .expect("script should evaluate");
        assert_eq!(
            response.script_path, "https://scripts.example.com/player.js",
            "{host}"
        );
        let request = engine
            .evaluate_script(
                &format!("https://{host}.example.com/player"),
                MitmPolicyPhase::Request,
            )
            .expect("script should evaluate");
        assert_eq!(
            request.script_path, "https://scripts.example.com/request.js",
            "{host}"
        );
    }
    let other = engine
        .evaluate_script(
            "https://site60.example.com/player",
            MitmPolicyPhase::Response,
        )
        .expect("script should evaluate");
    assert_eq!(other.kind, MitmPolicyScriptKind::None);
}

#[test]
fn quoted_surge_patterns_keep_their_backslashes() {
    // Unquoted by the core, `\?` would become `?` and `(a|?b)` is no regex;
    // `\.` would become `.` and match any character.
    let plugin = import_loon_plugin(concat!(
        "#!name=Quoted\n",
        "[Script]\n",
        "Search = type=http-response, pattern=\"^https?:\\/\\/(zhidao)\\.example\\.com\\/(question|\\?fr|\\?word)\", requires-body=1, script-path=https://scripts.example.com/search.js\n",
        "[MITM]\n",
        "hostname = %APPEND% zhidao.example.com\n",
    ))
    .expect("quoted patterns should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("quoted")
    );
    let engine = loaded_engine(&merged_plugin_source("Quoted", &[&plugin]));
    let hit = engine
        .evaluate_script(
            "https://zhidao.example.com/?word=a",
            MitmPolicyPhase::Response,
        )
        .expect("script should evaluate");
    assert_eq!(hit.script_path, "https://scripts.example.com/search.js");
    let dot = engine
        .evaluate_script(
            "https://zhidaoXexample.com/question",
            MitmPolicyPhase::Response,
        )
        .expect("script should evaluate");
    assert_eq!(dot.kind, MitmPolicyScriptKind::None);
}

#[test]
fn header_url_rewrites_become_redirects() {
    let plugin = import_loon_plugin(concat!(
        "#!name=Header\n",
        "[Rewrite]\n",
        "^https?://a\\.example\\.com/(.*) header https://b.example.com/$1\n",
        "[URL Rewrite]\n",
        "^https?://c\\.example\\.com/x https://d.example.com/y header\n",
        "[MITM]\n",
        "hostname = a.example.com, c.example.com\n",
    ))
    .expect("header rewrites should import");
    assert_eq!(
        plugin.report.level,
        LoonSupportLevel::Full,
        "{}",
        plugin.report.render_text("header")
    );
    let engine = loaded_engine(&merged_plugin_source("Header", &[&plugin]));
    let moved = engine
        .evaluate_url_rewrite("https://a.example.com/p?q=1", MitmPolicyPhase::Request)
        .expect("rewrite should evaluate");
    assert_eq!(moved.action, MitmPolicyRewriteAction::Redirect);
    assert_eq!(moved.value, "https://b.example.com/p?q=1");
    let surge = engine
        .evaluate_url_rewrite("https://c.example.com/x", MitmPolicyPhase::Request)
        .expect("rewrite should evaluate");
    assert_eq!(surge.action, MitmPolicyRewriteAction::Redirect);
}
