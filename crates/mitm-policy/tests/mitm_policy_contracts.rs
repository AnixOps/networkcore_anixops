use control_domain::{
    CertificateTrustState, DiagnosticSeverity, GrantedPermissions, HookPoint, HttpEvent,
    HttpHeaderMutationOperation, HttpMitmAction, HttpMitmEvent, HttpMitmPhase, HttpMitmScriptKind,
    MetadataEntry, MitmPluginService, PluginManifest, PluginPackage, PluginPermission,
};
use mitm_policy::{
    builtin_ad_block_plugin_package, AnixOpsMitmPluginService, AnixOpsMitmPolicyEngine,
    MitmPolicyHeaderField, MitmPolicyHeaderOperation, MitmPolicyMitmDecisionType, MitmPolicyPhase,
    MitmPolicyRewriteAction, MitmPolicyScriptKind, MITM_POLICY_AD_BLOCK_PLUGIN_ID,
    MITM_POLICY_CONFIG_LOADED_CODE, MITM_POLICY_CONFIG_PARSE_FAILED_CODE,
    MITM_POLICY_HTTP_EVENT_MUTATION_DEFERRED_CODE, MITM_POLICY_HTTP_EVENT_MUTATION_PLANNED_CODE,
    MITM_POLICY_HTTP_EVENT_SOURCE_MISSING_CODE, MITM_POLICY_MANIFEST_HOOK_MISSING_CODE,
};

#[test]
fn builtin_ad_block_plugin_package_loads_through_mitm_anixops_core() {
    let package = builtin_ad_block_plugin_package();
    let mut engine = AnixOpsMitmPolicyEngine::new().expect("policy engine should allocate");

    let report = engine
        .load_config(&package.source)
        .expect("built-in ad block policy should load");

    assert_eq!(report.version, "0.45.10");
    assert!(report.rewrite_rule_count >= 5);
    assert!(report.mitm_pattern_count >= 5);
    assert_diagnostic(&report.diagnostics, MITM_POLICY_CONFIG_LOADED_CODE);
    assert_eq!(
        engine.jq_max_input_bytes(),
        mitm_anixops_sys::ANIXOPS_JQ_MAX_INPUT_BYTES_DEFAULT
    );
    engine
        .set_jq_max_input_bytes(4096)
        .expect("JQ max input guard should be configurable");
    assert_eq!(engine.jq_max_input_bytes(), 4096);

    let rewrite = engine
        .evaluate_url_rewrite(
            "https://pubads.g.doubleclick.net/pagead/id",
            MitmPolicyPhase::Request,
        )
        .expect("ad URL rewrite should evaluate");
    assert_eq!(rewrite.action, MitmPolicyRewriteAction::Reject);

    engine.set_certificate_trust_state(CertificateTrustState::Trusted);
    let decision = engine
        .evaluate_mitm("stats.doubleclick.net", false)
        .expect("MITM host decision should evaluate");
    assert_eq!(decision.decision, MitmPolicyMitmDecisionType::Intercept);
}

#[test]
fn v04510_policy_wrapper_exposes_plan_header_body_and_script_contracts() {
    let mut engine = AnixOpsMitmPolicyEngine::new().expect("policy engine should allocate");
    engine
        .load_config(
            r#"
[Argument]
Mode = select,rust

[Rewrite]
^http:\/\/old\.networkcore\.example\/(.*) https://api.networkcore.example/$1 302
^https:\/\/api\.networkcore\.example\/v1 response-header-add X-NetworkCore rust-plan
^https:\/\/api\.networkcore\.example\/v1 response-body-replace-regex from to

[Script]
http-response ^https:\/\/api\.networkcore\.example\/v1 requires-body=1, timeout=4, max-size=2048, script-path=https://scripts.example/networkcore-response.js, tag=networkcore.response, argument=[{Mode}]
"#,
        )
        .expect("0.45.10 fixture should load");

    let redirect = engine
        .evaluate_url_rewrite(
            "http://old.networkcore.example/v1",
            MitmPolicyPhase::Request,
        )
        .expect("redirect rewrite should evaluate");
    assert_eq!(redirect.action, MitmPolicyRewriteAction::Redirect);
    assert_eq!(redirect.status_code, 302);
    assert_eq!(redirect.value, "https://api.networkcore.example/v1");

    let header = engine
        .evaluate_named_header(
            "https://api.networkcore.example/v1",
            MitmPolicyPhase::Response,
            0,
            "x-networkcore",
            "",
        )
        .expect("named header rewrite should evaluate");
    assert_eq!(header.action, MitmPolicyRewriteAction::HeaderMutation);
    assert_eq!(header.operation, MitmPolicyHeaderOperation::Add);
    assert_eq!(header.header_name, "X-NetworkCore");
    assert_eq!(header.value, "rust-plan");

    let (body, chain) = engine
        .apply_body_chain(
            "https://api.networkcore.example/v1",
            MitmPolicyPhase::Response,
            "from=1",
        )
        .expect("body chain should evaluate");
    assert_eq!(body, "to=1");
    assert!(chain.rewritten);
    assert_eq!(chain.rewrites.len(), 1);
    assert_eq!(
        chain.rewrites[0].action,
        MitmPolicyRewriteAction::BodyMutation
    );

    let script = engine
        .evaluate_script(
            "https://api.networkcore.example/v1",
            MitmPolicyPhase::Response,
        )
        .expect("script dispatch should evaluate");
    assert_eq!(script.kind, MitmPolicyScriptKind::HttpResponse);
    assert!(script.requires_body);
    assert_eq!(
        script.script_path,
        "https://scripts.example/networkcore-response.js"
    );
    assert_eq!(script.tag, "networkcore.response");
    assert_eq!(script.argument, "Mode=rust");
    assert_eq!(script.timeout_ms, 4000);
    assert_eq!(script.max_size, 2048);

    let (plan, plan_body) = engine
        .build_rewrite_plan(
            "https://api.networkcore.example/v1",
            MitmPolicyPhase::Response,
            "from=1",
        )
        .expect("rewrite plan should build");
    assert_eq!(plan.phase, MitmPolicyPhase::Response);
    assert!(plan.body_available);
    assert!(plan.requires_body);
    assert_eq!(plan_body, "to=1");
    assert_eq!(plan.rewrite.action, MitmPolicyRewriteAction::BodyMutation);
    assert_eq!(plan.header_rewrites.len(), 1);
    assert_eq!(
        plan.header_rewrites[0].action,
        MitmPolicyRewriteAction::HeaderMutation
    );
    assert_eq!(plan.script.kind, MitmPolicyScriptKind::HttpResponse);
}

#[test]
fn v04510_policy_wrapper_applies_bounded_header_list_contract() {
    let mut engine = AnixOpsMitmPolicyEngine::new().expect("policy engine should allocate");
    engine
        .load_config(
            r#"
[Rewrite]
^https:\/\/api\.networkcore\.example\/cookies response-header-add Set-Cookie "c=1; Path=/"
^https:\/\/api\.networkcore\.example\/cookies response-header-replace-regex Set-Cookie "a=1" "a=2"
^https:\/\/api\.networkcore\.example\/cookies response-header-del X-Remove
"#,
        )
        .expect("header fixture should load");

    let (headers, plan) = engine
        .apply_headers(
            "https://api.networkcore.example/cookies",
            MitmPolicyPhase::Response,
            &[
                MitmPolicyHeaderField {
                    name: "Set-Cookie".to_string(),
                    value: "a=1; Path=/".to_string(),
                },
                MitmPolicyHeaderField {
                    name: "set-cookie".to_string(),
                    value: "b=1; Path=/".to_string(),
                },
                MitmPolicyHeaderField {
                    name: "X-Remove".to_string(),
                    value: "yes".to_string(),
                },
            ],
        )
        .expect("header list should apply");

    assert!(!headers.truncated);
    assert_eq!(
        headers.fields,
        vec![
            MitmPolicyHeaderField {
                name: "Set-Cookie".to_string(),
                value: "a=2; Path=/".to_string(),
            },
            MitmPolicyHeaderField {
                name: "set-cookie".to_string(),
                value: "b=1; Path=/".to_string(),
            },
            MitmPolicyHeaderField {
                name: "Set-Cookie".to_string(),
                value: "c=1; Path=/".to_string(),
            },
        ]
    );
    assert_eq!(plan.header_rewrites.len(), 3);
    assert!(plan
        .header_rewrites
        .iter()
        .all(|rewrite| rewrite.action == MitmPolicyRewriteAction::HeaderMutation));
}

#[test]
fn adapter_loads_builtin_ad_block_plugin_and_reports_deferred_mutation() {
    let package = builtin_ad_block_plugin_package();
    let service = AnixOpsMitmPluginService::new();
    let instance = service
        .load(
            &package,
            &GrantedPermissions {
                permissions: package.manifest.permissions.clone(),
            },
        )
        .expect("built-in ad block plugin should load");

    let result = service
        .handle_http_event(
            &instance,
            &HttpEvent {
                request_id: "req-1".to_string(),
                headers: vec![MetadataEntry {
                    key: "host".to_string(),
                    value: "pubads.g.doubleclick.net".to_string(),
                }],
                body: Vec::new(),
            },
        )
        .expect("adapter should return audit and diagnostics");

    assert_eq!(instance.manifest.id, MITM_POLICY_AD_BLOCK_PLUGIN_ID);
    assert_eq!(service.audit(&result).len(), 1);
    assert_diagnostic(
        &result.diagnostics,
        MITM_POLICY_HTTP_EVENT_MUTATION_DEFERRED_CODE,
    );
}

#[test]
fn adapter_plans_builtin_ad_block_reject_for_rich_http_mitm_event() {
    let package = builtin_ad_block_plugin_package();
    let service = AnixOpsMitmPluginService::new();
    let instance = service
        .load(
            &package,
            &GrantedPermissions {
                permissions: package.manifest.permissions.clone(),
            },
        )
        .expect("built-in ad block plugin should load");

    let outcome = service
        .handle_http_mitm_event(
            &instance,
            &HttpMitmEvent {
                request_id: "req-rich-1".to_string(),
                url: "https://pubads.g.doubleclick.net/pagead/id".to_string(),
                method: Some("GET".to_string()),
                phase: HttpMitmPhase::Request,
                status_code: None,
                headers: Vec::new(),
                body: Vec::new(),
            },
        )
        .expect("rich HTTP MITM event should produce a policy plan");

    assert_eq!(outcome.action, HttpMitmAction::Reject { status_code: 403 });
    assert!(outcome.header_mutations.is_empty());
    assert!(outcome.body_mutation.is_none());
    assert!(outcome.script_dispatch.is_none());
    assert_diagnostic(
        &outcome.diagnostics,
        MITM_POLICY_HTTP_EVENT_MUTATION_PLANNED_CODE,
    );
    assert_eq!(outcome.audits[0].action, "mitm.policy.plan_http_mitm_event");
}

#[test]
fn adapter_maps_v04510_header_body_and_script_plan_to_domain_outcome() {
    let service = AnixOpsMitmPluginService::new();
    let package = PluginPackage {
        manifest: PluginManifest {
            id: "rich-plan-plugin".to_string(),
            version: "0.1.0".to_string(),
            permissions: vec![
                PluginPermission::ReadResponse,
                PluginPermission::ModifyResponse,
            ],
            hooks: vec![HookPoint::Response],
        },
        source: r#"
[Argument]
Mode = select,rust

[Rewrite]
^https:\/\/api\.networkcore\.example\/v1 response-header-add X-NetworkCore rich-plan
^https:\/\/api\.networkcore\.example\/v1 response-body-replace-regex from to

[Script]
http-response ^https:\/\/api\.networkcore\.example\/v1 requires-body=1, timeout=4, max-size=2048, script-path=https://scripts.example/networkcore-response.js, tag=networkcore.response, argument=[{Mode}]
"#
        .to_string(),
    };
    let instance = service
        .load(
            &package,
            &GrantedPermissions {
                permissions: package.manifest.permissions.clone(),
            },
        )
        .expect("rich plan plugin should load");

    let outcome = service
        .handle_http_mitm_event(
            &instance,
            &HttpMitmEvent {
                request_id: "req-rich-2".to_string(),
                url: "https://api.networkcore.example/v1".to_string(),
                method: None,
                phase: HttpMitmPhase::Response,
                status_code: Some(200),
                headers: Vec::new(),
                body: b"from=1".to_vec(),
            },
        )
        .expect("rich HTTP MITM event should produce a policy plan");

    assert_eq!(outcome.action, HttpMitmAction::Continue);
    assert_eq!(outcome.header_mutations.len(), 1);
    assert_eq!(
        outcome.header_mutations[0].operation,
        HttpHeaderMutationOperation::Add
    );
    assert_eq!(outcome.header_mutations[0].name, "X-NetworkCore");
    assert_eq!(
        outcome.header_mutations[0].value.as_deref(),
        Some("rich-plan")
    );
    assert_eq!(
        outcome
            .body_mutation
            .expect("body mutation should be planned")
            .body,
        b"to=1".to_vec()
    );
    let script = outcome
        .script_dispatch
        .expect("script dispatch should be planned");
    assert_eq!(script.kind, HttpMitmScriptKind::Response);
    assert_eq!(script.phase, HttpMitmPhase::Response);
    assert!(script.requires_body);
    assert_eq!(script.argument, "Mode=rust");
}

#[test]
fn adapter_defers_rich_http_mitm_event_when_loaded_source_is_missing() {
    let service = AnixOpsMitmPluginService::new();
    let instance = control_domain::PluginInstance {
        manifest: PluginManifest {
            id: "source-missing".to_string(),
            version: "0.1.0".to_string(),
            permissions: vec![PluginPermission::ReadRequest],
            hooks: vec![HookPoint::Request],
        },
        loaded_source: None,
    };

    let outcome = service
        .handle_http_mitm_event(
            &instance,
            &HttpMitmEvent {
                request_id: "req-rich-3".to_string(),
                url: "https://example.test/".to_string(),
                method: Some("GET".to_string()),
                phase: HttpMitmPhase::Request,
                status_code: None,
                headers: Vec::new(),
                body: Vec::new(),
            },
        )
        .expect("missing loaded source should defer without failing");

    assert_eq!(outcome.action, HttpMitmAction::Continue);
    assert_diagnostic(
        &outcome.diagnostics,
        MITM_POLICY_HTTP_EVENT_SOURCE_MISSING_CODE,
    );
}

#[test]
fn invalid_plugin_config_returns_stable_parse_error_without_leaking_source() {
    let mut engine = AnixOpsMitmPolicyEngine::new().expect("policy engine should allocate");
    let error = engine
        .load_config("[Rewrite]\n[ https://target.test 302\n")
        .expect_err("invalid rewrite regex should fail");

    assert_eq!(error.code, MITM_POLICY_CONFIG_PARSE_FAILED_CODE);
    assert!(!error.message.contains("https://target.test"));
}

#[test]
fn manifest_without_hooks_returns_stable_diagnostic() {
    let service = AnixOpsMitmPluginService::new();
    let diagnostics = service.validate_manifest(&PluginManifest {
        id: "plugin-without-hooks".to_string(),
        version: "0.1.0".to_string(),
        permissions: vec![PluginPermission::ReadRequest],
        hooks: Vec::new(),
    });

    assert!(diagnostics.iter().any(|diagnostic| diagnostic.code
        == MITM_POLICY_MANIFEST_HOOK_MISSING_CODE
        && diagnostic.severity == DiagnosticSeverity::Error));
}

#[test]
fn adapter_rejects_ungranted_permissions() {
    let service = AnixOpsMitmPluginService::new();
    let package = PluginPackage {
        manifest: PluginManifest {
            id: "permission-check".to_string(),
            version: "0.1.0".to_string(),
            permissions: vec![
                PluginPermission::ReadRequest,
                PluginPermission::ModifyResponse,
            ],
            hooks: vec![HookPoint::Request],
        },
        source: "[MITM]\nhostname = example.test\n".to_string(),
    };

    let error = service
        .load(
            &package,
            &GrantedPermissions {
                permissions: vec![PluginPermission::ReadRequest],
            },
        )
        .expect_err("missing granted permission should fail");

    assert_eq!(error.code, mitm_policy::MITM_POLICY_PERMISSION_DENIED_CODE);
}

fn assert_diagnostic(diagnostics: &[control_domain::Diagnostic], code: &str) {
    assert!(
        diagnostics.iter().any(|diagnostic| diagnostic.code == code),
        "expected diagnostic {code}, got {diagnostics:?}"
    );
}
