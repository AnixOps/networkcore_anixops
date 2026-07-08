use control_domain::{
    CertificateTrustState, DiagnosticSeverity, GrantedPermissions, HookPoint, HttpEvent,
    MetadataEntry, MitmPluginService, PluginManifest, PluginPackage, PluginPermission,
};
use mitm_policy::{
    builtin_ad_block_plugin_package, AnixOpsMitmPluginService, AnixOpsMitmPolicyEngine,
    MitmPolicyMitmDecisionType, MitmPolicyPhase, MitmPolicyRewriteAction,
    MITM_POLICY_AD_BLOCK_PLUGIN_ID, MITM_POLICY_CONFIG_LOADED_CODE,
    MITM_POLICY_CONFIG_PARSE_FAILED_CODE, MITM_POLICY_HTTP_EVENT_MUTATION_DEFERRED_CODE,
    MITM_POLICY_MANIFEST_HOOK_MISSING_CODE,
};

#[test]
fn builtin_ad_block_plugin_package_loads_through_mitm_anixops_core() {
    let package = builtin_ad_block_plugin_package();
    let mut engine = AnixOpsMitmPolicyEngine::new().expect("policy engine should allocate");

    let report = engine
        .load_config(&package.source)
        .expect("built-in ad block policy should load");

    assert_eq!(report.version, "0.41.0");
    assert!(report.rewrite_rule_count >= 5);
    assert!(report.mitm_pattern_count >= 5);
    assert_diagnostic(&report.diagnostics, MITM_POLICY_CONFIG_LOADED_CODE);

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

    assert!(diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == MITM_POLICY_MANIFEST_HOOK_MISSING_CODE
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
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == code),
        "expected diagnostic {code}, got {diagnostics:?}"
    );
}
