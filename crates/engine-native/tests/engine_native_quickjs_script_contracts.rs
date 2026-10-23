//! Contracts for the in-process QuickJS `[Script]` executor on the MITM hook.

use control_domain::{
    AuditEvent, Diagnostic, DomainResult, GrantedPermissions, HookPoint, HttpEvent,
    HttpMitmAction, HttpMitmEvent, HttpMitmOutcome, HttpMitmPhase, HttpMitmScriptDispatch,
    HttpMitmScriptKind, MetadataEntry, MitmPluginService, PluginInstance, PluginManifest,
    PluginPackage, PluginPermission, PluginResult,
};
use engine_native::{
    NativeHttpMitmPluginHook, NativePlainHttpMessage, NativeQuickJsScriptExecutor,
    NativeQuickJsScriptRuntimeConfig, ENGINE_NATIVE_QUICKJS_SCRIPT_CONFIG_INVALID_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_FAILED_CODE,
};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const SCRIPT_URL: &str = "https://scripts.networkcore.test/contract.js";

struct ScriptDispatchingService {
    timeout_ms: usize,
}

impl MitmPluginService for ScriptDispatchingService {
    fn validate_manifest(&self, _plugin_manifest: &PluginManifest) -> Vec<Diagnostic> {
        Vec::new()
    }

    fn load(
        &self,
        plugin_package: &PluginPackage,
        _granted_permissions: &GrantedPermissions,
    ) -> DomainResult<PluginInstance> {
        Ok(PluginInstance {
            manifest: plugin_package.manifest.clone(),
            loaded_source: None,
        })
    }

    fn handle_http_event(
        &self,
        _plugin_instance: &PluginInstance,
        _http_event: &HttpEvent,
    ) -> DomainResult<PluginResult> {
        Ok(PluginResult {
            audits: Vec::new(),
            diagnostics: Vec::new(),
        })
    }

    fn handle_http_mitm_event(
        &self,
        _plugin_instance: &PluginInstance,
        http_event: &HttpMitmEvent,
    ) -> DomainResult<HttpMitmOutcome> {
        let kind = match http_event.phase {
            HttpMitmPhase::Request => HttpMitmScriptKind::Request,
            HttpMitmPhase::Response => HttpMitmScriptKind::Response,
        };
        Ok(HttpMitmOutcome {
            action: HttpMitmAction::Continue,
            header_mutations: Vec::new(),
            body_mutation: None,
            script_dispatch: Some(HttpMitmScriptDispatch {
                kind,
                phase: http_event.phase,
                requires_body: true,
                timeout_ms: self.timeout_ms,
                max_size: 4096,
                script_path: SCRIPT_URL.to_string(),
                tag: "contract".to_string(),
                argument: "mode=contract".to_string(),
            }),
            audits: Vec::new(),
            diagnostics: Vec::new(),
        })
    }

    fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent> {
        plugin_result.audits.clone()
    }
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "networkcore-quickjs-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir should be created");
    dir
}

fn executor(script: &Path, store: Option<&Path>) -> NativeQuickJsScriptExecutor {
    let mut script_assets = BTreeMap::new();
    script_assets.insert(SCRIPT_URL.to_string(), script.display().to_string());
    NativeQuickJsScriptExecutor::new(NativeQuickJsScriptRuntimeConfig {
        script_assets,
        persistent_store_path: store.map(|path| path.display().to_string()),
        max_timeout_ms: 5000,
        max_body_bytes: 4096,
        memory_limit_bytes: 0,
    })
    .expect("mapped script should configure the QuickJS executor")
}

fn hook(executor: NativeQuickJsScriptExecutor, timeout_ms: usize) -> NativeHttpMitmPluginHook {
    NativeHttpMitmPluginHook::new(
        PluginInstance {
            manifest: PluginManifest {
                id: "networkcore.quickjs-contract".to_string(),
                version: "0.1.0".to_string(),
                permissions: vec![
                    PluginPermission::ReadRequest,
                    PluginPermission::ModifyRequest,
                    PluginPermission::ReadResponse,
                    PluginPermission::ModifyResponse,
                ],
                hooks: vec![HookPoint::Request, HookPoint::Response],
            },
            loaded_source: None,
        },
        Arc::new(ScriptDispatchingService { timeout_ms }),
    )
    .with_quickjs_script_executor(executor)
}

fn message(phase: HttpMitmPhase, body: &str) -> NativePlainHttpMessage {
    NativePlainHttpMessage {
        request_id: "quickjs-contract".to_string(),
        url: "https://api.networkcore.test/v1/feed".to_string(),
        method: Some("GET".to_string()),
        phase,
        status_code: (phase == HttpMitmPhase::Response).then_some(200),
        headers: vec![MetadataEntry {
            key: "Content-Type".to_string(),
            value: "application/json".to_string(),
        }],
        body: body.as_bytes().to_vec(),
    }
}

#[test]
fn quickjs_response_script_rewrites_body_and_persists_store() {
    let dir = temp_dir("response");
    let script = dir.join("response.js");
    std::fs::write(
        &script,
        "var body = JSON.parse($response.body); delete body.ad; body.mode = $argument;\
         $persistentStore.write('seen', 'last');\
         $done({ body: JSON.stringify(body), headers: { 'Content-Type': 'application/json', 'X-Script': '1' } });",
    )
    .unwrap();
    let store = dir.join("store.json");
    let hook = hook(executor(&script, Some(store.as_path())), 1000);
    assert_eq!(hook.script_engine(), Some("quickjs-ng"));
    assert_eq!(hook.script_sandbox(), None);

    let report = hook.plan_plain_http(&message(
        HttpMitmPhase::Response,
        "{\"ad\":1,\"items\":[]}",
    ));

    assert!(report.script_dispatch_executed, "{:?}", report.diagnostics);
    assert!(report.applied);
    assert_eq!(
        String::from_utf8(report.body).unwrap(),
        "{\"items\":[],\"mode\":\"mode=contract\"}"
    );
    assert!(report
        .headers
        .iter()
        .any(|header| header.key == "X-Script" && header.value == "1"));
    let stored = std::fs::read_to_string(&store).expect("store file should be written");
    assert!(stored.contains("\"last\":\"seen\""), "{stored}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn quickjs_request_script_can_answer_without_the_origin() {
    let dir = temp_dir("mock");
    let script = dir.join("mock.js");
    std::fs::write(
        &script,
        "$done({ response: { status: 403, headers: { 'Content-Type': 'text/plain' }, body: 'blocked ' + $request.method } });",
    )
    .unwrap();
    let hook = hook(executor(&script, None), 1000);

    let report = hook.plan_plain_http(&message(HttpMitmPhase::Request, ""));

    assert_eq!(report.terminal_action.as_deref(), Some("script-response"));
    assert_eq!(report.final_status_code, Some(403));
    assert_eq!(String::from_utf8(report.body).unwrap(), "blocked GET");
    assert_eq!(report.headers.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn quickjs_script_timeout_leaves_the_message_unchanged() {
    let dir = temp_dir("timeout");
    let script = dir.join("loop.js");
    std::fs::write(&script, "for (;;) {}").unwrap();
    let hook = hook(executor(&script, None), 100);

    let report = hook.plan_plain_http(&message(HttpMitmPhase::Response, "{\"a\":1}"));

    assert!(report.script_dispatch_failed);
    assert!(!report.script_dispatch_executed);
    assert_eq!(String::from_utf8(report.body).unwrap(), "{\"a\":1}");
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_FAILED_CODE
            && diagnostic.message.contains("script.timeout")
    }));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn quickjs_script_defers_when_the_authorized_asset_changes() {
    let dir = temp_dir("hash");
    let script = dir.join("asset.js");
    std::fs::write(&script, "$done({ body: 'authorized' });").unwrap();
    let hook = hook(executor(&script, None), 1000);
    std::fs::write(&script, "$done({ body: 'replaced' });").unwrap();

    let report = hook.plan_plain_http(&message(HttpMitmPhase::Response, "original"));

    assert!(report.script_dispatch_deferred);
    assert_eq!(String::from_utf8(report.body).unwrap(), "original");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn quickjs_executor_rejects_missing_assets_and_corrupt_stores() {
    let dir = temp_dir("config");
    let mut script_assets = BTreeMap::new();
    script_assets.insert(
        SCRIPT_URL.to_string(),
        dir.join("missing.js").display().to_string(),
    );
    let missing = NativeQuickJsScriptExecutor::new(NativeQuickJsScriptRuntimeConfig {
        script_assets,
        persistent_store_path: None,
        max_timeout_ms: 1000,
        max_body_bytes: 1024,
        memory_limit_bytes: 0,
    })
    .expect_err("missing script asset must be rejected");
    assert_eq!(missing.code, ENGINE_NATIVE_QUICKJS_SCRIPT_CONFIG_INVALID_CODE);

    let store = dir.join("store.json");
    std::fs::write(&store, "not json").unwrap();
    let corrupt = NativeQuickJsScriptExecutor::new(NativeQuickJsScriptRuntimeConfig {
        script_assets: BTreeMap::new(),
        persistent_store_path: Some(store.display().to_string()),
        max_timeout_ms: 1000,
        max_body_bytes: 1024,
        memory_limit_bytes: 0,
    })
    .expect_err("corrupt store must be rejected");
    assert_eq!(corrupt.code, ENGINE_NATIVE_QUICKJS_SCRIPT_CONFIG_INVALID_CODE);
    let _ = std::fs::remove_dir_all(&dir);
}
