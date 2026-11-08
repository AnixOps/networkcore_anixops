//! In-process QuickJS executor for MITM `[Script]` dispatches. Scripts run in
//! the `script-runtime` crate's sandbox: no file system, process, or network
//! access except the host-mediated `$`-API, so no OS sandbox is needed. Script
//! sources still come only from explicitly mapped local files whose SHA-256
//! is pinned when the executor is built.

use super::{
    bounded_script_timeout, engine_diagnostic, script_dispatch_matches_message,
    script_execution_deferred, NativeHttpScriptExecutionReport, NativeHttpScriptResponse,
    NativePlainHttpMessage, ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_EXECUTED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_FAILED_CODE, SOURCE_ENGINE_NATIVE_MITM,
};
use control_domain::{
    DiagnosticSeverity, DomainError, DomainResult, HttpMitmPhase, HttpMitmScriptDispatch,
    MetadataEntry,
};
use script_runtime::{
    binary_body_bytes, binary_body_string, DisabledScriptHttpClient, JsonFileScriptStore,
    MemoryScriptStore, QuickJsScriptRuntime, ScriptHttpClient, ScriptInvocation, ScriptLimits,
    ScriptNotification, ScriptPhase, ScriptRequest, ScriptResponse, ScriptRunStatus, ScriptStore,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const ENGINE_NATIVE_QUICKJS_SCRIPT_CONFIG_INVALID_CODE: &str =
    "engine.native.quickjs_script.config_invalid";

const QUICKJS_DEFAULT_MEMORY_LIMIT_BYTES: usize = 32 * 1024 * 1024;
const QUICKJS_MAX_SCRIPT_BYTES: u64 = 4 * 1024 * 1024;
/// Notifications kept for the host to collect; older ones are dropped.
pub const QUICKJS_MAX_PENDING_NOTIFICATIONS: usize = 64;
/// Longest run a scheduled script may ask for.
pub const QUICKJS_MAX_SCHEDULED_TIMEOUT_SECS: u32 = 300;

/// What a scheduled, event or generic script run is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeScheduledScriptKind {
    Cron,
    /// Event script with its event name (`network-changed`).
    Event(String),
    Generic,
}

/// One run of a script outside any HTTP flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeScheduledScriptRun {
    pub script_url: String,
    pub tag: String,
    pub argument: String,
    pub kind: NativeScheduledScriptKind,
    pub timeout_secs: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeScheduledScriptReport {
    pub executed: bool,
    /// `done`, `finished_without_done`, a failure code, or why it did not run.
    pub status: String,
    pub notifications: Vec<ScriptNotification>,
    pub logs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeQuickJsScriptRuntimeConfig {
    /// Script URL (`script-path`) to local file.
    pub script_assets: BTreeMap<String, String>,
    /// JSON file backing `$persistentStore`; in memory when absent.
    pub persistent_store_path: Option<String>,
    pub max_timeout_ms: usize,
    pub max_body_bytes: usize,
    /// QuickJS heap limit per dispatch; 0 selects the default.
    pub memory_limit_bytes: usize,
}

#[derive(Clone)]
pub struct NativeQuickJsScriptExecutor {
    config: NativeQuickJsScriptRuntimeConfig,
    script_asset_hashes: BTreeMap<String, String>,
    store: Arc<dyn ScriptStore>,
    runtime: QuickJsScriptRuntime,
    notifications: Arc<Mutex<VecDeque<ScriptNotification>>>,
}

impl std::fmt::Debug for NativeQuickJsScriptExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeQuickJsScriptExecutor")
            .field("script_assets", &self.config.script_assets.len())
            .field(
                "persistent_store",
                &self.config.persistent_store_path.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl NativeQuickJsScriptExecutor {
    /// Pins every mapped script by SHA-256 and opens the persistent store.
    pub fn new(config: NativeQuickJsScriptRuntimeConfig) -> DomainResult<Self> {
        let mut script_asset_hashes = BTreeMap::new();
        for (url, path) in &config.script_assets {
            let Some((_, hash)) = read_script_asset(std::path::Path::new(path)) else {
                return Err(config_invalid(
                    "QuickJS script mappings must point to readable local regular files",
                ));
            };
            script_asset_hashes.insert(url.clone(), hash);
        }
        let store: Arc<dyn ScriptStore> = match config.persistent_store_path.as_deref() {
            Some(path) => Arc::new(JsonFileScriptStore::open(path).map_err(|_| {
                config_invalid("QuickJS persistent store must be a JSON object file or absent")
            })?),
            None => Arc::new(MemoryScriptStore::new()),
        };
        Ok(Self {
            config,
            script_asset_hashes,
            runtime: QuickJsScriptRuntime::new(store.clone(), Arc::new(DisabledScriptHttpClient)),
            store,
            notifications: Arc::default(),
        })
    }

    /// Gives `$httpClient` (and `$task.fetch`) network access through
    /// `client`; without it every request fails with an error the script sees.
    pub fn with_http_client(mut self, client: Arc<dyn ScriptHttpClient>) -> Self {
        self.runtime = QuickJsScriptRuntime::new(self.store.clone(), client);
        self
    }

    pub fn config(&self) -> &NativeQuickJsScriptRuntimeConfig {
        &self.config
    }

    pub fn script_asset_hashes(&self) -> &BTreeMap<String, String> {
        &self.script_asset_hashes
    }

    pub fn execute(
        &self,
        dispatch: &HttpMitmScriptDispatch,
        message: &NativePlainHttpMessage,
    ) -> NativeHttpScriptExecutionReport {
        if !script_dispatch_matches_message(dispatch, message) {
            return script_execution_deferred(
                "native HTTP script dispatch phase does not match the intercepted message",
            );
        }
        let max_body_bytes = match (dispatch.max_size, self.config.max_body_bytes) {
            (0, 0) => usize::MAX,
            (0, runtime) => runtime,
            (rule, 0) => rule,
            (rule, runtime) => rule.min(runtime),
        };
        let body = if dispatch.requires_body {
            if message.body.len() > max_body_bytes {
                return script_execution_deferred(
                    "native HTTP script dispatch body exceeds the max-size limit",
                );
            }
            if dispatch.binary_body_mode {
                Some(binary_body_string(&message.body))
            } else {
                match std::str::from_utf8(&message.body) {
                    Ok(body) => Some(body.to_string()),
                    Err(_) => {
                        return script_execution_deferred(
                            "native HTTP script dispatch requires a UTF-8 buffered body",
                        )
                    }
                }
            }
        } else {
            None
        };
        let source = match self.script_source(&dispatch.script_path) {
            Ok(source) => source,
            Err(reason) => return script_execution_deferred(reason),
        };

        let headers = message
            .headers
            .iter()
            .map(|header| (header.key.clone(), header.value.clone()))
            .collect::<Vec<_>>();
        let method = message.method.clone().unwrap_or_else(|| "GET".to_string());
        let (phase, request, response) = match message.phase {
            HttpMitmPhase::Request => (
                ScriptPhase::Request,
                ScriptRequest {
                    url: message.url.clone(),
                    method,
                    headers,
                    body,
                },
                None,
            ),
            HttpMitmPhase::Response => (
                ScriptPhase::Response,
                ScriptRequest {
                    url: message.url.clone(),
                    method,
                    headers: Vec::new(),
                    body: None,
                },
                Some(ScriptResponse {
                    status: message.status_code.unwrap_or(200),
                    headers,
                    body,
                }),
            ),
        };
        let invocation = ScriptInvocation {
            phase,
            script_name: if dispatch.tag.is_empty() {
                dispatch.script_path.clone()
            } else {
                dispatch.tag.clone()
            },
            argument: dispatch.argument.clone(),
            request,
            response,
            binary_body: dispatch.binary_body_mode,
            event: None,
        };
        let timeout_ms = bounded_script_timeout(dispatch.timeout_ms, self.config.max_timeout_ms);
        let limits = ScriptLimits {
            timeout: Duration::from_millis(timeout_ms as u64),
            memory_limit_bytes: if self.config.memory_limit_bytes == 0 {
                QUICKJS_DEFAULT_MEMORY_LIMIT_BYTES
            } else {
                self.config.memory_limit_bytes
            },
            max_body_bytes,
            ..ScriptLimits::default()
        };

        let outcome = self.runtime.run(&source, &invocation, &limits);
        self.queue_notifications(&outcome.notifications);
        if let ScriptRunStatus::Failed(failure) = &outcome.status {
            return NativeHttpScriptExecutionReport {
                executed: false,
                applied: false,
                url: None,
                headers: None,
                body: None,
                status_code: None,
                response: None,
                diagnostics: vec![engine_diagnostic(
                    DiagnosticSeverity::Warning,
                    ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_FAILED_CODE,
                    format!("native QuickJS script dispatch failed: {}", failure.code()),
                    SOURCE_ENGINE_NATIVE_MITM,
                )],
            };
        }

        let mutation = outcome.applied_mutation().cloned().unwrap_or_default();
        let to_entries = |headers: Vec<(String, String)>| {
            headers
                .into_iter()
                .map(|(key, value)| MetadataEntry { key, value })
                .collect::<Vec<_>>()
        };
        // The host only accepts byte strings for binary `$done` bodies.
        let to_bytes = |body: String| {
            if dispatch.binary_body_mode {
                binary_body_bytes(&body).unwrap_or_default()
            } else {
                body.into_bytes()
            }
        };
        let response = mutation.response.map(|response| NativeHttpScriptResponse {
            status_code: response.status,
            headers: to_entries(response.headers),
            body: to_bytes(response.body.unwrap_or_default()),
        });
        let url = mutation.url;
        let headers = mutation.headers.map(to_entries);
        let body = mutation.body.map(to_bytes);
        let status_code = mutation.status;
        let applied = url.is_some()
            || headers.is_some()
            || body.is_some()
            || status_code.is_some()
            || response.is_some();
        NativeHttpScriptExecutionReport {
            executed: true,
            applied,
            url,
            headers,
            body,
            status_code,
            response,
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_EXECUTED_CODE,
                "native QuickJS script runtime completed a locally mapped script dispatch",
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        }
    }

    /// Notifications scripts posted since the last call, oldest first. The
    /// host shows them; at most [`QUICKJS_MAX_PENDING_NOTIFICATIONS`] wait.
    pub fn drain_notifications(&self) -> Vec<ScriptNotification> {
        self.notifications
            .lock()
            .map(|mut queue| queue.drain(..).collect())
            .unwrap_or_default()
    }

    /// Runs a cron, event or generic script. Blocks for up to the run's
    /// timeout, so async callers run it on a blocking thread.
    pub fn execute_scheduled(&self, run: &NativeScheduledScriptRun) -> NativeScheduledScriptReport {
        let source = match self.script_source(&run.script_url) {
            Ok(source) => source,
            Err(reason) => {
                return NativeScheduledScriptReport {
                    executed: false,
                    status: reason.to_string(),
                    notifications: Vec::new(),
                    logs: Vec::new(),
                }
            }
        };
        let (phase, event) = match &run.kind {
            NativeScheduledScriptKind::Cron => (ScriptPhase::Cron, None),
            NativeScheduledScriptKind::Event(name) => (ScriptPhase::Event, Some(name.clone())),
            NativeScheduledScriptKind::Generic => (ScriptPhase::Generic, None),
        };
        let name = if run.tag.is_empty() {
            run.script_url.clone()
        } else {
            run.tag.clone()
        };
        let invocation = ScriptInvocation::scheduled(phase, name, run.argument.clone(), event);
        let timeout_secs = run
            .timeout_secs
            .clamp(1, QUICKJS_MAX_SCHEDULED_TIMEOUT_SECS);
        let limits = ScriptLimits {
            timeout: Duration::from_secs(u64::from(timeout_secs)),
            memory_limit_bytes: if self.config.memory_limit_bytes == 0 {
                QUICKJS_DEFAULT_MEMORY_LIMIT_BYTES
            } else {
                self.config.memory_limit_bytes
            },
            ..ScriptLimits::default()
        };
        let outcome = self.runtime.run(&source, &invocation, &limits);
        self.queue_notifications(&outcome.notifications);
        let status = match &outcome.status {
            ScriptRunStatus::Done => "done".to_string(),
            ScriptRunStatus::FinishedWithoutDone => "finished_without_done".to_string(),
            ScriptRunStatus::Failed(failure) => failure.code().to_string(),
        };
        NativeScheduledScriptReport {
            executed: !matches!(outcome.status, ScriptRunStatus::Failed(_)),
            status,
            notifications: outcome.notifications,
            logs: outcome.logs,
        }
    }

    fn queue_notifications(&self, notifications: &[ScriptNotification]) {
        if notifications.is_empty() {
            return;
        }
        if let Ok(mut queue) = self.notifications.lock() {
            queue.extend(notifications.iter().cloned());
            while queue.len() > QUICKJS_MAX_PENDING_NOTIFICATIONS {
                queue.pop_front();
            }
        }
    }

    /// Source of a mapped script, checked against the hash pinned at build.
    fn script_source(&self, script_url: &str) -> Result<String, &'static str> {
        let asset_path =
            self.config.script_assets.get(script_url).ok_or(
                "native HTTP script dispatch has no explicitly configured local script asset",
            )?;
        let expected_hash = self.script_asset_hashes.get(script_url).ok_or(
            "native HTTP script runtime could not record the mapped local script asset hash",
        )?;
        let (source, actual_hash) = read_script_asset(std::path::Path::new(asset_path)).ok_or(
            "native HTTP script runtime mapped local script asset is unavailable or unsafe",
        )?;
        if actual_hash != *expected_hash {
            return Err(
                "native HTTP script runtime mapped local script asset changed after authorization",
            );
        }
        String::from_utf8(source)
            .map_err(|_| "native HTTP script runtime mapped local script asset is not UTF-8")
    }
}

fn config_invalid(message: &'static str) -> DomainError {
    DomainError::new(ENGINE_NATIVE_QUICKJS_SCRIPT_CONFIG_INVALID_CODE, message)
}

/// Reads a regular, non-symlink file once and hashes exactly the bytes that
/// will run, so a swap between check and use cannot change the script.
fn read_script_asset(path: &std::path::Path) -> Option<(Vec<u8>, String)> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > QUICKJS_MAX_SCRIPT_BYTES {
        return None;
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(QUICKJS_MAX_SCRIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > QUICKJS_MAX_SCRIPT_BYTES {
        return None;
    }
    let hash = format!("{:x}", Sha256::digest(&bytes));
    Some((bytes, hash))
}
