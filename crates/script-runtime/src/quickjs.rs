//! QuickJS (quickjs-ng through rquickjs) binding. It only registers the host
//! function, evaluates sources, drains jobs, and enforces the deadline and
//! heap limit; the `$`-API lives in [`crate::ScriptHost`].

use crate::driver::{finish_outcome, run_script, JsEngineContext, JsEngineError};
use crate::host::truncate_utf8;
use crate::{
    DisabledScriptHttpClient, MemoryScriptStore, ScriptFailure, ScriptHost, ScriptHttpClient,
    ScriptInvocation, ScriptLimits, ScriptOutcome, ScriptStore, SCRIPT_HOST_FUNCTION,
};
use rquickjs::context::EvalOptions;
use rquickjs::function::Opt;
use rquickjs::{qjs, CatchResultExt, CaughtError, Context, Ctx, Function, Runtime};
use std::cell::RefCell;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::ffi::CString;
use std::hash::{Hash, Hasher};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

const QUICKJS_MAX_STACK_BYTES: usize = 512 * 1024;
const MAX_ERROR_MESSAGE_BYTES: usize = 1024;
/// Scripts at least this large are compiled once and their bytecode reused;
/// smaller ones compile faster than a lookup is worth.
pub const BYTECODE_CACHE_MIN_SOURCE_BYTES: usize = 16 * 1024;
/// Bytecode kept across runs; past it the cache starts over.
const BYTECODE_CACHE_MAX_BYTES: usize = 8 * 1024 * 1024;

/// A script's identity: its length and two independent 64-bit hashes.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SourceKey(usize, u64, u64);

impl SourceKey {
    fn of(source: &str) -> Self {
        let mut first = DefaultHasher::new();
        source.hash(&mut first);
        let mut second = DefaultHasher::new();
        "networkcore.bytecode".hash(&mut second);
        source.hash(&mut second);
        Self(source.len(), first.finish(), second.finish())
    }
}

#[derive(Default)]
struct CacheEntries {
    map: HashMap<SourceKey, Arc<Vec<u8>>>,
    bytes: usize,
}

/// Bytecode of large scripts, shared by the runs of one runtime, so a script
/// that answers many requests is parsed once instead of on every request.
#[derive(Default)]
struct BytecodeCache {
    entries: Mutex<CacheEntries>,
}

impl BytecodeCache {
    fn get(&self, key: &SourceKey) -> Option<Arc<Vec<u8>>> {
        self.entries.lock().ok()?.map.get(key).cloned()
    }

    fn insert(&self, key: SourceKey, bytecode: Vec<u8>) {
        if bytecode.len() > BYTECODE_CACHE_MAX_BYTES {
            return;
        }
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.bytes + bytecode.len() > BYTECODE_CACHE_MAX_BYTES {
            entries.map.clear();
            entries.bytes = 0;
        }
        entries.bytes += bytecode.len();
        if let Some(old) = entries.map.insert(key, Arc::new(bytecode)) {
            entries.bytes -= old.len();
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
            .lock()
            .map(|entries| entries.map.len())
            .unwrap_or(0)
    }
}

/// Runs each dispatch in a fresh QuickJS runtime, so scripts share nothing but
/// the persistent store.
#[derive(Clone)]
pub struct QuickJsScriptRuntime {
    store: Arc<dyn ScriptStore>,
    http_client: Arc<dyn ScriptHttpClient>,
    bytecode: Arc<BytecodeCache>,
}

impl Default for QuickJsScriptRuntime {
    fn default() -> Self {
        Self::new(
            Arc::new(MemoryScriptStore::new()),
            Arc::new(DisabledScriptHttpClient),
        )
    }
}

impl std::fmt::Debug for QuickJsScriptRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QuickJsScriptRuntime")
            .finish_non_exhaustive()
    }
}

impl QuickJsScriptRuntime {
    pub const ENGINE_NAME: &'static str = "quickjs-ng";

    pub fn new(store: Arc<dyn ScriptStore>, http_client: Arc<dyn ScriptHttpClient>) -> Self {
        Self {
            store,
            http_client,
            bytecode: Arc::default(),
        }
    }

    pub fn store(&self) -> &Arc<dyn ScriptStore> {
        &self.store
    }

    pub fn run(
        &self,
        script: &str,
        invocation: &ScriptInvocation,
        limits: &ScriptLimits,
    ) -> ScriptOutcome {
        if invocation.body_exceeds(limits.max_body_bytes) {
            return ScriptOutcome::failed(ScriptFailure::BodyTooLarge);
        }

        let deadline = Instant::now() + limits.timeout;
        let host = Rc::new(RefCell::new(ScriptHost::new(
            invocation,
            limits,
            Arc::clone(&self.store),
        )));
        let context = QuickJsContext::new(Rc::clone(&host), limits, deadline);
        let result = match context.map(|context| context.with_bytecode(&self.bytecode)) {
            Ok(mut engine) => run_script(
                &mut engine,
                &host,
                self.http_client.as_ref(),
                script,
                &invocation.script_name,
                deadline,
            ),
            Err(error) => Err(error),
        };
        let mut host = host.borrow_mut();
        finish_outcome(result, &mut host)
    }
}

struct QuickJsContext {
    context: Context,
    runtime: Runtime,
    interrupted: Arc<AtomicBool>,
    bytecode: Arc<BytecodeCache>,
}

impl QuickJsContext {
    fn new(
        host: Rc<RefCell<ScriptHost>>,
        limits: &ScriptLimits,
        deadline: Instant,
    ) -> Result<Self, JsEngineError> {
        let runtime = Runtime::new().map_err(|error| {
            JsEngineError::Internal(format!("QuickJS runtime allocation failed: {error}"))
        })?;
        runtime.set_memory_limit(limits.memory_limit_bytes);
        runtime.set_max_stack_size(QUICKJS_MAX_STACK_BYTES);
        let interrupted = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&interrupted);
        runtime.set_interrupt_handler(Some(Box::new(move || {
            if Instant::now() >= deadline {
                flag.store(true, Ordering::Relaxed);
                true
            } else {
                false
            }
        })));
        let context = Context::full(&runtime).map_err(|error| {
            JsEngineError::Internal(format!("QuickJS context allocation failed: {error}"))
        })?;
        context
            .with(|ctx| {
                let function = Function::new(
                    ctx.clone(),
                    move |op: String, payload: Opt<String>| -> Option<String> {
                        host.borrow_mut()
                            .call(&op, payload.0.as_deref().unwrap_or(""))
                    },
                )?;
                ctx.globals().set(SCRIPT_HOST_FUNCTION, function)
            })
            .map_err(|error| {
                JsEngineError::Internal(format!("QuickJS host binding failed: {error}"))
            })?;
        Ok(Self {
            context,
            runtime,
            interrupted,
            bytecode: Arc::default(),
        })
    }

    fn with_bytecode(mut self, cache: &Arc<BytecodeCache>) -> Self {
        self.bytecode = Arc::clone(cache);
        self
    }

    fn classify(&self, message: String) -> JsEngineError {
        if self.interrupted.load(Ordering::Relaxed) {
            JsEngineError::Interrupted
        } else if message.contains("out of memory") || message.contains("Allocation failed") {
            JsEngineError::OutOfMemory
        } else {
            JsEngineError::Exception(truncate_utf8(message.trim(), MAX_ERROR_MESSAGE_BYTES))
        }
    }
}

impl JsEngineContext for QuickJsContext {
    fn eval(&mut self, source: &str, filename: &str) -> Result<(), JsEngineError> {
        let result = self.context.with(|ctx| {
            let mut options = EvalOptions::default();
            options.strict = false;
            options.filename = Some(filename.to_string());
            ctx.eval_with_options::<(), _>(source, options)
                .catch(&ctx)
                .map_err(|error| error.to_string())
        });
        result.map_err(|message| self.classify(message))
    }

    fn eval_script(&mut self, source: &str, filename: &str) -> Result<(), JsEngineError> {
        if source.len() < BYTECODE_CACHE_MIN_SOURCE_BYTES || source.contains('\0') {
            return self.eval(source, filename);
        }
        let key = SourceKey::of(source);
        let cache = Arc::clone(&self.bytecode);
        let result = self
            .context
            .with(|ctx| run_cached(&ctx, &cache, key, source, filename));
        result.map_err(|message| self.classify(message))
    }

    fn run_jobs(&mut self) -> Result<(), JsEngineError> {
        loop {
            match self.runtime.execute_pending_job() {
                Ok(true) => continue,
                Ok(false) => return Ok(()),
                Err(job) => {
                    let message = job.0.with(|ctx| {
                        CaughtError::from_error(&ctx, rquickjs::Error::Exception).to_string()
                    });
                    return Err(self.classify(message));
                }
            }
        }
    }
}

/// Runs `source` as sloppy-mode global code from its cached bytecode,
/// compiling and caching it first when it is not cached yet.
fn run_cached(
    ctx: &Ctx<'_>,
    cache: &BytecodeCache,
    key: SourceKey,
    source: &str,
    filename: &str,
) -> Result<(), String> {
    let raw = ctx.as_raw().as_ptr();
    let exception = || {
        Err::<(), _>(rquickjs::Error::Exception)
            .catch(ctx)
            .map_err(|error| error.to_string())
    };
    let function = match cache.get(&key) {
        // SAFETY: the bytes are what `JS_WriteObject` produced for this
        // engine build in `compile`; `JS_ReadObject` copies them.
        Some(bytecode) => unsafe {
            qjs::JS_ReadObject(
                raw,
                bytecode.as_ptr(),
                bytecode.len() as _,
                qjs::JS_READ_OBJ_BYTECODE as i32,
            )
        },
        None => compile(raw, cache, key, source, filename)?,
    };
    // SAFETY: `function` is an owned value of this context.
    if unsafe { qjs::JS_IsException(function) } {
        return exception();
    }
    // SAFETY: `JS_EvalFunction` takes ownership of `function`.
    let value = unsafe { qjs::JS_EvalFunction(raw, function) };
    // SAFETY: `value` is owned and freed once.
    unsafe {
        if qjs::JS_IsException(value) {
            return exception();
        }
        qjs::JS_FreeValue(raw, value);
    }
    Ok(())
}

/// Compiles `source` without running it and caches its bytecode. Returns the
/// compiled function, or the exception value when it does not compile.
fn compile(
    raw: *mut qjs::JSContext,
    cache: &BytecodeCache,
    key: SourceKey,
    source: &str,
    filename: &str,
) -> Result<qjs::JSValue, String> {
    let text = CString::new(source).map_err(|_| "script contains a NUL byte".to_string())?;
    let name = CString::new(filename).unwrap_or_default();
    // SAFETY: `text` is NUL-terminated and `source.len()` bytes long, as
    // `JS_Eval` requires; the flags compile global code without running it.
    let function = unsafe {
        qjs::JS_Eval(
            raw,
            text.as_ptr(),
            source.len() as _,
            name.as_ptr(),
            (qjs::JS_EVAL_TYPE_GLOBAL | qjs::JS_EVAL_FLAG_COMPILE_ONLY) as i32,
        )
    };
    // SAFETY: reads the tag of an owned value.
    if unsafe { qjs::JS_IsException(function) } {
        return Ok(function);
    }
    let mut size = 0;
    // SAFETY: `function` stays owned here; the returned buffer is freed with
    // `js_free` after copying. A failed write leaves a pending exception,
    // which is cleared: the script still runs, uncached.
    unsafe {
        let buffer =
            qjs::JS_WriteObject(raw, &mut size, function, qjs::JS_WRITE_OBJ_BYTECODE as i32);
        if buffer.is_null() {
            let pending = qjs::JS_GetException(raw);
            qjs::JS_FreeValue(raw, pending);
        } else {
            let bytecode = std::slice::from_raw_parts(buffer, size as _).to_vec();
            qjs::js_free(raw, buffer.cast());
            cache.insert(key, bytecode);
        }
    }
    Ok(function)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ScriptRequest, ScriptRunStatus};

    fn invocation() -> ScriptInvocation {
        ScriptInvocation {
            phase: crate::ScriptPhase::Request,
            script_name: "large".to_string(),
            argument: String::new(),
            request: ScriptRequest {
                url: "https://api.example.test/".to_string(),
                method: "GET".to_string(),
                headers: Vec::new(),
                body: None,
            },
            response: None,
            binary_body: false,
            event: None,
        }
    }

    #[test]
    fn large_scripts_are_compiled_once_and_run_fresh_each_time() {
        let runtime = QuickJsScriptRuntime::default();
        let padding = "x".repeat(BYTECODE_CACHE_MIN_SOURCE_BYTES);
        let script = format!(
            "var pad = '{padding}'; globalThis.runs = (globalThis.runs || 0) + 1;\n\
             function answer() {{ return runs + ':' + pad.length + ':' + $request.method; }}\n\
             $done({{ response: {{ status: 200, body: answer() }} }});"
        );
        let limits = ScriptLimits::default();
        for _ in 0..3 {
            let outcome = runtime.run(&script, &invocation(), &limits);
            assert_eq!(outcome.status, ScriptRunStatus::Done, "{:?}", outcome.logs);
            let body = outcome
                .applied_mutation()
                .and_then(|mutation| mutation.response.clone())
                .and_then(|response| response.body);
            // Each run starts from a fresh global object.
            assert_eq!(
                body.as_deref(),
                Some(format!("1:{}:GET", padding.len()).as_str())
            );
        }
        assert_eq!(runtime.bytecode.len(), 1);
    }

    #[test]
    fn large_scripts_that_do_not_compile_report_the_error_and_stay_uncached() {
        let runtime = QuickJsScriptRuntime::default();
        let script = format!(
            "var pad = '{}';\nfunction (",
            "x".repeat(BYTECODE_CACHE_MIN_SOURCE_BYTES)
        );
        for _ in 0..2 {
            let outcome = runtime.run(&script, &invocation(), &ScriptLimits::default());
            let ScriptRunStatus::Failed(failure) = &outcome.status else {
                panic!("expected a failure, got {:?}", outcome.status);
            };
            assert_eq!(failure.code(), "script.exception");
        }
        assert_eq!(runtime.bytecode.len(), 0);
    }

    #[test]
    fn a_full_cache_starts_over() {
        let cache = BytecodeCache::default();
        cache.insert(
            SourceKey::of("a"),
            vec![0; BYTECODE_CACHE_MAX_BYTES / 2 + 1],
        );
        cache.insert(
            SourceKey::of("b"),
            vec![0; BYTECODE_CACHE_MAX_BYTES / 2 + 1],
        );
        assert_eq!(cache.len(), 1);
        assert!(cache.get(&SourceKey::of("b")).is_some());
        cache.insert(SourceKey::of("c"), vec![0; BYTECODE_CACHE_MAX_BYTES + 1]);
        assert!(cache.get(&SourceKey::of("c")).is_none());
    }
}
