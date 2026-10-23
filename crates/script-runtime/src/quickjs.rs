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
use rquickjs::{CatchResultExt, CaughtError, Context, Function, Runtime};
use std::cell::RefCell;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

const QUICKJS_MAX_STACK_BYTES: usize = 512 * 1024;
const MAX_ERROR_MESSAGE_BYTES: usize = 1024;

/// Runs each dispatch in a fresh QuickJS runtime, so scripts share nothing but
/// the persistent store.
#[derive(Clone)]
pub struct QuickJsScriptRuntime {
    store: Arc<dyn ScriptStore>,
    http_client: Arc<dyn ScriptHttpClient>,
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
        Self { store, http_client }
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
        let request_body = invocation.request.body.as_deref().map_or(0, str::len);
        let response_body = invocation
            .response
            .as_ref()
            .and_then(|response| response.body.as_deref())
            .map_or(0, str::len);
        if request_body > limits.max_body_bytes || response_body > limits.max_body_bytes {
            return ScriptOutcome::failed(ScriptFailure::BodyTooLarge);
        }

        let deadline = Instant::now() + limits.timeout;
        let host = Rc::new(RefCell::new(ScriptHost::new(
            invocation,
            limits,
            Arc::clone(&self.store),
        )));
        let result = match QuickJsContext::new(Rc::clone(&host), limits, deadline) {
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
        })
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
