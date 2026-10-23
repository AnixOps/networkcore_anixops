//! Apple JavaScriptCore binding through the public C API (no Swift hop). It
//! only registers the host function and evaluates sources; the `$`-API lives
//! in [`crate::ScriptHost`] and the event loop in [`crate::run_script`].
//!
//! JavaScriptCore's public API has no interrupt and no heap limit (both are
//! private API, which App Store builds must not use). Each dispatch therefore
//! runs on its own worker thread under a watchdog:
//!
//! - Timers and `$httpClient` callbacks stop at the deadline in the shared
//!   event loop, exactly as with QuickJS.
//! - Synchronous JavaScript that is still running at the deadline cannot be
//!   stopped. The watchdog reports [`ScriptFailure::Timeout`], abandons the
//!   worker (its result is dropped when it finishes), and counts it as stuck.
//!   While [`MAX_STUCK_WORKERS`] workers are stuck, new dispatches fail fast
//!   with [`ScriptFailure::Engine`] instead of burning more CPU; the caller
//!   should disable the script and restart the tunnel.
//! - Memory is bounded only by the body caps checked before the script runs
//!   ([`crate::ScriptLimits::max_body_bytes`] and `max_output_bytes`).
//!   [`JscScriptRuntime::ENFORCES_HEAP_LIMIT`] is `false`.

use crate::driver::{finish_outcome, run_script, JsEngineContext, JsEngineError};
use crate::host::truncate_utf8;
use crate::{
    DisabledScriptHttpClient, MemoryScriptStore, ScriptFailure, ScriptHost, ScriptHttpClient,
    ScriptInvocation, ScriptLimits, ScriptOutcome, ScriptStore, SCRIPT_HOST_FUNCTION,
};
use std::cell::RefCell;
use std::os::raw::{c_int, c_uint, c_void};
use std::rc::Rc;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

/// Stuck workers tolerated before new dispatches are refused.
pub const MAX_STUCK_WORKERS: usize = 2;

const WORKER_STACK_BYTES: usize = 4 * 1024 * 1024;
const MAX_ERROR_MESSAGE_BYTES: usize = 1024;
/// Extra time the watchdog gives the event loop to report its own timeout.
const WATCHDOG_GRACE: Duration = Duration::from_millis(250);

const WORKER_RUNNING: u8 = 0;
const WORKER_FINISHED: u8 = 1;
const WORKER_ABANDONED: u8 = 2;

/// Runs each dispatch in a fresh JavaScriptCore context on a worker thread, so
/// scripts share nothing but the persistent store.
#[derive(Clone)]
pub struct JscScriptRuntime {
    store: Arc<dyn ScriptStore>,
    http_client: Arc<dyn ScriptHttpClient>,
    stuck_workers: Arc<AtomicUsize>,
}

impl Default for JscScriptRuntime {
    fn default() -> Self {
        Self::new(
            Arc::new(MemoryScriptStore::new()),
            Arc::new(DisabledScriptHttpClient),
        )
    }
}

impl std::fmt::Debug for JscScriptRuntime {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JscScriptRuntime")
            .field("stuck_workers", &self.stuck_workers())
            .finish_non_exhaustive()
    }
}

impl JscScriptRuntime {
    pub const ENGINE_NAME: &'static str = "javascriptcore";
    /// JavaScriptCore's public API cannot cap the heap.
    pub const ENFORCES_HEAP_LIMIT: bool = false;

    pub fn new(store: Arc<dyn ScriptStore>, http_client: Arc<dyn ScriptHttpClient>) -> Self {
        Self {
            store,
            http_client,
            stuck_workers: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn store(&self) -> &Arc<dyn ScriptStore> {
        &self.store
    }

    /// Workers abandoned at their deadline that are still running.
    pub fn stuck_workers(&self) -> usize {
        self.stuck_workers.load(Ordering::SeqCst)
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
        if self.stuck_workers() >= MAX_STUCK_WORKERS {
            return ScriptOutcome::failed(ScriptFailure::Engine(
                "javascriptcore: too many scripts are stuck past their timeout".to_string(),
            ));
        }

        let deadline = Instant::now() + limits.timeout;
        let state = Arc::new(AtomicU8::new(WORKER_RUNNING));
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = {
            let script = script.to_string();
            let invocation = invocation.clone();
            let limits = *limits;
            let store = Arc::clone(&self.store);
            let http_client = Arc::clone(&self.http_client);
            let stuck_workers = Arc::clone(&self.stuck_workers);
            let state = Arc::clone(&state);
            std::thread::Builder::new()
                .name("networkcore-jsc".to_string())
                .stack_size(WORKER_STACK_BYTES)
                .spawn(move || {
                    let outcome = run_on_worker(
                        &script,
                        &invocation,
                        &limits,
                        store,
                        http_client.as_ref(),
                        deadline,
                    );
                    if state
                        .compare_exchange(
                            WORKER_RUNNING,
                            WORKER_FINISHED,
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        )
                        .is_err()
                    {
                        // The watchdog gave up on this worker; it is no longer stuck.
                        stuck_workers.fetch_sub(1, Ordering::SeqCst);
                    }
                    let _ = sender.send(outcome);
                })
        };
        if let Err(error) = worker {
            return ScriptOutcome::failed(ScriptFailure::Engine(format!(
                "javascriptcore: worker thread failed to start: {error}"
            )));
        }

        match receiver.recv_timeout(limits.timeout + WATCHDOG_GRACE) {
            Ok(outcome) => outcome,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if state
                    .compare_exchange(
                        WORKER_RUNNING,
                        WORKER_ABANDONED,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    )
                    .is_ok()
                {
                    self.stuck_workers.fetch_add(1, Ordering::SeqCst);
                    ScriptOutcome::failed(ScriptFailure::Timeout)
                } else {
                    // Finished between the timeout and the state change.
                    receiver.recv().unwrap_or_else(|_| {
                        ScriptOutcome::failed(ScriptFailure::Engine(
                            "javascriptcore: worker exited without a result".to_string(),
                        ))
                    })
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => ScriptOutcome::failed(
                ScriptFailure::Engine("javascriptcore: worker exited without a result".to_string()),
            ),
        }
    }
}

fn run_on_worker(
    script: &str,
    invocation: &ScriptInvocation,
    limits: &ScriptLimits,
    store: Arc<dyn ScriptStore>,
    http_client: &dyn ScriptHttpClient,
    deadline: Instant,
) -> ScriptOutcome {
    let host = Rc::new(RefCell::new(ScriptHost::new(invocation, limits, store)));
    let result = match JscContext::new(Rc::clone(&host)) {
        Ok(mut engine) => run_script(
            &mut engine,
            &host,
            http_client,
            script,
            &invocation.script_name,
            deadline,
        ),
        Err(error) => Err(error),
    };
    let mut host = host.borrow_mut();
    finish_outcome(result, &mut host)
}

thread_local! {
    /// Host of the dispatch running on this worker. The public C API has no
    /// user data on function callbacks, and each worker runs one dispatch.
    static CURRENT_HOST: RefCell<Option<Rc<RefCell<ScriptHost>>>> = const { RefCell::new(None) };
}

struct JscContext {
    context: sys::JSGlobalContextRef,
}

impl JscContext {
    fn new(host: Rc<RefCell<ScriptHost>>) -> Result<Self, JsEngineError> {
        // SAFETY: a null class creates a context with the default global object.
        let context = unsafe { sys::JSGlobalContextCreate(std::ptr::null_mut()) };
        if context.is_null() {
            return Err(JsEngineError::Internal(
                "JavaScriptCore context allocation failed".to_string(),
            ));
        }
        CURRENT_HOST.with(|current| *current.borrow_mut() = Some(host));
        let engine = Self { context };
        let name = JsString::new(SCRIPT_HOST_FUNCTION);
        let mut exception: sys::JSValueRef = std::ptr::null();
        // SAFETY: the context is live; the property stays deletable (attributes 0)
        // because the prelude removes it from the global object.
        unsafe {
            let function =
                sys::JSObjectMakeFunctionWithCallback(context, name.0, Some(host_function));
            sys::JSObjectSetProperty(
                context,
                sys::JSContextGetGlobalObject(context),
                name.0,
                function as sys::JSValueRef,
                0,
                &mut exception,
            );
        }
        if !exception.is_null() {
            return Err(JsEngineError::Internal(format!(
                "JavaScriptCore host binding failed: {}",
                engine.describe(exception)
            )));
        }
        Ok(engine)
    }

    fn describe(&self, value: sys::JSValueRef) -> String {
        let mut exception: sys::JSValueRef = std::ptr::null();
        // SAFETY: value belongs to this live context.
        let string = unsafe { sys::JSValueToStringCopy(self.context, value, &mut exception) };
        if string.is_null() {
            return "unprintable exception".to_string();
        }
        let message = JsString(string).to_rust();
        truncate_utf8(message.trim(), MAX_ERROR_MESSAGE_BYTES)
    }
}

impl Drop for JscContext {
    fn drop(&mut self) {
        CURRENT_HOST.with(|current| current.borrow_mut().take());
        // SAFETY: created by JSGlobalContextCreate and released once.
        unsafe { sys::JSGlobalContextRelease(self.context) };
    }
}

impl JsEngineContext for JscContext {
    fn eval(&mut self, source: &str, filename: &str) -> Result<(), JsEngineError> {
        let source = JsString::new(source);
        let filename = JsString::new(filename);
        let mut exception: sys::JSValueRef = std::ptr::null();
        // SAFETY: the context is live. A null `this` evaluates sloppy-mode global
        // code. JavaScriptCore drains the microtask queue when the outermost API
        // call returns, so promise jobs have run by the time this returns.
        unsafe {
            sys::JSEvaluateScript(
                self.context,
                source.0,
                std::ptr::null_mut(),
                filename.0,
                1,
                &mut exception,
            );
        }
        if exception.is_null() {
            Ok(())
        } else {
            Err(JsEngineError::Exception(self.describe(exception)))
        }
    }

    fn run_jobs(&mut self) -> Result<(), JsEngineError> {
        // Microtasks are drained at the end of every eval; nothing is queued here.
        Ok(())
    }
}

unsafe extern "C" fn host_function(
    context: sys::JSContextRef,
    _function: sys::JSObjectRef,
    _this: sys::JSObjectRef,
    argument_count: usize,
    arguments: *const sys::JSValueRef,
    _exception: *mut sys::JSValueRef,
) -> sys::JSValueRef {
    let call = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let arguments = if argument_count == 0 || arguments.is_null() {
            &[][..]
        } else {
            // SAFETY: JavaScriptCore passes `argument_count` valid values.
            unsafe { std::slice::from_raw_parts(arguments, argument_count) }
        };
        let argument = |index: usize| -> Option<String> {
            let value = *arguments.get(index)?;
            // SAFETY: values belong to `context` for the duration of the call.
            unsafe {
                if sys::JSValueIsUndefined(context, value) || sys::JSValueIsNull(context, value) {
                    return None;
                }
                let string = sys::JSValueToStringCopy(context, value, std::ptr::null_mut());
                (!string.is_null()).then(|| JsString(string).to_rust())
            }
        };
        let op = argument(0).unwrap_or_default();
        let payload = argument(1).unwrap_or_default();
        CURRENT_HOST.with(|current| {
            let current = current.borrow();
            current
                .as_ref()
                .and_then(|host| host.borrow_mut().call(&op, &payload))
        })
    }));
    // SAFETY: `context` is the calling context.
    unsafe {
        match call {
            Ok(Some(result)) => {
                let result = JsString::new(&result);
                sys::JSValueMakeString(context, result.0)
            }
            _ => sys::JSValueMakeUndefined(context),
        }
    }
}

/// Owned `JSStringRef`, built from UTF-16 so any Rust string (including NUL
/// characters) round-trips.
struct JsString(sys::JSStringRef);

impl JsString {
    fn new(text: &str) -> Self {
        let units = text.encode_utf16().collect::<Vec<u16>>();
        // SAFETY: JavaScriptCore copies `units`.
        Self(unsafe { sys::JSStringCreateWithCharacters(units.as_ptr(), units.len()) })
    }

    fn to_rust(&self) -> String {
        // SAFETY: the string is live; the character pointer is valid for its length.
        unsafe {
            let length = sys::JSStringGetLength(self.0);
            let characters = sys::JSStringGetCharactersPtr(self.0);
            if length == 0 || characters.is_null() {
                return String::new();
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(characters, length))
        }
    }
}

impl Drop for JsString {
    fn drop(&mut self) {
        // SAFETY: created or copied by JavaScriptCore and released once.
        unsafe { sys::JSStringRelease(self.0) };
    }
}

/// The subset of `<JavaScriptCore/JavaScript.h>` this binding uses.
#[allow(non_snake_case)]
mod sys {
    use super::{c_int, c_uint, c_void};

    pub type JSContextRef = *const c_void;
    pub type JSGlobalContextRef = *mut c_void;
    pub type JSClassRef = *mut c_void;
    pub type JSObjectRef = *mut c_void;
    pub type JSStringRef = *mut c_void;
    pub type JSValueRef = *const c_void;
    pub type JSChar = u16;
    pub type JSObjectCallAsFunctionCallback = Option<
        unsafe extern "C" fn(
            JSContextRef,
            JSObjectRef,
            JSObjectRef,
            usize,
            *const JSValueRef,
            *mut JSValueRef,
        ) -> JSValueRef,
    >;

    #[link(name = "JavaScriptCore", kind = "framework")]
    unsafe extern "C" {
        pub fn JSGlobalContextCreate(global_object_class: JSClassRef) -> JSGlobalContextRef;
        pub fn JSGlobalContextRelease(context: JSGlobalContextRef);
        pub fn JSContextGetGlobalObject(context: JSContextRef) -> JSObjectRef;
        pub fn JSEvaluateScript(
            context: JSContextRef,
            script: JSStringRef,
            this_object: JSObjectRef,
            source_url: JSStringRef,
            starting_line_number: c_int,
            exception: *mut JSValueRef,
        ) -> JSValueRef;
        pub fn JSObjectMakeFunctionWithCallback(
            context: JSContextRef,
            name: JSStringRef,
            call_as_function: JSObjectCallAsFunctionCallback,
        ) -> JSObjectRef;
        pub fn JSObjectSetProperty(
            context: JSContextRef,
            object: JSObjectRef,
            property_name: JSStringRef,
            value: JSValueRef,
            attributes: c_uint,
            exception: *mut JSValueRef,
        );
        pub fn JSStringCreateWithCharacters(
            characters: *const JSChar,
            length: usize,
        ) -> JSStringRef;
        pub fn JSStringRelease(string: JSStringRef);
        pub fn JSStringGetLength(string: JSStringRef) -> usize;
        pub fn JSStringGetCharactersPtr(string: JSStringRef) -> *const JSChar;
        pub fn JSValueToStringCopy(
            context: JSContextRef,
            value: JSValueRef,
            exception: *mut JSValueRef,
        ) -> JSStringRef;
        pub fn JSValueIsUndefined(context: JSContextRef, value: JSValueRef) -> bool;
        pub fn JSValueIsNull(context: JSContextRef, value: JSValueRef) -> bool;
        pub fn JSValueMakeString(context: JSContextRef, string: JSStringRef) -> JSValueRef;
        pub fn JSValueMakeUndefined(context: JSContextRef) -> JSValueRef;
    }
}
