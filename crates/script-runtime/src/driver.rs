//! Engine-neutral event loop. A binding implements [`JsEngineContext`]; the
//! loop, `$httpClient` and timer dispatch, and result mapping are shared so
//! every engine behaves the same on the conformance fixtures.

use crate::host::{headers_object, HostEvent};
use crate::{
    ScriptFailure, ScriptHost, ScriptHttpClient, ScriptOutcome, ScriptRunStatus, SCRIPT_PRELUDE,
};
use serde_json::json;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Instant;

pub const PRELUDE_FILENAME: &str = "networkcore-prelude.js";
const DISPATCH_FILENAME: &str = "networkcore-dispatch.js";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsEngineError {
    /// The deadline passed while JavaScript was running or waiting.
    Interrupted,
    OutOfMemory,
    /// The script threw; the message is engine-formatted.
    Exception(String),
    Internal(String),
}

/// What an engine binding provides. The binding must define the host function
/// [`crate::SCRIPT_HOST_FUNCTION`] forwarding to [`ScriptHost::call`] before
/// [`run_script`] runs, and must evaluate sources as sloppy-mode global code,
/// because Loon scripts commonly assign undeclared globals.
pub trait JsEngineContext {
    fn eval(&mut self, source: &str, filename: &str) -> Result<(), JsEngineError>;
    /// Runs queued promise jobs until the queue is empty.
    fn run_jobs(&mut self) -> Result<(), JsEngineError>;
}

/// Runs the prelude and `script`, then services timers and `$httpClient`
/// callbacks until the script calls `$done`, runs out of work, or the
/// deadline passes.
pub fn run_script<E: JsEngineContext + ?Sized>(
    engine: &mut E,
    host: &Rc<RefCell<ScriptHost>>,
    http_client: &dyn ScriptHttpClient,
    script: &str,
    script_name: &str,
    deadline: Instant,
) -> Result<(), JsEngineError> {
    engine.eval(SCRIPT_PRELUDE, PRELUDE_FILENAME)?;
    engine.eval(script, script_name)?;
    engine.run_jobs()?;
    loop {
        if host.borrow().is_done() {
            return Ok(());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err(JsEngineError::Interrupted);
        }
        let event = host.borrow_mut().next_event(now);
        match event {
            HostEvent::Http(id, request) => {
                let event = match request {
                    Ok(mut request) => {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        request.timeout = if request.timeout.is_zero() {
                            remaining
                        } else {
                            request.timeout.min(remaining)
                        };
                        match http_client.execute(&request) {
                            Ok(response) => json!({
                                "kind": "http",
                                "id": id,
                                "error": null,
                                "status": response.status,
                                "headers": headers_object(&response.headers),
                                "body": response.body.unwrap_or_default(),
                            }),
                            Err(error) => http_error(id, &error),
                        }
                    }
                    Err(error) => http_error(id, &error),
                };
                dispatch(engine, &event)?;
            }
            HostEvent::Timer(id) => dispatch(engine, &json!({ "kind": "timer", "id": id }))?,
            HostEvent::Wait(at) => {
                std::thread::sleep(at.min(deadline).saturating_duration_since(now));
            }
            HostEvent::Idle => return Ok(()),
        }
    }
}

fn http_error(id: u64, error: &str) -> serde_json::Value {
    json!({ "kind": "http", "id": id, "error": error })
}

fn dispatch<E: JsEngineContext + ?Sized>(
    engine: &mut E,
    event: &serde_json::Value,
) -> Result<(), JsEngineError> {
    engine.eval(&format!("__nc_dispatch({event});"), DISPATCH_FILENAME)?;
    engine.run_jobs()
}

/// Maps the run result and the host state to an outcome. A valid `$done`
/// wins over a later error, as in Loon, where `$done` ends the dispatch.
pub fn finish_outcome(result: Result<(), JsEngineError>, host: &mut ScriptHost) -> ScriptOutcome {
    let results = host.take_results();
    let (status, mutation) = match (results.done, result) {
        (Some(Ok(mutation)), _) => (ScriptRunStatus::Done, mutation),
        (Some(Err(message)), _) => (
            ScriptRunStatus::Failed(ScriptFailure::InvalidDone(message)),
            Default::default(),
        ),
        (None, Ok(())) => (ScriptRunStatus::FinishedWithoutDone, Default::default()),
        (None, Err(error)) => (
            ScriptRunStatus::Failed(match error {
                JsEngineError::Interrupted => ScriptFailure::Timeout,
                JsEngineError::OutOfMemory => ScriptFailure::MemoryLimit,
                JsEngineError::Exception(message) => ScriptFailure::Exception(message),
                JsEngineError::Internal(message) => ScriptFailure::Engine(message),
            }),
            Default::default(),
        ),
    };
    ScriptOutcome {
        status,
        mutation,
        notifications: results.notifications,
        logs: results.logs,
        logs_truncated: results.logs_truncated,
    }
}
