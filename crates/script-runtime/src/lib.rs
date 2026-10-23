//! Loon-compatible HTTP script runtime for the M3 P1 plugin tier.
//!
//! The `$`-API (`$request`, `$response`, `$argument`, `$done`,
//! `$persistentStore`, `$notification`, `$httpClient`, `console`, timers) is
//! implemented once in Rust by [`ScriptHost`]. A JavaScript engine binding only
//! exposes one host function, evaluates the shared [`SCRIPT_PRELUDE`] and the
//! user script, and drains its job queue ([`JsEngineContext`]); the event loop
//! in [`run_script`] and the result mapping in [`finish_outcome`] are shared.
//!
//! QuickJS (quickjs-ng through rquickjs) is the desktop binding. The Apple
//! JavaScriptCore binding (M4) implements the same trait and must pass the same
//! conformance fixtures in `tests/fixtures/conformance`.
//!
//! Scripts never get file system, process, or network access of their own.
//! Everything they can reach goes through the host: the persistent store is
//! size-capped, notifications and logs are collected, and `$httpClient` calls
//! go to a [`ScriptHttpClient`] that is disabled unless the caller provides one.

mod driver;
mod host;
mod quickjs;
mod store;

pub use driver::{finish_outcome, run_script, JsEngineContext, JsEngineError};
pub use host::{ScriptHost, SCRIPT_HOST_FUNCTION, SCRIPT_PRELUDE};
pub use quickjs::QuickJsScriptRuntime;
pub use store::{
    JsonFileScriptStore, MemoryScriptStore, ScriptStore, SCRIPT_STORE_MAX_KEY_BYTES,
    SCRIPT_STORE_MAX_TOTAL_BYTES, SCRIPT_STORE_MAX_VALUE_BYTES,
};

use std::time::Duration;

/// Environment string scripts see as `$loon`.
pub const SCRIPT_ENVIRONMENT: &str = concat!("NetworkCore/", env!("CARGO_PKG_VERSION"));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptPhase {
    Request,
    Response,
}

impl ScriptPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

/// Request visible to a script as `$request`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScriptRequest {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    /// UTF-8 body; `None` when the script does not receive the body.
    pub body: Option<String>,
}

/// Response visible to a script as `$response`, or produced by a script.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScriptResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
}

/// One script dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptInvocation {
    pub phase: ScriptPhase,
    /// Script tag or name; also names the default persistent store key.
    pub script_name: String,
    /// The `argument=` value of the `[Script]` line, after argument expansion.
    pub argument: String,
    pub request: ScriptRequest,
    /// Present in the response phase.
    pub response: Option<ScriptResponse>,
}

/// Resource limits for one dispatch. They implement Loon's `timeout` and
/// `max-size` script options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptLimits {
    /// Wall-clock budget for the whole dispatch, including timers and
    /// `$httpClient` callbacks.
    pub timeout: Duration,
    /// QuickJS heap limit.
    pub memory_limit_bytes: usize,
    /// Larger bodies skip the script (Loon `max-size`).
    pub max_body_bytes: usize,
    /// Largest body or URL a script may return through `$done`.
    pub max_output_bytes: usize,
}

impl Default for ScriptLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            memory_limit_bytes: 32 * 1024 * 1024,
            max_body_bytes: 1024 * 1024,
            max_output_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Changes a script requested through `$done`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScriptMutation {
    /// New request URL (request phase).
    pub url: Option<String>,
    /// New response status (response phase).
    pub status: Option<u16>,
    /// Replacement header set.
    pub headers: Option<Vec<(String, String)>>,
    /// Replacement body.
    pub body: Option<String>,
    /// Response returned without contacting the origin (request phase).
    pub response: Option<ScriptResponse>,
}

impl ScriptMutation {
    pub fn is_empty(&self) -> bool {
        self.url.is_none()
            && self.status.is_none()
            && self.headers.is_none()
            && self.body.is_none()
            && self.response.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptNotification {
    pub title: String,
    pub subtitle: String,
    pub content: String,
    pub open_url: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptFailure {
    /// The body exceeds `max_body_bytes`; the script did not run.
    BodyTooLarge,
    Timeout,
    MemoryLimit,
    /// The script threw.
    Exception(String),
    /// `$done` received a value the host cannot apply.
    InvalidDone(String),
    Engine(String),
}

impl ScriptFailure {
    /// Stable code for diagnostics.
    pub fn code(&self) -> &'static str {
        match self {
            Self::BodyTooLarge => "script.body_too_large",
            Self::Timeout => "script.timeout",
            Self::MemoryLimit => "script.memory_limit",
            Self::Exception(_) => "script.exception",
            Self::InvalidDone(_) => "script.invalid_done",
            Self::Engine(_) => "script.engine",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptRunStatus {
    /// The script called `$done`.
    Done,
    /// The script ran out of work without calling `$done`; nothing changes.
    FinishedWithoutDone,
    Failed(ScriptFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptOutcome {
    pub status: ScriptRunStatus,
    /// Empty unless `status` is [`ScriptRunStatus::Done`].
    pub mutation: ScriptMutation,
    pub notifications: Vec<ScriptNotification>,
    pub logs: Vec<String>,
    pub logs_truncated: bool,
}

impl ScriptOutcome {
    pub(crate) fn failed(failure: ScriptFailure) -> Self {
        Self {
            status: ScriptRunStatus::Failed(failure),
            mutation: ScriptMutation::default(),
            notifications: Vec::new(),
            logs: Vec::new(),
            logs_truncated: false,
        }
    }

    /// The mutation to apply, if the script finished with a non-empty one.
    pub fn applied_mutation(&self) -> Option<&ScriptMutation> {
        (self.status == ScriptRunStatus::Done && !self.mutation.is_empty())
            .then_some(&self.mutation)
    }
}

/// Request a script made through `$httpClient`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptHttpClientRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    /// Never longer than the time left in the dispatch.
    pub timeout: Duration,
}

/// Network access for `$httpClient`. Implementations decide which hosts and
/// methods are allowed; an error string is passed to the script callback.
pub trait ScriptHttpClient: Send + Sync {
    fn execute(&self, request: &ScriptHttpClientRequest) -> Result<ScriptResponse, String>;
}

/// Default client: every `$httpClient` call fails with an error the script
/// can observe.
#[derive(Debug, Clone, Copy, Default)]
pub struct DisabledScriptHttpClient;

pub const SCRIPT_HTTP_CLIENT_DISABLED_MESSAGE: &str =
    "networkcore: $httpClient is disabled for this script";

impl ScriptHttpClient for DisabledScriptHttpClient {
    fn execute(&self, _request: &ScriptHttpClientRequest) -> Result<ScriptResponse, String> {
        Err(SCRIPT_HTTP_CLIENT_DISABLED_MESSAGE.to_string())
    }
}
