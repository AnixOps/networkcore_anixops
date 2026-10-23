//! The `$`-API host. Engine bindings expose [`ScriptHost::call`] to scripts as
//! one function named [`SCRIPT_HOST_FUNCTION`]; [`SCRIPT_PRELUDE`] builds the
//! Loon globals on top of it. Every operation takes and returns strings, so a
//! binding needs no knowledge of the API.

use crate::{
    ScriptHttpClientRequest, ScriptInvocation, ScriptLimits, ScriptMutation, ScriptNotification,
    ScriptPhase, ScriptResponse, ScriptStore, SCRIPT_ENVIRONMENT,
};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Global the binding defines before evaluating [`SCRIPT_PRELUDE`]. The
/// prelude removes it from the global object.
pub const SCRIPT_HOST_FUNCTION: &str = "__nc_host";

/// Shared JavaScript prelude, evaluated unchanged by every engine binding.
pub const SCRIPT_PRELUDE: &str = include_str!("prelude.js");

const MAX_NOTIFICATIONS: usize = 16;
const MAX_LOG_LINES: usize = 128;
const MAX_LOG_LINE_BYTES: usize = 2048;
const MAX_TIMERS: usize = 64;
const MAX_HTTP_REQUESTS: usize = 16;

pub(crate) enum HostEvent {
    Http(u64, Result<ScriptHttpClientRequest, String>),
    Timer(u64),
    Wait(Instant),
    Idle,
}

pub(crate) struct HostResults {
    pub done: Option<Result<ScriptMutation, String>>,
    pub notifications: Vec<ScriptNotification>,
    pub logs: Vec<String>,
    pub logs_truncated: bool,
}

pub struct ScriptHost {
    context_json: String,
    phase: ScriptPhase,
    default_store_key: String,
    max_output_bytes: usize,
    store: Arc<dyn ScriptStore>,
    done: Option<Result<ScriptMutation, String>>,
    notifications: Vec<ScriptNotification>,
    logs: Vec<String>,
    logs_truncated: bool,
    next_id: u64,
    timers: BTreeMap<u64, Instant>,
    pending_http: VecDeque<(u64, Result<ScriptHttpClientRequest, String>)>,
    http_requests: usize,
}

impl ScriptHost {
    pub fn new(
        invocation: &ScriptInvocation,
        limits: &ScriptLimits,
        store: Arc<dyn ScriptStore>,
    ) -> Self {
        Self {
            context_json: context_json(invocation),
            phase: invocation.phase,
            default_store_key: format!("networkcore.script.{}", invocation.script_name),
            max_output_bytes: limits.max_output_bytes,
            store,
            done: None,
            notifications: Vec::new(),
            logs: Vec::new(),
            logs_truncated: false,
            next_id: 1,
            timers: BTreeMap::new(),
            pending_http: VecDeque::new(),
            http_requests: 0,
        }
    }

    /// Handles one host call from the prelude. Unknown operations return
    /// `None` (`undefined` in JavaScript).
    pub fn call(&mut self, op: &str, payload: &str) -> Option<String> {
        match op {
            "context" => Some(self.context_json.clone()),
            "done" => {
                if self.done.is_none() {
                    self.done = Some(parse_done(self.phase, payload, self.max_output_bytes));
                }
                None
            }
            "store.read" => self.store.read(&self.store_key(payload)),
            "store.write" => Some(self.store_write(payload).to_string()),
            "store.remove" => Some(self.store.remove(&self.store_key(payload)).to_string()),
            "notify" => {
                self.notify(payload);
                None
            }
            "log" => {
                self.log(payload);
                None
            }
            "timer.set" => Some(self.set_timer(payload).to_string()),
            "timer.clear" => {
                if let Ok(id) = payload.trim().parse::<u64>() {
                    self.timers.remove(&id);
                }
                None
            }
            "http.request" => Some(self.queue_http(payload).to_string()),
            _ => None,
        }
    }

    pub fn is_done(&self) -> bool {
        self.done.is_some()
    }

    /// Next unit of asynchronous work: queued `$httpClient` calls first, then
    /// due timers in id order, then the earliest pending timer.
    pub(crate) fn next_event(&mut self, now: Instant) -> HostEvent {
        if let Some((id, request)) = self.pending_http.pop_front() {
            return HostEvent::Http(id, request);
        }
        let due = self
            .timers
            .iter()
            .find(|(_, at)| **at <= now)
            .map(|(id, _)| *id);
        if let Some(id) = due {
            self.timers.remove(&id);
            return HostEvent::Timer(id);
        }
        match self.timers.values().min() {
            Some(at) => HostEvent::Wait(*at),
            None => HostEvent::Idle,
        }
    }

    pub(crate) fn take_results(&mut self) -> HostResults {
        HostResults {
            done: self.done.take(),
            notifications: std::mem::take(&mut self.notifications),
            logs: std::mem::take(&mut self.logs),
            logs_truncated: self.logs_truncated,
        }
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn store_key(&self, key: &str) -> String {
        if key.is_empty() {
            self.default_store_key.clone()
        } else {
            key.to_string()
        }
    }

    fn store_write(&self, payload: &str) -> bool {
        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            return false;
        };
        let key = value.get("key").and_then(Value::as_str).unwrap_or("");
        let Some(data) = value.get("value").and_then(Value::as_str) else {
            return false;
        };
        self.store.write(&self.store_key(key), data)
    }

    fn notify(&mut self, payload: &str) {
        if self.notifications.len() >= MAX_NOTIFICATIONS {
            return;
        }
        let Ok(value) = serde_json::from_str::<Value>(payload) else {
            return;
        };
        let field = |name: &str| {
            truncate_utf8(
                value.get(name).and_then(Value::as_str).unwrap_or(""),
                MAX_LOG_LINE_BYTES,
            )
        };
        let open_url = Some(field("url")).filter(|url| !url.is_empty());
        self.notifications.push(ScriptNotification {
            title: field("title"),
            subtitle: field("subtitle"),
            content: field("content"),
            open_url,
        });
    }

    fn log(&mut self, line: &str) {
        if self.logs.len() >= MAX_LOG_LINES {
            self.logs_truncated = true;
            return;
        }
        if line.len() > MAX_LOG_LINE_BYTES {
            self.logs_truncated = true;
        }
        self.logs.push(truncate_utf8(line, MAX_LOG_LINE_BYTES));
    }

    /// Returns the timer id, or 0 when the timer limit is reached.
    fn set_timer(&mut self, payload: &str) -> u64 {
        if self.timers.len() >= MAX_TIMERS {
            return 0;
        }
        let delay_ms = payload
            .trim()
            .parse::<f64>()
            .ok()
            .filter(|delay| delay.is_finite() && *delay > 0.0)
            .unwrap_or(0.0)
            .min(u32::MAX as f64);
        let id = self.next_id();
        self.timers
            .insert(id, Instant::now() + Duration::from_millis(delay_ms as u64));
        id
    }

    /// Queues a `$httpClient` call. Invalid options still get an id so the
    /// script callback receives the error.
    fn queue_http(&mut self, payload: &str) -> u64 {
        let id = self.next_id();
        let request = if self.http_requests >= MAX_HTTP_REQUESTS {
            Err("networkcore: $httpClient request limit reached".to_string())
        } else {
            parse_http_request(payload)
        };
        self.http_requests += 1;
        self.pending_http.push_back((id, request));
        id
    }
}

fn context_json(invocation: &ScriptInvocation) -> String {
    let mut request = Map::new();
    request.insert("url".into(), json!(invocation.request.url));
    request.insert("method".into(), json!(invocation.request.method));
    request.insert(
        "headers".into(),
        headers_object(&invocation.request.headers),
    );
    if let Some(body) = &invocation.request.body {
        request.insert("body".into(), json!(body));
    }

    let mut context = Map::new();
    context.insert("phase".into(), json!(invocation.phase.as_str()));
    context.insert("scriptName".into(), json!(invocation.script_name));
    context.insert("argument".into(), json!(invocation.argument));
    context.insert("environment".into(), json!(SCRIPT_ENVIRONMENT));
    context.insert("request".into(), Value::Object(request));
    if let Some(response) = &invocation.response {
        let mut object = Map::new();
        object.insert("status".into(), json!(response.status));
        object.insert("headers".into(), headers_object(&response.headers));
        if let Some(body) = &response.body {
            object.insert("body".into(), json!(body));
        }
        context.insert("response".into(), Value::Object(object));
    }
    Value::Object(context).to_string()
}

/// Header lists become plain objects; repeated names are joined with ", ".
pub(crate) fn headers_object(headers: &[(String, String)]) -> Value {
    let mut object = Map::new();
    for (name, value) in headers {
        match object.get_mut(name) {
            Some(Value::String(existing)) => {
                existing.push_str(", ");
                existing.push_str(value);
            }
            _ => {
                object.insert(name.clone(), Value::String(value.clone()));
            }
        }
    }
    Value::Object(object)
}

fn present<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key).filter(|value| !value.is_null())
}

fn parse_done(
    phase: ScriptPhase,
    payload: &str,
    max_output_bytes: usize,
) -> Result<ScriptMutation, String> {
    let value = serde_json::from_str::<Value>(payload)
        .map_err(|_| "$done argument is not JSON-serializable".to_string())?;
    let Value::Object(object) = value else {
        return Err("$done argument must be an object".to_string());
    };

    let mut mutation = ScriptMutation::default();
    if let Some(headers) = present(&object, "headers") {
        mutation.headers = Some(parse_headers(headers)?);
    }
    if let Some(body) = present(&object, "body") {
        mutation.body = Some(parse_body(body, max_output_bytes)?);
    }
    match phase {
        ScriptPhase::Request => {
            if let Some(url) = present(&object, "url") {
                let url = url
                    .as_str()
                    .ok_or_else(|| "$done url must be a string".to_string())?;
                if url.len() > max_output_bytes || url.contains(['\r', '\n']) {
                    return Err("$done url is invalid".to_string());
                }
                mutation.url = Some(url.to_string());
            }
            if let Some(response) = present(&object, "response") {
                mutation.response = Some(parse_response(response, max_output_bytes)?);
            }
        }
        ScriptPhase::Response => {
            if let Some(status) = present(&object, "status") {
                mutation.status = Some(parse_status(status)?);
            }
        }
    }
    Ok(mutation)
}

fn parse_response(value: &Value, max_output_bytes: usize) -> Result<ScriptResponse, String> {
    let Value::Object(object) = value else {
        return Err("$done response must be an object".to_string());
    };
    let status = match present(object, "status") {
        Some(status) => parse_status(status)?,
        None => 200,
    };
    let headers = match present(object, "headers") {
        Some(headers) => parse_headers(headers)?,
        None => Vec::new(),
    };
    let body = match present(object, "body") {
        Some(body) => Some(parse_body(body, max_output_bytes)?),
        None => None,
    };
    Ok(ScriptResponse {
        status,
        headers,
        body,
    })
}

/// Accepts a number or a status line such as `HTTP/1.1 404 Not Found`.
fn parse_status(value: &Value) -> Result<u16, String> {
    let status = match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text
            .split_whitespace()
            .find_map(|token| token.parse::<u64>().ok()),
        _ => None,
    };
    status
        .filter(|status| (100..=599).contains(status))
        .map(|status| status as u16)
        .ok_or_else(|| "$done status must be an HTTP status between 100 and 599".to_string())
}

fn parse_headers(value: &Value) -> Result<Vec<(String, String)>, String> {
    let Value::Object(object) = value else {
        return Err("$done headers must be an object".to_string());
    };
    let mut headers = Vec::with_capacity(object.len());
    for (name, value) in object {
        let value = match value {
            Value::Null => continue,
            Value::String(text) => text.clone(),
            Value::Number(number) => number.to_string(),
            Value::Bool(flag) => flag.to_string(),
            _ => return Err(format!("$done header {name} must be a string")),
        };
        let name_valid = !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b':');
        if !name_valid || value.contains(['\r', '\n', '\0']) {
            return Err("$done headers contain an invalid name or value".to_string());
        }
        headers.push((name.clone(), value));
    }
    Ok(headers)
}

fn parse_body(value: &Value, max_output_bytes: usize) -> Result<String, String> {
    let body = value.as_str().ok_or_else(|| {
        "$done body must be a string; binary bodies are not supported".to_string()
    })?;
    if body.len() > max_output_bytes {
        return Err("$done body exceeds the output limit".to_string());
    }
    Ok(body.to_string())
}

fn parse_http_request(payload: &str) -> Result<ScriptHttpClientRequest, String> {
    let value = serde_json::from_str::<Value>(payload)
        .map_err(|_| "networkcore: invalid $httpClient options".to_string())?;
    let method = value
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("GET")
        .to_ascii_uppercase();
    let url = value.get("url").and_then(Value::as_str).unwrap_or("");
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err("networkcore: $httpClient needs an http or https URL".to_string());
    }
    let headers = match value.get("headers").filter(|headers| !headers.is_null()) {
        Some(headers) => parse_headers(headers)
            .map_err(|_| "networkcore: invalid $httpClient headers".to_string())?,
        None => Vec::new(),
    };
    let body = value
        .get("body")
        .and_then(Value::as_str)
        .map(str::to_string);
    let timeout_ms = value
        .get("timeout")
        .and_then(Value::as_f64)
        .filter(|timeout| timeout.is_finite() && *timeout > 0.0)
        .unwrap_or(0.0)
        .min(u32::MAX as f64);
    Ok(ScriptHttpClientRequest {
        method,
        url: url.to_string(),
        headers,
        body,
        // Zero means "the rest of the dispatch budget"; the driver caps it.
        timeout: Duration::from_millis(timeout_ms as u64),
    })
}

pub(crate) fn truncate_utf8(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}
