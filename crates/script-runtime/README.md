# script-runtime

Loon-compatible HTTP script runtime for MITM `[Script]` dispatches (roadmap
M3, Loon plugin tier P1).

The `$`-API is implemented once in Rust (`ScriptHost`):

| Global | Behavior |
|---|---|
| `$request`, `$response` | URL, method, headers (object), UTF-8 body when `requires-body=true`; response status. |
| `$argument` | The line's `argument=` value. |
| `$done(value)` | First call wins. Request phase: `url`, `headers`, `body`, or `response: {status, headers, body}` to answer without the origin. Response phase: `status` (number or status line), `headers`, `body`. `$done()` keeps the message. String bodies only. |
| `$persistentStore.read/write/remove` | Shared key-value store; key ≤ 256 B, value ≤ 512 KiB, total ≤ 8 MiB. A missing key uses `networkcore.script.<tag>`. |
| `$notification.post` | Collected in the outcome (16 at most). |
| `$httpClient.get/post/...` | Goes to a `ScriptHttpClient`; `DisabledScriptHttpClient` (the default) returns an error to the callback. |
| `$prefs.valueForKey/setValueForKey/removeValueForKey` | Quantumult X names for `$persistentStore`; same store. `removeAllValues` returns `false`. |
| `$notify(title, subtitle, content, options)` | Quantumult X name for `$notification.post`; `options["open-url"]` is the URL. |
| `$task.fetch(options)` | Quantumult X; a promise over `$httpClient` resolving `{statusCode, headers, body}` or rejecting `{error}`. Defined only when the script uses `$task` and never names `$loon`, because cross-client scripts (Env.js) check `$task` first and must take their Loon branch. |
| `$response.statusCode` | Same as `$response.status`, for Quantumult X scripts. |
| `console.*`, `setTimeout`, `clearTimeout` | Logs are collected (128 lines); timers run inside the dispatch budget. |
| `$loon`, `$script` | `NetworkCore/<version>`; script name and type. |

An engine binding implements `JsEngineContext` (evaluate sloppy-mode global
code, drain promise jobs) and defines one host function, `__nc_host(op,
payload)`, that forwards to `ScriptHost::call`. `run_script` evaluates the
shared `src/prelude.js` and the script, then services timers and `$httpClient`
callbacks until `$done`, idle, or the deadline. `finish_outcome` maps the
result the same way for every engine.

The desktop binding is QuickJS-ng through rquickjs (`QuickJsScriptRuntime`).
Each dispatch gets a fresh runtime with a heap limit and an interrupt handler
for the wall-clock timeout, so Loon's `timeout` and `max-size` hold even for
busy loops. Scripts have no file system, process, or network access of their
own. The iOS packet tunnel uses this binding too (decided 2026-10-24, until an
App Store build moves to JavaScriptCore); rquickjs ships no iOS bindings, so on
iOS targets the `bindgen` feature generates them from Xcode's libclang.

The Apple binding is JavaScriptCore through its public C API
(`JscScriptRuntime`, cargo feature `javascriptcore`, Apple targets only; roadmap
M4). Its public API has no interrupt and no heap limit, so each dispatch runs on
a worker thread under a watchdog:

- timers and `$httpClient` callbacks stop at the deadline in the shared event
  loop, as with QuickJS;
- synchronous JavaScript still running at the deadline is reported as
  `script.timeout`, and the worker is abandoned and counted as stuck; while
  `MAX_STUCK_WORKERS` (2) workers are stuck, new dispatches fail fast with
  `script.engine`, and the caller should disable the script and restart;
- memory is bounded only by the body caps checked before the script runs
  (`ENFORCES_HEAP_LIMIT = false`).

`tests/fixtures/conformance/<case>.js` plus `<case>.json` (invocation, initial
store, limits, expected outcome, and optional `requires` engine capabilities)
form the engine-neutral conformance suite. QuickJS runs every fixture; the CI
job "JavaScriptCore script conformance" (macOS) runs the same files with
JavaScriptCore, which may skip only `memory-limit` (`requires: heap-limit`).
