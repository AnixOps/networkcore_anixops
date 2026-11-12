//! Runtime control: JSON requests from the client while the engine runs.
//!
//! One request is a JSON object naming its command in `cmd`; the answer is a
//! JSON object. The same requests reach the iOS tunnel through
//! `networkcore_ios_runtime_control` and the desktop local proxy through
//! `LocalProxy::control_json`.
//!
//! | `cmd` | Request fields | Answer |
//! | --- | --- | --- |
//! | `traffic` | | [`crate::connections::TrafficSnapshot`] |
//! | `connections` | | [`crate::connections::ConnectionsSnapshot`] |
//! | `close_connection` | `id` | `{"closed": bool}` |
//! | `close_all` | | `{"closed": count}` |
//! | `mode` | | `{"mode": "rule" \| "global" \| "direct"}` |
//! | `set_mode` | `mode` | `{"mode": ...}` |
//! | `groups` | | `{"groups": [`[`crate::routing::GroupView`]`]}` |
//! | `select` | `group`, `member` | `{"now": member}` |
//! | `rule_sets` | | `{"rule_sets": [`[`crate::rule_sets::RuleSetStatus`]`]}` |
//! | `update_rule_sets` | | `{"scheduled": remote set count}` |
//! | `scripts` | | `{"scripts": [`[`ScheduledScriptView`]`]}` |
//! | `script_notifications` | | `{"notifications": [`[`ScriptNotificationView`]`]}`, each returned once |
//! | `network_changed` | | `{"scheduled": network-change script count}` |
//! | `run_script` | `tag` | `{"scheduled": bool}` |
//! | `outbound_health` | | `{"outbounds": [{"node", "protocol", "health"}]}`, only outbounds that report health |
//! | `resume_outbound` | `node` | `{"resumed": bool}` |
//! | `reload_rules` | `rules`, optional `dry_run` | `{"reloaded": bool, "rules", "generation"}` or `{"reloaded": false, "error": {"line", "code"}}` |
//!
//! `reload_rules` swaps the rule lines of a routing config while the engine
//! runs ([`crate::routing::RoutedOutbound::reload_rules`]): `rules` is the
//! whole new list ending with `FINAL`, naming only the configured nodes,
//! groups and rule sets. Open connections and their packets are untouched.
//! A refused list leaves the running rules in force; `error.line` is the
//! 0-based index of the first bad line and `error.code` one of
//! [`crate::routing::reject_code`]. With `dry_run` the list is only checked,
//! which the client's rule editor uses to mark lines. It is the only command
//! that may be longer than [`MAX_REQUEST_LEN`], up to
//! [`MAX_RELOAD_REQUEST_LEN`].
//!
//! The script commands need a MITM config with plugin scripts; the client
//! sends `network_changed` when the device's network changes and polls
//! `script_notifications` to show what scripts posted.
//!
//! Mode and group choices last until the engine stops; the client keeps
//! them in its profile (`mode`, a select group's `default`) for the next
//! start.

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::connections::{Dispatcher, Mode};
use crate::tunnel::FlowInterceptor;
use crate::{RuntimeError, RuntimeErrorCode};

/// The node name `outbound_health` gives the only outbound of a config
/// without policy groups.
pub const SINGLE_NODE: &str = "proxy";

/// Largest request accepted, except `reload_rules`.
pub const MAX_REQUEST_LEN: usize = 4096;

/// Largest `reload_rules` request accepted: 4096 rules of a typical length.
pub const MAX_RELOAD_REQUEST_LEN: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum ControlRequest {
    Traffic,
    Connections,
    CloseConnection {
        id: u64,
    },
    CloseAll,
    Mode,
    SetMode {
        mode: Mode,
    },
    Groups,
    Select {
        group: String,
        member: String,
    },
    RuleSets,
    UpdateRuleSets,
    Scripts,
    ScriptNotifications,
    NetworkChanged,
    RunScript {
        tag: String,
    },
    OutboundHealth,
    ResumeOutbound {
        node: String,
    },
    ReloadRules {
        rules: Vec<String>,
        #[serde(default)]
        dry_run: bool,
    },
}

/// Script commands, answered by the flow interceptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptControl {
    Scripts,
    Notifications,
    NetworkChanged,
    Run { tag: String },
}

/// A cron, network-change or generic plugin script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScheduledScriptView {
    pub tag: String,
    /// `cron`, `network-changed` or `generic`.
    pub trigger: &'static str,
    /// Cron expression of a `cron` script.
    pub cron: Option<String>,
    /// Local time of the next cron run, RFC 9557 (`2026-11-09T09:00:00+08:00[Asia/Shanghai]`).
    pub next_run: Option<String>,
    /// Result of the last run since the engine started: `done`,
    /// `finished_without_done`, or a failure code.
    pub last_status: Option<String>,
}

/// A notification a script posted (`$notification.post`, `$notify`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScriptNotificationView {
    pub title: String,
    pub subtitle: String,
    pub content: String,
    pub open_url: Option<String>,
}

/// Runs one JSON request against the flows of `dispatcher`.
pub fn handle(dispatcher: &Dispatcher, request: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    handle_with_interceptor(dispatcher, None, request)
}

/// [`handle`], with the script commands going to `interceptor`.
pub fn handle_with_interceptor(
    dispatcher: &Dispatcher,
    interceptor: Option<&dyn FlowInterceptor>,
    request: &[u8],
) -> Result<Vec<u8>, RuntimeError> {
    if request.is_empty() || request.len() > MAX_RELOAD_REQUEST_LEN {
        return Err(invalid("control request size is out of range"));
    }
    let long = request.len() > MAX_REQUEST_LEN;
    let request: ControlRequest = serde_json::from_slice(request)
        .map_err(|_| invalid("control request is not a known command"))?;
    if long && !matches!(request, ControlRequest::ReloadRules { .. }) {
        return Err(invalid("control request size is out of range"));
    }
    let tracker = dispatcher.tracker();
    let answer = match request {
        ControlRequest::Traffic => serde_json::to_value(tracker.traffic()),
        ControlRequest::Connections => serde_json::to_value(tracker.connections()),
        ControlRequest::CloseConnection { id } => Ok(json!({ "closed": tracker.close(id) })),
        ControlRequest::CloseAll => Ok(json!({ "closed": tracker.close_all() })),
        ControlRequest::Mode => Ok(json!({ "mode": dispatcher.mode() })),
        ControlRequest::SetMode { mode } => {
            dispatcher.set_mode(mode);
            Ok(json!({ "mode": dispatcher.mode() }))
        }
        ControlRequest::Groups => {
            let groups = dispatcher
                .routed_outbound()
                .map(|routed| routed.groups())
                .unwrap_or_default();
            Ok(json!({ "groups": groups }))
        }
        ControlRequest::Select { group, member } => {
            let routed = dispatcher
                .routed_outbound()
                .ok_or_else(|| invalid("this config has no policy groups"))?;
            Ok(json!({ "now": routed.select(&group, &member)? }))
        }
        ControlRequest::RuleSets => {
            let sets = dispatcher
                .routed_outbound()
                .map(|routed| routed.rule_sets().status())
                .unwrap_or_default();
            Ok(json!({ "rule_sets": sets }))
        }
        ControlRequest::UpdateRuleSets => {
            let scheduled = dispatcher
                .routed_outbound()
                .map_or(0, |routed| routed.rule_sets().refresh_now());
            Ok(json!({ "scheduled": scheduled }))
        }
        ControlRequest::Scripts => Ok(script(interceptor, ScriptControl::Scripts)?),
        ControlRequest::ScriptNotifications => {
            Ok(script(interceptor, ScriptControl::Notifications)?)
        }
        ControlRequest::NetworkChanged => Ok(script(interceptor, ScriptControl::NetworkChanged)?),
        ControlRequest::RunScript { tag } => Ok(script(interceptor, ScriptControl::Run { tag })?),
        ControlRequest::OutboundHealth => {
            let outbounds: Vec<_> = match dispatcher.routed_outbound() {
                Some(routed) => routed
                    .node_health()
                    .into_iter()
                    .map(|(node, protocol, health)| {
                        json!({ "node": node, "protocol": protocol, "health": health })
                    })
                    .collect(),
                None => {
                    let outbound = dispatcher.outbound();
                    outbound
                        .health()
                        .map(|health| {
                            json!({
                                "node": SINGLE_NODE,
                                "protocol": outbound.protocol(),
                                "health": health,
                            })
                        })
                        .into_iter()
                        .collect()
                }
            };
            Ok(json!({ "outbounds": outbounds }))
        }
        ControlRequest::ResumeOutbound { node } => {
            let resumed = match dispatcher.routed_outbound() {
                Some(routed) => routed
                    .resume_node(&node)
                    .ok_or_else(|| invalid("no such node"))?,
                None if node == SINGLE_NODE => dispatcher.outbound().resume(),
                None => return Err(invalid("no such node")),
            };
            Ok(json!({ "resumed": resumed }))
        }
        ControlRequest::ReloadRules { rules, dry_run } => {
            let routed = dispatcher
                .routed_outbound()
                .ok_or_else(|| invalid("this config has no routing rules"))?;
            Ok(match routed.reload_rules(&rules, dry_run) {
                Ok(done) => json!({
                    "reloaded": done.applied,
                    "rules": done.rules,
                    "generation": done.generation,
                }),
                Err(rejection) => json!({ "reloaded": false, "error": rejection }),
            })
        }
    };
    answer
        .and_then(|answer| serde_json::to_vec(&answer))
        .map_err(|_| RuntimeError::new(RuntimeErrorCode::InternalError, "control answer failed"))
}

/// The answer for runtimes without flows to control, such as a WireGuard
/// tunnel.
#[cfg(feature = "wireguard")]
pub(crate) fn unavailable() -> RuntimeError {
    invalid("this tunnel has no runtime controls")
}

fn script(
    interceptor: Option<&dyn FlowInterceptor>,
    request: ScriptControl,
) -> Result<serde_json::Value, RuntimeError> {
    interceptor
        .and_then(|interceptor| interceptor.script_control(&request))
        .ok_or_else(|| invalid("this config runs no plugin scripts"))
}

fn invalid(message: &'static str) -> RuntimeError {
    RuntimeError::new(RuntimeErrorCode::InvalidArgument, message)
}
