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
//!
//! Mode and group choices last until the engine stops; the client keeps
//! them in its profile (`mode`, a select group's `default`) for the next
//! start.

use serde::Deserialize;
use serde_json::json;

use crate::connections::{Dispatcher, Mode};
use crate::{RuntimeError, RuntimeErrorCode};

/// Largest request accepted.
pub const MAX_REQUEST_LEN: usize = 4096;

#[derive(Debug, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum ControlRequest {
    Traffic,
    Connections,
    CloseConnection { id: u64 },
    CloseAll,
    Mode,
    SetMode { mode: Mode },
    Groups,
    Select { group: String, member: String },
    RuleSets,
    UpdateRuleSets,
}

/// Runs one JSON request against the flows of `dispatcher`.
pub fn handle(dispatcher: &Dispatcher, request: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    if request.is_empty() || request.len() > MAX_REQUEST_LEN {
        return Err(invalid("control request size is out of range"));
    }
    let request: ControlRequest = serde_json::from_slice(request)
        .map_err(|_| invalid("control request is not a known command"))?;
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

fn invalid(message: &'static str) -> RuntimeError {
    RuntimeError::new(RuntimeErrorCode::InvalidArgument, message)
}
