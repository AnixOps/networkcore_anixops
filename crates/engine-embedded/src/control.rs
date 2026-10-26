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

use serde::Deserialize;
use serde_json::json;

use crate::connections::Dispatcher;
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
