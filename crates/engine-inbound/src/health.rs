//! The health of an inbound's fixed upstreams, as a forward's health checks
//! and circuit breaker see them; the management API reports it per inbound.

use serde::Serialize;

/// One upstream's state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetState {
    /// Nothing tried it yet: no check ran and no connection dialed it.
    #[default]
    Unknown,
    /// The last check or dial succeeded.
    Healthy,
    /// Checks or dials failed in a row, below the breaker's threshold.
    Unhealthy,
    /// The breaker is open: connections skip the target until
    /// `circuit_open_until_unix_ms`.
    CircuitOpen,
}

/// One upstream of an inbound that dials fixed targets.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TargetHealth {
    /// The configured host: an IP address or a name.
    pub address: String,
    pub port: u16,
    pub state: TargetState,
    pub consecutive_failures: u32,
    /// When the open breaker lets a trial through; 0 while it is closed.
    pub circuit_open_until_unix_ms: u64,
    /// The last active check's connect round trip in microseconds; 0 when
    /// it failed or none ran.
    pub rtt_us: u32,
    /// When the last active check ran; 0 when none did.
    pub checked_at_unix_ms: u64,
}
