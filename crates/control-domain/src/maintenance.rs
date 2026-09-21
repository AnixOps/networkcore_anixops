//! Transport-independent maintenance event validation and JSON boundary.
//!
//! A valid event is evidence supplied by a caller. It does not prove process
//! liveness, establish an authenticated node, acknowledge durable delivery, or
//! authorize an operation. Those responsibilities belong to the host adapter.

use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub const MAINTENANCE_SCHEMA_VERSION: u32 = 1;
pub const MAINTENANCE_MAX_EVENT_BYTES: usize = 16 * 1024;
pub const MAINTENANCE_MAX_BATCH_EVENTS: usize = 50;
pub const MAINTENANCE_MAX_BATCH_BYTES: usize = 256 * 1024;
pub const MAINTENANCE_MAX_FUTURE_SECONDS: i64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MaintenanceSeverity {
    P0,
    P1,
    P2,
    P3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MaintenanceStatus {
    Open,
    Degraded,
    Recovered,
}

/// Records only the explicitly permitted automatic actions. Configuration
/// rollback, upgrades and system/network changes are never automatic actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfHealAction {
    None,
    Retry,
    Restart,
    CircuitBreak,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelfHealResult {
    NotAttempted,
    Succeeded,
    Failed,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaintenanceEvent {
    pub schema_version: u32,
    pub event_id: String,
    pub occurred_at: String,
    pub environment: String,
    pub source: String,
    pub node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_version: Option<String>,
    pub plugin_id: String,
    pub instance_id: String,
    pub plugin_version: String,
    pub error_code: String,
    pub severity: MaintenanceSeverity,
    pub status: MaintenanceStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_failed_at: Option<String>,
    #[serde(default)]
    pub consecutive_failures: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub healthy_since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_heal_action: Option<SelfHealAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_heal_result: Option<SelfHealResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_key: Option<String>,
    /// Untrusted input despite its historical field name. The Control receiver
    /// must independently redact it before persistence or presentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_summary: Option<String>,
}

impl MaintenanceEvent {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != MAINTENANCE_SCHEMA_VERSION {
            return Err("unsupported schema_version");
        }
        for value in [
            &self.event_id,
            &self.node_id,
            &self.plugin_id,
            &self.instance_id,
        ] {
            validate_identifier(value)?;
        }
        if self.node_id.starts_with('0') || !self.node_id.bytes().all(|c| c.is_ascii_digit()) {
            return Err("node_id must be a positive decimal string");
        }
        validate_version(&self.plugin_version)?;
        for value in [&self.agent_version, &self.config_version]
            .into_iter()
            .flatten()
        {
            validate_version(value)?;
        }
        match self.environment.as_str() {
            "production" | "staging" | "development" => {}
            _ => return Err("unsupported environment"),
        }
        match self.source.as_str() {
            "agent" | "control" | "networkcore" | "deployment" => {}
            _ => return Err("unsupported source"),
        }
        if !self.error_code.starts_with(|c: char| c.is_ascii_uppercase())
            || self.error_code.len() > 128
            || !self
                .error_code
                .bytes()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || b"_.-".contains(&c))
        {
            return Err("invalid error_code");
        }
        let occurred_at = parse_timestamp(&self.occurred_at)?;
        let first_failed_at = self
            .first_failed_at
            .as_deref()
            .map(parse_timestamp)
            .transpose()?;
        let healthy_since = self
            .healthy_since
            .as_deref()
            .map(parse_timestamp)
            .transpose()?;
        if first_failed_at.is_some_and(|first| first > occurred_at)
            || healthy_since.is_some_and(|healthy| healthy > occurred_at)
            || matches!((first_failed_at, healthy_since), (Some(first), Some(healthy)) if first > healthy)
        {
            return Err("inconsistent observation timestamps");
        }
        if self.consecutive_failures > 1_000_000
            || (self.consecutive_failures > 0 && first_failed_at.is_none())
        {
            return Err("invalid consecutive_failures evidence");
        }
        if self.status == MaintenanceStatus::Recovered && healthy_since.is_none() {
            return Err("recovery requires healthy_since");
        }
        if matches!(self.self_heal_action, Some(SelfHealAction::Retry | SelfHealAction::Restart))
            && self.self_heal_result.is_none()
        {
            return Err("self_heal_action requires self_heal_result");
        }
        for value in [&self.diagnostic_ref, &self.ticket_key]
            .into_iter()
            .flatten()
        {
            validate_text(value, 256)?;
        }
        if let Some(value) = &self.redacted_summary {
            validate_text(value, 2000)?;
        }
        Ok(())
    }

    /// Validation against an explicit trusted clock keeps offline replay
    /// deterministic. There is no age cutoff that could silently discard a
    /// durably queued event; retention is applied by the receiver after ingest.
    pub fn validate_at(&self, now_unix_seconds: i64) -> Result<(), &'static str> {
        self.validate()?;
        if parse_timestamp(&self.occurred_at)?.unix_timestamp_nanos()
            > i128::from(now_unix_seconds.saturating_add(MAINTENANCE_MAX_FUTURE_SECONDS))
                * 1_000_000_000
        {
            return Err("occurred_at is in the future");
        }
        Ok(())
    }

    /// Validates the claimed identity against the host's authenticated session.
    /// The node identifier in the payload must never establish that session.
    pub fn validate_for_node(
        &self,
        authenticated_node_id: &str,
        now_unix_seconds: i64,
    ) -> Result<(), &'static str> {
        validate_identifier(authenticated_node_id)?;
        if self.node_id != authenticated_node_id {
            return Err("authenticated node mismatch");
        }
        self.validate_at(now_unix_seconds)
    }

    pub fn from_json(bytes: &[u8], now_unix_seconds: i64) -> Result<Self, &'static str> {
        if bytes.len() > MAINTENANCE_MAX_EVENT_BYTES {
            return Err("event payload too large");
        }
        // Never propagate parser errors containing raw payload or secrets.
        let event: Self = serde_json::from_slice(bytes).map_err(|_| "invalid event JSON")?;
        event.validate_at(now_unix_seconds)?;
        Ok(event)
    }

    pub fn to_json(&self, now_unix_seconds: i64) -> Result<Vec<u8>, &'static str> {
        self.validate_at(now_unix_seconds)?;
        let bytes = serde_json::to_vec(self).map_err(|_| "cannot serialize event")?;
        if bytes.len() > MAINTENANCE_MAX_EVENT_BYTES {
            return Err("event payload too large");
        }
        Ok(bytes)
    }

    /// Incident aggregation key; event_id is the separate durable dedupe key.
    /// Versions and error codes are excluded so updates continue an unclosed
    /// incident for the same plugin instance.
    pub fn dedupe_key(&self) -> String {
        format!(
            "{}|{}|{}|{}",
            self.environment,
            self.node_id,
            self.plugin_id,
            self.instance_id
        )
    }

    pub fn persistent_failure(&self) -> Result<bool, &'static str> {
        self.validate()?;
        let Some(first) = self.first_failed_at.as_deref() else {
            return Ok(false);
        };
        Ok(matches!(self.status, MaintenanceStatus::Open | MaintenanceStatus::Degraded)
            && self.healthy_since.is_none()
            && self.consecutive_failures >= 3
            && (parse_timestamp(&self.occurred_at)? - parse_timestamp(first)?).whole_seconds()
                >= 120)
    }

    pub fn sustained_recovery(&self) -> Result<bool, &'static str> {
        self.validate()?;
        let Some(healthy) = self.healthy_since.as_deref() else {
            return Ok(false);
        };
        Ok(self.status == MaintenanceStatus::Recovered
            && (parse_timestamp(&self.occurred_at)? - parse_timestamp(healthy)?).whole_seconds()
                >= 300)
    }
}

fn validate_identifier(value: &str) -> Result<(), &'static str> {
    if !value.starts_with(|c: char| c.is_ascii_alphanumeric())
        || value.len() > 128
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.:-".contains(&c))
    {
        return Err("invalid identifier");
    }
    Ok(())
}

fn validate_version(value: &str) -> Result<(), &'static str> {
    if !value.starts_with(|c: char| c.is_ascii_alphanumeric())
        || value.len() > 128
        || !value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.+-".contains(&c))
    {
        return Err("invalid version");
    }
    Ok(())
}

fn validate_text(value: &str, max_bytes: usize) -> Result<(), &'static str> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err("invalid diagnostic text");
    }
    Ok(())
}

fn parse_timestamp(value: &str) -> Result<OffsetDateTime, &'static str> {
    if value.len() < 20 || value.len() > 35 {
        return Err("invalid timestamp");
    }
    let parsed = OffsetDateTime::parse(value, &Rfc3339).map_err(|_| "invalid timestamp")?;
    if parsed.unix_timestamp() < 1_577_836_800 {
        return Err("timestamp outside supported range");
    }
    Ok(parsed)
}

pub const MAINTENANCE_WIRE_VERSION: &str = "anixops.maintenance/v1";

/// Decoded batch results retain each event's boundary. A malformed event must
/// not prevent a receiver from validating the remaining bounded batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceBatch {
    pub events: Vec<Result<MaintenanceEvent, &'static str>>,
}

impl MaintenanceBatch {
    pub fn from_json(
        bytes: &[u8],
        authenticated_node_id: &str,
        now_unix_seconds: i64,
    ) -> Result<Self, &'static str> {
        if bytes.len() > MAINTENANCE_MAX_BATCH_BYTES {
            return Err("batch payload too large");
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawBatch<'a> {
            version: String,
            #[serde(borrow)]
            events: Vec<&'a serde_json::value::RawValue>,
        }
        let batch: RawBatch<'_> =
            serde_json::from_slice(bytes).map_err(|_| "invalid batch JSON")?;
        if batch.version != MAINTENANCE_WIRE_VERSION {
            return Err("unsupported batch version");
        }
        if batch.events.is_empty() || batch.events.len() > MAINTENANCE_MAX_BATCH_EVENTS {
            return Err("invalid batch size");
        }
        let events = batch
            .events
            .into_iter()
            .map(|raw| {
                let event = MaintenanceEvent::from_json(raw.get().as_bytes(), now_unix_seconds)?;
                event.validate_for_node(authenticated_node_id, now_unix_seconds)?;
                Ok(event)
            })
            .collect();
        Ok(Self { events })
    }

    /// Produces the payload of the authenticated host's maintenance_events
    /// frame. It does not open a WebSocket, queue, or acknowledge any event.
    pub fn to_json(
        events: &[MaintenanceEvent],
        now_unix_seconds: i64,
    ) -> Result<Vec<u8>, &'static str> {
        if events.is_empty() || events.len() > MAINTENANCE_MAX_BATCH_EVENTS {
            return Err("invalid batch size");
        }
        for event in events {
            event.to_json(now_unix_seconds)?;
        }
        #[derive(Serialize)]
        struct Batch<'a> {
            version: &'static str,
            events: &'a [MaintenanceEvent],
        }
        let bytes = serde_json::to_vec(&Batch {
            version: MAINTENANCE_WIRE_VERSION,
            events,
        })
        .map_err(|_| "cannot serialize batch")?;
        if bytes.len() > MAINTENANCE_MAX_BATCH_BYTES {
            return Err("batch payload too large");
        }
        Ok(bytes)
    }
}
