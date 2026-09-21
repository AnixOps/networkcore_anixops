use control_domain::maintenance::{
    MaintenanceBatch, MaintenanceEvent, MaintenanceStatus, SelfHealAction,
    MAINTENANCE_MAX_BATCH_BYTES, MAINTENANCE_MAX_EVENT_BYTES, MAINTENANCE_WIRE_VERSION,
};
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const FIXTURE: &[u8] = include_bytes!("../../../docs/contracts/maintenance-event.fixture.json");

fn now() -> i64 {
    OffsetDateTime::parse("2026-09-22T00:02:00Z", &Rfc3339)
        .unwrap()
        .unix_timestamp()
}

fn event() -> MaintenanceEvent {
    MaintenanceEvent::from_json(FIXTURE, now()).unwrap()
}

#[test]
fn maintenance_wire_fixture_round_trips_without_changing_identity_or_evidence() {
    let original = event();
    let bytes = original.to_json(now()).unwrap();
    assert_eq!(
        MaintenanceEvent::from_json(&bytes, now()).unwrap(),
        original
    );
    let encoded: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(encoded["instance_id"], "machine-telemetry:default");
    assert_eq!(encoded["consecutive_failures"], 3);
    assert!(encoded.get("healthy_since").is_none());
    let schema: Value = serde_json::from_str(include_str!(
        "../../../docs/contracts/maintenance-event.schema.json"
    ))
    .unwrap();
    for required in schema["required"].as_array().unwrap() {
        assert!(encoded.get(required.as_str().unwrap()).is_some());
    }
    for field in encoded.as_object().unwrap().keys() {
        assert!(schema["properties"].get(field).is_some());
    }
}

#[test]
fn maintenance_rejects_unknown_duplicate_and_unsupported_wire_fields() {
    for (field, value) in [
        ("schema_version", json!(2)),
        ("severity", json!("critical")),
        ("status", json!("closed")),
        ("self_heal_action", json!("rollback")),
        ("self_heal_result", json!("maybe")),
        ("environment", json!("unknown")),
        ("source", json!("untrusted")),
        ("consecutive_failures", json!(-1)),
        ("consecutive_failures", json!(1_000_001)),
        ("unrecognized_secret", json!("private-value")),
    ] {
        let mut wire: Value = serde_json::from_slice(FIXTURE).unwrap();
        wire[field] = value;
        assert!(MaintenanceEvent::from_json(&serde_json::to_vec(&wire).unwrap(), now()).is_err());
    }
    let duplicate =
        String::from_utf8(FIXTURE.to_vec())
            .unwrap()
            .replacen('{', "{\"schema_version\": 1,", 1);
    assert_eq!(
        MaintenanceEvent::from_json(duplicate.as_bytes(), now()),
        Err("invalid event JSON")
    );
    assert_eq!(
        MaintenanceEvent::from_json(br#"{"source":"secret-token""#, now()),
        Err("invalid event JSON")
    );
}

#[test]
fn maintenance_rejects_invalid_identity_versions_lengths_and_clock_evidence() {
    for (field, value) in [
        ("node_id", json!("0")),
        ("node_id", json!("01")),
        ("node_id", json!("other-node")),
        ("event_id", json!(" ")),
        ("event_id", json!("|ambiguous")),
        ("instance_id", json!("../path")),
        ("plugin_id", json!("a".repeat(129))),
        ("plugin_version", json!("version with spaces")),
        ("agent_version", json!("secret\nvalue")),
        ("config_version", json!("+invalid")),
        ("error_code", json!("lowercase")),
        ("error_code", json!("9INVALID")),
        ("occurred_at", json!("2026-02-30T00:02:00Z")),
        ("occurred_at", json!("2019-12-31T23:59:59Z")),
        ("occurred_at", json!("2020-01-01T00:00:00+01:00")),
        ("occurred_at", json!("2026-09-22T00:07:00.001Z")),
        ("occurred_at", json!("2026-09-22T00:07:01Z")),
        ("first_failed_at", json!("2026-09-22T00:02:01Z")),
        ("redacted_summary", json!("秘密".repeat(400))),
        ("diagnostic_ref", json!("a".repeat(257))),
        ("ticket_key", json!("invalid\u{0000}value")),
    ] {
        let mut wire: Value = serde_json::from_slice(FIXTURE).unwrap();
        wire[field] = value;
        assert!(
            MaintenanceEvent::from_json(&serde_json::to_vec(&wire).unwrap(), now()).is_err(),
            "accepted invalid field {field}"
        );
    }
    let original = event();
    // Durable offline replay is not rejected because it is old.
    assert!(original.validate_at(now() + 365 * 24 * 60 * 60).is_ok());
    assert!(original.validate_at(now() - 300).is_ok());
    assert!(original.validate_at(now() - 301).is_err());
    assert!(original.validate_for_node("43", now()).is_err());
    assert!(original.validate_for_node("42", now()).is_ok());
}

#[test]
fn maintenance_failure_requires_both_three_observations_and_two_minutes() {
    let mut observed = event();
    assert!(observed.persistent_failure().unwrap());
    observed.consecutive_failures = 2;
    assert!(!observed.persistent_failure().unwrap());
    observed.consecutive_failures = 3;
    observed.first_failed_at = Some("2026-09-22T00:00:01Z".to_string());
    assert!(!observed.persistent_failure().unwrap());
    observed.first_failed_at = Some("2026-09-22T00:00:00.001Z".to_string());
    assert!(!observed.persistent_failure().unwrap());
    observed.first_failed_at = None;
    assert!(observed.persistent_failure().is_err());
}

#[test]
fn maintenance_recovery_requires_five_minutes_of_continuous_health() {
    let mut observed = event();
    observed.status = MaintenanceStatus::Recovered;
    observed.consecutive_failures = 0;
    observed.healthy_since = Some("2026-09-22T00:02:00Z".to_string());
    observed.occurred_at = "2026-09-22T00:06:59Z".to_string();
    assert!(!observed.sustained_recovery().unwrap());
    observed.occurred_at = "2026-09-22T00:07:00Z".to_string();
    assert!(observed.sustained_recovery().unwrap());
    observed.healthy_since = Some("2026-09-21T23:59:00Z".to_string());
    assert!(observed.validate().is_err());
    observed.healthy_since = None;
    assert!(observed.validate().is_err());
}

#[test]
fn maintenance_incident_key_continues_across_error_and_version_changes() {
    let original = event();
    let mut next = original.clone();
    next.event_id = "next-event".to_string();
    next.plugin_version = "1.0.1".to_string();
    next.config_version = Some("cfg-2".to_string());
    next.error_code = "PLUGIN_PROCESS_EXITED".to_string();
    assert_eq!(original.dedupe_key(), next.dedupe_key());
    next.instance_id = "other-instance".to_string();
    assert_ne!(original.dedupe_key(), next.dedupe_key());
    next = original.clone();
    next.node_id = "43".to_string();
    assert_ne!(original.dedupe_key(), next.dedupe_key());
}

#[test]
fn maintenance_batch_isolates_invalid_and_forged_events_and_preserves_good_events() {
    let valid: Value = serde_json::from_slice(FIXTURE).unwrap();
    let mut forged = valid.clone();
    forged["node_id"] = json!("43");
    let bytes = serde_json::to_vec(&json!({
        "version": MAINTENANCE_WIRE_VERSION,
        "events": [valid.clone(), {"secret":"private-value"}, forged, valid]
    }))
    .unwrap();
    let batch = MaintenanceBatch::from_json(&bytes, "42", now()).unwrap();
    assert_eq!(batch.events.len(), 4);
    assert!(batch.events[0].is_ok());
    assert_eq!(batch.events[1], Err("invalid event JSON"));
    assert_eq!(batch.events[2], Err("authenticated node mismatch"));
    assert!(batch.events[3].is_ok());
}

#[test]
fn maintenance_batch_enforces_event_count_byte_limits_and_wire_version() {
    let observed = event();
    assert!(MaintenanceBatch::to_json(&vec![observed.clone(); 50], now()).is_ok());
    assert!(MaintenanceBatch::to_json(&vec![observed.clone(); 51], now()).is_err());
    assert!(MaintenanceBatch::to_json(&[], now()).is_err());
    assert_eq!(
        MaintenanceEvent::from_json(&vec![b' '; MAINTENANCE_MAX_EVENT_BYTES + 1], now()),
        Err("event payload too large")
    );
    assert_eq!(
        MaintenanceBatch::from_json(&vec![b' '; MAINTENANCE_MAX_BATCH_BYTES + 1], "42", now()),
        Err("batch payload too large")
    );
    let bytes = MaintenanceBatch::to_json(&[observed], now()).unwrap();
    let bad_version = String::from_utf8(bytes)
        .unwrap()
        .replace(MAINTENANCE_WIRE_VERSION, "anixops.maintenance/v2");
    assert_eq!(
        MaintenanceBatch::from_json(bad_version.as_bytes(), "42", now()),
        Err("unsupported batch version")
    );
}

#[test]
fn maintenance_allows_blocked_restart_budget_without_an_automatic_rollback_action() {
    let mut observed = event();
    observed.self_heal_action = Some(SelfHealAction::CircuitBreak);
    let bytes = observed.to_json(now()).unwrap();
    assert_eq!(
        MaintenanceEvent::from_json(&bytes, now()).unwrap(),
        observed
    );
    let rollback = String::from_utf8(bytes)
        .unwrap()
        .replace("circuit_break", "rollback");
    assert!(MaintenanceEvent::from_json(rollback.as_bytes(), now()).is_err());
}
