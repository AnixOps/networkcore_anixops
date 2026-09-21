use control_domain::maintenance::{MaintenanceSeverity, MaintenanceStatus, SelfHealAction};
use control_domain::{Diagnostic, DiagnosticSeverity};
use control_runtime::maintenance::{
    adapt_maintenance_diagnostic, MaintenanceDiagnosticKind, MaintenanceObservationContext,
};

// 2026-09-22T00:02:00Z. Supplied by the host, never by the diagnostic payload.
const NOW: i64 = 1_790_035_320;

fn context() -> MaintenanceObservationContext {
    MaintenanceObservationContext {
        kind: MaintenanceDiagnosticKind::Diagnostic,
        event_id: "networkcore-event-1".to_string(),
        occurred_at: "2026-09-22T00:02:00Z".to_string(),
        environment: "staging".to_string(),
        node_id: "42".to_string(),
        agent_version: Some("1.2.3".to_string()),
        plugin_id: "networkcore".to_string(),
        instance_id: "networkcore:foreground".to_string(),
        plugin_version: "0.1.2-alpha.2".to_string(),
        config_version: Some("cfg-1".to_string()),
        status: MaintenanceStatus::Open,
        first_failed_at: Some("2026-09-22T00:00:00Z".to_string()),
        consecutive_failures: 3,
        healthy_since: None,
    }
}

#[test]
fn maintenance_adapter_never_exports_arbitrary_diagnostic_text_or_source() {
    let diagnostic = Diagnostic::new(
        DiagnosticSeverity::Error,
        "SECRET_API_KEY",
        "authorization=Bearer private-token password=secret-user-password",
        Some("https://user:password@example.invalid/subscription?token=private-value".to_string()),
    );
    let event = adapt_maintenance_diagnostic(&diagnostic, context(), NOW).unwrap();
    let wire = String::from_utf8(event.to_json(NOW).unwrap()).unwrap();
    for sensitive in [
        "SECRET_API_KEY",
        "private-token",
        "secret-user-password",
        "example.invalid",
        "private-value",
        "authorization",
    ] {
        assert!(!wire.contains(sensitive));
    }
    assert_eq!(event.error_code, "NETWORKCORE_ERROR");
    assert_eq!(event.source, "networkcore");
    assert_eq!(event.node_id, "42");
    assert_eq!(event.self_heal_action, Some(SelfHealAction::None));
    assert!(event.diagnostic_ref.is_none());
    assert!(event.ticket_key.is_none());
    assert!(event.persistent_failure().unwrap());
}

#[test]
fn maintenance_adapter_requires_explicit_valid_host_observation_evidence() {
    let diagnostic = Diagnostic::new(DiagnosticSeverity::Error, "engine.failed", "failed", None);
    let mut invalid = context();
    invalid.first_failed_at = None;
    assert!(adapt_maintenance_diagnostic(&diagnostic, invalid, NOW).is_err());
    invalid = context();
    invalid.node_id = "unverified-node".to_string();
    assert!(adapt_maintenance_diagnostic(&diagnostic, invalid, NOW).is_err());
    invalid = context();
    invalid.occurred_at = "2026-09-22T00:08:00Z".to_string();
    assert!(adapt_maintenance_diagnostic(&diagnostic, invalid, NOW).is_err());
}

#[test]
fn maintenance_adapter_preserves_manual_and_immediate_major_routing() {
    let diagnostic = Diagnostic::new(DiagnosticSeverity::Error, "opaque", "private", None);
    for (kind, expected_code) in [
        (MaintenanceDiagnosticKind::Credential, "PLUGIN_CREDENTIAL_INVALID"),
        (MaintenanceDiagnosticKind::Permission, "PLUGIN_PERMISSION_DENIED"),
        (MaintenanceDiagnosticKind::Signature, "PLUGIN_SIGNATURE_INVALID"),
        (MaintenanceDiagnosticKind::Configuration, "PLUGIN_CONFIG_INVALID"),
    ] {
        let mut observation = context();
        observation.kind = kind;
        observation.consecutive_failures = 1;
        let event = adapt_maintenance_diagnostic(&diagnostic, observation, NOW).unwrap();
        assert_eq!(event.error_code, expected_code);
        assert_eq!(event.self_heal_action, Some(SelfHealAction::None));
    }
    for kind in [
        MaintenanceDiagnosticKind::Security,
        MaintenanceDiagnosticKind::DataIntegrity,
        MaintenanceDiagnosticKind::ControlUnavailable,
    ] {
        let mut observation = context();
        observation.kind = kind;
        let event = adapt_maintenance_diagnostic(&diagnostic, observation, NOW).unwrap();
        assert_eq!(event.severity, MaintenanceSeverity::P0);
        assert_eq!(event.self_heal_action, Some(SelfHealAction::None));
    }
}
