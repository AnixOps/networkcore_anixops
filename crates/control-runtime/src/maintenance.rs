//! Explicit diagnostic-to-maintenance adaptation. The caller supplies real
//! observation times and host identity; this adapter never infers liveness
//! from recorded CLI status or creates its own observation history.

use control_domain::maintenance::{
    MaintenanceEvent, MaintenanceSeverity, MaintenanceStatus, SelfHealAction,
    SelfHealResult, MAINTENANCE_SCHEMA_VERSION,
};
use control_domain::{Diagnostic, DiagnosticSeverity};

/// Classification must come from the real health/process adapter, never from
/// untrusted free text. These codes preserve the host's manual/major routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenanceDiagnosticKind {
    Diagnostic,
    HealthCheck,
    ProcessExit,
    Credential,
    Permission,
    Signature,
    Configuration,
    Security,
    DataIntegrity,
    ControlUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceObservationContext {
    pub kind: MaintenanceDiagnosticKind,
    pub event_id: String,
    pub occurred_at: String,
    pub environment: String,
    /// Must originate from the embedding Agent's authenticated identity.
    pub node_id: String,
    pub agent_version: Option<String>,
    pub plugin_id: String,
    pub instance_id: String,
    pub plugin_version: String,
    pub config_version: Option<String>,
    pub status: MaintenanceStatus,
    pub first_failed_at: Option<String>,
    pub consecutive_failures: u32,
    pub healthy_since: Option<String>,
}

/// Exports only fixed diagnostic codes and summaries. A Diagnostic's message,
/// source, and arbitrary code can contain subscription credentials, URLs,
/// packet content or secrets and are intentionally not copied to the wire.
/// Detailed diagnostics stay in the host's separately redacted evidence store.
pub fn adapt_maintenance_diagnostic(
    diagnostic: &Diagnostic,
    context: MaintenanceObservationContext,
    now_unix_seconds: i64,
) -> Result<MaintenanceEvent, &'static str> {
    let (mut error_code, mut summary) = match diagnostic.severity {
        DiagnosticSeverity::Info => ("NETWORKCORE_INFO", "NetworkCore observation"),
        DiagnosticSeverity::Warning => ("NETWORKCORE_WARNING", "NetworkCore warning"),
        DiagnosticSeverity::Error => ("NETWORKCORE_ERROR", "NetworkCore diagnostic failure"),
    };
    let mut severity = match diagnostic.severity {
        DiagnosticSeverity::Info => MaintenanceSeverity::P3,
        DiagnosticSeverity::Warning => MaintenanceSeverity::P2,
        DiagnosticSeverity::Error => MaintenanceSeverity::P1,
    };
    match context.kind {
        MaintenanceDiagnosticKind::Diagnostic => {}
        MaintenanceDiagnosticKind::HealthCheck => {
            error_code = "PLUGIN_HEALTH_FAILED";
            summary = "Plugin health check failed";
        }
        MaintenanceDiagnosticKind::ProcessExit => {
            error_code = "PLUGIN_PROCESS_EXITED";
            summary = "Plugin process exited";
        }
        MaintenanceDiagnosticKind::Credential => {
            error_code = "PLUGIN_CREDENTIAL_INVALID";
            summary = "Plugin credentials require operator attention";
        }
        MaintenanceDiagnosticKind::Permission => {
            error_code = "PLUGIN_PERMISSION_DENIED";
            summary = "Plugin permission requires operator attention";
        }
        MaintenanceDiagnosticKind::Signature => {
            error_code = "PLUGIN_SIGNATURE_INVALID";
            summary = "Plugin signature verification failed";
        }
        MaintenanceDiagnosticKind::Configuration => {
            error_code = "PLUGIN_CONFIG_INVALID";
            summary = "Plugin configuration validation failed";
        }
        MaintenanceDiagnosticKind::Security => {
            error_code = "SECURITY_ANOMALY";
            summary = "Security anomaly requires owner attention";
            severity = MaintenanceSeverity::P0;
        }
        MaintenanceDiagnosticKind::DataIntegrity => {
            error_code = "DATA_INTEGRITY_ERROR";
            summary = "Data integrity requires owner attention";
            severity = MaintenanceSeverity::P0;
        }
        MaintenanceDiagnosticKind::ControlUnavailable => {
            error_code = "CONTROL_UNAVAILABLE";
            summary = "Control availability requires owner attention";
            severity = MaintenanceSeverity::P0;
        }
    }
    let event = MaintenanceEvent {
        schema_version: MAINTENANCE_SCHEMA_VERSION,
        event_id: context.event_id,
        occurred_at: context.occurred_at,
        environment: context.environment,
        source: "networkcore".to_string(),
        node_id: context.node_id,
        agent_version: context.agent_version,
        config_version: context.config_version,
        plugin_id: context.plugin_id,
        instance_id: context.instance_id,
        plugin_version: context.plugin_version,
        error_code: error_code.to_string(),
        severity,
        status: context.status,
        first_failed_at: context.first_failed_at,
        consecutive_failures: context.consecutive_failures,
        healthy_since: context.healthy_since,
        self_heal_action: Some(SelfHealAction::None),
        self_heal_result: Some(SelfHealResult::NotAttempted),
        diagnostic_ref: None,
        ticket_key: None,
        redacted_summary: Some(summary.to_string()),
    };
    event.validate_at(now_unix_seconds)?;
    Ok(event)
}
