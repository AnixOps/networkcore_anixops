//! Native proxy engine adapter contracts for NetworkCore.
//!
//! This crate intentionally exposes only descriptor, validation, and lifecycle
//! diagnostics until a real in-process runtime handle exists.

use control_domain::{
    Diagnostic, DiagnosticSeverity, DomainError, DomainResult, ProxyEngineConfig,
    ProxyEngineDescriptor, ProxyEngineEvent, ProxyEngineKind, ProxyEngineLifecycleState,
    ProxyEngineService, ProxyEngineStatus,
};

pub const DEFAULT_NATIVE_ENGINE_ID: &str = "native";

pub const SOURCE_ENGINE_NATIVE_CONFIG: &str = "engine.native.config";
pub const SOURCE_ENGINE_NATIVE_LIFECYCLE: &str = "engine.native.lifecycle";

pub const ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE: &str =
    "engine.native.config.engine_id_unsupported";
pub const ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE: &str =
    "engine.native.config.listener_missing";
pub const ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE: &str = "engine.native.config.node_missing";
pub const ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE: &str =
    "engine.native.start.runtime_unavailable";

#[derive(Debug, Clone, Copy, Default)]
pub struct NativeProxyEngineService;

impl NativeProxyEngineService {
    pub const fn new() -> Self {
        Self
    }
}

impl ProxyEngineService for NativeProxyEngineService {
    fn list_engines(&self) -> Vec<ProxyEngineDescriptor> {
        vec![ProxyEngineDescriptor {
            id: DEFAULT_NATIVE_ENGINE_ID.to_string(),
            kind: ProxyEngineKind::Native,
            version: None,
            capabilities: Vec::new(),
        }]
    }

    fn validate_config(&self, engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        if engine_config.engine_id != DEFAULT_NATIVE_ENGINE_ID {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE,
                "native proxy engine only supports the native engine id",
                SOURCE_ENGINE_NATIVE_CONFIG,
            ));
        }

        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Error,
            ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE,
            "native proxy listener support is not implemented yet",
            SOURCE_ENGINE_NATIVE_CONFIG,
        ));

        if engine_config.nodes.is_empty() {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE,
                "native proxy engine requires at least one outbound node before start",
                SOURCE_ENGINE_NATIVE_CONFIG,
            ));
        }

        diagnostics
    }

    fn start(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(&engine_config.engine_id)?;

        Err(domain_error(
            ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE,
            "native proxy runtime handle is not implemented yet",
        ))
    }

    fn reload(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(&engine_config.engine_id)?;

        Err(domain_error(
            ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE,
            "native proxy runtime handle is not implemented yet",
        ))
    }

    fn stop(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(engine_id)?;

        Ok(stopped_status(engine_id))
    }

    fn status(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(engine_id)?;

        Ok(stopped_status(engine_id))
    }

    fn events(&self, engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
        ensure_native_engine_id(engine_id)?;

        Ok(Vec::new())
    }
}

fn stopped_status(engine_id: &str) -> ProxyEngineStatus {
    ProxyEngineStatus {
        engine_id: engine_id.to_string(),
        state: ProxyEngineLifecycleState::Stopped,
        diagnostics: Vec::new(),
    }
}

fn ensure_native_engine_id(engine_id: &str) -> DomainResult<()> {
    if engine_id == DEFAULT_NATIVE_ENGINE_ID {
        return Ok(());
    }

    Err(domain_error(
        ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE,
        "native proxy engine only supports the native engine id",
    ))
}

fn domain_error(code: impl Into<String>, message: impl Into<String>) -> DomainError {
    DomainError::new(code, message)
}

fn engine_diagnostic(
    severity: DiagnosticSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
    source: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(severity, code, message, Some(source.into()))
}
