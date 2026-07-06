//! Runtime orchestration use cases for the AnixOps network control kernel.
//!
//! This crate depends only on domain contracts. It coordinates domain ports but
//! does not perform platform probing, process management, file I/O, networking,
//! UI work, or transport-specific control API behavior.

use control_domain::{
    ConfigSnapshot, ConfigurationService, Diagnostic, DiagnosticSeverity, DomainError,
    DomainResult, Metadata, NodeDescriptor, PlatformCapabilities, PlatformCapabilityService,
    PlatformCapabilityStatus, PlatformFeatureState, ProxyEngineConfig, ProxyEngineEvent,
    ProxyEngineService, ProxyEngineStatus,
};

/// Prepared configuration and platform context ready for runtime use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRuntimeConfig {
    pub platform: PlatformCapabilityStatus,
    pub capabilities: PlatformCapabilities,
    pub config: ConfigSnapshot,
    pub diagnostics: Vec<Diagnostic>,
}

/// Configuration-bearing runtime request used by start and reload use cases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfigRequest {
    pub engine_id: String,
    pub raw_config: String,
    pub nodes: Vec<NodeDescriptor>,
    pub metadata: Metadata,
}

impl RuntimeConfigRequest {
    /// Creates a runtime config request with no nodes or metadata.
    pub fn new(engine_id: impl Into<String>, raw_config: impl Into<String>) -> Self {
        Self {
            engine_id: engine_id.into(),
            raw_config: raw_config.into(),
            nodes: Vec::new(),
            metadata: Vec::new(),
        }
    }
}

/// Runtime operation result with aggregated diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeOperationResult {
    pub platform: PlatformCapabilityStatus,
    pub capabilities: PlatformCapabilities,
    pub engine_status: ProxyEngineStatus,
    pub diagnostics: Vec<Diagnostic>,
}

/// Runtime status snapshot with platform and engine state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStatusSnapshot {
    pub platform: PlatformCapabilityStatus,
    pub capabilities: PlatformCapabilities,
    pub engine_status: ProxyEngineStatus,
    pub diagnostics: Vec<Diagnostic>,
}

/// Pure runtime use case orchestrator.
pub struct RuntimeOrchestrator<C, P, E> {
    configuration: C,
    platform: P,
    engine: E,
}

impl<C, P, E> RuntimeOrchestrator<C, P, E>
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
{
    /// Creates a runtime orchestrator from domain port implementations.
    pub const fn new(configuration: C, platform: P, engine: E) -> Self {
        Self {
            configuration,
            platform,
            engine,
        }
    }

    /// Validates and normalizes raw configuration against current platform capabilities.
    pub fn prepare_config(&self, raw_config: &str) -> DomainResult<PreparedRuntimeConfig> {
        let platform = self.platform.status()?;
        let capabilities = platform_capabilities_from_status(&platform);
        let mut diagnostics = platform_diagnostics(&platform);

        diagnostics.extend(self.configuration.validate(raw_config, &capabilities));
        reject_error_diagnostics(
            &diagnostics,
            "runtime.config.invalid",
            "configuration validation failed",
        )?;

        let config = self.configuration.normalize(raw_config, &capabilities)?;

        Ok(PreparedRuntimeConfig {
            platform,
            capabilities,
            config,
            diagnostics,
        })
    }

    /// Starts a runtime engine after platform and engine configuration gates pass.
    pub fn start_runtime(
        &self,
        request: RuntimeConfigRequest,
    ) -> DomainResult<RuntimeOperationResult> {
        let (prepared, engine_config) = self.prepare_engine_config(&request)?;

        ensure_start_capabilities(&prepared.platform)?;
        let mut diagnostics = prepared.diagnostics.clone();
        diagnostics.extend(self.validate_engine_config(&engine_config)?);

        let engine_status = self.engine.start(&engine_config)?;
        diagnostics.extend(engine_status.diagnostics.clone());

        Ok(RuntimeOperationResult {
            platform: prepared.platform,
            capabilities: prepared.capabilities,
            engine_status,
            diagnostics,
        })
    }

    /// Reloads a runtime engine after platform and engine configuration gates pass.
    pub fn reload_runtime(
        &self,
        request: RuntimeConfigRequest,
    ) -> DomainResult<RuntimeOperationResult> {
        let (prepared, engine_config) = self.prepare_engine_config(&request)?;

        ensure_start_capabilities(&prepared.platform)?;
        let mut diagnostics = prepared.diagnostics.clone();
        diagnostics.extend(self.validate_engine_config(&engine_config)?);

        let engine_status = self.engine.reload(&engine_config)?;
        diagnostics.extend(engine_status.diagnostics.clone());

        Ok(RuntimeOperationResult {
            platform: prepared.platform,
            capabilities: prepared.capabilities,
            engine_status,
            diagnostics,
        })
    }

    /// Stops a runtime engine through the proxy engine port.
    pub fn stop_runtime(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        self.engine.stop(engine_id)
    }

    /// Reads current platform and engine status.
    pub fn runtime_status(&self, engine_id: &str) -> DomainResult<RuntimeStatusSnapshot> {
        let platform = self.platform.status()?;
        let capabilities = platform_capabilities_from_status(&platform);
        let mut diagnostics = platform_diagnostics(&platform);
        let engine_status = self.engine.status(engine_id)?;

        diagnostics.extend(engine_status.diagnostics.clone());

        Ok(RuntimeStatusSnapshot {
            platform,
            capabilities,
            engine_status,
            diagnostics,
        })
    }

    /// Reads runtime events for an engine through the proxy engine port.
    pub fn runtime_events(&self, engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
        self.engine.events(engine_id)
    }

    fn prepare_engine_config(
        &self,
        request: &RuntimeConfigRequest,
    ) -> DomainResult<(PreparedRuntimeConfig, ProxyEngineConfig)> {
        let prepared = self.prepare_config(&request.raw_config)?;
        let engine_config = ProxyEngineConfig {
            engine_id: request.engine_id.clone(),
            config: prepared.config.clone(),
            nodes: request.nodes.clone(),
            metadata: request.metadata.clone(),
        };

        Ok((prepared, engine_config))
    }

    fn validate_engine_config(
        &self,
        engine_config: &ProxyEngineConfig,
    ) -> DomainResult<Vec<Diagnostic>> {
        let diagnostics = self.engine.validate_config(engine_config);
        reject_error_diagnostics(
            &diagnostics,
            "runtime.engine_config.invalid",
            "engine configuration validation failed",
        )?;
        Ok(diagnostics)
    }
}

/// Converts rich platform status into the current configuration capability input.
pub fn platform_capabilities_from_status(
    status: &PlatformCapabilityStatus,
) -> PlatformCapabilities {
    PlatformCapabilities {
        os: status.os,
        supports_tunnel: status.tunnel.is_available(),
        supports_mitm: status.mitm_available(),
        supports_embedded_runtime: status.embedded_runtime.is_available(),
    }
}

fn ensure_start_capabilities(status: &PlatformCapabilityStatus) -> DomainResult<()> {
    ensure_available(
        &status.tunnel,
        "runtime.platform.tunnel_unavailable",
        "runtime tunnel is unavailable",
    )?;
    ensure_available(
        &status.embedded_runtime,
        "runtime.platform.embedded_runtime_unavailable",
        "embedded runtime is unavailable",
    )
}

fn ensure_available(
    feature: &PlatformFeatureState,
    code: &'static str,
    message: &'static str,
) -> DomainResult<()> {
    if feature.is_available() {
        Ok(())
    } else {
        let reason = feature
            .denial_reason()
            .unwrap_or("platform feature availability is unknown");
        Err(DomainError::new(code, format!("{message}: {reason}")))
    }
}

fn reject_error_diagnostics(
    diagnostics: &[Diagnostic],
    code: &'static str,
    message: &'static str,
) -> DomainResult<()> {
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    {
        Err(DomainError::new(code, message))
    } else {
        Ok(())
    }
}

fn platform_diagnostics(status: &PlatformCapabilityStatus) -> Vec<Diagnostic> {
    let mut diagnostics = status.diagnostics.clone();
    diagnostics.extend(status.mitm_certificate.diagnostics.clone());
    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;
    use control_domain::{
        CertificateTrustState, MitmCertificateStatus, OperatingSystem, PlatformFeatureState,
        ProxyEngineLifecycleState, SchemaVersion,
    };

    struct DiagnosticConfigService {
        diagnostics: Vec<Diagnostic>,
    }

    impl ConfigurationService for DiagnosticConfigService {
        fn validate(
            &self,
            _raw_config: &str,
            _capabilities: &PlatformCapabilities,
        ) -> Vec<Diagnostic> {
            self.diagnostics.clone()
        }

        fn normalize(
            &self,
            _raw_config: &str,
            _capabilities: &PlatformCapabilities,
        ) -> DomainResult<ConfigSnapshot> {
            Ok(empty_config())
        }

        fn migrate(
            &self,
            raw_config: &str,
            _from_version: SchemaVersion,
            _to_version: SchemaVersion,
        ) -> DomainResult<String> {
            Ok(raw_config.to_string())
        }
    }

    struct StaticPlatformService {
        status: PlatformCapabilityStatus,
    }

    impl PlatformCapabilityService for StaticPlatformService {
        fn status(&self) -> DomainResult<PlatformCapabilityStatus> {
            Ok(self.status.clone())
        }
    }

    struct StaticEngineService {
        config_diagnostics: Vec<Diagnostic>,
    }

    impl ProxyEngineService for StaticEngineService {
        fn list_engines(&self) -> Vec<control_domain::ProxyEngineDescriptor> {
            Vec::new()
        }

        fn validate_config(&self, _engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
            self.config_diagnostics.clone()
        }

        fn start(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
            Ok(ProxyEngineStatus {
                engine_id: engine_config.engine_id.clone(),
                state: ProxyEngineLifecycleState::Running,
                diagnostics: Vec::new(),
            })
        }

        fn reload(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
            Ok(ProxyEngineStatus {
                engine_id: engine_config.engine_id.clone(),
                state: ProxyEngineLifecycleState::Reloading,
                diagnostics: Vec::new(),
            })
        }

        fn stop(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
            Ok(ProxyEngineStatus {
                engine_id: engine_id.to_string(),
                state: ProxyEngineLifecycleState::Stopped,
                diagnostics: Vec::new(),
            })
        }

        fn status(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
            Ok(ProxyEngineStatus {
                engine_id: engine_id.to_string(),
                state: ProxyEngineLifecycleState::Running,
                diagnostics: Vec::new(),
            })
        }

        fn events(&self, _engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn platform_status_maps_to_configuration_capabilities() {
        let status = available_platform_status();
        let capabilities = platform_capabilities_from_status(&status);

        assert_eq!(capabilities.os, OperatingSystem::Ios);
        assert!(capabilities.supports_tunnel);
        assert!(capabilities.supports_mitm);
        assert!(capabilities.supports_embedded_runtime);
    }

    #[test]
    fn prepare_config_rejects_validation_errors() {
        let orchestrator = RuntimeOrchestrator::new(
            DiagnosticConfigService {
                diagnostics: vec![Diagnostic::new(
                    DiagnosticSeverity::Error,
                    "config.empty",
                    "configuration is empty",
                    None,
                )],
            },
            StaticPlatformService {
                status: available_platform_status(),
            },
            StaticEngineService {
                config_diagnostics: Vec::new(),
            },
        );

        let error = orchestrator
            .prepare_config("")
            .expect_err("validation errors should reject config");

        assert_eq!(error.code, "runtime.config.invalid");
    }

    #[test]
    fn start_runtime_rejects_engine_config_errors() {
        let orchestrator = RuntimeOrchestrator::new(
            DiagnosticConfigService {
                diagnostics: Vec::new(),
            },
            StaticPlatformService {
                status: available_platform_status(),
            },
            StaticEngineService {
                config_diagnostics: vec![Diagnostic::new(
                    DiagnosticSeverity::Error,
                    "engine.config.invalid",
                    "engine rejected config",
                    None,
                )],
            },
        );

        let error = orchestrator
            .start_runtime(RuntimeConfigRequest::new("native", "profile = default"))
            .expect_err("engine config errors should reject start");

        assert_eq!(error.code, "runtime.engine_config.invalid");
    }

    fn available_platform_status() -> PlatformCapabilityStatus {
        PlatformCapabilityStatus {
            os: OperatingSystem::Ios,
            tunnel: PlatformFeatureState::available(),
            mitm: PlatformFeatureState::available(),
            embedded_runtime: PlatformFeatureState::available(),
            remote_script_execution: PlatformFeatureState::unavailable(
                "remote scripts are disabled on iOS",
            ),
            mitm_certificate: MitmCertificateStatus::new(CertificateTrustState::Trusted),
            diagnostics: Vec::new(),
        }
    }

    fn empty_config() -> ConfigSnapshot {
        ConfigSnapshot {
            version: SchemaVersion::new(1),
            profiles: vec!["default".to_string()],
            policies: Vec::new(),
            dns: Vec::new(),
            plugins: Vec::new(),
        }
    }
}
