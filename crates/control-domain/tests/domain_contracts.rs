use control_domain::{
    CertificateTrustState, ConfigSnapshot, ConfigurationService, Diagnostic, DiagnosticSeverity,
    DomainResult, MitmCertificateStatus, OperatingSystem, PlatformCapabilities,
    PlatformCapabilityService, PlatformCapabilityStatus, PlatformFeatureState,
    ProxyEngineCapability, ProxyEngineConfig, ProxyEngineDescriptor, ProxyEngineEvent,
    ProxyEngineKind, ProxyEngineLifecycleState, ProxyEngineService, ProxyEngineStatus,
    SchemaVersion,
};

struct NoopConfigurationService;

impl ConfigurationService for NoopConfigurationService {
    fn validate(&self, raw_config: &str, _capabilities: &PlatformCapabilities) -> Vec<Diagnostic> {
        if raw_config.trim().is_empty() {
            vec![Diagnostic::new(
                DiagnosticSeverity::Error,
                "config.empty",
                "configuration is empty",
                None,
            )]
        } else {
            Vec::new()
        }
    }

    fn normalize(
        &self,
        _raw_config: &str,
        _capabilities: &PlatformCapabilities,
    ) -> DomainResult<ConfigSnapshot> {
        Ok(ConfigSnapshot {
            version: SchemaVersion::new(1),
            profiles: vec!["default".to_string()],
            policies: Vec::new(),
            dns: Vec::new(),
            plugins: Vec::new(),
        })
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

struct NoopProxyEngineService;

impl ProxyEngineService for NoopProxyEngineService {
    fn list_engines(&self) -> Vec<ProxyEngineDescriptor> {
        vec![ProxyEngineDescriptor {
            id: "native".to_string(),
            kind: ProxyEngineKind::Native,
            version: Some("test".to_string()),
            capabilities: vec![
                ProxyEngineCapability::TcpProxy,
                ProxyEngineCapability::UdpProxy,
                ProxyEngineCapability::HotReload,
            ],
        }]
    }

    fn validate_config(&self, _engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
        Vec::new()
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

struct NoopPlatformCapabilityService;

impl PlatformCapabilityService for NoopPlatformCapabilityService {
    fn status(&self) -> DomainResult<PlatformCapabilityStatus> {
        Ok(PlatformCapabilityStatus {
            os: OperatingSystem::Ios,
            tunnel: PlatformFeatureState::available(),
            mitm: PlatformFeatureState::available(),
            embedded_runtime: PlatformFeatureState::available(),
            remote_script_execution: PlatformFeatureState::unavailable(
                "remote script execution is disabled on iOS",
            ),
            mitm_certificate: MitmCertificateStatus::new(CertificateTrustState::InstalledUntrusted),
            diagnostics: Vec::new(),
        })
    }
}

#[test]
fn configuration_port_can_be_implemented_by_an_adapter() {
    let service = NoopConfigurationService;
    let capabilities = PlatformCapabilities {
        os: OperatingSystem::Linux,
        supports_tunnel: true,
        supports_mitm: false,
        supports_embedded_runtime: true,
    };

    let diagnostics = service.validate("", &capabilities);
    assert_eq!(diagnostics.len(), 1);

    let snapshot = service.normalize("profile = default", &capabilities);
    assert_eq!(
        snapshot.expect("snapshot should normalize").version.value(),
        1
    );
}

#[test]
fn proxy_engine_port_can_be_implemented_by_an_adapter() {
    let engine = NoopProxyEngineService;
    let capabilities = PlatformCapabilities {
        os: OperatingSystem::Linux,
        supports_tunnel: true,
        supports_mitm: false,
        supports_embedded_runtime: true,
    };
    let config_service = NoopConfigurationService;
    let config = config_service
        .normalize("profile = default", &capabilities)
        .expect("config should normalize");
    let engine_config = ProxyEngineConfig {
        engine_id: "native".to_string(),
        config,
        nodes: Vec::new(),
        metadata: Vec::new(),
    };

    assert_eq!(engine.list_engines().len(), 1);
    assert!(engine.validate_config(&engine_config).is_empty());
    assert_eq!(
        engine
            .start(&engine_config)
            .expect("engine should start")
            .state,
        ProxyEngineLifecycleState::Running
    );
}

#[test]
fn platform_capability_port_reports_mitm_certificate_state() {
    let service = NoopPlatformCapabilityService;
    let status = service.status().expect("platform status should load");

    assert_eq!(status.os, OperatingSystem::Ios);
    assert!(status.tunnel.is_available());
    assert!(!status.remote_script_execution.is_available());
    assert_eq!(
        status.remote_script_execution.denial_reason(),
        Some("remote script execution is disabled on iOS")
    );
    assert_eq!(
        status.mitm_certificate.state,
        CertificateTrustState::InstalledUntrusted
    );
    assert!(status.mitm_certificate.is_installed());
    assert!(!status.mitm_available());
    assert_eq!(
        status.mitm_denied_reason(),
        Some("mitm certificate is installed but not trusted")
    );
}
