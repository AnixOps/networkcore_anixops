use control_domain::{
    ConfigSnapshot, ConfigurationService, Diagnostic, DiagnosticSeverity, DomainResult,
    OperatingSystem, PlatformCapabilities, SchemaVersion,
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
    assert_eq!(snapshot.expect("snapshot should normalize").version.value(), 1);
}
