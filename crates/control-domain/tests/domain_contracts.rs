use control_domain::{
    CertificateTrustState, ConfigSnapshot, ConfigurationService, Diagnostic, DiagnosticSeverity,
    DomainResult, Endpoint, ListenerBind, ListenerDescriptor, ListenerKind, ListenerNetwork,
    ListenerRoute, MetadataEntry, MitmCertificateStatus, NodeCatalog, NodeDescriptor,
    OperatingSystem, PlatformCapabilities, PlatformCapabilityService, PlatformCapabilityStatus,
    PlatformFeatureState, Protocol, ProxyEngineCapability, ProxyEngineConfig,
    ProxyEngineDescriptor, ProxyEngineEvent, ProxyEngineKind, ProxyEngineLifecycleState,
    ProxyEngineService, ProxyEngineStatus, RawSubscription, RouteAction, RuleSet, SchemaVersion,
    SubscriptionDocument, SubscriptionService, SubscriptionSource,
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
            listeners: Vec::new(),
            nodes: Vec::new(),
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

struct NoopSubscriptionService;

impl SubscriptionService for NoopSubscriptionService {
    fn fetch(&self, source: &SubscriptionSource) -> DomainResult<RawSubscription> {
        Ok(RawSubscription {
            source_id: source.id.clone(),
            content: "node = test".to_string(),
        })
    }

    fn parse(&self, raw_subscription: &RawSubscription) -> DomainResult<SubscriptionDocument> {
        Ok(SubscriptionDocument {
            nodes: vec![node_from_subscription(&raw_subscription.source_id)],
            rules: vec![RuleSet {
                id: "subscription-default".to_string(),
                rules: Vec::new(),
                default_action: RouteAction::Proxy {
                    node_id: raw_subscription.source_id.clone(),
                },
            }],
            diagnostics: Vec::new(),
        })
    }

    fn normalize(&self, document: &SubscriptionDocument) -> DomainResult<NodeCatalog> {
        Ok(NodeCatalog {
            nodes: document.nodes.clone(),
            rules: document.rules.clone(),
        })
    }
}

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
fn config_snapshot_exposes_listener_configuration_as_domain_model() {
    let listener = ListenerDescriptor {
        id: "loopback-socks".to_string(),
        enabled: true,
        kind: ListenerKind::Socks,
        bind: ListenerBind {
            host: "127.0.0.1".to_string(),
            port: 1080,
        },
        network: ListenerNetwork::Tcp,
        route: ListenerRoute::RuleSet {
            rule_set_id: "default-policy".to_string(),
        },
        tags: vec!["local".to_string()],
        metadata: vec![MetadataEntry {
            key: "source".to_string(),
            value: "test".to_string(),
        }],
    };
    let snapshot = ConfigSnapshot {
        version: SchemaVersion::new(1),
        profiles: vec!["default".to_string()],
        listeners: vec![listener],
        nodes: Vec::new(),
        policies: Vec::new(),
        dns: Vec::new(),
        plugins: Vec::new(),
    };

    assert_eq!(snapshot.listeners[0].id, "loopback-socks");
    assert_eq!(snapshot.listeners[0].kind, ListenerKind::Socks);
    assert_eq!(snapshot.listeners[0].bind.port, 1080);
    assert_eq!(snapshot.listeners[0].network, ListenerNetwork::Tcp);
    assert_eq!(
        snapshot.listeners[0].route,
        ListenerRoute::RuleSet {
            rule_set_id: "default-policy".to_string()
        }
    );
    assert_eq!(snapshot.listeners[0].metadata[0].key, "source");
}

#[test]
fn listener_route_can_reference_default_action_without_runtime_validation() {
    let listener = ListenerDescriptor {
        id: "direct-loopback".to_string(),
        enabled: false,
        kind: ListenerKind::LocalTcp,
        bind: ListenerBind {
            host: "::1".to_string(),
            port: 8080,
        },
        network: ListenerNetwork::TcpUdp,
        route: ListenerRoute::DefaultAction(RouteAction::Direct),
        tags: Vec::new(),
        metadata: Vec::new(),
    };

    assert!(!listener.enabled);
    assert_eq!(listener.kind, ListenerKind::LocalTcp);
    assert_eq!(listener.bind.host, "::1");
    assert_eq!(listener.network, ListenerNetwork::TcpUdp);
    assert_eq!(
        listener.route,
        ListenerRoute::DefaultAction(RouteAction::Direct)
    );
}

#[test]
fn subscription_port_can_fetch_parse_and_normalize_a_catalog() {
    let service = NoopSubscriptionService;
    let source = SubscriptionSource {
        id: "subscription-node".to_string(),
        location: "inline".to_string(),
    };

    let raw = service.fetch(&source).expect("subscription should fetch");
    let document = service.parse(&raw).expect("subscription should parse");
    let catalog = service
        .normalize(&document)
        .expect("subscription should normalize");

    assert_eq!(raw.source_id, "subscription-node");
    assert_eq!(document.nodes.len(), 1);
    assert_eq!(catalog.nodes[0].id, "subscription-node");
    assert_eq!(catalog.rules[0].id, "subscription-default");
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

fn node_from_subscription(id: &str) -> NodeDescriptor {
    NodeDescriptor {
        id: id.to_string(),
        name: "Subscription node".to_string(),
        protocol: Protocol::Socks,
        endpoint: Endpoint {
            host: "127.0.0.1".to_string(),
            port: 1081,
        },
        tags: vec!["subscription".to_string()],
        metadata: Vec::new(),
    }
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
