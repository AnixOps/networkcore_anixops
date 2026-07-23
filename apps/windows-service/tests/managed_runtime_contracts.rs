use control_domain::{DomainError, DomainResult};
use networkcore_windows::{
    WindowsTunnelCommandResult, WindowsTunnelCommandService, WindowsTunnelPrepareStorageArgs,
    WindowsTunnelStartArgs, WindowsTunnelStatusArgs, WindowsTunnelStopArgs,
};
use networkcore_windows_service::WindowsManagedRuntime;
use platform_windows::managed::{
    read_managed_state, write_managed_config, WindowsDriverPackageConfig, WindowsManagedConfig,
    WindowsManagedNativeMitmConfig, WindowsProxySettings, WindowsProxySnapshot,
};
use platform_windows::system_integration::{
    WindowsDriverInstallResult, WindowsServiceState, WindowsServiceStatus, WindowsSystemIntegration,
};
use platform_windows::tunnel_config::{
    OwnedProcessHandle, WindowsRouteSnapshotEntry, WindowsTunnelLifecycleState,
    WindowsTunnelRuntimeOwnership, WindowsTunnelState,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use std::cell::RefCell;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::rc::Rc;

#[derive(Clone, Default)]
struct FakeIntegration {
    events: Rc<RefCell<Vec<String>>>,
    fail_proxy: bool,
}

impl WindowsSystemIntegration for FakeIntegration {
    fn install_service(&self, _executable: &Path) -> DomainResult<()> {
        self.events.borrow_mut().push("install-service".to_string());
        Ok(())
    }

    fn uninstall_service(&self) -> DomainResult<()> {
        self.events
            .borrow_mut()
            .push("uninstall-service".to_string());
        Ok(())
    }

    fn start_service(&self) -> DomainResult<WindowsServiceStatus> {
        self.events.borrow_mut().push("start-service".to_string());
        Ok(WindowsServiceStatus {
            state: WindowsServiceState::Running,
            process_id: 10,
        })
    }

    fn stop_service(&self) -> DomainResult<WindowsServiceStatus> {
        self.events.borrow_mut().push("stop-service".to_string());
        Ok(WindowsServiceStatus {
            state: WindowsServiceState::Stopped,
            process_id: 0,
        })
    }

    fn restart_service(&self) -> DomainResult<WindowsServiceStatus> {
        self.events.borrow_mut().push("restart-service".to_string());
        Ok(WindowsServiceStatus {
            state: WindowsServiceState::Running,
            process_id: 10,
        })
    }

    fn service_status(&self) -> DomainResult<WindowsServiceStatus> {
        Ok(WindowsServiceStatus {
            state: WindowsServiceState::Stopped,
            process_id: 0,
        })
    }

    fn apply_system_proxy(
        &self,
        _settings: &WindowsProxySettings,
    ) -> DomainResult<WindowsProxySnapshot> {
        self.events.borrow_mut().push("apply-proxy".to_string());
        if self.fail_proxy {
            return Err(DomainError::new("fake.proxy.failed", "proxy failure"));
        }
        Ok(WindowsProxySnapshot {
            enabled: false,
            server: String::new(),
            bypass: String::new(),
            winhttp_access_type: 1,
            winhttp_server: String::new(),
            winhttp_bypass: String::new(),
        })
    }

    fn restore_system_proxy(&self, _snapshot: &WindowsProxySnapshot) -> DomainResult<()> {
        self.events.borrow_mut().push("restore-proxy".to_string());
        Ok(())
    }

    fn install_root_certificate(&self, _certificate: &Path) -> DomainResult<String> {
        self.events
            .borrow_mut()
            .push("install-certificate".to_string());
        Ok("00112233445566778899AABBCCDDEEFF00112233".to_string())
    }

    fn remove_root_certificate(&self, _sha1_thumbprint: &str) -> DomainResult<()> {
        self.events
            .borrow_mut()
            .push("remove-certificate".to_string());
        Ok(())
    }

    fn install_driver(&self, inf_path: &Path) -> DomainResult<WindowsDriverInstallResult> {
        self.events.borrow_mut().push("install-driver".to_string());
        Ok(WindowsDriverInstallResult {
            inf_path: inf_path.to_path_buf(),
            reboot_required: false,
        })
    }

    fn uninstall_driver(&self, _inf_path: &Path) -> DomainResult<bool> {
        self.events.borrow_mut().push("remove-driver".to_string());
        Ok(false)
    }
}

#[derive(Clone, Default)]
struct FakeTunnel {
    events: Rc<RefCell<Vec<String>>>,
}

impl WindowsTunnelCommandService for FakeTunnel {
    fn prepare_storage(&mut self, _args: &WindowsTunnelPrepareStorageArgs) -> DomainResult<()> {
        self.events.borrow_mut().push("prepare-storage".to_string());
        Ok(())
    }

    fn start(
        &mut self,
        _args: &WindowsTunnelStartArgs,
    ) -> DomainResult<WindowsTunnelCommandResult> {
        self.events.borrow_mut().push("start-tunnel".to_string());
        Ok(WindowsTunnelCommandResult {
            state: fixture_tunnel_state(WindowsTunnelLifecycleState::Running),
            peer_ready: true,
            route_ready: true,
            route_count: 1,
        })
    }

    fn status(
        &mut self,
        _args: &WindowsTunnelStatusArgs,
    ) -> DomainResult<WindowsTunnelCommandResult> {
        self.events.borrow_mut().push("status-tunnel".to_string());
        Ok(WindowsTunnelCommandResult {
            state: fixture_tunnel_state(WindowsTunnelLifecycleState::Running),
            peer_ready: true,
            route_ready: true,
            route_count: 1,
        })
    }

    fn stop(&mut self, _args: &WindowsTunnelStopArgs) -> DomainResult<WindowsTunnelCommandResult> {
        self.events.borrow_mut().push("stop-tunnel".to_string());
        Ok(WindowsTunnelCommandResult {
            state: fixture_tunnel_state(WindowsTunnelLifecycleState::Stopped),
            peer_ready: false,
            route_ready: false,
            route_count: 0,
        })
    }
}

fn fixture_tunnel_state(state: WindowsTunnelLifecycleState) -> WindowsTunnelState {
    WindowsTunnelState {
        schema_version: 4,
        session_id: "managed-session".to_string(),
        plan_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
        selected_pop_id: "pop-a".to_string(),
        selected_endpoint: "198.51.100.10:11010".to_string(),
        state,
        config_path: "managed-session.easytier.toml".to_string(),
        last_client_sequence: 1,
        last_pop_sequence: 1,
        client_bundle_id: "client".to_string(),
        client_sequence: 1,
        pop_bundle_id: "pop".to_string(),
        pop_sequence: 1,
        easytier_version: "2.6.1".to_string(),
        route_snapshot: vec![WindowsRouteSnapshotEntry {
            destination_cidr: "198.51.100.10/32".to_string(),
            gateway: Some("192.0.2.1".to_string()),
            interface_index: Some(1),
            metric: Some(10),
        }],
        rollback_status: "clean".to_string(),
        runtime_ownership: WindowsTunnelRuntimeOwnership {
            process: OwnedProcessHandle {
                session_id: "managed-session".to_string(),
                process_id: 100,
                creation_marker: "marker".to_string(),
            },
            binary_sha256: "a".repeat(64),
            cli_file_name: "easytier-cli.exe".to_string(),
            cli_sha256: "b".repeat(64),
            route_cidrs: vec!["203.0.113.0/24".to_string()],
            virtual_route_snapshot: vec![WindowsRouteSnapshotEntry {
                destination_cidr: "203.0.113.0/24".to_string(),
                gateway: Some("10.10.0.1".to_string()),
                interface_index: Some(42),
                metric: Some(7),
            }],
        },
    }
}

fn fixture_config(with_tunnel: bool) -> WindowsManagedConfig {
    WindowsManagedConfig {
        schema_version: 1,
        system_proxy: Some(WindowsProxySettings {
            enabled: true,
            server: "127.0.0.1:7890".to_string(),
            bypass: "<local>".to_string(),
        }),
        root_certificate_path: Some(PathBuf::from("ca.pem")),
        driver_package: Some(WindowsDriverPackageConfig {
            inf_path: PathBuf::from("driver.inf"),
        }),
        tunnel: with_tunnel.then(|| platform_windows::managed::WindowsManagedTunnelConfig {
            client_envelope: PathBuf::from("client.json"),
            pop_envelope: PathBuf::from("pop.json"),
            pop_id: "pop-a".to_string(),
            device_id: "device-a".to_string(),
            delivery_public_key_file: PathBuf::from("delivery.pem"),
            easytier_binary: PathBuf::from("easytier-core.exe"),
            easytier_cli: PathBuf::from("easytier-cli.exe"),
            easytier_version: "2.6.1".to_string(),
            easytier_sha256: "a".repeat(64),
            easytier_cli_sha256: "b".repeat(64),
            network_name: "managed-network".to_string(),
            network_secret_file: PathBuf::from("secret.txt"),
            state_path: PathBuf::from("tunnel-state.json"),
        }),
        sing_box: None,
        native_mitm: None,
    }
}

fn fixture_paths(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "networkcore-windows-service-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("fixture directory");
    (
        root.join("managed-config.json"),
        root.join("managed-state.json"),
        root,
    )
}

fn write_mitm_ca(root: &Path) -> (PathBuf, PathBuf) {
    let certificate_path = root.join("root-ca.pem");
    let private_key_path = root.join("root-ca-key.pem");
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "NetworkCore Windows service test CA");
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key_pair = KeyPair::generate().expect("test CA key generates");
    let certificate = params
        .self_signed(&key_pair)
        .expect("test CA cert generates");
    fs::write(&certificate_path, certificate.pem()).expect("test CA cert writes");
    fs::write(&private_key_path, key_pair.serialize_pem()).expect("test CA key writes");
    (certificate_path, private_key_path)
}

fn unused_loopback_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("test listener binds");
    listener.local_addr().expect("test listener address").port()
}

#[test]
fn managed_runtime_applies_and_purges_all_windows_mutations() {
    let (config_path, state_path, root) = fixture_paths("apply-purge");
    write_managed_config(&config_path, &fixture_config(false)).expect("config writes");
    let events = Rc::new(RefCell::new(Vec::new()));
    let integration = FakeIntegration {
        events: events.clone(),
        fail_proxy: false,
    };
    let tunnel = FakeTunnel {
        events: events.clone(),
    };
    let mut runtime =
        WindowsManagedRuntime::new(integration, tunnel, config_path, state_path.clone());

    let running = runtime.start().expect("managed runtime starts");
    assert_eq!(running.last_transition, "running");
    assert_eq!(
        &events.borrow()[..3],
        ["install-driver", "install-certificate", "apply-proxy"].map(String::from)
    );
    let stopped = runtime.stop().expect("managed runtime stops");
    assert_eq!(stopped.last_transition, "stopped");
    let purged = runtime.purge().expect("managed runtime purges");
    assert_eq!(purged.last_transition, "purged");
    assert!(purged.certificate_sha1.is_none());
    assert!(purged.driver_inf_path.is_none());
    let persisted = read_managed_state(&state_path).expect("state remains readable");
    assert_eq!(persisted.last_transition, "purged");
    assert!(events.borrow().contains(&"restore-proxy".to_string()));
    assert!(events.borrow().contains(&"remove-certificate".to_string()));
    assert!(events.borrow().contains(&"remove-driver".to_string()));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn managed_runtime_rolls_back_certificate_when_proxy_apply_fails() {
    let (config_path, state_path, root) = fixture_paths("rollback");
    write_managed_config(&config_path, &fixture_config(false)).expect("config writes");
    let events = Rc::new(RefCell::new(Vec::new()));
    let integration = FakeIntegration {
        events: events.clone(),
        fail_proxy: true,
    };
    let tunnel = FakeTunnel::default();
    let mut runtime =
        WindowsManagedRuntime::new(integration, tunnel, config_path, state_path.clone());

    let error = runtime.start().expect_err("proxy failure is returned");
    assert_eq!(error.code, "fake.proxy.failed");
    assert!(events.borrow().contains(&"remove-certificate".to_string()));
    let state = read_managed_state(&state_path).expect("failed state is persisted");
    assert_eq!(state.last_transition, "failed");
    assert!(state.certificate_sha1.is_none());
    assert!(state.driver_inf_path.is_none());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn managed_runtime_owns_tunnel_start_and_stop_lifecycle() {
    let (config_path, state_path, root) = fixture_paths("tunnel");
    write_managed_config(&config_path, &fixture_config(true)).expect("config writes");
    let events = Rc::new(RefCell::new(Vec::new()));
    let integration = FakeIntegration {
        events: events.clone(),
        fail_proxy: false,
    };
    let tunnel = FakeTunnel {
        events: events.clone(),
    };
    let mut runtime = WindowsManagedRuntime::new(integration, tunnel, config_path, state_path);

    let running = runtime.start().expect("managed tunnel starts");
    assert!(running.tunnel_running);
    let stopped = runtime.stop().expect("managed tunnel stops");
    assert!(!stopped.tunnel_running);
    assert!(events.borrow().contains(&"prepare-storage".to_string()));
    assert!(events.borrow().contains(&"start-tunnel".to_string()));
    assert!(events.borrow().contains(&"stop-tunnel".to_string()));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn managed_runtime_owns_native_https_mitm_lifecycle() {
    let (config_path, state_path, root) = fixture_paths("native-mitm");
    let (certificate_path, private_key_path) = write_mitm_ca(&root);
    let listener_port = unused_loopback_port();
    let mut config = fixture_config(false);
    config.root_certificate_path = None;
    config.driver_package = None;
    config.native_mitm = Some(WindowsManagedNativeMitmConfig {
        enabled: true,
        listen_host: "127.0.0.1".to_string(),
        listen_port: listener_port,
        upstream_socks_host: "127.0.0.1".to_string(),
        upstream_socks_port: unused_loopback_port(),
        ca_certificate_path: certificate_path,
        ca_private_key_path: private_key_path,
        log_path: root.join("native-mitm.log"),
    });
    write_managed_config(&config_path, &config).expect("config writes");
    let events = Rc::new(RefCell::new(Vec::new()));
    let integration = FakeIntegration {
        events: events.clone(),
        fail_proxy: false,
    };
    let tunnel = FakeTunnel {
        events: events.clone(),
    };
    let mut runtime = WindowsManagedRuntime::new(integration, tunnel, config_path, state_path);

    let running = runtime.start().expect("managed native MITM starts");
    assert!(running.native_mitm_running);
    let expected_listener = format!("127.0.0.1:{listener_port}");
    assert_eq!(
        running.native_mitm_listener.as_deref(),
        Some(expected_listener.as_str())
    );
    assert!(events.borrow().contains(&"install-certificate".to_string()));

    let stopped = runtime.stop().expect("managed native MITM stops");
    assert!(!stopped.native_mitm_running);
    let _ = fs::remove_dir_all(root);
}
