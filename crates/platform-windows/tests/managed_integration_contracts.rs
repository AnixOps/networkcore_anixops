use platform_windows::managed::{
    read_managed_config, WindowsDriverPackageConfig, WindowsManagedConfig,
    WindowsManagedNativeMitmConfig, WindowsManagedSingBoxConfig, WindowsManagedState,
    WindowsManagedTunnelConfig, WindowsProxySettings, WindowsProxySnapshot,
    WindowsSystemProxyOwner, WINDOWS_MANAGED_CONFIG_INVALID_CODE,
    WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION, WINDOWS_MANAGED_STATE_SCHEMA_VERSION,
};
use platform_windows::system_integration::{WindowsServiceState, NETWORKCORE_WINDOWS_SERVICE_NAME};
use std::path::PathBuf;

fn fixture_tunnel() -> WindowsManagedTunnelConfig {
    WindowsManagedTunnelConfig {
        client_envelope: PathBuf::from(r"C:\ProgramData\AnixOps\NetworkCore\client.json"),
        pop_envelope: PathBuf::from(r"C:\ProgramData\AnixOps\NetworkCore\pop.json"),
        pop_id: "pop-a".to_string(),
        device_id: "device-a".to_string(),
        delivery_public_key_file: PathBuf::from(r"C:\ProgramData\AnixOps\NetworkCore\delivery.pem"),
        easytier_binary: PathBuf::from(r"C:\Program Files\EasyTier\easytier-core.exe"),
        easytier_cli: PathBuf::from(r"C:\Program Files\EasyTier\easytier-cli.exe"),
        easytier_version: "2.6.1".to_string(),
        easytier_sha256: "d33d1d119b40c768c4d96c66236ba1c033e72a9c041e88aa9c84bd67a38d04a5"
            .to_string(),
        easytier_cli_sha256: "1a83ab65ea2cc02bbcd58f5bc8b24cd3942cbe9c4ac1b9cb2acd9881410bfcd3"
            .to_string(),
        network_name: "managed-network".to_string(),
        network_secret_file: PathBuf::from(
            r"C:\ProgramData\AnixOps\NetworkCore\network-secret.txt",
        ),
        state_path: PathBuf::from(r"C:\ProgramData\AnixOps\NetworkCore\tunnel-state.json"),
    }
}

#[test]
fn managed_configuration_activates_proxy_certificate_driver_and_tunnel() {
    let config = WindowsManagedConfig {
        schema_version: WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION,
        system_proxy: Some(WindowsProxySettings {
            enabled: true,
            server: "127.0.0.1:7890".to_string(),
            bypass: "<local>".to_string(),
        }),
        system_proxy_owner: WindowsSystemProxyOwner::Service,
        root_certificate_path: Some(PathBuf::from(
            r"C:\ProgramData\AnixOps\NetworkCore\networkcore-ca.pem",
        )),
        driver_package: Some(WindowsDriverPackageConfig {
            inf_path: PathBuf::from(r"C:\Program Files\AnixOps\NetworkCore\driver\netcore.inf"),
        }),
        tunnel: Some(fixture_tunnel()),
        sing_box: None,
        native_mitm: None,
    };

    config.validate().expect("managed configuration is valid");
    let json = serde_json::to_value(&config).expect("managed config serializes");
    assert_eq!(
        json["schema_version"],
        WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION
    );
    assert_eq!(json["system_proxy"]["server"], "127.0.0.1:7890");
    assert_eq!(json["system_proxy_owner"], "service");
    assert_eq!(
        json["driver_package"]["inf_path"],
        r"C:\Program Files\AnixOps\NetworkCore\driver\netcore.inf"
    );
}

#[test]
fn managed_tunnel_renders_existing_cli_start_and_stop_contracts() {
    let tunnel = fixture_tunnel();
    let start = tunnel.start_arguments();
    let stop = tunnel.stop_arguments();

    assert_eq!(start[0], "tunnel");
    assert_eq!(start[1], "start");
    assert!(start
        .windows(2)
        .any(|pair| pair[0] == "--pop-id" && pair[1] == "pop-a"));
    assert!(start
        .windows(2)
        .any(|pair| pair[0] == "--network-name" && pair[1] == "managed-network"));
    assert!(start.iter().any(|value| value == "--confirm"));
    assert_eq!(stop[0], "tunnel");
    assert_eq!(stop[1], "stop");
    assert!(stop.iter().any(|value| value == "--confirm"));
}

#[test]
fn managed_configuration_accepts_explicit_sing_box_process_paths() {
    let config = WindowsManagedConfig {
        schema_version: WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION,
        system_proxy: None,
        system_proxy_owner: WindowsSystemProxyOwner::Service,
        root_certificate_path: None,
        driver_package: None,
        tunnel: None,
        sing_box: Some(WindowsManagedSingBoxConfig {
            enabled: true,
            executable_path: PathBuf::from(
                r"C:\Program Files\AnixOps\NetworkCore\bin\sing-box.exe",
            ),
            config_path: PathBuf::from(r"C:\ProgramData\AnixOps\NetworkCore\sing-box\config.json"),
            working_directory: Some(PathBuf::from(
                r"C:\ProgramData\AnixOps\NetworkCore\sing-box",
            )),
            log_path: PathBuf::from(r"C:\ProgramData\AnixOps\NetworkCore\logs\sing-box.log"),
        }),
        native_mitm: None,
    };

    config.validate().expect("sing-box process paths are valid");
    let json = serde_json::to_value(&config).expect("sing-box config serializes");
    assert_eq!(json["sing_box"]["enabled"], true);
    assert_eq!(
        json["sing_box"]["executable_path"],
        r"C:\Program Files\AnixOps\NetworkCore\bin\sing-box.exe"
    );
}

#[test]
fn managed_configuration_rejects_enabled_proxy_without_endpoint() {
    let config = WindowsManagedConfig {
        schema_version: WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION,
        system_proxy: Some(WindowsProxySettings {
            enabled: true,
            server: " ".to_string(),
            bypass: String::new(),
        }),
        system_proxy_owner: WindowsSystemProxyOwner::Service,
        root_certificate_path: None,
        driver_package: None,
        tunnel: None,
        sing_box: None,
        native_mitm: None,
    };

    let error = config.validate().expect_err("proxy endpoint is required");
    assert_eq!(error.code, WINDOWS_MANAGED_CONFIG_INVALID_CODE);
}

#[test]
fn managed_state_retains_rollback_material_for_system_mutations() {
    let state = WindowsManagedState {
        schema_version: WINDOWS_MANAGED_STATE_SCHEMA_VERSION,
        proxy_snapshot: Some(WindowsProxySnapshot {
            enabled: false,
            server: String::new(),
            bypass: String::new(),
            winhttp_access_type: 1,
            winhttp_server: String::new(),
            winhttp_bypass: String::new(),
        }),
        certificate_sha1: Some("00112233445566778899AABBCCDDEEFF00112233".to_string()),
        driver_inf_path: Some(PathBuf::from(r"C:\driver\netcore.inf")),
        driver_reboot_required: false,
        tunnel_running: true,
        sing_box_running: false,
        sing_box_process_id: None,
        sing_box_exit_code: None,
        sing_box_log_path: None,
        native_mitm_running: true,
        native_mitm_listener: Some("127.0.0.1:7890".to_string()),
        native_mitm_certificate_sha1: Some("102132435465768798A9BACBDCEDFE0F10213243".to_string()),
        native_mitm_last_error: None,
        last_error: None,
        last_transition: "running".to_string(),
    };

    let json = serde_json::to_value(&state).expect("managed state serializes");
    assert_eq!(json["last_transition"], "running");
    assert_eq!(json["tunnel_running"], true);
    assert!(json["proxy_snapshot"].is_object());
    assert_eq!(json["native_mitm_listener"], "127.0.0.1:7890");
    assert!(json["last_error"].is_null());
}

#[test]
fn managed_configuration_accepts_native_https_mitm_with_explicit_socks_upstream() {
    let config = WindowsManagedConfig {
        schema_version: WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION,
        system_proxy: Some(WindowsProxySettings {
            enabled: true,
            server: "127.0.0.1:7890".to_string(),
            bypass: "<local>".to_string(),
        }),
        system_proxy_owner: WindowsSystemProxyOwner::Service,
        root_certificate_path: None,
        driver_package: None,
        tunnel: None,
        sing_box: None,
        native_mitm: Some(WindowsManagedNativeMitmConfig {
            enabled: true,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
            upstream_socks_host: "127.0.0.1".to_string(),
            upstream_socks_port: 7891,
            ca_certificate_path: PathBuf::from(
                r"C:\ProgramData\AnixOps\NetworkCore\mitm\root-ca.pem",
            ),
            ca_private_key_path: PathBuf::from(
                r"C:\ProgramData\AnixOps\NetworkCore\mitm\root-ca-key.pem",
            ),
            log_path: PathBuf::from(r"C:\ProgramData\AnixOps\NetworkCore\logs\native-mitm.log"),
            sing_box_config_snapshot_path: Some(PathBuf::from(
                r"C:\ProgramData\AnixOps\NetworkCore\mitm\sing-box-config.before-mitm.json",
            )),
        }),
    };

    config.validate().expect("native MITM config is valid");
    let mut desktop_owned = config.clone();
    desktop_owned.system_proxy_owner = WindowsSystemProxyOwner::Desktop;
    assert!(desktop_owned.validate().is_err());
    let mut json = serde_json::to_value(&config).expect("native MITM config serializes");
    assert_eq!(json["native_mitm"]["listen_port"], 7890);
    assert_eq!(json["native_mitm"]["upstream_socks_port"], 7891);
    assert_eq!(
        json["native_mitm"]["sing_box_config_snapshot_path"],
        r"C:\ProgramData\AnixOps\NetworkCore\mitm\sing-box-config.before-mitm.json"
    );
    json["native_mitm"]
        .as_object_mut()
        .expect("native MITM config serializes as an object")
        .remove("sing_box_config_snapshot_path");
    let legacy: WindowsManagedConfig =
        serde_json::from_value(json).expect("pre-snapshot native MITM config remains readable");
    assert_eq!(
        legacy
            .native_mitm
            .and_then(|native_mitm| native_mitm.sing_box_config_snapshot_path),
        None
    );
}

#[test]
fn legacy_managed_configuration_migrates_to_service_owned_proxy() {
    let path = std::env::temp_dir().join(format!(
        "networkcore-managed-config-v1-{}.json",
        std::process::id()
    ));
    std::fs::write(
        &path,
        r#"{
  "schema_version": 1,
  "system_proxy": {"enabled": true, "server": "127.0.0.1:7890", "bypass": "<local>"},
  "root_certificate_path": null,
  "driver_package": null,
  "tunnel": null
}"#,
    )
    .expect("legacy managed configuration writes");

    let config = read_managed_config(&path).expect("legacy config migrates in memory");
    assert_eq!(config.schema_version, WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION);
    assert_eq!(config.system_proxy_owner, WindowsSystemProxyOwner::Service);
    let _ = std::fs::remove_file(path);
}

#[test]
fn current_managed_configuration_requires_an_explicit_proxy_owner() {
    let path = std::env::temp_dir().join(format!(
        "networkcore-managed-config-v2-{}.json",
        std::process::id()
    ));
    std::fs::write(
        &path,
        r#"{
  "schema_version": 2,
  "system_proxy": null,
  "root_certificate_path": null,
  "driver_package": null,
  "tunnel": null
}"#,
    )
    .expect("incomplete configuration writes");

    assert!(read_managed_config(&path).is_err());
    let _ = std::fs::remove_file(path);
}

#[test]
fn windows_service_contract_uses_stable_scm_identity() {
    assert_eq!(NETWORKCORE_WINDOWS_SERVICE_NAME, "AnixOpsNetworkCore");
    assert_eq!(
        serde_json::to_string(&WindowsServiceState::Running).expect("service state serializes"),
        "\"running\""
    );
}
