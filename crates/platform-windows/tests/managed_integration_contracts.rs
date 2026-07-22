use platform_windows::managed::{
    WindowsDriverPackageConfig, WindowsManagedConfig, WindowsManagedState,
    WindowsManagedTunnelConfig, WindowsProxySettings, WindowsProxySnapshot,
    WINDOWS_MANAGED_CONFIG_INVALID_CODE, WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION,
    WINDOWS_MANAGED_STATE_SCHEMA_VERSION,
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
        root_certificate_path: Some(PathBuf::from(
            r"C:\ProgramData\AnixOps\NetworkCore\networkcore-ca.pem",
        )),
        driver_package: Some(WindowsDriverPackageConfig {
            inf_path: PathBuf::from(r"C:\Program Files\AnixOps\NetworkCore\driver\netcore.inf"),
        }),
        tunnel: Some(fixture_tunnel()),
    };

    config.validate().expect("managed configuration is valid");
    let json = serde_json::to_value(&config).expect("managed config serializes");
    assert_eq!(
        json["schema_version"],
        WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION
    );
    assert_eq!(json["system_proxy"]["server"], "127.0.0.1:7890");
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
fn managed_configuration_rejects_enabled_proxy_without_endpoint() {
    let config = WindowsManagedConfig {
        schema_version: WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION,
        system_proxy: Some(WindowsProxySettings {
            enabled: true,
            server: " ".to_string(),
            bypass: String::new(),
        }),
        root_certificate_path: None,
        driver_package: None,
        tunnel: None,
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
        last_transition: "running".to_string(),
    };

    let json = serde_json::to_value(&state).expect("managed state serializes");
    assert_eq!(json["last_transition"], "running");
    assert_eq!(json["tunnel_running"], true);
    assert!(json["proxy_snapshot"].is_object());
}

#[test]
fn windows_service_contract_uses_stable_scm_identity() {
    assert_eq!(NETWORKCORE_WINDOWS_SERVICE_NAME, "AnixOpsNetworkCore");
    assert_eq!(
        serde_json::to_string(&WindowsServiceState::Running).expect("service state serializes"),
        "\"running\""
    );
}
