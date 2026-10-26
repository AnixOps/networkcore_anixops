use platform_windows::managed::{
    read_managed_config, WindowsDriverPackageConfig, WindowsManagedConfig,
    WindowsManagedEmbeddedConfig, WindowsManagedNativeMitmConfig,
    WindowsManagedNativeMitmScriptRuntimeConfig, WindowsManagedState, WindowsProxySettings,
    WindowsProxySnapshot, WindowsSystemProxyOwner, WINDOWS_MANAGED_CONFIG_INVALID_CODE,
    WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION, WINDOWS_MANAGED_EMBEDDED_CONFIG_INVALID_CODE,
    WINDOWS_MANAGED_STATE_SCHEMA_VERSION,
};
use platform_windows::system_integration::{WindowsServiceState, NETWORKCORE_WINDOWS_SERVICE_NAME};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[test]
fn managed_configuration_activates_proxy_certificate_and_driver() {
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
        native_mitm: None,
        embedded: None,
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
fn managed_configuration_runs_the_embedded_engine_as_the_only_core() {
    let embedded = WindowsManagedEmbeddedConfig {
        enabled: true,
        envelope_path: PathBuf::from(r"C:\ProgramData\AnixOps\NetworkCore\embedded\envelope.json"),
        listen_host: "127.0.0.1".to_string(),
        listen_port: 7890,
    };
    let mut config = WindowsManagedConfig {
        schema_version: WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION,
        system_proxy: Some(WindowsProxySettings {
            enabled: true,
            server: "127.0.0.1:7890".to_string(),
            bypass: "<local>".to_string(),
        }),
        system_proxy_owner: WindowsSystemProxyOwner::Desktop,
        root_certificate_path: None,
        driver_package: None,
        native_mitm: None,
        embedded: Some(embedded.clone()),
    };
    config.validate().expect("embedded engine config is valid");
    assert_eq!(embedded.listener(), "127.0.0.1:7890");

    // A config written before the embedded engine existed still reads.
    let mut json = serde_json::to_value(&config).unwrap();
    json.as_object_mut().unwrap().remove("embedded");
    let legacy: WindowsManagedConfig = serde_json::from_value(json).unwrap();
    assert!(legacy.embedded.is_none());

    for (host, port) in [("0.0.0.0", 7890), ("localhost", 7890), ("127.0.0.1", 0)] {
        config.embedded = Some(WindowsManagedEmbeddedConfig {
            listen_host: host.to_string(),
            listen_port: port,
            ..embedded.clone()
        });
        assert_eq!(
            config
                .validate()
                .expect_err("listener must be loopback")
                .code,
            WINDOWS_MANAGED_EMBEDDED_CONFIG_INVALID_CODE
        );
    }
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
        native_mitm: None,
        embedded: None,
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
        native_mitm_running: true,
        native_mitm_listener: Some("127.0.0.1:7890".to_string()),
        native_mitm_certificate_sha1: Some("102132435465768798A9BACBDCEDFE0F10213243".to_string()),
        native_mitm_last_error: None,
        embedded_running: false,
        embedded_listener: None,
        embedded_last_error: None,
        last_error: None,
        last_transition: "running".to_string(),
    };

    let json = serde_json::to_value(&state).expect("managed state serializes");
    assert_eq!(json["last_transition"], "running");
    assert!(json.get("tunnel_running").is_none());
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
            bilibili_web_ad_block_enabled: false,
            script_runtime: Some(WindowsManagedNativeMitmScriptRuntimeConfig {
                policy_source_path: PathBuf::from(
                    r"C:\ProgramData\AnixOps\NetworkCore\scripts\policy.conf",
                ),
                runner_path: PathBuf::from(r"C:\ProgramData\AnixOps\NetworkCore\scripts\runner.js"),
                node_binary: r"C:\Program Files\nodejs\node.exe".to_string(),
                script_maps: BTreeMap::from([(
                    "https://scripts.networkcore.test/rewrite.js".to_string(),
                    PathBuf::from(r"C:\ProgramData\AnixOps\NetworkCore\scripts\rewrite.js"),
                )]),
                persistent_store_path: Some(PathBuf::from(
                    r"C:\ProgramData\AnixOps\NetworkCore\scripts\store.json",
                )),
            }),
        }),
        embedded: None,
    };

    config.validate().expect("native MITM config is valid");
    let mut desktop_owned = config.clone();
    desktop_owned.system_proxy_owner = WindowsSystemProxyOwner::Desktop;
    assert!(desktop_owned.validate().is_err());
    let mut json = serde_json::to_value(&config).expect("native MITM config serializes");
    assert_eq!(json["native_mitm"]["listen_port"], 7890);
    assert_eq!(json["native_mitm"]["upstream_socks_port"], 7891);
    assert_eq!(json["native_mitm"]["bilibili_web_ad_block_enabled"], false);
    assert_eq!(
        json["native_mitm"]["script_runtime"]["policy_source_path"],
        r"C:\ProgramData\AnixOps\NetworkCore\scripts\policy.conf"
    );
    json["native_mitm"]
        .as_object_mut()
        .expect("native MITM config serializes as an object")
        .remove("bilibili_web_ad_block_enabled");
    let legacy: WindowsManagedConfig =
        serde_json::from_value(json).expect("pre-snapshot native MITM config remains readable");
    assert!(
        !legacy
            .native_mitm
            .expect("legacy native MITM configuration remains present")
            .bilibili_web_ad_block_enabled
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
