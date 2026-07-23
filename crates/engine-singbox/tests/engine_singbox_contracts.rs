use control_domain::{
    Endpoint, MetadataEntry, NodeDescriptor, Protocol, ProxyEngineKind, ProxyEngineService,
    NODE_METADATA_HYSTERIA2_OBFS_MAX_PACKET_SIZE, NODE_METADATA_HYSTERIA2_OBFS_MIN_PACKET_SIZE,
    NODE_METADATA_HYSTERIA2_OBFS_PASSWORD, NODE_METADATA_HYSTERIA2_OBFS_TYPE,
    NODE_METADATA_HYSTERIA2_PASSWORD, NODE_METADATA_HYSTERIA2_SERVER_PORTS,
    NODE_METADATA_SHADOWSOCKS_METHOD, NODE_METADATA_SHADOWSOCKS_PASSWORD, NODE_METADATA_TLS_ALPN,
    NODE_METADATA_TLS_CERTIFICATE_PUBLIC_KEY_SHA256, NODE_METADATA_TLS_ENABLED,
    NODE_METADATA_TLS_INSECURE, NODE_METADATA_TLS_REALITY_PUBLIC_KEY,
    NODE_METADATA_TLS_REALITY_SHORT_ID, NODE_METADATA_TLS_SERVER_NAME,
    NODE_METADATA_TLS_UTLS_FINGERPRINT, NODE_METADATA_TROJAN_PASSWORD,
    NODE_METADATA_TUIC_CONGESTION_CONTROL, NODE_METADATA_TUIC_PASSWORD, NODE_METADATA_TUIC_UUID,
    NODE_METADATA_V2RAY_TRANSPORT_HOST, NODE_METADATA_V2RAY_TRANSPORT_PATH,
    NODE_METADATA_V2RAY_TRANSPORT_SERVICE_NAME, NODE_METADATA_V2RAY_TRANSPORT_TYPE,
    NODE_METADATA_VLESS_FLOW, NODE_METADATA_VLESS_UUID, NODE_METADATA_VMESS_ALTER_ID,
    NODE_METADATA_VMESS_SECURITY, NODE_METADATA_VMESS_UUID,
};
use engine_singbox::{
    inspect_sing_box_native_config, measure_sing_box_clash_api_outbound_delay,
    rewrite_sing_box_mixed_inbound_listener, GithubSingBoxReleaseInstaller, SingBoxHttpClient,
    SingBoxInstallRequest, SingBoxLocalControllerConfig, SingBoxLocalProxyConfigRequest,
    SingBoxManagedProcessState, SingBoxManagedProcessSupervisor, SingBoxReleaseInstaller,
    SingBoxTarget, SingBoxTargetArch, SingBoxTargetOs,
    DEFAULT_SING_BOX_CLASH_API_DELAY_TIMEOUT_MILLIS, DEFAULT_SING_BOX_ENGINE_ID,
    ENGINE_SINGBOX_CONFIG_MIXED_INBOUND_MISSING_CODE, ENGINE_SINGBOX_CONFIG_RENDERED_CODE,
    ENGINE_SINGBOX_DOWNLOAD_ASSET_SELECTED_CODE, ENGINE_SINGBOX_DOWNLOAD_BINARY_READY_CODE,
    ENGINE_SINGBOX_DOWNLOAD_CHECKSUM_VERIFIED_CODE,
    ENGINE_SINGBOX_DOWNLOAD_LATEST_VERSION_RESOLVED_CODE,
};
use flate2::{write::DeflateEncoder, write::GzEncoder, Compression};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;
use tar::{Builder, Header};

#[test]
fn sing_box_descriptor_announces_public_engine_capabilities() {
    let service = engine_singbox::SingBoxProxyEngineService::new();

    let descriptors = service.list_engines();

    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0].id, DEFAULT_SING_BOX_ENGINE_ID);
    assert_eq!(descriptors[0].kind, ProxyEngineKind::SingBox);
    assert!(descriptors[0].version.is_some());
    assert!(!descriptors[0].capabilities.is_empty());
}

#[test]
fn managed_process_supervisor_starts_stopped() {
    let mut supervisor = SingBoxManagedProcessSupervisor::default();

    let status = supervisor
        .status()
        .expect("managed supervisor status should be readable");

    assert_eq!(status.state, SingBoxManagedProcessState::Stopped);
    assert_eq!(status.process_id, None);
}

#[test]
fn release_asset_selection_prefers_generic_linux_amd64_tarball() {
    let release = engine_singbox::parse_sing_box_release(
        r#"
{
  "tag_name": "v1.2.3",
  "assets": [
    {
      "name": "sing-box-1.2.3-linux-amd64-glibc.tar.gz",
      "browser_download_url": "https://example.invalid/glibc.tar.gz",
      "size": 1,
      "digest": "sha256:1111"
    },
    {
      "name": "sing-box-1.2.3-linux-amd64.tar.gz",
      "browser_download_url": "https://example.invalid/generic.tar.gz",
      "size": 2,
      "digest": "sha256:2222"
    }
  ]
}
"#,
    )
    .expect("release should parse");

    let plan = engine_singbox::select_sing_box_asset(
        &release,
        SingBoxTarget::new(SingBoxTargetOs::Linux, SingBoxTargetArch::Amd64),
    )
    .expect("linux amd64 asset should be selected");

    assert_eq!(plan.version, "1.2.3");
    assert_eq!(plan.asset_name, "sing-box-1.2.3-linux-amd64.tar.gz");
    assert_eq!(plan.sha256_digest.as_deref(), Some("2222"));
}

#[test]
fn latest_installer_downloads_verifies_and_extracts_sing_box_tarball() {
    let tarball = sing_box_tarball();
    let digest = sha256_hex(&tarball);
    let release_json = format!(
        r#"{{
  "tag_name": "v1.2.3",
  "assets": [
    {{
      "name": "sing-box-1.2.3-linux-amd64.tar.gz",
      "browser_download_url": "https://example.invalid/sing-box-1.2.3-linux-amd64.tar.gz",
      "size": {},
      "digest": "sha256:{}"
    }}
  ]
}}"#,
        tarball.len(),
        digest
    );
    let http = MemorySingBoxHttpClient {
        release_json,
        asset_bytes: tarball,
    };
    let installer = GithubSingBoxReleaseInstaller::with_http_client(http);
    let root = unique_temp_root();
    let request = SingBoxInstallRequest {
        install_root: root.clone(),
        target: SingBoxTarget::new(SingBoxTargetOs::Linux, SingBoxTargetArch::Amd64),
        force: false,
    };

    let report = installer
        .install_latest(&request)
        .expect("installer should download and extract latest sing-box");

    assert_eq!(report.version, "1.2.3");
    assert!(report.downloaded);
    assert_eq!(report.asset_sha256.as_deref(), Some(digest.as_str()));
    assert_eq!(
        fs::read(&report.executable_path).expect("sing-box executable should exist"),
        b"fake-sing-box"
    );
    assert!(report.archive_path.exists());
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_SINGBOX_DOWNLOAD_LATEST_VERSION_RESOLVED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_SINGBOX_DOWNLOAD_ASSET_SELECTED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_SINGBOX_DOWNLOAD_CHECKSUM_VERIFIED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_SINGBOX_DOWNLOAD_BINARY_READY_CODE,
    );

    let cached_report = installer
        .install_latest(&request)
        .expect("installer should reuse existing latest binary");
    assert!(!cached_report.downloaded);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn latest_installer_extracts_windows_sing_box_zip_entry() {
    let zip = sing_box_zip();
    let digest = sha256_hex(&zip);
    let release_json = format!(
        r#"{{
  "tag_name": "v1.2.3",
  "assets": [
    {{
      "name": "sing-box-1.2.3-windows-amd64.zip",
      "browser_download_url": "https://example.invalid/sing-box-1.2.3-windows-amd64.zip",
      "size": {},
      "digest": "sha256:{}"
    }}
  ]
}}"#,
        zip.len(),
        digest
    );
    let installer = GithubSingBoxReleaseInstaller::with_http_client(MemorySingBoxHttpClient {
        release_json,
        asset_bytes: zip,
    });
    let root = unique_temp_root();
    let report = installer
        .install_latest(&SingBoxInstallRequest {
            install_root: root.clone(),
            target: SingBoxTarget::new(SingBoxTargetOs::Windows, SingBoxTargetArch::Amd64),
            force: false,
        })
        .expect("installer should extract the Windows sing-box executable");

    assert_eq!(
        fs::read(&report.executable_path).expect("Windows executable should exist"),
        b"fake-windows-sing-box"
    );
    assert!(report.downloaded);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn native_config_import_preserves_advanced_sing_box_fields_and_finds_mixed_inbound() {
    let raw = r#"
{
  "log": { "level": "debug" },
  "inbounds": [
    { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080 }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "reality-ws",
      "server": "edge.example.test",
      "server_port": 443,
      "uuid": "00000000-0000-0000-0000-000000000001",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "cdn.example.test",
        "reality": { "enabled": true, "public_key": "fixture", "short_id": "abcd" }
      },
      "transport": { "type": "ws", "path": "/gateway" }
    }
  ],
  "route": { "final": "reality-ws" },
  "dns": { "servers": [{ "tag": "local", "address": "local" }] }
}
"#;

    let imported = inspect_sing_box_native_config(raw).expect("native sing-box config is detected");

    assert_eq!(imported.json, raw.trim());
    assert_eq!(
        imported
            .local_http_proxy
            .as_ref()
            .map(|proxy| proxy.endpoint()),
        Some("127.0.0.1:2080".to_string())
    );
    assert!(imported.json.contains("\"reality\""));
    assert!(imported.json.contains("\"transport\""));
    assert!(imported.json.contains("\"dns\""));
}

#[test]
fn native_config_import_leaves_share_link_json_for_the_profile_parser() {
    let vmess_share = r#"{ "v": "2", "ps": "fixture", "add": "edge.example.test", "port": "443" }"#;

    assert_eq!(inspect_sing_box_native_config(vmess_share), None);
}

#[test]
fn native_config_import_selects_a_later_loopback_http_inbound() {
    let raw = r#"
{
  "inbounds": [
    { "type": "mixed", "listen": "192.0.2.5", "listen_port": 1080 },
    { "type": "socks", "listen": "127.0.0.1", "listen_port": 1081 },
    { "type": "http", "listen": "0.0.0.0", "listen_port": 2080 }
  ],
  "outbounds": [{ "type": "direct", "tag": "direct" }]
}
"#;

    let imported = inspect_sing_box_native_config(raw).expect("native sing-box config is detected");

    assert_eq!(
        imported
            .local_http_proxy
            .as_ref()
            .map(|proxy| proxy.endpoint()),
        Some("127.0.0.1:2080".to_string())
    );
}

#[test]
fn native_mitm_rewrite_only_changes_the_controlled_mixed_inbound_listener() {
    let raw = r#"
{
  "inbounds": [
    { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080 },
    { "type": "tun", "tag": "tun-in", "mtu": 9000 }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "reality-ws",
      "server": "edge.example.test",
      "server_port": 443,
      "uuid": "00000000-0000-0000-0000-000000000001",
      "tls": { "enabled": true, "reality": { "enabled": true, "public_key": "fixture" } },
      "transport": { "type": "ws", "path": "/gateway" }
    }
  ],
  "route": { "final": "reality-ws" },
  "dns": { "servers": [{ "tag": "local", "address": "local" }] }
}
"#;

    let rewritten = rewrite_sing_box_mixed_inbound_listener(raw, "127.0.0.1", 7891)
        .expect("controlled mixed inbound can be rewritten");
    let json: serde_json::Value =
        serde_json::from_str(&rewritten).expect("rewritten config remains valid JSON");

    assert_eq!(json["inbounds"][0]["listen"], "127.0.0.1");
    assert_eq!(json["inbounds"][0]["listen_port"], 7891);
    assert_eq!(json["inbounds"][1]["mtu"], 9000);
    assert_eq!(
        json["outbounds"][0]["tls"]["reality"]["public_key"],
        "fixture"
    );
    assert_eq!(json["outbounds"][0]["transport"]["path"], "/gateway");
    assert_eq!(json["route"]["final"], "reality-ws");
    assert_eq!(json["dns"]["servers"][0]["address"], "local");
}

#[test]
fn native_mitm_rewrite_rejects_configs_without_a_controlled_mixed_inbound() {
    let error = rewrite_sing_box_mixed_inbound_listener(
        r#"{ "inbounds": [{ "type": "http", "tag": "mixed-in", "listen_port": 7890 }] }"#,
        "127.0.0.1",
        7891,
    )
    .expect_err("an HTTP-only or untagged inbound cannot be a SOCKS upstream");

    assert_eq!(error.code, ENGINE_SINGBOX_CONFIG_MIXED_INBOUND_MISSING_CODE);
}

#[test]
fn renders_local_mixed_inbound_config_from_shadowsocks_node_catalog() {
    let rendered =
        engine_singbox::render_sing_box_local_proxy_config(&SingBoxLocalProxyConfigRequest {
            nodes: vec![shadowsocks_node()],
            selected_node_id: None,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        })
        .expect("shadowsocks node should render to sing-box config");

    let json: serde_json::Value =
        serde_json::from_str(&rendered.json).expect("rendered config should be valid json");
    assert_eq!(rendered.selected_node_id, "ss-hk");
    assert_eq!(rendered.selected_node_name, "香港");
    assert_eq!(json["inbounds"][0]["type"], "mixed");
    assert_eq!(json["inbounds"][0]["listen"], "127.0.0.1");
    assert_eq!(json["inbounds"][0]["listen_port"], 7890);
    assert_eq!(json["outbounds"][0]["type"], "shadowsocks");
    assert_eq!(json["outbounds"][0]["server"], "82.47.34.99");
    assert_eq!(json["outbounds"][0]["server_port"], 11111);
    assert_eq!(json["outbounds"][0]["method"], "aes-256-gcm");
    assert_eq!(
        json["outbounds"][0]["password"],
        "f43c0eee-13b9-4f07-bec9-d4b744141503"
    );
    assert_eq!(json["route"]["final"], "ss-hk");
    assert!(json.get("experimental").is_none());
    assert_diagnostic(&rendered.diagnostics, ENGINE_SINGBOX_CONFIG_RENDERED_CODE);
}

#[test]
fn renders_loopback_clash_selector_for_explicit_runtime_node_switching() {
    let rendered = engine_singbox::render_sing_box_local_proxy_selector_config(
        &SingBoxLocalProxyConfigRequest {
            nodes: vec![shadowsocks_node(), trojan_node()],
            selected_node_id: Some("trojan-us".to_string()),
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        },
        &SingBoxLocalControllerConfig::loopback_selector(),
    )
    .expect("supported nodes should render behind a selector");

    let json: serde_json::Value = serde_json::from_str(&rendered.json)
        .expect("rendered selector config should be valid json");
    assert_eq!(rendered.selected_node_id, "trojan-us");
    assert_eq!(
        rendered
            .controller
            .as_ref()
            .map(|controller| controller.endpoint()),
        Some("127.0.0.1:9091".to_string())
    );
    assert_eq!(rendered.selectable_nodes.len(), 2);
    assert_eq!(
        rendered.selectable_nodes[0].outbound_tag,
        "networkcore-node-0"
    );
    assert_eq!(
        rendered.selectable_nodes[1].outbound_tag,
        "networkcore-node-1"
    );
    assert_eq!(json["outbounds"][0]["type"], "selector");
    assert_eq!(json["outbounds"][0]["tag"], "networkcore-selector");
    assert_eq!(json["outbounds"][0]["default"], "networkcore-node-1");
    assert_eq!(json["outbounds"][0]["outbounds"][0], "networkcore-node-0");
    assert_eq!(json["outbounds"][1]["tag"], "networkcore-node-0");
    assert_eq!(json["outbounds"][2]["tag"], "networkcore-node-1");
    assert_eq!(json["route"]["final"], "networkcore-selector");
    assert_eq!(
        json["experimental"]["clash_api"]["external_controller"],
        "127.0.0.1:9091"
    );
}

#[test]
fn rejects_non_loopback_clash_controller_for_generated_selector() {
    let error = engine_singbox::render_sing_box_local_proxy_selector_config(
        &SingBoxLocalProxyConfigRequest {
            nodes: vec![shadowsocks_node()],
            selected_node_id: None,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        },
        &SingBoxLocalControllerConfig {
            host: "0.0.0.0".to_string(),
            port: 9091,
            selector_tag: "networkcore-selector".to_string(),
            interrupt_exist_connections: true,
        },
    )
    .expect_err("a generated runtime controller must remain loopback-only");

    assert_eq!(
        error.code,
        engine_singbox::ENGINE_SINGBOX_CONFIG_SELECTOR_INVALID_CODE
    );
}

#[test]
fn measures_one_generated_outbound_through_the_loopback_clash_api() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("test controller should bind");
    let port = listener
        .local_addr()
        .expect("test controller address should resolve")
        .port();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener
            .accept()
            .expect("test controller should accept the delay request");
        let mut request = [0_u8; 2_048];
        let length = stream
            .read(&mut request)
            .expect("test controller should read the delay request");
        let request = String::from_utf8_lossy(&request[..length]);
        assert!(request.starts_with("GET /proxies/networkcore-node-1/delay?"));
        assert!(request.contains("url=https%3A%2F%2Fexample.com%2Fdelay"));
        assert!(request.contains("timeout=10000"));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\nConnection: close\r\n\r\n{\"delay\":42}",
            )
            .expect("test controller should return the delay response");
    });

    let report = measure_sing_box_clash_api_outbound_delay(
        &SingBoxLocalControllerConfig {
            host: "127.0.0.1".to_string(),
            port,
            selector_tag: "networkcore-selector".to_string(),
            interrupt_exist_connections: true,
        },
        "networkcore-node-1",
        "https://example.com/delay",
        DEFAULT_SING_BOX_CLASH_API_DELAY_TIMEOUT_MILLIS,
    )
    .expect("loopback controller should return a delay result");

    assert_eq!(report.outbound_tag, "networkcore-node-1");
    assert_eq!(report.test_url, "https://example.com/delay");
    assert_eq!(report.delay_millis, 42);
    server
        .join()
        .expect("test controller assertions should succeed");
}

#[test]
fn renders_basic_trojan_vless_and_vmess_outbounds() {
    for (node, expected_type, expected_secret_key) in [
        (trojan_node(), "trojan", "password"),
        (vless_node(), "vless", "uuid"),
        (vmess_node(), "vmess", "uuid"),
    ] {
        let rendered =
            engine_singbox::render_sing_box_local_proxy_config(&SingBoxLocalProxyConfigRequest {
                nodes: vec![node],
                selected_node_id: None,
                listen_host: "127.0.0.1".to_string(),
                listen_port: 7890,
            })
            .expect("basic supported protocol should render to sing-box config");
        let json: serde_json::Value =
            serde_json::from_str(&rendered.json).expect("rendered config should be valid json");

        assert_eq!(json["outbounds"][0]["type"], expected_type);
        assert!(json["outbounds"][0][expected_secret_key].is_string());
    }

    let trojan =
        engine_singbox::render_sing_box_local_proxy_config(&SingBoxLocalProxyConfigRequest {
            nodes: vec![trojan_node()],
            selected_node_id: None,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        })
        .expect("trojan node should render");
    let trojan_json: serde_json::Value =
        serde_json::from_str(&trojan.json).expect("rendered config should be valid json");
    assert_eq!(trojan_json["outbounds"][0]["tls"]["enabled"], true);

    let vmess =
        engine_singbox::render_sing_box_local_proxy_config(&SingBoxLocalProxyConfigRequest {
            nodes: vec![vmess_node()],
            selected_node_id: None,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        })
        .expect("vmess node should render");
    let vmess_json: serde_json::Value =
        serde_json::from_str(&vmess.json).expect("rendered config should be valid json");
    assert_eq!(vmess_json["outbounds"][0]["security"], "auto");
    assert_eq!(vmess_json["outbounds"][0]["alter_id"], 0);
}

#[test]
fn renders_v2ray_tls_reality_and_transport_options() {
    let mut vless = vless_node();
    vless.metadata.extend([
        metadata_entry(NODE_METADATA_VLESS_FLOW, "xtls-rprx-vision"),
        metadata_entry(NODE_METADATA_TLS_ENABLED, "true"),
        metadata_entry(NODE_METADATA_TLS_SERVER_NAME, "cdn.vless.example.test"),
        metadata_entry(NODE_METADATA_TLS_INSECURE, "true"),
        metadata_entry(NODE_METADATA_TLS_ALPN, "h2,http/1.1"),
        metadata_entry(NODE_METADATA_TLS_UTLS_FINGERPRINT, "chrome"),
        metadata_entry(NODE_METADATA_TLS_REALITY_PUBLIC_KEY, "reality-public-key"),
        metadata_entry(NODE_METADATA_TLS_REALITY_SHORT_ID, "abcd"),
        metadata_entry(NODE_METADATA_V2RAY_TRANSPORT_TYPE, "ws"),
        metadata_entry(NODE_METADATA_V2RAY_TRANSPORT_HOST, "cdn.vless.example.test"),
        metadata_entry(NODE_METADATA_V2RAY_TRANSPORT_PATH, "/gateway"),
    ]);
    let vless =
        engine_singbox::render_sing_box_local_proxy_config(&SingBoxLocalProxyConfigRequest {
            nodes: vec![vless],
            selected_node_id: None,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        })
        .expect("VLESS Reality WebSocket node should render");
    let vless_json: serde_json::Value =
        serde_json::from_str(&vless.json).expect("rendered config should be valid json");
    let vless_outbound = &vless_json["outbounds"][0];
    assert_eq!(vless_outbound["flow"], "xtls-rprx-vision");
    assert_eq!(vless_outbound["tls"]["enabled"], true);
    assert_eq!(
        vless_outbound["tls"]["server_name"],
        "cdn.vless.example.test"
    );
    assert_eq!(vless_outbound["tls"]["insecure"], true);
    assert_eq!(vless_outbound["tls"]["alpn"][0], "h2");
    assert_eq!(vless_outbound["tls"]["utls"]["fingerprint"], "chrome");
    assert_eq!(
        vless_outbound["tls"]["reality"]["public_key"],
        "reality-public-key"
    );
    assert_eq!(vless_outbound["tls"]["reality"]["short_id"], "abcd");
    assert_eq!(vless_outbound["transport"]["type"], "ws");
    assert_eq!(
        vless_outbound["transport"]["headers"]["Host"][0],
        "cdn.vless.example.test"
    );
    assert_eq!(vless_outbound["transport"]["path"], "/gateway");

    let mut vmess = vmess_node();
    vmess.metadata.extend([
        metadata_entry(NODE_METADATA_VMESS_SECURITY, "chacha20-poly1305"),
        metadata_entry(NODE_METADATA_VMESS_ALTER_ID, "0"),
        metadata_entry(NODE_METADATA_TLS_ENABLED, "true"),
        metadata_entry(NODE_METADATA_TLS_SERVER_NAME, "cdn.vmess.example.test"),
        metadata_entry(NODE_METADATA_V2RAY_TRANSPORT_TYPE, "grpc"),
        metadata_entry(NODE_METADATA_V2RAY_TRANSPORT_SERVICE_NAME, "TunService"),
    ]);
    let vmess =
        engine_singbox::render_sing_box_local_proxy_config(&SingBoxLocalProxyConfigRequest {
            nodes: vec![vmess],
            selected_node_id: None,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        })
        .expect("VMess gRPC node should render");
    let vmess_json: serde_json::Value =
        serde_json::from_str(&vmess.json).expect("rendered config should be valid json");
    let vmess_outbound = &vmess_json["outbounds"][0];
    assert_eq!(vmess_outbound["security"], "chacha20-poly1305");
    assert_eq!(vmess_outbound["alter_id"], 0);
    assert_eq!(
        vmess_outbound["tls"]["server_name"],
        "cdn.vmess.example.test"
    );
    assert_eq!(vmess_outbound["transport"]["type"], "grpc");
    assert_eq!(vmess_outbound["transport"]["service_name"], "TunService");

    let mut trojan = trojan_node();
    trojan.metadata.extend([
        metadata_entry(NODE_METADATA_TLS_ENABLED, "true"),
        metadata_entry(NODE_METADATA_V2RAY_TRANSPORT_TYPE, "httpupgrade"),
        metadata_entry(
            NODE_METADATA_V2RAY_TRANSPORT_HOST,
            "cdn.trojan.example.test",
        ),
        metadata_entry(NODE_METADATA_V2RAY_TRANSPORT_PATH, "/upgrade"),
    ]);
    let trojan =
        engine_singbox::render_sing_box_local_proxy_config(&SingBoxLocalProxyConfigRequest {
            nodes: vec![trojan],
            selected_node_id: None,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        })
        .expect("Trojan HTTPUpgrade node should render");
    let trojan_json: serde_json::Value =
        serde_json::from_str(&trojan.json).expect("rendered config should be valid json");
    let trojan_outbound = &trojan_json["outbounds"][0];
    assert_eq!(trojan_outbound["transport"]["type"], "httpupgrade");
    assert_eq!(
        trojan_outbound["transport"]["host"],
        "cdn.trojan.example.test"
    );
    assert_eq!(trojan_outbound["transport"]["path"], "/upgrade");
}

#[test]
fn renders_v2ray_http_and_quic_transport_options() {
    let mut vless = vless_node();
    vless.metadata.extend([
        metadata_entry(NODE_METADATA_TLS_ENABLED, "true"),
        metadata_entry(NODE_METADATA_V2RAY_TRANSPORT_TYPE, "http"),
        metadata_entry(
            NODE_METADATA_V2RAY_TRANSPORT_HOST,
            "cdn-a.example.test,cdn-b.example.test",
        ),
        metadata_entry(NODE_METADATA_V2RAY_TRANSPORT_PATH, "/h2"),
    ]);
    let vless =
        engine_singbox::render_sing_box_local_proxy_config(&SingBoxLocalProxyConfigRequest {
            nodes: vec![vless],
            selected_node_id: None,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        })
        .expect("VLESS HTTP node should render");
    let vless_json: serde_json::Value =
        serde_json::from_str(&vless.json).expect("rendered config should be valid json");
    let vless_transport = &vless_json["outbounds"][0]["transport"];
    assert_eq!(vless_transport["type"], "http");
    assert_eq!(vless_transport["host"][0], "cdn-a.example.test");
    assert_eq!(vless_transport["host"][1], "cdn-b.example.test");
    assert_eq!(vless_transport["path"], "/h2");

    let mut vmess = vmess_node();
    vmess
        .metadata
        .push(metadata_entry(NODE_METADATA_V2RAY_TRANSPORT_TYPE, "quic"));
    let vmess =
        engine_singbox::render_sing_box_local_proxy_config(&SingBoxLocalProxyConfigRequest {
            nodes: vec![vmess],
            selected_node_id: None,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        })
        .expect("VMess QUIC node should render");
    let vmess_json: serde_json::Value =
        serde_json::from_str(&vmess.json).expect("rendered config should be valid json");
    assert_eq!(
        vmess_json["outbounds"][0]["transport"],
        serde_json::json!({ "type": "quic" })
    );
}

#[test]
fn renders_hysteria2_and_tuic_outbounds_with_quic_tls_options() {
    let hysteria2 =
        engine_singbox::render_sing_box_local_proxy_config(&SingBoxLocalProxyConfigRequest {
            nodes: vec![hysteria2_node()],
            selected_node_id: None,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        })
        .expect("hysteria2 node should render to a sing-box config");
    let hysteria2_json: serde_json::Value =
        serde_json::from_str(&hysteria2.json).expect("rendered config should be valid json");
    let hysteria2_outbound = &hysteria2_json["outbounds"][0];
    assert_eq!(hysteria2_outbound["type"], "hysteria2");
    assert_eq!(hysteria2_outbound["server"], "hy2.example.test");
    assert!(hysteria2_outbound["server_port"].is_null());
    assert_eq!(hysteria2_outbound["server_ports"][0], "3000:3002");
    assert_eq!(hysteria2_outbound["password"], "hy2-password");
    assert_eq!(hysteria2_outbound["obfs"]["type"], "gecko");
    assert_eq!(hysteria2_outbound["obfs"]["password"], "mask");
    assert_eq!(hysteria2_outbound["obfs"]["min_packet_size"], 512);
    assert_eq!(hysteria2_outbound["obfs"]["max_packet_size"], 1200);
    assert_eq!(hysteria2_outbound["tls"]["enabled"], true);
    assert_eq!(
        hysteria2_outbound["tls"]["server_name"],
        "cdn.hy2.example.test"
    );
    assert_eq!(hysteria2_outbound["tls"]["insecure"], true);
    assert_eq!(hysteria2_outbound["tls"]["alpn"][0], "h3");
    assert_eq!(hysteria2_outbound["tls"]["alpn"][1], "h2");
    assert_eq!(
        hysteria2_outbound["tls"]["certificate_public_key_sha256"][0],
        "pin-A"
    );

    let tuic =
        engine_singbox::render_sing_box_local_proxy_config(&SingBoxLocalProxyConfigRequest {
            nodes: vec![tuic_node()],
            selected_node_id: None,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        })
        .expect("tuic node should render to a sing-box config");
    let tuic_json: serde_json::Value =
        serde_json::from_str(&tuic.json).expect("rendered config should be valid json");
    let tuic_outbound = &tuic_json["outbounds"][0];
    assert_eq!(tuic_outbound["type"], "tuic");
    assert_eq!(
        tuic_outbound["uuid"],
        "00000000-0000-0000-0000-000000000001"
    );
    assert_eq!(tuic_outbound["password"], "tuic-password");
    assert_eq!(tuic_outbound["congestion_control"], "bbr");
    assert_eq!(tuic_outbound["tls"]["server_name"], "cdn.tuic.example.test");
    assert_eq!(tuic_outbound["tls"]["alpn"][0], "h3");
    assert_eq!(tuic_json["route"]["final"], "tuic-us");
}

#[test]
fn blank_node_selection_skips_unsupported_protocols() {
    let unsupported = node_with_metadata(
        "hysteria-us",
        Protocol::Hysteria,
        "hysteria.password",
        "not-rendered",
    );
    let rendered =
        engine_singbox::render_sing_box_local_proxy_config(&SingBoxLocalProxyConfigRequest {
            nodes: vec![unsupported, trojan_node()],
            selected_node_id: None,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        })
        .expect("blank selection should choose the first supported node");

    assert_eq!(rendered.selected_node_id, "trojan-us");
}

struct MemorySingBoxHttpClient {
    release_json: String,
    asset_bytes: Vec<u8>,
}

fn shadowsocks_node() -> NodeDescriptor {
    NodeDescriptor {
        id: "ss-hk".to_string(),
        name: "香港".to_string(),
        protocol: Protocol::Shadowsocks,
        endpoint: Endpoint {
            host: "82.47.34.99".to_string(),
            port: 11111,
        },
        tags: vec!["subscription".to_string()],
        metadata: vec![
            MetadataEntry {
                key: NODE_METADATA_SHADOWSOCKS_METHOD.to_string(),
                value: "aes-256-gcm".to_string(),
            },
            MetadataEntry {
                key: NODE_METADATA_SHADOWSOCKS_PASSWORD.to_string(),
                value: "f43c0eee-13b9-4f07-bec9-d4b744141503".to_string(),
            },
        ],
    }
}

fn trojan_node() -> NodeDescriptor {
    node_with_metadata(
        "trojan-us",
        Protocol::Trojan,
        NODE_METADATA_TROJAN_PASSWORD,
        "trojan-password",
    )
}

fn vless_node() -> NodeDescriptor {
    node_with_metadata(
        "vless-us",
        Protocol::Vless,
        NODE_METADATA_VLESS_UUID,
        "58ea5aee-98d8-4f2d-a56c-e691ddc96931",
    )
}

fn vmess_node() -> NodeDescriptor {
    node_with_metadata(
        "vmess-us",
        Protocol::Vmess,
        NODE_METADATA_VMESS_UUID,
        "253db8e4-23c9-46bd-81f3-e5a1212177d8",
    )
}

fn hysteria2_node() -> NodeDescriptor {
    NodeDescriptor {
        id: "hysteria2-us".to_string(),
        name: "Hysteria2 US".to_string(),
        protocol: Protocol::Hysteria2,
        endpoint: Endpoint {
            host: "hy2.example.test".to_string(),
            port: 3000,
        },
        tags: vec!["subscription".to_string(), "hysteria2".to_string()],
        metadata: vec![
            MetadataEntry {
                key: NODE_METADATA_HYSTERIA2_PASSWORD.to_string(),
                value: "hy2-password".to_string(),
            },
            MetadataEntry {
                key: NODE_METADATA_HYSTERIA2_SERVER_PORTS.to_string(),
                value: "3000:3002".to_string(),
            },
            MetadataEntry {
                key: NODE_METADATA_HYSTERIA2_OBFS_TYPE.to_string(),
                value: "gecko".to_string(),
            },
            MetadataEntry {
                key: NODE_METADATA_HYSTERIA2_OBFS_PASSWORD.to_string(),
                value: "mask".to_string(),
            },
            MetadataEntry {
                key: NODE_METADATA_HYSTERIA2_OBFS_MIN_PACKET_SIZE.to_string(),
                value: "512".to_string(),
            },
            MetadataEntry {
                key: NODE_METADATA_HYSTERIA2_OBFS_MAX_PACKET_SIZE.to_string(),
                value: "1200".to_string(),
            },
            MetadataEntry {
                key: NODE_METADATA_TLS_SERVER_NAME.to_string(),
                value: "cdn.hy2.example.test".to_string(),
            },
            MetadataEntry {
                key: NODE_METADATA_TLS_INSECURE.to_string(),
                value: "true".to_string(),
            },
            MetadataEntry {
                key: NODE_METADATA_TLS_ALPN.to_string(),
                value: "h3,h2".to_string(),
            },
            MetadataEntry {
                key: NODE_METADATA_TLS_CERTIFICATE_PUBLIC_KEY_SHA256.to_string(),
                value: "pin-A".to_string(),
            },
        ],
    }
}

fn tuic_node() -> NodeDescriptor {
    NodeDescriptor {
        id: "tuic-us".to_string(),
        name: "TUIC US".to_string(),
        protocol: Protocol::Tuic,
        endpoint: Endpoint {
            host: "tuic.example.test".to_string(),
            port: 443,
        },
        tags: vec!["subscription".to_string(), "tuic".to_string()],
        metadata: vec![
            MetadataEntry {
                key: NODE_METADATA_TUIC_UUID.to_string(),
                value: "00000000-0000-0000-0000-000000000001".to_string(),
            },
            MetadataEntry {
                key: NODE_METADATA_TUIC_PASSWORD.to_string(),
                value: "tuic-password".to_string(),
            },
            MetadataEntry {
                key: NODE_METADATA_TUIC_CONGESTION_CONTROL.to_string(),
                value: "bbr".to_string(),
            },
            MetadataEntry {
                key: NODE_METADATA_TLS_SERVER_NAME.to_string(),
                value: "cdn.tuic.example.test".to_string(),
            },
            MetadataEntry {
                key: NODE_METADATA_TLS_ALPN.to_string(),
                value: "h3".to_string(),
            },
        ],
    }
}

fn node_with_metadata(
    id: &str,
    protocol: Protocol,
    metadata_key: &str,
    metadata_value: &str,
) -> NodeDescriptor {
    NodeDescriptor {
        id: id.to_string(),
        name: id.to_string(),
        protocol,
        endpoint: Endpoint {
            host: "example.test".to_string(),
            port: 443,
        },
        tags: vec!["subscription".to_string()],
        metadata: vec![MetadataEntry {
            key: metadata_key.to_string(),
            value: metadata_value.to_string(),
        }],
    }
}

fn metadata_entry(key: &str, value: &str) -> MetadataEntry {
    MetadataEntry {
        key: key.to_string(),
        value: value.to_string(),
    }
}

impl SingBoxHttpClient for MemorySingBoxHttpClient {
    fn get_text(&self, _url: &str) -> control_domain::DomainResult<String> {
        Ok(self.release_json.clone())
    }

    fn get_bytes(&self, _url: &str) -> control_domain::DomainResult<Vec<u8>> {
        Ok(self.asset_bytes.clone())
    }
}

fn sing_box_tarball() -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = Builder::new(encoder);
    let mut header = Header::new_gnu();
    let content = b"fake-sing-box";
    header.set_size(content.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    builder
        .append_data(
            &mut header,
            "sing-box-1.2.3-linux-amd64/sing-box",
            &content[..],
        )
        .expect("tarball fixture should append executable");
    let encoder = builder
        .into_inner()
        .expect("tarball fixture should finish tar stream");
    encoder
        .finish()
        .expect("tarball fixture should finish gzip stream")
}

fn sing_box_zip() -> Vec<u8> {
    let content = b"fake-windows-sing-box";
    let name = b"sing-box-1.2.3-windows-amd64/sing-box.exe";
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(content)
        .expect("ZIP fixture should compress executable");
    let compressed = encoder.finish().expect("ZIP fixture should finish deflate");
    let mut zip = Vec::new();
    push_u32(&mut zip, 0x0403_4b50);
    push_u16(&mut zip, 20);
    push_u16(&mut zip, 0);
    push_u16(&mut zip, 8);
    push_u16(&mut zip, 0);
    push_u16(&mut zip, 0);
    push_u32(&mut zip, 0);
    push_u32(&mut zip, compressed.len() as u32);
    push_u32(&mut zip, content.len() as u32);
    push_u16(&mut zip, name.len() as u16);
    push_u16(&mut zip, 0);
    zip.extend_from_slice(name);
    zip.extend_from_slice(&compressed);

    let central_offset = zip.len() as u32;
    push_u32(&mut zip, 0x0201_4b50);
    push_u16(&mut zip, 20);
    push_u16(&mut zip, 20);
    push_u16(&mut zip, 0);
    push_u16(&mut zip, 8);
    push_u16(&mut zip, 0);
    push_u16(&mut zip, 0);
    push_u32(&mut zip, 0);
    push_u32(&mut zip, compressed.len() as u32);
    push_u32(&mut zip, content.len() as u32);
    push_u16(&mut zip, name.len() as u16);
    push_u16(&mut zip, 0);
    push_u16(&mut zip, 0);
    push_u16(&mut zip, 0);
    push_u16(&mut zip, 0);
    push_u32(&mut zip, 0);
    push_u32(&mut zip, 0);
    zip.extend_from_slice(name);

    let central_size = zip.len() as u32 - central_offset;
    push_u32(&mut zip, 0x0605_4b50);
    push_u16(&mut zip, 0);
    push_u16(&mut zip, 0);
    push_u16(&mut zip, 1);
    push_u16(&mut zip, 1);
    push_u32(&mut zip, central_size);
    push_u32(&mut zip, central_offset);
    push_u16(&mut zip, 0);
    zip
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn unique_temp_root() -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "networkcore-engine-singbox-test-{}-{unique}",
        std::process::id()
    ))
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(bytes);
    let alphabet = b"0123456789abcdef";
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(alphabet[(byte >> 4) as usize] as char);
        output.push(alphabet[(byte & 0x0f) as usize] as char);
    }
    output
}

fn assert_diagnostic(diagnostics: &[control_domain::Diagnostic], code: &str) {
    assert!(
        diagnostics.iter().any(|diagnostic| diagnostic.code == code),
        "missing diagnostic {code}: {diagnostics:?}"
    );
}
