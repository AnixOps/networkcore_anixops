use control_domain::{
    Endpoint, MetadataEntry, NodeDescriptor, Protocol, ProxyEngineKind, ProxyEngineService,
    NODE_METADATA_SHADOWSOCKS_METHOD, NODE_METADATA_SHADOWSOCKS_PASSWORD,
    NODE_METADATA_TROJAN_PASSWORD, NODE_METADATA_VLESS_UUID, NODE_METADATA_VMESS_UUID,
};
use engine_singbox::{
    GithubSingBoxReleaseInstaller, SingBoxHttpClient, SingBoxInstallRequest,
    SingBoxLocalProxyConfigRequest, SingBoxManagedProcessState, SingBoxManagedProcessSupervisor,
    SingBoxReleaseInstaller, SingBoxTarget, SingBoxTargetArch, SingBoxTargetOs,
    DEFAULT_SING_BOX_ENGINE_ID, ENGINE_SINGBOX_CONFIG_RENDERED_CODE,
    ENGINE_SINGBOX_DOWNLOAD_ASSET_SELECTED_CODE, ENGINE_SINGBOX_DOWNLOAD_BINARY_READY_CODE,
    ENGINE_SINGBOX_DOWNLOAD_CHECKSUM_VERIFIED_CODE,
    ENGINE_SINGBOX_DOWNLOAD_LATEST_VERSION_RESOLVED_CODE,
};
use flate2::{write::DeflateEncoder, write::GzEncoder, Compression};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
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
    assert_diagnostic(&rendered.diagnostics, ENGINE_SINGBOX_CONFIG_RENDERED_CODE);
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
