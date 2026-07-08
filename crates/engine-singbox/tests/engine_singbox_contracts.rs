use control_domain::{
    Endpoint, MetadataEntry, NodeDescriptor, Protocol, ProxyEngineKind, ProxyEngineService,
    NODE_METADATA_SHADOWSOCKS_METHOD, NODE_METADATA_SHADOWSOCKS_PASSWORD,
};
use engine_singbox::{
    GithubSingBoxReleaseInstaller, SingBoxHttpClient, SingBoxInstallRequest,
    SingBoxLocalProxyConfigRequest, SingBoxReleaseInstaller, SingBoxTarget, SingBoxTargetArch,
    SingBoxTargetOs, DEFAULT_SING_BOX_ENGINE_ID, ENGINE_SINGBOX_CONFIG_RENDERED_CODE,
    ENGINE_SINGBOX_DOWNLOAD_ASSET_SELECTED_CODE,
    ENGINE_SINGBOX_DOWNLOAD_BINARY_READY_CODE, ENGINE_SINGBOX_DOWNLOAD_CHECKSUM_VERIFIED_CODE,
    ENGINE_SINGBOX_DOWNLOAD_LATEST_VERSION_RESOLVED_CODE,
};
use flate2::{write::GzEncoder, Compression};
use std::fs;
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
fn renders_local_mixed_inbound_config_from_shadowsocks_node_catalog() {
    let rendered = engine_singbox::render_sing_box_local_proxy_config(
        &SingBoxLocalProxyConfigRequest {
            nodes: vec![shadowsocks_node()],
            selected_node_id: None,
            listen_host: "127.0.0.1".to_string(),
            listen_port: 7890,
        },
    )
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
