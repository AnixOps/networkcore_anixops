//! sing-box public proxy engine adapter contracts for NetworkCore.
//!
//! This crate owns public engine release metadata parsing, target asset
//! selection, download provenance, checksum verification, and extraction into a
//! runtime cache. It does not bundle third-party binaries into NetworkCore
//! release artifacts.

use control_domain::{
    Diagnostic, DiagnosticSeverity, DomainError, DomainResult, NodeDescriptor, Protocol,
    ProxyEngineCapability, ProxyEngineConfig, ProxyEngineDescriptor, ProxyEngineEvent,
    ProxyEngineKind, ProxyEngineLifecycleState, ProxyEngineService, ProxyEngineStatus,
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
use flate2::read::{DeflateDecoder, GzDecoder};
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use tar::Archive;

pub const DEFAULT_SING_BOX_ENGINE_ID: &str = "sing-box";
pub const SING_BOX_REPOSITORY: &str = "SagerNet/sing-box";
pub const SING_BOX_LATEST_RELEASE_API_URL: &str =
    "https://api.github.com/repos/SagerNet/sing-box/releases/latest";
pub const NETWORKCORE_SING_BOX_USER_AGENT: &str = "networkcore-anixops-singbox-installer";

pub const SOURCE_ENGINE_SINGBOX_CONFIG: &str = "engine.singbox.config";
pub const SOURCE_ENGINE_SINGBOX_DOWNLOAD: &str = "engine.singbox.download";
pub const SOURCE_ENGINE_SINGBOX_LIFECYCLE: &str = "engine.singbox.lifecycle";

pub const ENGINE_SINGBOX_CONFIG_ENGINE_ID_UNSUPPORTED_CODE: &str =
    "engine.singbox.config.engine_id_unsupported";
pub const ENGINE_SINGBOX_CONFIG_TRANSLATION_READY_CODE: &str =
    "engine.singbox.config.translation_ready";
pub const ENGINE_SINGBOX_CONFIG_NODE_MISSING_CODE: &str = "engine.singbox.config.node_missing";
pub const ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE: &str =
    "engine.singbox.config.node_unsupported";
pub const ENGINE_SINGBOX_CONFIG_SECRET_MISSING_CODE: &str = "engine.singbox.config.secret_missing";
pub const ENGINE_SINGBOX_CONFIG_RENDERED_CODE: &str = "engine.singbox.config.rendered";
pub const ENGINE_SINGBOX_CONFIG_NATIVE_INVALID_CODE: &str = "engine.singbox.config.native_invalid";
pub const ENGINE_SINGBOX_CONFIG_MIXED_INBOUND_MISSING_CODE: &str =
    "engine.singbox.config.mixed_inbound_missing";
pub const ENGINE_SINGBOX_CONFIG_SELECTOR_INVALID_CODE: &str =
    "engine.singbox.config.selector_invalid";
pub const ENGINE_SINGBOX_CLASH_API_REQUEST_FAILED_CODE: &str =
    "engine.singbox.clash_api.request_failed";
pub const ENGINE_SINGBOX_CLASH_API_SELECTOR_MISMATCH_CODE: &str =
    "engine.singbox.clash_api.selector_mismatch";
pub const ENGINE_SINGBOX_CLASH_API_DELAY_INVALID_CODE: &str =
    "engine.singbox.clash_api.delay_invalid";
pub const ENGINE_SINGBOX_DOWNLOAD_TARGET_UNSUPPORTED_CODE: &str =
    "engine.singbox.download.target_unsupported";
pub const ENGINE_SINGBOX_DOWNLOAD_RELEASE_FETCH_FAILED_CODE: &str =
    "engine.singbox.download.release_fetch_failed";
pub const ENGINE_SINGBOX_DOWNLOAD_RELEASE_PARSE_FAILED_CODE: &str =
    "engine.singbox.download.release_parse_failed";
pub const ENGINE_SINGBOX_DOWNLOAD_LATEST_VERSION_RESOLVED_CODE: &str =
    "engine.singbox.download.latest_version_resolved";
pub const ENGINE_SINGBOX_DOWNLOAD_ASSET_SELECTED_CODE: &str =
    "engine.singbox.download.asset_selected";
pub const ENGINE_SINGBOX_DOWNLOAD_ASSET_MISSING_CODE: &str =
    "engine.singbox.download.asset_missing";
pub const ENGINE_SINGBOX_DOWNLOAD_ASSET_FETCH_FAILED_CODE: &str =
    "engine.singbox.download.asset_fetch_failed";
pub const ENGINE_SINGBOX_DOWNLOAD_ARCHIVE_UNSUPPORTED_CODE: &str =
    "engine.singbox.download.archive_unsupported";
pub const ENGINE_SINGBOX_DOWNLOAD_ARCHIVE_WRITTEN_CODE: &str =
    "engine.singbox.download.archive_written";
pub const ENGINE_SINGBOX_DOWNLOAD_CHECKSUM_VERIFIED_CODE: &str =
    "engine.singbox.download.checksum_verified";
pub const ENGINE_SINGBOX_DOWNLOAD_CHECKSUM_MISMATCH_CODE: &str =
    "engine.singbox.download.checksum_mismatch";
pub const ENGINE_SINGBOX_DOWNLOAD_EXTRACT_FAILED_CODE: &str =
    "engine.singbox.download.extract_failed";
pub const ENGINE_SINGBOX_DOWNLOAD_BINARY_READY_CODE: &str = "engine.singbox.download.binary_ready";
pub const ENGINE_SINGBOX_DOWNLOAD_BINARY_ALREADY_PRESENT_CODE: &str =
    "engine.singbox.download.binary_already_present";
pub const ENGINE_SINGBOX_DOWNLOAD_BINARY_PERMISSION_FAILED_CODE: &str =
    "engine.singbox.download.binary_permission_failed";
pub const ENGINE_SINGBOX_RUNTIME_UNWIRED_CODE: &str = "engine.singbox.runtime.unwired";
pub const ENGINE_SINGBOX_PROCESS_START_FAILED_CODE: &str = "engine.singbox.process.start_failed";
pub const ENGINE_SINGBOX_PROCESS_STARTED_CODE: &str = "engine.singbox.process.started";
pub const ENGINE_SINGBOX_PROCESS_EXITED_CODE: &str = "engine.singbox.process.exited";
pub const ENGINE_SINGBOX_CONFIG_CHECK_FAILED_CODE: &str = "engine.singbox.config.check_failed";
pub const ENGINE_SINGBOX_RUNTIME_ALREADY_RUNNING_CODE: &str =
    "engine.singbox.runtime.already_running";

#[derive(Debug, Clone, Copy, Default)]
pub struct SingBoxProxyEngineService;

impl SingBoxProxyEngineService {
    pub const fn new() -> Self {
        Self
    }
}

impl ProxyEngineService for SingBoxProxyEngineService {
    fn list_engines(&self) -> Vec<ProxyEngineDescriptor> {
        vec![ProxyEngineDescriptor {
            id: DEFAULT_SING_BOX_ENGINE_ID.to_string(),
            kind: ProxyEngineKind::SingBox,
            version: Some("latest-managed-by-adapter".to_string()),
            capabilities: vec![
                ProxyEngineCapability::TcpProxy,
                ProxyEngineCapability::UdpProxy,
            ],
        }]
    }

    fn validate_config(&self, engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        if engine_config.engine_id != DEFAULT_SING_BOX_ENGINE_ID {
            diagnostics.push(sing_box_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_SINGBOX_CONFIG_ENGINE_ID_UNSUPPORTED_CODE,
                "sing-box adapter only supports the sing-box engine id",
                SOURCE_ENGINE_SINGBOX_CONFIG,
            ));
        }

        diagnostics.push(sing_box_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_SINGBOX_CONFIG_TRANSLATION_READY_CODE,
            "sing-box local proxy config translation is available for supported node catalogs",
            SOURCE_ENGINE_SINGBOX_CONFIG,
        ));

        diagnostics
    }

    fn start(&self, _engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        Err(unwired_runtime_error())
    }

    fn reload(&self, _engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        Err(unwired_runtime_error())
    }

    fn stop(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        Ok(ProxyEngineStatus {
            engine_id: engine_id.to_string(),
            state: ProxyEngineLifecycleState::Stopped,
            diagnostics: vec![sing_box_diagnostic(
                DiagnosticSeverity::Warning,
                ENGINE_SINGBOX_RUNTIME_UNWIRED_CODE,
                "sing-box lifecycle is not wired to a managed process yet",
                SOURCE_ENGINE_SINGBOX_LIFECYCLE,
            )],
        })
    }

    fn status(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        Ok(ProxyEngineStatus {
            engine_id: engine_id.to_string(),
            state: ProxyEngineLifecycleState::Stopped,
            diagnostics: vec![sing_box_diagnostic(
                DiagnosticSeverity::Warning,
                ENGINE_SINGBOX_RUNTIME_UNWIRED_CODE,
                "sing-box lifecycle is not wired to a managed process yet",
                SOURCE_ENGINE_SINGBOX_LIFECYCLE,
            )],
        })
    }

    fn events(&self, _engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingBoxTargetOs {
    Linux,
    Macos,
    Windows,
}

impl SingBoxTargetOs {
    pub const fn asset_name(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "darwin",
            Self::Windows => "windows",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingBoxTargetArch {
    Amd64,
    Arm64,
    X86,
    Armv7,
}

impl SingBoxTargetArch {
    pub const fn asset_name(self) -> &'static str {
        match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
            Self::X86 => "386",
            Self::Armv7 => "armv7",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingBoxArchiveKind {
    TarGz,
    Zip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SingBoxTarget {
    pub os: SingBoxTargetOs,
    pub arch: SingBoxTargetArch,
}

impl SingBoxTarget {
    pub const fn new(os: SingBoxTargetOs, arch: SingBoxTargetArch) -> Self {
        Self { os, arch }
    }

    pub fn current() -> DomainResult<Self> {
        let os = match std::env::consts::OS {
            "linux" => SingBoxTargetOs::Linux,
            "macos" => SingBoxTargetOs::Macos,
            "windows" => SingBoxTargetOs::Windows,
            other => {
                return Err(DomainError::new(
                    ENGINE_SINGBOX_DOWNLOAD_TARGET_UNSUPPORTED_CODE,
                    format!("unsupported sing-box host os: {other}"),
                ));
            }
        };

        let arch = match std::env::consts::ARCH {
            "x86_64" => SingBoxTargetArch::Amd64,
            "aarch64" => SingBoxTargetArch::Arm64,
            "x86" | "i686" => SingBoxTargetArch::X86,
            "arm" => SingBoxTargetArch::Armv7,
            other => {
                return Err(DomainError::new(
                    ENGINE_SINGBOX_DOWNLOAD_TARGET_UNSUPPORTED_CODE,
                    format!("unsupported sing-box host arch: {other}"),
                ));
            }
        };

        Ok(Self { os, arch })
    }

    pub fn directory_name(self) -> String {
        format!("{}-{}", self.os.asset_name(), self.arch.asset_name())
    }

    pub const fn executable_name(self) -> &'static str {
        match self.os {
            SingBoxTargetOs::Windows => "sing-box.exe",
            SingBoxTargetOs::Linux | SingBoxTargetOs::Macos => "sing-box",
        }
    }

    pub const fn archive_kind(self) -> SingBoxArchiveKind {
        match self.os {
            SingBoxTargetOs::Windows => SingBoxArchiveKind::Zip,
            SingBoxTargetOs::Linux | SingBoxTargetOs::Macos => SingBoxArchiveKind::TarGz,
        }
    }

    pub fn preferred_asset_names(self, version: &str) -> Vec<String> {
        let platform = self.os.asset_name();
        let arch = self.arch.asset_name();
        let base = format!("sing-box-{version}-{platform}-{arch}");

        match self.os {
            SingBoxTargetOs::Linux => vec![
                format!("{base}.tar.gz"),
                format!("{base}-glibc.tar.gz"),
                format!("{base}-musl.tar.gz"),
            ],
            SingBoxTargetOs::Macos => vec![format!("{base}.tar.gz")],
            SingBoxTargetOs::Windows => vec![format!("{base}.zip")],
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SingBoxRelease {
    pub tag_name: String,
    pub assets: Vec<SingBoxReleaseAsset>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SingBoxReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
    pub digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxAssetPlan {
    pub version: String,
    pub target: SingBoxTarget,
    pub asset_name: String,
    pub download_url: String,
    pub archive_kind: SingBoxArchiveKind,
    pub sha256_digest: Option<String>,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxInstallRequest {
    pub install_root: PathBuf,
    pub target: SingBoxTarget,
    pub force: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxInstallReport {
    pub version: String,
    pub target: SingBoxTarget,
    pub asset_name: String,
    pub asset_url: String,
    pub asset_sha256: Option<String>,
    pub archive_path: PathBuf,
    pub executable_path: PathBuf,
    pub downloaded: bool,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxLocalProxyConfigRequest {
    pub nodes: Vec<NodeDescriptor>,
    pub selected_node_id: Option<String>,
    pub listen_host: String,
    pub listen_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxLocalProxyConfig {
    pub json: String,
    pub selected_node_id: String,
    pub selected_node_name: String,
    pub listen_host: String,
    pub listen_port: u16,
    pub selectable_nodes: Vec<SingBoxLocalProxySelectableNode>,
    pub controller: Option<SingBoxLocalControllerConfig>,
    pub diagnostics: Vec<Diagnostic>,
}

pub const DEFAULT_SING_BOX_LOCAL_CONTROLLER_HOST: &str = "127.0.0.1";
pub const DEFAULT_SING_BOX_LOCAL_CONTROLLER_PORT: u16 = 9091;
pub const DEFAULT_SING_BOX_LOCAL_SELECTOR_TAG: &str = "networkcore-selector";
pub const DEFAULT_SING_BOX_CLASH_API_DELAY_TEST_URL: &str = "https://www.gstatic.com/generate_204";
pub const DEFAULT_SING_BOX_CLASH_API_DELAY_TIMEOUT_MILLIS: u16 = 10_000;

/// A local-only sing-box Clash API controller used for explicit runtime
/// selector changes by a desktop client. It never exposes the controller on a
/// non-loopback address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxLocalControllerConfig {
    pub host: String,
    pub port: u16,
    pub selector_tag: String,
    pub interrupt_exist_connections: bool,
}

impl SingBoxLocalControllerConfig {
    pub fn loopback_selector() -> Self {
        Self {
            host: DEFAULT_SING_BOX_LOCAL_CONTROLLER_HOST.to_string(),
            port: DEFAULT_SING_BOX_LOCAL_CONTROLLER_PORT,
            selector_tag: DEFAULT_SING_BOX_LOCAL_SELECTOR_TAG.to_string(),
            interrupt_exist_connections: true,
        }
    }

    pub fn endpoint(&self) -> String {
        let host = self.host.trim();
        if host == "::1" {
            format!("[{host}]:{}", self.port)
        } else {
            format!("{host}:{}", self.port)
        }
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.endpoint())
    }
}

pub fn sing_box_local_selector_outbound_tag(index: usize) -> String {
    format!("networkcore-node-{index}")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxLocalProxySelectableNode {
    pub id: String,
    pub name: String,
    pub outbound_tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxClashApiSelectorStatus {
    pub selector_tag: String,
    pub current_outbound_tag: String,
    pub outbound_tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxClashApiDelayResult {
    pub outbound_tag: String,
    pub test_url: String,
    pub delay_millis: u64,
}

/// An operator-provided sing-box document that can be used without reducing it
/// to NetworkCore's basic node catalog. The original JSON is retained so
/// transport, DNS, routing, and experimental fields remain owned by sing-box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxNativeConfigImport {
    pub json: String,
    pub local_http_proxy: Option<SingBoxLocalHttpProxy>,
}

/// A local HTTP-compatible inbound that the Windows system-proxy integration
/// can point to after a native sing-box configuration is imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxLocalHttpProxy {
    pub server: String,
    pub port: u16,
}

impl SingBoxLocalHttpProxy {
    pub fn endpoint(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }
}

/// Recognize a native sing-box document while preserving its original content.
///
/// A node URL or a VMess share link JSON object is intentionally not treated as
/// a native config. Those inputs continue through the basic catalog renderer.
pub fn inspect_sing_box_native_config(content: &str) -> Option<SingBoxNativeConfigImport> {
    let json = content.trim();
    let value: Value = serde_json::from_str(json).ok()?;
    let object = value.as_object()?;
    if !object.contains_key("inbounds") && !object.contains_key("outbounds") {
        return None;
    }

    Some(SingBoxNativeConfigImport {
        json: json.to_string(),
        local_http_proxy: find_local_http_proxy(&value),
    })
}

/// Render a native sing-box document with its GUI-controlled `mixed-in`
/// inbound redirected to a local listener.
///
/// This only changes the listener fields on an inbound explicitly marked with
/// both `tag: mixed-in` and `type: mixed`. Callers that need the original
/// document must retain it separately before committing the returned JSON.
pub fn rewrite_sing_box_mixed_inbound_listener(
    content: &str,
    listen_host: &str,
    listen_port: u16,
) -> DomainResult<String> {
    if listen_host.trim().is_empty() || listen_port == 0 {
        return Err(DomainError::new(
            ENGINE_SINGBOX_CONFIG_NATIVE_INVALID_CODE,
            "sing-box mixed inbound listener endpoint must be explicit",
        ));
    }

    let mut config: Value = serde_json::from_str(content).map_err(|error| {
        DomainError::new(
            ENGINE_SINGBOX_CONFIG_NATIVE_INVALID_CODE,
            format!("native sing-box config is not valid JSON: {error}"),
        )
    })?;
    let inbound = config
        .get_mut("inbounds")
        .and_then(Value::as_array_mut)
        .and_then(|inbounds| {
            inbounds.iter_mut().find(|inbound| {
                inbound.get("tag").and_then(Value::as_str) == Some("mixed-in")
                    && inbound.get("type").and_then(Value::as_str) == Some("mixed")
            })
        })
        .ok_or_else(|| {
            DomainError::new(
                ENGINE_SINGBOX_CONFIG_MIXED_INBOUND_MISSING_CODE,
                "native sing-box config needs a type=mixed inbound tagged mixed-in for GUI HTTPS MITM",
            )
        })?;
    inbound["listen"] = Value::String(listen_host.to_string());
    inbound["listen_port"] = Value::from(listen_port);

    serde_json::to_string_pretty(&config).map_err(|error| {
        DomainError::new(
            ENGINE_SINGBOX_CONFIG_NATIVE_INVALID_CODE,
            format!("native sing-box config could not be serialized: {error}"),
        )
    })
}

fn find_local_http_proxy(config: &Value) -> Option<SingBoxLocalHttpProxy> {
    let inbounds = config.get("inbounds")?.as_array()?;
    for inbound in inbounds {
        let Some(inbound_type) = inbound.get("type").and_then(Value::as_str) else {
            continue;
        };
        if !matches!(inbound_type, "mixed" | "http") {
            continue;
        }
        let Some(port) = inbound
            .get("listen_port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
        else {
            continue;
        };
        if port == 0 {
            continue;
        }
        let server = match inbound.get("listen").and_then(Value::as_str) {
            None | Some("") | Some("0.0.0.0") | Some("127.0.0.1") => "127.0.0.1",
            Some("localhost") => "localhost",
            _ => continue,
        };
        return Some(SingBoxLocalHttpProxy {
            server: server.to_string(),
            port,
        });
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxProcessRunRequest {
    pub executable_path: PathBuf,
    pub config_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxProcessRunReport {
    pub exit_code: Option<i32>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxManagedProcessRequest {
    pub executable_path: PathBuf,
    pub config_path: PathBuf,
    pub working_directory: Option<PathBuf>,
    pub log_path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SingBoxManagedProcessState {
    Stopped,
    Running,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingBoxManagedProcessStatus {
    pub state: SingBoxManagedProcessState,
    pub process_id: Option<u32>,
    pub exit_code: Option<i32>,
}

/// Owns one sing-box child process and keeps its stdout/stderr in an operator-visible log.
/// The supervisor deliberately accepts an explicit executable path; downloading and provenance
/// remain the responsibility of the release installer boundary.
pub struct SingBoxManagedProcessSupervisor {
    child: Option<Child>,
    last_status: SingBoxManagedProcessStatus,
}

impl Default for SingBoxManagedProcessSupervisor {
    fn default() -> Self {
        Self {
            child: None,
            last_status: SingBoxManagedProcessStatus {
                state: SingBoxManagedProcessState::Stopped,
                process_id: None,
                exit_code: None,
            },
        }
    }
}

impl SingBoxManagedProcessSupervisor {
    pub fn start(
        &mut self,
        request: &SingBoxManagedProcessRequest,
    ) -> DomainResult<SingBoxManagedProcessStatus> {
        if let Some(status) = self.reap_if_exited()? {
            if status.state == SingBoxManagedProcessState::Running {
                return Err(DomainError::new(
                    ENGINE_SINGBOX_RUNTIME_ALREADY_RUNNING_CODE,
                    "sing-box managed process is already running",
                ));
            }
        }

        Self::check_configuration(request)?;
        ensure_log_parent(&request.log_path)?;
        let working_directory = request
            .working_directory
            .as_deref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<inherit>".to_string());
        append_process_log(
            &request.log_path,
            &format!(
                "starting sing-box executable={} config={} cwd={}",
                request.executable_path.display(),
                request.config_path.display(),
                working_directory
            ),
        )?;

        let stdout = File::options()
            .create(true)
            .append(true)
            .open(&request.log_path)
            .map_err(|error| process_error("sing-box stdout log could not be opened", error))?;
        let stderr = stdout
            .try_clone()
            .map_err(|error| process_error("sing-box stderr log could not be opened", error))?;
        let mut command = Command::new(&request.executable_path);
        command
            .arg("run")
            .arg("-c")
            .arg(&request.config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        if let Some(working_directory) = &request.working_directory {
            command.current_dir(working_directory);
        }

        let child = command.spawn().map_err(|error| {
            process_error("sing-box managed process could not be started", error)
        })?;
        let process_id = child.id();
        self.child = Some(child);
        self.last_status = SingBoxManagedProcessStatus {
            state: SingBoxManagedProcessState::Running,
            process_id: Some(process_id),
            exit_code: None,
        };
        append_process_log(
            &request.log_path,
            &format!("sing-box managed process started pid={process_id}"),
        )?;
        Ok(self.last_status.clone())
    }

    pub fn status(&mut self) -> DomainResult<SingBoxManagedProcessStatus> {
        let _ = self.reap_if_exited()?;
        Ok(self.last_status.clone())
    }

    pub fn stop(&mut self, log_path: &Path) -> DomainResult<SingBoxManagedProcessStatus> {
        let Some(mut child) = self.child.take() else {
            self.last_status.state = SingBoxManagedProcessState::Stopped;
            self.last_status.process_id = None;
            return Ok(self.last_status.clone());
        };

        let process_id = child.id();
        child.kill().map_err(|error| {
            process_error("sing-box managed process could not be stopped", error)
        })?;
        let status = child.wait().map_err(|error| {
            process_error(
                "sing-box managed process exit could not be collected",
                error,
            )
        })?;
        let exit_code = status.code();
        self.last_status = SingBoxManagedProcessStatus {
            state: SingBoxManagedProcessState::Stopped,
            process_id: None,
            exit_code,
        };
        append_process_log(
            log_path,
            &format!("sing-box managed process stopped pid={process_id} exit_code={exit_code:?}"),
        )?;
        Ok(self.last_status.clone())
    }

    /// Runs the same `sing-box check -c` preflight used before the managed process starts.
    ///
    /// Callers can use this to expose a non-mutating configuration check before submitting a
    /// service start request. stdout and stderr are retained in the explicit managed log path.
    pub fn check_configuration(request: &SingBoxManagedProcessRequest) -> DomainResult<()> {
        let mut command = Command::new(&request.executable_path);
        command
            .arg("check")
            .arg("-c")
            .arg(&request.config_path)
            .stdin(Stdio::null());
        if let Some(working_directory) = &request.working_directory {
            command.current_dir(working_directory);
        }
        let output = command.output().map_err(|error| {
            process_error("sing-box configuration check could not be started", error)
        })?;
        ensure_log_parent(&request.log_path)?;
        append_process_log(
            &request.log_path,
            &format!(
                "check sing-box config exit_code={:?}\nstdout={}\nstderr={}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        )?;
        if output.status.success() {
            return Ok(());
        }
        Err(DomainError::new(
            ENGINE_SINGBOX_CONFIG_CHECK_FAILED_CODE,
            format!(
                "sing-box configuration check failed with exit code {:?}",
                output.status.code()
            ),
        ))
    }

    fn reap_if_exited(&mut self) -> DomainResult<Option<SingBoxManagedProcessStatus>> {
        let Some(child) = self.child.as_mut() else {
            return Ok(Some(self.last_status.clone()));
        };
        let Some(status) = child
            .try_wait()
            .map_err(|error| process_error("sing-box process status could not be read", error))?
        else {
            return Ok(Some(self.last_status.clone()));
        };
        let process_id = child.id();
        let exit_code = status.code();
        self.child = None;
        self.last_status = SingBoxManagedProcessStatus {
            state: if status.success() {
                SingBoxManagedProcessState::Stopped
            } else {
                SingBoxManagedProcessState::Failed
            },
            process_id: None,
            exit_code,
        };
        Ok(Some(SingBoxManagedProcessStatus {
            state: self.last_status.state,
            process_id: Some(process_id),
            exit_code,
        }))
    }
}

impl Drop for SingBoxManagedProcessSupervisor {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn ensure_log_parent(path: &Path) -> DomainResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| process_error("sing-box log directory could not be created", error))?;
    }
    Ok(())
}

fn append_process_log(path: &Path, message: &str) -> DomainResult<()> {
    let mut file = File::options()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| process_error("sing-box log could not be opened", error))?;
    writeln!(file, "{message}")
        .map_err(|error| process_error("sing-box log could not be written", error))
}

fn process_error(message: &str, error: impl std::fmt::Display) -> DomainError {
    DomainError::new(
        ENGINE_SINGBOX_PROCESS_START_FAILED_CODE,
        format!("{message}: {error}"),
    )
}

pub trait SingBoxHttpClient {
    fn get_text(&self, url: &str) -> DomainResult<String>;

    fn get_bytes(&self, url: &str) -> DomainResult<Vec<u8>>;
}

pub trait SingBoxReleaseInstaller {
    fn install_latest(&self, request: &SingBoxInstallRequest)
        -> DomainResult<SingBoxInstallReport>;
}

pub trait SingBoxProcessRunner {
    fn run(&self, request: &SingBoxProcessRunRequest) -> DomainResult<SingBoxProcessRunReport>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandSingBoxProcessRunner;

impl CommandSingBoxProcessRunner {
    pub const fn new() -> Self {
        Self
    }
}

impl SingBoxProcessRunner for CommandSingBoxProcessRunner {
    fn run(&self, request: &SingBoxProcessRunRequest) -> DomainResult<SingBoxProcessRunReport> {
        let mut child = Command::new(request.executable_path.as_os_str())
            .arg("run")
            .arg("-c")
            .arg(request.config_path.as_os_str())
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|error| {
                DomainError::new(
                    ENGINE_SINGBOX_PROCESS_START_FAILED_CODE,
                    format!("failed to start sing-box process: {error}"),
                )
            })?;
        let mut diagnostics = vec![sing_box_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_SINGBOX_PROCESS_STARTED_CODE,
            "sing-box process was started in the foreground",
            SOURCE_ENGINE_SINGBOX_LIFECYCLE,
        )];
        let status = child.wait().map_err(|error| {
            DomainError::new(
                ENGINE_SINGBOX_PROCESS_START_FAILED_CODE,
                format!("failed while waiting for sing-box process: {error}"),
            )
        })?;
        let exit_code = status.code();
        diagnostics.push(sing_box_diagnostic(
            if status.success() {
                DiagnosticSeverity::Info
            } else {
                DiagnosticSeverity::Error
            },
            ENGINE_SINGBOX_PROCESS_EXITED_CODE,
            format!("sing-box process exited with status {exit_code:?}"),
            SOURCE_ENGINE_SINGBOX_LIFECYCLE,
        ));

        Ok(SingBoxProcessRunReport {
            exit_code,
            diagnostics,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ReqwestSingBoxHttpClient {
    client: Client,
}

impl ReqwestSingBoxHttpClient {
    pub fn new() -> DomainResult<Self> {
        let client = Client::builder()
            .user_agent(NETWORKCORE_SING_BOX_USER_AGENT)
            .build()
            .map_err(|error| {
                DomainError::new(
                    ENGINE_SINGBOX_DOWNLOAD_RELEASE_FETCH_FAILED_CODE,
                    format!("failed to create sing-box release HTTP client: {error}"),
                )
            })?;

        Ok(Self { client })
    }
}

impl SingBoxHttpClient for ReqwestSingBoxHttpClient {
    fn get_text(&self, url: &str) -> DomainResult<String> {
        self.client
            .get(url)
            .header("Accept", "application/vnd.github+json")
            .send()
            .and_then(|response| response.error_for_status())
            .and_then(|response| response.text())
            .map_err(|error| {
                DomainError::new(
                    ENGINE_SINGBOX_DOWNLOAD_RELEASE_FETCH_FAILED_CODE,
                    format!("failed to fetch sing-box latest release metadata: {error}"),
                )
            })
    }

    fn get_bytes(&self, url: &str) -> DomainResult<Vec<u8>> {
        self.client
            .get(url)
            .send()
            .and_then(|response| response.error_for_status())
            .and_then(|mut response| {
                let mut bytes = Vec::new();
                response.copy_to(&mut bytes)?;
                Ok(bytes)
            })
            .map_err(|error| {
                DomainError::new(
                    ENGINE_SINGBOX_DOWNLOAD_ASSET_FETCH_FAILED_CODE,
                    format!("failed to download sing-box release asset: {error}"),
                )
            })
    }
}

#[derive(Debug, Clone)]
pub struct GithubSingBoxReleaseInstaller<C = ReqwestSingBoxHttpClient> {
    http: C,
    latest_release_url: String,
}

impl GithubSingBoxReleaseInstaller<ReqwestSingBoxHttpClient> {
    pub fn new() -> DomainResult<Self> {
        Ok(Self {
            http: ReqwestSingBoxHttpClient::new()?,
            latest_release_url: SING_BOX_LATEST_RELEASE_API_URL.to_string(),
        })
    }
}

impl<C> GithubSingBoxReleaseInstaller<C> {
    pub fn with_http_client(http: C) -> Self {
        Self {
            http,
            latest_release_url: SING_BOX_LATEST_RELEASE_API_URL.to_string(),
        }
    }
}

impl<C> SingBoxReleaseInstaller for GithubSingBoxReleaseInstaller<C>
where
    C: SingBoxHttpClient,
{
    fn install_latest(
        &self,
        request: &SingBoxInstallRequest,
    ) -> DomainResult<SingBoxInstallReport> {
        let release_json = self.http.get_text(&self.latest_release_url)?;
        let release = parse_sing_box_release(&release_json)?;
        let plan = select_sing_box_asset(&release, request.target)?;
        install_sing_box_asset(&self.http, request, &plan)
    }
}

pub fn parse_sing_box_release(raw_json: &str) -> DomainResult<SingBoxRelease> {
    serde_json::from_str(raw_json).map_err(|error| {
        DomainError::new(
            ENGINE_SINGBOX_DOWNLOAD_RELEASE_PARSE_FAILED_CODE,
            format!("failed to parse sing-box latest release metadata: {error}"),
        )
    })
}

pub fn select_sing_box_asset(
    release: &SingBoxRelease,
    target: SingBoxTarget,
) -> DomainResult<SingBoxAssetPlan> {
    let version = release.tag_name.trim_start_matches('v').to_string();
    if version.is_empty() {
        return Err(DomainError::new(
            ENGINE_SINGBOX_DOWNLOAD_RELEASE_PARSE_FAILED_CODE,
            "sing-box latest release tag is empty",
        ));
    }

    let preferred_names = target.preferred_asset_names(&version);
    let asset = preferred_names.iter().find_map(|name| {
        release
            .assets
            .iter()
            .find(|asset| asset.name.as_str() == name.as_str())
    });

    let Some(asset) = asset else {
        return Err(DomainError::new(
            ENGINE_SINGBOX_DOWNLOAD_ASSET_MISSING_CODE,
            format!(
                "sing-box release {} has no supported asset for {}",
                release.tag_name,
                target.directory_name()
            ),
        ));
    };

    Ok(SingBoxAssetPlan {
        version,
        target,
        asset_name: asset.name.clone(),
        download_url: asset.browser_download_url.clone(),
        archive_kind: target.archive_kind(),
        sha256_digest: normalize_sha256_digest(asset.digest.as_deref()),
        size: asset.size,
    })
}

pub fn render_sing_box_local_proxy_config(
    request: &SingBoxLocalProxyConfigRequest,
) -> DomainResult<SingBoxLocalProxyConfig> {
    render_sing_box_local_proxy_config_with_controller(request, None)
}

/// Render a local proxy configuration with all translatable catalog nodes
/// behind a sing-box selector and a local-only Clash API controller.
pub fn render_sing_box_local_proxy_selector_config(
    request: &SingBoxLocalProxyConfigRequest,
    controller: &SingBoxLocalControllerConfig,
) -> DomainResult<SingBoxLocalProxyConfig> {
    render_sing_box_local_proxy_config_with_controller(request, Some(controller))
}

fn render_sing_box_local_proxy_config_with_controller(
    request: &SingBoxLocalProxyConfigRequest,
    controller: Option<&SingBoxLocalControllerConfig>,
) -> DomainResult<SingBoxLocalProxyConfig> {
    let node = select_node(&request.nodes, request.selected_node_id.as_deref())?;
    let mut diagnostics = Vec::new();
    let (outbounds, route_final, selectable_nodes, controller, experimental) =
        if let Some(controller) = controller {
            validate_loopback_controller(controller)?;
            let mut rendered_nodes = Vec::new();
            let mut selectable_nodes = Vec::new();

            for (index, candidate) in request.nodes.iter().enumerate() {
                if !supports_local_proxy_protocol(&candidate.protocol) {
                    diagnostics.push(sing_box_diagnostic(
                        DiagnosticSeverity::Warning,
                        ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE,
                        format!(
                            "skipped unsupported node {} while rendering sing-box selector",
                            candidate.id
                        ),
                        SOURCE_ENGINE_SINGBOX_CONFIG,
                    ));
                    continue;
                }
                let mut outbound = match render_sing_box_outbound(candidate) {
                    Ok(outbound) => outbound,
                    Err(error) => {
                        diagnostics.push(sing_box_diagnostic(
                            DiagnosticSeverity::Warning,
                            error.code,
                            format!(
                                "skipped node {} while rendering sing-box selector",
                                candidate.id
                            ),
                            SOURCE_ENGINE_SINGBOX_CONFIG,
                        ));
                        continue;
                    }
                };
                let outbound_tag = sing_box_local_selector_outbound_tag(index);
                outbound["tag"] = Value::String(outbound_tag.clone());
                rendered_nodes.push(outbound);
                selectable_nodes.push(SingBoxLocalProxySelectableNode {
                    id: candidate.id.clone(),
                    name: candidate.name.clone(),
                    outbound_tag,
                });
            }

            let selected = selectable_nodes
                .iter()
                .find(|candidate| candidate.id == node.id)
                .ok_or_else(|| {
                    DomainError::new(
                        ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE,
                        "selected node could not be rendered for the sing-box selector",
                    )
                })?;
            if selectable_nodes.is_empty() {
                return Err(DomainError::new(
                    ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE,
                    "node catalog has no sing-box selector-compatible node",
                ));
            }

            let selector = json!({
                "type": "selector",
                "tag": controller.selector_tag.as_str(),
                "outbounds": selectable_nodes
                    .iter()
                    .map(|candidate| candidate.outbound_tag.as_str())
                    .collect::<Vec<_>>(),
                "default": selected.outbound_tag.as_str(),
                "interrupt_exist_connections": controller.interrupt_exist_connections,
            });
            let mut outbounds = Vec::with_capacity(rendered_nodes.len() + 2);
            outbounds.push(selector);
            outbounds.extend(rendered_nodes);
            outbounds.push(json!({
                "type": "direct",
                "tag": "direct"
            }));
            let experimental = json!({
                "clash_api": {
                    "external_controller": controller.endpoint(),
                }
            });
            (
                outbounds,
                controller.selector_tag.clone(),
                selectable_nodes,
                Some(controller.clone()),
                Some(experimental),
            )
        } else {
            let outbound = render_sing_box_outbound(node)?;
            (
                vec![
                    outbound,
                    json!({
                        "type": "direct",
                        "tag": "direct"
                    }),
                ],
                node.id.clone(),
                vec![SingBoxLocalProxySelectableNode {
                    id: node.id.clone(),
                    name: node.name.clone(),
                    outbound_tag: node.id.clone(),
                }],
                None,
                None,
            )
        };

    let mut config = json!({
        "log": {
            "level": "info"
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": request.listen_host.as_str(),
                "listen_port": request.listen_port
            }
        ],
        "outbounds": outbounds,
        "route": {
            "final": route_final
        }
    });
    if let Some(experimental) = experimental {
        config["experimental"] = experimental;
    }
    let json = serde_json::to_string_pretty(&config).map_err(|error| {
        DomainError::new(
            ENGINE_SINGBOX_CONFIG_RENDERED_CODE,
            format!("failed to serialize sing-box config: {error}"),
        )
    })?;

    Ok(SingBoxLocalProxyConfig {
        json,
        selected_node_id: node.id.clone(),
        selected_node_name: node.name.clone(),
        listen_host: request.listen_host.clone(),
        listen_port: request.listen_port,
        selectable_nodes,
        controller,
        diagnostics: {
            diagnostics.push(sing_box_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_SINGBOX_CONFIG_RENDERED_CODE,
                "rendered sing-box local mixed inbound config from NetworkCore node catalog",
                SOURCE_ENGINE_SINGBOX_CONFIG,
            ));
            diagnostics
        },
    })
}

pub fn read_sing_box_clash_api_selector(
    controller: &SingBoxLocalControllerConfig,
) -> DomainResult<SingBoxClashApiSelectorStatus> {
    validate_loopback_controller(controller)?;
    let url = sing_box_clash_api_selector_url(controller)?;
    let client = sing_box_clash_api_client()?;
    let response = client
        .get(url)
        .send()
        .map_err(|_| sing_box_clash_api_error("sing-box selector could not be read"))?
        .error_for_status()
        .map_err(|_| sing_box_clash_api_error("sing-box selector could not be read"))?;
    let response = response
        .text()
        .map_err(|_| sing_box_clash_api_error("sing-box selector response could not be read"))?;
    let payload: SingBoxClashApiSelectorResponse = serde_json::from_str(&response)
        .map_err(|_| sing_box_clash_api_error("sing-box selector response was invalid"))?;
    let current_outbound_tag = payload.now.ok_or_else(|| {
        sing_box_clash_api_error("sing-box selector response did not include the active outbound")
    })?;

    Ok(SingBoxClashApiSelectorStatus {
        selector_tag: controller.selector_tag.clone(),
        current_outbound_tag,
        outbound_tags: payload.all,
    })
}

pub fn select_sing_box_clash_api_outbound(
    controller: &SingBoxLocalControllerConfig,
    outbound_tag: &str,
) -> DomainResult<SingBoxClashApiSelectorStatus> {
    validate_sing_box_clash_api_outbound_tag(outbound_tag)?;
    validate_loopback_controller(controller)?;
    let url = sing_box_clash_api_selector_url(controller)?;
    let client = sing_box_clash_api_client()?;
    let request_body = serde_json::to_string(&json!({ "name": outbound_tag }))
        .map_err(|_| sing_box_clash_api_error("sing-box selector request could not be encoded"))?;
    client
        .patch(url)
        .header("Content-Type", "application/json")
        .body(request_body)
        .send()
        .map_err(|_| sing_box_clash_api_error("sing-box selector could not be updated"))?
        .error_for_status()
        .map_err(|_| sing_box_clash_api_error("sing-box selector could not be updated"))?;

    let status = read_sing_box_clash_api_selector(controller)?;
    if status.current_outbound_tag != outbound_tag {
        return Err(DomainError::new(
            ENGINE_SINGBOX_CLASH_API_SELECTOR_MISMATCH_CODE,
            "sing-box selector did not report the requested active outbound",
        ));
    }
    Ok(status)
}

/// Measures one generated outbound through the local sing-box Clash API.
///
/// This is deliberately an operator-triggered request. It does not create a
/// sing-box `urltest` outbound or schedule background measurements.
pub fn measure_sing_box_clash_api_outbound_delay(
    controller: &SingBoxLocalControllerConfig,
    outbound_tag: &str,
    test_url: &str,
    timeout_millis: u16,
) -> DomainResult<SingBoxClashApiDelayResult> {
    validate_sing_box_clash_api_outbound_tag(outbound_tag)?;
    validate_loopback_controller(controller)?;
    if timeout_millis == 0 {
        return Err(DomainError::new(
            ENGINE_SINGBOX_CLASH_API_DELAY_INVALID_CODE,
            "sing-box delay test timeout must be greater than zero",
        ));
    }
    let test_url = reqwest::Url::parse(test_url.trim()).map_err(|_| {
        DomainError::new(
            ENGINE_SINGBOX_CLASH_API_DELAY_INVALID_CODE,
            "sing-box delay test URL must be an absolute HTTPS URL",
        )
    })?;
    if test_url.scheme() != "https" {
        return Err(DomainError::new(
            ENGINE_SINGBOX_CLASH_API_DELAY_INVALID_CODE,
            "sing-box delay test URL must use HTTPS",
        ));
    }

    let mut url = sing_box_clash_api_proxy_url(controller, outbound_tag)?;
    url.path_segments_mut()
        .map_err(|_| sing_box_clash_api_error("sing-box delay URL cannot accept a path"))?
        .push("delay");
    url.query_pairs_mut()
        .append_pair("url", test_url.as_str())
        .append_pair("timeout", &timeout_millis.to_string());

    let response = sing_box_clash_api_client_with_timeout(std::time::Duration::from_millis(
        u64::from(timeout_millis) + 2_000,
    ))?
    .get(url)
    .send()
    .map_err(|_| sing_box_clash_api_error("sing-box delay test could not be completed"))?
    .error_for_status()
    .map_err(|_| sing_box_clash_api_error("sing-box delay test could not be completed"))?
    .text()
    .map_err(|_| sing_box_clash_api_error("sing-box delay test response could not be read"))?;
    let payload: SingBoxClashApiDelayResponse = serde_json::from_str(&response)
        .map_err(|_| sing_box_clash_api_error("sing-box delay test response was invalid"))?;
    let delay_millis = payload.delay.filter(|delay| *delay > 0).ok_or_else(|| {
        sing_box_clash_api_error("sing-box delay test response did not include a positive delay")
    })?;

    Ok(SingBoxClashApiDelayResult {
        outbound_tag: outbound_tag.to_string(),
        test_url: test_url.to_string(),
        delay_millis,
    })
}

#[derive(Debug, Deserialize)]
struct SingBoxClashApiSelectorResponse {
    #[serde(default)]
    now: Option<String>,
    #[serde(default)]
    all: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SingBoxClashApiDelayResponse {
    #[serde(default)]
    delay: Option<u64>,
}

fn validate_sing_box_clash_api_outbound_tag(outbound_tag: &str) -> DomainResult<()> {
    if outbound_tag.trim().is_empty() {
        return Err(DomainError::new(
            ENGINE_SINGBOX_CONFIG_SELECTOR_INVALID_CODE,
            "sing-box selector outbound tag must not be empty",
        ));
    }
    Ok(())
}

fn validate_loopback_controller(controller: &SingBoxLocalControllerConfig) -> DomainResult<()> {
    let host = controller.host.trim();
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == "[::1]";
    if !loopback || controller.port == 0 || controller.selector_tag.trim().is_empty() {
        return Err(DomainError::new(
            ENGINE_SINGBOX_CONFIG_SELECTOR_INVALID_CODE,
            "sing-box runtime selector requires an explicit loopback controller and selector tag",
        ));
    }
    Ok(())
}

fn sing_box_clash_api_selector_url(
    controller: &SingBoxLocalControllerConfig,
) -> DomainResult<reqwest::Url> {
    sing_box_clash_api_proxy_url(controller, &controller.selector_tag)
}

fn sing_box_clash_api_proxy_url(
    controller: &SingBoxLocalControllerConfig,
    outbound_tag: &str,
) -> DomainResult<reqwest::Url> {
    let mut url = reqwest::Url::parse(&controller.base_url()).map_err(|_| {
        DomainError::new(
            ENGINE_SINGBOX_CONFIG_SELECTOR_INVALID_CODE,
            "sing-box Clash API controller URL is invalid",
        )
    })?;
    url.path_segments_mut()
        .map_err(|_| {
            DomainError::new(
                ENGINE_SINGBOX_CONFIG_SELECTOR_INVALID_CODE,
                "sing-box Clash API controller URL cannot accept a selector path",
            )
        })?
        .extend(["proxies", outbound_tag]);
    Ok(url)
}

fn sing_box_clash_api_client() -> DomainResult<Client> {
    sing_box_clash_api_client_with_timeout(std::time::Duration::from_secs(10))
}

fn sing_box_clash_api_client_with_timeout(timeout: std::time::Duration) -> DomainResult<Client> {
    Client::builder()
        .timeout(timeout)
        .user_agent(NETWORKCORE_SING_BOX_USER_AGENT)
        .build()
        .map_err(|_| sing_box_clash_api_error("sing-box Clash API client could not be created"))
}

fn sing_box_clash_api_error(message: &str) -> DomainError {
    DomainError::new(ENGINE_SINGBOX_CLASH_API_REQUEST_FAILED_CODE, message)
}

fn render_sing_box_outbound(node: &NodeDescriptor) -> DomainResult<serde_json::Value> {
    match &node.protocol {
        Protocol::Shadowsocks => {
            let method = required_node_metadata(
                node,
                NODE_METADATA_SHADOWSOCKS_METHOD,
                "shadowsocks node is missing method metadata",
            )?;
            let password = required_node_metadata(
                node,
                NODE_METADATA_SHADOWSOCKS_PASSWORD,
                "shadowsocks node is missing password metadata",
            )?;
            Ok(json!({
                "type": "shadowsocks",
                "tag": node.id.as_str(),
                "server": node.endpoint.host.as_str(),
                "server_port": node.endpoint.port,
                "method": method,
                "password": password,
            }))
        }
        Protocol::Trojan => render_trojan_outbound(node),
        Protocol::Vless => render_vless_outbound(node),
        Protocol::Vmess => render_vmess_outbound(node),
        Protocol::Hysteria2 => render_hysteria2_outbound(node),
        Protocol::Tuic => render_tuic_outbound(node),
        Protocol::Http | Protocol::Socks | Protocol::Hysteria | Protocol::Other(_) => {
            Err(DomainError::new(
                ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE,
                format!(
                    "sing-box local proxy config does not support {:?} nodes",
                    node.protocol
                ),
            ))
        }
    }
}

fn render_trojan_outbound(node: &NodeDescriptor) -> DomainResult<Value> {
    let password = required_node_metadata(
        node,
        NODE_METADATA_TROJAN_PASSWORD,
        "trojan node is missing password metadata",
    )?;
    let mut outbound = json!({
        "type": "trojan",
        "tag": node.id.as_str(),
        "server": node.endpoint.host.as_str(),
        "server_port": node.endpoint.port,
        "password": password,
    });
    append_v2ray_outbound_options(&mut outbound, node, true)?;
    Ok(outbound)
}

fn render_vless_outbound(node: &NodeDescriptor) -> DomainResult<Value> {
    let uuid = required_node_metadata(
        node,
        NODE_METADATA_VLESS_UUID,
        "vless node is missing uuid metadata",
    )?;
    let mut outbound = json!({
        "type": "vless",
        "tag": node.id.as_str(),
        "server": node.endpoint.host.as_str(),
        "server_port": node.endpoint.port,
        "uuid": uuid,
    });
    if let Some(flow) = metadata_value(node, NODE_METADATA_VLESS_FLOW) {
        if !flow.trim().is_empty() {
            outbound
                .as_object_mut()
                .expect("vless outbound must be a JSON object")
                .insert("flow".to_string(), json!(flow));
        }
    }
    append_v2ray_outbound_options(&mut outbound, node, false)?;
    Ok(outbound)
}

fn render_vmess_outbound(node: &NodeDescriptor) -> DomainResult<Value> {
    let uuid = required_node_metadata(
        node,
        NODE_METADATA_VMESS_UUID,
        "vmess node is missing uuid metadata",
    )?;
    let security = metadata_value(node, NODE_METADATA_VMESS_SECURITY).unwrap_or("auto");
    if !matches!(
        security,
        "auto" | "none" | "zero" | "aes-128-gcm" | "chacha20-poly1305" | "aes-128-ctr"
    ) {
        return Err(DomainError::new(
            ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE,
            "vmess security metadata is not supported by sing-box",
        ));
    }
    let alter_id = optional_nonnegative_u32_node_metadata(
        node,
        NODE_METADATA_VMESS_ALTER_ID,
        "vmess alter_id metadata must be a non-negative integer",
    )?
    .unwrap_or(0);
    let mut outbound = json!({
        "type": "vmess",
        "tag": node.id.as_str(),
        "server": node.endpoint.host.as_str(),
        "server_port": node.endpoint.port,
        "uuid": uuid,
        "security": security,
        "alter_id": alter_id,
    });
    append_v2ray_outbound_options(&mut outbound, node, false)?;
    Ok(outbound)
}

fn append_v2ray_outbound_options(
    outbound: &mut Value,
    node: &NodeDescriptor,
    default_tls_enabled: bool,
) -> DomainResult<()> {
    let fields = outbound
        .as_object_mut()
        .expect("sing-box V2Ray-family outbound must be a JSON object");
    if let Some(tls) = render_v2ray_tls(node, default_tls_enabled)? {
        fields.insert("tls".to_string(), tls);
    }
    if let Some(transport) = render_v2ray_transport(node)? {
        fields.insert("transport".to_string(), transport);
    }
    Ok(())
}

fn render_v2ray_tls(node: &NodeDescriptor, default_enabled: bool) -> DomainResult<Option<Value>> {
    let enabled = optional_boolean_node_metadata(
        node,
        NODE_METADATA_TLS_ENABLED,
        "tls enabled metadata must be true or false",
    )?
    .unwrap_or(default_enabled);
    if !enabled {
        return Ok(None);
    }
    let server_name = metadata_value(node, NODE_METADATA_TLS_SERVER_NAME)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(node.endpoint.host.as_str());
    let insecure = optional_boolean_node_metadata(
        node,
        NODE_METADATA_TLS_INSECURE,
        "tls insecure metadata must be true or false",
    )?
    .unwrap_or(false);
    let mut tls = json!({
        "enabled": true,
        "server_name": server_name,
        "insecure": insecure,
    });
    let fields = tls
        .as_object_mut()
        .expect("tls configuration must be a JSON object");
    if let Some(alpn) = optional_node_metadata_list(node, NODE_METADATA_TLS_ALPN) {
        fields.insert("alpn".to_string(), json!(alpn));
    }
    if let Some(pins) =
        optional_node_metadata_list(node, NODE_METADATA_TLS_CERTIFICATE_PUBLIC_KEY_SHA256)
    {
        fields.insert("certificate_public_key_sha256".to_string(), json!(pins));
    }
    if let Some(fingerprint) = metadata_value(node, NODE_METADATA_TLS_UTLS_FINGERPRINT) {
        if !fingerprint.trim().is_empty() {
            fields.insert(
                "utls".to_string(),
                json!({ "enabled": true, "fingerprint": fingerprint }),
            );
        }
    }
    if let Some(public_key) = metadata_value(node, NODE_METADATA_TLS_REALITY_PUBLIC_KEY) {
        if public_key.trim().is_empty() {
            return Err(DomainError::new(
                ENGINE_SINGBOX_CONFIG_SECRET_MISSING_CODE,
                "tls reality public_key metadata cannot be empty",
            ));
        }
        let mut reality = json!({
            "enabled": true,
            "public_key": public_key,
        });
        if let Some(short_id) = metadata_value(node, NODE_METADATA_TLS_REALITY_SHORT_ID) {
            if !short_id.trim().is_empty() {
                reality
                    .as_object_mut()
                    .expect("tls reality configuration must be a JSON object")
                    .insert("short_id".to_string(), json!(short_id));
            }
        }
        fields.insert("reality".to_string(), reality);
    }
    Ok(Some(tls))
}

fn render_v2ray_transport(node: &NodeDescriptor) -> DomainResult<Option<Value>> {
    let Some(kind) = metadata_value(node, NODE_METADATA_V2RAY_TRANSPORT_TYPE) else {
        return Ok(None);
    };
    let hosts = optional_node_metadata_list(node, NODE_METADATA_V2RAY_TRANSPORT_HOST);
    let path = metadata_value(node, NODE_METADATA_V2RAY_TRANSPORT_PATH)
        .filter(|value| !value.trim().is_empty());
    let service_name = metadata_value(node, NODE_METADATA_V2RAY_TRANSPORT_SERVICE_NAME)
        .filter(|value| !value.trim().is_empty());
    let transport = match kind.trim().to_ascii_lowercase().as_str() {
        "ws" => {
            let mut value = json!({ "type": "ws" });
            let fields = value
                .as_object_mut()
                .expect("websocket transport must be a JSON object");
            if let Some(path) = path {
                fields.insert("path".to_string(), json!(path));
            }
            if let Some(hosts) = hosts {
                fields.insert("headers".to_string(), json!({ "Host": hosts }));
            }
            value
        }
        "grpc" => {
            let mut value = json!({ "type": "grpc" });
            if let Some(service_name) = service_name {
                value
                    .as_object_mut()
                    .expect("grpc transport must be a JSON object")
                    .insert("service_name".to_string(), json!(service_name));
            }
            value
        }
        "http" => {
            let mut value = json!({ "type": "http" });
            let fields = value
                .as_object_mut()
                .expect("http transport must be a JSON object");
            if let Some(hosts) = hosts {
                fields.insert("host".to_string(), json!(hosts));
            }
            if let Some(path) = path {
                fields.insert("path".to_string(), json!(path));
            }
            value
        }
        "httpupgrade" => {
            let mut value = json!({ "type": "httpupgrade" });
            let fields = value
                .as_object_mut()
                .expect("httpupgrade transport must be a JSON object");
            if let Some(host) = hosts.and_then(|hosts| hosts.into_iter().next()) {
                fields.insert("host".to_string(), json!(host));
            }
            if let Some(path) = path {
                fields.insert("path".to_string(), json!(path));
            }
            value
        }
        "quic" => json!({ "type": "quic" }),
        _ => {
            return Err(DomainError::new(
                ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE,
                "V2Ray transport metadata is not supported by sing-box",
            ));
        }
    };
    Ok(Some(transport))
}

fn render_hysteria2_outbound(node: &NodeDescriptor) -> DomainResult<Value> {
    let password = required_node_metadata(
        node,
        NODE_METADATA_HYSTERIA2_PASSWORD,
        "hysteria2 node is missing password metadata",
    )?;
    let mut outbound = json!({
        "type": "hysteria2",
        "tag": node.id.as_str(),
        "server": node.endpoint.host.as_str(),
        "server_port": node.endpoint.port,
        "password": password,
        "tls": render_quic_tls(node)?,
    });
    if let Some(server_ports) =
        optional_node_metadata_list(node, NODE_METADATA_HYSTERIA2_SERVER_PORTS)
    {
        let fields = outbound
            .as_object_mut()
            .expect("hysteria2 outbound must be a JSON object");
        fields.remove("server_port");
        fields.insert("server_ports".to_string(), json!(server_ports));
    }
    if let Some(kind) = metadata_value(node, NODE_METADATA_HYSTERIA2_OBFS_TYPE) {
        let password = required_node_metadata(
            node,
            NODE_METADATA_HYSTERIA2_OBFS_PASSWORD,
            "hysteria2 obfs metadata is missing password",
        )?;
        let mut obfs = json!({
            "type": kind,
            "password": password,
        });
        match kind {
            "salamander" => {}
            "gecko" => {
                if let Some(value) = optional_positive_u64_node_metadata(
                    node,
                    NODE_METADATA_HYSTERIA2_OBFS_MIN_PACKET_SIZE,
                    "hysteria2 gecko min_packet_size metadata must be a positive integer",
                )? {
                    obfs.as_object_mut()
                        .expect("hysteria2 obfs must be a JSON object")
                        .insert("min_packet_size".to_string(), json!(value));
                }
                if let Some(value) = optional_positive_u64_node_metadata(
                    node,
                    NODE_METADATA_HYSTERIA2_OBFS_MAX_PACKET_SIZE,
                    "hysteria2 gecko max_packet_size metadata must be a positive integer",
                )? {
                    obfs.as_object_mut()
                        .expect("hysteria2 obfs must be a JSON object")
                        .insert("max_packet_size".to_string(), json!(value));
                }
            }
            _ => {
                return Err(DomainError::new(
                    ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE,
                    "hysteria2 obfs metadata type must be salamander or gecko",
                ));
            }
        }
        outbound
            .as_object_mut()
            .expect("hysteria2 outbound must be a JSON object")
            .insert("obfs".to_string(), obfs);
    }
    Ok(outbound)
}

fn render_tuic_outbound(node: &NodeDescriptor) -> DomainResult<Value> {
    let uuid = required_node_metadata(
        node,
        NODE_METADATA_TUIC_UUID,
        "tuic node is missing uuid metadata",
    )?;
    let mut outbound = json!({
        "type": "tuic",
        "tag": node.id.as_str(),
        "server": node.endpoint.host.as_str(),
        "server_port": node.endpoint.port,
        "uuid": uuid,
        "tls": render_quic_tls(node)?,
    });
    let fields = outbound
        .as_object_mut()
        .expect("tuic outbound must be a JSON object");
    if let Some(password) = metadata_value(node, NODE_METADATA_TUIC_PASSWORD) {
        if !password.trim().is_empty() {
            fields.insert("password".to_string(), json!(password));
        }
    }
    if let Some(congestion_control) = metadata_value(node, NODE_METADATA_TUIC_CONGESTION_CONTROL) {
        if !congestion_control.trim().is_empty() {
            fields.insert("congestion_control".to_string(), json!(congestion_control));
        }
    }
    Ok(outbound)
}

fn render_quic_tls(node: &NodeDescriptor) -> DomainResult<Value> {
    let server_name = metadata_value(node, NODE_METADATA_TLS_SERVER_NAME)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(node.endpoint.host.as_str());
    let insecure = optional_boolean_node_metadata(
        node,
        NODE_METADATA_TLS_INSECURE,
        "tls insecure metadata must be true or false",
    )?
    .unwrap_or(false);
    let mut tls = json!({
        "enabled": true,
        "server_name": server_name,
        "insecure": insecure,
    });
    if let Some(alpn) = optional_node_metadata_list(node, NODE_METADATA_TLS_ALPN) {
        tls.as_object_mut()
            .expect("tls configuration must be a JSON object")
            .insert("alpn".to_string(), json!(alpn));
    }
    if let Some(pins) =
        optional_node_metadata_list(node, NODE_METADATA_TLS_CERTIFICATE_PUBLIC_KEY_SHA256)
    {
        tls.as_object_mut()
            .expect("tls configuration must be a JSON object")
            .insert("certificate_public_key_sha256".to_string(), json!(pins));
    }
    Ok(tls)
}

fn required_node_metadata<'a>(
    node: &'a NodeDescriptor,
    key: &str,
    message: &str,
) -> DomainResult<&'a str> {
    metadata_value(node, key)
        .ok_or_else(|| DomainError::new(ENGINE_SINGBOX_CONFIG_SECRET_MISSING_CODE, message))
}

fn optional_node_metadata_list<'a>(node: &'a NodeDescriptor, key: &str) -> Option<Vec<&'a str>> {
    let values = metadata_value(node, key)?
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    (!values.is_empty()).then_some(values)
}

fn optional_boolean_node_metadata(
    node: &NodeDescriptor,
    key: &str,
    message: &'static str,
) -> DomainResult<Option<bool>> {
    let Some(value) = metadata_value(node, key) else {
        return Ok(None);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(Some(true)),
        "false" | "0" | "" => Ok(Some(false)),
        _ => Err(DomainError::new(
            ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE,
            message,
        )),
    }
}

fn optional_positive_u64_node_metadata(
    node: &NodeDescriptor,
    key: &str,
    message: &'static str,
) -> DomainResult<Option<u64>> {
    let Some(value) = metadata_value(node, key) else {
        return Ok(None);
    };
    let value = value
        .trim()
        .parse::<u64>()
        .map_err(|_| DomainError::new(ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE, message))?;
    if value == 0 {
        return Err(DomainError::new(
            ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE,
            message,
        ));
    }
    Ok(Some(value))
}

fn optional_nonnegative_u32_node_metadata(
    node: &NodeDescriptor,
    key: &str,
    message: &'static str,
) -> DomainResult<Option<u32>> {
    let Some(value) = metadata_value(node, key) else {
        return Ok(None);
    };
    value
        .trim()
        .parse::<u32>()
        .map(Some)
        .map_err(|_| DomainError::new(ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE, message))
}

pub fn default_sing_box_install_root() -> PathBuf {
    if let Some(path) = non_empty_env_path("NETWORKCORE_ENGINE_DIR") {
        return path.join(DEFAULT_SING_BOX_ENGINE_ID);
    }

    match std::env::consts::OS {
        "windows" => non_empty_env_path("LOCALAPPDATA")
            .unwrap_or_else(|| PathBuf::from(".networkcore"))
            .join("NetworkCore")
            .join("engines")
            .join(DEFAULT_SING_BOX_ENGINE_ID),
        "macos" => non_empty_env_path("HOME")
            .unwrap_or_else(|| PathBuf::from("."))
            .join("Library")
            .join("Application Support")
            .join("NetworkCore")
            .join("engines")
            .join(DEFAULT_SING_BOX_ENGINE_ID),
        _ => non_empty_env_path("XDG_DATA_HOME")
            .or_else(|| non_empty_env_path("HOME").map(|home| home.join(".local").join("share")))
            .unwrap_or_else(|| PathBuf::from(".networkcore"))
            .join("networkcore")
            .join("engines")
            .join(DEFAULT_SING_BOX_ENGINE_ID),
    }
}

pub fn sing_box_diagnostic(
    severity: DiagnosticSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
    source: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(severity, code, message, Some(source.into()))
}

fn select_node<'a>(
    nodes: &'a [NodeDescriptor],
    selected_node_id: Option<&str>,
) -> DomainResult<&'a NodeDescriptor> {
    if nodes.is_empty() {
        return Err(DomainError::new(
            ENGINE_SINGBOX_CONFIG_NODE_MISSING_CODE,
            "sing-box config generation requires at least one node",
        ));
    }

    if let Some(selected_node_id) = selected_node_id {
        return nodes
            .iter()
            .find(|node| node.id == selected_node_id)
            .ok_or_else(|| {
                DomainError::new(
                    ENGINE_SINGBOX_CONFIG_NODE_MISSING_CODE,
                    "selected node id was not present in the node catalog",
                )
            });
    }

    nodes
        .iter()
        .find(|node| supports_local_proxy_protocol(&node.protocol))
        .ok_or_else(|| {
            DomainError::new(
                ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE,
                "node catalog has no sing-box local proxy supported node",
            )
        })
}

fn supports_local_proxy_protocol(protocol: &Protocol) -> bool {
    matches!(
        protocol,
        Protocol::Shadowsocks
            | Protocol::Trojan
            | Protocol::Vless
            | Protocol::Vmess
            | Protocol::Hysteria2
            | Protocol::Tuic
    )
}

fn metadata_value<'a>(node: &'a NodeDescriptor, key: &str) -> Option<&'a str> {
    node.metadata
        .iter()
        .find(|entry| entry.key == key)
        .map(|entry| entry.value.as_str())
}

fn install_sing_box_asset<C>(
    http: &C,
    request: &SingBoxInstallRequest,
    plan: &SingBoxAssetPlan,
) -> DomainResult<SingBoxInstallReport>
where
    C: SingBoxHttpClient,
{
    let version_dir = request
        .install_root
        .join(&plan.version)
        .join(plan.target.directory_name());
    let archive_path = version_dir.join("downloads").join(&plan.asset_name);
    let executable_path = version_dir.join("bin").join(plan.target.executable_name());
    let mut diagnostics = vec![
        sing_box_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_SINGBOX_DOWNLOAD_LATEST_VERSION_RESOLVED_CODE,
            format!("resolved latest sing-box release {}", plan.version),
            SOURCE_ENGINE_SINGBOX_DOWNLOAD,
        ),
        sing_box_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_SINGBOX_DOWNLOAD_ASSET_SELECTED_CODE,
            format!("selected sing-box release asset {}", plan.asset_name),
            SOURCE_ENGINE_SINGBOX_DOWNLOAD,
        ),
    ];

    if executable_path.exists() && !request.force {
        diagnostics.push(sing_box_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_SINGBOX_DOWNLOAD_BINARY_ALREADY_PRESENT_CODE,
            "sing-box latest executable is already present",
            SOURCE_ENGINE_SINGBOX_DOWNLOAD,
        ));
        diagnostics.push(sing_box_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_SINGBOX_DOWNLOAD_BINARY_READY_CODE,
            "sing-box executable is ready",
            SOURCE_ENGINE_SINGBOX_DOWNLOAD,
        ));

        return Ok(SingBoxInstallReport {
            version: plan.version.clone(),
            target: plan.target,
            asset_name: plan.asset_name.clone(),
            asset_url: plan.download_url.clone(),
            asset_sha256: plan.sha256_digest.clone(),
            archive_path,
            executable_path,
            downloaded: false,
            diagnostics,
        });
    }

    let archive_parent = archive_path.parent().ok_or_else(|| {
        DomainError::new(
            ENGINE_SINGBOX_DOWNLOAD_ASSET_FETCH_FAILED_CODE,
            "sing-box archive path has no parent directory",
        )
    })?;
    let executable_parent = executable_path.parent().ok_or_else(|| {
        DomainError::new(
            ENGINE_SINGBOX_DOWNLOAD_ASSET_FETCH_FAILED_CODE,
            "sing-box executable path has no parent directory",
        )
    })?;

    fs::create_dir_all(archive_parent).map_err(|error| {
        DomainError::new(
            ENGINE_SINGBOX_DOWNLOAD_ASSET_FETCH_FAILED_CODE,
            format!("failed to create sing-box download directory: {error}"),
        )
    })?;
    fs::create_dir_all(executable_parent).map_err(|error| {
        DomainError::new(
            ENGINE_SINGBOX_DOWNLOAD_ASSET_FETCH_FAILED_CODE,
            format!("failed to create sing-box binary directory: {error}"),
        )
    })?;

    let archive_bytes = http.get_bytes(&plan.download_url)?;
    verify_sha256_digest(
        &archive_bytes,
        plan.sha256_digest.as_deref(),
        &mut diagnostics,
    )?;
    fs::write(&archive_path, &archive_bytes).map_err(|error| {
        DomainError::new(
            ENGINE_SINGBOX_DOWNLOAD_ASSET_FETCH_FAILED_CODE,
            format!("failed to write sing-box archive: {error}"),
        )
    })?;
    diagnostics.push(sing_box_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_SINGBOX_DOWNLOAD_ARCHIVE_WRITTEN_CODE,
        "sing-box release archive was written to the engine cache",
        SOURCE_ENGINE_SINGBOX_DOWNLOAD,
    ));

    match plan.archive_kind {
        SingBoxArchiveKind::TarGz => extract_sing_box_tar_gz(
            &archive_bytes,
            plan.target.executable_name(),
            &executable_path,
        )?,
        SingBoxArchiveKind::Zip => extract_sing_box_zip(
            &archive_bytes,
            plan.target.executable_name(),
            &executable_path,
        )?,
    }
    mark_executable(&executable_path)?;
    diagnostics.push(sing_box_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_SINGBOX_DOWNLOAD_BINARY_READY_CODE,
        "sing-box executable is ready",
        SOURCE_ENGINE_SINGBOX_DOWNLOAD,
    ));

    Ok(SingBoxInstallReport {
        version: plan.version.clone(),
        target: plan.target,
        asset_name: plan.asset_name.clone(),
        asset_url: plan.download_url.clone(),
        asset_sha256: plan.sha256_digest.clone(),
        archive_path,
        executable_path,
        downloaded: true,
        diagnostics,
    })
}

fn extract_sing_box_tar_gz(
    archive_bytes: &[u8],
    executable_name: &str,
    executable_path: &Path,
) -> DomainResult<()> {
    let decoder = GzDecoder::new(Cursor::new(archive_bytes));
    let mut archive = Archive::new(decoder);
    let entries = archive.entries().map_err(|error| {
        DomainError::new(
            ENGINE_SINGBOX_DOWNLOAD_EXTRACT_FAILED_CODE,
            format!("failed to read sing-box archive entries: {error}"),
        )
    })?;

    for entry in entries {
        let mut entry = entry.map_err(|error| {
            DomainError::new(
                ENGINE_SINGBOX_DOWNLOAD_EXTRACT_FAILED_CODE,
                format!("failed to inspect sing-box archive entry: {error}"),
            )
        })?;
        let is_executable = {
            let path = entry.path().map_err(|error| {
                DomainError::new(
                    ENGINE_SINGBOX_DOWNLOAD_EXTRACT_FAILED_CODE,
                    format!("failed to inspect sing-box archive path: {error}"),
                )
            })?;
            path.file_name().and_then(|name| name.to_str()) == Some(executable_name)
        };

        if !is_executable {
            continue;
        }

        let mut output = File::create(executable_path).map_err(|error| {
            DomainError::new(
                ENGINE_SINGBOX_DOWNLOAD_EXTRACT_FAILED_CODE,
                format!("failed to create sing-box executable: {error}"),
            )
        })?;
        std::io::copy(&mut entry, &mut output).map_err(|error| {
            DomainError::new(
                ENGINE_SINGBOX_DOWNLOAD_EXTRACT_FAILED_CODE,
                format!("failed to extract sing-box executable: {error}"),
            )
        })?;
        return Ok(());
    }

    Err(DomainError::new(
        ENGINE_SINGBOX_DOWNLOAD_EXTRACT_FAILED_CODE,
        "sing-box executable was not found in the release archive",
    ))
}

fn extract_sing_box_zip(
    archive_bytes: &[u8],
    executable_name: &str,
    executable_path: &Path,
) -> DomainResult<()> {
    const END_OF_CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0605_4b50;
    const CENTRAL_DIRECTORY_SIGNATURE: u32 = 0x0201_4b50;
    const LOCAL_FILE_HEADER_SIGNATURE: u32 = 0x0403_4b50;

    let eocd_offset = archive_bytes
        .windows(4)
        .rposition(|window| {
            u32::from_le_bytes(window.try_into().unwrap()) == END_OF_CENTRAL_DIRECTORY_SIGNATURE
        })
        .ok_or_else(|| {
            zip_extract_error("sing-box ZIP end-of-central-directory record is missing")
        })?;
    let entry_count = read_zip_u16(archive_bytes, eocd_offset + 10)? as usize;
    let central_directory_offset = read_zip_u32(archive_bytes, eocd_offset + 16)? as usize;
    let mut cursor = central_directory_offset;

    for _ in 0..entry_count {
        if read_zip_u32(archive_bytes, cursor)? != CENTRAL_DIRECTORY_SIGNATURE {
            return Err(zip_extract_error(
                "sing-box ZIP central-directory entry signature is invalid",
            ));
        }
        let flags = read_zip_u16(archive_bytes, cursor + 8)?;
        let compression = read_zip_u16(archive_bytes, cursor + 10)?;
        let compressed_size = read_zip_u32(archive_bytes, cursor + 20)? as usize;
        let uncompressed_size = read_zip_u32(archive_bytes, cursor + 24)? as usize;
        let name_length = read_zip_u16(archive_bytes, cursor + 28)? as usize;
        let extra_length = read_zip_u16(archive_bytes, cursor + 30)? as usize;
        let comment_length = read_zip_u16(archive_bytes, cursor + 32)? as usize;
        let local_header_offset = read_zip_u32(archive_bytes, cursor + 42)? as usize;
        let name_start = cursor
            .checked_add(46)
            .ok_or_else(|| zip_extract_error("sing-box ZIP entry name offset overflowed"))?;
        let name_end = name_start
            .checked_add(name_length)
            .ok_or_else(|| zip_extract_error("sing-box ZIP entry name length overflowed"))?;
        let name = archive_bytes
            .get(name_start..name_end)
            .ok_or_else(|| zip_extract_error("sing-box ZIP entry name is truncated"))?;
        let matches_executable = name
            .rsplit(|byte| *byte == b'/' || *byte == b'\\')
            .next()
            .and_then(|value| std::str::from_utf8(value).ok())
            == Some(executable_name);

        let next_cursor = name_end
            .checked_add(extra_length)
            .and_then(|value| value.checked_add(comment_length))
            .ok_or_else(|| zip_extract_error("sing-box ZIP central-directory offset overflowed"))?;
        cursor = next_cursor;
        if !matches_executable {
            continue;
        }
        if flags & 0x0001 != 0 {
            return Err(zip_extract_error(
                "sing-box ZIP executable entry is encrypted",
            ));
        }

        if read_zip_u32(archive_bytes, local_header_offset)? != LOCAL_FILE_HEADER_SIGNATURE {
            return Err(zip_extract_error(
                "sing-box ZIP local-file header signature is invalid",
            ));
        }
        let local_name_length = read_zip_u16(archive_bytes, local_header_offset + 26)? as usize;
        let local_extra_length = read_zip_u16(archive_bytes, local_header_offset + 28)? as usize;
        let data_start = local_header_offset
            .checked_add(30)
            .and_then(|value| value.checked_add(local_name_length))
            .and_then(|value| value.checked_add(local_extra_length))
            .ok_or_else(|| zip_extract_error("sing-box ZIP data offset overflowed"))?;
        let data_end = data_start
            .checked_add(compressed_size)
            .ok_or_else(|| zip_extract_error("sing-box ZIP data length overflowed"))?;
        let compressed = archive_bytes
            .get(data_start..data_end)
            .ok_or_else(|| zip_extract_error("sing-box ZIP executable data is truncated"))?;
        let mut executable = Vec::with_capacity(uncompressed_size);
        match compression {
            0 => executable.extend_from_slice(compressed),
            8 => {
                DeflateDecoder::new(Cursor::new(compressed))
                    .read_to_end(&mut executable)
                    .map_err(|error| {
                        zip_extract_error(&format!(
                            "failed to inflate sing-box ZIP executable: {error}"
                        ))
                    })?;
            }
            _ => {
                return Err(zip_extract_error(
                    "sing-box ZIP executable uses an unsupported compression method",
                ));
            }
        }
        if executable.len() != uncompressed_size {
            return Err(zip_extract_error(
                "sing-box ZIP executable size does not match its central-directory record",
            ));
        }
        fs::write(executable_path, executable).map_err(|error| {
            zip_extract_error(&format!("failed to write sing-box ZIP executable: {error}"))
        })?;
        return Ok(());
    }

    Err(zip_extract_error(
        "sing-box executable was not found in the ZIP release archive",
    ))
}

fn read_zip_u16(bytes: &[u8], offset: usize) -> DomainResult<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| zip_extract_error("sing-box ZIP record offset overflowed"))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| zip_extract_error("sing-box ZIP record is truncated"))?;
    Ok(u16::from_le_bytes(value.try_into().unwrap()))
}

fn read_zip_u32(bytes: &[u8], offset: usize) -> DomainResult<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| zip_extract_error("sing-box ZIP record offset overflowed"))?;
    let value = bytes
        .get(offset..end)
        .ok_or_else(|| zip_extract_error("sing-box ZIP record is truncated"))?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}

fn zip_extract_error(message: &str) -> DomainError {
    DomainError::new(ENGINE_SINGBOX_DOWNLOAD_EXTRACT_FAILED_CODE, message)
}

fn verify_sha256_digest(
    bytes: &[u8],
    expected: Option<&str>,
    diagnostics: &mut Vec<Diagnostic>,
) -> DomainResult<()> {
    let Some(expected) = expected else {
        return Ok(());
    };

    let actual = sha256_hex(bytes);
    if actual != expected {
        return Err(DomainError::new(
            ENGINE_SINGBOX_DOWNLOAD_CHECKSUM_MISMATCH_CODE,
            "sing-box release asset sha256 digest did not match GitHub metadata",
        ));
    }

    diagnostics.push(sing_box_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_SINGBOX_DOWNLOAD_CHECKSUM_VERIFIED_CODE,
        "sing-box release asset sha256 digest was verified",
        SOURCE_ENGINE_SINGBOX_DOWNLOAD,
    ));
    Ok(())
}

fn normalize_sha256_digest(digest: Option<&str>) -> Option<String> {
    digest
        .and_then(|value| value.strip_prefix("sha256:"))
        .map(|value| value.to_ascii_lowercase())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let alphabet = b"0123456789abcdef";
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(alphabet[(byte >> 4) as usize] as char);
        output.push(alphabet[(byte & 0x0f) as usize] as char);
    }
    output
}

fn mark_executable(executable_path: &Path) -> DomainResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(executable_path)
            .map_err(|error| {
                DomainError::new(
                    ENGINE_SINGBOX_DOWNLOAD_BINARY_PERMISSION_FAILED_CODE,
                    format!("failed to inspect sing-box executable permissions: {error}"),
                )
            })?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(executable_path, permissions).map_err(|error| {
            DomainError::new(
                ENGINE_SINGBOX_DOWNLOAD_BINARY_PERMISSION_FAILED_CODE,
                format!("failed to mark sing-box executable as runnable: {error}"),
            )
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = executable_path;
    }

    Ok(())
}

fn non_empty_env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn unwired_runtime_error() -> DomainError {
    DomainError::new(
        ENGINE_SINGBOX_RUNTIME_UNWIRED_CODE,
        "sing-box process lifecycle is not wired yet",
    )
}
