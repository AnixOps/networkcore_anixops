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
    NODE_METADATA_SHADOWSOCKS_METHOD, NODE_METADATA_SHADOWSOCKS_PASSWORD,
};
use flate2::read::{DeflateDecoder, GzDecoder};
use reqwest::blocking::Client;
use serde::Deserialize;
use serde_json::json;
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
    pub diagnostics: Vec<Diagnostic>,
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

        self.check_configuration(request)?;
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

    fn check_configuration(&self, request: &SingBoxManagedProcessRequest) -> DomainResult<()> {
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
    let node = select_node(&request.nodes, request.selected_node_id.as_deref())?;
    if node.protocol != Protocol::Shadowsocks {
        return Err(DomainError::new(
            ENGINE_SINGBOX_CONFIG_NODE_UNSUPPORTED_CODE,
            "sing-box alpha local proxy config currently supports shadowsocks nodes only",
        ));
    }

    let method = metadata_value(node, NODE_METADATA_SHADOWSOCKS_METHOD).ok_or_else(|| {
        DomainError::new(
            ENGINE_SINGBOX_CONFIG_SECRET_MISSING_CODE,
            "shadowsocks node is missing method metadata",
        )
    })?;
    let password = metadata_value(node, NODE_METADATA_SHADOWSOCKS_PASSWORD).ok_or_else(|| {
        DomainError::new(
            ENGINE_SINGBOX_CONFIG_SECRET_MISSING_CODE,
            "shadowsocks node is missing password metadata",
        )
    })?;

    let config = json!({
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
        "outbounds": [
            {
                "type": "shadowsocks",
                "tag": node.id.as_str(),
                "server": node.endpoint.host.as_str(),
                "server_port": node.endpoint.port,
                "method": method,
                "password": password
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "final": node.id.as_str()
        }
    });
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
        diagnostics: vec![sing_box_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_SINGBOX_CONFIG_RENDERED_CODE,
            "rendered sing-box local mixed inbound config from NetworkCore node catalog",
            SOURCE_ENGINE_SINGBOX_CONFIG,
        )],
    })
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

    Ok(&nodes[0])
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
            8 => DeflateDecoder::new(Cursor::new(compressed))
                .read_to_end(&mut executable)
                .map_err(|error| {
                    zip_extract_error(&format!(
                        "failed to inflate sing-box ZIP executable: {error}"
                    ))
                })?,
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
