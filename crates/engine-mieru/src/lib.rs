//! Explicit external-core contracts for Mieru.
//!
//! This crate does not contain Mieru source or binaries. It parses the
//! operator-provided `mierus://` shape, verifies an explicitly selected local
//! executable, and exposes a process supervisor whose launch arguments are
//! supplied by the caller. Official-release download orchestration remains a
//! separate explicitly authorized operation.

use control_domain::{
    Diagnostic, DiagnosticSeverity, DomainError, DomainResult, Endpoint, MetadataEntry,
    NodeDescriptor, Protocol, ProxyEngineCapability, ProxyEngineConfig, ProxyEngineDescriptor,
    ProxyEngineEvent, ProxyEngineKind, ProxyEngineLifecycleState, ProxyEngineService,
    ProxyEngineStatus,
};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use url::Url;

pub const DEFAULT_MIERU_ENGINE_ID: &str = "mieru";
pub const MIERU_OFFICIAL_REPOSITORY: &str = "enfein/mieru";
pub const MIERU_SHARE_LINK_INVALID_CODE: &str = "engine.mieru.share_link_invalid";
pub const MIERU_BINARY_DIGEST_MISSING_CODE: &str = "engine.mieru.binary_digest_missing";
pub const MIERU_BINARY_DIGEST_MISMATCH_CODE: &str = "engine.mieru.binary_digest_mismatch";
pub const MIERU_BINARY_NOT_REGULAR_FILE_CODE: &str = "engine.mieru.binary_not_regular_file";
pub const MIERU_RUNTIME_UNWIRED_CODE: &str = "engine.mieru.runtime.unwired";
pub const MIERU_PROCESS_ALREADY_RUNNING_CODE: &str = "engine.mieru.process.already_running";
pub const MIERU_PROCESS_START_FAILED_CODE: &str = "engine.mieru.process.start_failed";
pub const MIERU_PROCESS_STATUS_FAILED_CODE: &str = "engine.mieru.process.status_failed";
pub const MIERU_PROCESS_STOP_FAILED_CODE: &str = "engine.mieru.process.stop_failed";
pub const SOURCE_ENGINE_MIERU_CONFIG: &str = "engine.mieru.config";
pub const SOURCE_ENGINE_MIERU_BINARY: &str = "engine.mieru.binary";
pub const SOURCE_ENGINE_MIERU_LIFECYCLE: &str = "engine.mieru.lifecycle";

#[derive(Clone, PartialEq, Eq)]
pub struct MieruNodeConfig {
    pub username: String,
    pub password: String,
    pub server: String,
    pub port: u16,
    pub port_range: Option<String>,
    pub mtu: Option<u16>,
    pub multiplexing: Option<bool>,
    pub handshake_mode: Option<String>,
    pub traffic_pattern: Option<String>,
    pub name: String,
}

impl fmt::Debug for MieruNodeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MieruNodeConfig")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("port_range", &self.port_range)
            .field("mtu", &self.mtu)
            .field("multiplexing", &self.multiplexing)
            .field("handshake_mode", &self.handshake_mode)
            .field("traffic_pattern", &self.traffic_pattern)
            .field("name", &self.name)
            .finish()
    }
}

pub fn parse_mieru_share_link(link: &str) -> DomainResult<MieruNodeConfig> {
    let parsed = Url::parse(link).map_err(|_| invalid_link("mierus link is not a valid URL"))?;
    if parsed.scheme() != "mierus" {
        return Err(invalid_link("mieru share link must use the mierus scheme"));
    }
    let username = parsed.username().trim();
    let password = parsed
        .password()
        .ok_or_else(|| invalid_link("mieru share link must contain credentials"))?;
    if username.is_empty() || password.is_empty() {
        return Err(invalid_link("mieru share link credentials cannot be empty"));
    }
    let server = parsed
        .host_str()
        .filter(|host| !host.trim().is_empty())
        .ok_or_else(|| invalid_link("mieru share link server cannot be empty"))?;
    let port = parsed
        .port()
        .ok_or_else(|| invalid_link("mieru share link must contain a server port"))?;
    let name = parsed
        .fragment()
        .filter(|fragment| !fragment.trim().is_empty())
        .unwrap_or(server)
        .to_string();
    let mut port_range = None;
    let mut mtu = None;
    let mut multiplexing = None;
    let mut handshake_mode = None;
    let mut traffic_pattern = None;
    for (key, value) in parsed.query_pairs() {
        let value = value.into_owned();
        match key.as_ref() {
            "port_range" | "ports" => port_range = Some(non_empty(value, "port range")?),
            "mtu" => mtu = Some(parse_u16(&value, "mtu")?),
            "multiplexing" | "multiplex" => multiplexing = Some(parse_bool(&value)?),
            "handshake_mode" | "handshake" => {
                handshake_mode = Some(non_empty(value, "handshake mode")?)
            }
            "traffic_pattern" | "traffic" => {
                traffic_pattern = Some(non_empty(value, "traffic pattern")?)
            }
            _ => {}
        }
    }

    Ok(MieruNodeConfig {
        username: username.to_string(),
        password: password.to_string(),
        server: server.to_string(),
        port,
        port_range,
        mtu,
        multiplexing,
        handshake_mode,
        traffic_pattern,
        name,
    })
}

impl MieruNodeConfig {
    pub fn to_node_descriptor(&self) -> NodeDescriptor {
        let mut metadata = vec![
            MetadataEntry {
                key: "mieru.username".to_string(),
                value: self.username.clone(),
            },
            MetadataEntry {
                key: "mieru.password".to_string(),
                value: self.password.clone(),
            },
        ];
        for (key, value) in [
            ("mieru.port_range", self.port_range.clone()),
            ("mieru.mtu", self.mtu.map(|value| value.to_string())),
            (
                "mieru.multiplexing",
                self.multiplexing.map(|value| value.to_string()),
            ),
            ("mieru.handshake_mode", self.handshake_mode.clone()),
            ("mieru.traffic_pattern", self.traffic_pattern.clone()),
        ] {
            if let Some(value) = value {
                metadata.push(MetadataEntry {
                    key: key.to_string(),
                    value,
                });
            }
        }
        NodeDescriptor {
            id: format!("mieru-{}-{}", self.server, self.port),
            name: self.name.clone(),
            protocol: Protocol::Mieru,
            endpoint: Endpoint {
                host: self.server.clone(),
                port: self.port,
            },
            tags: vec!["subscription".to_string(), "mieru".to_string()],
            metadata,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruBinaryVerificationReport {
    pub path: PathBuf,
    pub sha256: String,
    pub verified: bool,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn verify_local_mieru_binary(
    path: &Path,
    expected_sha256: Option<&str>,
) -> DomainResult<MieruBinaryVerificationReport> {
    let metadata = fs::metadata(path).map_err(|error| {
        DomainError::new(
            MIERU_BINARY_NOT_REGULAR_FILE_CODE,
            format!("Mieru executable metadata could not be read: {error}"),
        )
    })?;
    if !metadata.is_file() {
        return Err(DomainError::new(
            MIERU_BINARY_NOT_REGULAR_FILE_CODE,
            "Mieru executable must be a regular file",
        ));
    }
    let expected = expected_sha256
        .map(normalize_digest)
        .transpose()?
        .ok_or_else(|| {
            DomainError::new(
                MIERU_BINARY_DIGEST_MISSING_CODE,
                "Mieru executable verification requires an explicit sha256 digest",
            )
        })?;
    let mut file = File::open(path).map_err(|error| {
        DomainError::new(
            MIERU_BINARY_NOT_REGULAR_FILE_CODE,
            format!("Mieru executable could not be opened: {error}"),
        )
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            DomainError::new(
                MIERU_BINARY_NOT_REGULAR_FILE_CODE,
                format!("Mieru executable could not be read: {error}"),
            )
        })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let actual = format!("{digest:x}");
    if actual != expected {
        return Err(DomainError::new(
            MIERU_BINARY_DIGEST_MISMATCH_CODE,
            "Mieru executable sha256 digest does not match the explicit expected digest",
        ));
    }
    Ok(MieruBinaryVerificationReport {
        path: path.to_path_buf(),
        sha256: actual,
        verified: true,
        diagnostics: vec![Diagnostic::new(
            DiagnosticSeverity::Info,
            "engine.mieru.binary_verified",
            "Mieru executable passed explicit sha256 verification",
            Some(SOURCE_ENGINE_MIERU_BINARY.to_string()),
        )],
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruProcessLaunchRequest {
    pub executable_path: PathBuf,
    pub args: Vec<String>,
    pub working_directory: Option<PathBuf>,
    pub log_path: PathBuf,
    pub expected_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MieruManagedProcessState {
    Stopped,
    Running,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruManagedProcessStatus {
    pub state: MieruManagedProcessState,
    pub process_id: Option<u32>,
    pub exit_code: Option<i32>,
}

pub struct MieruManagedProcessSupervisor {
    child: Option<Child>,
    last_status: MieruManagedProcessStatus,
}

impl Default for MieruManagedProcessSupervisor {
    fn default() -> Self {
        Self {
            child: None,
            last_status: MieruManagedProcessStatus {
                state: MieruManagedProcessState::Stopped,
                process_id: None,
                exit_code: None,
            },
        }
    }
}

impl MieruManagedProcessSupervisor {
    pub fn start(
        &mut self,
        request: &MieruProcessLaunchRequest,
    ) -> DomainResult<MieruManagedProcessStatus> {
        if self.status()?.state == MieruManagedProcessState::Running {
            return Err(DomainError::new(
                MIERU_PROCESS_ALREADY_RUNNING_CODE,
                "Mieru managed process is already running",
            ));
        }
        verify_local_mieru_binary(&request.executable_path, Some(&request.expected_sha256))?;
        if let Some(parent) = request.log_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                DomainError::new(
                    MIERU_PROCESS_START_FAILED_CODE,
                    format!("Mieru log directory could not be created: {error}"),
                )
            })?;
        }
        let stdout = File::options()
            .create(true)
            .append(true)
            .open(&request.log_path)
            .map_err(|error| process_error(MIERU_PROCESS_START_FAILED_CODE, error))?;
        let stderr = stdout
            .try_clone()
            .map_err(|error| process_error(MIERU_PROCESS_START_FAILED_CODE, error))?;
        let mut command = Command::new(&request.executable_path);
        command
            .args(&request.args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        if let Some(directory) = &request.working_directory {
            command.current_dir(directory);
        }
        let child = command
            .spawn()
            .map_err(|error| process_error(MIERU_PROCESS_START_FAILED_CODE, error))?;
        let process_id = child.id();
        self.child = Some(child);
        self.last_status = MieruManagedProcessStatus {
            state: MieruManagedProcessState::Running,
            process_id: Some(process_id),
            exit_code: None,
        };
        Ok(self.last_status.clone())
    }

    pub fn status(&mut self) -> DomainResult<MieruManagedProcessStatus> {
        let Some(child) = self.child.as_mut() else {
            return Ok(self.last_status.clone());
        };
        let Some(exit) = child
            .try_wait()
            .map_err(|error| process_error(MIERU_PROCESS_STATUS_FAILED_CODE, error))?
        else {
            return Ok(self.last_status.clone());
        };
        self.child = None;
        self.last_status = MieruManagedProcessStatus {
            state: if exit.success() {
                MieruManagedProcessState::Stopped
            } else {
                MieruManagedProcessState::Failed
            },
            process_id: None,
            exit_code: exit.code(),
        };
        Ok(self.last_status.clone())
    }

    pub fn stop(&mut self) -> DomainResult<MieruManagedProcessStatus> {
        let Some(mut child) = self.child.take() else {
            self.last_status.state = MieruManagedProcessState::Stopped;
            self.last_status.process_id = None;
            return Ok(self.last_status.clone());
        };
        child
            .kill()
            .map_err(|error| process_error(MIERU_PROCESS_STOP_FAILED_CODE, error))?;
        let exit = child
            .wait()
            .map_err(|error| process_error(MIERU_PROCESS_STOP_FAILED_CODE, error))?;
        self.last_status = MieruManagedProcessStatus {
            state: MieruManagedProcessState::Stopped,
            process_id: None,
            exit_code: exit.code(),
        };
        Ok(self.last_status.clone())
    }
}

impl Drop for MieruManagedProcessSupervisor {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MieruProxyEngineService;

impl ProxyEngineService for MieruProxyEngineService {
    fn list_engines(&self) -> Vec<ProxyEngineDescriptor> {
        vec![ProxyEngineDescriptor {
            id: DEFAULT_MIERU_ENGINE_ID.to_string(),
            kind: ProxyEngineKind::Other("mieru-external".to_string()),
            version: Some("external-operator-supplied".to_string()),
            capabilities: vec![ProxyEngineCapability::TcpProxy],
        }]
    }

    fn validate_config(&self, engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
        if engine_config.engine_id != DEFAULT_MIERU_ENGINE_ID {
            return vec![Diagnostic::new(
                DiagnosticSeverity::Error,
                "engine.mieru.config.engine_id_unsupported",
                "Mieru adapter only supports the mieru engine id",
                Some(SOURCE_ENGINE_MIERU_CONFIG.to_string()),
            )];
        }
        vec![Diagnostic::new(
            DiagnosticSeverity::Warning,
            MIERU_RUNTIME_UNWIRED_CODE,
            "Mieru requires an explicitly verified external process launch request",
            Some(SOURCE_ENGINE_MIERU_LIFECYCLE.to_string()),
        )]
    }

    fn start(&self, _engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        Err(DomainError::new(
            MIERU_RUNTIME_UNWIRED_CODE,
            "Mieru adapter lifecycle requires an explicit process launch request",
        ))
    }

    fn reload(&self, _engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        Err(DomainError::new(
            MIERU_RUNTIME_UNWIRED_CODE,
            "Mieru adapter reload is not wired to an external process yet",
        ))
    }

    fn stop(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        Ok(ProxyEngineStatus {
            engine_id: engine_id.to_string(),
            state: ProxyEngineLifecycleState::Stopped,
            diagnostics: vec![Diagnostic::new(
                DiagnosticSeverity::Warning,
                MIERU_RUNTIME_UNWIRED_CODE,
                "Mieru adapter has no owned process for this service instance",
                Some(SOURCE_ENGINE_MIERU_LIFECYCLE.to_string()),
            )],
        })
    }

    fn status(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        self.stop(engine_id)
    }

    fn events(&self, _engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
        Ok(Vec::new())
    }
}

fn invalid_link(message: &str) -> DomainError {
    DomainError::new(MIERU_SHARE_LINK_INVALID_CODE, message)
}

fn non_empty(value: String, field: &str) -> DomainResult<String> {
    if value.trim().is_empty() {
        return Err(invalid_link(&format!("Mieru {field} cannot be empty")));
    }
    Ok(value)
}

fn parse_u16(value: &str, field: &str) -> DomainResult<u16> {
    value
        .parse::<u16>()
        .map_err(|_| invalid_link(&format!("Mieru {field} must be an unsigned 16-bit integer")))
}

fn parse_bool(value: &str) -> DomainResult<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Err(invalid_link("Mieru multiplexing must be a boolean")),
    }
}

fn normalize_digest(value: &str) -> DomainResult<String> {
    let value = value.trim().strip_prefix("sha256:").unwrap_or(value).trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DomainError::new(
            MIERU_BINARY_DIGEST_MISSING_CODE,
            "Mieru executable digest must be a 64-character sha256 hex value",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

fn process_error(code: &'static str, error: impl fmt::Display) -> DomainError {
    DomainError::new(
        code,
        format!("Mieru managed process operation failed: {error}"),
    )
}

#[allow(dead_code)]
fn append_process_log(path: &Path, message: &str) -> DomainResult<()> {
    let mut file = File::options()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| process_error(MIERU_PROCESS_START_FAILED_CODE, error))?;
    writeln!(file, "{message}")
        .map_err(|error| process_error(MIERU_PROCESS_START_FAILED_CODE, error))
}
