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
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use url::Url;

pub const DEFAULT_MIERU_ENGINE_ID: &str = "mieru";
pub const MIERU_OFFICIAL_REPOSITORY: &str = "enfein/mieru";
pub const MIERU_SHARE_LINK_INVALID_CODE: &str = "engine.mieru.share_link_invalid";
pub const MIERU_BINARY_DIGEST_MISSING_CODE: &str = "engine.mieru.binary_digest_missing";
pub const MIERU_BINARY_DIGEST_MISMATCH_CODE: &str = "engine.mieru.binary_digest_mismatch";
pub const MIERU_BINARY_NOT_REGULAR_FILE_CODE: &str = "engine.mieru.binary_not_regular_file";
pub const MIERU_RELEASE_URL_INVALID_CODE: &str = "engine.mieru.release_url_invalid";
pub const MIERU_RELEASE_DOWNLOAD_NOT_CONFIRMED_CODE: &str =
    "engine.mieru.release_download_not_confirmed";
pub const MIERU_RELEASE_DOWNLOAD_FAILED_CODE: &str = "engine.mieru.release_download_failed";
pub const MIERU_RUNTIME_UNWIRED_CODE: &str = "engine.mieru.runtime.unwired";
pub const MIERU_PROCESS_ALREADY_RUNNING_CODE: &str = "engine.mieru.process.already_running";
pub const MIERU_PROCESS_START_FAILED_CODE: &str = "engine.mieru.process.start_failed";
pub const MIERU_PROCESS_STATUS_FAILED_CODE: &str = "engine.mieru.process.status_failed";
pub const MIERU_PROCESS_STOP_FAILED_CODE: &str = "engine.mieru.process.stop_failed";
pub const MIERU_COMMAND_FAILED_CODE: &str = "engine.mieru.command.failed";
pub const MIERU_CONFIG_INVALID_CODE: &str = "engine.mieru.config.invalid";
pub const MIERU_CONFIG_WRITE_FAILED_CODE: &str = "engine.mieru.config.write_failed";
pub const MIERU_CONFIG_TRAFFIC_PATTERN_DEFERRED_CODE: &str =
    "engine.mieru.config.traffic_pattern_deferred";
pub const MIERU_LISTENER_NOT_READY_CODE: &str = "engine.mieru.listener.not_ready";
pub const MIERU_LISTENER_PROBE_FAILED_CODE: &str = "engine.mieru.listener.probe_failed";
pub const SOURCE_ENGINE_MIERU_CONFIG: &str = "engine.mieru.config";
pub const SOURCE_ENGINE_MIERU_BINARY: &str = "engine.mieru.binary";
pub const SOURCE_ENGINE_MIERU_LIFECYCLE: &str = "engine.mieru.lifecycle";
const MIERU_RELEASE_MAX_BYTES: usize = 256 * 1024 * 1024;

pub trait MieruReleaseHttpClient {
    fn get_bytes(&self, url: &str) -> DomainResult<Vec<u8>>;
}

#[derive(Debug, Clone)]
pub struct ReqwestMieruReleaseHttpClient {
    client: reqwest::blocking::Client,
}

impl ReqwestMieruReleaseHttpClient {
    pub fn new() -> DomainResult<Self> {
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                let host = attempt.url().host_str();
                let allowed = matches!(
                    host,
                    Some("github.com")
                        | Some("www.github.com")
                        | Some("release-assets.githubusercontent.com")
                        | Some("objects.githubusercontent.com")
                );
                if allowed && attempt.previous().len() < 3 {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("networkcore-mieru-adapter")
            .build()
            .map_err(|error| {
                release_download_error(format!("Mieru HTTP client failed: {error}"))
            })?;
        Ok(Self { client })
    }
}

impl MieruReleaseHttpClient for ReqwestMieruReleaseHttpClient {
    fn get_bytes(&self, url: &str) -> DomainResult<Vec<u8>> {
        let mut response = self.client.get(url).send().map_err(|error| {
            release_download_error(format!("Mieru release download failed: {error}"))
        })?;
        if !response.status().is_success() {
            return Err(release_download_error(format!(
                "Mieru release download returned HTTP {}",
                response.status()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MIERU_RELEASE_MAX_BYTES as u64)
        {
            return Err(release_download_error(
                "Mieru release asset exceeds the 256 MiB download limit",
            ));
        }
        let mut bytes = Vec::new();
        response
            .take((MIERU_RELEASE_MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                release_download_error(format!("Mieru release body could not be read: {error}"))
            })?;
        if bytes.len() > MIERU_RELEASE_MAX_BYTES {
            return Err(release_download_error(
                "Mieru release asset exceeds the 256 MiB download limit",
            ));
        }
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruReleaseDownloadRequest {
    pub download_url: String,
    pub destination_path: PathBuf,
    pub expected_sha256: String,
    pub confirmed: bool,
    pub force: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruReleaseDownloadReport {
    pub download_url: String,
    pub destination_path: PathBuf,
    pub sha256: String,
    pub downloaded: bool,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn download_mieru_release<R: MieruReleaseHttpClient>(
    http: &R,
    request: &MieruReleaseDownloadRequest,
) -> DomainResult<MieruReleaseDownloadReport> {
    validate_mieru_release_url(&request.download_url)?;
    if !request.confirmed {
        return Err(DomainError::new(
            MIERU_RELEASE_DOWNLOAD_NOT_CONFIRMED_CODE,
            "Mieru release download requires explicit confirmation",
        ));
    }
    let expected = normalize_digest(&request.expected_sha256)?;
    if !request.destination_path.is_absolute() {
        return Err(release_download_error(
            "Mieru release destination must be an absolute path",
        ));
    }
    if request.destination_path.is_symlink() {
        return Err(release_download_error(
            "refusing to replace symlink Mieru release destination",
        ));
    }

    if request.destination_path.is_file() && !request.force {
        let existing = verify_local_mieru_binary(&request.destination_path, Some(&expected))?;
        return Ok(MieruReleaseDownloadReport {
            download_url: request.download_url.clone(),
            destination_path: existing.path,
            sha256: existing.sha256,
            downloaded: false,
            diagnostics: vec![Diagnostic::new(
                DiagnosticSeverity::Info,
                "engine.mieru.release_binary_already_present",
                "verified existing Mieru release binary",
                Some(SOURCE_ENGINE_MIERU_BINARY.to_string()),
            )],
        });
    }

    let bytes = http.get_bytes(&request.download_url)?;
    let actual = sha256_hex(&bytes);
    if actual != expected {
        return Err(DomainError::new(
            MIERU_BINARY_DIGEST_MISMATCH_CODE,
            "Mieru release asset sha256 digest does not match the explicit expected digest",
        ));
    }
    write_release_binary_atomically(&request.destination_path, &bytes)?;
    Ok(MieruReleaseDownloadReport {
        download_url: request.download_url.clone(),
        destination_path: request.destination_path.clone(),
        sha256: actual,
        downloaded: true,
        diagnostics: vec![Diagnostic::new(
            DiagnosticSeverity::Info,
            "engine.mieru.release_binary_verified",
            "Mieru official release asset was downloaded and sha256 verified",
            Some(SOURCE_ENGINE_MIERU_BINARY.to_string()),
        )],
    })
}

pub fn download_latest_mieru_release(
    request: &MieruReleaseDownloadRequest,
) -> DomainResult<MieruReleaseDownloadReport> {
    let http = ReqwestMieruReleaseHttpClient::new()?;
    download_mieru_release(&http, request)
}

#[derive(Clone, PartialEq, Eq)]
pub struct MieruNodeConfig {
    pub username: String,
    pub password: String,
    pub server: String,
    pub port: u16,
    pub port_range: Option<String>,
    pub additional_ports: Vec<u16>,
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
            .field("additional_ports", &self.additional_ports)
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
    let mut port = parsed.port();
    let name = parsed
        .fragment()
        .filter(|fragment| !fragment.trim().is_empty())
        .unwrap_or(server)
        .to_string();
    let mut port_range = None;
    let mut additional_ports = Vec::new();
    let mut mtu = None;
    let mut multiplexing = None;
    let mut handshake_mode = None;
    let mut traffic_pattern = None;
    for (key, value) in parsed.query_pairs() {
        let value = value.into_owned();
        match key.as_ref() {
            "port" => {
                let value = non_empty(value, "port")?;
                if value.contains('-') {
                    port_range = Some(value.clone());
                    port = Some(parse_range_start(&value)?);
                } else {
                    let parsed_port = parse_u16(&value, "port")?;
                    if port.is_some() {
                        additional_ports.push(parsed_port);
                    } else {
                        port = Some(parsed_port);
                    }
                }
            }
            "port_range" | "ports" => {
                let value = non_empty(value, "port range")?;
                if port.is_none() {
                    port = Some(parse_range_start(&value)?);
                }
                port_range = Some(value);
            }
            "protocol" => {
                if !value.eq_ignore_ascii_case("TCP") {
                    return Err(invalid_link(
                        "Mieru adapter currently accepts only TCP protocol bindings",
                    ));
                }
            }
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
    let port = port
        .ok_or_else(|| invalid_link("mieru share link must contain a server port or query port"))?;

    Ok(MieruNodeConfig {
        username: username.to_string(),
        password: password.to_string(),
        server: server.to_string(),
        port,
        port_range,
        additional_ports,
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
pub struct MieruClientConfigRequest {
    pub node: MieruNodeConfig,
    pub socks5_host: String,
    pub socks5_port: u16,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MieruClientConfigReport {
    pub content: String,
    pub socks5_endpoint: String,
    pub traffic_pattern_deferred: bool,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruClientConfigWriteRequest {
    pub config_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruClientConfigWriteReport {
    pub config_path: PathBuf,
    pub snapshot_path: Option<PathBuf>,
    pub snapshot_written: bool,
    pub bytes_written: usize,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruLocalListenerConfig {
    pub host: String,
    pub port: u16,
}

pub fn read_mieru_local_listener_config(path: &Path) -> DomainResult<MieruLocalListenerConfig> {
    let bytes = fs::read(path).map_err(|error| {
        DomainError::new(
            MIERU_CONFIG_INVALID_CODE,
            format!("Mieru config could not be read for listener verification: {error}"),
        )
    })?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        DomainError::new(
            MIERU_CONFIG_INVALID_CODE,
            format!("Mieru config is not valid JSON: {error}"),
        )
    })?;
    if value
        .get("socks5ListenLAN")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Err(DomainError::new(
            MIERU_CONFIG_INVALID_CODE,
            "Mieru local listener must not enable LAN access",
        ));
    }
    let port = value
        .get("socks5Port")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| {
            DomainError::new(
                MIERU_CONFIG_INVALID_CODE,
                "Mieru config must contain a non-zero socks5Port",
            )
        })?;
    Ok(MieruLocalListenerConfig {
        host: "127.0.0.1".to_string(),
        port,
    })
}

impl fmt::Debug for MieruClientConfigReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MieruClientConfigReport")
            .field("content", &"<redacted>")
            .field("socks5_endpoint", &self.socks5_endpoint)
            .field("traffic_pattern_deferred", &self.traffic_pattern_deferred)
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

pub fn render_mieru_client_config(
    request: &MieruClientConfigRequest,
) -> DomainResult<MieruClientConfigReport> {
    validate_socks5_bind(&request.socks5_host, request.socks5_port)?;
    if let Some(mtu) = request.node.mtu {
        if !(1280..=1400).contains(&mtu) {
            return Err(DomainError::new(
                MIERU_CONFIG_INVALID_CODE,
                "Mieru MTU must be between 1280 and 1400",
            ));
        }
    }

    let mut port_bindings = if let Some(port_range) = &request.node.port_range {
        vec![json!({"protocol": "TCP", "portRange": port_range})]
    } else {
        vec![json!({"protocol": "TCP", "port": request.node.port})]
    };
    port_bindings.extend(
        request
            .node
            .additional_ports
            .iter()
            .map(|port| json!({"protocol": "TCP", "port": port})),
    );
    let mut profile = json!({
        "profileName": "default",
        "user": {
            "name": request.node.username.clone(),
            "password": request.node.password.clone(),
        },
        "servers": [{
            "ipAddress": request.node.server.clone(),
            "portBindings": port_bindings,
        }],
    });
    let object = profile.as_object_mut().ok_or_else(|| {
        DomainError::new(MIERU_CONFIG_INVALID_CODE, "Mieru profile is not an object")
    })?;
    if let Some(mtu) = request.node.mtu {
        object.insert("mtu".to_string(), json!(mtu));
    }
    if let Some(multiplexing) = request.node.multiplexing {
        object.insert(
            "multiplexing".to_string(),
            json!({"level": if multiplexing { "MULTIPLEXING_HIGH" } else { "MULTIPLEXING_OFF" }}),
        );
    }
    if let Some(handshake_mode) = &request.node.handshake_mode {
        object.insert("handshakeMode".to_string(), json!(handshake_mode));
    }

    let config = json!({
        "profiles": [profile],
        "activeProfile": "default",
        "socks5Port": request.socks5_port,
        "socks5ListenLAN": false,
    });
    let mut diagnostics = vec![Diagnostic::new(
        DiagnosticSeverity::Info,
        "engine.mieru.config.rendered",
        "Mieru TCP client configuration was rendered with loopback SOCKS5 output",
        Some(SOURCE_ENGINE_MIERU_CONFIG.to_string()),
    )];
    let traffic_pattern_deferred = request.node.traffic_pattern.is_some();
    if traffic_pattern_deferred {
        diagnostics.push(Diagnostic::new(
            DiagnosticSeverity::Warning,
            MIERU_CONFIG_TRAFFIC_PATTERN_DEFERRED_CODE,
            "Mieru traffic pattern metadata was retained but not expanded into the protobuf configuration object",
            Some(SOURCE_ENGINE_MIERU_CONFIG.to_string()),
        ));
    }
    Ok(MieruClientConfigReport {
        content: serde_json::to_string_pretty(&config).map_err(|error| {
            DomainError::new(
                MIERU_CONFIG_INVALID_CODE,
                format!("Mieru client configuration could not be serialized: {error}"),
            )
        })?,
        socks5_endpoint: format!("{}:{}", request.socks5_host, request.socks5_port),
        traffic_pattern_deferred,
        diagnostics,
    })
}

pub fn write_mieru_client_config(
    request: &MieruClientConfigWriteRequest,
) -> DomainResult<MieruClientConfigWriteReport> {
    if !request.config_path.is_absolute()
        || !request.snapshot_path.is_absolute()
        || request.config_path == request.snapshot_path
        || request.content.is_empty()
    {
        return Err(DomainError::new(
            MIERU_CONFIG_WRITE_FAILED_CODE,
            "Mieru config write requires distinct absolute paths and non-empty content",
        ));
    }
    reject_config_symlink(&request.config_path)?;
    let previous = if request.config_path.exists() {
        Some(
            fs::read(&request.config_path)
                .map_err(|error| config_write_error("read existing Mieru config", error))?,
        )
    } else {
        None
    };
    if let Some(contents) = &previous {
        write_config_new(&request.snapshot_path, contents)?;
    }

    let temporary_path = request
        .config_path
        .with_extension(format!("networkcore-{}.tmp", std::process::id()));
    let write_result =
        write_config_new(&temporary_path, request.content.as_bytes()).and_then(|_| {
            fs::rename(&temporary_path, &request.config_path)
                .map_err(|error| config_write_error("replace Mieru config", error))
        });
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);
        restore_config(&request.config_path, previous.as_deref());
        return Err(error);
    }
    let verified = match fs::read(&request.config_path) {
        Ok(contents) => contents == request.content.as_bytes(),
        Err(error) => {
            restore_config(&request.config_path, previous.as_deref());
            return Err(config_write_error("verify Mieru config", error));
        }
    };
    if !verified {
        restore_config(&request.config_path, previous.as_deref());
        return Err(DomainError::new(
            MIERU_CONFIG_WRITE_FAILED_CODE,
            "written Mieru config did not match the requested content",
        ));
    }
    Ok(MieruClientConfigWriteReport {
        config_path: request.config_path.clone(),
        snapshot_path: previous.as_ref().map(|_| request.snapshot_path.clone()),
        snapshot_written: previous.is_some(),
        bytes_written: request.content.len(),
        verified,
    })
}

fn reject_config_symlink(path: &Path) -> DomainResult<()> {
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(DomainError::new(
            MIERU_CONFIG_WRITE_FAILED_CODE,
            format!(
                "refusing to replace symlink Mieru config path: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn write_config_new(path: &Path, contents: &[u8]) -> DomainResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| config_write_error("create config directory", error))?;
    }
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| config_write_error("create Mieru config file", error))?;
    set_config_permissions(path)?;
    file.write_all(contents)
        .map_err(|error| config_write_error("write Mieru config file", error))?;
    file.sync_all()
        .map_err(|error| config_write_error("sync Mieru config file", error))
}

fn restore_config(path: &Path, previous: Option<&[u8]>) {
    if let Some(contents) = previous {
        let _ = fs::write(path, contents);
        let _ = set_config_permissions(path);
    } else {
        let _ = fs::remove_file(path);
    }
}

fn config_write_error(operation: &str, error: impl fmt::Display) -> DomainError {
    DomainError::new(
        MIERU_CONFIG_WRITE_FAILED_CODE,
        format!("failed to {operation}: {error}"),
    )
}

fn set_config_permissions(path: &Path) -> DomainResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| config_write_error("set Mieru config permissions", error))?;
    }
    Ok(())
}

fn validate_socks5_bind(host: &str, port: u16) -> DomainResult<()> {
    if !matches!(host, "127.0.0.1" | "localhost" | "::1") || port < 1025 {
        return Err(DomainError::new(
            MIERU_CONFIG_INVALID_CODE,
            "Mieru SOCKS5 output must bind to localhost and a port at or above 1025",
        ));
    }
    Ok(())
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruCommandReport {
    pub exit_code: Option<i32>,
    pub succeeded: bool,
    pub diagnostics: Vec<Diagnostic>,
}

pub trait MieruCommandRunner {
    fn run(&self, executable_path: &Path, arguments: &[String])
        -> DomainResult<MieruCommandReport>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandMieruCommandRunner;

impl CommandMieruCommandRunner {
    pub const fn new() -> Self {
        Self
    }
}

impl MieruCommandRunner for CommandMieruCommandRunner {
    fn run(
        &self,
        executable_path: &Path,
        arguments: &[String],
    ) -> DomainResult<MieruCommandReport> {
        let status = Command::new(executable_path)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| process_error(MIERU_COMMAND_FAILED_CODE, error))?;
        let exit_code = status.code();
        Ok(MieruCommandReport {
            exit_code,
            succeeded: status.success(),
            diagnostics: vec![Diagnostic::new(
                if status.success() {
                    DiagnosticSeverity::Info
                } else {
                    DiagnosticSeverity::Error
                },
                if status.success() {
                    "engine.mieru.command.completed"
                } else {
                    MIERU_COMMAND_FAILED_CODE
                },
                format!("Mieru command completed with exit code {exit_code:?}"),
                Some(SOURCE_ENGINE_MIERU_LIFECYCLE.to_string()),
            )],
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruClientControlRequest {
    pub executable_path: PathBuf,
    pub expected_sha256: String,
    pub config_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruClientControlReport {
    pub executable_path: PathBuf,
    pub config_path: PathBuf,
    pub applied: bool,
    pub started: bool,
    pub stopped: bool,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruClientStatusReport {
    pub executable_path: PathBuf,
    pub config_path: PathBuf,
    pub command_succeeded: bool,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruListenerProbeReport {
    pub endpoint: String,
    pub reachable: bool,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn probe_mieru_listener(
    host: &str,
    port: u16,
    timeout: Duration,
) -> DomainResult<MieruListenerProbeReport> {
    if host.trim().is_empty() || port == 0 {
        return Err(DomainError::new(
            MIERU_LISTENER_PROBE_FAILED_CODE,
            "Mieru listener probe requires a non-empty host and non-zero port",
        ));
    }
    let endpoint = format!("{host}:{port}");
    let reachable = endpoint
        .to_socket_addrs()
        .map_err(|error| {
            DomainError::new(
                MIERU_LISTENER_PROBE_FAILED_CODE,
                format!("Mieru listener endpoint could not be resolved: {error}"),
            )
        })?
        .any(|address| TcpStream::connect_timeout(&address, timeout).is_ok());
    Ok(MieruListenerProbeReport {
        endpoint,
        reachable,
        diagnostics: vec![Diagnostic::new(
            if reachable {
                DiagnosticSeverity::Info
            } else {
                DiagnosticSeverity::Warning
            },
            if reachable {
                "engine.mieru.listener.reachable"
            } else {
                MIERU_LISTENER_NOT_READY_CODE
            },
            if reachable {
                "Mieru local SOCKS5 listener is reachable"
            } else {
                "Mieru local SOCKS5 listener is not reachable"
            },
            Some(SOURCE_ENGINE_MIERU_LIFECYCLE.to_string()),
        )],
    })
}

pub fn wait_for_mieru_listener(
    host: &str,
    port: u16,
    timeout: Duration,
) -> DomainResult<MieruListenerProbeReport> {
    let deadline = Instant::now() + timeout;
    loop {
        let report = probe_mieru_listener(host, port, Duration::from_millis(250))?;
        if report.reachable {
            return Ok(report);
        }
        if Instant::now() >= deadline {
            return Err(DomainError::new(
                MIERU_LISTENER_NOT_READY_CODE,
                format!(
                    "Mieru local SOCKS5 listener did not become reachable at {}",
                    report.endpoint
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn apply_and_start_mieru_client<R: MieruCommandRunner>(
    runner: &R,
    request: &MieruClientControlRequest,
) -> DomainResult<MieruClientControlReport> {
    verify_local_mieru_binary(&request.executable_path, Some(&request.expected_sha256))?;
    let apply = runner.run(
        &request.executable_path,
        &[
            "apply".to_string(),
            "config".to_string(),
            request.config_path.display().to_string(),
        ],
    )?;
    if !apply.succeeded {
        return Err(DomainError::new(
            MIERU_COMMAND_FAILED_CODE,
            "Mieru apply config command failed",
        ));
    }
    let start = runner.run(&request.executable_path, &["start".to_string()])?;
    if !start.succeeded {
        return Err(DomainError::new(
            MIERU_COMMAND_FAILED_CODE,
            "Mieru start command failed",
        ));
    }
    let mut diagnostics = apply.diagnostics;
    diagnostics.extend(start.diagnostics);
    Ok(MieruClientControlReport {
        executable_path: request.executable_path.clone(),
        config_path: request.config_path.clone(),
        applied: true,
        started: true,
        stopped: false,
        diagnostics,
    })
}

pub fn stop_mieru_client<R: MieruCommandRunner>(
    runner: &R,
    request: &MieruClientControlRequest,
) -> DomainResult<MieruClientControlReport> {
    verify_local_mieru_binary(&request.executable_path, Some(&request.expected_sha256))?;
    let stop = runner.run(&request.executable_path, &["stop".to_string()])?;
    if !stop.succeeded {
        return Err(DomainError::new(
            MIERU_COMMAND_FAILED_CODE,
            "Mieru stop command failed",
        ));
    }
    Ok(MieruClientControlReport {
        executable_path: request.executable_path.clone(),
        config_path: request.config_path.clone(),
        applied: false,
        started: false,
        stopped: true,
        diagnostics: stop.diagnostics,
    })
}

pub fn status_mieru_client<R: MieruCommandRunner>(
    runner: &R,
    request: &MieruClientControlRequest,
) -> DomainResult<MieruClientStatusReport> {
    verify_local_mieru_binary(&request.executable_path, Some(&request.expected_sha256))?;
    let status = runner.run(&request.executable_path, &["status".to_string()])?;
    if !status.succeeded {
        return Err(DomainError::new(
            MIERU_COMMAND_FAILED_CODE,
            "Mieru status command failed",
        ));
    }
    Ok(MieruClientStatusReport {
        executable_path: request.executable_path.clone(),
        config_path: request.config_path.clone(),
        command_succeeded: true,
        diagnostics: status.diagnostics,
    })
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MieruReadinessReport {
    pub process_status: MieruManagedProcessStatus,
    pub listener_endpoint: String,
    pub listener_reachable: bool,
    pub ready: bool,
    pub diagnostics: Vec<Diagnostic>,
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

    pub fn readiness(
        &mut self,
        host: &str,
        port: u16,
        timeout: std::time::Duration,
    ) -> DomainResult<MieruReadinessReport> {
        let process_status = self.status()?;
        let listener_endpoint = format!("{host}:{port}");
        if process_status.state != MieruManagedProcessState::Running {
            return Ok(MieruReadinessReport {
                process_status,
                listener_endpoint,
                listener_reachable: false,
                ready: false,
                diagnostics: vec![Diagnostic::new(
                    DiagnosticSeverity::Warning,
                    MIERU_LISTENER_NOT_READY_CODE,
                    "Mieru process is not running; local SOCKS5 readiness is false",
                    Some(SOURCE_ENGINE_MIERU_LIFECYCLE.to_string()),
                )],
            });
        }
        let addresses = (host, port).to_socket_addrs().map_err(|error| {
            DomainError::new(
                MIERU_LISTENER_PROBE_FAILED_CODE,
                format!("Mieru local SOCKS5 endpoint could not be resolved: {error}"),
            )
        })?;
        let listener_reachable = addresses
            .into_iter()
            .any(|address| TcpStream::connect_timeout(&address, timeout).is_ok());
        Ok(MieruReadinessReport {
            process_status,
            listener_endpoint,
            listener_reachable,
            ready: listener_reachable,
            diagnostics: vec![Diagnostic::new(
                if listener_reachable {
                    DiagnosticSeverity::Info
                } else {
                    DiagnosticSeverity::Warning
                },
                if listener_reachable {
                    "engine.mieru.listener.ready"
                } else {
                    MIERU_LISTENER_NOT_READY_CODE
                },
                if listener_reachable {
                    "Mieru process and local SOCKS5 listener are ready"
                } else {
                    "Mieru process is running but local SOCKS5 listener is unreachable"
                },
                Some(SOURCE_ENGINE_MIERU_LIFECYCLE.to_string()),
            )],
        })
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

fn parse_range_start(value: &str) -> DomainResult<u16> {
    value
        .split_once('-')
        .map(|(start, _)| start)
        .ok_or_else(|| invalid_link("Mieru port range must use start-end syntax"))
        .and_then(|start| parse_u16(start.trim(), "port range start"))
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

fn validate_mieru_release_url(value: &str) -> DomainResult<()> {
    let url = Url::parse(value).map_err(|_| {
        DomainError::new(
            MIERU_RELEASE_URL_INVALID_CODE,
            "Mieru release URL must be a valid HTTPS URL",
        )
    })?;
    if url.scheme() != "https"
        || url.host_str() != Some("github.com")
        || !url.path().starts_with("/enfein/mieru/releases/download/")
        || url.path().ends_with('/')
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DomainError::new(
            MIERU_RELEASE_URL_INVALID_CODE,
            "Mieru release URL must target an official enfein/mieru GitHub release asset",
        ));
    }
    Ok(())
}

fn write_release_binary_atomically(path: &Path, bytes: &[u8]) -> DomainResult<()> {
    let parent = path.parent().ok_or_else(|| {
        release_download_error("Mieru release destination has no parent directory")
    })?;
    fs::create_dir_all(parent).map_err(|error| {
        release_download_error(format!(
            "Mieru release directory could not be created: {error}"
        ))
    })?;
    let temporary = path.with_extension("download.tmp");
    if temporary.exists() || temporary.is_symlink() {
        return Err(release_download_error(
            "Mieru release temporary path already exists",
        ));
    }
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| {
            release_download_error(format!(
                "Mieru release temporary file could not be created: {error}"
            ))
        })?;
    file.write_all(bytes).map_err(|error| {
        release_download_error(format!(
            "Mieru release temporary file could not be written: {error}"
        ))
    })?;
    file.sync_all().map_err(|error| {
        release_download_error(format!(
            "Mieru release temporary file could not be synced: {error}"
        ))
    })?;
    drop(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o700)).map_err(|error| {
            release_download_error(format!(
                "Mieru release permissions could not be set: {error}"
            ))
        })?;
    }
    fs::rename(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        release_download_error(format!(
            "Mieru release binary could not be installed: {error}"
        ))
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{digest:x}")
}

fn release_download_error(message: impl Into<String>) -> DomainError {
    DomainError::new(MIERU_RELEASE_DOWNLOAD_FAILED_CODE, message)
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
