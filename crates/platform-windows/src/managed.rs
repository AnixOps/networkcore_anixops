//! Durable configuration and state shared by the Windows GUI and service host.

use control_domain::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION: u32 = 1;
pub const WINDOWS_MANAGED_STATE_SCHEMA_VERSION: u32 = 1;
pub const WINDOWS_MANAGED_CONFIG_INVALID_CODE: &str = "windows.managed.config_invalid";
pub const WINDOWS_MANAGED_CONFIG_IO_CODE: &str = "windows.managed.config_io_failed";
pub const WINDOWS_MANAGED_STATE_IO_CODE: &str = "windows.managed.state_io_failed";
pub const WINDOWS_MANAGED_PRODUCT_DIRECTORY: &str = "AnixOps\\NetworkCore";
pub const WINDOWS_MANAGED_CONFIG_FILE_NAME: &str = "managed-config.json";
pub const WINDOWS_MANAGED_STATE_FILE_NAME: &str = "managed-state.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsProxySettings {
    pub enabled: bool,
    pub server: String,
    pub bypass: String,
}

impl WindowsProxySettings {
    pub fn validate(&self) -> DomainResult<()> {
        if self.enabled && self.server.trim().is_empty() {
            return Err(config_error("enabled system proxy requires a server"));
        }
        if self.server.contains('\0') || self.bypass.contains('\0') {
            return Err(config_error(
                "system proxy values contain an invalid character",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsProxySnapshot {
    pub enabled: bool,
    pub server: String,
    pub bypass: String,
    pub winhttp_access_type: u32,
    pub winhttp_server: String,
    pub winhttp_bypass: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsDriverPackageConfig {
    pub inf_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsManagedTunnelConfig {
    pub client_envelope: PathBuf,
    pub pop_envelope: PathBuf,
    pub pop_id: String,
    pub device_id: String,
    pub delivery_public_key_file: PathBuf,
    pub easytier_binary: PathBuf,
    pub easytier_cli: PathBuf,
    pub easytier_version: String,
    pub easytier_sha256: String,
    pub easytier_cli_sha256: String,
    pub network_name: String,
    pub network_secret_file: PathBuf,
    pub state_path: PathBuf,
}

impl WindowsManagedTunnelConfig {
    pub fn start_arguments(&self) -> Vec<String> {
        vec![
            "tunnel".to_string(),
            "start".to_string(),
            self.client_envelope.to_string_lossy().into_owned(),
            self.pop_envelope.to_string_lossy().into_owned(),
            "--pop-id".to_string(),
            self.pop_id.clone(),
            "--device-id".to_string(),
            self.device_id.clone(),
            "--delivery-public-key-file".to_string(),
            self.delivery_public_key_file.to_string_lossy().into_owned(),
            "--easytier-bin".to_string(),
            self.easytier_binary.to_string_lossy().into_owned(),
            "--easytier-cli".to_string(),
            self.easytier_cli.to_string_lossy().into_owned(),
            "--easytier-version".to_string(),
            self.easytier_version.clone(),
            "--easytier-sha256".to_string(),
            self.easytier_sha256.clone(),
            "--easytier-cli-sha256".to_string(),
            self.easytier_cli_sha256.clone(),
            "--network-name".to_string(),
            self.network_name.clone(),
            "--network-secret-file".to_string(),
            self.network_secret_file.to_string_lossy().into_owned(),
            "--state-path".to_string(),
            self.state_path.to_string_lossy().into_owned(),
            "--confirm".to_string(),
        ]
    }

    pub fn stop_arguments(&self) -> Vec<String> {
        vec![
            "tunnel".to_string(),
            "stop".to_string(),
            self.state_path.to_string_lossy().into_owned(),
            "--confirm".to_string(),
        ]
    }

    fn validate(&self) -> DomainResult<()> {
        let required_text = [
            self.pop_id.as_str(),
            self.device_id.as_str(),
            self.easytier_version.as_str(),
            self.easytier_sha256.as_str(),
            self.easytier_cli_sha256.as_str(),
            self.network_name.as_str(),
        ];
        if required_text.iter().any(|value| value.trim().is_empty()) {
            return Err(config_error("managed tunnel fields must not be empty"));
        }

        let required_paths = [
            self.client_envelope.as_path(),
            self.pop_envelope.as_path(),
            self.delivery_public_key_file.as_path(),
            self.easytier_binary.as_path(),
            self.easytier_cli.as_path(),
            self.network_secret_file.as_path(),
            self.state_path.as_path(),
        ];
        if required_paths
            .iter()
            .any(|path| path.as_os_str().is_empty())
        {
            return Err(config_error("managed tunnel paths must not be empty"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsManagedConfig {
    pub schema_version: u32,
    pub system_proxy: Option<WindowsProxySettings>,
    pub root_certificate_path: Option<PathBuf>,
    pub driver_package: Option<WindowsDriverPackageConfig>,
    pub tunnel: Option<WindowsManagedTunnelConfig>,
}

impl WindowsManagedConfig {
    pub fn validate(&self) -> DomainResult<()> {
        if self.schema_version != WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION {
            return Err(config_error(
                "unsupported managed configuration schema version",
            ));
        }
        if let Some(proxy) = &self.system_proxy {
            proxy.validate()?;
        }
        if let Some(path) = &self.root_certificate_path {
            if path.as_os_str().is_empty() {
                return Err(config_error("root certificate path must not be empty"));
            }
        }
        if let Some(driver) = &self.driver_package {
            if driver.inf_path.as_os_str().is_empty() {
                return Err(config_error("driver INF path must not be empty"));
            }
        }
        if let Some(tunnel) = &self.tunnel {
            tunnel.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsManagedState {
    pub schema_version: u32,
    pub proxy_snapshot: Option<WindowsProxySnapshot>,
    pub certificate_sha1: Option<String>,
    pub driver_inf_path: Option<PathBuf>,
    pub driver_reboot_required: bool,
    pub tunnel_running: bool,
    pub last_transition: String,
}

impl Default for WindowsManagedState {
    fn default() -> Self {
        Self {
            schema_version: WINDOWS_MANAGED_STATE_SCHEMA_VERSION,
            proxy_snapshot: None,
            certificate_sha1: None,
            driver_inf_path: None,
            driver_reboot_required: false,
            tunnel_running: false,
            last_transition: "created".to_string(),
        }
    }
}

pub fn windows_managed_data_directory() -> PathBuf {
    env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join(WINDOWS_MANAGED_PRODUCT_DIRECTORY)
}

pub fn windows_managed_config_path() -> PathBuf {
    windows_managed_data_directory().join(WINDOWS_MANAGED_CONFIG_FILE_NAME)
}

pub fn windows_managed_state_path() -> PathBuf {
    windows_managed_data_directory().join(WINDOWS_MANAGED_STATE_FILE_NAME)
}

pub fn read_managed_config(path: &Path) -> DomainResult<WindowsManagedConfig> {
    let bytes =
        fs::read(path).map_err(|_| config_io_error("managed configuration could not be read"))?;
    let config: WindowsManagedConfig = serde_json::from_slice(&bytes)
        .map_err(|_| config_error("managed configuration is not valid JSON"))?;
    config.validate()?;
    Ok(config)
}

pub fn write_managed_config(path: &Path, config: &WindowsManagedConfig) -> DomainResult<()> {
    config.validate()?;
    write_json_atomic(path, config, WINDOWS_MANAGED_CONFIG_IO_CODE)
}

pub fn read_managed_state(path: &Path) -> DomainResult<WindowsManagedState> {
    let bytes = fs::read(path).map_err(|_| state_io_error("managed state could not be read"))?;
    let state: WindowsManagedState = serde_json::from_slice(&bytes)
        .map_err(|_| state_io_error("managed state is not valid JSON"))?;
    if state.schema_version != WINDOWS_MANAGED_STATE_SCHEMA_VERSION {
        return Err(state_io_error("unsupported managed state schema version"));
    }
    Ok(state)
}

pub fn write_managed_state(path: &Path, state: &WindowsManagedState) -> DomainResult<()> {
    if state.schema_version != WINDOWS_MANAGED_STATE_SCHEMA_VERSION {
        return Err(state_io_error("unsupported managed state schema version"));
    }
    write_json_atomic(path, state, WINDOWS_MANAGED_STATE_IO_CODE)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T, code: &str) -> DomainResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| DomainError::new(code, "managed path has no parent"))?;
    fs::create_dir_all(parent)
        .map_err(|_| DomainError::new(code, "managed data directory could not be created"))?;
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| DomainError::new(code, "managed JSON could not be serialized"))?;
    let temporary = path.with_extension("json.tmp");
    let mut file = fs::File::create(&temporary)
        .map_err(|_| DomainError::new(code, "managed temporary file could not be created"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| DomainError::new(code, "managed temporary file could not be written"))?;
    replace_managed_file(&temporary, path)
        .map_err(|_| DomainError::new(code, "managed file could not be committed"))
}

#[cfg(windows)]
fn replace_managed_file(temporary: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let temporary = temporary
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    if unsafe {
        MoveFileExW(
            temporary.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn replace_managed_file(temporary: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(temporary, destination)
}

fn config_error(message: &str) -> DomainError {
    DomainError::new(WINDOWS_MANAGED_CONFIG_INVALID_CODE, message)
}

fn config_io_error(message: &str) -> DomainError {
    DomainError::new(WINDOWS_MANAGED_CONFIG_IO_CODE, message)
}

fn state_io_error(message: &str) -> DomainError {
    DomainError::new(WINDOWS_MANAGED_STATE_IO_CODE, message)
}
