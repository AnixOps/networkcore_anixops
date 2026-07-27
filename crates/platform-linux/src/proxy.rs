//! Explicit environment-proxy file management for a Linux baseline.
//!
//! This adapter never discovers or edits a default system proxy location. The
//! caller supplies the file and snapshot paths and must explicitly authorize
//! mutations.

use control_domain::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const LINUX_PROXY_SCHEMA_VERSION: u32 = 1;
pub const LINUX_PROXY_INVALID_CODE: &str = "platform.linux.proxy.invalid";
pub const LINUX_PROXY_CONFIRMATION_REQUIRED_CODE: &str =
    "platform.linux.proxy.confirmation_required";
pub const LINUX_PROXY_WRITE_FAILED_CODE: &str = "platform.linux.proxy.write_failed";
pub const LINUX_PROXY_ROLLBACK_FAILED_CODE: &str = "platform.linux.proxy.rollback_failed";
pub const LINUX_PROXY_CONFLICT_CODE: &str = "platform.linux.proxy.external_change";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxEnvironmentProxyApplyRequest {
    pub file_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub proxy_url: String,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxEnvironmentProxyApplyReport {
    pub file_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub previous_exists: bool,
    pub verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxEnvironmentProxyRollbackRequest {
    pub file_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxEnvironmentProxyRollbackReport {
    pub file_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub restored_previous_file: bool,
    pub snapshot_retained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxEnvironmentProxyStatusReport {
    pub file_path: PathBuf,
    pub exists: bool,
    pub managed_schema_version: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnvironmentProxySnapshot {
    schema_version: u32,
    previous_exists: bool,
    previous_contents: String,
    applied_contents: String,
}

pub fn apply_environment_proxy(
    request: &LinuxEnvironmentProxyApplyRequest,
) -> DomainResult<LinuxEnvironmentProxyApplyReport> {
    validate_paths(&request.file_path, &request.snapshot_path)?;
    validate_proxy_url(&request.proxy_url)?;
    if !request.confirmed {
        return Err(DomainError::new(
            LINUX_PROXY_CONFIRMATION_REQUIRED_CODE,
            "environment proxy mutation requires explicit confirmation",
        ));
    }
    reject_symlink(&request.file_path)?;
    if request.snapshot_path.exists() {
        return Err(DomainError::new(
            LINUX_PROXY_WRITE_FAILED_CODE,
            "refusing to overwrite an existing environment proxy snapshot",
        ));
    }

    let (previous_exists, previous_contents) = match fs::read_to_string(&request.file_path) {
        Ok(contents) => (true, contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (false, String::new()),
        Err(error) => return Err(write_error("read environment proxy file", error)),
    };
    let previous_contents_for_recovery = previous_contents.clone();
    let applied_contents = render_environment_proxy_file(&request.proxy_url);
    let snapshot = serde_json::to_string_pretty(&EnvironmentProxySnapshot {
        schema_version: LINUX_PROXY_SCHEMA_VERSION,
        previous_exists,
        previous_contents,
        applied_contents: applied_contents.clone(),
    })
    .map_err(|error| write_error("render environment proxy snapshot", error))?;
    write_new_file(&request.snapshot_path, snapshot.as_bytes())?;

    if let Err(error) = write_atomic_file(&request.file_path, applied_contents.as_bytes()) {
        let _ = fs::remove_file(&request.snapshot_path);
        return Err(write_error("write environment proxy file", error));
    }
    let verified = fs::read_to_string(&request.file_path)
        .map(|contents| contents == applied_contents)
        .map_err(|error| write_error("verify environment proxy file", error))?;
    if !verified {
        let _ = fs::remove_file(&request.file_path);
        if previous_exists {
            let _ = write_atomic_file(
                &request.file_path,
                previous_contents_for_recovery.as_bytes(),
            );
        }
        return Err(DomainError::new(
            LINUX_PROXY_WRITE_FAILED_CODE,
            "written environment proxy file did not match the requested content",
        ));
    }
    Ok(LinuxEnvironmentProxyApplyReport {
        file_path: request.file_path.clone(),
        snapshot_path: request.snapshot_path.clone(),
        previous_exists,
        verified,
    })
}

pub fn rollback_environment_proxy(
    request: &LinuxEnvironmentProxyRollbackRequest,
) -> DomainResult<LinuxEnvironmentProxyRollbackReport> {
    validate_paths(&request.file_path, &request.snapshot_path)?;
    if !request.confirmed {
        return Err(DomainError::new(
            LINUX_PROXY_CONFIRMATION_REQUIRED_CODE,
            "environment proxy rollback requires explicit confirmation",
        ));
    }
    let snapshot_contents = fs::read_to_string(&request.snapshot_path)
        .map_err(|error| rollback_error("read environment proxy snapshot", error))?;
    let snapshot = serde_json::from_str::<EnvironmentProxySnapshot>(&snapshot_contents)
        .map_err(|error| rollback_error("parse environment proxy snapshot", error))?;
    if snapshot.schema_version != LINUX_PROXY_SCHEMA_VERSION {
        return Err(DomainError::new(
            LINUX_PROXY_ROLLBACK_FAILED_CODE,
            "environment proxy snapshot schema version is unsupported",
        ));
    }
    let current = match fs::read_to_string(&request.file_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(rollback_error("read current environment proxy file", error)),
    };
    if current != snapshot.applied_contents {
        return Err(DomainError::new(
            LINUX_PROXY_CONFLICT_CODE,
            "environment proxy file changed outside NetworkCore; refusing rollback",
        ));
    }
    if snapshot.previous_exists {
        write_atomic_file(&request.file_path, snapshot.previous_contents.as_bytes())
            .map_err(|error| rollback_error("restore environment proxy file", error))?;
    } else if request.file_path.exists() {
        fs::remove_file(&request.file_path)
            .map_err(|error| rollback_error("remove NetworkCore environment proxy file", error))?;
    }
    Ok(LinuxEnvironmentProxyRollbackReport {
        file_path: request.file_path.clone(),
        snapshot_path: request.snapshot_path.clone(),
        restored_previous_file: snapshot.previous_exists,
        snapshot_retained: true,
    })
}

pub fn status_environment_proxy(path: &Path) -> DomainResult<LinuxEnvironmentProxyStatusReport> {
    if !path.is_absolute() {
        return Err(DomainError::new(
            LINUX_PROXY_INVALID_CODE,
            "environment proxy status requires an absolute file path",
        ));
    }
    let exists = path.exists();
    let managed_schema_version = if exists {
        fs::read_to_string(path)
            .ok()
            .and_then(|contents| detect_managed_schema(&contents))
    } else {
        None
    };
    Ok(LinuxEnvironmentProxyStatusReport {
        file_path: path.to_path_buf(),
        exists,
        managed_schema_version,
    })
}

fn validate_paths(file_path: &Path, snapshot_path: &Path) -> DomainResult<()> {
    if !file_path.is_absolute() || !snapshot_path.is_absolute() || file_path == snapshot_path {
        return Err(DomainError::new(
            LINUX_PROXY_INVALID_CODE,
            "environment proxy requires distinct absolute file and snapshot paths",
        ));
    }
    Ok(())
}

fn validate_proxy_url(proxy_url: &str) -> DomainResult<()> {
    let valid_scheme = ["http://", "https://", "socks5://", "socks5h://"]
        .iter()
        .any(|scheme| proxy_url.starts_with(scheme));
    if !valid_scheme
        || proxy_url.trim().is_empty()
        || proxy_url
            .chars()
            .any(|character| character == '\n' || character == '\r')
    {
        return Err(DomainError::new(
            LINUX_PROXY_INVALID_CODE,
            "environment proxy URL must use a supported scheme and contain no line breaks",
        ));
    }
    Ok(())
}

fn render_environment_proxy_file(proxy_url: &str) -> String {
    format!(
        "# NetworkCore managed environment proxy\nHTTP_PROXY={proxy_url}\nHTTPS_PROXY={proxy_url}\nALL_PROXY={proxy_url}\nNO_PROXY=127.0.0.1,localhost\n"
    )
}

fn detect_managed_schema(contents: &str) -> Option<u32> {
    contents
        .lines()
        .find(|line| *line == "# NetworkCore managed environment proxy")
        .map(|_| LINUX_PROXY_SCHEMA_VERSION)
}

fn reject_symlink(path: &Path) -> DomainResult<()> {
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(DomainError::new(
            LINUX_PROXY_WRITE_FAILED_CODE,
            "refusing to replace a symlink environment proxy file",
        ));
    }
    Ok(())
}

fn write_new_file(path: &Path, contents: &[u8]) -> DomainResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| write_error("create proxy parent", error))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| write_error("create proxy snapshot", error))?;
    file.write_all(contents)
        .map_err(|error| write_error("write proxy snapshot", error))?;
    set_private_mode(&file)?;
    Ok(())
}

fn write_atomic_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary_path = path.with_extension(format!("networkcore-{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)?;
        file.write_all(contents)?;
        set_private_mode_io(&file)?;
        file.sync_all()?;
        fs::rename(&temporary_path, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result
}

fn write_error(operation: &str, error: impl std::fmt::Display) -> DomainError {
    DomainError::new(
        LINUX_PROXY_WRITE_FAILED_CODE,
        format!("failed to {operation}: {error}"),
    )
}

fn rollback_error(operation: &str, error: impl std::fmt::Display) -> DomainError {
    DomainError::new(
        LINUX_PROXY_ROLLBACK_FAILED_CODE,
        format!("failed to {operation}: {error}"),
    )
}

fn set_private_mode(file: &std::fs::File) -> DomainResult<()> {
    set_private_mode_io(file).map_err(|error| write_error("set proxy file permissions", error))
}

fn set_private_mode_io(_file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        _file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
