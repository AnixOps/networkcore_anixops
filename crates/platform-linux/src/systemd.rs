//! Pure systemd unit generation plans.
//!
//! Rendering a unit is not installation. A future CLI must require an explicit
//! `install-service --confirm` action before writing the returned content.

use control_domain::{DomainError, DomainResult};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const LINUX_SYSTEMD_UNIT_SCHEMA_VERSION: u32 = 1;
pub const LINUX_SYSTEMD_UNIT_INVALID_CODE: &str = "platform.linux.systemd.unit_invalid";
pub const LINUX_SYSTEMD_REMOVAL_INVALID_CODE: &str = "platform.linux.systemd.removal_invalid";
pub const LINUX_SYSTEMD_UNIT_WRITE_FAILED_CODE: &str = "platform.linux.systemd.unit_write_failed";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxManagedServiceUnitRequest {
    pub unit_name: String,
    pub description: String,
    pub executable_path: PathBuf,
    pub arguments: Vec<String>,
    pub service_user: String,
    pub service_group: String,
    pub state_directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxManagedServiceUnitPlan {
    pub schema_version: u32,
    pub unit_name: String,
    pub content: String,
    pub install_confirmation_required: bool,
    pub restart_policy: String,
    pub start_limit_burst: u32,
    pub start_limit_interval_seconds: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxManagedServiceUnitRemovalPlan {
    pub schema_version: u32,
    pub unit_name: String,
    pub unit_path: PathBuf,
    pub confirmation_required: bool,
    pub purge_confirmation_required: bool,
    pub preserved_state_directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxManagedServiceUnitInstallRequest {
    pub unit_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxManagedServiceUnitInstallReport {
    pub unit_path: PathBuf,
    pub snapshot_path: Option<PathBuf>,
    pub snapshot_written: bool,
    pub bytes_written: usize,
    pub verified: bool,
}

pub fn install_systemd_unit(
    request: &LinuxManagedServiceUnitInstallRequest,
) -> DomainResult<LinuxManagedServiceUnitInstallReport> {
    validate_install_request(request)?;
    reject_symlink(&request.unit_path)?;
    let existing = if request.unit_path.exists() {
        Some(
            fs::read(&request.unit_path)
                .map_err(|error| write_error("read existing unit", error))?,
        )
    } else {
        None
    };

    if let Some(contents) = &existing {
        write_new_bytes(&request.snapshot_path, contents)
            .map_err(|error| write_error("write unit snapshot", error))?;
    }

    let temporary_path = request
        .unit_path
        .with_extension(format!("service.networkcore-{}.tmp", std::process::id()));
    let write_result = write_new_bytes(&temporary_path, request.content.as_bytes())
        .and_then(|_| fs::rename(&temporary_path, &request.unit_path));
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);
        if let Some(contents) = existing.as_ref() {
            let _ = fs::write(&request.unit_path, contents);
        }
        return Err(write_error("write systemd unit", error));
    }

    let verified = match fs::read(&request.unit_path) {
        Ok(contents) => contents == request.content.as_bytes(),
        Err(error) => {
            if let Some(contents) = existing.as_ref() {
                let _ = fs::write(&request.unit_path, contents);
            } else {
                let _ = fs::remove_file(&request.unit_path);
            }
            return Err(write_error("verify systemd unit", error));
        }
    };
    if !verified {
        if let Some(contents) = existing.as_ref() {
            let _ = fs::write(&request.unit_path, contents);
        } else {
            let _ = fs::remove_file(&request.unit_path);
        }
        return Err(DomainError::new(
            LINUX_SYSTEMD_UNIT_WRITE_FAILED_CODE,
            "written systemd unit did not match the requested content",
        ));
    }

    Ok(LinuxManagedServiceUnitInstallReport {
        unit_path: request.unit_path.clone(),
        snapshot_path: existing.as_ref().map(|_| request.snapshot_path.clone()),
        snapshot_written: existing.is_some(),
        bytes_written: request.content.len(),
        verified,
    })
}

pub fn plan_systemd_unit_removal(
    unit_name: &str,
    state_directory: &Path,
) -> DomainResult<LinuxManagedServiceUnitRemovalPlan> {
    if unit_name.trim().is_empty()
        || unit_name.contains('/')
        || unit_name.chars().any(char::is_whitespace)
        || !state_directory.is_absolute()
    {
        return Err(DomainError::new(
            LINUX_SYSTEMD_REMOVAL_INVALID_CODE,
            "systemd removal requires a named unit and an absolute state directory",
        ));
    }
    Ok(LinuxManagedServiceUnitRemovalPlan {
        schema_version: LINUX_SYSTEMD_UNIT_SCHEMA_VERSION,
        unit_name: unit_name.to_string(),
        unit_path: PathBuf::from("/etc/systemd/system").join(unit_name),
        confirmation_required: true,
        purge_confirmation_required: true,
        preserved_state_directory: state_directory.to_path_buf(),
    })
}

pub fn render_systemd_unit(
    request: &LinuxManagedServiceUnitRequest,
) -> DomainResult<LinuxManagedServiceUnitPlan> {
    validate_request(request)?;
    let exec_start = std::iter::once(request.executable_path.as_path())
        .map(systemd_quote_path)
        .chain(
            request
                .arguments
                .iter()
                .map(|argument| systemd_quote(argument)),
        )
        .collect::<Vec<_>>()
        .join(" ");
    let state_directory = systemd_quote_path(&request.state_directory);
    let content = format!(
        "[Unit]\nDescription={}\nAfter=network-online.target\nWants=network-online.target\nStartLimitIntervalSec=60\nStartLimitBurst=3\n\n[Service]\nType=simple\nUser={}\nGroup={}\nWorkingDirectory={}\nEnvironment=NETWORKCORE_STATE_DIR={}\nExecStart={}\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\nReadWritePaths={}\nRestart=on-failure\nRestartSec=5s\n\n[Install]\nWantedBy=multi-user.target\n",
        systemd_quote(&request.description),
        systemd_quote(&request.service_user),
        systemd_quote(&request.service_group),
        state_directory,
        state_directory,
        exec_start,
        state_directory,
    );
    Ok(LinuxManagedServiceUnitPlan {
        schema_version: LINUX_SYSTEMD_UNIT_SCHEMA_VERSION,
        unit_name: request.unit_name.clone(),
        content,
        install_confirmation_required: true,
        restart_policy: "on-failure".to_string(),
        start_limit_burst: 3,
        start_limit_interval_seconds: 60,
    })
}

fn validate_request(request: &LinuxManagedServiceUnitRequest) -> DomainResult<()> {
    if request.unit_name.trim().is_empty()
        || request.unit_name.contains('/')
        || request.unit_name.chars().any(char::is_whitespace)
        || request.description.trim().is_empty()
        || request.service_user.trim().is_empty()
        || request.service_group.trim().is_empty()
        || request.service_user == "root"
        || request.service_group == "root"
        || !request.executable_path.is_absolute()
        || !request.state_directory.is_absolute()
    {
        return Err(DomainError::new(
            LINUX_SYSTEMD_UNIT_INVALID_CODE,
            "systemd unit requires a named non-root service, absolute executable/state paths, and a valid description",
        ));
    }
    if request
        .arguments
        .iter()
        .chain(std::iter::once(&request.description))
        .any(|value| value.contains('\n') || value.contains('\r'))
    {
        return Err(DomainError::new(
            LINUX_SYSTEMD_UNIT_INVALID_CODE,
            "systemd unit arguments and description must not contain line breaks",
        ));
    }
    Ok(())
}

fn validate_install_request(request: &LinuxManagedServiceUnitInstallRequest) -> DomainResult<()> {
    if !request.unit_path.is_absolute()
        || !request.snapshot_path.is_absolute()
        || request.unit_path == request.snapshot_path
        || request.content.is_empty()
        || !request.content.contains("[Unit]\n")
        || !request.content.contains("[Service]\n")
    {
        return Err(DomainError::new(
            LINUX_SYSTEMD_UNIT_WRITE_FAILED_CODE,
            "systemd unit write requires distinct absolute paths and rendered unit content",
        ));
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> DomainResult<()> {
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(DomainError::new(
            LINUX_SYSTEMD_UNIT_WRITE_FAILED_CODE,
            format!(
                "refusing to replace symlink systemd unit path: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn write_new_bytes(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

fn write_error(operation: &str, error: impl std::fmt::Display) -> DomainError {
    DomainError::new(
        LINUX_SYSTEMD_UNIT_WRITE_FAILED_CODE,
        format!("failed to {operation}: {error}"),
    )
}

fn systemd_quote_path(path: &Path) -> String {
    systemd_quote(&path.to_string_lossy())
}

fn systemd_quote(value: &str) -> String {
    if value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "_./:-".contains(character))
    {
        return value.to_string();
    }
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
