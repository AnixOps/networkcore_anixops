//! Pure systemd unit generation plans.
//!
//! Rendering a unit is not installation. A future CLI must require an explicit
//! `install-service --confirm` action before writing the returned content.

use control_domain::{DomainError, DomainResult};
use std::path::{Path, PathBuf};

pub const LINUX_SYSTEMD_UNIT_SCHEMA_VERSION: u32 = 1;
pub const LINUX_SYSTEMD_UNIT_INVALID_CODE: &str = "platform.linux.systemd.unit_invalid";

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
