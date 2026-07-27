//! Systemd unit generation, installation, and explicitly confirmed control.
//!
//! Rendering a unit is not installation. Installation and service control remain
//! separate operations and both require explicit confirmation at the caller.

use control_domain::{DomainError, DomainResult};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const LINUX_SYSTEMD_UNIT_SCHEMA_VERSION: u32 = 1;
pub const LINUX_SYSTEMD_UNIT_INVALID_CODE: &str = "platform.linux.systemd.unit_invalid";
pub const LINUX_SYSTEMD_REMOVAL_INVALID_CODE: &str = "platform.linux.systemd.removal_invalid";
pub const LINUX_SYSTEMD_UNIT_WRITE_FAILED_CODE: &str = "platform.linux.systemd.unit_write_failed";
pub const LINUX_SYSTEMD_UNIT_REMOVE_FAILED_CODE: &str = "platform.linux.systemd.unit_remove_failed";
pub const LINUX_SYSTEMD_CONTROL_FAILED_CODE: &str = "platform.linux.systemd.control_failed";
pub const LINUX_SYSTEMD_CONTROL_CONFIRMATION_REQUIRED_CODE: &str =
    "platform.linux.systemd.control_confirmation_required";
pub const LINUX_SYSTEMD_REFRESH_SCHEDULE_INVALID_CODE: &str =
    "platform.linux.systemd.refresh_schedule_invalid";
pub const LINUX_SYSTEMD_REFRESH_SCHEDULE_CONFLICT_CODE: &str =
    "platform.linux.systemd.refresh_schedule_conflict";

const REFRESH_SCHEDULE_MARKER: &str = "X-NetworkCore-Subscription-Refresh=true";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSubscriptionRefreshScheduleRequest {
    pub unit_name: String,
    pub executable_path: PathBuf,
    pub catalog_path: PathBuf,
    pub status_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub source_id: String,
    pub interval_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSubscriptionRefreshSchedulePlan {
    pub service_name: String,
    pub timer_name: String,
    pub service_content: String,
    pub timer_content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSubscriptionRefreshScheduleReport {
    pub service_name: String,
    pub timer_name: String,
    pub installed: bool,
    pub timer_active: bool,
    pub plan_snapshot_path: PathBuf,
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxManagedServiceUnitRemovalRequest {
    pub unit_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxManagedServiceUnitRemovalReport {
    pub unit_path: PathBuf,
    pub snapshot_path: Option<PathBuf>,
    pub snapshot_written: bool,
    pub removed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxSystemdServiceAction {
    Start,
    Stop,
    Restart,
    Status,
    Reload,
    DaemonReload,
    Enable,
}

impl LinuxSystemdServiceAction {
    pub const fn command(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
            Self::Status => "is-active",
            Self::Reload => "reload",
            Self::DaemonReload => "daemon-reload",
            Self::Enable => "enable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSystemdServiceControlRequest {
    pub unit_name: String,
    pub action: LinuxSystemdServiceAction,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSystemdServiceControlReport {
    pub unit_name: String,
    pub action: LinuxSystemdServiceAction,
    pub succeeded: bool,
    pub exit_code: Option<i32>,
    pub diagnostics: Vec<control_domain::Diagnostic>,
}

pub trait LinuxSystemdCommandRunner {
    fn run(&self, action: LinuxSystemdServiceAction, unit_name: &str) -> DomainResult<Option<i32>>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandLinuxSystemdCommandRunner;

impl CommandLinuxSystemdCommandRunner {
    pub const fn new() -> Self {
        Self
    }
}

impl LinuxSystemdCommandRunner for CommandLinuxSystemdCommandRunner {
    fn run(&self, action: LinuxSystemdServiceAction, unit_name: &str) -> DomainResult<Option<i32>> {
        let status = Command::new("systemctl")
            .arg(action.command())
            .args((action != LinuxSystemdServiceAction::DaemonReload).then_some(unit_name))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| control_error(format!("systemctl could not be started: {error}")))?;
        Ok(status.code())
    }
}

pub fn control_systemd_service<R: LinuxSystemdCommandRunner>(
    runner: &R,
    request: &LinuxSystemdServiceControlRequest,
) -> DomainResult<LinuxSystemdServiceControlReport> {
    validate_unit_name(&request.unit_name)?;
    let requires_confirmation = !matches!(request.action, LinuxSystemdServiceAction::Status);
    if requires_confirmation && !request.confirmed {
        return Err(DomainError::new(
            LINUX_SYSTEMD_CONTROL_CONFIRMATION_REQUIRED_CODE,
            "systemd service control requires explicit confirmation",
        ));
    }
    let exit_code = runner.run(request.action, &request.unit_name)?;
    let succeeded = exit_code == Some(0);
    let diagnostics = vec![control_domain::Diagnostic::new(
        if succeeded {
            control_domain::DiagnosticSeverity::Info
        } else {
            control_domain::DiagnosticSeverity::Error
        },
        if succeeded {
            "platform.linux.systemd.control_completed"
        } else {
            LINUX_SYSTEMD_CONTROL_FAILED_CODE
        },
        format!(
            "systemd {} completed for managed unit with exit code {:?}",
            request.action.command(),
            exit_code
        ),
        Some("platform.linux.systemd".to_string()),
    )];
    Ok(LinuxSystemdServiceControlReport {
        unit_name: request.unit_name.clone(),
        action: request.action,
        succeeded,
        exit_code,
        diagnostics,
    })
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

pub fn remove_systemd_unit(
    request: &LinuxManagedServiceUnitRemovalRequest,
) -> DomainResult<LinuxManagedServiceUnitRemovalReport> {
    if !request.confirmed {
        return Err(DomainError::new(
            LINUX_SYSTEMD_UNIT_REMOVE_FAILED_CODE,
            "systemd unit removal requires explicit confirmation",
        ));
    }
    if !request.unit_path.is_absolute()
        || !request.snapshot_path.is_absolute()
        || request.unit_path == request.snapshot_path
    {
        return Err(DomainError::new(
            LINUX_SYSTEMD_UNIT_REMOVE_FAILED_CODE,
            "systemd unit removal requires distinct absolute paths",
        ));
    }
    reject_symlink(&request.unit_path)
        .map_err(|error| DomainError::new(LINUX_SYSTEMD_UNIT_REMOVE_FAILED_CODE, error.message))?;
    if !request.unit_path.exists() {
        return Ok(LinuxManagedServiceUnitRemovalReport {
            unit_path: request.unit_path.clone(),
            snapshot_path: None,
            snapshot_written: false,
            removed: false,
        });
    }
    let contents =
        fs::read(&request.unit_path).map_err(|error| remove_error("read systemd unit", error))?;
    write_new_bytes(&request.snapshot_path, &contents)
        .map_err(|error| remove_error("write systemd unit snapshot", error))?;
    fs::remove_file(&request.unit_path)
        .map_err(|error| remove_error("remove systemd unit", error))?;
    Ok(LinuxManagedServiceUnitRemovalReport {
        unit_path: request.unit_path.clone(),
        snapshot_path: Some(request.snapshot_path.clone()),
        snapshot_written: true,
        removed: true,
    })
}

pub fn plan_systemd_unit_removal(
    unit_name: &str,
    state_directory: &Path,
) -> DomainResult<LinuxManagedServiceUnitRemovalPlan> {
    if unit_name.trim().is_empty()
        || unit_name.contains('/')
        || unit_name.chars().any(char::is_whitespace)
        || !is_linux_absolute_path(state_directory)
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

pub fn render_subscription_refresh_schedule(
    request: &LinuxSubscriptionRefreshScheduleRequest,
) -> DomainResult<LinuxSubscriptionRefreshSchedulePlan> {
    validate_refresh_schedule_request(request)?;
    let service_name = format!("{}.service", request.unit_name);
    let timer_name = format!("{}.timer", request.unit_name);
    let exec_start = [
        systemd_quote_path(&request.executable_path),
        "subscription".to_string(),
        "refresh".to_string(),
        "start".to_string(),
        "--catalog".to_string(),
        systemd_quote_path(&request.catalog_path),
        "--refresh-status".to_string(),
        systemd_quote_path(&request.status_path),
        "--snapshot".to_string(),
        systemd_quote_path(&request.snapshot_path),
        "--source-id".to_string(),
        systemd_quote(&request.source_id),
        "--interval-seconds".to_string(),
        request.interval_seconds.to_string(),
        "--confirm".to_string(),
    ]
    .join(" ");
    let service_content = format!(
        "[Unit]\nDescription=NetworkCore subscription refresh ({})\n{}\n\n[Service]\nType=oneshot\nExecStart={}\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nProtectHome=true\n",
        request.unit_name, REFRESH_SCHEDULE_MARKER, exec_start,
    );
    let timer_content = format!(
        "[Unit]\nDescription=NetworkCore subscription refresh timer ({})\n{}\n\n[Timer]\nOnBootSec=1min\nOnUnitInactiveSec={}s\nPersistent=true\nUnit={}\n\n[Install]\nWantedBy=timers.target\n",
        request.unit_name, REFRESH_SCHEDULE_MARKER, request.interval_seconds, service_name,
    );
    Ok(LinuxSubscriptionRefreshSchedulePlan {
        service_name,
        timer_name,
        service_content,
        timer_content,
    })
}

pub fn install_subscription_refresh_schedule<R: LinuxSystemdCommandRunner>(
    runner: &R,
    request: &LinuxSubscriptionRefreshScheduleRequest,
) -> DomainResult<LinuxSubscriptionRefreshScheduleReport> {
    let plan = render_subscription_refresh_schedule(request)?;
    let service_path = PathBuf::from("/etc/systemd/system").join(&plan.service_name);
    let timer_path = PathBuf::from("/etc/systemd/system").join(&plan.timer_name);
    reject_symlink(&service_path)?;
    reject_symlink(&timer_path)?;
    if service_path.exists() != timer_path.exists() {
        return Err(DomainError::new(
            LINUX_SYSTEMD_REFRESH_SCHEDULE_CONFLICT_CODE,
            "subscription refresh schedule is incomplete or externally modified",
        ));
    }
    let plan_snapshot_path = request
        .snapshot_path
        .with_extension("schedule-systemd-plan");
    let plan_snapshot = format!("{}\n{}", plan.service_content, plan.timer_content);
    write_owned_schedule_file(&plan_snapshot_path, &plan_snapshot)?;
    let service_changed = write_owned_schedule_file(&service_path, &plan.service_content)?;
    let timer_changed = write_owned_schedule_file(&timer_path, &plan.timer_content)?;
    if service_changed || timer_changed {
        require_systemctl_success(runner, LinuxSystemdServiceAction::DaemonReload, "")?;
    }
    require_systemctl_success(runner, LinuxSystemdServiceAction::Enable, &plan.timer_name)?;
    require_systemctl_success(runner, LinuxSystemdServiceAction::Start, &plan.timer_name)?;
    let timer_active =
        require_systemctl_success(runner, LinuxSystemdServiceAction::Status, &plan.timer_name)?;
    Ok(LinuxSubscriptionRefreshScheduleReport {
        service_name: plan.service_name,
        timer_name: plan.timer_name,
        installed: true,
        timer_active,
        plan_snapshot_path,
    })
}

pub fn stop_subscription_refresh_schedule<R: LinuxSystemdCommandRunner>(
    runner: &R,
    unit_name: &str,
    snapshot_path: &Path,
) -> DomainResult<LinuxSubscriptionRefreshScheduleReport> {
    validate_refresh_schedule_name(unit_name)?;
    let timer_name = format!("{unit_name}.timer");
    let service_name = format!("{unit_name}.service");
    if verify_refresh_schedule_pair(unit_name, snapshot_path)?.is_none() {
        return Ok(LinuxSubscriptionRefreshScheduleReport {
            service_name,
            timer_name,
            installed: false,
            timer_active: false,
            plan_snapshot_path: PathBuf::new(),
        });
    }
    require_systemctl_success(runner, LinuxSystemdServiceAction::Stop, &timer_name)?;
    Ok(LinuxSubscriptionRefreshScheduleReport {
        service_name,
        timer_name,
        installed: true,
        timer_active: false,
        plan_snapshot_path: PathBuf::new(),
    })
}

pub fn uninstall_subscription_refresh_schedule<R: LinuxSystemdCommandRunner>(
    runner: &R,
    unit_name: &str,
    snapshot_path: &Path,
) -> DomainResult<LinuxSubscriptionRefreshScheduleReport> {
    validate_refresh_schedule_name(unit_name)?;
    let service_name = format!("{unit_name}.service");
    let timer_name = format!("{unit_name}.timer");
    let Some((service_path, timer_path)) = verify_refresh_schedule_pair(unit_name, snapshot_path)?
    else {
        return Ok(LinuxSubscriptionRefreshScheduleReport {
            service_name,
            timer_name,
            installed: false,
            timer_active: false,
            plan_snapshot_path: PathBuf::new(),
        });
    };
    require_systemctl_success(runner, LinuxSystemdServiceAction::Stop, &timer_name)?;
    fs::remove_file(&service_path)
        .map_err(|error| remove_error("remove subscription refresh service", error))?;
    fs::remove_file(&timer_path)
        .map_err(|error| remove_error("remove subscription refresh timer", error))?;
    require_systemctl_success(runner, LinuxSystemdServiceAction::DaemonReload, "")?;
    Ok(LinuxSubscriptionRefreshScheduleReport {
        service_name,
        timer_name,
        installed: false,
        timer_active: false,
        plan_snapshot_path: PathBuf::new(),
    })
}

pub fn subscription_refresh_schedule_status<R: LinuxSystemdCommandRunner>(
    runner: &R,
    unit_name: &str,
    snapshot_path: &Path,
) -> DomainResult<LinuxSubscriptionRefreshScheduleReport> {
    validate_refresh_schedule_name(unit_name)?;
    let service_name = format!("{unit_name}.service");
    let timer_name = format!("{unit_name}.timer");
    let installed = verify_refresh_schedule_pair(unit_name, snapshot_path)?.is_some();
    let timer_active = if installed {
        require_systemctl_success(runner, LinuxSystemdServiceAction::Status, &timer_name)?
    } else {
        false
    };
    Ok(LinuxSubscriptionRefreshScheduleReport {
        service_name,
        timer_name,
        installed,
        timer_active,
        plan_snapshot_path: PathBuf::new(),
    })
}

fn validate_refresh_schedule_request(
    request: &LinuxSubscriptionRefreshScheduleRequest,
) -> DomainResult<()> {
    validate_refresh_schedule_name(&request.unit_name)?;
    if request.interval_seconds < 300
        || request.source_id.trim().is_empty()
        || !is_linux_absolute_path(&request.executable_path)
        || !is_linux_absolute_path(&request.catalog_path)
        || !is_linux_absolute_path(&request.status_path)
        || !is_linux_absolute_path(&request.snapshot_path)
        || [
            request.executable_path.to_string_lossy(),
            request.catalog_path.to_string_lossy(),
            request.status_path.to_string_lossy(),
            request.snapshot_path.to_string_lossy(),
        ]
        .iter()
        .any(|value| contains_control(value))
        || contains_control(&request.source_id)
    {
        return Err(DomainError::new(LINUX_SYSTEMD_REFRESH_SCHEDULE_INVALID_CODE, "subscription refresh schedule requires safe absolute paths, a source id, and an interval of at least 300 seconds"));
    }
    Ok(())
}

// The rendered unit is consumed by Linux systemd even when its contract tests run on Windows.
fn is_linux_absolute_path(path: &Path) -> bool {
    path.to_string_lossy().starts_with('/')
}

fn validate_refresh_schedule_name(unit_name: &str) -> DomainResult<()> {
    if unit_name.is_empty()
        || unit_name.contains('.')
        || !unit_name.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '_'
        })
    {
        return Err(DomainError::new(
            LINUX_SYSTEMD_REFRESH_SCHEDULE_INVALID_CODE,
            "subscription refresh unit name must be a simple base name without suffixes",
        ));
    }
    Ok(())
}

fn contains_control(value: &str) -> bool {
    value.chars().any(|character| character.is_control())
}

fn write_owned_schedule_file(path: &Path, content: &str) -> DomainResult<bool> {
    reject_symlink(path)?;
    if path.exists() {
        let existing = fs::read_to_string(path)
            .map_err(|error| write_error("read subscription refresh unit", error))?;
        if existing == content {
            return Ok(false);
        }
        return Err(DomainError::new(
            LINUX_SYSTEMD_REFRESH_SCHEDULE_CONFLICT_CODE,
            "refusing to overwrite an existing subscription refresh unit with different content",
        ));
    }
    fs::write(path, content)
        .map_err(|error| write_error("write subscription refresh unit", error))?;
    Ok(true)
}

fn verify_owned_schedule_file(path: &Path, expected_name: &str) -> DomainResult<bool> {
    reject_symlink(path)?;
    if !path.exists() {
        return Ok(false);
    }
    let content = fs::read_to_string(path)
        .map_err(|error| write_error("read subscription refresh unit", error))?;
    if !content.contains(REFRESH_SCHEDULE_MARKER)
        || path.file_name().is_none_or(|name| name != expected_name)
    {
        return Err(DomainError::new(
            LINUX_SYSTEMD_REFRESH_SCHEDULE_CONFLICT_CODE,
            "refusing to operate on a non-NetworkCore subscription refresh unit",
        ));
    }
    Ok(true)
}

fn verify_refresh_schedule_pair(
    unit_name: &str,
    snapshot_path: &Path,
) -> DomainResult<Option<(PathBuf, PathBuf)>> {
    if !snapshot_path.is_absolute() {
        return Err(DomainError::new(
            LINUX_SYSTEMD_REFRESH_SCHEDULE_INVALID_CODE,
            "subscription refresh schedule requires an absolute plan snapshot path",
        ));
    }
    let service_name = format!("{unit_name}.service");
    let timer_name = format!("{unit_name}.timer");
    let service_path = PathBuf::from("/etc/systemd/system").join(&service_name);
    let timer_path = PathBuf::from("/etc/systemd/system").join(&timer_name);
    let service_exists = verify_owned_schedule_file(&service_path, &service_name)?;
    let timer_exists = verify_owned_schedule_file(&timer_path, &timer_name)?;
    if service_exists != timer_exists {
        return Err(DomainError::new(
            LINUX_SYSTEMD_REFRESH_SCHEDULE_CONFLICT_CODE,
            "subscription refresh schedule is incomplete or externally modified",
        ));
    }
    if !service_exists {
        return Ok(None);
    }
    let expected = fs::read_to_string(snapshot_path.with_extension("schedule-systemd-plan"))
        .map_err(|_| {
            DomainError::new(
                LINUX_SYSTEMD_REFRESH_SCHEDULE_CONFLICT_CODE,
                "subscription refresh schedule plan snapshot is missing",
            )
        })?;
    let current = format!(
        "{}\n{}",
        fs::read_to_string(&service_path)
            .map_err(|error| write_error("read subscription refresh service", error))?,
        fs::read_to_string(&timer_path)
            .map_err(|error| write_error("read subscription refresh timer", error))?
    );
    if current != expected {
        return Err(DomainError::new(
            LINUX_SYSTEMD_REFRESH_SCHEDULE_CONFLICT_CODE,
            "subscription refresh schedule differs from its NetworkCore plan snapshot",
        ));
    }
    Ok(Some((service_path, timer_path)))
}

fn require_systemctl_success<R: LinuxSystemdCommandRunner>(
    runner: &R,
    action: LinuxSystemdServiceAction,
    unit_name: &str,
) -> DomainResult<bool> {
    if runner.run(action, unit_name)? == Some(0) {
        Ok(true)
    } else {
        Err(DomainError::new(
            LINUX_SYSTEMD_CONTROL_FAILED_CODE,
            "systemd subscription refresh schedule operation failed",
        ))
    }
}

fn validate_request(request: &LinuxManagedServiceUnitRequest) -> DomainResult<()> {
    validate_unit_name(&request.unit_name)?;
    if request.description.trim().is_empty()
        || request.service_user.trim().is_empty()
        || request.service_group.trim().is_empty()
        || request.service_user == "root"
        || request.service_group == "root"
        || !is_linux_absolute_path(&request.executable_path)
        || !is_linux_absolute_path(&request.state_directory)
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

fn validate_unit_name(unit_name: &str) -> DomainResult<()> {
    if unit_name.trim().is_empty()
        || unit_name.contains('/')
        || unit_name.chars().any(char::is_whitespace)
    {
        return Err(DomainError::new(
            LINUX_SYSTEMD_UNIT_INVALID_CODE,
            "systemd unit name must be non-empty and contain no slash or whitespace",
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

fn remove_error(operation: &str, error: impl std::fmt::Display) -> DomainError {
    DomainError::new(
        LINUX_SYSTEMD_UNIT_REMOVE_FAILED_CODE,
        format!("failed to {operation}: {error}"),
    )
}

fn control_error(message: impl Into<String>) -> DomainError {
    DomainError::new(LINUX_SYSTEMD_CONTROL_FAILED_CODE, message)
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
