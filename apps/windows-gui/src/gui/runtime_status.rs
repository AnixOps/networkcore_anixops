use super::ui_state::{connection_state, ConnectionState, RuntimeFacts};
use platform_windows::managed::{
    read_managed_config, read_managed_state, windows_managed_config_path,
    windows_managed_state_path,
};
use platform_windows::system_integration::{
    read_current_user_system_proxy, NativeWindowsSystemIntegration, WindowsServiceState,
    WindowsSystemIntegration,
};
use std::path::Path;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, STILL_ACTIVE};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SingBoxProcessStatus {
    NotConfigured,
    Starting,
    Running {
        process_id: u32,
    },
    Exited {
        process_id: u32,
        exit_code: Option<i32>,
    },
    Unavailable {
        process_id: Option<u32>,
        reason: String,
    },
}

impl SingBoxProcessStatus {
    pub fn label(&self) -> String {
        match self {
            Self::NotConfigured => "Not configured".to_string(),
            Self::Starting => "Starting".to_string(),
            Self::Running { process_id } => format!("Running (PID {process_id})"),
            Self::Exited {
                process_id,
                exit_code,
            } => format!(
                "Exited (PID {process_id}{})",
                exit_code
                    .map(|code| format!(", exit {code}"))
                    .unwrap_or_default()
            ),
            Self::Unavailable { reason, .. } => format!("Status unavailable: {reason}"),
        }
    }

    fn process_is_running(&self) -> Option<bool> {
        match self {
            Self::Running { .. } => Some(true),
            Self::Exited { .. } => Some(false),
            Self::Unavailable { .. } | Self::NotConfigured | Self::Starting => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsRuntimeStatus {
    pub connection: ConnectionState,
    pub service_state: WindowsServiceState,
    pub service_process_id: u32,
    pub service_detail: Option<String>,
    pub sing_box: SingBoxProcessStatus,
    pub system_proxy_enabled: Option<bool>,
    pub system_proxy_server: Option<String>,
    pub system_proxy_matches_managed: Option<bool>,
    pub last_transition: Option<String>,
    pub last_error: Option<String>,
    pub configuration_error: Option<String>,
}

impl WindowsRuntimeStatus {
    pub fn status_line(&self) -> String {
        let service = format!("Service: {:?}", self.service_state);
        let proxy = match self.system_proxy_enabled {
            Some(true) => format!(
                "System proxy: On{}",
                self.system_proxy_server
                    .as_deref()
                    .filter(|server| !server.is_empty())
                    .map(|server| format!(" ({server})"))
                    .unwrap_or_default()
            ),
            Some(false) => "System proxy: Off".to_string(),
            None => "System proxy: Unavailable".to_string(),
        };
        let proxy = if self.system_proxy_matches_managed == Some(false) {
            format!("{proxy} (does not match the active profile)")
        } else {
            proxy
        };
        format!("{service}; core: {}; {proxy}", self.sing_box.label())
    }
}

/// Reads each available runtime authority independently. A persisted state file
/// helps explain failures, but it never alone establishes a connected state:
/// SCM, the owned sing-box PID, and current-user proxy settings are observed as
/// separate facts.
pub fn read_runtime_status() -> WindowsRuntimeStatus {
    read_runtime_status_at(
        &windows_managed_config_path(),
        &windows_managed_state_path(),
        &NativeWindowsSystemIntegration::new(),
    )
}

pub fn read_runtime_status_at<I>(
    config_path: &Path,
    state_path: &Path,
    integration: &I,
) -> WindowsRuntimeStatus
where
    I: WindowsSystemIntegration,
{
    let config = read_managed_config(config_path);
    let configuration_error = config.as_ref().err().map(ToString::to_string);
    let sing_box_configured = config
        .as_ref()
        .ok()
        .and_then(|config| config.sing_box.as_ref())
        .is_some_and(|sing_box| sing_box.enabled);
    let managed_proxy = config
        .as_ref()
        .ok()
        .and_then(|config| config.system_proxy.as_ref())
        .filter(|proxy| proxy.enabled);

    let (service_state, service_process_id, service_detail) = match integration.service_status() {
        Ok(status) => (status.state, status.process_id, None),
        Err(error) => (WindowsServiceState::Unknown, 0, Some(error.to_string())),
    };

    let runtime = read_managed_state(state_path).ok();
    let sing_box = match runtime.as_ref() {
        Some(state) if state.sing_box_running => match state.sing_box_process_id {
            Some(process_id) => match probe_process(process_id) {
                Ok(ProcessProbe::Running) => SingBoxProcessStatus::Running { process_id },
                Ok(ProcessProbe::Exited(exit_code)) => SingBoxProcessStatus::Exited {
                    process_id,
                    exit_code: Some(exit_code),
                },
                Err(reason) => SingBoxProcessStatus::Unavailable {
                    process_id: Some(process_id),
                    reason,
                },
            },
            None => SingBoxProcessStatus::Unavailable {
                process_id: None,
                reason: "managed state did not record a core process ID".to_string(),
            },
        },
        Some(state) if sing_box_configured => match state.last_transition.as_str() {
            "starting" => SingBoxProcessStatus::Starting,
            _ => SingBoxProcessStatus::Exited {
                process_id: state.sing_box_process_id.unwrap_or_default(),
                exit_code: state.sing_box_exit_code,
            },
        },
        _ => SingBoxProcessStatus::NotConfigured,
    };

    let proxy = read_current_user_system_proxy();
    let system_proxy_matches_managed = managed_proxy.and_then(|expected| {
        proxy.as_ref().ok().map(|current| {
            current.enabled == expected.enabled
                && current.server == expected.server
                && current.bypass == expected.bypass
        })
    });
    let facts = RuntimeFacts {
        service_state,
        sing_box_configured,
        sing_box_state_recorded_running: runtime
            .as_ref()
            .is_some_and(|state| state.sing_box_running),
        sing_box_process_running: sing_box.process_is_running(),
        system_proxy_matches_managed: system_proxy_matches_managed == Some(true),
        last_transition: runtime.as_ref().map(|state| state.last_transition.clone()),
        last_error: runtime.as_ref().and_then(|state| state.last_error.clone()),
        configuration_error: configuration_error.clone(),
    };

    WindowsRuntimeStatus {
        connection: connection_state(&facts),
        service_state,
        service_process_id,
        service_detail,
        sing_box,
        system_proxy_enabled: proxy.as_ref().ok().map(|value| value.enabled),
        system_proxy_server: proxy.ok().map(|value| value.server),
        system_proxy_matches_managed,
        last_transition: facts.last_transition,
        last_error: facts.last_error,
        configuration_error,
    }
}

enum ProcessProbe {
    Running,
    Exited(i32),
}

fn probe_process(process_id: u32) -> Result<ProcessProbe, String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if handle.is_null() {
        return Err(format!("process query failed (win32={})", unsafe {
            GetLastError()
        }));
    }
    let mut exit_code = 0u32;
    let queried = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
    unsafe {
        CloseHandle(handle);
    }
    if queried == 0 {
        return Err(format!("process exit query failed (win32={})", unsafe {
            GetLastError()
        }));
    }
    if exit_code == STILL_ACTIVE as u32 {
        Ok(ProcessProbe::Running)
    } else {
        Ok(ProcessProbe::Exited(exit_code as i32))
    }
}
