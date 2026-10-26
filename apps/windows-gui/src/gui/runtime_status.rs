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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedCoreStatus {
    NotConfigured,
    Starting,
    EmbeddedRunning {
        endpoint: String,
    },
    /// The service recorded a failure after the engine was configured.
    Failed {
        reason: String,
    },
}

impl ManagedCoreStatus {
    pub fn label(&self) -> String {
        match self {
            Self::NotConfigured => "Not configured".to_string(),
            Self::Starting => "Starting".to_string(),
            Self::EmbeddedRunning { endpoint } => format!("Embedded engine running ({endpoint})"),
            Self::Failed { reason } => format!("Stopped: {reason}"),
        }
    }

    pub fn liveness_confirmed(&self) -> Option<bool> {
        match self {
            Self::EmbeddedRunning { .. } => Some(true),
            Self::Failed { .. } => Some(false),
            Self::NotConfigured | Self::Starting => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsRuntimeStatus {
    pub connection: ConnectionState,
    pub service_state: WindowsServiceState,
    pub service_process_id: u32,
    pub service_detail: Option<String>,
    pub core: ManagedCoreStatus,
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
        let issue = self
            .configuration_error
            .as_deref()
            .or(self.last_error.as_deref())
            .map(|error| format!("; issue: {}", error.trim().replace(['\r', '\n'], " ")))
            .unwrap_or_default();
        format!("{service}; core: {}; {proxy}{issue}", self.core.label())
    }
}

/// Reads each available runtime authority independently. A persisted state file
/// helps explain failures, but it never alone establishes a connected state:
/// SCM, the selected core's liveness evidence, and current-user proxy settings
/// are observed as separate facts.
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
    let embedded_listener = config
        .as_ref()
        .ok()
        .and_then(|config| config.embedded.as_ref())
        .filter(|embedded| embedded.enabled)
        .map(|embedded| embedded.listener());
    let embedded_configured = embedded_listener.is_some();
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
    let core = match runtime.as_ref() {
        Some(state) if embedded_configured && state.embedded_running => {
            ManagedCoreStatus::EmbeddedRunning {
                endpoint: state.embedded_listener.clone().unwrap_or_default(),
            }
        }
        Some(state) if embedded_configured && state.last_transition == "starting" => {
            ManagedCoreStatus::Starting
        }
        Some(state) if embedded_configured && state.last_transition == "failed" => {
            ManagedCoreStatus::Failed {
                reason: state
                    .embedded_last_error
                    .clone()
                    .or_else(|| state.last_error.clone())
                    .unwrap_or_else(|| "the embedded engine stopped".to_string()),
            }
        }
        _ => ManagedCoreStatus::NotConfigured,
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
        core_configured: embedded_configured,
        core_configuration_validated: embedded_configured
            && runtime.as_ref().is_some_and(|state| state.embedded_running),
        core_listener_reachable: embedded_configured
            && runtime.as_ref().is_some_and(|state| {
                embedded_listener.as_deref() == state.embedded_listener.as_deref()
            }),
        core_state_recorded_running: embedded_configured
            && runtime.as_ref().is_some_and(|state| state.embedded_running),
        core_liveness_confirmed: core.liveness_confirmed(),
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
        core,
        system_proxy_enabled: proxy.as_ref().ok().map(|value| value.enabled),
        system_proxy_server: proxy.ok().map(|value| value.server),
        system_proxy_matches_managed,
        last_transition: facts.last_transition,
        last_error: facts.last_error,
        configuration_error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_liveness_uses_service_verified_listener_status() {
        let status = ManagedCoreStatus::EmbeddedRunning {
            endpoint: "127.0.0.1:7890".to_string(),
        };

        assert_eq!(status.liveness_confirmed(), Some(true));
        assert_eq!(status.label(), "Embedded engine running (127.0.0.1:7890)");
        assert_eq!(
            ManagedCoreStatus::Failed {
                reason: "listener failed".to_string()
            }
            .liveness_confirmed(),
            Some(false)
        );
    }

    #[test]
    fn status_line_surfaces_a_compact_runtime_error() {
        let status = WindowsRuntimeStatus {
            connection: ConnectionState::CoreError,
            service_state: WindowsServiceState::Running,
            service_process_id: 42,
            service_detail: None,
            core: ManagedCoreStatus::Failed {
                reason: "listener failed".to_string(),
            },
            system_proxy_enabled: Some(false),
            system_proxy_server: None,
            system_proxy_matches_managed: Some(false),
            last_transition: Some("failed".to_string()),
            last_error: Some("listener failed\nport unavailable".to_string()),
            configuration_error: None,
        };

        assert!(status
            .status_line()
            .contains("issue: listener failed port unavailable"));
    }
}
