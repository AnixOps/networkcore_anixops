use crate::gui::{
    runtime_status::{read_runtime_status, SingBoxProcessStatus},
    startup::{owns_current_proxy, save_desktop_state, DesktopState},
    ui_state::ConnectionState,
    validate_managed_configuration,
};
use engine_singbox::{
    inspect_sing_box_local_selector_controller, read_sing_box_clash_api_selector_with_timeout,
};
use platform_windows::managed::{
    read_managed_config, windows_managed_config_path, WindowsProxySettings, WindowsProxySnapshot,
};
use platform_windows::system_integration::{
    managed_proxy_listener_ready, read_current_user_system_proxy, NativeWindowsSystemIntegration,
    WindowsServiceState, WindowsSystemIntegration,
};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ConnectedProxy {
    pub snapshot: WindowsProxySnapshot,
    pub applied_proxy: WindowsProxySettings,
}

pub const fn can_connect(connection: ConnectionState) -> bool {
    !matches!(
        connection,
        ConnectionState::Connected | ConnectionState::Connecting
    )
}

pub const fn can_disconnect(connection: ConnectionState, has_gui_owned_proxy: bool) -> bool {
    has_gui_owned_proxy || !matches!(connection, ConnectionState::Disconnected)
}

pub const fn should_auto_connect(enabled: bool, already_attempted: bool, connected: bool) -> bool {
    enabled && !already_attempted && !connected
}

pub const fn should_restart_gui_started_core(
    enabled: bool,
    already_attempted: bool,
    gui_started_connection: bool,
    connection: ConnectionState,
) -> bool {
    enabled
        && !already_attempted
        && gui_started_connection
        && matches!(connection, ConnectionState::CoreError)
}

pub fn should_restore_abandoned_owned_proxy(
    has_proxy_snapshot: bool,
    service_state: WindowsServiceState,
    sing_box: &SingBoxProcessStatus,
    already_attempted: bool,
) -> bool {
    has_proxy_snapshot
        && !already_attempted
        && matches!(
            service_state,
            WindowsServiceState::NotInstalled | WindowsServiceState::Stopped
        )
        && matches!(
            sing_box,
            SingBoxProcessStatus::NotConfigured
                | SingBoxProcessStatus::Exited { .. }
                | SingBoxProcessStatus::Unavailable {
                    process_id: None,
                    ..
                }
        )
}

pub fn connect(config_path: PathBuf, desktop: DesktopState) -> Result<ConnectedProxy, String> {
    let managed_config_path = windows_managed_config_path();
    if config_path != managed_config_path {
        return Err(
            "Apply this configuration before connecting so the Windows service uses the validated file."
                .to_string(),
        );
    }
    validate_managed_configuration(&config_path)?;
    let managed = read_managed_config(&config_path).map_err(|error| error.to_string())?;
    if managed.system_proxy_owner.is_service_managed() {
        return Err(
            "This configuration is managed by the Windows service. Use the explicit advanced workflow or import a daily desktop profile before connecting."
                .to_string(),
        );
    }
    let proxy = managed
        .system_proxy
        .filter(|proxy| proxy.enabled)
        .ok_or_else(|| {
            "Connection requires an enabled managed system proxy. Import a profile or configure one first."
                .to_string()
        })?;
    let selector_controller = managed
        .sing_box
        .as_ref()
        .filter(|sing_box| sing_box.enabled)
        .map(|sing_box| {
            fs::read_to_string(&sing_box.config_path)
                .map_err(|error| {
                    format!("managed sing-box configuration could not be read: {error}")
                })
                .map(|content| inspect_sing_box_local_selector_controller(&content))
        })
        .transpose()?
        .flatten();
    let integration = NativeWindowsSystemIntegration::new();
    integration
        .start_service()
        .map_err(|error| rollback_failed_connection(&integration, &desktop, error.to_string()))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut waiting_for = format!("local proxy listener at {}", proxy.server);
    loop {
        let runtime = read_runtime_status();
        if runtime.service_state == WindowsServiceState::Running
            && matches!(
                &runtime.sing_box,
                crate::gui::runtime_status::SingBoxProcessStatus::Running { .. }
            )
        {
            let listener_ready = managed_proxy_listener_ready(&proxy, Duration::from_millis(500))
                .map_err(|error| {
                rollback_failed_connection(&integration, &desktop, error.to_string())
            })?;
            if !listener_ready {
                waiting_for = format!("local proxy listener at {}", proxy.server);
            } else if let Some(controller) = selector_controller.as_ref() {
                match read_sing_box_clash_api_selector_with_timeout(
                    controller,
                    Duration::from_millis(750),
                ) {
                    Ok(_) => return apply_proxy_after_readiness(&integration, proxy, desktop),
                    Err(error) => {
                        waiting_for = format!(
                            "sing-box selector controller at {}: {error}",
                            controller.endpoint()
                        );
                    }
                }
            } else {
                return apply_proxy_after_readiness(&integration, proxy, desktop);
            }
        }
        if matches!(
            runtime.connection,
            ConnectionState::CoreError | ConnectionState::ConfigurationError
        ) {
            let message = runtime
                .last_error
                .or(runtime.configuration_error)
                .unwrap_or_else(|| "managed runtime failed before the core was ready".to_string());
            return Err(rollback_failed_connection(&integration, &desktop, message));
        }
        if Instant::now() >= deadline {
            return Err(rollback_failed_connection(
                &integration,
                &desktop,
                format!("timed out waiting for {waiting_for}"),
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn apply_proxy_after_readiness(
    integration: &NativeWindowsSystemIntegration,
    proxy: WindowsProxySettings,
    mut desktop: DesktopState,
) -> Result<ConnectedProxy, String> {
    let current = read_current_user_system_proxy().map_err(|error| {
        rollback_failed_connection(
            integration,
            &desktop,
            format!("current-user proxy could not be read before connection: {error}"),
        )
    })?;
    let existing_snapshot = owns_current_proxy(&desktop, &current)
        .then(|| desktop.proxy_snapshot.clone())
        .flatten();
    let applied_snapshot = integration.apply_system_proxy(&proxy).map_err(|error| {
        rollback_failed_connection(
            integration,
            &desktop,
            format!("system proxy could not be applied after core readiness verification: {error}"),
        )
    })?;
    let snapshot = existing_snapshot.unwrap_or(applied_snapshot);
    desktop.proxy_snapshot = Some(snapshot.clone());
    desktop.applied_proxy = Some(proxy.clone());
    if let Err(error) = save_desktop_state(&desktop) {
        let restore = integration.restore_system_proxy(&snapshot);
        let stopped = integration.stop_service();
        return Err(match (restore, stopped) {
            (Ok(()), Ok(_)) => format!(
                "proxy ownership could not be saved after connection; the proxy was restored: {error}"
            ),
            (restore, stopped) => format!(
                "proxy ownership could not be saved after connection: {error}; rollback result proxy={restore:?} service={stopped:?}"
            ),
        });
    }
    Ok(ConnectedProxy {
        snapshot,
        applied_proxy: proxy,
    })
}

fn rollback_failed_connection(
    integration: &NativeWindowsSystemIntegration,
    desktop: &DesktopState,
    message: String,
) -> String {
    let proxy_result = desktop.proxy_snapshot.as_ref().map_or(Ok(()), |snapshot| {
        let current = read_current_user_system_proxy().map_err(|error| error.to_string())?;
        if owns_current_proxy(desktop, &current) {
            integration
                .restore_system_proxy(snapshot)
                .map_err(|error| error.to_string())?;
        }
        Ok::<(), String>(())
    });
    let service_result = integration
        .stop_service()
        .map(|_| ())
        .map_err(|error| error.to_string());
    match (proxy_result, service_result) {
        (Ok(()), Ok(())) => message,
        (proxy, service) => {
            format!("{message}; cleanup result proxy={proxy:?} service={service:?}")
        }
    }
}

pub fn disconnect(desktop: DesktopState) -> Result<String, String> {
    let integration = NativeWindowsSystemIntegration::new();
    let mut proxy_restored = false;
    if let Some(snapshot) = desktop.proxy_snapshot.clone() {
        let current = read_current_user_system_proxy().map_err(|error| error.to_string())?;
        if owns_current_proxy(&desktop, &current) {
            integration
                .restore_system_proxy(&snapshot)
                .map_err(|error| error.to_string())?;
            proxy_restored = true;
        }
    }
    integration
        .stop_service()
        .map_err(|error| error.to_string())?;
    Ok(if proxy_restored {
        "Service stopped and the GUI-owned desktop proxy snapshot was restored.".to_string()
    } else {
        "Service stopped. The current-user proxy was left unchanged because it was not owned by this GUI session."
            .to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_actions_respect_the_aggregated_runtime_state() {
        assert!(!can_connect(ConnectionState::Connected));
        assert!(!can_connect(ConnectionState::Connecting));
        assert!(can_connect(ConnectionState::CoreError));
        assert!(!can_disconnect(ConnectionState::Disconnected, false));
        assert!(can_disconnect(ConnectionState::CoreError, false));
        assert!(can_disconnect(ConnectionState::Disconnected, true));
    }

    #[test]
    fn controlled_recovery_requires_a_connection_started_by_this_gui_run() {
        assert!(!should_restart_gui_started_core(
            true,
            false,
            false,
            ConnectionState::CoreError,
        ));
        assert!(should_restart_gui_started_core(
            true,
            false,
            true,
            ConnectionState::CoreError,
        ));
        assert!(!should_restart_gui_started_core(
            true,
            true,
            true,
            ConnectionState::CoreError,
        ));
    }

    #[test]
    fn abandoned_gui_proxy_recovery_runs_once_only_after_the_runtime_is_gone() {
        assert!(should_restore_abandoned_owned_proxy(
            true,
            WindowsServiceState::Stopped,
            &SingBoxProcessStatus::Exited {
                process_id: 42,
                exit_code: Some(1),
            },
            false,
        ));
        assert!(!should_restore_abandoned_owned_proxy(
            true,
            WindowsServiceState::Stopped,
            &SingBoxProcessStatus::Exited {
                process_id: 42,
                exit_code: Some(1),
            },
            true,
        ));
        assert!(!should_restore_abandoned_owned_proxy(
            true,
            WindowsServiceState::Running,
            &SingBoxProcessStatus::Running { process_id: 42 },
            false,
        ));
    }
}
