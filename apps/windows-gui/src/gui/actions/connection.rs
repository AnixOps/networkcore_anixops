use crate::gui::{
    load_validated_managed_configuration,
    runtime_status::{read_runtime_status, ManagedCoreStatus},
    startup::{owns_current_proxy, save_desktop_state, DesktopState},
    ui_state::ConnectionState,
};
use engine_singbox::{
    inspect_sing_box_local_selector_controller, read_sing_box_clash_api_selector_with_timeout,
    SingBoxLocalControllerConfig, SingBoxManagedProcessRequest, SingBoxManagedProcessSupervisor,
};
use platform_windows::managed::{
    windows_managed_config_path, WindowsManagedConfig, WindowsProxySettings, WindowsProxySnapshot,
};
use platform_windows::system_integration::{
    managed_proxy_listener_ready, read_current_user_system_proxy, NativeWindowsSystemIntegration,
    WindowsServiceState, WindowsSystemIntegration,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ConnectedProxy {
    pub snapshot: WindowsProxySnapshot,
    pub applied_proxy: WindowsProxySettings,
}

#[derive(Debug)]
pub enum RestartedService {
    Desktop(ConnectedProxy),
    ServiceManaged,
}

struct DesktopConnectionPlan {
    proxy: WindowsProxySettings,
    selector_controller: Option<SingBoxLocalControllerConfig>,
    sing_box: Option<SingBoxManagedProcessRequest>,
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
    core: &ManagedCoreStatus,
    already_attempted: bool,
) -> bool {
    has_proxy_snapshot
        && !already_attempted
        && matches!(
            service_state,
            WindowsServiceState::NotInstalled | WindowsServiceState::Stopped
        )
        && matches!(
            core,
            ManagedCoreStatus::NotConfigured
                | ManagedCoreStatus::Exited { .. }
                | ManagedCoreStatus::Unavailable {
                    process_id: None,
                    ..
                }
        )
}

pub fn connect(config_path: PathBuf, desktop: DesktopState) -> Result<ConnectedProxy, String> {
    let plan = load_desktop_connection_plan(&config_path)?;
    start_desktop_connection(plan, desktop)
}

pub fn connect_direct(
    config_path: PathBuf,
    desktop: DesktopState,
    supervisor: &mut SingBoxManagedProcessSupervisor,
) -> Result<ConnectedProxy, String> {
    let plan = load_desktop_connection_plan(&config_path)?;
    let request = plan.sing_box.clone().ok_or_else(|| {
        "Desktop mode requires an enabled sing-box configuration. Install sing-box and import a compatible profile first."
            .to_string()
    })?;
    supervisor
        .start(&request)
        .map_err(|error| error.to_string())?;

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let listener_ready = managed_proxy_listener_ready(&plan.proxy, Duration::from_millis(500))
            .map_err(|error| error.to_string())?;
        let selector_ready = match plan.selector_controller.as_ref() {
            Some(controller) => read_sing_box_clash_api_selector_with_timeout(
                controller,
                Duration::from_millis(750),
            )
            .is_ok(),
            None => true,
        };
        if listener_ready && selector_ready {
            return apply_proxy_after_direct_readiness(&plan.proxy, desktop, supervisor, &request);
        }
        if supervisor
            .status()
            .map_err(|error| error.to_string())?
            .state
            != engine_singbox::SingBoxManagedProcessState::Running
        {
            let _ = supervisor.stop(&request.log_path);
            return Err("Desktop sing-box process exited before it became ready.".to_string());
        }
        if Instant::now() >= deadline {
            let _ = supervisor.stop(&request.log_path);
            return Err(
                "Timed out waiting for the desktop sing-box proxy and selector controller."
                    .to_string(),
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn disconnect_direct(
    config_path: PathBuf,
    desktop: DesktopState,
    supervisor: &mut SingBoxManagedProcessSupervisor,
) -> Result<String, String> {
    let managed = load_validated_daily_managed_configuration(&config_path)?;
    let integration = NativeWindowsSystemIntegration::new();
    let mut proxy_restored = false;
    if let Some(snapshot) = desktop.proxy_snapshot.as_ref() {
        let current = read_current_user_system_proxy().map_err(|error| error.to_string())?;
        if owns_current_proxy(&desktop, &current) {
            integration
                .restore_system_proxy(snapshot)
                .map_err(|error| error.to_string())?;
            proxy_restored = true;
        }
    }
    if let Some(sing_box) = managed.sing_box {
        supervisor
            .stop(&sing_box.log_path)
            .map_err(|error| error.to_string())?;
    }
    Ok(if proxy_restored {
        "Desktop core stopped and the GUI-owned proxy snapshot was restored.".to_string()
    } else {
        "Desktop core stopped. The current-user proxy was left unchanged because it was not owned by this GUI session.".to_string()
    })
}

pub fn restart(config_path: PathBuf, desktop: DesktopState) -> Result<RestartedService, String> {
    let managed = load_validated_daily_managed_configuration(&config_path)?;
    if managed.system_proxy_owner.is_service_managed() {
        NativeWindowsSystemIntegration::new()
            .restart_service()
            .map_err(|error| error.to_string())?;
        return Ok(RestartedService::ServiceManaged);
    }
    let plan = desktop_connection_plan(managed)?;
    disconnect(desktop.clone())?;
    start_desktop_connection(plan, desktop).map(RestartedService::Desktop)
}

fn load_desktop_connection_plan(config_path: &Path) -> Result<DesktopConnectionPlan, String> {
    desktop_connection_plan(load_validated_daily_managed_configuration(config_path)?)
}

fn load_validated_daily_managed_configuration(
    config_path: &Path,
) -> Result<WindowsManagedConfig, String> {
    let managed_config_path = windows_managed_config_path();
    if config_path != managed_config_path.as_path() {
        return Err(
            "Apply this configuration before connecting or restarting so the Windows service uses the validated file."
                .to_string(),
        );
    }
    load_validated_managed_configuration(config_path)
}

fn desktop_connection_plan(managed: WindowsManagedConfig) -> Result<DesktopConnectionPlan, String> {
    if managed.system_proxy_owner.is_service_managed() {
        return Err(
            "This configuration is managed by the Windows service. Use the explicit advanced workflow or import a daily desktop profile before connecting."
                .to_string(),
        );
    }
    if managed.tunnel.is_some()
        || managed.mieru.as_ref().is_some_and(|mieru| mieru.enabled)
        || managed
            .native_mitm
            .as_ref()
            .is_some_and(|mitm| mitm.enabled)
    {
        return Err(
            "This profile enables a tunnel, Mieru, or HTTPS MITM and must run in Windows service mode."
                .to_string(),
        );
    }
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
    let proxy = managed
        .system_proxy
        .filter(|proxy| proxy.enabled)
        .ok_or_else(|| {
            "Connection requires an enabled managed system proxy. Import a profile or configure one first."
                .to_string()
        })?;
    let sing_box = managed
        .sing_box
        .as_ref()
        .filter(|sing_box| sing_box.enabled)
        .map(|sing_box| SingBoxManagedProcessRequest {
            executable_path: sing_box.executable_path.clone(),
            config_path: sing_box.config_path.clone(),
            working_directory: sing_box.working_directory.clone(),
            log_path: sing_box.log_path.clone(),
        });
    Ok(DesktopConnectionPlan {
        proxy,
        selector_controller,
        sing_box,
    })
}

fn apply_proxy_after_direct_readiness(
    proxy: &WindowsProxySettings,
    mut desktop: DesktopState,
    supervisor: &mut SingBoxManagedProcessSupervisor,
    request: &SingBoxManagedProcessRequest,
) -> Result<ConnectedProxy, String> {
    let integration = NativeWindowsSystemIntegration::new();
    let current = read_current_user_system_proxy().map_err(|error| error.to_string())?;
    let existing_snapshot = owns_current_proxy(&desktop, &current)
        .then(|| desktop.proxy_snapshot.clone())
        .flatten();
    let applied_snapshot = match integration.apply_system_proxy(proxy) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let _ = supervisor.stop(&request.log_path);
            return Err(error.to_string());
        }
    };
    let snapshot = existing_snapshot.unwrap_or(applied_snapshot);
    desktop.proxy_snapshot = Some(snapshot.clone());
    desktop.applied_proxy = Some(proxy.clone());
    if let Err(error) = save_desktop_state(&desktop) {
        let _ = integration.restore_system_proxy(&snapshot);
        let _ = supervisor.stop(&request.log_path);
        return Err(format!(
            "desktop proxy ownership could not be saved after connection: {error}"
        ));
    }
    Ok(ConnectedProxy {
        snapshot,
        applied_proxy: proxy.clone(),
    })
}

fn start_desktop_connection(
    plan: DesktopConnectionPlan,
    desktop: DesktopState,
) -> Result<ConnectedProxy, String> {
    let DesktopConnectionPlan {
        proxy,
        selector_controller,
        ..
    } = plan;
    let integration = NativeWindowsSystemIntegration::new();
    integration
        .start_service()
        .map_err(|error| rollback_failed_connection(&integration, &desktop, error.to_string()))?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut waiting_for = format!("local proxy listener at {}", proxy.server);
    loop {
        let runtime = read_runtime_status();
        if runtime.service_state == WindowsServiceState::Running
            && runtime.core.liveness_confirmed() == Some(true)
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
    use platform_windows::managed::{
        WindowsSystemProxyOwner, WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION,
    };

    fn managed_config(
        owner: WindowsSystemProxyOwner,
        proxy: Option<WindowsProxySettings>,
    ) -> WindowsManagedConfig {
        WindowsManagedConfig {
            schema_version: WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION,
            system_proxy: proxy,
            system_proxy_owner: owner,
            root_certificate_path: None,
            driver_package: None,
            tunnel: None,
            sing_box: None,
            mieru: None,
            native_mitm: None,
        }
    }

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
            &ManagedCoreStatus::Exited {
                process_id: 42,
                exit_code: Some(1),
            },
            false,
        ));
        assert!(!should_restore_abandoned_owned_proxy(
            true,
            WindowsServiceState::Stopped,
            &ManagedCoreStatus::Exited {
                process_id: 42,
                exit_code: Some(1),
            },
            true,
        ));
        assert!(!should_restore_abandoned_owned_proxy(
            true,
            WindowsServiceState::Running,
            &ManagedCoreStatus::Running { process_id: 42 },
            false,
        ));
    }

    #[test]
    fn daily_desktop_restart_requires_an_owned_enabled_proxy_plan() {
        let proxy = WindowsProxySettings {
            enabled: true,
            server: "127.0.0.1:7890".to_string(),
            bypass: "<local>".to_string(),
        };
        let plan = desktop_connection_plan(managed_config(
            WindowsSystemProxyOwner::Desktop,
            Some(proxy.clone()),
        ))
        .expect("daily desktop restart should have a readiness plan");
        assert_eq!(plan.proxy, proxy);

        assert!(
            desktop_connection_plan(managed_config(WindowsSystemProxyOwner::Desktop, None,))
                .is_err()
        );
        assert!(desktop_connection_plan(managed_config(
            WindowsSystemProxyOwner::Service,
            Some(proxy),
        ))
        .is_err());
    }
}
