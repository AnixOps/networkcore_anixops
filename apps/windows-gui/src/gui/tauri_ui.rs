use super::actions::connection;
use super::runtime_status::{read_runtime_status, ManagedCoreStatus, WindowsRuntimeStatus};
use super::startup::{
    load_desktop_state, owns_current_proxy, save_desktop_state, DesktopProfileNode,
    DesktopRoutingMode, DesktopRuntimeMode, DesktopState, DesktopSubscriptionSource,
};
use super::{
    append_managed_log, load_validated_managed_configuration, managed_config_or_default,
    profile_node_options, write_diagnostic_report_at,
};
use config_core::routing_import::import_subscription_routing;
use config_core::CoreSubscriptionService;
use control_domain::{NodeDescriptor, SubscriptionService, SubscriptionSource};
use engine_embedded::config::{RuntimeConfig, CONFIG_SCHEMA_VERSION};
use engine_embedded::delay::measure_delay;
use engine_embedded::nodes::{outbound_for_node, routing_envelope, single_node_envelope};
use platform_windows::managed::{
    read_managed_state, windows_managed_config_path, windows_managed_data_directory,
    windows_managed_log_directory, windows_managed_state_path, write_managed_config,
    write_managed_state, write_managed_text_atomic, WindowsManagedConfig,
    WindowsManagedEmbeddedConfig, WindowsManagedNativeMitmConfig, WindowsManagedTunnelConfig,
    WindowsProxySettings, WindowsSystemProxyOwner,
};
use platform_windows::mitm_security::{
    protect_windows_managed_mitm_private_key, remove_windows_managed_mitm_private_key,
};
use platform_windows::system_integration::{
    current_user_startup_enabled, disable_current_user_startup, enable_current_user_startup,
    read_current_user_system_proxy, NativeWindowsSystemIntegration, WindowsServiceState,
    WindowsSystemIntegration,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::{
    fs,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{Manager, Runtime, State, WindowEvent};

const APP_LOG_SCOPE: &str = "tauri-gui";
const MITM_CA_SUBJECT: &str = "AnixOps NetworkCore Windows HTTPS MITM CA";
const SUBSCRIPTION_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);
const NODE_SELECTION_INTERVAL: Duration = Duration::from_secs(30 * 60);
const DEFAULT_NODE_SELECTION_URL: &str = "https://www.gstatic.com/generate_204";
const LOYALSOLDIER_GFW_URL: &str =
    "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/gfw.txt";
const LOYALSOLDIER_CHINA_URL: &str =
    "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/china-list.txt";
const CHINA_IP_URL: &str =
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt";
const ROUTING_RULE_DIRECTORY: &str = "routing-rules";
const EMBEDDED_PROFILE_ID: &str = "windows-tauri-profile";
/// The embedded engine's listener, which is the system proxy unless HTTPS
/// MITM takes that port.
const EMBEDDED_LISTEN_PORT: u16 = 7890;
/// The embedded engine's listener behind HTTPS MITM, which relays to it.
const EMBEDDED_MITM_UPSTREAM_PORT: u16 = 7891;
/// Routed id of a single-outbound profile once a routing mode applies.
const EMBEDDED_PROXY_OUTBOUND: &str = "proxy";
const EMBEDDED_DELAY_TIMEOUT: Duration = Duration::from_secs(5);
/// Nodes the fastest-node search measures at once.
const EMBEDDED_DELAY_PARALLELISM: usize = 16;

#[derive(Clone)]
struct DesktopAppState {
    desktop: Arc<Mutex<DesktopState>>,
    lifecycle: Arc<RuntimeLifecycle>,
    direct_core: Arc<Mutex<connection::DesktopCore>>,
}

struct DesktopTray {
    _icon: TrayIcon,
}

#[derive(Default)]
struct RuntimeLifecycle {
    gui_started_connection: Mutex<bool>,
    core_recovery_attempted: Mutex<bool>,
    subscription_refresh_active: Arc<Mutex<bool>>,
}

struct SubscriptionRefreshGuard {
    active: Arc<Mutex<bool>>,
}

impl Drop for SubscriptionRefreshGuard {
    fn drop(&mut self) {
        if let Ok(mut active) = self.active.lock() {
            *active = false;
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeSnapshot {
    connection: String,
    connection_label: String,
    service: StatusFact,
    core: StatusFact,
    proxy: StatusFact,
    selected_node: Option<String>,
    subscription: Option<String>,
    subscription_last_updated: Option<String>,
    subscription_last_attempt: Option<String>,
    subscription_next_attempt: Option<String>,
    subscription_refresh_result: String,
    subscription_added_node_count: usize,
    subscription_removed_node_count: usize,
    subscription_changed_node_count: usize,
    subscription_refresh_error_code: Option<String>,
    subscription_error: Option<String>,
    last_error: Option<String>,
    configuration_error: Option<String>,
    start_after_login: bool,
    auto_connect: bool,
    auto_recover_core: bool,
    auto_subscription_refresh: bool,
    auto_select_fastest_node: bool,
    bilibili_web_ad_block_enabled: bool,
    script_runtime_configured: bool,
    dark_theme: bool,
    runtime_mode: String,
    routing_mode: String,
    /// The imported profile runs on the embedded engine.
    embedded_engine: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusFact {
    label: String,
    detail: Option<String>,
    tone: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NodeSummary {
    id: String,
    label: String,
    protocol: String,
    selected: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubscriptionSummary {
    id: String,
    location: String,
    selected: bool,
    last_successful_update: Option<String>,
    last_attempt: Option<String>,
    next_attempt: Option<String>,
    result: String,
    added_node_count: usize,
    removed_node_count: usize,
    changed_node_count: usize,
    error_code: Option<String>,
    last_update_error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeGroupSummary {
    tag: String,
    group_type: String,
    selected: Option<String>,
    outbounds: Vec<String>,
    /// Display names for `outbounds`; empty when they are the names.
    outbound_labels: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationResult {
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PreferenceValues {
    start_after_login: bool,
    auto_connect: bool,
    auto_recover_core: bool,
    auto_subscription_refresh: bool,
    auto_select_fastest_node: bool,
    bilibili_web_ad_block_enabled: bool,
    dark_theme: bool,
    runtime_mode: String,
}

pub(super) fn run(debug: bool) -> Result<(), String> {
    let desktop = load_desktop_state()?;
    let _ = append_managed_log(APP_LOG_SCOPE, &format!("startup debug={debug}"));

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main_window(app);
        }))
        .manage(DesktopAppState {
            desktop: Arc::new(Mutex::new(desktop)),
            lifecycle: Arc::new(RuntimeLifecycle::default()),
            direct_core: Arc::new(Mutex::new(connection::DesktopCore::default())),
        })
        .setup(|app| {
            install_tray(app)?;
            show_main_window(app);
            let state = app.state::<DesktopAppState>().inner().clone();
            start_automatic_connection(state.clone());
            start_core_recovery_monitor(state);
            start_subscription_refresh_monitor(app.state::<DesktopAppState>().inner().clone());
            start_fastest_node_monitor(app.state::<DesktopAppState>().inner().clone());
            Ok(())
        })
        .on_page_load(|_webview, payload| {
            let _ = append_managed_log(
                APP_LOG_SCOPE,
                &format!("webview page load {:?}: {}", payload.event(), payload.url()),
            );
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            runtime_snapshot,
            list_nodes,
            list_native_groups,
            list_subscriptions,
            connect,
            disconnect,
            restart_service,
            validate_configuration,
            switch_node,
            select_native_group_outbound,
            test_node_delay,
            select_fastest_node,
            save_preferences,
            create_diagnostics,
            import_subscription,
            update_subscription,
            select_subscription,
            remove_subscription,
            check_profile_runtime,
            install_service,
            start_service,
            stop_service,
            restore_network_settings,
            configure_tunnel,
            clear_tunnel,
            set_routing_mode,
            refresh_routing_rules,
            configure_script_runtime,
            clear_script_runtime,
            enable_https_mitm,
            disable_https_mitm,
            install_certificate,
            remove_certificate,
            install_driver,
            remove_driver,
        ])
        .run(tauri::generate_context!())
        .map_err(|error| error.to_string())
}

fn install_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    let show = MenuItem::with_id(app, "show", "Show NetworkCore", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;
    let icon = app
        .default_window_icon()
        .cloned()
        .ok_or("Tauri default window icon is not configured")?;
    let tray = TrayIconBuilder::with_id("networkcore")
        .icon(icon)
        .tooltip("AnixOps Net")
        .menu(&menu)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main_window(app),
            "quit" => {
                if let Some(state) = app.try_state::<DesktopAppState>() {
                    stop_desktop_core_for_exit(state.inner().clone());
                }
                app.exit(0);
            }
            _ => {}
        })
        .build(app)?;
    app.manage(DesktopTray { _icon: tray });
    Ok(())
}

fn show_main_window<R: Runtime, M: Manager<R>>(app: &M) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn start_automatic_connection(state: DesktopAppState) {
    std::thread::spawn(move || {
        let desktop = match state.desktop.lock() {
            Ok(desktop) => desktop.clone(),
            Err(_) => {
                let _ = append_managed_log(APP_LOG_SCOPE, "automatic connection state lock failed");
                return;
            }
        };
        let runtime = read_runtime_status();
        if !connection::should_auto_connect(
            desktop.auto_connect,
            false,
            runtime.connection.is_connected(),
        ) {
            return;
        }
        match connection::connect(windows_managed_config_path(), desktop) {
            Ok(connected) => match state.desktop.lock() {
                Ok(mut persisted) => {
                    persisted.proxy_snapshot = Some(connected.snapshot);
                    persisted.applied_proxy = Some(connected.applied_proxy);
                    if let Err(error) = save_desktop_state(&persisted) {
                        let _ = append_managed_log(
                            APP_LOG_SCOPE,
                            &format!("automatic connection state save failed: {error}"),
                        );
                    } else {
                        mark_gui_started_connection(&state);
                        let _ = append_managed_log(APP_LOG_SCOPE, "automatic connection completed");
                    }
                }
                Err(_) => {
                    let _ = append_managed_log(
                        APP_LOG_SCOPE,
                        "automatic connection completed but state lock failed",
                    );
                }
            },
            Err(error) => {
                let _ = append_managed_log(
                    APP_LOG_SCOPE,
                    &format!("automatic connection failed: {error}"),
                );
            }
        }
    });
}

fn start_core_recovery_monitor(state: DesktopAppState) {
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(2));
        let desktop = match state.desktop.lock() {
            Ok(desktop) => desktop.clone(),
            Err(_) => continue,
        };
        let runtime = read_runtime_status();
        let should_recover = match (
            state.lifecycle.gui_started_connection.lock(),
            state.lifecycle.core_recovery_attempted.lock(),
        ) {
            (Ok(gui_started), Ok(mut attempted))
                if connection::should_restart_gui_started_core(
                    desktop.auto_recover_core,
                    *attempted,
                    *gui_started,
                    runtime.connection,
                ) =>
            {
                *attempted = true;
                true
            }
            _ => false,
        };
        if !should_recover {
            continue;
        }
        let _ = append_managed_log(APP_LOG_SCOPE, "one controlled core recovery was requested");
        match connection::connect(windows_managed_config_path(), desktop) {
            Ok(connected) => match state.desktop.lock() {
                Ok(mut persisted) => {
                    persisted.proxy_snapshot = Some(connected.snapshot);
                    persisted.applied_proxy = Some(connected.applied_proxy);
                    if let Err(error) = save_desktop_state(&persisted) {
                        let _ = append_managed_log(
                            APP_LOG_SCOPE,
                            &format!("core recovery state save failed: {error}"),
                        );
                    } else {
                        let _ = append_managed_log(
                            APP_LOG_SCOPE,
                            "one controlled core recovery completed",
                        );
                    }
                }
                Err(_) => {
                    let _ = append_managed_log(
                        APP_LOG_SCOPE,
                        "core recovery completed but state lock failed",
                    );
                }
            },
            Err(error) => {
                let _ = append_managed_log(
                    APP_LOG_SCOPE,
                    &format!("one controlled core recovery failed: {error}"),
                );
            }
        }
    });
}

fn start_subscription_refresh_monitor(state: DesktopAppState) {
    std::thread::spawn(move || {
        let mut next_refresh = Instant::now() + SUBSCRIPTION_REFRESH_INTERVAL;
        loop {
            std::thread::sleep(Duration::from_secs(30));
            if Instant::now() < next_refresh {
                continue;
            }
            next_refresh = Instant::now() + SUBSCRIPTION_REFRESH_INTERVAL;
            let location = match state.desktop.lock() {
                Ok(desktop) if desktop.auto_subscription_refresh => {
                    desktop.profile_source_url.clone()
                }
                _ => None,
            };
            let Some(location) = location else {
                continue;
            };
            match import_subscription_blocking(
                state.clone(),
                location,
                "Automatic subscription update completed.",
            ) {
                Ok(_) => {
                    let _ = append_managed_log(
                        APP_LOG_SCOPE,
                        "automatic subscription update completed",
                    );
                }
                Err(error) => {
                    let _ = append_managed_log(
                        APP_LOG_SCOPE,
                        &format!("automatic subscription update skipped or failed: {error}"),
                    );
                }
            }
        }
    });
}

fn start_fastest_node_monitor(state: DesktopAppState) {
    std::thread::spawn(move || {
        let mut next_selection = Instant::now() + NODE_SELECTION_INTERVAL;
        loop {
            std::thread::sleep(Duration::from_secs(30));
            if Instant::now() < next_selection {
                continue;
            }
            next_selection = Instant::now() + NODE_SELECTION_INTERVAL;
            let enabled = state
                .desktop
                .lock()
                .map(|desktop| desktop.auto_select_fastest_node)
                .unwrap_or(false);
            if !enabled || !read_runtime_status().connection.is_connected() {
                continue;
            }
            match select_fastest_node_blocking(state.clone()) {
                Ok(result) => {
                    let _ = append_managed_log(APP_LOG_SCOPE, &result.message);
                }
                Err(error) => {
                    let _ = append_managed_log(
                        APP_LOG_SCOPE,
                        &format!("automatic fastest-node selection skipped or failed: {error}"),
                    );
                }
            }
        }
    });
}

fn mark_gui_started_connection(state: &DesktopAppState) {
    if let Ok(mut started) = state.lifecycle.gui_started_connection.lock() {
        *started = true;
    }
}

fn mark_gui_connection_stopped(state: &DesktopAppState) {
    if let Ok(mut started) = state.lifecycle.gui_started_connection.lock() {
        *started = false;
    }
}

async fn run_blocking<T: Send + 'static>(
    task: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|error| format!("background desktop operation failed: {error}"))?
}

#[tauri::command]
async fn runtime_snapshot(state: State<'_, DesktopAppState>) -> Result<RuntimeSnapshot, String> {
    let state = state.inner().clone();
    run_blocking(move || runtime_snapshot_blocking(state)).await
}

fn runtime_snapshot_blocking(state: DesktopAppState) -> Result<RuntimeSnapshot, String> {
    let desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    let direct_running = state
        .direct_core
        .lock()
        .map_err(|_| "desktop core lock failed")?
        .is_running()?;
    Ok(snapshot(&read_runtime_status(), &desktop, direct_running))
}

#[tauri::command]
fn list_nodes(state: State<'_, DesktopAppState>) -> Result<Vec<NodeSummary>, String> {
    let desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    Ok(desktop
        .profile_node_catalog
        .iter()
        .map(|node| NodeSummary {
            id: node.id.clone(),
            label: node.label.clone(),
            protocol: node.protocol.clone(),
            selected: desktop.profile_node_id.as_deref() == Some(node.id.as_str()),
        })
        .collect())
}

#[tauri::command]
async fn list_native_groups(
    state: State<'_, DesktopAppState>,
) -> Result<Vec<NativeGroupSummary>, String> {
    let state = state.inner().clone();
    run_blocking(move || list_native_groups_blocking(state)).await
}

fn list_native_groups_blocking(state: DesktopAppState) -> Result<Vec<NativeGroupSummary>, String> {
    if active_embedded_config()?.is_none() {
        return Ok(Vec::new());
    }
    let Ok(profile) = read_embedded_profile() else {
        return Ok(Vec::new());
    };
    let desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    Ok(embedded_groups(&profile, &desktop.profile_node_catalog))
}

#[tauri::command]
async fn select_native_group_outbound(
    group_tag: String,
    outbound_tag: String,
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || select_native_group_outbound_blocking(group_tag, outbound_tag, state))
        .await
}

fn select_native_group_outbound_blocking(
    group_tag: String,
    outbound_tag: String,
    state: DesktopAppState,
) -> Result<OperationResult, String> {
    let embedded = require_embedded_config()?;
    select_embedded_group_member(&state, &embedded, &group_tag, &outbound_tag)
}

#[tauri::command]
fn list_subscriptions(
    state: State<'_, DesktopAppState>,
) -> Result<Vec<SubscriptionSummary>, String> {
    let desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    Ok(desktop
        .subscription_sources
        .iter()
        .map(|source| SubscriptionSummary {
            id: source.id.clone(),
            location: source.location.clone(),
            selected: desktop.profile_source_url.as_deref() == Some(source.location.as_str())
                || desktop
                    .profile_source_path
                    .as_ref()
                    .is_some_and(|path| path.display().to_string() == source.location),
            last_successful_update: source.last_successful_update.clone(),
            last_attempt: source.last_attempt.clone(),
            next_attempt: source.next_attempt.clone(),
            result: source.result.clone(),
            added_node_count: source.added_node_count,
            removed_node_count: source.removed_node_count,
            changed_node_count: source.changed_node_count,
            error_code: source.error_code.clone(),
            last_update_error: source.last_update_error.clone(),
        })
        .collect())
}

#[tauri::command]
async fn connect(state: State<'_, DesktopAppState>) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || connect_blocking(state)).await
}

fn connect_blocking(state: DesktopAppState) -> Result<OperationResult, String> {
    let desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?
        .clone();
    let connected = match desktop.runtime_mode {
        DesktopRuntimeMode::Desktop => connection::connect_direct(
            windows_managed_config_path(),
            desktop.clone(),
            &mut *state
                .direct_core
                .lock()
                .map_err(|_| "desktop core lock failed")?,
        )?,
        DesktopRuntimeMode::Service => {
            connection::connect(windows_managed_config_path(), desktop.clone())?
        }
    };
    let mut persisted = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    persisted.proxy_snapshot = Some(connected.snapshot);
    persisted.applied_proxy = Some(connected.applied_proxy);
    save_desktop_state(&persisted)?;
    mark_gui_started_connection(&state);
    Ok(OperationResult {
        message: match desktop.runtime_mode {
            DesktopRuntimeMode::Desktop => {
                "Connected. The desktop-owned core and current-user proxy are verified.".to_string()
            }
            DesktopRuntimeMode::Service => {
                "Connected. The managed core and current-user proxy are verified.".to_string()
            }
        },
    })
}

#[tauri::command]
async fn disconnect(state: State<'_, DesktopAppState>) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || disconnect_blocking(state)).await
}

fn disconnect_blocking(state: DesktopAppState) -> Result<OperationResult, String> {
    let desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?
        .clone();
    let message = match desktop.runtime_mode {
        DesktopRuntimeMode::Desktop => connection::disconnect_direct(
            windows_managed_config_path(),
            desktop.clone(),
            &mut *state
                .direct_core
                .lock()
                .map_err(|_| "desktop core lock failed")?,
        )?,
        DesktopRuntimeMode::Service => connection::disconnect(desktop)?,
    };
    let mut persisted = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    persisted.proxy_snapshot = None;
    persisted.applied_proxy = None;
    save_desktop_state(&persisted)?;
    mark_gui_connection_stopped(&state);
    Ok(OperationResult { message })
}

fn stop_desktop_core_for_exit(state: DesktopAppState) {
    let desktop = match state.desktop.lock() {
        Ok(desktop) => desktop.clone(),
        Err(_) => return,
    };
    if desktop.runtime_mode != DesktopRuntimeMode::Desktop {
        return;
    }
    let result = state
        .direct_core
        .lock()
        .map_err(|_| "desktop core lock failed".to_string())
        .and_then(|mut core| {
            connection::disconnect_direct(windows_managed_config_path(), desktop, &mut core)
        });
    if let Err(error) = result {
        let _ = append_managed_log(
            APP_LOG_SCOPE,
            &format!("desktop exit cleanup failed: {error}"),
        );
    }
}

#[tauri::command]
async fn restart_service(state: State<'_, DesktopAppState>) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || restart_service_blocking(state)).await
}

fn restart_service_blocking(state: DesktopAppState) -> Result<OperationResult, String> {
    let desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?
        .clone();
    let message = if desktop.runtime_mode == DesktopRuntimeMode::Desktop {
        let _ = connection::disconnect_direct(
            windows_managed_config_path(),
            desktop.clone(),
            &mut *state
                .direct_core
                .lock()
                .map_err(|_| "desktop core lock failed")?,
        );
        let connected = connection::connect_direct(
            windows_managed_config_path(),
            desktop,
            &mut *state
                .direct_core
                .lock()
                .map_err(|_| "desktop core lock failed")?,
        )?;
        let mut persisted = state
            .desktop
            .lock()
            .map_err(|_| "desktop state lock failed")?;
        persisted.proxy_snapshot = Some(connected.snapshot);
        persisted.applied_proxy = Some(connected.applied_proxy);
        save_desktop_state(&persisted)?;
        "Desktop core restarted and proxy settings were reapplied.".to_string()
    } else {
        match connection::restart(windows_managed_config_path(), desktop)? {
            connection::RestartedService::Desktop(_) => {
                "Service restarted and desktop proxy settings were reapplied.".to_string()
            }
            connection::RestartedService::ServiceManaged => {
                "Service restart was submitted. Waiting for managed runtime status.".to_string()
            }
        }
    };
    Ok(OperationResult { message })
}

#[tauri::command]
async fn validate_configuration() -> Result<OperationResult, String> {
    run_blocking(validate_configuration_blocking).await
}

fn validate_configuration_blocking() -> Result<OperationResult, String> {
    load_validated_managed_configuration(&windows_managed_config_path())?;
    Ok(OperationResult {
        message: "Managed configuration and enabled core preflight succeeded.".to_string(),
    })
}

#[tauri::command]
async fn switch_node(
    node_id: String,
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || switch_node_blocking(node_id, state)).await
}

fn switch_node_blocking(
    node_id: String,
    state: DesktopAppState,
) -> Result<OperationResult, String> {
    let desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?
        .clone();
    let update_running_core = node_operations_runtime_running(&state, &desktop)?;
    let node = selected_catalog_node(&desktop, &node_id)?;
    let embedded = require_embedded_config()?;
    switch_embedded_node(&state, &desktop, &embedded, &node.id, update_running_core)?;
    Ok(OperationResult {
        message: if update_running_core {
            "Active node switched and the embedded engine restarted with it.".to_string()
        } else {
            "Active node saved. It will be applied when the core next connects.".to_string()
        },
    })
}

#[tauri::command]
async fn test_node_delay(
    node_id: String,
    url: String,
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || test_node_delay_blocking(state, node_id, url)).await
}

#[tauri::command]
async fn select_fastest_node(state: State<'_, DesktopAppState>) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || select_fastest_node_blocking(state)).await
}

fn select_fastest_node_blocking(state: DesktopAppState) -> Result<OperationResult, String> {
    let desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?
        .clone();
    let test_url = desktop
        .delay_test_url
        .as_deref()
        .unwrap_or(DEFAULT_NODE_SELECTION_URL);
    let embedded = require_embedded_config()?;
    select_fastest_embedded_node(&state, &desktop, &embedded, test_url)
}

fn test_node_delay_blocking(
    state: DesktopAppState,
    node_id: String,
    url: String,
) -> Result<OperationResult, String> {
    let desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?
        .clone();
    let node = selected_catalog_node(&desktop, &node_id)?;
    require_embedded_config()?;
    let delay = measure_embedded_node_delay(&node.id, &url)?;
    Ok(OperationResult {
        message: format!("{} ms via {url}", delay.as_millis()),
    })
}

/// The embedded engine config when an imported profile runs on it.
fn active_embedded_config() -> Result<Option<WindowsManagedEmbeddedConfig>, String> {
    Ok(managed_config_or_default()?
        .embedded
        .filter(|embedded| embedded.enabled))
}

fn require_embedded_config() -> Result<WindowsManagedEmbeddedConfig, String> {
    active_embedded_config()?.ok_or_else(|| "Import a profile first.".to_string())
}

/// The imported embedded profile (`profile.json`).
fn read_embedded_profile() -> Result<Value, String> {
    let content = fs::read_to_string(embedded_profile_path())
        .map_err(|error| format!("Import the profile again before using it: {error}"))?;
    serde_json::from_str(&content).map_err(|error| error.to_string())
}

fn routed_groups(profile: &Value) -> &[Value] {
    profile
        .pointer("/routing/groups")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn routed_group<'a>(profile: &'a Value, id: &str) -> Option<&'a Value> {
    routed_groups(profile)
        .iter()
        .find(|group| group.get("id").and_then(Value::as_str) == Some(id))
}

fn group_members(group: &Value) -> Vec<String> {
    group
        .get("members")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

/// The member a group routes to now: a select group's default (when it is a
/// member) and otherwise the first member, as the engine decides.
fn group_choice(group: &Value) -> Option<String> {
    let members = group_members(group);
    let default = group
        .get("default")
        .and_then(Value::as_str)
        .filter(|_| group.get("type").and_then(Value::as_str) == Some("select"))
        .filter(|default| members.iter().any(|member| member == default));
    default
        .map(str::to_string)
        .or_else(|| members.into_iter().next())
}

/// The groups FINAL passes through, following each group's choice, and the
/// target it ends at.
fn routed_final_chain(profile: &Value) -> (Vec<String>, Option<String>) {
    let mut target = profile
        .pointer("/routing/rules")
        .and_then(Value::as_array)
        .and_then(|rules| rules.last())
        .and_then(Value::as_str)
        .and_then(|rule| rule.strip_prefix("FINAL,"))
        .map(|target| target.trim().to_string());
    let mut chain = Vec::new();
    while let Some(id) = target.clone() {
        if chain.contains(&id) {
            break;
        }
        let Some(group) = routed_group(profile, &id) else {
            break;
        };
        chain.push(id);
        target = group_choice(group);
    }
    (chain, target)
}

/// The node FINAL ends at, if it ends at a node.
fn routed_selected_node(profile: &Value) -> Option<String> {
    let (_, target) = routed_final_chain(profile);
    target.filter(|id| {
        profile
            .pointer(&format!("/routing/outbounds/{}", json_pointer_escape(id)))
            .is_some()
    })
}

fn json_pointer_escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

/// The first select group on FINAL's route that has `node_id` as a member.
fn routed_switch_group_for_node(profile: &Value, node_id: &str) -> Option<String> {
    let (chain, _) = routed_final_chain(profile);
    chain.into_iter().find(|id| {
        routed_group(profile, id).is_some_and(|group| {
            group.get("type").and_then(Value::as_str) == Some("select")
                && group_members(group).iter().any(|member| member == node_id)
        })
    })
}

/// Makes `member` the default of the select group `group_id`.
fn set_routed_group_default(
    profile: &mut Value,
    group_id: &str,
    member: &str,
) -> Result<(), String> {
    let group = profile
        .pointer_mut("/routing/groups")
        .and_then(Value::as_array_mut)
        .and_then(|groups| {
            groups
                .iter_mut()
                .find(|group| group.get("id").and_then(Value::as_str) == Some(group_id))
        })
        .ok_or_else(|| format!("Policy group {group_id} is not part of the imported profile."))?;
    if group.get("type").and_then(Value::as_str) != Some("select") {
        return Err(format!(
            "Policy group {group_id} chooses automatically; only select groups can be switched."
        ));
    }
    if !group_members(group)
        .iter()
        .any(|candidate| candidate == member)
    {
        return Err(format!(
            "{member} is not a member of policy group {group_id}."
        ));
    }
    group
        .as_object_mut()
        .ok_or_else(|| "policy group must be a JSON object".to_string())?
        .insert("default".to_string(), Value::String(member.to_string()));
    Ok(())
}

/// Copies select-group defaults from `previous` into `profile` where the
/// group and the member still exist.
fn carry_routed_group_defaults(previous: &Value, profile: &mut Value) {
    let defaults: Vec<(String, String)> = routed_groups(previous)
        .iter()
        .filter_map(|group| {
            Some((
                group.get("id")?.as_str()?.to_string(),
                group.get("default")?.as_str()?.to_string(),
            ))
        })
        .collect();
    for (group, member) in defaults {
        let _ = set_routed_group_default(profile, &group, &member);
    }
}

/// The routed profile's groups in the shape the policy group card shows,
/// with node ids labelled by their names.
fn embedded_groups(profile: &Value, nodes: &[DesktopProfileNode]) -> Vec<NativeGroupSummary> {
    let label = |member: &str| {
        nodes
            .iter()
            .find(|node| node.id == member)
            .map(|node| node.label.clone())
            .unwrap_or_else(|| member.to_string())
    };
    routed_groups(profile)
        .iter()
        .filter_map(|group| {
            let tag = group.get("id")?.as_str()?.to_string();
            let members = group_members(group);
            let group_type = match group.get("type")?.as_str()? {
                "select" => "selector",
                "url-test" => "urltest",
                other => other,
            }
            .to_string();
            Some(NativeGroupSummary {
                tag,
                group_type,
                selected: group_choice(group),
                outbound_labels: members.iter().map(|member| label(member)).collect(),
                outbounds: members,
            })
        })
        .collect()
}

/// Makes `member` the choice of the select group `group_id`, rebuilds the
/// envelope for the routing mode and restarts a running core on it.
fn select_embedded_group_member(
    state: &DesktopAppState,
    embedded: &WindowsManagedEmbeddedConfig,
    group_id: &str,
    member: &str,
) -> Result<OperationResult, String> {
    let desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?
        .clone();
    let mut profile = read_embedded_profile()?;
    set_routed_group_default(&mut profile, group_id, member)?;
    let rendered = profile.to_string();
    let envelope = embedded_envelope_for_mode(&rendered, desktop.routing_mode, false)?;
    write_managed_text_atomic(&embedded_profile_path(), &rendered)
        .map_err(|error| error.to_string())?;
    write_managed_text_atomic(&embedded.envelope_path, &envelope)
        .map_err(|error| error.to_string())?;
    {
        let mut persisted = state
            .desktop
            .lock()
            .map_err(|_| "desktop state lock failed")?;
        persisted.profile_node_id = routed_selected_node(&profile);
        save_desktop_state(&persisted)?;
    }
    let running = node_operations_runtime_running(state, &desktop)?;
    if running {
        restart_service_blocking(state.clone())?;
    }
    Ok(OperationResult {
        message: if running {
            format!(
                "Policy group {group_id} now uses {member}; the embedded engine restarted with it."
            )
        } else {
            format!("Policy group {group_id} now uses {member}. It applies when the core next connects.")
        },
    })
}

/// Envelope with the one outbound saved for `node_id` at import.
fn embedded_node_profile(node_id: &str) -> Result<String, String> {
    let content = fs::read_to_string(embedded_nodes_path())
        .map_err(|error| format!("Import the profile again before using its nodes: {error}"))?;
    let mut nodes: serde_json::Map<String, Value> =
        serde_json::from_str(&content).map_err(|error| error.to_string())?;
    let outbound = nodes
        .remove(node_id)
        .ok_or_else(|| "Selected node is not part of the current imported profile.".to_string())?;
    Ok(json!({
        "schema_version": CONFIG_SCHEMA_VERSION,
        "profile_id": EMBEDDED_PROFILE_ID,
        "outbound": outbound,
    })
    .to_string())
}

/// Delay of `url` through the node's own outbound, measured in this process,
/// so it works while disconnected and never goes through the system proxy.
fn measure_embedded_node_delay(node_id: &str, url: &str) -> Result<Duration, String> {
    let profile = embedded_node_profile(node_id)?;
    measure_delay(profile.as_bytes(), url, EMBEDDED_DELAY_TIMEOUT)
        .map_err(|error| error.to_string())
}

/// Makes `node_id` the profile's outbound, reapplies the routing mode and,
/// when the core runs, restarts it on the new envelope.
fn switch_embedded_node(
    state: &DesktopAppState,
    desktop: &DesktopState,
    embedded: &WindowsManagedEmbeddedConfig,
    node_id: &str,
    update_running_core: bool,
) -> Result<(), String> {
    let current = read_embedded_profile()?;
    let profile = if current.get("routing").is_some() {
        // A routed profile keeps its rules: the node becomes the choice of the
        // select group it belongs to on the route FINAL takes.
        let mut routed = current;
        let group = routed_switch_group_for_node(&routed, node_id).ok_or_else(|| {
            "This node is not in the profile's main policy group; choose it under Policy groups."
                .to_string()
        })?;
        set_routed_group_default(&mut routed, &group, node_id)?;
        routed.to_string()
    } else {
        embedded_node_profile(node_id)?
    };
    write_managed_text_atomic(&embedded_profile_path(), &profile)
        .map_err(|error| error.to_string())?;
    let envelope = embedded_envelope_or_profile(profile, desktop.routing_mode);
    write_managed_text_atomic(&embedded.envelope_path, &envelope)
        .map_err(|error| error.to_string())?;
    {
        let mut persisted = state
            .desktop
            .lock()
            .map_err(|_| "desktop state lock failed")?;
        persisted.profile_node_id = Some(node_id.to_string());
        save_desktop_state(&persisted)?;
    }
    if update_running_core {
        restart_service_blocking(state.clone())?;
    }
    Ok(())
}

fn select_fastest_embedded_node(
    state: &DesktopAppState,
    desktop: &DesktopState,
    embedded: &WindowsManagedEmbeddedConfig,
    test_url: &str,
) -> Result<OperationResult, String> {
    // On a routed profile only nodes of the main policy group can be chosen.
    let routed = read_embedded_profile()
        .ok()
        .filter(|profile| profile.get("routing").is_some());
    let candidates: Vec<DesktopProfileNode> = desktop
        .profile_node_catalog
        .iter()
        .filter(|node| {
            routed
                .as_ref()
                .is_none_or(|profile| routed_switch_group_for_node(profile, &node.id).is_some())
        })
        .cloned()
        .collect();
    let mut fastest: Option<(&DesktopProfileNode, Duration)> = None;
    for chunk in candidates.chunks(EMBEDDED_DELAY_PARALLELISM) {
        let delays: Vec<_> = std::thread::scope(|scope| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|node| scope.spawn(move || measure_embedded_node_delay(&node.id, test_url)))
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().ok().and_then(Result::ok))
                .collect()
        });
        for (node, delay) in chunk.iter().zip(delays) {
            let Some(delay) = delay else { continue };
            if fastest.is_none_or(|(_, best)| delay < best) {
                fastest = Some((node, delay));
            }
        }
    }
    let (node, delay) =
        fastest.ok_or_else(|| "No imported node returned a successful delay test.".to_string())?;
    let delay_millis = delay.as_millis();
    if desktop.profile_node_id.as_deref() == Some(node.id.as_str()) {
        return Ok(OperationResult {
            message: format!(
                "{} is already the fastest responding node at {delay_millis} ms.",
                node.label
            ),
        });
    }
    let update_running_core = node_operations_runtime_running(state, desktop)?;
    switch_embedded_node(state, desktop, embedded, &node.id, update_running_core)?;
    Ok(OperationResult {
        message: format!("Selected fastest node: {} ({delay_millis} ms).", node.label),
    })
}

fn node_operations_runtime_running(
    state: &DesktopAppState,
    desktop: &DesktopState,
) -> Result<bool, String> {
    match desktop.runtime_mode {
        DesktopRuntimeMode::Desktop => state
            .direct_core
            .lock()
            .map_err(|_| "desktop core lock failed")?
            .is_running(),
        DesktopRuntimeMode::Service => Ok(read_runtime_status().connection.is_connected()),
    }
}

#[tauri::command]
async fn save_preferences(
    preferences: PreferenceValues,
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || save_preferences_blocking(preferences, state)).await
}

fn save_preferences_blocking(
    preferences: PreferenceValues,
    state: DesktopAppState,
) -> Result<OperationResult, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let startup_enabled =
        current_user_startup_enabled(&executable).map_err(|error| error.to_string())?;
    if preferences.start_after_login && !startup_enabled {
        enable_current_user_startup(&executable).map_err(|error| error.to_string())?;
    } else if !preferences.start_after_login && startup_enabled {
        disable_current_user_startup(&executable).map_err(|error| error.to_string())?;
    }
    let mut desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    desktop.start_after_login = preferences.start_after_login;
    desktop.auto_connect = preferences.auto_connect;
    desktop.auto_recover_core = preferences.auto_recover_core;
    desktop.auto_subscription_refresh = preferences.auto_subscription_refresh;
    let next_refresh_attempt = scheduled_refresh_timestamp(preferences.auto_subscription_refresh);
    desktop.profile_next_attempt = next_refresh_attempt.clone();
    if let Some(location) = desktop.profile_source_url.clone() {
        if let Some(source) = desktop
            .subscription_sources
            .iter_mut()
            .find(|source| source.location == location)
        {
            source.next_attempt = next_refresh_attempt;
        }
    }
    desktop.auto_select_fastest_node = preferences.auto_select_fastest_node;
    desktop.bilibili_web_ad_block_enabled = preferences.bilibili_web_ad_block_enabled;
    desktop.dark_theme = preferences.dark_theme;
    desktop.runtime_mode = match preferences.runtime_mode.as_str() {
        "desktop" => DesktopRuntimeMode::Desktop,
        "service" => DesktopRuntimeMode::Service,
        _ => return Err("runtime mode must be either desktop or service".to_string()),
    };
    save_desktop_state(&desktop)?;
    Ok(OperationResult {
        message: "Desktop preferences saved.".to_string(),
    })
}

#[tauri::command]
async fn create_diagnostics() -> Result<OperationResult, String> {
    run_blocking(create_diagnostics_blocking).await
}

fn create_diagnostics_blocking() -> Result<OperationResult, String> {
    let path = write_diagnostic_report_at(&windows_managed_config_path())?;
    Ok(OperationResult {
        message: format!("Diagnostics written to {}", path.display()),
    })
}

#[tauri::command]
async fn import_subscription(
    location: String,
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || import_subscription_blocking(state, location, "Subscription imported."))
        .await
}

#[tauri::command]
async fn update_subscription(state: State<'_, DesktopAppState>) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || {
        let location = state
            .desktop
            .lock()
            .map_err(|_| "desktop state lock failed")?
            .profile_source_url
            .clone()
            .ok_or_else(|| {
                "Import an HTTP or HTTPS subscription URL before updating it.".to_string()
            })?;
        import_subscription_blocking(state, location, "Subscription updated.")
    })
    .await
}

#[tauri::command]
async fn select_subscription(
    id: String,
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || {
        let location = state
            .desktop
            .lock()
            .map_err(|_| "desktop state lock failed")?
            .subscription_sources
            .iter()
            .find(|source| source.id == id)
            .map(|source| source.location.clone())
            .ok_or_else(|| "Selected subscription source was not found.".to_string())?;
        import_subscription_blocking(state, location, "Subscription selected.")
    })
    .await
}

#[tauri::command]
async fn remove_subscription(
    id: String,
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || remove_subscription_blocking(id, state)).await
}

fn remove_subscription_blocking(
    id: String,
    state: DesktopAppState,
) -> Result<OperationResult, String> {
    let mut desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    let before = desktop.subscription_sources.len();
    desktop
        .subscription_sources
        .retain(|source| source.id != id);
    if desktop.subscription_sources.len() == before {
        return Err("Selected subscription source was not found.".to_string());
    }
    save_desktop_state(&desktop)?;
    Ok(OperationResult {
        message: "Subscription source removed from the catalog.".to_string(),
    })
}

fn import_subscription_blocking(
    state: DesktopAppState,
    location: String,
    message: &'static str,
) -> Result<OperationResult, String> {
    let _refresh_guard = acquire_subscription_refresh(&state)?;
    let mut desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?
        .clone();
    let result = record_subscription_import(&location, &mut desktop);
    let mut persisted = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    *persisted = desktop;
    result?;
    Ok(OperationResult {
        message: message.to_string(),
    })
}

fn acquire_subscription_refresh(
    state: &DesktopAppState,
) -> Result<SubscriptionRefreshGuard, String> {
    let mut active = state
        .lifecycle
        .subscription_refresh_active
        .lock()
        .map_err(|_| "subscription refresh lock failed")?;
    if *active {
        return Err(
            "Subscription refresh is already active; wait for the current attempt to finish."
                .to_string(),
        );
    }
    *active = true;
    Ok(SubscriptionRefreshGuard {
        active: state.lifecycle.subscription_refresh_active.clone(),
    })
}

#[tauri::command]
async fn check_profile_runtime(
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || check_profile_runtime_blocking(state)).await
}

/// Checks that the embedded engine accepts the profile it would run.
fn check_profile_runtime_blocking(state: DesktopAppState) -> Result<OperationResult, String> {
    let embedded = require_embedded_config()?;
    let envelope = fs::read(&embedded.envelope_path)
        .map_err(|error| format!("Import the profile again before checking it: {error}"))?;
    RuntimeConfig::from_json(&envelope).map_err(|error| {
        format!(
            "The embedded engine rejects this profile: {}",
            error.message
        )
    })?;
    let desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    let active = desktop
        .profile_node_id
        .as_deref()
        .and_then(|id| {
            desktop
                .profile_node_catalog
                .iter()
                .find(|node| node.id == id)
        })
        .map(|node| node.label.clone())
        .unwrap_or_else(|| "the profile's rules".to_string());
    Ok(OperationResult {
        message: format!(
            "Profile ready: {active} ({} nodes)",
            desktop.profile_node_catalog.len()
        ),
    })
}

fn record_subscription_import(location: &str, desktop: &mut DesktopState) -> Result<(), String> {
    let attempt = super::current_local_timestamp();
    record_subscription_attempt(desktop, location, attempt.clone());
    save_desktop_state(desktop)?;
    let previous_nodes = desktop.profile_node_catalog.clone();
    match import_subscription_at(location, desktop) {
        Ok(()) => {
            let timestamp = super::current_local_timestamp();
            let (added_node_count, removed_node_count, changed_node_count) =
                subscription_node_change_counts(&previous_nodes, &desktop.profile_node_catalog);
            desktop.profile_last_successful_update = Some(timestamp.clone());
            desktop.profile_next_attempt =
                scheduled_refresh_timestamp(desktop.auto_subscription_refresh);
            desktop.profile_refresh_result = "success".to_string();
            desktop.profile_added_node_count = added_node_count;
            desktop.profile_removed_node_count = removed_node_count;
            desktop.profile_changed_node_count = changed_node_count;
            desktop.profile_refresh_error_code = None;
            desktop.profile_last_update_error = None;
            record_subscription_result(
                desktop,
                location,
                Some(timestamp),
                "success",
                (added_node_count, removed_node_count, changed_node_count),
                None,
            );
            save_desktop_state(desktop)
        }
        Err(error) => {
            let error_code = redacted_subscription_error_code(&error);
            desktop.profile_next_attempt =
                scheduled_refresh_timestamp(desktop.auto_subscription_refresh);
            desktop.profile_refresh_result = "failed".to_string();
            desktop.profile_added_node_count = 0;
            desktop.profile_removed_node_count = 0;
            desktop.profile_changed_node_count = 0;
            desktop.profile_refresh_error_code = Some(error_code.clone());
            desktop.profile_last_update_error = Some(
                "Subscription refresh failed; inspect diagnostics for the redacted error code."
                    .to_string(),
            );
            record_subscription_result(
                desktop,
                location,
                None,
                "failed",
                (0, 0, 0),
                Some(error_code.clone()),
            );
            let _ = save_desktop_state(desktop);
            Err(format!("Subscription refresh failed ({error_code})."))
        }
    }
}

fn record_subscription_attempt(desktop: &mut DesktopState, location: &str, attempt: String) {
    desktop.profile_last_attempt = Some(attempt.clone());
    desktop.profile_refresh_result = "running".to_string();
    desktop.profile_refresh_error_code = None;
    let id = subscription_source_id(location);
    let source = desktop
        .subscription_sources
        .iter_mut()
        .find(|source| source.id == id);
    if let Some(source) = source {
        source.last_attempt = Some(attempt);
        source.result = "running".to_string();
        source.error_code = None;
    } else {
        desktop
            .subscription_sources
            .push(DesktopSubscriptionSource {
                id,
                location: location.to_string(),
                last_attempt: Some(attempt),
                last_successful_update: None,
                next_attempt: None,
                result: "running".to_string(),
                added_node_count: 0,
                removed_node_count: 0,
                changed_node_count: 0,
                error_code: None,
                last_update_error: None,
            });
    }
}

fn record_subscription_result(
    desktop: &mut DesktopState,
    location: &str,
    successful_update: Option<String>,
    result: &str,
    node_counts: (usize, usize, usize),
    error_code: Option<String>,
) {
    let (added_node_count, removed_node_count, changed_node_count) = node_counts;
    let id = subscription_source_id(location);
    let next_attempt = desktop.profile_next_attempt.clone();
    if let Some(source) = desktop
        .subscription_sources
        .iter_mut()
        .find(|source| source.id == id)
    {
        source.last_successful_update = successful_update;
        source.next_attempt = next_attempt;
        source.result = result.to_string();
        source.added_node_count = added_node_count;
        source.removed_node_count = removed_node_count;
        source.changed_node_count = changed_node_count;
        source.error_code = error_code.clone();
        source.last_update_error = error_code.map(|_| "refresh_failed".to_string());
        return;
    }
    desktop
        .subscription_sources
        .push(DesktopSubscriptionSource {
            id,
            location: location.to_string(),
            last_attempt: desktop.profile_last_attempt.clone(),
            last_successful_update: successful_update,
            next_attempt,
            result: result.to_string(),
            added_node_count,
            removed_node_count,
            changed_node_count,
            error_code: error_code.clone(),
            last_update_error: error_code.map(|_| "refresh_failed".to_string()),
        });
}

fn scheduled_refresh_timestamp(enabled: bool) -> Option<String> {
    enabled.then(|| {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_add(SUBSCRIPTION_REFRESH_INTERVAL.as_secs());
        format!("unix-epoch-seconds:{seconds}")
    })
}

fn redacted_subscription_error_code(error: &str) -> String {
    let normalized = error.to_ascii_lowercase();
    if normalized.contains("timed out") || normalized.contains("timeout") {
        "windows.subscription.fetch_timeout".to_string()
    } else if normalized.contains("status") || normalized.contains("http") {
        "windows.subscription.fetch_failed".to_string()
    } else if normalized.contains("disconnect") {
        "windows.subscription.runtime_active".to_string()
    } else if normalized.contains("supported proxy node") || normalized.contains("parse") {
        "windows.subscription.invalid_payload".to_string()
    } else {
        "windows.subscription.refresh_failed".to_string()
    }
}

fn subscription_node_change_counts(
    previous: &[DesktopProfileNode],
    current: &[DesktopProfileNode],
) -> (usize, usize, usize) {
    let added = current
        .iter()
        .filter(|node| !previous.iter().any(|before| before.id == node.id))
        .count();
    let removed = previous
        .iter()
        .filter(|node| !current.iter().any(|after| after.id == node.id))
        .count();
    let changed = current
        .iter()
        .filter(|node| {
            previous
                .iter()
                .find(|before| before.id == node.id)
                .is_some_and(|before| {
                    before.label != node.label
                        || before.protocol != node.protocol
                        || before.outbound_tag != node.outbound_tag
                })
        })
        .count();
    (added, removed, changed)
}

fn subscription_source_id(location: &str) -> String {
    format!(
        "source-{:x}",
        location.bytes().fold(0_u64, |hash, byte| {
            hash.wrapping_mul(16777619).wrapping_add(u64::from(byte))
        })
    )
}

fn import_subscription_at(location: &str, desktop: &mut DesktopState) -> Result<(), String> {
    let service = NativeWindowsSystemIntegration::new()
        .service_status()
        .map_err(|error| error.to_string())?;
    if !matches!(
        service.state,
        WindowsServiceState::NotInstalled | WindowsServiceState::Stopped
    ) {
        return Err(
            "Disconnect before importing or updating a profile so the running core keeps its active configuration."
                .to_string(),
        );
    }
    let (payload, source_path, source_url) = read_subscription(location)?;
    import_embedded_subscription(&payload, source_path, source_url, desktop)
}

/// Runs a subscription whose nodes the embedded engine supports in-process:
/// the GUI in desktop mode, the service otherwise.
fn import_embedded_subscription(
    payload: &str,
    source_path: Option<PathBuf>,
    source_url: Option<String>,
    desktop: &mut DesktopState,
) -> Result<(), String> {
    let service = CoreSubscriptionService::new();
    let source = SubscriptionSource {
        id: EMBEDDED_PROFILE_ID.to_string(),
        location: format!("inline:{payload}"),
    };
    let raw = service.fetch(&source).map_err(|error| error.to_string())?;
    let document = service.parse(&raw).map_err(|error| error.to_string())?;
    let catalog = service
        .normalize(&document)
        .map_err(|error| error.to_string())?;
    if catalog.nodes.is_empty() {
        return Err("Profile did not contain a supported proxy node".to_string());
    }
    // Subscription rules and policy groups drive the route when every node is
    // supported and the engine accepts the result; otherwise one node runs
    // alone.
    let routed = import_subscription_routing(payload, &catalog.nodes)
        .spec
        .and_then(|spec| routing_envelope(EMBEDDED_PROFILE_ID, &catalog.nodes, &spec).ok())
        // The engine caps the routed node and rule counts.
        .filter(|envelope| RuntimeConfig::from_json(envelope.as_bytes()).is_ok());
    // A single-node profile lists every supported node so it can be switched
    // and delay tested; a routed one is driven by its own groups.
    let routed_import = routed.is_some();
    let (envelope, selected_node_id, node_outbounds) = match routed {
        Some(envelope) => {
            // Group choices made before a refresh survive it where the group
            // and member still exist.
            let mut profile: Value =
                serde_json::from_str(&envelope).map_err(|error| error.to_string())?;
            if let Ok(previous) = read_embedded_profile() {
                carry_routed_group_defaults(&previous, &mut profile);
            }
            let node_outbounds = catalog
                .nodes
                .iter()
                .filter_map(|node| {
                    outbound_for_node(node)
                        .ok()
                        .map(|outbound| (node.clone(), outbound))
                })
                .collect::<Vec<_>>();
            let selected = routed_selected_node(&profile);
            (profile.to_string(), selected, node_outbounds)
        }
        None => {
            let selected = desktop
                .profile_node_id
                .as_deref()
                .filter(|id| catalog.nodes.iter().any(|node| node.id == *id));
            let (envelope, node) =
                single_node_envelope(EMBEDDED_PROFILE_ID, &catalog.nodes, selected).map_err(
                    |reason| format!("The embedded engine cannot run this profile: {reason}"),
                )?;
            let node_outbounds = catalog
                .nodes
                .iter()
                .filter_map(|node| {
                    outbound_for_node(node)
                        .ok()
                        .map(|outbound| (node.clone(), outbound))
                })
                .collect::<Vec<_>>();
            (envelope, Some(node.id), node_outbounds)
        }
    };
    let saved_outbounds: serde_json::Map<String, Value> = node_outbounds
        .iter()
        .map(|(node, outbound)| (node.id.clone(), outbound.clone()))
        .collect();
    write_managed_text_atomic(
        &embedded_nodes_path(),
        &Value::Object(saved_outbounds).to_string(),
    )
    .map_err(|error| error.to_string())?;
    let supported_nodes: Vec<NodeDescriptor> =
        node_outbounds.into_iter().map(|(node, _)| node).collect();
    let node_catalog = profile_node_options(&supported_nodes);
    // The imported envelope is kept so routing modes can be reapplied to it.
    write_managed_text_atomic(&embedded_profile_path(), &envelope)
        .map_err(|error| error.to_string())?;
    if routed_import {
        // A profile with its own rules runs them by default.
        desktop.routing_mode = DesktopRoutingMode::Rule;
    }
    let envelope = embedded_envelope_or_profile(envelope, desktop.routing_mode);
    let envelope_path = embedded_directory().join("envelope.json");
    write_managed_text_atomic(&envelope_path, &envelope).map_err(|error| error.to_string())?;
    let mut managed = managed_config_or_default()?;
    let mitm = managed
        .native_mitm
        .as_ref()
        .is_some_and(|native_mitm| native_mitm.enabled);
    set_embedded_listener(&mut managed, envelope_path, mitm);
    write_managed_config(&windows_managed_config_path(), &managed)
        .map_err(|error| format!("Managed configuration update failed: {error}"))?;
    desktop.profile_source_path = source_path;
    desktop.profile_source_url = source_url;
    desktop.profile_node_id = selected_node_id;
    desktop.profile_node_catalog = node_catalog;
    Ok(())
}

/// Runs the embedded engine from `envelope_path`. On its own it is the system
/// proxy and the desktop owns it; behind HTTPS MITM it moves to the MITM
/// proxy's upstream port and the service owns the system proxy, which points
/// at the MITM listener.
fn set_embedded_listener(managed: &mut WindowsManagedConfig, envelope_path: PathBuf, mitm: bool) {
    let listen_port = if mitm {
        EMBEDDED_MITM_UPSTREAM_PORT
    } else {
        EMBEDDED_LISTEN_PORT
    };
    managed.system_proxy = Some(WindowsProxySettings {
        enabled: true,
        server: format!("127.0.0.1:{EMBEDDED_LISTEN_PORT}"),
        bypass: "<local>".to_string(),
    });
    managed.system_proxy_owner = if mitm {
        WindowsSystemProxyOwner::Service
    } else {
        WindowsSystemProxyOwner::Desktop
    };
    managed.embedded = Some(WindowsManagedEmbeddedConfig {
        enabled: true,
        envelope_path,
        listen_host: "127.0.0.1".to_string(),
        listen_port,
    });
}

fn embedded_directory() -> PathBuf {
    windows_managed_data_directory().join("embedded")
}

fn embedded_profile_path() -> PathBuf {
    embedded_directory().join("profile.json")
}

/// `{node id: outbound}` for the nodes of a single-node profile.
fn embedded_nodes_path() -> PathBuf {
    embedded_directory().join("nodes.json")
}

/// The profile with the routing mode applied, or the profile alone (logged)
/// when the mode's rules are unavailable.
fn embedded_envelope_or_profile(profile: String, mode: DesktopRoutingMode) -> String {
    match embedded_envelope_for_mode(&profile, mode, false) {
        Ok(routed) => routed,
        Err(error) => {
            let _ = append_managed_log(
                APP_LOG_SCOPE,
                &format!("routing mode was not applied to the embedded profile: {error}"),
            );
            profile
        }
    }
}

/// The imported envelope with `mode`'s rules in place of its own: the
/// profile's FINAL target (or its single outbound) is the proxy, and the
/// mode's lists become rule sets.
fn embedded_envelope_for_mode(
    profile: &str,
    mode: DesktopRoutingMode,
    force_refresh: bool,
) -> Result<String, String> {
    if mode == DesktopRoutingMode::Rule {
        // The profile's own rules and groups, or its one node for everything.
        RuntimeConfig::from_json(profile.as_bytes())
            .map_err(|error| format!("embedded profile was rejected: {}", error.message))?;
        return Ok(profile.to_string());
    }
    let rule_directory = windows_managed_data_directory().join(ROUTING_RULE_DIRECTORY);
    if mode != DesktopRoutingMode::Direct {
        refresh_routing_rule_assets(&rule_directory, mode, force_refresh)?;
    }
    let mut envelope: Value = serde_json::from_str(profile).map_err(|error| error.to_string())?;
    let object = envelope
        .as_object_mut()
        .ok_or_else(|| "embedded profile must be a JSON object".to_string())?;
    let (mut routing, proxy) = match (object.remove("outbound"), object.remove("routing")) {
        (Some(outbound), None) => (
            json!({ "outbounds": { EMBEDDED_PROXY_OUTBOUND: outbound } }),
            EMBEDDED_PROXY_OUTBOUND.to_string(),
        ),
        (None, Some(routing)) => {
            let proxy = routing
                .get("rules")
                .and_then(Value::as_array)
                .and_then(|rules| rules.last())
                .and_then(Value::as_str)
                .and_then(|rule| rule.strip_prefix("FINAL,"))
                .map(str::to_string)
                .ok_or_else(|| "embedded profile routing must end with FINAL".to_string())?;
            (routing, proxy)
        }
        _ => return Err("embedded profile must carry one outbound or routing".to_string()),
    };
    let list = |name: &str| read_rule_set_asset(&rule_directory.join(name));
    let (rules, rule_sets) = match mode {
        DesktopRoutingMode::BypassChina | DesktopRoutingMode::ReturnChina => {
            let (mut domain_suffix, _) = list("china-domains.json")?;
            let (more_domains, ip_cidr) = list("china-ips.json")?;
            domain_suffix.extend(more_domains);
            let (china_target, final_target) = if mode == DesktopRoutingMode::BypassChina {
                ("DIRECT".to_string(), proxy)
            } else {
                (proxy, "DIRECT".to_string())
            };
            (
                vec![
                    format!("RULE-SET,china,{china_target}"),
                    format!("FINAL,{final_target}"),
                ],
                json!({ "china": { "domain_suffix": domain_suffix, "ip_cidr": ip_cidr } }),
            )
        }
        DesktopRoutingMode::GfwList => {
            let (domain_suffix, ip_cidr) = list("gfw-domains.json")?;
            (
                vec![format!("RULE-SET,gfw,{proxy}"), "FINAL,DIRECT".to_string()],
                json!({ "gfw": { "domain_suffix": domain_suffix, "ip_cidr": ip_cidr } }),
            )
        }
        DesktopRoutingMode::Direct => (vec!["FINAL,DIRECT".to_string()], json!({})),
        DesktopRoutingMode::Rule => unreachable!("rule mode returns the profile above"),
    };
    let routing_object = routing
        .as_object_mut()
        .ok_or_else(|| "embedded profile routing must be a JSON object".to_string())?;
    routing_object.insert("rules".to_string(), json!(rules));
    routing_object.insert("rule_sets".to_string(), rule_sets);
    object.insert("routing".to_string(), routing);
    let rendered = serde_json::to_string(&envelope).map_err(|error| error.to_string())?;
    RuntimeConfig::from_json(rendered.as_bytes())
        .map_err(|error| format!("routed embedded profile was rejected: {}", error.message))?;
    Ok(rendered)
}

/// Domain suffixes and networks of a rule asset written by
/// [`write_rule_set_asset`].
fn read_rule_set_asset(path: &Path) -> Result<(Vec<String>, Vec<String>), String> {
    let content = fs::read_to_string(path).map_err(|error| {
        format!(
            "routing rules could not be read from {}: {error}",
            path.display()
        )
    })?;
    let source: Value = serde_json::from_str(&content).map_err(|error| error.to_string())?;
    let mut domain_suffix = Vec::new();
    let mut ip_cidr = Vec::new();
    for rule in source
        .get("rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for (key, entries) in [
            ("domain_suffix", &mut domain_suffix),
            ("ip_cidr", &mut ip_cidr),
        ] {
            entries.extend(
                rule.get(key)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_string),
            );
        }
    }
    Ok((domain_suffix, ip_cidr))
}

fn read_subscription(location: &str) -> Result<(String, Option<PathBuf>, Option<String>), String> {
    if location.starts_with("https://") || location.starts_with("http://") {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| error.to_string())?;
        let payload = client
            .get(location)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|error| error.to_string())?
            .text()
            .map_err(|error| error.to_string())?;
        return Ok((payload, None, Some(location.to_string())));
    }
    let path = PathBuf::from(location);
    let payload = fs::read_to_string(&path).map_err(|error| error.to_string())?;
    Ok((payload, Some(path), None))
}

#[tauri::command]
async fn install_service() -> Result<OperationResult, String> {
    run_blocking(install_service_blocking).await
}

fn install_service_blocking() -> Result<OperationResult, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let service = executable
        .parent()
        .ok_or_else(|| "GUI executable has no parent directory".to_string())?
        .join("networkcore-windows-service.exe");
    NativeWindowsSystemIntegration::new()
        .install_service(&service)
        .map_err(|error| error.to_string())?;
    Ok(OperationResult {
        message: "Windows service installed.".to_string(),
    })
}

#[tauri::command]
async fn start_service() -> Result<OperationResult, String> {
    run_blocking(start_service_blocking).await
}

fn start_service_blocking() -> Result<OperationResult, String> {
    NativeWindowsSystemIntegration::new()
        .start_service()
        .map_err(|error| error.to_string())?;
    Ok(OperationResult {
        message: "Windows service start requested.".to_string(),
    })
}

#[tauri::command]
async fn stop_service(state: State<'_, DesktopAppState>) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || stop_service_blocking(state)).await
}

fn stop_service_blocking(state: DesktopAppState) -> Result<OperationResult, String> {
    NativeWindowsSystemIntegration::new()
        .stop_service()
        .map_err(|error| error.to_string())?;
    mark_gui_connection_stopped(&state);
    Ok(OperationResult {
        message: "Windows service stop requested.".to_string(),
    })
}

#[tauri::command]
async fn restore_network_settings(
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || restore_network_settings_blocking(state)).await
}

fn restore_network_settings_blocking(state: DesktopAppState) -> Result<OperationResult, String> {
    let mut desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    let snapshot = desktop
        .proxy_snapshot
        .clone()
        .ok_or_else(|| "No GUI-owned system proxy snapshot is available to restore.".to_string())?;
    let current = read_current_user_system_proxy().map_err(|error| error.to_string())?;
    if !owns_current_proxy(&desktop, &current) {
        desktop.proxy_snapshot = None;
        desktop.applied_proxy = None;
        save_desktop_state(&desktop)?;
        return Ok(OperationResult {
            message: "Current proxy settings no longer match the GUI-owned value and were left unchanged."
                .to_string(),
        });
    }
    NativeWindowsSystemIntegration::new()
        .restore_system_proxy(&snapshot)
        .map_err(|error| error.to_string())?;
    desktop.proxy_snapshot = None;
    desktop.applied_proxy = None;
    save_desktop_state(&desktop)?;
    mark_gui_connection_stopped(&state);
    Ok(OperationResult {
        message: "Network settings restored from the GUI-owned proxy snapshot.".to_string(),
    })
}

#[tauri::command]
async fn configure_tunnel(config_json: String) -> Result<OperationResult, String> {
    run_blocking(move || configure_tunnel_blocking(config_json)).await
}

fn configure_tunnel_blocking(config_json: String) -> Result<OperationResult, String> {
    let tunnel: WindowsManagedTunnelConfig =
        serde_json::from_str(&config_json).map_err(|error| error.to_string())?;
    let mut managed = managed_config_or_default()?;
    managed.tunnel = Some(tunnel);
    write_managed_config(&windows_managed_config_path(), &managed)
        .map_err(|error| error.to_string())?;
    Ok(OperationResult {
        message: "Managed TUN configuration saved. Start the Windows service to apply it."
            .to_string(),
    })
}

#[tauri::command]
async fn clear_tunnel() -> Result<OperationResult, String> {
    run_blocking(clear_tunnel_blocking).await
}

fn clear_tunnel_blocking() -> Result<OperationResult, String> {
    let mut managed = managed_config_or_default()?;
    managed.tunnel = None;
    write_managed_config(&windows_managed_config_path(), &managed)
        .map_err(|error| error.to_string())?;
    Ok(OperationResult {
        message: "Managed TUN configuration cleared. Stop the Windows service to tear down an active tunnel."
            .to_string(),
    })
}

#[tauri::command]
async fn set_routing_mode(
    mode: String,
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || set_routing_mode_blocking(&mode, state, false)).await
}

#[tauri::command]
async fn refresh_routing_rules(
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || {
        let mode = state
            .desktop
            .lock()
            .map_err(|_| "desktop state lock failed")?
            .routing_mode;
        set_routing_mode_blocking(routing_mode_name(mode), state, true)
    })
    .await
}

fn set_routing_mode_blocking(
    mode: &str,
    state: DesktopAppState,
    force_refresh: bool,
) -> Result<OperationResult, String> {
    let mode = parse_routing_mode(mode)?;
    ensure_routing_configuration_stopped(&state)?;
    let mut desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    let embedded = active_embedded_config()?
        .ok_or_else(|| "Import a profile before applying a routing mode.".to_string())?;
    let profile = fs::read_to_string(embedded_profile_path()).map_err(|error| {
        format!("Import the profile again before applying a routing mode: {error}")
    })?;
    let envelope = embedded_envelope_for_mode(&profile, mode, force_refresh)?;
    write_managed_text_atomic(&embedded.envelope_path, &envelope)
        .map_err(|error| error.to_string())?;
    desktop.routing_mode = mode;
    save_desktop_state(&desktop)?;
    Ok(OperationResult {
        message: format!(
            "{} routing mode saved. Connect to apply the updated route.",
            routing_mode_label(mode)
        ),
    })
}

fn ensure_routing_configuration_stopped(state: &DesktopAppState) -> Result<(), String> {
    let service = NativeWindowsSystemIntegration::new()
        .service_status()
        .map_err(|error| error.to_string())?;
    if !matches!(
        service.state,
        WindowsServiceState::NotInstalled | WindowsServiceState::Stopped
    ) {
        return Err("Disconnect before changing the routing mode.".to_string());
    }
    if state
        .direct_core
        .lock()
        .map_err(|_| "desktop core lock failed")?
        .is_running()?
    {
        return Err("Disconnect before changing the routing mode.".to_string());
    }
    Ok(())
}

fn refresh_routing_rule_assets(
    directory: &Path,
    mode: DesktopRoutingMode,
    force_refresh: bool,
) -> Result<(), String> {
    fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    let needs_china = matches!(
        mode,
        DesktopRoutingMode::BypassChina | DesktopRoutingMode::ReturnChina
    );
    if needs_china {
        write_rule_set_asset(
            directory.join("china-domains.json"),
            LOYALSOLDIER_CHINA_URL,
            false,
            force_refresh,
        )?;
        write_rule_set_asset(
            directory.join("china-ips.json"),
            CHINA_IP_URL,
            true,
            force_refresh,
        )?;
    }
    if mode == DesktopRoutingMode::GfwList {
        write_rule_set_asset(
            directory.join("gfw-domains.json"),
            LOYALSOLDIER_GFW_URL,
            false,
            force_refresh,
        )?;
    }
    Ok(())
}

fn write_rule_set_asset(
    path: PathBuf,
    url: &str,
    ip: bool,
    force_refresh: bool,
) -> Result<(), String> {
    if path.exists() && !force_refresh {
        return Ok(());
    }
    let content = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("routing rules HTTP client could not be created: {error}"))?
        .get(url)
        .send()
        .and_then(|response| response.error_for_status())
        .map_err(|error| format!("routing rules could not be downloaded from {url}: {error}"))?
        .text()
        .map_err(|error| format!("routing rules response could not be read from {url}: {error}"))?;
    let entries = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_whitespace().next())
        .filter(|entry| {
            if ip {
                entry.parse::<std::net::IpAddr>().is_ok() || entry.contains('/')
            } else {
                entry.contains('.') && !entry.contains('/')
            }
        })
        .map(str::to_string)
        .collect::<Vec<_>>();
    if entries.is_empty() {
        return Err(format!(
            "routing rules source returned no usable entries: {url}"
        ));
    }
    let rule = if ip {
        json!({ "ip_cidr": entries })
    } else {
        json!({ "domain_suffix": entries })
    };
    let source = serde_json::to_string_pretty(&json!({ "version": 1, "rules": [rule] }))
        .map_err(|error| error.to_string())?;
    write_managed_text_atomic(&path, &source).map_err(|error| error.to_string())
}

fn parse_routing_mode(value: &str) -> Result<DesktopRoutingMode, String> {
    match value {
        "bypass_china" => Ok(DesktopRoutingMode::BypassChina),
        "gfw_list" => Ok(DesktopRoutingMode::GfwList),
        "direct" => Ok(DesktopRoutingMode::Direct),
        "return_china" => Ok(DesktopRoutingMode::ReturnChina),
        "rule" => Ok(DesktopRoutingMode::Rule),
        _ => Err(
            "routing mode must be bypass_china, gfw_list, direct, return_china, or rule"
                .to_string(),
        ),
    }
}
fn routing_mode_name(mode: DesktopRoutingMode) -> &'static str {
    match mode {
        DesktopRoutingMode::BypassChina => "bypass_china",
        DesktopRoutingMode::GfwList => "gfw_list",
        DesktopRoutingMode::Direct => "direct",
        DesktopRoutingMode::ReturnChina => "return_china",
        DesktopRoutingMode::Rule => "rule",
    }
}
fn routing_mode_label(mode: DesktopRoutingMode) -> &'static str {
    match mode {
        DesktopRoutingMode::BypassChina => "Bypass China",
        DesktopRoutingMode::GfwList => "GFW list",
        DesktopRoutingMode::Direct => "Direct",
        DesktopRoutingMode::ReturnChina => "Return China",
        DesktopRoutingMode::Rule => "Subscription rules",
    }
}

#[tauri::command]
async fn configure_script_runtime(script_runtime_json: String) -> Result<OperationResult, String> {
    run_blocking(move || configure_script_runtime_blocking(script_runtime_json)).await
}

fn configure_script_runtime_blocking(
    script_runtime_json: String,
) -> Result<OperationResult, String> {
    let _ = script_runtime_json;
    Err(
        "Native MITM script execution is unavailable until Windows has a no-network sandbox."
            .to_string(),
    )
}

#[tauri::command]
async fn clear_script_runtime() -> Result<OperationResult, String> {
    run_blocking(clear_script_runtime_blocking).await
}

fn clear_script_runtime_blocking() -> Result<OperationResult, String> {
    let service = NativeWindowsSystemIntegration::new()
        .service_status()
        .map_err(|error| error.to_string())?;
    if !matches!(
        service.state,
        WindowsServiceState::NotInstalled | WindowsServiceState::Stopped
    ) {
        return Err("Disconnect before changing the managed script runtime.".to_string());
    }
    let mut managed = managed_config_or_default()?;
    let native_mitm = managed
        .native_mitm
        .as_mut()
        .ok_or_else(|| "HTTPS MITM is not configured.".to_string())?;
    native_mitm.script_runtime = None;
    write_managed_config(&windows_managed_config_path(), &managed)
        .map_err(|error| error.to_string())?;
    Ok(OperationResult {
        message: "Managed script runtime cleared. Restart the Windows service to apply it."
            .to_string(),
    })
}

#[tauri::command]
async fn enable_https_mitm(state: State<'_, DesktopAppState>) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || enable_https_mitm_blocking(state)).await
}

fn enable_https_mitm_blocking(state: DesktopAppState) -> Result<OperationResult, String> {
    let desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?
        .clone();
    let embedded = active_embedded_config()?
        .ok_or_else(|| "Import a profile before enabling HTTPS MITM.".to_string())?;
    if managed_config_or_default()?
        .native_mitm
        .is_some_and(|native_mitm| native_mitm.script_runtime.is_some())
    {
        return Err(
            "Clear the legacy managed script runtime before enabling HTTPS MITM; Windows script execution requires a no-network sandbox."
                .to_string(),
        );
    }
    let restart = stop_running_service_for_mitm_reconfigure()?;
    let (certificate_path, private_key_path) = ensure_mitm_ca_material()?;
    if let Err(error) = protect_windows_managed_mitm_private_key(&private_key_path) {
        let _ = append_managed_log(
            APP_LOG_SCOPE,
            &format!(
                "native HTTPS MITM private key protection failed: {}",
                error.message
            ),
        );
        let _ = remove_windows_managed_mitm_private_key(&private_key_path);
        return Err(error.message);
    }
    let mut managed = managed_config_or_default()?;
    // The MITM proxy takes the system proxy port and relays every session to
    // the embedded engine behind it; the service runs both.
    managed.native_mitm = Some(WindowsManagedNativeMitmConfig {
        enabled: true,
        listen_host: "127.0.0.1".to_string(),
        listen_port: EMBEDDED_LISTEN_PORT,
        upstream_socks_host: "127.0.0.1".to_string(),
        upstream_socks_port: EMBEDDED_MITM_UPSTREAM_PORT,
        ca_certificate_path: certificate_path.clone(),
        ca_private_key_path: private_key_path,
        log_path: windows_managed_log_directory().join("native-mitm.log"),
        bilibili_web_ad_block_enabled: desktop.bilibili_web_ad_block_enabled,
        script_runtime: None,
    });
    set_embedded_listener(&mut managed, embedded.envelope_path, true);
    write_managed_config(&windows_managed_config_path(), &managed)
        .map_err(|error| format!("Managed configuration update failed: {error}"))?;
    if restart {
        NativeWindowsSystemIntegration::new()
            .start_service()
            .map_err(|error| error.to_string())?;
    }
    Ok(OperationResult {
        message: format!(
            "HTTPS MITM enabled with CA material at {}.",
            certificate_path.display()
        ),
    })
}

#[tauri::command]
async fn disable_https_mitm() -> Result<OperationResult, String> {
    run_blocking(disable_https_mitm_blocking).await
}

fn disable_https_mitm_blocking() -> Result<OperationResult, String> {
    let mut managed = managed_config_or_default()?;
    let native_mitm = managed
        .native_mitm
        .take()
        .ok_or_else(|| "HTTPS MITM is not configured.".to_string())?;
    let restart = stop_running_service_for_mitm_reconfigure()?;
    // The embedded engine takes the system proxy port back.
    if let Some(embedded) = managed.embedded.clone().filter(|embedded| embedded.enabled) {
        set_embedded_listener(&mut managed, embedded.envelope_path, false);
    } else {
        managed.system_proxy = None;
    }
    write_managed_config(&windows_managed_config_path(), &managed)
        .map_err(|error| error.to_string())?;
    let certificate_cleanup_error =
        if let Ok(mut runtime_state) = read_managed_state(&windows_managed_state_path()) {
            if let Some(thumbprint) = runtime_state.native_mitm_certificate_sha1.take() {
                match NativeWindowsSystemIntegration::new().remove_root_certificate(&thumbprint) {
                    Ok(()) => write_managed_state(&windows_managed_state_path(), &runtime_state)
                        .err()
                        .map(|error| error.to_string()),
                    Err(error) => Some(error.to_string()),
                }
            } else {
                None
            }
        } else {
            None
        };
    let private_key_cleanup_error =
        remove_windows_managed_mitm_private_key(&native_mitm.ca_private_key_path)
            .err()
            .map(|error| error.message);
    if restart {
        NativeWindowsSystemIntegration::new()
            .start_service()
            .map_err(|error| error.to_string())?;
    }
    if let Some(error) = certificate_cleanup_error {
        return Err(error);
    }
    if let Some(error) = private_key_cleanup_error {
        return Err(error);
    }
    Ok(OperationResult {
        message: "HTTPS MITM disabled; the embedded engine is the system proxy again.".to_string(),
    })
}

fn stop_running_service_for_mitm_reconfigure() -> Result<bool, String> {
    let integration = NativeWindowsSystemIntegration::new();
    let status = integration
        .service_status()
        .map_err(|error| error.to_string())?;
    if status.state == WindowsServiceState::Running {
        integration
            .stop_service()
            .map_err(|error| error.to_string())?;
        return Ok(true);
    }
    Ok(false)
}

fn ensure_mitm_ca_material() -> Result<(PathBuf, PathBuf), String> {
    let directory = windows_managed_data_directory().join("mitm");
    let certificate_path = directory.join("root-ca.pem");
    let private_key_path = directory.join("root-ca-key.pem");
    if certificate_path.exists() && private_key_path.exists() {
        return Ok((certificate_path, private_key_path));
    }
    fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, MITM_CA_SUBJECT);
    distinguished_name.push(DnType::OrganizationName, "AnixOps NetworkCore");
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key_pair = KeyPair::generate().map_err(|error| error.to_string())?;
    let certificate = params
        .self_signed(&key_pair)
        .map_err(|error| error.to_string())?;
    fs::write(&certificate_path, certificate.pem()).map_err(|error| error.to_string())?;
    fs::write(&private_key_path, key_pair.serialize_pem()).map_err(|error| error.to_string())?;
    Ok((certificate_path, private_key_path))
}

#[tauri::command]
async fn install_certificate(
    path: String,
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || install_certificate_blocking(path, state)).await
}

fn install_certificate_blocking(
    path: String,
    state: DesktopAppState,
) -> Result<OperationResult, String> {
    let thumbprint = NativeWindowsSystemIntegration::new()
        .install_root_certificate(&PathBuf::from(path))
        .map_err(|error| error.to_string())?;
    let mut desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    desktop.certificate_sha1 = Some(thumbprint.clone());
    save_desktop_state(&desktop)?;
    Ok(OperationResult {
        message: format!("Certificate installed: {thumbprint}"),
    })
}

#[tauri::command]
async fn remove_certificate(state: State<'_, DesktopAppState>) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || remove_certificate_blocking(state)).await
}

fn remove_certificate_blocking(state: DesktopAppState) -> Result<OperationResult, String> {
    let mut desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    let thumbprint = desktop
        .certificate_sha1
        .clone()
        .ok_or_else(|| "No GUI-installed certificate is recorded.".to_string())?;
    NativeWindowsSystemIntegration::new()
        .remove_root_certificate(&thumbprint)
        .map_err(|error| error.to_string())?;
    desktop.certificate_sha1 = None;
    save_desktop_state(&desktop)?;
    Ok(OperationResult {
        message: "Certificate removed.".to_string(),
    })
}

#[tauri::command]
async fn install_driver(
    path: String,
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || install_driver_blocking(path, state)).await
}

fn install_driver_blocking(
    path: String,
    state: DesktopAppState,
) -> Result<OperationResult, String> {
    let installed = NativeWindowsSystemIntegration::new()
        .install_driver(&PathBuf::from(path))
        .map_err(|error| error.to_string())?;
    let mut desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    desktop.driver_inf_path = Some(installed.inf_path);
    save_desktop_state(&desktop)?;
    Ok(OperationResult {
        message: "Driver installed.".to_string(),
    })
}

#[tauri::command]
async fn remove_driver(state: State<'_, DesktopAppState>) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || remove_driver_blocking(state)).await
}

fn remove_driver_blocking(state: DesktopAppState) -> Result<OperationResult, String> {
    let mut desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    let path = desktop
        .driver_inf_path
        .clone()
        .ok_or_else(|| "No GUI-installed driver is recorded.".to_string())?;
    NativeWindowsSystemIntegration::new()
        .uninstall_driver(&path)
        .map_err(|error| error.to_string())?;
    desktop.driver_inf_path = None;
    save_desktop_state(&desktop)?;
    Ok(OperationResult {
        message: "Driver removed.".to_string(),
    })
}

fn selected_catalog_node(
    desktop: &DesktopState,
    node_id: &str,
) -> Result<DesktopProfileNode, String> {
    desktop
        .profile_node_catalog
        .iter()
        .find(|node| node.id == node_id)
        .cloned()
        .ok_or_else(|| "Selected node is not part of the current imported profile.".to_string())
}

fn snapshot(
    runtime: &WindowsRuntimeStatus,
    desktop: &DesktopState,
    direct_running: bool,
) -> RuntimeSnapshot {
    let desktop_connected = desktop.runtime_mode == DesktopRuntimeMode::Desktop
        && direct_running
        && read_current_user_system_proxy()
            .ok()
            .is_some_and(|proxy| owns_current_proxy(desktop, &proxy));
    RuntimeSnapshot {
        connection: if desktop_connected {
            "Connected".to_string()
        } else {
            runtime.connection.label().to_string()
        },
        connection_label: if desktop.runtime_mode == DesktopRuntimeMode::Desktop {
            if desktop_connected {
                "Desktop mode is running the embedded engine and managing the current-user proxy."
                    .to_string()
            } else if direct_running {
                "The embedded engine is running; the current-user proxy is not applied.".to_string()
            } else {
                "Desktop mode is selected. Connect to start the embedded engine without the Windows service."
                    .to_string()
            }
        } else {
            runtime.status_line()
        },
        service: StatusFact {
            label: if desktop.runtime_mode == DesktopRuntimeMode::Desktop {
                "Not used".to_string()
            } else {
                format!("{:?}", runtime.service_state)
            },
            detail: if desktop.runtime_mode == DesktopRuntimeMode::Desktop {
                Some("Desktop mode does not start the Windows service.".to_string())
            } else {
                runtime.service_detail.clone()
            },
            tone: if desktop_connected || runtime.connection.is_connected() {
                "success"
            } else {
                "neutral"
            },
        },
        core: if desktop.runtime_mode == DesktopRuntimeMode::Desktop {
            StatusFact {
                label: if direct_running { "Running" } else { "Stopped" }.to_string(),
                detail: Some("Embedded engine in this app".to_string()),
                tone: if direct_running { "success" } else { "neutral" },
            }
        } else {
            core_status(&runtime.core)
        },
        proxy: StatusFact {
            label: runtime
                .system_proxy_enabled
                .map(|enabled| if enabled { "Enabled" } else { "Disabled" }.to_string())
                .unwrap_or_else(|| "Unavailable".to_string()),
            detail: runtime.system_proxy_server.clone(),
            tone: match runtime.system_proxy_matches_managed {
                Some(true) => "success",
                Some(false) => "warning",
                None => "neutral",
            },
        },
        selected_node: desktop.profile_node_id.clone(),
        subscription: desktop.profile_source_url.clone().or_else(|| {
            desktop
                .profile_source_path
                .as_ref()
                .map(|path| path.display().to_string())
        }),
        subscription_last_updated: desktop.profile_last_successful_update.clone(),
        subscription_last_attempt: desktop.profile_last_attempt.clone(),
        subscription_next_attempt: desktop.profile_next_attempt.clone(),
        subscription_refresh_result: desktop.profile_refresh_result.clone(),
        subscription_added_node_count: desktop.profile_added_node_count,
        subscription_removed_node_count: desktop.profile_removed_node_count,
        subscription_changed_node_count: desktop.profile_changed_node_count,
        subscription_refresh_error_code: desktop.profile_refresh_error_code.clone(),
        subscription_error: desktop.profile_last_update_error.clone(),
        last_error: runtime.last_error.clone(),
        configuration_error: runtime.configuration_error.clone(),
        start_after_login: desktop.start_after_login,
        auto_connect: desktop.auto_connect,
        auto_recover_core: desktop.auto_recover_core,
        auto_subscription_refresh: desktop.auto_subscription_refresh,
        auto_select_fastest_node: desktop.auto_select_fastest_node,
        bilibili_web_ad_block_enabled: desktop.bilibili_web_ad_block_enabled,
        script_runtime_configured: managed_script_runtime_configured(),
        dark_theme: desktop.dark_theme,
        runtime_mode: match desktop.runtime_mode {
            DesktopRuntimeMode::Desktop => "desktop".to_string(),
            DesktopRuntimeMode::Service => "service".to_string(),
        },
        routing_mode: routing_mode_name(desktop.routing_mode).to_string(),
        embedded_engine: active_embedded_config().ok().flatten().is_some(),
    }
}

fn managed_script_runtime_configured() -> bool {
    managed_config_or_default()
        .ok()
        .and_then(|managed| managed.native_mitm)
        .and_then(|native_mitm| native_mitm.script_runtime)
        .is_some()
}

fn core_status(status: &ManagedCoreStatus) -> StatusFact {
    StatusFact {
        label: status.label(),
        detail: None,
        tone: match status {
            ManagedCoreStatus::EmbeddedRunning { .. } => "success",
            ManagedCoreStatus::Failed { .. } => "danger",
            ManagedCoreStatus::Starting => "warning",
            ManagedCoreStatus::NotConfigured => "neutral",
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routed_profile() -> Value {
        json!({
            "schema_version": 1,
            "profile_id": "windows-embedded",
            "routing": {
                "outbounds": {
                    "hk": { "type": "shadowsocks" },
                    "jp": { "type": "shadowsocks" },
                    "us": { "type": "shadowsocks" }
                },
                "rules": ["DOMAIN-SUFFIX,example.jp,jp", "FINAL,Proxy"],
                "groups": [
                    { "id": "Proxy", "type": "select", "members": ["Auto", "jp", "DIRECT"], "default": null },
                    { "id": "Auto", "type": "url-test", "members": ["hk", "us"] },
                    { "id": "Streaming", "type": "select", "members": ["us", "hk"], "default": "hk" }
                ]
            }
        })
    }

    #[test]
    fn routed_profile_final_chain_follows_group_choices() {
        let mut profile = routed_profile();
        assert_eq!(
            routed_final_chain(&profile),
            (
                vec!["Proxy".to_string(), "Auto".to_string()],
                Some("hk".to_string())
            )
        );
        assert_eq!(routed_selected_node(&profile).as_deref(), Some("hk"));

        set_routed_group_default(&mut profile, "Proxy", "DIRECT").unwrap();
        assert_eq!(routed_final_chain(&profile).1.as_deref(), Some("DIRECT"));
        assert_eq!(routed_selected_node(&profile), None);
    }

    #[test]
    fn routed_node_switch_uses_the_main_select_group() {
        let mut profile = routed_profile();
        // jp is a member of Proxy, which FINAL reaches first.
        assert_eq!(
            routed_switch_group_for_node(&profile, "jp").as_deref(),
            Some("Proxy")
        );
        // hk is only in the url-test group and a group off FINAL's route.
        assert_eq!(routed_switch_group_for_node(&profile, "hk"), None);

        set_routed_group_default(&mut profile, "Proxy", "jp").unwrap();
        assert_eq!(routed_selected_node(&profile).as_deref(), Some("jp"));
        assert!(set_routed_group_default(&mut profile, "Auto", "us").is_err());
        assert!(set_routed_group_default(&mut profile, "Proxy", "us").is_err());
        assert!(set_routed_group_default(&mut profile, "Missing", "jp").is_err());
    }

    #[test]
    fn routed_group_defaults_survive_a_refresh() {
        let mut previous = routed_profile();
        set_routed_group_default(&mut previous, "Proxy", "jp").unwrap();
        set_routed_group_default(&mut previous, "Streaming", "us").unwrap();
        let mut refreshed = routed_profile();
        refreshed["routing"]["groups"][0]["members"] = json!(["Auto", "DIRECT"]);

        carry_routed_group_defaults(&previous, &mut refreshed);

        // jp left the Proxy group, so its old default is dropped.
        assert_eq!(routed_selected_node(&refreshed).as_deref(), Some("hk"));
        assert_eq!(
            routed_group(&refreshed, "Streaming")
                .and_then(group_choice)
                .as_deref(),
            Some("us")
        );
    }

    #[test]
    fn embedded_groups_label_nodes_by_name() {
        let nodes = vec![node("hk", "Hong Kong"), node("jp", "Tokyo")];
        let groups = embedded_groups(&routed_profile(), &nodes);

        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].tag, "Proxy");
        assert_eq!(groups[0].group_type, "selector");
        assert_eq!(groups[0].selected.as_deref(), Some("Auto"));
        assert_eq!(groups[0].outbound_labels, vec!["Auto", "Tokyo", "DIRECT"]);
        assert_eq!(groups[1].group_type, "urltest");
        assert_eq!(groups[1].selected.as_deref(), Some("hk"));
        assert!(groups.iter().all(|group| group.json.is_empty()));
    }

    #[test]
    fn rule_mode_round_trips() {
        assert_eq!(parse_routing_mode("rule"), Ok(DesktopRoutingMode::Rule));
        assert_eq!(routing_mode_name(DesktopRoutingMode::Rule), "rule");
    }

    fn node(id: &str, label: &str) -> DesktopProfileNode {
        DesktopProfileNode {
            id: id.to_string(),
            label: label.to_string(),
            protocol: "Shadowsocks".to_string(),
            outbound_tag: format!("node-{id}"),
        }
    }

    #[test]
    fn refresh_node_counts_use_stable_node_identity() {
        let previous = vec![node("retained", "Old retained"), node("removed", "Removed")];
        let current = vec![node("retained", "New retained"), node("added", "Added")];

        assert_eq!(
            subscription_node_change_counts(&previous, &current),
            (1, 1, 1)
        );
    }

    #[test]
    fn refresh_error_codes_are_stable_and_redacted() {
        assert_eq!(
            redacted_subscription_error_code(
                "request timed out for https://secret.invalid/?token=redacted"
            ),
            "windows.subscription.fetch_timeout"
        );
        assert_eq!(
            redacted_subscription_error_code("unsupported payload password=never-store"),
            "windows.subscription.refresh_failed"
        );
    }

    #[test]
    fn next_attempt_only_exists_for_enabled_schedule() {
        assert!(scheduled_refresh_timestamp(false).is_none());
        assert!(scheduled_refresh_timestamp(true)
            .as_deref()
            .is_some_and(|value| value.starts_with("unix-epoch-seconds:")));
    }
}
