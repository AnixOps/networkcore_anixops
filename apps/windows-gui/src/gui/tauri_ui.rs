use super::actions::{connection, nodes};
use super::runtime_status::{read_runtime_status, SingBoxProcessStatus, WindowsRuntimeStatus};
use super::startup::{
    load_desktop_state, owns_current_proxy, save_desktop_state, DesktopProfileNode, DesktopState,
    DesktopSubscriptionSource,
};
use super::{
    append_managed_log, load_validated_managed_configuration, managed_config_or_default,
    profile_node_options, profile_node_options_from_selector, write_diagnostic_report_at,
};
use config_core::CoreSubscriptionService;
use control_domain::{PublicEngineKind, PublicEngineRunPlan, SubscriptionService, SubscriptionSource};
use engine_mieru::{
    download_latest_mieru_release, mieru_node_from_descriptor, render_mieru_client_config,
    rollback_mieru_client_config,
    verify_local_mieru_binary, write_mieru_client_config, MieruClientConfigRequest,
    MieruClientConfigWriteRequest, MieruReleaseDownloadRequest,
};
use engine_singbox::{
    inspect_sing_box_native_config, measure_sing_box_clash_api_outbound_delay,
    read_sing_box_clash_api_selector, render_sing_box_local_proxy_selector_config,
    rewrite_sing_box_mixed_inbound_listener, sing_box_config_sha256, GithubSingBoxReleaseInstaller,
    SingBoxInstallRequest, SingBoxLocalControllerConfig, SingBoxLocalProxyConfigRequest,
    SingBoxReleaseInstaller, SingBoxTarget, SingBoxTargetArch, SingBoxTargetOs,
    DEFAULT_SING_BOX_CLASH_API_DELAY_TIMEOUT_MILLIS,
};
use platform_windows::managed::{
    read_managed_state, windows_managed_config_path, windows_managed_data_directory,
    windows_managed_log_directory, windows_managed_state_path, write_managed_config,
    write_managed_state, write_managed_text_atomic, WindowsManagedConfig,
    WindowsManagedNativeMitmConfig, WindowsManagedNativeMitmScriptRuntimeConfig,
    WindowsManagedMieruConfig, WindowsManagedSingBoxConfig, WindowsManagedTunnelConfig, WindowsProxySettings,
    WindowsSystemProxyOwner,
};
use platform_windows::system_integration::{
    current_user_startup_enabled, disable_current_user_startup, enable_current_user_startup,
    read_current_user_system_proxy, NativeWindowsSystemIntegration, WindowsServiceState,
    WindowsSystemIntegration,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::{
    fs,
    time::{Duration, Instant},
};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::{Manager, Runtime, State, WindowEvent};

const APP_LOG_SCOPE: &str = "tauri-gui";
const SING_BOX_DIRECT_LISTEN_PORT: u16 = 7890;
const SING_BOX_MITM_UPSTREAM_PORT: u16 = 7891;
const MITM_CA_SUBJECT: &str = "AnixOps NetworkCore Windows HTTPS MITM CA";
const SUBSCRIPTION_REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);
const NODE_SELECTION_INTERVAL: Duration = Duration::from_secs(30 * 60);
const DEFAULT_NODE_SELECTION_URL: &str = "https://www.gstatic.com/generate_204";

#[derive(Clone)]
struct DesktopAppState {
    desktop: Arc<Mutex<DesktopState>>,
    lifecycle: Arc<RuntimeLifecycle>,
}

struct DesktopTray {
    _icon: TrayIcon,
}

#[derive(Default)]
struct RuntimeLifecycle {
    gui_started_connection: Mutex<bool>,
    core_recovery_attempted: Mutex<bool>,
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
    subscription_error: Option<String>,
    last_error: Option<String>,
    configuration_error: Option<String>,
    start_after_login: bool,
    auto_connect: bool,
    auto_recover_core: bool,
    auto_subscription_refresh: bool,
    auto_select_fastest_node: bool,
    dns_configured: bool,
    script_runtime_configured: bool,
    dark_theme: bool,
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
    last_update_error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct NativeGroupSummary {
    tag: String,
    group_type: String,
    selected: Option<String>,
    outbounds: Vec<String>,
    json: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationResult {
    message: String,
}

struct ImportedMitmProfile {
    executable_path: PathBuf,
    config_path: PathBuf,
    config_parent: PathBuf,
    sing_box_config_snapshot_path: Option<PathBuf>,
    source_path: Option<PathBuf>,
    source_url: Option<String>,
    selected_node_id: Option<String>,
    node_catalog: Vec<DesktopProfileNode>,
    config_sha256: Option<String>,
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
            replace_native_group,
            test_node_delay,
            select_fastest_node,
            save_preferences,
            create_diagnostics,
            import_subscription,
            update_subscription,
            select_subscription,
            remove_subscription,
            check_profile_runtime,
            install_core,
            install_mieru,
            verify_mieru,
            install_service,
            start_service,
            stop_service,
            restore_network_settings,
            configure_tunnel,
            clear_tunnel,
            configure_dns,
            clear_dns,
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
        .tooltip("AnixOps NetworkCore")
        .menu(&menu)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main_window(app),
            "quit" => app.exit(0),
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
    Ok(snapshot(&read_runtime_status(), &desktop))
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
async fn list_native_groups() -> Result<Vec<NativeGroupSummary>, String> {
    run_blocking(list_native_groups_blocking).await
}

fn list_native_groups_blocking() -> Result<Vec<NativeGroupSummary>, String> {
    let Some(sing_box) = managed_config_or_default()?.sing_box else {
        return Ok(Vec::new());
    };
    let content = fs::read_to_string(sing_box.config_path).map_err(|error| error.to_string())?;
    native_groups(&content)
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
    let service = NativeWindowsSystemIntegration::new()
        .service_status()
        .map_err(|error| error.to_string())?;
    if !matches!(
        service.state,
        WindowsServiceState::NotInstalled | WindowsServiceState::Stopped
    ) {
        return Err("Disconnect before changing a native selector group.".to_string());
    }
    let managed = managed_config_or_default()?;
    let sing_box = managed.sing_box.ok_or_else(|| {
        "Import a native sing-box profile before editing selector groups.".to_string()
    })?;
    let raw = fs::read_to_string(&sing_box.config_path).map_err(|error| error.to_string())?;
    let rendered = rewrite_native_selector_default(&raw, &group_tag, &outbound_tag)?;
    write_managed_text_atomic(&sing_box.config_path, &rendered)
        .map_err(|error| error.to_string())?;
    let mut desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    if desktop.profile_config_sha256.is_some() {
        desktop.profile_config_sha256 = Some(sing_box_config_sha256(&rendered));
        save_desktop_state(&desktop)?;
    }
    Ok(OperationResult {
        message: format!("Native selector {group_tag} now defaults to {outbound_tag}."),
    })
}

#[tauri::command]
async fn replace_native_group(
    group_tag: String,
    group_json: String,
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || replace_native_group_blocking(group_tag, group_json, state)).await
}

fn replace_native_group_blocking(
    group_tag: String,
    group_json: String,
    state: DesktopAppState,
) -> Result<OperationResult, String> {
    let service = NativeWindowsSystemIntegration::new()
        .service_status()
        .map_err(|error| error.to_string())?;
    if !matches!(
        service.state,
        WindowsServiceState::NotInstalled | WindowsServiceState::Stopped
    ) {
        return Err("Disconnect before editing a native outbound group.".to_string());
    }
    let managed = managed_config_or_default()?;
    let sing_box = managed.sing_box.ok_or_else(|| {
        "Import a native sing-box profile before editing outbound groups.".to_string()
    })?;
    let raw = fs::read_to_string(&sing_box.config_path).map_err(|error| error.to_string())?;
    let rendered = replace_native_group_json(&raw, &group_tag, &group_json)?;
    write_managed_text_atomic(&sing_box.config_path, &rendered)
        .map_err(|error| error.to_string())?;
    let mut desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    if desktop.profile_config_sha256.is_some() {
        desktop.profile_config_sha256 = Some(sing_box_config_sha256(&rendered));
        save_desktop_state(&desktop)?;
    }
    Ok(OperationResult {
        message: format!("Native outbound group {group_tag} was updated."),
    })
}

fn native_groups(content: &str) -> Result<Vec<NativeGroupSummary>, String> {
    let config: Value = serde_json::from_str(content).map_err(|error| error.to_string())?;
    let outbounds = config
        .get("outbounds")
        .and_then(Value::as_array)
        .ok_or_else(|| "Managed sing-box configuration has no outbound list.".to_string())?;
    Ok(outbounds
        .iter()
        .filter_map(|outbound| {
            let tag = outbound.get("tag").and_then(Value::as_str)?.trim();
            let group_type = outbound.get("type").and_then(Value::as_str)?.trim();
            let members = outbound
                .get("outbounds")
                .and_then(Value::as_array)?
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>();
            if tag.is_empty() || group_type.is_empty() || members.is_empty() {
                return None;
            }
            Some(NativeGroupSummary {
                tag: tag.to_string(),
                group_type: group_type.to_string(),
                selected: outbound
                    .get("default")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                outbounds: members,
                json: serde_json::to_string_pretty(outbound).ok()?,
            })
        })
        .collect())
}

fn rewrite_native_selector_default(
    content: &str,
    group_tag: &str,
    outbound_tag: &str,
) -> Result<String, String> {
    if group_tag.trim().is_empty() || outbound_tag.trim().is_empty() {
        return Err("Native selector group and outbound tags must not be empty.".to_string());
    }
    let mut config: Value = serde_json::from_str(content).map_err(|error| error.to_string())?;
    let outbounds = config
        .get_mut("outbounds")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "Managed sing-box configuration has no outbound list.".to_string())?;
    let selector = outbounds
        .iter_mut()
        .find(|outbound| {
            outbound.get("type").and_then(Value::as_str) == Some("selector")
                && outbound.get("tag").and_then(Value::as_str) == Some(group_tag)
        })
        .ok_or_else(|| "Native selector group was not found.".to_string())?;
    let contains_outbound = selector
        .get("outbounds")
        .and_then(Value::as_array)
        .is_some_and(|members| {
            members
                .iter()
                .any(|member| member.as_str() == Some(outbound_tag))
        });
    if !contains_outbound {
        return Err("Requested outbound is not part of the native selector group.".to_string());
    }
    selector["default"] = Value::String(outbound_tag.to_string());
    serde_json::to_string_pretty(&config).map_err(|error| error.to_string())
}

fn replace_native_group_json(
    content: &str,
    group_tag: &str,
    group_json: &str,
) -> Result<String, String> {
    if group_tag.trim().is_empty() {
        return Err("Native outbound group tag must not be empty.".to_string());
    }
    let replacement: Value = serde_json::from_str(group_json).map_err(|error| error.to_string())?;
    let replacement_tag = replacement
        .get("tag")
        .and_then(Value::as_str)
        .filter(|tag| !tag.trim().is_empty())
        .ok_or_else(|| "Native outbound group JSON requires a tag.".to_string())?;
    if replacement
        .get("type")
        .and_then(Value::as_str)
        .is_none_or(|kind| kind.trim().is_empty())
    {
        return Err("Native outbound group JSON requires a type.".to_string());
    }
    if replacement
        .get("outbounds")
        .and_then(Value::as_array)
        .is_none_or(|members| {
            members.is_empty()
                || members
                    .iter()
                    .any(|member| member.as_str().is_none_or(|tag| tag.trim().is_empty()))
        })
    {
        return Err("Native outbound group JSON requires non-empty outbound tags.".to_string());
    }
    if replacement_tag != group_tag {
        return Err("Native outbound group JSON tag must match the selected group.".to_string());
    }
    let mut config: Value = serde_json::from_str(content).map_err(|error| error.to_string())?;
    let outbounds = config
        .get_mut("outbounds")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "Managed sing-box configuration has no outbound list.".to_string())?;
    let group = outbounds
        .iter_mut()
        .find(|outbound| {
            outbound.get("tag").and_then(Value::as_str) == Some(group_tag)
                && outbound
                    .get("outbounds")
                    .and_then(Value::as_array)
                    .is_some()
        })
        .ok_or_else(|| "Native outbound group was not found.".to_string())?;
    *group = replacement;
    serde_json::to_string_pretty(&config).map_err(|error| error.to_string())
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
    let connected = connection::connect(windows_managed_config_path(), desktop.clone())?;
    let mut persisted = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    persisted.proxy_snapshot = Some(connected.snapshot);
    persisted.applied_proxy = Some(connected.applied_proxy);
    save_desktop_state(&persisted)?;
    mark_gui_started_connection(&state);
    Ok(OperationResult {
        message: "Connected. The managed core and current-user proxy are verified.".to_string(),
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
    let message = connection::disconnect(desktop)?;
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
    let message = match connection::restart(windows_managed_config_path(), desktop)? {
        connection::RestartedService::Desktop(_) => {
            "Service restarted and desktop proxy settings were reapplied.".to_string()
        }
        connection::RestartedService::ServiceManaged => {
            "Service restart was submitted. Waiting for managed runtime status.".to_string()
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
    let node = selected_catalog_node(&desktop, &node_id)?;
    let config_sha256 = desktop.profile_config_sha256.ok_or_else(|| {
        "Import the current generated profile before switching its active node.".to_string()
    })?;
    let switched = nodes::switch_generated_node(node_id.clone(), node.outbound_tag, config_sha256)?;
    let mut persisted = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    persisted.profile_node_id = Some(switched.node_id);
    persisted.profile_config_sha256 = Some(switched.config_sha256);
    save_desktop_state(&persisted)?;
    Ok(OperationResult {
        message: "Active node switched and saved for the next service start.".to_string(),
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
    let mut fastest: Option<(DesktopProfileNode, u64)> = None;
    for node in &desktop.profile_node_catalog {
        let report = match measure_sing_box_clash_api_outbound_delay(
            &SingBoxLocalControllerConfig::loopback_selector(),
            &node.outbound_tag,
            test_url,
            DEFAULT_SING_BOX_CLASH_API_DELAY_TIMEOUT_MILLIS,
        ) {
            Ok(report) => report,
            Err(_) => continue,
        };
        if fastest
            .as_ref()
            .is_none_or(|(_, delay)| report.delay_millis < *delay)
        {
            fastest = Some((node.clone(), report.delay_millis));
        }
    }
    let (node, delay_millis) =
        fastest.ok_or_else(|| "No imported node returned a successful delay test.".to_string())?;
    if desktop.profile_node_id.as_deref() == Some(node.id.as_str()) {
        return Ok(OperationResult {
            message: format!(
                "{} is already the fastest responding node at {delay_millis} ms.",
                node.label
            ),
        });
    }
    let config_sha256 = desktop.profile_config_sha256.ok_or_else(|| {
        "Import a generated NodeCatalog profile before selecting the fastest node.".to_string()
    })?;
    let switched = nodes::switch_generated_node(node.id.clone(), node.outbound_tag, config_sha256)?;
    let mut persisted = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    persisted.profile_node_id = Some(switched.node_id);
    persisted.profile_config_sha256 = Some(switched.config_sha256);
    save_desktop_state(&persisted)?;
    Ok(OperationResult {
        message: format!("Selected fastest node: {} ({delay_millis} ms).", node.label),
    })
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
    let report = measure_sing_box_clash_api_outbound_delay(
        &SingBoxLocalControllerConfig::loopback_selector(),
        &node.outbound_tag,
        &url,
        DEFAULT_SING_BOX_CLASH_API_DELAY_TIMEOUT_MILLIS,
    )
    .map_err(|error| error.to_string())?;
    Ok(OperationResult {
        message: format!("{} ms via {}", report.delay_millis, report.test_url),
    })
}

#[tauri::command]
async fn save_preferences(
    start_after_login: bool,
    auto_connect: bool,
    auto_recover_core: bool,
    auto_subscription_refresh: bool,
    auto_select_fastest_node: bool,
    dark_theme: bool,
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || {
        save_preferences_blocking(
            start_after_login,
            auto_connect,
            auto_recover_core,
            auto_subscription_refresh,
            auto_select_fastest_node,
            dark_theme,
            state,
        )
    })
    .await
}

fn save_preferences_blocking(
    start_after_login: bool,
    auto_connect: bool,
    auto_recover_core: bool,
    auto_subscription_refresh: bool,
    auto_select_fastest_node: bool,
    dark_theme: bool,
    state: DesktopAppState,
) -> Result<OperationResult, String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let startup_enabled =
        current_user_startup_enabled(&executable).map_err(|error| error.to_string())?;
    if start_after_login && !startup_enabled {
        enable_current_user_startup(&executable).map_err(|error| error.to_string())?;
    } else if !start_after_login && startup_enabled {
        disable_current_user_startup(&executable).map_err(|error| error.to_string())?;
    }
    let mut desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    desktop.start_after_login = start_after_login;
    desktop.auto_connect = auto_connect;
    desktop.auto_recover_core = auto_recover_core;
    desktop.auto_subscription_refresh = auto_subscription_refresh;
    desktop.auto_select_fastest_node = auto_select_fastest_node;
    desktop.dark_theme = dark_theme;
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

#[tauri::command]
async fn check_profile_runtime(
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || check_profile_runtime_blocking(state)).await
}

fn check_profile_runtime_blocking(state: DesktopAppState) -> Result<OperationResult, String> {
    let desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    let status =
        read_sing_box_clash_api_selector(&SingBoxLocalControllerConfig::loopback_selector())
            .map_err(|error| error.to_string())?;
    if !status
        .outbound_tags
        .iter()
        .any(|outbound_tag| outbound_tag == &status.current_outbound_tag)
    {
        return Err(
            "sing-box controller returned an active outbound outside the generated selector"
                .to_string(),
        );
    }
    let active = desktop
        .profile_node_catalog
        .iter()
        .find(|node| node.outbound_tag == status.current_outbound_tag)
        .map(|node| node.label.clone())
        .unwrap_or(status.current_outbound_tag);
    Ok(OperationResult {
        message: format!(
            "Selector ready: {active} ({} nodes)",
            status.outbound_tags.len()
        ),
    })
}

fn record_subscription_import(location: &str, desktop: &mut DesktopState) -> Result<(), String> {
    match import_subscription_at(location, desktop) {
        Ok(()) => {
            let timestamp = super::current_local_timestamp();
            desktop.profile_last_successful_update = Some(timestamp.clone());
            desktop.profile_last_update_error = None;
            record_subscription_source(desktop, location, Some(timestamp), None);
            save_desktop_state(desktop)
        }
        Err(error) => {
            desktop.profile_last_update_error = Some(error.clone());
            record_subscription_source(desktop, location, None, Some(error.clone()));
            let _ = save_desktop_state(desktop);
            Err(error)
        }
    }
}

fn record_subscription_source(
    desktop: &mut DesktopState,
    location: &str,
    successful_update: Option<String>,
    update_error: Option<String>,
) {
    let id = subscription_source_id(location);
    if let Some(source) = desktop
        .subscription_sources
        .iter_mut()
        .find(|source| source.id == id)
    {
        source.last_successful_update = successful_update;
        source.last_update_error = update_error;
        return;
    }
    desktop
        .subscription_sources
        .push(DesktopSubscriptionSource {
            id,
            location: location.to_string(),
            last_successful_update: successful_update,
            last_update_error: update_error,
        });
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
    let executable_path = desktop
        .sing_box_executable_path
        .clone()
        .ok_or_else(|| "Install sing-box before importing a profile".to_string())?;
    let config_path = windows_managed_data_directory()
        .join("sing-box")
        .join("config.json");
    let config_parent = config_path
        .parent()
        .ok_or_else(|| "sing-box config path has no parent directory".to_string())?
        .to_path_buf();
    fs::create_dir_all(&config_parent).map_err(|error| error.to_string())?;
    let (proxy, selected_node_id, node_catalog, config_sha256) = if let Some(native) =
        inspect_sing_box_native_config(&payload)
    {
        write_managed_text_atomic(&config_path, &native.json).map_err(|error| error.to_string())?;
        (
            native.local_http_proxy.map(|proxy| proxy.endpoint()),
            None,
            Vec::new(),
            None,
        )
    } else {
        let service = CoreSubscriptionService::new();
        let source = SubscriptionSource {
            id: "windows-tauri-profile".to_string(),
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
        let selected_node_id = desktop
            .profile_node_id
            .as_deref()
            .filter(|id| catalog.nodes.iter().any(|node| node.id == *id));
        let run_plan = PublicEngineRunPlan::select(&catalog.nodes, selected_node_id)
            .map_err(|error| error.message)?;
        if run_plan.engine == PublicEngineKind::Mieru {
            return import_mieru_subscription_plan(&run_plan, desktop);
        }
        let source_options = profile_node_options(&catalog.nodes);
        let rendered = render_sing_box_local_proxy_selector_config(
            &SingBoxLocalProxyConfigRequest {
                nodes: catalog.nodes,
                selected_node_id: desktop.profile_node_id.clone(),
                listen_host: "127.0.0.1".to_string(),
                listen_port: 7890,
            },
            &SingBoxLocalControllerConfig::loopback_selector(),
        )
        .map_err(|error| error.to_string())?;
        let node_catalog =
            profile_node_options_from_selector(&rendered.selectable_nodes, &source_options)?;
        write_managed_text_atomic(&config_path, &rendered.json)
            .map_err(|error| error.to_string())?;
        (
            Some("127.0.0.1:7890".to_string()),
            Some(rendered.selected_node_id),
            node_catalog,
            Some(sing_box_config_sha256(&rendered.json)),
        )
    };
    let mut managed = managed_config_or_default()?;
    managed.system_proxy = proxy.map(|server| WindowsProxySettings {
        enabled: true,
        server,
        bypass: "<local>".to_string(),
    });
    managed.system_proxy_owner = WindowsSystemProxyOwner::Desktop;
    managed.sing_box = Some(WindowsManagedSingBoxConfig {
        enabled: true,
        executable_path,
        config_path,
        working_directory: Some(config_parent),
        log_path: windows_managed_log_directory().join("sing-box.log"),
    });
    write_managed_config(&windows_managed_config_path(), &managed)
        .map_err(|error| error.to_string())?;
    desktop.profile_source_path = source_path;
    desktop.profile_source_url = source_url;
    desktop.profile_node_id = selected_node_id;
    desktop.profile_node_catalog = node_catalog;
    desktop.profile_config_sha256 = config_sha256;
    Ok(())
}

fn import_mieru_subscription_plan(
    plan: &PublicEngineRunPlan,
    desktop: &mut DesktopState,
) -> Result<(), String> {
    let mut managed = managed_config_or_default()?;
    let mieru = managed.mieru.clone().filter(|config| config.enabled).ok_or_else(|| {
        "Selected Mieru node requires an enabled managed Mieru executable, digest, and listener configuration."
            .to_string()
    })?;
    mieru.validate().map_err(|error| error.message)?;
    let node = mieru_node_from_descriptor(&plan.node).map_err(|error| error.message)?;
    let rendered = render_mieru_client_config(&MieruClientConfigRequest {
        node,
        socks5_host: mieru.socks5_host.clone(),
        socks5_port: mieru.socks5_port,
    })
    .map_err(|error| error.message)?;
    let snapshot_path = mieru.config_path.with_extension("before-networkcore.json");
    let write_report = write_mieru_client_config(&MieruClientConfigWriteRequest {
        config_path: mieru.config_path.clone(),
        snapshot_path,
        content: rendered.content,
    })
    .map_err(|error| error.message)?;
    managed.sing_box = None;
    managed.mieru = Some(WindowsManagedMieruConfig { enabled: true, ..mieru.clone() });
    managed.system_proxy = Some(WindowsProxySettings {
        enabled: true,
        server: format!("{}:{}", mieru.socks5_host, mieru.socks5_port),
        bypass: "<local>".to_string(),
    });
    managed.system_proxy_owner = WindowsSystemProxyOwner::Desktop;
    if let Err(error) = write_managed_config(&windows_managed_config_path(), &managed) {
        let _ = rollback_mieru_client_config(
            &mieru.config_path,
            &write_report.snapshot_path.unwrap_or_default(),
            write_report.snapshot_written,
        );
        return Err(error.message);
    }
    desktop.profile_node_id = Some(plan.node.id.clone());
    desktop.profile_node_catalog.clear();
    desktop.profile_config_sha256 = None;
    Ok(())
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
async fn install_core(state: State<'_, DesktopAppState>) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || install_core_blocking(state)).await
}

#[tauri::command]
async fn install_mieru(
    download_url: String,
    destination_path: String,
    expected_sha256: String,
    confirm: bool,
) -> Result<OperationResult, String> {
    run_blocking(move || {
        let report = download_latest_mieru_release(&MieruReleaseDownloadRequest {
            download_url,
            destination_path: PathBuf::from(destination_path),
            expected_sha256,
            confirmed: confirm,
            force: false,
        })
        .map_err(|error| error.to_string())?;
        Ok(OperationResult {
            message: format!("Mieru verified at {}", report.destination_path.display()),
        })
    })
    .await
}

#[tauri::command]
async fn verify_mieru(
    executable_path: String,
    expected_sha256: String,
) -> Result<OperationResult, String> {
    run_blocking(move || {
        let report = verify_local_mieru_binary(Path::new(&executable_path), Some(&expected_sha256))
            .map_err(|error| error.to_string())?;
        Ok(OperationResult {
            message: format!("Mieru digest verified: {}", report.sha256),
        })
    })
    .await
}

fn install_core_blocking(state: DesktopAppState) -> Result<OperationResult, String> {
    let installer = GithubSingBoxReleaseInstaller::new().map_err(|error| error.to_string())?;
    let report = installer
        .install_latest(&SingBoxInstallRequest {
            install_root: windows_managed_data_directory()
                .join("sing-box")
                .join("engine"),
            target: SingBoxTarget::new(SingBoxTargetOs::Windows, SingBoxTargetArch::Amd64),
            force: false,
        })
        .map_err(|error| error.to_string())?;
    let mut desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    desktop.sing_box_executable_path = Some(report.executable_path.clone());
    save_desktop_state(&desktop)?;
    Ok(OperationResult {
        message: format!("sing-box installed at {}", report.executable_path.display()),
    })
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
async fn configure_dns(
    dns_json: String,
    state: State<'_, DesktopAppState>,
) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || configure_dns_blocking(dns_json, state)).await
}

fn configure_dns_blocking(
    dns_json: String,
    state: DesktopAppState,
) -> Result<OperationResult, String> {
    let dns: Value = serde_json::from_str(&dns_json).map_err(|error| error.to_string())?;
    if !dns.is_object() {
        return Err("sing-box DNS configuration must be a JSON object.".to_string());
    }
    update_managed_sing_box_dns(Some(dns), &state)?;
    Ok(OperationResult {
        message: "Managed DNS configuration saved. Restart the Windows service to apply it."
            .to_string(),
    })
}

#[tauri::command]
async fn clear_dns(state: State<'_, DesktopAppState>) -> Result<OperationResult, String> {
    let state = state.inner().clone();
    run_blocking(move || clear_dns_blocking(state)).await
}

fn clear_dns_blocking(state: DesktopAppState) -> Result<OperationResult, String> {
    update_managed_sing_box_dns(None, &state)?;
    Ok(OperationResult {
        message: "Managed DNS configuration cleared. Restart the Windows service to apply it."
            .to_string(),
    })
}

#[tauri::command]
async fn configure_script_runtime(script_runtime_json: String) -> Result<OperationResult, String> {
    run_blocking(move || configure_script_runtime_blocking(script_runtime_json)).await
}

fn configure_script_runtime_blocking(
    script_runtime_json: String,
) -> Result<OperationResult, String> {
    let script_runtime: WindowsManagedNativeMitmScriptRuntimeConfig =
        serde_json::from_str(&script_runtime_json).map_err(|error| error.to_string())?;
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
        .ok_or_else(|| "Enable HTTPS MITM before configuring script dispatch.".to_string())?;
    native_mitm.script_runtime = Some(script_runtime);
    write_managed_config(&windows_managed_config_path(), &managed)
        .map_err(|error| error.to_string())?;
    Ok(OperationResult {
        message: "Managed script runtime saved. Restart the Windows service to apply it."
            .to_string(),
    })
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

fn update_managed_sing_box_dns(dns: Option<Value>, state: &DesktopAppState) -> Result<(), String> {
    let service = NativeWindowsSystemIntegration::new()
        .service_status()
        .map_err(|error| error.to_string())?;
    if !matches!(
        service.state,
        WindowsServiceState::NotInstalled | WindowsServiceState::Stopped
    ) {
        return Err("Disconnect before changing the managed DNS configuration.".to_string());
    }
    let managed = managed_config_or_default()?;
    let sing_box = managed
        .sing_box
        .ok_or_else(|| "Import a profile before configuring managed DNS.".to_string())?;
    let raw = fs::read_to_string(&sing_box.config_path).map_err(|error| error.to_string())?;
    let mut config: Value = serde_json::from_str(&raw).map_err(|error| error.to_string())?;
    let object = config
        .as_object_mut()
        .ok_or_else(|| "Managed sing-box configuration must be a JSON object.".to_string())?;
    match dns {
        Some(value) => {
            object.insert("dns".to_string(), value);
        }
        None => {
            object.remove("dns");
        }
    }
    let rendered = serde_json::to_string_pretty(&config).map_err(|error| error.to_string())?;
    write_managed_text_atomic(&sing_box.config_path, &rendered)
        .map_err(|error| error.to_string())?;
    let mut desktop = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    if desktop.profile_config_sha256.is_some() {
        desktop.profile_config_sha256 = Some(sing_box_config_sha256(&rendered));
        save_desktop_state(&desktop)?;
    }
    Ok(())
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
    let location = desktop
        .profile_source_url
        .clone()
        .or_else(|| {
            desktop
                .profile_source_path
                .as_ref()
                .map(|path| path.display().to_string())
        })
        .ok_or_else(|| "Import a profile before enabling HTTPS MITM.".to_string())?;
    let restart = stop_running_service_for_mitm_reconfigure()?;
    let (certificate_path, private_key_path) = ensure_mitm_ca_material()?;
    let previous_sing_box_config = read_managed_sing_box_config_before_import()?;
    let imported = prepare_mitm_profile(&location, &desktop)?;
    let mut managed = managed_config_or_default()?;
    let script_runtime = managed
        .native_mitm
        .as_ref()
        .and_then(|native_mitm| native_mitm.script_runtime.clone());
    managed.system_proxy = Some(WindowsProxySettings {
        enabled: true,
        server: format!("127.0.0.1:{SING_BOX_DIRECT_LISTEN_PORT}"),
        bypass: "<local>".to_string(),
    });
    managed.system_proxy_owner = WindowsSystemProxyOwner::Service;
    managed.sing_box = Some(WindowsManagedSingBoxConfig {
        enabled: true,
        executable_path: imported.executable_path.clone(),
        config_path: imported.config_path.clone(),
        working_directory: Some(imported.config_parent.clone()),
        log_path: windows_managed_log_directory().join("sing-box.log"),
    });
    managed.native_mitm = Some(WindowsManagedNativeMitmConfig {
        enabled: true,
        listen_host: "127.0.0.1".to_string(),
        listen_port: SING_BOX_DIRECT_LISTEN_PORT,
        upstream_socks_host: "127.0.0.1".to_string(),
        upstream_socks_port: SING_BOX_MITM_UPSTREAM_PORT,
        ca_certificate_path: certificate_path.clone(),
        ca_private_key_path: private_key_path,
        log_path: windows_managed_log_directory().join("native-mitm.log"),
        sing_box_config_snapshot_path: imported.sing_box_config_snapshot_path.clone(),
        script_runtime,
    });
    write_imported_profile_managed_config(
        &managed,
        &imported.config_path,
        previous_sing_box_config.as_deref(),
    )?;
    let mut persisted = state
        .desktop
        .lock()
        .map_err(|_| "desktop state lock failed")?;
    persisted.profile_source_path = imported.source_path;
    persisted.profile_source_url = imported.source_url;
    persisted.profile_node_id = imported.selected_node_id;
    persisted.profile_node_catalog = imported.node_catalog;
    persisted.profile_config_sha256 = imported.config_sha256;
    save_desktop_state(&persisted)?;
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
    let sing_box = managed.sing_box.as_mut().ok_or_else(|| {
        "Managed sing-box configuration is required to disable HTTPS MITM.".to_string()
    })?;
    let native_snapshot = native_mitm
        .sing_box_config_snapshot_path
        .as_ref()
        .map(|path| {
            let content = fs::read_to_string(path).map_err(|error| {
                format!("Native sing-box MITM rollback snapshot could not be read: {error}")
            })?;
            let local_http_proxy = inspect_sing_box_native_config(&content)
                .and_then(|config| config.local_http_proxy)
                .map(|proxy| proxy.endpoint());
            Ok::<_, String>((path.clone(), content, local_http_proxy))
        })
        .transpose()?;
    let restart = stop_running_service_for_mitm_reconfigure()?;
    let direct_proxy_server = if let Some((_, content, local_http_proxy)) = &native_snapshot {
        write_managed_text_atomic(&sing_box.config_path, content).map_err(|error| {
            format!("Native sing-box configuration could not be restored after HTTPS MITM: {error}")
        })?;
        local_http_proxy.clone()
    } else {
        rewrite_managed_sing_box_listen_port(sing_box, SING_BOX_DIRECT_LISTEN_PORT)?;
        Some(format!("127.0.0.1:{SING_BOX_DIRECT_LISTEN_PORT}"))
    };
    managed.system_proxy = direct_proxy_server.map(|server| WindowsProxySettings {
        enabled: true,
        server,
        bypass: "<local>".to_string(),
    });
    managed.system_proxy_owner = WindowsSystemProxyOwner::Service;
    write_managed_config(&windows_managed_config_path(), &managed)
        .map_err(|error| error.to_string())?;
    if let Some((path, _, _)) = native_snapshot {
        if let Err(error) = fs::remove_file(&path) {
            let _ = append_managed_log(
                APP_LOG_SCOPE,
                &format!(
                    "native sing-box MITM rollback snapshot retained at {}: {error}",
                    path.display()
                ),
            );
        }
    }
    if let Ok(mut runtime_state) = read_managed_state(&windows_managed_state_path()) {
        if let Some(thumbprint) = runtime_state.native_mitm_certificate_sha1.take() {
            NativeWindowsSystemIntegration::new()
                .remove_root_certificate(&thumbprint)
                .map_err(|error| error.to_string())?;
            write_managed_state(&windows_managed_state_path(), &runtime_state)
                .map_err(|error| error.to_string())?;
        }
    }
    let _ = fs::remove_file(native_mitm.ca_private_key_path);
    if restart {
        NativeWindowsSystemIntegration::new()
            .start_service()
            .map_err(|error| error.to_string())?;
    }
    Ok(OperationResult {
        message: "HTTPS MITM disabled and the previous sing-box configuration was restored."
            .to_string(),
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

fn rewrite_managed_sing_box_listen_port(
    sing_box: &mut WindowsManagedSingBoxConfig,
    listen_port: u16,
) -> Result<(), String> {
    let raw = fs::read_to_string(&sing_box.config_path).map_err(|error| {
        format!("Managed sing-box config could not be read for HTTPS MITM reconfiguration: {error}")
    })?;
    let rewritten = rewrite_sing_box_mixed_inbound_listener(&raw, "127.0.0.1", listen_port)
        .map_err(|error| error.to_string())?;
    write_managed_text_atomic(&sing_box.config_path, &rewritten).map_err(|error| {
        format!(
            "Managed sing-box config could not be written for HTTPS MITM reconfiguration: {error}"
        )
    })?;
    sing_box.enabled = true;
    Ok(())
}

fn prepare_mitm_profile(
    location: &str,
    desktop: &DesktopState,
) -> Result<ImportedMitmProfile, String> {
    let (payload, source_path, source_url) = read_subscription(location)?;
    let executable_path = desktop
        .sing_box_executable_path
        .clone()
        .ok_or_else(|| "Install sing-box before enabling HTTPS MITM.".to_string())?;
    let config_path = windows_managed_data_directory()
        .join("sing-box")
        .join("config.json");
    let config_parent = config_path
        .parent()
        .ok_or_else(|| "sing-box config path has no parent directory".to_string())?
        .to_path_buf();
    fs::create_dir_all(&config_parent).map_err(|error| error.to_string())?;
    if let Some(native) = inspect_sing_box_native_config(&payload) {
        let snapshot = stage_native_sing_box_mitm_config(
            &config_path,
            &native.json,
            SING_BOX_MITM_UPSTREAM_PORT,
        )?;
        return Ok(ImportedMitmProfile {
            executable_path,
            config_path,
            config_parent,
            sing_box_config_snapshot_path: Some(snapshot),
            source_path,
            source_url,
            selected_node_id: None,
            node_catalog: Vec::new(),
            config_sha256: None,
        });
    }
    let service = CoreSubscriptionService::new();
    let source = SubscriptionSource {
        id: "windows-tauri-mitm-profile".to_string(),
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
    let source_options = profile_node_options(&catalog.nodes);
    let rendered = render_sing_box_local_proxy_selector_config(
        &SingBoxLocalProxyConfigRequest {
            nodes: catalog.nodes,
            selected_node_id: desktop.profile_node_id.clone(),
            listen_host: "127.0.0.1".to_string(),
            listen_port: SING_BOX_MITM_UPSTREAM_PORT,
        },
        &SingBoxLocalControllerConfig::loopback_selector(),
    )
    .map_err(|error| error.to_string())?;
    let node_catalog =
        profile_node_options_from_selector(&rendered.selectable_nodes, &source_options)?;
    write_managed_text_atomic(&config_path, &rendered.json).map_err(|error| error.to_string())?;
    Ok(ImportedMitmProfile {
        executable_path,
        config_path,
        config_parent,
        sing_box_config_snapshot_path: None,
        source_path,
        source_url,
        selected_node_id: Some(rendered.selected_node_id),
        node_catalog,
        config_sha256: Some(sing_box_config_sha256(&rendered.json)),
    })
}

fn stage_native_sing_box_mitm_config(
    config_path: &Path,
    original_json: &str,
    listen_port: u16,
) -> Result<PathBuf, String> {
    let rewritten =
        rewrite_sing_box_mixed_inbound_listener(original_json, "127.0.0.1", listen_port)
            .map_err(|error| error.to_string())?;
    let snapshot_path = windows_managed_data_directory()
        .join("mitm")
        .join("sing-box-config.before-mitm.json");
    write_managed_text_atomic(&snapshot_path, original_json).map_err(|error| {
        format!("Native sing-box MITM rollback snapshot could not be written: {error}")
    })?;
    write_managed_text_atomic(config_path, &rewritten).map_err(|error| {
        format!("Native sing-box configuration could not be prepared for HTTPS MITM: {error}")
    })?;
    Ok(snapshot_path)
}

fn read_managed_sing_box_config_before_import() -> Result<Option<String>, String> {
    let config_path = windows_managed_data_directory()
        .join("sing-box")
        .join("config.json");
    match fs::read_to_string(&config_path) {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "Existing managed sing-box configuration could not be read from {}: {error}",
            config_path.display()
        )),
    }
}

fn write_imported_profile_managed_config(
    managed: &WindowsManagedConfig,
    config_path: &Path,
    previous_config: Option<&str>,
) -> Result<(), String> {
    if let Err(error) = write_managed_config(&windows_managed_config_path(), managed) {
        let original_error = error.to_string();
        if let Err(rollback) = restore_imported_sing_box_config(config_path, previous_config) {
            return Err(format!(
                "Managed configuration update failed: {original_error}; the imported sing-box configuration could not be rolled back: {rollback}"
            ));
        }
        return Err(format!(
            "Managed configuration update failed: {original_error}"
        ));
    }
    Ok(())
}

fn restore_imported_sing_box_config(
    config_path: &Path,
    previous_config: Option<&str>,
) -> Result<(), String> {
    match previous_config {
        Some(content) => write_managed_text_atomic(config_path, content).map_err(|error| {
            format!(
                "prior sing-box configuration could not be written to {}: {error}",
                config_path.display()
            )
        }),
        None => match fs::remove_file(config_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "new sing-box configuration could not be removed from {}: {error}",
                config_path.display()
            )),
        },
    }
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

fn snapshot(runtime: &WindowsRuntimeStatus, desktop: &DesktopState) -> RuntimeSnapshot {
    RuntimeSnapshot {
        connection: runtime.connection.label().to_string(),
        connection_label: runtime.status_line(),
        service: StatusFact {
            label: format!("{:?}", runtime.service_state),
            detail: runtime.service_detail.clone(),
            tone: if runtime.connection.is_connected() {
                "success"
            } else {
                "neutral"
            },
        },
        core: core_status(&runtime.sing_box),
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
        subscription_error: desktop.profile_last_update_error.clone(),
        last_error: runtime.last_error.clone(),
        configuration_error: runtime.configuration_error.clone(),
        start_after_login: desktop.start_after_login,
        auto_connect: desktop.auto_connect,
        auto_recover_core: desktop.auto_recover_core,
        auto_subscription_refresh: desktop.auto_subscription_refresh,
        auto_select_fastest_node: desktop.auto_select_fastest_node,
        dns_configured: managed_dns_configured(),
        script_runtime_configured: managed_script_runtime_configured(),
        dark_theme: desktop.dark_theme,
    }
}

fn managed_dns_configured() -> bool {
    managed_config_or_default()
        .ok()
        .and_then(|managed| managed.sing_box)
        .and_then(|sing_box| fs::read_to_string(sing_box.config_path).ok())
        .and_then(|config| serde_json::from_str::<Value>(&config).ok())
        .and_then(|config| config.get("dns").cloned())
        .is_some()
}

fn managed_script_runtime_configured() -> bool {
    managed_config_or_default()
        .ok()
        .and_then(|managed| managed.native_mitm)
        .and_then(|native_mitm| native_mitm.script_runtime)
        .is_some()
}

fn core_status(status: &SingBoxProcessStatus) -> StatusFact {
    StatusFact {
        label: status.label(),
        detail: None,
        tone: match status {
            SingBoxProcessStatus::Running { .. } => "success",
            SingBoxProcessStatus::Exited { .. } | SingBoxProcessStatus::Unavailable { .. } => {
                "danger"
            }
            SingBoxProcessStatus::Starting => "warning",
            SingBoxProcessStatus::NotConfigured => "neutral",
        },
    }
}
