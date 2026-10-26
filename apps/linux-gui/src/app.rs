//! The Tauri window: the shared React interface (`apps/windows-gui/ui`) over the Linux backend. Command names
//! and argument shapes match the interface's `bridge.ts`; Windows-only commands answer that they are not
//! available, and the snapshot's `platform` field hides them in the interface.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::Duration;

use engine_embedded::profile::RoutingMode;
use networkcore_linux_gui::backend::engine;
use networkcore_linux_gui::backend::state::Store;
use networkcore_linux_gui::backend::system_proxy::Desktop;
use networkcore_linux_gui::backend::{
    autostart, format_delay, Backend, GroupSummary, NodeSummary, OperationResult, PreferencesInput,
    RuntimeSnapshot, SubscriptionSummary, PASTED_LOCATION,
};
use tauri::{RunEvent, State};

/// The URL the delay tests fetch, as on Windows.
const DELAY_URL: &str = "https://www.gstatic.com/generate_204";
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
const UNAVAILABLE: &str = "Not available on Linux yet";

struct AppState(Arc<Mutex<Backend>>);

fn lock(backend: &Mutex<Backend>) -> MutexGuard<'_, Backend> {
    backend.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Runs `task` on a blocking thread with the backend locked, so the window keeps polling meanwhile.
async fn with_backend<T, F>(state: &AppState, task: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&mut Backend) -> Result<T, String> + Send + 'static,
{
    let backend = state.0.clone();
    tauri::async_runtime::spawn_blocking(move || task(&mut lock(&backend)))
        .await
        .map_err(|error| error.to_string())?
}

/// Runs `task` on a blocking thread without the lock, for network work.
async fn off_lock<T, F>(task: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(task)
        .await
        .map_err(|error| error.to_string())?
}

fn http_get(url: &str) -> Result<String, reqwest::Error> {
    reqwest::blocking::Client::builder()
        .timeout(FETCH_TIMEOUT)
        .build()?
        .get(url)
        .send()
        .and_then(reqwest::blocking::Response::error_for_status)?
        .text()
}

/// A URL's body, a local file, or the pasted share links themselves.
fn fetch(location: &str) -> Result<String, String> {
    if location.starts_with("https://") || location.starts_with("http://") {
        return http_get(location)
            .map_err(|error| format!("the subscription could not be downloaded: {error}"));
    }
    if location.contains("://") {
        return Ok(location.to_string());
    }
    let path = match location.strip_prefix("~/") {
        Some(rest) => std::env::var_os("HOME").map_or_else(
            || PathBuf::from(location),
            |home| PathBuf::from(home).join(rest),
        ),
        None => PathBuf::from(location),
    };
    fs::read_to_string(&path)
        .map_err(|error| format!("{} could not be read: {error}", path.display()))
}

/// Downloads the public rule lists `mode` needs (all of them with `force`, else the missing ones) outside the
/// lock and caches them.
async fn download_rule_lists(
    state: &AppState,
    mode: RoutingMode,
    force: bool,
) -> Result<usize, String> {
    let (store, lists) = {
        let backend = lock(&state.0);
        (backend.store(), backend.rule_lists_to_download(mode, force))
    };
    off_lock(move || {
        for list in &lists {
            let content = http_get(list.url()).map_err(|error| {
                format!(
                    "the routing rules could not be downloaded from {}: {error}",
                    list.url()
                )
            })?;
            let entries = list.parse(&content);
            if entries.is_empty() {
                return Err(format!("{} returned no usable entries", list.url()));
            }
            store
                .write_rule_list(*list, &entries)
                .map_err(|error| format!("the routing rules could not be saved: {error}"))?;
        }
        Ok(lists.len())
    })
    .await
}

/// Connects after fetching any rule list the routing mode still lacks.
async fn connect_with_rules(state: &AppState) -> Result<OperationResult, String> {
    let mode = lock(&state.0).routing_mode();
    if let Err(error) = download_rule_lists(state, mode, false).await {
        lock(&state.0).record_error(&error);
        return Err(error);
    }
    with_backend(state, Backend::connect).await
}

#[tauri::command]
fn runtime_snapshot(state: State<'_, AppState>) -> RuntimeSnapshot {
    lock(&state.0).snapshot()
}

#[tauri::command]
fn list_nodes(state: State<'_, AppState>) -> Vec<NodeSummary> {
    lock(&state.0).nodes()
}

#[tauri::command]
fn list_subscriptions(state: State<'_, AppState>) -> Vec<SubscriptionSummary> {
    lock(&state.0).subscriptions()
}

#[tauri::command]
fn list_native_groups(state: State<'_, AppState>) -> Vec<GroupSummary> {
    lock(&state.0).groups()
}

#[tauri::command]
async fn select_native_group_outbound(
    state: State<'_, AppState>,
    group_tag: String,
    outbound_tag: String,
) -> Result<OperationResult, String> {
    with_backend(&state, move |backend| {
        backend.select_group_member(&group_tag, &outbound_tag)
    })
    .await
}

#[tauri::command]
async fn set_routing_mode(
    state: State<'_, AppState>,
    mode: String,
) -> Result<OperationResult, String> {
    let mode = RoutingMode::parse(&mode).ok_or("unknown routing mode")?;
    download_rule_lists(&state, mode, false).await?;
    with_backend(&state, move |backend| backend.set_routing_mode(mode)).await
}

/// Downloads the current mode's public rule lists again; they apply on the next connection.
#[tauri::command]
async fn refresh_routing_rules(state: State<'_, AppState>) -> Result<OperationResult, String> {
    let mode = lock(&state.0).routing_mode();
    let count = download_rule_lists(&state, mode, true).await?;
    Ok(OperationResult {
        message: if count == 0 {
            "The current routing mode uses no public rule lists".to_string()
        } else {
            format!("Routing rules refreshed ({count} lists); they apply on the next connection")
        },
    })
}

#[tauri::command]
async fn connect(state: State<'_, AppState>) -> Result<OperationResult, String> {
    connect_with_rules(&state).await
}

#[tauri::command]
async fn disconnect(state: State<'_, AppState>) -> Result<OperationResult, String> {
    with_backend(&state, Backend::disconnect).await
}

/// "Restart core": starts the engine again with the current node.
#[tauri::command]
async fn restart_service(state: State<'_, AppState>) -> Result<OperationResult, String> {
    connect_with_rules(&state).await
}

#[tauri::command]
async fn validate_configuration(state: State<'_, AppState>) -> Result<OperationResult, String> {
    with_backend(&state, |backend| backend.validate()).await
}

#[tauri::command]
async fn check_profile_runtime(state: State<'_, AppState>) -> Result<OperationResult, String> {
    with_backend(&state, |backend| backend.validate()).await
}

#[tauri::command]
async fn switch_node(
    state: State<'_, AppState>,
    node_id: String,
) -> Result<OperationResult, String> {
    with_backend(&state, move |backend| backend.switch_node(&node_id)).await
}

#[tauri::command]
async fn test_node_delay(
    state: State<'_, AppState>,
    node_id: String,
    url: String,
) -> Result<OperationResult, String> {
    let (nodes, name) = {
        let backend = lock(&state.0);
        (
            backend.node_list(),
            backend
                .node_name(&node_id)
                .unwrap_or_else(|| node_id.clone()),
        )
    };
    let delay = off_lock(move || engine::node_delay(&nodes, &node_id, &url)).await?;
    Ok(OperationResult {
        message: format!("{name}: {}", format_delay(delay)),
    })
}

#[tauri::command]
async fn select_fastest_node(state: State<'_, AppState>) -> Result<OperationResult, String> {
    let nodes = lock(&state.0).node_list();
    let (id, delay) = off_lock(move || {
        engine::fastest_node(&nodes, DELAY_URL)
            .ok_or_else(|| "no node answered the delay test".to_string())
    })
    .await?;
    let switched = with_backend(&state, move |backend| backend.switch_node(&id)).await?;
    Ok(OperationResult {
        message: format!("{} ({})", switched.message, format_delay(delay)),
    })
}

#[tauri::command]
async fn save_preferences(
    state: State<'_, AppState>,
    preferences: PreferencesInput,
) -> Result<OperationResult, String> {
    with_backend(&state, move |backend| {
        backend.save_preferences(&preferences)
    })
    .await
}

#[tauri::command]
async fn create_diagnostics(state: State<'_, AppState>) -> Result<OperationResult, String> {
    with_backend(&state, |backend| backend.diagnostics()).await
}

#[tauri::command]
async fn import_subscription(
    state: State<'_, AppState>,
    location: String,
) -> Result<OperationResult, String> {
    let location = location.trim().to_string();
    if location.is_empty() {
        return Err("enter a subscription link, share links or a file path".to_string());
    }
    let label = if location.contains("://") && !location.starts_with("http") {
        PASTED_LOCATION.to_string()
    } else {
        location.clone()
    };
    let content = off_lock(move || fetch(&location)).await?;
    with_backend(&state, move |backend| backend.import(&label, &content)).await
}

#[tauri::command]
async fn update_subscription(state: State<'_, AppState>) -> Result<OperationResult, String> {
    let (id, location) = lock(&state.0)
        .refreshable_location()
        .ok_or("the current subscription is not a link that can be updated")?;
    let fetched = off_lock(move || Ok(fetch(&location))).await?;
    with_backend(&state, move |backend| backend.finish_refresh(&id, fetched)).await
}

#[tauri::command]
async fn select_subscription(
    state: State<'_, AppState>,
    id: String,
) -> Result<OperationResult, String> {
    with_backend(&state, move |backend| backend.select_subscription(&id)).await
}

#[tauri::command]
async fn remove_subscription(
    state: State<'_, AppState>,
    id: String,
) -> Result<OperationResult, String> {
    with_backend(&state, move |backend| backend.remove_subscription(&id)).await
}

#[tauri::command]
async fn restore_network_settings(state: State<'_, AppState>) -> Result<OperationResult, String> {
    with_backend(&state, Backend::restore_network_settings).await
}

/// Commands the Windows client has and Linux does not yet; the interface hides their controls.
macro_rules! unavailable {
    ($($name:ident),* $(,)?) => {
        $(
            #[tauri::command]
            fn $name() -> Result<(), String> {
                Err(UNAVAILABLE.to_string())
            }
        )*
    };
}

unavailable!(
    install_service,
    start_service,
    stop_service,
    configure_script_runtime,
    clear_script_runtime,
    enable_https_mitm,
    disable_https_mitm,
    install_certificate,
    remove_certificate,
    install_driver,
    remove_driver,
);

pub fn run() -> Result<(), String> {
    let dir = Store::default_dir().ok_or("HOME is not set")?;
    // Inside an AppImage the running file is a temporary mount; autostart must point at the image itself.
    let executable = std::env::var_os("APPIMAGE")
        .map(PathBuf::from)
        .map_or_else(std::env::current_exe, Ok)
        .map_err(|error| error.to_string())?;
    let backend = Backend::open(
        Store::new(dir),
        Desktop::from_env(),
        autostart::autostart_dir(),
        executable,
    );
    let auto_connect = backend.auto_connect();
    let shared = Arc::new(Mutex::new(backend));
    if auto_connect {
        let state = AppState(shared.clone());
        thread::spawn(move || {
            let _ = tauri::async_runtime::block_on(connect_with_rules(&state));
        });
    }

    let app = tauri::Builder::default()
        .manage(AppState(shared.clone()))
        .invoke_handler(tauri::generate_handler![
            runtime_snapshot,
            list_nodes,
            list_native_groups,
            list_subscriptions,
            connect,
            disconnect,
            restart_service,
            validate_configuration,
            check_profile_runtime,
            switch_node,
            test_node_delay,
            select_fastest_node,
            save_preferences,
            create_diagnostics,
            import_subscription,
            update_subscription,
            select_subscription,
            remove_subscription,
            restore_network_settings,
            select_native_group_outbound,
            set_routing_mode,
            refresh_routing_rules,
            install_service,
            start_service,
            stop_service,
            configure_script_runtime,
            clear_script_runtime,
            enable_https_mitm,
            disable_https_mitm,
            install_certificate,
            remove_certificate,
            install_driver,
            remove_driver,
        ])
        .build(tauri::generate_context!())
        .map_err(|error| error.to_string())?;
    app.run(move |_, event| {
        // Put the desktop's proxy settings back when the window closes; a crash leaves them for the next start.
        if let RunEvent::Exit = event {
            lock(&shared).shutdown();
        }
    });
    Ok(())
}
