use platform_windows::managed::{
    windows_managed_data_directory, write_managed_text_atomic, WindowsProxySettings,
    WindowsProxySnapshot,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const DESKTOP_STATE_FILE: &str = "desktop-state.json";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DesktopState {
    pub proxy_snapshot: Option<WindowsProxySnapshot>,
    #[serde(default)]
    pub applied_proxy: Option<WindowsProxySettings>,
    pub certificate_sha1: Option<String>,
    pub driver_inf_path: Option<PathBuf>,
    #[serde(default)]
    pub sing_box_executable_path: Option<PathBuf>,
    #[serde(default)]
    pub profile_source_path: Option<PathBuf>,
    #[serde(default)]
    pub profile_source_url: Option<String>,
    #[serde(default)]
    pub profile_node_id: Option<String>,
    #[serde(default)]
    pub delay_test_url: Option<String>,
    #[serde(default)]
    pub debug_enabled: bool,
    #[serde(default)]
    pub dark_theme: bool,
    #[serde(default)]
    pub profile_last_successful_update: Option<String>,
    #[serde(default)]
    pub profile_last_update_error: Option<String>,
    #[serde(default)]
    pub start_after_login: bool,
    #[serde(default)]
    pub auto_connect: bool,
    #[serde(default)]
    pub auto_recover_core: bool,
}

pub fn desktop_state_path() -> PathBuf {
    windows_managed_data_directory().join(DESKTOP_STATE_FILE)
}

pub fn load_desktop_state() -> Result<DesktopState, String> {
    let path = desktop_state_path();
    if !path.exists() {
        return Ok(DesktopState::default());
    }
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "desktop state could not be read from {}: {error}",
            path.display()
        )
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("desktop state is invalid at {}: {error}", path.display()))
}

pub fn save_desktop_state(state: &DesktopState) -> Result<(), String> {
    let content = serde_json::to_string_pretty(state)
        .map_err(|error| format!("desktop state could not be serialized: {error}"))?;
    write_managed_text_atomic(&desktop_state_path(), &content).map_err(|error| error.to_string())
}

pub fn owns_current_proxy(state: &DesktopState, current: &WindowsProxySettings) -> bool {
    state.proxy_snapshot.is_some()
        && state.applied_proxy.as_ref().is_some_and(|expected| {
            current.enabled == expected.enabled
                && current.server == expected.server
                && current.bypass == expected.bypass
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_state_defaults_daily_lifecycle_preferences() {
        let state: DesktopState = serde_json::from_str(r#"{"debug_enabled":true}"#)
            .expect("older desktop state should remain readable");
        assert!(state.debug_enabled);
        assert!(!state.start_after_login);
        assert!(!state.auto_connect);
        assert!(!state.auto_recover_core);
        assert!(state.applied_proxy.is_none());
    }

    #[test]
    fn proxy_recovery_requires_the_owned_applied_settings() {
        let state = DesktopState {
            proxy_snapshot: Some(WindowsProxySnapshot {
                enabled: false,
                server: String::new(),
                bypass: String::new(),
                winhttp_access_type: 1,
                winhttp_server: String::new(),
                winhttp_bypass: String::new(),
            }),
            applied_proxy: Some(WindowsProxySettings {
                enabled: true,
                server: "127.0.0.1:7890".to_string(),
                bypass: "<local>".to_string(),
            }),
            ..DesktopState::default()
        };
        assert!(owns_current_proxy(
            &state,
            &WindowsProxySettings {
                enabled: true,
                server: "127.0.0.1:7890".to_string(),
                bypass: "<local>".to_string(),
            }
        ));
        assert!(!owns_current_proxy(
            &state,
            &WindowsProxySettings {
                enabled: true,
                server: "proxy.example:8080".to_string(),
                bypass: "<local>".to_string(),
            }
        ));
    }
}
