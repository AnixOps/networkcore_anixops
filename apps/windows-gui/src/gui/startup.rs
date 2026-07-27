use platform_windows::managed::{
    windows_managed_data_directory, write_managed_text_atomic, WindowsProxySettings,
    WindowsProxySnapshot,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const DESKTOP_STATE_FILE: &str = "desktop-state.json";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopRuntimeMode {
    #[default]
    Desktop,
    Service,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesktopRoutingMode {
    #[default]
    BypassChina,
    GfwList,
    Direct,
    ReturnChina,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopProfileNode {
    pub id: String,
    pub label: String,
    pub protocol: String,
    pub outbound_tag: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopSubscriptionSource {
    pub id: String,
    pub location: String,
    #[serde(default)]
    pub last_attempt: Option<String>,
    #[serde(default)]
    pub last_successful_update: Option<String>,
    #[serde(default)]
    pub next_attempt: Option<String>,
    #[serde(default)]
    pub result: String,
    #[serde(default)]
    pub added_node_count: usize,
    #[serde(default)]
    pub removed_node_count: usize,
    #[serde(default)]
    pub changed_node_count: usize,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub last_update_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DesktopState {
    #[serde(default)]
    pub runtime_mode: DesktopRuntimeMode,
    #[serde(default)]
    pub routing_mode: DesktopRoutingMode,
    #[serde(default)]
    pub routing_proxy_outbound: Option<String>,
    #[serde(default)]
    pub bilibili_web_ad_block_enabled: bool,
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
    pub profile_node_catalog: Vec<DesktopProfileNode>,
    #[serde(default)]
    pub profile_config_sha256: Option<String>,
    #[serde(default)]
    pub delay_test_url: Option<String>,
    #[serde(default)]
    pub debug_enabled: bool,
    #[serde(default)]
    pub dark_theme: bool,
    #[serde(default)]
    pub profile_last_successful_update: Option<String>,
    #[serde(default)]
    pub profile_last_attempt: Option<String>,
    #[serde(default)]
    pub profile_next_attempt: Option<String>,
    #[serde(default)]
    pub profile_refresh_result: String,
    #[serde(default)]
    pub profile_added_node_count: usize,
    #[serde(default)]
    pub profile_removed_node_count: usize,
    #[serde(default)]
    pub profile_changed_node_count: usize,
    #[serde(default)]
    pub profile_refresh_error_code: Option<String>,
    #[serde(default)]
    pub profile_last_update_error: Option<String>,
    #[serde(default)]
    pub start_after_login: bool,
    #[serde(default)]
    pub auto_connect: bool,
    #[serde(default)]
    pub auto_recover_core: bool,
    #[serde(default)]
    pub auto_subscription_refresh: bool,
    #[serde(default)]
    pub auto_select_fastest_node: bool,
    #[serde(default)]
    pub subscription_sources: Vec<DesktopSubscriptionSource>,
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
        assert!(!state.auto_subscription_refresh);
        assert!(!state.auto_select_fastest_node);
        assert_eq!(state.runtime_mode, DesktopRuntimeMode::Desktop);
        assert_eq!(state.routing_mode, DesktopRoutingMode::BypassChina);
        assert!(!state.bilibili_web_ad_block_enabled);
        assert!(state.applied_proxy.is_none());
        assert!(state.profile_node_catalog.is_empty());
        assert!(state.profile_config_sha256.is_none());
    }

    #[test]
    fn desktop_state_round_trips_generated_selector_catalog_identity() {
        let state = DesktopState {
            profile_node_catalog: vec![DesktopProfileNode {
                id: "primary".to_string(),
                label: "Primary [primary] (Shadowsocks)".to_string(),
                protocol: "Shadowsocks".to_string(),
                outbound_tag: "networkcore-node-0".to_string(),
            }],
            profile_config_sha256: Some("a1b2".to_string()),
            ..DesktopState::default()
        };

        let decoded: DesktopState = serde_json::from_str(
            &serde_json::to_string(&state).expect("desktop state should serialize"),
        )
        .expect("desktop state should deserialize");

        assert_eq!(decoded.profile_node_catalog, state.profile_node_catalog);
        assert_eq!(decoded.profile_config_sha256, state.profile_config_sha256);
    }

    #[test]
    fn legacy_subscription_source_defaults_refresh_status_fields() {
        let source: DesktopSubscriptionSource =
            serde_json::from_str(r#"{"id":"source-1","location":"https://example.invalid/sub"}"#)
                .expect("older saved source should remain readable");

        assert!(source.last_attempt.is_none());
        assert!(source.next_attempt.is_none());
        assert_eq!(source.result, "");
        assert_eq!(source.added_node_count, 0);
        assert!(source.error_code.is_none());
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
