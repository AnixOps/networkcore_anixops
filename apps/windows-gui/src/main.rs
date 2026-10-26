#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {
    eprintln!("networkcore-windows-gui requires Windows");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    if std::env::args().any(|argument| argument == "--cleanup-startup") {
        if let Err(error) = gui::cleanup_current_user_startup() {
            gui::show_fatal_error(&error);
            std::process::exit(1);
        }
        return;
    }
    let debug = std::env::args().any(|argument| argument == "--debug" || argument == "-d");
    if let Err(error) = gui::run_tauri(debug) {
        gui::show_fatal_error(&error);
    }
}

#[cfg(windows)]
#[allow(dead_code)]
mod gui {
    mod actions;
    mod runtime_status;
    mod startup;
    mod tauri_ui;
    mod ui_state;

    use self::startup::DesktopProfileNode;
    use control_domain::NodeDescriptor;
    use platform_windows::managed::{
        append_managed_log, read_managed_config, read_managed_state, windows_managed_config_path,
        windows_managed_log_directory, windows_managed_state_path, write_managed_text_atomic,
        WindowsManagedConfig, WindowsSystemProxyOwner, WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION,
    };
    use platform_windows::system_integration::{
        disable_current_user_startup, NativeWindowsSystemIntegration, WindowsSystemIntegration,
    };
    use std::env;
    use std::fs;
    use std::mem::zeroed;
    use std::path::{Path, PathBuf};
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

    const APP_TITLE: &str = "AnixOps NetworkCore";

    pub fn run_tauri(debug: bool) -> Result<(), String> {
        tauri_ui::run(debug)
    }

    pub fn show_fatal_error(message: &str) {
        let _ = append_managed_log("gui", &format!("fatal: {message}"));
        let title = wide(APP_TITLE);
        let message = wide(message);
        unsafe {
            MessageBoxW(
                null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }

    pub fn cleanup_current_user_startup() -> Result<(), String> {
        let executable = env::current_exe().map_err(|error| error.to_string())?;
        disable_current_user_startup(&executable).map_err(|error| error.to_string())
    }

    pub(super) fn load_validated_managed_configuration(
        path: &Path,
    ) -> Result<WindowsManagedConfig, String> {
        read_managed_config(path).map_err(|error| error.to_string())
    }

    fn write_diagnostic_report_at(config_path: &Path) -> Result<PathBuf, String> {
        let mut report = String::from("AnixOps NetworkCore Windows diagnostics\n");
        report.push_str("managed_config_path=redacted\n");

        match NativeWindowsSystemIntegration::new().service_status() {
            Ok(status) => report.push_str(&format!(
                "service_state={:?} service_process_id={}\n",
                status.state, status.process_id
            )),
            Err(error) => report.push_str(&format!(
                "service_status_error={}\n",
                redact_diagnostic_text(&error.to_string())
            )),
        }

        let config = match read_managed_config(config_path) {
            Ok(config) => {
                report.push_str(&format!(
                    "managed_config_schema_version={} embedded_enabled={} native_mitm_enabled={}\n",
                    config.schema_version,
                    config
                        .embedded
                        .as_ref()
                        .is_some_and(|embedded| embedded.enabled),
                    config
                        .native_mitm
                        .as_ref()
                        .is_some_and(|native_mitm| native_mitm.enabled)
                ));
                Some(config)
            }
            Err(error) => {
                report.push_str(&format!(
                    "managed_config_error={}\n",
                    redact_diagnostic_text(&error.to_string())
                ));
                None
            }
        };

        match read_managed_state(&windows_managed_state_path()) {
            Ok(managed) => report.push_str(&format!(
                "runtime_transition={} runtime_error={} embedded_running={} embedded_listener={} embedded_error={} native_mitm_running={} native_mitm_listener={} native_mitm_error={}\n",
                managed.last_transition,
                redact_diagnostic_text(
                    &managed.last_error.unwrap_or_else(|| "none".to_string()),
                ),
                managed.embedded_running,
                managed.embedded_listener.unwrap_or_else(|| "none".to_string()),
                redact_diagnostic_text(
                    &managed
                        .embedded_last_error
                        .unwrap_or_else(|| "none".to_string()),
                ),
                managed.native_mitm_running,
                managed.native_mitm_listener.unwrap_or_else(|| "none".to_string()),
                redact_diagnostic_text(
                    &managed
                        .native_mitm_last_error
                        .unwrap_or_else(|| "none".to_string()),
                )
            )),
            Err(error) => report.push_str(&format!(
                "managed_state_error={}\n",
                redact_diagnostic_text(&error.to_string())
            )),
        }

        let mut logs = vec![
            windows_managed_log_directory().join("gui.log"),
            windows_managed_log_directory().join("tauri-gui.log"),
            windows_managed_log_directory().join("service.log"),
        ];
        if let Some(native_mitm) = config.and_then(|config| config.native_mitm) {
            logs.push(native_mitm.log_path);
        }
        logs.sort();
        logs.dedup();
        for path in logs {
            let log_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("managed-log");
            report.push_str(&format!("\n--- log: {log_name} ---\n"));
            match read_log_tail(&path, 80) {
                Ok(content) if content.is_empty() => report.push_str("(empty)\n"),
                Ok(content) => report.push_str(&redact_diagnostic_text(&content)),
                Err(error) => report.push_str(&format!(
                    "(unavailable: {})\n",
                    redact_diagnostic_text(&error)
                )),
            }
        }

        let path = windows_managed_log_directory().join("diagnostics.txt");
        write_managed_text_atomic(&path, &report).map_err(|error| error.to_string())?;
        Ok(path)
    }

    fn read_log_tail(path: &Path, line_limit: usize) -> Result<String, String> {
        let content = fs::read_to_string(path).map_err(|error| error.to_string())?;
        let lines = content.lines().collect::<Vec<_>>();
        let start = lines.len().saturating_sub(line_limit);
        if start == lines.len() {
            return Ok(String::new());
        }
        Ok(format!("{}\n", lines[start..].join("\n")))
    }

    fn redact_diagnostic_text(value: &str) -> String {
        let mut redacted = value.to_string();
        for scheme in [
            "https://",
            "http://",
            "ss://",
            "trojan://",
            "vless://",
            "vmess://",
            "hysteria2://",
            "hy2://",
            "tuic://",
            "mierus://",
        ] {
            redacted = redact_diagnostic_url(&redacted, scheme);
        }
        for marker in [
            "password=",
            "password:",
            "token=",
            "token:",
            "access_token=",
            "access_token:",
            "refresh_token=",
            "refresh_token:",
            "secret=",
            "secret:",
            "credential=",
            "credential:",
            "authorization:",
            "api_key=",
            "api_key:",
            "private_key=",
            "private_key:",
            "uuid=",
            "uuid:",
            "\"password\":",
            "\"token\":",
            "\"access_token\":",
            "\"refresh_token\":",
            "\"secret\":",
            "\"credential\":",
            "\"authorization\":",
            "\"api_key\":",
            "\"private_key\":",
            "\"uuid\":",
        ] {
            redacted = redact_diagnostic_line_value(&redacted, marker);
        }
        redacted
    }

    fn redact_diagnostic_url(value: &str, scheme: &str) -> String {
        let mut redacted = String::new();
        let mut remaining = value;
        loop {
            let lowered = remaining.to_ascii_lowercase();
            let Some(offset) = lowered.find(scheme) else {
                redacted.push_str(remaining);
                return redacted;
            };
            redacted.push_str(&remaining[..offset]);
            redacted.push_str("[redacted-url]");
            let url_end = remaining[offset..]
                .find(|character: char| {
                    character.is_ascii_whitespace() || matches!(character, '\"' | '\'' | '<' | '>')
                })
                .unwrap_or(remaining[offset..].len());
            remaining = &remaining[offset + url_end..];
        }
    }

    fn redact_diagnostic_line_value(value: &str, marker: &str) -> String {
        let mut redacted = String::new();
        let mut remaining = value;
        loop {
            let lowered = remaining.to_ascii_lowercase();
            let Some(offset) = lowered.find(marker) else {
                redacted.push_str(remaining);
                return redacted;
            };
            let marker_end = offset + marker.len();
            redacted.push_str(&remaining[..marker_end]);
            redacted.push_str("[redacted]");
            let line_end = remaining[marker_end..]
                .find('\n')
                .map(|index| marker_end + index)
                .unwrap_or(remaining.len());
            remaining = &remaining[line_end..];
        }
    }

    /// Nodes are addressed by id, which is also their outbound in the
    /// embedded engine's profile.
    fn profile_node_options(nodes: &[NodeDescriptor]) -> Vec<DesktopProfileNode> {
        nodes
            .iter()
            .map(|node| DesktopProfileNode {
                id: node.id.clone(),
                label: profile_node_label(node),
                protocol: format!("{:?}", node.protocol),
                outbound_tag: node.id.clone(),
            })
            .collect()
    }

    fn profile_node_label(node: &NodeDescriptor) -> String {
        let name = node.name.replace(['\r', '\n'], " ");
        format!("{name} [{}] ({:?})", node.id, node.protocol)
    }

    fn managed_config_or_default() -> Result<WindowsManagedConfig, String> {
        let path = windows_managed_config_path();
        if path.exists() {
            return read_managed_config(&path).map_err(|error| error.to_string());
        }
        Ok(WindowsManagedConfig {
            schema_version: WINDOWS_MANAGED_CONFIG_SCHEMA_VERSION,
            system_proxy: None,
            system_proxy_owner: WindowsSystemProxyOwner::Service,
            root_certificate_path: None,
            driver_package: None,
            tunnel: None,
            native_mitm: None,
            embedded: None,
        })
    }

    fn current_local_timestamp() -> String {
        let mut local_time: SYSTEMTIME = unsafe { zeroed() };
        unsafe {
            GetLocalTime(&mut local_time);
        }
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            local_time.wYear,
            local_time.wMonth,
            local_time.wDay,
            local_time.wHour,
            local_time.wMinute,
            local_time.wSecond
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use control_domain::{Endpoint, Protocol};

        #[test]
        fn diagnostics_redact_urls_and_credential_values() {
            let report = redact_diagnostic_text(
                "fetch https://user:password@example.test/sub?token=never-store\nAuthorization: Bearer never-store\nprivate_key=never-store\n{\"access_token\":\"never-store\",\"uuid\":\"never-store\"}\n",
            );

            assert!(report.contains("[redacted-url]"));
            assert!(report.contains("Authorization:[redacted]"));
            assert!(report.contains("private_key=[redacted]"));
            assert!(report.contains("\"access_token\":[redacted]"));
            assert!(!report.contains("never-store"));
            assert!(!report.contains("user:password@example.test"));
        }

        #[test]
        fn profile_nodes_are_labelled_and_addressed_by_stable_id() {
            let nodes = vec![NodeDescriptor {
                id: "primary-node".to_string(),
                name: "Primary\nnode".to_string(),
                protocol: Protocol::Shadowsocks,
                endpoint: Endpoint {
                    host: "edge.example.test".to_string(),
                    port: 443,
                },
                tags: Vec::new(),
                metadata: Vec::new(),
            }];
            let options = profile_node_options(&nodes);

            assert_eq!(
                options[0].label,
                "Primary node [primary-node] (Shadowsocks)"
            );
            assert_eq!(options[0].outbound_tag, "primary-node");
        }
    }
}
