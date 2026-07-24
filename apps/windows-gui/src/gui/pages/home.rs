use crate::gui::ui_state::ConnectionState;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{HINSTANCE, HWND};

pub type LabelFactory = unsafe fn(HWND, HINSTANCE, *mut c_void, &str, i32, i32, i32, i32) -> HWND;
pub type ButtonFactory =
    unsafe fn(HWND, HINSTANCE, *mut c_void, &str, usize, i32, i32, i32, i32) -> HWND;

#[derive(Debug, Clone, Copy)]
pub struct CommandIds {
    pub connect: usize,
    pub disconnect: usize,
    pub refresh: usize,
    pub restore_proxy: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct Controls {
    pub connection: HWND,
    pub node: HWND,
    pub subscription: HWND,
    pub core: HWND,
    pub service: HWND,
    pub proxy: HWND,
    pub failure: HWND,
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn create(
    parent: HWND,
    instance: HINSTANCE,
    font: *mut c_void,
    label: LabelFactory,
    group: LabelFactory,
    button: ButtonFactory,
    command: CommandIds,
) -> Controls {
    label(parent, instance, font, "Connection", 24, 20, 220, 22);
    let connection = label(parent, instance, font, "Not connected", 24, 48, 360, 34);
    button(
        parent,
        instance,
        font,
        "Connect",
        command.connect,
        24,
        96,
        160,
        38,
    );
    button(
        parent,
        instance,
        font,
        "Disconnect",
        command.disconnect,
        196,
        96,
        160,
        38,
    );
    button(
        parent,
        instance,
        font,
        "Refresh",
        command.refresh,
        368,
        96,
        120,
        38,
    );
    button(
        parent,
        instance,
        font,
        "Restore network settings",
        command.restore_proxy,
        500,
        96,
        200,
        38,
    );
    let failure = label(parent, instance, font, "", 24, 150, 850, 42);
    group(parent, instance, font, "Current session", 20, 208, 860, 242);
    label(parent, instance, font, "Current node", 42, 242, 150, 22);
    let node = label(parent, instance, font, "Not selected", 210, 242, 630, 22);
    label(parent, instance, font, "Subscription", 42, 282, 150, 22);
    let subscription = label(parent, instance, font, "Not imported", 210, 282, 630, 22);
    label(parent, instance, font, "sing-box core", 42, 322, 150, 22);
    let core = label(parent, instance, font, "Not configured", 210, 322, 630, 22);
    label(parent, instance, font, "Windows service", 42, 362, 150, 22);
    let service = label(parent, instance, font, "Loading", 210, 362, 630, 22);
    label(parent, instance, font, "System proxy", 42, 402, 150, 22);
    let proxy = label(parent, instance, font, "Loading", 210, 402, 630, 22);
    Controls {
        connection,
        node,
        subscription,
        core,
        service,
        proxy,
        failure,
    }
}

pub const fn connection_summary(connection: ConnectionState) -> &'static str {
    if connection.is_connected() {
        "Connected: service, core, and proxy are ready"
    } else {
        connection.label()
    }
}

pub fn proxy_summary(enabled: Option<bool>, server: Option<&str>) -> String {
    match enabled {
        Some(true) => format!(
            "Enabled{}",
            server
                .filter(|value| !value.is_empty())
                .map(|value| format!(" ({value})"))
                .unwrap_or_default()
        ),
        Some(false) => "Disabled".to_string(),
        None => "Could not read the current user setting".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_summary_only_marks_all_runtime_facts_ready_when_connected() {
        assert_eq!(
            connection_summary(ConnectionState::Connected),
            "Connected: service, core, and proxy are ready"
        );
        assert_eq!(connection_summary(ConnectionState::CoreError), "Core error");
    }

    #[test]
    fn proxy_summary_keeps_an_unavailable_read_distinct_from_off() {
        assert_eq!(proxy_summary(Some(false), None), "Disabled");
        assert_eq!(
            proxy_summary(Some(true), Some("127.0.0.1:7890")),
            "Enabled (127.0.0.1:7890)"
        );
        assert_eq!(
            proxy_summary(None, None),
            "Could not read the current user setting"
        );
    }
}
