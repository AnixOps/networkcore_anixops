use std::ffi::c_void;
use windows_sys::Win32::Foundation::{HINSTANCE, HWND};

pub type LabelFactory = unsafe fn(HWND, HINSTANCE, *mut c_void, &str, i32, i32, i32, i32) -> HWND;
pub type ButtonFactory =
    unsafe fn(HWND, HINSTANCE, *mut c_void, &str, usize, i32, i32, i32, i32) -> HWND;
pub type EditFactory = unsafe fn(HWND, HINSTANCE, *mut c_void, &str, i32, i32, i32, i32) -> HWND;
pub type CheckboxFactory =
    unsafe fn(HWND, HINSTANCE, *mut c_void, &str, usize, bool, i32, i32, i32, i32) -> HWND;

#[derive(Debug, Clone, Copy)]
pub struct CommandIds {
    pub open_config: usize,
    pub validate_config: usize,
    pub apply_config: usize,
    pub install_core: usize,
    pub start_after_login: usize,
    pub auto_connect: usize,
    pub auto_recover_core: usize,
    pub enable_proxy: usize,
    pub restore_proxy: usize,
}

pub struct InitialValues<'a> {
    pub config_path: &'a str,
    pub start_after_login: bool,
    pub auto_connect: bool,
    pub auto_recover_core: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Controls {
    pub config_path: HWND,
    pub proxy_server: HWND,
    pub proxy_bypass: HWND,
    pub start_after_login: HWND,
    pub auto_connect: HWND,
    pub auto_recover_core: HWND,
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn create(
    parent: HWND,
    instance: HINSTANCE,
    font: *mut c_void,
    label: LabelFactory,
    group: LabelFactory,
    button: ButtonFactory,
    edit: EditFactory,
    checkbox: CheckboxFactory,
    command: CommandIds,
    initial: InitialValues<'_>,
) -> Controls {
    label(parent, instance, font, "Settings", 24, 20, 300, 26);
    label(
        parent,
        instance,
        font,
        "Managed configuration",
        24,
        62,
        230,
        22,
    );
    let config_path = edit(parent, instance, font, initial.config_path, 24, 92, 560, 28);
    button(
        parent,
        instance,
        font,
        "Open JSON",
        command.open_config,
        596,
        92,
        110,
        30,
    );
    button(
        parent,
        instance,
        font,
        "Validate",
        command.validate_config,
        718,
        92,
        110,
        30,
    );
    button(
        parent,
        instance,
        font,
        "Apply",
        command.apply_config,
        24,
        138,
        110,
        30,
    );
    button(
        parent,
        instance,
        font,
        "Install sing-box",
        command.install_core,
        146,
        138,
        150,
        30,
    );
    group(parent, instance, font, "Daily startup", 20, 184, 860, 118);
    let start_after_login = checkbox(
        parent,
        instance,
        font,
        "Start NetworkCore after I sign in",
        command.start_after_login,
        initial.start_after_login,
        40,
        216,
        420,
        24,
    );
    let auto_connect = checkbox(
        parent,
        instance,
        font,
        "Connect automatically after startup",
        command.auto_connect,
        initial.auto_connect,
        40,
        244,
        420,
        24,
    );
    let auto_recover_core = checkbox(
        parent,
        instance,
        font,
        "Restart once when a GUI-started core exits",
        command.auto_recover_core,
        initial.auto_recover_core,
        40,
        272,
        500,
        24,
    );
    group(
        parent,
        instance,
        font,
        "Manual system proxy recovery",
        20,
        318,
        860,
        146,
    );
    label(parent, instance, font, "Server", 40, 354, 80, 22);
    let proxy_server = edit(parent, instance, font, "127.0.0.1:7890", 124, 350, 250, 28);
    label(parent, instance, font, "Bypass", 396, 354, 80, 22);
    let proxy_bypass = edit(parent, instance, font, "<local>", 472, 350, 330, 28);
    button(
        parent,
        instance,
        font,
        "Enable proxy",
        command.enable_proxy,
        40,
        402,
        140,
        30,
    );
    button(
        parent,
        instance,
        font,
        "Restore proxy",
        command.restore_proxy,
        192,
        402,
        140,
        30,
    );
    label(
        parent,
        instance,
        font,
        "Manual proxy controls are only for recovery or an explicit local-proxy workflow. Connect uses the managed service lifecycle.",
        40,
        434,
        800,
        22,
    );
    Controls {
        config_path,
        proxy_server,
        proxy_bypass,
        start_after_login,
        auto_connect,
        auto_recover_core,
    }
}

pub const fn daily_lifecycle_summary(
    start_after_login: bool,
    auto_connect: bool,
    auto_recover_core: bool,
) -> &'static str {
    match (start_after_login, auto_connect, auto_recover_core) {
        (true, true, true) => {
            "NetworkCore will start, connect once, and recover one GUI-started core failure."
        }
        (true, true, false) => "NetworkCore will start and connect once after sign-in.",
        (true, false, _) => {
            "NetworkCore will start after sign-in and wait for an explicit connection."
        }
        (false, true, true) => {
            "This GUI session will connect once and recover one GUI-started core failure."
        }
        (false, true, false) => "This GUI session will connect once after startup.",
        (false, false, true) => {
            "One recovery is allowed only after this GUI successfully connects."
        }
        (false, false, false) => "NetworkCore requires an explicit connection request.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_summary_keeps_recovery_scoped_to_a_gui_started_connection() {
        assert_eq!(
            daily_lifecycle_summary(false, false, true),
            "One recovery is allowed only after this GUI successfully connects."
        );
    }
}
