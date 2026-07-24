use super::actions::connection::{can_connect, can_disconnect};
use super::ui_state::ConnectionState;
use super::widgets::{last_error, wide};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{HWND, POINT};
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NOTIFYICONDATAW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreatePopupMenu, DestroyMenu, GetCursorPos, LoadIconW, RegisterWindowMessageW,
    SetForegroundWindow, TrackPopupMenu, HMENU, IDI_APPLICATION, MF_GRAYED, MF_STRING,
    TPM_RETURNCMD, TPM_RIGHTBUTTON, WM_LBUTTONDBLCLK, WM_RBUTTONUP,
};

pub const TRAY_CALLBACK_MESSAGE: u32 = 0x8000 + 41;
const TRAY_ICON_ID: u32 = 1;
const TASKBAR_CREATED_MESSAGE_NAME: &str = "TaskbarCreated";

static TASKBAR_CREATED_MESSAGE: OnceLock<u32> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrayMenuState {
    pub connection: ConnectionState,
    pub busy: bool,
    pub has_gui_owned_proxy: bool,
}

impl TrayMenuState {
    pub const fn connect_enabled(self) -> bool {
        !self.busy && can_connect(self.connection)
    }

    pub const fn disconnect_enabled(self) -> bool {
        !self.busy && can_disconnect(self.connection, self.has_gui_owned_proxy)
    }
}

pub unsafe fn add(window: HWND) -> Result<(), String> {
    let mut icon: NOTIFYICONDATAW = std::mem::zeroed();
    icon.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    icon.hWnd = window;
    icon.uID = TRAY_ICON_ID;
    icon.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    icon.uCallbackMessage = TRAY_CALLBACK_MESSAGE;
    icon.hIcon = LoadIconW(std::ptr::null_mut(), IDI_APPLICATION);
    write_tip(&mut icon, "AnixOps NetworkCore");
    if Shell_NotifyIconW(NIM_ADD, &icon) == 0 {
        return Err("system tray icon could not be created".to_string());
    }
    Ok(())
}

/// Registers the Shell broadcast sent after Explorer rebuilds the notification
/// area. Registration happens before the window starts receiving broadcasts.
pub fn register_taskbar_created_message() -> Result<(), String> {
    if TASKBAR_CREATED_MESSAGE.get().is_some() {
        return Ok(());
    }
    let name = wide(TASKBAR_CREATED_MESSAGE_NAME);
    let message = unsafe { RegisterWindowMessageW(name.as_ptr()) };
    if message == 0 {
        return Err(last_error("TaskbarCreated message could not be registered"));
    }
    match TASKBAR_CREATED_MESSAGE.set(message) {
        Ok(()) => Ok(()),
        Err(_) => match TASKBAR_CREATED_MESSAGE.get() {
            Some(registered) if *registered == message => Ok(()),
            _ => Err("TaskbarCreated message registration changed unexpectedly".to_string()),
        },
    }
}

pub fn is_taskbar_created_message(message: u32) -> bool {
    TASKBAR_CREATED_MESSAGE
        .get()
        .is_some_and(|registered| matches_taskbar_created_message(*registered, message))
}

const fn matches_taskbar_created_message(registered: u32, received: u32) -> bool {
    registered == received
}

pub unsafe fn remove(window: HWND) {
    let mut icon: NOTIFYICONDATAW = std::mem::zeroed();
    icon.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    icon.hWnd = window;
    icon.uID = TRAY_ICON_ID;
    let _ = Shell_NotifyIconW(NIM_DELETE, &icon);
}

pub unsafe fn update(window: HWND, connection: ConnectionState, node: &str) {
    let mut icon: NOTIFYICONDATAW = std::mem::zeroed();
    icon.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    icon.hWnd = window;
    icon.uID = TRAY_ICON_ID;
    icon.uFlags = NIF_TIP;
    write_tip(
        &mut icon,
        &format!("NetworkCore: {} | {}", connection.label(), node),
    );
    let _ = Shell_NotifyIconW(NIM_MODIFY, &icon);
}

pub unsafe fn handle_callback(
    window: HWND,
    lparam: isize,
    state: TrayMenuState,
    status: &str,
    node: &str,
    command: TrayCommandIds,
) -> Option<usize> {
    match lparam as u32 {
        WM_LBUTTONDBLCLK => Some(command.open),
        WM_RBUTTONUP => show_menu(window, state, status, node, command),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TrayCommandIds {
    pub open: usize,
    pub connect: usize,
    pub disconnect: usize,
    pub refresh: usize,
    pub exit: usize,
}

unsafe fn show_menu(
    window: HWND,
    state: TrayMenuState,
    status: &str,
    node: &str,
    command: TrayCommandIds,
) -> Option<usize> {
    let menu = CreatePopupMenu();
    if menu.is_null() {
        return None;
    }
    append(menu, MF_STRING, command.open, "Open NetworkCore");
    append(menu, MF_STRING | MF_GRAYED, 0, &format!("Status: {status}"));
    append(
        menu,
        MF_STRING
            | (if state.connect_enabled() {
                0
            } else {
                MF_GRAYED
            }),
        command.connect,
        "Connect",
    );
    append(
        menu,
        MF_STRING
            | (if state.disconnect_enabled() {
                0
            } else {
                MF_GRAYED
            }),
        command.disconnect,
        "Disconnect",
    );
    append(menu, MF_STRING | MF_GRAYED, 0, &format!("Node: {node}"));
    append(menu, MF_STRING, command.refresh, "Refresh status");
    append(menu, MF_STRING, command.exit, "Exit");
    let mut point: POINT = std::mem::zeroed();
    let _ = GetCursorPos(&mut point);
    let _ = SetForegroundWindow(window);
    let selected = TrackPopupMenu(
        menu,
        TPM_RETURNCMD | TPM_RIGHTBUTTON,
        point.x,
        point.y,
        0,
        window,
        std::ptr::null(),
    );
    let _ = DestroyMenu(menu);
    (selected != 0).then_some(selected as usize)
}

unsafe fn append(menu: HMENU, flags: u32, id: usize, text: &str) {
    let text = text.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let _ = AppendMenuW(menu, flags, id, text.as_ptr());
}

fn write_tip(icon: &mut NOTIFYICONDATAW, text: &str) {
    let mut encoded = text.encode_utf16();
    let capacity = icon.szTip.len().saturating_sub(1);
    for slot in icon.szTip.iter_mut().take(capacity) {
        let Some(value) = encoded.next() else {
            break;
        };
        *slot = value;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connected_menu_disables_connect_and_enables_disconnect() {
        let state = TrayMenuState {
            connection: ConnectionState::Connected,
            busy: false,
            has_gui_owned_proxy: true,
        };
        assert!(!state.connect_enabled());
        assert!(state.disconnect_enabled());
    }

    #[test]
    fn active_operation_disables_both_connection_commands() {
        let state = TrayMenuState {
            connection: ConnectionState::Disconnected,
            busy: true,
            has_gui_owned_proxy: false,
        };
        assert!(!state.connect_enabled());
        assert!(!state.disconnect_enabled());
    }

    #[test]
    fn taskbar_rebuild_message_is_distinguished_from_regular_window_messages() {
        assert!(matches_taskbar_created_message(42, 42));
        assert!(!matches_taskbar_created_message(42, TRAY_CALLBACK_MESSAGE));
    }
}
