use std::ffi::c_void;
use std::path::Path;
use std::ptr::null;
use windows_sys::Win32::Foundation::{GetLastError, HINSTANCE, HWND};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, GetWindowTextLengthW, GetWindowTextW, SendMessageW, SetWindowTextW,
    BM_GETCHECK, BM_SETCHECK, BS_AUTOCHECKBOX, BS_GROUPBOX, CBS_DROPDOWN, ES_AUTOHSCROLL, HMENU,
    WM_SETFONT, WS_BORDER, WS_CHILD, WS_TABSTOP, WS_VISIBLE, WS_VSCROLL,
};

const BUTTON_CHECKED: u32 = 1;

#[allow(clippy::too_many_arguments)]
pub unsafe fn label(
    parent: HWND,
    instance: HINSTANCE,
    font: *mut c_void,
    text: &str,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> HWND {
    let control = control(
        parent,
        instance,
        "STATIC",
        text,
        WS_CHILD | WS_VISIBLE,
        0,
        x,
        y,
        width,
        height,
        0,
    );
    SendMessageW(control, WM_SETFONT, font as usize, 1);
    control
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn group(
    parent: HWND,
    instance: HINSTANCE,
    font: *mut c_void,
    text: &str,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> HWND {
    let control = control(
        parent,
        instance,
        "BUTTON",
        text,
        WS_CHILD | WS_VISIBLE | BS_GROUPBOX as u32,
        0,
        x,
        y,
        width,
        height,
        0,
    );
    SendMessageW(control, WM_SETFONT, font as usize, 1);
    control
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn button(
    parent: HWND,
    instance: HINSTANCE,
    font: *mut c_void,
    text: &str,
    id: usize,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> HWND {
    let control = control(
        parent,
        instance,
        "BUTTON",
        text,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP,
        0,
        x,
        y,
        width,
        height,
        id,
    );
    SendMessageW(control, WM_SETFONT, font as usize, 1);
    control
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn checkbox(
    parent: HWND,
    instance: HINSTANCE,
    font: *mut c_void,
    text: &str,
    id: usize,
    checked: bool,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> HWND {
    let control = control(
        parent,
        instance,
        "BUTTON",
        text,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX as u32,
        0,
        x,
        y,
        width,
        height,
        id,
    );
    SendMessageW(control, WM_SETFONT, font as usize, 1);
    SendMessageW(control, BM_SETCHECK, usize::from(checked), 0);
    control
}

pub unsafe fn checkbox_checked(control: HWND) -> bool {
    SendMessageW(control, BM_GETCHECK, 0, 0) as u32 == BUTTON_CHECKED
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn edit(
    parent: HWND,
    instance: HINSTANCE,
    font: *mut c_void,
    text: &str,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> HWND {
    let control = control(
        parent,
        instance,
        "EDIT",
        text,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | ES_AUTOHSCROLL as u32,
        0,
        x,
        y,
        width,
        height,
        0,
    );
    SendMessageW(control, WM_SETFONT, font as usize, 1);
    control
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn selector(
    parent: HWND,
    instance: HINSTANCE,
    font: *mut c_void,
    text: &str,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
) -> HWND {
    let control = control(
        parent,
        instance,
        "COMBOBOX",
        text,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWN as u32,
        0,
        x,
        y,
        width,
        height + 160,
        0,
    );
    SendMessageW(control, WM_SETFONT, font as usize, 1);
    control
}

#[allow(clippy::too_many_arguments)]
pub unsafe fn control(
    parent: HWND,
    instance: HINSTANCE,
    class_name: &str,
    text: &str,
    style: u32,
    extended_style: u32,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    id: usize,
) -> HWND {
    let class_name = wide(class_name);
    let text = wide(text);
    CreateWindowExW(
        extended_style,
        class_name.as_ptr(),
        text.as_ptr(),
        style,
        x,
        y,
        width,
        height,
        parent,
        id as HMENU,
        instance,
        null(),
    )
}

pub unsafe fn set_text(control: HWND, text: &str) {
    let text = wide(text);
    SetWindowTextW(control, text.as_ptr());
}

pub unsafe fn text(control: HWND) -> String {
    let length = GetWindowTextLengthW(control);
    let mut buffer = vec![0u16; length as usize + 1];
    GetWindowTextW(control, buffer.as_mut_ptr(), buffer.len() as i32);
    String::from_utf16_lossy(&buffer[..length as usize])
}

pub fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

pub fn wide_os(value: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;

    value.as_os_str().encode_wide().chain(Some(0)).collect()
}

pub fn last_error(message: &str) -> String {
    format!("{message} (win32={})", unsafe { GetLastError() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wide_text_has_one_null_terminator() {
        assert_eq!(
            wide("NetworkCore"),
            vec![78, 101, 116, 119, 111, 114, 107, 67, 111, 114, 101, 0]
        );
    }
}
