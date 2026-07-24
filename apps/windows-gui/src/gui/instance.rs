use super::widgets::{last_error, wide};
use std::ptr::null;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, ERROR_ALREADY_EXISTS, HANDLE,
};
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE,
};

const GUI_INSTANCE_MUTEX: &str = "Local\\AnixOpsNetworkCoreWindowsGui";

pub(super) enum InstanceClaim {
    Primary(InstanceGuard),
    Existing,
}

pub(super) struct InstanceGuard {
    handle: HANDLE,
}

impl Drop for InstanceGuard {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

pub(super) fn claim() -> Result<InstanceClaim, String> {
    let mutex_name = wide(GUI_INSTANCE_MUTEX);
    unsafe {
        SetLastError(0);
    }
    let handle = unsafe { CreateMutexW(null(), 0, mutex_name.as_ptr()) };
    if handle.is_null() {
        return Err(last_error(
            "NetworkCore GUI instance lock could not be created",
        ));
    }
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        unsafe {
            CloseHandle(handle);
        }
        return Ok(InstanceClaim::Existing);
    }
    Ok(InstanceClaim::Primary(InstanceGuard { handle }))
}

pub(super) fn activate_existing_window(class_name: &str) -> bool {
    let class_name = wide(class_name);
    let window = unsafe { FindWindowW(class_name.as_ptr(), null()) };
    if window.is_null() {
        return false;
    }
    unsafe {
        ShowWindow(window, SW_RESTORE);
        SetForegroundWindow(window);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_instance_claim_is_detected_without_creating_a_second_gui_owner() {
        let primary = claim().expect("first GUI instance claim should succeed");
        assert!(matches!(&primary, InstanceClaim::Primary(_)));

        let duplicate = claim().expect("second GUI instance claim should be observable");
        assert!(matches!(duplicate, InstanceClaim::Existing));
    }
}
