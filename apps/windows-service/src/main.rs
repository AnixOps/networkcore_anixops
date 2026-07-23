use networkcore_windows::native_windows_tunnel_command_service;
use networkcore_windows_service::{copy_managed_configuration, WindowsManagedRuntime};
use platform_windows::managed::{
    append_managed_log, windows_managed_config_path, windows_managed_state_path,
};
#[cfg(windows)]
use platform_windows::system_integration::NETWORKCORE_WINDOWS_SERVICE_NAME;
use platform_windows::system_integration::{
    NativeWindowsSystemIntegration, WindowsSystemIntegration,
};
use std::env;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        let _ = append_managed_log("service", &format!("fatal: {error}"));
        eprintln!("{}", error);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = env::args().skip(1);
    let command = arguments.next();
    let _ = append_managed_log("service", &format!("command={command:?}"));
    match command.as_deref() {
        Some("service") => run_service_dispatcher(),
        Some("install") => {
            let executable = env::current_exe()?;
            NativeWindowsSystemIntegration::new().install_service(&executable)?;
            Ok(())
        }
        Some("uninstall") => {
            NativeWindowsSystemIntegration::new().uninstall_service()?;
            Ok(())
        }
        Some("start") => {
            let status = NativeWindowsSystemIntegration::new().start_service()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        Some("stop") => {
            let status = NativeWindowsSystemIntegration::new().stop_service()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        Some("restart") => {
            let status = NativeWindowsSystemIntegration::new().restart_service()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        Some("status") => {
            let status = NativeWindowsSystemIntegration::new().service_status()?;
            println!("{}", serde_json::to_string_pretty(&status)?);
            Ok(())
        }
        Some("configure") => {
            let source = arguments.next().map(PathBuf::from).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "configure requires a managed JSON path",
                )
            })?;
            copy_managed_configuration(&source, &windows_managed_config_path())?;
            Ok(())
        }
        Some("purge") => {
            let mut runtime = native_runtime();
            let state = runtime.purge()?;
            println!("{}", serde_json::to_string_pretty(&state)?);
            Ok(())
        }
        _ => {
            eprintln!(
                "Usage: networkcore-windows-service <service|install|uninstall|start|stop|restart|status|configure <path>|purge>"
            );
            std::process::exit(2);
        }
    }
}

fn native_runtime() -> WindowsManagedRuntime<
    NativeWindowsSystemIntegration,
    networkcore_windows::NativeWindowsTunnelCommandService,
> {
    WindowsManagedRuntime::new(
        NativeWindowsSystemIntegration::new(),
        native_windows_tunnel_command_service(),
        windows_managed_config_path(),
        windows_managed_state_path(),
    )
}

#[cfg(not(windows))]
fn run_service_dispatcher() -> Result<(), Box<dyn std::error::Error>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Windows service dispatcher requires Windows",
    )
    .into())
}

#[cfg(windows)]
fn run_service_dispatcher() -> Result<(), Box<dyn std::error::Error>> {
    windows_service_host::dispatch()
}

#[cfg(windows)]
mod windows_service_host {
    use super::*;
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{GetLastError, NO_ERROR};
    use windows_sys::Win32::System::Services::{
        RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
        SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_SHUTDOWN,
        SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS,
        SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
        SERVICE_WIN32_OWN_PROCESS,
    };

    static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

    pub fn dispatch() -> Result<(), Box<dyn std::error::Error>> {
        let _ = append_managed_log("service", "SCM dispatcher started");
        let mut service_name = wide(NETWORKCORE_WINDOWS_SERVICE_NAME);
        let entries = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: service_name.as_mut_ptr(),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: null_mut(),
                lpServiceProc: None,
            },
        ];
        if unsafe { StartServiceCtrlDispatcherW(entries.as_ptr()) } == 0 {
            let error = format!("service dispatcher failed (win32={})", unsafe {
                GetLastError()
            });
            let _ = append_managed_log("service", &format!("error: {error}"));
            return Err(error.into());
        }
        let _ = append_managed_log("service", "SCM dispatcher stopped");
        Ok(())
    }

    unsafe extern "system" fn service_main(_count: u32, _arguments: *mut *mut u16) {
        let service_name = wide(NETWORKCORE_WINDOWS_SERVICE_NAME);
        let status_handle = RegisterServiceCtrlHandlerExW(
            service_name.as_ptr(),
            Some(service_control_handler),
            null(),
        );
        if status_handle.is_null() {
            let _ = append_managed_log(
                "service",
                "error: service control handler registration failed",
            );
            return;
        }
        report_status(status_handle, SERVICE_START_PENDING, 0, 10_000);

        let mut runtime = native_runtime();
        match runtime.start() {
            Ok(_) => {
                let _ = append_managed_log("service", "managed runtime started");
            }
            Err(error) => {
                let _ = append_managed_log("service", &format!("runtime start failed: {error}"));
                report_status(status_handle, SERVICE_STOPPED, 1, 0);
                return;
            }
        }

        report_status(status_handle, SERVICE_RUNNING, 0, 0);
        while !STOP_REQUESTED.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(500));
        }

        report_status(status_handle, SERVICE_STOP_PENDING, 0, 30_000);
        let exit_code = match runtime.stop() {
            Ok(_) => {
                let _ = append_managed_log("service", "managed runtime stopped");
                0
            }
            Err(error) => {
                let _ = append_managed_log("service", &format!("runtime stop failed: {error}"));
                1
            }
        };
        report_status(status_handle, SERVICE_STOPPED, exit_code, 0);
    }

    unsafe extern "system" fn service_control_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut c_void,
        _context: *mut c_void,
    ) -> u32 {
        if control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN {
            STOP_REQUESTED.store(true, Ordering::SeqCst);
        }
        NO_ERROR
    }

    unsafe fn report_status(
        handle: SERVICE_STATUS_HANDLE,
        state: u32,
        exit_code: u32,
        wait_hint: u32,
    ) {
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: if state == SERVICE_RUNNING {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: exit_code,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: 0,
            dwWaitHint: wait_hint,
        };
        SetServiceStatus(handle, &status);
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(Some(0)).collect()
    }
}
