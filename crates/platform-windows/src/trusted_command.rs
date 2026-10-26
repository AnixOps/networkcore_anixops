//! Windows system commands started with a trusted executable path and a minimal environment.

#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::{Command, Stdio};

#[cfg(windows)]
pub(crate) fn native_windows_powershell_command() -> std::io::Result<Command> {
    let system_directory = native_windows_system_directory()?;
    let executable = fs::canonicalize(
        system_directory
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
    )?;
    native_windows_command_with_trusted_environment(&executable, system_directory)
}

#[cfg(windows)]
fn native_windows_command_with_trusted_environment(
    executable: &Path,
    system_directory: PathBuf,
) -> std::io::Result<Command> {
    if !executable.is_file() {
        return Err(native_windows_command_error());
    }
    let system_root = system_directory
        .parent()
        .ok_or_else(native_windows_command_error)?;
    let powershell_module_root = system_root
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("Modules");

    let mut command = Command::new(executable);
    command
        .env_clear()
        .env("SystemRoot", system_root)
        .env("PATH", &system_directory)
        .env("PSModulePath", powershell_module_root)
        .current_dir(&system_directory)
        .stdin(Stdio::null());
    Ok(command)
}

#[cfg(windows)]
fn native_windows_system_directory() -> std::io::Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buffer = vec![0_u16; 260];
    let mut length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if length as usize >= buffer.len() {
        buffer.resize(length as usize + 1, 0);
        length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if length == 0 || length as usize >= buffer.len() {
            return Err(native_windows_command_error());
        }
    }

    let system_directory = PathBuf::from(OsString::from_wide(&buffer[..length as usize]));
    let system_directory = fs::canonicalize(system_directory)?;
    if !system_directory.is_dir() {
        return Err(native_windows_command_error());
    }
    Ok(system_directory)
}

#[cfg(windows)]
fn native_windows_command_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        "trusted Windows command path is invalid",
    )
}
