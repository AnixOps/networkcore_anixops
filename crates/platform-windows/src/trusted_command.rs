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
    let executable = without_verbatim_prefix(fs::canonicalize(
        system_directory
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
    )?);
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
        .env("windir", system_root)
        .env("PATH", &system_directory)
        .env("PSModulePath", powershell_module_root)
        .current_dir(&system_directory)
        .stdin(Stdio::null());
    if let Some(drive) = system_root.components().next() {
        command.env("SystemDrive", drive.as_os_str());
    }
    // Windows PowerShell needs per-user profile and temp locations to load
    // its own modules (module analysis cache, assembly shadow copies). They do
    // not affect which executables or modules are resolved: PATH and
    // PSModulePath above stay pinned to the system directory.
    for name in PROFILE_ENVIRONMENT {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    Ok(command)
}

#[cfg(windows)]
const PROFILE_ENVIRONMENT: [&str; 8] = [
    "TEMP",
    "TMP",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "ProgramData",
    "ALLUSERSPROFILE",
    "USERNAME",
];

/// `fs::canonicalize` returns `\\?\C:\...` on Windows. Windows PowerShell
/// derives `$PSHOME` and module paths from these values and cannot load its
/// built-in modules (for example Microsoft.PowerShell.Utility, which provides
/// `New-Object`) from verbatim paths, so hand it the plain drive form.
#[cfg(any(windows, test))]
fn without_verbatim_prefix(path: std::path::PathBuf) -> std::path::PathBuf {
    let Some(text) = path.to_str() else {
        return path;
    };
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return std::path::PathBuf::from(format!(r"\\{rest}"));
    }
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => std::path::PathBuf::from(rest),
        _ => path,
    }
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
    let system_directory = without_verbatim_prefix(fs::canonicalize(system_directory)?);
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

#[cfg(test)]
mod tests {
    use super::without_verbatim_prefix;
    use std::path::PathBuf;

    #[test]
    fn verbatim_drive_paths_lose_their_prefix() {
        assert_eq!(
            without_verbatim_prefix(PathBuf::from(r"\\?\C:\Windows\System32")),
            PathBuf::from(r"C:\Windows\System32")
        );
        assert_eq!(
            without_verbatim_prefix(PathBuf::from(r"\\?\UNC\server\share")),
            PathBuf::from(r"\\server\share")
        );
        assert_eq!(
            without_verbatim_prefix(PathBuf::from(r"C:\Windows")),
            PathBuf::from(r"C:\Windows")
        );
        assert_eq!(
            without_verbatim_prefix(PathBuf::from(r"\\?\Volume{x}\a")),
            PathBuf::from(r"\\?\Volume{x}\a")
        );
    }
}
