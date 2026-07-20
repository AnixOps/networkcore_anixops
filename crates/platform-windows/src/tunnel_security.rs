//! Windows-only storage boundary for foreground tunnel inputs.
//!
//! Native start operations establish and protect a fixed ProgramData root before exposing a
//! state or secret path to the runtime. Read-only status and stop operations inspect the same
//! root without creating directories or changing ACLs.

use control_domain::{DomainError, DomainResult};
use std::path::{Path, PathBuf};

use crate::tunnel_runtime::WINDOWS_TUNNEL_START_FAILED_CODE;

#[cfg(windows)]
use crate::tunnel_config::is_safe_tunnel_file_name;
#[cfg(windows)]
use std::fs;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
#[cfg(windows)]
use std::process::{Command, Stdio};

#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum NativeWindowsSystemTool {
    PowerShell,
    Route,
}

#[cfg(windows)]
pub(crate) fn native_windows_system_command(
    tool: NativeWindowsSystemTool,
) -> std::io::Result<Command> {
    let system_directory = native_windows_system_directory()?;
    let executable = match tool {
        NativeWindowsSystemTool::PowerShell => system_directory
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
        NativeWindowsSystemTool::Route => system_directory.join("route.exe"),
    };
    let executable = fs::canonicalize(executable)?;
    native_windows_command_with_trusted_environment(&executable, system_directory)
}

#[cfg(windows)]
pub(crate) fn native_windows_hardened_command(executable: &Path) -> std::io::Result<Command> {
    let executable = fs::canonicalize(executable)?;
    let system_directory = native_windows_system_directory()?;
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

#[cfg(windows)]
const NATIVE_WINDOWS_TUNNEL_PREPARE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$base = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
if ([String]::IsNullOrWhiteSpace($base)) { throw 'common application data is unavailable' }
$vendorDirectory = Join-Path $base 'AnixOps'
$root = Join-Path $vendorDirectory 'WindowsTunnel'
$stateDirectory = Join-Path $root 'state'
$secretDirectory = Join-Path $root 'secrets'
$easytierDirectory = Join-Path $root 'easytier'

function Assert-NoReparsePoint {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'reparse points are not allowed'
    }
    return $item
}

function Assert-ExistingProtectedDirectory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw 'protected directory is absent' }
    $item = Assert-NoReparsePoint $Path
    if (-not $item.PSIsContainer) { throw 'protected path is not a directory' }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne 'S-1-5-32-544') { throw 'protected directory owner is invalid' }
    if (-not $acl.AreAccessRulesProtected) { throw 'ACL inheritance is enabled' }
    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rules = @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw 'unexpected ACL rule count' }
    foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
        $matches = @($rules | Where-Object {
            $_.IdentityReference.Value -eq $sidValue -and
            $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            $_.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl -and
            $_.InheritanceFlags -eq $InheritanceFlags -and
            $_.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None
        })
        if ($matches.Count -ne 1) { throw 'required ACL rule is missing' }
    }
}

function Set-ExactProtectedDirectorySecurity {
    param([string]$Path)
    $item = Assert-NoReparsePoint $Path
    if (-not $item.PSIsContainer) { throw 'protected path is not a directory' }
    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $administrators = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
    $acl.SetOwner($administrators)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleAll($rule) }
    foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $sidValue
        $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $identity, [System.Security.AccessControl.FileSystemRights]::FullControl, $inheritanceFlags, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow
        [void]$acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    Assert-ExistingProtectedDirectory $Path
}

function New-ProtectedDirectory {
    param([string]$Path)
    New-Item -ItemType Directory -LiteralPath $Path -ErrorAction Stop | Out-Null
    Set-ExactProtectedDirectorySecurity $Path
}

function Ensure-ProtectedDirectory {
    param([string]$Path)
    $created = $false
    try {
        New-ProtectedDirectory $Path
        $created = $true
    } catch {
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw }
    }
    if (-not $created) { Assert-ExistingProtectedDirectory $Path }
}

foreach ($directory in @($vendorDirectory, $root, $stateDirectory, $secretDirectory, $easytierDirectory)) {
    Ensure-ProtectedDirectory $directory
}
Assert-ExistingProtectedDirectory $easytierDirectory

[Console]::Out.WriteLine((Get-Item -LiteralPath $base -Force -ErrorAction Stop).FullName)
[Console]::Out.WriteLine((Get-Item -LiteralPath $vendorDirectory -Force -ErrorAction Stop).FullName)
[Console]::Out.WriteLine((Get-Item -LiteralPath $root -Force -ErrorAction Stop).FullName)
[Console]::Out.WriteLine((Get-Item -LiteralPath $stateDirectory -Force -ErrorAction Stop).FullName)
[Console]::Out.WriteLine((Get-Item -LiteralPath $secretDirectory -Force -ErrorAction Stop).FullName)
[Console]::Out.WriteLine((Get-Item -LiteralPath $easytierDirectory -Force -ErrorAction Stop).FullName)
"#;

#[cfg(windows)]
const NATIVE_WINDOWS_TUNNEL_INSPECT_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$base = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
if ([String]::IsNullOrWhiteSpace($base)) { throw 'common application data is unavailable' }
$vendorDirectory = Join-Path $base 'AnixOps'
$root = Join-Path $vendorDirectory 'WindowsTunnel'
$stateDirectory = Join-Path $root 'state'
$secretDirectory = Join-Path $root 'secrets'
$easytierDirectory = Join-Path $root 'easytier'

function Assert-ExistingProtectedDirectory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw 'protected directory is absent' }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'reparse points are not allowed'
    }
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne 'S-1-5-32-544') { throw 'protected directory owner is invalid' }
    if (-not $acl.AreAccessRulesProtected) { throw 'ACL inheritance is enabled' }
    $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $rules = @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw 'unexpected ACL rule count' }
    foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
        $matches = @($rules | Where-Object {
            $_.IdentityReference.Value -eq $sidValue -and
            $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            $_.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl -and
            $_.InheritanceFlags -eq $inheritanceFlags -and
            $_.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None
        })
        if ($matches.Count -ne 1) { throw 'required ACL rule is missing' }
    }
}

foreach ($directory in @($vendorDirectory, $root, $stateDirectory, $secretDirectory, $easytierDirectory)) {
    Assert-ExistingProtectedDirectory $directory
}
Assert-ExistingProtectedDirectory $easytierDirectory

[Console]::Out.WriteLine((Get-Item -LiteralPath $base -Force -ErrorAction Stop).FullName)
[Console]::Out.WriteLine((Get-Item -LiteralPath $vendorDirectory -Force -ErrorAction Stop).FullName)
[Console]::Out.WriteLine((Get-Item -LiteralPath $root -Force -ErrorAction Stop).FullName)
[Console]::Out.WriteLine((Get-Item -LiteralPath $stateDirectory -Force -ErrorAction Stop).FullName)
[Console]::Out.WriteLine((Get-Item -LiteralPath $secretDirectory -Force -ErrorAction Stop).FullName)
[Console]::Out.WriteLine((Get-Item -LiteralPath $easytierDirectory -Force -ErrorAction Stop).FullName)
"#;

#[cfg(windows)]
const NATIVE_WINDOWS_TUNNEL_PROTECT_SECRET_FILE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$path = $env:ANIXOPS_WINDOWS_TUNNEL_SECRET_PATH
if ([String]::IsNullOrWhiteSpace($path)) { throw 'secret path is unavailable' }
$base = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
if ([String]::IsNullOrWhiteSpace($base)) { throw 'common application data is unavailable' }
$vendorDirectory = Join-Path $base 'AnixOps'
$root = Join-Path $vendorDirectory 'WindowsTunnel'
$stateDirectory = Join-Path $root 'state'
$secretDirectory = Join-Path $root 'secrets'
$item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
if (-not ($item -is [System.IO.FileInfo])) { throw 'secret path is not a regular file' }
if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'reparse points are not allowed'
}
$secretDirectoryItem = Get-Item -LiteralPath $secretDirectory -Force -ErrorAction Stop
if (-not $secretDirectoryItem.PSIsContainer) { throw 'secret directory is not a directory' }
if (($secretDirectoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'reparse points are not allowed'
}
if (-not [String]::Equals($item.DirectoryName, $secretDirectoryItem.FullName, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'secret path is not a direct child'
}

function Assert-ExactProtectedSecretFile {
    param([string]$Path)
    $verifiedItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not ($verifiedItem -is [System.IO.FileInfo])) { throw 'secret path is not a regular file' }
    if (($verifiedItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'reparse points are not allowed'
    }
    $verified = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner = $verified.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne 'S-1-5-32-544') { throw 'secret file owner is invalid' }
    if (-not $verified.AreAccessRulesProtected) { throw 'ACL inheritance is enabled' }
    $rules = @($verified.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { throw 'unexpected ACL rule count' }
    foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
        $matches = @($rules | Where-Object {
            $_.IdentityReference.Value -eq $sidValue -and
            $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            $_.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl -and
            $_.InheritanceFlags -eq [System.Security.AccessControl.InheritanceFlags]::None -and
            $_.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None
        })
        if ($matches.Count -ne 1) { throw 'required ACL rule is missing' }
    }
}

$acl = Get-Acl -LiteralPath $path -ErrorAction Stop
$administrators = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
$acl.SetOwner($administrators)
$acl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleAll($rule) }
foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
    $identity = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $sidValue
    $rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $identity, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]::None, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow
    [void]$acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
Assert-ExactProtectedSecretFile $path
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeWindowsTunnelSecurePaths {
    pub state_directory: PathBuf,
    pub secret_directory: PathBuf,
    pub easytier_directory: PathBuf,
    pub delivery_ledger_path: PathBuf,
}

/// Creates and protects the fixed Windows tunnel storage root for an elevated start.
pub fn native_windows_prepare_tunnel_secure_paths() -> DomainResult<NativeWindowsTunnelSecurePaths>
{
    native_windows_prepare_tunnel_secure_paths_impl()
}

#[cfg(windows)]
fn native_windows_prepare_tunnel_secure_paths_impl() -> DomainResult<NativeWindowsTunnelSecurePaths>
{
    let mut command = native_windows_system_command(NativeWindowsSystemTool::PowerShell)
        .map_err(|_| secure_path_error())?;
    let output = command
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(NATIVE_WINDOWS_TUNNEL_PREPARE_SCRIPT)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|_| secure_path_error())?;
    native_windows_secure_paths_from_output(output)
}

#[cfg(windows)]
fn native_windows_inspect_tunnel_secure_paths_impl() -> DomainResult<NativeWindowsTunnelSecurePaths>
{
    let mut command = native_windows_system_command(NativeWindowsSystemTool::PowerShell)
        .map_err(|_| secure_path_error())?;
    let output = command
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(NATIVE_WINDOWS_TUNNEL_INSPECT_SCRIPT)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|_| secure_path_error())?;
    native_windows_secure_paths_from_output(output)
}

#[cfg(not(windows))]
fn native_windows_prepare_tunnel_secure_paths_impl() -> DomainResult<NativeWindowsTunnelSecurePaths>
{
    Err(secure_path_error())
}

/// Prepares an operator-provided state file path under the protected state directory.
#[cfg(windows)]
pub fn native_windows_prepare_state_path(path: &Path) -> DomainResult<PathBuf> {
    let secure_paths = native_windows_prepare_tunnel_secure_paths_impl()?;
    native_windows_validate_state_path_in_directory(path, &secure_paths.state_directory, false)
}

#[cfg(not(windows))]
pub fn native_windows_prepare_state_path(_path: &Path) -> DomainResult<PathBuf> {
    Err(secure_path_error())
}

/// Prepares and protects an existing operator-provided secret file under the fixed secret root.
#[cfg(windows)]
pub fn native_windows_prepare_secret_file(path: &Path) -> DomainResult<PathBuf> {
    let secure_paths = native_windows_prepare_tunnel_secure_paths_impl()?;
    let secret_path = native_windows_validate_state_path_in_directory(
        path,
        &secure_paths.secret_directory,
        true,
    )?;
    native_windows_protect_secret_file(&secret_path)?;
    native_windows_validate_state_path_in_directory(
        &secret_path,
        &secure_paths.secret_directory,
        true,
    )
}

/// Prepares and validates an existing EasyTier artifact under the fixed install root.
#[cfg(windows)]
pub fn native_windows_prepare_easytier_artifact(path: &Path) -> DomainResult<PathBuf> {
    let secure_paths = native_windows_prepare_tunnel_secure_paths_impl()?;
    native_windows_validate_easytier_artifact_in_directory(path, &secure_paths.easytier_directory)
}

#[cfg(not(windows))]
pub fn native_windows_prepare_easytier_artifact(_path: &Path) -> DomainResult<PathBuf> {
    Err(secure_path_error())
}

#[cfg(not(windows))]
pub fn native_windows_prepare_secret_file(_path: &Path) -> DomainResult<PathBuf> {
    Err(secure_path_error())
}

/// Inspects one existing state file without creating a directory or changing any ACL.
#[cfg(windows)]
pub fn native_windows_validate_existing_state_path(path: &Path) -> DomainResult<PathBuf> {
    let secure_paths = native_windows_inspect_tunnel_secure_paths_impl()?;
    native_windows_validate_state_path_in_directory(path, &secure_paths.state_directory, true)
}

/// Inspects one existing EasyTier artifact without changing the protected root.
#[cfg(windows)]
pub fn native_windows_validate_existing_easytier_artifact(path: &Path) -> DomainResult<PathBuf> {
    let secure_paths = native_windows_inspect_tunnel_secure_paths_impl()?;
    native_windows_validate_easytier_artifact_in_directory(path, &secure_paths.easytier_directory)
}

#[cfg(not(windows))]
pub fn native_windows_validate_existing_easytier_artifact(_path: &Path) -> DomainResult<PathBuf> {
    Err(secure_path_error())
}

#[cfg(not(windows))]
pub fn native_windows_validate_existing_state_path(_path: &Path) -> DomainResult<PathBuf> {
    Err(secure_path_error())
}

#[cfg(windows)]
fn native_windows_secure_paths_from_output(
    output: std::process::Output,
) -> DomainResult<NativeWindowsTunnelSecurePaths> {
    if !output.status.success() {
        return Err(secure_path_error());
    }
    let output = String::from_utf8(output.stdout).map_err(|_| secure_path_error())?;
    let paths = output.lines().collect::<Vec<_>>();
    if paths.len() != 6 || paths.iter().any(|path| path.trim().is_empty()) {
        return Err(secure_path_error());
    }

    let base = fs::canonicalize(paths[0]).map_err(|_| secure_path_error())?;
    let vendor = fs::canonicalize(paths[1]).map_err(|_| secure_path_error())?;
    let root = fs::canonicalize(paths[2]).map_err(|_| secure_path_error())?;
    let state_directory = fs::canonicalize(paths[3]).map_err(|_| secure_path_error())?;
    let secret_directory = fs::canonicalize(paths[4]).map_err(|_| secure_path_error())?;
    let easytier_directory = fs::canonicalize(paths[5]).map_err(|_| secure_path_error())?;
    if vendor.parent() != Some(base.as_path())
        || vendor.file_name().and_then(|name| name.to_str()) != Some("AnixOps")
        || root.parent() != Some(vendor.as_path())
        || root.file_name().and_then(|name| name.to_str()) != Some("WindowsTunnel")
        || state_directory.parent() != Some(root.as_path())
        || secret_directory.parent() != Some(root.as_path())
        || easytier_directory.parent() != Some(root.as_path())
        || state_directory.file_name().and_then(|name| name.to_str()) != Some("state")
        || secret_directory.file_name().and_then(|name| name.to_str()) != Some("secrets")
        || easytier_directory.file_name().and_then(|name| name.to_str()) != Some("easytier")
    {
        return Err(secure_path_error());
    }
    let delivery_ledger_path = state_directory.join("delivery-sequence-ledger.json");

    Ok(NativeWindowsTunnelSecurePaths {
        state_directory,
        secret_directory,
        easytier_directory,
        delivery_ledger_path,
    })
}

#[cfg(windows)]
fn native_windows_validate_easytier_artifact_in_directory(
    path: &Path,
    expected_directory: &Path,
) -> DomainResult<PathBuf> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| is_safe_tunnel_file_name(name))
        .ok_or_else(secure_path_error)?;
    let supplied_parent = path.parent().ok_or_else(secure_path_error)?;
    if native_windows_is_reparse_point(supplied_parent)? {
        return Err(secure_path_error());
    }
    let canonical_parent = fs::canonicalize(supplied_parent).map_err(|_| secure_path_error())?;
    let canonical_directory =
        fs::canonicalize(expected_directory).map_err(|_| secure_path_error())?;
    if canonical_parent != canonical_directory
        || native_windows_is_reparse_point(&canonical_directory)?
    {
        return Err(secure_path_error());
    }

    let candidate = canonical_directory.join(file_name);
    let metadata = fs::symlink_metadata(&candidate).map_err(|_| secure_path_error())?;
    if native_windows_metadata_is_reparse_point(&metadata) || !metadata.file_type().is_file() {
        return Err(secure_path_error());
    }
    let canonical_file = fs::canonicalize(&candidate).map_err(|_| secure_path_error())?;
    if !canonical_file.is_file() || canonical_file.parent() != Some(canonical_directory.as_path()) {
        return Err(secure_path_error());
    }
    Ok(canonical_file)
}

#[cfg(windows)]
fn native_windows_validate_state_path_in_directory(
    path: &Path,
    expected_directory: &Path,
    require_existing: bool,
) -> DomainResult<PathBuf> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| is_safe_tunnel_file_name(name))
        .ok_or_else(secure_path_error)?;
    let supplied_parent = path.parent().ok_or_else(secure_path_error)?;
    if native_windows_is_reparse_point(supplied_parent)? {
        return Err(secure_path_error());
    }
    let canonical_parent = fs::canonicalize(supplied_parent).map_err(|_| secure_path_error())?;
    let canonical_directory =
        fs::canonicalize(expected_directory).map_err(|_| secure_path_error())?;
    if canonical_parent != canonical_directory
        || native_windows_is_reparse_point(&canonical_directory)?
    {
        return Err(secure_path_error());
    }

    let candidate = canonical_directory.join(file_name);
    match fs::symlink_metadata(&candidate) {
        Ok(metadata) => {
            if native_windows_metadata_is_reparse_point(&metadata)
                || !metadata.file_type().is_file()
            {
                return Err(secure_path_error());
            }
            let canonical_file = fs::canonicalize(&candidate).map_err(|_| secure_path_error())?;
            if canonical_file.parent() != Some(canonical_directory.as_path()) {
                return Err(secure_path_error());
            }
            Ok(canonical_file)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !require_existing => {
            Ok(candidate)
        }
        Err(_) => Err(secure_path_error()),
    }
}

#[cfg(windows)]
fn native_windows_is_reparse_point(path: &Path) -> DomainResult<bool> {
    let metadata = fs::symlink_metadata(path).map_err(|_| secure_path_error())?;
    Ok(native_windows_metadata_is_reparse_point(&metadata))
}

#[cfg(windows)]
fn native_windows_metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn native_windows_protect_secret_file(path: &Path) -> DomainResult<()> {
    let mut command = native_windows_system_command(NativeWindowsSystemTool::PowerShell)
        .map_err(|_| secure_path_error())?;
    let output = command
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(NATIVE_WINDOWS_TUNNEL_PROTECT_SECRET_FILE_SCRIPT)
        .env("ANIXOPS_WINDOWS_TUNNEL_SECRET_PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|_| secure_path_error())?;
    output
        .status
        .success()
        .then_some(())
        .ok_or_else(secure_path_error)
}

fn secure_path_error() -> DomainError {
    DomainError::new(
        WINDOWS_TUNNEL_START_FAILED_CODE,
        "Windows tunnel input path protection failed",
    )
}
