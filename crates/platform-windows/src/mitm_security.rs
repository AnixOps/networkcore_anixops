//! Windows ACL boundary for NetworkCore-owned HTTPS MITM private material.

use control_domain::{DomainError, DomainResult};
use std::path::{Path, PathBuf};

use crate::managed::windows_managed_data_directory;

pub const WINDOWS_MANAGED_MITM_PRIVATE_KEY_PROTECTION_FAILED_CODE: &str =
    "windows.managed.mitm.private_key_protection_failed";

pub fn windows_managed_mitm_private_key_path() -> PathBuf {
    windows_managed_data_directory()
        .join("mitm")
        .join("root-ca-key.pem")
}

/// Removes inherited and broad access from the sole NetworkCore-owned MITM
/// private key. The generating account and LocalSystem retain exact access so
/// the GUI can explicitly disable MITM and the managed service can use it.
pub fn protect_windows_managed_mitm_private_key(path: &Path) -> DomainResult<()> {
    if path != windows_managed_mitm_private_key_path() {
        return Err(private_key_protection_error());
    }
    run_windows_managed_mitm_private_key_acl(path, "protect")
}

/// Verifies that the sole NetworkCore-owned MITM private key still has the
/// exact DACL established at creation time. This never mutates the key or its
/// ACL, so the managed service can fail closed when access has drifted.
pub fn validate_windows_managed_mitm_private_key(path: &Path) -> DomainResult<()> {
    if path != windows_managed_mitm_private_key_path() {
        return Err(private_key_protection_error());
    }
    run_windows_managed_mitm_private_key_acl(path, "validate")
}

/// Removes only the fixed NetworkCore-owned MITM private key. A missing key
/// is already-clean state; every other filesystem failure remains actionable.
pub fn remove_windows_managed_mitm_private_key(path: &Path) -> DomainResult<()> {
    if path != windows_managed_mitm_private_key_path() {
        return Err(private_key_protection_error());
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(private_key_protection_error()),
    }
}

#[cfg(any(windows, test))]
const MANAGED_MITM_PRIVATE_KEY_ACL_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
try { [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }
$path = $env:NETWORKCORE_MITM_PRIVATE_KEY_PATH
if ([String]::IsNullOrWhiteSpace($path)) { throw 'private key path is unavailable' }
$expectedDirectory = $env:NETWORKCORE_MITM_PRIVATE_KEY_DIRECTORY
if ([String]::IsNullOrWhiteSpace($expectedDirectory)) { throw 'private key directory is unavailable' }
$mode = $env:NETWORKCORE_MITM_PRIVATE_KEY_ACL_MODE
if ($mode -ne 'protect' -and $mode -ne 'validate') { throw 'private key ACL mode is invalid' }
$item = [System.IO.FileInfo]::new($path)
$directory = [System.IO.DirectoryInfo]::new($expectedDirectory)
if (-not $item.Exists -or -not $directory.Exists) { throw 'private key path is invalid' }
if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or ($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'reparse points are not allowed' }
if ($item.Name -ne 'root-ca-key.pem' -or -not [String]::Equals($item.DirectoryName, $directory.FullName, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'private key path is outside the managed MITM directory' }
$acl = $item.GetAccessControl()
$owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ([String]::IsNullOrWhiteSpace($owner) -or $owner -eq 'S-1-5-18') { throw 'private key owner is invalid' }
if ($mode -eq 'protect') {
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleAll($rule) }
    foreach ($sidValue in @($owner, 'S-1-5-18')) {
        $identity = [System.Security.Principal.SecurityIdentifier]::new($sidValue)
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($identity, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]::None, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
        [void]$acl.AddAccessRule($rule)
    }
    $item.SetAccessControl($acl)
}
$item.Refresh()
$verified = $item.GetAccessControl()
if (-not $verified.AreAccessRulesProtected) { throw 'ACL inheritance is enabled' }
$rules = @($verified.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
if ($rules.Count -ne 2) { throw 'unexpected ACL rule count' }
foreach ($sidValue in @($owner, 'S-1-5-18')) {
    $found = 0
    foreach ($candidate in $rules) {
        if ($candidate.IdentityReference.Value -eq $sidValue -and
            $candidate.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
            $candidate.FileSystemRights -eq [System.Security.AccessControl.FileSystemRights]::FullControl -and
            $candidate.InheritanceFlags -eq [System.Security.AccessControl.InheritanceFlags]::None -and
            $candidate.PropagationFlags -eq [System.Security.AccessControl.PropagationFlags]::None) { $found += 1 }
    }
    if ($found -ne 1) { throw 'required private key ACL rule is missing' }
}
"#;

#[cfg(windows)]
fn run_windows_managed_mitm_private_key_acl(path: &Path, mode: &str) -> DomainResult<()> {
    use crate::trusted_command::native_windows_powershell_command;
    use std::process::Stdio;

    let mut command =
        native_windows_powershell_command().map_err(|_| private_key_protection_error())?;
    let directory = path.parent().ok_or_else(private_key_protection_error)?;
    let output = command
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(MANAGED_MITM_PRIVATE_KEY_ACL_SCRIPT)
        .env("NETWORKCORE_MITM_PRIVATE_KEY_PATH", path)
        .env("NETWORKCORE_MITM_PRIVATE_KEY_DIRECTORY", directory)
        .env("NETWORKCORE_MITM_PRIVATE_KEY_ACL_MODE", mode)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|_| private_key_protection_error())?;
    if output.status.success() {
        Ok(())
    } else {
        Err(private_key_protection_error_with_acl_detail(&output.stderr))
    }
}

#[cfg(not(windows))]
fn run_windows_managed_mitm_private_key_acl(_path: &Path, _mode: &str) -> DomainResult<()> {
    Err(private_key_protection_error())
}

fn private_key_protection_error() -> DomainError {
    DomainError::new(
        WINDOWS_MANAGED_MITM_PRIVATE_KEY_PROTECTION_FAILED_CODE,
        "NetworkCore-owned HTTPS MITM private key protection failed",
    )
}

#[cfg(windows)]
fn private_key_protection_error_with_acl_detail(stderr: &[u8]) -> DomainError {
    let detail = String::from_utf8_lossy(stderr)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| {
            line.chars()
                .filter(|character| !character.is_control())
                .take(240)
                .collect::<String>()
        })
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| "ACL command returned no diagnostic output".to_string());
    DomainError::new(
        WINDOWS_MANAGED_MITM_PRIVATE_KEY_PROTECTION_FAILED_CODE,
        format!("NetworkCore-owned HTTPS MITM private key protection failed: {detail}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_mitm_private_key_path_is_fixed_under_managed_data() {
        let path = windows_managed_mitm_private_key_path();
        assert_eq!(
            path.file_name().and_then(|name| name.to_str()),
            Some("root-ca-key.pem")
        );
        assert_eq!(
            path.parent()
                .and_then(|path| path.file_name())
                .and_then(|name| name.to_str()),
            Some("mitm")
        );
    }

    #[test]
    fn acl_script_uses_the_rust_validated_managed_mitm_directory() {
        assert!(
            MANAGED_MITM_PRIVATE_KEY_ACL_SCRIPT.contains("NETWORKCORE_MITM_PRIVATE_KEY_DIRECTORY")
        );
        assert!(!MANAGED_MITM_PRIVATE_KEY_ACL_SCRIPT.contains("CommonApplicationData"));
    }

    #[test]
    fn acl_script_builds_rules_in_expression_mode() {
        // `New-Object -ArgumentList $x, [Type]::Member` parses `[Type]::Member`
        // in argument mode as a plain string, and cmdlets live in modules that
        // can fail to load under the trusted minimal environment. The script
        // therefore uses only .NET constructors and methods.
        for cmdlet in [
            "New-Object",
            "Set-Acl",
            "Get-Acl",
            "Get-Item",
            "Where-Object",
        ] {
            assert!(
                !MANAGED_MITM_PRIVATE_KEY_ACL_SCRIPT.contains(cmdlet),
                "{cmdlet} must not be used"
            );
        }
        assert!(MANAGED_MITM_PRIVATE_KEY_ACL_SCRIPT.contains("FileSystemAccessRule]::new("));
        assert!(MANAGED_MITM_PRIVATE_KEY_ACL_SCRIPT.contains("[Console]::OutputEncoding"));
    }

    /// Runs the real ACL script through the trusted PowerShell environment on
    /// a scratch key, so a script or environment regression fails Windows CI
    /// instead of the user's "enable HTTPS MITM" button.
    #[cfg(windows)]
    #[test]
    fn acl_script_protects_and_validates_a_scratch_key() {
        let directory =
            std::env::temp_dir().join(format!("networkcore-mitm-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("scratch directory");
        let key = directory.join("root-ca-key.pem");
        std::fs::write(&key, b"scratch").expect("scratch key");

        let protect = run_windows_managed_mitm_private_key_acl(&key, "protect");
        let validate = run_windows_managed_mitm_private_key_acl(&key, "validate");
        let _ = std::fs::remove_dir_all(&directory);

        protect.unwrap_or_else(|error| panic!("protect failed: {}", error.message));
        validate.unwrap_or_else(|error| panic!("validate failed: {}", error.message));
    }

    #[test]
    fn rejects_any_private_key_path_outside_the_fixed_mitm_location() {
        let rejected = windows_managed_mitm_private_key_path().with_file_name("other-key.pem");
        let error = protect_windows_managed_mitm_private_key(&rejected)
            .expect_err("only the fixed NetworkCore MITM key path may be protected");

        assert_eq!(
            error.code,
            WINDOWS_MANAGED_MITM_PRIVATE_KEY_PROTECTION_FAILED_CODE
        );
    }

    #[test]
    fn validation_rejects_any_private_key_path_outside_the_fixed_mitm_location() {
        let rejected = windows_managed_mitm_private_key_path().with_file_name("other-key.pem");
        let error = validate_windows_managed_mitm_private_key(&rejected)
            .expect_err("only the fixed NetworkCore MITM key path may be validated");

        assert_eq!(
            error.code,
            WINDOWS_MANAGED_MITM_PRIVATE_KEY_PROTECTION_FAILED_CODE
        );
    }

    #[test]
    fn removal_rejects_any_private_key_path_outside_the_fixed_mitm_location() {
        let error = remove_windows_managed_mitm_private_key(Path::new("other-key.pem"))
            .expect_err("only the fixed NetworkCore MITM key path may be removed");

        assert_eq!(
            error.code,
            WINDOWS_MANAGED_MITM_PRIVATE_KEY_PROTECTION_FAILED_CODE
        );
    }
}
