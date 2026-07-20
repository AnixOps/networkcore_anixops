#[cfg(not(windows))]
use platform_windows::tunnel_runtime::WINDOWS_TUNNEL_START_FAILED_CODE;
#[cfg(not(windows))]
use platform_windows::tunnel_security::{
    native_windows_prepare_secret_file, native_windows_prepare_state_path,
    native_windows_prepare_tunnel_secure_paths, native_windows_validate_existing_state_path,
};
#[cfg(not(windows))]
use std::path::Path;

#[test]
fn native_windows_prepare_uses_trusted_programdata_and_exact_storage_ownership() {
    let source = include_str!("../src/tunnel_security.rs").replace("\r\n", "\n");
    let prepare = native_script(&source, "NATIVE_WINDOWS_TUNNEL_PREPARE_SCRIPT");
    let inspection = native_script(&source, "NATIVE_WINDOWS_TUNNEL_INSPECT_SCRIPT");
    let secret_protection =
        native_script(&source, "NATIVE_WINDOWS_TUNNEL_PROTECT_SECRET_FILE_SCRIPT");

    for script in [prepare, inspection, secret_protection] {
        assert!(script.contains(
            "$base = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)"
        ));
        assert!(script.contains("$vendorDirectory = Join-Path $base 'AnixOps'"));
        assert!(script.contains("$root = Join-Path $vendorDirectory 'WindowsTunnel'"));
    }
    for script in [prepare, inspection] {
        assert!(script.contains("$stateDirectory = Join-Path $root 'state'"));
        assert!(script.contains("$secretDirectory = Join-Path $root 'secrets'"));
        assert!(script.contains("ReparsePoint"));
        assert!(script.contains("GetOwner([System.Security.Principal.SecurityIdentifier]).Value"));
        assert!(script.contains("S-1-5-32-544"));
        assert!(script.contains("$rules.Count -ne 2"));
        assert!(script.contains("FileSystemRights]::FullControl"));
    }

    assert!(prepare.contains("function New-ProtectedDirectory"));
    assert!(prepare.contains("function Ensure-ProtectedDirectory"));
    assert!(prepare.contains("New-Item -ItemType Directory -LiteralPath $Path -ErrorAction Stop"));
    assert!(!prepare.contains("New-Item -ItemType Directory -LiteralPath $Path -Force"));
    assert!(prepare.contains("if (-not $created) { Assert-ExistingProtectedDirectory $Path }"));
    assert!(prepare.contains("SetOwner"));
    assert!(prepare.contains("Set-Acl"));
    assert!(prepare.contains("@($vendorDirectory, $root, $stateDirectory, $secretDirectory)"));

    assert!(secret_protection.contains("SetOwner"));
    assert!(secret_protection
        .contains("GetOwner([System.Security.Principal.SecurityIdentifier]).Value"));
    assert!(secret_protection.contains("$rules.Count -ne 2"));
    assert!(secret_protection.contains("FileSystemRights]::FullControl"));

    let prepare_helper_marker =
        "#[cfg(windows)]\nfn native_windows_prepare_tunnel_secure_paths_impl(";
    let prepare_helper_start = source
        .find(prepare_helper_marker)
        .expect("Windows secure path preparation helper exists");
    let inspection_helper_marker =
        "#[cfg(windows)]\nfn native_windows_inspect_tunnel_secure_paths_impl(";
    let inspection_helper_start = source
        .find(inspection_helper_marker)
        .expect("Windows secure path inspection helper exists");
    let prepare_helper = &source[prepare_helper_start..inspection_helper_start];

    let stdin = prepare_helper
        .find(".stdin(Stdio::null())")
        .expect("secure path preparation discards child stdin");
    let stdout = prepare_helper
        .find(".stdout(Stdio::piped())")
        .expect("secure path preparation captures child stdout");
    let stderr = prepare_helper
        .find(".stderr(Stdio::piped())")
        .expect("secure path preparation captures child stderr");
    let output = prepare_helper
        .find(".output()")
        .expect("secure path preparation captures command output");
    assert!(stdin < stdout && stdout < stderr && stderr < output);

    assert!(source.contains("if paths.len() != 5"));
    assert!(source.contains("let base = fs::canonicalize(paths[0])"));
    assert!(source.contains("let vendor = fs::canonicalize(paths[1])"));
    assert!(source.contains("let root = fs::canonicalize(paths[2])"));
    assert!(source.contains("vendor.parent() != Some(base.as_path())"));
    assert!(
        source.contains("vendor.file_name().and_then(|name| name.to_str()) != Some(\"AnixOps\")")
    );
    assert!(source.contains("root.parent() != Some(vendor.as_path())"));
    assert!(source
        .contains("root.file_name().and_then(|name| name.to_str()) != Some(\"WindowsTunnel\")"));
}

#[test]
fn existing_state_validation_uses_inspection_only_storage_checks() {
    let source = include_str!("../src/tunnel_security.rs").replace("\r\n", "\n");
    let inspection = native_script(&source, "NATIVE_WINDOWS_TUNNEL_INSPECT_SCRIPT");

    assert!(inspection.contains("Get-Acl"));
    assert!(inspection.contains("ReparsePoint"));
    assert!(!inspection.contains("New-Item"));
    assert!(!inspection.contains("Set-Acl"));
    assert!(!inspection.contains("SetOwner"));
    assert!(!inspection.contains("SetAccessRuleProtection"));

    let validation_marker = "#[cfg(windows)]\npub fn native_windows_validate_existing_state_path(";
    let validation_start = source
        .find(validation_marker)
        .expect("Windows existing state validation exists");
    let validation_end = source[validation_start..]
        .find("\n#[cfg(not(windows))]\npub fn native_windows_validate_existing_state_path(")
        .expect("Windows existing state validation ends before non-Windows implementation");
    let validation = &source[validation_start..validation_start + validation_end];

    assert!(validation.contains("native_windows_inspect_tunnel_secure_paths_impl()"));
    assert!(!validation.contains("native_windows_prepare_tunnel_secure_paths_impl()"));
    assert!(!validation.contains("Set-Acl"));
}

#[test]
fn native_windows_secure_path_preparation_remains_non_windows_fail_closed() {
    let source = include_str!("../src/tunnel_security.rs").replace("\r\n", "\n");
    let marker = "#[cfg(not(windows))]\nfn native_windows_prepare_tunnel_secure_paths_impl(";
    let start = source
        .find(marker)
        .expect("non-Windows secure path preparation helper exists");
    let end = source[start..]
        .find("\n/// Prepares an operator-provided state file path")
        .expect("non-Windows secure path preparation helper is bounded");
    let implementation = &source[start..start + end];

    assert!(implementation.contains("Err(secure_path_error())"));
}

fn native_script<'a>(source: &'a str, name: &str) -> &'a str {
    let marker = format!("const {name}: &str = r#\"");
    let start = source
        .find(&marker)
        .unwrap_or_else(|| panic!("{name} exists"));
    let end = source[start..]
        .find("\"#;")
        .unwrap_or_else(|| panic!("{name} is bounded"));

    &source[start..start + end]
}

#[cfg(not(windows))]
#[test]
fn non_windows_secure_path_operations_fail_closed_without_native_execution() {
    let preparation = native_windows_prepare_tunnel_secure_paths()
        .expect_err("non-Windows secure storage preparation is unavailable");
    assert_eq!(preparation.code, WINDOWS_TUNNEL_START_FAILED_CODE);

    let state_preparation = native_windows_prepare_state_path(Path::new("state.json"))
        .expect_err("non-Windows state preparation is unavailable");
    assert_eq!(state_preparation.code, WINDOWS_TUNNEL_START_FAILED_CODE);

    let secret_preparation = native_windows_prepare_secret_file(Path::new("secret.txt"))
        .expect_err("non-Windows secret preparation is unavailable");
    assert_eq!(secret_preparation.code, WINDOWS_TUNNEL_START_FAILED_CODE);

    let state_validation = native_windows_validate_existing_state_path(Path::new("state.json"))
        .expect_err("non-Windows state inspection is unavailable");
    assert_eq!(state_validation.code, WINDOWS_TUNNEL_START_FAILED_CODE);
}
