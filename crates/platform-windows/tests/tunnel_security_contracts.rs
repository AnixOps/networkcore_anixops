use platform_windows::tunnel_runtime::WINDOWS_TUNNEL_START_FAILED_CODE;
use platform_windows::tunnel_security::{
    native_windows_prepare_secret_file, native_windows_prepare_state_path,
    native_windows_prepare_tunnel_secure_paths, native_windows_validate_existing_state_path,
};
use std::path::Path;

#[test]
fn native_windows_prepare_uses_bounded_programdata_acl_setup() {
    let source = include_str!("../src/tunnel_security.rs").replace("\r\n", "\n");

    assert!(source.contains(
        "[Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)"
    ));
    assert!(source.contains("$root = Join-Path $base 'AnixOps\\WindowsTunnel'"));
    assert!(source.contains("$stateDirectory = Join-Path $root 'state'"));
    assert!(source.contains("$secretDirectory = Join-Path $root 'secrets'"));
    assert!(source.contains("ReparsePoint"));
    assert!(source.contains("SetAccessRuleProtection($true, $false)"));
    assert!(source.contains("S-1-5-18"));
    assert!(source.contains("S-1-5-32-544"));
    assert!(source.contains("FileSystemRights]::FullControl"));
    assert!(source.contains("Set-Acl"));

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
}

#[test]
fn existing_state_validation_uses_inspection_only_storage_checks() {
    let source = include_str!("../src/tunnel_security.rs").replace("\r\n", "\n");
    let inspection_marker = "const NATIVE_WINDOWS_TUNNEL_INSPECT_SCRIPT: &str = r#\"";
    let inspection_start = source
        .find(inspection_marker)
        .expect("Windows secure path inspection script exists");
    let inspection_end = source[inspection_start..]
        .find("\"#;")
        .expect("Windows secure path inspection script has a bounded source slice");
    let inspection = &source[inspection_start..inspection_start + inspection_end];

    assert!(inspection.contains("Get-Acl"));
    assert!(inspection.contains("ReparsePoint"));
    assert!(!inspection.contains("New-Item"));
    assert!(!inspection.contains("Set-Acl"));
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
