use platform_linux::proxy::{
    apply_environment_proxy, rollback_environment_proxy, status_environment_proxy,
    LinuxEnvironmentProxyApplyRequest, LinuxEnvironmentProxyRollbackRequest,
    LINUX_PROXY_CONFIRMATION_REQUIRED_CODE, LINUX_PROXY_CONFLICT_CODE,
};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static FIXTURE_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

fn fixture_root() -> PathBuf {
    let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "networkcore-linux-proxy-contract-{}-{sequence}",
        std::process::id(),
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("proxy fixture directory should be created");
    root
}

#[test]
fn applies_environment_proxy_with_snapshot_and_private_file_contents() {
    let root = fixture_root();
    let file_path = root.join("environment");
    let snapshot_path = root.join("environment.snapshot.json");
    fs::write(&file_path, "PATH=/usr/bin\n").expect("existing environment file should be written");

    let report = apply_environment_proxy(&LinuxEnvironmentProxyApplyRequest {
        file_path: file_path.clone(),
        snapshot_path: snapshot_path.clone(),
        proxy_url: "socks5://127.0.0.1:7890".to_string(),
        confirmed: true,
    })
    .expect("confirmed proxy apply should succeed");

    assert!(report.verified);
    assert!(report.previous_exists);
    let contents = fs::read_to_string(&file_path).unwrap();
    assert!(contents.contains("HTTP_PROXY=socks5://127.0.0.1:7890"));
    assert!(!contents.contains("environment.snapshot"));
    assert!(snapshot_path.exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn rollback_rejects_external_environment_file_changes() {
    let root = fixture_root();
    let file_path = root.join("environment");
    let snapshot_path = root.join("environment.snapshot.json");
    let request = LinuxEnvironmentProxyApplyRequest {
        file_path: file_path.clone(),
        snapshot_path: snapshot_path.clone(),
        proxy_url: "http://127.0.0.1:8080".to_string(),
        confirmed: true,
    };
    apply_environment_proxy(&request).expect("proxy apply should succeed");
    fs::write(&file_path, "external change\n").expect("external change should be written");

    let error = rollback_environment_proxy(&LinuxEnvironmentProxyRollbackRequest {
        file_path,
        snapshot_path,
        confirmed: true,
    })
    .expect_err("external changes must block rollback");
    assert_eq!(error.code, LINUX_PROXY_CONFLICT_CODE);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn proxy_mutation_requires_confirmation_and_status_is_read_only() {
    let root = fixture_root();
    let file_path = root.join("environment");
    let snapshot_path = root.join("environment.snapshot.json");
    let error = apply_environment_proxy(&LinuxEnvironmentProxyApplyRequest {
        file_path: file_path.clone(),
        snapshot_path,
        proxy_url: "http://127.0.0.1:8080".to_string(),
        confirmed: false,
    })
    .expect_err("proxy mutation must require confirmation");
    assert_eq!(error.code, LINUX_PROXY_CONFIRMATION_REQUIRED_CODE);
    let status = status_environment_proxy(&file_path).expect("status should be read-only");
    assert!(!status.exists);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn apply_refuses_to_overwrite_an_existing_snapshot() {
    let root = fixture_root();
    let file_path = root.join("environment");
    let snapshot_path = root.join("environment.snapshot.json");
    fs::write(&snapshot_path, "operator-owned snapshot\n")
        .expect("existing snapshot should be written");

    let error = apply_environment_proxy(&LinuxEnvironmentProxyApplyRequest {
        file_path,
        snapshot_path,
        proxy_url: "http://127.0.0.1:8080".to_string(),
        confirmed: true,
    })
    .expect_err("apply must not overwrite an existing snapshot");
    assert_eq!(
        error.code,
        platform_linux::proxy::LINUX_PROXY_WRITE_FAILED_CODE
    );
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn applied_environment_proxy_file_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let root = fixture_root();
    let file_path = root.join("environment");
    let snapshot_path = root.join("environment.snapshot.json");
    apply_environment_proxy(&LinuxEnvironmentProxyApplyRequest {
        file_path: file_path.clone(),
        snapshot_path,
        proxy_url: "http://127.0.0.1:8080".to_string(),
        confirmed: true,
    })
    .expect("confirmed proxy apply should succeed");

    let mode = fs::metadata(file_path)
        .expect("proxy file metadata should be readable")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    let _ = fs::remove_dir_all(root);
}
