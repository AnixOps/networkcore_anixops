use platform_linux::systemd::{
    install_systemd_unit, plan_systemd_unit_removal, render_systemd_unit,
    LinuxManagedServiceUnitInstallRequest, LinuxManagedServiceUnitRequest,
    LINUX_SYSTEMD_UNIT_INVALID_CODE,
};
use std::fs;
use std::path::PathBuf;

#[test]
fn renders_bounded_non_root_systemd_unit_without_installing_it() {
    let plan = render_systemd_unit(&LinuxManagedServiceUnitRequest {
        unit_name: "networkcore.service".to_string(),
        description: "NetworkCore managed runtime".to_string(),
        executable_path: PathBuf::from("/usr/lib/networkcore/networkcore-linux"),
        arguments: vec!["connect".to_string(), "--managed".to_string()],
        service_user: "networkcore".to_string(),
        service_group: "networkcore".to_string(),
        state_directory: PathBuf::from("/var/lib/networkcore"),
    })
    .expect("valid unit request should render");

    assert!(plan.install_confirmation_required);
    assert_eq!(plan.restart_policy, "on-failure");
    assert_eq!(plan.start_limit_burst, 3);
    assert!(plan.content.contains("User=networkcore"));
    assert!(plan.content.contains("NoNewPrivileges=true"));
    assert!(plan.content.contains("Restart=on-failure"));
    assert!(plan.content.contains("StartLimitBurst=3"));
    assert!(!plan.content.contains("Restart=always"));
}

#[test]
fn rejects_root_or_relative_unit_requests() {
    let error = render_systemd_unit(&LinuxManagedServiceUnitRequest {
        unit_name: "networkcore.service".to_string(),
        description: "NetworkCore".to_string(),
        executable_path: PathBuf::from("networkcore-linux"),
        arguments: Vec::new(),
        service_user: "root".to_string(),
        service_group: "root".to_string(),
        state_directory: PathBuf::from("state"),
    })
    .expect_err("root and relative paths must be rejected");
    assert_eq!(error.code, LINUX_SYSTEMD_UNIT_INVALID_CODE);
}

#[test]
fn rejects_newlines_that_could_escape_unit_fields() {
    let error = render_systemd_unit(&LinuxManagedServiceUnitRequest {
        unit_name: "networkcore.service".to_string(),
        description: "NetworkCore\nExecStart=/bin/sh".to_string(),
        executable_path: PathBuf::from("/usr/lib/networkcore/networkcore-linux"),
        arguments: Vec::new(),
        service_user: "networkcore".to_string(),
        service_group: "networkcore".to_string(),
        state_directory: PathBuf::from("/var/lib/networkcore"),
    })
    .expect_err("newline injection must be rejected");
    assert_eq!(error.code, LINUX_SYSTEMD_UNIT_INVALID_CODE);
}

#[test]
fn removal_plan_preserves_state_and_requires_separate_purge_confirmation() {
    let plan = plan_systemd_unit_removal(
        "networkcore.service",
        std::path::Path::new("/var/lib/networkcore"),
    )
    .expect("valid removal plan should render");

    assert_eq!(
        plan.unit_path,
        std::path::Path::new("/etc/systemd/system/networkcore.service")
    );
    assert!(plan.confirmation_required);
    assert!(plan.purge_confirmation_required);
    assert_eq!(
        plan.preserved_state_directory,
        std::path::Path::new("/var/lib/networkcore")
    );
}

#[test]
fn installs_unit_with_snapshot_and_write_verification_without_systemctl() {
    let root = std::env::temp_dir().join(format!(
        "networkcore-systemd-install-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("fixture directory should be created");
    let unit_path = root.join("networkcore.service");
    let snapshot_path = root.join("networkcore.service.snapshot");
    fs::write(&unit_path, "old unit\n").expect("existing unit should be written");

    let report = install_systemd_unit(&LinuxManagedServiceUnitInstallRequest {
        unit_path: unit_path.clone(),
        snapshot_path: snapshot_path.clone(),
        content: "[Unit]\nDescription=NetworkCore\n\n[Service]\nExecStart=/bin/true\n".to_string(),
    })
    .expect("unit should install");

    assert!(report.snapshot_written);
    assert!(report.verified);
    assert_eq!(fs::read_to_string(&snapshot_path).unwrap(), "old unit\n");
    assert_eq!(
        fs::read_to_string(&unit_path).unwrap(),
        "[Unit]\nDescription=NetworkCore\n\n[Service]\nExecStart=/bin/true\n"
    );
    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn refuses_to_replace_a_systemd_unit_symlink() {
    use std::os::unix::fs::symlink;

    let root = std::env::temp_dir().join(format!(
        "networkcore-systemd-symlink-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("fixture directory should be created");
    let target = root.join("target.service");
    let unit_path = root.join("networkcore.service");
    fs::write(&target, "external unit\n").expect("target unit should be written");
    symlink(&target, &unit_path).expect("unit symlink should be created");

    let error = install_systemd_unit(&LinuxManagedServiceUnitInstallRequest {
        unit_path,
        snapshot_path: root.join("snapshot.unit"),
        content: "[Unit]\n\n[Service]\nExecStart=/bin/true\n".to_string(),
    })
    .expect_err("unit symlink must be rejected");

    assert_eq!(
        error.code,
        platform_linux::systemd::LINUX_SYSTEMD_UNIT_WRITE_FAILED_CODE
    );
    assert_eq!(fs::read_to_string(&target).unwrap(), "external unit\n");
    let _ = fs::remove_dir_all(&root);
}
