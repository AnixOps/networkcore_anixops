use platform_linux::systemd::{
    control_systemd_service, install_systemd_unit, plan_systemd_unit_removal, remove_systemd_unit,
    render_systemd_unit, LinuxManagedServiceUnitInstallRequest,
    LinuxManagedServiceUnitRemovalRequest, LinuxManagedServiceUnitRequest,
    LinuxSystemdCommandRunner, LinuxSystemdServiceAction, LinuxSystemdServiceControlRequest,
    LINUX_SYSTEMD_CONTROL_CONFIRMATION_REQUIRED_CODE, LINUX_SYSTEMD_CONTROL_FAILED_CODE,
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

#[derive(Default)]
struct RecordingSystemdRunner {
    calls: std::cell::RefCell<Vec<(LinuxSystemdServiceAction, String)>>,
    exit_code: Option<i32>,
}

impl LinuxSystemdCommandRunner for RecordingSystemdRunner {
    fn run(
        &self,
        action: LinuxSystemdServiceAction,
        unit_name: &str,
    ) -> control_domain::DomainResult<Option<i32>> {
        self.calls
            .borrow_mut()
            .push((action, unit_name.to_string()));
        Ok(self.exit_code)
    }
}

#[test]
fn service_control_requires_confirmation_before_runner_invocation() {
    let runner = RecordingSystemdRunner {
        exit_code: Some(0),
        ..Default::default()
    };
    let error = control_systemd_service(
        &runner,
        &LinuxSystemdServiceControlRequest {
            unit_name: "networkcore.service".to_string(),
            action: LinuxSystemdServiceAction::Start,
            confirmed: false,
        },
    )
    .expect_err("service mutation must require confirmation");

    assert_eq!(error.code, LINUX_SYSTEMD_CONTROL_CONFIRMATION_REQUIRED_CODE);
    assert!(runner.calls.borrow().is_empty());
}

#[test]
fn service_control_reports_action_and_exit_code() {
    let runner = RecordingSystemdRunner {
        exit_code: Some(0),
        ..Default::default()
    };
    let report = control_systemd_service(
        &runner,
        &LinuxSystemdServiceControlRequest {
            unit_name: "networkcore.service".to_string(),
            action: LinuxSystemdServiceAction::Status,
            confirmed: true,
        },
    )
    .expect("confirmed status should invoke the runner");

    assert!(report.succeeded);
    assert_eq!(report.exit_code, Some(0));
    assert_eq!(report.action.command(), "is-active");
    assert_eq!(
        runner.calls.borrow().as_slice(),
        &[(
            LinuxSystemdServiceAction::Status,
            "networkcore.service".to_string()
        )]
    );
}

#[test]
fn service_control_separates_runtime_reload_from_daemon_reload() {
    assert_eq!(LinuxSystemdServiceAction::Reload.command(), "reload");
    assert_eq!(
        LinuxSystemdServiceAction::DaemonReload.command(),
        "daemon-reload"
    );
}

#[test]
fn daemon_reload_requires_confirmation_and_reaches_runner() {
    let runner = RecordingSystemdRunner {
        exit_code: Some(0),
        ..Default::default()
    };
    let error = control_systemd_service(
        &runner,
        &LinuxSystemdServiceControlRequest {
            unit_name: "networkcore.service".to_string(),
            action: LinuxSystemdServiceAction::DaemonReload,
            confirmed: false,
        },
    )
    .expect_err("daemon reload must require confirmation");
    assert_eq!(error.code, LINUX_SYSTEMD_CONTROL_CONFIRMATION_REQUIRED_CODE);
    assert!(runner.calls.borrow().is_empty());

    let report = control_systemd_service(
        &runner,
        &LinuxSystemdServiceControlRequest {
            unit_name: "networkcore.service".to_string(),
            action: LinuxSystemdServiceAction::DaemonReload,
            confirmed: true,
        },
    )
    .expect("confirmed daemon reload should invoke the runner");
    assert!(report.succeeded);
    assert_eq!(
        runner.calls.borrow().as_slice(),
        &[(
            LinuxSystemdServiceAction::DaemonReload,
            "networkcore.service".to_string()
        )]
    );
}

#[test]
fn read_only_status_does_not_require_confirmation() {
    let runner = RecordingSystemdRunner {
        exit_code: Some(0),
        ..Default::default()
    };
    let report = control_systemd_service(
        &runner,
        &LinuxSystemdServiceControlRequest {
            unit_name: "networkcore.service".to_string(),
            action: LinuxSystemdServiceAction::Status,
            confirmed: false,
        },
    )
    .expect("read-only status should not require confirmation");
    assert!(report.succeeded);
}

#[test]
fn service_control_exposes_nonzero_exit_as_failed_report() {
    let runner = RecordingSystemdRunner {
        exit_code: Some(3),
        ..Default::default()
    };
    let report = control_systemd_service(
        &runner,
        &LinuxSystemdServiceControlRequest {
            unit_name: "networkcore.service".to_string(),
            action: LinuxSystemdServiceAction::Stop,
            confirmed: true,
        },
    )
    .expect("runner exit status should be represented in the report");

    assert!(!report.succeeded);
    assert_eq!(report.exit_code, Some(3));
    assert_eq!(
        report.diagnostics[0].code,
        LINUX_SYSTEMD_CONTROL_FAILED_CODE
    );
}

#[test]
fn service_control_rejects_path_like_unit_names() {
    let runner = RecordingSystemdRunner {
        exit_code: Some(0),
        ..Default::default()
    };
    let error = control_systemd_service(
        &runner,
        &LinuxSystemdServiceControlRequest {
            unit_name: "../networkcore.service".to_string(),
            action: LinuxSystemdServiceAction::Restart,
            confirmed: true,
        },
    )
    .expect_err("path-like unit names must be rejected");

    assert_eq!(error.code, LINUX_SYSTEMD_UNIT_INVALID_CODE);
    assert!(runner.calls.borrow().is_empty());
}

#[test]
fn removes_unit_only_after_snapshot_and_confirmation() {
    let root =
        std::env::temp_dir().join(format!("networkcore-systemd-remove-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("fixture directory should be created");
    let unit_path = root.join("networkcore.service");
    let snapshot_path = root.join("snapshot.unit");
    fs::write(&unit_path, "managed unit\n").expect("unit should be written");

    let report = remove_systemd_unit(&LinuxManagedServiceUnitRemovalRequest {
        unit_path: unit_path.clone(),
        snapshot_path: snapshot_path.clone(),
        confirmed: true,
    })
    .expect("confirmed removal should succeed");

    assert!(report.removed);
    assert!(report.snapshot_written);
    assert!(!unit_path.exists());
    assert_eq!(fs::read_to_string(snapshot_path).unwrap(), "managed unit\n");
    let _ = fs::remove_dir_all(&root);
}
