use platform_linux::systemd::{
    render_systemd_unit, LinuxManagedServiceUnitRequest, LINUX_SYSTEMD_UNIT_INVALID_CODE,
};
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
