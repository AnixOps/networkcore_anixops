use control_domain::{DomainError, DomainResult};
use platform_linux::trust::{
    apply_linux_trust, rollback_linux_trust, LinuxTrustApplyRequest, LinuxTrustRefreshRunner,
    LinuxTrustRollbackRequest, LINUX_TRUST_CONFIRMATION_REQUIRED_CODE, LINUX_TRUST_CONFLICT_CODE,
    LINUX_TRUST_REFRESH_FAILED_CODE,
};
use std::cell::RefCell;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static FIXTURE_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

fn fixture_root() -> PathBuf {
    let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "networkcore-linux-trust-contract-{}-{sequence}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("trust fixture directory should be created");
    root
}

#[derive(Default)]
struct RecordingRefreshRunner {
    calls: RefCell<usize>,
    failure: bool,
}

impl LinuxTrustRefreshRunner for RecordingRefreshRunner {
    fn refresh(&self) -> DomainResult<()> {
        *self.calls.borrow_mut() += 1;
        if self.failure {
            Err(DomainError::new(
                "test.refresh_failed",
                "test trust refresh failed",
            ))
        } else {
            Ok(())
        }
    }
}

fn write_certificate(root: &PathBuf) -> PathBuf {
    let path = root.join("networkcore-ca.crt");
    fs::write(
        &path,
        "-----BEGIN CERTIFICATE-----\npublic-ca\n-----END CERTIFICATE-----\n",
    )
    .expect("certificate fixture should be written");
    path
}

#[test]
fn trust_apply_refreshes_and_rollback_restores_snapshot() {
    let root = fixture_root();
    let certificate_path = write_certificate(&root);
    let trust_file_path = root.join("anchors/networkcore-ca.crt");
    fs::create_dir_all(trust_file_path.parent().unwrap()).expect("trust directory should exist");
    fs::write(&trust_file_path, "previous trust\n").expect("previous trust should be written");
    let snapshot_path = root.join("state/networkcore-trust.snapshot.json");
    fs::create_dir_all(snapshot_path.parent().unwrap()).expect("snapshot directory should exist");
    let runner = RecordingRefreshRunner::default();

    let report = apply_linux_trust(
        &runner,
        &LinuxTrustApplyRequest {
            certificate_path,
            trust_file_path: trust_file_path.clone(),
            snapshot_path: snapshot_path.clone(),
            confirmed: true,
        },
    )
    .expect("confirmed trust apply should succeed");
    assert!(report.verified);
    assert!(report.refreshed);
    assert_eq!(*runner.calls.borrow(), 1);
    assert!(fs::read_to_string(&trust_file_path)
        .unwrap()
        .contains("BEGIN CERTIFICATE"));

    let rollback = rollback_linux_trust(
        &runner,
        &LinuxTrustRollbackRequest {
            trust_file_path,
            snapshot_path,
            confirmed: true,
        },
    )
    .expect("confirmed trust rollback should succeed");
    assert!(rollback.restored_previous_file);
    assert!(rollback.snapshot_retained);
    assert_eq!(
        fs::read_to_string(root.join("anchors/networkcore-ca.crt")).unwrap(),
        "previous trust\n"
    );
    assert_eq!(*runner.calls.borrow(), 2);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn trust_rollback_rejects_external_changes() {
    let root = fixture_root();
    let certificate_path = write_certificate(&root);
    let trust_file_path = root.join("networkcore-ca.crt");
    let snapshot_path = root.join("networkcore-trust.snapshot.json");
    let runner = RecordingRefreshRunner::default();
    apply_linux_trust(
        &runner,
        &LinuxTrustApplyRequest {
            certificate_path,
            trust_file_path: trust_file_path.clone(),
            snapshot_path: snapshot_path.clone(),
            confirmed: true,
        },
    )
    .expect("trust apply should succeed");
    fs::write(&trust_file_path, "external change\n").expect("external trust change should write");
    let error = rollback_linux_trust(
        &runner,
        &LinuxTrustRollbackRequest {
            trust_file_path,
            snapshot_path,
            confirmed: true,
        },
    )
    .expect_err("external trust change must block rollback");
    assert_eq!(error.code, LINUX_TRUST_CONFLICT_CODE);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn trust_refresh_failure_restores_previous_file_and_requires_confirmation() {
    let root = fixture_root();
    let certificate_path = write_certificate(&root);
    let trust_file_path = root.join("networkcore-ca.crt");
    fs::write(&trust_file_path, "previous trust\n").expect("previous trust should write");
    let snapshot_path = root.join("networkcore-trust.snapshot.json");
    let runner = RecordingRefreshRunner {
        failure: true,
        ..Default::default()
    };
    let error = apply_linux_trust(
        &runner,
        &LinuxTrustApplyRequest {
            certificate_path: certificate_path.clone(),
            trust_file_path: trust_file_path.clone(),
            snapshot_path: snapshot_path.clone(),
            confirmed: false,
        },
    )
    .expect_err("trust mutation must require confirmation");
    assert_eq!(error.code, LINUX_TRUST_CONFIRMATION_REQUIRED_CODE);

    let error = apply_linux_trust(
        &runner,
        &LinuxTrustApplyRequest {
            certificate_path,
            trust_file_path: trust_file_path.clone(),
            snapshot_path,
            confirmed: true,
        },
    )
    .expect_err("refresh failure should fail trust apply");
    assert_eq!(error.code, LINUX_TRUST_REFRESH_FAILED_CODE);
    assert_eq!(
        fs::read_to_string(trust_file_path).unwrap(),
        "previous trust\n"
    );
    let _ = fs::remove_dir_all(root);
}
