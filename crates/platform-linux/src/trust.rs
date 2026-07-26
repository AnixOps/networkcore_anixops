//! Explicit Ubuntu-style CA trust-file mutation.
//!
//! The caller supplies both the trust-file and rollback snapshot paths. This
//! adapter never discovers a distribution default and refreshes the trust
//! database only after an explicitly confirmed, verified file write.

use control_domain::{DomainError, DomainResult};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const LINUX_TRUST_SCHEMA_VERSION: u32 = 1;
pub const LINUX_TRUST_INVALID_CODE: &str = "platform.linux.trust.invalid";
pub const LINUX_TRUST_CONFIRMATION_REQUIRED_CODE: &str =
    "platform.linux.trust.confirmation_required";
pub const LINUX_TRUST_WRITE_FAILED_CODE: &str = "platform.linux.trust.write_failed";
pub const LINUX_TRUST_REFRESH_FAILED_CODE: &str = "platform.linux.trust.refresh_failed";
pub const LINUX_TRUST_ROLLBACK_FAILED_CODE: &str = "platform.linux.trust.rollback_failed";
pub const LINUX_TRUST_CONFLICT_CODE: &str = "platform.linux.trust.external_change";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxTrustApplyRequest {
    pub certificate_path: PathBuf,
    pub trust_file_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxTrustApplyReport {
    pub certificate_path: PathBuf,
    pub trust_file_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub previous_exists: bool,
    pub verified: bool,
    pub refreshed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxTrustRollbackRequest {
    pub trust_file_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxTrustRollbackReport {
    pub trust_file_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub restored_previous_file: bool,
    pub snapshot_retained: bool,
    pub refreshed: bool,
}

pub trait LinuxTrustRefreshRunner {
    fn refresh(&self) -> DomainResult<()>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandLinuxTrustRefreshRunner;

impl CommandLinuxTrustRefreshRunner {
    pub const fn new() -> Self {
        Self
    }
}

impl LinuxTrustRefreshRunner for CommandLinuxTrustRefreshRunner {
    fn refresh(&self) -> DomainResult<()> {
        let status = Command::new("update-ca-certificates")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| {
                refresh_error(format!("update-ca-certificates could not start: {error}"))
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(refresh_error(format!(
                "update-ca-certificates exited with status {status}"
            )))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LinuxTrustSnapshot {
    schema_version: u32,
    previous_exists: bool,
    previous_contents: String,
    applied_contents: String,
}

pub fn apply_linux_trust<R: LinuxTrustRefreshRunner>(
    runner: &R,
    request: &LinuxTrustApplyRequest,
) -> DomainResult<LinuxTrustApplyReport> {
    validate_paths(
        &request.certificate_path,
        &request.trust_file_path,
        &request.snapshot_path,
    )?;
    if !request.confirmed {
        return Err(DomainError::new(
            LINUX_TRUST_CONFIRMATION_REQUIRED_CODE,
            "linux trust mutation requires explicit confirmation",
        ));
    }
    reject_symlink(&request.certificate_path)?;
    reject_symlink(&request.trust_file_path)?;
    reject_symlink(&request.snapshot_path)?;

    let certificate = fs::read_to_string(&request.certificate_path).map_err(|error| {
        write_error(format!(
            "read CA certificate {}: {error}",
            request.certificate_path.display()
        ))
    })?;
    validate_certificate(&certificate)?;
    if request.snapshot_path.exists() {
        return Err(DomainError::new(
            LINUX_TRUST_WRITE_FAILED_CODE,
            "refusing to overwrite an existing linux trust snapshot",
        ));
    }

    let (previous_exists, previous_contents) = match fs::read_to_string(&request.trust_file_path) {
        Ok(contents) => (true, contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (false, String::new()),
        Err(error) => return Err(write_error(format!("read existing trust file: {error}"))),
    };
    if previous_contents.contains("PRIVATE KEY") {
        return Err(DomainError::new(
            LINUX_TRUST_INVALID_CODE,
            "refusing to snapshot a trust file containing private-key material",
        ));
    }
    let applied_contents = certificate;
    let snapshot = serde_json::to_string_pretty(&LinuxTrustSnapshot {
        schema_version: LINUX_TRUST_SCHEMA_VERSION,
        previous_exists,
        previous_contents: previous_contents.clone(),
        applied_contents: applied_contents.clone(),
    })
    .map_err(|error| write_error(format!("render linux trust snapshot: {error}")))?;
    write_new_file(&request.snapshot_path, snapshot.as_bytes())?;

    if let Err(error) = write_atomic_file(&request.trust_file_path, applied_contents.as_bytes()) {
        let _ = fs::remove_file(&request.snapshot_path);
        return Err(write_error(format!("write linux trust file: {error}")));
    }
    if let Err(error) = verify_contents(&request.trust_file_path, &applied_contents) {
        recover_file(
            &request.trust_file_path,
            previous_exists,
            &previous_contents,
        );
        let _ = fs::remove_file(&request.snapshot_path);
        return Err(error);
    }

    if let Err(error) = runner.refresh() {
        recover_file(
            &request.trust_file_path,
            previous_exists,
            &previous_contents,
        );
        let _ = fs::remove_file(&request.snapshot_path);
        return Err(DomainError::new(
            LINUX_TRUST_REFRESH_FAILED_CODE,
            error.message,
        ));
    }

    Ok(LinuxTrustApplyReport {
        certificate_path: request.certificate_path.clone(),
        trust_file_path: request.trust_file_path.clone(),
        snapshot_path: request.snapshot_path.clone(),
        previous_exists,
        verified: true,
        refreshed: true,
    })
}

pub fn rollback_linux_trust<R: LinuxTrustRefreshRunner>(
    runner: &R,
    request: &LinuxTrustRollbackRequest,
) -> DomainResult<LinuxTrustRollbackReport> {
    validate_rollback_paths(&request.trust_file_path, &request.snapshot_path)?;
    if !request.confirmed {
        return Err(DomainError::new(
            LINUX_TRUST_CONFIRMATION_REQUIRED_CODE,
            "linux trust rollback requires explicit confirmation",
        ));
    }
    reject_symlink(&request.trust_file_path)?;
    reject_symlink(&request.snapshot_path)?;
    let snapshot_contents = fs::read_to_string(&request.snapshot_path)
        .map_err(|error| rollback_error(format!("read linux trust snapshot: {error}")))?;
    let snapshot = serde_json::from_str::<LinuxTrustSnapshot>(&snapshot_contents)
        .map_err(|error| rollback_error(format!("parse linux trust snapshot: {error}")))?;
    if snapshot.schema_version != LINUX_TRUST_SCHEMA_VERSION {
        return Err(rollback_error(
            "linux trust snapshot schema version is unsupported".to_string(),
        ));
    }
    let current = match fs::read_to_string(&request.trust_file_path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(rollback_error(format!(
                "read current linux trust file: {error}"
            )))
        }
    };
    if current != snapshot.applied_contents {
        return Err(DomainError::new(
            LINUX_TRUST_CONFLICT_CODE,
            "linux trust file changed outside NetworkCore; refusing rollback",
        ));
    }

    if snapshot.previous_exists {
        write_atomic_file(
            &request.trust_file_path,
            snapshot.previous_contents.as_bytes(),
        )
        .map_err(|error| rollback_error(format!("restore linux trust file: {error}")))?;
    } else if request.trust_file_path.exists() {
        fs::remove_file(&request.trust_file_path)
            .map_err(|error| rollback_error(format!("remove linux trust file: {error}")))?;
    }
    if let Err(error) = runner.refresh() {
        let _ = write_atomic_file(
            &request.trust_file_path,
            snapshot.applied_contents.as_bytes(),
        );
        return Err(DomainError::new(
            LINUX_TRUST_REFRESH_FAILED_CODE,
            error.message,
        ));
    }

    Ok(LinuxTrustRollbackReport {
        trust_file_path: request.trust_file_path.clone(),
        snapshot_path: request.snapshot_path.clone(),
        restored_previous_file: snapshot.previous_exists,
        snapshot_retained: true,
        refreshed: true,
    })
}

fn validate_paths(certificate: &Path, trust_file: &Path, snapshot: &Path) -> DomainResult<()> {
    if !certificate.is_absolute()
        || !trust_file.is_absolute()
        || !snapshot.is_absolute()
        || certificate == trust_file
        || certificate == snapshot
        || trust_file == snapshot
    {
        return Err(DomainError::new(
            LINUX_TRUST_INVALID_CODE,
            "linux trust requires distinct absolute certificate, trust, and snapshot paths",
        ));
    }
    Ok(())
}

fn validate_rollback_paths(trust_file: &Path, snapshot: &Path) -> DomainResult<()> {
    if !trust_file.is_absolute() || !snapshot.is_absolute() || trust_file == snapshot {
        return Err(DomainError::new(
            LINUX_TRUST_INVALID_CODE,
            "linux trust rollback requires distinct absolute trust and snapshot paths",
        ));
    }
    Ok(())
}

fn validate_certificate(contents: &str) -> DomainResult<()> {
    if !contents.contains("-----BEGIN CERTIFICATE-----")
        || !contents.contains("-----END CERTIFICATE-----")
        || contents.contains("-----BEGIN PRIVATE KEY-----")
    {
        return Err(DomainError::new(
            LINUX_TRUST_INVALID_CODE,
            "linux trust source must contain a public CA certificate PEM and no private key",
        ));
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> DomainResult<()> {
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(DomainError::new(
            LINUX_TRUST_INVALID_CODE,
            format!("refusing to mutate symlink path {}", path.display()),
        ));
    }
    Ok(())
}

fn write_new_file(path: &Path, contents: &[u8]) -> DomainResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| write_error(format!("create {}: {error}", path.display())))?;
    file.write_all(contents)
        .and_then(|_| file.sync_all())
        .map_err(|error| write_error(format!("write {}: {error}", path.display())))
}

fn write_atomic_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension(format!("networkcore-{}.tmp", std::process::id()));
    fs::write(&temporary, contents)?;
    fs::rename(temporary, path)
}

fn verify_contents(path: &Path, expected: &str) -> DomainResult<()> {
    let actual = fs::read_to_string(path)
        .map_err(|error| write_error(format!("verify {}: {error}", path.display())))?;
    if actual != expected {
        return Err(write_error(format!(
            "verified {} did not match requested content",
            path.display()
        )));
    }
    Ok(())
}

fn recover_file(path: &Path, previous_exists: bool, previous_contents: &str) {
    if previous_exists {
        let _ = write_atomic_file(path, previous_contents.as_bytes());
    } else {
        let _ = fs::remove_file(path);
    }
}

fn write_error(message: String) -> DomainError {
    DomainError::new(LINUX_TRUST_WRITE_FAILED_CODE, message)
}

fn rollback_error(message: String) -> DomainError {
    DomainError::new(LINUX_TRUST_ROLLBACK_FAILED_CODE, message)
}

fn refresh_error(message: String) -> DomainError {
    DomainError::new(LINUX_TRUST_REFRESH_FAILED_CODE, message)
}
