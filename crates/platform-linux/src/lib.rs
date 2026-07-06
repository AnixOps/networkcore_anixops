//! Linux platform capability adapter contracts.
//!
//! This crate intentionally starts with read-only mapping primitives and a static
//! service double. Real Linux probing will be added behind this boundary after
//! the CI and release contracts are in place.

use control_domain::{
    CertificateTrustState, Diagnostic, DiagnosticSeverity, DomainResult, MitmCertificateStatus,
    OperatingSystem, PlatformCapabilityService, PlatformCapabilityStatus, PlatformFeatureState,
};

pub const SOURCE_TUNNEL: &str = "platform.tunnel";
pub const SOURCE_PERMISSION: &str = "platform.permission";
pub const SOURCE_DNS: &str = "platform.dns";
pub const SOURCE_SERVICE: &str = "platform.service";
pub const SOURCE_MITM_CERTIFICATE: &str = "platform.mitm_certificate";

pub const TUN_DEVICE_MISSING_CODE: &str = "platform.linux.tun.device_missing";
pub const TUN_PERMISSION_DENIED_CODE: &str = "platform.linux.tun.permission_denied";
pub const PERMISSION_ELEVATION_REQUIRED_CODE: &str = "platform.linux.permission.elevation_required";
pub const DNS_MANAGER_UNKNOWN_CODE: &str = "platform.linux.dns.manager_unknown";
pub const SERVICE_MANAGER_UNKNOWN_CODE: &str = "platform.linux.service.manager_unknown";
pub const MITM_CERTIFICATE_NOT_INSTALLED_CODE: &str =
    "platform.linux.mitm_certificate.not_installed";
pub const MITM_CERTIFICATE_INSTALLED_UNTRUSTED_CODE: &str =
    "platform.linux.mitm_certificate.installed_untrusted";
pub const MITM_CERTIFICATE_TRUSTED_CODE: &str = "platform.linux.mitm_certificate.trusted";
pub const MITM_CERTIFICATE_REVOKED_CODE: &str = "platform.linux.mitm_certificate.revoked";
pub const MITM_CERTIFICATE_UNKNOWN_CODE: &str = "platform.linux.mitm_certificate.unknown";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxFeatureProbe {
    pub state: PlatformFeatureState,
    pub diagnostics: Vec<Diagnostic>,
}

impl LinuxFeatureProbe {
    pub fn available() -> Self {
        Self {
            state: PlatformFeatureState::available(),
            diagnostics: Vec::new(),
        }
    }

    pub fn unavailable(reason: impl Into<String>, diagnostic: Diagnostic) -> Self {
        Self {
            state: PlatformFeatureState::unavailable(reason),
            diagnostics: vec![diagnostic],
        }
    }

    pub fn unknown(diagnostic: Diagnostic) -> Self {
        Self {
            state: PlatformFeatureState::unknown(),
            diagnostics: vec![diagnostic],
        }
    }

    pub fn with_diagnostic(mut self, diagnostic: Diagnostic) -> Self {
        self.diagnostics.push(diagnostic);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxCertificateProbe {
    pub state: CertificateTrustState,
    pub subject: Option<String>,
    pub fingerprint_sha256: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
}

impl LinuxCertificateProbe {
    pub fn new(state: CertificateTrustState) -> Self {
        Self {
            state,
            subject: None,
            fingerprint_sha256: None,
            diagnostics: Vec::new(),
        }
    }

    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    pub fn with_fingerprint_sha256(mut self, fingerprint_sha256: impl Into<String>) -> Self {
        self.fingerprint_sha256 = Some(fingerprint_sha256.into());
        self
    }

    pub fn with_diagnostic(mut self, diagnostic: Diagnostic) -> Self {
        self.diagnostics.push(diagnostic);
        self
    }

    pub fn into_status(self) -> MitmCertificateStatus {
        MitmCertificateStatus {
            state: self.state,
            subject: self.subject,
            fingerprint_sha256: self.fingerprint_sha256,
            diagnostics: self.diagnostics,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxPlatformSnapshot {
    pub tunnel: LinuxFeatureProbe,
    pub mitm: LinuxFeatureProbe,
    pub embedded_runtime: LinuxFeatureProbe,
    pub remote_script_execution: LinuxFeatureProbe,
    pub mitm_certificate: LinuxCertificateProbe,
    pub diagnostics: Vec<Diagnostic>,
}

impl LinuxPlatformSnapshot {
    pub fn available_for_tests() -> Self {
        Self {
            tunnel: LinuxFeatureProbe::available(),
            mitm: LinuxFeatureProbe::available(),
            embedded_runtime: LinuxFeatureProbe::available(),
            remote_script_execution: LinuxFeatureProbe::available(),
            mitm_certificate: LinuxCertificateProbe::new(CertificateTrustState::Trusted),
            diagnostics: Vec::new(),
        }
    }

    pub fn with_diagnostic(mut self, diagnostic: Diagnostic) -> Self {
        self.diagnostics.push(diagnostic);
        self
    }

    pub fn into_status(self) -> PlatformCapabilityStatus {
        let LinuxPlatformSnapshot {
            tunnel,
            mitm,
            embedded_runtime,
            remote_script_execution,
            mitm_certificate,
            diagnostics: snapshot_diagnostics,
        } = self;

        let LinuxFeatureProbe {
            state: tunnel,
            diagnostics: tunnel_diagnostics,
        } = tunnel;
        let LinuxFeatureProbe {
            state: mitm,
            diagnostics: mitm_diagnostics,
        } = mitm;
        let LinuxFeatureProbe {
            state: embedded_runtime,
            diagnostics: embedded_runtime_diagnostics,
        } = embedded_runtime;
        let LinuxFeatureProbe {
            state: remote_script_execution,
            diagnostics: remote_script_execution_diagnostics,
        } = remote_script_execution;

        let mut diagnostics = tunnel_diagnostics;
        diagnostics.extend(mitm_diagnostics);
        diagnostics.extend(embedded_runtime_diagnostics);
        diagnostics.extend(remote_script_execution_diagnostics);
        diagnostics.extend(snapshot_diagnostics);

        PlatformCapabilityStatus {
            os: OperatingSystem::Linux,
            tunnel,
            mitm,
            embedded_runtime,
            remote_script_execution,
            mitm_certificate: mitm_certificate.into_status(),
            diagnostics,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticLinuxPlatformCapabilityService {
    snapshot: LinuxPlatformSnapshot,
}

impl StaticLinuxPlatformCapabilityService {
    pub fn new(snapshot: LinuxPlatformSnapshot) -> Self {
        Self { snapshot }
    }

    pub fn snapshot(&self) -> &LinuxPlatformSnapshot {
        &self.snapshot
    }
}

impl PlatformCapabilityService for StaticLinuxPlatformCapabilityService {
    fn status(&self) -> DomainResult<PlatformCapabilityStatus> {
        Ok(self.snapshot.clone().into_status())
    }
}

pub fn linux_diagnostic(
    severity: DiagnosticSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
    source: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(severity, code, message, Some(source.into()))
}
