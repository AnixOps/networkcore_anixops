//! Linux platform capability adapter contracts.
//!
//! This crate exposes read-only mapping primitives, a static service double, and
//! a host probe service that only inspects Linux capability facts. It must not
//! mutate networking, DNS, certificates, services, or process privileges.

use control_domain::{
    CertificateTrustState, Diagnostic, DiagnosticSeverity, DomainResult, MitmCertificateStatus,
    OperatingSystem, PlatformCapabilityService, PlatformCapabilityStatus, PlatformFeatureState,
};
use std::fs;
use std::path::{Path, PathBuf};

pub const SOURCE_TUNNEL: &str = "platform.tunnel";
pub const SOURCE_PERMISSION: &str = "platform.permission";
pub const SOURCE_DNS: &str = "platform.dns";
pub const SOURCE_SERVICE: &str = "platform.service";
pub const SOURCE_MITM_CERTIFICATE: &str = "platform.mitm_certificate";

pub const TUN_DEVICE_MISSING_CODE: &str = "platform.linux.tun.device_missing";
pub const TUN_PERMISSION_DENIED_CODE: &str = "platform.linux.tun.permission_denied";
pub const TUN_PROBE_UNKNOWN_CODE: &str = "platform.linux.tun.probe_unknown";
pub const PERMISSION_NOT_ROOT_CODE: &str = "platform.linux.permission.not_root";
pub const PERMISSION_CAPABILITY_MISSING_CODE: &str = "platform.linux.permission.capability_missing";
pub const PERMISSION_ELEVATION_REQUIRED_CODE: &str = "platform.linux.permission.elevation_required";
pub const PERMISSION_PROBE_FAILED_CODE: &str = "platform.linux.permission.probe_failed";
pub const DNS_MANAGER_DETECTED_CODE: &str = "platform.linux.dns.manager_detected";
pub const DNS_MANAGER_UNKNOWN_CODE: &str = "platform.linux.dns.manager_unknown";
pub const DNS_MUTATION_NOT_SUPPORTED_CODE: &str = "platform.linux.dns.mutation_not_supported";
pub const SERVICE_SYSTEMD_DETECTED_CODE: &str = "platform.linux.service.systemd_detected";
pub const SERVICE_MANAGER_UNKNOWN_CODE: &str = "platform.linux.service.manager_unknown";
pub const SERVICE_UNSUPPORTED_ENVIRONMENT_CODE: &str =
    "platform.linux.service.unsupported_environment";
pub const SERVICE_MUTATION_NOT_SUPPORTED_CODE: &str =
    "platform.linux.service.mutation_not_supported";
pub const MITM_CERTIFICATE_NOT_INSTALLED_CODE: &str =
    "platform.linux.mitm_certificate.not_installed";
pub const MITM_CERTIFICATE_INSTALLED_UNTRUSTED_CODE: &str =
    "platform.linux.mitm_certificate.installed_untrusted";
pub const MITM_CERTIFICATE_TRUSTED_CODE: &str = "platform.linux.mitm_certificate.trusted";
pub const MITM_CERTIFICATE_REVOKED_CODE: &str = "platform.linux.mitm_certificate.revoked";
pub const MITM_CERTIFICATE_UNKNOWN_CODE: &str = "platform.linux.mitm_certificate.unknown";

const CAP_NET_ADMIN_BIT: u32 = 12;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxTunDeviceState {
    Available,
    Missing,
    PermissionDenied,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxDnsManagerState {
    SystemdResolved,
    NetworkManager,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxServiceManagerState {
    Systemd,
    Unsupported,
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinuxPrivilegeProbe {
    pub effective_uid: Option<u32>,
    pub cap_net_admin: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxReadOnlyProbeSnapshot {
    pub tun_device: LinuxTunDeviceState,
    pub privileges: LinuxPrivilegeProbe,
    pub dns_manager: LinuxDnsManagerState,
    pub service_manager: LinuxServiceManagerState,
    pub mitm_certificate: LinuxCertificateProbe,
}

impl LinuxReadOnlyProbeSnapshot {
    pub fn unknown() -> Self {
        Self {
            tun_device: LinuxTunDeviceState::Unknown,
            privileges: LinuxPrivilegeProbe::default(),
            dns_manager: LinuxDnsManagerState::Unknown,
            service_manager: LinuxServiceManagerState::Unknown,
            mitm_certificate: LinuxCertificateProbe::new(CertificateTrustState::NotInstalled)
                .with_diagnostic(linux_diagnostic(
                    DiagnosticSeverity::Warning,
                    MITM_CERTIFICATE_NOT_INSTALLED_CODE,
                    "linux MITM certificate is not installed",
                    SOURCE_MITM_CERTIFICATE,
                )),
        }
    }
}

pub trait LinuxReadOnlyProbe {
    fn snapshot(&self) -> LinuxReadOnlyProbeSnapshot;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadOnlyLinuxPlatformCapabilityService<P> {
    probe: P,
}

impl<P> ReadOnlyLinuxPlatformCapabilityService<P> {
    pub fn new(probe: P) -> Self {
        Self { probe }
    }

    pub fn probe(&self) -> &P {
        &self.probe
    }
}

impl<P> PlatformCapabilityService for ReadOnlyLinuxPlatformCapabilityService<P>
where
    P: LinuxReadOnlyProbe,
{
    fn status(&self) -> DomainResult<PlatformCapabilityStatus> {
        Ok(read_only_snapshot_to_platform(self.probe.snapshot()).into_status())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLinuxReadOnlyProbe {
    tun_device_path: PathBuf,
    proc_status_path: PathBuf,
    resolv_conf_path: PathBuf,
    systemd_runtime_path: PathBuf,
    network_manager_runtime_path: PathBuf,
    container_marker_path: PathBuf,
    mitm_certificate: LinuxCertificateProbe,
}

impl HostLinuxReadOnlyProbe {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for HostLinuxReadOnlyProbe {
    fn default() -> Self {
        Self {
            tun_device_path: PathBuf::from("/dev/net/tun"),
            proc_status_path: PathBuf::from("/proc/self/status"),
            resolv_conf_path: PathBuf::from("/etc/resolv.conf"),
            systemd_runtime_path: PathBuf::from("/run/systemd/system"),
            network_manager_runtime_path: PathBuf::from("/run/NetworkManager"),
            container_marker_path: PathBuf::from("/.dockerenv"),
            mitm_certificate: LinuxCertificateProbe::new(CertificateTrustState::NotInstalled)
                .with_diagnostic(linux_diagnostic(
                    DiagnosticSeverity::Warning,
                    MITM_CERTIFICATE_NOT_INSTALLED_CODE,
                    "linux MITM certificate is not installed",
                    SOURCE_MITM_CERTIFICATE,
                )),
        }
    }
}

impl LinuxReadOnlyProbe for HostLinuxReadOnlyProbe {
    fn snapshot(&self) -> LinuxReadOnlyProbeSnapshot {
        LinuxReadOnlyProbeSnapshot {
            tun_device: probe_tun_device(&self.tun_device_path),
            privileges: probe_process_privileges(&self.proc_status_path),
            dns_manager: probe_dns_manager(
                &self.resolv_conf_path,
                &self.network_manager_runtime_path,
            ),
            service_manager: probe_service_manager(
                &self.systemd_runtime_path,
                &self.container_marker_path,
            ),
            mitm_certificate: self.mitm_certificate.clone(),
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

pub fn parse_linux_proc_status(status: &str) -> LinuxPrivilegeProbe {
    let mut effective_uid = None;
    let mut cap_net_admin = None;

    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Uid:") {
            effective_uid = value
                .split_whitespace()
                .nth(1)
                .and_then(|uid| uid.parse::<u32>().ok());
        }

        if let Some(value) = line.strip_prefix("CapEff:") {
            cap_net_admin = value
                .split_whitespace()
                .next()
                .and_then(|hex| u128::from_str_radix(hex, 16).ok())
                .map(|capabilities| capabilities & (1_u128 << CAP_NET_ADMIN_BIT) != 0);
        }
    }

    LinuxPrivilegeProbe {
        effective_uid,
        cap_net_admin,
    }
}

fn read_only_snapshot_to_platform(snapshot: LinuxReadOnlyProbeSnapshot) -> LinuxPlatformSnapshot {
    let LinuxReadOnlyProbeSnapshot {
        tun_device,
        privileges,
        dns_manager,
        service_manager,
        mitm_certificate,
    } = snapshot;

    let mut diagnostics = Vec::new();
    let mut tunnel = map_tun_device(tun_device);

    if let Some(uid) = privileges.effective_uid {
        if uid != 0 {
            diagnostics.push(linux_diagnostic(
                DiagnosticSeverity::Info,
                PERMISSION_NOT_ROOT_CODE,
                "current linux process is not running as root",
                SOURCE_PERMISSION,
            ));
        }
    }

    match privileges.cap_net_admin {
        Some(true) => {}
        Some(false) => {
            diagnostics.push(linux_diagnostic(
                DiagnosticSeverity::Warning,
                PERMISSION_CAPABILITY_MISSING_CODE,
                "linux CAP_NET_ADMIN is not available to the current process",
                SOURCE_PERMISSION,
            ));
            if tunnel.state.is_available() {
                tunnel = LinuxFeatureProbe::unavailable(
                    "linux CAP_NET_ADMIN is missing",
                    linux_diagnostic(
                        DiagnosticSeverity::Error,
                        PERMISSION_ELEVATION_REQUIRED_CODE,
                        "linux tunnel setup requires CAP_NET_ADMIN or equivalent authorization",
                        SOURCE_PERMISSION,
                    ),
                );
            }
        }
        None => diagnostics.push(linux_diagnostic(
            DiagnosticSeverity::Warning,
            PERMISSION_PROBE_FAILED_CODE,
            "linux process capability state could not be determined",
            SOURCE_PERMISSION,
        )),
    }

    diagnostics.extend(map_dns_manager(dns_manager));
    diagnostics.extend(map_service_manager(service_manager));

    LinuxPlatformSnapshot {
        tunnel,
        mitm: LinuxFeatureProbe::available(),
        embedded_runtime: LinuxFeatureProbe::available(),
        remote_script_execution: LinuxFeatureProbe::available(),
        mitm_certificate,
        diagnostics,
    }
}

fn map_tun_device(state: LinuxTunDeviceState) -> LinuxFeatureProbe {
    match state {
        LinuxTunDeviceState::Available => LinuxFeatureProbe::available(),
        LinuxTunDeviceState::Missing => LinuxFeatureProbe::unavailable(
            "linux TUN device is missing",
            linux_diagnostic(
                DiagnosticSeverity::Error,
                TUN_DEVICE_MISSING_CODE,
                "/dev/net/tun is not available",
                SOURCE_TUNNEL,
            ),
        ),
        LinuxTunDeviceState::PermissionDenied => LinuxFeatureProbe::unavailable(
            "linux TUN permissions are insufficient",
            linux_diagnostic(
                DiagnosticSeverity::Error,
                TUN_PERMISSION_DENIED_CODE,
                "current process cannot open the linux TUN device",
                SOURCE_TUNNEL,
            ),
        ),
        LinuxTunDeviceState::Unknown => LinuxFeatureProbe::unknown(linux_diagnostic(
            DiagnosticSeverity::Warning,
            TUN_PROBE_UNKNOWN_CODE,
            "linux TUN device state could not be determined",
            SOURCE_TUNNEL,
        )),
    }
}

fn map_dns_manager(state: LinuxDnsManagerState) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    match state {
        LinuxDnsManagerState::SystemdResolved => diagnostics.push(linux_diagnostic(
            DiagnosticSeverity::Info,
            DNS_MANAGER_DETECTED_CODE,
            "linux DNS manager detected: systemd-resolved",
            SOURCE_DNS,
        )),
        LinuxDnsManagerState::NetworkManager => diagnostics.push(linux_diagnostic(
            DiagnosticSeverity::Info,
            DNS_MANAGER_DETECTED_CODE,
            "linux DNS manager detected: NetworkManager",
            SOURCE_DNS,
        )),
        LinuxDnsManagerState::Unknown => diagnostics.push(linux_diagnostic(
            DiagnosticSeverity::Warning,
            DNS_MANAGER_UNKNOWN_CODE,
            "linux DNS manager could not be identified",
            SOURCE_DNS,
        )),
    }
    diagnostics.push(linux_diagnostic(
        DiagnosticSeverity::Info,
        DNS_MUTATION_NOT_SUPPORTED_CODE,
        "linux DNS mutation is not supported by the read-only adapter",
        SOURCE_DNS,
    ));
    diagnostics
}

fn map_service_manager(state: LinuxServiceManagerState) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    match state {
        LinuxServiceManagerState::Systemd => diagnostics.push(linux_diagnostic(
            DiagnosticSeverity::Info,
            SERVICE_SYSTEMD_DETECTED_CODE,
            "linux service manager detected: systemd",
            SOURCE_SERVICE,
        )),
        LinuxServiceManagerState::Unsupported => diagnostics.push(linux_diagnostic(
            DiagnosticSeverity::Warning,
            SERVICE_UNSUPPORTED_ENVIRONMENT_CODE,
            "linux service management is unsupported in the current environment",
            SOURCE_SERVICE,
        )),
        LinuxServiceManagerState::Unknown => diagnostics.push(linux_diagnostic(
            DiagnosticSeverity::Warning,
            SERVICE_MANAGER_UNKNOWN_CODE,
            "linux service manager could not be identified",
            SOURCE_SERVICE,
        )),
    }
    diagnostics.push(linux_diagnostic(
        DiagnosticSeverity::Info,
        SERVICE_MUTATION_NOT_SUPPORTED_CODE,
        "linux service mutation is not supported by the read-only adapter",
        SOURCE_SERVICE,
    ));
    diagnostics
}

#[cfg(target_os = "linux")]
fn probe_tun_device(path: &Path) -> LinuxTunDeviceState {
    match fs::OpenOptions::new().read(true).write(true).open(path) {
        Ok(_) => LinuxTunDeviceState::Available,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => LinuxTunDeviceState::Missing,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            LinuxTunDeviceState::PermissionDenied
        }
        Err(_) => LinuxTunDeviceState::Unknown,
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_tun_device(_path: &Path) -> LinuxTunDeviceState {
    LinuxTunDeviceState::Unknown
}

fn probe_process_privileges(path: &Path) -> LinuxPrivilegeProbe {
    fs::read_to_string(path)
        .map(|status| parse_linux_proc_status(&status))
        .unwrap_or_default()
}

fn probe_dns_manager(resolv_conf_path: &Path, network_manager_path: &Path) -> LinuxDnsManagerState {
    if fs::read_link(resolv_conf_path)
        .map(|target| target.to_string_lossy().contains("systemd"))
        .unwrap_or(false)
    {
        return LinuxDnsManagerState::SystemdResolved;
    }

    if fs::read_to_string(resolv_conf_path)
        .map(|contents| contents.contains("127.0.0.53"))
        .unwrap_or(false)
    {
        return LinuxDnsManagerState::SystemdResolved;
    }

    if network_manager_path.exists() {
        return LinuxDnsManagerState::NetworkManager;
    }

    LinuxDnsManagerState::Unknown
}

fn probe_service_manager(
    systemd_runtime_path: &Path,
    container_marker_path: &Path,
) -> LinuxServiceManagerState {
    if systemd_runtime_path.is_dir() {
        return LinuxServiceManagerState::Systemd;
    }

    if container_marker_path.exists() {
        return LinuxServiceManagerState::Unsupported;
    }

    LinuxServiceManagerState::Unknown
}
