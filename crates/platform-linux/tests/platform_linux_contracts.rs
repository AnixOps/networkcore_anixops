use control_domain::{
    CertificateTrustState, Diagnostic, DiagnosticSeverity, OperatingSystem,
    PlatformCapabilityService,
};
use platform_linux::{
    linux_diagnostic, parse_linux_proc_status, LinuxCertificateProbe, LinuxDnsManagerState,
    LinuxFeatureProbe, LinuxPlatformSnapshot, LinuxPrivilegeProbe, LinuxReadOnlyProbe,
    LinuxReadOnlyProbeSnapshot, LinuxServiceManagerState, LinuxTunDeviceState,
    ReadOnlyLinuxPlatformCapabilityService, StaticLinuxPlatformCapabilityService,
    DNS_MANAGER_DETECTED_CODE, DNS_MANAGER_UNKNOWN_CODE, DNS_MUTATION_NOT_SUPPORTED_CODE,
    MITM_CERTIFICATE_INSTALLED_UNTRUSTED_CODE, MITM_CERTIFICATE_NOT_INSTALLED_CODE,
    MITM_CERTIFICATE_REVOKED_CODE, MITM_CERTIFICATE_TRUSTED_CODE, MITM_CERTIFICATE_UNKNOWN_CODE,
    PERMISSION_CAPABILITY_MISSING_CODE, PERMISSION_ELEVATION_REQUIRED_CODE,
    PERMISSION_NOT_ROOT_CODE, PERMISSION_PROBE_FAILED_CODE, SERVICE_MANAGER_UNKNOWN_CODE,
    SERVICE_MUTATION_NOT_SUPPORTED_CODE, SERVICE_SYSTEMD_DETECTED_CODE, SOURCE_DNS,
    SOURCE_MITM_CERTIFICATE, SOURCE_PERMISSION, SOURCE_SERVICE, SOURCE_TUNNEL,
    TUN_DEVICE_MISSING_CODE, TUN_PERMISSION_DENIED_CODE, TUN_PROBE_UNKNOWN_CODE,
};

#[test]
fn available_snapshot_maps_to_linux_platform_status() {
    let service =
        StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot::available_for_tests());

    let status = service.status().expect("static linux status");

    assert_eq!(status.os, OperatingSystem::Linux);
    assert!(status.tunnel.is_available());
    assert!(status.mitm.is_available());
    assert!(status.embedded_runtime.is_available());
    assert!(status.remote_script_execution.is_available());
    assert!(status.mitm_available());
    assert_eq!(
        status.mitm_certificate.state,
        CertificateTrustState::Trusted
    );
    assert!(status.diagnostics.is_empty());
    assert!(status.mitm_certificate.diagnostics.is_empty());
}

#[test]
fn tun_missing_maps_to_unavailable_with_stable_diagnostic() {
    let service = StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot {
        tunnel: LinuxFeatureProbe::unavailable(
            "linux TUN device is missing",
            linux_diagnostic(
                DiagnosticSeverity::Error,
                TUN_DEVICE_MISSING_CODE,
                "/dev/net/tun is not available",
                SOURCE_TUNNEL,
            ),
        ),
        ..LinuxPlatformSnapshot::available_for_tests()
    });

    let status = service.status().expect("static linux status");

    assert!(!status.tunnel.is_available());
    assert_eq!(
        status.tunnel.denial_reason(),
        Some("linux TUN device is missing")
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Error,
        TUN_DEVICE_MISSING_CODE,
        SOURCE_TUNNEL,
    );
}

#[test]
fn permission_denied_preserves_linux_permission_diagnostics() {
    let service = StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot {
        tunnel: LinuxFeatureProbe::unavailable(
            "linux TUN permissions are insufficient",
            linux_diagnostic(
                DiagnosticSeverity::Error,
                TUN_PERMISSION_DENIED_CODE,
                "current process cannot open the linux TUN device",
                SOURCE_TUNNEL,
            ),
        ),
        diagnostics: vec![linux_diagnostic(
            DiagnosticSeverity::Error,
            PERMISSION_ELEVATION_REQUIRED_CODE,
            "elevated permissions are required for linux network setup",
            SOURCE_PERMISSION,
        )],
        ..LinuxPlatformSnapshot::available_for_tests()
    });

    let status = service.status().expect("static linux status");

    assert!(!status.tunnel.is_available());
    assert_eq!(
        status.tunnel.denial_reason(),
        Some("linux TUN permissions are insufficient")
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Error,
        TUN_PERMISSION_DENIED_CODE,
        SOURCE_TUNNEL,
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Error,
        PERMISSION_ELEVATION_REQUIRED_CODE,
        SOURCE_PERMISSION,
    );
}

#[test]
fn dns_and_service_unknown_are_reported_as_non_blocking_diagnostics() {
    let service = StaticLinuxPlatformCapabilityService::new(
        LinuxPlatformSnapshot::available_for_tests()
            .with_diagnostic(linux_diagnostic(
                DiagnosticSeverity::Warning,
                DNS_MANAGER_UNKNOWN_CODE,
                "linux DNS manager could not be identified",
                SOURCE_DNS,
            ))
            .with_diagnostic(linux_diagnostic(
                DiagnosticSeverity::Warning,
                SERVICE_MANAGER_UNKNOWN_CODE,
                "linux service manager could not be identified",
                SOURCE_SERVICE,
            )),
    );

    let status = service.status().expect("static linux status");

    assert!(status.tunnel.is_available());
    assert!(status.mitm_available());
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Warning,
        DNS_MANAGER_UNKNOWN_CODE,
        SOURCE_DNS,
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Warning,
        SERVICE_MANAGER_UNKNOWN_CODE,
        SOURCE_SERVICE,
    );
}

#[test]
fn certificate_state_matrix_maps_to_domain_certificate_status() {
    let cases = [
        (
            CertificateTrustState::NotInstalled,
            MITM_CERTIFICATE_NOT_INSTALLED_CODE,
            false,
        ),
        (
            CertificateTrustState::InstalledUntrusted,
            MITM_CERTIFICATE_INSTALLED_UNTRUSTED_CODE,
            false,
        ),
        (
            CertificateTrustState::Trusted,
            MITM_CERTIFICATE_TRUSTED_CODE,
            true,
        ),
        (
            CertificateTrustState::Revoked,
            MITM_CERTIFICATE_REVOKED_CODE,
            false,
        ),
        (
            CertificateTrustState::Unknown,
            MITM_CERTIFICATE_UNKNOWN_CODE,
            false,
        ),
    ];

    for (state, code, mitm_available) in cases {
        let service = StaticLinuxPlatformCapabilityService::new(LinuxPlatformSnapshot {
            mitm_certificate: LinuxCertificateProbe::new(state)
                .with_subject("CN=NetworkCore Test Root")
                .with_fingerprint_sha256("00:11:22")
                .with_diagnostic(linux_diagnostic(
                    certificate_severity(state),
                    code,
                    "linux MITM certificate state mapped from platform probe",
                    SOURCE_MITM_CERTIFICATE,
                )),
            ..LinuxPlatformSnapshot::available_for_tests()
        });

        let status = service.status().expect("static linux status");

        assert_eq!(status.mitm_certificate.state, state);
        assert_eq!(
            status.mitm_certificate.subject.as_deref(),
            Some("CN=NetworkCore Test Root")
        );
        assert_eq!(
            status.mitm_certificate.fingerprint_sha256.as_deref(),
            Some("00:11:22")
        );
        assert_eq!(status.mitm_available(), mitm_available);
        assert_diagnostic(
            &status.mitm_certificate.diagnostics,
            certificate_severity(state),
            code,
            SOURCE_MITM_CERTIFICATE,
        );
    }
}

#[test]
fn read_only_probe_maps_detected_host_facts_without_mutating_system_state() {
    let service = ReadOnlyLinuxPlatformCapabilityService::new(MemoryLinuxReadOnlyProbe::new(
        LinuxReadOnlyProbeSnapshot {
            tun_device: LinuxTunDeviceState::Available,
            privileges: LinuxPrivilegeProbe {
                effective_uid: Some(0),
                cap_net_admin: Some(true),
            },
            dns_manager: LinuxDnsManagerState::SystemdResolved,
            service_manager: LinuxServiceManagerState::Systemd,
            mitm_certificate: LinuxCertificateProbe::new(CertificateTrustState::NotInstalled)
                .with_diagnostic(linux_diagnostic(
                    DiagnosticSeverity::Warning,
                    MITM_CERTIFICATE_NOT_INSTALLED_CODE,
                    "linux MITM certificate is not installed",
                    SOURCE_MITM_CERTIFICATE,
                )),
        },
    ));

    let status = service.status().expect("read-only linux status");

    assert!(status.tunnel.is_available());
    assert!(status.embedded_runtime.is_available());
    assert!(status.remote_script_execution.is_available());
    assert!(!status.mitm_available());
    assert_eq!(
        status.mitm_certificate.state,
        CertificateTrustState::NotInstalled
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Info,
        DNS_MANAGER_DETECTED_CODE,
        SOURCE_DNS,
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Info,
        DNS_MUTATION_NOT_SUPPORTED_CODE,
        SOURCE_DNS,
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Info,
        SERVICE_SYSTEMD_DETECTED_CODE,
        SOURCE_SERVICE,
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Info,
        SERVICE_MUTATION_NOT_SUPPORTED_CODE,
        SOURCE_SERVICE,
    );
}

#[test]
fn read_only_probe_denies_tunnel_when_cap_net_admin_is_missing() {
    let service = ReadOnlyLinuxPlatformCapabilityService::new(MemoryLinuxReadOnlyProbe::new(
        LinuxReadOnlyProbeSnapshot {
            tun_device: LinuxTunDeviceState::Available,
            privileges: LinuxPrivilegeProbe {
                effective_uid: Some(1000),
                cap_net_admin: Some(false),
            },
            dns_manager: LinuxDnsManagerState::Unknown,
            service_manager: LinuxServiceManagerState::Unknown,
            mitm_certificate: LinuxCertificateProbe::new(CertificateTrustState::NotInstalled),
        },
    ));

    let status = service.status().expect("read-only linux status");

    assert!(!status.tunnel.is_available());
    assert_eq!(
        status.tunnel.denial_reason(),
        Some("linux CAP_NET_ADMIN is missing")
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Info,
        PERMISSION_NOT_ROOT_CODE,
        SOURCE_PERMISSION,
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Warning,
        PERMISSION_CAPABILITY_MISSING_CODE,
        SOURCE_PERMISSION,
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Error,
        PERMISSION_ELEVATION_REQUIRED_CODE,
        SOURCE_PERMISSION,
    );
}

#[test]
fn read_only_probe_preserves_unknown_tun_and_permission_diagnostics() {
    let service = ReadOnlyLinuxPlatformCapabilityService::new(MemoryLinuxReadOnlyProbe::new(
        LinuxReadOnlyProbeSnapshot {
            tun_device: LinuxTunDeviceState::Unknown,
            privileges: LinuxPrivilegeProbe {
                effective_uid: None,
                cap_net_admin: None,
            },
            dns_manager: LinuxDnsManagerState::Unknown,
            service_manager: LinuxServiceManagerState::Unknown,
            mitm_certificate: LinuxCertificateProbe::new(CertificateTrustState::Unknown),
        },
    ));

    let status = service.status().expect("read-only linux status");

    assert!(!status.tunnel.is_available());
    assert_eq!(
        status.tunnel.denial_reason(),
        Some("platform feature availability is unknown")
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Warning,
        TUN_PROBE_UNKNOWN_CODE,
        SOURCE_TUNNEL,
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Warning,
        PERMISSION_PROBE_FAILED_CODE,
        SOURCE_PERMISSION,
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Warning,
        DNS_MANAGER_UNKNOWN_CODE,
        SOURCE_DNS,
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Warning,
        SERVICE_MANAGER_UNKNOWN_CODE,
        SOURCE_SERVICE,
    );
}

#[test]
fn proc_status_parser_extracts_effective_uid_and_cap_net_admin() {
    let privileges = parse_linux_proc_status(
        "Name:\tnetworkcore\nUid:\t1000\t1001\t1000\t1000\nCapEff:\t0000000000001000\n",
    );

    assert_eq!(privileges.effective_uid, Some(1001));
    assert_eq!(privileges.cap_net_admin, Some(true));

    let without_capability = parse_linux_proc_status(
        "Name:\tnetworkcore\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\n",
    );

    assert_eq!(without_capability.effective_uid, Some(1000));
    assert_eq!(without_capability.cap_net_admin, Some(false));
}

fn certificate_severity(state: CertificateTrustState) -> DiagnosticSeverity {
    match state {
        CertificateTrustState::Trusted => DiagnosticSeverity::Info,
        CertificateTrustState::Revoked => DiagnosticSeverity::Error,
        CertificateTrustState::NotInstalled
        | CertificateTrustState::InstalledUntrusted
        | CertificateTrustState::Unknown => DiagnosticSeverity::Warning,
    }
}

fn assert_diagnostic(
    diagnostics: &[Diagnostic],
    severity: DiagnosticSeverity,
    code: &str,
    source: &str,
) {
    assert!(
        diagnostics.iter().any(|diagnostic| {
            diagnostic.severity == severity
                && diagnostic.code == code
                && diagnostic.source.as_deref() == Some(source)
        }),
        "missing diagnostic {code} from {source}: {diagnostics:?}"
    );
}

#[derive(Debug, Clone)]
struct MemoryLinuxReadOnlyProbe {
    snapshot: LinuxReadOnlyProbeSnapshot,
}

impl MemoryLinuxReadOnlyProbe {
    fn new(snapshot: LinuxReadOnlyProbeSnapshot) -> Self {
        Self { snapshot }
    }
}

impl LinuxReadOnlyProbe for MemoryLinuxReadOnlyProbe {
    fn snapshot(&self) -> LinuxReadOnlyProbeSnapshot {
        self.snapshot.clone()
    }
}
