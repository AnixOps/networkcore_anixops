use control_domain::{
    CertificateTrustState, Diagnostic, DiagnosticSeverity, OperatingSystem,
    PlatformCapabilityService,
};
use platform_ios::{
    certificate_severity, IosEmbeddedRuntimeProbe, IosMitmCertificateProbe,
    IosNetworkExtensionProbe, IosPlatformSnapshot, IosSharedStorageProbe,
    IosVpnConfigurationState, StaticIosPlatformCapabilityService, APP_GROUP_UNAVAILABLE_CODE,
    EMBEDDED_RUNTIME_AVAILABLE_CODE, EMBEDDED_RUNTIME_MISSING_CODE,
    KEYCHAIN_ACCESS_DENIED_CODE, MITM_CERTIFICATE_INSTALLED_UNTRUSTED_CODE,
    MITM_CERTIFICATE_NOT_INSTALLED_CODE, MITM_CERTIFICATE_REVOKED_CODE,
    MITM_CERTIFICATE_TRUSTED_CODE, MITM_CERTIFICATE_UNKNOWN_CODE,
    NETWORK_EXTENSION_ENTITLEMENT_MISSING_CODE, REMOTE_SCRIPT_EXECUTION_DISABLED_CODE,
    REMOTE_SCRIPT_EXECUTION_DISABLED_REASON, SOURCE_APP_GROUP, SOURCE_EMBEDDED_RUNTIME,
    SOURCE_KEYCHAIN, SOURCE_MITM_CERTIFICATE, SOURCE_NETWORK_EXTENSION,
    SOURCE_REMOTE_SCRIPT_EXECUTION, SOURCE_VPN_CONFIGURATION,
    VPN_CONFIGURATION_AUTHORIZATION_DENIED_CODE, VPN_CONFIGURATION_AUTHORIZATION_REQUIRED_CODE,
    VPN_CONFIGURATION_NOT_SAVED_CODE,
};

#[test]
fn available_snapshot_maps_to_ios_platform_status_with_remote_scripts_disabled() {
    let service =
        StaticIosPlatformCapabilityService::new(IosPlatformSnapshot::available_for_tests());

    let status = service.status().expect("static ios status");

    assert_eq!(status.os, OperatingSystem::Ios);
    assert!(status.tunnel.is_available());
    assert!(status.mitm.is_available());
    assert!(status.embedded_runtime.is_available());
    assert!(!status.remote_script_execution.is_available());
    assert_eq!(
        status.remote_script_execution.denial_reason(),
        Some(REMOTE_SCRIPT_EXECUTION_DISABLED_REASON)
    );
    assert!(status.mitm_available());
    assert_eq!(
        status.mitm_certificate.state,
        CertificateTrustState::Trusted
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Info,
        EMBEDDED_RUNTIME_AVAILABLE_CODE,
        SOURCE_EMBEDDED_RUNTIME,
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Error,
        REMOTE_SCRIPT_EXECUTION_DISABLED_CODE,
        SOURCE_REMOTE_SCRIPT_EXECUTION,
    );
}

#[test]
fn entitlement_missing_denies_tunnel_with_stable_diagnostic() {
    let service = StaticIosPlatformCapabilityService::new(IosPlatformSnapshot {
        network_extension: IosNetworkExtensionProbe::entitlement_missing(),
        ..IosPlatformSnapshot::available_for_tests()
    });

    let status = service.status().expect("static ios status");

    assert!(!status.tunnel.is_available());
    assert_eq!(
        status.tunnel.denial_reason(),
        Some("iOS Network Extension entitlement is missing")
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Error,
        NETWORK_EXTENSION_ENTITLEMENT_MISSING_CODE,
        SOURCE_NETWORK_EXTENSION,
    );
}

#[test]
fn vpn_configuration_states_deny_tunnel_with_stable_diagnostics() {
    let cases = [
        (
            IosVpnConfigurationState::NotSaved,
            DiagnosticSeverity::Warning,
            VPN_CONFIGURATION_NOT_SAVED_CODE,
            "iOS VPN configuration is not saved",
        ),
        (
            IosVpnConfigurationState::AuthorizationRequired,
            DiagnosticSeverity::Warning,
            VPN_CONFIGURATION_AUTHORIZATION_REQUIRED_CODE,
            "iOS VPN authorization is required",
        ),
        (
            IosVpnConfigurationState::AuthorizationDenied,
            DiagnosticSeverity::Error,
            VPN_CONFIGURATION_AUTHORIZATION_DENIED_CODE,
            "iOS VPN authorization is denied",
        ),
    ];

    for (vpn_state, severity, code, reason) in cases {
        let service = StaticIosPlatformCapabilityService::new(IosPlatformSnapshot {
            network_extension: IosNetworkExtensionProbe::vpn_configuration(vpn_state),
            ..IosPlatformSnapshot::available_for_tests()
        });

        let status = service.status().expect("static ios status");

        assert!(!status.tunnel.is_available());
        assert_eq!(status.tunnel.denial_reason(), Some(reason));
        assert_diagnostic(&status.diagnostics, severity, code, SOURCE_VPN_CONFIGURATION);
    }
}

#[test]
fn embedded_runtime_missing_is_reported_as_unavailable() {
    let service = StaticIosPlatformCapabilityService::new(IosPlatformSnapshot {
        embedded_runtime: IosEmbeddedRuntimeProbe::missing(),
        ..IosPlatformSnapshot::available_for_tests()
    });

    let status = service.status().expect("static ios status");

    assert!(!status.embedded_runtime.is_available());
    assert_eq!(
        status.embedded_runtime.denial_reason(),
        Some("iOS embedded runtime is missing")
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Error,
        EMBEDDED_RUNTIME_MISSING_CODE,
        SOURCE_EMBEDDED_RUNTIME,
    );
}

#[test]
fn shared_storage_probe_reports_app_group_and_keychain_failures() {
    let service = StaticIosPlatformCapabilityService::new(IosPlatformSnapshot {
        shared_storage: IosSharedStorageProbe {
            app_group_available: false,
            keychain_access_available: false,
        },
        ..IosPlatformSnapshot::available_for_tests()
    });

    let status = service.status().expect("static ios status");

    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Error,
        APP_GROUP_UNAVAILABLE_CODE,
        SOURCE_APP_GROUP,
    );
    assert_diagnostic(
        &status.diagnostics,
        DiagnosticSeverity::Error,
        KEYCHAIN_ACCESS_DENIED_CODE,
        SOURCE_KEYCHAIN,
    );
}

#[test]
fn mitm_certificate_state_matrix_maps_to_domain_certificate_status() {
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
        let service = StaticIosPlatformCapabilityService::new(IosPlatformSnapshot {
            mitm_certificate: IosMitmCertificateProbe::new(state)
                .with_subject("CN=NetworkCore iOS Test Root")
                .with_fingerprint_sha256("AA:BB:CC")
                .with_default_diagnostic(),
            ..IosPlatformSnapshot::available_for_tests()
        });

        let status = service.status().expect("static ios status");

        assert_eq!(status.mitm_certificate.state, state);
        assert_eq!(
            status.mitm_certificate.subject.as_deref(),
            Some("CN=NetworkCore iOS Test Root")
        );
        assert_eq!(
            status.mitm_certificate.fingerprint_sha256.as_deref(),
            Some("AA:BB:CC")
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
fn user_disabled_mitm_stays_unavailable_even_with_trusted_certificate() {
    let service = StaticIosPlatformCapabilityService::new(IosPlatformSnapshot {
        mitm_user_enabled: false,
        ..IosPlatformSnapshot::available_for_tests()
    });

    let status = service.status().expect("static ios status");

    assert!(!status.mitm.is_available());
    assert!(!status.mitm_available());
    assert_eq!(
        status.mitm.denial_reason(),
        Some("iOS MITM is disabled by user policy")
    );
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
