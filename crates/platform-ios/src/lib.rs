//! iOS platform capability adapter contracts.
//!
//! This crate exposes pure Rust mapping primitives for sanitized iOS platform
//! facts. It must not depend on Swift, Xcode, NetworkExtension, UIKit,
//! Security.framework, signing assets, or App Store Connect APIs.

use control_domain::{
    CertificateTrustState, Diagnostic, DiagnosticSeverity, DomainResult, MitmCertificateStatus,
    OperatingSystem, PlatformCapabilityService, PlatformCapabilityStatus, PlatformFeatureState,
};

pub const SOURCE_NETWORK_EXTENSION: &str = "platform.ios.network_extension";
pub const SOURCE_VPN_CONFIGURATION: &str = "platform.ios.vpn_configuration";
pub const SOURCE_APP_GROUP: &str = "platform.ios.app_group";
pub const SOURCE_KEYCHAIN: &str = "platform.ios.keychain";
pub const SOURCE_EMBEDDED_RUNTIME: &str = "platform.ios.embedded_runtime";
pub const SOURCE_REMOTE_SCRIPT_EXECUTION: &str = "platform.ios.remote_script_execution";
pub const SOURCE_MITM_CERTIFICATE: &str = "platform.ios.mitm_certificate";

pub const NETWORK_EXTENSION_ENTITLEMENT_MISSING_CODE: &str =
    "platform.ios.network_extension.entitlement_missing";
pub const NETWORK_EXTENSION_PROVIDER_UNAVAILABLE_CODE: &str =
    "platform.ios.network_extension.provider_unavailable";
pub const VPN_CONFIGURATION_MANAGER_UNAVAILABLE_CODE: &str =
    "platform.ios.vpn_configuration.manager_unavailable";
pub const VPN_CONFIGURATION_NOT_SAVED_CODE: &str = "platform.ios.vpn_configuration.not_saved";
pub const VPN_CONFIGURATION_AUTHORIZATION_REQUIRED_CODE: &str =
    "platform.ios.vpn_configuration.authorization_required";
pub const VPN_CONFIGURATION_AUTHORIZATION_DENIED_CODE: &str =
    "platform.ios.vpn_configuration.authorization_denied";
pub const APP_GROUP_UNAVAILABLE_CODE: &str = "platform.ios.app_group.unavailable";
pub const KEYCHAIN_ACCESS_DENIED_CODE: &str = "platform.ios.keychain.access_denied";
pub const EMBEDDED_RUNTIME_AVAILABLE_CODE: &str = "platform.ios.embedded_runtime.available";
pub const EMBEDDED_RUNTIME_MISSING_CODE: &str = "platform.ios.embedded_runtime.missing";
pub const EMBEDDED_RUNTIME_ABI_MISMATCH_CODE: &str =
    "platform.ios.embedded_runtime.abi_mismatch";
pub const EMBEDDED_RUNTIME_INITIALIZATION_FAILED_CODE: &str =
    "platform.ios.embedded_runtime.initialization_failed";
pub const REMOTE_SCRIPT_EXECUTION_DISABLED_CODE: &str =
    "platform.ios.remote_script_execution.disabled_by_policy";
pub const MITM_CERTIFICATE_NOT_INSTALLED_CODE: &str = "platform.ios.mitm_certificate.not_installed";
pub const MITM_CERTIFICATE_INSTALLED_UNTRUSTED_CODE: &str =
    "platform.ios.mitm_certificate.installed_untrusted";
pub const MITM_CERTIFICATE_TRUSTED_CODE: &str = "platform.ios.mitm_certificate.trusted";
pub const MITM_CERTIFICATE_REVOKED_CODE: &str = "platform.ios.mitm_certificate.revoked";
pub const MITM_CERTIFICATE_UNKNOWN_CODE: &str = "platform.ios.mitm_certificate.unknown";

pub const REMOTE_SCRIPT_EXECUTION_DISABLED_REASON: &str =
    "remote script execution is disabled on iOS";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IosFeatureProbe {
    pub state: PlatformFeatureState,
    pub diagnostics: Vec<Diagnostic>,
}

impl IosFeatureProbe {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IosNetworkExtensionEntitlementState {
    Present,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IosNetworkExtensionProviderState {
    Available,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IosVpnConfigurationState {
    SavedAndAuthorized,
    ManagerUnavailable,
    NotSaved,
    AuthorizationRequired,
    AuthorizationDenied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IosNetworkExtensionProbe {
    pub entitlement: IosNetworkExtensionEntitlementState,
    pub provider: IosNetworkExtensionProviderState,
    pub vpn_configuration: IosVpnConfigurationState,
}

impl IosNetworkExtensionProbe {
    pub const fn available() -> Self {
        Self {
            entitlement: IosNetworkExtensionEntitlementState::Present,
            provider: IosNetworkExtensionProviderState::Available,
            vpn_configuration: IosVpnConfigurationState::SavedAndAuthorized,
        }
    }

    pub const fn entitlement_missing() -> Self {
        Self {
            entitlement: IosNetworkExtensionEntitlementState::Missing,
            ..Self::available()
        }
    }

    pub const fn provider_unavailable() -> Self {
        Self {
            provider: IosNetworkExtensionProviderState::Unavailable,
            ..Self::available()
        }
    }

    pub const fn vpn_configuration(state: IosVpnConfigurationState) -> Self {
        Self {
            vpn_configuration: state,
            ..Self::available()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IosEmbeddedRuntimeState {
    Available,
    Missing,
    AbiMismatch,
    InitializationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IosEmbeddedRuntimeProbe {
    pub state: IosEmbeddedRuntimeState,
}

impl IosEmbeddedRuntimeProbe {
    pub const fn available() -> Self {
        Self {
            state: IosEmbeddedRuntimeState::Available,
        }
    }

    pub const fn missing() -> Self {
        Self {
            state: IosEmbeddedRuntimeState::Missing,
        }
    }

    pub const fn abi_mismatch() -> Self {
        Self {
            state: IosEmbeddedRuntimeState::AbiMismatch,
        }
    }

    pub const fn initialization_failed() -> Self {
        Self {
            state: IosEmbeddedRuntimeState::InitializationFailed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IosMitmCertificateProbe {
    pub state: CertificateTrustState,
    pub subject: Option<String>,
    pub fingerprint_sha256: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
}

impl IosMitmCertificateProbe {
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

    pub fn with_default_diagnostic(self) -> Self {
        let severity = certificate_severity(self.state);
        let code = certificate_diagnostic_code(self.state);
        let message = certificate_diagnostic_message(self.state);
        self.with_diagnostic(ios_diagnostic(
            severity,
            code,
            message,
            SOURCE_MITM_CERTIFICATE,
        ))
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
pub struct IosSharedStorageProbe {
    pub app_group_available: bool,
    pub keychain_access_available: bool,
}

impl IosSharedStorageProbe {
    pub const fn available() -> Self {
        Self {
            app_group_available: true,
            keychain_access_available: true,
        }
    }

    pub const fn app_group_unavailable() -> Self {
        Self {
            app_group_available: false,
            keychain_access_available: true,
        }
    }

    pub const fn keychain_access_denied() -> Self {
        Self {
            app_group_available: true,
            keychain_access_available: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IosPlatformSnapshot {
    pub network_extension: IosNetworkExtensionProbe,
    pub embedded_runtime: IosEmbeddedRuntimeProbe,
    pub mitm_certificate: IosMitmCertificateProbe,
    pub shared_storage: IosSharedStorageProbe,
    pub mitm_user_enabled: bool,
    pub diagnostics: Vec<Diagnostic>,
}

impl IosPlatformSnapshot {
    pub fn available_for_tests() -> Self {
        Self {
            network_extension: IosNetworkExtensionProbe::available(),
            embedded_runtime: IosEmbeddedRuntimeProbe::available(),
            mitm_certificate: IosMitmCertificateProbe::new(CertificateTrustState::Trusted)
                .with_default_diagnostic(),
            shared_storage: IosSharedStorageProbe::available(),
            mitm_user_enabled: true,
            diagnostics: Vec::new(),
        }
    }

    pub fn with_diagnostic(mut self, diagnostic: Diagnostic) -> Self {
        self.diagnostics.push(diagnostic);
        self
    }

    pub fn into_status(self) -> PlatformCapabilityStatus {
        let IosPlatformSnapshot {
            network_extension,
            embedded_runtime,
            mitm_certificate,
            shared_storage,
            mitm_user_enabled,
            diagnostics: snapshot_diagnostics,
        } = self;

        let IosFeatureProbe {
            state: tunnel,
            diagnostics: tunnel_diagnostics,
        } = map_network_extension(network_extension);
        let IosFeatureProbe {
            state: embedded_runtime,
            diagnostics: embedded_runtime_diagnostics,
        } = map_embedded_runtime(embedded_runtime);
        let IosFeatureProbe {
            state: remote_script_execution,
            diagnostics: remote_script_execution_diagnostics,
        } = remote_script_execution_disabled();
        let mut diagnostics = tunnel_diagnostics;
        diagnostics.extend(embedded_runtime_diagnostics);
        diagnostics.extend(remote_script_execution_diagnostics);
        diagnostics.extend(map_shared_storage(shared_storage));
        diagnostics.extend(snapshot_diagnostics);

        let mitm_certificate = mitm_certificate.into_status();
        let mitm = map_mitm_state(mitm_user_enabled, mitm_certificate.state);

        PlatformCapabilityStatus {
            os: OperatingSystem::Ios,
            tunnel,
            mitm,
            embedded_runtime,
            remote_script_execution,
            mitm_certificate,
            diagnostics,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticIosPlatformCapabilityService {
    snapshot: IosPlatformSnapshot,
}

impl StaticIosPlatformCapabilityService {
    pub fn new(snapshot: IosPlatformSnapshot) -> Self {
        Self { snapshot }
    }

    pub fn snapshot(&self) -> &IosPlatformSnapshot {
        &self.snapshot
    }
}

impl PlatformCapabilityService for StaticIosPlatformCapabilityService {
    fn status(&self) -> DomainResult<PlatformCapabilityStatus> {
        Ok(self.snapshot.clone().into_status())
    }
}

pub fn ios_diagnostic(
    severity: DiagnosticSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
    source: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(severity, code, message, Some(source.into()))
}

pub fn certificate_diagnostic_code(state: CertificateTrustState) -> &'static str {
    match state {
        CertificateTrustState::NotInstalled => MITM_CERTIFICATE_NOT_INSTALLED_CODE,
        CertificateTrustState::InstalledUntrusted => MITM_CERTIFICATE_INSTALLED_UNTRUSTED_CODE,
        CertificateTrustState::Trusted => MITM_CERTIFICATE_TRUSTED_CODE,
        CertificateTrustState::Revoked => MITM_CERTIFICATE_REVOKED_CODE,
        CertificateTrustState::Unknown => MITM_CERTIFICATE_UNKNOWN_CODE,
    }
}

pub fn certificate_severity(state: CertificateTrustState) -> DiagnosticSeverity {
    match state {
        CertificateTrustState::Trusted => DiagnosticSeverity::Info,
        CertificateTrustState::Revoked => DiagnosticSeverity::Error,
        CertificateTrustState::NotInstalled
        | CertificateTrustState::InstalledUntrusted
        | CertificateTrustState::Unknown => DiagnosticSeverity::Warning,
    }
}

fn certificate_diagnostic_message(state: CertificateTrustState) -> &'static str {
    match state {
        CertificateTrustState::NotInstalled => "iOS MITM certificate is not installed",
        CertificateTrustState::InstalledUntrusted => {
            "iOS MITM certificate is installed but not confirmed trusted"
        }
        CertificateTrustState::Trusted => "iOS MITM certificate trust is confirmed",
        CertificateTrustState::Revoked => "iOS MITM certificate is revoked or invalid",
        CertificateTrustState::Unknown => "iOS MITM certificate state is unknown",
    }
}

fn map_network_extension(probe: IosNetworkExtensionProbe) -> IosFeatureProbe {
    if probe.entitlement == IosNetworkExtensionEntitlementState::Missing {
        return IosFeatureProbe::unavailable(
            "iOS Network Extension entitlement is missing",
            ios_diagnostic(
                DiagnosticSeverity::Error,
                NETWORK_EXTENSION_ENTITLEMENT_MISSING_CODE,
                "iOS Network Extension entitlement is missing",
                SOURCE_NETWORK_EXTENSION,
            ),
        );
    }

    if probe.provider == IosNetworkExtensionProviderState::Unavailable {
        return IosFeatureProbe::unavailable(
            "iOS Network Extension provider is unavailable",
            ios_diagnostic(
                DiagnosticSeverity::Error,
                NETWORK_EXTENSION_PROVIDER_UNAVAILABLE_CODE,
                "iOS NEPacketTunnelProvider target is unavailable",
                SOURCE_NETWORK_EXTENSION,
            ),
        );
    }

    match probe.vpn_configuration {
        IosVpnConfigurationState::SavedAndAuthorized => IosFeatureProbe::available(),
        IosVpnConfigurationState::ManagerUnavailable => IosFeatureProbe::unavailable(
            "iOS VPN configuration manager is unavailable",
            ios_diagnostic(
                DiagnosticSeverity::Error,
                VPN_CONFIGURATION_MANAGER_UNAVAILABLE_CODE,
                "iOS NETunnelProviderManager cannot read or save VPN configuration",
                SOURCE_VPN_CONFIGURATION,
            ),
        ),
        IosVpnConfigurationState::NotSaved => IosFeatureProbe::unavailable(
            "iOS VPN configuration is not saved",
            ios_diagnostic(
                DiagnosticSeverity::Warning,
                VPN_CONFIGURATION_NOT_SAVED_CODE,
                "iOS VPN configuration has not been saved",
                SOURCE_VPN_CONFIGURATION,
            ),
        ),
        IosVpnConfigurationState::AuthorizationRequired => IosFeatureProbe::unavailable(
            "iOS VPN authorization is required",
            ios_diagnostic(
                DiagnosticSeverity::Warning,
                VPN_CONFIGURATION_AUTHORIZATION_REQUIRED_CODE,
                "iOS VPN configuration requires user authorization",
                SOURCE_VPN_CONFIGURATION,
            ),
        ),
        IosVpnConfigurationState::AuthorizationDenied => IosFeatureProbe::unavailable(
            "iOS VPN authorization is denied",
            ios_diagnostic(
                DiagnosticSeverity::Error,
                VPN_CONFIGURATION_AUTHORIZATION_DENIED_CODE,
                "iOS VPN authorization was denied or revoked",
                SOURCE_VPN_CONFIGURATION,
            ),
        ),
    }
}

fn map_embedded_runtime(probe: IosEmbeddedRuntimeProbe) -> IosFeatureProbe {
    match probe.state {
        IosEmbeddedRuntimeState::Available => IosFeatureProbe::available().with_diagnostic(
            ios_diagnostic(
                DiagnosticSeverity::Info,
                EMBEDDED_RUNTIME_AVAILABLE_CODE,
                "iOS embedded runtime is available",
                SOURCE_EMBEDDED_RUNTIME,
            ),
        ),
        IosEmbeddedRuntimeState::Missing => IosFeatureProbe::unavailable(
            "iOS embedded runtime is missing",
            ios_diagnostic(
                DiagnosticSeverity::Error,
                EMBEDDED_RUNTIME_MISSING_CODE,
                "iOS embedded runtime artifact or link target is missing",
                SOURCE_EMBEDDED_RUNTIME,
            ),
        ),
        IosEmbeddedRuntimeState::AbiMismatch => IosFeatureProbe::unavailable(
            "iOS embedded runtime ABI is incompatible",
            ios_diagnostic(
                DiagnosticSeverity::Error,
                EMBEDDED_RUNTIME_ABI_MISMATCH_CODE,
                "iOS embedded runtime ABI or schema is incompatible",
                SOURCE_EMBEDDED_RUNTIME,
            ),
        ),
        IosEmbeddedRuntimeState::InitializationFailed => IosFeatureProbe::unavailable(
            "iOS embedded runtime initialization failed",
            ios_diagnostic(
                DiagnosticSeverity::Error,
                EMBEDDED_RUNTIME_INITIALIZATION_FAILED_CODE,
                "iOS embedded runtime initialization failed",
                SOURCE_EMBEDDED_RUNTIME,
            ),
        ),
    }
}

fn remote_script_execution_disabled() -> IosFeatureProbe {
    IosFeatureProbe::unavailable(
        REMOTE_SCRIPT_EXECUTION_DISABLED_REASON,
        ios_diagnostic(
            DiagnosticSeverity::Error,
            REMOTE_SCRIPT_EXECUTION_DISABLED_CODE,
            REMOTE_SCRIPT_EXECUTION_DISABLED_REASON,
            SOURCE_REMOTE_SCRIPT_EXECUTION,
        ),
    )
}

fn map_shared_storage(probe: IosSharedStorageProbe) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();

    if !probe.app_group_available {
        diagnostics.push(ios_diagnostic(
            DiagnosticSeverity::Error,
            APP_GROUP_UNAVAILABLE_CODE,
            "iOS App Group shared storage is unavailable",
            SOURCE_APP_GROUP,
        ));
    }

    if !probe.keychain_access_available {
        diagnostics.push(ios_diagnostic(
            DiagnosticSeverity::Error,
            KEYCHAIN_ACCESS_DENIED_CODE,
            "iOS Keychain sharing access is denied",
            SOURCE_KEYCHAIN,
        ));
    }

    diagnostics
}

fn map_mitm_state(
    user_enabled: bool,
    certificate_state: CertificateTrustState,
) -> PlatformFeatureState {
    if !user_enabled {
        return PlatformFeatureState::unavailable("iOS MITM is disabled by user policy");
    }

    if certificate_state.is_trusted() {
        PlatformFeatureState::available()
    } else {
        PlatformFeatureState::unavailable(
            certificate_state
                .denial_reason()
                .unwrap_or("iOS MITM certificate is not trusted"),
        )
    }
}
