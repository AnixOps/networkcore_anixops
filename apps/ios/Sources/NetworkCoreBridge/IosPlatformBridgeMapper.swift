// Maps sanitized iOS snapshot DTOs to platform capability status.
//
// Codes, sources, severities and feature decisions mirror crates/platform-ios/src/lib.rs.
// IosPlatformBridgeMapperTests pins the code strings so the two sides cannot drift apart silently.

public enum IosDiagnosticSeverity: String, Sendable, Equatable {
    case info
    case warning
    case error
}

public struct IosDiagnostic: Sendable, Equatable {
    public let severity: IosDiagnosticSeverity
    public let code: String
    public let message: String
    public let source: String

    public init(severity: IosDiagnosticSeverity, code: String, message: String, source: String) {
        self.severity = severity
        self.code = code
        self.message = message
        self.source = source
    }
}

public struct IosFeatureStatus: Sendable, Equatable {
    public let available: Bool
    public let unavailableReason: String?

    public init(available: Bool, unavailableReason: String?) {
        self.available = available
        self.unavailableReason = unavailableReason
    }

    public static let enabled = IosFeatureStatus(available: true, unavailableReason: nil)

    public static func disabled(_ reason: String) -> IosFeatureStatus {
        IosFeatureStatus(available: false, unavailableReason: reason)
    }
}

public struct IosPlatformStatus: Sendable, Equatable {
    public let tunnel: IosFeatureStatus
    public let mitm: IosFeatureStatus
    public let embeddedRuntime: IosFeatureStatus
    public let remoteScriptExecution: IosFeatureStatus
    public let mitmCertificateTrust: IosCertificateTrustFact
    public let diagnostics: [IosDiagnostic]
    public let mitmCertificateDiagnostics: [IosDiagnostic]

    public init(
        tunnel: IosFeatureStatus,
        mitm: IosFeatureStatus,
        embeddedRuntime: IosFeatureStatus,
        remoteScriptExecution: IosFeatureStatus,
        mitmCertificateTrust: IosCertificateTrustFact,
        diagnostics: [IosDiagnostic],
        mitmCertificateDiagnostics: [IosDiagnostic]
    ) {
        self.tunnel = tunnel
        self.mitm = mitm
        self.embeddedRuntime = embeddedRuntime
        self.remoteScriptExecution = remoteScriptExecution
        self.mitmCertificateTrust = mitmCertificateTrust
        self.diagnostics = diagnostics
        self.mitmCertificateDiagnostics = mitmCertificateDiagnostics
    }
}

/// Stable diagnostic codes. The strings must equal the constants in crates/platform-ios.
public enum IosPlatformCodes {
    public static let networkExtensionEntitlementMissing = "platform.ios.network_extension.entitlement_missing"
    public static let networkExtensionProviderUnavailable = "platform.ios.network_extension.provider_unavailable"
    public static let vpnConfigurationManagerUnavailable = "platform.ios.vpn_configuration.manager_unavailable"
    public static let vpnConfigurationNotSaved = "platform.ios.vpn_configuration.not_saved"
    public static let vpnConfigurationAuthorizationRequired = "platform.ios.vpn_configuration.authorization_required"
    public static let vpnConfigurationAuthorizationDenied = "platform.ios.vpn_configuration.authorization_denied"
    public static let appGroupUnavailable = "platform.ios.app_group.unavailable"
    public static let keychainAccessDenied = "platform.ios.keychain.access_denied"
    public static let embeddedRuntimeAvailable = "platform.ios.embedded_runtime.available"
    public static let embeddedRuntimeMissing = "platform.ios.embedded_runtime.missing"
    public static let embeddedRuntimeAbiMismatch = "platform.ios.embedded_runtime.abi_mismatch"
    public static let embeddedRuntimeInitializationFailed = "platform.ios.embedded_runtime.initialization_failed"
    public static let remoteScriptExecutionDisabled = "platform.ios.remote_script_execution.disabled_by_policy"
    public static let mitmCertificateNotInstalled = "platform.ios.mitm_certificate.not_installed"
    public static let mitmCertificateInstalledUntrusted = "platform.ios.mitm_certificate.installed_untrusted"
    public static let mitmCertificateTrusted = "platform.ios.mitm_certificate.trusted"
    public static let mitmCertificateRevoked = "platform.ios.mitm_certificate.revoked"
    public static let mitmCertificateUnknown = "platform.ios.mitm_certificate.unknown"
}

/// Diagnostic source labels. Each diagnostic names the platform area it came from.
public enum IosPlatformSources {
    public static let networkExtension = "platform.ios.network_extension"
    public static let vpnConfiguration = "platform.ios.vpn_configuration"
    public static let appGroup = "platform.ios.app_group"
    public static let keychain = "platform.ios.keychain"
    public static let embeddedRuntime = "platform.ios.embedded_runtime"
    public static let remoteScriptExecution = "platform.ios.remote_script_execution"
    public static let mitmCertificate = "platform.ios.mitm_certificate"
}

public enum IosPlatformBridgeMapper {
    public static func map(_ snapshot: IosPlatformSnapshotDTO) -> IosPlatformStatus {
        let tunnel = mapNetworkExtension(snapshot.networkExtension)
        let runtime = mapEmbeddedRuntime(snapshot.embeddedRuntime)
        let remote = remoteScriptExecutionDisabled()

        // Same order as the Rust mapper: tunnel, embedded runtime, remote script, shared storage.
        var diagnostics = tunnel.diagnostics + runtime.diagnostics + remote.diagnostics
        diagnostics += mapSharedStorage(snapshot.sharedStorage)

        return IosPlatformStatus(
            tunnel: tunnel.feature,
            mitm: mapMitm(userEnabled: snapshot.mitmUserEnabled, trust: snapshot.mitmCertificate.trust),
            embeddedRuntime: runtime.feature,
            remoteScriptExecution: remote.feature,
            mitmCertificateTrust: snapshot.mitmCertificate.trust,
            diagnostics: diagnostics,
            mitmCertificateDiagnostics: [certificateDiagnostic(snapshot.mitmCertificate.trust)]
        )
    }

    private struct ProbeResult {
        let feature: IosFeatureStatus
        let diagnostics: [IosDiagnostic]
    }

    private static func diagnostic(
        _ severity: IosDiagnosticSeverity,
        _ code: String,
        _ message: String,
        _ source: String
    ) -> IosDiagnostic {
        IosDiagnostic(severity: severity, code: code, message: message, source: source)
    }

    private static func unavailable(_ reason: String, _ diagnostic: IosDiagnostic) -> ProbeResult {
        ProbeResult(feature: .disabled(reason), diagnostics: [diagnostic])
    }

    private static func mapNetworkExtension(_ facts: IosNetworkExtensionFacts) -> ProbeResult {
        if facts.entitlement == .missing {
            return unavailable(
                "iOS Network Extension entitlement is missing",
                diagnostic(
                    .error,
                    IosPlatformCodes.networkExtensionEntitlementMissing,
                    "iOS Network Extension entitlement is missing",
                    IosPlatformSources.networkExtension
                )
            )
        }

        if facts.provider == .unavailable {
            return unavailable(
                "iOS Network Extension provider is unavailable",
                diagnostic(
                    .error,
                    IosPlatformCodes.networkExtensionProviderUnavailable,
                    "iOS NEPacketTunnelProvider target is unavailable",
                    IosPlatformSources.networkExtension
                )
            )
        }

        switch facts.vpnConfiguration {
        case .savedAndAuthorized:
            return ProbeResult(feature: .enabled, diagnostics: [])
        case .managerUnavailable:
            return unavailable(
                "iOS VPN configuration manager is unavailable",
                diagnostic(
                    .error,
                    IosPlatformCodes.vpnConfigurationManagerUnavailable,
                    "iOS NETunnelProviderManager cannot read or save VPN configuration",
                    IosPlatformSources.vpnConfiguration
                )
            )
        case .notSaved:
            return unavailable(
                "iOS VPN configuration is not saved",
                diagnostic(
                    .warning,
                    IosPlatformCodes.vpnConfigurationNotSaved,
                    "iOS VPN configuration has not been saved",
                    IosPlatformSources.vpnConfiguration
                )
            )
        case .authorizationRequired:
            return unavailable(
                "iOS VPN authorization is required",
                diagnostic(
                    .warning,
                    IosPlatformCodes.vpnConfigurationAuthorizationRequired,
                    "iOS VPN configuration requires user authorization",
                    IosPlatformSources.vpnConfiguration
                )
            )
        case .authorizationDenied:
            return unavailable(
                "iOS VPN authorization is denied",
                diagnostic(
                    .error,
                    IosPlatformCodes.vpnConfigurationAuthorizationDenied,
                    "iOS VPN authorization was denied or revoked",
                    IosPlatformSources.vpnConfiguration
                )
            )
        }
    }

    private static func mapEmbeddedRuntime(_ fact: IosEmbeddedRuntimeFact) -> ProbeResult {
        switch fact {
        case .available:
            return ProbeResult(
                feature: .enabled,
                diagnostics: [
                    diagnostic(
                        .info,
                        IosPlatformCodes.embeddedRuntimeAvailable,
                        "iOS embedded runtime is available",
                        IosPlatformSources.embeddedRuntime
                    ),
                ]
            )
        case .missing:
            return unavailable(
                "iOS embedded runtime is missing",
                diagnostic(
                    .error,
                    IosPlatformCodes.embeddedRuntimeMissing,
                    "iOS embedded runtime artifact or link target is missing",
                    IosPlatformSources.embeddedRuntime
                )
            )
        case .abiMismatch:
            return unavailable(
                "iOS embedded runtime ABI is incompatible",
                diagnostic(
                    .error,
                    IosPlatformCodes.embeddedRuntimeAbiMismatch,
                    "iOS embedded runtime ABI or schema is incompatible",
                    IosPlatformSources.embeddedRuntime
                )
            )
        case .initializationFailed:
            return unavailable(
                "iOS embedded runtime initialization failed",
                diagnostic(
                    .error,
                    IosPlatformCodes.embeddedRuntimeInitializationFailed,
                    "iOS embedded runtime initialization failed",
                    IosPlatformSources.embeddedRuntime
                )
            )
        }
    }

    private static func remoteScriptExecutionDisabled() -> ProbeResult {
        let reason = "remote script execution is disabled on iOS"
        return unavailable(
            reason,
            diagnostic(
                .error,
                IosPlatformCodes.remoteScriptExecutionDisabled,
                reason,
                IosPlatformSources.remoteScriptExecution
            )
        )
    }

    private static func mapSharedStorage(_ facts: IosSharedStorageFacts) -> [IosDiagnostic] {
        var diagnostics: [IosDiagnostic] = []
        if !facts.appGroupAvailable {
            diagnostics.append(
                diagnostic(
                    .error,
                    IosPlatformCodes.appGroupUnavailable,
                    "iOS App Group shared storage is unavailable",
                    IosPlatformSources.appGroup
                )
            )
        }
        if !facts.keychainAccessAvailable {
            diagnostics.append(
                diagnostic(
                    .error,
                    IosPlatformCodes.keychainAccessDenied,
                    "iOS Keychain sharing access is denied",
                    IosPlatformSources.keychain
                )
            )
        }
        return diagnostics
    }

    private static func mapMitm(userEnabled: Bool, trust: IosCertificateTrustFact) -> IosFeatureStatus {
        if !userEnabled {
            return .disabled("iOS MITM is disabled by user policy")
        }
        if trust == .trusted {
            return .enabled
        }
        return .disabled("iOS MITM certificate is not trusted")
    }

    private static func certificateDiagnostic(_ trust: IosCertificateTrustFact) -> IosDiagnostic {
        switch trust {
        case .notInstalled:
            return diagnostic(
                .warning,
                IosPlatformCodes.mitmCertificateNotInstalled,
                "iOS MITM certificate is not installed",
                IosPlatformSources.mitmCertificate
            )
        case .installedUntrusted:
            return diagnostic(
                .warning,
                IosPlatformCodes.mitmCertificateInstalledUntrusted,
                "iOS MITM certificate is installed but not confirmed trusted",
                IosPlatformSources.mitmCertificate
            )
        case .trusted:
            return diagnostic(
                .info,
                IosPlatformCodes.mitmCertificateTrusted,
                "iOS MITM certificate trust is confirmed",
                IosPlatformSources.mitmCertificate
            )
        case .revoked:
            return diagnostic(
                .error,
                IosPlatformCodes.mitmCertificateRevoked,
                "iOS MITM certificate is revoked or invalid",
                IosPlatformSources.mitmCertificate
            )
        case .unknown:
            return diagnostic(
                .warning,
                IosPlatformCodes.mitmCertificateUnknown,
                "iOS MITM certificate state is unknown",
                IosPlatformSources.mitmCertificate
            )
        }
    }
}
