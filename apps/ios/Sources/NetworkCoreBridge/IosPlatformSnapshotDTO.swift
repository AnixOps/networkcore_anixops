// Sanitized iOS platform facts. Mirrors IosPlatformSnapshot in crates/platform-ios.
//
// These DTOs must never carry bundle IDs, Team IDs, provisioning profile UUIDs, absolute paths,
// Keychain queries or values, certificate payloads, private keys, traffic samples or full
// subscription URLs. Only the enum facts and booleans below may cross into the Rust mapper.

public enum IosNetworkExtensionEntitlementFact: String, Sendable, Equatable {
    case present
    case missing
}

public enum IosNetworkExtensionProviderFact: String, Sendable, Equatable {
    case available
    case unavailable
}

public enum IosVpnConfigurationFact: String, Sendable, Equatable {
    case savedAndAuthorized
    case managerUnavailable
    case notSaved
    case authorizationRequired
    case authorizationDenied
}

public struct IosNetworkExtensionFacts: Sendable, Equatable {
    public let entitlement: IosNetworkExtensionEntitlementFact
    public let provider: IosNetworkExtensionProviderFact
    public let vpnConfiguration: IosVpnConfigurationFact

    public init(
        entitlement: IosNetworkExtensionEntitlementFact,
        provider: IosNetworkExtensionProviderFact,
        vpnConfiguration: IosVpnConfigurationFact
    ) {
        self.entitlement = entitlement
        self.provider = provider
        self.vpnConfiguration = vpnConfiguration
    }
}

public enum IosEmbeddedRuntimeFact: String, Sendable, Equatable {
    case available
    case missing
    case abiMismatch
    case initializationFailed
}

public struct IosSharedStorageFacts: Sendable, Equatable {
    public let appGroupAvailable: Bool
    public let keychainAccessAvailable: Bool

    public init(appGroupAvailable: Bool, keychainAccessAvailable: Bool) {
        self.appGroupAvailable = appGroupAvailable
        self.keychainAccessAvailable = keychainAccessAvailable
    }
}

public enum IosCertificateTrustFact: String, Sendable, Equatable {
    case notInstalled
    case installedUntrusted
    case trusted
    case revoked
    case unknown
}

public struct IosMitmCertificateFacts: Sendable, Equatable {
    public let trust: IosCertificateTrustFact
    public let subject: String?
    public let fingerprintSHA256: String?

    public init(trust: IosCertificateTrustFact, subject: String?, fingerprintSHA256: String?) {
        self.trust = trust
        self.subject = subject
        self.fingerprintSHA256 = fingerprintSHA256
    }
}

public struct IosPlatformSnapshotDTO: Sendable, Equatable {
    public let networkExtension: IosNetworkExtensionFacts
    public let embeddedRuntime: IosEmbeddedRuntimeFact
    public let mitmCertificate: IosMitmCertificateFacts
    public let sharedStorage: IosSharedStorageFacts
    public let mitmUserEnabled: Bool

    public init(
        networkExtension: IosNetworkExtensionFacts,
        embeddedRuntime: IosEmbeddedRuntimeFact,
        mitmCertificate: IosMitmCertificateFacts,
        sharedStorage: IosSharedStorageFacts,
        mitmUserEnabled: Bool
    ) {
        self.networkExtension = networkExtension
        self.embeddedRuntime = embeddedRuntime
        self.mitmCertificate = mitmCertificate
        self.sharedStorage = sharedStorage
        self.mitmUserEnabled = mitmUserEnabled
    }
}
