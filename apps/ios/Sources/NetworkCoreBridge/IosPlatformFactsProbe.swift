/// Facts the app and the tunnel extension can state for this build.
///
/// The entitlement and extension are compiled into the build and no App Group is configured. Callers pass
/// the facts they can observe: the app passes the saved VPN configuration state, the extension passes the
/// live runtime handshake. The defaults describe a build before either is known.
public enum IosPlatformFactsProbe {
    public static func currentSnapshot(
        vpnConfiguration: IosVpnConfigurationFact = .notSaved,
        embeddedRuntime: IosEmbeddedRuntimeFact = NetworkCoreRuntimeFFI.embeddedRuntimeFact(
            reported: nil,
            initializationSucceeded: false
        )
    ) -> IosPlatformSnapshotDTO {
        IosPlatformSnapshotDTO(
            networkExtension: IosNetworkExtensionFacts(
                entitlement: .present,
                provider: .available,
                vpnConfiguration: vpnConfiguration
            ),
            embeddedRuntime: embeddedRuntime,
            mitmCertificate: IosMitmCertificateFacts(trust: .notInstalled, subject: nil, fingerprintSHA256: nil),
            sharedStorage: IosSharedStorageFacts(appGroupAvailable: false, keychainAccessAvailable: true),
            mitmUserEnabled: false
        )
    }

    public static func currentStatus(
        vpnConfiguration: IosVpnConfigurationFact = .notSaved,
        embeddedRuntime: IosEmbeddedRuntimeFact = NetworkCoreRuntimeFFI.embeddedRuntimeFact(
            reported: nil,
            initializationSucceeded: false
        )
    ) -> IosPlatformStatus {
        IosPlatformBridgeMapper.map(currentSnapshot(vpnConfiguration: vpnConfiguration, embeddedRuntime: embeddedRuntime))
    }
}
