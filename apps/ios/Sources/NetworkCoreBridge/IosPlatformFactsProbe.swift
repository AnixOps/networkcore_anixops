/// Facts the app and the tunnel extension can state for this build, before live probes exist.
///
/// These are static values, not live probes. The entitlement and extension are compiled into the build,
/// no VPN configuration has been saved, no App Group is configured, and the Rust runtime is not linked.
/// Each value is replaced by a live probe when its gate lands.
public enum IosPlatformFactsProbe {
    public static func currentSnapshot() -> IosPlatformSnapshotDTO {
        IosPlatformSnapshotDTO(
            networkExtension: IosNetworkExtensionFacts(
                entitlement: .present,
                provider: .available,
                vpnConfiguration: .notSaved
            ),
            embeddedRuntime: NetworkCoreRuntimeFFI.embeddedRuntimeFact(
                reported: nil,
                initializationSucceeded: false
            ),
            mitmCertificate: IosMitmCertificateFacts(trust: .notInstalled, subject: nil, fingerprintSHA256: nil),
            sharedStorage: IosSharedStorageFacts(appGroupAvailable: false, keychainAccessAvailable: true),
            mitmUserEnabled: false
        )
    }

    public static func currentStatus() -> IosPlatformStatus {
        IosPlatformBridgeMapper.map(currentSnapshot())
    }
}
