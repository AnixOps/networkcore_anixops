import NetworkCoreApp
import NetworkCoreBridge
import XCTest

final class NetworkCoreAppDecisionTests: XCTestCase {
    private func status(
        entitlement: IosNetworkExtensionEntitlementFact = .present,
        runtime: IosEmbeddedRuntimeFact = .available
    ) -> IosPlatformStatus {
        IosPlatformBridgeMapper.map(
            IosPlatformSnapshotDTO(
                networkExtension: IosNetworkExtensionFacts(
                    entitlement: entitlement,
                    provider: .available,
                    vpnConfiguration: .savedAndAuthorized
                ),
                embeddedRuntime: runtime,
                mitmCertificate: IosMitmCertificateFacts(trust: .trusted, subject: nil, fingerprintSHA256: nil),
                sharedStorage: IosSharedStorageFacts(appGroupAvailable: true, keychainAccessAvailable: true),
                mitmUserEnabled: false
            )
        )
    }

    func testHealthyStatusAllowsStartingTunnel() {
        let coordinator = AppCoordinator(status: status())

        XCTAssertTrue(coordinator.canStartTunnel)
        XCTAssertEqual(coordinator.decision, .startTunnel)
    }

    func testMissingEntitlementBlocksWithTheTunnelCode() {
        let coordinator = AppCoordinator(status: status(entitlement: .missing))

        XCTAssertFalse(coordinator.canStartTunnel)
        XCTAssertEqual(
            coordinator.decision,
            .blocked(
                reason: "iOS Network Extension entitlement is missing",
                code: IosPlatformCodes.networkExtensionEntitlementMissing
            )
        )
    }

    func testMissingRuntimeBlocksWithTheRuntimeCode() {
        let decision = VpnConfigurationController.decide(for: status(runtime: .missing))

        XCTAssertEqual(
            decision,
            .blocked(
                reason: "iOS embedded runtime is missing",
                code: IosPlatformCodes.embeddedRuntimeMissing
            )
        )
    }

    func testApplyRefreshesDecisionWhenStatusRecovers() {
        var coordinator = AppCoordinator(status: status(runtime: .abiMismatch))
        XCTAssertFalse(coordinator.canStartTunnel)

        coordinator.apply(status())
        XCTAssertTrue(coordinator.canStartTunnel)
    }
}
