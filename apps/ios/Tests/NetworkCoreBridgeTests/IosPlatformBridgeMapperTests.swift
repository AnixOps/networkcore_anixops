import NetworkCoreBridge
import XCTest

final class IosPlatformBridgeMapperTests: XCTestCase {
    private func makeSnapshot(
        entitlement: IosNetworkExtensionEntitlementFact = .present,
        provider: IosNetworkExtensionProviderFact = .available,
        vpn: IosVpnConfigurationFact = .savedAndAuthorized,
        runtime: IosEmbeddedRuntimeFact = .available,
        trust: IosCertificateTrustFact = .trusted,
        appGroupAvailable: Bool = true,
        keychainAvailable: Bool = true,
        mitmUserEnabled: Bool = true
    ) -> IosPlatformSnapshotDTO {
        IosPlatformSnapshotDTO(
            networkExtension: IosNetworkExtensionFacts(
                entitlement: entitlement,
                provider: provider,
                vpnConfiguration: vpn
            ),
            embeddedRuntime: runtime,
            mitmCertificate: IosMitmCertificateFacts(trust: trust, subject: nil, fingerprintSHA256: nil),
            sharedStorage: IosSharedStorageFacts(
                appGroupAvailable: appGroupAvailable,
                keychainAccessAvailable: keychainAvailable
            ),
            mitmUserEnabled: mitmUserEnabled
        )
    }

    private func codes(_ status: IosPlatformStatus) -> [String] {
        status.diagnostics.map { $0.code }
    }

    func testHealthySnapshotEnablesTunnelAndRuntimeButNeverRemoteScripts() {
        let status = IosPlatformBridgeMapper.map(makeSnapshot())

        XCTAssertTrue(status.tunnel.available)
        XCTAssertNil(status.tunnel.unavailableReason)
        XCTAssertTrue(status.embeddedRuntime.available)
        XCTAssertTrue(status.mitm.available)
        XCTAssertFalse(status.remoteScriptExecution.available)
        XCTAssertEqual(
            codes(status),
            [
                IosPlatformCodes.embeddedRuntimeAvailable,
                IosPlatformCodes.remoteScriptExecutionDisabled,
            ]
        )
        XCTAssertEqual(
            status.mitmCertificateDiagnostics.map { $0.code },
            [IosPlatformCodes.mitmCertificateTrusted]
        )
    }

    func testMissingEntitlementBlocksTunnelWithStableCode() {
        let status = IosPlatformBridgeMapper.map(makeSnapshot(entitlement: .missing))

        XCTAssertFalse(status.tunnel.available)
        XCTAssertEqual(status.tunnel.unavailableReason, "iOS Network Extension entitlement is missing")
        XCTAssertEqual(codes(status).first, IosPlatformCodes.networkExtensionEntitlementMissing)
    }

    func testProviderUnavailableBlocksTunnelWithStableCode() {
        let status = IosPlatformBridgeMapper.map(makeSnapshot(provider: .unavailable))

        XCTAssertFalse(status.tunnel.available)
        XCTAssertEqual(codes(status).first, IosPlatformCodes.networkExtensionProviderUnavailable)
    }

    func testVpnConfigurationStatesMapToStableCodes() {
        let cases: [(IosVpnConfigurationFact, String)] = [
            (.managerUnavailable, IosPlatformCodes.vpnConfigurationManagerUnavailable),
            (.notSaved, IosPlatformCodes.vpnConfigurationNotSaved),
            (.authorizationRequired, IosPlatformCodes.vpnConfigurationAuthorizationRequired),
            (.authorizationDenied, IosPlatformCodes.vpnConfigurationAuthorizationDenied),
        ]
        for (fact, expectedCode) in cases {
            let status = IosPlatformBridgeMapper.map(makeSnapshot(vpn: fact))
            XCTAssertFalse(status.tunnel.available, "\(fact)")
            XCTAssertEqual(codes(status).first, expectedCode, "\(fact)")
        }
    }

    func testEmbeddedRuntimeFailuresMapToStableCodesAndBlockRuntime() {
        let cases: [(IosEmbeddedRuntimeFact, String)] = [
            (.missing, IosPlatformCodes.embeddedRuntimeMissing),
            (.abiMismatch, IosPlatformCodes.embeddedRuntimeAbiMismatch),
            (.initializationFailed, IosPlatformCodes.embeddedRuntimeInitializationFailed),
        ]
        for (fact, expectedCode) in cases {
            let status = IosPlatformBridgeMapper.map(makeSnapshot(runtime: fact))
            XCTAssertFalse(status.embeddedRuntime.available, "\(fact)")
            XCTAssertTrue(codes(status).contains(expectedCode), "\(fact)")
        }
    }

    func testSharedStorageFailuresMapToStableCodes() {
        let status = IosPlatformBridgeMapper.map(
            makeSnapshot(appGroupAvailable: false, keychainAvailable: false)
        )

        XCTAssertTrue(codes(status).contains(IosPlatformCodes.appGroupUnavailable))
        XCTAssertTrue(codes(status).contains(IosPlatformCodes.keychainAccessDenied))
    }

    func testMitmRequiresUserOptInAndTrustedCertificate() {
        let disabled = IosPlatformBridgeMapper.map(makeSnapshot(mitmUserEnabled: false))
        XCTAssertFalse(disabled.mitm.available)
        XCTAssertEqual(disabled.mitm.unavailableReason, "iOS MITM is disabled by user policy")

        let untrusted = IosPlatformBridgeMapper.map(makeSnapshot(trust: .installedUntrusted))
        XCTAssertFalse(untrusted.mitm.available)
        XCTAssertEqual(
            untrusted.mitmCertificateDiagnostics.map { $0.code },
            [IosPlatformCodes.mitmCertificateInstalledUntrusted]
        )
        XCTAssertEqual(untrusted.mitmCertificateDiagnostics.first?.severity, IosDiagnosticSeverity.warning)
    }

    func testCertificateTrustStatesMapToStableCodesAndSeverity() {
        let cases: [(IosCertificateTrustFact, String, IosDiagnosticSeverity)] = [
            (.notInstalled, IosPlatformCodes.mitmCertificateNotInstalled, .warning),
            (.installedUntrusted, IosPlatformCodes.mitmCertificateInstalledUntrusted, .warning),
            (.trusted, IosPlatformCodes.mitmCertificateTrusted, .info),
            (.revoked, IosPlatformCodes.mitmCertificateRevoked, .error),
            (.unknown, IosPlatformCodes.mitmCertificateUnknown, .warning),
        ]
        for (fact, expectedCode, expectedSeverity) in cases {
            let status = IosPlatformBridgeMapper.map(makeSnapshot(trust: fact))
            XCTAssertEqual(status.mitmCertificateTrust, fact, "\(fact)")
            XCTAssertEqual(status.mitmCertificateDiagnostics.first?.code, expectedCode, "\(fact)")
            XCTAssertEqual(status.mitmCertificateDiagnostics.first?.severity, expectedSeverity, "\(fact)")
        }
    }

    func testAbiHandshakeMapsMismatchAndInitializationFailure() {
        XCTAssertEqual(
            NetworkCoreRuntimeFFI.embeddedRuntimeFact(reported: nil, initializationSucceeded: true),
            .missing
        )

        let older = NetworkCoreRuntimeFFI.Handshake(abiVersion: 0, dtoSchemaVersion: 1, featureSetVersion: 1)
        XCTAssertEqual(
            NetworkCoreRuntimeFFI.embeddedRuntimeFact(reported: older, initializationSucceeded: true),
            .abiMismatch
        )
        XCTAssertEqual(
            NetworkCoreRuntimeFFI.embeddedRuntimeFact(
                reported: NetworkCoreRuntimeFFI.Handshake.current,
                initializationSucceeded: false
            ),
            .initializationFailed
        )
        XCTAssertEqual(
            NetworkCoreRuntimeFFI.embeddedRuntimeFact(
                reported: NetworkCoreRuntimeFFI.Handshake.current,
                initializationSucceeded: true
            ),
            .available
        )
    }

    func testDiagnosticsContainNoPathsOrIdentifiers() {
        let status = IosPlatformBridgeMapper.map(
            makeSnapshot(
                entitlement: .missing,
                provider: .unavailable,
                vpn: .managerUnavailable,
                runtime: .abiMismatch,
                trust: .revoked,
                appGroupAvailable: false,
                keychainAvailable: false
            )
        )

        for diagnostic in status.diagnostics + status.mitmCertificateDiagnostics {
            XCTAssertFalse(diagnostic.message.contains("/"), diagnostic.code)
            XCTAssertFalse(diagnostic.source.contains("/"), diagnostic.code)
            XCTAssertTrue(diagnostic.code.hasPrefix("platform.ios."), diagnostic.code)
        }
    }
}
