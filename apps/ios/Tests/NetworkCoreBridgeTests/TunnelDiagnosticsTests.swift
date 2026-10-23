import Foundation
import NetworkCoreBridge
import XCTest

final class TunnelDiagnosticsTests: XCTestCase {
    func testOlderAppsEmptyMessageStillAsksForRuntimeStatus() {
        XCTAssertEqual(TunnelAppMessage.decode(Data()), .runtimeStatus)
        XCTAssertEqual(TunnelAppMessage.decode(Data("anything".utf8)), .runtimeStatus)
        XCTAssertEqual(TunnelAppMessage.decode(TunnelAppMessage.diagnostics.encoded), .diagnostics)
        XCTAssertEqual(TunnelAppMessage.decode(TunnelAppMessage.runtimeStatus.encoded), .runtimeStatus)
    }

    func testEventLogKeepsOnlyTheNewestEntries() {
        let log = TunnelDiagnosticLog(capacity: 3)
        for index in 1...5 {
            log.record("event \(index)", at: Date(timeIntervalSince1970: Double(index)))
        }

        XCTAssertEqual(log.snapshot().map(\.message), ["event 3", "event 4", "event 5"])
    }

    func testDiagnosticsRoundTripThroughJSON() throws {
        let diagnostics = TunnelDiagnostics(
            runtimeStatus: #"{"dns_queries":3}"#,
            memoryFootprintBytes: 12_582_912,
            uptimeSeconds: 61.5,
            handshake: .current,
            events: [TunnelDiagnosticEvent(time: Date(timeIntervalSince1970: 1_700_000_000.25), message: "startTunnel")]
        )

        XCTAssertEqual(try TunnelDiagnostics.decoded(from: diagnostics.encoded()), diagnostics)
    }

    func testOutboundKindCarriesNoAddressOrSecret() throws {
        let node = try ShadowsocksNodeLink.parse(
            "ss://2022-blake3-aes-128-gcm:QUJDREVGR0hJSktMTU5PUA%3D%3D@203.0.113.7:8388#home"
        )
        let config = EmbeddedRuntimeConfig(node: node, profileID: "default")

        XCTAssertEqual(config.outboundKind, "shadowsocks (2022-blake3-aes-128-gcm)")
        XCTAssertFalse(config.outboundKind.contains("203.0.113.7"))
        XCTAssertFalse(config.outboundKind.contains("QUJD"))
    }

    func testReportIncludesPrettyStatusAndEvents() {
        let report = DeveloperReport(
            appVersion: "0.1.0",
            appBuild: "7",
            systemVersion: "iOS 18.0",
            connection: "已连接",
            outboundKind: "wireguard",
            lastDisconnectError: nil,
            diagnostics: TunnelDiagnostics(
                runtimeStatus: #"{"tcp_last_failure":"timeout","dns_queries":3}"#,
                memoryFootprintBytes: 12_582_912,
                uptimeSeconds: 3725,
                handshake: .current,
                events: [TunnelDiagnosticEvent(time: Date(timeIntervalSince1970: 0), message: "startTunnel succeeded")]
            ),
            generatedAt: Date(timeIntervalSince1970: 0)
        )
        let text = report.text

        XCTAssertTrue(text.contains("app: 0.1.0 (7)"))
        XCTAssertTrue(text.contains("outbound: wireguard"))
        XCTAssertTrue(text.contains("extension memory: 12.0 MB"))
        XCTAssertTrue(text.contains("extension uptime: 1h 2m 5s"))
        XCTAssertTrue(text.contains("\"dns_queries\" : 3,\n  \"tcp_last_failure\" : \"timeout\""))
        XCTAssertTrue(text.contains("1970-01-01T00:00:00.000Z startTunnel succeeded"))
    }

    func testReportWithoutExtensionSaysSo() {
        let report = DeveloperReport(
            appVersion: "0.1.0",
            appBuild: "7",
            systemVersion: "iOS 18.0",
            connection: "未连接",
            outboundKind: nil,
            lastDisconnectError: "隧道已停止：node key is unavailable",
            diagnostics: nil,
            generatedAt: Date(timeIntervalSince1970: 0)
        )

        XCTAssertTrue(report.text.contains("outbound: none"))
        XCTAssertTrue(report.text.contains("隧道已停止：node key is unavailable"))
        XCTAssertTrue(report.text.hasSuffix("extension: not reachable"))
    }

    func testPrettyJSONLeavesNonJSONTextAlone() {
        XCTAssertEqual(DeveloperReport.prettyJSON("not json"), "not json")
    }
}
