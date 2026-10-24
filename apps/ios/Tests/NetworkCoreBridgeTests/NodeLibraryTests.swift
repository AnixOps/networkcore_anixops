import Foundation
import NetworkCoreBridge
import XCTest

final class NodeLibraryTests: XCTestCase {
    private let report = """
    {"nodes":[
    {"id":"a","name":"Tokyo","protocol":"trojan","server":"a.example","port":443,
     "outbound":{"type":"trojan","server":"a.example","port":443,"password":"pa"}},
    {"id":"b","name":"","protocol":"hysteria2","server":"b.example","port":8443,
     "outbound":{"type":"hysteria2","server":"b.example","port":8443,"password":"pb"}}],
    "unsupported":[]}
    """

    private func decoded() throws -> NativeImportReport {
        try NativeImportReport.decoded(from: Data(report.utf8))
    }

    func testSubscriptionTextKeepsEveryNodeAndSelectsTheFirst() throws {
        let imported = try TunnelNodeImport.parseImport("trojan://x", profileID: "p") { _ in Data(self.report.utf8) }
        XCTAssertEqual(imported.profile.displayName, "Tokyo")
        let report = try XCTUnwrap(imported.report)
        let library = NodeLibrary(report: report, subscriptionURL: nil, keeping: nil)
        XCTAssertEqual(library.nodes.map(\.id), ["a", "b"])
        XCTAssertEqual(library.selectedID, "a")
        XCTAssertNil(try TunnelNodeImport.parseImport(
            "ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw%3D%3D@example.com:8388#Tokyo%201",
            profileID: "p"
        ).report)
    }

    func testRefreshKeepsTheSelectedNodeWhenItIsStillListed() throws {
        let report = try decoded()
        XCTAssertEqual(NodeLibrary(report: report, subscriptionURL: "https://s.example/x", keeping: "b").selectedID, "b")
        XCTAssertEqual(NodeLibrary(report: report, subscriptionURL: nil, keeping: "gone").selectedID, "a")
    }

    func testSwitchingBuildsTheProfileForThatNode() throws {
        let library = NodeLibrary(report: try decoded(), subscriptionURL: nil, keeping: nil)
        let node = try XCTUnwrap(library.node(id: "b"))
        let profile = try TunnelProfile(node: node, profileID: "default")
        XCTAssertEqual(profile.serverAddress, "b.example")
        // A node without a name is shown by its server.
        XCTAssertEqual(profile.displayName, "b.example")
        XCTAssertEqual(profile.config.outboundKind, "hysteria2")
        XCTAssertTrue(NodeLibrary.usesUDP(node.protocol))
        XCTAssertFalse(NodeLibrary.usesUDP("trojan"))
    }

    func testKeychainValueRoundTrips() throws {
        let library = NodeLibrary(
            report: try decoded(),
            subscriptionURL: "https://s.example/x?token=t",
            keeping: "b",
            at: Date(timeIntervalSince1970: 1_700_000_000)
        )
        XCTAssertEqual(try NodeLibrary.fromKeychainValue(library.keychainValue()), library)
    }

    func testSubscriptionLinksAreSingleHttpUrls() {
        XCTAssertEqual(SubscriptionLink.url(from: "  https://sub.example/api?token=x \n")?.host, "sub.example")
        XCTAssertNotNil(SubscriptionLink.url(from: "http://sub.example/a"))
        XCTAssertNil(SubscriptionLink.url(from: "trojan://p@a.example:443"))
        XCTAssertNil(SubscriptionLink.url(from: "https://a.example/x\nhttps://b.example/y"))
        XCTAssertNil(SubscriptionLink.url(from: "https://"))
        XCTAssertEqual(SubscriptionLink.displayHost("https://sub.example/api?token=x"), "sub.example")
    }
}
