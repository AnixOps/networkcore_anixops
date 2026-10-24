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

    private let routedReport = """
    {"nodes":[
    {"id":"a","name":"Tokyo","protocol":"trojan","server":"a.example","port":443,
     "outbound":{"type":"trojan","server":"a.example","port":443,"password":"pa"}},
    {"id":"b","name":"","protocol":"hysteria2","server":"b.example","port":8443,
     "outbound":{"type":"hysteria2","server":"b.example","port":8443,"password":"pb"}}],
    "unsupported":[],
    "routing":{"rules":["DOMAIN-SUFFIX,google.com,Proxy","FINAL,Proxy"],
    "groups":[{"id":"Proxy","type":"select","members":["Auto","a","DIRECT"],"default":null},
    {"id":"Auto","type":"url-test","members":["a","b"],"url":"http://www.gstatic.com/generate_204","interval_secs":300}]}}
    """

    func testSubscriptionRulesBecomeTheRuntimeRoutingSection() throws {
        let report = try NativeImportReport.decoded(from: Data(routedReport.utf8))
        var library = NodeLibrary(report: report, subscriptionURL: "https://s.example/x", keeping: nil)
        XCTAssertTrue(library.routesByRules)
        let proxy = try XCTUnwrap(library.routing?.groups.first)
        XCTAssertTrue(proxy.isSelectable)
        XCTAssertEqual(library.selection(in: proxy), "Auto")
        XCTAssertEqual(library.displayName(ofMember: "b"), "b.example")
        XCTAssertEqual(library.displayName(ofMember: "Auto"), "Auto")

        library.groupSelections["Proxy"] = "a"
        let routing = try XCTUnwrap(library.runtimeRouting())
        XCTAssertEqual(routing.groups.map { $0.default }, ["a", nil])
        XCTAssertEqual(routing.outbounds["b"]?["password"], .string("pb"))

        let profile = try TunnelProfile(node: try XCTUnwrap(library.selected), profileID: "default")
        let routed = profile.config.withRouting(routing)
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: routed.encoded()) as? [String: Any])
        XCTAssertNil(json["outbound"])
        let section = try XCTUnwrap(json["routing"] as? [String: Any])
        XCTAssertEqual(section["rules"] as? [String], ["DOMAIN-SUFFIX,google.com,Proxy", "FINAL,Proxy"])
        let groups = try XCTUnwrap(section["groups"] as? [[String: Any]])
        XCTAssertEqual(groups.first?["default"] as? String, "a")
        XCTAssertEqual(groups.last?["interval_secs"] as? Int, 300)
        // The profile copy never carries the other nodes' credentials.
        let stored = String(decoding: try routed.withoutSecret().encoded(), as: UTF8.self)
        XCTAssertFalse(stored.contains("routing"))
        XCTAssertFalse(stored.contains("pb"))

        library.followsRules = false
        XCTAssertNil(library.runtimeRouting())
        XCTAssertFalse(library.routesByRules)
    }

    func testRefreshKeepsTheRulesSwitchAndValidGroupPicks() throws {
        let report = try NativeImportReport.decoded(from: Data(routedReport.utf8))
        var library = NodeLibrary(report: report, subscriptionURL: "https://s.example/x", keeping: nil)
        library.followsRules = false
        library.groupSelections = ["Proxy": "DIRECT", "Gone": "a"]
        library.selectedID = "b"
        let refreshed = library.refreshed(with: report)
        XCTAssertFalse(refreshed.followsRules)
        XCTAssertEqual(refreshed.groupSelections, ["Proxy": "DIRECT"])
        XCTAssertEqual(refreshed.selectedID, "b")
        XCTAssertEqual(refreshed.subscriptionURL, "https://s.example/x")
        // A subscription that gains rules follows them.
        let plain = NodeLibrary(report: try decoded(), subscriptionURL: "https://s.example/x", keeping: nil)
        XCTAssertFalse(plain.routesByRules)
        XCTAssertTrue(plain.refreshed(with: report).routesByRules)
    }

    func testLibrariesSavedBeforeRulesStillLoad() throws {
        let saved = """
        {"nodes":[],"selectedID":null,"subscriptionURL":"https://s.example/x","updatedAt":1700000000000}
        """
        let library = try NodeLibrary.fromKeychainValue(saved)
        XCTAssertNil(library.routing)
        XCTAssertFalse(library.followsRules)
        XCTAssertEqual(library.groupSelections, [:])
    }
}
