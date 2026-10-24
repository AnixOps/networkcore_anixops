@testable import NetworkCoreBridge
import XCTest

final class MitmPluginTests: XCTestCase {
    private let adBlock = """
    #!name = Example Ad Block
    #!desc = Rejects ad endpoints

    [Rule]
    DOMAIN,ads.example.com,REJECT

    [Rewrite]
    ^https?://api\\.example\\.com/v1/ad reject-dict
    ^https?://old\\.example\\.com/(.*) 302 https://new.example.com/$1

    [Script]
    http-response ^https?://api\\.example\\.com/v1/feed script-path=feed.js, requires-body=true, tag=feed

    [MITM]
    hostname = %APPEND% api.example.com, Old.Example.com, -login.example.com
    """

    func testSummaryReadsNameHostsAndSectionCounts() throws {
        let plugin = try MitmPlugin(text: adBlock)

        XCTAssertEqual(plugin.name, "Example Ad Block")
        XCTAssertTrue(plugin.isEnabled)
        let summary = plugin.summary
        XCTAssertEqual(summary.hostnames, ["api.example.com", "old.example.com"])
        XCTAssertEqual(summary.rewriteLines, 2)
        XCTAssertEqual(summary.scriptLines, 1)
        XCTAssertEqual(summary.ruleLines, 1)
    }

    func testRejectsEmptyOversizedAndInertText() {
        XCTAssertThrowsError(try MitmPlugin(text: "  \n")) { XCTAssertEqual($0 as? MitmPluginError, .empty) }
        XCTAssertThrowsError(try MitmPlugin(text: String(repeating: "#", count: MitmPlugin.maxBytes + 1))) {
            XCTAssertEqual($0 as? MitmPluginError, .tooLarge)
        }
        XCTAssertThrowsError(try MitmPlugin(text: "[Rule]\nDOMAIN,a.example,REJECT\n")) {
            XCTAssertEqual($0 as? MitmPluginError, .nothingToApply)
        }
        XCTAssertEqual(try MitmPlugin(text: "[MITM]\nhostname = a.example\n", fallbackName: "file").name, "file")
    }

    func testLibraryHandsOnlyEnabledPluginsToTheTunnelWhileSwitchedOn() throws {
        var library = MitmPluginLibrary()
        let first = try MitmPlugin(text: adBlock)
        let second = try MitmPlugin(text: "[MITM]\nhostname = b.example\n", fallbackName: "second")
        try library.add(first)
        try library.add(second)

        XCTAssertEqual(library.activeTexts, [], "the master switch starts off")
        library.isEnabled = true
        XCTAssertEqual(library.activeTexts, [first.text, second.text])
        try library.setEnabled(false, for: first.id)
        XCTAssertEqual(library.activeTexts, [second.text])
        library.remove(second.id)
        XCTAssertEqual(library.activeTexts, [])
        XCTAssertEqual(library.plugins.map(\.id), [first.id])
    }

    func testLibraryCapsTheEnabledTotal() throws {
        var library = MitmPluginLibrary()
        let body = "[MITM]\nhostname = a.example\n" + String(repeating: "#", count: 200 * 1024)
        try library.add(MitmPlugin(text: body))
        try library.add(MitmPlugin(text: body))
        XCTAssertThrowsError(try library.add(MitmPlugin(text: body))) {
            XCTAssertEqual($0 as? MitmPluginError, .libraryFull)
        }
        XCTAssertEqual(library.plugins.count, 2)
    }

    func testLibraryAndProfileValueRoundTrip() throws {
        var library = MitmPluginLibrary()
        library.isEnabled = true
        try library.add(MitmPlugin(text: adBlock))
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("mitm-plugins-\(UUID()).json")
        defer { try? FileManager.default.removeItem(at: url) }

        try library.save(to: url)
        XCTAssertEqual(try MitmPluginLibrary.load(from: url), library)
        XCTAssertEqual(
            try MitmPluginLibrary.load(from: url.appendingPathExtension("missing")),
            MitmPluginLibrary()
        )
        let value = try MitmPluginLibrary.profileValue(library.activeTexts)
        XCTAssertEqual(MitmPluginLibrary.texts(fromProfileValue: value), [adBlock])
        XCTAssertEqual(MitmPluginLibrary.texts(fromProfileValue: nil), [])
    }

    func testRuntimeConfigCarriesMitmOnlyWhenAddedAndNeverInTheProfile() throws {
        let node = ShadowsocksNode(
            host: "203.0.113.7",
            port: 8388,
            method: "2022-blake3-aes-128-gcm",
            password: "YWJjZGVmZ2hpamtsbW5vcA==",
            name: "node"
        )
        let authority = try MitmCertificateAuthority.generate()
        let config = EmbeddedRuntimeConfig(node: node, profileID: "default")

        XCTAssertNil(try json(config)["mitm"])
        let decrypting = try config.withMitm(plugins: [adBlock], authority: authority)
        let mitm = try XCTUnwrap(try json(decrypting)["mitm"] as? [String: Any])
        XCTAssertEqual(mitm["plugins"] as? [String], [adBlock])
        XCTAssertEqual(mitm["ca_certificate"] as? String, authority.certificateDER.base64EncodedString())
        XCTAssertEqual(
            mitm["ca_private_key"] as? String,
            try authority.privateKeyRepresentation().base64EncodedString()
        )
        XCTAssertEqual(try EmbeddedRuntimeConfig.decoded(from: decrypting.encoded()), decrypting)
        XCTAssertNil(decrypting.withoutSecret().mitm, "the root key never goes into the tunnel profile")
        XCTAssertNil(decrypting.withoutMitm().mitm)
        XCTAssertNil(try config.withMitm(plugins: [], authority: authority).mitm)
    }

    private func json(_ config: EmbeddedRuntimeConfig) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: config.encoded()) as? [String: Any])
    }
}
