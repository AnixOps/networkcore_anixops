@testable import NetworkCoreBridge
import XCTest

final class MitmScriptTests: XCTestCase {
    private let plugin = """
    #!name = Feed Cleaner

    [Script]
    http-response ^https?://api\\.example\\.com/v1/feed script-path=https://cdn.example.com/feed.js, requires-body=true, tag=feed
    # http-response ^https://x script-path=https://cdn.example.com/off.js
    http-request ^https?://api\\.example\\.com/v1/ad script-path=scripts/ad.js, tag = ad
    http-response ^https?://api\\.example\\.com/v2/feed script-path=https://cdn.example.com/feed.js
    http-request ^https?://api\\.example\\.com/legacy script-path=http://insecure.example.com/legacy.js

    [MITM]
    hostname = api.example.com
    """

    func testScriptReferencesResolveAgainstThePluginAddressAndKeepOnlyHTTPS() throws {
        let remote = try MitmPlugin(text: plugin, sourceURL: URL(string: "https://plugins.example.com/loon/feed.plugin"))
        let references = remote.scriptReferences

        XCTAssertEqual(references.map(\.path), [
            "https://cdn.example.com/feed.js",
            "scripts/ad.js",
            "http://insecure.example.com/legacy.js",
        ])
        XCTAssertEqual(references.map(\.tag), ["feed", "ad", nil])
        XCTAssertEqual(references[0].url?.absoluteString, "https://cdn.example.com/feed.js")
        XCTAssertEqual(references[1].url?.absoluteString, "https://plugins.example.com/loon/scripts/ad.js")
        XCTAssertNil(references[2].url)

        let local = try MitmPlugin(text: plugin)
        XCTAssertNil(local.scriptReferences[1].url, "a relative path in a local plugin has nowhere to come from")
    }

    func testScriptIsPinnedByDigestAndBounded() throws {
        let url = try XCTUnwrap(URL(string: "https://cdn.example.com/feed.js"))
        let script = try MitmScript(path: url.absoluteString, url: url, data: Data("$done({})".utf8))

        XCTAssertEqual(script.sha256, MitmScript.digest(Data("$done({})".utf8)))
        XCTAssertEqual(script.sha256.count, 64)
        XCTAssertThrowsError(try MitmScript(path: "a", url: url, data: Data(count: MitmScript.maxBytes + 1))) {
            XCTAssertEqual($0 as? MitmScriptError, .tooLarge)
        }
        XCTAssertThrowsError(try MitmScript(path: "a", url: url, data: Data([0xff, 0xfe]))) {
            XCTAssertEqual($0 as? MitmScriptError, .notText)
        }
    }

    func testLibraryHandsOnlyAllowedScriptsOfActivePluginsToTheTunnel() throws {
        var plugins = MitmPluginLibrary()
        plugins.isEnabled = true
        try plugins.add(MitmPlugin(text: plugin, sourceURL: URL(string: "https://plugins.example.com/loon/feed.plugin")))
        let feed = try XCTUnwrap(URL(string: "https://cdn.example.com/feed.js"))
        var scripts = MitmScriptLibrary()
        scripts.allow(try MitmScript(path: feed.absoluteString, url: feed, data: Data("$done({})".utf8)))
        let unrelated = try XCTUnwrap(URL(string: "https://cdn.example.com/other.js"))
        scripts.allow(try MitmScript(path: unrelated.absoluteString, url: unrelated, data: Data("$done({})".utf8)))

        XCTAssertEqual(try scripts.sources(for: plugins.activeScriptReferences), [feed.absoluteString: "$done({})"])

        plugins.isEnabled = false
        XCTAssertEqual(try scripts.sources(for: plugins.activeScriptReferences), [:])

        scripts.revoke(feed.absoluteString)
        plugins.isEnabled = true
        XCTAssertEqual(try scripts.sources(for: plugins.activeScriptReferences), [:])
    }

    func testLibraryCapsTheActiveTotal() throws {
        var scripts = MitmScriptLibrary()
        var references: [MitmScriptReference] = []
        let body = Data(String(repeating: "a", count: MitmScript.maxBytes).utf8)
        for index in 0..<3 {
            let url = try XCTUnwrap(URL(string: "https://cdn.example.com/\(index).js"))
            scripts.allow(try MitmScript(path: url.absoluteString, url: url, data: body))
            references.append(MitmScriptReference(path: url.absoluteString, tag: nil, base: nil))
        }

        XCTAssertNoThrow(try scripts.sources(for: Array(references.prefix(2))))
        XCTAssertThrowsError(try scripts.sources(for: references)) {
            XCTAssertEqual($0 as? MitmScriptError, .libraryFull)
        }
    }

    func testLibraryAndProfileValueRoundTrip() throws {
        let url = try XCTUnwrap(URL(string: "https://cdn.example.com/feed.js"))
        var scripts = MitmScriptLibrary()
        scripts.allow(try MitmScript(path: url.absoluteString, url: url, data: Data("$done({})".utf8)))
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("mitm-scripts-\(UUID()).json")
        defer { try? FileManager.default.removeItem(at: file) }

        try scripts.save(to: file)
        XCTAssertEqual(try MitmScriptLibrary.load(from: file), scripts)
        XCTAssertEqual(try MitmScriptLibrary.load(from: file.appendingPathExtension("missing")), MitmScriptLibrary())

        let sources = [url.absoluteString: "$done({})"]
        XCTAssertEqual(MitmScriptLibrary.sources(fromProfileValue: try MitmScriptLibrary.profileValue(sources)), sources)
        XCTAssertEqual(MitmScriptLibrary.sources(fromProfileValue: nil), [:])
    }

    func testAssetsAreWrittenByDigestAndStaleOnesRemoved() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("mitm-assets-\(UUID())")
        defer { try? FileManager.default.removeItem(at: directory) }

        let first = try MitmScriptLibrary.writeAssets(["a.js": "one", "b.js": "two"], to: directory)
        XCTAssertEqual(try String(contentsOfFile: XCTUnwrap(first["a.js"]), encoding: .utf8), "one")
        XCTAssertEqual(
            URL(fileURLWithPath: try XCTUnwrap(first["b.js"])).lastPathComponent,
            "\(MitmScript.digest(Data("two".utf8))).js"
        )

        let second = try MitmScriptLibrary.writeAssets(["a.js": "one"], to: directory)
        XCTAssertEqual(second, ["a.js": try XCTUnwrap(first["a.js"])])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).count, 1)
    }

    func testRuntimeConfigCarriesScriptAssets() throws {
        let node = ShadowsocksNode(
            host: "203.0.113.7",
            port: 8388,
            method: "2022-blake3-aes-128-gcm",
            password: "YWJjZGVmZ2hpamtsbW5vcA==",
            name: "node"
        )
        let authority = try MitmCertificateAuthority.generate()
        let config = try EmbeddedRuntimeConfig(node: node, profileID: "default").withMitm(
            plugins: [plugin],
            authority: authority,
            scriptAssets: ["https://cdn.example.com/feed.js": "/tmp/feed.js"],
            scriptStorePath: "/tmp/store.json"
        )

        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: config.encoded()) as? [String: Any])
        let mitm = try XCTUnwrap(object["mitm"] as? [String: Any])
        XCTAssertEqual(mitm["script_assets"] as? [String: String], ["https://cdn.example.com/feed.js": "/tmp/feed.js"])
        XCTAssertEqual(mitm["script_store_path"] as? String, "/tmp/store.json")
        XCTAssertEqual(try EmbeddedRuntimeConfig.decoded(from: config.encoded()), config)
        XCTAssertNil(config.withoutSecret().mitm)
    }
}
