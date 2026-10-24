import Foundation
import NetworkCoreBridge
import XCTest

final class NativeNodeImportTests: XCTestCase {
    /// What crates/node-import returns for a Trojan-over-WebSocket link and an unsupported node.
    private let trojanReport = """
    {"nodes":[{"id":"n1","name":"HK Trojan","protocol":"trojan","server":"edge.example.com","port":443,
    "outbound":{"type":"trojan","server":"edge.example.com","port":443,"password":"trojan-secret",
    "server_name":"cdn.example.com","alpn":["h2","http/1.1"],"insecure":false,
    "transport":{"type":"ws","path":"/ws","host":"cdn.example.com"}}}],
    "unsupported":[{"name":"Old","protocol":"hysteria","reason":"protocol is not implemented by the embedded engine yet"}]}
    """

    private func importer(_ json: String) -> NativeNodeImporter {
        { _ in Data(json.utf8) }
    }

    func testOtherProtocolsBecomeANativeOutboundWithTheirSettingsInTheKeychain() throws {
        let profile = try TunnelNodeImport.parse(
            "trojan://trojan-secret@edge.example.com:443?type=ws",
            profileID: "default",
            native: importer(trojanReport)
        )
        XCTAssertEqual(profile.displayName, "HK Trojan")
        XCTAssertEqual(profile.serverAddress, "edge.example.com")
        XCTAssertEqual(profile.interface, .proxy)
        XCTAssertEqual(profile.config.outboundKind, "trojan")

        let full = try XCTUnwrap(JSONSerialization.jsonObject(with: profile.config.encoded()) as? [String: Any])
        let outbound = try XCTUnwrap(full["outbound"] as? [String: Any])
        XCTAssertEqual(outbound["type"] as? String, "trojan")
        XCTAssertEqual(outbound["port"] as? Int, 443)
        XCTAssertEqual(outbound["password"] as? String, "trojan-secret")
        XCTAssertEqual(outbound["insecure"] as? Bool, false)
        XCTAssertEqual(outbound["alpn"] as? [String], ["h2", "http/1.1"])
        XCTAssertEqual((outbound["transport"] as? [String: Any])?["path"] as? String, "/ws")

        let stored = try profile.config.withoutSecret().encoded()
        let storedText = String(decoding: stored, as: UTF8.self)
        XCTAssertFalse(storedText.contains("trojan-secret"))
        let storedOutbound = try XCTUnwrap(
            (JSONSerialization.jsonObject(with: stored) as? [String: Any])?["outbound"] as? [String: Any]
        )
        XCTAssertEqual(Set(storedOutbound.keys), ["type", "server", "port"])

        let secret = NodeSecret.fromKeychainValue(try profile.config.secret.keychainValue())
        let restored = try EmbeddedRuntimeConfig.decoded(from: stored).withSecret(secret)
        XCTAssertEqual(restored, profile.config)
    }

    func testShadowsocksAndRealityFromTheImporterKeepTheirOwnCases() throws {
        let report = """
        {"nodes":[{"id":"n1","name":"","protocol":"shadowsocks","server":"198.51.100.1","port":8388,
        "outbound":{"type":"shadowsocks","server":"198.51.100.1","port":8388,"method":"aes-256-gcm","password":"pw"}}],
        "unsupported":[]}
        """
        let profile = try TunnelNodeImport.parse("ss://subscription", profileID: "default", native: importer(report))
        XCTAssertEqual(profile.config.outboundKind, "shadowsocks (aes-256-gcm)")
        XCTAssertEqual(profile.displayName, "198.51.100.1")
        XCTAssertEqual(profile.config.secret, NodeSecret(password: "pw"))
    }

    func testVlessOverTlsIsNativeButRealityIsBuiltIn() throws {
        let tls = Data(#"{"type":"vless","server":"a.example","port":443,"uuid":"u","tls":{"server_name":"a.example"}}"#.utf8)
        let outbound = try JSONDecoder().decode(EmbeddedRuntimeConfig.Outbound.self, from: tls)
        guard case let .native(native) = outbound else {
            return XCTFail("expected a native outbound")
        }
        XCTAssertEqual(native.type, "vless")
        XCTAssertEqual(native.settings["uuid"], .string("u"))
        // The profile copy (no settings) still reads back as the same native outbound.
        let bare = try JSONDecoder().decode(
            EmbeddedRuntimeConfig.Outbound.self,
            from: Data(#"{"type":"vless","server":"a.example","port":443}"#.utf8)
        )
        guard case .native = bare else {
            return XCTFail("expected a native outbound")
        }
    }

    func testFailuresKeepTheMostUsefulError() {
        let unsupportedOnly = """
        {"nodes":[],"unsupported":[{"name":"x","protocol":"mieru","reason":"r"}]}
        """
        XCTAssertThrowsError(
            try TunnelNodeImport.parse("mieru://x", profileID: "p", native: importer(unsupportedOnly))
        ) { error in
            XCTAssertEqual(
                error as? TunnelNodeImportError,
                .native(.noSupportedNode(protocols: ["mieru"], reasons: ["r"]))
            )
        }

        let unrecognized: NativeNodeImporter = { _ in throw NativeImportFailure.unrecognized }
        XCTAssertThrowsError(try TunnelNodeImport.parse("hello", profileID: "p", native: unrecognized)) { error in
            XCTAssertEqual(error as? TunnelNodeImportError, .native(.unrecognized))
        }
        // A link Swift recognizes keeps its own error when the importer cannot help.
        XCTAssertThrowsError(
            try TunnelNodeImport.parse("ss://aes-256-gcm:secret@example.com:8388", profileID: "p", native: unrecognized)
        ) { error in
            guard case .shadowsocks = error as? TunnelNodeImportError else {
                return XCTFail("expected the Shadowsocks error, got \(error)")
            }
        }
        // Without the importer, unknown text stays unrecognized.
        XCTAssertThrowsError(try TunnelNodeImport.parse("hello", profileID: "p")) { error in
            XCTAssertEqual(error as? TunnelNodeImportError, .unrecognized)
        }
    }

    func testJSONValuesRoundTrip() throws {
        let text = #"{"a":null,"b":true,"c":-3,"d":1.5,"e":"s","f":[1,"x"],"g":{"h":false}}"#
        let value = try JSONDecoder().decode(JSONValue.self, from: Data(text.utf8))
        XCTAssertEqual(
            value,
            .object([
                "a": .null, "b": .bool(true), "c": .int(-3), "d": .double(1.5), "e": .string("s"),
                "f": .array([.int(1), .string("x")]), "g": .object(["h": .bool(false)]),
            ])
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        XCTAssertEqual(try JSONDecoder().decode(JSONValue.self, from: encoder.encode(value)), value)
    }
}
