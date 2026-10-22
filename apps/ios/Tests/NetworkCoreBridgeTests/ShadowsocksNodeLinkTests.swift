import Foundation
import NetworkCoreBridge
import XCTest

final class ShadowsocksNodeLinkTests: XCTestCase {
    private let key = "AAECAwQFBgcICQoLDA0ODw=="

    func testPercentEncodedUserinfo() throws {
        let node = try ShadowsocksNodeLink.parse(
            "ss://2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw%3D%3D@example.com:8388#Tokyo%201"
        )
        XCTAssertEqual(node.host, "example.com")
        XCTAssertEqual(node.port, 8388)
        XCTAssertEqual(node.method, "2022-blake3-aes-128-gcm")
        XCTAssertEqual(node.password, key)
        XCTAssertEqual(node.name, "Tokyo 1")
    }

    func testBase64UrlUserinfoWithoutPadding() throws {
        let userinfo = Data("2022-blake3-aes-128-gcm:\(key)".utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        let node = try ShadowsocksNodeLink.parse("ss://\(userinfo)@192.0.2.10:443")
        XCTAssertEqual(node.host, "192.0.2.10")
        XCTAssertEqual(node.port, 443)
        XCTAssertEqual(node.password, key)
        XCTAssertNil(node.name)
    }

    func testLegacyFullyEncodedLink() throws {
        let encoded = Data("2022-blake3-chacha20-poly1305:\(key)@example.org:8443".utf8).base64EncodedString()
        let node = try ShadowsocksNodeLink.parse("ss://\(encoded)#legacy")
        XCTAssertEqual(node.host, "example.org")
        XCTAssertEqual(node.port, 8443)
        XCTAssertEqual(node.method, "2022-blake3-chacha20-poly1305")
        XCTAssertEqual(node.name, "legacy")
    }

    func testIPv6HostDropsBrackets() throws {
        let node = try ShadowsocksNodeLink.parse("ss://2022-blake3-aes-256-gcm:abc@[2001:db8::1]:8388")
        XCTAssertEqual(node.host, "2001:db8::1")
    }

    func testRejectsUnsupportedInput() {
        XCTAssertThrowsError(try ShadowsocksNodeLink.parse("vless://abc@example.com:443")) { error in
            XCTAssertEqual(error as? ShadowsocksLinkError, .notShadowsocksLink)
        }
        XCTAssertThrowsError(try ShadowsocksNodeLink.parse("ss://aes-256-gcm:secret@example.com:8388")) { error in
            XCTAssertEqual(error as? ShadowsocksLinkError, .unsupportedMethod)
        }
        XCTAssertThrowsError(
            try ShadowsocksNodeLink.parse("ss://2022-blake3-aes-128-gcm:k@example.com:8388/?plugin=v2ray-plugin")
        ) { error in
            XCTAssertEqual(error as? ShadowsocksLinkError, .unsupportedPlugin)
        }
        XCTAssertThrowsError(try ShadowsocksNodeLink.parse("ss://2022-blake3-aes-128-gcm:k@example.com")) { error in
            XCTAssertEqual(error as? ShadowsocksLinkError, .malformed)
        }
    }

    func testRuntimeConfigMatchesTheRustEnvelope() throws {
        let node = ShadowsocksNode(
            host: "example.com",
            port: 8388,
            method: "2022-blake3-aes-128-gcm",
            password: key,
            name: "n"
        )
        let data = try EmbeddedRuntimeConfig(node: node, profileID: "node-1").encoded()
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["schema_version", "profile_id", "mtu", "outbound"])
        XCTAssertEqual(object["schema_version"] as? Int, 1)
        XCTAssertEqual(object["profile_id"] as? String, "node-1")
        let outbound = try XCTUnwrap(object["outbound"] as? [String: Any])
        XCTAssertEqual(outbound["type"] as? String, "shadowsocks")
        XCTAssertEqual(outbound["port"] as? Int, 8388)
        XCTAssertEqual(outbound["password"] as? String, key)
    }

    func testStoredConfigDropsTheKeyAndTheExtensionRestoresIt() throws {
        let node = ShadowsocksNode(
            host: "example.com",
            port: 8388,
            method: "2022-blake3-aes-256-gcm",
            password: key,
            name: nil
        )
        let full = EmbeddedRuntimeConfig(node: node, profileID: "default")
        let stored = try full.withoutSecret().encoded()
        XCTAssertNil(String(data: stored, encoding: .utf8)?.range(of: key))

        let restored = try EmbeddedRuntimeConfig.decoded(from: stored).withPassword(key)
        XCTAssertEqual(restored, full)
        XCTAssertEqual(try restored.encoded(), try full.encoded())
    }

    func testFailureCodesMapToRuntimeFacts() {
        XCTAssertEqual(NetworkCoreRuntimeFFI.embeddedRuntimeFact(forFailureCode: 0), .available)
        XCTAssertEqual(NetworkCoreRuntimeFFI.embeddedRuntimeFact(forFailureCode: 1), .missing)
        XCTAssertEqual(NetworkCoreRuntimeFFI.embeddedRuntimeFact(forFailureCode: 3), .abiMismatch)
        XCTAssertEqual(NetworkCoreRuntimeFFI.embeddedRuntimeFact(forFailureCode: 4), .abiMismatch)
        XCTAssertEqual(NetworkCoreRuntimeFFI.embeddedRuntimeFact(forFailureCode: 6), .initializationFailed)
        XCTAssertEqual(NetworkCoreRuntimeFFI.embeddedRuntimeFact(forFailureCode: 8), .initializationFailed)
    }

    func testSavedConfigurationUnblocksTheAppWhenTheRuntimeIsLinked() {
        let status = IosPlatformFactsProbe.currentStatus(vpnConfiguration: .savedAndAuthorized, embeddedRuntime: .available)
        XCTAssertTrue(status.tunnel.available)
        XCTAssertTrue(status.embeddedRuntime.available)
    }
}
