import Foundation
import NetworkCoreBridge
import XCTest

final class VlessNodeLinkTests: XCTestCase {
    private let uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"
    private let publicKey = "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"

    private func link(_ query: String, host: String = "vpn.example.com", fragment: String = "#Tokyo%201") -> String {
        "vless://\(uuid)@\(host):443?\(query)\(fragment)"
    }

    private var realityQuery: String {
        "encryption=none&security=reality&sni=www.example.com&fp=chrome&pbk=\(publicKey)&sid=6ba85179e30d4fc2&flow=xtls-rprx-vision&type=tcp&headerType=none"
    }

    func testParsesAnXrayRealityShareLink() throws {
        let node = try VlessNodeLink.parse(link(realityQuery))
        XCTAssertEqual(node.host, "vpn.example.com")
        XCTAssertEqual(node.port, 443)
        XCTAssertEqual(node.uuid, uuid)
        XCTAssertEqual(node.flow, "xtls-rprx-vision")
        XCTAssertEqual(node.serverName, "www.example.com")
        XCTAssertEqual(node.publicKey, publicKey)
        XCTAssertEqual(node.shortID, "6ba85179e30d4fc2")
        XCTAssertEqual(node.name, "Tokyo 1")
    }

    func testOptionalParametersAndIPv6Host() throws {
        let node = try VlessNodeLink.parse(
            link("security=reality&sni=www.example.com&pbk=\(publicKey)", host: "[2001:db8::1]", fragment: "")
        )
        XCTAssertEqual(node.host, "2001:db8::1")
        XCTAssertEqual(node.flow, "")
        XCTAssertEqual(node.shortID, "")
        XCTAssertNil(node.name)
    }

    func testRejectsUnsupportedLinks() {
        let cases: [(String, VlessLinkError)] = [
            ("ss://abc@example.com:443", .notVlessLink),
            ("vless://\(uuid)@example.com?security=reality", .malformed),
            ("vless://not-a-uuid@example.com:443?security=reality&sni=a&pbk=\(publicKey)", .invalidUUID),
            (link("security=tls&sni=www.example.com"), .unsupportedSecurity),
            (link("security=none"), .unsupportedSecurity),
            (link(realityQuery.replacingOccurrences(of: "type=tcp", with: "type=ws")), .unsupportedTransport),
            (link(realityQuery.replacingOccurrences(of: "flow=xtls-rprx-vision", with: "flow=xtls-rprx-direct")), .unsupportedFlow),
            (link("security=reality&pbk=\(publicKey)"), .invalidRealitySettings),
            (link("security=reality&sni=www.example.com&pbk=c2hvcnQ"), .invalidRealitySettings),
            (link("security=reality&sni=www.example.com&pbk=\(publicKey)&sid=xyz"), .invalidRealitySettings),
            (link("security=reality&sni=www.example.com&pbk=\(publicKey)&sid=00112233445566778"), .invalidRealitySettings),
        ]
        for (text, expected) in cases {
            XCTAssertThrowsError(try VlessNodeLink.parse(text), text) { error in
                XCTAssertEqual(error as? VlessLinkError, expected, text)
            }
        }
    }

    func testImportBuildsTheRustEnvelopeAndKeepsTheUUIDOutOfTheProfile() throws {
        let profile = try TunnelNodeImport.parse(link(realityQuery), profileID: "default")
        XCTAssertEqual(profile.serverAddress, "vpn.example.com")
        XCTAssertEqual(profile.displayName, "Tokyo 1")
        XCTAssertEqual(profile.interface, .proxy)

        let full = try XCTUnwrap(JSONSerialization.jsonObject(with: profile.config.encoded()) as? [String: Any])
        let outbound = try XCTUnwrap(full["outbound"] as? [String: Any])
        XCTAssertEqual(Set(outbound.keys), ["type", "server", "port", "uuid", "flow", "reality"])
        XCTAssertEqual(outbound["type"] as? String, "vless")
        XCTAssertEqual(outbound["uuid"] as? String, uuid)
        XCTAssertEqual(outbound["flow"] as? String, "xtls-rprx-vision")
        let reality = try XCTUnwrap(outbound["reality"] as? [String: Any])
        XCTAssertEqual(
            reality as NSDictionary,
            [
                "server_name": "www.example.com",
                "public_key": publicKey,
                "short_id": "6ba85179e30d4fc2",
                "fingerprint": "chrome",
            ] as NSDictionary
        )

        let stored = try profile.config.withoutSecret().encoded()
        XCTAssertFalse(String(decoding: stored, as: UTF8.self).contains(uuid))

        let secret = NodeSecret.fromKeychainValue(try profile.config.secret.keychainValue())
        XCTAssertEqual(secret, NodeSecret(uuid: uuid))
        let restored = try EmbeddedRuntimeConfig.decoded(from: stored).withSecret(secret)
        XCTAssertEqual(restored, profile.config)
    }
}
