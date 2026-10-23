import Foundation
import NetworkCoreBridge
import XCTest

final class WireGuardConfigTests: XCTestCase {
    private let privateKey = Data(repeating: 7, count: 32).base64EncodedString()
    private let publicKey = Data(repeating: 9, count: 32).base64EncodedString()
    private let presharedKey = Data(repeating: 3, count: 32).base64EncodedString()

    private var sample: String {
        """
        [Interface]
        # laptop
        PrivateKey = \(privateKey)
        Address = 10.7.0.2/32, fd00:7::2/128
        DNS = 10.7.0.1, corp.example
        MTU = 1380

        [Peer]
        PublicKey = \(publicKey)
        PresharedKey = \(presharedKey)
        AllowedIPs = 0.0.0.0/0
        AllowedIPs = ::/0
        Endpoint = vpn.example.com:51820
        PersistentKeepalive = 25
        """
    }

    func testParsesAWgQuickConfig() throws {
        let node = try WireGuardConfig.parse(sample)
        XCTAssertEqual(node.privateKey, privateKey)
        XCTAssertEqual(node.peerPublicKey, publicKey)
        XCTAssertEqual(node.presharedKey, presharedKey)
        XCTAssertEqual(node.addresses, ["10.7.0.2/32", "fd00:7::2/128"])
        XCTAssertEqual(node.dnsServers, ["10.7.0.1"])
        XCTAssertEqual(node.mtu, 1380)
        XCTAssertEqual(node.allowedIPs, ["0.0.0.0/0", "::/0"])
        XCTAssertEqual(node.endpointHost, "vpn.example.com")
        XCTAssertEqual(node.endpointPort, 51820)
        XCTAssertEqual(node.persistentKeepalive, 25)
    }

    func testIPv6EndpointAndDefaults() throws {
        let text = """
        [Interface]
        PrivateKey = \(privateKey)
        Address = 10.7.0.2
        [Peer]
        PublicKey = \(publicKey)
        AllowedIPs = 10.7.0.0/24
        Endpoint = [2001:db8::1]:51820
        """
        let node = try WireGuardConfig.parse(text)
        XCTAssertEqual(node.endpointHost, "2001:db8::1")
        XCTAssertNil(node.presharedKey)
        XCTAssertNil(node.mtu)
        XCTAssertNil(node.persistentKeepalive)
        XCTAssertEqual(TunnelInterface(node: node).mtu, WireGuardNode.defaultMTU)
    }

    func testRejectsBadConfigsWithoutEchoingKeys() {
        let missingPeer = "[Interface]\nPrivateKey = \(privateKey)\nAddress = 10.0.0.2/32"
        XCTAssertThrowsError(try WireGuardConfig.parse(missingPeer)) { error in
            XCTAssertEqual(error as? WireGuardConfigError, .missingField("Peer"))
        }
        let shortKey = sample.replacingOccurrences(of: privateKey, with: "c2hvcnQ=")
        XCTAssertThrowsError(try WireGuardConfig.parse(shortKey)) { error in
            XCTAssertEqual(error as? WireGuardConfigError, .invalidKey)
            XCTAssertFalse(String(describing: error).contains("c2hvcnQ"))
        }
        let twoPeers = sample + "\n[Peer]\nPublicKey = \(publicKey)\nAllowedIPs = 10.0.0.0/8\nEndpoint = a.example:1"
        XCTAssertThrowsError(try WireGuardConfig.parse(twoPeers)) { error in
            XCTAssertEqual(error as? WireGuardConfigError, .unsupportedPeerCount)
        }
        let badEndpoint = sample.replacingOccurrences(of: "vpn.example.com:51820", with: "vpn.example.com")
        XCTAssertThrowsError(try WireGuardConfig.parse(badEndpoint)) { error in
            XCTAssertEqual(error as? WireGuardConfigError, .invalidEndpoint)
        }
    }

    func testImportBuildsTheRustEnvelopeAndKeepsSecretsOutOfTheProfile() throws {
        let profile = try TunnelNodeImport.parse(sample, profileID: "default")
        XCTAssertEqual(profile.serverAddress, "vpn.example.com")
        XCTAssertEqual(profile.interface.addresses, ["10.7.0.2/32", "fd00:7::2/128"])
        XCTAssertEqual(profile.interface.includedRoutes, ["0.0.0.0/0", "::/0"])
        XCTAssertEqual(profile.config.mtu, 1380)

        let full = try XCTUnwrap(JSONSerialization.jsonObject(with: profile.config.encoded()) as? [String: Any])
        let outbound = try XCTUnwrap(full["outbound"] as? [String: Any])
        XCTAssertEqual(
            Set(outbound.keys),
            ["type", "private_key", "peer_public_key", "preshared_key", "server", "port", "persistent_keepalive_secs"]
        )
        XCTAssertEqual(outbound["type"] as? String, "wireguard")
        XCTAssertEqual(outbound["port"] as? Int, 51820)

        let stored = try profile.config.withoutSecret().encoded()
        let storedText = String(decoding: stored, as: UTF8.self)
        XCTAssertFalse(storedText.contains(privateKey))
        XCTAssertFalse(storedText.contains(presharedKey))

        let secret = NodeSecret.fromKeychainValue(try profile.config.secret.keychainValue())
        let restored = try EmbeddedRuntimeConfig.decoded(from: stored).withSecret(secret)
        XCTAssertEqual(restored, profile.config)
    }

    func testKeychainValuesSavedBeforeJSONAreShadowsocksPasswords() {
        XCTAssertEqual(NodeSecret.fromKeychainValue("AAECAwQFBgcICQoLDA0ODw=="), NodeSecret(password: "AAECAwQFBgcICQoLDA0ODw=="))
    }

    func testUnrecognizedTextIsRejected() {
        XCTAssertThrowsError(try TunnelNodeImport.parse("trojan://abc@example.com:443", profileID: "default")) { error in
            XCTAssertEqual(error as? TunnelNodeImportError, .unrecognized)
        }
    }

    func testCIDRParsingAndMasks() {
        XCTAssertEqual(CIDR.parse("10.7.0.0/24")?.ipv4SubnetMask, "255.255.255.0")
        XCTAssertEqual(CIDR.parse("10.7.0.2")?.prefixLength, 32)
        XCTAssertEqual(CIDR.parse("0.0.0.0/0")?.ipv4SubnetMask, "0.0.0.0")
        XCTAssertEqual(CIDR.parse("::/0")?.isDefaultRoute, true)
        XCTAssertEqual(CIDR.parse("fd00::1/64")?.isIPv6, true)
        XCTAssertNil(CIDR.parse("10.7.0.0/33"))
        XCTAssertNil(CIDR.parse("vpn.example.com"))
    }
}
