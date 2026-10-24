@testable import NetworkCoreBridge
import Security
import XCTest

final class MitmCertificateAuthorityTests: XCTestCase {
    func testGeneratedRootParsesAndIsACertificateAuthority() throws {
        let authority = try MitmCertificateAuthority.generate(commonName: "NetworkCore Test CA")

        XCTAssertEqual(authority.commonName, "NetworkCore Test CA")
        XCTAssertEqual(authority.sha256Fingerprint.split(separator: ":").count, 32)
        // The root signs itself, so it verifies as its own anchor.
        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        XCTAssertEqual(SecTrustCreateWithCertificates(authority.certificate, policy, &trust), errSecSuccess)
        let rootTrust = try XCTUnwrap(trust)
        SecTrustSetAnchorCertificates(rootTrust, [authority.certificate] as CFArray)
        var error: CFError?
        XCTAssertTrue(SecTrustEvaluateWithError(rootTrust, &error), String(describing: error))
    }

    func testLeafVerifiesForTlsWhenTheRootIsTrusted() throws {
        let authority = try MitmCertificateAuthority.generate()

        XCTAssertEqual(authority.trustState(anchors: [authority.certificate]), .trusted)
        let other = try MitmCertificateAuthority.generate()
        XCTAssertEqual(authority.trustState(anchors: [other.certificate]), .notTrusted)
    }

    func testRootIsNotTrustedBySystemStoreUntilTheUserEnablesIt() throws {
        let authority = try MitmCertificateAuthority.generate()

        XCTAssertEqual(authority.trustState(), .notTrusted)
    }

    func testLeafSubjectAndIssuerEncoding() throws {
        let authority = try MitmCertificateAuthority.generate(commonName: "Issuer Name")
        let leaf = try authority.issueLeaf(host: "api.example.com")
        let certificate = try XCTUnwrap(SecCertificateCreateWithData(nil, leaf.certificateDER as CFData))

        XCTAssertEqual(SecCertificateCopySubjectSummary(certificate) as String?, "api.example.com")
        XCTAssertEqual(
            try DER.subjectField(ofCertificate: authority.certificateDER),
            DER.name(commonName: "Issuer Name", organization: MitmCertificateAuthority.organization)
        )
    }

    func testKeychainItemRoundTripsWithoutTheKeychain() throws {
        let authority = try MitmCertificateAuthority.generate()

        let restored = try MitmCertificateStore.decode(MitmCertificateStore.encode(authority))
        XCTAssertEqual(restored.certificateDER, authority.certificateDER)
        XCTAssertEqual(try restored.privateKeyRepresentation(), try authority.privateKeyRepresentation())
        XCTAssertEqual(restored.trustState(anchors: [authority.certificate]), .trusted)
        XCTAssertThrowsError(try MitmCertificateStore.decode(Data("{}".utf8)))
    }

    func testConfigurationProfileCarriesOneRootPayload() throws {
        let authority = try MitmCertificateAuthority.generate()
        let data = try authority.configurationProfile()
        let profile = try XCTUnwrap(
            PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        )

        XCTAssertEqual(profile["PayloadType"] as? String, "Configuration")
        let payloads = try XCTUnwrap(profile["PayloadContent"] as? [[String: Any]])
        XCTAssertEqual(payloads.count, 1)
        XCTAssertEqual(payloads[0]["PayloadType"] as? String, "com.apple.security.root")
        XCTAssertEqual(payloads[0]["PayloadContent"] as? Data, authority.certificateDER)
    }

    func testDerPrimitives() {
        XCTAssertEqual(DER.oid("1.2.840.10045.4.3.2"), Data([0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02]))
        XCTAssertEqual(DER.integer(0), Data([0x02, 0x01, 0x00]))
        XCTAssertEqual(DER.integer(Data([0x00, 0x80])), Data([0x02, 0x02, 0x00, 0x80]))
        XCTAssertEqual(DER.tlv(0x04, Data(count: 200)).prefix(3), Data([0x04, 0x81, 0xC8]))
        XCTAssertEqual(DER.time(Date(timeIntervalSince1970: 0)), DER.tlv(0x17, Data("700101000000Z".utf8)))
        XCTAssertEqual(
            DER.time(Date(timeIntervalSince1970: 2_556_144_000)),
            DER.tlv(0x18, Data("20510101000000Z".utf8))
        )
    }
}
