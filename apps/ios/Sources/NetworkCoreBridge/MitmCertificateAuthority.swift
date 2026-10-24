import CryptoKit
import Foundation
import Security

/// The device's HTTPS decryption (MITM) root certificate.
///
/// The app creates it once with a P-256 key from the Security framework, so no Rust code runs in the app. The
/// packet tunnel extension later reads the same key from the shared Keychain group to issue per-host leaf
/// certificates. iOS only uses the root for TLS after the user installs its configuration profile and turns on
/// full trust in Settings > General > About > Certificate Trust Settings; `trustState(certificate:signingKey:)`
/// detects that last step.
public struct MitmCertificateAuthority {
    public enum Failure: Error, Equatable {
        case keyGeneration(String)
        case signing(String)
        case invalidCertificate
        case invalidKey
    }

    /// Issued leaf certificates stay under Apple's 825-day limit for TLS server certificates.
    public static let leafValidityDays = 397
    public static let rootValidityDays = 3650
    public static let organization = "AnixOps Net"

    public let certificate: SecCertificate
    public let certificateDER: Data
    public let privateKey: SecKey

    public init(certificateDER: Data, privateKey: SecKey) throws {
        guard let certificate = SecCertificateCreateWithData(nil, certificateDER as CFData) else {
            throw Failure.invalidCertificate
        }
        self.certificate = certificate
        self.certificateDER = certificateDER
        self.privateKey = privateKey
    }

    /// Creates a new root valid from one day ago (clock skew) for `rootValidityDays`.
    public static func generate(commonName: String? = nil, now: Date = Date()) throws -> MitmCertificateAuthority {
        let key = try makeKey()
        let publicPoint = try publicKeyPoint(key)
        let name = DER.name(
            commonName: commonName ?? defaultCommonName(now: now),
            organization: organization
        )
        let keyIdentifier = Data(Insecure.SHA1.hash(data: publicPoint))
        let extensions = [
            DER.certificateExtension(DER.OID.basicConstraints, critical: true, value: DER.sequence(DER.boolean(true), DER.integer(0))),
            // keyCertSign and cRLSign.
            DER.certificateExtension(DER.OID.keyUsage, critical: true, value: DER.bitString(Data([0x06]), unusedBits: 1)),
            DER.certificateExtension(DER.OID.subjectKeyIdentifier, critical: false, value: DER.octetString(keyIdentifier)),
        ]
        let der = try signCertificate(
            serial: randomSerial(),
            issuer: name,
            subject: name,
            notBefore: now.addingTimeInterval(-86_400),
            notAfter: now.addingTimeInterval(Double(rootValidityDays) * 86_400),
            subjectPublicKeyPoint: publicPoint,
            extensions: extensions,
            signer: key
        )
        return try MitmCertificateAuthority(certificateDER: der, privateKey: key)
    }

    /// Issues a TLS server certificate for `host`, signed by this root. The leaf reuses a fresh P-256 key.
    public func issueLeaf(host: String, now: Date = Date()) throws -> (certificateDER: Data, privateKey: SecKey) {
        let key = try Self.makeKey()
        let publicPoint = try Self.publicKeyPoint(key)
        let issuerPoint = try Self.publicKeyPoint(privateKey)
        let issuer = try DER.subjectField(ofCertificate: certificateDER)
        let extensions = [
            DER.certificateExtension(DER.OID.basicConstraints, critical: true, value: DER.sequence()),
            // digitalSignature.
            DER.certificateExtension(DER.OID.keyUsage, critical: true, value: DER.bitString(Data([0x80]), unusedBits: 7)),
            DER.certificateExtension(DER.OID.extendedKeyUsage, critical: false, value: DER.sequence(DER.oid(DER.OID.serverAuth))),
            DER.certificateExtension(
                DER.OID.subjectAltName,
                critical: false,
                value: DER.sequence(DER.tlv(0x82, Data(host.utf8)))
            ),
            DER.certificateExtension(
                DER.OID.authorityKeyIdentifier,
                critical: false,
                value: DER.sequence(DER.tlv(0x80, Data(Insecure.SHA1.hash(data: issuerPoint))))
            ),
        ]
        let der = try Self.signCertificate(
            serial: Self.randomSerial(),
            issuer: issuer,
            subject: DER.name(commonName: host, organization: nil),
            notBefore: now.addingTimeInterval(-86_400),
            notAfter: now.addingTimeInterval(Double(Self.leafValidityDays) * 86_400),
            subjectPublicKeyPoint: publicPoint,
            extensions: extensions,
            signer: privateKey
        )
        return (der, key)
    }

    /// The SHA-256 fingerprint shown to the user so they can match it in Settings.
    public var sha256Fingerprint: String {
        SHA256.hash(data: certificateDER).map { String(format: "%02X", $0) }.joined(separator: ":")
    }

    public var commonName: String {
        (SecCertificateCopySubjectSummary(certificate) as String?) ?? Self.organization
    }

    /// The private key as ANSI X9.63 bytes (04 || X || Y || D), the form the Keychain item stores.
    public func privateKeyRepresentation() throws -> Data {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else {
            throw Failure.invalidKey
        }
        return data
    }

    public static func privateKey(fromRepresentation data: Data) throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 256,
        ]
        guard let key = SecKeyCreateWithData(data as CFData, attributes as CFDictionary, nil) else {
            throw Failure.invalidKey
        }
        return key
    }

    static func defaultCommonName(now: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        formatter.dateFormat = "yyyyMMdd-HHmm"
        return "\(organization) MITM CA \(formatter.string(from: now))"
    }

    private static func makeKey() throws -> SecKey {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw Failure.keyGeneration(error.map { String(describing: $0.takeRetainedValue()) } ?? "unknown")
        }
        return key
    }

    /// The uncompressed public point (04 || X || Y) of a P-256 key.
    private static func publicKeyPoint(_ key: SecKey) throws -> Data {
        let publicKey = SecKeyCopyPublicKey(key) ?? key
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?, data.count >= 65 else {
            throw Failure.invalidKey
        }
        return data.prefix(65)
    }

    private static func randomSerial() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        bytes[0] &= 0x7F
        bytes[0] |= 0x01
        return Data(bytes)
    }

    private static func signCertificate(
        serial: Data,
        issuer: Data,
        subject: Data,
        notBefore: Date,
        notAfter: Date,
        subjectPublicKeyPoint: Data,
        extensions: [Data],
        signer: SecKey
    ) throws -> Data {
        let signatureAlgorithm = DER.sequence(DER.oid(DER.OID.ecdsaWithSHA256))
        let subjectPublicKeyInfo = DER.sequence(
            DER.sequence(DER.oid(DER.OID.ecPublicKey), DER.oid(DER.OID.prime256v1)),
            DER.bitString(subjectPublicKeyPoint, unusedBits: 0)
        )
        let tbs = DER.sequence(
            DER.tlv(0xA0, DER.integer(2)),
            DER.integer(serial),
            signatureAlgorithm,
            issuer,
            DER.sequence(DER.time(notBefore), DER.time(notAfter)),
            subject,
            subjectPublicKeyInfo,
            DER.tlv(0xA3, DER.sequence(extensions))
        )
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            signer,
            .ecdsaSignatureMessageX962SHA256,
            tbs as CFData,
            &error
        ) as Data? else {
            throw Failure.signing(error.map { String(describing: $0.takeRetainedValue()) } ?? "unknown")
        }
        return DER.sequence(tbs, signatureAlgorithm, DER.bitString(signature, unusedBits: 0))
    }
}

// MARK: - Trust state

/// Where the user is in the trust flow.
public enum MitmTrustState: String, Codable, Equatable {
    /// No root certificate yet.
    case notGenerated
    /// The root exists, but iOS does not trust it for TLS: the profile is not installed, or full trust is off.
    case notTrusted
    /// iOS accepts leaf certificates signed by the root.
    case trusted
}

extension MitmCertificateAuthority {
    static let trustProbeHost = "trust-probe.networkcore.test"

    /// Issues a probe leaf and asks iOS whether it would accept it for TLS. Pass `anchors` only in tests; in the
    /// app the system trust store decides, which includes user roots with full trust turned on.
    public func trustState(anchors: [SecCertificate]? = nil, now: Date = Date()) -> MitmTrustState {
        guard let leaf = try? issueLeaf(host: Self.trustProbeHost, now: now),
              let leafCertificate = SecCertificateCreateWithData(nil, leaf.certificateDER as CFData)
        else {
            return .notTrusted
        }
        var trust: SecTrust?
        let policy = SecPolicyCreateSSL(true, Self.trustProbeHost as CFString)
        guard SecTrustCreateWithCertificates([leafCertificate, certificate] as CFArray, policy, &trust) == errSecSuccess,
              let trust
        else {
            return .notTrusted
        }
        SecTrustSetNetworkFetchAllowed(trust, false)
        SecTrustSetVerifyDate(trust, now as CFDate)
        if let anchors {
            SecTrustSetAnchorCertificates(trust, anchors as CFArray)
        }
        return SecTrustEvaluateWithError(trust, nil) ? .trusted : .notTrusted
    }
}

// MARK: - Configuration profile

extension MitmCertificateAuthority {
    public static let profileContentType = "application/x-apple-aspen-config"

    /// A configuration profile with one `com.apple.security.root` payload, which iOS installs from Safari or Files.
    public func configurationProfile(identifier: String = "net.anixops.networkcore.mitm-ca") throws -> Data {
        let name = commonName
        let payload: [String: Any] = [
            "PayloadCertificateFileName": "\(name).cer",
            "PayloadContent": certificateDER,
            "PayloadDescription": "HTTPS decryption root certificate generated on this device.",
            "PayloadDisplayName": name,
            "PayloadIdentifier": "\(identifier).root",
            "PayloadType": "com.apple.security.root",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1,
        ]
        let profile: [String: Any] = [
            "PayloadContent": [payload],
            "PayloadDescription": "Lets \(Self.organization) decrypt HTTPS for hosts listed in your MITM settings.",
            "PayloadDisplayName": name,
            "PayloadIdentifier": identifier,
            "PayloadOrganization": Self.organization,
            "PayloadRemovalDisallowed": false,
            "PayloadType": "Configuration",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1,
        ]
        return try PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0)
    }
}

// MARK: - DER

/// The small DER subset needed for X.509 certificates.
enum DER {
    enum OID {
        static let commonName = "2.5.4.3"
        static let organizationName = "2.5.4.10"
        static let ecPublicKey = "1.2.840.10045.2.1"
        static let prime256v1 = "1.2.840.10045.3.1.7"
        static let ecdsaWithSHA256 = "1.2.840.10045.4.3.2"
        static let subjectKeyIdentifier = "2.5.29.14"
        static let keyUsage = "2.5.29.15"
        static let subjectAltName = "2.5.29.17"
        static let basicConstraints = "2.5.29.19"
        static let authorityKeyIdentifier = "2.5.29.35"
        static let extendedKeyUsage = "2.5.29.37"
        static let serverAuth = "1.3.6.1.5.5.7.3.1"
    }

    static func tlv(_ tag: UInt8, _ content: Data) -> Data {
        var out = Data([tag])
        let length = content.count
        if length < 0x80 {
            out.append(UInt8(length))
        } else {
            var bytes = [UInt8]()
            var remaining = length
            while remaining > 0 {
                bytes.insert(UInt8(remaining & 0xFF), at: 0)
                remaining >>= 8
            }
            out.append(0x80 | UInt8(bytes.count))
            out.append(contentsOf: bytes)
        }
        out.append(content)
        return out
    }

    static func sequence(_ parts: Data...) -> Data {
        sequence(parts)
    }

    static func sequence(_ parts: [Data]) -> Data {
        tlv(0x30, parts.reduce(into: Data()) { $0.append($1) })
    }

    static func set(_ parts: Data...) -> Data {
        tlv(0x31, parts.reduce(into: Data()) { $0.append($1) })
    }

    static func boolean(_ value: Bool) -> Data {
        tlv(0x01, Data([value ? 0xFF : 0x00]))
    }

    static func integer(_ value: Int) -> Data {
        var bytes = [UInt8]()
        var remaining = value
        repeat {
            bytes.insert(UInt8(remaining & 0xFF), at: 0)
            remaining >>= 8
        } while remaining > 0
        return integer(Data(bytes))
    }

    /// A non-negative integer from big-endian bytes, minimally encoded.
    static func integer(_ bytes: Data) -> Data {
        var trimmed = Array(bytes.drop { $0 == 0 })
        if trimmed.isEmpty {
            trimmed = [0]
        }
        if trimmed[0] & 0x80 != 0 {
            trimmed.insert(0, at: 0)
        }
        return tlv(0x02, Data(trimmed))
    }

    static func oid(_ dotted: String) -> Data {
        let arcs = dotted.split(separator: ".").compactMap { UInt64($0) }
        var body = Data()
        guard arcs.count >= 2 else {
            return tlv(0x06, body)
        }
        body.append(contentsOf: base128(arcs[0] * 40 + arcs[1]))
        for arc in arcs.dropFirst(2) {
            body.append(contentsOf: base128(arc))
        }
        return tlv(0x06, body)
    }

    static func utf8String(_ text: String) -> Data {
        tlv(0x0C, Data(text.utf8))
    }

    static func octetString(_ data: Data) -> Data {
        tlv(0x04, data)
    }

    static func bitString(_ data: Data, unusedBits: UInt8) -> Data {
        tlv(0x03, Data([unusedBits]) + data)
    }

    /// UTCTime through 2049, GeneralizedTime after, as RFC 5280 requires.
    static func time(_ date: Date) -> Data {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let year = calendar.component(.year, from: date)
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "UTC")
        if year < 2050 {
            formatter.dateFormat = "yyMMddHHmmss'Z'"
            return tlv(0x17, Data(formatter.string(from: date).utf8))
        }
        formatter.dateFormat = "yyyyMMddHHmmss'Z'"
        return tlv(0x18, Data(formatter.string(from: date).utf8))
    }

    static func name(commonName: String, organization: String?) -> Data {
        var rdns = [set(sequence(oid(OID.commonName), utf8String(commonName)))]
        if let organization {
            rdns.append(set(sequence(oid(OID.organizationName), utf8String(organization))))
        }
        return sequence(rdns)
    }

    static func certificateExtension(_ identifier: String, critical: Bool, value: Data) -> Data {
        critical
            ? sequence(oid(identifier), boolean(true), octetString(value))
            : sequence(oid(identifier), octetString(value))
    }

    /// The encoded subject of a certificate this module produced, copied byte for byte so a leaf's issuer
    /// matches the root's subject exactly.
    static func subjectField(ofCertificate der: Data) throws -> Data {
        var certificate = Reader(der)
        var tbs = try Reader(certificate.read(expecting: 0x30).content)
        var fields = try Reader(tbs.read(expecting: 0x30).content)
        if fields.peekTag == 0xA0 {
            _ = try fields.read(expecting: 0xA0)
        }
        _ = try fields.read(expecting: 0x02) // serial
        _ = try fields.read(expecting: 0x30) // signature algorithm
        _ = try fields.read(expecting: 0x30) // issuer
        _ = try fields.read(expecting: 0x30) // validity
        return try fields.read(expecting: 0x30).encoded
    }

    private static func base128(_ value: UInt64) -> [UInt8] {
        var bytes = [UInt8(value & 0x7F)]
        var remaining = value >> 7
        while remaining > 0 {
            bytes.insert(UInt8(remaining & 0x7F) | 0x80, at: 0)
            remaining >>= 7
        }
        return bytes
    }

    struct Reader {
        struct Element {
            let content: Data
            let encoded: Data
        }

        private let data: [UInt8]
        private var offset = 0

        init(_ data: Data) {
            self.data = Array(data)
        }

        var peekTag: UInt8? {
            offset < data.count ? data[offset] : nil
        }

        mutating func read(expecting tag: UInt8) throws -> Element {
            let start = offset
            guard offset + 2 <= data.count, data[offset] == tag else {
                throw MitmCertificateAuthority.Failure.invalidCertificate
            }
            offset += 1
            var length = Int(data[offset])
            offset += 1
            if length & 0x80 != 0 {
                let count = length & 0x7F
                guard count > 0, count <= 4, offset + count <= data.count else {
                    throw MitmCertificateAuthority.Failure.invalidCertificate
                }
                length = 0
                for _ in 0 ..< count {
                    length = (length << 8) | Int(data[offset])
                    offset += 1
                }
            }
            guard offset + length <= data.count else {
                throw MitmCertificateAuthority.Failure.invalidCertificate
            }
            let content = Data(data[offset ..< offset + length])
            offset += length
            return Element(content: content, encoded: Data(data[start ..< offset]))
        }
    }
}
