import Foundation
import Security

/// Keeps the MITM root certificate and its private key in the shared Keychain group, where the packet tunnel
/// extension reads them to issue leaf certificates. Like `NodeSecretStore`, errors carry only the `OSStatus`.
public enum MitmCertificateStore {
    public struct Failure: Error, Equatable {
        public let status: OSStatus
    }

    struct Item: Codable, Equatable {
        /// DER certificate, base64.
        var certificate: String
        /// ANSI X9.63 private key (04 || X || Y || D), base64.
        var privateKey: String
    }

    static let service = "networkcore.mitm-ca"
    static let account = "root"

    public static func load() throws -> MitmCertificateAuthority? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw Failure(status: status)
        }
        return try decode(data)
    }

    public static func save(_ authority: MitmCertificateAuthority) throws {
        let data = try encode(authority)
        try delete()
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            // The tunnel can start on demand while the device is locked, after the first unlock since boot.
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw Failure(status: status)
        }
    }

    public static func delete() throws {
        let identity: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(identity as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Failure(status: status)
        }
    }

    static func encode(_ authority: MitmCertificateAuthority) throws -> Data {
        let item = Item(
            certificate: authority.certificateDER.base64EncodedString(),
            privateKey: try authority.privateKeyRepresentation().base64EncodedString()
        )
        return try JSONEncoder().encode(item)
    }

    static func decode(_ data: Data) throws -> MitmCertificateAuthority {
        guard let item = try? JSONDecoder().decode(Item.self, from: data),
              let certificate = Data(base64Encoded: item.certificate),
              let key = Data(base64Encoded: item.privateKey)
        else {
            throw Failure(status: errSecDecode)
        }
        return try MitmCertificateAuthority(
            certificateDER: certificate,
            privateKey: MitmCertificateAuthority.privateKey(fromRepresentation: key)
        )
    }
}
