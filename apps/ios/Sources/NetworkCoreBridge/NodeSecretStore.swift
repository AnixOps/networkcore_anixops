import Foundation
import Security

/// Keeps node keys in the Keychain so the tunnel profile only carries a persistent reference.
///
/// Items go to the default access group, which is the first entry of `keychain-access-groups`. Both the app and
/// the packet tunnel extension list the same shared group first, so the extension can read what the app saved.
/// Errors carry only the `OSStatus`, never the key.
public enum NodeSecretStore {
    public struct Failure: Error, Equatable {
        public let status: OSStatus
    }

    static let service = "networkcore.node-key"

    /// Replaces the key saved for `account` and returns its persistent reference, for
    /// `NEVPNProtocol.passwordReference`.
    public static func save(_ password: String, account: String) throws -> Data {
        var identity: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        identity.merge(platformAttributes) { _, new in new }
        let deleted = SecItemDelete(identity as CFDictionary)
        guard deleted == errSecSuccess || deleted == errSecItemNotFound else {
            throw Failure(status: deleted)
        }

        var attributes = identity
        attributes[kSecValueData as String] = Data(password.utf8)
        // The tunnel can start on demand while the device is locked, after the first unlock since boot.
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        attributes[kSecReturnPersistentRef as String] = true
        var result: CFTypeRef?
        let status = SecItemAdd(attributes as CFDictionary, &result)
        guard status == errSecSuccess, let reference = result as? Data else {
            throw Failure(status: status)
        }
        return reference
    }

    /// Reads the key behind a persistent reference returned by `save(_:account:)`.
    public static func password(for reference: Data) throws -> String {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecValuePersistentRef as String: reference,
            kSecReturnData as String: true,
        ]
        query.merge(platformAttributes) { _, new in new }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data, let password = String(data: data, encoding: .utf8)
        else {
            throw Failure(status: status == errSecSuccess ? errSecDecode : status)
        }
        return password
    }

    /// On macOS only the data protection keychain honors `keychain-access-groups`, which the app and the tunnel
    /// extension share; the legacy file keychain would keep the key out of the extension's reach.
    private static var platformAttributes: [String: Any] {
        #if os(macOS)
        return [kSecUseDataProtectionKeychain as String: true]
        #else
        return [:]
        #endif
    }
}
