import Foundation

/// JSON config envelope for the embedded runtime, schema version 1.
///
/// Mirrors `RuntimeConfig` in crates/engine-embedded/src/config.rs. Optional DNS and limit sections are
/// left to the runtime defaults.
///
/// The tunnel profile stores this config with an empty password (`withoutSecret()`); the node key lives in the
/// Keychain behind `NETunnelProviderProtocol.passwordReference` and the extension restores it with
/// `withPassword(_:)` just before handing the config to the runtime.
public struct EmbeddedRuntimeConfig: Codable, Equatable {
    public static let schemaVersion = 1

    public struct Outbound: Codable, Equatable {
        public let type: String
        public let server: String
        public let port: UInt16
        public let method: String
        public let password: String
    }

    public let schemaVersion: Int
    public let profileID: String
    public let mtu: Int
    public private(set) var outbound: Outbound

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case profileID = "profile_id"
        case mtu
        case outbound
    }

    public init(node: ShadowsocksNode, profileID: String, mtu: Int = 1500) {
        schemaVersion = Self.schemaVersion
        self.profileID = profileID
        self.mtu = mtu
        outbound = Outbound(
            type: "shadowsocks",
            server: node.host,
            port: node.port,
            method: node.method,
            password: node.password
        )
    }

    /// The same config with the node key removed, for storing in the tunnel profile.
    public func withoutSecret() -> EmbeddedRuntimeConfig {
        withPassword("")
    }

    /// The same config with the node key set.
    public func withPassword(_ password: String) -> EmbeddedRuntimeConfig {
        var copy = self
        copy.outbound = Outbound(
            type: outbound.type,
            server: outbound.server,
            port: outbound.port,
            method: outbound.method,
            password: password
        )
        return copy
    }

    public static func decoded(from data: Data) throws -> EmbeddedRuntimeConfig {
        try JSONDecoder().decode(EmbeddedRuntimeConfig.self, from: data)
    }

    public func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }
}

/// Keys shared by the app and the extension in `NETunnelProviderProtocol.providerConfiguration`.
public enum TunnelProfileKeys {
    /// `Data` holding the encoded `EmbeddedRuntimeConfig`, without the node key.
    public static let runtimeConfig = "networkcore.runtime-config"
    /// Display name of the imported node. Not secret.
    public static let nodeName = "networkcore.node-name"
}
