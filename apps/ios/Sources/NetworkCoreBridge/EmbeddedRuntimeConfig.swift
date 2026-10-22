import Foundation

/// JSON config envelope for the embedded runtime, schema version 1.
///
/// Mirrors `RuntimeConfig` in crates/engine-embedded/src/config.rs. Optional DNS and limit sections are
/// left to the runtime defaults.
public struct EmbeddedRuntimeConfig: Encodable, Equatable {
    public static let schemaVersion = 1

    public struct Outbound: Encodable, Equatable {
        public let type: String
        public let server: String
        public let port: UInt16
        public let method: String
        public let password: String
    }

    public let schemaVersion: Int
    public let profileID: String
    public let mtu: Int
    public let outbound: Outbound

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

    public func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }
}

/// Keys shared by the app and the extension in `NETunnelProviderProtocol.providerConfiguration`.
public enum TunnelProfileKeys {
    /// `Data` holding the encoded `EmbeddedRuntimeConfig`.
    public static let runtimeConfig = "networkcore.runtime-config"
    /// Display name of the imported node. Not secret.
    public static let nodeName = "networkcore.node-name"
}
