import Foundation

/// JSON config envelope for the embedded runtime, schema version 1.
///
/// Mirrors `RuntimeConfig` in crates/engine-embedded/src/config.rs. Optional DNS and limit sections are
/// left to the runtime defaults.
///
/// The tunnel profile stores this config without its secrets (`withoutSecret()`); they live in the Keychain
/// behind `NETunnelProviderProtocol.passwordReference` as a `NodeSecret`, and the extension restores them with
/// `withSecret(_:)` just before handing the config to the runtime.
public struct EmbeddedRuntimeConfig: Codable, Equatable {
    public static let schemaVersion = 1

    public enum Outbound: Equatable {
        case shadowsocks(server: String, port: UInt16, method: String, password: String)
        case wireguard(WireGuardPeer)
    }

    /// One WireGuard peer, keys in standard base64.
    public struct WireGuardPeer: Equatable {
        public var privateKey: String
        public var peerPublicKey: String
        public var presharedKey: String?
        public var server: String
        public var port: UInt16
        public var persistentKeepaliveSecs: UInt16?
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
        outbound = .shadowsocks(server: node.host, port: node.port, method: node.method, password: node.password)
    }

    public init(node: WireGuardNode, profileID: String) {
        schemaVersion = Self.schemaVersion
        self.profileID = profileID
        mtu = node.mtu ?? WireGuardNode.defaultMTU
        outbound = .wireguard(
            WireGuardPeer(
                privateKey: node.privateKey,
                peerPublicKey: node.peerPublicKey,
                presharedKey: node.presharedKey,
                server: node.endpointHost,
                port: node.endpointPort,
                persistentKeepaliveSecs: node.persistentKeepalive
            )
        )
    }

    /// The secrets this config carries, for the Keychain.
    public var secret: NodeSecret {
        switch outbound {
        case let .shadowsocks(_, _, _, password):
            return NodeSecret(password: password)
        case let .wireguard(peer):
            return NodeSecret(privateKey: peer.privateKey, presharedKey: peer.presharedKey)
        }
    }

    /// The same config with every secret removed, for storing in the tunnel profile.
    public func withoutSecret() -> EmbeddedRuntimeConfig {
        withSecret(NodeSecret())
    }

    /// The same config with its secrets set from `secret`.
    public func withSecret(_ secret: NodeSecret) -> EmbeddedRuntimeConfig {
        var copy = self
        switch outbound {
        case let .shadowsocks(server, port, method, _):
            copy.outbound = .shadowsocks(server: server, port: port, method: method, password: secret.password ?? "")
        case var .wireguard(peer):
            peer.privateKey = secret.privateKey ?? ""
            peer.presharedKey = secret.presharedKey
            copy.outbound = .wireguard(peer)
        }
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

extension EmbeddedRuntimeConfig.Outbound: Codable {
    enum CodingKeys: String, CodingKey {
        case type
        case server
        case port
        case method
        case password
        case privateKey = "private_key"
        case peerPublicKey = "peer_public_key"
        case presharedKey = "preshared_key"
        case persistentKeepaliveSecs = "persistent_keepalive_secs"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        let server = try container.decode(String.self, forKey: .server)
        let port = try container.decode(UInt16.self, forKey: .port)
        switch type {
        case "shadowsocks":
            self = .shadowsocks(
                server: server,
                port: port,
                method: try container.decode(String.self, forKey: .method),
                password: try container.decode(String.self, forKey: .password)
            )
        case "wireguard":
            self = .wireguard(
                EmbeddedRuntimeConfig.WireGuardPeer(
                    privateKey: try container.decode(String.self, forKey: .privateKey),
                    peerPublicKey: try container.decode(String.self, forKey: .peerPublicKey),
                    presharedKey: try container.decodeIfPresent(String.self, forKey: .presharedKey),
                    server: server,
                    port: port,
                    persistentKeepaliveSecs: try container.decodeIfPresent(UInt16.self, forKey: .persistentKeepaliveSecs)
                )
            )
        default:
            throw DecodingError.dataCorruptedError(forKey: .type, in: container, debugDescription: "unknown outbound type")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .shadowsocks(server, port, method, password):
            try container.encode("shadowsocks", forKey: .type)
            try container.encode(server, forKey: .server)
            try container.encode(port, forKey: .port)
            try container.encode(method, forKey: .method)
            try container.encode(password, forKey: .password)
        case let .wireguard(peer):
            try container.encode("wireguard", forKey: .type)
            try container.encode(peer.server, forKey: .server)
            try container.encode(peer.port, forKey: .port)
            try container.encode(peer.privateKey, forKey: .privateKey)
            try container.encode(peer.peerPublicKey, forKey: .peerPublicKey)
            try container.encodeIfPresent(peer.presharedKey, forKey: .presharedKey)
            try container.encodeIfPresent(peer.persistentKeepaliveSecs, forKey: .persistentKeepaliveSecs)
        }
    }
}

/// Secrets of one node as stored in the Keychain: a small JSON object.
public struct NodeSecret: Codable, Equatable {
    public var password: String?
    public var privateKey: String?
    public var presharedKey: String?

    enum CodingKeys: String, CodingKey {
        case password
        case privateKey = "private_key"
        case presharedKey = "preshared_key"
    }

    public init(password: String? = nil, privateKey: String? = nil, presharedKey: String? = nil) {
        self.password = password
        self.privateKey = privateKey
        self.presharedKey = presharedKey
    }

    /// The value written to the Keychain.
    public func keychainValue() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return String(decoding: try encoder.encode(self), as: UTF8.self)
    }

    /// Reads a Keychain value. Items saved before secrets became JSON hold the bare Shadowsocks password.
    public static func fromKeychainValue(_ value: String) -> NodeSecret {
        if let data = value.data(using: .utf8),
           let secret = try? JSONDecoder().decode(NodeSecret.self, from: data),
           secret != NodeSecret()
        {
            return secret
        }
        return NodeSecret(password: value)
    }
}

/// Keys shared by the app and the extension in `NETunnelProviderProtocol.providerConfiguration`.
public enum TunnelProfileKeys {
    /// `Data` holding the encoded `EmbeddedRuntimeConfig`, without secrets.
    public static let runtimeConfig = "networkcore.runtime-config"
    /// `Data` holding the encoded `TunnelInterface`. Profiles saved before it existed use `TunnelInterface.proxy`.
    public static let tunnelInterface = "networkcore.tunnel-interface"
    /// Display name of the imported node. Not secret.
    public static let nodeName = "networkcore.node-name"
}
