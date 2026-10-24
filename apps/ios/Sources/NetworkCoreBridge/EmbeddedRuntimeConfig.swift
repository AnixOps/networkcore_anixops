import Foundation

/// JSON config envelope for the embedded runtime, schema version 1.
///
/// Mirrors `RuntimeConfig` in crates/engine-embedded/src/config.rs. Optional DNS and limit sections are
/// left to the runtime defaults.
///
/// The tunnel profile stores this config without its secrets (`withoutSecret()`); they live in the Keychain
/// behind `NETunnelProviderProtocol.passwordReference` as a `NodeSecret`, and the extension restores them with
/// `withSecret(_:)` just before handing the config to the runtime. To follow a subscription's rules it also adds the
/// `routing` section from the node library (`withRouting(_:)`), which replaces `outbound` in the encoded envelope.
public struct EmbeddedRuntimeConfig: Codable, Equatable {
    public static let schemaVersion = 1

    public enum Outbound: Equatable {
        case shadowsocks(server: String, port: UInt16, method: String, password: String)
        case wireguard(WireGuardPeer)
        case vless(VlessOutbound)
        /// Any other outbound the runtime registry knows, as the Rust importer produced it.
        case native(NativeOutbound)
    }

    /// An outbound the app passes through without interpreting: Trojan, VMess, VLESS over TLS, Hysteria2, TUIC
    /// and the rest of crates/node-import's output. `settings` (everything but the type and address) is the
    /// secret: it holds the password or user id, and the profile keeps only `type`, `server` and `port`.
    public struct NativeOutbound: Equatable {
        static let addressKeys: Set<String> = ["type", "server", "port"]

        public var type: String
        public var server: String
        public var port: UInt16
        public var settings: [String: JSONValue]

        public init(type: String, server: String, port: UInt16, settings: [String: JSONValue]) {
            self.type = type
            self.server = server
            self.port = port
            self.settings = settings
        }
    }

    /// One VLESS + REALITY server. `uuid` is the secret.
    public struct VlessOutbound: Equatable {
        public var server: String
        public var port: UInt16
        public var uuid: String
        public var flow: String
        public var reality: RealitySettings
    }

    public struct RealitySettings: Codable, Equatable {
        public var serverName: String
        public var publicKey: String
        public var shortID: String
        public var fingerprint: String

        enum CodingKeys: String, CodingKey {
            case serverName = "server_name"
            case publicKey = "public_key"
            case shortID = "short_id"
            case fingerprint
        }
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

    /// The `mitm` section: enabled plugin texts and the device root. It holds the root's private key, so it is
    /// never stored in the tunnel profile; the extension adds it with `withMitm(plugins:authority:)`.
    public struct Mitm: Codable, Equatable {
        public var plugins: [String]
        /// Root certificate, base64 DER.
        public var caCertificate: String
        /// Root private key, base64 X9.63.
        public var caPrivateKey: String

        enum CodingKeys: String, CodingKey {
            case plugins
            case caCertificate = "ca_certificate"
            case caPrivateKey = "ca_private_key"
        }
    }

    /// The `routing` section: every subscription node by id, with the subscription's rules and policy groups. It
    /// holds every node's credentials, so it is never stored in the tunnel profile; the extension builds it from the
    /// node library (`NodeLibrary.runtimeRouting()`).
    public struct Routing: Codable, Equatable {
        public var outbounds: [String: [String: JSONValue]]
        public var rules: [String]
        public var groups: [NativeImportReport.Routing.Group]

        public init(outbounds: [String: [String: JSONValue]], rules: [String], groups: [NativeImportReport.Routing.Group]) {
            self.outbounds = outbounds
            self.rules = rules
            self.groups = groups
        }
    }

    public let schemaVersion: Int
    public let profileID: String
    public let mtu: Int
    /// The selected node. With `routing` set it is left out of the encoded envelope, which carries exactly one of
    /// the two; it still names the node for the app and diagnostics.
    public private(set) var outbound: Outbound
    public private(set) var routing: Routing?
    public private(set) var mitm: Mitm?

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case profileID = "profile_id"
        case mtu
        case outbound
        case routing
        case mitm
    }

    /// Only the extension encodes a routed config, and only for the runtime; nothing decodes one.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(schemaVersion, forKey: .schemaVersion)
        try container.encode(profileID, forKey: .profileID)
        try container.encode(mtu, forKey: .mtu)
        if let routing {
            try container.encode(routing, forKey: .routing)
        } else {
            try container.encode(outbound, forKey: .outbound)
        }
        try container.encodeIfPresent(mitm, forKey: .mitm)
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

    public init(node: VlessNode, profileID: String, mtu: Int = 1500) {
        schemaVersion = Self.schemaVersion
        self.profileID = profileID
        self.mtu = mtu
        outbound = .vless(
            VlessOutbound(
                server: node.host,
                port: node.port,
                uuid: node.uuid,
                flow: node.flow,
                reality: RealitySettings(
                    serverName: node.serverName,
                    publicKey: node.publicKey,
                    shortID: node.shortID,
                    fingerprint: "chrome"
                )
            )
        )
    }

    public init(outbound: Outbound, profileID: String, mtu: Int = 1500) {
        schemaVersion = Self.schemaVersion
        self.profileID = profileID
        self.mtu = mtu
        self.outbound = outbound
    }

    /// The secrets this config carries, for the Keychain.
    public var secret: NodeSecret {
        switch outbound {
        case let .shadowsocks(_, _, _, password):
            return NodeSecret(password: password)
        case let .wireguard(peer):
            return NodeSecret(privateKey: peer.privateKey, presharedKey: peer.presharedKey)
        case let .vless(vless):
            return NodeSecret(uuid: vless.uuid)
        case let .native(native):
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let settings = (try? encoder.encode(native.settings)).map { String(decoding: $0, as: UTF8.self) }
            return NodeSecret(outbound: settings)
        }
    }

    /// The same config with every secret removed, for storing in the tunnel profile.
    public func withoutSecret() -> EmbeddedRuntimeConfig {
        var copy = withSecret(NodeSecret())
        copy.mitm = nil
        copy.routing = nil
        return copy
    }

    /// The same config routing by a subscription's rules and groups; nil goes back to the selected node alone.
    public func withRouting(_ routing: Routing?) -> EmbeddedRuntimeConfig {
        var copy = self
        copy.routing = routing
        return copy
    }

    /// The same config decrypting HTTPS for the plugins' hosts with `authority`. No plugins removes the section.
    public func withMitm(plugins: [String], authority: MitmCertificateAuthority) throws -> EmbeddedRuntimeConfig {
        var copy = self
        copy.mitm = plugins.isEmpty ? nil : Mitm(
            plugins: plugins,
            caCertificate: authority.certificateDER.base64EncodedString(),
            caPrivateKey: try authority.privateKeyRepresentation().base64EncodedString()
        )
        return copy
    }

    /// The same config without HTTPS decryption.
    public func withoutMitm() -> EmbeddedRuntimeConfig {
        var copy = self
        copy.mitm = nil
        return copy
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
        case var .vless(vless):
            vless.uuid = secret.uuid ?? ""
            copy.outbound = .vless(vless)
        case var .native(native):
            native.settings = secret.outbound
                .flatMap { try? JSONDecoder().decode([String: JSONValue].self, from: Data($0.utf8)) } ?? [:]
            copy.outbound = .native(native)
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
        case uuid
        case flow
        case reality
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
        // VLESS over TLS or a transport is a native outbound; only REALITY has its own case.
        case "vless" where container.contains(.reality):
            self = .vless(
                EmbeddedRuntimeConfig.VlessOutbound(
                    server: server,
                    port: port,
                    uuid: try container.decode(String.self, forKey: .uuid),
                    flow: try container.decodeIfPresent(String.self, forKey: .flow) ?? "",
                    reality: try container.decode(EmbeddedRuntimeConfig.RealitySettings.self, forKey: .reality)
                )
            )
        default:
            var settings: [String: JSONValue] = [:]
            let all = try decoder.container(keyedBy: DynamicCodingKey.self)
            for key in all.allKeys where !EmbeddedRuntimeConfig.NativeOutbound.addressKeys.contains(key.stringValue) {
                settings[key.stringValue] = try all.decode(JSONValue.self, forKey: key)
            }
            self = .native(EmbeddedRuntimeConfig.NativeOutbound(type: type, server: server, port: port, settings: settings))
        }
    }

    public func encode(to encoder: Encoder) throws {
        if case let .native(native) = self {
            var all = encoder.container(keyedBy: DynamicCodingKey.self)
            for (key, value) in native.settings where !EmbeddedRuntimeConfig.NativeOutbound.addressKeys.contains(key) {
                try all.encode(value, forKey: DynamicCodingKey(key))
            }
            try all.encode(native.type, forKey: DynamicCodingKey("type"))
            try all.encode(native.server, forKey: DynamicCodingKey("server"))
            try all.encode(native.port, forKey: DynamicCodingKey("port"))
            return
        }
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
        case let .vless(vless):
            try container.encode("vless", forKey: .type)
            try container.encode(vless.server, forKey: .server)
            try container.encode(vless.port, forKey: .port)
            try container.encode(vless.uuid, forKey: .uuid)
            try container.encode(vless.flow, forKey: .flow)
            try container.encode(vless.reality, forKey: .reality)
        case .native:
            // Encoded above.
            break
        }
    }
}

/// Secrets of one node as stored in the Keychain: a small JSON object.
public struct NodeSecret: Codable, Equatable {
    public var password: String?
    public var privateKey: String?
    public var presharedKey: String?
    /// VLESS user id.
    public var uuid: String?
    /// JSON settings of a native outbound (`EmbeddedRuntimeConfig.NativeOutbound.settings`).
    public var outbound: String?

    enum CodingKeys: String, CodingKey {
        case password
        case privateKey = "private_key"
        case presharedKey = "preshared_key"
        case uuid
        case outbound
    }

    public init(
        password: String? = nil,
        privateKey: String? = nil,
        presharedKey: String? = nil,
        uuid: String? = nil,
        outbound: String? = nil
    ) {
        self.password = password
        self.privateKey = privateKey
        self.presharedKey = presharedKey
        self.uuid = uuid
        self.outbound = outbound
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
    /// `true` when the tunnel follows the subscription's rules and groups: the extension then adds the `routing`
    /// section from the node library in the Keychain (`NodeLibrary.keychainAccount`). Absent means the selected node
    /// carries all traffic.
    public static let routing = "networkcore.routing"
    /// `Data` holding a JSON array of the enabled MITM plugin texts (`MitmPluginLibrary.profileValue`). Absent or
    /// empty means no HTTPS decryption.
    public static let mitmPlugins = "networkcore.mitm-plugins"
}
