import Foundation

/// The node list the Rust importer (crates/node-import) returns for a subscription text: share links of every
/// protocol the engine runs, base64 link lists, Clash YAML, JSON outbound configs and Surge, Loon or Quantumult X proxy
/// lines. The app calls the C ABI and hands the JSON here, so this part needs no Rust library and is tested on its
/// own.
public struct NativeImportReport: Decodable, Equatable {
    public struct Node: Codable, Equatable, Identifiable {
        public let id: String
        public let name: String
        /// The outbound `type`, for example `trojan` or `hysteria2`.
        public let `protocol`: String
        public let server: String
        public let port: UInt16
        /// The runtime outbound entry, credentials included.
        public let outbound: [String: JSONValue]
    }

    /// A node that was recognized but cannot run. `reason` is fixed text without node values.
    public struct Unsupported: Decodable, Equatable {
        public let name: String
        public let `protocol`: String
        public let reason: String
    }

    /// The subscription's rules and policy groups, as the engine's `routing` section without its outbounds. The
    /// importer offers them only when every node can run; rules and group members name nodes by `Node.id`, groups
    /// by `Group.id`, or `DIRECT` and `REJECT`.
    public struct Routing: Codable, Equatable {
        public struct Group: Codable, Equatable, Identifiable {
            public let id: String
            /// `select`, `url-test` or `fallback`.
            public let type: String
            public let members: [String]
            /// The member a `select` group starts on.
            public var `default`: String?
            public let url: String?
            public let intervalSecs: UInt32?
            public let toleranceMs: UInt16?

            enum CodingKeys: String, CodingKey {
                case id
                case type
                case members
                case `default`
                case url
                case intervalSecs = "interval_secs"
                case toleranceMs = "tolerance_ms"
            }

            public var isSelectable: Bool {
                type == "select"
            }
        }

        public let rules: [String]
        public let groups: [Group]
    }

    public let nodes: [Node]
    public let unsupported: [Unsupported]
    public let routing: Routing?

    public static func decoded(from data: Data) throws -> NativeImportReport {
        try JSONDecoder().decode(NativeImportReport.self, from: data)
    }
}

/// Why the Rust importer returned no runnable node.
public enum NativeImportFailure: Error, Equatable {
    /// The text is not a format the importer knows.
    case unrecognized
    case empty
    case tooLarge
    /// Every node was unsupported; the first reasons, without node values.
    case noSupportedNode(protocols: [String], reasons: [String])
    /// The importer library is missing or failed.
    case unavailable
}

/// Runs the Rust importer on a text and returns its JSON report, or throws `NativeImportFailure`.
public typealias NativeNodeImporter = (String) throws -> Data

extension TunnelProfile {
    /// The profile for the first runnable node of a report.
    static func first(in report: NativeImportReport, profileID: String) throws -> TunnelProfile {
        guard let node = report.nodes.first else {
            throw NativeImportFailure.noSupportedNode(
                protocols: report.unsupported.map(\.protocol),
                reasons: Array(Set(report.unsupported.map(\.reason))).sorted()
            )
        }
        return try TunnelProfile(node: node, profileID: profileID)
    }

    /// The profile that runs one imported node.
    public init(node: NativeImportReport.Node, profileID: String) throws {
        // Shadowsocks and VLESS + REALITY land in their own cases, so their secrets are split as for pasted links;
        // everything else becomes a native outbound.
        let outbound = try JSONDecoder().decode(
            EmbeddedRuntimeConfig.Outbound.self,
            from: JSONEncoder().encode(node.outbound)
        )
        self.init(
            config: EmbeddedRuntimeConfig(outbound: outbound, profileID: profileID),
            interface: .proxy,
            serverAddress: node.server,
            displayName: node.name.isEmpty ? node.server : node.name
        )
    }
}
