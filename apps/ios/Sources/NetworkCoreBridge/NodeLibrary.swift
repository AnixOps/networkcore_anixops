import Foundation

/// Every node of the last subscription or multi-node import, for the node list. It holds the nodes' credentials,
/// so the app keeps it in the Keychain (`NodeSecretStore`), never in the tunnel profile; the profile only carries
/// the selected node.
public struct NodeLibrary: Codable, Equatable {
    public static let keychainAccount = "node-library"

    /// The subscription link the nodes came from, for refreshing; nil for pasted text.
    public var subscriptionURL: String?
    public var nodes: [NativeImportReport.Node]
    public var selectedID: String?
    public var updatedAt: Date

    public init(subscriptionURL: String?, nodes: [NativeImportReport.Node], selectedID: String?, updatedAt: Date) {
        self.subscriptionURL = subscriptionURL
        self.nodes = nodes
        self.selectedID = selectedID
        self.updatedAt = updatedAt
    }

    /// A library from a fresh report. The previous selection survives a refresh when that node is still listed.
    public init(report: NativeImportReport, subscriptionURL: String?, keeping previousID: String?, at date: Date = Date()) {
        let selected = report.nodes.first { $0.id == previousID } ?? report.nodes.first
        self.init(subscriptionURL: subscriptionURL, nodes: report.nodes, selectedID: selected?.id, updatedAt: date)
    }

    public var selected: NativeImportReport.Node? {
        nodes.first { $0.id == selectedID }
    }

    public func node(id: String) -> NativeImportReport.Node? {
        nodes.first { $0.id == id }
    }

    /// QUIC protocols: a TCP connect time to their port says nothing about them.
    public static func usesUDP(_ protocolName: String) -> Bool {
        ["hysteria2", "tuic"].contains(protocolName)
    }

    public func keychainValue() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .millisecondsSince1970
        return String(decoding: try encoder.encode(self), as: UTF8.self)
    }

    public static func fromKeychainValue(_ value: String) throws -> NodeLibrary {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return try decoder.decode(NodeLibrary.self, from: Data(value.utf8))
    }
}

/// Recognizes a pasted subscription link: one http(s) URL and nothing else.
public enum SubscriptionLink {
    public static func url(from text: String) -> URL? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.contains(where: \.isWhitespace),
              let url = URL(string: trimmed),
              let scheme = url.scheme?.lowercased(), scheme == "https" || scheme == "http",
              let host = url.host, !host.isEmpty
        else {
            return nil
        }
        return url
    }

    /// The host alone, for showing which subscription is in use without its token.
    public static func displayHost(_ url: String) -> String {
        URL(string: url)?.host ?? url
    }
}
