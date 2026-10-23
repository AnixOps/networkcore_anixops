import Foundation

/// A VLESS + REALITY node imported from a `vless://` share link.
///
/// The uuid is the node's credential: it stays in this value only long enough to build the tunnel profile,
/// and errors never include it.
public struct VlessNode: Sendable, Equatable {
    public static let visionFlow = "xtls-rprx-vision"

    public let host: String
    public let port: UInt16
    public let uuid: String
    /// `xtls-rprx-vision` or empty.
    public let flow: String
    public let serverName: String
    /// REALITY public key (`pbk`), base64url as printed by `xray x25519`.
    public let publicKey: String
    /// REALITY short id (`sid`), hex, possibly empty.
    public let shortID: String
    public let name: String?

    public init(
        host: String,
        port: UInt16,
        uuid: String,
        flow: String,
        serverName: String,
        publicKey: String,
        shortID: String,
        name: String?
    ) {
        self.host = host
        self.port = port
        self.uuid = uuid
        self.flow = flow
        self.serverName = serverName
        self.publicKey = publicKey
        self.shortID = shortID
        self.name = name
    }
}

public enum VlessLinkError: Error, Equatable {
    case notVlessLink
    case malformed
    case invalidUUID
    /// Only `security=reality` is supported.
    case unsupportedSecurity
    /// Only the raw TCP transport (`type=tcp`) is supported.
    case unsupportedTransport
    case unsupportedFlow
    case invalidRealitySettings
}

public enum VlessNodeLink {
    /// Parses the Xray share-link format:
    /// `vless://uuid@host:port?security=reality&sni=…&pbk=…&sid=…&flow=xtls-rprx-vision&type=tcp#name`.
    ///
    /// The fingerprint parameter (`fp`) is accepted but not used: the embedded engine always presents Chrome.
    public static func parse(_ link: String) throws -> VlessNode {
        let trimmed = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("vless://") else {
            throw VlessLinkError.notVlessLink
        }
        guard let components = URLComponents(string: trimmed),
              let host = components.host, !host.isEmpty,
              let port = components.port, port > 0, port <= Int(UInt16.max),
              let user = components.user, !user.isEmpty
        else {
            throw VlessLinkError.malformed
        }
        guard let uuid = UUID(uuidString: user) else {
            throw VlessLinkError.invalidUUID
        }

        var query: [String: String] = [:]
        for item in components.queryItems ?? [] {
            query[item.name.lowercased()] = item.value ?? ""
        }
        guard query["security"]?.lowercased() == "reality" else {
            throw VlessLinkError.unsupportedSecurity
        }
        if let encryption = query["encryption"], !encryption.isEmpty, encryption.lowercased() != "none" {
            throw VlessLinkError.unsupportedSecurity
        }
        if let transport = query["type"], !transport.isEmpty, transport.lowercased() != "tcp" {
            throw VlessLinkError.unsupportedTransport
        }
        if let headerType = query["headertype"], !headerType.isEmpty, headerType.lowercased() != "none" {
            throw VlessLinkError.unsupportedTransport
        }
        let flow = (query["flow"] ?? "").lowercased()
        guard flow.isEmpty || flow == VlessNode.visionFlow else {
            throw VlessLinkError.unsupportedFlow
        }

        let serverName = query["sni"] ?? query["servername"] ?? ""
        let publicKey = query["pbk"] ?? query["publickey"] ?? ""
        let shortID = (query["sid"] ?? query["shortid"] ?? "").lowercased()
        guard !serverName.isEmpty,
              decodeBase64(publicKey)?.count == 32,
              shortID.count <= 16, shortID.count % 2 == 0,
              shortID.allSatisfy(\.isHexDigit)
        else {
            throw VlessLinkError.invalidRealitySettings
        }

        // URLComponents keeps IPv6 brackets in `host`.
        let bareHost = host.hasPrefix("[") && host.hasSuffix("]") ? String(host.dropFirst().dropLast()) : host
        let name = components.fragment.flatMap { $0.isEmpty ? nil : $0 }
        return VlessNode(
            host: bareHost,
            port: UInt16(port),
            uuid: uuid.uuidString.lowercased(),
            flow: flow,
            serverName: serverName,
            publicKey: publicKey,
            shortID: shortID,
            name: name
        )
    }

    /// Accepts standard and URL-safe base64, with or without padding.
    static func decodeBase64(_ text: String) -> Data? {
        var normalized = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let remainder = normalized.count % 4
        if remainder == 1 {
            return nil
        }
        if remainder > 0 {
            normalized += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: normalized)
    }
}
