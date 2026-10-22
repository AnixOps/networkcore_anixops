import Foundation

/// A Shadowsocks-2022 node imported from an `ss://` link.
///
/// The password stays in this value only long enough to build the tunnel profile. Errors never include it.
public struct ShadowsocksNode: Sendable, Equatable {
    public static let supportedMethods: Set<String> = [
        "2022-blake3-aes-128-gcm",
        "2022-blake3-aes-256-gcm",
        "2022-blake3-chacha20-poly1305",
    ]

    public let host: String
    public let port: UInt16
    public let method: String
    public let password: String
    public let name: String?

    public init(host: String, port: UInt16, method: String, password: String, name: String?) {
        self.host = host
        self.port = port
        self.method = method
        self.password = password
        self.name = name
    }
}

public enum ShadowsocksLinkError: Error, Equatable {
    case notShadowsocksLink
    case malformed
    case unsupportedMethod
    case unsupportedPlugin
}

public enum ShadowsocksNodeLink {
    /// Parses SIP002 links (`ss://userinfo@host:port#name`, with base64url or percent-encoded userinfo)
    /// and the legacy fully base64-encoded form.
    public static func parse(_ link: String) throws -> ShadowsocksNode {
        let trimmed = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.lowercased().hasPrefix("ss://") else {
            throw ShadowsocksLinkError.notShadowsocksLink
        }
        var body = String(trimmed.dropFirst("ss://".count))
        var name: String?
        if let hash = body.firstIndex(of: "#") {
            let fragment = String(body[body.index(after: hash)...])
            name = fragment.removingPercentEncoding ?? fragment
            body = String(body[..<hash])
        }
        if !body.contains("@") {
            // Legacy form: base64(method:password@host:port).
            guard let decoded = decodeBase64(body), decoded.contains("@") else {
                throw ShadowsocksLinkError.malformed
            }
            body = decoded
        }
        guard let components = URLComponents(string: "ss://" + body),
              let host = components.host, !host.isEmpty,
              let port = components.port, port > 0, port <= Int(UInt16.max)
        else {
            throw ShadowsocksLinkError.malformed
        }
        if let items = components.queryItems, items.contains(where: { $0.name == "plugin" }) {
            throw ShadowsocksLinkError.unsupportedPlugin
        }

        let method: String
        let password: String
        if let user = components.user, let encodedPassword = components.password {
            method = user
            password = encodedPassword
        } else if let user = components.percentEncodedUser,
                  let decoded = decodeBase64(user.removingPercentEncoding ?? user),
                  let colon = decoded.firstIndex(of: ":")
        {
            method = String(decoded[..<colon])
            password = String(decoded[decoded.index(after: colon)...])
        } else {
            throw ShadowsocksLinkError.malformed
        }

        let normalizedMethod = method.lowercased()
        guard ShadowsocksNode.supportedMethods.contains(normalizedMethod) else {
            throw ShadowsocksLinkError.unsupportedMethod
        }
        guard !password.isEmpty else {
            throw ShadowsocksLinkError.malformed
        }
        // URLComponents keeps IPv6 brackets in `host`.
        let bareHost = host.hasPrefix("[") && host.hasSuffix("]") ? String(host.dropFirst().dropLast()) : host
        return ShadowsocksNode(
            host: bareHost,
            port: UInt16(port),
            method: normalizedMethod,
            password: password,
            name: name.flatMap { $0.isEmpty ? nil : $0 }
        )
    }

    /// Accepts standard and URL-safe base64, with or without padding.
    static func decodeBase64(_ text: String) -> String? {
        var normalized = text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let remainder = normalized.count % 4
        if remainder == 1 {
            return nil
        }
        if remainder > 0 {
            normalized += String(repeating: "=", count: 4 - remainder)
        }
        guard let data = Data(base64Encoded: normalized) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}
