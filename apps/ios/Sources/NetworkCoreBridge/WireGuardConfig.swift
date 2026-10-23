import Foundation

/// A WireGuard tunnel imported from a `wg-quick` style config with exactly one peer.
///
/// The private and preshared keys stay in this value only long enough to build the tunnel profile. Errors never
/// include them.
public struct WireGuardNode: Sendable, Equatable {
    /// `wg-quick`'s default MTU.
    public static let defaultMTU = 1420

    public let privateKey: String
    public let addresses: [String]
    public let dnsServers: [String]
    public let mtu: Int?
    public let peerPublicKey: String
    public let presharedKey: String?
    public let endpointHost: String
    public let endpointPort: UInt16
    public let allowedIPs: [String]
    public let persistentKeepalive: UInt16?
}

public enum WireGuardConfigError: Error, Equatable {
    case malformed
    case missingField(String)
    case invalidKey
    case invalidAddress
    case invalidEndpoint
    case unsupportedPeerCount
}

public enum WireGuardConfig {
    public static func parse(_ text: String) throws -> WireGuardNode {
        enum Section {
            case none, interface, peer
        }
        var section = Section.none
        var peers = 0
        var interface: [String: [String]] = [:]
        var peer: [String: [String]] = [:]

        for rawLine in text.split(whereSeparator: \.isNewline) {
            var line = Substring(rawLine)
            if let comment = line.firstIndex(where: { $0 == "#" || $0 == ";" }) {
                line = line[..<comment]
            }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty {
                continue
            }
            switch trimmed.lowercased() {
            case "[interface]":
                section = .interface
                continue
            case "[peer]":
                section = .peer
                peers += 1
                continue
            default:
                break
            }
            // Split at the first "=": base64 values end with "=" padding.
            guard let equals = trimmed.firstIndex(of: "=") else {
                throw WireGuardConfigError.malformed
            }
            let key = trimmed[..<equals].trimmingCharacters(in: .whitespaces).lowercased()
            let value = trimmed[trimmed.index(after: equals)...].trimmingCharacters(in: .whitespaces)
            switch section {
            case .interface:
                interface[key, default: []].append(value)
            case .peer:
                peer[key, default: []].append(value)
            case .none:
                throw WireGuardConfigError.malformed
            }
        }
        guard peers == 1 else {
            throw peers == 0 ? WireGuardConfigError.missingField("Peer") : WireGuardConfigError.unsupportedPeerCount
        }

        let privateKey = try key(interface, "privatekey", field: "PrivateKey")
        let peerPublicKey = try key(peer, "publickey", field: "PublicKey")
        let presharedKey = try peer["presharedkey"].flatMap(\.last).map { value -> String in
            guard isKey(value) else {
                throw WireGuardConfigError.invalidKey
            }
            return value
        }

        let addresses = list(interface["address"])
        guard !addresses.isEmpty else {
            throw WireGuardConfigError.missingField("Address")
        }
        guard addresses.allSatisfy({ CIDR.parse($0) != nil }) else {
            throw WireGuardConfigError.invalidAddress
        }
        let allowedIPs = list(peer["allowedips"])
        guard !allowedIPs.isEmpty else {
            throw WireGuardConfigError.missingField("AllowedIPs")
        }
        guard allowedIPs.allSatisfy({ CIDR.parse($0) != nil }) else {
            throw WireGuardConfigError.invalidAddress
        }
        // wg-quick also accepts search domains under DNS; only numeric servers configure the tunnel.
        let dnsServers = list(interface["dns"]).filter { IPAddressText.isIPv4($0) || IPAddressText.isIPv6($0) }

        var mtu: Int?
        if let value = interface["mtu"]?.last {
            guard let parsed = Int(value), (1280...9000).contains(parsed) else {
                throw WireGuardConfigError.malformed
            }
            mtu = parsed
        }
        var keepalive: UInt16?
        if let value = peer["persistentkeepalive"]?.last, value.lowercased() != "off" {
            guard let parsed = UInt16(value) else {
                throw WireGuardConfigError.malformed
            }
            keepalive = parsed == 0 ? nil : parsed
        }

        guard let endpoint = peer["endpoint"]?.last else {
            throw WireGuardConfigError.missingField("Endpoint")
        }
        let (host, port) = try parseEndpoint(endpoint)

        return WireGuardNode(
            privateKey: privateKey,
            addresses: addresses,
            dnsServers: dnsServers,
            mtu: mtu,
            peerPublicKey: peerPublicKey,
            presharedKey: presharedKey,
            endpointHost: host,
            endpointPort: port,
            allowedIPs: allowedIPs,
            persistentKeepalive: keepalive
        )
    }

    private static func key(_ fields: [String: [String]], _ name: String, field: String) throws -> String {
        guard let value = fields[name]?.last else {
            throw WireGuardConfigError.missingField(field)
        }
        guard isKey(value) else {
            throw WireGuardConfigError.invalidKey
        }
        return value
    }

    static func isKey(_ value: String) -> Bool {
        Data(base64Encoded: value)?.count == 32
    }

    private static func list(_ values: [String]?) -> [String] {
        (values ?? []).flatMap { $0.split(separator: ",") }
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// `host:port`, `a.b.c.d:port` or `[v6]:port`.
    static func parseEndpoint(_ endpoint: String) throws -> (String, UInt16) {
        let host: Substring
        let portText: Substring
        if endpoint.hasPrefix("[") {
            guard let close = endpoint.firstIndex(of: "]"),
                  endpoint.index(after: close) < endpoint.endIndex,
                  endpoint[endpoint.index(after: close)] == ":"
            else {
                throw WireGuardConfigError.invalidEndpoint
            }
            host = endpoint[endpoint.index(after: endpoint.startIndex)..<close]
            portText = endpoint[endpoint.index(close, offsetBy: 2)...]
        } else {
            guard let colon = endpoint.lastIndex(of: ":") else {
                throw WireGuardConfigError.invalidEndpoint
            }
            host = endpoint[..<colon]
            portText = endpoint[endpoint.index(after: colon)...]
        }
        guard !host.isEmpty, !host.contains(":") || endpoint.hasPrefix("["),
              let port = UInt16(portText), port > 0
        else {
            throw WireGuardConfigError.invalidEndpoint
        }
        return (String(host), port)
    }
}
