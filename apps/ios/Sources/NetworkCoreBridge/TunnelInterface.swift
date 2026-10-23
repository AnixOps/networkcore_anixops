import Foundation

/// Addresses, routes, DNS and MTU of the tunnel interface, saved next to the runtime config so the extension
/// can build `NEPacketTunnelNetworkSettings` without knowing the protocol.
public struct TunnelInterface: Codable, Equatable {
    /// Interface addresses in CIDR form.
    public var addresses: [String]
    /// DNS servers reached inside the tunnel. Empty leaves DNS to the system.
    public var dnsServers: [String]
    /// Routes sent into the tunnel, in CIDR form. `0.0.0.0/0` and `::/0` are the default routes.
    public var includedRoutes: [String]
    public var mtu: Int

    enum CodingKeys: String, CodingKey {
        case addresses
        case dnsServers = "dns_servers"
        case includedRoutes = "included_routes"
        case mtu
    }

    public init(addresses: [String], dnsServers: [String], includedRoutes: [String], mtu: Int) {
        self.addresses = addresses
        self.dnsServers = dnsServers
        self.includedRoutes = includedRoutes
        self.mtu = mtu
    }

    /// Full tunnel for proxy outbounds, whose userspace stack answers on any address. 198.18.0.0/15 is reserved
    /// for benchmarking and never routed publicly; DNS to 198.18.0.2 is answered over the proxy.
    public static let proxy = TunnelInterface(
        addresses: ["198.18.0.1/24", "fd00:4e43::1/64"],
        dnsServers: ["198.18.0.2"],
        includedRoutes: ["0.0.0.0/0", "::/0"],
        mtu: 1500
    )

    /// A WireGuard peer's interface, as its `wg-quick` file describes it.
    public init(node: WireGuardNode) {
        self.init(
            addresses: node.addresses,
            dnsServers: node.dnsServers,
            includedRoutes: node.allowedIPs,
            mtu: node.mtu ?? WireGuardNode.defaultMTU
        )
    }

    public static func decoded(from data: Data) throws -> TunnelInterface {
        try JSONDecoder().decode(TunnelInterface.self, from: data)
    }

    public func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }
}

/// An IPv4 or IPv6 address with a prefix length. A bare address is a host route.
public struct CIDR: Equatable {
    public let address: String
    public let prefixLength: Int
    public let isIPv6: Bool

    public static func parse(_ text: String) -> CIDR? {
        let parts = text.trimmingCharacters(in: .whitespaces).split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2 else {
            return nil
        }
        let address = String(parts[0])
        let isIPv6: Bool
        if IPAddressText.isIPv4(address) {
            isIPv6 = false
        } else if IPAddressText.isIPv6(address) {
            isIPv6 = true
        } else {
            return nil
        }
        let maximum = isIPv6 ? 128 : 32
        var prefixLength = maximum
        if parts.count == 2 {
            guard let parsed = Int(parts[1]), (0...maximum).contains(parsed) else {
                return nil
            }
            prefixLength = parsed
        }
        return CIDR(address: address, prefixLength: prefixLength, isIPv6: isIPv6)
    }

    public var isDefaultRoute: Bool {
        prefixLength == 0
    }

    /// Dotted subnet mask for an IPv4 prefix, such as `255.255.255.0` for /24.
    public var ipv4SubnetMask: String? {
        guard !isIPv6 else {
            return nil
        }
        let mask: UInt32 = prefixLength == 0 ? 0 : UInt32.max << UInt32(32 - prefixLength)
        return [24, 16, 8, 0].map { String((mask >> UInt32($0)) & 0xFF) }.joined(separator: ".")
    }
}

/// Numeric address checks without a resolver.
public enum IPAddressText {
    public static func isIPv4(_ text: String) -> Bool {
        var address = in_addr()
        return inet_pton(AF_INET, text, &address) == 1
    }

    public static func isIPv6(_ text: String) -> Bool {
        var address = in6_addr()
        return inet_pton(AF_INET6, text, &address) == 1
    }
}
