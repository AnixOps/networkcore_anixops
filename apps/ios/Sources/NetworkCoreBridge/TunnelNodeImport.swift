import Foundation

/// Everything the app saves for one imported node.
public struct TunnelProfile: Equatable {
    /// Runtime config with its secrets; the app saves `config.secret` to the Keychain and
    /// `config.withoutSecret()` to the profile.
    public let config: EmbeddedRuntimeConfig
    public let interface: TunnelInterface
    /// `NETunnelProviderProtocol.serverAddress`.
    public let serverAddress: String
    public let displayName: String
}

public enum TunnelNodeImportError: Error, Equatable {
    case unrecognized
    case shadowsocks(ShadowsocksLinkError)
    case wireguard(WireGuardConfigError)
    case vless(VlessLinkError)
}

/// Turns pasted text into a tunnel profile: an `ss://` or `vless://` link, or a WireGuard config.
public enum TunnelNodeImport {
    public static func parse(_ text: String, profileID: String) throws -> TunnelProfile {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("ss://") {
            let node: ShadowsocksNode
            do {
                node = try ShadowsocksNodeLink.parse(trimmed)
            } catch let error as ShadowsocksLinkError {
                throw TunnelNodeImportError.shadowsocks(error)
            }
            return TunnelProfile(
                config: EmbeddedRuntimeConfig(node: node, profileID: profileID),
                interface: .proxy,
                serverAddress: node.host,
                displayName: node.name ?? node.host
            )
        }
        if trimmed.lowercased().hasPrefix("vless://") {
            let node: VlessNode
            do {
                node = try VlessNodeLink.parse(trimmed)
            } catch let error as VlessLinkError {
                throw TunnelNodeImportError.vless(error)
            }
            return TunnelProfile(
                config: EmbeddedRuntimeConfig(node: node, profileID: profileID),
                interface: .proxy,
                serverAddress: node.host,
                displayName: node.name ?? node.host
            )
        }
        if trimmed.range(of: "[interface]", options: .caseInsensitive) != nil {
            let node: WireGuardNode
            do {
                node = try WireGuardConfig.parse(trimmed)
            } catch let error as WireGuardConfigError {
                throw TunnelNodeImportError.wireguard(error)
            }
            return TunnelProfile(
                config: EmbeddedRuntimeConfig(node: node, profileID: profileID),
                interface: TunnelInterface(node: node),
                serverAddress: node.endpointHost,
                displayName: "WireGuard \(node.endpointHost)"
            )
        }
        throw TunnelNodeImportError.unrecognized
    }
}
