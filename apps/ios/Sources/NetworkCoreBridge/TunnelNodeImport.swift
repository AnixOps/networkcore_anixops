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
    /// The Rust importer could not use the text either.
    case native(NativeImportFailure)
}

/// What an import produced: the profile to save, and the importer's report when there was one.
public struct TunnelImport: Equatable {
    public let profile: TunnelProfile
    public let report: NativeImportReport?
}

/// Turns pasted text into a tunnel profile: an `ss://` or `vless://` link, or a WireGuard config, read in Swift;
/// anything else (other protocols, other transports, subscription texts) goes to `native`, the Rust importer,
/// which takes the first node the engine can run.
public enum TunnelNodeImport {
    public static func parse(
        _ text: String,
        profileID: String,
        native: NativeNodeImporter? = nil
    ) throws -> TunnelProfile {
        try parseImport(text, profileID: profileID, native: native).profile
    }

    /// The profile and, when the Rust importer read the text, its whole report (every node of a subscription).
    public static func parseImport(
        _ text: String,
        profileID: String,
        native: NativeNodeImporter? = nil
    ) throws -> TunnelImport {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let builtInError: TunnelNodeImportError
        do {
            return TunnelImport(profile: try parseBuiltIn(trimmed, profileID: profileID), report: nil)
        } catch let error as TunnelNodeImportError {
            builtInError = error
        }
        // WireGuard configs are only read in Swift.
        guard let native = native, !isWireGuard(builtInError) else {
            throw builtInError
        }
        let report: NativeImportReport
        do {
            report = try NativeImportReport.decoded(from: native(trimmed))
        } catch let failure as NativeImportFailure {
            // A link the Swift parser recognized keeps its more specific error.
            throw builtInError == .unrecognized ? .native(failure) : builtInError
        } catch {
            throw builtInError == .unrecognized ? .native(.unavailable) : builtInError
        }
        do {
            return TunnelImport(profile: try TunnelProfile.first(in: report, profileID: profileID), report: report)
        } catch let failure as NativeImportFailure {
            throw TunnelNodeImportError.native(failure)
        } catch {
            throw TunnelNodeImportError.native(.unavailable)
        }
    }

    private static func isWireGuard(_ error: TunnelNodeImportError) -> Bool {
        if case .wireguard = error {
            return true
        }
        return false
    }

    private static func parseBuiltIn(_ trimmed: String, profileID: String) throws -> TunnelProfile {
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
