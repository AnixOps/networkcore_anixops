import NetworkCoreBridge

/// Whether the containing app may ask the system to start the packet tunnel.
public enum VpnConfigurationDecision: Sendable, Equatable {
    case startTunnel
    case blocked(reason: String, code: String?)
}

/// Pure decision logic over sanitized platform status. It never touches NetworkExtension or Security APIs.
public enum VpnConfigurationController {
    public static func decide(for status: IosPlatformStatus) -> VpnConfigurationDecision {
        if !status.tunnel.available {
            return .blocked(
                reason: status.tunnel.unavailableReason ?? "iOS tunnel is unavailable",
                code: firstCode(status.diagnostics, sources: tunnelSources)
            )
        }
        if !status.embeddedRuntime.available {
            return .blocked(
                reason: status.embeddedRuntime.unavailableReason ?? "iOS embedded runtime is unavailable",
                code: firstCode(status.diagnostics, sources: [IosPlatformSources.embeddedRuntime])
            )
        }
        return .startTunnel
    }

    private static let tunnelSources = [IosPlatformSources.networkExtension, IosPlatformSources.vpnConfiguration]

    /// The code comes from the same area as the blocking reason, so the reason and the code never disagree.
    static func firstCode(_ diagnostics: [IosDiagnostic], sources: [String]) -> String? {
        diagnostics.first(where: { sources.contains($0.source) })?.code
    }
}
