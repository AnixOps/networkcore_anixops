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
                code: firstErrorCode(status.diagnostics)
            )
        }
        if !status.embeddedRuntime.available {
            return .blocked(
                reason: status.embeddedRuntime.unavailableReason ?? "iOS embedded runtime is unavailable",
                code: firstErrorCode(status.diagnostics)
            )
        }
        return .startTunnel
    }

    /// Diagnostics keep the tunnel, runtime, remote-script, then storage order, so the first error is the blocking one.
    static func firstErrorCode(_ diagnostics: [IosDiagnostic]) -> String? {
        diagnostics.first(where: { $0.severity == .error })?.code
    }
}
