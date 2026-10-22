import NetworkCoreBridge

/// Holds the app-level tunnel decision and refreshes it whenever sanitized platform status changes.
public struct AppCoordinator: Sendable, Equatable {
    public private(set) var decision: VpnConfigurationDecision

    public init(status: IosPlatformStatus) {
        decision = VpnConfigurationController.decide(for: status)
    }

    public mutating func apply(_ status: IosPlatformStatus) {
        decision = VpnConfigurationController.decide(for: status)
    }

    public var canStartTunnel: Bool {
        if case .startTunnel = decision {
            return true
        }
        return false
    }
}
