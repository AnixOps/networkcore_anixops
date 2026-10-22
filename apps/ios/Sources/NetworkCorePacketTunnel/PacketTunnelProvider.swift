import NetworkCoreBridge
import NetworkExtension

/// Lifecycle handoff for the packet tunnel. It re-reads platform facts on every start and fails closed
/// until the embedded Rust runtime is linked through the FFI boundary. It never reads subscription secrets.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let status = IosPlatformFactsProbe.currentStatus()

        if !status.tunnel.available {
            completionHandler(PacketTunnelFailure(reason: status.tunnel.unavailableReason ?? "iOS tunnel is unavailable"))
            return
        }
        if !status.embeddedRuntime.available {
            completionHandler(
                PacketTunnelFailure(reason: status.embeddedRuntime.unavailableReason ?? "iOS embedded runtime is unavailable")
            )
            return
        }
        completionHandler(PacketTunnelFailure(reason: "iOS embedded runtime handoff is not implemented"))
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }
}

/// Error returned to the system when the tunnel refuses to start. It carries only a fixed reason string.
struct PacketTunnelFailure: LocalizedError {
    let reason: String

    var errorDescription: String? {
        reason
    }
}
