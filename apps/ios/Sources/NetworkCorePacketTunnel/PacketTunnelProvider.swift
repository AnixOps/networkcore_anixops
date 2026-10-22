import Foundation
import NetworkCoreBridge
import NetworkExtension

/// Packet tunnel backed by the embedded Rust runtime.
///
/// It re-reads platform facts and the runtime handshake on every start and fails closed when either is
/// unavailable. It never starts another process and never logs the tunnel profile.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    /// Addresses inside the tunnel. 198.18.0.0/15 is reserved for benchmarking and never routed publicly.
    private static let tunnelIPv4Address = "198.18.0.1"
    private static let tunnelDNSServer = "198.18.0.2"
    private static let tunnelIPv6Address = "fd00:4e43::1"
    private static let tunnelMTU = 1500

    private var session: EmbeddedRuntimeSession?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let runtimeFact = NetworkCoreRuntimeFFI.embeddedRuntimeFact(
            reported: EmbeddedRuntimeSession.reportedHandshake(),
            initializationSucceeded: true
        )
        let status = IosPlatformFactsProbe.currentStatus(
            vpnConfiguration: .savedAndAuthorized,
            embeddedRuntime: runtimeFact
        )
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
        guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
              let config = tunnelProtocol.providerConfiguration?[TunnelProfileKeys.runtimeConfig] as? Data
        else {
            completionHandler(PacketTunnelFailure(reason: "tunnel profile is missing"))
            return
        }

        let session: EmbeddedRuntimeSession
        do {
            session = try EmbeddedRuntimeSession(config: config, packetFlow: packetFlow)
        } catch let failure as EmbeddedRuntimeSession.Failure {
            completionHandler(PacketTunnelFailure(reason: "embedded runtime rejected the tunnel profile (code \(failure.code))"))
            return
        } catch {
            completionHandler(PacketTunnelFailure(reason: "embedded runtime rejected the tunnel profile"))
            return
        }

        let remote = tunnelProtocol.serverAddress ?? Self.tunnelIPv4Address
        setTunnelNetworkSettings(Self.networkSettings(remoteAddress: remote)) { [weak self] error in
            guard let self = self else {
                completionHandler(PacketTunnelFailure(reason: "tunnel provider was released"))
                return
            }
            if let error = error {
                completionHandler(error)
                return
            }
            do {
                try session.start()
                self.session = session
                completionHandler(nil)
            } catch let failure as EmbeddedRuntimeSession.Failure {
                completionHandler(PacketTunnelFailure(reason: "embedded runtime could not start (code \(failure.code))"))
            } catch {
                completionHandler(PacketTunnelFailure(reason: "embedded runtime could not start"))
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        session?.stop()
        session = nil
        completionHandler()
    }

    /// Any message from the app returns the runtime's sanitized status JSON.
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        completionHandler?(session?.statusJSON())
    }

    /// Full-tunnel settings: every IPv4 and IPv6 route and all DNS go through the tunnel. The provider's own
    /// connections to the proxy server are not routed into the tunnel by the system.
    static func networkSettings(remoteAddress: String) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        let ipv4 = NEIPv4Settings(addresses: [tunnelIPv4Address], subnetMasks: ["255.255.255.0"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        let ipv6 = NEIPv6Settings(addresses: [tunnelIPv6Address], networkPrefixLengths: [64])
        ipv6.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6
        let dns = NEDNSSettings(servers: [tunnelDNSServer])
        dns.matchDomains = [""]
        settings.dnsSettings = dns
        settings.mtu = NSNumber(value: tunnelMTU)
        return settings
    }
}

/// Error returned to the system when the tunnel refuses to start. It carries only a fixed reason string.
struct PacketTunnelFailure: LocalizedError {
    let reason: String

    var errorDescription: String? {
        reason
    }
}
