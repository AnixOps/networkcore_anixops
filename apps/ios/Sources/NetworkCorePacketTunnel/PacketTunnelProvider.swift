import Foundation
import NetworkCoreBridge
import NetworkExtension

/// Packet tunnel backed by the embedded Rust runtime.
///
/// It re-reads platform facts and the runtime handshake on every start and fails closed when either is
/// unavailable. It never starts another process and never logs the tunnel profile.
final class PacketTunnelProvider: NEPacketTunnelProvider {
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
              let template = tunnelProtocol.providerConfiguration?[TunnelProfileKeys.runtimeConfig] as? Data
        else {
            completionHandler(PacketTunnelFailure(reason: "tunnel profile is missing"))
            return
        }
        guard let keyReference = tunnelProtocol.passwordReference else {
            completionHandler(PacketTunnelFailure(reason: "tunnel profile has no node key; import the node again"))
            return
        }
        let config: Data
        let interface: TunnelInterface
        do {
            let secret = NodeSecret.fromKeychainValue(try NodeSecretStore.password(for: keyReference))
            config = try EmbeddedRuntimeConfig.decoded(from: template).withSecret(secret).encoded()
            interface = try (tunnelProtocol.providerConfiguration?[TunnelProfileKeys.tunnelInterface] as? Data)
                .map(TunnelInterface.decoded(from:)) ?? .proxy
        } catch let failure as NodeSecretStore.Failure {
            completionHandler(PacketTunnelFailure(reason: "node key is unavailable (keychain status \(failure.status))"))
            return
        } catch {
            completionHandler(PacketTunnelFailure(reason: "tunnel profile is malformed"))
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

        guard let settings = Self.networkSettings(interface, remoteAddress: tunnelProtocol.serverAddress ?? "127.0.0.1") else {
            completionHandler(PacketTunnelFailure(reason: "tunnel profile has invalid interface addresses"))
            return
        }
        setTunnelNetworkSettings(settings) { [weak self] error in
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

    /// Interface settings from the saved profile. The provider's own sockets (to the proxy server or the
    /// WireGuard endpoint) are never routed into the tunnel by the system. Returns nil for an address or route
    /// that does not parse.
    static func networkSettings(_ interface: TunnelInterface, remoteAddress: String) -> NEPacketTunnelNetworkSettings? {
        let addresses = interface.addresses.map(CIDR.parse)
        let routes = interface.includedRoutes.map(CIDR.parse)
        guard addresses.allSatisfy({ $0 != nil }), routes.allSatisfy({ $0 != nil }) else {
            return nil
        }
        let v4Addresses = addresses.compactMap { $0 }.filter { !$0.isIPv6 }
        let v6Addresses = addresses.compactMap { $0 }.filter { $0.isIPv6 }
        let v4Routes = routes.compactMap { $0 }.filter { !$0.isIPv6 }
        let v6Routes = routes.compactMap { $0 }.filter { $0.isIPv6 }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        if !v4Addresses.isEmpty {
            let ipv4 = NEIPv4Settings(
                addresses: v4Addresses.map(\.address),
                subnetMasks: v4Addresses.compactMap(\.ipv4SubnetMask)
            )
            ipv4.includedRoutes = v4Routes.map { route in
                route.isDefaultRoute
                    ? NEIPv4Route.default()
                    : NEIPv4Route(destinationAddress: route.address, subnetMask: route.ipv4SubnetMask ?? "255.255.255.255")
            }
            settings.ipv4Settings = ipv4
        }
        if !v6Addresses.isEmpty {
            let ipv6 = NEIPv6Settings(
                addresses: v6Addresses.map(\.address),
                networkPrefixLengths: v6Addresses.map { NSNumber(value: $0.prefixLength) }
            )
            ipv6.includedRoutes = v6Routes.map { route in
                route.isDefaultRoute
                    ? NEIPv6Route.default()
                    : NEIPv6Route(destinationAddress: route.address, networkPrefixLength: NSNumber(value: route.prefixLength))
            }
            settings.ipv6Settings = ipv6
        }
        if !interface.dnsServers.isEmpty {
            let dns = NEDNSSettings(servers: interface.dnsServers)
            dns.matchDomains = [""]
            settings.dnsSettings = dns
        }
        settings.mtu = NSNumber(value: interface.mtu)
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
