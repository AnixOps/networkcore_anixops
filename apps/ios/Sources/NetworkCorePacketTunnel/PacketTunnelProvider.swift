import Foundation
import NetworkCoreBridge
import NetworkExtension
import os

/// Packet tunnel backed by the embedded Rust runtime.
///
/// It re-reads platform facts and the runtime handshake on every start and fails closed when either is
/// unavailable. It never starts another process and never logs the tunnel profile.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private var session: EmbeddedRuntimeSession?
    private var startedAt: Date?
    private var memoryPressure: DispatchSourceMemoryPressure?
    /// Recent events for the app's developer mode. Same rule as the system log: fixed reasons and codes only.
    private let events = TunnelDiagnosticLog()

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        Self.log.notice("startTunnel")
        events.record("startTunnel")
        watchMemoryPressure()
        let completionHandler: (Error?) -> Void = { [events] error in
            if let error = error {
                Self.log.error("startTunnel failed: \(error.localizedDescription, privacy: .public)")
                events.record("startTunnel failed: \(error.localizedDescription)")
            } else {
                Self.log.notice("startTunnel succeeded")
                events.record("startTunnel succeeded")
            }
            completionHandler(error)
        }
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
        events.record("profile loaded, mtu \(interface.mtu), \(interface.addresses.count) addresses, \(interface.includedRoutes.count) routes, \(interface.dnsServers.count) dns servers")

        let session: EmbeddedRuntimeSession
        do {
            session = try EmbeddedRuntimeSession(config: config, packetFlow: packetFlow)
            events.record("runtime initialized")
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
            self.events.record("network settings applied")
            do {
                try session.start()
                self.session = session
                self.startedAt = Date()
                completionHandler(nil)
            } catch let failure as EmbeddedRuntimeSession.Failure {
                completionHandler(PacketTunnelFailure(reason: "embedded runtime could not start (code \(failure.code))"))
            } catch {
                completionHandler(PacketTunnelFailure(reason: "embedded runtime could not start"))
            }
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        Self.log.notice("stopTunnel reason \(reason.rawValue, privacy: .public)")
        events.record("stopTunnel reason \(reason.rawValue)")
        session?.stop()
        session = nil
        startedAt = nil
        memoryPressure?.cancel()
        memoryPressure = nil
        completionHandler()
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        events.record("device sleep")
        completionHandler()
    }

    override func wake() {
        events.record("device wake")
    }

    /// Only fixed reasons and codes are logged, never the profile or keys.
    private static let log = Logger(subsystem: "networkcore.packet-tunnel", category: "tunnel")

    /// The diagnostics request returns `TunnelDiagnostics`; any other message returns the runtime's sanitized
    /// status JSON.
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        switch TunnelAppMessage.decode(messageData) {
        case .runtimeStatus:
            completionHandler?(session?.statusJSON())
        case .diagnostics:
            let diagnostics = TunnelDiagnostics(
                runtimeStatus: session?.statusJSON().flatMap { String(data: $0, encoding: .utf8) },
                memoryFootprintBytes: Self.memoryFootprint(),
                uptimeSeconds: startedAt.map { Date().timeIntervalSince($0) },
                handshake: EmbeddedRuntimeSession.reportedHandshake(),
                events: events.snapshot()
            )
            completionHandler?(try? diagnostics.encoded())
        }
    }

    /// Records system memory pressure, the usual warning before iOS kills an extension over its memory limit.
    private func watchMemoryPressure() {
        guard memoryPressure == nil else {
            return
        }
        let source = DispatchSource.makeMemoryPressureSource(eventMask: [.warning, .critical], queue: .global())
        source.setEventHandler { [weak self, weak source] in
            guard let self = self, let source = source else {
                return
            }
            let level = source.data.contains(.critical) ? "critical" : "warning"
            let footprint = Self.memoryFootprint().map(DeveloperReport.megabytes) ?? "unknown"
            Self.log.notice("memory pressure \(level, privacy: .public)")
            self.events.record("memory pressure \(level), footprint \(footprint)")
        }
        source.resume()
        memoryPressure = source
    }

    /// The extension's physical memory footprint, the figure iOS compares against the extension memory limit.
    static func memoryFootprint() -> UInt64? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) { pointer in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? info.phys_footprint : nil
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
///
/// The reason sits in `errorUserInfo` so it survives the trip to the app, which reads it with
/// `fetchLastDisconnectError`.
struct PacketTunnelFailure: LocalizedError, CustomNSError {
    static let errorDomain = "networkcore.packet-tunnel"

    let reason: String

    var errorDescription: String? {
        reason
    }

    var errorCode: Int {
        1
    }

    var errorUserInfo: [String: Any] {
        [NSLocalizedDescriptionKey: reason]
    }
}
