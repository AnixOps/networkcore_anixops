import Foundation
import NetworkCoreBridge
import NetworkExtension

/// The saved tunnel as the widgets and the Control Center switch see it: status, node name and protocol only.
/// Compiled into the app and the widget extension; it reads the system VPN configuration, never the node secret.
struct TunnelSnapshot {
    var status: NEVPNStatus
    var nodeName: String?
    var outboundKind: String?

    /// Shown in the widget gallery, where no real configuration is read.
    static let placeholder = TunnelSnapshot(status: .connected, nodeName: "Tokyo 01", outboundKind: "shadowsocks-2022")

    var isOn: Bool {
        status == .connected || status == .connecting || status == .reasserting
    }

    static func load() async -> TunnelSnapshot {
        guard let manager = try? await NETunnelProviderManager.loadAllFromPreferences().first else {
            return TunnelSnapshot(status: .invalid, nodeName: nil, outboundKind: nil)
        }
        let configuration = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        let runtime = (configuration?[TunnelProfileKeys.runtimeConfig] as? Data).flatMap { try? EmbeddedRuntimeConfig.decoded(from: $0) }
        return TunnelSnapshot(
            status: manager.connection.status,
            nodeName: configuration?[TunnelProfileKeys.nodeName] as? String,
            outboundKind: runtime?.outboundKind
        )
    }
}

/// Starts or stops the saved tunnel from a widget button or the Control Center switch.
enum TunnelSwitch {
    enum Failure: Error, LocalizedError {
        case notConfigured
        case startFailed

        var errorDescription: String? {
            switch self {
            case .notConfigured:
                return String(localized: "请先在 App 里导入节点")
            case .startFailed:
                return String(localized: "无法启动隧道")
            }
        }
    }

    static func set(on: Bool) async throws {
        guard let manager = try await NETunnelProviderManager.loadAllFromPreferences().first,
              manager.protocolConfiguration != nil
        else {
            throw Failure.notConfigured
        }
        guard on else {
            manager.connection.stopVPNTunnel()
            return
        }
        if !manager.isEnabled {
            manager.isEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
        }
        do {
            try manager.connection.startVPNTunnel()
        } catch {
            throw Failure.startFailed
        }
    }
}
