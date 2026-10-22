import Foundation
import NetworkCoreBridge
import NetworkExtension

/// Owns the app's single VPN configuration: imports an `ss://` node, saves it as the tunnel profile, and
/// starts or stops the packet tunnel. The node key goes only into the Keychain; the saved profile holds a
/// persistent reference to it and a config without it.
@MainActor
final class TunnelController: ObservableObject {
    @Published private(set) var coordinator: AppCoordinator
    @Published private(set) var nodeName: String?
    @Published private(set) var connection: NEVPNStatus = .invalid
    @Published private(set) var message: String?
    @Published private(set) var runtimeStatus: String?

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    init() {
        coordinator = AppCoordinator(status: Self.platformStatus(saved: false))
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.refresh()
            }
        }
    }

    deinit {
        if let statusObserver = statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
    }

    var isConnected: Bool {
        connection == .connected || connection == .connecting || connection == .reasserting
    }

    func load() async {
        do {
            manager = try await NETunnelProviderManager.loadAllFromPreferences().first
            message = nil
        } catch {
            message = "无法读取 VPN 配置"
        }
        refresh()
    }

    func importLink(_ link: String) async {
        let node: ShadowsocksNode
        do {
            node = try ShadowsocksNodeLink.parse(link)
        } catch let error as ShadowsocksLinkError {
            message = Self.describe(error)
            return
        } catch {
            message = "无法解析节点链接"
            return
        }
        guard let providerBundleIdentifier = Self.tunnelBundleIdentifier() else {
            message = "找不到隧道扩展"
            return
        }

        let profileID = "default"
        let config: Data
        let keyReference: Data
        do {
            config = try EmbeddedRuntimeConfig(node: node, profileID: profileID).withoutSecret().encoded()
        } catch {
            message = "无法生成隧道配置"
            return
        }
        do {
            keyReference = try NodeSecretStore.save(node.password, account: profileID)
        } catch {
            message = "无法把节点密钥保存到钥匙串"
            return
        }

        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = providerBundleIdentifier
        tunnelProtocol.serverAddress = node.host
        tunnelProtocol.passwordReference = keyReference
        tunnelProtocol.providerConfiguration = [
            TunnelProfileKeys.runtimeConfig: config,
            TunnelProfileKeys.nodeName: node.name ?? node.host,
        ]

        let target = manager ?? NETunnelProviderManager()
        target.protocolConfiguration = tunnelProtocol
        target.localizedDescription = "NetworkCore"
        target.isEnabled = true
        do {
            try await target.saveToPreferences()
            // Reload so the connection object reflects the saved profile.
            try await target.loadFromPreferences()
            manager = target
            message = "已保存节点"
        } catch {
            message = "保存 VPN 配置失败或未获授权"
        }
        refresh()
    }

    func toggle() {
        guard let manager = manager else {
            return
        }
        if isConnected {
            manager.connection.stopVPNTunnel()
            return
        }
        guard coordinator.canStartTunnel else {
            return
        }
        do {
            try manager.connection.startVPNTunnel()
            message = nil
        } catch {
            message = "无法启动隧道"
        }
    }

    /// Asks the running extension for its sanitized runtime status.
    func refreshRuntimeStatus() {
        guard let session = manager?.connection as? NETunnelProviderSession, connection == .connected else {
            runtimeStatus = nil
            return
        }
        do {
            try session.sendProviderMessage(Data()) { [weak self] data in
                let text = data.flatMap { String(data: $0, encoding: .utf8) }
                Task { @MainActor in
                    self?.runtimeStatus = text
                }
            }
        } catch {
            runtimeStatus = nil
        }
    }

    private func refresh() {
        let saved = manager?.isEnabled == true && manager?.protocolConfiguration != nil
        coordinator.apply(Self.platformStatus(saved: saved))
        connection = manager?.connection.status ?? .invalid
        let configuration = (manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        nodeName = configuration?[TunnelProfileKeys.nodeName] as? String
    }

    /// The app cannot load the runtime itself: this build ships it inside the extension, which re-checks
    /// the live handshake on every start.
    private static func platformStatus(saved: Bool) -> IosPlatformStatus {
        IosPlatformFactsProbe.currentStatus(
            vpnConfiguration: saved ? .savedAndAuthorized : .notSaved,
            embeddedRuntime: .available
        )
    }

    private static func tunnelBundleIdentifier() -> String? {
        guard let plugins = Bundle.main.builtInPlugInsURL,
              let urls = try? FileManager.default.contentsOfDirectory(at: plugins, includingPropertiesForKeys: nil)
        else {
            return nil
        }
        for url in urls where url.pathExtension == "appex" {
            guard let bundle = Bundle(url: url),
                  let info = bundle.object(forInfoDictionaryKey: "NSExtension") as? [String: Any],
                  info["NSExtensionPointIdentifier"] as? String == "com.apple.networkextension.packet-tunnel"
            else {
                continue
            }
            return bundle.bundleIdentifier
        }
        return nil
    }

    private static func describe(_ error: ShadowsocksLinkError) -> String {
        switch error {
        case .notShadowsocksLink:
            return "请粘贴 ss:// 开头的链接"
        case .malformed:
            return "节点链接格式不正确"
        case .unsupportedMethod:
            return "目前只支持 Shadowsocks-2022 加密方式"
        case .unsupportedPlugin:
            return "暂不支持带插件的节点"
        }
    }
}
