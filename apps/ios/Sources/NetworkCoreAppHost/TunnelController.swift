import Foundation
import NetworkCoreBridge
import NetworkExtension

/// Owns the app's single VPN configuration: imports an `ss://` node or a WireGuard config, saves it as the
/// tunnel profile, and starts or stops the packet tunnel. Node secrets go only into the Keychain; the saved
/// profile holds a persistent reference to them and a config without them.
@MainActor
final class TunnelController: ObservableObject {
    @Published private(set) var coordinator: AppCoordinator
    @Published private(set) var nodeName: String?
    @Published private(set) var connection: NEVPNStatus = .invalid
    @Published private(set) var message: String?
    @Published private(set) var runtimeStatus: String?
    /// Developer mode: the extension's diagnostics and the last stop error, kept after the message is replaced.
    @Published private(set) var diagnostics: TunnelDiagnostics?
    @Published private(set) var lastDisconnectError: String?
    /// When the current connection came up, for the elapsed time on the home screen.
    @Published private(set) var connectedSince: Date?

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

    /// Parses pasted text for the import preview without saving anything.
    func preview(_ link: String) -> Result<ImportPreview, ImportFailure> {
        do {
            let profile = try TunnelNodeImport.parse(link, profileID: Self.profileID)
            return .success(ImportPreview(
                name: profile.displayName,
                outboundKind: profile.config.outboundKind,
                maskedServer: ImportPreview.mask(profile.serverAddress)
            ))
        } catch let error as TunnelNodeImportError {
            return .failure(ImportFailure(message: Self.describe(error)))
        } catch {
            return .failure(ImportFailure(message: "无法解析节点"))
        }
    }

    func clearMessage() {
        message = nil
    }

    /// Saves the node as the tunnel profile. Returns whether it was saved; on failure `message` says why.
    @discardableResult
    func importLink(_ link: String) async -> Bool {
        let profileID = Self.profileID
        let profile: TunnelProfile
        do {
            profile = try TunnelNodeImport.parse(link, profileID: profileID)
        } catch let error as TunnelNodeImportError {
            message = Self.describe(error)
            return false
        } catch {
            message = "无法解析节点"
            return false
        }
        guard let providerBundleIdentifier = Self.tunnelBundleIdentifier() else {
            message = "找不到隧道扩展"
            return false
        }

        let config: Data
        let interface: Data
        let keyReference: Data
        do {
            config = try profile.config.withoutSecret().encoded()
            interface = try profile.interface.encoded()
        } catch {
            message = "无法生成隧道配置"
            return false
        }
        do {
            keyReference = try NodeSecretStore.save(profile.config.secret.keychainValue(), account: profileID)
        } catch {
            message = "无法把节点密钥保存到钥匙串"
            return false
        }

        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = providerBundleIdentifier
        tunnelProtocol.serverAddress = profile.serverAddress
        tunnelProtocol.passwordReference = keyReference
        var providerConfiguration: [String: Any] = [
            TunnelProfileKeys.runtimeConfig: config,
            TunnelProfileKeys.tunnelInterface: interface,
            TunnelProfileKeys.nodeName: profile.displayName,
        ]
        let library = (try? MitmPluginLibrary.load(from: MitmPluginLibrary.defaultURL)) ?? MitmPluginLibrary()
        if let plugins = try? MitmPluginLibrary.profileValue(library.activeTexts), !library.activeTexts.isEmpty {
            providerConfiguration[TunnelProfileKeys.mitmPlugins] = plugins
            let scripts = (try? MitmScriptLibrary.load(from: MitmScriptLibrary.defaultURL)) ?? MitmScriptLibrary()
            if let sources = try? scripts.sources(for: library.activeScriptReferences), !sources.isEmpty,
               let value = try? MitmScriptLibrary.profileValue(sources)
            {
                providerConfiguration[TunnelProfileKeys.mitmScripts] = value
            }
        }
        tunnelProtocol.providerConfiguration = providerConfiguration

        let target = manager ?? NETunnelProviderManager()
        target.protocolConfiguration = tunnelProtocol
        target.localizedDescription = "AnixOps Net"
        target.isEnabled = true
        do {
            try await target.saveToPreferences()
            // Reload so the connection object reflects the saved profile.
            try await target.loadFromPreferences()
            manager = target
            message = nil
        } catch {
            message = "保存 VPN 配置失败或未获授权"
            refresh()
            return false
        }
        refresh()
        return true
    }

    /// Puts the enabled HTTPS decryption plugins and the scripts the user allowed in them into the saved profile.
    /// Without a profile there is nothing to update: the next import picks them up. A running tunnel keeps its
    /// plugins until it reconnects. Returns whether the profile changed.
    @discardableResult
    func applyMitmPlugins(_ texts: [String], scripts: [String: String] = [:]) async -> Bool {
        guard let manager,
              let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol
        else {
            return false
        }
        var configuration = tunnelProtocol.providerConfiguration ?? [:]
        let current = MitmPluginLibrary.texts(fromProfileValue: configuration[TunnelProfileKeys.mitmPlugins] as? Data)
        let currentScripts = MitmScriptLibrary.sources(fromProfileValue: configuration[TunnelProfileKeys.mitmScripts] as? Data)
        let scripts = texts.isEmpty ? [:] : scripts
        guard current != texts || currentScripts != scripts else {
            return false
        }
        if texts.isEmpty {
            configuration.removeValue(forKey: TunnelProfileKeys.mitmPlugins)
        } else {
            guard let value = try? MitmPluginLibrary.profileValue(texts) else {
                message = "无法生成插件配置"
                return false
            }
            configuration[TunnelProfileKeys.mitmPlugins] = value
        }
        if scripts.isEmpty {
            configuration.removeValue(forKey: TunnelProfileKeys.mitmScripts)
        } else {
            guard let value = try? MitmScriptLibrary.profileValue(scripts) else {
                message = "无法生成脚本配置"
                return false
            }
            configuration[TunnelProfileKeys.mitmScripts] = value
        }
        tunnelProtocol.providerConfiguration = configuration
        manager.protocolConfiguration = tunnelProtocol
        do {
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
        } catch {
            message = "保存插件到 VPN 配置失败"
            refresh()
            return false
        }
        refresh()
        return true
    }

    func toggle() {
        guard let manager = manager else {
            message = "请先导入节点"
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
            try session.sendProviderMessage(TunnelAppMessage.runtimeStatus.encoded) { [weak self] data in
                let text = data.flatMap { String(data: $0, encoding: .utf8) }
                Task { @MainActor in
                    self?.runtimeStatus = text
                }
            }
        } catch {
            runtimeStatus = nil
        }
    }

    /// Asks the running extension for developer-mode diagnostics; clears them when it is not running.
    func refreshDiagnostics() {
        guard let session = manager?.connection as? NETunnelProviderSession, isConnected else {
            diagnostics = nil
            return
        }
        do {
            try session.sendProviderMessage(TunnelAppMessage.diagnostics.encoded) { [weak self] data in
                let diagnostics = data.flatMap { try? TunnelDiagnostics.decoded(from: $0) }
                Task { @MainActor in
                    self?.diagnostics = diagnostics
                }
            }
        } catch {
            diagnostics = nil
        }
    }

    /// Reads the system's record of why the tunnel last stopped, for developer mode.
    func refreshLastDisconnectError() {
        manager?.connection.fetchLastDisconnectError { [weak self] error in
            let text = error.map { Self.describe(disconnectError: $0 as NSError) }
            Task { @MainActor in
                self?.lastDisconnectError = text
            }
        }
    }

    /// The saved profile's outbound protocol, without address or key.
    var outboundKind: String? {
        let configuration = (manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        guard let data = configuration?[TunnelProfileKeys.runtimeConfig] as? Data else {
            return nil
        }
        return (try? EmbeddedRuntimeConfig.decoded(from: data))?.outboundKind
    }

    private func refresh() {
        let saved = manager?.isEnabled == true && manager?.protocolConfiguration != nil
        coordinator.apply(Self.platformStatus(saved: saved))
        let previous = connection
        connection = manager?.connection.status ?? .invalid
        connectedSince = connection == .connected ? manager?.connection.connectedDate : nil
        if connection == .disconnected, previous != .disconnected, previous != .invalid {
            showLastDisconnectError()
        }
        let configuration = (manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        nodeName = configuration?[TunnelProfileKeys.nodeName] as? String
    }

    /// Shows why the tunnel stopped, such as the extension's start failure, which iOS otherwise hides.
    private func showLastDisconnectError() {
        manager?.connection.fetchLastDisconnectError { [weak self] error in
            guard let error = error else {
                return
            }
            let text = Self.describe(disconnectError: error as NSError)
            Task { @MainActor in
                self?.message = text
                self?.lastDisconnectError = text
            }
        }
    }

    /// The error and its underlying errors, which carry the extension's fixed failure reason.
    nonisolated private static func describe(disconnectError: NSError) -> String {
        var lines = ["隧道已停止：\(disconnectError.localizedDescription)"]
        var underlying = disconnectError.userInfo[NSUnderlyingErrorKey] as? NSError
        while let error = underlying {
            lines.append("\(error.localizedDescription) (\(error.domain) \(error.code))")
            underlying = error.userInfo[NSUnderlyingErrorKey] as? NSError
        }
        return lines.joined(separator: "\n")
    }

    /// The app cannot load the runtime itself: this build ships it inside the extension, which re-checks
    /// the live handshake on every start.
    private static func platformStatus(saved: Bool) -> IosPlatformStatus {
        IosPlatformFactsProbe.currentStatus(
            vpnConfiguration: saved ? .savedAndAuthorized : .notSaved,
            embeddedRuntime: .available
        )
    }

    private static let profileID = "default"

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

    private static func describe(_ error: TunnelNodeImportError) -> String {
        switch error {
        case .unrecognized:
            return "请粘贴 ss://、vless:// 链接或 WireGuard 配置"
        case let .shadowsocks(error):
            switch error {
            case .notShadowsocksLink, .malformed:
                return "节点链接格式不正确"
            case .unsupportedMethod:
                return "目前只支持 Shadowsocks-2022 加密方式"
            case .unsupportedPlugin:
                return "暂不支持带插件的节点"
            }
        case let .vless(error):
            switch error {
            case .notVlessLink, .malformed:
                return "节点链接格式不正确"
            case .invalidUUID:
                return "VLESS 用户 ID 格式不正确"
            case .unsupportedSecurity:
                return "目前只支持 REALITY 安全类型的 VLESS 节点"
            case .unsupportedTransport:
                return "目前只支持 TCP 传输的 VLESS 节点"
            case .unsupportedFlow:
                return "目前只支持 xtls-rprx-vision 流控或不使用流控"
            case .invalidRealitySettings:
                return "REALITY 参数（sni、pbk、sid）不正确"
            }
        case let .wireguard(error):
            switch error {
            case .malformed:
                return "WireGuard 配置格式不正确"
            case let .missingField(field):
                return "WireGuard 配置缺少 \(field)"
            case .invalidKey:
                return "WireGuard 密钥格式不正确"
            case .invalidAddress:
                return "WireGuard 地址或 AllowedIPs 格式不正确"
            case .invalidEndpoint:
                return "WireGuard Endpoint 格式不正确"
            case .unsupportedPeerCount:
                return "目前只支持一个 Peer 的 WireGuard 配置"
            }
        }
    }
}

/// What the import sheet shows before saving: no password, key or full server address.
struct ImportPreview: Equatable {
    let name: String
    let outboundKind: String
    let maskedServer: String

    /// Keeps the first two and last four characters of a host so the user can recognize it in a screenshot-safe way.
    static func mask(_ host: String) -> String {
        guard host.count > 8 else {
            return "••••"
        }
        return "\(host.prefix(2))••••\(host.suffix(4))"
    }
}

struct ImportFailure: Error, Equatable {
    let message: String
}
