import Foundation
import NetworkCoreBridge
import NetworkExtension
#if os(iOS)
import WidgetKit
#endif

/// Owns the app's single VPN configuration: imports a node (a share link of any protocol the engine runs, a
/// subscription text or a WireGuard config), saves it as the
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
    /// Every node of the last subscription or multi-node import, from the Keychain. Nil after a single-node import.
    @Published private(set) var library: NodeLibrary?
    /// Delay test results by node id.
    @Published private(set) var latencies: [String: NodeLatency] = [:]
    @Published private(set) var refreshingSubscription = false

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    /// Set when a node switch stopped the tunnel; the tunnel starts again once it is down.
    private var restartAfterStop = false

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
            message = String(localized: "无法读取 VPN 配置")
        }
        library = (try? NodeSecretStore.value(account: NodeLibrary.keychainAccount))
            .flatMap { $0 }
            .flatMap { try? NodeLibrary.fromKeychainValue($0) }
        refresh()
    }

    /// Parses pasted text for the import preview without saving anything. A subscription link is downloaded only
    /// when it is imported.
    func preview(_ link: String) -> Result<ImportPreview, ImportFailure> {
        if let url = SubscriptionLink.url(from: link) {
            let host = url.host ?? url.absoluteString
            return .success(ImportPreview(
                name: host,
                outboundKind: ImportPreview.subscriptionKind,
                maskedServer: ImportPreview.mask(host)
            ))
        }
        do {
            let profile = try TunnelNodeImport.parse(link, profileID: Self.profileID, native: NativeNodeImporterFFI.importNodes)
            return .success(ImportPreview(
                name: profile.displayName,
                outboundKind: profile.config.outboundKind,
                maskedServer: ImportPreview.mask(profile.serverAddress)
            ))
        } catch let error as TunnelNodeImportError {
            return .failure(ImportFailure(message: Self.describe(error)))
        } catch {
            return .failure(ImportFailure(message: String(localized: "无法解析节点")))
        }
    }

    func clearMessage() {
        message = nil
    }

    /// Saves the node as the tunnel profile; a subscription link is downloaded first and every node goes to the
    /// node list. Returns whether it was saved; on failure `message` says why.
    @discardableResult
    func importLink(_ link: String) async -> Bool {
        if let url = SubscriptionLink.url(from: link) {
            return await importSubscription(url, refreshing: nil)
        }
        let imported: TunnelImport
        do {
            imported = try TunnelNodeImport.parseImport(
                link,
                profileID: Self.profileID,
                native: NativeNodeImporterFFI.importNodes
            )
        } catch let error as TunnelNodeImportError {
            message = Self.describe(error)
            return false
        } catch {
            message = String(localized: "无法解析节点")
            return false
        }
        let nodes = imported.report.map { NodeLibrary(report: $0, subscriptionURL: nil, keeping: nil) }
        guard await save(imported.profile, routed: nodes?.routesByRules == true) else {
            return false
        }
        storeLibrary(nodes)
        return true
    }

    /// Re-downloads the current subscription and keeps the selected node, the rules switch and the group picks
    /// where they still apply.
    @discardableResult
    func refreshSubscription() async -> Bool {
        guard let current = library, let link = current.subscriptionURL, let url = URL(string: link) else {
            return false
        }
        refreshingSubscription = true
        defer { refreshingSubscription = false }
        return await importSubscription(url, refreshing: current)
    }

    /// Switches between the subscription's rules and groups and the selected node alone. A running tunnel
    /// restarts on the new setting.
    func setFollowsRules(_ on: Bool) async {
        guard var nodes = library, nodes.routing != nil, nodes.followsRules != on, let selected = nodes.selected else {
            return
        }
        let profile: TunnelProfile
        do {
            profile = try TunnelProfile(node: selected, profileID: Self.profileID)
        } catch {
            message = String(localized: "无法生成隧道配置")
            return
        }
        nodes.followsRules = on
        let wasRunning = isConnected
        guard await save(profile, routed: nodes.routesByRules) else {
            return
        }
        storeLibrary(nodes)
        if wasRunning {
            restart()
        }
    }

    /// Picks the member a `select` group uses. A tunnel running by the rules restarts on it.
    func selectMember(_ member: String, inGroup groupID: String) async {
        guard var nodes = library,
              let group = nodes.routing?.groups.first(where: { $0.id == groupID }),
              group.isSelectable, group.members.contains(member), nodes.selection(in: group) != member
        else {
            return
        }
        nodes.groupSelections[groupID] = member
        storeLibrary(nodes)
        if nodes.routesByRules, isConnected {
            restart()
        }
    }

    /// Makes `id` the tunnel's node. A running tunnel restarts on it unless the subscription's rules pick the nodes.
    func selectNode(_ id: String) async {
        guard var nodes = library, let node = nodes.node(id: id), nodes.selectedID != id else {
            return
        }
        let profile: TunnelProfile
        do {
            profile = try TunnelProfile(node: node, profileID: Self.profileID)
        } catch {
            message = String(localized: "无法生成隧道配置")
            return
        }
        let wasRunning = isConnected
        guard await save(profile, routed: nodes.routesByRules) else {
            return
        }
        nodes.selectedID = id
        storeLibrary(nodes)
        if wasRunning, !nodes.routesByRules {
            restart()
        }
    }

    /// Stops the tunnel and starts it again once it is down, so the extension reads the new profile and node list.
    private func restart() {
        restartAfterStop = true
        manager?.connection.stopVPNTunnel()
    }

    /// Measures every listed node's TCP connect time, a few at a time.
    func testLatency() async {
        guard let nodes = library?.nodes, !nodes.isEmpty else {
            return
        }
        for node in nodes {
            latencies[node.id] = NodeLibrary.usesUDP(node.protocol) ? .notMeasurable : .measuring
        }
        let targets = nodes.filter { !NodeLibrary.usesUDP($0.protocol) }
        let batch = 8
        for start in stride(from: 0, to: targets.count, by: batch) {
            let slice = targets[start..<min(start + batch, targets.count)]
            let probes = slice.map { (id: $0.id, host: $0.server, port: $0.port) }
            let results = await withTaskGroup(of: (String, TimeInterval?).self, returning: [(String, TimeInterval?)].self) { group in
                for probe in probes {
                    group.addTask {
                        (probe.id, await NodeLatencyProbe.tcpConnect(host: probe.host, port: probe.port))
                    }
                }
                var results: [(String, TimeInterval?)] = []
                for await result in group {
                    results.append(result)
                }
                return results
            }
            for (id, seconds) in results {
                latencies[id] = seconds.map { .millis(Int(($0 * 1000).rounded())) } ?? .failed
            }
        }
    }

    /// Downloads and imports a subscription; `refreshing` is the library it replaces, nil for a new subscription.
    private func importSubscription(_ url: URL, refreshing previous: NodeLibrary?) async -> Bool {
        let text: String
        do {
            text = try await Self.download(url)
        } catch {
            message = String(localized: "订阅下载失败，请检查链接和网络")
            return false
        }
        let report: NativeImportReport
        do {
            report = try NativeImportReport.decoded(from: NativeNodeImporterFFI.importNodes(text))
        } catch let failure as NativeImportFailure {
            message = Self.describe(.native(failure))
            return false
        } catch {
            message = Self.describe(.native(.unavailable))
            return false
        }
        let nodes = previous?.refreshed(with: report)
            ?? NodeLibrary(report: report, subscriptionURL: url.absoluteString, keeping: nil)
        guard let selected = nodes.selected else {
            message = Self.describe(.native(.noSupportedNode(
                protocols: report.unsupported.map(\.protocol),
                reasons: []
            )))
            return false
        }
        let profile: TunnelProfile
        do {
            profile = try TunnelProfile(node: selected, profileID: Self.profileID)
        } catch {
            message = String(localized: "无法生成隧道配置")
            return false
        }
        // A refresh that keeps the same node and rules switch leaves the saved profile and the running tunnel alone.
        let unchanged = previous?.selected == selected && previous?.routesByRules == nodes.routesByRules
        if !unchanged {
            guard await save(profile, routed: nodes.routesByRules) else {
                return false
            }
        }
        storeLibrary(nodes)
        return true
    }

    /// Subscription bodies are text; the importer refuses anything larger than this.
    private static let maxSubscriptionBytes = 4 * 1024 * 1024

    private static func download(_ url: URL) async throws -> String {
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 30)
        request.setValue("AnixOpsNet/1.0", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode),
              data.count <= maxSubscriptionBytes
        else {
            throw URLError(.badServerResponse)
        }
        return String(decoding: data, as: UTF8.self)
    }

    private func storeLibrary(_ nodes: NodeLibrary?) {
        if library?.nodes != nodes?.nodes {
            latencies = [:]
        }
        library = nodes
        if let nodes, let value = try? nodes.keychainValue() {
            _ = try? NodeSecretStore.save(value, account: NodeLibrary.keychainAccount)
        } else {
            try? NodeSecretStore.delete(account: NodeLibrary.keychainAccount)
        }
    }

    /// Saves `profile` as the tunnel profile; `routed` makes the extension follow the node library's rules.
    private func save(_ profile: TunnelProfile, routed: Bool = false) async -> Bool {
        let profileID = Self.profileID
        guard let providerBundleIdentifier = Self.tunnelBundleIdentifier() else {
            message = String(localized: "找不到隧道扩展")
            return false
        }

        let config: Data
        let interface: Data
        let keyReference: Data
        do {
            config = try profile.config.withoutSecret().encoded()
            interface = try profile.interface.encoded()
        } catch {
            message = String(localized: "无法生成隧道配置")
            return false
        }
        do {
            keyReference = try NodeSecretStore.save(profile.config.secret.keychainValue(), account: profileID)
        } catch {
            message = String(localized: "无法把节点密钥保存到钥匙串")
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
        if routed {
            providerConfiguration[TunnelProfileKeys.routing] = true
        }
        let library = (try? MitmPluginLibrary.load(from: MitmPluginLibrary.defaultURL)) ?? MitmPluginLibrary()
        if let plugins = try? MitmPluginLibrary.profileValue(library.activeTexts), !library.activeTexts.isEmpty {
            providerConfiguration[TunnelProfileKeys.mitmPlugins] = plugins
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
            message = String(localized: "保存 VPN 配置失败或未获授权")
            refresh()
            return false
        }
        refresh()
        return true
    }

    /// Puts the enabled HTTPS decryption plugins into the saved profile. Without a profile there is nothing to
    /// update: the next import picks them up. A running tunnel keeps its plugins until it reconnects.
    /// Returns whether the profile changed.
    @discardableResult
    func applyMitmPlugins(_ texts: [String]) async -> Bool {
        guard let manager,
              let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol
        else {
            return false
        }
        var configuration = tunnelProtocol.providerConfiguration ?? [:]
        let current = MitmPluginLibrary.texts(fromProfileValue: configuration[TunnelProfileKeys.mitmPlugins] as? Data)
        guard current != texts else {
            return false
        }
        if texts.isEmpty {
            configuration.removeValue(forKey: TunnelProfileKeys.mitmPlugins)
        } else {
            guard let value = try? MitmPluginLibrary.profileValue(texts) else {
                message = String(localized: "无法生成插件配置")
                return false
            }
            configuration[TunnelProfileKeys.mitmPlugins] = value
        }
        tunnelProtocol.providerConfiguration = configuration
        manager.protocolConfiguration = tunnelProtocol
        do {
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
        } catch {
            message = String(localized: "保存插件到 VPN 配置失败")
            refresh()
            return false
        }
        refresh()
        return true
    }

    func toggle() {
        guard let manager = manager else {
            message = String(localized: "请先导入节点")
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
            message = String(localized: "无法启动隧道")
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
        if restartAfterStop, connection == .disconnected {
            // The node switch stopped the tunnel on purpose: no error to show, just start it on the new node.
            restartAfterStop = false
            try? manager?.connection.startVPNTunnel()
        } else if connection == .disconnected, previous != .disconnected, previous != .invalid {
            showLastDisconnectError()
        }
        let configuration = (manager?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        let previousNode = nodeName
        nodeName = configuration?[TunnelProfileKeys.nodeName] as? String
        if connection != previous || nodeName != previousNode {
            Self.reloadWidgets()
        }
    }

    /// The Home Screen widget and the Control Center switch read the VPN configuration themselves;
    /// this only tells them it changed.
    private static func reloadWidgets() {
        #if os(iOS)
        WidgetCenter.shared.reloadAllTimelines()
        if #available(iOS 18.0, *) {
            ControlCenter.shared.reloadAllControls()
        }
        #endif
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
        var lines = [String(localized: "隧道已停止：\(disconnectError.localizedDescription)")]
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
            return String(localized: "请粘贴节点链接、订阅内容或 WireGuard 配置")
        case let .native(failure):
            switch failure {
            case .unrecognized:
                return String(localized: "无法识别的节点链接或订阅格式")
            case .empty:
                return String(localized: "内容为空")
            case .tooLarge:
                return String(localized: "订阅内容过大")
            case let .noSupportedNode(protocols, _):
                let names = Array(Set(protocols)).sorted().joined(separator: "、")
                return names.isEmpty
                    ? String(localized: "没有可用的节点")
                    : String(localized: "没有可用的节点（暂不支持：\(names)）")
            case .unavailable:
                return String(localized: "导入组件不可用，请更新 App")
            }
        case let .shadowsocks(error):
            switch error {
            case .notShadowsocksLink, .malformed:
                return String(localized: "节点链接格式不正确")
            case .unsupportedMethod:
                return String(localized: "目前只支持 Shadowsocks-2022 加密方式")
            case .unsupportedPlugin:
                return String(localized: "暂不支持带插件的节点")
            }
        case let .vless(error):
            switch error {
            case .notVlessLink, .malformed:
                return String(localized: "节点链接格式不正确")
            case .invalidUUID:
                return String(localized: "VLESS 用户 ID 格式不正确")
            case .unsupportedSecurity:
                return String(localized: "目前只支持 REALITY 安全类型的 VLESS 节点")
            case .unsupportedTransport:
                return String(localized: "目前只支持 TCP 传输的 VLESS 节点")
            case .unsupportedFlow:
                return String(localized: "目前只支持 xtls-rprx-vision 流控或不使用流控")
            case .invalidRealitySettings:
                return String(localized: "REALITY 参数（sni、pbk、sid）不正确")
            }
        case let .wireguard(error):
            switch error {
            case .malformed:
                return String(localized: "WireGuard 配置格式不正确")
            case let .missingField(field):
                return String(localized: "WireGuard 配置缺少 \(field)")
            case .invalidKey:
                return String(localized: "WireGuard 密钥格式不正确")
            case .invalidAddress:
                return String(localized: "WireGuard 地址或 AllowedIPs 格式不正确")
            case .invalidEndpoint:
                return String(localized: "WireGuard Endpoint 格式不正确")
            case .unsupportedPeerCount:
                return String(localized: "目前只支持一个 Peer 的 WireGuard 配置")
            }
        }
    }
}

/// A delay test result for one node.
enum NodeLatency: Equatable {
    case measuring
    case millis(Int)
    case failed
    /// QUIC nodes: the app cannot measure them without the tunnel engine.
    case notMeasurable
}

/// What the import sheet shows before saving: no password, key or full server address.
struct ImportPreview: Equatable {
    /// `outboundKind` of a subscription link, which is only downloaded on import.
    static let subscriptionKind = "subscription"

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
