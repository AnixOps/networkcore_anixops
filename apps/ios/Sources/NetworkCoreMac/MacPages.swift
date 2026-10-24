import ServiceManagement
import SwiftUI

/// Overview: the hero card answers "am I connected, through which node"; the node and any notice follow.
struct MacHomePage: View {
    @ObservedObject var tunnel: TunnelController
    @ObservedObject var state: MacAppState
    @Environment(\.brand) private var brand

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                MacHeroCard(tunnel: tunnel, state: state)
                if let message = tunnel.message {
                    MacNotice(text: message) {
                        tunnel.clearMessage()
                    }
                }
                HStack(alignment: .top, spacing: 16) {
                    nodeCard
                    MacCard(title: "隐私") {
                        Label("不收集你的流量和浏览记录", systemImage: "hand.raised")
                        Label("节点密码和密钥只保存在本机钥匙串", systemImage: "key")
                    }
                }
            }
            .padding(24)
            .frame(maxWidth: 860)
            .frame(maxWidth: .infinity)
        }
    }

    @ViewBuilder
    private var nodeCard: some View {
        MacCard(title: "当前节点") {
            if let name = tunnel.nodeName {
                HStack(spacing: 12) {
                    ProtocolBadge(outboundKind: tunnel.outboundKind)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(name)
                            .font(.body.weight(.semibold))
                            .foregroundStyle(brand.text)
                            .lineLimit(1)
                        Text(ProtocolBadge.spokenName(for: tunnel.outboundKind))
                            .font(.caption)
                            .foregroundStyle(brand.text2)
                    }
                    Spacer(minLength: 8)
                    Button("查看") {
                        state.section = .proxies
                    }
                }
            } else {
                Text("还没有节点")
                    .foregroundStyle(brand.text2)
                Button("导入节点") {
                    state.importing = true
                }
            }
        }
    }
}

/// The route-line connect button with the status, elapsed time and one primary action.
private struct MacHeroCard: View {
    @ObservedObject var tunnel: TunnelController
    @ObservedObject var state: MacAppState
    @Environment(\.brand) private var brand

    private var phase: ConnectPhase { tunnel.phase }

    var body: some View {
        HStack(spacing: 28) {
            Button(action: tap) {
                RouteLineMark(phase: phase, size: 92)
                    .frame(width: 136, height: 136)
                    .background(Brand.line.opacity(0.06), in: Circle())
                    .overlay(
                        Circle().strokeBorder(phase == .on ? Brand.mint.opacity(0.7) : Brand.line.opacity(0.25), lineWidth: 1.5)
                    )
                    .contentShape(Circle())
            }
            .buttonStyle(MacPressableStyle())
            .disabled(phase == .disconnecting)
            .accessibilityLabel(phase.accessibilityLabel)

            VStack(alignment: .leading, spacing: 8) {
                Text(phase.title)
                    .font(.largeTitle.weight(.semibold))
                    .contentTransition(.opacity)
                subtitle
                    .font(.callout.monospacedDigit())
                    .foregroundStyle(Brand.line.opacity(0.75))
                if let name = tunnel.nodeName {
                    Label(name, systemImage: "point.topleft.down.to.point.bottomright.curvepath")
                        .font(.callout)
                        .foregroundStyle(Brand.line.opacity(0.9))
                        .lineLimit(1)
                }
                Button(action: tap) {
                    Text(actionTitle)
                        .font(.body.weight(.semibold))
                        .padding(.horizontal, 14)
                        .padding(.vertical, 3)
                }
                .buttonStyle(.borderedProminent)
                .tint(phase == .on ? Brand.deep.opacity(0.85) : Brand.mint)
                .foregroundStyle(phase == .on ? Brand.line : Brand.deep)
                .controlSize(.large)
                .disabled(phase == .disconnecting)
                .padding(.top, 4)
            }
            .animation(.easeInOut(duration: 0.22), value: phase)
            Spacer(minLength: 0)
        }
        .foregroundStyle(Brand.line)
        .padding(28)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(brand.heroGradient, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    private var actionTitle: LocalizedStringKey {
        switch phase {
        case .unconfigured:
            return "导入节点"
        case .off:
            return "action.connect"
        case .connecting, .reasserting, .on:
            return "断开"
        case .disconnecting:
            return "正在断开…"
        }
    }

    @ViewBuilder
    private var subtitle: some View {
        switch phase {
        case .on:
            if let since = tunnel.connectedSince {
                TimelineView(.periodic(from: since, by: 1)) { context in
                    Text(Self.elapsed(from: since, to: context.date))
                }
            } else {
                Text("安全隧道已建立")
            }
        case .off:
            if case let .blocked(reason, _) = tunnel.coordinator.decision {
                Text(reason)
            } else {
                Text("点击连接，或按 ⇧⌘C")
            }
        case .unconfigured:
            Text("导入第一个节点后即可连接")
        case .connecting:
            Text("正在建立安全隧道")
        case .reasserting:
            Text("网络已切换，马上恢复")
        case .disconnecting:
            Text(" ")
        }
    }

    private func tap() {
        if phase == .unconfigured {
            state.importing = true
        } else {
            tunnel.toggle()
        }
    }

    static func elapsed(from start: Date, to now: Date) -> String {
        let seconds = max(0, Int(now.timeIntervalSince(start)))
        return String(format: "%02d:%02d:%02d", seconds / 3600, seconds / 60 % 60, seconds % 60)
    }
}

/// Proxies: the saved node today; subscriptions and policy groups join this list when the kernel supports them.
struct MacProxiesPage: View {
    @ObservedObject var tunnel: TunnelController
    @ObservedObject var state: MacAppState
    @Environment(\.brand) private var brand

    var body: some View {
        if let name = tunnel.nodeName {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    MacCard(title: "节点") {
                        HStack(spacing: 12) {
                            ProtocolBadge(outboundKind: tunnel.outboundKind)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(name)
                                    .font(.body.weight(.semibold))
                                    .foregroundStyle(brand.text)
                                Text(ProtocolBadge.spokenName(for: tunnel.outboundKind))
                                    .font(.caption)
                                    .foregroundStyle(brand.text2)
                            }
                            Spacer()
                            Circle()
                                .fill(Brand.amber)
                                .frame(width: 8, height: 8)
                                .accessibilityLabel("当前节点")
                        }
                    }
                    Text("导入新节点会替换当前节点。多节点、订阅和策略组会在内核支持后开放。")
                        .font(.caption)
                        .foregroundStyle(brand.text2)
                        .padding(.horizontal, 4)
                }
                .padding(24)
                .frame(maxWidth: 860)
                .frame(maxWidth: .infinity)
            }
        } else {
            BrandEmptyState(
                systemImage: "globe",
                title: "还没有节点",
                message: "粘贴 ss://、vless:// 链接，或导入 WireGuard 配置。"
            ) {
                Button("导入节点") {
                    state.importing = true
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .padding(.top, 6)
            }
            .frame(maxWidth: 520)
            .padding(.top, 80)
        }
    }
}

/// A section whose kernel or platform support is still on the roadmap: says what will live here.
struct MacPlaceholderPage: View {
    let systemImage: String
    let title: LocalizedStringKey
    let message: LocalizedStringKey

    var body: some View {
        BrandEmptyState(systemImage: systemImage, title: title, message: message)
            .frame(maxWidth: 520)
            .padding(.top, 80)
    }
}

/// Activity: the current session as the system and the tunnel extension report it.
struct MacActivityPage: View {
    @ObservedObject var tunnel: TunnelController
    @Environment(\.brand) private var brand

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                MacCard(title: "当前会话") {
                    LabeledContent("连接", value: ConnectPhase.describe(tunnel.connection))
                    LabeledContent("节点", value: tunnel.nodeName ?? String(localized: "未导入"))
                    LabeledContent("出站协议", value: ProtocolBadge.spokenName(for: tunnel.outboundKind))
                    LabeledContent("上次停止原因", value: tunnel.lastDisconnectError ?? String(localized: "无记录"))
                }
                MacCard(title: "运行状态") {
                    Text(tunnel.runtimeStatus ?? String(localized: "隧道未运行"))
                        .font(.callout.monospaced())
                        .foregroundStyle(brand.text2)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    Button("立即刷新") {
                        refresh()
                    }
                }
                BrandEmptyState(
                    systemImage: "list.bullet.rectangle",
                    title: "请求记录还没开放",
                    message: "每条连接命中的规则、策略和插件标记需要内核提供数据，会在后续版本显示在这里。"
                )
            }
            .padding(24)
            .frame(maxWidth: 860)
            .frame(maxWidth: .infinity)
        }
        .onAppear(perform: refresh)
    }

    private func refresh() {
        tunnel.refreshRuntimeStatus()
        tunnel.refreshLastDisconnectError()
    }
}

/// Settings: appearance, login item, privacy and the version.
struct MacSettingsPage: View {
    @AppStorage(Appearance.storageKey) private var appearance = Appearance.system
    @Environment(\.brand) private var brand
    @State private var opensAtLogin = SMAppService.mainApp.status == .enabled
    @State private var loginError: String?

    var body: some View {
        Form {
            Section("外观") {
                Picker("外观", selection: $appearance) {
                    ForEach(Appearance.allCases) { option in
                        Text(option.label).tag(option)
                    }
                }
                .pickerStyle(.segmented)
                Text("纯黑主题适合 OLED 屏幕。")
                    .font(.caption)
                    .foregroundStyle(brand.text2)
            }

            Section("启动") {
                Toggle("登录 Mac 后打开 AnixOps Net", isOn: $opensAtLogin)
                    .onChange(of: opensAtLogin) { _, enabled in
                        // Also fires when a failed change is reverted below; only act on a real change.
                        if enabled != (SMAppService.mainApp.status == .enabled) {
                            setOpensAtLogin(enabled)
                        }
                    }
                if let loginError {
                    Text(loginError)
                        .font(.caption)
                        .foregroundStyle(brand.danger)
                }
            }

            Section("隐私") {
                Label("不收集你的流量和浏览记录", systemImage: "hand.raised")
                Label("节点密码和密钥只保存在本机钥匙串", systemImage: "key")
            }

            Section("关于") {
                LabeledContent("版本", value: Self.version)
            }
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
        .frame(maxWidth: 720)
        .frame(maxWidth: .infinity)
    }

    private func setOpensAtLogin(_ enabled: Bool) {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
            loginError = nil
        } catch {
            loginError = String(localized: "无法更改登录项，请在 系统设置 > 通用 > 登录项 中调整。")
        }
        let actual = SMAppService.mainApp.status == .enabled
        if actual != opensAtLogin {
            opensAtLogin = actual
        }
    }

    private static var version: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "—"
        let build = info?["CFBundleVersion"] as? String ?? "—"
        return "\(short) (\(build))"
    }
}

/// A titled surface card in the current palette.
struct MacCard<Content: View>: View {
    @Environment(\.brand) private var brand
    let title: LocalizedStringKey
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(title)
                .font(.headline)
                .foregroundStyle(brand.text)
            content
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(brand.surface, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(brand.border.opacity(0.6)))
    }
}

/// An error or notice with a dismiss button.
private struct MacNotice: View {
    @Environment(\.brand) private var brand
    let text: String
    let dismiss: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(brand.warning)
                .accessibilityHidden(true)
            Text(text)
                .font(.callout)
                .foregroundStyle(brand.text)
                .frame(maxWidth: .infinity, alignment: .leading)
                .textSelection(.enabled)
            Button(action: dismiss) {
                Image(systemName: "xmark")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("关闭提示")
        }
        .padding(14)
        .background(brand.surface, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(brand.warning.opacity(0.4)))
    }
}

/// Shrinks slightly while pressed.
private struct MacPressableStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.96 : 1)
            .animation(.spring(response: 0.25, dampingFraction: 0.8), value: configuration.isPressed)
    }
}
