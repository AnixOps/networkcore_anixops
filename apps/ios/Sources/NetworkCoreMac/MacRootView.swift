import SwiftUI

/// The main window: a sidebar with the six sections, the page, and a toolbar with import and connect.
struct MacRootView: View {
    @ObservedObject var tunnel: TunnelController
    @ObservedObject var state: MacAppState
    @AppStorage(Appearance.storageKey) private var appearance = Appearance.system
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        let brand = BrandPalette.resolve(appearance: appearance, scheme: colorScheme)
        NavigationSplitView {
            sidebar(brand)
        } detail: {
            NavigationStack {
                page
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
                    .background(brand.bg)
                    .navigationTitle(state.section?.title ?? "AnixOps Net")
            }
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    state.importing = true
                } label: {
                    Label("导入节点", systemImage: "plus")
                }
                .help("导入节点（⌘I）")
                Button {
                    tunnel.toggle()
                } label: {
                    Label(tunnel.toggleTitle, systemImage: "power")
                }
                .help("连接或断开（⇧⌘C）")
                .disabled(tunnel.phase == .unconfigured || tunnel.phase == .disconnecting)
            }
        }
        .tint(brand.primary)
        .environment(\.brand, brand)
        .sheet(isPresented: $state.importing) {
            ImportView(tunnel: tunnel)
                .frame(width: 480, height: 580)
                .environment(\.brand, brand)
                .tint(brand.primary)
        }
    }

    private func sidebar(_ brand: BrandPalette) -> some View {
        List(selection: $state.section) {
            ForEach(MacSection.allCases) { section in
                Label(section.title, systemImage: section.systemImage)
                    .tag(section)
            }
        }
        .listStyle(.sidebar)
        .modifier(SolidBackground(brand: brand))
        .safeAreaInset(edge: .bottom) {
            SidebarStatus(tunnel: tunnel)
                .padding(12)
        }
        .navigationSplitViewColumnWidth(min: 190, ideal: 210, max: 260)
    }

    @ViewBuilder
    private var page: some View {
        switch state.section ?? .home {
        case .home:
            MacHomePage(tunnel: tunnel, state: state)
        case .proxies:
            MacProxiesPage(tunnel: tunnel, state: state)
        case .rules:
            MacPlaceholderPage(
                systemImage: "arrow.triangle.branch",
                title: "规则与分流",
                message: "按域名和 IP 分流、规则集和规则测试会放在这里。当前版本按节点配置转发全部流量。"
            )
        case .extensions:
            MacPlaceholderPage(
                systemImage: "puzzlepiece.extension",
                title: "HTTPS 解密与插件",
                message: "Mac 版的根证书信任和插件管理还在开发中，目前请在 iPhone 上使用。"
            )
        case .activity:
            MacActivityPage(tunnel: tunnel)
        case .settings:
            MacSettingsPage()
        }
    }
}

/// OLED keeps the sidebar pure black; other themes keep the system sidebar material.
private struct SolidBackground: ViewModifier {
    let brand: BrandPalette

    @ViewBuilder
    func body(content: Content) -> some View {
        if brand.solidBars {
            content
                .scrollContentBackground(.hidden)
                .background(brand.bg)
        } else {
            content
        }
    }
}

/// The connection at a glance under the sidebar, so it stays visible on every page.
private struct SidebarStatus: View {
    @Environment(\.brand) private var brand
    @ObservedObject var tunnel: TunnelController

    var body: some View {
        HStack(spacing: 10) {
            BrandMark(size: 26)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Circle()
                        .fill(dotColor)
                        .frame(width: 7, height: 7)
                    Text(tunnel.phase.title)
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(brand.text)
                }
                Text(tunnel.nodeName ?? String(localized: "还没有节点"))
                    .font(.caption)
                    .foregroundStyle(brand.text2)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(10)
        .background(brand.surface.opacity(0.8), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .accessibilityElement(children: .combine)
    }

    private var dotColor: Color {
        switch tunnel.phase {
        case .on:
            return brand.primary
        case .connecting, .reasserting, .disconnecting:
            return Brand.amber
        case .off, .unconfigured:
            return brand.text3
        }
    }
}
