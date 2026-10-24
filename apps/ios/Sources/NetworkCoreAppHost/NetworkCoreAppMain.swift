import NetworkCoreBridge
import NetworkExtension
import SwiftUI

// SwiftUI entry point for the containing app. The app target compiles NetworkCoreApp sources directly,
// so this file refers to AppCoordinator without importing the NetworkCoreApp module.
@main
struct NetworkCoreAppMain: App {
    @StateObject private var tunnel = TunnelController()
    @AppStorage(Appearance.storageKey) private var appearance = Appearance.system

    var body: some Scene {
        WindowGroup {
            RootView(tunnel: tunnel)
                .preferredColorScheme(appearance.colorScheme)
                .task {
                    await tunnel.load()
                }
        }
    }
}

/// The five top-level sections shared by every AnixOps Net client.
enum AppTab: Hashable {
    case home
    case proxies
    case rules
    case extensions
    case settings
}

struct RootView: View {
    @ObservedObject var tunnel: TunnelController
    @AppStorage(Appearance.storageKey) private var appearance = Appearance.system
    @Environment(\.colorScheme) private var colorScheme
    @State private var tab = AppTab.home
    @State private var importing = false

    var body: some View {
        let brand = BrandPalette.resolve(appearance: appearance, scheme: colorScheme)
        TabView(selection: $tab) {
            HomeView(tunnel: tunnel, tab: $tab, importing: $importing)
                .tabItem { Label("首页", systemImage: "house") }
                .tag(AppTab.home)
            ProxiesView(tunnel: tunnel, importing: $importing)
                .tabItem { Label("代理", systemImage: "globe") }
                .tag(AppTab.proxies)
            ComingSoonView(
                title: "规则",
                systemImage: "arrow.triangle.branch",
                heading: "规则与分流",
                message: "按域名和 IP 分流、规则集和规则测试会放在这里。当前版本按节点配置转发全部流量。"
            )
            .tabItem { Label("规则", systemImage: "arrow.triangle.branch") }
            .tag(AppTab.rules)
            ExtensionsView()
                .tabItem { Label("扩展", systemImage: "puzzlepiece.extension") }
                .tag(AppTab.extensions)
            SettingsView(tunnel: tunnel)
                .tabItem { Label("设置", systemImage: "slider.horizontal.3") }
                .tag(AppTab.settings)
        }
        .tint(brand.primary)
        .environment(\.brand, brand)
        .sheet(isPresented: $importing) {
            ImportView(tunnel: tunnel)
                .environment(\.brand, brand)
                .tint(brand.primary)
        }
    }
}

/// A section whose kernel support is still on the roadmap: says what will live here instead of showing fake data.
struct ComingSoonView: View {
    @Environment(\.brand) private var brand
    let title: String
    let systemImage: String
    let heading: String
    let message: String

    var body: some View {
        NavigationStack {
            ScrollView {
                BrandEmptyState(systemImage: systemImage, title: heading, message: message)
                    .padding(.top, 80)
            }
            .background(brand.bg.ignoresSafeArea())
            .navigationTitle(title)
            .brandBars(brand)
        }
    }
}

extension View {
    /// OLED keeps the navigation and tab bars pure black; other themes keep the system material.
    @ViewBuilder
    func brandBars(_ brand: BrandPalette) -> some View {
        if brand.solidBars {
            self
                .toolbarBackground(brand.bg, for: .navigationBar, .tabBar)
                .toolbarBackground(.visible, for: .navigationBar, .tabBar)
        } else {
            self
        }
    }
}
