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
            RulesView(tunnel: tunnel)
                .tabItem { Label("规则", systemImage: "arrow.triangle.branch") }
            .tag(AppTab.rules)
            ExtensionsView(tunnel: tunnel)
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
