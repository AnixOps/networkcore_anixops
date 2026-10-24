import AppKit
import NetworkExtension
import SwiftUI

// SwiftUI entry point for the macOS app. Like the iOS app target it compiles the NetworkCoreApp sources and the
// shared host files (TunnelController, ImportView, brand views) directly, so it uses them without imports.
@main
struct NetworkCoreMacApp: App {
    @StateObject private var tunnel = TunnelController()
    @StateObject private var state = MacAppState()
    @AppStorage(Appearance.storageKey) private var appearance = Appearance.system

    var body: some Scene {
        // One window: a VPN client has a single connection, so a second window would only repeat it.
        Window("AnixOps Net", id: MacAppState.mainWindowID) {
            MacRootView(tunnel: tunnel, state: state)
                .preferredColorScheme(appearance.colorScheme)
                .task {
                    await tunnel.load()
                }
        }
        .defaultSize(width: 980, height: 680)
        .commands {
            MacCommands(tunnel: tunnel, state: state)
        }

        MenuBarExtra {
            MenuBarContent(tunnel: tunnel, state: state)
        } label: {
            Image(systemName: tunnel.connection == .connected ? "network.badge.shield.half.filled" : "network")
                .accessibilityLabel("AnixOps Net")
        }
    }
}

/// Window-level state the menu commands and the menu bar item also change.
@MainActor
final class MacAppState: ObservableObject {
    static let mainWindowID = "main"

    @Published var section: MacSection? = .home
    @Published var importing = false
}

/// The six desktop sections, matching the Windows client: the five shared tabs plus Activity.
enum MacSection: String, CaseIterable, Identifiable, Hashable {
    case home
    case proxies
    case rules
    case extensions
    case activity
    case settings

    var id: String { rawValue }

    var title: LocalizedStringKey {
        switch self {
        case .home:
            return "概览"
        case .proxies:
            return "代理"
        case .rules:
            return "规则"
        case .extensions:
            return "扩展"
        case .activity:
            return "活动"
        case .settings:
            return "设置"
        }
    }

    var systemImage: String {
        switch self {
        case .home:
            return "house"
        case .proxies:
            return "globe"
        case .rules:
            return "arrow.triangle.branch"
        case .extensions:
            return "puzzlepiece.extension"
        case .activity:
            return "waveform.path.ecg"
        case .settings:
            return "gearshape"
        }
    }
}

extension TunnelController {
    var phase: ConnectPhase {
        ConnectPhase(status: connection, hasNode: nodeName != nil)
    }

    var toggleTitle: LocalizedStringKey {
        // "连接" alone is the noun "Connection" in the catalog, so the verb has its own key.
        isConnected ? "断开" : "action.connect"
    }
}

/// The app menu additions: import, connect or disconnect, and Settings opening the Settings section.
struct MacCommands: Commands {
    @ObservedObject var tunnel: TunnelController
    @ObservedObject var state: MacAppState

    var body: some Commands {
        CommandGroup(replacing: .appSettings) {
            OpenSectionButton(state: state, section: .settings, title: "设置…")
                .keyboardShortcut(",", modifiers: .command)
        }
        CommandGroup(replacing: .newItem) {
            Button("导入节点…") {
                state.importing = true
            }
            .keyboardShortcut("i", modifiers: .command)
        }
        CommandMenu("连接") {
            Button(tunnel.toggleTitle) {
                tunnel.toggle()
            }
            .keyboardShortcut("c", modifiers: [.command, .shift])
            .disabled(tunnel.phase == .unconfigured || tunnel.phase == .disconnecting)
        }
    }
}

/// Brings the main window forward on a section; reopens it if the user closed it.
private struct OpenSectionButton: View {
    @Environment(\.openWindow) private var openWindow
    @ObservedObject var state: MacAppState
    let section: MacSection
    let title: LocalizedStringKey

    var body: some View {
        Button(title) {
            state.section = section
            openWindow(id: MacAppState.mainWindowID)
            NSApp.activate(ignoringOtherApps: true)
        }
    }
}

/// The menu bar item: the status, one connect switch and a way back to the window.
private struct MenuBarContent: View {
    @Environment(\.openWindow) private var openWindow
    @ObservedObject var tunnel: TunnelController
    @ObservedObject var state: MacAppState

    var body: some View {
        Text(tunnel.phase.title)
        if let name = tunnel.nodeName {
            Text(name)
        }
        Divider()
        if tunnel.phase == .unconfigured {
            Button("导入节点…") {
                state.importing = true
                showWindow()
            }
        } else {
            Button(tunnel.toggleTitle) {
                tunnel.toggle()
            }
            .disabled(tunnel.phase == .disconnecting)
        }
        Divider()
        Button("打开 AnixOps Net") {
            showWindow()
        }
        Button("退出 AnixOps Net") {
            NSApp.terminate(nil)
        }
    }

    private func showWindow() {
        openWindow(id: MacAppState.mainWindowID)
        NSApp.activate(ignoringOtherApps: true)
    }
}
