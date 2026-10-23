import NetworkCoreBridge
import NetworkExtension
import SwiftUI

// SwiftUI entry point for the containing app. The app target compiles NetworkCoreApp sources directly,
// so this file refers to AppCoordinator without importing the NetworkCoreApp module.
@main
struct NetworkCoreAppMain: App {
    @StateObject private var tunnel = TunnelController()

    var body: some Scene {
        WindowGroup {
            TunnelView(tunnel: tunnel)
                .task {
                    await tunnel.load()
                }
        }
    }
}

struct TunnelView: View {
    @ObservedObject var tunnel: TunnelController
    @State private var link = ""

    var body: some View {
        Form {
            Section("节点") {
                if let name = tunnel.nodeName {
                    Text(name)
                }
                // Multi-line so a WireGuard config can be pasted whole.
                TextField("粘贴 ss://、vless:// 链接或 WireGuard 配置", text: $link, axis: .vertical)
                    .lineLimit(1...8)
                    .font(.footnote.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Button("导入并保存") {
                    let pasted = link
                    link = ""
                    Task {
                        await tunnel.importLink(pasted)
                    }
                }
                .disabled(link.isEmpty)
            }

            Section("隧道") {
                StatusView(decision: tunnel.coordinator.decision)
                Text(Self.describe(tunnel.connection))
                    .foregroundStyle(.secondary)
                Button(tunnel.isConnected ? "断开" : "连接") {
                    tunnel.toggle()
                }
                .disabled(!tunnel.isConnected && !tunnel.coordinator.canStartTunnel)
            }

            if tunnel.connection == .connected {
                Section("运行状态") {
                    Button("刷新") {
                        tunnel.refreshRuntimeStatus()
                    }
                    if let status = tunnel.runtimeStatus {
                        Text(status)
                            .font(.footnote.monospaced())
                            .textSelection(.enabled)
                    }
                }
            }

            if let message = tunnel.message {
                Section {
                    Text(message)
                }
            }
        }
    }

    static func describe(_ status: NEVPNStatus) -> String {
        switch status {
        case .connected:
            return "已连接"
        case .connecting:
            return "连接中"
        case .disconnecting:
            return "断开中"
        case .reasserting:
            return "重新连接中"
        case .disconnected:
            return "未连接"
        case .invalid:
            return "未配置"
        @unknown default:
            return "未知状态"
        }
    }
}

struct StatusView: View {
    let decision: VpnConfigurationDecision

    var body: some View {
        switch decision {
        case .startTunnel:
            Text("可以启动隧道")
        case let .blocked(reason, code):
            VStack(alignment: .leading, spacing: 4) {
                Text(reason)
                if let code = code {
                    Text(code)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}
