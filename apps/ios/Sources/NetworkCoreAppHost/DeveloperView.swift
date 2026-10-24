import NetworkCoreBridge
import SwiftUI
import UIKit

/// Hidden developer mode: tapping the version row seven times turns it on, and the developer page turns it off.
enum DeveloperMode {
    static let storageKey = "developerModeEnabled"
    static let unlockTaps = 7

    static var appVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "unknown"
    }

    static var appBuild: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "unknown"
    }
}

/// The "关于" section: shows the version and counts taps on it to unlock developer mode.
struct AboutSection: View {
    @ObservedObject var tunnel: TunnelController
    @AppStorage(DeveloperMode.storageKey) private var developerMode = false
    @State private var taps = 0
    @State private var hint: String?

    var body: some View {
        Section("关于") {
            HStack {
                Text("版本")
                Spacer()
                Text("\(DeveloperMode.appVersion) (\(DeveloperMode.appBuild))")
                    .foregroundStyle(.secondary)
            }
            .contentShape(Rectangle())
            .onTapGesture {
                countTap()
            }
            if let hint = hint {
                Text(hint)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if developerMode {
                NavigationLink("开发者模式") {
                    DeveloperView(tunnel: tunnel)
                }
            }
        }
    }

    private func countTap() {
        guard !developerMode else {
            hint = String(localized: "开发者模式已开启")
            return
        }
        taps += 1
        let remaining = DeveloperMode.unlockTaps - taps
        if remaining <= 0 {
            developerMode = true
            taps = 0
            hint = String(localized: "已开启开发者模式")
        } else if remaining <= 3 {
            hint = String(localized: "再点 \(remaining) 次开启开发者模式")
        }
    }
}

/// Developer page: extension state, runtime status, event log and a copyable report without secrets.
struct DeveloperView: View {
    @ObservedObject var tunnel: TunnelController
    @AppStorage(DeveloperMode.storageKey) private var developerMode = false
    @Environment(\.dismiss) private var dismiss
    @State private var autoRefresh = true
    @State private var copied = false

    var body: some View {
        Form {
            Section("概览") {
                row("App", "\(DeveloperMode.appVersion) (\(DeveloperMode.appBuild))")
                row(String(localized: "系统"), systemVersion)
                row(String(localized: "连接"), ConnectPhase.describe(tunnel.connection))
                row(String(localized: "出站协议"), tunnel.outboundKind ?? String(localized: "未导入"))
            }

            Section("扩展") {
                if let diagnostics = tunnel.diagnostics {
                    row(String(localized: "内存占用"), diagnostics.memoryFootprintBytes.map(DeveloperReport.megabytes) ?? String(localized: "未知"))
                    row(String(localized: "运行时长"), diagnostics.uptimeSeconds.map(DeveloperReport.duration) ?? String(localized: "未启动"))
                    row(
                        String(localized: "运行时 ABI"),
                        "\(diagnostics.runtimeABIVersion)/\(diagnostics.runtimeSchemaVersion)/\(diagnostics.runtimeFeatureSetVersion)"
                    )
                } else {
                    Text(tunnel.isConnected ? "扩展没有响应" : "隧道未运行")
                        .foregroundStyle(.secondary)
                }
                Toggle("每 2 秒自动刷新", isOn: $autoRefresh)
                Button("立即刷新") {
                    refresh()
                }
            }

            Section("上次停止原因") {
                Text(tunnel.lastDisconnectError ?? String(localized: "无记录"))
                    .font(.footnote.monospaced())
                    .textSelection(.enabled)
            }

            Section("运行状态") {
                Text(tunnel.diagnostics?.runtimeStatus.map(DeveloperReport.prettyJSON) ?? String(localized: "无"))
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
            }

            Section("扩展事件（最近 \(TunnelDiagnosticLog.defaultCapacity) 条）") {
                let events = tunnel.diagnostics?.events ?? []
                if events.isEmpty {
                    Text("无")
                        .foregroundStyle(.secondary)
                }
                ForEach(Array(events.reversed().enumerated()), id: \.offset) { _, event in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(event.time, format: .dateTime.hour().minute().second())
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                        Text(event.message)
                            .font(.caption.monospaced())
                    }
                }
            }

            Section {
                Button(copied ? "已复制" : "复制诊断信息") {
                    UIPasteboard.general.string = report().text
                    copied = true
                }
                Button("关闭开发者模式", role: .destructive) {
                    developerMode = false
                    dismiss()
                }
            } footer: {
                Text("诊断信息不含节点名称、服务器地址和密钥。")
            }
        }
        .navigationTitle("开发者模式")
        .task(id: autoRefresh) {
            refresh()
            while autoRefresh, !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                guard !Task.isCancelled else {
                    return
                }
                tunnel.refreshDiagnostics()
            }
        }
    }

    private var systemVersion: String {
        "\(UIDevice.current.systemName) \(UIDevice.current.systemVersion)"
    }

    private func refresh() {
        copied = false
        tunnel.refreshDiagnostics()
        tunnel.refreshLastDisconnectError()
    }

    private func report() -> DeveloperReport {
        DeveloperReport(
            appVersion: DeveloperMode.appVersion,
            appBuild: DeveloperMode.appBuild,
            systemVersion: systemVersion,
            connection: ConnectPhase.describe(tunnel.connection),
            outboundKind: tunnel.outboundKind,
            lastDisconnectError: tunnel.lastDisconnectError,
            diagnostics: tunnel.diagnostics,
            generatedAt: Date()
        )
    }

    private func row(_ title: String, _ value: String) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(value)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
    }
}
