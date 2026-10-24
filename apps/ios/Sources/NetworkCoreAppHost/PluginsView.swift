import NetworkCoreBridge
import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// The plugin part of the "扩展" tab: the HTTPS decryption switch, local Loon plugin import and the list.
struct PluginsSection: View {
    @Environment(\.brand) private var brand
    @ObservedObject var tunnel: TunnelController
    @ObservedObject var model: PluginsModel
    @State private var importingFile = false

    var body: some View {
        Section {
            Toggle("HTTPS 解密", isOn: Binding(
                get: { model.library.isEnabled },
                set: { enabled in Task { await model.setMasterEnabled(enabled, tunnel: tunnel) } }
            ))
            .disabled(!model.library.isEnabled && model.trustState != .trusted)
            .listRowBackground(brand.surface)

            ForEach(model.library.plugins) { plugin in
                PluginRow(plugin: plugin) { enabled in
                    Task { await model.setEnabled(enabled, for: plugin.id, tunnel: tunnel) }
                }
                .listRowBackground(brand.surface)
            }
            .onDelete { offsets in
                let ids = offsets.map { model.library.plugins[$0].id }
                Task { await model.remove(ids, tunnel: tunnel) }
            }

            Menu {
                Button {
                    importingFile = true
                } label: {
                    Label("从文件导入", systemImage: "doc")
                }
                Button {
                    Task { await model.importText(UIPasteboard.general.string, name: nil, tunnel: tunnel) }
                } label: {
                    Label("从剪贴板导入", systemImage: "doc.on.clipboard")
                }
            } label: {
                Label("导入插件", systemImage: "plus")
            }
            .listRowBackground(brand.surface)
        } header: {
            Text("插件")
        } footer: {
            Text(model.footer)
        }
        .fileImporter(isPresented: $importingFile, allowedContentTypes: PluginsModel.contentTypes) { result in
            Task { await model.importFile(result, tunnel: tunnel) }
        }
        .task {
            model.load()
        }
    }
}

private struct PluginRow: View {
    let plugin: MitmPlugin
    let setEnabled: (Bool) -> Void

    var body: some View {
        let summary = plugin.summary
        Toggle(isOn: Binding(get: { plugin.isEnabled }, set: setEnabled)) {
            VStack(alignment: .leading, spacing: 2) {
                Text(plugin.name)
                Text(Self.detail(summary))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
        }
    }

    private static func detail(_ summary: MitmPluginSummary) -> String {
        var parts = ["\(summary.hostnames.count) 个主机", "\(summary.rewriteLines) 条重写"]
        if summary.scriptLines > 0 {
            parts.append("\(summary.scriptLines) 个脚本暂不运行")
        }
        if summary.ruleLines > 0 {
            parts.append("\(summary.ruleLines) 条规则暂不生效")
        }
        return parts.joined(separator: " · ")
    }
}

@MainActor
final class PluginsModel: ObservableObject {
    /// Loon plugins usually end in `.plugin` or `.lpx`; any text file is accepted.
    static let contentTypes: [UTType] = [.plainText, .text, .data]

    @Published private(set) var library = MitmPluginLibrary()
    @Published private(set) var trustState = MitmTrustState.notGenerated
    @Published private(set) var note: String?

    func load() {
        do {
            library = try MitmPluginLibrary.load(from: MitmPluginLibrary.defaultURL)
        } catch {
            note = "读取插件列表失败"
        }
        trustState = (try? MitmCertificateStore.load())?.trustState() ?? .notGenerated
    }

    var footer: String {
        if let note {
            return note
        }
        switch trustState {
        case .trusted:
            return "只解密插件 [MITM] 列出的主机，仅支持 HTTP/1.1。脚本和插件里的分流规则暂不生效。"
        case .notTrusted, .notGenerated:
            return "开启前请先在上面生成并信任 HTTPS 解密证书。"
        }
    }

    func setMasterEnabled(_ enabled: Bool, tunnel: TunnelController) async {
        if enabled {
            trustState = (try? MitmCertificateStore.load())?.trustState() ?? .notGenerated
            guard trustState == .trusted else {
                note = "证书尚未被信任，请先完成证书设置。"
                return
            }
        }
        var next = library
        next.isEnabled = enabled
        await commit(next, tunnel: tunnel)
    }

    func setEnabled(_ enabled: Bool, for id: UUID, tunnel: TunnelController) async {
        var next = library
        do {
            try next.setEnabled(enabled, for: id)
        } catch {
            note = Self.describe(error)
            return
        }
        await commit(next, tunnel: tunnel)
    }

    func remove(_ ids: [UUID], tunnel: TunnelController) async {
        var next = library
        ids.forEach { next.remove($0) }
        await commit(next, tunnel: tunnel)
    }

    func importFile(_ result: Result<URL, Error>, tunnel: TunnelController) async {
        guard case let .success(url) = result else {
            note = "没有读取到文件"
            return
        }
        let scoped = url.startAccessingSecurityScopedResource()
        defer {
            if scoped {
                url.stopAccessingSecurityScopedResource()
            }
        }
        guard let data = try? Data(contentsOf: url), data.count <= MitmPlugin.maxBytes,
              let text = String(data: data, encoding: .utf8)
        else {
            note = "文件不是 UTF-8 文本或超过 256 KB"
            return
        }
        await importText(text, name: url.deletingPathExtension().lastPathComponent, tunnel: tunnel)
    }

    func importText(_ text: String?, name: String?, tunnel: TunnelController) async {
        guard let text else {
            note = "剪贴板里没有文本"
            return
        }
        var next = library
        do {
            let plugin = try MitmPlugin(text: text, fallbackName: name ?? "未命名插件")
            try next.add(plugin)
        } catch {
            note = Self.describe(error)
            return
        }
        await commit(next, tunnel: tunnel)
    }

    /// Saves the list, then hands the enabled plugins to the tunnel profile.
    private func commit(_ next: MitmPluginLibrary, tunnel: TunnelController) async {
        do {
            try next.save(to: MitmPluginLibrary.defaultURL)
        } catch {
            note = "保存插件列表失败"
            return
        }
        library = next
        let changed = await tunnel.applyMitmPlugins(next.activeTexts)
        note = changed && tunnel.isConnected ? "已保存，重新连接后生效。" : nil
    }

    private static func describe(_ error: Error) -> String {
        switch error as? MitmPluginError {
        case .empty:
            return "插件内容为空"
        case .tooLarge:
            return "插件超过 256 KB"
        case .nothingToApply:
            return "没有找到可用的重写、脚本或 [MITM] 主机"
        case .libraryFull:
            return "启用的插件合计超过 512 KB，请先停用一些插件"
        case nil:
            return "导入失败"
        }
    }
}
