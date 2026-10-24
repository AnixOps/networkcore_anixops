import NetworkCoreBridge
import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// The plugin part of the "扩展" tab: the HTTPS decryption switch, Loon plugin import (file, clipboard or
/// address), the list, and the scripts those plugins name, each run only after the user allows it.
struct PluginsSection: View {
    @Environment(\.brand) private var brand
    @ObservedObject var tunnel: TunnelController
    @ObservedObject var model: PluginsModel
    @State private var importingFile = false
    @State private var enteringAddress = false
    @State private var address = ""
    @State private var pendingScript: MitmScriptReference?

    var body: some View {
        pluginSection
        if !model.scriptReferences.isEmpty {
            scriptSection
        }
    }

    private var pluginSection: some View {
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
                Button {
                    address = ""
                    enteringAddress = true
                } label: {
                    Label("从网址导入", systemImage: "link")
                }
            } label: {
                Label(model.isDownloading ? "正在下载…" : "导入插件", systemImage: "plus")
            }
            .disabled(model.isDownloading)
            .listRowBackground(brand.surface)
        } header: {
            Text("插件")
        } footer: {
            Text(model.footer)
        }
        .fileImporter(isPresented: $importingFile, allowedContentTypes: PluginsModel.contentTypes) { result in
            Task { await model.importFile(result, tunnel: tunnel) }
        }
        .alert("从网址导入插件", isPresented: $enteringAddress) {
            TextField("https://", text: $address)
                .keyboardType(.URL)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("取消", role: .cancel) {}
            Button("导入") {
                Task { await model.importAddress(address, tunnel: tunnel) }
            }
        } message: {
            Text("只支持 https 地址。插件里的脚本不会自动运行，需要逐个允许。")
        }
        .task {
            model.load()
        }
    }

    private var scriptSection: some View {
        Section {
            ForEach(model.scriptReferences, id: \.path) { reference in
                ScriptRow(reference: reference, allowed: model.scripts.scripts[reference.path]) {
                    pendingScript = reference
                }
                .disabled(model.isDownloading)
                .swipeActions {
                    if model.scripts.scripts[reference.path] != nil {
                        Button("撤销", role: .destructive) {
                            Task { await model.revoke(reference.path, tunnel: tunnel) }
                        }
                    }
                }
                .listRowBackground(brand.surface)
            }
        } header: {
            Text("脚本")
        } footer: {
            Text("脚本在隧道内的 QuickJS 中运行，可以读取和修改所在插件 [MITM] 主机的请求和响应，不能自行联网。只运行允许时下载的那一份；左滑撤销。")
        }
        .confirmationDialog(
            "允许运行这个脚本？",
            isPresented: Binding(get: { pendingScript != nil }, set: { if !$0 { pendingScript = nil } }),
            titleVisibility: .visible,
            presenting: pendingScript
        ) { reference in
            Button("下载并允许") {
                Task { await model.allow(reference, tunnel: tunnel) }
            }
            Button("取消", role: .cancel) {}
        } message: { reference in
            Text("将从 \(reference.url?.absoluteString ?? reference.path) 下载。脚本可以查看和改写解密后的流量，请只允许你信任的来源。地址上的内容之后变了，需要重新允许。")
        }
    }
}

private struct ScriptRow: View {
    let reference: MitmScriptReference
    let allowed: MitmScript?
    let allow: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(reference.tag ?? reference.url?.lastPathComponent ?? reference.path)
                Text(detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
            }
            Spacer()
            if allowed == nil, reference.url != nil {
                Button("允许", action: allow)
                    .buttonStyle(.bordered)
            }
        }
    }

    private var detail: String {
        if let allowed {
            return "已允许 · \(allowed.sha256.prefix(12)) · \(allowed.allowedAt.formatted(date: .abbreviated, time: .omitted))"
        }
        if reference.url == nil {
            return "不会运行：脚本地址不是 https"
        }
        return "未允许，不会运行 · \(reference.url?.host() ?? "")"
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
            parts.append("\(summary.scriptLines) 个脚本")
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
    @Published private(set) var scripts = MitmScriptLibrary()
    @Published private(set) var trustState = MitmTrustState.notGenerated
    @Published private(set) var note: String?
    @Published private(set) var isDownloading = false

    func load() {
        do {
            library = try MitmPluginLibrary.load(from: MitmPluginLibrary.defaultURL)
            scripts = try MitmScriptLibrary.load(from: MitmScriptLibrary.defaultURL)
        } catch {
            note = "读取插件列表失败"
        }
        trustState = (try? MitmCertificateStore.load())?.trustState() ?? .notGenerated
    }

    /// Scripts named by the enabled plugins, without repeats.
    var scriptReferences: [MitmScriptReference] {
        var seen: Set<String> = []
        return library.plugins.filter(\.isEnabled).flatMap(\.scriptReferences).filter { seen.insert($0.path).inserted }
    }

    var footer: String {
        if let note {
            return note
        }
        switch trustState {
        case .trusted:
            return "只解密插件 [MITM] 列出的主机，仅支持 HTTP/1.1。插件里的分流规则暂不生效。"
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

    func importText(_ text: String?, name: String?, sourceURL: URL? = nil, tunnel: TunnelController) async {
        guard let text else {
            note = "剪贴板里没有文本"
            return
        }
        var next = library
        do {
            let plugin = try MitmPlugin(text: text, fallbackName: name ?? "未命名插件", sourceURL: sourceURL)
            try next.add(plugin)
        } catch {
            note = Self.describe(error)
            return
        }
        await commit(next, tunnel: tunnel)
    }

    /// Downloads a plugin the user typed the address of. Its scripts are listed but not fetched.
    func importAddress(_ address: String, tunnel: TunnelController) async {
        guard let url = URL(string: address.trimmingCharacters(in: .whitespacesAndNewlines)),
              url.scheme?.lowercased() == "https", url.host() != nil
        else {
            note = "请输入 https 开头的插件地址"
            return
        }
        guard let data = await download(url, maxBytes: MitmPlugin.maxBytes, kind: "插件") else {
            return
        }
        guard let text = String(data: data, encoding: .utf8) else {
            note = "插件不是 UTF-8 文本"
            return
        }
        await importText(text, name: url.deletingPathExtension().lastPathComponent, sourceURL: url, tunnel: tunnel)
    }

    /// Downloads the script the user just agreed to and pins that copy.
    func allow(_ reference: MitmScriptReference, tunnel: TunnelController) async {
        guard let url = reference.url else {
            note = "脚本地址不是 https，无法下载"
            return
        }
        guard let data = await download(url, maxBytes: MitmScript.maxBytes, kind: "脚本") else {
            return
        }
        var next = scripts
        do {
            next.allow(try MitmScript(path: reference.path, url: url, data: data))
            _ = try next.sources(for: library.activeScriptReferences)
        } catch {
            note = Self.describe(error)
            return
        }
        await commit(library, scripts: next, tunnel: tunnel)
    }

    func revoke(_ path: String, tunnel: TunnelController) async {
        var next = scripts
        next.revoke(path)
        await commit(library, scripts: next, tunnel: tunnel)
    }

    private func download(_ url: URL, maxBytes: Int, kind: String) async -> Data? {
        isDownloading = true
        defer { isDownloading = false }
        do {
            return try await MitmDownload.fetch(url, maxBytes: maxBytes)
        } catch MitmDownload.Failure.tooLarge {
            note = "\(kind)超过 \(maxBytes / 1024) KB"
        } catch MitmDownload.Failure.notHTTPS {
            note = "\(kind)地址不是 https，或被重定向到了非 https 地址"
        } catch let MitmDownload.Failure.status(code) {
            note = "下载\(kind)失败（HTTP \(code)）"
        } catch {
            note = "下载\(kind)失败，请检查网络和地址"
        }
        return nil
    }

    /// Saves the lists, then hands the enabled plugins and their allowed scripts to the tunnel profile.
    private func commit(_ next: MitmPluginLibrary, scripts nextScripts: MitmScriptLibrary? = nil, tunnel: TunnelController) async {
        let nextScripts = nextScripts ?? scripts
        let sources: [String: String]
        do {
            sources = try nextScripts.sources(for: next.activeScriptReferences)
        } catch {
            note = Self.describe(error)
            return
        }
        do {
            try next.save(to: MitmPluginLibrary.defaultURL)
            try nextScripts.save(to: MitmScriptLibrary.defaultURL)
        } catch {
            note = "保存插件列表失败"
            return
        }
        library = next
        scripts = nextScripts
        let changed = await tunnel.applyMitmPlugins(next.activeTexts, scripts: sources)
        note = changed && tunnel.isConnected ? "已保存，重新连接后生效。" : nil
    }

    private static func describe(_ error: Error) -> String {
        switch error {
        case MitmPluginError.empty:
            return "插件内容为空"
        case MitmPluginError.tooLarge:
            return "插件超过 256 KB"
        case MitmPluginError.nothingToApply:
            return "没有找到可用的重写、脚本或 [MITM] 主机"
        case MitmPluginError.libraryFull:
            return "启用的插件合计超过 512 KB，请先停用一些插件"
        case MitmScriptError.tooLarge:
            return "脚本超过 1 MB"
        case MitmScriptError.notText, MitmScriptError.notHTTPS:
            return "下载到的内容不是脚本文本"
        case MitmScriptError.libraryFull:
            return "已允许的脚本合计超过 2 MB，请先撤销一些脚本或停用插件"
        default:
            return "导入失败"
        }
    }
}
