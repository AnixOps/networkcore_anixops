import Network
import NetworkCoreBridge
import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// The "扩展" tab: the HTTPS decryption certificate wizard and local Loon plugins.
struct ExtensionsView: View {
    @Environment(\.brand) private var brand
    @ObservedObject var tunnel: TunnelController
    @StateObject private var plugins = PluginsModel()

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    NavigationLink {
                        CertificateView()
                    } label: {
                        Label("HTTPS 解密证书", systemImage: "lock.shield")
                    }
                    .listRowBackground(brand.surface)
                } footer: {
                    Text("解密 HTTPS 需要先在本机生成并信任一张根证书。证书和私钥只保存在本机钥匙串。")
                }

                PluginsSection(tunnel: tunnel, model: plugins)
            }
            .scrollContentBackground(.hidden)
            .background(brand.bg.ignoresSafeArea())
            .navigationTitle("扩展")
            .brandBars(brand)
        }
    }
}

/// Walks the user through generating the root, installing its profile and turning on full trust, and shows
/// which step the device is at.
struct CertificateView: View {
    @Environment(\.brand) private var brand
    @Environment(\.openURL) private var openURL
    @Environment(\.scenePhase) private var scenePhase
    @StateObject private var model = CertificateModel()
    @State private var confirmingRegenerate = false

    var body: some View {
        Form {
            Section {
                HStack(spacing: 12) {
                    Image(systemName: model.state.symbol)
                        .font(.title2)
                        .foregroundStyle(model.state == .trusted ? brand.primary : brand.warning)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(model.state.title)
                            .font(.headline)
                        Text(model.state.detail)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                .listRowBackground(brand.surface)
            }

            Section("步骤") {
                step(1, "生成根证书", done: model.authority != nil)
                step(2, "安装描述文件", done: model.state == .trusted, note: "在 Safari 中允许下载，然后到 设置 > 已下载描述文件 安装。")
                step(3, "开启完全信任", done: model.state == .trusted, note: "设置 > 通用 > 关于本机 > 证书信任设置，打开这张证书的开关。")
            }

            Section {
                if model.authority == nil {
                    Button("生成根证书") {
                        model.generate()
                    }
                } else {
                    Button("安装描述文件") {
                        if let url = model.serveProfile() {
                            openURL(url)
                        }
                    }
                    Button("重新检测信任状态") {
                        model.refresh()
                    }
                }
            }

            if let authority = model.authority {
                Section("证书") {
                    LabeledContent("名称", value: authority.commonName)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("SHA-256 指纹")
                        Text(authority.sha256Fingerprint)
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                    ShareLink(
                        item: CertificateFile(data: authority.certificateDER, name: authority.commonName),
                        preview: SharePreview("\(authority.commonName).cer")
                    ) {
                        Text("导出证书（.cer）")
                    }
                }

                Section {
                    Button("重新生成根证书", role: .destructive) {
                        confirmingRegenerate = true
                    }
                } footer: {
                    Text("重新生成后旧证书立即失效，需要重新安装并信任。请同时在 设置 > 通用 > VPN与设备管理 删除旧描述文件。")
                }
            }

            if let error = model.error {
                Section {
                    Text(error)
                        .font(.footnote)
                        .foregroundStyle(brand.danger)
                }
            }
        }
        .scrollContentBackground(.hidden)
        .background(brand.bg.ignoresSafeArea())
        .navigationTitle("HTTPS 解密证书")
        .confirmationDialog("重新生成根证书？", isPresented: $confirmingRegenerate, titleVisibility: .visible) {
            Button("重新生成", role: .destructive) {
                model.generate()
            }
        }
        .task {
            model.load()
        }
        .onChange(of: scenePhase) { _, phase in
            // Returning from Settings is when trust usually changes.
            if phase == .active {
                model.refresh()
            }
        }
    }

    private func step(_ number: Int, _ title: String, done: Bool, note: String? = nil) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: done ? "checkmark.circle.fill" : "\(number).circle")
                .foregroundStyle(done ? brand.primary : brand.text3)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                if let note {
                    Text(note)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .listRowBackground(brand.surface)
    }
}

extension MitmTrustState {
    var title: String {
        switch self {
        case .notGenerated: "尚未生成证书"
        case .notTrusted: "证书未被信任"
        case .trusted: "证书已信任"
        }
    }

    var detail: String {
        switch self {
        case .notGenerated: "生成本机专属的根证书后才能解密 HTTPS。"
        case .notTrusted: "描述文件可能未安装，或尚未在证书信任设置中开启完全信任。"
        case .trusted: "可以解密 MITM 主机列表中的 HTTPS 流量。"
        }
    }

    var symbol: String {
        switch self {
        case .notGenerated: "lock.open"
        case .notTrusted: "exclamationmark.shield"
        case .trusted: "checkmark.shield"
        }
    }
}

@MainActor
final class CertificateModel: ObservableObject {
    @Published private(set) var authority: MitmCertificateAuthority?
    @Published private(set) var state = MitmTrustState.notGenerated
    @Published private(set) var error: String?
    private let server = ProfileServer()

    func load() {
        do {
            authority = try MitmCertificateStore.load()
            error = nil
        } catch {
            self.error = "读取证书失败（\(Self.describe(error))）"
        }
        refresh()
    }

    func generate() {
        do {
            let created = try MitmCertificateAuthority.generate()
            try MitmCertificateStore.save(created)
            authority = created
            error = nil
        } catch {
            self.error = "生成证书失败（\(Self.describe(error))）"
        }
        refresh()
    }

    func refresh() {
        state = authority?.trustState() ?? .notGenerated
    }

    /// Serves the profile on loopback and returns the URL for Safari, which hands it to Settings.
    func serveProfile() -> URL? {
        guard let authority else {
            return nil
        }
        do {
            return try server.serve(authority.configurationProfile(), contentType: MitmCertificateAuthority.profileContentType)
        } catch {
            self.error = "无法提供描述文件（\(Self.describe(error))）"
            return nil
        }
    }

    private static func describe(_ error: Error) -> String {
        if let failure = error as? MitmCertificateStore.Failure {
            return "OSStatus \(failure.status)"
        }
        return String(describing: error)
    }
}

/// A one-file HTTP server on 127.0.0.1. Safari downloads the profile from it while the app keeps running in a
/// background task; the listener stops after `lifetime`.
final class ProfileServer {
    static let lifetime: TimeInterval = 120

    private var listener: NWListener?
    private var generation = 0
    private var backgroundTask = UIBackgroundTaskIdentifier.invalid
    private let queue = DispatchQueue(label: "networkcore.profile-server")

    @MainActor
    func serve(_ body: Data, contentType: String) throws -> URL {
        stop()
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        let response = Self.response(body: body, contentType: contentType)
        listener.newConnectionHandler = { [queue] connection in
            connection.start(queue: queue)
            connection.receive(minimumIncompleteLength: 1, maximumLength: 16_384) { _, _, _, _ in
                connection.send(content: response, completion: .contentProcessed { _ in
                    connection.cancel()
                })
            }
        }
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready, .failed, .cancelled:
                ready.signal()
            default:
                break
            }
        }
        listener.start(queue: queue)
        _ = ready.wait(timeout: .now() + 2)
        guard let port = listener.port else {
            listener.cancel()
            throw URLError(.cannotConnectToHost)
        }
        self.listener = listener
        generation += 1
        let served = generation
        backgroundTask = UIApplication.shared.beginBackgroundTask { [weak self] in
            Task { @MainActor in self?.stop() }
        }
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(Self.lifetime))
            if self?.generation == served {
                self?.stop()
            }
        }
        return URL(string: "http://127.0.0.1:\(port.rawValue)/networkcore-ca.mobileconfig")!
    }

    @MainActor
    func stop() {
        listener?.cancel()
        listener = nil
        if backgroundTask != .invalid {
            UIApplication.shared.endBackgroundTask(backgroundTask)
            backgroundTask = .invalid
        }
    }

    private static func response(body: Data, contentType: String) -> Data {
        var head = "HTTP/1.1 200 OK\r\n"
        head += "Content-Type: \(contentType)\r\n"
        head += "Content-Disposition: attachment; filename=\"networkcore-ca.mobileconfig\"\r\n"
        head += "Content-Length: \(body.count)\r\n"
        head += "Cache-Control: no-store\r\n"
        head += "Connection: close\r\n\r\n"
        return Data(head.utf8) + body
    }
}

/// The root certificate as a shareable `.cer` file.
struct CertificateFile: Transferable {
    let data: Data
    let name: String

    static var transferRepresentation: some TransferRepresentation {
        DataRepresentation(exportedContentType: .x509Certificate) { $0.data }
            .suggestedFileName { "\($0.name).cer" }
    }
}
