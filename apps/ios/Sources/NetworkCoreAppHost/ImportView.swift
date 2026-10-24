import SwiftUI
import UniformTypeIdentifiers

/// The import sheet: paste or pick a file, check the parsed node, then save it.
struct ImportView: View {
    @ObservedObject var tunnel: TunnelController
    @Environment(\.brand) private var brand
    @Environment(\.dismiss) private var dismiss

    private enum Step {
        case input
        case preview(ImportPreview)
        case done(String)
    }

    @State private var step = Step.input
    @State private var text = ""
    @State private var error: String?
    @State private var saving = false
    @State private var pickingFile = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                progressBar
                    .padding(.horizontal, 16)
                    .padding(.top, 8)
                switch step {
                case .input:
                    input
                case let .preview(preview):
                    previewStep(preview)
                case let .done(name):
                    DoneStep(name: name) {
                        dismiss()
                    } again: {
                        text = ""
                        step = .input
                    }
                }
            }
            .background(brand.bg.ignoresSafeArea())
            .navigationTitle(title)
            #if os(iOS)
            .navigationBarTitleDisplayMode(.inline)
            #endif
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(isDone ? "完成" : "取消") {
                        dismiss()
                    }
                }
            }
            .fileImporter(isPresented: $pickingFile, allowedContentTypes: [.plainText, .data]) { result in
                readFile(result)
            }
        }
    }

    private var title: String {
        switch step {
        case .input:
            return String(localized: "导入")
        case .preview:
            return String(localized: "确认导入")
        case .done:
            return String(localized: "完成")
        }
    }

    private var isDone: Bool {
        if case .done = step {
            return true
        }
        return false
    }

    private var stepIndex: Int {
        switch step {
        case .input:
            return 0
        case .preview:
            return 1
        case .done:
            return 2
        }
    }

    private var progressBar: some View {
        HStack(spacing: 6) {
            ForEach(0..<3) { index in
                Capsule()
                    .fill(index <= stepIndex ? brand.primary : brand.border)
                    .frame(height: 4)
            }
        }
        .animation(.easeInOut(duration: 0.22), value: stepIndex)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("第 \(stepIndex + 1) 步，共 3 步")
    }

    private var input: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                PasteButton(payloadType: String.self) { strings in
                    guard let pasted = strings.first else {
                        return
                    }
                    Task { @MainActor in
                        text = pasted
                        recognize()
                    }
                }
                .buttonBorderShape(.capsule)
                .frame(maxWidth: .infinity, alignment: .leading)

                Button {
                    pickingFile = true
                } label: {
                    Label("从文件导入 WireGuard 配置", systemImage: "doc")
                        .font(.body.weight(.medium))
                }

                VStack(alignment: .leading, spacing: 8) {
                    Text("或手动输入")
                        .font(.footnote)
                        .foregroundStyle(brand.text2)
                    ZStack(alignment: .topLeading) {
                        if text.isEmpty {
                            Text("ss:// · vless:// · WireGuard 配置")
                                .font(.footnote.monospaced())
                                .foregroundStyle(brand.text3)
                                .padding(.horizontal, 13)
                                .padding(.vertical, 16)
                                .accessibilityHidden(true)
                        }
                        TextEditor(text: $text)
                            .font(.footnote.monospaced())
                            #if os(iOS)
                            .textInputAutocapitalization(.never)
                            #endif
                            .autocorrectionDisabled()
                            .scrollContentBackground(.hidden)
                            .padding(8)
                            .accessibilityLabel("节点链接或配置")
                    }
                    .frame(height: 140)
                    .background(brand.surface, in: RoundedRectangle(cornerRadius: 14, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(brand.border))
                }

                if let error = error {
                    Label(error, systemImage: "exclamationmark.circle.fill")
                        .font(.subheadline)
                        .foregroundStyle(brand.danger)
                }

                Text("支持 Shadowsocks-2022、VLESS 链接和单个 Peer 的 WireGuard 配置。订阅、Clash / Loon / Surge 配置会在后续版本支持。")
                    .font(.caption)
                    .foregroundStyle(brand.text2)

                Button(action: recognize) {
                    Text("识别")
                        .font(.body.weight(.semibold))
                        .frame(maxWidth: .infinity)
                        .frame(height: 44)
                }
                .buttonStyle(.borderedProminent)
                .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
            .padding(16)
        }
    }

    private func previewStep(_ preview: ImportPreview) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                BrandCard {
                    HStack(spacing: 12) {
                        ProtocolBadge(outboundKind: preview.outboundKind)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(preview.name)
                                .font(.headline)
                                .foregroundStyle(brand.text)
                            Text(preview.maskedServer)
                                .font(.footnote.monospaced())
                                .foregroundStyle(brand.text2)
                            Text(preview.outboundKind)
                                .font(.caption)
                                .foregroundStyle(brand.text2)
                        }
                    }
                }

                if let current = tunnel.nodeName {
                    Label("将替换当前节点“\(current)”", systemImage: "arrow.triangle.2.circlepath")
                        .font(.subheadline)
                        .foregroundStyle(brand.text2)
                }

                Text("密码和密钥只保存在钥匙串里，界面和诊断信息都不会显示。")
                    .font(.caption)
                    .foregroundStyle(brand.text2)

                if let error = error {
                    Label(error, systemImage: "exclamationmark.circle.fill")
                        .font(.subheadline)
                        .foregroundStyle(brand.danger)
                }

                Button {
                    save(preview)
                } label: {
                    Group {
                        if saving {
                            ProgressView()
                        } else {
                            Text("导入")
                        }
                    }
                    .font(.body.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .frame(height: 44)
                }
                .buttonStyle(.borderedProminent)
                .disabled(saving)

                Button("返回修改") {
                    error = nil
                    step = .input
                }
                .frame(maxWidth: .infinity)
            }
            .padding(16)
        }
    }

    private func recognize() {
        switch tunnel.preview(text) {
        case let .success(preview):
            error = nil
            withAnimation(.easeInOut(duration: 0.22)) {
                step = .preview(preview)
            }
        case let .failure(failure):
            error = failure.message
        }
    }

    private func save(_ preview: ImportPreview) {
        saving = true
        Task {
            let saved = await tunnel.importLink(text)
            saving = false
            if saved {
                error = nil
                text = ""
                withAnimation(.easeInOut(duration: 0.22)) {
                    step = .done(preview.name)
                }
            } else {
                error = tunnel.message ?? String(localized: "导入失败")
                tunnel.clearMessage()
            }
        }
    }

    private func readFile(_ result: Result<URL, Error>) {
        guard case let .success(url) = result else {
            error = String(localized: "无法读取文件")
            return
        }
        let scoped = url.startAccessingSecurityScopedResource()
        defer {
            if scoped {
                url.stopAccessingSecurityScopedResource()
            }
        }
        // WireGuard configs are a few hundred bytes; refuse anything that is clearly not one.
        guard let data = try? Data(contentsOf: url), data.count <= 64 * 1024,
              let contents = String(data: data, encoding: .utf8)
        else {
            error = String(localized: "文件不是可识别的文本配置")
            return
        }
        text = contents
        recognize()
    }
}

/// The success screen: the brand mark draws its route line, then the user goes back to connect.
private struct DoneStep: View {
    @Environment(\.brand) private var brand
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let name: String
    let connect: () -> Void
    let again: () -> Void
    @State private var drawn: CGFloat = 0

    var body: some View {
        VStack(spacing: 16) {
            Spacer()
            BrandMark(size: 120, drawn: drawn)
            Text("导入完成")
                .font(.title2.weight(.bold))
                .foregroundStyle(brand.text)
            Text("“\(name)”已设为当前节点。")
                .font(.subheadline)
                .foregroundStyle(brand.text2)
                .multilineTextAlignment(.center)
            Spacer()
            Button(action: connect) {
                Text("去连接")
                    .font(.body.weight(.semibold))
                    .frame(maxWidth: .infinity)
                    .frame(height: 44)
            }
            .buttonStyle(.borderedProminent)
            Button("继续导入", action: again)
        }
        .padding(24)
        .sensoryFeedback(.success, trigger: drawn) { _, new in new == 1 }
        .onAppear {
            if reduceMotion {
                drawn = 1
            } else {
                withAnimation(.easeOut(duration: 0.9)) {
                    drawn = 1
                }
            }
        }
    }
}
