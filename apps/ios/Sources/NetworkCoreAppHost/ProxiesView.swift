import NetworkCoreBridge
import SwiftUI

/// Proxies: every node of the imported subscription (or the single saved node), with delay tests and switching.
struct ProxiesView: View {
    @ObservedObject var tunnel: TunnelController
    @Binding var importing: Bool
    @Environment(\.brand) private var brand
    @State private var testing = false

    var body: some View {
        NavigationStack {
            Group {
                if let library = tunnel.library, !library.nodes.isEmpty {
                    nodeList(library)
                } else if let name = tunnel.nodeName {
                    singleNode(name)
                } else {
                    empty
                }
            }
            .background(brand.bg.ignoresSafeArea())
            .navigationTitle("代理")
            .toolbar {
                if tunnel.library?.nodes.isEmpty == false {
                    ToolbarItem(placement: .topBarLeading) {
                        Button {
                            testing = true
                            Task {
                                await tunnel.testLatency()
                                testing = false
                            }
                        } label: {
                            Image(systemName: "speedometer")
                        }
                        .disabled(testing)
                        .accessibilityLabel("测试延迟")
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        importing = true
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityLabel("导入节点")
                }
            }
            .brandBars(brand)
        }
    }

    private func nodeList(_ library: NodeLibrary) -> some View {
        List {
            Section {
                ForEach(library.nodes) { node in
                    Button {
                        Task {
                            await tunnel.selectNode(node.id)
                        }
                    } label: {
                        row(node, selected: !library.routesByRules && node.id == library.selectedID)
                    }
                    .buttonStyle(.plain)
                    .disabled(library.routesByRules)
                    .listRowBackground(brand.surface)
                }
            } header: {
                if let link = library.subscriptionURL {
                    Text("订阅 \(SubscriptionLink.displayHost(link)) · \(library.nodes.count) 个节点")
                } else {
                    Text("节点")
                }
            } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    if library.routesByRules {
                        Text("正在按订阅规则分流，节点由策略组决定；可以在“规则”页切换策略组或关闭规则。")
                    }
                    Text("延迟为到服务器端口的 TCP 连接时间；Hysteria2、TUIC 走 UDP，不在此测量。连接中切换节点会自动重连。")
                }
            }
        }
        .scrollContentBackground(.hidden)
        .refreshable {
            if library.subscriptionURL != nil {
                await tunnel.refreshSubscription()
            }
        }
    }

    private func row(_ node: NativeImportReport.Node, selected: Bool) -> some View {
        HStack(spacing: 12) {
            ProtocolBadge(outboundKind: node.protocol)
            VStack(alignment: .leading, spacing: 2) {
                Text(node.name.isEmpty ? ImportPreview.mask(node.server) : node.name)
                    .font(.body.weight(selected ? .semibold : .regular))
                    .foregroundStyle(brand.text)
                    .lineLimit(1)
                Text(ProtocolBadge.spokenName(for: node.protocol))
                    .font(.footnote)
                    .foregroundStyle(brand.text2)
            }
            Spacer()
            latency(tunnel.latencies[node.id])
            if selected {
                Circle()
                    .fill(Brand.amber)
                    .frame(width: 8, height: 8)
                    .accessibilityLabel("当前节点")
            }
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }

    @ViewBuilder
    private func latency(_ result: NodeLatency?) -> some View {
        switch result {
        case .none:
            EmptyView()
        case .measuring:
            ProgressView()
                .controlSize(.small)
        case let .millis(value):
            Text("\(value) ms")
                .font(.footnote.monospacedDigit())
                .foregroundStyle(value < 300 ? brand.text2 : brand.danger)
        case .failed:
            Text("超时")
                .font(.footnote)
                .foregroundStyle(brand.danger)
        case .notMeasurable:
            Text("UDP")
                .font(.footnote)
                .foregroundStyle(brand.text3)
        }
    }

    private func singleNode(_ name: String) -> some View {
        List {
            Section {
                HStack(spacing: 12) {
                    ProtocolBadge(outboundKind: tunnel.outboundKind)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(name)
                            .font(.body.weight(.semibold))
                            .foregroundStyle(brand.text)
                        Text(ProtocolBadge.spokenName(for: tunnel.outboundKind))
                            .font(.footnote)
                            .foregroundStyle(brand.text2)
                    }
                    Spacer()
                    Circle()
                        .fill(Brand.amber)
                        .frame(width: 8, height: 8)
                        .accessibilityLabel("当前节点")
                }
                .padding(.vertical, 4)
                .listRowBackground(brand.surface)
            } header: {
                Text("节点")
            } footer: {
                Text("导入订阅链接或多个节点后，这里会列出全部节点，可以测延迟和切换。")
            }
        }
        .scrollContentBackground(.hidden)
    }

    private var empty: some View {
        ScrollView {
            BrandEmptyState(
                systemImage: "globe",
                title: "还没有节点",
                message: "粘贴订阅链接，或 ss://、vless://、trojan://、vmess://、hysteria2://、tuic:// 等链接和订阅内容，或导入 WireGuard 配置。"
            ) {
                Button {
                    importing = true
                } label: {
                    Text("导入节点")
                        .font(.body.weight(.semibold))
                        .padding(.horizontal, 24)
                        .frame(height: 44)
                }
                .buttonStyle(.borderedProminent)
                .padding(.top, 6)
            }
            .padding(.top, 80)
        }
    }
}
