import SwiftUI

/// Proxies: the saved node today; subscriptions and policy groups join this list when the kernel supports them.
struct ProxiesView: View {
    @ObservedObject var tunnel: TunnelController
    @Binding var importing: Bool
    @Environment(\.brand) private var brand

    var body: some View {
        NavigationStack {
            Group {
                if let name = tunnel.nodeName {
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
                            Text("导入新节点会替换当前节点。多节点、订阅和策略组会在内核支持后开放。")
                        }
                    }
                    .scrollContentBackground(.hidden)
                } else {
                    ScrollView {
                        BrandEmptyState(
                            systemImage: "globe",
                            title: "还没有节点",
                            message: "粘贴 ss://、vless:// 链接，或导入 WireGuard 配置。"
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
            .background(brand.bg.ignoresSafeArea())
            .navigationTitle("代理")
            .toolbar {
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
}
