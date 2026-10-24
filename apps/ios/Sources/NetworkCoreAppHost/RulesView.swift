import NetworkCoreBridge
import SwiftUI

/// Rules: whether the tunnel follows the subscription's rules, and its policy groups. Only subscriptions that carry
/// rules and groups (Clash, Surge or Loon profiles) have anything to show here.
struct RulesView: View {
    @ObservedObject var tunnel: TunnelController
    @Environment(\.brand) private var brand

    var body: some View {
        NavigationStack {
            Group {
                if let library = tunnel.library, let routing = library.routing {
                    rules(library, routing)
                } else {
                    ScrollView {
                        BrandEmptyState(
                            systemImage: "arrow.triangle.branch",
                            title: "规则与分流",
                            message: "导入带规则和策略组的订阅（Clash、Surge、Loon 配置）后，可以在这里按订阅规则分流和切换策略组。现在全部流量走所选节点。"
                        )
                        .padding(.top, 80)
                    }
                }
            }
            .background(brand.bg.ignoresSafeArea())
            .navigationTitle("规则")
            .brandBars(brand)
        }
    }

    private func rules(_ library: NodeLibrary, _ routing: NativeImportReport.Routing) -> some View {
        List {
            Section {
                Toggle("按订阅规则分流", isOn: Binding(
                    get: { library.followsRules },
                    set: { on in
                        Task {
                            await tunnel.setFollowsRules(on)
                        }
                    }
                ))
                .listRowBackground(brand.surface)
            } header: {
                Text("\(routing.rules.count) 条规则 · \(routing.groups.count) 个策略组")
            } footer: {
                Text("关闭后全部流量走代理页选中的节点。连接中修改会自动重连。")
            }

            Section {
                ForEach(routing.groups) { group in
                    groupRow(group, library: library)
                        .listRowBackground(brand.surface)
                }
            } header: {
                Text("策略组")
            } footer: {
                Text("自动选择和故障转移的组由内核按延迟和可用性挑选节点。")
            }
            .disabled(!library.followsRules)
        }
        .scrollContentBackground(.hidden)
    }

    @ViewBuilder
    private func groupRow(_ group: NativeImportReport.Routing.Group, library: NodeLibrary) -> some View {
        if group.isSelectable {
            Picker(selection: Binding(
                get: { library.selection(in: group) ?? "" },
                set: { member in
                    Task {
                        await tunnel.selectMember(member, inGroup: group.id)
                    }
                }
            )) {
                ForEach(group.members, id: \.self) { member in
                    Text(verbatim: name(of: member, in: library))
                        .tag(member)
                }
            } label: {
                Text(verbatim: group.id)
            }
            .pickerStyle(.menu)
        } else {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(verbatim: group.id)
                        .foregroundStyle(brand.text)
                    Text(group.type == "fallback" ? String(localized: "故障转移") : String(localized: "自动选择"))
                        .font(.footnote)
                        .foregroundStyle(brand.text2)
                }
                Spacer()
                Text("\(group.members.count) 个成员")
                    .font(.footnote)
                    .foregroundStyle(brand.text2)
            }
        }
    }

    private func name(of member: String, in library: NodeLibrary) -> String {
        switch member {
        case "DIRECT":
            return String(localized: "直连")
        case "REJECT":
            return String(localized: "拒绝")
        default:
            return library.displayName(ofMember: member)
        }
    }
}
