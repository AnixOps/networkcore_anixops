import SwiftUI

/// Settings: appearance, privacy and the About section that unlocks developer mode.
struct SettingsView: View {
    @ObservedObject var tunnel: TunnelController
    @AppStorage(Appearance.storageKey) private var appearance = Appearance.system
    @Environment(\.brand) private var brand

    var body: some View {
        NavigationStack {
            Form {
                Section("外观") {
                    Picker("外观", selection: $appearance) {
                        ForEach(Appearance.allCases) { option in
                            Text(option.label).tag(option)
                        }
                    }
                    .pickerStyle(.segmented)
                    .listRowBackground(brand.surface)
                }

                Section {
                    Label("不收集你的流量和浏览记录", systemImage: "hand.raised")
                        .listRowBackground(brand.surface)
                    Label("节点密码和密钥只保存在本机钥匙串", systemImage: "key")
                        .listRowBackground(brand.surface)
                } header: {
                    Text("隐私")
                }

                AboutSection(tunnel: tunnel)
                    .listRowBackground(brand.surface)
            }
            .scrollContentBackground(.hidden)
            .background(brand.bg.ignoresSafeArea())
            .navigationTitle("设置")
            .brandBars(brand)
        }
    }
}
