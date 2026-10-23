import SwiftUI

/// Home: the connect card answers "am I connected, through which node", then the node and any error.
struct HomeView: View {
    @ObservedObject var tunnel: TunnelController
    @Binding var tab: AppTab
    @Binding var importing: Bool
    @Environment(\.brand) private var brand

    private var phase: ConnectPhase {
        ConnectPhase(status: tunnel.connection, hasNode: tunnel.nodeName != nil)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    header
                    ConnectCard(tunnel: tunnel, phase: phase, importing: $importing)
                    nodeCard
                    if let message = tunnel.message {
                        MessageCard(text: message) {
                            tunnel.clearMessage()
                        }
                    }
                }
                .padding(.horizontal, 16)
                .padding(.bottom, 24)
            }
            .background(brand.bg.ignoresSafeArea())
            .toolbar(.hidden, for: .navigationBar)
            .brandBars(brand)
        }
    }

    private var header: some View {
        HStack {
            Wordmark()
            Spacer()
            Button {
                importing = true
            } label: {
                Image(systemName: "plus")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(brand.primary)
                    .frame(width: 40, height: 40)
                    .background(brand.raised, in: Circle())
            }
            .accessibilityLabel("导入节点")
        }
        .frame(height: 52)
        .padding(.top, 4)
    }

    @ViewBuilder
    private var nodeCard: some View {
        if let name = tunnel.nodeName {
            Button {
                tab = .proxies
            } label: {
                BrandCard {
                    HStack(spacing: 12) {
                        ProtocolBadge(outboundKind: tunnel.outboundKind)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("当前节点")
                                .font(.footnote)
                                .foregroundStyle(brand.text2)
                            Text(name)
                                .font(.body.weight(.semibold))
                                .foregroundStyle(brand.text)
                                .lineLimit(1)
                        }
                        Spacer(minLength: 8)
                        Image(systemName: "chevron.right")
                            .font(.footnote.weight(.semibold))
                            .foregroundStyle(brand.text3)
                    }
                }
            }
            .buttonStyle(.plain)
        }
    }
}

/// The hero card: the route-line connect button, the status and the elapsed time.
private struct ConnectCard: View {
    @ObservedObject var tunnel: TunnelController
    let phase: ConnectPhase
    @Binding var importing: Bool

    var body: some View {
        VStack(spacing: 14) {
            Button(action: tap) {
                RouteLineMark(phase: phase, size: 104)
                    .frame(width: 156, height: 156)
                    .background(Brand.line.opacity(0.06), in: Circle())
                    .overlay(
                        Circle().strokeBorder(phase == .on ? Brand.mint.opacity(0.7) : Brand.line.opacity(0.25), lineWidth: 1.5)
                    )
                    .contentShape(Circle())
            }
            .buttonStyle(PressableStyle())
            .disabled(phase == .disconnecting)
            .accessibilityLabel(phase.accessibilityLabel)
            .sensoryFeedback(.success, trigger: phase) { _, new in new == .on }
            .sensoryFeedback(.impact(weight: .light), trigger: phase) { _, new in new == .connecting }

            VStack(spacing: 4) {
                Text(phase.title)
                    .font(.title3.weight(.semibold))
                    .contentTransition(.opacity)
                subtitle
                    .font(.footnote.monospacedDigit())
                    .foregroundStyle(Brand.line.opacity(0.75))
                    .multilineTextAlignment(.center)
            }
            .animation(.easeInOut(duration: 0.22), value: phase)
        }
        .foregroundStyle(Brand.line)
        .padding(.vertical, 24)
        .padding(.horizontal, 20)
        .frame(maxWidth: .infinity)
        .background(heroBackground, in: RoundedRectangle(cornerRadius: 24, style: .continuous))
    }

    @Environment(\.brand) private var brand

    private var heroBackground: LinearGradient {
        brand.heroGradient
    }

    @ViewBuilder
    private var subtitle: some View {
        switch phase {
        case .on:
            if let since = tunnel.connectedSince {
                TimelineView(.periodic(from: since, by: 1)) { context in
                    Text(Self.elapsed(from: since, to: context.date))
                }
            } else {
                Text(tunnel.nodeName ?? "")
            }
        case .off:
            if case let .blocked(reason, _) = tunnel.coordinator.decision {
                Text(reason)
            } else {
                Text("轻点连接")
            }
        case .unconfigured:
            Text("轻点导入第一个节点")
        case .connecting:
            Text("正在建立安全隧道")
        case .reasserting:
            Text("网络已切换，马上恢复")
        case .disconnecting:
            Text(" ")
        }
    }

    private func tap() {
        if phase == .unconfigured {
            importing = true
        } else {
            tunnel.toggle()
        }
    }

    static func elapsed(from start: Date, to now: Date) -> String {
        let seconds = max(0, Int(now.timeIntervalSince(start)))
        return String(format: "%02d:%02d:%02d", seconds / 3600, seconds / 60 % 60, seconds % 60)
    }
}

/// Shrinks slightly while pressed, without the default list highlight.
struct PressableStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.96 : 1)
            .animation(.spring(response: 0.25, dampingFraction: 0.8), value: configuration.isPressed)
    }
}

/// An error or notice: what happened, with a dismiss button. Developer mode has the full diagnostics.
private struct MessageCard: View {
    @Environment(\.brand) private var brand
    let text: String
    let dismiss: () -> Void

    var body: some View {
        BrandCard {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(brand.warning)
                    .accessibilityHidden(true)
                Text(text)
                    .font(.subheadline)
                    .foregroundStyle(brand.text)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
                Button(action: dismiss) {
                    Image(systemName: "xmark")
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(brand.text3)
                        .frame(width: 28, height: 28)
                }
                .accessibilityLabel("关闭提示")
            }
        }
    }
}
