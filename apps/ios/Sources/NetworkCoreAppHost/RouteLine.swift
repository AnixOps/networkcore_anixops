import NetworkExtension
import SwiftUI

/// What the connect button shows, derived from the VPN status.
enum ConnectPhase: Equatable {
    case unconfigured
    case off
    case connecting
    case on
    case reasserting
    case disconnecting

    init(status: NEVPNStatus, hasNode: Bool) {
        switch status {
        case .connected:
            self = .on
        case .connecting:
            self = .connecting
        case .reasserting:
            self = .reasserting
        case .disconnecting:
            self = .disconnecting
        case .disconnected, .invalid:
            self = hasNode ? .off : .unconfigured
        @unknown default:
            self = hasNode ? .off : .unconfigured
        }
    }

    var isBusy: Bool {
        self == .connecting || self == .reasserting || self == .disconnecting
    }

    var title: String {
        switch self {
        case .unconfigured:
            return String(localized: "还没有节点")
        case .off:
            return String(localized: "未连接")
        case .connecting:
            return String(localized: "正在连接…")
        case .on:
            return String(localized: "已连接")
        case .reasserting:
            return String(localized: "网络变化，正在重连")
        case .disconnecting:
            return String(localized: "正在断开…")
        }
    }

    var accessibilityLabel: String {
        switch self {
        case .unconfigured:
            return String(localized: "导入节点")
        case .off:
            return String(localized: "连接，当前未连接")
        case .connecting, .reasserting:
            return String(localized: "断开，正在连接")
        case .on:
            return String(localized: "断开，当前已连接")
        case .disconnecting:
            return String(localized: "正在断开")
        }
    }

    /// Plain-text VPN status for developer mode and its copied report.
    static func describe(_ status: NEVPNStatus) -> String {
        switch status {
        case .connected:
            return String(localized: "已连接")
        case .connecting:
            return String(localized: "连接中")
        case .disconnecting:
            return String(localized: "断开中")
        case .reasserting:
            return String(localized: "重新连接中")
        case .disconnected:
            return String(localized: "未连接")
        case .invalid:
            return String(localized: "未配置")
        @unknown default:
            return String(localized: "未知状态")
        }
    }
}

/// The brand's route line: the "N" of the app icon, from the mint start point to the amber end point.
struct RouteLineShape: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        func point(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
            CGPoint(x: rect.minX + rect.width * x, y: rect.minY + rect.height * y)
        }
        path.move(to: point(0.30, 0.72))
        path.addLine(to: point(0.30, 0.28))
        path.addLine(to: point(0.70, 0.72))
        path.addLine(to: point(0.70, 0.28))
        return path
    }
}

/// The route-line mark drawn for a phase: dashed when off, growing in a loop while connecting,
/// solid with a lit end point when connected. Reduce Motion replaces the loop with a steady half line.
struct RouteLineMark: View {
    let phase: ConnectPhase
    var size: CGFloat = 104
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var pop = false

    private var lineWidth: CGFloat { size * 0.09 }
    private var dotSize: CGFloat { size * 0.15 }

    var body: some View {
        TimelineView(.animation(paused: !phase.isBusy || reduceMotion)) { context in
            ZStack {
                RouteLineShape()
                    .stroke(Brand.line.opacity(0.16), style: stroke(dashed: false))
                RouteLineShape()
                    .trim(from: 0, to: progress(at: context.date))
                    .stroke(lineStyle, style: stroke(dashed: phase == .off || phase == .unconfigured))
                dot(at: CGPoint(x: 0.30, y: 0.72), color: Brand.mint)
                dot(at: CGPoint(x: 0.70, y: 0.28), color: phase == .on ? Brand.amber : Brand.amber.opacity(0.45))
                    .scaleEffect(pop ? 1.45 : 1)
            }
            .frame(width: size, height: size)
        }
        .onChange(of: phase) { _, newPhase in
            guard newPhase == .on, !reduceMotion else {
                return
            }
            withAnimation(.spring(response: 0.22, dampingFraction: 0.5)) {
                pop = true
            }
            withAnimation(.spring(response: 0.35, dampingFraction: 0.85).delay(0.22)) {
                pop = false
            }
        }
        .accessibilityHidden(true)
    }

    private var lineStyle: AnyShapeStyle {
        switch phase {
        case .on:
            return AnyShapeStyle(LinearGradient(colors: [Brand.lineStart, Brand.line], startPoint: .bottomLeading, endPoint: .topTrailing))
        case .connecting, .reasserting, .disconnecting:
            return AnyShapeStyle(Brand.lineStart)
        case .off, .unconfigured:
            return AnyShapeStyle(Brand.line.opacity(0.45))
        }
    }

    private func stroke(dashed: Bool) -> StrokeStyle {
        StrokeStyle(
            lineWidth: lineWidth,
            lineCap: .round,
            lineJoin: .round,
            dash: dashed ? [size * 0.06, size * 0.07] : []
        )
    }

    private func progress(at date: Date) -> CGFloat {
        guard phase.isBusy else {
            return 1
        }
        if reduceMotion {
            return 0.5
        }
        let period = 1.2
        let t = date.timeIntervalSinceReferenceDate.truncatingRemainder(dividingBy: period) / period
        let drawn = min(t / 0.7, 1)
        // Ease out so the line slows as it reaches the end point.
        let eased = 1 - pow(1 - drawn, 3)
        return CGFloat(phase == .disconnecting ? 1 - eased : eased)
    }

    private func dot(at unit: CGPoint, color: Color) -> some View {
        Circle()
            .fill(color)
            .frame(width: dotSize, height: dotSize)
            .position(x: size * unit.x, y: size * unit.y)
    }
}

/// The app icon drawn in SwiftUI, used for the wordmark and the import success screen.
struct BrandMark: View {
    var size: CGFloat = 30
    var drawn: CGFloat = 1

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.23, style: .continuous)
                .fill(Brand.iconTeal)
            RouteLineShape()
                .trim(from: 0, to: drawn)
                .stroke(Brand.line, style: StrokeStyle(lineWidth: size * 0.1, lineCap: .round, lineJoin: .round))
            Circle()
                .fill(Brand.amber)
                .frame(width: size * 0.13, height: size * 0.13)
                .position(x: size * 0.70, y: size * 0.28)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// "AnixOps Net" with "Net" in the brand color.
struct Wordmark: View {
    @Environment(\.brand) private var brand

    var body: some View {
        HStack(spacing: 10) {
            BrandMark(size: 30)
            (Text("AnixOps ").foregroundColor(brand.text) + Text("Net").foregroundColor(brand.primary))
                .font(.title2.weight(.bold))
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("AnixOps Net")
        .accessibilityAddTraits(.isHeader)
    }
}
