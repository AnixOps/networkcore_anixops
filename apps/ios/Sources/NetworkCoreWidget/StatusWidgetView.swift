import SwiftUI
import WidgetKit

struct StatusWidgetView: View {
    @Environment(\.widgetFamily) private var family
    let entry: StatusEntry

    private var snapshot: TunnelSnapshot { entry.snapshot }
    private var phase: ConnectPhase { ConnectPhase(status: snapshot.status, hasNode: snapshot.nodeName != nil) }

    var body: some View {
        switch family {
        case .accessoryCircular:
            Button(intent: ToggleTunnelIntent(on: !snapshot.isOn)) {
                StaticRouteLine(phase: phase, size: 40, accessory: true)
            }
            .buttonStyle(.plain)
            .disabled(phase == .unconfigured)
            .containerBackground(for: .widget) { AccessoryWidgetBackground() }
            .widgetLabel(phase.title)
            .accessibilityLabel(phase.accessibilityLabel)
        case .accessoryRectangular:
            VStack(alignment: .leading, spacing: 2) {
                Label("AnixOps Net", systemImage: snapshot.isOn ? "network" : "network.slash")
                    .font(.headline)
                    .widgetAccentable()
                Text(phase.title)
                if let name = snapshot.nodeName {
                    Text(name).foregroundStyle(.secondary).lineLimit(1)
                }
            }
            .containerBackground(for: .widget) { Color.clear }
        case .accessoryInline:
            Label(phase.title, systemImage: snapshot.isOn ? "network" : "network.slash")
                .containerBackground(for: .widget) { Color.clear }
        case .systemMedium:
            HStack(spacing: 16) {
                connectButton(size: 96)
                details
                Spacer(minLength: 0)
            }
            .heroBackground()
        default:
            VStack(alignment: .leading, spacing: 8) {
                connectButton(size: 64)
                Spacer(minLength: 0)
                Text(phase.title)
                    .font(.headline)
                if let name = snapshot.nodeName {
                    Text(name)
                        .font(.caption)
                        .foregroundStyle(Brand.line.opacity(0.75))
                        .lineLimit(1)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .heroBackground()
        }
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text("AnixOps Net")
                .font(.caption.weight(.semibold))
                .foregroundStyle(Brand.line.opacity(0.75))
            Text(phase.title)
                .font(.title3.weight(.semibold))
            if let name = snapshot.nodeName {
                HStack(spacing: 6) {
                    Text(ProtocolBadge.abbreviation(for: snapshot.outboundKind))
                        .font(.caption2.weight(.bold))
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Brand.line.opacity(0.15), in: RoundedRectangle(cornerRadius: 5, style: .continuous))
                    Text(name)
                        .font(.subheadline)
                        .lineLimit(1)
                }
                .foregroundStyle(Brand.line.opacity(0.85))
            } else {
                Text("先在 App 里导入节点")
                    .font(.subheadline)
                    .foregroundStyle(Brand.line.opacity(0.75))
            }
        }
    }

    /// The route-line button connects when off and disconnects when on; without a node it opens the app.
    @ViewBuilder
    private func connectButton(size: CGFloat) -> some View {
        if phase == .unconfigured {
            StaticRouteLine(phase: phase, size: size)
        } else {
            Button(intent: ToggleTunnelIntent(on: !snapshot.isOn)) {
                StaticRouteLine(phase: phase, size: size)
            }
            .buttonStyle(.plain)
            .accessibilityLabel(phase.accessibilityLabel)
        }
    }
}

/// The connect button's route line without animation, since widgets render static snapshots.
struct StaticRouteLine: View {
    let phase: ConnectPhase
    let size: CGFloat
    var accessory = false

    var body: some View {
        let on = phase == .on
        let line = size * 0.62
        ZStack {
            if !accessory {
                Circle()
                    .fill(Brand.line.opacity(0.06))
                Circle()
                    .strokeBorder(on ? Brand.mint.opacity(0.7) : Brand.line.opacity(0.25), lineWidth: 1.5)
            }
            ZStack {
                RouteLineShape()
                    .stroke(Brand.line.opacity(accessory ? 0.3 : 0.16), style: stroke(width: line * 0.09, dashed: false))
                RouteLineShape()
                    .trim(from: 0, to: phase.isBusy ? 0.6 : 1)
                    .stroke(on ? Brand.line : Brand.line.opacity(0.55), style: stroke(width: line * 0.09, dashed: !on && !phase.isBusy))
                Circle()
                    .fill(Brand.mint)
                    .frame(width: line * 0.15, height: line * 0.15)
                    .position(x: line * 0.30, y: line * 0.72)
                Circle()
                    .fill(on ? Brand.amber : Brand.amber.opacity(0.45))
                    .frame(width: line * 0.15, height: line * 0.15)
                    .position(x: line * 0.70, y: line * 0.28)
                    .widgetAccentable()
            }
            .frame(width: line, height: line)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }

    private func stroke(width: CGFloat, dashed: Bool) -> StrokeStyle {
        StrokeStyle(lineWidth: width, lineCap: .round, lineJoin: .round, dash: dashed ? [width * 0.7, width * 0.9] : [])
    }
}

private extension View {
    /// The brand hero gradient as the widget background, with light text on top.
    func heroBackground() -> some View {
        foregroundStyle(Brand.line)
            .containerBackground(for: .widget) {
                LinearGradient(colors: [Brand.deep, Brand.iconTeal], startPoint: .topLeading, endPoint: .bottomTrailing)
            }
    }
}
