import SwiftUI
import WidgetKit

@main
struct NetworkCoreWidgets: WidgetBundle {
    var body: some Widget {
        StatusWidget()
        if #available(iOS 18.0, *) {
            ConnectControl()
        }
    }
}

/// Home Screen and Lock Screen widget: is the tunnel up, through which node, with a connect button.
struct StatusWidget: Widget {
    static let kind = "io.anixops.net.status"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: Self.kind, provider: StatusProvider()) { entry in
            StatusWidgetView(entry: entry)
        }
        .configurationDisplayName("连接状态")
        .description("查看是否已连接，轻点即可连接或断开。")
        .supportedFamilies([.systemSmall, .systemMedium, .accessoryCircular, .accessoryRectangular, .accessoryInline])
    }
}

struct StatusEntry: TimelineEntry {
    let date: Date
    let snapshot: TunnelSnapshot
}

/// The app reloads the timeline whenever the tunnel status changes; the 15-minute refresh catches
/// changes made while the app was not running, such as iOS stopping the tunnel.
struct StatusProvider: TimelineProvider {
    func placeholder(in context: Context) -> StatusEntry {
        StatusEntry(date: .now, snapshot: .placeholder)
    }

    func getSnapshot(in context: Context, completion: @escaping (StatusEntry) -> Void) {
        if context.isPreview {
            completion(placeholder(in: context))
            return
        }
        Task {
            completion(StatusEntry(date: .now, snapshot: await TunnelSnapshot.load()))
        }
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<StatusEntry>) -> Void) {
        Task {
            let entry = StatusEntry(date: .now, snapshot: await TunnelSnapshot.load())
            completion(Timeline(entries: [entry], policy: .after(.now.addingTimeInterval(15 * 60))))
        }
    }
}

/// Control Center, Lock Screen and Action button switch (iOS 18).
@available(iOS 18.0, *)
struct ConnectControl: ControlWidget {
    static let kind = "io.anixops.net.connect"

    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: Self.kind, provider: Provider()) { isOn in
            ControlWidgetToggle("AnixOps Net", isOn: isOn, action: ToggleTunnelIntent()) { on in
                Label(on ? "已连接" : "未连接", systemImage: on ? "network" : "network.slash")
            }
            .tint(Brand.iconTeal)
        }
        .displayName("连接 AnixOps Net")
        .description("在控制中心连接或断开。")
    }

    struct Provider: ControlValueProvider {
        var previewValue: Bool { false }

        func currentValue() async throws -> Bool {
            await TunnelSnapshot.load().isOn
        }
    }
}
