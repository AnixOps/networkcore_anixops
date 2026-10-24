import AppIntents
import WidgetKit

/// Connects or disconnects the saved tunnel. Compiled into the app and the widget extension so the
/// interactive widget, the Control Center switch and Shortcuts share one action.
struct ToggleTunnelIntent: SetValueIntent {
    static let title: LocalizedStringResource = "连接或断开 AnixOps Net"
    static let description = IntentDescription("用已导入的节点连接，或断开当前连接。")

    @Parameter(title: "已连接")
    var value: Bool

    init() {}

    init(on: Bool) {
        value = on
    }

    func perform() async throws -> some IntentResult {
        try await TunnelSwitch.set(on: value)
        WidgetCenter.shared.reloadAllTimelines()
        return .result()
    }
}
