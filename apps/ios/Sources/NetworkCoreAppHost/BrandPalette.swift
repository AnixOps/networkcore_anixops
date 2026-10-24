import SwiftUI

/// The appearance picked in Settings. `system` follows iOS; `oled` is dark with a pure black background.
enum Appearance: String, CaseIterable, Identifiable {
    case system
    case light
    case dark
    case oled

    static let storageKey = "appearance"

    var id: String { rawValue }

    var label: String {
        switch self {
        case .system:
            return "跟随系统"
        case .light:
            return "浅色"
        case .dark:
            return "深色"
        case .oled:
            return "纯黑"
        }
    }

    var colorScheme: ColorScheme? {
        switch self {
        case .system:
            return nil
        case .light:
            return .light
        case .dark, .oled:
            return .dark
        }
    }
}

/// Brand colors. The values mirror apps/ios/Design/tokens.json; change both together.
struct BrandPalette: Sendable {
    let bg: Color
    let surface: Color
    let raised: Color
    let border: Color
    let soft: Color
    let primary: Color
    let onPrimary: Color
    let text: Color
    let text2: Color
    let text3: Color
    let warning: Color
    let danger: Color
    let amberText: Color
    let heroStart: Color
    let heroEnd: Color
    /// OLED keeps the tab bar black instead of the system material.
    let solidBars: Bool

    static let light = BrandPalette(
        bg: Color(hex: 0xF2F6F6), surface: Color(hex: 0xFFFFFF), raised: Color(hex: 0xEAF0F0),
        border: Color(hex: 0xDCE5E4), soft: Color(hex: 0xCCFBF1), primary: Color(hex: 0x0F766E),
        onPrimary: Color(hex: 0xFFFFFF), text: Color(hex: 0x0B1F1E), text2: Color(hex: 0x4B5F5D),
        text3: Color(hex: 0x7A8C8A), warning: Color(hex: 0xC2410C), danger: Color(hex: 0xB91C1C),
        amberText: Color(hex: 0xB45309), heroStart: Brand.deep, heroEnd: Color(hex: 0x0F766E), solidBars: false
    )

    static let dark = BrandPalette(
        bg: Color(hex: 0x071414), surface: Color(hex: 0x0E1F1E), raised: Color(hex: 0x142928),
        border: Color(hex: 0x21403E), soft: Color(hex: 0x0F3D3A), primary: Color(hex: 0x2DD4BF),
        onPrimary: Color(hex: 0x042F2E), text: Color(hex: 0xE6F2F1), text2: Color(hex: 0xA3BAB8),
        text3: Color(hex: 0x7F9896), warning: Color(hex: 0xFB923C), danger: Color(hex: 0xF87171),
        amberText: Color(hex: 0xFBBF24), heroStart: Brand.deep, heroEnd: Color(hex: 0x0F766E), solidBars: false
    )

    static let oled = BrandPalette(
        bg: Color(hex: 0x000000), surface: Color(hex: 0x0A0F0F), raised: Color(hex: 0x121A1A),
        border: Color(hex: 0x1C2B2A), soft: Color(hex: 0x0B2E2B), primary: Color(hex: 0x2DD4BF),
        onPrimary: Color(hex: 0x042F2E), text: Color(hex: 0xE6F2F1), text2: Color(hex: 0xA3BAB8),
        text3: Color(hex: 0x7F9896), warning: Color(hex: 0xFB923C), danger: Color(hex: 0xF87171),
        amberText: Color(hex: 0xFBBF24), heroStart: Color(hex: 0x021A19), heroEnd: Color(hex: 0x0B5550), solidBars: true
    )

    static func resolve(appearance: Appearance, scheme: ColorScheme) -> BrandPalette {
        switch appearance {
        case .oled:
            return .oled
        case .dark:
            return .dark
        case .light:
            return .light
        case .system:
            return scheme == .dark ? .dark : .light
        }
    }

    var heroGradient: LinearGradient {
        LinearGradient(colors: [heroStart, heroEnd], startPoint: .topLeading, endPoint: .bottomTrailing)
    }
}

/// Colors that stay the same in every theme: they come straight from the app icon.
enum Brand {
    static let deep = Color(hex: 0x042F2E)
    static let mint = Color(hex: 0x5EEAD4)
    static let lineStart = Color(hex: 0x99F6E4)
    static let line = Color(hex: 0xF0FDFA)
    static let amber = Color(hex: 0xFBBF24)
    static let iconTeal = Color(hex: 0x0F766E)
}

extension Color {
    init(hex: UInt32) {
        self.init(
            .sRGB,
            red: Double((hex >> 16) & 0xFF) / 255,
            green: Double((hex >> 8) & 0xFF) / 255,
            blue: Double(hex & 0xFF) / 255,
            opacity: 1
        )
    }
}

private struct BrandPaletteKey: EnvironmentKey {
    static let defaultValue = BrandPalette.light
}

extension EnvironmentValues {
    var brand: BrandPalette {
        get { self[BrandPaletteKey.self] }
        set { self[BrandPaletteKey.self] = newValue }
    }
}

/// A rounded surface card in the current palette.
struct BrandCard<Content: View>: View {
    @Environment(\.brand) private var brand
    var padding: CGFloat = 16
    @ViewBuilder var content: Content

    var body: some View {
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(brand.surface, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }
}

/// A short protocol badge such as "SS", "VLESS" or "WG"; never a third-party project logo.
struct ProtocolBadge: View {
    @Environment(\.brand) private var brand
    let outboundKind: String?

    var body: some View {
        Text(Self.abbreviation(for: outboundKind))
            .font(.caption.weight(.bold))
            .foregroundStyle(brand.primary)
            .frame(minWidth: 36, minHeight: 36)
            .padding(.horizontal, 4)
            .background(brand.soft, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .accessibilityLabel(Self.spokenName(for: outboundKind))
    }

    static func abbreviation(for kind: String?) -> String {
        guard let kind = kind?.lowercased() else {
            return "—"
        }
        if kind.hasPrefix("shadowsocks") {
            return "SS"
        }
        if kind.hasPrefix("vless") {
            return "VLESS"
        }
        if kind.hasPrefix("wireguard") {
            return "WG"
        }
        if kind.hasPrefix("hysteria2") {
            return "HY2"
        }
        return kind.uppercased()
    }

    static func spokenName(for kind: String?) -> String {
        guard let kind = kind?.lowercased() else {
            return "未知协议"
        }
        if kind.hasPrefix("shadowsocks") {
            return "Shadowsocks"
        }
        if kind.hasPrefix("vless") {
            return "VLESS"
        }
        if kind.hasPrefix("wireguard") {
            return "WireGuard"
        }
        let names = ["trojan": "Trojan", "vmess": "VMess", "hysteria2": "Hysteria2", "tuic": "TUIC"]
        return names[kind] ?? kind
    }
}

/// A centered empty state with an icon, a title and one line of explanation.
struct BrandEmptyState<Actions: View>: View {
    @Environment(\.brand) private var brand
    let systemImage: String
    let title: String
    let message: String
    @ViewBuilder var actions: Actions

    var body: some View {
        VStack(spacing: 14) {
            Image(systemName: systemImage)
                .font(.system(size: 30, weight: .medium))
                .foregroundStyle(brand.primary)
                .frame(width: 64, height: 64)
                .background(brand.soft, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
            Text(title)
                .font(.title3.weight(.semibold))
                .foregroundStyle(brand.text)
            Text(message)
                .font(.subheadline)
                .foregroundStyle(brand.text2)
                .multilineTextAlignment(.center)
            actions
        }
        .padding(24)
        .frame(maxWidth: .infinity)
    }
}

extension BrandEmptyState where Actions == EmptyView {
    init(systemImage: String, title: String, message: String) {
        self.init(systemImage: systemImage, title: title, message: message) {
            EmptyView()
        }
    }
}
