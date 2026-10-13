import NetworkCoreBridge
import SwiftUI

// SwiftUI entry point for the containing app. The app target compiles NetworkCoreApp sources directly,
// so this file refers to AppCoordinator without importing the NetworkCoreApp module.
@main
struct NetworkCoreAppMain: App {
    private let coordinator = AppCoordinator(status: IosPlatformFactsProbe.currentStatus())

    var body: some Scene {
        WindowGroup {
            StatusView(decision: coordinator.decision)
        }
    }
}

struct StatusView: View {
    let decision: VpnConfigurationDecision

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("NetworkCore")
                .font(.title2)
            switch decision {
            case .startTunnel:
                Text("可以启动隧道")
            case let .blocked(reason, code):
                Text(reason)
                if let code = code {
                    Text(code)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding()
    }
}
