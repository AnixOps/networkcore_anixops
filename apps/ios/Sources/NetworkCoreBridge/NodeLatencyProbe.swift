import Foundation
import Network

/// Time to open a TCP connection to a node's server, the app's delay test. The app does not link the tunnel
/// engine, so it cannot run a node's protocol; the handshake to its port is the part of the delay it can measure.
/// QUIC nodes (`NodeLibrary.usesUDP`) are not measured this way.
public enum NodeLatencyProbe {
    public static func tcpConnect(host: String, port: UInt16, timeout: TimeInterval = 5) async -> TimeInterval? {
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
            return nil
        }
        let connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: .tcp)
        let once = ResumeOnce()
        let started = Date()
        return await withCheckedContinuation { continuation in
            let finish: (TimeInterval?) -> Void = { result in
                guard once.claim() else {
                    return
                }
                connection.cancel()
                continuation.resume(returning: result)
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    finish(Date().timeIntervalSince(started))
                case .failed, .cancelled:
                    finish(nil)
                case .waiting:
                    // No route or refused: the system would keep retrying until the timeout.
                    finish(nil)
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .utility))
            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + timeout) {
                finish(nil)
            }
        }
    }
}

/// Lets exactly one of several callbacks resume a continuation.
private final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false

    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if claimed {
            return false
        }
        claimed = true
        return true
    }
}
