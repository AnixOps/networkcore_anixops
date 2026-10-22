import Foundation
import NetworkCoreBridge
import NetworkCoreRuntimeC
import NetworkExtension

/// One embedded Rust runtime inside the packet tunnel process.
///
/// Packets read from `packetFlow` go to the runtime; packets the runtime emits are written back on the
/// runtime's own thread. `stop()` joins that thread, so no packet is written after it returns.
final class EmbeddedRuntimeSession {
    /// Failure carrying only the C ABI code, never config content.
    struct Failure: Error {
        let code: Int32

        var fact: IosEmbeddedRuntimeFact {
            NetworkCoreRuntimeFFI.embeddedRuntimeFact(forFailureCode: code)
        }
    }

    static func reportedHandshake() -> NetworkCoreRuntimeFFI.Handshake {
        NetworkCoreRuntimeFFI.Handshake(
            abiVersion: networkcore_ios_abi_version(),
            dtoSchemaVersion: networkcore_ios_schema_version(),
            featureSetVersion: networkcore_ios_feature_set_version()
        )
    }

    private let packetFlow: NEPacketTunnelFlow
    private let lock = NSLock()
    private var handle: OpaquePointer?
    private var running = false
    private var writer: Unmanaged<PacketWriter>?

    init(config: Data, packetFlow: NEPacketTunnelFlow) throws {
        self.packetFlow = packetFlow
        var created: OpaquePointer?
        let code = config.withUnsafeBytes { raw -> Int32 in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else {
                return NetworkCoreRuntimeFFI.Code.invalidArgument
            }
            return networkcore_ios_runtime_init(base, raw.count, &created)
        }
        guard code == NetworkCoreRuntimeFFI.Code.ok, let created = created else {
            throw Failure(code: code)
        }
        handle = created
    }

    deinit {
        stop()
        if let handle = handle {
            networkcore_ios_runtime_free_handle(handle)
        }
    }

    func start() throws {
        lock.lock()
        defer { lock.unlock() }
        guard let handle = handle, !running else {
            throw Failure(code: NetworkCoreRuntimeFFI.Code.invalidArgument)
        }
        let writer = Unmanaged.passRetained(PacketWriter(packetFlow: packetFlow))
        let code = networkcore_ios_runtime_start_tunnel(handle, { context, packet, length in
            guard let context = context, let packet = packet, length > 0 else {
                return
            }
            Unmanaged<PacketWriter>.fromOpaque(context).takeUnretainedValue().write(packet, length)
        }, writer.toOpaque())
        guard code == NetworkCoreRuntimeFFI.Code.ok else {
            writer.release()
            throw Failure(code: code)
        }
        self.writer = writer
        running = true
        readPackets()
    }

    func stop() {
        lock.lock()
        defer { lock.unlock() }
        guard running, let handle = handle else {
            return
        }
        running = false
        _ = networkcore_ios_runtime_stop_tunnel(handle)
        writer?.release()
        writer = nil
    }

    /// Sanitized status JSON from the runtime, for the app's status view.
    func statusJSON() -> Data? {
        lock.lock()
        defer { lock.unlock() }
        guard let handle = handle else {
            return nil
        }
        var buffer = NetworkCoreBuffer(ptr: nil, len: 0, cap: 0)
        guard networkcore_ios_runtime_collect_status(handle, &buffer) == NetworkCoreRuntimeFFI.Code.ok else {
            return nil
        }
        defer { networkcore_ios_runtime_free_buffer(buffer) }
        guard let pointer = buffer.ptr, buffer.len > 0 else {
            return nil
        }
        return Data(bytes: pointer, count: buffer.len)
    }

    private func runningHandle() -> OpaquePointer? {
        lock.lock()
        defer { lock.unlock() }
        return running ? handle : nil
    }

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self = self, let handle = self.runningHandle() else {
                return
            }
            for packet in packets {
                packet.withUnsafeBytes { raw in
                    guard let base = raw.bindMemory(to: UInt8.self).baseAddress, raw.count > 0 else {
                        return
                    }
                    // A full queue drops the packet; TCP retransmits it.
                    _ = networkcore_ios_runtime_input_packet(handle, base, raw.count)
                }
            }
            self.readPackets()
        }
    }
}

/// Writer context handed to the runtime. Retained while the tunnel runs.
private final class PacketWriter {
    private let packetFlow: NEPacketTunnelFlow
    private let ipv4 = NSNumber(value: AF_INET)
    private let ipv6 = NSNumber(value: AF_INET6)

    init(packetFlow: NEPacketTunnelFlow) {
        self.packetFlow = packetFlow
    }

    func write(_ packet: UnsafePointer<UInt8>, _ length: Int) {
        let family = (packet.pointee >> 4) == 6 ? ipv6 : ipv4
        packetFlow.writePackets([Data(bytes: packet, count: length)], withProtocols: [family])
    }
}
