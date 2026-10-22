// Version handshake for the embedded Rust runtime.
//
// No C symbol, header, staticlib or XCFramework is linked here: only NetworkCorePacketTunnel links the
// runtime XCFramework, and it reports the handshake and C ABI codes through this type. The FFI boundary
// design fixes the ABI and schema versions. A reported runtime that disagrees with them maps to abi_mismatch,
// and initialization failure maps to initialization_failed. Neither case may fall back to an external
// process, daemon, CLI or unaudited helper.

public enum NetworkCoreRuntimeFFI {
    public static let abiVersion: UInt32 = 1
    public static let dtoSchemaVersion: UInt32 = 1
    public static let featureSetVersion: UInt32 = 1

    public struct Handshake: Sendable, Equatable {
        public let abiVersion: UInt32
        public let dtoSchemaVersion: UInt32
        public let featureSetVersion: UInt32

        public init(abiVersion: UInt32, dtoSchemaVersion: UInt32, featureSetVersion: UInt32) {
            self.abiVersion = abiVersion
            self.dtoSchemaVersion = dtoSchemaVersion
            self.featureSetVersion = featureSetVersion
        }

        public static let current = Handshake(
            abiVersion: NetworkCoreRuntimeFFI.abiVersion,
            dtoSchemaVersion: NetworkCoreRuntimeFFI.dtoSchemaVersion,
            featureSetVersion: NetworkCoreRuntimeFFI.featureSetVersion
        )
    }

    /// Maps the runtime handshake to the embedded runtime fact used by IosPlatformSnapshotDTO.
    public static func embeddedRuntimeFact(
        reported: Handshake?,
        expected: Handshake = .current,
        initializationSucceeded: Bool
    ) -> IosEmbeddedRuntimeFact {
        guard let reported = reported else {
            return .missing
        }
        guard reported == expected else {
            return .abiMismatch
        }
        return initializationSucceeded ? .available : .initializationFailed
    }

    /// C ABI result codes, mirrored from crates/engine-embedded/include/networkcore_ios_runtime.h.
    public enum Code {
        public static let ok: Int32 = 0
        public static let artifactMissing: Int32 = 1
        public static let missingSymbol: Int32 = 2
        public static let abiMismatch: Int32 = 3
        public static let schemaMismatch: Int32 = 4
        public static let invalidArgument: Int32 = 5
        public static let configRejected: Int32 = 6
        public static let resourceExhausted: Int32 = 7
        public static let panicCaught: Int32 = 8
        public static let internalError: Int32 = 9
        public static let packetDropped: Int32 = 10
    }

    /// Maps a failing init or start code to the embedded runtime fact, as the FFI boundary design's error table does.
    public static func embeddedRuntimeFact(forFailureCode code: Int32) -> IosEmbeddedRuntimeFact {
        switch code {
        case Code.ok:
            return .available
        case Code.artifactMissing:
            return .missing
        case Code.missingSymbol, Code.abiMismatch, Code.schemaMismatch:
            return .abiMismatch
        default:
            return .initializationFailed
        }
    }
}
