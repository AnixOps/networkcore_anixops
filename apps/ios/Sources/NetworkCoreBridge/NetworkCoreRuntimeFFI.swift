// Version handshake for the embedded Rust runtime.
//
// No C symbol, header, staticlib or XCFramework is linked here. The FFI boundary design fixes the ABI
// and schema versions first. A reported runtime that disagrees with them maps to abi_mismatch,
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
}
