import Foundation
import NetworkCoreBridge
import NetworkCoreImportC

/// Calls the Rust importer (crates/node-import) linked into the app. The packet tunnel engine is not linked here;
/// only the extension runs it.
enum NativeNodeImporterFFI {
    static func importNodes(_ text: String) throws -> Data {
        guard networkcore_import_abi_version() == NETWORKCORE_IMPORT_ABI_VERSION else {
            throw NativeImportFailure.unavailable
        }
        var out = NetworkCoreImportBuffer(ptr: nil, len: 0, cap: 0)
        let bytes = Array(text.utf8)
        let code = bytes.withUnsafeBufferPointer { buffer in
            networkcore_import_nodes(buffer.baseAddress, buffer.count, &out)
        }
        defer { networkcore_import_free_buffer(out) }
        switch code {
        case NETWORKCORE_IMPORT_OK:
            guard let pointer = out.ptr else {
                throw NativeImportFailure.unavailable
            }
            return Data(bytes: pointer, count: out.len)
        case NETWORKCORE_IMPORT_ERR_EMPTY:
            throw NativeImportFailure.empty
        case NETWORKCORE_IMPORT_ERR_TOO_LARGE:
            throw NativeImportFailure.tooLarge
        case NETWORKCORE_IMPORT_ERR_UNRECOGNIZED, NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT:
            throw NativeImportFailure.unrecognized
        default:
            throw NativeImportFailure.unavailable
        }
    }
}
