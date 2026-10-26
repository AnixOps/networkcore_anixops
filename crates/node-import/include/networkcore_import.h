/*
 * NetworkCore node import C ABI for the iOS containing app.
 *
 * Source of truth: crates/node-import/src/ffi.rs. Keep the two in sync and bump
 * NETWORKCORE_IMPORT_ABI_VERSION on any incompatible change.
 *
 * Ownership:
 *   - The input text belongs to the caller and is only read during the call.
 *   - NetworkCoreImportBuffer values are owned by the library; release each one once
 *     with networkcore_import_free_buffer, also after a failing call.
 */
#ifndef NETWORKCORE_IMPORT_H
#define NETWORKCORE_IMPORT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NETWORKCORE_IMPORT_ABI_VERSION 1u

#define NETWORKCORE_IMPORT_OK 0
#define NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT 1
#define NETWORKCORE_IMPORT_ERR_EMPTY 2
#define NETWORKCORE_IMPORT_ERR_TOO_LARGE 3
#define NETWORKCORE_IMPORT_ERR_UNRECOGNIZED 4
#define NETWORKCORE_IMPORT_ERR_PANIC_CAUGHT 5
#define NETWORKCORE_IMPORT_ERR_INTERNAL_ERROR 6
#define NETWORKCORE_IMPORT_ERR_UNSUPPORTED 7

typedef struct NetworkCoreImportBuffer {
    uint8_t *ptr;
    size_t len;
    size_t cap;
} NetworkCoreImportBuffer;

uint32_t networkcore_import_abi_version(void);
int32_t networkcore_import_nodes(const uint8_t *text, size_t text_len, NetworkCoreImportBuffer *out);
/* node: JSON {"name": ..., "outbound": {...}}; out: the share link as UTF-8 text. */
int32_t networkcore_import_share_link(const uint8_t *node, size_t node_len, NetworkCoreImportBuffer *out);
void networkcore_import_free_buffer(NetworkCoreImportBuffer buffer);

#ifdef __cplusplus
}
#endif

#endif /* NETWORKCORE_IMPORT_H */
