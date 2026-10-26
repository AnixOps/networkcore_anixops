//! C ABI for the iOS containing app: subscription text in, node list JSON
//! out. The app links this library alone; the packet tunnel engine stays in
//! the extension.
//!
//! Every symbol is prefixed `networkcore_import_`, catches panics and returns
//! a stable code. The input buffer stays owned by Swift and is only read
//! during the call; the output buffer is owned by Rust and released with
//! `networkcore_import_free_buffer`. The C header lives in
//! `include/networkcore_import.h` and must match this file.

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::{import_text, share_link, ImportError};

pub const NETWORKCORE_IMPORT_ABI_VERSION: u32 = 1;

pub const NETWORKCORE_IMPORT_OK: i32 = 0;
pub const NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT: i32 = 1;
pub const NETWORKCORE_IMPORT_ERR_EMPTY: i32 = 2;
pub const NETWORKCORE_IMPORT_ERR_TOO_LARGE: i32 = 3;
pub const NETWORKCORE_IMPORT_ERR_UNRECOGNIZED: i32 = 4;
pub const NETWORKCORE_IMPORT_ERR_PANIC_CAUGHT: i32 = 5;
pub const NETWORKCORE_IMPORT_ERR_INTERNAL_ERROR: i32 = 6;
/// The node's protocol has no share link format, or its entry lacks a field.
pub const NETWORKCORE_IMPORT_ERR_UNSUPPORTED: i32 = 7;

/// Largest node entry [`networkcore_import_share_link`] accepts.
pub const MAX_SHARE_LINK_INPUT_LEN: usize = 64 * 1024;

/// Rust-owned byte buffer handed to Swift.
#[repr(C)]
pub struct NetworkCoreImportBuffer {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl NetworkCoreImportBuffer {
    fn from_vec(bytes: Vec<u8>) -> Self {
        let mut bytes = std::mem::ManuallyDrop::new(bytes);
        Self {
            ptr: bytes.as_mut_ptr(),
            len: bytes.len(),
            cap: bytes.capacity(),
        }
    }
}

#[no_mangle]
pub extern "C" fn networkcore_import_abi_version() -> u32 {
    NETWORKCORE_IMPORT_ABI_VERSION
}

/// Parses `text` (UTF-8) and writes the report as JSON:
/// `{"nodes":[{"id","name","protocol","server","port","outbound"}],
///   "unsupported":[{"name","protocol","reason"}], "routing"?:{"rules","groups"}}`;
/// `routing` appears only when the subscription's rules can run (see
/// [`crate::ImportReport::routing`]).
///
/// # Safety
///
/// `text` must point to `text_len` readable bytes (it may be null when
/// `text_len` is 0), and `out` must be a valid pointer to writable storage for
/// one `NetworkCoreImportBuffer`. The buffer must be released with
/// `networkcore_import_free_buffer`, also on failure.
#[no_mangle]
pub unsafe extern "C" fn networkcore_import_nodes(
    text: *const u8,
    text_len: usize,
    out: *mut NetworkCoreImportBuffer,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() || (text.is_null() && text_len > 0) {
            return NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: checked non-null above.
        unsafe { out.write(NetworkCoreImportBuffer::from_vec(Vec::new())) };
        if text_len == 0 {
            return NETWORKCORE_IMPORT_ERR_EMPTY;
        }
        if text_len > crate::MAX_IMPORT_TEXT_LEN {
            return NETWORKCORE_IMPORT_ERR_TOO_LARGE;
        }
        // SAFETY: the caller guarantees `text_len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(text, text_len) };
        let Ok(text) = std::str::from_utf8(bytes) else {
            return NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT;
        };
        let report = match import_text(text) {
            Ok(report) => report,
            Err(ImportError::Empty) => return NETWORKCORE_IMPORT_ERR_EMPTY,
            Err(ImportError::TooLarge) => return NETWORKCORE_IMPORT_ERR_TOO_LARGE,
            Err(ImportError::Unrecognized) => return NETWORKCORE_IMPORT_ERR_UNRECOGNIZED,
        };
        match serde_json::to_vec(&report) {
            Ok(json) => {
                // SAFETY: checked non-null above; the empty placeholder owns no memory.
                unsafe { out.write(NetworkCoreImportBuffer::from_vec(json)) };
                NETWORKCORE_IMPORT_OK
            }
            Err(_) => NETWORKCORE_IMPORT_ERR_INTERNAL_ERROR,
        }
    }))
    .unwrap_or(NETWORKCORE_IMPORT_ERR_PANIC_CAUGHT)
}

/// Writes the share link of one node as UTF-8 text (see
/// [`crate::share_link`]). `node` is JSON `{"name": ..., "outbound": {...}}`
/// with an outbound entry as `networkcore_import_nodes` returns it.
///
/// # Safety
///
/// As for [`networkcore_import_nodes`], with `node`/`node_len` in place of
/// the text.
#[no_mangle]
pub unsafe extern "C" fn networkcore_import_share_link(
    node: *const u8,
    node_len: usize,
    out: *mut NetworkCoreImportBuffer,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if out.is_null() || (node.is_null() && node_len > 0) {
            return NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: checked non-null above.
        unsafe { out.write(NetworkCoreImportBuffer::from_vec(Vec::new())) };
        if node_len == 0 {
            return NETWORKCORE_IMPORT_ERR_EMPTY;
        }
        if node_len > MAX_SHARE_LINK_INPUT_LEN {
            return NETWORKCORE_IMPORT_ERR_TOO_LARGE;
        }
        // SAFETY: the caller guarantees `node_len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(node, node_len) };
        let Ok(entry) = serde_json::from_slice::<serde_json::Value>(bytes) else {
            return NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT;
        };
        if !entry["outbound"].is_object() {
            return NETWORKCORE_IMPORT_ERR_INVALID_ARGUMENT;
        }
        let name = entry["name"].as_str().unwrap_or_default();
        match share_link(name, &entry["outbound"]) {
            Ok(link) => {
                // SAFETY: checked non-null above; the empty placeholder owns no memory.
                unsafe { out.write(NetworkCoreImportBuffer::from_vec(link.into_bytes())) };
                NETWORKCORE_IMPORT_OK
            }
            Err(_) => NETWORKCORE_IMPORT_ERR_UNSUPPORTED,
        }
    }))
    .unwrap_or(NETWORKCORE_IMPORT_ERR_PANIC_CAUGHT)
}

/// Releases a buffer returned by this library. A null buffer is ignored.
///
/// # Safety
///
/// `buffer` must be exactly as returned by this library and released once.
#[no_mangle]
pub unsafe extern "C" fn networkcore_import_free_buffer(buffer: NetworkCoreImportBuffer) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if buffer.ptr.is_null() || buffer.cap == 0 {
            return;
        }
        // SAFETY: the buffer was produced by NetworkCoreImportBuffer::from_vec.
        drop(unsafe { Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.cap) });
    }));
}
