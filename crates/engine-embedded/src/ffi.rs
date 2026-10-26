//! C ABI for the iOS packet tunnel.
//!
//! Follows `docs/architecture/ios-embedded-runtime-ffi-boundary-design.md`:
//! every symbol is prefixed `networkcore_ios_`, catches panics, and returns a
//! stable error code. Input buffers stay owned by Swift and are only read
//! during the call. Output buffers and the runtime handle are owned by Rust and
//! released with `networkcore_ios_runtime_free_buffer` and
//! `networkcore_ios_runtime_free_handle`. The C header lives in
//! `include/networkcore_ios_runtime.h` and must match this file.

use std::ffi::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::Mutex;

use crate::{EmbeddedRuntime, RuntimeErrorCode};

pub const NETWORKCORE_IOS_ABI_VERSION: u32 = 1;
pub const NETWORKCORE_IOS_SCHEMA_VERSION: u32 = crate::config::CONFIG_SCHEMA_VERSION;
pub const NETWORKCORE_IOS_FEATURE_SET_VERSION: u32 = 1;

pub const NETWORKCORE_IOS_OK: i32 = 0;
pub const NETWORKCORE_IOS_ERR_ARTIFACT_MISSING: i32 = 1;
pub const NETWORKCORE_IOS_ERR_MISSING_SYMBOL: i32 = 2;
pub const NETWORKCORE_IOS_ERR_ABI_MISMATCH: i32 = 3;
pub const NETWORKCORE_IOS_ERR_SCHEMA_MISMATCH: i32 = 4;
pub const NETWORKCORE_IOS_ERR_INVALID_ARGUMENT: i32 = 5;
pub const NETWORKCORE_IOS_ERR_CONFIG_REJECTED: i32 = 6;
pub const NETWORKCORE_IOS_ERR_RESOURCE_EXHAUSTED: i32 = 7;
pub const NETWORKCORE_IOS_ERR_PANIC_CAUGHT: i32 = 8;
pub const NETWORKCORE_IOS_ERR_INTERNAL_ERROR: i32 = 9;
/// Returned by `networkcore_ios_runtime_input_packet` when the packet was dropped.
pub const NETWORKCORE_IOS_ERR_PACKET_DROPPED: i32 = 10;
/// Returned by `networkcore_ios_measure_delay` when the URL did not answer in time.
pub const NETWORKCORE_IOS_ERR_DELAY_TIMEOUT: i32 = 11;
/// Returned by `networkcore_ios_measure_delay` when the outbound, TLS or HTTP
/// exchange failed, or the answer was not HTTP.
pub const NETWORKCORE_IOS_ERR_DELAY_FAILED: i32 = 12;

/// Largest config envelope accepted across the boundary.
const MAX_CONFIG_LEN: usize = 64 * 1024;
/// Largest delay test URL accepted across the boundary.
#[cfg(feature = "local-proxy")]
const MAX_URL_LEN: usize = 2048;
/// Longest delay test timeout accepted across the boundary.
#[cfg(feature = "local-proxy")]
const MAX_DELAY_TIMEOUT_MS: u32 = 60_000;
/// Largest IP packet accepted from the TUN side.
const MAX_PACKET_LEN: usize = 65_535;

/// Rust-owned byte buffer handed to Swift.
#[repr(C)]
pub struct NetworkCoreBuffer {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl NetworkCoreBuffer {
    fn from_vec(bytes: Vec<u8>) -> Self {
        let mut bytes = std::mem::ManuallyDrop::new(bytes);
        Self {
            ptr: bytes.as_mut_ptr(),
            len: bytes.len(),
            cap: bytes.capacity(),
        }
    }
}

/// Writes one IP packet to the TUN interface. Called on the tunnel thread
/// until `networkcore_ios_runtime_stop_tunnel` returns. The packet pointer is
/// valid only for the duration of the call.
pub type NetworkCorePacketWriter =
    extern "C" fn(context: *mut c_void, packet: *const u8, len: usize);

/// Opaque runtime handle as seen from C. It points at a `RuntimeCell`.
#[repr(C)]
pub struct NetworkCoreRuntime {
    _private: [u8; 0],
}

struct RuntimeCell {
    inner: Mutex<EmbeddedRuntime>,
}

struct WriterContext(*mut c_void);

// SAFETY: the Swift side promises the context stays valid and thread-safe until
// stop_tunnel returns, which joins the only thread that uses it.
unsafe impl Send for WriterContext {}
unsafe impl Sync for WriterContext {}

impl WriterContext {
    fn get(&self) -> *mut c_void {
        self.0
    }
}

fn code_for(code: RuntimeErrorCode) -> i32 {
    match code {
        RuntimeErrorCode::InvalidArgument => NETWORKCORE_IOS_ERR_INVALID_ARGUMENT,
        RuntimeErrorCode::SchemaMismatch => NETWORKCORE_IOS_ERR_SCHEMA_MISMATCH,
        RuntimeErrorCode::ConfigRejected => NETWORKCORE_IOS_ERR_CONFIG_REJECTED,
        RuntimeErrorCode::ResourceExhausted => NETWORKCORE_IOS_ERR_RESOURCE_EXHAUSTED,
        RuntimeErrorCode::PanicCaught => NETWORKCORE_IOS_ERR_PANIC_CAUGHT,
        RuntimeErrorCode::InternalError => NETWORKCORE_IOS_ERR_INTERNAL_ERROR,
    }
}

fn guarded(body: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(NETWORKCORE_IOS_ERR_PANIC_CAUGHT)
}

fn with_runtime(
    handle: *mut NetworkCoreRuntime,
    body: impl FnOnce(&mut EmbeddedRuntime) -> i32,
) -> i32 {
    if handle.is_null() {
        return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT;
    }
    // SAFETY: non-null handles come from networkcore_ios_runtime_init and stay
    // valid until networkcore_ios_runtime_free_handle.
    let cell = unsafe { &*(handle as *const RuntimeCell) };
    match cell.inner.lock() {
        Ok(mut inner) => body(&mut inner),
        // A panic poisoned the lock: the runtime state is unknown.
        Err(_) => NETWORKCORE_IOS_ERR_PANIC_CAUGHT,
    }
}

#[no_mangle]
pub extern "C" fn networkcore_ios_abi_version() -> u32 {
    NETWORKCORE_IOS_ABI_VERSION
}

#[no_mangle]
pub extern "C" fn networkcore_ios_schema_version() -> u32 {
    NETWORKCORE_IOS_SCHEMA_VERSION
}

#[no_mangle]
pub extern "C" fn networkcore_ios_feature_set_version() -> u32 {
    NETWORKCORE_IOS_FEATURE_SET_VERSION
}

/// Validates the JSON config envelope and creates a runtime handle.
///
/// # Safety
///
/// `config` must point to `config_len` readable bytes, and `out_handle` must be
/// a valid pointer to writable storage for one handle pointer.
#[no_mangle]
pub unsafe extern "C" fn networkcore_ios_runtime_init(
    config: *const u8,
    config_len: usize,
    out_handle: *mut *mut NetworkCoreRuntime,
) -> i32 {
    guarded(|| {
        if out_handle.is_null() {
            return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: checked non-null above; the caller provides writable storage.
        unsafe { *out_handle = ptr::null_mut() };
        if config.is_null() || config_len == 0 || config_len > MAX_CONFIG_LEN {
            return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: the caller guarantees `config_len` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(config, config_len) };
        match EmbeddedRuntime::from_json(bytes) {
            Ok(runtime) => {
                let cell = Box::new(RuntimeCell {
                    inner: Mutex::new(runtime),
                });
                // SAFETY: as above.
                unsafe { *out_handle = Box::into_raw(cell) as *mut NetworkCoreRuntime };
                NETWORKCORE_IOS_OK
            }
            Err(err) => code_for(err.code),
        }
    })
}

/// Starts the tunnel. `writer` receives every outgoing IP packet.
///
/// # Safety
///
/// `handle` must come from `networkcore_ios_runtime_init`. `writer` and
/// `context` must stay valid until `networkcore_ios_runtime_stop_tunnel` or
/// `networkcore_ios_runtime_free_handle` returns, and `writer` must not call
/// back into this library.
#[no_mangle]
pub unsafe extern "C" fn networkcore_ios_runtime_start_tunnel(
    handle: *mut NetworkCoreRuntime,
    writer: Option<NetworkCorePacketWriter>,
    context: *mut c_void,
) -> i32 {
    guarded(|| {
        let Some(writer) = writer else {
            return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT;
        };
        with_runtime(handle, |runtime| {
            let context = WriterContext(context);
            let sink = Box::new(move |packet: &[u8]| {
                writer(context.get(), packet.as_ptr(), packet.len());
            });
            match runtime.start(sink) {
                Ok(()) => NETWORKCORE_IOS_OK,
                Err(err) => code_for(err.code),
            }
        })
    })
}

/// Queues one IP packet read from the TUN interface.
///
/// # Safety
///
/// `handle` must come from `networkcore_ios_runtime_init`, and `packet` must
/// point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn networkcore_ios_runtime_input_packet(
    handle: *mut NetworkCoreRuntime,
    packet: *const u8,
    len: usize,
) -> i32 {
    guarded(|| {
        if packet.is_null() || len == 0 || len > MAX_PACKET_LEN {
            return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: the caller guarantees `len` readable bytes.
        let packet = unsafe { std::slice::from_raw_parts(packet, len) };
        with_runtime(handle, |runtime| {
            if runtime.input_packet(packet) {
                NETWORKCORE_IOS_OK
            } else {
                NETWORKCORE_IOS_ERR_PACKET_DROPPED
            }
        })
    })
}

/// Stops the tunnel and joins its thread. Idempotent.
///
/// # Safety
///
/// `handle` must come from `networkcore_ios_runtime_init`.
#[no_mangle]
pub unsafe extern "C" fn networkcore_ios_runtime_stop_tunnel(
    handle: *mut NetworkCoreRuntime,
) -> i32 {
    guarded(|| {
        with_runtime(handle, |runtime| {
            runtime.stop();
            NETWORKCORE_IOS_OK
        })
    })
}

/// Writes a sanitized JSON status document into `out`.
///
/// # Safety
///
/// `handle` must come from `networkcore_ios_runtime_init`, and `out` must be a
/// valid pointer to writable storage for one `NetworkCoreBuffer`. The buffer
/// must be released with `networkcore_ios_runtime_free_buffer`.
#[no_mangle]
pub unsafe extern "C" fn networkcore_ios_runtime_collect_status(
    handle: *mut NetworkCoreRuntime,
    out: *mut NetworkCoreBuffer,
) -> i32 {
    guarded(|| {
        if out.is_null() {
            return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: checked non-null above.
        unsafe { out.write(NetworkCoreBuffer::from_vec(Vec::new())) };
        with_runtime(handle, |runtime| {
            match serde_json::to_vec(&runtime.status()) {
                Ok(bytes) => {
                    // SAFETY: checked non-null above; the empty placeholder owns no memory.
                    unsafe { out.write(NetworkCoreBuffer::from_vec(bytes)) };
                    NETWORKCORE_IOS_OK
                }
                Err(_) => NETWORKCORE_IOS_ERR_INTERNAL_ERROR,
            }
        })
    })
}

/// Measures an HTTP(S) `url` through the outbound of `config` (an engine
/// envelope with one `outbound`) and writes the time to the first line of the
/// response, in milliseconds, into `out_millis`. Blocks the calling thread for
/// at most `timeout_ms`; needs no runtime handle, so the containing app can
/// test nodes while the tunnel is down.
///
/// # Safety
///
/// `config` must point to `config_len` readable bytes, `url` to `url_len`
/// readable UTF-8 bytes, and `out_millis` must be a valid pointer to writable
/// storage for one `u32`.
#[cfg(feature = "local-proxy")]
#[no_mangle]
pub unsafe extern "C" fn networkcore_ios_measure_delay(
    config: *const u8,
    config_len: usize,
    url: *const u8,
    url_len: usize,
    timeout_ms: u32,
    out_millis: *mut u32,
) -> i32 {
    use crate::delay::{measure_delay, DelayError};

    guarded(|| {
        if out_millis.is_null() {
            return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: checked non-null above; the caller provides writable storage.
        unsafe { *out_millis = 0 };
        if config.is_null()
            || config_len == 0
            || config_len > MAX_CONFIG_LEN
            || url.is_null()
            || url_len == 0
            || url_len > MAX_URL_LEN
            || timeout_ms == 0
            || timeout_ms > MAX_DELAY_TIMEOUT_MS
        {
            return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: the caller guarantees `config_len` and `url_len` readable bytes.
        let config = unsafe { std::slice::from_raw_parts(config, config_len) };
        let url = unsafe { std::slice::from_raw_parts(url, url_len) };
        let Ok(url) = std::str::from_utf8(url) else {
            return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT;
        };
        let timeout = std::time::Duration::from_millis(u64::from(timeout_ms));
        match measure_delay(config, url, timeout) {
            Ok(delay) => {
                let millis = u32::try_from(delay.as_millis()).unwrap_or(u32::MAX).max(1);
                // SAFETY: as above.
                unsafe { *out_millis = millis };
                NETWORKCORE_IOS_OK
            }
            Err(DelayError::Config(err)) => code_for(err.code),
            Err(DelayError::InvalidUrl) => NETWORKCORE_IOS_ERR_INVALID_ARGUMENT,
            Err(DelayError::Timeout) => NETWORKCORE_IOS_ERR_DELAY_TIMEOUT,
            Err(DelayError::Failed(_) | DelayError::NotHttp) => NETWORKCORE_IOS_ERR_DELAY_FAILED,
        }
    })
}

/// Releases a buffer returned by this library. A null buffer is ignored.
///
/// # Safety
///
/// `buffer` must be exactly as returned by this library and released once.
#[no_mangle]
pub unsafe extern "C" fn networkcore_ios_runtime_free_buffer(buffer: NetworkCoreBuffer) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if buffer.ptr.is_null() || buffer.cap == 0 {
            return;
        }
        // SAFETY: the buffer was produced by NetworkCoreBuffer::from_vec.
        drop(unsafe { Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.cap) });
    }));
}

/// Stops the tunnel if needed and releases the handle. A null handle is ignored.
///
/// # Safety
///
/// `handle` must come from `networkcore_ios_runtime_init` and be released once.
#[no_mangle]
pub unsafe extern "C" fn networkcore_ios_runtime_free_handle(handle: *mut NetworkCoreRuntime) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return;
        }
        // SAFETY: the handle came from Box::into_raw in networkcore_ios_runtime_init.
        drop(unsafe { Box::from_raw(handle as *mut RuntimeCell) });
    }));
}
