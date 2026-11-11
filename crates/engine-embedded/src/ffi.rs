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

use crate::tunnel::{PacketWriter, MAX_WRITE_BATCH};
use crate::{EmbeddedRuntime, RuntimeErrorCode};

pub const NETWORKCORE_IOS_ABI_VERSION: u32 = 1;
pub const NETWORKCORE_IOS_SCHEMA_VERSION: u32 = crate::config::CONFIG_SCHEMA_VERSION;
/// 2 added `networkcore_ios_runtime_control`, 3 added
/// `networkcore_ios_mitm_inspect_plugin`, 4 added
/// `networkcore_ios_runtime_start_tunnel_batched` and
/// `networkcore_ios_runtime_input_packets`.
pub const NETWORKCORE_IOS_FEATURE_SET_VERSION: u32 = 4;

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

/// One IP packet borrowed for the duration of a call.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetworkCorePacket {
    pub ptr: *const u8,
    pub len: usize,
}

/// Writes a burst of IP packets to the TUN interface, in order (feature set
/// 4). Called on the tunnel thread until `networkcore_ios_runtime_stop_tunnel`
/// returns; `count` is 1 to 64. The packets are valid only for the call.
pub type NetworkCorePacketBatchWriter =
    extern "C" fn(context: *mut c_void, packets: *const NetworkCorePacket, count: usize);

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

/// Hands each burst of the tunnel's packets to a C batch writer at once.
struct BatchWriter {
    writer: NetworkCorePacketBatchWriter,
    context: WriterContext,
}

impl PacketWriter for BatchWriter {
    fn write(&self, packet: &[u8]) {
        let one = NetworkCorePacket {
            ptr: packet.as_ptr(),
            len: packet.len(),
        };
        (self.writer)(self.context.get(), &one, 1);
    }

    fn write_batch(&self, packets: &[Vec<u8>]) {
        for chunk in packets.chunks(MAX_WRITE_BATCH) {
            let mut views = [NetworkCorePacket {
                ptr: ptr::null(),
                len: 0,
            }; MAX_WRITE_BATCH];
            for (view, packet) in views.iter_mut().zip(chunk) {
                *view = NetworkCorePacket {
                    ptr: packet.as_ptr(),
                    len: packet.len(),
                };
            }
            (self.writer)(self.context.get(), views.as_ptr(), chunk.len());
        }
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

/// Starts the tunnel like `networkcore_ios_runtime_start_tunnel`, handing
/// the packets that are ready together to `writer` in one call (feature set
/// 4), so the host can write them with one `writePackets`.
///
/// # Safety
///
/// As for `networkcore_ios_runtime_start_tunnel`.
#[no_mangle]
pub unsafe extern "C" fn networkcore_ios_runtime_start_tunnel_batched(
    handle: *mut NetworkCoreRuntime,
    writer: Option<NetworkCorePacketBatchWriter>,
    context: *mut c_void,
) -> i32 {
    guarded(|| {
        let Some(writer) = writer else {
            return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT;
        };
        with_runtime(handle, |runtime| {
            let sink = BatchWriter {
                writer,
                context: WriterContext(context),
            };
            match runtime.start(sink) {
                Ok(()) => NETWORKCORE_IOS_OK,
                Err(err) => code_for(err.code),
            }
        })
    })
}

/// Queues the IP packets of one `readPackets` callback (feature set 4) and
/// writes how many were queued to `out_accepted`; the rest were dropped
/// because the queue was full or invalid. Takes the runtime lock once.
///
/// # Safety
///
/// `handle` must come from `networkcore_ios_runtime_init`, `packets` must
/// point to `count` packets that each point to `len` readable bytes, and
/// `out_accepted` must be null or writable.
#[no_mangle]
pub unsafe extern "C" fn networkcore_ios_runtime_input_packets(
    handle: *mut NetworkCoreRuntime,
    packets: *const NetworkCorePacket,
    count: usize,
    out_accepted: *mut usize,
) -> i32 {
    guarded(|| {
        if packets.is_null() || count == 0 {
            return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: the caller guarantees `count` packets.
        let packets = unsafe { std::slice::from_raw_parts(packets, count) };
        with_runtime(handle, |runtime| {
            let mut accepted = 0usize;
            for packet in packets {
                if packet.ptr.is_null() || packet.len == 0 || packet.len > MAX_PACKET_LEN {
                    continue;
                }
                // SAFETY: the caller guarantees `len` readable bytes.
                let bytes = unsafe { std::slice::from_raw_parts(packet.ptr, packet.len) };
                if runtime.input_packet(bytes) {
                    accepted += 1;
                }
            }
            if !out_accepted.is_null() {
                // SAFETY: checked non-null; the caller guarantees it is writable.
                unsafe { *out_accepted = accepted };
            }
            if accepted == count {
                NETWORKCORE_IOS_OK
            } else {
                NETWORKCORE_IOS_ERR_PACKET_DROPPED
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

/// Answers one JSON runtime control request (`{"cmd": ...}`, see
/// [`crate::control`]) with a JSON document in `out`: the connection list,
/// traffic counters, and closing connections. Works before the tunnel starts
/// and after it stops. A request that is too long, not JSON or not a known
/// command returns `NETWORKCORE_IOS_ERR_INVALID_ARGUMENT`.
///
/// # Safety
///
/// `handle` must come from `networkcore_ios_runtime_init`, `request` must
/// point to `request_len` readable bytes, and `out` must be a valid pointer to
/// writable storage for one `NetworkCoreBuffer`. The buffer must be released
/// with `networkcore_ios_runtime_free_buffer`.
#[no_mangle]
pub unsafe extern "C" fn networkcore_ios_runtime_control(
    handle: *mut NetworkCoreRuntime,
    request: *const u8,
    request_len: usize,
    out: *mut NetworkCoreBuffer,
) -> i32 {
    guarded(|| {
        if out.is_null() {
            return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: checked non-null above.
        unsafe { out.write(NetworkCoreBuffer::from_vec(Vec::new())) };
        if request.is_null() || request_len == 0 || request_len > crate::control::MAX_REQUEST_LEN {
            return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: the caller guarantees `request_len` readable bytes.
        let request = unsafe { std::slice::from_raw_parts(request, request_len) };
        with_runtime(handle, |runtime| match runtime.control_json(request) {
            Ok(bytes) => {
                // SAFETY: checked non-null above; the empty placeholder owns no memory.
                unsafe { out.write(NetworkCoreBuffer::from_vec(bytes)) };
                NETWORKCORE_IOS_OK
            }
            Err(err) => code_for(err.code),
        })
    })
}

/// Imports one Loon / Surge / Quantumult X plugin text and writes a JSON
/// description to `out` (see [`crate::mitm::inspect`]): name, support level,
/// hostnames, line counts and the remote files to download. Needs no runtime
/// handle. Text that is empty, too long or not UTF-8 returns
/// `NETWORKCORE_IOS_ERR_INVALID_ARGUMENT`.
///
/// # Safety
///
/// `text` must point to `text_len` readable bytes and `out` must be a valid
/// pointer to writable storage for one `NetworkCoreBuffer`. The buffer must be
/// released with `networkcore_ios_runtime_free_buffer`.
#[cfg(feature = "mitm")]
#[no_mangle]
pub unsafe extern "C" fn networkcore_ios_mitm_inspect_plugin(
    text: *const u8,
    text_len: usize,
    out: *mut NetworkCoreBuffer,
) -> i32 {
    guarded(|| {
        if out.is_null() {
            return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: checked non-null above.
        unsafe { out.write(NetworkCoreBuffer::from_vec(Vec::new())) };
        if text.is_null() || text_len == 0 || text_len > crate::mitm::inspect::MAX_PLUGIN_LEN {
            return NETWORKCORE_IOS_ERR_INVALID_ARGUMENT;
        }
        // SAFETY: the caller guarantees `text_len` readable bytes.
        let text = unsafe { std::slice::from_raw_parts(text, text_len) };
        match crate::mitm::inspect::inspect_plugin_json(text) {
            Some(bytes) => {
                // SAFETY: checked non-null above; the empty placeholder owns no memory.
                unsafe { out.write(NetworkCoreBuffer::from_vec(bytes)) };
                NETWORKCORE_IOS_OK
            }
            None => NETWORKCORE_IOS_ERR_INVALID_ARGUMENT,
        }
    })
}

/// Pins every socket the engine opens (to proxy servers, DNS upstreams and
/// direct destinations) to a network interface, by interface index, so it
/// leaves through that interface instead of the tunnel's default route.
///
/// On iOS a Network Extension's own sockets bypass its tunnel, but on macOS
/// (packet tunnel System Extension) they follow the routing table: with the
/// default route in the tunnel they would loop back into the engine. The
/// tunnel calls this with the physical interface before it starts the engine
/// and again whenever the network changes. `0` leaves that address family
/// unpinned; both `0` removes the pin. Process-wide (no runtime handle), like
/// [`crate::protect::set_socket_protector`]. Uses `IP_BOUND_IF` /
/// `IPV6_BOUND_IF`, so a non-zero index returns
/// `NETWORKCORE_IOS_ERR_INVALID_ARGUMENT` on other platforms.
#[no_mangle]
pub extern "C" fn networkcore_ios_set_bound_interface(ipv4_index: u32, ipv6_index: u32) -> i32 {
    guarded(|| bound_interface::set(ipv4_index, ipv6_index))
}

mod bound_interface {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    static IPV4: AtomicU32 = AtomicU32::new(0);
    static IPV6: AtomicU32 = AtomicU32::new(0);
    static INSTALLED: AtomicBool = AtomicBool::new(false);

    pub(super) fn set(ipv4_index: u32, ipv6_index: u32) -> i32 {
        if ipv4_index == 0 && ipv6_index == 0 {
            IPV4.store(0, Ordering::SeqCst);
            IPV6.store(0, Ordering::SeqCst);
            if INSTALLED.swap(false, Ordering::SeqCst) {
                crate::protect::set_socket_protector(None);
            }
            return super::NETWORKCORE_IOS_OK;
        }
        install(ipv4_index, ipv6_index)
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn install(ipv4_index: u32, ipv6_index: u32) -> i32 {
        use std::sync::Arc;
        IPV4.store(ipv4_index, Ordering::SeqCst);
        IPV6.store(ipv6_index, Ordering::SeqCst);
        if !INSTALLED.swap(true, Ordering::SeqCst) {
            crate::protect::set_socket_protector(Some(Arc::new(
                |socket: crate::protect::RawSocketHandle, target: std::net::SocketAddr| {
                    let index = if target.is_ipv4() {
                        IPV4.load(Ordering::SeqCst)
                    } else {
                        IPV6.load(Ordering::SeqCst)
                    };
                    bind(socket, index, target.is_ipv6())
                },
            )));
        }
        super::NETWORKCORE_IOS_OK
    }

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    fn install(_ipv4_index: u32, _ipv6_index: u32) -> i32 {
        super::NETWORKCORE_IOS_ERR_INVALID_ARGUMENT
    }

    /// `IP_BOUND_IF` / `IPV6_BOUND_IF` from `<netinet/in.h>` / `<netinet6/in6.h>`.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const IP_BOUND_IF: libc::c_int = 25;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    const IPV6_BOUND_IF: libc::c_int = 125;

    /// Binds `socket` to interface `index`; `0` leaves it to the routing table.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn bind(
        socket: crate::protect::RawSocketHandle,
        index: u32,
        ipv6: bool,
    ) -> std::io::Result<()> {
        if index == 0 {
            return Ok(());
        }
        let (level, name) = if ipv6 {
            (libc::IPPROTO_IPV6, IPV6_BOUND_IF)
        } else {
            (libc::IPPROTO_IP, IP_BOUND_IF)
        };
        let value: libc::c_uint = index;
        // SAFETY: `socket` is an open socket owned by the caller, and `value`
        // lives for the call with the length passed.
        let result = unsafe {
            libc::setsockopt(
                socket,
                level,
                name,
                (&value as *const libc::c_uint).cast(),
                std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
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
