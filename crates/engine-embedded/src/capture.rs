//! Capture (抓包): the bytes and HTTP messages of connections, for the
//! client's request detail and for export.
//!
//! Off by default. The client turns it on with the `set_capture` control
//! command; from then on every new connection the [`crate::connections`]
//! dispatcher opens keeps the first [`MAX_DIRECTION_BYTES`] of each
//! direction (the app's own payload, before any proxy protocol: plain text
//! for plain protocols, TLS records for HTTPS) and, for connections HTTPS
//! decryption (`mitm`) took over, the decrypted HTTP/1.1 requests and
//! responses with the first [`MAX_HTTP_BODY_BYTES`] of each body. All of it
//! stays in memory under one budget (`max_total_bytes`, default
//! [`DEFAULT_MAX_TOTAL_BYTES`], at most [`MAX_TOTAL_BYTES_LIMIT`]); past it
//! the oldest captured connections are dropped first, so the Network
//! Extension stays inside its memory limit.
//!
//! What is captured is returned only to an explicit `capture_connection` or
//! `export_capture` request and is never written to status, logs or errors.
//! Exports are `pcapng` (each connection as a synthetic TCP or UDP flow over
//! raw IP that Wireshark reads; a decrypted connection carries its HTTP text,
//! a domain destination gets an address from 198.18.0.0/15 named in a name
//! resolution block) and `har` (HAR 1.2 of the decrypted HTTP messages).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::Future;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::Serialize;
use serde_json::{json, Value};

use crate::connections::Network;

/// Capture budget when `set_capture` names none.
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 2 * 1024 * 1024;
/// Largest budget `set_capture` accepts.
pub const MAX_TOTAL_BYTES_LIMIT: usize = 16 * 1024 * 1024;
/// Smallest budget `set_capture` accepts.
pub const MIN_TOTAL_BYTES: usize = 64 * 1024;
/// Bytes kept per connection and direction.
pub const MAX_DIRECTION_BYTES: usize = 64 * 1024;
/// Datagrams (or TCP reads and writes that could not be merged) kept per
/// connection.
pub const MAX_CHUNKS: usize = 512;
/// Bytes kept of one HTTP request or response body.
pub const MAX_HTTP_BODY_BYTES: usize = 64 * 1024;
/// HTTP exchanges kept per connection.
pub const MAX_HTTP_EXCHANGES: usize = 64;
/// Connections kept at most, whatever their size.
pub const MAX_CAPTURED_CONNECTIONS: usize = 1024;
/// Bytes counted for one connection besides its data, so many empty
/// connections still use the budget.
const CONNECTION_OVERHEAD: usize = 256;
/// Bytes counted for one chunk besides its data.
const CHUNK_OVERHEAD: usize = 32;

/// Which way bytes went: from the app (`up`) or to it (`down`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Up,
    Down,
}

impl Direction {
    fn index(self) -> usize {
        match self {
            Self::Up => 0,
            Self::Down => 1,
        }
    }
}

struct Chunk {
    direction: Direction,
    at_ms: u64,
    data: Vec<u8>,
}

/// The first bytes of a body and how long it was.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapturedBody {
    pub data: Vec<u8>,
    /// Bytes the body had, captured or not.
    pub size: u64,
}

impl CapturedBody {
    /// The first [`MAX_HTTP_BODY_BYTES`] of `body`.
    pub fn of(body: &[u8]) -> Self {
        Self {
            data: body[..body.len().min(MAX_HTTP_BODY_BYTES)].to_vec(),
            size: body.len() as u64,
        }
    }

    fn truncated(&self) -> bool {
        self.size > self.data.len() as u64
    }

    fn json(&self) -> Value {
        json!({
            "size": self.size,
            "truncated": self.truncated(),
            "data_base64": base64_encode(&self.data),
        })
    }
}

/// One decrypted HTTP request and its response.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpExchange {
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub method: String,
    pub url: String,
    /// The request as the app sent it.
    pub request_headers: Vec<(String, String)>,
    pub request_body: CapturedBody,
    /// The response as the app got it; `None` when none came.
    pub status: Option<u16>,
    pub response_headers: Vec<(String, String)>,
    pub response_body: CapturedBody,
    /// `answered_locally` (a rewrite rule answered), `streaming` (an
    /// upgrade or event stream, body not kept) or `too_large` (relayed
    /// without decryption from there on).
    pub note: Option<&'static str>,
}

impl HttpExchange {
    pub fn new(method: &str, url: &str, headers: &[(String, String)]) -> Self {
        Self {
            started_at_ms: unix_millis(),
            method: method.to_string(),
            url: url.to_string(),
            request_headers: headers.to_vec(),
            ..Self::default()
        }
    }

    fn memory(&self) -> usize {
        let headers = |headers: &[(String, String)]| {
            headers
                .iter()
                .map(|(name, value)| name.len() + value.len() + 16)
                .sum::<usize>()
        };
        self.method.len()
            + self.url.len()
            + headers(&self.request_headers)
            + headers(&self.response_headers)
            + self.request_body.data.len()
            + self.response_body.data.len()
            + CHUNK_OVERHEAD
    }

    fn json(&self) -> Value {
        let headers = |headers: &[(String, String)]| {
            headers
                .iter()
                .map(|(name, value)| json!([name, value]))
                .collect::<Vec<_>>()
        };
        json!({
            "started_at_ms": self.started_at_ms,
            "ended_at_ms": self.ended_at_ms,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "note": self.note,
            "request": {
                "headers": headers(&self.request_headers),
                "body": self.request_body.json(),
            },
            "response": {
                "headers": headers(&self.response_headers),
                "body": self.response_body.json(),
            },
        })
    }
}

struct Captured {
    network: Network,
    host: Option<String>,
    destination: String,
    started_at_ms: u64,
    ended_at_ms: Option<u64>,
    /// HTTPS decryption took the connection over: its raw bytes are the
    /// re-encrypted upstream, so only its HTTP messages are kept.
    decrypted: bool,
    chunks: Vec<Chunk>,
    /// Bytes kept, by direction.
    kept: [usize; 2],
    /// Bytes seen while capturing, by direction.
    seen: [u64; 2],
    http: Vec<HttpExchange>,
    /// What this connection counts against the budget.
    memory: usize,
}

impl Captured {
    fn json(&self, id: u64) -> Value {
        let direction = |index: usize| {
            json!({
                "seen": self.seen[index],
                "captured": self.kept[index],
                "truncated": self.seen[index] > self.kept[index] as u64,
            })
        };
        json!({
            "id": id,
            "network": self.network,
            "host": self.host,
            "destination": self.destination,
            "started_at_ms": self.started_at_ms,
            "ended_at_ms": self.ended_at_ms,
            "decrypted": self.decrypted,
            "upload": direction(0),
            "download": direction(1),
            "chunks": self
                .chunks
                .iter()
                .map(|chunk| json!({
                    "dir": chunk.direction,
                    "at_ms": chunk.at_ms,
                    "data_base64": base64_encode(&chunk.data),
                }))
                .collect::<Vec<_>>(),
            "http": self.http.iter().map(HttpExchange::json).collect::<Vec<_>>(),
        })
    }
}

#[derive(Default)]
struct Inner {
    connections: BTreeMap<u64, Captured>,
    used: usize,
}

impl Inner {
    /// Drops the oldest connections other than `keep` until the budget
    /// holds; `false` when `keep` alone is over it.
    fn make_room(&mut self, keep: u64, budget: usize) -> bool {
        while self.used > budget || self.connections.len() > MAX_CAPTURED_CONNECTIONS {
            let oldest = self.connections.keys().copied().find(|&id| id != keep);
            let Some(oldest) = oldest else {
                return false;
            };
            if let Some(dropped) = self.connections.remove(&oldest) {
                self.used = self.used.saturating_sub(dropped.memory);
            }
        }
        true
    }
}

/// The capture switch, its budget and what it kept.
pub struct CaptureStore {
    enabled: AtomicBool,
    max_total_bytes: AtomicUsize,
    inner: Mutex<Inner>,
}

impl Default for CaptureStore {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            max_total_bytes: AtomicUsize::new(DEFAULT_MAX_TOTAL_BYTES),
            inner: Mutex::default(),
        }
    }
}

/// The `capture`, `set_capture` and `clear_capture` answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureStatus {
    pub enabled: bool,
    pub max_total_bytes: usize,
    pub used_bytes: usize,
    pub connections: usize,
}

impl CaptureStore {
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Turns capture on or off for later connections and data. `max_total_bytes`
    /// is clamped to [`MIN_TOTAL_BYTES`]..=[`MAX_TOTAL_BYTES_LIMIT`]; a smaller
    /// budget drops the oldest connections at once.
    pub fn set(&self, enabled: bool, max_total_bytes: Option<usize>) {
        if let Some(budget) = max_total_bytes {
            let budget = budget.clamp(MIN_TOTAL_BYTES, MAX_TOTAL_BYTES_LIMIT);
            self.max_total_bytes.store(budget, Ordering::Relaxed);
            lock(&self.inner).make_room(u64::MAX, budget);
        }
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Forgets everything captured; the switch stays as it is.
    pub fn clear(&self) {
        let mut inner = lock(&self.inner);
        inner.connections.clear();
        inner.used = 0;
    }

    pub fn status(&self) -> CaptureStatus {
        let inner = lock(&self.inner);
        CaptureStatus {
            enabled: self.enabled(),
            max_total_bytes: self.max_total_bytes.load(Ordering::Relaxed),
            used_bytes: inner.used,
            connections: inner.connections.len(),
        }
    }

    /// Starts capturing a new connection when capture is on; `true` when it
    /// does.
    pub(crate) fn begin(
        &self,
        id: u64,
        network: Network,
        host: Option<&str>,
        destination: &str,
        started_at_ms: u64,
    ) -> bool {
        if !self.enabled() {
            return false;
        }
        let memory = CONNECTION_OVERHEAD + destination.len() + host.map_or(0, str::len);
        let budget = self.max_total_bytes.load(Ordering::Relaxed);
        let mut inner = lock(&self.inner);
        inner.connections.insert(
            id,
            Captured {
                network,
                host: host.map(str::to_string),
                destination: destination.to_string(),
                started_at_ms,
                ended_at_ms: None,
                decrypted: false,
                chunks: Vec::new(),
                kept: [0, 0],
                seen: [0, 0],
                http: Vec::new(),
                memory,
            },
        );
        inner.used += memory;
        inner.make_room(id, budget)
    }

    /// Keeps the bytes of one read, write or datagram of connection `id`.
    pub(crate) fn record(&self, id: u64, direction: Direction, data: &[u8]) {
        if data.is_empty() || !self.enabled() {
            return;
        }
        let budget = self.max_total_bytes.load(Ordering::Relaxed);
        let mut inner = lock(&self.inner);
        let Some(captured) = inner.connections.get_mut(&id) else {
            return;
        };
        let index = direction.index();
        captured.seen[index] = captured.seen[index].saturating_add(data.len() as u64);
        if captured.decrypted {
            return;
        }
        let room = MAX_DIRECTION_BYTES - captured.kept[index];
        let take = data.len().min(room);
        if take == 0 {
            return;
        }
        let data = &data[..take];
        let now = unix_millis();
        // A TCP stream is one byte stream per direction: consecutive pieces
        // the same way join one chunk. Datagrams stay apart.
        let merge = captured.network == Network::Tcp
            && captured
                .chunks
                .last()
                .is_some_and(|last| last.direction == direction);
        let added = if merge {
            if let Some(last) = captured.chunks.last_mut() {
                last.data.extend_from_slice(data);
            }
            take
        } else {
            if captured.chunks.len() >= MAX_CHUNKS {
                return;
            }
            captured.chunks.push(Chunk {
                direction,
                at_ms: now,
                data: data.to_vec(),
            });
            take + CHUNK_OVERHEAD
        };
        captured.kept[index] += take;
        captured.memory += added;
        inner.used += added;
        if !inner.make_room(id, budget) {
            // This connection alone is over the budget: drop it.
            if let Some(dropped) = inner.connections.remove(&id) {
                inner.used = inner.used.saturating_sub(dropped.memory);
            }
        }
    }

    /// Marks connection `id` as taken over by HTTPS decryption: its raw
    /// bytes are dropped and only its HTTP messages are kept.
    pub(crate) fn mark_decrypted(&self, id: u64) {
        let mut inner = lock(&self.inner);
        let Some(captured) = inner.connections.get_mut(&id) else {
            return;
        };
        captured.decrypted = true;
        let freed: usize = captured
            .chunks
            .drain(..)
            .map(|chunk| chunk.data.len() + CHUNK_OVERHEAD)
            .sum();
        captured.kept = [0, 0];
        captured.memory = captured.memory.saturating_sub(freed);
        inner.used = inner.used.saturating_sub(freed);
    }

    /// Adds one decrypted HTTP exchange to connection `id`.
    #[cfg_attr(not(feature = "mitm"), allow(dead_code))]
    pub(crate) fn add_exchange(&self, id: u64, mut exchange: HttpExchange) {
        if !self.enabled() {
            return;
        }
        if exchange.ended_at_ms.is_none() {
            exchange.ended_at_ms = Some(unix_millis());
        }
        let budget = self.max_total_bytes.load(Ordering::Relaxed);
        let memory = exchange.memory();
        let mut inner = lock(&self.inner);
        let Some(captured) = inner.connections.get_mut(&id) else {
            return;
        };
        if captured.http.len() >= MAX_HTTP_EXCHANGES {
            return;
        }
        captured.http.push(exchange);
        captured.memory += memory;
        inner.used += memory;
        if !inner.make_room(id, budget) {
            if let Some(dropped) = inner.connections.remove(&id) {
                inner.used = inner.used.saturating_sub(dropped.memory);
            }
        }
    }

    /// Notes that connection `id` closed.
    pub(crate) fn end(&self, id: u64, ended_at_ms: u64) {
        if let Some(captured) = lock(&self.inner).connections.get_mut(&id) {
            captured.ended_at_ms = Some(ended_at_ms);
        }
    }

    /// What was kept of connection `id`, as the `capture_connection` answer
    /// shows it; `None` when nothing was (capture was off, or the
    /// connection was dropped for newer ones).
    pub fn connection_json(&self, id: u64) -> Option<Value> {
        lock(&self.inner)
            .connections
            .get(&id)
            .map(|captured| captured.json(id))
    }

    /// The captured connections (all, or only `id`) as a pcapng file.
    pub fn export_pcapng(&self, id: Option<u64>) -> Vec<u8> {
        let inner = lock(&self.inner);
        let mut file = pcapng::File::new();
        let mut names = Vec::new();
        for (&connection, captured) in selected(&inner, id) {
            let flow = pcapng::Flow::new(connection, captured);
            if let Some(host) = &captured.host {
                if host.parse::<IpAddr>().is_err() {
                    names.push((flow.server.ip(), host.clone()));
                }
            }
            flow.write(&mut file, captured);
        }
        file.finish(&names)
    }

    /// The decrypted HTTP messages (all, or only connection `id`'s) as HAR
    /// 1.2 JSON.
    pub fn export_har(&self, id: Option<u64>) -> Vec<u8> {
        let inner = lock(&self.inner);
        let mut entries = Vec::new();
        for (&connection, captured) in selected(&inner, id) {
            for exchange in &captured.http {
                entries.push(har::entry(connection, captured, exchange));
            }
        }
        let har = json!({
            "log": {
                "version": "1.2",
                "creator": { "name": "AnixOps Net", "version": env!("CARGO_PKG_VERSION") },
                "entries": entries,
            }
        });
        serde_json::to_vec_pretty(&har).unwrap_or_default()
    }
}

fn selected(inner: &Inner, id: Option<u64>) -> Vec<(&u64, &Captured)> {
    match id {
        Some(id) => inner.connections.get_key_value(&id).into_iter().collect(),
        None => inner.connections.iter().collect(),
    }
}

/// The export formats of `export_capture`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    Pcapng,
    Har,
}

impl ExportFormat {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Pcapng => "application/vnd.tcpdump.pcap",
            Self::Har => "application/json",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Pcapng => "pcapng",
            Self::Har => "har",
        }
    }
}

/// The `export_capture` answer, written straight into one buffer so the
/// file is not copied again on its way out:
/// `{"format", "file_name", "content_type", "size", "data_base64"}`.
pub fn export_answer(store: &CaptureStore, format: ExportFormat, id: Option<u64>) -> Vec<u8> {
    let file = match format {
        ExportFormat::Pcapng => store.export_pcapng(id),
        ExportFormat::Har => store.export_har(id),
    };
    let stem = match id {
        Some(id) => format!("anixops-capture-{id}"),
        None => format!("anixops-capture-{}", unix_millis() / 1000),
    };
    let head = json!({
        "format": format,
        "file_name": format!("{stem}.{}", format.extension()),
        "content_type": format.content_type(),
        "size": file.len(),
    })
    .to_string();
    // `head` is a JSON object: reopen it to append the data field.
    let mut answer = String::with_capacity(head.len() + file.len() * 4 / 3 + 32);
    answer.push_str(&head[..head.len() - 1]);
    answer.push_str(",\"data_base64\":\"");
    base64::engine::general_purpose::STANDARD.encode_string(&file, &mut answer);
    drop(file);
    answer.push_str("\"}");
    answer.into_bytes()
}

tokio::task_local! {
    /// The connection a decrypted flow opened to the origin, so the HTTPS
    /// decryption running in the same task can file its HTTP messages
    /// under it.
    static FLOW: RefCell<Option<(Arc<CaptureStore>, u64)>>;
}

/// Runs `future` (one decrypted flow) with a slot for the connection it
/// opens; see [`current_flow`].
#[cfg_attr(not(feature = "mitm"), allow(dead_code))]
pub(crate) async fn scope<F: Future>(future: F) -> F::Output {
    FLOW.scope(RefCell::new(None), future).await
}

/// Called by the dispatcher for each connection it opens with capture on:
/// the first one inside a [`scope`] is the flow's.
pub(crate) fn note_flow(store: &Arc<CaptureStore>, id: u64) {
    let _ = FLOW.try_with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some((store.clone(), id));
        }
    });
}

/// The capture store and connection of the current decrypted flow, when
/// capture was on as it opened. Its raw bytes stop being kept.
#[cfg_attr(not(feature = "mitm"), allow(dead_code))]
pub(crate) fn current_flow() -> Option<(Arc<CaptureStore>, u64)> {
    let flow = FLOW.try_with(|slot| slot.borrow().clone()).ok().flatten()?;
    flow.0.mark_decrypted(flow.1);
    Some(flow)
}

fn base64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub(crate) fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The port of `destination` (`host:port`, `[v6]:port`), or 0.
fn destination_port(destination: &str) -> u16 {
    destination
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse().ok())
        .unwrap_or(0)
}

/// The HTTP/1.1 text of decrypted exchanges, as the pcapng export carries
/// a decrypted connection: requests up, responses down.
fn http_text(exchange: &HttpExchange) -> (Vec<u8>, Vec<u8>) {
    let path = exchange
        .url
        .find("://")
        .and_then(|scheme| {
            let rest = &exchange.url[scheme + 3..];
            rest.find('/').map(|slash| &rest[slash..])
        })
        .unwrap_or("/");
    let mut up = format!("{} {} HTTP/1.1\r\n", exchange.method, path).into_bytes();
    for (name, value) in &exchange.request_headers {
        up.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    up.extend_from_slice(b"\r\n");
    up.extend_from_slice(&exchange.request_body.data);
    let mut down = Vec::new();
    if let Some(status) = exchange.status {
        down.extend_from_slice(
            format!("HTTP/1.1 {status} {}\r\n", har::status_text(status)).as_bytes(),
        );
        for (name, value) in &exchange.response_headers {
            down.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        down.extend_from_slice(b"\r\n");
        down.extend_from_slice(&exchange.response_body.data);
    }
    (up, down)
}

mod pcapng {
    //! A minimal pcapng writer: one raw-IP interface, synthetic IPv4/IPv6
    //! TCP and UDP packets, and a name resolution block.

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{destination_port, http_text, Captured, Direction, Network};

    /// `LINKTYPE_RAW`: packets start with the IP header.
    const LINKTYPE_RAW: u16 = 101;
    /// Largest TCP or UDP payload per synthetic packet.
    const SEGMENT: usize = 16 * 1024;
    const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(10, 7, 0, 1);
    const CLIENT_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const TCP_FIN: u8 = 0x01;
    const TCP_SYN: u8 = 0x02;
    const TCP_PSH: u8 = 0x08;
    const TCP_ACK: u8 = 0x10;

    pub(super) struct File {
        packets: Vec<u8>,
    }

    impl File {
        pub(super) fn new() -> Self {
            Self {
                packets: Vec::new(),
            }
        }

        /// One enhanced packet block, with an optional comment.
        fn packet(&mut self, at_ms: u64, packet: &[u8], comment: Option<&str>) {
            let micros = at_ms.saturating_mul(1000);
            let mut options = Vec::new();
            if let Some(comment) = comment {
                option(&mut options, 1, comment.as_bytes());
                option(&mut options, 0, &[]);
            }
            let mut body = Vec::with_capacity(20 + packet.len() + 3 + options.len());
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&((micros >> 32) as u32).to_le_bytes());
            body.extend_from_slice(&(micros as u32).to_le_bytes());
            body.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            body.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            body.extend_from_slice(packet);
            pad(&mut body);
            body.extend_from_slice(&options);
            block(&mut self.packets, 6, &body);
        }

        /// The whole file: section header, interface, names, packets.
        pub(super) fn finish(self, names: &[(IpAddr, String)]) -> Vec<u8> {
            let mut out = Vec::with_capacity(self.packets.len() + 256);
            let mut section = Vec::new();
            section.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
            section.extend_from_slice(&1u16.to_le_bytes());
            section.extend_from_slice(&0u16.to_le_bytes());
            section.extend_from_slice(&(-1i64).to_le_bytes());
            let mut options = Vec::new();
            option(&mut options, 4, b"AnixOps Net");
            option(&mut options, 0, &[]);
            section.extend_from_slice(&options);
            block(&mut out, 0x0A0D_0D0A, &section);

            let mut interface = Vec::new();
            interface.extend_from_slice(&LINKTYPE_RAW.to_le_bytes());
            interface.extend_from_slice(&0u16.to_le_bytes());
            interface.extend_from_slice(&0u32.to_le_bytes());
            let mut options = Vec::new();
            option(&mut options, 2, b"anixops-tunnel");
            option(&mut options, 0, &[]);
            interface.extend_from_slice(&options);
            block(&mut out, 1, &interface);

            if !names.is_empty() {
                let mut records = Vec::new();
                for (address, name) in names {
                    let mut value = match address {
                        IpAddr::V4(v4) => v4.octets().to_vec(),
                        IpAddr::V6(v6) => v6.octets().to_vec(),
                    };
                    value.extend_from_slice(name.as_bytes());
                    value.push(0);
                    let kind = if address.is_ipv4() { 1 } else { 2 };
                    option(&mut records, kind, &value);
                }
                option(&mut records, 0, &[]);
                block(&mut out, 4, &records);
            }
            out.extend_from_slice(&self.packets);
            out
        }
    }

    /// A block: type, total length, body, total length.
    fn block(out: &mut Vec<u8>, kind: u32, body: &[u8]) {
        let total = (12 + body.len()) as u32;
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(&total.to_le_bytes());
    }

    /// An option (or name record): code, length, value padded to 32 bits.
    fn option(out: &mut Vec<u8>, code: u16, value: &[u8]) {
        out.extend_from_slice(&code.to_le_bytes());
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(value);
        pad(out);
    }

    fn pad(out: &mut Vec<u8>) {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }

    /// One connection as a synthetic flow between a fixed client address
    /// and its server.
    pub(super) struct Flow {
        id: u64,
        network: Network,
        client: SocketAddr,
        pub(super) server: SocketAddr,
        client_seq: u32,
        server_seq: u32,
    }

    impl Flow {
        pub(super) fn new(id: u64, captured: &Captured) -> Self {
            let port = destination_port(&captured.destination);
            let server = captured
                .destination
                .parse::<SocketAddr>()
                .unwrap_or_else(|_| {
                    // 198.18.0.0/15, one address per connection.
                    let low = (id & 0x1_ffff) as u32;
                    let address = Ipv4Addr::from(0xC612_0000 | low);
                    SocketAddr::new(IpAddr::V4(address), port)
                });
            let client_ip = if server.is_ipv4() {
                IpAddr::V4(CLIENT_V4)
            } else {
                IpAddr::V6(CLIENT_V6)
            };
            let client_port = 10_000 + (id % 50_000) as u16;
            Self {
                id,
                network: captured.network,
                client: SocketAddr::new(client_ip, client_port),
                server,
                client_seq: 1_000,
                server_seq: 50_000,
            }
        }

        pub(super) fn write(mut self, file: &mut File, captured: &Captured) {
            let comment = format!(
                "anixops connection {}: {}{}",
                self.id,
                captured
                    .host
                    .as_deref()
                    .map(|host| format!("{host} "))
                    .unwrap_or_default(),
                captured.destination,
            );
            let pieces: Vec<(Direction, u64, Vec<u8>)> = if captured.decrypted {
                captured
                    .http
                    .iter()
                    .flat_map(|exchange| {
                        let (up, down) = http_text(exchange);
                        let ended = exchange.ended_at_ms.unwrap_or(exchange.started_at_ms);
                        [
                            (Direction::Up, exchange.started_at_ms, up),
                            (Direction::Down, ended, down),
                        ]
                    })
                    .filter(|(_, _, data)| !data.is_empty())
                    .collect()
            } else {
                captured
                    .chunks
                    .iter()
                    .map(|chunk| (chunk.direction, chunk.at_ms, chunk.data.clone()))
                    .collect()
            };
            match self.network {
                Network::Tcp => {
                    let start = captured.started_at_ms;
                    self.tcp(file, start, TCP_SYN, Direction::Up, &[], Some(&comment));
                    self.tcp(file, start, TCP_SYN | TCP_ACK, Direction::Down, &[], None);
                    self.tcp(file, start, TCP_ACK, Direction::Up, &[], None);
                    for (direction, at_ms, data) in pieces {
                        for segment in data.chunks(SEGMENT) {
                            self.tcp(file, at_ms, TCP_PSH | TCP_ACK, direction, segment, None);
                        }
                    }
                    if let Some(end) = captured.ended_at_ms {
                        self.tcp(file, end, TCP_FIN | TCP_ACK, Direction::Up, &[], None);
                        self.tcp(file, end, TCP_FIN | TCP_ACK, Direction::Down, &[], None);
                        self.tcp(file, end, TCP_ACK, Direction::Up, &[], None);
                    }
                }
                Network::Udp => {
                    let mut first = Some(comment.as_str());
                    for (direction, at_ms, data) in pieces {
                        for datagram in data.chunks(SEGMENT) {
                            let packet =
                                self.ip(direction, 17, &udp(self.ends(direction), datagram));
                            file.packet(at_ms, &packet, first.take());
                        }
                    }
                }
            }
        }

        fn ends(&self, direction: Direction) -> (SocketAddr, SocketAddr) {
            match direction {
                Direction::Up => (self.client, self.server),
                Direction::Down => (self.server, self.client),
            }
        }

        fn tcp(
            &mut self,
            file: &mut File,
            at_ms: u64,
            flags: u8,
            direction: Direction,
            payload: &[u8],
            comment: Option<&str>,
        ) {
            let (seq, ack) = match direction {
                Direction::Up => (self.client_seq, self.server_seq),
                Direction::Down => (self.server_seq, self.client_seq),
            };
            let ack = if flags & TCP_ACK != 0 { ack } else { 0 };
            let (source, destination) = self.ends(direction);
            let mut segment = Vec::with_capacity(20 + payload.len());
            segment.extend_from_slice(&source.port().to_be_bytes());
            segment.extend_from_slice(&destination.port().to_be_bytes());
            segment.extend_from_slice(&seq.to_be_bytes());
            segment.extend_from_slice(&ack.to_be_bytes());
            segment.push(5 << 4);
            segment.push(flags);
            segment.extend_from_slice(&65_535u16.to_be_bytes());
            segment.extend_from_slice(&[0, 0, 0, 0]);
            segment.extend_from_slice(payload);
            let checksum = transport_checksum(source.ip(), destination.ip(), 6, &segment);
            segment[16..18].copy_from_slice(&checksum.to_be_bytes());
            let advance = payload.len() as u32 + u32::from(flags & (TCP_SYN | TCP_FIN) != 0);
            match direction {
                Direction::Up => self.client_seq = self.client_seq.wrapping_add(advance),
                Direction::Down => self.server_seq = self.server_seq.wrapping_add(advance),
            }
            let packet = self.ip(direction, 6, &segment);
            file.packet(at_ms, &packet, comment);
        }

        fn ip(&self, direction: Direction, protocol: u8, payload: &[u8]) -> Vec<u8> {
            let (source, destination) = self.ends(direction);
            match (source.ip(), destination.ip()) {
                (IpAddr::V4(source), IpAddr::V4(destination)) => {
                    let total = (20 + payload.len()) as u16;
                    let mut header = Vec::with_capacity(20 + payload.len());
                    header.extend_from_slice(&[0x45, 0]);
                    header.extend_from_slice(&total.to_be_bytes());
                    header.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
                    header.extend_from_slice(&source.octets());
                    header.extend_from_slice(&destination.octets());
                    let checksum = fold(sum(&header, 0));
                    header[10..12].copy_from_slice(&checksum.to_be_bytes());
                    header.extend_from_slice(payload);
                    header
                }
                (source, destination) => {
                    let mut header = Vec::with_capacity(40 + payload.len());
                    header.extend_from_slice(&[0x60, 0, 0, 0]);
                    header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                    header.push(protocol);
                    header.push(64);
                    header.extend_from_slice(&v6(source).octets());
                    header.extend_from_slice(&v6(destination).octets());
                    header.extend_from_slice(payload);
                    header
                }
            }
        }
    }

    fn v6(address: IpAddr) -> Ipv6Addr {
        match address {
            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
            IpAddr::V6(v6) => v6,
        }
    }

    fn udp((source, destination): (SocketAddr, SocketAddr), payload: &[u8]) -> Vec<u8> {
        let length = (8 + payload.len()) as u16;
        let mut datagram = Vec::with_capacity(8 + payload.len());
        datagram.extend_from_slice(&source.port().to_be_bytes());
        datagram.extend_from_slice(&destination.port().to_be_bytes());
        datagram.extend_from_slice(&length.to_be_bytes());
        datagram.extend_from_slice(&[0, 0]);
        datagram.extend_from_slice(payload);
        let checksum = match transport_checksum(source.ip(), destination.ip(), 17, &datagram) {
            0 => 0xffff,
            value => value,
        };
        datagram[6..8].copy_from_slice(&checksum.to_be_bytes());
        datagram
    }

    /// The TCP/UDP checksum over the pseudo header and `segment`.
    fn transport_checksum(
        source: IpAddr,
        destination: IpAddr,
        protocol: u8,
        segment: &[u8],
    ) -> u16 {
        let mut pseudo = Vec::with_capacity(40);
        match (source, destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                pseudo.extend_from_slice(&source.octets());
                pseudo.extend_from_slice(&destination.octets());
                pseudo.extend_from_slice(&[0, protocol]);
                pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
            }
            (source, destination) => {
                pseudo.extend_from_slice(&v6(source).octets());
                pseudo.extend_from_slice(&v6(destination).octets());
                pseudo.extend_from_slice(&(segment.len() as u32).to_be_bytes());
                pseudo.extend_from_slice(&[0, 0, 0, protocol]);
            }
        }
        fold(sum(segment, sum(&pseudo, 0)))
    }

    fn sum(bytes: &[u8], mut acc: u32) -> u32 {
        let mut pairs = bytes.chunks_exact(2);
        for pair in &mut pairs {
            acc = acc.wrapping_add(u32::from(u16::from_be_bytes([pair[0], pair[1]])));
        }
        if let [last] = pairs.remainder() {
            acc = acc.wrapping_add(u32::from(*last) << 8);
        }
        acc
    }

    fn fold(mut acc: u32) -> u16 {
        while acc >> 16 != 0 {
            acc = (acc & 0xffff) + (acc >> 16);
        }
        !(acc as u16)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn checksums_verify_to_zero() {
            let header = [
                0x45u8, 0, 0, 0x1c, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 7, 0, 1, 192, 0, 2, 1,
            ];
            let checksum = fold(sum(&header, 0));
            let mut filled = header;
            filled[10..12].copy_from_slice(&checksum.to_be_bytes());
            assert_eq!(fold(sum(&filled, 0)), 0);
        }
    }
}

mod har {
    //! HAR 1.2 entries for decrypted HTTP exchanges.

    use std::net::SocketAddr;

    use serde_json::{json, Value};

    use super::{base64_encode, Captured, CapturedBody, HttpExchange, MAX_HTTP_BODY_BYTES};

    pub(super) fn entry(id: u64, captured: &Captured, exchange: &HttpExchange) -> Value {
        let ended = exchange.ended_at_ms.unwrap_or(exchange.started_at_ms);
        let wait = ended.saturating_sub(exchange.started_at_ms);
        let header = |name: &str, headers: &[(String, String)]| {
            headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
        };
        let headers = |headers: &[(String, String)]| {
            headers
                .iter()
                .map(|(name, value)| json!({ "name": name, "value": value }))
                .collect::<Vec<_>>()
        };
        let mut request = json!({
            "method": exchange.method,
            "url": exchange.url,
            "httpVersion": "HTTP/1.1",
            "cookies": [],
            "headers": headers(&exchange.request_headers),
            "queryString": query(&exchange.url),
            "headersSize": -1,
            "bodySize": exchange.request_body.size,
        });
        if exchange.request_body.size > 0 {
            let mime = header("Content-Type", &exchange.request_headers).unwrap_or_default();
            let mut post = json!({ "mimeType": mime });
            text(&mut post, &exchange.request_body);
            request["postData"] = post;
        }
        let status = exchange.status.unwrap_or(0);
        let mime = header("Content-Type", &exchange.response_headers).unwrap_or_default();
        let mut content = json!({ "size": exchange.response_body.size, "mimeType": mime });
        text(&mut content, &exchange.response_body);
        let body_size = if exchange.status.is_some() {
            exchange.response_body.size as i64
        } else {
            -1
        };
        let mut entry = json!({
            "startedDateTime": iso8601(exchange.started_at_ms),
            "time": wait,
            "request": request,
            "response": {
                "status": status,
                "statusText": status_text(status),
                "httpVersion": "HTTP/1.1",
                "cookies": [],
                "headers": headers(&exchange.response_headers),
                "content": content,
                "redirectURL": header("Location", &exchange.response_headers).unwrap_or_default(),
                "headersSize": -1,
                "bodySize": body_size,
            },
            "cache": {},
            "timings": { "send": 0, "wait": wait, "receive": 0 },
            "connection": id.to_string(),
        });
        if let Ok(address) = captured.destination.parse::<SocketAddr>() {
            entry["serverIPAddress"] = json!(address.ip().to_string());
        }
        let mut comment = Vec::new();
        if let Some(note) = exchange.note {
            comment.push(note.to_string());
        }
        if exchange.request_body.truncated() || exchange.response_body.truncated() {
            comment.push(format!("bodies truncated to {MAX_HTTP_BODY_BYTES} bytes"));
        }
        if !comment.is_empty() {
            entry["comment"] = json!(comment.join("; "));
        }
        entry
    }

    /// `text` (UTF-8) or `text` + `encoding: base64`.
    fn text(target: &mut Value, body: &CapturedBody) {
        if body.data.is_empty() {
            return;
        }
        match std::str::from_utf8(&body.data) {
            Ok(text) => target["text"] = json!(text),
            Err(_) => {
                target["text"] = json!(base64_encode(&body.data));
                target["encoding"] = json!("base64");
            }
        }
    }

    fn query(url: &str) -> Vec<Value> {
        let Some((_, query)) = url.split_once('?') else {
            return Vec::new();
        };
        let query = query.split('#').next().unwrap_or("");
        query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                json!({ "name": name, "value": value })
            })
            .collect()
    }

    pub(super) fn status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            206 => "Partial Content",
            301 => "Moved Permanently",
            302 => "Found",
            304 => "Not Modified",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "",
        }
    }

    /// `2026-11-14T09:57:13.123Z` for Unix milliseconds.
    pub(super) fn iso8601(millis: u64) -> String {
        let seconds = millis / 1000;
        let days = (seconds / 86_400) as i64;
        let rest = seconds % 86_400;
        // Civil date from days since 1970-01-01 (H. Hinnant).
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        format!(
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
            rest / 3600,
            rest % 3600 / 60,
            rest % 60,
            millis % 1000,
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn formats_utc_times() {
            assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
            assert_eq!(iso8601(1_794_995_833_123), "2026-11-18T09:57:13.123Z");
            assert_eq!(iso8601(951_782_400_000), "2000-02-29T00:00:00.000Z");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(budget: usize) -> CaptureStore {
        let store = CaptureStore::default();
        store.set(true, Some(budget));
        store
    }

    #[test]
    fn off_by_default_and_keeps_nothing() {
        let store = CaptureStore::default();
        assert!(!store.begin(1, Network::Tcp, None, "192.0.2.1:80", 1));
        store.record(1, Direction::Up, b"GET /");
        assert_eq!(store.status().connections, 0);
        assert!(store.connection_json(1).is_none());
    }

    #[test]
    fn keeps_the_first_bytes_of_each_direction_and_merges_tcp() {
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        assert!(store.begin(7, Network::Tcp, Some("example.test"), "192.0.2.1:80", 1));
        store.record(7, Direction::Up, b"GET / HTTP/1.1\r\n");
        store.record(7, Direction::Up, b"\r\n");
        store.record(7, Direction::Down, &vec![b'x'; MAX_DIRECTION_BYTES + 10]);
        store.end(7, 2);
        let value = store.connection_json(7).unwrap();
        let chunks = value["chunks"].as_array().unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0]["dir"], "up");
        assert_eq!(
            chunks[0]["data_base64"],
            base64_encode(b"GET / HTTP/1.1\r\n\r\n")
        );
        assert_eq!(value["download"]["captured"], MAX_DIRECTION_BYTES);
        assert_eq!(value["download"]["truncated"], true);
        assert_eq!(value["upload"]["truncated"], false);
        assert_eq!(value["ended_at_ms"], 2);
    }

    #[test]
    fn udp_datagrams_stay_apart() {
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        store.begin(3, Network::Udp, None, "192.0.2.1:53", 1);
        store.record(3, Direction::Up, b"q1");
        store.record(3, Direction::Up, b"q2");
        let value = store.connection_json(3).unwrap();
        assert_eq!(value["chunks"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn the_budget_drops_the_oldest_connections() {
        let store = store(MIN_TOTAL_BYTES);
        for id in 1..=4 {
            store.begin(id, Network::Tcp, None, "192.0.2.1:80", 1);
            store.record(id, Direction::Down, &vec![0u8; 30 * 1024]);
        }
        let status = store.status();
        assert!(status.used_bytes <= MIN_TOTAL_BYTES, "{status:?}");
        assert!(store.connection_json(1).is_none());
        assert!(store.connection_json(4).is_some());
        store.clear();
        assert_eq!(store.status().used_bytes, 0);
    }

    #[test]
    fn decrypted_connections_keep_http_only_and_export() {
        let store = Arc::new(store(MAX_TOTAL_BYTES_LIMIT));
        store.begin(
            9,
            Network::Tcp,
            Some("api.example.test"),
            "api.example.test:443",
            1_000,
        );
        store.record(9, Direction::Up, b"\x16\x03\x01tls");
        store.mark_decrypted(9);
        store.record(9, Direction::Up, b"\x17\x03\x03more");
        let mut exchange = HttpExchange::new(
            "GET",
            "https://api.example.test/a?x=1&y",
            &[("Host".to_string(), "api.example.test".to_string())],
        );
        exchange.status = Some(200);
        exchange.response_headers = vec![("Content-Type".to_string(), "text/plain".to_string())];
        exchange.response_body = CapturedBody::of(b"hello");
        store.add_exchange(9, exchange);

        let value = store.connection_json(9).unwrap();
        assert_eq!(value["decrypted"], true);
        assert!(value["chunks"].as_array().unwrap().is_empty());
        assert_eq!(value["http"][0]["status"], 200);
        assert_eq!(
            value["http"][0]["response"]["body"]["data_base64"],
            base64_encode(b"hello")
        );

        let har: Value = serde_json::from_slice(&store.export_har(None)).unwrap();
        let entry = &har["log"]["entries"][0];
        assert_eq!(har["log"]["version"], "1.2");
        assert_eq!(entry["request"]["method"], "GET");
        assert_eq!(entry["request"]["queryString"][0]["name"], "x");
        assert_eq!(entry["response"]["content"]["text"], "hello");

        let pcap = store.export_pcapng(Some(9));
        assert_eq!(&pcap[..4], &[0x0A, 0x0D, 0x0D, 0x0A]);
        assert!(pcap.windows(5).any(|window| window == b"hello"));
        assert!(pcap.windows(16).any(|window| window == b"api.example.test"));
        assert!(pcap.len().is_multiple_of(4));

        let answer: Value =
            serde_json::from_slice(&export_answer(&store, ExportFormat::Pcapng, Some(9))).unwrap();
        assert_eq!(answer["file_name"], "anixops-capture-9.pcapng");
        assert_eq!(answer["size"], pcap.len());
        let data = base64::engine::general_purpose::STANDARD
            .decode(answer["data_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(data.len(), pcap.len());
    }

    #[test]
    fn exports_udp_over_ipv6() {
        let store = store(MAX_TOTAL_BYTES_LIMIT);
        store.begin(2, Network::Udp, None, "[2001:db8::1]:53", 1);
        store.record(2, Direction::Up, b"query");
        store.record(2, Direction::Down, b"answer");
        let pcap = store.export_pcapng(None);
        assert!(pcap.windows(6).any(|window| window == b"answer"));
        // The synthetic client fd00::1 talks to the real IPv6 server.
        let client = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert!(pcap.windows(16).any(|window| window == client));
    }
}
