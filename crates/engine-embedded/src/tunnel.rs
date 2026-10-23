//! Packet tunnel: IP packets in, IP packets out, connections through an outbound.
//!
//! The tunnel owns one current-thread tokio runtime on a dedicated thread. IP
//! packets from the TUN side enter through [`Tunnel::input_packet`]; packets
//! produced by the userspace TCP/IP stack leave through the [`PacketSink`]
//! callback on the tunnel thread. TCP flows are relayed through the outbound,
//! UDP/53 is forwarded as DNS-over-TCP, and other UDP is dropped so QUIC falls
//! back to TCP. A WireGuard tunnel (`Tunnel::start_wireguard`) skips the
//! stack and seals packets straight to its peer.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::thread;
use std::time::Duration;

use engine_outbound::{TargetAddr, TcpOutbound};
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::udp::UdpMsg;
use netstack_smoltcp::StackBuilder;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot, Semaphore};

use crate::dns::{self, OutboundFailure};
#[cfg(feature = "wireguard")]
use crate::wireguard::{self, WireGuardSettings};

/// Receives every IP packet the stack emits. Called on the tunnel thread.
pub type PacketSink = Box<dyn Fn(&[u8]) + Send + Sync + 'static>;

/// Packets queued from the TUN side before the stack drops new ones.
const INPUT_QUEUE_PACKETS: usize = 512;
/// How long a new flow waits for the application's first bytes, so they can
/// travel inside the proxy request header.
const FIRST_PAYLOAD_WAIT: Duration = Duration::from_millis(100);
const FIRST_PAYLOAD_MAX: usize = 4096;
const RELAY_BUFFER_BYTES: usize = 8 * 1024;
const DNS_PORT: u16 = 53;

#[derive(Clone, Debug)]
pub struct TunnelSettings {
    pub mtu: u16,
    pub tcp_window_bytes: u32,
    pub max_tcp_connections: usize,
    pub max_dns_in_flight: usize,
    pub idle_timeout: Duration,
    pub connect_timeout: Duration,
    pub dns_upstream: SocketAddr,
    pub dns_timeout: Duration,
}

/// Live counters. Snapshots are safe to expose: no addresses, no payloads.
#[derive(Default)]
pub struct TunnelStats {
    pub(crate) packets_in: AtomicU64,
    pub(crate) packets_in_dropped: AtomicU64,
    pub(crate) packets_out: AtomicU64,
    pub(crate) tcp_active: AtomicU64,
    pub(crate) tcp_total: AtomicU64,
    pub(crate) tcp_rejected: AtomicU64,
    pub(crate) tcp_connect_failed: AtomicU64,
    pub(crate) udp_dropped: AtomicU64,
    pub(crate) dns_queries: AtomicU64,
    pub(crate) dns_failed: AtomicU64,
    pub(crate) bytes_up: AtomicU64,
    pub(crate) bytes_down: AtomicU64,
    /// Last `OutboundFailure` code, 0 for none.
    pub(crate) dns_last_failure: AtomicU8,
    pub(crate) tcp_last_failure: AtomicU8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TunnelStatsSnapshot {
    pub packets_in: u64,
    pub packets_in_dropped: u64,
    pub packets_out: u64,
    pub tcp_active: u64,
    pub tcp_total: u64,
    pub tcp_rejected: u64,
    pub tcp_connect_failed: u64,
    pub udp_dropped: u64,
    pub dns_queries: u64,
    pub dns_failed: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub dns_last_failure: Option<&'static str>,
    pub tcp_last_failure: Option<&'static str>,
}

impl TunnelStats {
    pub fn snapshot(&self) -> TunnelStatsSnapshot {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        TunnelStatsSnapshot {
            packets_in: get(&self.packets_in),
            packets_in_dropped: get(&self.packets_in_dropped),
            packets_out: get(&self.packets_out),
            tcp_active: get(&self.tcp_active),
            tcp_total: get(&self.tcp_total),
            tcp_rejected: get(&self.tcp_rejected),
            tcp_connect_failed: get(&self.tcp_connect_failed),
            udp_dropped: get(&self.udp_dropped),
            dns_queries: get(&self.dns_queries),
            dns_failed: get(&self.dns_failed),
            bytes_up: get(&self.bytes_up),
            bytes_down: get(&self.bytes_down),
            dns_last_failure: last_failure(&self.dns_last_failure),
            tcp_last_failure: last_failure(&self.tcp_last_failure),
        }
    }
}

fn last_failure(slot: &AtomicU8) -> Option<&'static str> {
    OutboundFailure::from_code(slot.load(Ordering::Relaxed)).map(OutboundFailure::as_str)
}

fn record(slot: &AtomicU8, failure: OutboundFailure) {
    slot.store(failure as u8, Ordering::Relaxed);
}

pub(crate) fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

pub struct Tunnel {
    packet_tx: mpsc::Sender<Vec<u8>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
    stats: Arc<TunnelStats>,
}

impl Tunnel {
    pub fn start(
        settings: TunnelSettings,
        outbound: Arc<dyn TcpOutbound>,
        sink: PacketSink,
    ) -> io::Result<Self> {
        Self::launch(move |packet_rx, stats| {
            spawn_tasks(settings, outbound, sink, packet_rx, stats)
        })
    }

    /// Starts a WireGuard tunnel to one peer. Resolving the endpoint and
    /// binding the UDP socket happen before this returns.
    #[cfg(feature = "wireguard")]
    pub fn start_wireguard(settings: WireGuardSettings, sink: PacketSink) -> io::Result<Self> {
        Self::launch(move |packet_rx, stats| {
            wireguard::spawn_tasks(settings, sink, packet_rx, stats)
        })
    }

    /// Runs `setup` on a new tunnel thread inside its tokio runtime and waits
    /// for it to report whether the tasks started.
    fn launch<F>(setup: F) -> io::Result<Self>
    where
        F: FnOnce(mpsc::Receiver<Vec<u8>>, Arc<TunnelStats>) -> io::Result<()> + Send + 'static,
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let stats = Arc::new(TunnelStats::default());
        let (packet_tx, packet_rx) = mpsc::channel(INPUT_QUEUE_PACKETS);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);

        let thread_stats = stats.clone();
        let thread = thread::Builder::new()
            .name("networkcore-tunnel".into())
            .spawn(move || {
                runtime.block_on(async move {
                    match setup(packet_rx, thread_stats) {
                        Ok(()) => {
                            let _ = ready_tx.send(Ok(()));
                            let _ = shutdown_rx.await;
                        }
                        Err(err) => {
                            let _ = ready_tx.send(Err(err));
                        }
                    }
                });
                // Dropping the runtime cancels every flow; bound the wait for
                // resolver threads so stop stays prompt.
                runtime.shutdown_timeout(Duration::from_secs(1));
            })?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                packet_tx,
                shutdown_tx: Some(shutdown_tx),
                thread: Some(thread),
                stats,
            }),
            Ok(Err(err)) => {
                let _ = thread.join();
                Err(err)
            }
            Err(_) => {
                let _ = thread.join();
                Err(io::Error::other("tunnel thread exited during startup"))
            }
        }
    }

    /// Queues one IP packet from the TUN side. Returns `false` when the packet
    /// was dropped because the queue is full or the tunnel stopped.
    pub fn input_packet(&self, packet: &[u8]) -> bool {
        if packet.is_empty() {
            return false;
        }
        bump(&self.stats.packets_in);
        if self.packet_tx.try_send(packet.to_vec()).is_ok() {
            true
        } else {
            bump(&self.stats.packets_in_dropped);
            false
        }
    }

    pub fn stats(&self) -> TunnelStatsSnapshot {
        self.stats.snapshot()
    }

    pub fn is_running(&self) -> bool {
        self.thread.is_some()
    }

    /// Stops the tunnel and joins its thread. After this returns the sink is
    /// never called again. Calling it twice is a no-op.
    pub fn stop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.stop();
    }
}

fn spawn_tasks(
    settings: TunnelSettings,
    outbound: Arc<dyn TcpOutbound>,
    sink: PacketSink,
    mut packet_rx: mpsc::Receiver<Vec<u8>>,
    stats: Arc<TunnelStats>,
) -> io::Result<()> {
    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .enable_icmp(false)
        .mtu(usize::from(settings.mtu))
        .tcp_recv_buffer_size(settings.tcp_window_bytes)
        .tcp_send_buffer_size(settings.tcp_window_bytes)
        .build()?;
    let runner = runner.ok_or_else(|| io::Error::other("userspace TCP runner is unavailable"))?;
    let udp_socket =
        udp_socket.ok_or_else(|| io::Error::other("userspace UDP socket is unavailable"))?;
    let mut tcp_listener =
        tcp_listener.ok_or_else(|| io::Error::other("userspace TCP listener is unavailable"))?;

    tokio::spawn(runner);

    let (mut stack_sink, mut stack_stream) = stack.split();

    // Stack -> TUN.
    let out_stats = stats.clone();
    tokio::spawn(async move {
        while let Some(packet) = stack_stream.next().await {
            if let Ok(packet) = packet {
                bump(&out_stats.packets_out);
                sink(&packet);
            }
        }
    });

    // TUN -> stack. Invalid packets are rejected by the stack and skipped.
    tokio::spawn(async move {
        while let Some(packet) = packet_rx.recv().await {
            let _ = stack_sink.send(packet).await;
        }
    });

    // TCP flows.
    let tcp_permits = Arc::new(Semaphore::new(settings.max_tcp_connections));
    let tcp_outbound = outbound.clone();
    let tcp_stats = stats.clone();
    let tcp_settings = settings.clone();
    tokio::spawn(async move {
        while let Some((stream, _local, remote)) = tcp_listener.next().await {
            let Ok(permit) = tcp_permits.clone().try_acquire_owned() else {
                bump(&tcp_stats.tcp_rejected);
                drop(stream);
                continue;
            };
            bump(&tcp_stats.tcp_total);
            let outbound = tcp_outbound.clone();
            let stats = tcp_stats.clone();
            let settings = tcp_settings.clone();
            tokio::spawn(async move {
                let _permit = permit;
                stats.tcp_active.fetch_add(1, Ordering::Relaxed);
                handle_tcp(stream, remote, outbound.as_ref(), &stats, &settings).await;
                stats.tcp_active.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });

    // UDP: DNS only.
    let (mut udp_rx, mut udp_tx) = udp_socket.split();
    let (reply_tx, mut reply_rx) = mpsc::channel::<UdpMsg>(64);
    tokio::spawn(async move {
        while let Some(reply) = reply_rx.recv().await {
            if udp_tx.send(reply).await.is_err() {
                break;
            }
        }
    });
    let dns_permits = Arc::new(Semaphore::new(settings.max_dns_in_flight));
    tokio::spawn(async move {
        while let Some((payload, src, dst)) = udp_rx.next().await {
            if dst.port() != DNS_PORT {
                bump(&stats.udp_dropped);
                continue;
            }
            let Ok(permit) = dns_permits.clone().try_acquire_owned() else {
                bump(&stats.dns_failed);
                continue;
            };
            bump(&stats.dns_queries);
            let outbound = outbound.clone();
            let stats = stats.clone();
            let reply_tx = reply_tx.clone();
            let upstream = settings.dns_upstream;
            let timeout = settings.dns_timeout;
            tokio::spawn(async move {
                let _permit = permit;
                match dns::query_over_tcp(outbound.as_ref(), upstream, &payload, timeout).await {
                    // The reply goes back from the address the app queried.
                    Ok(response) => {
                        let _ = reply_tx.send((response, dst, src)).await;
                    }
                    Err(failure) => {
                        bump(&stats.dns_failed);
                        record(&stats.dns_last_failure, failure);
                    }
                }
            });
        }
    });

    Ok(())
}

async fn handle_tcp(
    mut inbound: netstack_smoltcp::TcpStream,
    target: SocketAddr,
    outbound: &dyn TcpOutbound,
    stats: &TunnelStats,
    settings: &TunnelSettings,
) {
    let mut first = vec![0u8; FIRST_PAYLOAD_MAX];
    let first_len = match tokio::time::timeout(FIRST_PAYLOAD_WAIT, inbound.read(&mut first)).await {
        Ok(Ok(0)) | Ok(Err(_)) => return,
        Ok(Ok(n)) => n,
        Err(_) => 0,
    };
    first.truncate(first_len);

    let target = TargetAddr::Ip(target);
    let mut remote =
        match tokio::time::timeout(settings.connect_timeout, outbound.connect(&target)).await {
            Ok(Ok(remote)) => remote,
            Ok(Err(err)) => {
                bump(&stats.tcp_connect_failed);
                record(&stats.tcp_last_failure, OutboundFailure::connect(&err));
                return;
            }
            Err(_) => {
                bump(&stats.tcp_connect_failed);
                record(&stats.tcp_last_failure, OutboundFailure::ConnectTimeout);
                return;
            }
        };
    if !first.is_empty() {
        let written = match remote.write_all(&first).await {
            Ok(()) => remote.flush().await,
            Err(err) => Err(err),
        };
        if let Err(err) = written {
            bump(&stats.tcp_connect_failed);
            record(&stats.tcp_last_failure, OutboundFailure::reply(&err));
            return;
        }
        stats
            .bytes_up
            .fetch_add(first.len() as u64, Ordering::Relaxed);
    }
    drop(first);

    let activity = Arc::new(AtomicU64::new(0));
    let mut inbound = Counted::new(inbound, activity.clone(), &stats.bytes_up);
    let mut remote = Counted::new(remote, activity.clone(), &stats.bytes_down);
    let copy = tokio::io::copy_bidirectional_with_sizes(
        &mut inbound,
        &mut remote,
        RELAY_BUFFER_BYTES,
        RELAY_BUFFER_BYTES,
    );
    tokio::pin!(copy);
    let mut last_seen = activity.load(Ordering::Relaxed);
    loop {
        tokio::select! {
            result = &mut copy => {
                // Resets are routine; only a reply the outbound rejects is worth reporting.
                if let Err(err) = result {
                    if err.kind() == io::ErrorKind::InvalidData {
                        record(&stats.tcp_last_failure, OutboundFailure::ReplyRejected);
                    }
                }
                break;
            }
            _ = tokio::time::sleep(settings.idle_timeout) => {
                let seen = activity.load(Ordering::Relaxed);
                if seen == last_seen {
                    break;
                }
                last_seen = seen;
            }
        }
    }
}

/// Counts bytes read from the wrapped stream and records activity for the idle timer.
struct Counted<'a, S> {
    inner: S,
    activity: Arc<AtomicU64>,
    bytes_read: &'a AtomicU64,
}

impl<'a, S> Counted<'a, S> {
    fn new(inner: S, activity: Arc<AtomicU64>, bytes_read: &'a AtomicU64) -> Self {
        Self {
            inner,
            activity,
            bytes_read,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<'_, S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(cx, buf);
        let n = (buf.filled().len() - before) as u64;
        if n > 0 {
            this.bytes_read.fetch_add(n, Ordering::Relaxed);
            this.activity.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<'_, S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
