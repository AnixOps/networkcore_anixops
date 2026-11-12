//! The client multiplexer (`engine_outbound::mux`) against our sing-mux
//! server through the serve loop: data both ways, the yamux windows, the
//! connection pool and its reuse rate, and the latency of small requests
//! next to a bulk upload (P14 in the feature table).

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use engine_inbound::server::{serve_with_udp, InboundStats, ServeSettings};
use engine_inbound::udp::BoundUdpOutbound;
use engine_inbound::{Accepted, Rejected, StreamInbound, User, UserStore};
use engine_outbound::mux::fair::Discipline;
use engine_outbound::mux::{MuxOutbound, MuxSettings};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout, Sleep};

const TIMEOUT: Duration = Duration::from_secs(20);

/// Every connection is alice asking for the multiplexing destination.
struct MuxInbound {
    users: Arc<UserStore>,
}

impl StreamInbound for MuxInbound {
    fn protocol(&self) -> &'static str {
        "sing-mux-test"
    }

    fn users(&self) -> &Arc<UserStore> {
        &self.users
    }

    fn accept<'a>(
        &'a self,
        stream: BoxStream,
        _peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(async move {
            Ok(Accepted {
                user: self.users.get("alice"),
                target: TargetAddr::Domain("sp.mux.sing-box.arpa".into(), 444),
                stream,
                udp: None,
                mux: false,
            })
        })
    }
}

/// The server's way out.
struct Direct;

impl TcpOutbound for Direct {
    fn protocol(&self) -> &'static str {
        "direct"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = TcpStream::connect((target.host(), target.port())).await?;
            stream.set_nodelay(true)?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}

/// The client's protocol: a plain connection to the server, which takes
/// every connection as a multiplexed one. With a rate, what the client
/// sends is held to it.
struct ToServer {
    server: SocketAddr,
    upload_bytes_per_sec: Option<u64>,
    dials: AtomicU64,
}

impl TcpOutbound for ToServer {
    fn protocol(&self) -> &'static str {
        "to-server"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            assert_eq!(target.host(), "sp.mux.sing-box.arpa");
            self.dials.fetch_add(1, Ordering::Relaxed);
            let stream = TcpStream::connect(self.server).await?;
            stream.set_nodelay(true)?;
            Ok(match self.upload_bytes_per_sec {
                None => Box::new(stream) as BoxStream,
                Some(rate) => Box::new(Throttled {
                    inner: stream,
                    rate,
                    wait: None,
                }) as BoxStream,
            })
        })
    }
}

/// A link that sends `rate` bytes a second, 4 KiB at a time.
struct Throttled {
    inner: TcpStream,
    rate: u64,
    wait: Option<Pin<Box<Sleep>>>,
}

impl AsyncRead for Throttled {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Throttled {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Some(wait) = &mut this.wait {
            ready!(wait.as_mut().poll(cx));
            this.wait = None;
        }
        let chunk = buf.len().min(4096);
        let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &buf[..chunk]))?;
        let pause = Duration::from_secs_f64(n as f64 / this.rate as f64);
        this.wait = Some(Box::pin(sleep(pause)));
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.set_nodelay(true);
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });
    addr
}

/// A target that reads and drops everything.
async fn tcp_sink() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                while matches!(stream.read(&mut buf).await, Ok(n) if n > 0) {}
            });
        }
    });
    addr
}

async fn start_server() -> SocketAddr {
    let users = Arc::new(UserStore::default());
    users.add(User::with_password("alice", "unused")).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let settings = ServeSettings {
        connect_timeout: Duration::from_secs(2),
        ..ServeSettings::default()
    };
    tokio::spawn(serve_with_udp(
        listener,
        Arc::new(MuxInbound { users }),
        Arc::new(Direct),
        Some(Arc::new(BoundUdpOutbound::new(
            "127.0.0.1:0".parse().unwrap(),
        ))),
        settings,
        Arc::new(InboundStats::default()),
    ));
    addr
}

fn client(server: SocketAddr, upload: Option<u64>, settings: MuxSettings) -> MuxOutbound {
    MuxOutbound::new(
        Arc::new(ToServer {
            server,
            upload_bytes_per_sec: upload,
            dials: AtomicU64::new(0),
        }),
        settings,
    )
}

/// Opens a stream to `target`, sends `message` and reads it back.
async fn echo_once(mux: &MuxOutbound, target: SocketAddr, message: &[u8]) {
    let mut stream = mux.connect(&TargetAddr::Ip(target)).await.unwrap();
    stream.write_all(message).await.unwrap();
    let mut back = vec![0u8; message.len()];
    stream.read_exact(&mut back).await.unwrap();
    assert_eq!(back, message);
    stream.shutdown().await.unwrap();
    let mut rest = Vec::new();
    stream.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn streams_reuse_pooled_connections() {
    let server = start_server().await;
    let echo = tcp_echo().await;
    let mux = Arc::new(client(server, None, MuxSettings::default()));

    timeout(TIMEOUT, async {
        // One after another: the first stream dials, the rest reuse it.
        for i in 0..50u32 {
            echo_once(&mux, echo, format!("sequential {i}").as_bytes()).await;
        }
        // At once: the pool grows to max_connections and no further.
        let tasks: Vec<_> = (0..50u32)
            .map(|i| {
                let mux = mux.clone();
                tokio::spawn(async move {
                    echo_once(&mux, echo, format!("concurrent {i}").as_bytes()).await;
                })
            })
            .collect();
        for task in tasks {
            task.await.unwrap();
        }
    })
    .await
    .expect("echo streams timed out");

    let stats = mux.stats();
    let opened = stats.sessions_opened.load(Ordering::Relaxed);
    assert_eq!(stats.streams_opened.load(Ordering::Relaxed), 100);
    assert!((1..=4).contains(&opened), "{opened} connections");
    let rate = stats.reuse_rate();
    println!("mux reuse: {opened} connections for 100 streams, reuse rate {rate:.3}");
    assert!(rate >= 0.8, "reuse rate {rate}");
    let reuse = mux.reuse_stats().unwrap();
    assert_eq!(reuse["mux"]["streams_opened"], 100);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_transfers_run_through_the_windows() {
    let server = start_server().await;
    let echo = tcp_echo().await;
    let mux = client(server, None, MuxSettings::default());
    // Sixteen windows each way, on two streams at once.
    let data: Vec<u8> = (0..4 * 1024 * 1024u32).map(|i| (i % 251) as u8).collect();
    let transfer = |stream: BoxStream| {
        let data = data.clone();
        async move {
            let (mut reader, mut writer) = tokio::io::split(stream);
            let send = async {
                writer.write_all(&data).await.unwrap();
                writer.shutdown().await.unwrap();
            };
            let receive = async {
                let mut back = Vec::new();
                reader.read_to_end(&mut back).await.unwrap();
                back
            };
            let ((), back) = tokio::join!(send, receive);
            assert!(back == data, "echoed bytes differ");
        }
    };
    timeout(TIMEOUT, async {
        let first = mux.connect(&TargetAddr::Ip(echo)).await.unwrap();
        let second = mux.connect(&TargetAddr::Ip(echo)).await.unwrap();
        tokio::join!(transfer(first), transfer(second));
    })
    .await
    .expect("large transfer timed out");
    assert_eq!(mux.stats().sessions_opened.load(Ordering::Relaxed), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_targets_fail_the_stream_not_the_connection() {
    let server = start_server().await;
    let echo = tcp_echo().await;
    let mux = client(server, None, MuxSettings::default());
    // Nothing listens there: the server closes the stream.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let nowhere = closed.local_addr().unwrap();
    drop(closed);
    timeout(TIMEOUT, async {
        let mut stream = mux.connect(&TargetAddr::Ip(nowhere)).await.unwrap();
        let _ = stream.write_all(b"hello").await;
        let mut buf = [0u8; 8];
        let read = stream.read(&mut buf).await;
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
        drop(stream);
        echo_once(&mux, echo, b"still there").await;
    })
    .await
    .expect("refused stream timed out");
    assert_eq!(mux.stats().sessions_opened.load(Ordering::Relaxed), 1);
}

/// Latencies of `count` small request/response exchanges, each on a new
/// stream, while one stream uploads as fast as the link takes it. Returns
/// the sorted latencies and the bulk bytes sent meanwhile.
async fn small_requests_beside_bulk(
    discipline: Discipline,
    count: usize,
) -> (Vec<Duration>, u64, Duration) {
    const RATE: u64 = 1024 * 1024;
    let server = start_server().await;
    let echo = tcp_echo().await;
    let sink = tcp_sink().await;
    let settings = MuxSettings {
        max_connections: 1,
        discipline,
        ..MuxSettings::default()
    };
    let mux = Arc::new(client(server, Some(RATE), settings));

    let stop = Arc::new(AtomicBool::new(false));
    let sent = Arc::new(AtomicU64::new(0));
    let bulk = {
        let (mux, stop, sent) = (mux.clone(), stop.clone(), sent.clone());
        tokio::spawn(async move {
            let mut stream = mux.connect(&TargetAddr::Ip(sink)).await.unwrap();
            let chunk = vec![0x5a; 64 * 1024];
            while !stop.load(Ordering::Relaxed) {
                stream.write_all(&chunk).await.unwrap();
                sent.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            }
        })
    };
    // Let the bulk upload fill everything it may fill.
    sleep(Duration::from_millis(500)).await;
    let began = Instant::now();
    let before = sent.load(Ordering::Relaxed);
    let mut latencies = Vec::with_capacity(count);
    for i in 0..count {
        let start = Instant::now();
        timeout(
            TIMEOUT,
            echo_once(&mux, echo, format!("small {i:04}").as_bytes()),
        )
        .await
        .expect("small request timed out");
        latencies.push(start.elapsed());
        sleep(Duration::from_millis(10)).await;
    }
    let elapsed = began.elapsed();
    let bulk_bytes = sent.load(Ordering::Relaxed) - before;
    stop.store(true, Ordering::Relaxed);
    bulk.abort();
    latencies.sort();
    (latencies, bulk_bytes, elapsed)
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let index = ((sorted.len() as f64 * p).ceil() as usize).clamp(1, sorted.len()) - 1;
    sorted[index]
}

/// P14: one connection, a 1 MiB/s uplink kept full by a bulk upload, and
/// 100 small requests on new streams beside it. The fair queue keeps their
/// P99 near one frame time; queue order (what a plain multiplexer does)
/// puts a whole window of bulk data ahead of each.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bulk_upload_does_not_raise_small_request_p99() {
    let (fair, fair_bulk, fair_time) = small_requests_beside_bulk(Discipline::Fair, 100).await;
    let (fifo, _, _) = small_requests_beside_bulk(Discipline::Fifo, 100).await;
    let (fair_p50, fair_p99) = (percentile(&fair, 0.5), percentile(&fair, 0.99));
    let (fifo_p50, fifo_p99) = (percentile(&fifo, 0.5), percentile(&fifo, 0.99));
    let bulk_rate = fair_bulk as f64 / fair_time.as_secs_f64();
    println!(
        "small requests beside a bulk upload at 1 MiB/s: fair p50 {fair_p50:?} p99 {fair_p99:?}, \
         fifo p50 {fifo_p50:?} p99 {fifo_p99:?}; bulk kept {:.0} KiB/s under fair",
        bulk_rate / 1024.0
    );
    assert!(
        fair_p99 < Duration::from_millis(150),
        "fair p99 {fair_p99:?}"
    );
    assert!(
        fair_p99 * 2 < fifo_p99,
        "fair p99 {fair_p99:?} vs fifo {fifo_p99:?}"
    );
    // The bulk stream still gets most of the link.
    assert!(bulk_rate > 0.5 * 1024.0 * 1024.0, "bulk {bulk_rate:.0} B/s");
}
