//! Packet-tunnel benchmark: the same code path as the iOS Network Extension,
//! driven by the Linux kernel's TCP stack through a TUN device.
//!
//! ```text
//! client (kernel TCP) -> TUN -> Tunnel (userspace TCP/IP, relay) -> outbound -> server process
//! ```
//!
//! `tunnel_bench run` starts two child processes of itself: `server` (data
//! source/sink, plus a Shadowsocks-2022 server in front of it) and `tunnel`
//! (the TUN device and one [`Tunnel`]). Only the tunnel process is measured
//! for CPU, wakeups and memory, so the numbers are what the extension costs.
//!
//! The TUN device must already exist and belong to the current user, e.g.
//!
//! ```text
//! sudo ip tuntap add dev ncb0 mode tun user "$(id -u)"
//! sudo ip addr add 198.18.0.1/16 dev ncb0
//! sudo ip link set ncb0 mtu 1500 up
//! cargo run --release -p engine-embedded --example tunnel_bench -- run --tun ncb0 --json out.json
//! ```
//!
//! Options of `run`: `--tun NAME`, `--outbound redirect|ss2022`, `--seconds N`
//! (per throughput test), `--window-kib N`, `--max-conns N`, `--conns N`
//! (memory test), `--connects N` (latency test), `--json PATH`.
//!
//! Two scale tests have their own commands and fail (exit 1) when a target is
//! missed:
//!
//! - `scale --tun NAME --concurrent N [--max-rss-mb M]`: N connections open
//!   at once through the tunnel (the same TUN set-up as `run`); every one must
//!   be established and echo one byte while all are open. Pass `--max-conns`
//!   above N.
//! - `udp-sessions --flows N [--max-rss-mb M]`: no TUN needed. N UDP flows,
//!   each from its own app socket, are fed to one in-process [`Tunnel`] whose
//!   outbound keeps every flow open in memory; every flow must open and the
//!   process RSS with all of them open must stay under M MiB.
//!
//! `.github/workflows/perf.yml` runs `run` for a pull request's base and head,
//! and both scale tests on the head.

#[cfg(target_os = "linux")]
fn main() {
    if let Err(err) = linux::main() {
        eprintln!("tunnel_bench: {err}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("tunnel_bench needs Linux (a TUN device)");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::os::fd::RawFd;
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use base64::Engine as _;
    use engine_embedded::dns_policy::DnsPolicy;
    use engine_embedded::shadowsocks::{Method, Ss2022Outbound};
    use engine_embedded::tunnel::{PacketSink, Tunnel, TunnelSettings};
    use engine_inbound::server::{serve, InboundStats, ServeSettings};
    use engine_outbound::{
        BoxFuture, BoxStream, DatagramRecv, DatagramSend, TargetAddr, TcpDialer, TcpOutbound,
        UdpFlow,
    };
    use inbound_shadowsocks::Ss2022Inbound;
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Where the client connects: any address routed into the TUN device.
    const TARGET: &str = "198.18.0.2:5201";
    const CHUNK: usize = 64 * 1024;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;

    type Args = HashMap<String, String>;

    pub fn main() -> io::Result<()> {
        let mut argv = std::env::args().skip(1);
        let command = argv.next().unwrap_or_default();
        let mut args = Args::new();
        while let Some(key) = argv.next() {
            let key = key.trim_start_matches("--").to_string();
            let value = argv.next().unwrap_or_default();
            args.insert(key, value);
        }
        match command.as_str() {
            "run" => run(&args),
            "scale" => scale(&args),
            "udp-sessions" => udp_sessions(&args),
            "server" => server_child(),
            "tunnel" => tunnel_child(&args),
            _ => Err(io::Error::other(
                "usage: tunnel_bench run|scale --tun NAME [--outbound redirect|ss2022] [--json PATH] \
                 | tunnel_bench udp-sessions --flows N [--json PATH]",
            )),
        }
    }

    fn arg<'a>(args: &'a Args, key: &str, default: &'a str) -> &'a str {
        args.get(key).map(String::as_str).unwrap_or(default)
    }

    fn num(args: &Args, key: &str, default: u64) -> io::Result<u64> {
        match args.get(key) {
            Some(value) => value
                .parse()
                .map_err(|_| io::Error::other(format!("--{key} is not a number"))),
            None => Ok(default),
        }
    }

    fn key() -> String {
        base64::engine::general_purpose::STANDARD.encode([7u8; 16])
    }

    /// Sends every flow to one local address, whatever the target.
    struct Redirect(SocketAddr);

    impl TcpOutbound for Redirect {
        fn protocol(&self) -> &'static str {
            "bench-redirect"
        }

        fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async move {
                let stream = tokio::net::TcpStream::connect(self.0).await?;
                stream.set_nodelay(true)?;
                Ok(Box::new(stream) as BoxStream)
            })
        }
    }

    // ---- server process -------------------------------------------------

    fn server_child() -> io::Result<()> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let sink = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let sink_addr = sink.local_addr()?;
            tokio::spawn(async move {
                while let Ok((stream, _)) = sink.accept().await {
                    tokio::spawn(async move {
                        let _ = data_connection(stream).await;
                    });
                }
            });
            let ss = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let ss_port = ss.local_addr()?.port();
            let inbound = Arc::new(Ss2022Inbound::new(
                inbound_shadowsocks::Method::Aes128Gcm,
                &key(),
                false,
            )?);
            tokio::spawn(serve(
                ss,
                inbound,
                Arc::new(Redirect(sink_addr)),
                ServeSettings::default(),
                Arc::new(InboundStats::default()),
            ));
            println!("READY {} {}", sink_addr.port(), ss_port);
            io::stdout().flush()?;
            std::future::pending::<()>().await;
            Ok::<(), io::Error>(())
        })
    }

    /// One command byte, then: `D` streams data until the peer leaves, `U`
    /// counts what arrives and answers the total, `E` echoes, anything else
    /// holds the connection open.
    async fn data_connection(mut stream: tokio::net::TcpStream) -> io::Result<()> {
        stream.set_nodelay(true)?;
        let mut command = [0u8; 1];
        stream.read_exact(&mut command).await?;
        let mut buf = vec![0x5a; CHUNK];
        match command[0] {
            b'D' => loop {
                stream.write_all(&buf).await?;
            },
            b'U' => {
                let mut total = 0u64;
                loop {
                    let n = stream.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    total += n as u64;
                }
                stream.write_all(&total.to_be_bytes()).await?;
            }
            b'E' => loop {
                let n = stream.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                stream.write_all(&buf[..n]).await?;
            },
            _ => while stream.read(&mut buf).await? > 0 {},
        }
        Ok(())
    }

    // ---- tunnel process -------------------------------------------------

    fn tunnel_child(args: &Args) -> io::Result<()> {
        let sink_port = num(args, "sink", 0)? as u16;
        let ss_port = num(args, "ss", 0)? as u16;
        let fd = open_tun(arg(args, "tun", "ncb0"))?;
        let outbound: Arc<dyn TcpOutbound> = match arg(args, "outbound", "redirect") {
            "redirect" => Arc::new(Redirect(SocketAddr::from(([127, 0, 0, 1], sink_port)))),
            "ss2022" => Arc::new(Ss2022Outbound::new(
                "127.0.0.1",
                ss_port,
                Method::Aes128Gcm,
                &key(),
                Arc::new(TcpDialer),
            )?),
            other => return Err(io::Error::other(format!("unknown outbound {other}"))),
        };
        let settings = TunnelSettings {
            mtu: num(args, "mtu", 1500)? as u16,
            tcp_window_bytes: (num(args, "window-kib", 64)? * 1024) as u32,
            max_tcp_connections: num(args, "max-conns", 128)? as usize,
            max_udp_flows: num(args, "max-udp-flows", 256)? as usize,
            max_dns_in_flight: 32,
            idle_timeout: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(10),
            dns: Arc::new(DnsPolicy::tcp(
                SocketAddr::from(([127, 0, 0, 1], 53)),
                Duration::from_secs(5),
            )),
        };
        let sink: PacketSink = Box::new(move |packet: &[u8]| {
            // SAFETY: `fd` stays open for the life of the process.
            let _ = unsafe { libc::write(fd, packet.as_ptr().cast(), packet.len()) };
        });

        let started = Instant::now();
        let tunnel = Arc::new(Tunnel::start(settings, outbound, sink)?);
        let start_us = started.elapsed().as_micros();

        let reader = tunnel.clone();
        thread::Builder::new()
            .name("tun-read".into())
            .spawn(move || {
                let mut buf = vec![0u8; 65536];
                loop {
                    // SAFETY: `buf` is valid for `buf.len()` bytes.
                    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                    if n > 0 {
                        reader.input_packet(&buf[..n as usize]);
                    } else if n == 0
                        || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
                    {
                        break;
                    }
                }
            })?;

        let control = TcpListener::bind("127.0.0.1:0")?;
        println!("READY {} {}", control.local_addr()?.port(), start_us);
        io::stdout().flush()?;
        for stream in control.incoming() {
            let mut stream = stream?;
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line)?;
            let sample = sample(&tunnel);
            writeln!(stream, "{sample}")?;
        }
        Ok(())
    }

    fn open_tun(name: &str) -> io::Result<RawFd> {
        const TUNSETIFF: u64 = 0x4004_54ca;
        #[repr(C)]
        #[allow(dead_code)] // read by the kernel, not by Rust
        struct IfReq {
            name: [libc::c_char; libc::IFNAMSIZ],
            flags: libc::c_short,
            pad: [u8; 22],
        }
        if name.is_empty() || name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::other("bad TUN name"));
        }
        let mut request = IfReq {
            name: [0; libc::IFNAMSIZ],
            flags: (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short,
            pad: [0; 22],
        };
        for (slot, byte) in request.name.iter_mut().zip(name.bytes()) {
            *slot = byte as libc::c_char;
        }
        // SAFETY: a NUL-terminated path; the request outlives the call.
        unsafe {
            let fd = libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::ioctl(fd, TUNSETIFF as _, &mut request as *mut IfReq) < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }
            Ok(fd)
        }
    }

    /// Process memory, CPU and context switches, plus the tunnel counters.
    fn sample(tunnel: &Tunnel) -> Value {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let field = |name: &str| -> u64 {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|value| value.parse().ok())
                .unwrap_or(0)
        };
        // SAFETY: getrusage fills the zeroed struct.
        let usage = unsafe {
            let mut usage: libc::rusage = std::mem::zeroed();
            libc::getrusage(libc::RUSAGE_SELF, &mut usage);
            usage
        };
        let micros = |time: libc::timeval| time.tv_sec as u64 * 1_000_000 + time.tv_usec as u64;
        json!({
            "rss_kb": field("VmRSS:"),
            "hwm_kb": field("VmHWM:"),
            "threads": field("Threads:"),
            "cpu_us": micros(usage.ru_utime) + micros(usage.ru_stime),
            "nvcsw": usage.ru_nvcsw as u64,
            "nivcsw": usage.ru_nivcsw as u64,
            "tunnel": serde_json::to_value(tunnel.stats()).unwrap_or(Value::Null),
        })
    }

    // ---- orchestration --------------------------------------------------

    struct Children {
        server: Child,
        tunnel: Child,
        control: u16,
    }

    impl Drop for Children {
        fn drop(&mut self) {
            let _ = self.tunnel.kill();
            let _ = self.server.kill();
            let _ = self.tunnel.wait();
            let _ = self.server.wait();
        }
    }

    fn spawn_child(args: &[&str]) -> io::Result<(Child, Vec<String>)> {
        let mut child = Command::new(std::env::current_exe()?)
            .args(args)
            .stdout(Stdio::piped())
            .spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("no stdout"))?;
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line)?;
        let words: Vec<String> = line.split_whitespace().map(str::to_string).collect();
        if words.first().map(String::as_str) != Some("READY") {
            let _ = child.kill();
            return Err(io::Error::other(format!("child {args:?} did not start")));
        }
        Ok((child, words[1..].to_vec()))
    }

    fn stats(children: &Children) -> io::Result<Value> {
        let mut stream = TcpStream::connect(("127.0.0.1", children.control))?;
        stream.write_all(b"stats\n")?;
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line)?;
        serde_json::from_str(&line).map_err(io::Error::other)
    }

    fn get(value: &Value, key: &str) -> f64 {
        value[key].as_f64().unwrap_or(0.0)
    }

    fn delta(before: &Value, after: &Value, key: &str) -> f64 {
        get(after, key) - get(before, key)
    }

    fn target() -> SocketAddr {
        TARGET.parse().expect("valid target")
    }

    fn connect(command: u8) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect_timeout(&target(), Duration::from_secs(10))?;
        stream.set_nodelay(true)?;
        stream.write_all(&[command])?;
        Ok(stream)
    }

    /// Starts the server and tunnel processes; returns them and the tunnel's
    /// start time in microseconds.
    fn start(args: &Args) -> io::Result<(Children, f64)> {
        let outbound = arg(args, "outbound", "redirect").to_string();
        let (server, ports) = spawn_child(&["server"])?;
        let (sink, ss) = (ports[0].clone(), ports[1].clone());
        let mut tunnel_args = vec![
            "tunnel",
            "--sink",
            sink.as_str(),
            "--ss",
            ss.as_str(),
            "--outbound",
            outbound.as_str(),
        ];
        let forwarded: Vec<(String, String)> = ["tun", "window-kib", "max-conns", "mtu"]
            .iter()
            .filter_map(|key| {
                args.get(*key)
                    .map(|value| (format!("--{key}"), value.clone()))
            })
            .collect();
        for (key, value) in &forwarded {
            tunnel_args.push(key.as_str());
            tunnel_args.push(value.as_str());
        }
        let (tunnel, words) = match spawn_child(&tunnel_args) {
            Ok(started) => started,
            Err(err) => {
                let mut server = server;
                let _ = server.kill();
                return Err(err);
            }
        };
        let children = Children {
            server,
            tunnel,
            control: words[0].parse().map_err(io::Error::other)?,
        };
        let start_us: f64 = words[1].parse().unwrap_or(0.0);
        Ok((children, start_us))
    }

    fn write_report(args: &Args, report: &Value) -> io::Result<()> {
        let text = serde_json::to_string_pretty(report).map_err(io::Error::other)?;
        println!("{text}");
        if let Some(path) = args.get("json") {
            std::fs::write(path, text)?;
        }
        Ok(())
    }

    fn run(args: &Args) -> io::Result<()> {
        let outbound = arg(args, "outbound", "redirect").to_string();
        let seconds = num(args, "seconds", 5)? as f64;
        let conns = num(args, "conns", 100)? as usize;
        let connects = num(args, "connects", 200)? as usize;
        let (children, start_us) = start(args)?;

        thread::sleep(Duration::from_secs(1));
        let started = stats(&children)?;
        let mut report = json!({
            "outbound": outbound,
            "window_kib": num(args, "window-kib", 64)?,
            "start_ms": start_us / 1000.0,
            "rss_after_start_kb": get(&started, "rss_kb"),
            "threads": get(&started, "threads"),
        });

        report["idle"] = idle(&children, Duration::from_secs(10), &[])?;
        report["connect"] = connect_latency(connects)?;
        thread::sleep(Duration::from_secs(1));
        report["download_1"] = download(&children, 1, seconds)?;
        thread::sleep(Duration::from_secs(1));
        report["download_8"] = download(&children, 8, seconds)?;
        thread::sleep(Duration::from_secs(1));
        report["upload_1"] = upload(&children, seconds)?;
        thread::sleep(Duration::from_secs(1));
        report["memory"] = memory(&children, conns)?;
        thread::sleep(Duration::from_secs(1));
        let held = (0..conns)
            .map(|_| connect(b'H'))
            .collect::<io::Result<Vec<_>>>()?;
        thread::sleep(Duration::from_secs(1));
        report["idle_conns"] = idle(&children, Duration::from_secs(10), &held)?;
        drop(held);
        thread::sleep(Duration::from_secs(1));
        let last = stats(&children)?;
        report["hwm_kb"] = json!(get(&last, "hwm_kb"));
        report["tunnel"] = last["tunnel"].clone();
        write_report(args, &report)
    }

    /// CPU and wakeups of the tunnel process while nothing moves.
    fn idle(children: &Children, period: Duration, held: &[TcpStream]) -> io::Result<Value> {
        let before = stats(children)?;
        thread::sleep(period);
        let after = stats(children)?;
        let secs = period.as_secs_f64();
        Ok(json!({
            "conns": held.len(),
            "cpu_ms_per_s": delta(&before, &after, "cpu_us") / 1000.0 / secs,
            "wakeups_per_s": delta(&before, &after, "nvcsw") / secs,
            "rss_kb": get(&after, "rss_kb"),
        }))
    }

    fn percentile(sorted: &[f64], p: f64) -> f64 {
        if sorted.is_empty() {
            return 0.0;
        }
        let index = ((sorted.len() - 1) as f64 * p).round() as usize;
        sorted[index]
    }

    /// Sequential new connections: handshake with the userspace stack, then
    /// the first echoed byte, which includes the outbound dial.
    fn connect_latency(count: usize) -> io::Result<Value> {
        let mut handshake = Vec::with_capacity(count);
        let mut first_byte = Vec::with_capacity(count);
        for _ in 0..count {
            let begin = Instant::now();
            let mut stream = TcpStream::connect_timeout(&target(), Duration::from_secs(10))?;
            handshake.push(begin.elapsed().as_secs_f64() * 1000.0);
            stream.set_nodelay(true)?;
            stream.write_all(b"Ex")?;
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte)?;
            first_byte.push(begin.elapsed().as_secs_f64() * 1000.0);
        }
        handshake.sort_by(f64::total_cmp);
        first_byte.sort_by(f64::total_cmp);
        Ok(json!({
            "count": count,
            "handshake_p50_ms": percentile(&handshake, 0.5),
            "handshake_p99_ms": percentile(&handshake, 0.99),
            "first_byte_p50_ms": percentile(&first_byte, 0.5),
            "first_byte_p90_ms": percentile(&first_byte, 0.9),
            "first_byte_p99_ms": percentile(&first_byte, 0.99),
        }))
    }

    fn throughput(before: &Value, after: &Value, bytes: f64, secs: f64) -> Value {
        let cpu_ms = delta(before, after, "cpu_us") / 1000.0;
        json!({
            "mbps": bytes * 8.0 / secs / 1e6,
            "cpu_ms_per_gib": if bytes > 0.0 { cpu_ms / (bytes / GIB) } else { 0.0 },
            "cpu_util": cpu_ms / 1000.0 / secs,
            "rss_kb": get(after, "rss_kb"),
        })
    }

    fn download(children: &Children, flows: usize, secs: f64) -> io::Result<Value> {
        let streams = (0..flows)
            .map(|_| connect(b'D'))
            .collect::<io::Result<Vec<_>>>()?;
        let before = stats(children)?;
        let begin = Instant::now();
        let deadline = begin + Duration::from_secs_f64(secs);
        let workers: Vec<_> = streams
            .into_iter()
            .map(|mut stream| {
                thread::spawn(move || {
                    let mut buf = vec![0u8; CHUNK];
                    let mut total = 0u64;
                    while Instant::now() < deadline {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => total += n as u64,
                        }
                    }
                    total
                })
            })
            .collect();
        let bytes: u64 = workers.into_iter().map(|w| w.join().unwrap_or(0)).sum();
        let elapsed = begin.elapsed().as_secs_f64();
        let after = stats(children)?;
        let mut result = throughput(&before, &after, bytes as f64, elapsed);
        result["flows"] = json!(flows);
        Ok(result)
    }

    fn upload(children: &Children, secs: f64) -> io::Result<Value> {
        let mut stream = connect(b'U')?;
        let before = stats(children)?;
        let begin = Instant::now();
        let deadline = begin + Duration::from_secs_f64(secs);
        let buf = vec![0x33u8; CHUNK];
        while Instant::now() < deadline {
            stream.write_all(&buf)?;
        }
        stream.shutdown(Shutdown::Write)?;
        let mut total = [0u8; 8];
        stream.read_exact(&mut total)?;
        let elapsed = begin.elapsed().as_secs_f64();
        let after = stats(children)?;
        let mut result = throughput(&before, &after, u64::from_be_bytes(total) as f64, elapsed);
        result["flows"] = json!(1);
        Ok(result)
    }

    /// `conns` downloads the app does not read: every buffer on the path
    /// fills up, the worst case of a slow app. Then all close.
    fn memory(children: &Children, conns: usize) -> io::Result<Value> {
        let before = stats(children)?;
        let streams = (0..conns)
            .map(|_| connect(b'D'))
            .collect::<io::Result<Vec<_>>>()?;
        thread::sleep(Duration::from_secs(3));
        let stalled = stats(children)?;
        drop(streams);
        thread::sleep(Duration::from_secs(3));
        let closed = stats(children)?;
        let base = get(&before, "rss_kb");
        Ok(json!({
            "conns": conns,
            "rss_before_kb": base,
            "rss_stalled_kb": get(&stalled, "rss_kb"),
            "per_conn_kb": (get(&stalled, "rss_kb") - base) / conns.max(1) as f64,
            "rss_after_close_kb": get(&closed, "rss_kb"),
        }))
    }

    // ---- scale: concurrent connections ------------------------------------

    /// Fails the command when `failures` is not empty.
    fn verdict(args: &Args, mut report: Value, failures: Vec<String>) -> io::Result<()> {
        report["pass"] = json!(failures.is_empty());
        report["failures"] = json!(failures);
        write_report(args, &report)?;
        if failures.is_empty() {
            Ok(())
        } else {
            Err(io::Error::other(failures.join("; ")))
        }
    }

    fn rss_limit(args: &Args, rss_kb: f64, failures: &mut Vec<String>) -> io::Result<()> {
        if args.contains_key("max-rss-mb") {
            let limit = num(args, "max-rss-mb", 0)?;
            if rss_kb / 1024.0 > limit as f64 {
                failures.push(format!(
                    "RSS {:.1} MiB is above the {limit} MiB limit",
                    rss_kb / 1024.0
                ));
            }
        }
        Ok(())
    }

    /// Sends one byte and reads the echo.
    fn echo_once(stream: &mut TcpStream) -> io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.write_all(b"x")?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)
    }

    /// `--concurrent N` echo connections open at once: opened from parallel
    /// threads, then each echoes one byte while all of them are open.
    fn scale(args: &Args) -> io::Result<()> {
        let count = num(args, "concurrent", 5000)? as usize;
        let threads = (num(args, "threads", 32)? as usize).clamp(1, count.max(1));
        let (children, _) = start(args)?;
        thread::sleep(Duration::from_secs(1));
        let before = stats(&children)?;

        let begin = Instant::now();
        let per = count.div_ceil(threads);
        let openers: Vec<_> = (0..threads)
            .map(|index| {
                let n = per.min(count.saturating_sub(index * per));
                thread::spawn(move || {
                    let mut streams = Vec::with_capacity(n);
                    let mut failed = 0usize;
                    for _ in 0..n {
                        match connect(b'E') {
                            Ok(stream) => streams.push(stream),
                            Err(_) => failed += 1,
                        }
                    }
                    (streams, failed)
                })
            })
            .collect();
        let mut groups = Vec::with_capacity(threads);
        let mut connect_failed = 0;
        for opener in openers {
            let (streams, failed) = opener
                .join()
                .map_err(|_| io::Error::other("opener thread panicked"))?;
            connect_failed += failed;
            groups.push(streams);
        }
        let open_secs = begin.elapsed().as_secs_f64();
        let established: usize = groups.iter().map(Vec::len).sum();
        thread::sleep(Duration::from_secs(2));
        let open = stats(&children)?;

        // One byte through every connection while all stay open.
        let echoers: Vec<_> = groups
            .into_iter()
            .map(|mut streams| {
                thread::spawn(move || {
                    let mut latencies = Vec::with_capacity(streams.len());
                    let mut failed = 0usize;
                    for stream in &mut streams {
                        let begin = Instant::now();
                        let echoed = echo_once(stream);
                        match echoed {
                            Ok(()) => latencies.push(begin.elapsed().as_secs_f64() * 1000.0),
                            Err(_) => failed += 1,
                        }
                    }
                    (streams, latencies, failed)
                })
            })
            .collect();
        let mut held = Vec::with_capacity(established);
        let mut latencies = Vec::with_capacity(established);
        let mut echo_failed = 0;
        for echoer in echoers {
            let (streams, mut times, failed) = echoer
                .join()
                .map_err(|_| io::Error::other("echo thread panicked"))?;
            held.extend(streams);
            latencies.append(&mut times);
            echo_failed += failed;
        }
        latencies.sort_by(f64::total_cmp);
        let echoed = stats(&children)?;
        drop(held);
        thread::sleep(Duration::from_secs(5));
        let closed = stats(&children)?;

        let base = get(&before, "rss_kb");
        let rss_open = get(&open, "rss_kb").max(get(&echoed, "rss_kb"));
        let tunnel = |sample: &Value, key: &str| sample["tunnel"][key].as_f64().unwrap_or(0.0);
        let mut report = json!({
            "outbound": arg(args, "outbound", "redirect"),
            "concurrent": count,
            "threads": threads,
            "established": established,
            "connect_failed": connect_failed,
            "open_secs": open_secs,
            "echo_ok": latencies.len(),
            "echo_failed": echo_failed,
            "echo_p50_ms": percentile(&latencies, 0.5),
            "echo_p99_ms": percentile(&latencies, 0.99),
            "echo_max_ms": latencies.last().copied().unwrap_or(0.0),
            "tcp_active_open": tunnel(&open, "tcp_active"),
            "tcp_rejected": tunnel(&closed, "tcp_rejected") - tunnel(&before, "tcp_rejected"),
            "rss_before_kb": base,
            "rss_open_kb": rss_open,
            "per_conn_kb": (rss_open - base) / established.max(1) as f64,
            "rss_after_close_kb": get(&closed, "rss_kb"),
            "tcp_active_after_close": tunnel(&closed, "tcp_active"),
            "cpu_ms_open": delta(&before, &open, "cpu_us") / 1000.0,
            "hwm_kb": get(&closed, "hwm_kb"),
        });
        let mut failures = Vec::new();
        if established < count {
            failures.push(format!("{established} of {count} connections established"));
        }
        if echo_failed > 0 {
            failures.push(format!("{echo_failed} connections did not echo"));
        }
        rss_limit(args, rss_open, &mut failures)?;
        report["max_rss_mb"] = json!(args.get("max-rss-mb"));
        verdict(args, report, failures)
    }

    // ---- udp-sessions: UDP flow table at scale ----------------------------

    /// Keeps every UDP flow open: sends are counted and dropped, replies
    /// never come, so a flow lives until the tunnel's idle timeout.
    struct UdpHold;

    struct HoldSend;

    impl DatagramSend for HoldSend {
        fn send<'a>(&'a mut self, _payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    struct HoldRecv;

    impl DatagramRecv for HoldRecv {
        fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
            Box::pin(std::future::pending())
        }
    }

    impl TcpOutbound for UdpHold {
        fn protocol(&self) -> &'static str {
            "bench-udp-hold"
        }

        fn connect<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async { Err(io::Error::other("udp-sessions opens no TCP")) })
        }

        fn open_udp<'a>(&'a self, _target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
            Box::pin(async { Ok(UdpFlow::new(Box::new(HoldSend), Box::new(HoldRecv))) })
        }
    }

    fn rss_kb() -> f64 {
        std::fs::read_to_string("/proc/self/status")
            .unwrap_or_default()
            .lines()
            .find_map(|line| line.strip_prefix("VmRSS:"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|value| value.parse().ok())
            .unwrap_or(0.0)
    }

    /// One UDP datagram from app socket `index` (10.64.0.0/10, one port per
    /// address block) to a fixed destination.
    fn udp_packet(index: usize) -> Vec<u8> {
        let host = (index / 50_000) as u32 + 1;
        let port = 10_000 + (index % 50_000) as u16;
        let source = (0x0a40_0000u32 + host).to_be_bytes();
        let mut packet = Vec::with_capacity(64);
        etherparse::PacketBuilder::ipv4(source, [203, 0, 113, 9], 64)
            .udp(port, 4000)
            .write(&mut packet, &[0x42; 32])
            .expect("UDP packet builds");
        packet
    }

    fn udp_sessions(args: &Args) -> io::Result<()> {
        let flows = num(args, "flows", 100_000)? as usize;
        let settings = TunnelSettings {
            mtu: 1500,
            tcp_window_bytes: 16 * 1024,
            max_tcp_connections: 128,
            max_udp_flows: flows + 1024,
            max_dns_in_flight: 32,
            idle_timeout: Duration::from_secs(300),
            connect_timeout: Duration::from_secs(10),
            dns: Arc::new(DnsPolicy::tcp(
                SocketAddr::from(([127, 0, 0, 1], 53)),
                Duration::from_secs(5),
            )),
        };
        let rss_before = rss_kb();
        let sink: PacketSink = Box::new(|_packet: &[u8]| {});
        let tunnel = Tunnel::start(settings, Arc::new(UdpHold), sink)?;
        thread::sleep(Duration::from_millis(500));
        let rss_started = rss_kb();

        // Feed every flow's first datagram; back off while the queue is full.
        let begin = Instant::now();
        let mut retries = 0u64;
        for index in 0..flows {
            let packet = udp_packet(index);
            while !tunnel.input_packet(&packet) {
                retries += 1;
                thread::sleep(Duration::from_micros(200));
            }
        }
        let fed_secs = begin.elapsed().as_secs_f64();
        // The tunnel closes a flow after 60 s without traffic: wait for the
        // flows to open, well inside that.
        let deadline = Instant::now() + Duration::from_secs(40);
        let mut snapshot = tunnel.stats();
        while (snapshot.udp_flows + snapshot.udp_failed + snapshot.udp_dropped) < flows as u64
            && Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(100));
            snapshot = tunnel.stats();
        }
        let open_secs = begin.elapsed().as_secs_f64();
        thread::sleep(Duration::from_secs(2));
        let rss_open = rss_kb();
        let snapshot = tunnel.stats();

        let report = json!({
            "flows": flows,
            "opened": snapshot.udp_flows,
            "failed": snapshot.udp_failed,
            "dropped": snapshot.udp_dropped,
            "input_retries": retries,
            "fed_secs": fed_secs,
            "open_secs": open_secs,
            "flows_per_s": snapshot.udp_flows as f64 / open_secs.max(1e-9),
            "rss_before_kb": rss_before,
            "rss_started_kb": rss_started,
            "rss_open_kb": rss_open,
            "per_flow_kb": (rss_open - rss_started) / flows.max(1) as f64,
            "max_rss_mb": args.get("max-rss-mb"),
            "tunnel": serde_json::to_value(&snapshot).unwrap_or(Value::Null),
        });
        let mut failures = Vec::new();
        if snapshot.udp_flows < flows as u64 {
            failures.push(format!(
                "{} of {flows} UDP flows opened ({} failed, {} dropped)",
                snapshot.udp_flows, snapshot.udp_failed, snapshot.udp_dropped
            ));
        }
        rss_limit(args, rss_open, &mut failures)?;
        drop(tunnel);
        verdict(args, report, failures)
    }
}
