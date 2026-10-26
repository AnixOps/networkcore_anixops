//! Our server inbounds against the reference clients: Xray-core, sing-box
//! and the official Hysteria client each connect through a node built from
//! anixcore inbound configs and relay TCP and SOCKS5 UDP to echo targets
//! (UDP in each protocol's own form, or XUDP where the client uses it).
//!
//! The tests are `#[ignore]`d; the interop CI job runs them with
//! `--ignored` after `.github/scripts/reality-interop.sh start` has written
//! the environment:
//!
//! - `NC_INTEROP_BIN`: directory with `xray`, `sing-box` and `hysteria`
//!   (a missing binary skips that client)
//! - `NC_SERVER_CERT`, `NC_SERVER_KEY`, `NC_SERVER_NAME`: a self-signed
//!   certificate with that name, which the clients trust
//! - `NC_REALITY_PRIVATE_KEY`, `NC_REALITY_PUBLIC_KEY`, `NC_REALITY_SHORT_ID`,
//!   `NC_REALITY_SERVER_NAME`, `NC_REALITY_DEST`: REALITY settings and the
//!   camouflage target
//! - `NC_VLESS_UUID`, `NC_TCP_ECHO`, `NC_UDP_ECHO`

use std::fmt::Write as _;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use node_runtime::{default_registry, InboundConfig, Node};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const TIMEOUT: Duration = Duration::from_secs(15);
const SS_METHOD: &str = "2022-blake3-aes-128-gcm";
const SS_SERVER_KEY: &str = "AQIDBAUGBwgJCgsMDQ4PEA==";
const SS_USER_KEY: &str = "EA8ODQwLCgkIBwYFBAMCAQ==";
const PASSWORD: &str = "interop-password";
const OBFS_PASSWORD: &str = "interop-obfs";
const WS_PATH: &str = "/ws";
const GRPC_SERVICE: &str = "interop";

struct Env {
    bin: PathBuf,
    cert: String,
    key: String,
    server_name: String,
    reality_private_key: String,
    reality_public_key: String,
    reality_short_id: String,
    reality_server_name: String,
    reality_dest: SocketAddr,
    uuid: String,
    echo: SocketAddr,
    udp_echo: SocketAddr,
}

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

impl Env {
    fn load() -> Self {
        Self {
            bin: PathBuf::from(var("NC_INTEROP_BIN")),
            cert: var("NC_SERVER_CERT"),
            key: var("NC_SERVER_KEY"),
            server_name: var("NC_SERVER_NAME"),
            reality_private_key: var("NC_REALITY_PRIVATE_KEY"),
            reality_public_key: var("NC_REALITY_PUBLIC_KEY"),
            reality_short_id: var("NC_REALITY_SHORT_ID"),
            reality_server_name: var("NC_REALITY_SERVER_NAME"),
            reality_dest: var("NC_REALITY_DEST").parse().expect("NC_REALITY_DEST"),
            uuid: var("NC_VLESS_UUID"),
            echo: var("NC_TCP_ECHO").parse().expect("NC_TCP_ECHO"),
            udp_echo: var("NC_UDP_ECHO").parse().expect("NC_UDP_ECHO"),
        }
    }

    fn tls(&self, alpn: &[&str]) -> Value {
        json!({"certificate_path": self.cert, "key_path": self.key, "alpn": alpn})
    }
}

/// What a client must speak to one of our inbounds.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Proto {
    VlessReality { vision: bool },
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria2 { obfs: bool },
    Tuic,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Net {
    Tcp,
    Ws,
    Grpc,
}

struct Case {
    tag: &'static str,
    proto: Proto,
    net: Net,
    tls: bool,
}

const CASES: &[Case] = &[
    Case {
        tag: "vless-reality-vision",
        proto: Proto::VlessReality { vision: true },
        net: Net::Tcp,
        tls: false,
    },
    Case {
        tag: "vless-reality",
        proto: Proto::VlessReality { vision: false },
        net: Net::Tcp,
        tls: false,
    },
    Case {
        tag: "vless-tls-ws",
        proto: Proto::Vless,
        net: Net::Ws,
        tls: true,
    },
    Case {
        tag: "vless-tls-grpc",
        proto: Proto::Vless,
        net: Net::Grpc,
        tls: true,
    },
    Case {
        tag: "vmess-tcp",
        proto: Proto::Vmess,
        net: Net::Tcp,
        tls: false,
    },
    Case {
        tag: "vmess-ws",
        proto: Proto::Vmess,
        net: Net::Ws,
        tls: false,
    },
    Case {
        tag: "vmess-tls-grpc",
        proto: Proto::Vmess,
        net: Net::Grpc,
        tls: true,
    },
    Case {
        tag: "trojan-tls",
        proto: Proto::Trojan,
        net: Net::Tcp,
        tls: true,
    },
    Case {
        tag: "trojan-tls-ws",
        proto: Proto::Trojan,
        net: Net::Ws,
        tls: true,
    },
    Case {
        tag: "trojan-tls-grpc",
        proto: Proto::Trojan,
        net: Net::Grpc,
        tls: true,
    },
    Case {
        tag: "ss2022-multi-user",
        proto: Proto::Shadowsocks,
        net: Net::Tcp,
        tls: false,
    },
    Case {
        tag: "hysteria2",
        proto: Proto::Hysteria2 { obfs: false },
        net: Net::Tcp,
        tls: true,
    },
    Case {
        tag: "hysteria2-salamander",
        proto: Proto::Hysteria2 { obfs: true },
        net: Net::Tcp,
        tls: true,
    },
    Case {
        tag: "tuic",
        proto: Proto::Tuic,
        net: Net::Tcp,
        tls: true,
    },
];

/// The anixcore inbound config for `case`, on a free loopback port.
fn inbound(env: &Env, case: &Case) -> Value {
    let mut inbound = json!({"tag": case.tag, "listen": "127.0.0.1", "listen_port": 0});
    let object = inbound.as_object_mut().unwrap();
    let user = |extra: Value| {
        let mut user = json!({"name": "alice"});
        user.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        json!([user])
    };
    match case.proto {
        Proto::VlessReality { vision } => {
            object.insert("type".into(), "vless".into());
            let flow = if vision { "xtls-rprx-vision" } else { "" };
            object.insert(
                "users".into(),
                user(json!({"uuid": env.uuid, "flow": flow})),
            );
            object.insert(
                "reality".into(),
                json!({
                    "private_key": env.reality_private_key,
                    "short_ids": [env.reality_short_id],
                    "server_names": [env.reality_server_name],
                    "handshake": {
                        "server": env.reality_dest.ip().to_string(),
                        "server_port": env.reality_dest.port(),
                    },
                }),
            );
        }
        Proto::Vless => {
            object.insert("type".into(), "vless".into());
            object.insert("users".into(), user(json!({"uuid": env.uuid})));
        }
        Proto::Vmess => {
            object.insert("type".into(), "vmess".into());
            object.insert("users".into(), user(json!({"uuid": env.uuid})));
        }
        Proto::Trojan => {
            object.insert("type".into(), "trojan".into());
            object.insert("users".into(), user(json!({"password": PASSWORD})));
        }
        Proto::Shadowsocks => {
            object.insert("type".into(), "shadowsocks".into());
            object.insert("method".into(), SS_METHOD.into());
            object.insert("password".into(), SS_SERVER_KEY.into());
            object.insert("users".into(), user(json!({"password": SS_USER_KEY})));
        }
        Proto::Hysteria2 { obfs } => {
            object.insert("type".into(), "hysteria2".into());
            object.insert("users".into(), user(json!({"password": PASSWORD})));
            if obfs {
                object.insert(
                    "obfs".into(),
                    json!({"type": "salamander", "password": OBFS_PASSWORD}),
                );
            }
        }
        Proto::Tuic => {
            object.insert("type".into(), "tuic".into());
            object.insert(
                "users".into(),
                user(json!({"uuid": env.uuid, "password": PASSWORD})),
            );
            object.insert("congestion_control".into(), "bbr".into());
        }
    }
    match case.net {
        Net::Tcp => {}
        Net::Ws => {
            object.insert("transport".into(), json!({"type": "ws", "path": WS_PATH}));
        }
        Net::Grpc => {
            object.insert(
                "transport".into(),
                json!({"type": "grpc", "service_name": GRPC_SERVICE}),
            );
        }
    }
    if case.tls {
        let alpn: &[&str] = match case.proto {
            Proto::Hysteria2 { .. } | Proto::Tuic => &["h3"],
            _ => &[],
        };
        object.insert("tls".into(), env.tls(alpn));
    }
    inbound
}

#[derive(Clone, Copy, Debug)]
enum Client {
    Xray,
    SingBox,
    Hysteria,
}

impl Client {
    fn binary(self) -> &'static str {
        match self {
            Client::Xray => "xray",
            Client::SingBox => "sing-box",
            Client::Hysteria => "hysteria",
        }
    }

    fn config_extension(self) -> &'static str {
        match self {
            Client::Xray | Client::SingBox => "json",
            Client::Hysteria => "yaml",
        }
    }

    fn supports(self, case: &Case) -> bool {
        match self {
            Client::Xray => !matches!(case.proto, Proto::Hysteria2 { .. } | Proto::Tuic),
            Client::SingBox => true,
            Client::Hysteria => matches!(case.proto, Proto::Hysteria2 { .. }),
        }
    }

    /// Config file contents and the arguments that run it.
    fn config(
        self,
        env: &Env,
        case: &Case,
        server: SocketAddr,
        socks: u16,
    ) -> (String, Vec<&'static str>) {
        match self {
            Client::Xray => (
                xray_config(env, case, server, socks).to_string(),
                vec!["run", "-c"],
            ),
            Client::SingBox => (
                sing_box_config(env, case, server, socks).to_string(),
                vec!["run", "-c"],
            ),
            Client::Hysteria => (
                hysteria_config(env, case, server, socks),
                vec!["client", "-c"],
            ),
        }
    }
}

fn xray_config(env: &Env, case: &Case, server: SocketAddr, socks: u16) -> Value {
    let address = server.ip().to_string();
    let port = server.port();
    let (protocol, settings) = match case.proto {
        Proto::VlessReality { vision } => (
            "vless",
            json!({"vnext": [{"address": address, "port": port, "users": [{
                "id": env.uuid, "encryption": "none",
                "flow": if vision { "xtls-rprx-vision" } else { "" },
            }]}]}),
        ),
        Proto::Vless => (
            "vless",
            json!({"vnext": [{"address": address, "port": port,
                "users": [{"id": env.uuid, "encryption": "none"}]}]}),
        ),
        Proto::Vmess => (
            "vmess",
            json!({"vnext": [{"address": address, "port": port,
                "users": [{"id": env.uuid, "security": "aes-128-gcm"}]}]}),
        ),
        Proto::Trojan => (
            "trojan",
            json!({"servers": [{"address": address, "port": port, "password": PASSWORD}]}),
        ),
        Proto::Shadowsocks => (
            "shadowsocks",
            json!({"servers": [{"address": address, "port": port, "method": SS_METHOD,
                "password": format!("{SS_SERVER_KEY}:{SS_USER_KEY}")}]}),
        ),
        Proto::Hysteria2 { .. } | Proto::Tuic => unreachable!("not an Xray client case"),
    };
    let mut stream = json!({"network": match case.net {
        Net::Tcp => "tcp",
        Net::Ws => "ws",
        Net::Grpc => "grpc",
    }});
    let stream_object = stream.as_object_mut().unwrap();
    match case.net {
        Net::Tcp => {}
        // `?ed=` sends the first bytes in the upgrade request (early data).
        Net::Ws => {
            stream_object.insert(
                "wsSettings".into(),
                json!({"path": format!("{WS_PATH}?ed=2048"), "host": env.server_name}),
            );
        }
        Net::Grpc => {
            stream_object.insert("grpcSettings".into(), json!({"serviceName": GRPC_SERVICE}));
        }
    }
    if let Proto::VlessReality { .. } = case.proto {
        stream_object.insert("security".into(), "reality".into());
        stream_object.insert(
            "realitySettings".into(),
            json!({
                "serverName": env.reality_server_name,
                "fingerprint": "chrome",
                "publicKey": env.reality_public_key,
                "shortId": env.reality_short_id,
            }),
        );
    } else if case.tls {
        stream_object.insert("security".into(), "tls".into());
        stream_object.insert(
            "tlsSettings".into(),
            json!({
                "serverName": env.server_name,
                "certificates": [{"usage": "verify", "certificateFile": env.cert}],
            }),
        );
    }
    json!({
        "log": {"loglevel": "debug"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks, "protocol": "socks",
            "settings": {"auth": "noauth", "udp": true, "ip": "127.0.0.1"}}],
        "outbounds": [{"protocol": protocol, "settings": settings, "streamSettings": stream}],
    })
}

fn sing_box_config(env: &Env, case: &Case, server: SocketAddr, socks: u16) -> Value {
    let mut outbound = json!({
        "tag": "proxy",
        "server": server.ip().to_string(),
        "server_port": server.port(),
    });
    let object = outbound.as_object_mut().unwrap();
    let tls = |alpn: &[&str]| {
        let mut tls = json!({
            "enabled": true,
            "server_name": env.server_name,
            "certificate_path": env.cert,
        });
        if !alpn.is_empty() {
            tls["alpn"] = json!(alpn);
        }
        tls
    };
    match case.proto {
        Proto::VlessReality { vision } => {
            object.insert("type".into(), "vless".into());
            object.insert("uuid".into(), env.uuid.clone().into());
            object.insert(
                "flow".into(),
                Value::from(if vision { "xtls-rprx-vision" } else { "" }),
            );
            object.insert(
                "tls".into(),
                json!({
                    "enabled": true,
                    "server_name": env.reality_server_name,
                    "utls": {"enabled": true, "fingerprint": "chrome"},
                    "reality": {"enabled": true, "public_key": env.reality_public_key,
                        "short_id": env.reality_short_id},
                }),
            );
        }
        Proto::Vless => {
            object.insert("type".into(), "vless".into());
            object.insert("uuid".into(), env.uuid.clone().into());
        }
        Proto::Vmess => {
            object.insert("type".into(), "vmess".into());
            object.insert("uuid".into(), env.uuid.clone().into());
            object.insert("security".into(), "aes-128-gcm".into());
            object.insert("alter_id".into(), 0.into());
        }
        Proto::Trojan => {
            object.insert("type".into(), "trojan".into());
            object.insert("password".into(), PASSWORD.into());
        }
        Proto::Shadowsocks => {
            object.insert("type".into(), "shadowsocks".into());
            object.insert("method".into(), SS_METHOD.into());
            object.insert(
                "password".into(),
                format!("{SS_SERVER_KEY}:{SS_USER_KEY}").into(),
            );
        }
        Proto::Hysteria2 { obfs } => {
            object.insert("type".into(), "hysteria2".into());
            object.insert("password".into(), PASSWORD.into());
            if obfs {
                object.insert(
                    "obfs".into(),
                    json!({"type": "salamander", "password": OBFS_PASSWORD}),
                );
            }
        }
        Proto::Tuic => {
            object.insert("type".into(), "tuic".into());
            object.insert("uuid".into(), env.uuid.clone().into());
            object.insert("password".into(), PASSWORD.into());
            object.insert("congestion_control".into(), "bbr".into());
        }
    }
    match case.net {
        Net::Tcp => {}
        Net::Ws => {
            object.insert(
                "transport".into(),
                json!({"type": "ws", "path": WS_PATH, "max_early_data": 2048,
                    "early_data_header_name": "Sec-WebSocket-Protocol",
                    "headers": {"Host": env.server_name}}),
            );
        }
        Net::Grpc => {
            object.insert(
                "transport".into(),
                json!({"type": "grpc", "service_name": GRPC_SERVICE}),
            );
        }
    }
    if case.tls {
        let alpn: &[&str] = match (case.proto, case.net) {
            (Proto::Hysteria2 { .. } | Proto::Tuic, _) => &["h3"],
            (_, Net::Grpc) => &["h2"],
            _ => &[],
        };
        object.insert("tls".into(), tls(alpn));
    }
    json!({
        "log": {"level": "debug"},
        "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": socks}],
        "outbounds": [outbound],
    })
}

fn hysteria_config(env: &Env, case: &Case, server: SocketAddr, socks: u16) -> String {
    let mut config = format!(
        "server: {server}\nauth: {PASSWORD}\ntls:\n  sni: {}\n  ca: {}\nsocks5:\n  listen: 127.0.0.1:{socks}\n",
        env.server_name, env.cert
    );
    if let Proto::Hysteria2 { obfs: true } = case.proto {
        write!(
            config,
            "obfs:\n  type: salamander\n  salamander:\n    password: {OBFS_PASSWORD}\n"
        )
        .unwrap();
    }
    config
}

/// A client process, killed when dropped.
struct Running {
    child: Child,
    log: PathBuf,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Running {
    fn log_tail(&self) -> String {
        let log = std::fs::read_to_string(&self.log).unwrap_or_default();
        let lines: Vec<&str> = log.lines().collect();
        lines[lines.len().saturating_sub(40)..].join("\n")
    }
}

fn free_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn spawn(binary: &Path, args: &[&str], config: &Path, log: PathBuf) -> std::io::Result<Running> {
    let output = std::fs::File::create(&log)?;
    let child = Command::new(binary)
        .args(args)
        .arg(config)
        .stdin(Stdio::null())
        .stdout(output.try_clone()?)
        .stderr(output)
        .spawn()?;
    Ok(Running { child, log })
}

async fn wait_for_port(port: u16) -> bool {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// SOCKS5 CONNECT to `target` through the client on `socks`.
async fn socks_connect(socks: u16, target: SocketAddr) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", socks)).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply != [5, 0] {
        return Err(std::io::Error::other(format!(
            "socks greeting reply {reply:?}"
        )));
    }
    let SocketAddr::V4(target) = target else {
        return Err(std::io::Error::other("the echo target must be IPv4"));
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&target.ip().octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[1] != 0 {
        return Err(std::io::Error::other(format!(
            "socks connect reply {}",
            head[1]
        )));
    }
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0]) + 2
        }
        other => return Err(std::io::Error::other(format!("socks address type {other}"))),
    };
    let mut bound = vec![0u8; rest];
    stream.read_exact(&mut bound).await?;
    Ok(stream)
}

/// Sends `payload` through the client and checks the echo.
async fn echo(socks: u16, target: SocketAddr, payload: &[u8]) -> Result<(), String> {
    let stream = tokio::time::timeout(TIMEOUT, socks_connect(socks, target))
        .await
        .map_err(|_| "socks connect timed out".to_owned())?
        .map_err(|error| format!("socks connect: {error}"))?;
    let (mut reader, mut writer) = stream.into_split();
    let write = async {
        writer.write_all(payload).await?;
        writer.flush().await
    };
    let mut received = vec![0u8; payload.len()];
    let read = reader.read_exact(&mut received);
    let (written, read) = tokio::time::timeout(TIMEOUT, async { tokio::join!(write, read) })
        .await
        .map_err(|_| "echo timed out".to_owned())?;
    written.map_err(|error| format!("write: {error}"))?;
    read.map_err(|error| format!("read: {error}"))?;
    if received != payload {
        return Err("echo differs from what was sent".to_owned());
    }
    Ok(())
}

/// SOCKS5 UDP ASSOCIATE through the client on `socks`, then datagrams to
/// the UDP echo `target`. Returns the payload bytes echoed.
async fn udp_echo(socks: u16, target: SocketAddr) -> Result<u64, String> {
    let SocketAddr::V4(target) = target else {
        return Err("the udp echo target must be IPv4".to_owned());
    };
    let associate = async {
        let mut control = TcpStream::connect(("127.0.0.1", socks)).await?;
        control.write_all(&[5, 1, 0]).await?;
        let mut reply = [0u8; 2];
        control.read_exact(&mut reply).await?;
        if reply != [5, 0] {
            return Err(std::io::Error::other(format!(
                "socks greeting reply {reply:?}"
            )));
        }
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let mut head = [0u8; 4];
        control.read_exact(&mut head).await?;
        if head[1] != 0 {
            return Err(std::io::Error::other(format!(
                "socks udp associate reply {}",
                head[1]
            )));
        }
        if head[3] != 1 {
            return Err(std::io::Error::other(format!(
                "socks relay address type {}",
                head[3]
            )));
        }
        let mut bound = [0u8; 6];
        control.read_exact(&mut bound).await?;
        let mut ip = std::net::Ipv4Addr::new(bound[0], bound[1], bound[2], bound[3]);
        if ip.is_unspecified() {
            ip = std::net::Ipv4Addr::LOCALHOST;
        }
        let relay = SocketAddr::from((ip, u16::from_be_bytes([bound[4], bound[5]])));
        Ok((control, relay))
    };
    let (_control, relay) = tokio::time::timeout(TIMEOUT, associate)
        .await
        .map_err(|_| "socks udp associate timed out".to_owned())?
        .map_err(|error| format!("socks udp associate: {error}"))?;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .map_err(|error| format!("udp bind: {error}"))?;
    let mut header = vec![0, 0, 0, 1];
    header.extend_from_slice(&target.ip().octets());
    header.extend_from_slice(&target.port().to_be_bytes());
    let mut echoed = 0u64;
    for (index, size) in [64usize, 1200, 8].into_iter().enumerate() {
        let payload: Vec<u8> = (0..size).map(|i| (i * 7 + index) as u8).collect();
        let mut datagram = header.clone();
        datagram.extend_from_slice(&payload);
        let mut answered = false;
        // The first datagram can race the relay's session setup; resend.
        for _ in 0..5 {
            socket
                .send_to(&datagram, relay)
                .await
                .map_err(|error| format!("udp send: {error}"))?;
            let mut buf = vec![0u8; 65536];
            let Ok(received) =
                tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await
            else {
                continue;
            };
            let (len, _) = received.map_err(|error| format!("udp recv: {error}"))?;
            let reply = &buf[..len];
            // RSV RSV FRAG ATYP, then the source address in any form.
            let header_len = match reply.get(3) {
                Some(1) => 4 + 4 + 2,
                Some(4) => 4 + 16 + 2,
                Some(3) => 4 + 1 + usize::from(reply.get(4).copied().unwrap_or(0)) + 2,
                _ => usize::MAX,
            };
            if reply.len() < header_len || reply[..3] != [0, 0, 0] {
                return Err(format!(
                    "udp reply has a bad SOCKS5 header: {:?}",
                    &reply[..len.min(10)]
                ));
            }
            if reply[header_len..] != payload[..] {
                return Err(format!(
                    "udp echo of {size} bytes differs from what was sent"
                ));
            }
            answered = true;
            break;
        }
        if !answered {
            return Err(format!("no udp echo for a {size} byte datagram"));
        }
        echoed += size as u64;
    }
    Ok(echoed)
}

async fn run_client(
    env: &Env,
    node: &Node,
    client: Client,
    case: &Case,
    server: SocketAddr,
    dir: &Path,
) -> Result<(), String> {
    let binary = env.bin.join(client.binary());
    let socks = free_port();
    let (config, args) = client.config(env, case, server, socks);
    let name = format!("{}-{}", client.binary(), case.tag);
    // The clients pick the config format from the extension.
    let path = dir.join(format!("{name}.{}", client.config_extension()));
    std::fs::write(&path, config).map_err(|error| format!("write config: {error}"))?;
    let running = spawn(&binary, &args, &path, dir.join(format!("{name}.log")))
        .map_err(|error| format!("start {}: {error}", binary.display()))?;
    let before = traffic(node, case.tag);
    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i * 31 % 251) as u8).collect();
    let result = async {
        if !wait_for_port(socks).await {
            return Err("client socks port did not open".to_owned());
        }
        echo(socks, env.echo, &payload).await?;
        echo(socks, env.echo, b"second connection").await?;
        // Xray sends VLESS and VMess UDP as XUDP (Mux.Cool), as does
        // sing-box for VLESS; the others use each protocol's UDP form.
        let udp = udp_echo(socks, env.udp_echo).await?;
        // Relayed bytes are charged to the user once the relay sees them.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let (up, down) = traffic(node, case.tag);
        let expected = (payload.len() + "second connection".len()) as u64 + udp;
        if up - before.0 < expected || down - before.1 < expected {
            return Err(format!(
                "user traffic up {} down {}, expected at least {expected} each way",
                up - before.0,
                down - before.1
            ));
        }
        Ok(())
    }
    .await;
    result.map_err(|error| format!("{error}\n--- {name}.log ---\n{}", running.log_tail()))
}

fn traffic(node: &Node, tag: &str) -> (u64, u64) {
    node.users(tag)
        .unwrap()
        .traffic(false)
        .iter()
        .filter(|entry| entry.name == "alice")
        .fold((0, 0), |(up, down), entry| {
            (up + entry.up, down + entry.down)
        })
}

async fn interop(client: Client) {
    let env = Env::load();
    let binary = env.bin.join(client.binary());
    if !binary.exists() {
        eprintln!(
            "skipping {}: {} is missing",
            client.binary(),
            binary.display()
        );
        return;
    }
    let dir = std::env::temp_dir().join(format!("nc-client-interop-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let node = Arc::new(Node::new(default_registry(), true));
    let mut failures = Vec::new();
    let mut passed = 0;
    for case in CASES.iter().filter(|case| client.supports(case)) {
        let config: InboundConfig = serde_json::from_value(inbound(&env, case)).unwrap();
        let server = match node.add_inbound(config).await {
            Ok(server) => server,
            Err(error) => {
                failures.push(format!("{}: inbound: {error}", case.tag));
                continue;
            }
        };
        match run_client(&env, &node, client, case, server, &dir).await {
            Ok(()) => {
                eprintln!("ok   {} -> {}", client.binary(), case.tag);
                passed += 1;
            }
            Err(error) => {
                eprintln!("FAIL {} -> {}", client.binary(), case.tag);
                failures.push(format!("{}: {error}", case.tag));
            }
        }
        let _ = node.remove_inbound(case.tag);
    }
    assert!(
        failures.is_empty(),
        "{} -> our inbounds: {passed} passed, {} failed\n\n{}",
        client.binary(),
        failures.len(),
        failures.join("\n\n")
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the interop environment (.github/scripts/reality-interop.sh)"]
async fn xray_clients() {
    interop(Client::Xray).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the interop environment (.github/scripts/reality-interop.sh)"]
async fn sing_box_clients() {
    interop(Client::SingBox).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the interop environment (.github/scripts/reality-interop.sh)"]
async fn hysteria_clients() {
    interop(Client::Hysteria).await;
}
