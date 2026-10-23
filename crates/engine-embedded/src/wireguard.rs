//! WireGuard: IP packets from the TUN side are sealed straight into UDP
//! datagrams to one peer, with no userspace TCP/IP stack in between.
//!
//! The Noise state machine is boringtun's `Tunn` (BSD-3-Clause). This module
//! only moves bytes between the packet queue, one connected UDP socket and the
//! [`PacketSink`], and drives the handshake and keepalive timers. The peer's
//! `AllowedIPs` are applied by the Network Extension routes, not here.

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use engine_outbound::registry::{parse_settings, Settings};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::tunnel::{bump, PacketSink, TunnelStats};

pub const PROTOCOL: &str = "wireguard";
/// Config `type` name of a WireGuard outbound.
pub const TYPE_NAME: &str = "wireguard";

/// boringtun needs `src.len() + 32` and at least 148 bytes; a UDP datagram is
/// at most 64 KiB, so one buffer of this size fits every case.
const BUFFER_BYTES: usize = 65_536 + 148;
/// boringtun's timers have a 250 ms granularity.
const TIMER_TICK: Duration = Duration::from_millis(250);

/// Settings for one peer. Holds key material, so it has no `Debug`.
#[derive(Clone)]
pub struct WireGuardSettings {
    pub private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub server: String,
    pub port: u16,
    pub persistent_keepalive_secs: Option<u16>,
}

/// One WireGuard peer as it appears in the config. Keys are standard base64,
/// as in a `wg-quick` file; the private and preshared keys are injected from
/// the Keychain.
#[derive(Deserialize)]
struct WireGuardConfig {
    private_key: String,
    peer_public_key: String,
    #[serde(default)]
    preshared_key: Option<String>,
    server: String,
    port: u16,
    #[serde(default)]
    persistent_keepalive_secs: Option<u16>,
}

/// Parses and validates the settings of a `"type": "wireguard"` outbound.
pub fn settings_from(settings: &Settings) -> Result<WireGuardSettings, &'static str> {
    let config: WireGuardConfig =
        parse_settings(settings, "wireguard settings are missing or invalid")?;
    let private_key = decode_key(&config.private_key)
        .ok_or("wireguard private key must be 32 bytes of base64")?;
    let peer_public_key = decode_key(&config.peer_public_key)
        .ok_or("wireguard peer public key must be 32 bytes of base64")?;
    let preshared_key = match config.preshared_key.as_deref() {
        None | Some("") => None,
        Some(key) => {
            Some(decode_key(key).ok_or("wireguard preshared key must be 32 bytes of base64")?)
        }
    };
    let server = config.server.trim();
    if server.is_empty() || config.port == 0 {
        return Err("wireguard endpoint is invalid");
    }
    Ok(WireGuardSettings {
        private_key,
        peer_public_key,
        preshared_key,
        server: server.to_owned(),
        port: config.port,
        persistent_keepalive_secs: config.persistent_keepalive_secs,
    })
}

/// Decodes a standard base64 WireGuard key.
pub fn decode_key(encoded: &str) -> Option<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    bytes.try_into().ok()
}

fn resolve(server: &str, port: u16) -> io::Result<SocketAddr> {
    // The Network Extension's own sockets never route through the tunnel, so
    // the system resolver is safe to use for the endpoint.
    (server, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "endpoint did not resolve"))
}

fn session_index() -> io::Result<u32> {
    let mut bytes = [0u8; 4];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| io::Error::other("random index is unavailable"))?;
    // boringtun shifts the index left by 8 bits.
    Ok(u32::from_le_bytes(bytes) >> 8)
}

/// Starts the WireGuard tasks on the current tokio runtime.
pub(crate) fn spawn_tasks(
    settings: WireGuardSettings,
    sink: PacketSink,
    mut packet_rx: mpsc::Receiver<Vec<u8>>,
    stats: Arc<TunnelStats>,
) -> io::Result<()> {
    let endpoint = resolve(&settings.server, settings.port)?;
    let bind: SocketAddr = match endpoint {
        SocketAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = std::net::UdpSocket::bind(bind)?;
    socket.connect(endpoint)?;
    socket.set_nonblocking(true)?;
    let socket = Arc::new(UdpSocket::from_std(socket)?);

    let tunn = Arc::new(Mutex::new(Tunn::new(
        StaticSecret::from(settings.private_key),
        PublicKey::from(settings.peer_public_key),
        settings.preshared_key,
        settings.persistent_keepalive_secs.filter(|secs| *secs > 0),
        session_index()?,
        None,
    )));

    // TUN -> peer. The first packet also starts the handshake.
    let up_tunn = tunn.clone();
    let up_socket = socket.clone();
    let up_stats = stats.clone();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; BUFFER_BYTES];
        while let Some(packet) = packet_rx.recv().await {
            let result = lock(&up_tunn).encapsulate(&packet, &mut buffer);
            if let TunnResult::WriteToNetwork(datagram) = result {
                if up_socket.send(datagram).await.is_ok() {
                    up_stats
                        .bytes_up
                        .fetch_add(packet.len() as u64, Ordering::Relaxed);
                }
            }
        }
    });

    // Peer -> TUN.
    let down_tunn = tunn.clone();
    let down_socket = socket.clone();
    tokio::spawn(async move {
        let mut datagram = vec![0u8; BUFFER_BYTES];
        let mut buffer = vec![0u8; BUFFER_BYTES];
        let peer = Some(endpoint.ip());
        loop {
            let Ok(len) = down_socket.recv(&mut datagram).await else {
                // ICMP errors surface here on a connected socket; back off
                // instead of spinning while the peer is unreachable.
                tokio::time::sleep(TIMER_TICK).await;
                continue;
            };
            receive(
                &down_tunn,
                &down_socket,
                peer,
                &datagram[..len],
                &mut buffer,
                &sink,
                &stats,
            )
            .await;
        }
    });

    // Handshake, rekey and keepalive timers.
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 256];
        // Bind each result first: a guard held across an await would make the
        // task non-Send.
        let initiation = lock(&tunn).format_handshake_initiation(&mut buffer, false);
        if let TunnResult::WriteToNetwork(initiation) = initiation {
            let _ = socket.send(initiation).await;
        }
        let mut ticker = tokio::time::interval(TIMER_TICK);
        loop {
            ticker.tick().await;
            let result = lock(&tunn).update_timers(&mut buffer);
            if let TunnResult::WriteToNetwork(datagram) = result {
                let _ = socket.send(datagram).await;
            }
        }
    });

    Ok(())
}

async fn receive(
    tunn: &Mutex<Tunn>,
    socket: &UdpSocket,
    peer: Option<IpAddr>,
    datagram: &[u8],
    buffer: &mut [u8],
    sink: &PacketSink,
    stats: &TunnelStats,
) {
    let mut input = datagram;
    loop {
        let result = lock(tunn).decapsulate(peer, input, buffer);
        match result {
            // Handshake replies and queued packets: keep draining with an
            // empty datagram until boringtun reports it is done.
            TunnResult::WriteToNetwork(reply) => {
                let _ = socket.send(reply).await;
                input = &[];
            }
            TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                // A keepalive decrypts to an empty packet.
                if !packet.is_empty() {
                    bump(&stats.packets_out);
                    stats
                        .bytes_down
                        .fetch_add(packet.len() as u64, Ordering::Relaxed);
                    sink(packet);
                }
                return;
            }
            TunnResult::Done | TunnResult::Err(_) => return,
        }
    }
}

/// The lock is never held across an await, so a poisoned lock only means a
/// panic inside boringtun; keep using the state rather than stopping traffic.
fn lock(tunn: &Mutex<Tunn>) -> std::sync::MutexGuard<'_, Tunn> {
    tunn.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
