//! WireGuard tunnel tests against an in-process boringtun peer that reflects
//! every UDP packet back to its sender.

#![cfg(feature = "wireguard")]

use std::net::UdpSocket;
use std::sync::mpsc::{self, Receiver};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use engine_embedded::tunnel::PacketSink;
use engine_embedded::{EmbeddedRuntime, RuntimeErrorCode, RuntimeState};
use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};

const CLIENT_KEY: [u8; 32] = [7; 32];
const PEER_KEY: [u8; 32] = [9; 32];
const PRESHARED: [u8; 32] = [3; 32];
const APP: [u8; 4] = [10, 7, 0, 2];
const REMOTE: [u8; 4] = [10, 7, 0, 1];
const WAIT: Duration = Duration::from_secs(10);

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn public_key(private: [u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(private)).to_bytes()
}

fn config(port: u16, preshared: Option<&str>) -> Vec<u8> {
    let mut outbound = serde_json::json!({
        "type": "wireguard",
        "private_key": b64(&CLIENT_KEY),
        "peer_public_key": b64(&public_key(PEER_KEY)),
        "server": "127.0.0.1",
        "port": port,
        "persistent_keepalive_secs": 25,
    });
    if let Some(preshared) = preshared {
        outbound["preshared_key"] = preshared.into();
    }
    serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "profile_id": "wg-test",
        "mtu": 1420,
        "outbound": outbound,
    }))
    .unwrap()
}

/// Swaps the addresses and ports of a UDP/IPv4 packet.
fn reflect(packet: &[u8]) -> Option<Vec<u8>> {
    let sliced = SlicedPacket::from_ip(packet).ok()?;
    let Some(etherparse::NetSlice::Ipv4(ip)) = &sliced.net else {
        return None;
    };
    let Some(TransportSlice::Udp(udp)) = &sliced.transport else {
        return None;
    };
    let mut reply = Vec::new();
    PacketBuilder::ipv4(ip.header().destination(), ip.header().source(), 64)
        .udp(udp.destination_port(), udp.source_port())
        .write(&mut reply, udp.payload())
        .ok()?;
    Some(reply)
}

/// Runs a WireGuard peer on a loopback UDP socket until the test process exits.
fn start_peer(preshared: Option<[u8; 32]>) -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    thread::spawn(move || {
        let mut tunn = Tunn::new(
            StaticSecret::from(PEER_KEY),
            PublicKey::from(public_key(CLIENT_KEY)),
            preshared,
            None,
            1,
            None,
        );
        let mut datagram = vec![0u8; 65_536];
        let mut out = vec![0u8; 65_536 + 148];
        let mut sealed = vec![0u8; 65_536 + 148];
        loop {
            let Ok((len, from)) = socket.recv_from(&mut datagram) else {
                return;
            };
            let mut input = &datagram[..len];
            loop {
                match tunn.decapsulate(Some(from.ip()), input, &mut out) {
                    TunnResult::WriteToNetwork(reply) => {
                        let _ = socket.send_to(reply, from);
                        input = &[];
                    }
                    TunnResult::WriteToTunnelV4(packet, _) => {
                        if let Some(reply) = reflect(packet) {
                            if let TunnResult::WriteToNetwork(data) =
                                tunn.encapsulate(&reply, &mut sealed)
                            {
                                let _ = socket.send_to(data, from);
                            }
                        }
                        break;
                    }
                    _ => break,
                }
            }
        }
    });
    port
}

fn capture() -> (PacketSink, Receiver<Vec<u8>>) {
    let (tx, rx) = mpsc::channel();
    let tx = Mutex::new(tx);
    let sink: PacketSink = Box::new(move |packet: &[u8]| {
        let _ = tx.lock().unwrap().send(packet.to_vec());
    });
    (sink, rx)
}

fn udp_packet(payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::new();
    PacketBuilder::ipv4(APP, REMOTE, 64)
        .udp(40000, 9000)
        .write(&mut packet, payload)
        .unwrap();
    packet
}

/// Sends packets until the reflected one comes back: the first ones may be
/// queued behind the handshake.
fn round_trip(runtime: &EmbeddedRuntime, rx: &Receiver<Vec<u8>>, payload: &[u8]) {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        assert!(runtime.input_packet(&udp_packet(payload)));
        while let Ok(packet) = rx.recv_timeout(Duration::from_millis(200)) {
            let sliced = SlicedPacket::from_ip(&packet).unwrap();
            if let Some(TransportSlice::Udp(udp)) = &sliced.transport {
                assert_eq!(udp.source_port(), 9000);
                assert_eq!(udp.destination_port(), 40000);
                assert_eq!(udp.payload(), payload);
                return;
            }
        }
    }
    panic!("reflected packet did not come back through the tunnel");
}

#[test]
fn packets_round_trip_through_a_wireguard_peer() {
    let port = start_peer(None);
    let mut runtime = EmbeddedRuntime::from_json(&config(port, None)).unwrap();
    let (sink, rx) = capture();
    runtime.start(sink).unwrap();

    round_trip(&runtime, &rx, b"hello through wireguard");
    round_trip(&runtime, &rx, &[0x5a; 1200]);

    let status = runtime.status();
    assert_eq!(status.outbound, "wireguard");
    assert_eq!(status.state, RuntimeState::Running);
    assert!(status.stats.packets_out >= 2);
    assert!(status.stats.bytes_down > 0);
    runtime.stop();
    runtime.stop();
    assert_eq!(runtime.status().state, RuntimeState::Stopped);
}

#[test]
fn preshared_key_is_used() {
    let port = start_peer(Some(PRESHARED));
    let mut runtime = EmbeddedRuntime::from_json(&config(port, Some(&b64(&PRESHARED)))).unwrap();
    let (sink, rx) = capture();
    runtime.start(sink).unwrap();
    round_trip(&runtime, &rx, b"with psk");
    runtime.stop();
}

#[test]
fn invalid_keys_are_rejected_without_echoing_them() {
    let mut bad = serde_json::from_slice::<serde_json::Value>(&config(51820, None)).unwrap();
    bad["outbound"]["private_key"] = "c2hvcnQ=".into();
    let err = match EmbeddedRuntime::from_json(&serde_json::to_vec(&bad).unwrap()) {
        Ok(_) => panic!("a short key must be rejected"),
        Err(err) => err,
    };
    assert_eq!(err.code, RuntimeErrorCode::ConfigRejected);
    assert!(!err.message.contains("c2hvcnQ"));

    let mut bad = serde_json::from_slice::<serde_json::Value>(&config(51820, None)).unwrap();
    bad["outbound"]["port"] = 0.into();
    assert!(EmbeddedRuntime::from_json(&serde_json::to_vec(&bad).unwrap()).is_err());
}

#[test]
fn status_never_contains_key_material() {
    let runtime = EmbeddedRuntime::from_json(&config(51820, Some(&b64(&PRESHARED)))).unwrap();
    let status = serde_json::to_string(&runtime.status()).unwrap();
    for secret in [
        b64(&CLIENT_KEY),
        b64(&PRESHARED),
        b64(&public_key(PEER_KEY)),
    ] {
        assert!(!status.contains(&secret));
    }
    assert!(!status.contains("127.0.0.1"));
}
