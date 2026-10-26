//! UDP relay for one authenticated TUIC connection.
//!
//! Packet commands arrive as QUIC datagrams (native mode) or alone on
//! unidirectional streams (quic mode); see `outbound_tuic::udp`. Each
//! association id gets its own socket through a [`SessionRelay`], and its
//! replies go back in the mode of the association's latest packet. Dissociate
//! ends an association; all of them end with the connection.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use engine_inbound::server::InboundStats;
use engine_inbound::udp::{ReplySink, SessionRelay, UdpOutbound, MAX_SESSIONS};
use engine_inbound::UserEntry;
use engine_outbound::{BoxFuture, TargetAddr};
use outbound_tuic::udp::{
    encode_packet, random_packet_id, Defragger, TuicPacket, CMD_PACKET, MAX_PACKET_COMMAND,
};
use outbound_tuic::VERSION;
use transport_quic::quinn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Native,
    Quic,
}

pub(crate) struct UdpRelay {
    relay: Arc<SessionRelay>,
    user: Arc<UserEntry>,
    sink: Arc<PacketSink>,
    defraggers: Mutex<HashMap<u16, Defragger>>,
}

impl UdpRelay {
    pub(crate) fn new(
        connection: quinn::Connection,
        outbound: Arc<dyn UdpOutbound>,
        user: Arc<UserEntry>,
        stats: Arc<InboundStats>,
    ) -> Arc<Self> {
        let sink = Arc::new(PacketSink {
            connection,
            modes: Mutex::default(),
            packet_id: AtomicU16::new(random_packet_id()),
        });
        Arc::new(Self {
            relay: SessionRelay::new(outbound, sink.clone(), stats),
            user,
            sink,
            defraggers: Mutex::default(),
        })
    }

    /// Relays the connection's datagrams until it closes, then ends every
    /// association.
    pub(crate) async fn run_datagrams(self: Arc<Self>) {
        while let Ok(datagram) = self.sink.connection.read_datagram().await {
            // Heartbeats and anything else that is not a packet are dropped.
            if datagram.len() < 2 || datagram[0] != VERSION || datagram[1] != CMD_PACKET {
                continue;
            }
            if let Some(packet) = TuicPacket::parse(&datagram) {
                self.packet(packet, Mode::Native).await;
            }
        }
        self.close();
    }

    /// Handles a Packet command read from a unidirectional stream, whose
    /// `VER TYPE` was already read.
    pub(crate) async fn stream_packet(self: Arc<Self>, mut recv: quinn::RecvStream) {
        let Ok(rest) = recv.read_to_end(MAX_PACKET_COMMAND - 2).await else {
            return;
        };
        let mut command = Vec::with_capacity(2 + rest.len());
        command.extend_from_slice(&[VERSION, CMD_PACKET]);
        command.extend_from_slice(&rest);
        if let Some(packet) = TuicPacket::parse(&command) {
            self.packet(packet, Mode::Quic).await;
        }
    }

    pub(crate) fn dissociate(&self, assoc_id: u16) {
        self.relay.dissociate(u64::from(assoc_id));
        lock(&self.defraggers).remove(&assoc_id);
        lock(&self.sink.modes).remove(&assoc_id);
    }

    pub(crate) fn close(&self) {
        self.relay.close();
        lock(&self.defraggers).clear();
    }

    async fn packet(&self, packet: TuicPacket, mode: Mode) {
        let assoc_id = packet.assoc_id;
        let whole = if packet.frag_total <= 1 {
            Some(packet)
        } else {
            let mut defraggers = lock(&self.defraggers);
            if !defraggers.contains_key(&assoc_id) && defraggers.len() >= MAX_SESSIONS {
                defraggers.clear();
            }
            defraggers.entry(assoc_id).or_default().feed(packet)
        };
        let Some(TuicPacket {
            address: Some(target),
            payload,
            ..
        }) = whole
        else {
            return;
        };
        {
            let mut modes = lock(&self.sink.modes);
            if modes.len() < MAX_SESSIONS || modes.contains_key(&assoc_id) {
                modes.insert(assoc_id, mode);
            }
        }
        self.relay
            .send(u64::from(assoc_id), Some(&self.user), &target, &payload)
            .await;
    }
}

struct PacketSink {
    connection: quinn::Connection,
    modes: Mutex<HashMap<u16, Mode>>,
    packet_id: AtomicU16,
}

impl ReplySink for PacketSink {
    fn reply<'a>(
        &'a self,
        session: u64,
        source: SocketAddr,
        payload: &'a [u8],
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let assoc_id = session as u16;
            let mode = lock(&self.modes)
                .get(&assoc_id)
                .copied()
                .unwrap_or(Mode::Native);
            let packet_id = self.packet_id.fetch_add(1, Ordering::Relaxed);
            let source = TargetAddr::Ip(source);
            match mode {
                Mode::Native => {
                    let Some(max_size) = self.connection.max_datagram_size() else {
                        return false;
                    };
                    for datagram in
                        encode_packet(assoc_id, packet_id, &source, payload, Some(max_size))
                    {
                        match self.connection.send_datagram(datagram) {
                            Ok(()) => {}
                            Err(quinn::SendDatagramError::ConnectionLost(_)) => return false,
                            // Too large or not allowed right now: drop it.
                            Err(_) => break,
                        }
                    }
                    true
                }
                Mode::Quic => {
                    let Some(command) = encode_packet(assoc_id, packet_id, &source, payload, None)
                        .into_iter()
                        .next()
                    else {
                        return true;
                    };
                    let Ok(mut stream) = self.connection.open_uni().await else {
                        return false;
                    };
                    if stream.write_all(&command).await.is_err() {
                        return false;
                    }
                    stream.finish().is_ok()
                }
            }
        })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
