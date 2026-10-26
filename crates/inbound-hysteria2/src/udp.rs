//! UDP relay for one authenticated Hysteria2 connection.
//!
//! The client's datagrams carry UDP messages (`outbound_hysteria2::udp`).
//! Each session id gets its own socket from the inbound's [`UdpOutbound`]
//! through a [`SessionRelay`]; replies go back as messages with the source
//! address, fragmented to the connection's datagram limit. Sessions end
//! after two idle minutes and all of them with the connection, which closes
//! when the user is removed.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use engine_inbound::server::InboundStats;
use engine_inbound::udp::{ReplySink, SessionRelay, UdpOutbound, MAX_SESSIONS};
use engine_inbound::UserEntry;
use engine_outbound::BoxFuture;
use outbound_hysteria2::udp::{encode_message, random_packet_id, Defragger, UdpMessage};
use transport_quic::quinn;

use crate::parse_address;

/// Relays the connection's datagrams until it closes.
pub(crate) async fn relay(
    connection: quinn::Connection,
    outbound: Arc<dyn UdpOutbound>,
    user: Arc<UserEntry>,
    stats: Arc<InboundStats>,
) {
    let sink = Arc::new(DatagramSink {
        connection: connection.clone(),
        packet_id: AtomicU16::new(random_packet_id()),
    });
    let relay = SessionRelay::new(outbound, sink, stats);
    // Only fragmented packets need reassembly state.
    let mut defraggers: HashMap<u32, Defragger> = HashMap::new();
    while let Ok(datagram) = connection.read_datagram().await {
        let Some(message) = UdpMessage::parse(&datagram) else {
            continue;
        };
        let session = message.session_id;
        let whole = if message.frag_count <= 1 {
            Some(message)
        } else {
            if !defraggers.contains_key(&session) && defraggers.len() >= MAX_SESSIONS {
                defraggers.clear();
            }
            defraggers.entry(session).or_default().feed(message)
        };
        let Some(whole) = whole else {
            continue;
        };
        if let Some(target) = parse_address(&whole.address) {
            relay
                .send(u64::from(session), Some(&user), &target, &whole.payload)
                .await;
        }
    }
    relay.close();
}

struct DatagramSink {
    connection: quinn::Connection,
    packet_id: AtomicU16,
}

impl ReplySink for DatagramSink {
    fn reply<'a>(
        &'a self,
        session: u64,
        source: SocketAddr,
        payload: &'a [u8],
    ) -> BoxFuture<'a, bool> {
        Box::pin(async move {
            let Some(max_size) = self.connection.max_datagram_size() else {
                return false;
            };
            let packet_id = self.packet_id.fetch_add(1, Ordering::Relaxed).max(1);
            let session = session as u32;
            for datagram in
                encode_message(session, packet_id, &source.to_string(), payload, max_size)
            {
                match self.connection.send_datagram(datagram) {
                    Ok(()) => {}
                    Err(quinn::SendDatagramError::ConnectionLost(_)) => return false,
                    // Too large or not allowed right now: drop this reply.
                    Err(_) => break,
                }
            }
            true
        })
    }
}
