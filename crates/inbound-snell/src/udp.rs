//! UDP over TCP (§4.1): one datagram per frame in each direction.

use std::sync::Arc;
use std::time::Duration;

use engine_inbound::server::ConnectionContext;
use engine_inbound::UserEntry;
use outbound_snell::request::{encode_udp_downstream, parse_udp_upstream, REPLY_TUNNEL};
use outbound_snell::Frame;
use tokio::time::Instant;

use crate::conn::{Conn, READ_CHUNK};

/// A UDP session without datagrams in either direction for this long ends.
const UDP_IDLE: Duration = Duration::from_secs(300);

/// Largest datagram read from the egress socket.
const MAX_DATAGRAM: usize = 64 * 1024;

/// Relays until the client ends the session, the egress fails, the session
/// idles out or the user is removed.
pub(crate) async fn relay(
    mut conn: Conn,
    user: Option<&Arc<UserEntry>>,
    context: &ConnectionContext<'_>,
) {
    let Some(egress) = context.udp() else {
        return;
    };
    let Ok(socket) = egress.bind().await else {
        return;
    };
    // The reply is a frame of its own.
    if conn.send_single(&[REPLY_TUNNEL]).await.is_err() {
        return;
    }
    let max_payload = conn.encoder.framing().max_payload();
    let mut raw = vec![0u8; READ_CHUNK];
    let mut down = vec![0u8; MAX_DATAGRAM];
    let idle = tokio::time::sleep(UDP_IDLE);
    tokio::pin!(idle);
    let revoked = async {
        match user {
            Some(user) => user.revoked().await,
            None => std::future::pending().await,
        }
    };
    tokio::pin!(revoked);
    loop {
        tokio::select! {
            frame = conn.next_frame(&mut raw) => {
                // A zero chunk, end of input or a broken frame ends the
                // session.
                let Ok(Some(Frame::Data(frame))) = frame else {
                    return;
                };
                let Ok((target, payload)) = parse_udp_upstream(&frame) else {
                    return;
                };
                idle.as_mut().reset(Instant::now() + UDP_IDLE);
                context.count(user, payload.len() as u64, 0);
                // Unreachable or refused targets drop the datagram, as UDP
                // would.
                let _ = socket.send_to(payload, &target).await;
            }
            received = socket.recv_from(&mut down) => {
                let Ok((n, source)) = received else {
                    return;
                };
                let mut datagram = Vec::with_capacity(n + 19);
                encode_udp_downstream(&mut datagram, source, &down[..n]);
                if datagram.len() > max_payload {
                    continue;
                }
                idle.as_mut().reset(Instant::now() + UDP_IDLE);
                context.count(user, 0, n as u64);
                if conn.send_single(&datagram).await.is_err() {
                    return;
                }
            }
            _ = &mut idle => return,
            _ = &mut revoked => {
                context.revoked();
                return;
            }
        }
    }
}
