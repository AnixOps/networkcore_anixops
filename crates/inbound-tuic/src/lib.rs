//! TUIC v5 server inbound over QUIC.
//!
//! The client authenticates on a unidirectional stream with `VER 0x05 | TYPE
//! 0x00 | UUID | TOKEN`, where TOKEN is the TLS keying material exported
//! with the UUID as label and the user's password as context. Each
//! bidirectional stream then starts with `VER 0x05 | TYPE 0x01 | ADDR` and
//! carries one TCP connection. Streams that arrive before the Authenticate
//! command wait for it up to the handshake timeout.
//!
//! Users are matched by `uuid` and need a `password`; streams are charged to
//! the user that authenticated the connection, and removing the user closes
//! the connection. Connections that send a wrong token are closed.
//!
//! UDP is relayed when the node provides a UDP outbound: Packet
//! commands in native mode (QUIC datagrams, fragmented) or quic mode
//! (unidirectional streams), one socket per association, replies in the
//! association's mode, Dissociate honored. Packets before authentication are
//! dropped.
//!
//! Not yet: the zero-RTT handshake.

mod factory;
mod udp;

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};

use engine_inbound::addr::{read_addr_port, AddrCodes};
use engine_inbound::registry::BuildError;
use engine_inbound::server::{relay_accepted, InboundStats, ServeSettings};
use engine_inbound::udp::UdpOutbound;
use engine_inbound::users::{UserIndex, Validator};
use engine_inbound::{Accepted, PacketInbound, User, UserEntry, UserStore};
use engine_outbound::{BoxFuture, TcpOutbound};
use inbound_transport::TlsServerSettings;
use outbound_tuic::udp::{CMD_DISSOCIATE, CMD_PACKET};
use outbound_tuic::{auth_token, parse_uuid, CMD_AUTHENTICATE, CMD_CONNECT, VERSION};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::watch;
use transport_quic::quinn::crypto::rustls::QuicServerConfig;
use transport_quic::{quinn, Congestion, QuicStream};

pub use factory::{TuicInboundFactory, TYPE_NAME};

pub const PROTOCOL: &str = "tuic";

/// TUIC address type codes: domain 0, IPv4 1, IPv6 2.
const TUIC_ADDR: AddrCodes = AddrCodes {
    ipv4: 0x01,
    domain: 0x00,
    ipv6: 0x02,
};
/// QUIC application error code for a refused or revoked client.
const CLOSE_REFUSED: u32 = 0x100;

pub struct TuicInbound {
    users: Arc<UserStore>,
    index: UserIndex<[u8; 16]>,
    crypto: Arc<QuicServerConfig>,
    congestion: Congestion,
}

impl TuicInbound {
    /// `tls.alpn` defaults to `h3`.
    pub fn new(tls: &TlsServerSettings, congestion: Congestion) -> Result<Self, BuildError> {
        let mut tls = tls.clone();
        if tls.alpn.is_empty() {
            tls.alpn = vec!["h3".to_owned()];
        }
        let config = inbound_transport::server_config(&tls)?;
        let crypto =
            QuicServerConfig::try_from(config).map_err(|_| "tls settings are unusable for quic")?;
        let validator: Validator = Box::new(|user: &User| {
            let uuid = user.uuid.as_deref().ok_or("tuic user uuid is missing")?;
            parse_uuid(uuid).ok_or("tuic user uuid is invalid")?;
            match user.password.as_deref() {
                Some(password) if !password.is_empty() => Ok(()),
                _ => Err("tuic user password is missing"),
            }
        });
        let users = Arc::new(UserStore::new(Some(validator)));
        Ok(Self {
            index: UserIndex::new(users.clone(), |user: &User| {
                parse_uuid(user.uuid.as_deref()?)
            }),
            users,
            crypto: Arc::new(crypto),
            congestion,
        })
    }

    async fn connection(
        self: Arc<Self>,
        incoming: quinn::Incoming,
        outbound: Arc<dyn TcpOutbound>,
        udp: Option<Arc<dyn UdpOutbound>>,
        settings: Arc<ServeSettings>,
        stats: Arc<InboundStats>,
    ) {
        let Ok(connecting) = incoming.accept() else {
            return;
        };
        let Ok(Ok(connection)) = tokio::time::timeout(settings.handshake_timeout, connecting).await
        else {
            stats.handshake_failed.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let peer = connection.remote_address();
        let (auth_tx, auth_rx) = watch::channel(None::<Arc<UserEntry>>);
        let relay: Arc<OnceLock<Arc<udp::UdpRelay>>> = Arc::default();
        let commands = tokio::spawn(self.clone().unidirectional(
            connection.clone(),
            auth_tx,
            relay.clone(),
            udp,
            stats.clone(),
        ));
        let deadline = {
            let connection = connection.clone();
            let mut auth = auth_rx.clone();
            let timeout = settings.handshake_timeout;
            tokio::spawn(async move {
                let authenticated =
                    tokio::time::timeout(timeout, auth.wait_for(Option::is_some)).await;
                if !matches!(authenticated, Ok(Ok(_))) {
                    connection.close(quinn::VarInt::from_u32(CLOSE_REFUSED), b"");
                }
            })
        };
        while let Ok((send, recv)) = connection.accept_bi().await {
            tokio::spawn(stream(
                QuicStream::new(send, recv),
                connection.clone(),
                peer,
                auth_rx.clone(),
                outbound.clone(),
                settings.clone(),
                stats.clone(),
            ));
        }
        commands.abort();
        deadline.abort();
        if let Some(relay) = relay.get() {
            relay.close();
        }
    }

    /// Handles the client's unidirectional streams: Authenticate, and UDP
    /// Packet and Dissociate commands.
    async fn unidirectional(
        self: Arc<Self>,
        connection: quinn::Connection,
        auth: watch::Sender<Option<Arc<UserEntry>>>,
        relay: Arc<OnceLock<Arc<udp::UdpRelay>>>,
        udp_outbound: Option<Arc<dyn UdpOutbound>>,
        stats: Arc<InboundStats>,
    ) {
        // quinn's own `read_exact` and `read_chunk`, not the tokio traits.
        while let Ok(mut recv) = connection.accept_uni().await {
            let mut head = [0u8; 2];
            if recv.read_exact(&mut head).await.is_err() || head[0] != VERSION {
                continue;
            }
            match (head[1], relay.get()) {
                (CMD_AUTHENTICATE, _) => {}
                (CMD_PACKET, Some(relay)) => {
                    tokio::spawn(relay.clone().stream_packet(recv));
                    continue;
                }
                (CMD_DISSOCIATE, Some(relay)) => {
                    let mut id = [0u8; 2];
                    if recv.read_exact(&mut id).await.is_ok() {
                        relay.dissociate(u16::from_be_bytes(id));
                    }
                    continue;
                }
                _ => {
                    tokio::spawn(async move {
                        while let Ok(Some(_)) = recv.read_chunk(usize::MAX, true).await {}
                    });
                    continue;
                }
            }
            let mut body = [0u8; 16 + 32];
            if recv.read_exact(&mut body).await.is_err() {
                continue;
            }
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&body[..16]);
            let user = self.index.get(&uuid).filter(|user| {
                let password = user.user().password.as_deref().unwrap_or_default();
                auth_token(&connection, &uuid, password.as_bytes())
                    .is_ok_and(|expected| constant_time_eq(&expected, &body[16..]))
            });
            match user {
                Some(user) if !user.is_revoked() => {
                    let first = auth.borrow().is_none();
                    if first {
                        auth.send_replace(Some(user.clone()));
                        if let Some(outbound) = &udp_outbound {
                            let udp = udp::UdpRelay::new(
                                connection.clone(),
                                outbound.clone(),
                                user.clone(),
                                stats.clone(),
                            );
                            if relay.set(udp.clone()).is_ok() {
                                tokio::spawn(udp.run_datagrams());
                            }
                        }
                        tokio::spawn(close_on_revoke(user, connection.clone()));
                    }
                }
                _ => {
                    stats.handshake_failed.fetch_add(1, Ordering::Relaxed);
                    connection.close(quinn::VarInt::from_u32(CLOSE_REFUSED), b"");
                    return;
                }
            }
        }
    }
}

impl PacketInbound for TuicInbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn users(&self) -> &Arc<UserStore> {
        &self.users
    }

    fn serve(
        self: Arc<Self>,
        socket: std::net::UdpSocket,
        outbound: Arc<dyn TcpOutbound>,
        udp: Option<Arc<dyn UdpOutbound>>,
        settings: ServeSettings,
        stats: Arc<InboundStats>,
    ) -> BoxFuture<'static, io::Result<()>> {
        Box::pin(async move {
            let endpoint = transport_quic::server_endpoint(
                socket,
                self.crypto.clone(),
                self.congestion,
                None,
            )?;
            let settings = Arc::new(settings);
            while let Some(incoming) = endpoint.accept().await {
                stats.accepted.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(self.clone().connection(
                    incoming,
                    outbound.clone(),
                    udp.clone(),
                    settings.clone(),
                    stats.clone(),
                ));
            }
            Ok(())
        })
    }
}

/// One Connect stream: waits for authentication, reads the target and
/// relays.
async fn stream(
    mut stream: QuicStream,
    connection: quinn::Connection,
    peer: SocketAddr,
    mut auth: watch::Receiver<Option<Arc<UserEntry>>>,
    outbound: Arc<dyn TcpOutbound>,
    settings: Arc<ServeSettings>,
    stats: Arc<InboundStats>,
) {
    let request = tokio::time::timeout(settings.handshake_timeout, read_connect(&mut stream)).await;
    let Ok(Ok(target)) = request else {
        stats.handshake_failed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let user = tokio::time::timeout(settings.handshake_timeout, auth.wait_for(Option::is_some))
        .await
        .ok()
        .and_then(Result::ok)
        .and_then(|user| user.clone());
    let Some(user) = user else {
        return;
    };
    if user.is_revoked() {
        connection.close(quinn::VarInt::from_u32(CLOSE_REFUSED), b"");
        return;
    }
    relay_accepted(
        Accepted {
            user: Some(user),
            target,
            stream: Box::new(stream),
            udp: None,
            mux: false,
        },
        peer,
        outbound.as_ref(),
        &settings,
        &stats,
    )
    .await;
}

/// `VER | TYPE Connect | ADDR`.
async fn read_connect<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<engine_outbound::TargetAddr> {
    let mut head = [0u8; 2];
    reader.read_exact(&mut head).await?;
    if head != [VERSION, CMD_CONNECT] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tuic stream is not a connect command",
        ));
    }
    read_addr_port(reader, TUIC_ADDR).await
}

async fn close_on_revoke(user: Arc<UserEntry>, connection: quinn::Connection) {
    tokio::select! {
        _ = user.revoked() => {
            connection.close(quinn::VarInt::from_u32(CLOSE_REFUSED), b"");
        }
        _ = connection.closed() => {}
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_outbound::TargetAddr;

    #[tokio::test]
    async fn reads_connect_commands() {
        let mut domain: &[u8] = &[VERSION, CMD_CONNECT, 0x00, 3, b'a', b'.', b'b', 0, 80];
        assert_eq!(
            read_connect(&mut domain).await.unwrap(),
            TargetAddr::Domain("a.b".into(), 80)
        );
        let mut v4: &[u8] = &[VERSION, CMD_CONNECT, 0x01, 127, 0, 0, 1, 1, 187];
        assert_eq!(
            read_connect(&mut v4).await.unwrap(),
            TargetAddr::Ip("127.0.0.1:443".parse().unwrap())
        );
        let mut wrong: &[u8] = &[4, CMD_CONNECT, 0x01, 127, 0, 0, 1, 1, 187];
        assert!(read_connect(&mut wrong).await.is_err());
    }

    #[test]
    fn compares_tokens_in_constant_time() {
        assert!(constant_time_eq(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_eq(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_eq(&[1, 2], &[1, 2, 3]));
    }
}
