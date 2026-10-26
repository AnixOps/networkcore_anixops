//! Hysteria2 server inbound over QUIC.
//!
//! A client opens a QUIC connection (ALPN `h3`) and authenticates with an
//! HTTP/3 `POST /auth` carrying `Hysteria-Auth`; a known user's password gets
//! status 233, anything else a plain 404 so the port looks like an HTTP/3
//! server. After that each bidirectional stream that starts with varint
//! 0x401 is a TCP request `len | "host:port" | len | padding`, answered with
//! `status 0 | len 0 | len | padding` before the payload flows.
//!
//! Users are matched by `password`; streams are charged to the user that
//! authenticated the connection, and removing the user closes the
//! connection. Salamander obfuscation is optional.
//!
//! Not yet: UDP relay (the server announces `Hysteria-UDP: false`), Brutal
//! congestion control, port hopping and masquerade content.

mod factory;
mod h3;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock};

use engine_inbound::registry::BuildError;
use engine_inbound::server::{relay_accepted, InboundStats, ServeSettings};
use engine_inbound::users::{UserIndex, Validator};
use engine_inbound::{Accepted, PacketInbound, User, UserEntry, UserStore};
use engine_outbound::{BoxFuture, TargetAddr, TcpOutbound};
use inbound_transport::TlsServerSettings;
use outbound_hysteria2::{put_varint, read_varint, AUTH_OK_STATUS, TCP_REQUEST_ID};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use transport_quic::quinn::crypto::rustls::QuicServerConfig;
use transport_quic::salamander::Salamander;
use transport_quic::{quinn, Congestion, QuicStream};

pub use factory::{Hysteria2InboundFactory, TYPE_NAME};

pub const PROTOCOL: &str = "hysteria2";

const MAX_ADDRESS_LEN: u64 = 2048;
const MAX_PADDING_LEN: u64 = 4096;
const AUTH_PATH: &str = "/auth";
/// QUIC application error code for a refused or revoked client.
const CLOSE_REFUSED: u32 = 0x100;

pub struct Hysteria2Inbound {
    users: Arc<UserStore>,
    index: UserIndex<String>,
    crypto: Arc<QuicServerConfig>,
    salamander: Option<Salamander>,
}

impl Hysteria2Inbound {
    /// `tls.alpn` defaults to `h3`.
    pub fn new(
        tls: &TlsServerSettings,
        salamander: Option<Salamander>,
    ) -> Result<Self, BuildError> {
        let mut tls = tls.clone();
        if tls.alpn.is_empty() {
            tls.alpn = vec!["h3".to_owned()];
        }
        let config = inbound_transport::server_config(&tls)?;
        let crypto =
            QuicServerConfig::try_from(config).map_err(|_| "tls settings are unusable for quic")?;
        let validator: Validator = Box::new(|user: &User| match user.password.as_deref() {
            Some(password) if !password.is_empty() => Ok(()),
            _ => Err("hysteria2 user password is missing"),
        });
        let users = Arc::new(UserStore::new(Some(validator)));
        Ok(Self {
            index: UserIndex::new(users.clone(), |user: &User| user.password.clone()),
            users,
            crypto: Arc::new(crypto),
            salamander,
        })
    }

    async fn connection(
        self: Arc<Self>,
        incoming: quinn::Incoming,
        outbound: Arc<dyn TcpOutbound>,
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
        let Ok(mut control) = connection.open_uni().await else {
            return;
        };
        if control
            .write_all(&h3::control_stream_preface())
            .await
            .is_err()
        {
            return;
        }
        let drain = tokio::spawn(drain_unidirectional(connection.clone()));
        let auth: Arc<OnceLock<Arc<UserEntry>>> = Arc::default();
        let deadline = {
            let connection = connection.clone();
            let auth = auth.clone();
            let timeout = settings.handshake_timeout;
            tokio::spawn(async move {
                tokio::time::sleep(timeout).await;
                if auth.get().is_none() {
                    connection.close(quinn::VarInt::from_u32(CLOSE_REFUSED), b"");
                }
            })
        };
        while let Ok((send, recv)) = connection.accept_bi().await {
            tokio::spawn(self.clone().stream(
                QuicStream::new(send, recv),
                Session {
                    connection: connection.clone(),
                    peer,
                    auth: auth.clone(),
                },
                outbound.clone(),
                settings.clone(),
                stats.clone(),
            ));
        }
        drain.abort();
        deadline.abort();
        drop(control);
    }

    async fn stream(
        self: Arc<Self>,
        mut stream: QuicStream,
        session: Session,
        outbound: Arc<dyn TcpOutbound>,
        settings: Arc<ServeSettings>,
        stats: Arc<InboundStats>,
    ) {
        let first =
            tokio::time::timeout(settings.handshake_timeout, read_varint(&mut stream)).await;
        let Ok(Ok(first)) = first else {
            return;
        };
        if first != TCP_REQUEST_ID {
            self.http_request(first, stream, &session, &settings, &stats)
                .await;
            return;
        }
        let Some(user) = session.auth.get().cloned() else {
            // TCP requests before authentication are a protocol violation.
            session.refuse();
            return;
        };
        if user.is_revoked() {
            session.refuse();
            return;
        }
        let request =
            tokio::time::timeout(settings.handshake_timeout, read_tcp_request(&mut stream)).await;
        let Ok(Ok(target)) = request else {
            stats.handshake_failed.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let Ok(response) = tcp_response() else {
            return;
        };
        if stream.write_all(&response).await.is_err() {
            return;
        }
        relay_accepted(
            Accepted {
                user: Some(user),
                target,
                stream: Box::new(stream),
            },
            session.peer,
            outbound.as_ref(),
            &settings,
            &stats,
        )
        .await;
    }

    /// Answers one HTTP/3 request: the auth request of a known user gets
    /// 233, everything else 404.
    async fn http_request(
        &self,
        frame_type: u64,
        mut stream: QuicStream,
        session: &Session,
        settings: &ServeSettings,
        stats: &InboundStats,
    ) {
        let headers = tokio::time::timeout(
            settings.handshake_timeout,
            h3::read_request_headers(&mut stream, frame_type),
        )
        .await;
        let Ok(Ok(fields)) = headers else {
            return;
        };
        let is_auth = h3::field(&fields, ":method") == Some("POST")
            && h3::field(&fields, ":path") == Some(AUTH_PATH);
        let password = if is_auth {
            h3::field(&fields, "hysteria-auth")
        } else {
            None
        };
        let user = password
            .and_then(|password| self.index.get(&password.to_owned()))
            .filter(|user| !user.is_revoked());
        let frame = match user {
            Some(user) => {
                if session.auth.set(user.clone()).is_ok() {
                    tokio::spawn(close_on_revoke(user, session.connection.clone()));
                }
                let padding = random_padding().unwrap_or_default();
                h3::response_frame(
                    AUTH_OK_STATUS,
                    &[
                        ("hysteria-udp", "false"),
                        ("hysteria-cc-rx", "auto"),
                        ("hysteria-padding", &padding),
                    ],
                )
            }
            None => {
                stats.handshake_failed.fetch_add(1, Ordering::Relaxed);
                h3::response_frame(404, &[])
            }
        };
        if stream.write_all(&frame).await.is_err() {
            return;
        }
        let _ = stream.shutdown().await;
        // Keep reading until the client finishes its request: dropping the
        // receive side first sends STOP_SENDING, which can fail the client's
        // own finish before it reads the response.
        let _ = tokio::time::timeout(
            settings.handshake_timeout,
            tokio::io::copy(&mut (&mut stream).take(64 * 1024), &mut tokio::io::sink()),
        )
        .await;
    }
}

impl PacketInbound for Hysteria2Inbound {
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
        settings: ServeSettings,
        stats: Arc<InboundStats>,
    ) -> BoxFuture<'static, io::Result<()>> {
        Box::pin(async move {
            let endpoint = transport_quic::server_endpoint(
                socket,
                self.crypto.clone(),
                Congestion::Cubic,
                self.salamander.clone(),
            )?;
            let settings = Arc::new(settings);
            while let Some(incoming) = endpoint.accept().await {
                stats.accepted.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(self.clone().connection(
                    incoming,
                    outbound.clone(),
                    settings.clone(),
                    stats.clone(),
                ));
            }
            Ok(())
        })
    }
}

/// Per-connection state shared by its streams.
struct Session {
    connection: quinn::Connection,
    peer: SocketAddr,
    /// The user that authenticated this connection.
    auth: Arc<OnceLock<Arc<UserEntry>>>,
}

impl Session {
    fn refuse(&self) {
        self.connection
            .close(quinn::VarInt::from_u32(CLOSE_REFUSED), b"");
    }
}

async fn close_on_revoke(user: Arc<UserEntry>, connection: quinn::Connection) {
    tokio::select! {
        _ = user.revoked() => {
            connection.close(quinn::VarInt::from_u32(CLOSE_REFUSED), b"");
        }
        _ = connection.closed() => {}
    }
}

/// Reads and drops the client's unidirectional streams (HTTP/3 control and
/// QPACK streams) so they never block on flow control.
async fn drain_unidirectional(connection: quinn::Connection) {
    while let Ok(mut recv) = connection.accept_uni().await {
        tokio::spawn(
            async move { while let Ok(Some(_)) = recv.read_chunk(usize::MAX, true).await {} },
        );
    }
}

/// Reads the rest of a TCP request after its 0x401 id.
async fn read_tcp_request<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<TargetAddr> {
    let address_len = read_varint(reader).await?;
    if address_len == 0 || address_len > MAX_ADDRESS_LEN {
        return Err(invalid("hysteria2 request address length is invalid"));
    }
    let mut address = vec![0u8; address_len as usize];
    reader.read_exact(&mut address).await?;
    let padding_len = read_varint(reader).await?;
    if padding_len > MAX_PADDING_LEN {
        return Err(invalid("hysteria2 request padding is too long"));
    }
    let mut padding = vec![0u8; padding_len as usize];
    reader.read_exact(&mut padding).await?;
    let address = String::from_utf8(address)
        .map_err(|_| invalid("hysteria2 request address is not UTF-8"))?;
    parse_address(&address).ok_or_else(|| invalid("hysteria2 request address is invalid"))
}

/// `host:port`, with IPv6 hosts in brackets.
fn parse_address(address: &str) -> Option<TargetAddr> {
    let (host, port) = address.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        return None;
    }
    Some(match host.parse::<IpAddr>() {
        Ok(ip) => TargetAddr::Ip(SocketAddr::new(ip, port)),
        Err(_) => TargetAddr::Domain(host.to_owned(), port),
    })
}

/// Success: status 0, empty message, random padding.
fn tcp_response() -> io::Result<Vec<u8>> {
    let padding = random_padding()?;
    let mut out = Vec::with_capacity(4 + padding.len());
    out.push(0);
    put_varint(&mut out, 0);
    put_varint(&mut out, padding.len() as u64);
    out.extend_from_slice(padding.as_bytes());
    Ok(out)
}

/// Random alphanumeric text of 64 to 511 characters.
fn random_padding() -> io::Result<String> {
    const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let rng = SystemRandom::new();
    let mut len = [0u8; 2];
    rng.fill(&mut len)
        .map_err(|_| io::Error::other("system random source failed"))?;
    let len = 64 + usize::from(u16::from_be_bytes(len)) % 448;
    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes)
        .map_err(|_| io::Error::other("system random source failed"))?;
    Ok(bytes
        .iter()
        .map(|byte| char::from(ALPHABET[usize::from(*byte) % ALPHABET.len()]))
        .collect())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_request_addresses() {
        assert_eq!(
            parse_address("example.com:443"),
            Some(TargetAddr::Domain("example.com".into(), 443))
        );
        assert_eq!(
            parse_address("[::1]:53"),
            Some(TargetAddr::Ip("[::1]:53".parse().unwrap()))
        );
        assert_eq!(
            parse_address("10.0.0.1:80"),
            Some(TargetAddr::Ip("10.0.0.1:80".parse().unwrap()))
        );
        assert_eq!(parse_address("example.com"), None);
        assert_eq!(parse_address(":80"), None);
        assert_eq!(parse_address("host:99999"), None);
    }

    #[tokio::test]
    async fn reads_tcp_requests() {
        let mut request = Vec::new();
        put_varint(&mut request, 15);
        request.extend_from_slice(b"example.com:443");
        put_varint(&mut request, 3);
        request.extend_from_slice(b"pad");
        let mut reader = request.as_slice();
        assert_eq!(
            read_tcp_request(&mut reader).await.unwrap(),
            TargetAddr::Domain("example.com".into(), 443)
        );
        let mut too_long = Vec::new();
        put_varint(&mut too_long, MAX_ADDRESS_LEN + 1);
        assert!(read_tcp_request(&mut too_long.as_slice()).await.is_err());
    }
}
