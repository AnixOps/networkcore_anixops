//! TUIC v5 TCP outbound over QUIC.
//!
//! The client opens one QUIC connection per outbound and authenticates on a
//! unidirectional stream with
//!
//! ```text
//! VER 0x05 | TYPE 0x00 (Authenticate) | UUID (16) | TOKEN (32)
//! ```
//!
//! where TOKEN is the TLS keying material exported with the UUID as label and
//! the password as context, so the password never crosses the wire. The
//! server sends no answer. Each proxied TCP connection is a bidirectional
//! stream that starts with
//!
//! ```text
//! VER 0x05 | TYPE 0x01 (Connect) | ADDR
//! ```
//!
//! (ADDR: `0x00 len domain`, `0x01 ipv4` or `0x02 ipv6`, then a big-endian
//! port) and then carries the payload both ways.
//!
//! The connection is shared by every stream and opened again when it closes;
//! QUIC keep-alives keep it open between connections. UDP relay is not
//! supported yet.
//!
//! [`TuicFactory`] registers the outbound under `"type": "tuic"`.

mod factory;

use std::io;
use std::net::IpAddr;

use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};
use tokio::sync::Mutex;
use transport_quic::{quic_error, quinn, Congestion, QuicConnection, QuicConnector, QuicStream};
use transport_tls::TlsSettings;

pub use factory::{parse_uuid, TuicFactory, TYPE_NAME};

pub const PROTOCOL: &str = "tuic";

pub const VERSION: u8 = 0x05;
pub const CMD_AUTHENTICATE: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;
pub const ADDR_DOMAIN: u8 = 0x00;
pub const ADDR_IPV4: u8 = 0x01;
pub const ADDR_IPV6: u8 = 0x02;

pub struct TuicOutbound {
    uuid: [u8; 16],
    password: Vec<u8>,
    quic: QuicConnector,
    session: Mutex<Option<QuicConnection>>,
}

impl TuicOutbound {
    pub fn new(
        server: impl Into<String>,
        port: u16,
        uuid: [u8; 16],
        password: impl Into<String>,
        tls: &TlsSettings,
        congestion: Congestion,
    ) -> io::Result<Self> {
        let password = password.into();
        if password.is_empty() {
            return Err(invalid("tuic password is empty"));
        }
        Ok(Self {
            uuid,
            password: password.into_bytes(),
            quic: QuicConnector::new(server, port, tls, &["h3"], congestion)?,
            session: Mutex::new(None),
        })
    }

    /// The live QUIC connection, authenticating a new one if needed.
    async fn connection(&self) -> io::Result<quinn::Connection> {
        let mut session = self.session.lock().await;
        if let Some(current) = session.as_ref() {
            if current.connection.close_reason().is_none() {
                return Ok(current.connection.clone());
            }
        }
        *session = None;
        let fresh = self.quic.connect().await?;
        authenticate(&fresh.connection, &self.uuid, &self.password).await?;
        let connection = fresh.connection.clone();
        *session = Some(fresh);
        Ok(connection)
    }
}

/// Sends the Authenticate command on its own unidirectional stream.
async fn authenticate(
    connection: &quinn::Connection,
    uuid: &[u8; 16],
    password: &[u8],
) -> io::Result<()> {
    let mut command = Vec::with_capacity(2 + 16 + 32);
    command.extend_from_slice(&[VERSION, CMD_AUTHENTICATE]);
    command.extend_from_slice(uuid);
    command.extend_from_slice(&auth_token(connection, uuid, password)?);
    let mut stream = connection.open_uni().await.map_err(quic_error)?;
    stream.write_all(&command).await?;
    stream
        .finish()
        .map_err(|_| io::Error::other("tuic authentication stream closed"))?;
    Ok(())
}

/// TLS exporter output for this connection, label UUID, context password.
pub fn auth_token(
    connection: &quinn::Connection,
    uuid: &[u8; 16],
    password: &[u8],
) -> io::Result<[u8; 32]> {
    let mut token = [0u8; 32];
    connection
        .export_keying_material(&mut token, uuid, password)
        .map_err(|_| io::Error::other("tuic token export failed"))?;
    Ok(token)
}

impl TcpOutbound for TuicOutbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let header = connect_header(target)?;
            let connection = self.connection().await?;
            let (mut send, recv) = connection.open_bi().await.map_err(quic_error)?;
            send.write_all(&header).await?;
            Ok(QuicStream::boxed(send, recv))
        })
    }
}

/// The Connect command for `target`.
pub fn connect_header(target: &TargetAddr) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(2 + 1 + 256 + 2);
    out.extend_from_slice(&[VERSION, CMD_CONNECT]);
    match target {
        TargetAddr::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                out.push(ADDR_IPV4);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(ADDR_IPV6);
                out.extend_from_slice(&ip.octets());
            }
        },
        TargetAddr::Domain(domain, _) => {
            let len = u8::try_from(domain.len())
                .ok()
                .filter(|len| *len > 0)
                .ok_or_else(|| invalid("tuic target domain length is invalid"))?;
            out.push(ADDR_DOMAIN);
            out.push(len);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    Ok(out)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
