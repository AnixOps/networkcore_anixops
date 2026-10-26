//! SOCKS5 TCP outbound: CONNECT through an upstream SOCKS5 server (RFC 1928),
//! with optional username/password authentication (RFC 1929).
//!
//! The handshake finishes before [`TcpOutbound::connect`] returns, so the
//! returned stream is the raw tunnel to the target.
//!
//! UDP ([`TcpOutbound::open_udp`]) uses `UDP ASSOCIATE`: the TCP connection
//! stays open as the association's lifetime, and datagrams go to the relay
//! address in the reply as `RSV(2) FRAG ATYP ADDR PORT payload`. An
//! unspecified relay address means the server's own address. Fragmented
//! replies are dropped.
//!
//! [`SocksFactory`] registers the outbound under `"type": "socks"`.

mod factory;

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use engine_outbound::{
    BoxFuture, BoxStream, DatagramRecv, DatagramSend, Dialer, TargetAddr, TcpOutbound, UdpFlow,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

pub use factory::{SocksFactory, TYPE_NAME};

pub const PROTOCOL: &str = "socks";

const VERSION: u8 = 0x05;
const AUTH_VERSION: u8 = 0x01;
const METHOD_NONE: u8 = 0x00;
const METHOD_PASSWORD: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const REP_SUCCEEDED: u8 = 0x00;

/// Username and password for RFC 1929. Has no `Debug` on purpose.
#[derive(Clone)]
pub struct SocksCredentials {
    pub username: String,
    pub password: String,
}

pub struct SocksOutbound {
    server: String,
    port: u16,
    credentials: Option<SocksCredentials>,
    dialer: Arc<dyn Dialer>,
}

impl SocksOutbound {
    pub fn new(
        server: impl Into<String>,
        port: u16,
        credentials: Option<SocksCredentials>,
        dialer: Arc<dyn Dialer>,
    ) -> io::Result<Self> {
        let server = server.into();
        if server.is_empty() || port == 0 {
            return Err(invalid("socks server address is empty"));
        }
        if let Some(credentials) = &credentials {
            let fits = |value: &str| (1..=255).contains(&value.len());
            if !fits(&credentials.username) || !fits(&credentials.password) {
                return Err(invalid(
                    "socks username and password must be 1 to 255 bytes",
                ));
            }
        }
        Ok(Self {
            server,
            port,
            credentials,
            dialer,
        })
    }
}

impl TcpOutbound for SocksOutbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let request = request(CMD_CONNECT, target)?;
            let mut stream = self.dialer.dial(&self.server, self.port).await?;
            negotiate(&mut stream, self.credentials.as_ref()).await?;
            stream.write_all(&request).await?;
            read_reply(&mut stream).await?;
            Ok(stream)
        })
    }

    fn open_udp<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<UdpFlow>> {
        Box::pin(async move {
            let mut header = vec![0, 0, 0];
            write_address(&mut header, target)?;
            let unspecified = TargetAddr::Ip((Ipv4Addr::UNSPECIFIED, 0).into());
            let request = request(CMD_UDP_ASSOCIATE, &unspecified)?;
            let mut control = self.dialer.dial(&self.server, self.port).await?;
            negotiate(&mut control, self.credentials.as_ref()).await?;
            control.write_all(&request).await?;
            let (host, port) = match read_reply(&mut control).await? {
                TargetAddr::Ip(addr) if addr.ip().is_unspecified() => {
                    (self.server.clone(), addr.port())
                }
                relay => (relay.host(), relay.port()),
            };
            let relay = self.dialer.open_datagram(&host, port).await?;
            Ok(UdpFlow::new(
                Box::new(UdpSend {
                    send: relay.send,
                    header,
                    packet: Vec::new(),
                }),
                Box::new(UdpRecv {
                    recv: relay.recv,
                    control,
                }),
            ))
        })
    }
}

/// Sends each datagram to the relay with the target's SOCKS UDP header.
struct UdpSend {
    send: Box<dyn DatagramSend>,
    /// `RSV RSV FRAG ATYP ADDR PORT` for the flow's target.
    header: Vec<u8>,
    packet: Vec<u8>,
}

impl DatagramSend for UdpSend {
    fn send<'a>(&'a mut self, payload: &'a [u8]) -> BoxFuture<'a, io::Result<()>> {
        Box::pin(async move {
            self.packet.clear();
            self.packet.extend_from_slice(&self.header);
            self.packet.extend_from_slice(payload);
            self.send.send(&self.packet).await
        })
    }
}

/// Receives relay datagrams; ends when the server closes the association's
/// TCP connection.
struct UdpRecv {
    recv: Box<dyn DatagramRecv>,
    control: BoxStream,
}

impl DatagramRecv for UdpRecv {
    fn recv(&mut self) -> BoxFuture<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            let mut probe = [0u8; 1];
            loop {
                tokio::select! {
                    received = self.recv.recv() => {
                        if let Some(payload) = udp_payload(&received?) {
                            return Ok(payload.to_vec());
                        }
                    }
                    // The server sends nothing on the TCP connection; any
                    // read result means the association is over.
                    _ = self.control.read(&mut probe) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "socks server ended the udp association",
                        ));
                    }
                }
            }
        })
    }
}

/// The payload of an unfragmented SOCKS UDP datagram.
fn udp_payload(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 4 || packet[2] != 0 {
        return None;
    }
    let address_len = match packet[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => 1 + usize::from(*packet.get(4)?),
        _ => return None,
    };
    packet.get(4 + address_len + 2..)
}

async fn negotiate(
    stream: &mut BoxStream,
    credentials: Option<&SocksCredentials>,
) -> io::Result<()> {
    let greeting: &[u8] = match credentials {
        Some(_) => &[VERSION, 2, METHOD_NONE, METHOD_PASSWORD],
        None => &[VERSION, 1, METHOD_NONE],
    };
    stream.write_all(greeting).await?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    if choice[0] != VERSION {
        return Err(protocol_error("socks server sent an unexpected version"));
    }
    match (choice[1], credentials) {
        (METHOD_NONE, _) => Ok(()),
        (METHOD_PASSWORD, Some(credentials)) => {
            let mut auth = Vec::with_capacity(3 + 255 + 255);
            auth.push(AUTH_VERSION);
            auth.push(credentials.username.len() as u8);
            auth.extend_from_slice(credentials.username.as_bytes());
            auth.push(credentials.password.len() as u8);
            auth.extend_from_slice(credentials.password.as_bytes());
            stream.write_all(&auth).await?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await?;
            if status[1] != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "socks server rejected the credentials",
                ));
            }
            Ok(())
        }
        (METHOD_NO_ACCEPTABLE, _) | (METHOD_PASSWORD, None) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks server requires an authentication method not configured",
        )),
        _ => Err(protocol_error("socks server chose an unknown method")),
    }
}

fn request(command: u8, target: &TargetAddr) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(4 + 1 + 255 + 2);
    out.extend_from_slice(&[VERSION, command, 0x00]);
    write_address(&mut out, target)?;
    Ok(out)
}

/// `ATYP ADDR PORT`.
fn write_address(out: &mut Vec<u8>, target: &TargetAddr) -> io::Result<()> {
    match target {
        TargetAddr::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                out.push(ATYP_IPV4);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(ATYP_IPV6);
                out.extend_from_slice(&ip.octets());
            }
        },
        TargetAddr::Domain(domain, _) => {
            let len = u8::try_from(domain.len())
                .ok()
                .filter(|len| *len > 0)
                .ok_or_else(|| invalid("socks target domain length is invalid"))?;
            out.push(ATYP_DOMAIN);
            out.push(len);
            out.extend_from_slice(domain.as_bytes());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    Ok(())
}

/// Reads the whole reply, bound address included, so no reply byte is left
/// in front of the target's data. Returns the bound address.
async fn read_reply<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<TargetAddr> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(protocol_error("socks server sent an unexpected version"));
    }
    if head[1] != REP_SUCCEEDED {
        return Err(io::Error::new(
            reply_error_kind(head[1]),
            "socks server could not connect to the target",
        ));
    }
    let address_len = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            usize::from(len[0])
        }
        _ => return Err(protocol_error("socks server sent an unknown address type")),
    };
    let mut bound = [0u8; 255 + 2];
    let bound = &mut bound[..address_len + 2];
    stream.read_exact(bound).await?;
    let (address, port) = bound.split_at(address_len);
    let port = u16::from_be_bytes([port[0], port[1]]);
    Ok(match head[3] {
        ATYP_IPV4 => {
            let octets: [u8; 4] = address.try_into().expect("4-byte address");
            TargetAddr::Ip((IpAddr::from(octets), port).into())
        }
        ATYP_IPV6 => {
            let octets: [u8; 16] = address.try_into().expect("16-byte address");
            TargetAddr::Ip((IpAddr::from(octets), port).into())
        }
        _ => TargetAddr::Domain(String::from_utf8_lossy(address).into_owned(), port),
    })
}

fn reply_error_kind(code: u8) -> io::ErrorKind {
    match code {
        0x02 => io::ErrorKind::PermissionDenied,
        0x03 | 0x04 => io::ErrorKind::HostUnreachable,
        0x05 => io::ErrorKind::ConnectionRefused,
        0x06 => io::ErrorKind::TimedOut,
        0x07 | 0x08 => io::ErrorKind::Unsupported,
        _ => io::ErrorKind::Other,
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn protocol_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
