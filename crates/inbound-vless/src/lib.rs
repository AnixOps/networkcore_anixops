//! VLESS server inbound (version 0, TCP command).
//!
//! Request: `VER(0) UUID(16) ADDONS_LEN ADDONS CMD PORT ATYP ADDR`, then the
//! payload. The response header `VER(0) ADDONS_LEN(0)` is sent with the first
//! payload back to the client. Users are matched by `uuid`. A client that is
//! not a known VLESS user goes to the fallback, or is held open and drained.
//!
//! TLS is terminated by `inbound-transport` when the settings carry `tls`,
//! or by the [`reality`] server when they carry `reality`. Behind REALITY,
//! users may have the `xtls-rprx-vision` flow ([`vision`]); as in Xray, a
//! client must request exactly the flow its user is configured with.
//! The UDP command carries `LENGTH(2) PAYLOAD` datagrams to the request
//! target in both directions; as in Xray it takes no flow, also for Vision
//! users. The mux command (3, no address) carries Mux.Cool frames, which
//! Xray and sing-box clients use for UDP (XUDP) and Xray's `mux` for TCP; it
//! takes no flow or the user's flow (Xray sends Vision users' XUDP inside
//! Vision). Not yet: Vision over standard TLS; a client asking for it is
//! refused.

mod factory;
pub mod reality;
pub mod vision;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use engine_inbound::addr::{read_port_addr, VMESS};
use engine_inbound::stream::PrefixedStream;
use engine_inbound::udp::{Datagram, DatagramCodec, DatagramReader};
use engine_inbound::users::{UserIndex, Validator};
use engine_inbound::{
    fallback_or_hold, Accepted, Rejected, StreamInbound, User, UserEntry, UserStore,
    FIRST_READ_BYTES,
};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use outbound_vless::{parse_uuid, Flow};
use tls_mimic::TlsStream;
use tokio::io::{AsyncRead, AsyncReadExt};

pub use factory::{VlessInboundFactory, TYPE_NAME};
pub use reality::{RealityInbound, RealitySettings};
pub use vision::VisionStream;

pub const PROTOCOL: &str = "vless";

const VERSION: u8 = 0;
/// Version byte plus UUID.
const AUTH_LEN: usize = 17;
const COMMAND_TCP: u8 = 1;
const COMMAND_UDP: u8 = 2;
const COMMAND_MUX: u8 = 3;
/// The placeholder target of a mux request, as Xray names it.
const MUX_TARGET: &str = "v1.mux.cool";
/// Protobuf tag of the `Flow` field in the addons message.
const ADDONS_FLOW_TAG: u8 = 0x0a;
/// Addons length byte, addons, command, port, address type and a domain.
const MAX_REQUEST_HEADER: usize = 1 + 255 + 1 + 2 + 1 + 1 + 255;

pub struct VlessInbound {
    users: Arc<UserStore>,
    index: UserIndex<[u8; 16]>,
    fallback: Option<TargetAddr>,
}

/// The request header after the UUID, and the payload read with it.
struct Request {
    command: u8,
    flow: Flow,
    target: TargetAddr,
    payload: Vec<u8>,
}

impl VlessInbound {
    pub fn new(fallback: Option<TargetAddr>) -> Self {
        Self::with_vision(fallback, false)
    }

    /// `vision`: users may have the `xtls-rprx-vision` flow, which needs the
    /// REALITY transport.
    pub fn with_vision(fallback: Option<TargetAddr>, vision: bool) -> Self {
        let validator: Validator = Box::new(move |user: &User| {
            let uuid = user.uuid.as_deref().ok_or("vless user uuid is missing")?;
            parse_uuid(uuid).map_err(|_| "vless user uuid is invalid")?;
            match user.flow.as_deref().map(Flow::from_name) {
                None | Some(Some(Flow::None)) => Ok(()),
                Some(Some(Flow::Vision)) if vision => Ok(()),
                Some(Some(Flow::Vision)) => Err("vless vision flow needs reality"),
                Some(None) => Err("vless flow is unknown"),
            }
        });
        let users = Arc::new(UserStore::new(Some(validator)));
        Self {
            index: UserIndex::new(users.clone(), user_uuid),
            users,
            fallback,
        }
    }

    /// Reads at least the version and UUID. Returns the bytes read and the
    /// matching user, if any.
    async fn authenticate<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<(Vec<u8>, Option<Arc<UserEntry>>), Rejected> {
        let mut first = read_some(stream).await?;
        if first.is_empty() {
            return Err(Rejected::close("client closed before the request"));
        }
        // Without a fallback there is nothing else the bytes could be for, so
        // a request split across reads is completed.
        while first.len() < AUTH_LEN && self.fallback.is_none() {
            let more = read_some(stream).await?;
            if more.is_empty() {
                return Err(Rejected::close("vless request is truncated"));
            }
            first.extend_from_slice(&more);
        }
        let user = if first.len() >= AUTH_LEN && first[0] == VERSION {
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&first[1..AUTH_LEN]);
            self.index.get(&uuid)
        } else {
            None
        };
        Ok((first, user))
    }

    async fn handshake(&self, mut stream: BoxStream) -> Result<Accepted, Rejected> {
        let (first, user) = self.authenticate(&mut stream).await?;
        let Some(user) = user else {
            return fallback_or_hold(
                self.fallback.as_ref(),
                first,
                stream,
                "vless request is not for a known user",
            );
        };
        let request = read_request(&mut stream, first[AUTH_LEN..].to_vec()).await?;
        if request.flow == Flow::Vision || !flow_allowed(&user, &request) {
            return Err(Rejected::close("vless flow does not match the user"));
        }
        Ok(accepted(user, request, stream))
    }

    /// The handshake behind REALITY, where the Vision flow is possible.
    pub(crate) async fn handshake_reality(
        &self,
        mut tls: TlsStream<BoxStream>,
    ) -> Result<Accepted, Rejected> {
        let (first, user) = self.authenticate(&mut tls).await?;
        let Some(user) = user else {
            return fallback_or_hold(
                self.fallback.as_ref(),
                first,
                Box::new(tls),
                "vless request is not for a known user",
            );
        };
        let request = read_request(&mut tls, first[AUTH_LEN..].to_vec()).await?;
        if !flow_allowed(&user, &request) {
            return Err(Rejected::close("vless flow does not match the user"));
        }
        if request.flow == Flow::Vision {
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&first[1..AUTH_LEN]);
            return Ok(Accepted {
                user: Some(user),
                target: request.target,
                stream: Box::new(VisionStream::new(tls, uuid, &request.payload)),
                udp: None,
                mux: request.command == COMMAND_MUX,
            });
        }
        Ok(accepted(user, request, Box::new(tls)))
    }
}

fn accepted(user: Arc<UserEntry>, request: Request, stream: BoxStream) -> Accepted {
    let udp = (request.command == COMMAND_UDP).then(|| {
        Box::new(VlessDatagrams {
            target: request.target.clone(),
        }) as Box<dyn DatagramCodec>
    });
    Accepted {
        user: Some(user),
        target: request.target,
        stream: Box::new(
            PrefixedStream::new(stream)
                .with_read_prefix(request.payload)
                .with_write_prefix(vec![VERSION, 0]),
        ),
        udp,
        mux: request.command == COMMAND_MUX,
    }
}

/// VLESS UDP: `LENGTH(2) PAYLOAD` per datagram, all to the request target.
struct VlessDatagrams {
    target: TargetAddr,
}

impl DatagramCodec for VlessDatagrams {
    fn read<'a>(
        &'a self,
        reader: &'a mut DatagramReader,
    ) -> BoxFuture<'a, io::Result<Option<Datagram>>> {
        Box::pin(async move {
            let len = match reader.read_u16().await {
                Ok(len) => usize::from(len),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(error) => return Err(error),
            };
            let mut payload = vec![0u8; len];
            reader.read_exact(&mut payload).await?;
            Ok(Some((self.target.clone(), payload)))
        })
    }

    fn encode(&self, _source: SocketAddr, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let len = u16::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "udp payload too large"))?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(payload);
        Ok(())
    }
}

/// As in Xray: TCP uses exactly the user's flow, UDP never takes one, mux
/// either.
fn flow_allowed(user: &UserEntry, request: &Request) -> bool {
    match request.command {
        COMMAND_UDP => request.flow == Flow::None,
        COMMAND_MUX => request.flow == Flow::None || request.flow == user_flow(user),
        _ => request.flow == user_flow(user),
    }
}

async fn read_some<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; FIRST_READ_BYTES];
    let n = stream.read(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

/// Reads until the request header in `buffer` (which starts after the UUID)
/// is complete.
async fn read_request<S: AsyncRead + Unpin>(
    stream: &mut S,
    mut buffer: Vec<u8>,
) -> Result<Request, Rejected> {
    loop {
        if let Some(request) = parse_request(&buffer).await? {
            return Ok(request);
        }
        if buffer.len() > MAX_REQUEST_HEADER {
            return Err(Rejected::close("vless request header is malformed"));
        }
        let more = read_some(stream).await?;
        if more.is_empty() {
            return Err(Rejected::close("vless request is truncated"));
        }
        buffer.extend_from_slice(&more);
    }
}

/// Parses the request header; `None` while it is incomplete.
async fn parse_request(buffer: &[u8]) -> Result<Option<Request>, Rejected> {
    let Some(&addons_len) = buffer.first() else {
        return Ok(None);
    };
    let command_at = 1 + usize::from(addons_len);
    let Some(&command) = buffer.get(command_at) else {
        return Ok(None);
    };
    let Some(flow) = requested_flow(&buffer[1..command_at]) else {
        return Err(Rejected::close("vless flow is not supported"));
    };
    if command == COMMAND_MUX {
        return Ok(Some(Request {
            command,
            flow,
            target: TargetAddr::Domain(MUX_TARGET.into(), 0),
            payload: buffer[command_at + 1..].to_vec(),
        }));
    }
    if command != COMMAND_TCP && command != COMMAND_UDP {
        return Err(Rejected::close("vless command is not supported"));
    }
    let mut cursor = &buffer[command_at + 1..];
    match read_port_addr(&mut cursor, VMESS).await {
        Ok(target) => Ok(Some(Request {
            command,
            flow,
            target,
            payload: cursor.to_vec(),
        })),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn user_flow(user: &UserEntry) -> Flow {
    user.user()
        .flow
        .as_deref()
        .and_then(Flow::from_name)
        .unwrap_or(Flow::None)
}

impl StreamInbound for VlessInbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn users(&self) -> &Arc<UserStore> {
        &self.users
    }

    fn accept<'a>(
        &'a self,
        stream: BoxStream,
        _peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(self.handshake(stream))
    }
}

fn user_uuid(user: &User) -> Option<[u8; 16]> {
    parse_uuid(user.uuid.as_deref()?).ok()
}

/// The flow named in the addons message; `None` when it is malformed or
/// unknown.
fn requested_flow(addons: &[u8]) -> Option<Flow> {
    if addons.is_empty() {
        return Some(Flow::None);
    }
    if addons[0] != ADDONS_FLOW_TAG {
        return None;
    }
    let len = usize::from(*addons.get(1)?);
    let name = std::str::from_utf8(addons.get(2..2 + len)?).ok()?;
    Flow::from_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_flow_addon() {
        assert_eq!(requested_flow(&[]), Some(Flow::None));
        let mut vision = vec![ADDONS_FLOW_TAG, 16];
        vision.extend_from_slice(b"xtls-rprx-vision");
        assert_eq!(requested_flow(&vision), Some(Flow::Vision));
        assert_eq!(
            requested_flow(&[ADDONS_FLOW_TAG, 3, b'b', b'a', b'd']),
            None
        );
        assert_eq!(requested_flow(&[ADDONS_FLOW_TAG, 9]), None);
        assert_eq!(requested_flow(&[0x12, 0]), None);
    }

    #[test]
    fn validates_users() {
        let inbound = VlessInbound::new(None);
        let users = inbound.users();
        assert!(users
            .add(User::with_uuid("a", "b831381d-6324-4d53-ad4f-8cda48b30811"))
            .is_ok());
        assert!(users.add(User::with_uuid("b", "not-a-uuid")).is_err());
        assert!(users.add(User::with_password("c", "x")).is_err());
        let mut vision = User::with_uuid("d", "b831381d-6324-4d53-ad4f-8cda48b30812");
        vision.flow = Some("xtls-rprx-vision".into());
        assert!(users.add(vision.clone()).is_err());
        assert!(VlessInbound::with_vision(None, true)
            .users()
            .add(vision)
            .is_ok());
    }
}
