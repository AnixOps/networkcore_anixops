//! VLESS server inbound (version 0, TCP command).
//!
//! Request: `VER(0) UUID(16) ADDONS_LEN ADDONS CMD PORT ATYP ADDR`, then the
//! payload. The response header `VER(0) ADDONS_LEN(0)` is sent with the first
//! payload back to the client. Users are matched by `uuid`. A client that is
//! not a known VLESS user goes to the fallback, or is held open and drained.
//!
//! TLS is terminated by `inbound-transport` when the settings carry `tls`,
//! or by the [`reality`] server when they carry `reality`.
//! Not yet: the `xtls-rprx-vision` flow, UDP and mux commands; a client
//! asking for any of them is refused.

mod factory;
pub mod reality;

use std::net::SocketAddr;
use std::sync::Arc;

use engine_inbound::addr::{read_port_addr, VMESS};
use engine_inbound::stream::PrefixedStream;
use engine_inbound::users::{UserIndex, Validator};
use engine_inbound::{
    fallback_or_hold, read_first, Accepted, Rejected, StreamInbound, User, UserStore,
};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use outbound_vless::{parse_uuid, Flow};
use tokio::io::AsyncReadExt;

pub use factory::{VlessInboundFactory, TYPE_NAME};
pub use reality::{RealityInbound, RealitySettings};

pub const PROTOCOL: &str = "vless";

const VERSION: u8 = 0;
/// Version byte plus UUID.
const AUTH_LEN: usize = 17;
const COMMAND_TCP: u8 = 1;
/// Protobuf tag of the `Flow` field in the addons message.
const ADDONS_FLOW_TAG: u8 = 0x0a;

pub struct VlessInbound {
    users: Arc<UserStore>,
    index: UserIndex<[u8; 16]>,
    fallback: Option<TargetAddr>,
}

impl VlessInbound {
    pub fn new(fallback: Option<TargetAddr>) -> Self {
        let validator: Validator = Box::new(|user: &User| {
            let uuid = user.uuid.as_deref().ok_or("vless user uuid is missing")?;
            parse_uuid(uuid).map_err(|_| "vless user uuid is invalid")?;
            match user.flow.as_deref().map(Flow::from_name) {
                None | Some(Some(Flow::None)) => Ok(()),
                Some(Some(Flow::Vision)) => Err("vless vision flow is not supported yet"),
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

    async fn handshake(&self, mut stream: BoxStream) -> Result<Accepted, Rejected> {
        let mut first = read_first(&mut stream).await?;
        if first.is_empty() {
            return Err(Rejected::close("client closed before the request"));
        }
        // Without a fallback there is nothing else the bytes could be for, so
        // a request split across reads is completed.
        while first.len() < AUTH_LEN && self.fallback.is_none() {
            let more = read_first(&mut stream).await?;
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
        let Some(user) = user else {
            return fallback_or_hold(
                self.fallback.as_ref(),
                first,
                stream,
                "vless request is not for a known user",
            );
        };

        let mut reader = PrefixedStream::new(stream).with_read_prefix(first[AUTH_LEN..].to_vec());
        let addons_len = usize::from(reader.read_u8().await?);
        let mut addons = vec![0u8; addons_len];
        reader.read_exact(&mut addons).await?;
        if requested_flow(&addons) != Some(Flow::None) {
            return Err(Rejected::close("vless flow is not supported"));
        }
        if reader.read_u8().await? != COMMAND_TCP {
            return Err(Rejected::close("vless command is not supported"));
        }
        let target = read_port_addr(&mut reader, VMESS).await?;
        Ok(Accepted {
            user: Some(user),
            target,
            stream: Box::new(reader.with_write_prefix(vec![VERSION, 0])),
        })
    }
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
        assert!(users.add(vision).is_err());
    }
}
