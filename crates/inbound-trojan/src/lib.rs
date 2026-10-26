//! Trojan server inbound (trojan-gfw protocol).
//!
//! The client sends `hex(SHA-224(password)) CRLF CMD ATYP DST.ADDR DST.PORT
//! CRLF` and then the payload, usually in the first TLS record. Users are
//! matched by the hash of their `password`. A first record that is not a
//! Trojan request for a known user goes to the fallback (a web server, so the
//! port looks like an ordinary HTTPS site) or, without one, is held open and
//! drained.
//!
//! TLS is terminated by `inbound-transport` when the settings carry `tls`;
//! without it the inbound expects a TLS terminator in front. Only `CONNECT`
//! is supported; UDP associate is refused for now.

mod factory;

use std::net::SocketAddr;
use std::sync::Arc;

use engine_inbound::addr::{read_addr_port, SOCKS};
use engine_inbound::stream::PrefixedStream;
use engine_inbound::users::{UserIndex, Validator};
use engine_inbound::{
    fallback_or_hold, read_first, Accepted, Rejected, StreamInbound, User, UserStore,
};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use outbound_trojan::password_hash;
use tokio::io::AsyncReadExt;

pub use factory::{TrojanInboundFactory, TYPE_NAME};

pub const PROTOCOL: &str = "trojan";

const HASH_LEN: usize = 56;
const CRLF: &[u8] = b"\r\n";
const CMD_CONNECT: u8 = 0x01;

pub struct TrojanInbound {
    users: Arc<UserStore>,
    index: UserIndex<[u8; HASH_LEN]>,
    fallback: Option<TargetAddr>,
}

impl TrojanInbound {
    pub fn new(fallback: Option<TargetAddr>) -> Self {
        let validator: Validator = Box::new(|user: &User| match user.password.as_deref() {
            Some(password) if !password.is_empty() => Ok(()),
            _ => Err("trojan user password is missing"),
        });
        let users = Arc::new(UserStore::new(Some(validator)));
        Self {
            index: UserIndex::new(users.clone(), user_hash),
            users,
            fallback,
        }
    }

    async fn handshake(&self, mut stream: BoxStream) -> Result<Accepted, Rejected> {
        let first = read_first(&mut stream).await?;
        if first.is_empty() {
            return Err(Rejected::close("client closed before the request"));
        }
        let user = if first.len() >= HASH_LEN + CRLF.len() && &first[HASH_LEN..HASH_LEN + 2] == CRLF
        {
            let mut hash = [0u8; HASH_LEN];
            hash.copy_from_slice(&first[..HASH_LEN]);
            self.index.get(&hash)
        } else {
            None
        };
        let Some(user) = user else {
            return fallback_or_hold(
                self.fallback.as_ref(),
                first,
                stream,
                "trojan request is not for a known user",
            );
        };

        let mut reader =
            PrefixedStream::new(stream).with_read_prefix(first[HASH_LEN + CRLF.len()..].to_vec());
        if reader.read_u8().await? != CMD_CONNECT {
            return Err(Rejected::close("trojan command is not supported"));
        }
        let target = read_addr_port(&mut reader, SOCKS).await?;
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
        if crlf != CRLF {
            return Err(Rejected::close("trojan request is malformed"));
        }
        Ok(Accepted {
            user: Some(user),
            target,
            stream: Box::new(reader),
        })
    }
}

impl StreamInbound for TrojanInbound {
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

fn user_hash(user: &User) -> Option<[u8; HASH_LEN]> {
    user.password.as_deref().map(password_hash)
}
