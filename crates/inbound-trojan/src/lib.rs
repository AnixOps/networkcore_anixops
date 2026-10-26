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
//! without it the inbound expects a TLS terminator in front. `CONNECT` and
//! `UDP ASSOCIATE` are supported; UDP packets on the stream are `ATYP ADDR
//! PORT LENGTH CRLF PAYLOAD` in both directions.

mod factory;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use engine_inbound::addr::{read_addr_port, write_addr_port, SOCKS};
use engine_inbound::stream::PrefixedStream;
use engine_inbound::udp::{DatagramCodec, DatagramReader};
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
const CMD_UDP_ASSOCIATE: u8 = 0x03;

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
        let command = reader.read_u8().await?;
        if command != CMD_CONNECT && command != CMD_UDP_ASSOCIATE {
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
            udp: (command == CMD_UDP_ASSOCIATE)
                .then(|| Box::new(TrojanDatagrams) as Box<dyn DatagramCodec>),
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

/// Trojan UDP packets: `ATYP ADDR PORT LENGTH CRLF PAYLOAD`.
struct TrojanDatagrams;

impl DatagramCodec for TrojanDatagrams {
    fn read<'a>(
        &'a self,
        mut reader: &'a mut DatagramReader,
    ) -> BoxFuture<'a, io::Result<Option<(TargetAddr, Vec<u8>)>>> {
        Box::pin(async move {
            let target = match read_addr_port(&mut reader, SOCKS).await {
                Ok(target) => target,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(error) => return Err(error),
            };
            let len = usize::from(reader.read_u16().await?);
            let mut crlf = [0u8; 2];
            reader.read_exact(&mut crlf).await?;
            if crlf != CRLF {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "trojan udp packet is malformed",
                ));
            }
            let mut payload = vec![0u8; len];
            reader.read_exact(&mut payload).await?;
            Ok(Some((target, payload)))
        })
    }

    fn encode(&self, source: SocketAddr, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let len = u16::try_from(payload.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "udp payload too large"))?;
        write_addr_port(out, source, SOCKS);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(CRLF);
        out.extend_from_slice(payload);
        Ok(())
    }
}

fn user_hash(user: &User) -> Option<[u8; HASH_LEN]> {
    user.password.as_deref().map(password_hash)
}
