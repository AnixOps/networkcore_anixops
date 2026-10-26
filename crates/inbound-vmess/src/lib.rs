//! VMess AEAD server inbound (alterId 0).
//!
//! Request: `AuthID(16) || seal(len) || nonce(8) || seal(header)`, then the
//! body. The AuthID is AES-128 under a key derived from each user's UUID, so
//! the server tries every user until one decrypts to a valid CRC and a
//! timestamp within 120 seconds; AuthIDs are remembered to refuse replays.
//! Unknown or replayed clients are held open and drained.
//!
//! Body securities `aes-128-gcm`, `chacha20-poly1305` and `none`, with the
//! ChunkStream option and optional ChunkMasking and GlobalPadding. The UDP
//! command carries one datagram per body chunk to the request target. Not
//! yet: authenticated length, the legacy MD5 header (alterId > 0) and mux.
//!
//! TLS is terminated by `inbound-transport` when the settings carry `tls`.

mod factory;
mod stream;

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use aes::{Aes128, Block};
use engine_inbound::addr::{read_port_addr, VMESS};
use engine_inbound::replay::ReplayCache;
use engine_inbound::udp::{Datagram, DatagramCodec, DatagramReader, MAX_DATAGRAM};
use engine_inbound::users::Validator;
use engine_inbound::{Accepted, Rejected, StreamInbound, User, UserEntry, UserStore};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use outbound_vmess::crypto::{
    chacha_key, cmd_key, fnv1a32, kdf, kdf16, seal_aes_gcm, sha256_16, AUTH_ID_KEY, HEADER_KEY,
    HEADER_LENGTH_KEY, HEADER_LENGTH_NONCE, HEADER_NONCE, RESPONSE_IV, RESPONSE_KEY,
    RESPONSE_LENGTH_IV, RESPONSE_LENGTH_KEY,
};
use outbound_vmess::parse_uuid;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use tokio::io::AsyncReadExt;

pub use factory::{VmessInboundFactory, TYPE_NAME};

use stream::{BodyCodec, VmessServerStream};

pub const PROTOCOL: &str = "vmess";

const VERSION: u8 = 1;
const TAG_LEN: usize = 16;
const MAX_AUTH_ID_AGE_SECS: u64 = 120;
const AUTH_ID_TTL: Duration = Duration::from_secs(2 * MAX_AUTH_ID_AGE_SECS);
/// Version, IV, key, V, option, padding/security, reserved, command.
const FIXED_HEADER_LEN: usize = 1 + 16 + 16 + 1 + 1 + 1 + 1 + 1;
const CHECKSUM_LEN: usize = 4;
const COMMAND_TCP: u8 = 1;
const COMMAND_UDP: u8 = 2;

const OPTION_CHUNK_STREAM: u8 = 0x01;
const OPTION_CHUNK_MASKING: u8 = 0x04;
const OPTION_GLOBAL_PADDING: u8 = 0x08;
const OPTION_AUTHENTICATED_LENGTH: u8 = 0x10;

const SECURITY_AES_128_GCM: u8 = 3;
const SECURITY_CHACHA20_POLY1305: u8 = 4;
const SECURITY_NONE: u8 = 5;

/// One user, ready for AuthID trial decryption.
struct Candidate {
    auth_cipher: Aes128,
    cmd_key: [u8; 16],
    entry: Arc<UserEntry>,
}

pub struct VmessInbound {
    users: Arc<UserStore>,
    candidates: Mutex<(u64, Arc<Vec<Candidate>>)>,
    auth_ids: ReplayCache,
}

impl Default for VmessInbound {
    fn default() -> Self {
        Self::new()
    }
}

impl VmessInbound {
    pub fn new() -> Self {
        let validator: Validator = Box::new(|user: &User| {
            let uuid = user.uuid.as_deref().ok_or("vmess user uuid is missing")?;
            parse_uuid(uuid).ok_or("vmess user uuid is invalid")?;
            Ok(())
        });
        Self {
            users: Arc::new(UserStore::new(Some(validator))),
            candidates: Mutex::new((u64::MAX, Arc::new(Vec::new()))),
            auth_ids: ReplayCache::new(AUTH_ID_TTL),
        }
    }

    fn candidates(&self) -> Arc<Vec<Candidate>> {
        let generation = self.users.generation();
        let mut cache = self.candidates.lock().unwrap_or_else(|e| e.into_inner());
        if cache.0 != generation {
            let (generation, entries) = self.users.snapshot();
            let candidates = entries
                .into_iter()
                .filter_map(|entry| {
                    let uuid = parse_uuid(entry.user().uuid.as_deref()?)?;
                    let cmd_key = cmd_key(&uuid);
                    let auth_key = kdf16(&cmd_key, &[AUTH_ID_KEY]);
                    let auth_cipher = Aes128::new_from_slice(&auth_key).ok()?;
                    Some(Candidate {
                        auth_cipher,
                        cmd_key,
                        entry,
                    })
                })
                .collect();
            *cache = (generation, Arc::new(candidates));
        }
        cache.1.clone()
    }

    /// The user whose key turns `auth_id` into a fresh, checksummed AuthID.
    fn find_user(&self, auth_id: &[u8; 16]) -> Option<(Arc<UserEntry>, [u8; 16])> {
        let now = unix_time_secs();
        self.candidates().iter().find_map(|candidate| {
            let mut block = Block::from(*auth_id);
            candidate.auth_cipher.decrypt_block(&mut block);
            let plain = block.as_slice();
            let crc = u32::from_be_bytes(plain[12..16].try_into().ok()?);
            if crc32fast::hash(&plain[..12]) != crc {
                return None;
            }
            let time = u64::from_be_bytes(plain[..8].try_into().ok()?);
            (now.abs_diff(time) <= MAX_AUTH_ID_AGE_SECS)
                .then(|| (candidate.entry.clone(), candidate.cmd_key))
        })
    }

    async fn handshake(&self, mut stream: BoxStream) -> Result<Accepted, Rejected> {
        let mut auth_id = [0u8; 16];
        stream.read_exact(&mut auth_id).await?;
        let Some((user, cmd_key)) = self.find_user(&auth_id) else {
            return Err(Rejected::hold("vmess auth id matches no user", stream));
        };
        if !self.auth_ids.insert(&auth_id) {
            return Err(Rejected::hold("vmess auth id was replayed", stream));
        }

        let mut sealed_length = [0u8; 2 + TAG_LEN];
        stream.read_exact(&mut sealed_length).await?;
        let mut connection_nonce = [0u8; 8];
        stream.read_exact(&mut connection_nonce).await?;
        let (id, nonce): (&[u8], &[u8]) = (&auth_id, &connection_nonce);
        let path = move |label: &'static [u8]| -> [&[u8]; 3] { [label, id, nonce] };
        if open_with_aad(
            &kdf16(&cmd_key, &path(HEADER_LENGTH_KEY)),
            &kdf(&cmd_key, &path(HEADER_LENGTH_NONCE)),
            &auth_id,
            &mut sealed_length,
        )
        .is_none()
        {
            return Err(Rejected::hold(
                "vmess header length failed to decrypt",
                stream,
            ));
        }
        let length = usize::from(u16::from_be_bytes([sealed_length[0], sealed_length[1]]));
        let mut header = vec![0u8; length + TAG_LEN];
        stream.read_exact(&mut header).await?;
        if open_with_aad(
            &kdf16(&cmd_key, &path(HEADER_KEY)),
            &kdf(&cmd_key, &path(HEADER_NONCE)),
            &auth_id,
            &mut header,
        )
        .is_none()
        {
            return Err(Rejected::hold("vmess header failed to decrypt", stream));
        }
        header.truncate(length);
        let request = parse_header(&header).await?;

        let response_key = sha256_16(&request.body_key);
        let response_iv = sha256_16(&request.body_iv);
        let masking = request.options & OPTION_CHUNK_MASKING != 0;
        let padding = request.options & OPTION_GLOBAL_PADDING != 0;
        let reader = BodyCodec::new(
            body_key(request.security, &request.body_key),
            request.body_iv,
            masking,
            padding,
        );
        let writer = BodyCodec::new(
            body_key(request.security, &response_key),
            response_iv,
            masking,
            padding,
        );
        let response_header = seal_response_header(&response_key, &response_iv, request.response_v);
        let stream = VmessServerStream::new(stream, reader, writer, response_header, Vec::new());
        let udp = (request.command == COMMAND_UDP).then(|| {
            Box::new(VmessDatagrams {
                target: request.target.clone(),
            }) as Box<dyn DatagramCodec>
        });
        Ok(Accepted {
            user: Some(user),
            target: request.target,
            stream: Box::new(stream),
            udp,
        })
    }
}

impl StreamInbound for VmessInbound {
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

/// VMess UDP: the body stream returns one chunk per read and seals one
/// chunk per write, so each chunk is one datagram to the request target.
struct VmessDatagrams {
    target: TargetAddr,
}

impl DatagramCodec for VmessDatagrams {
    fn read<'a>(
        &'a self,
        reader: &'a mut DatagramReader,
    ) -> BoxFuture<'a, io::Result<Option<Datagram>>> {
        Box::pin(async move {
            let mut payload = vec![0u8; MAX_DATAGRAM];
            let n = reader.read(&mut payload).await?;
            if n == 0 {
                return Ok(None);
            }
            payload.truncate(n);
            Ok(Some((self.target.clone(), payload)))
        })
    }

    fn encode(&self, _source: SocketAddr, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        out.extend_from_slice(payload);
        Ok(())
    }
}

struct Request {
    command: u8,
    body_iv: [u8; 16],
    body_key: [u8; 16],
    response_v: u8,
    options: u8,
    security: u8,
    target: TargetAddr,
}

/// Validates the decrypted request header.
async fn parse_header(header: &[u8]) -> Result<Request, Rejected> {
    if header.len() < FIXED_HEADER_LEN + CHECKSUM_LEN {
        return Err(Rejected::close("vmess header is too short"));
    }
    let (body, checksum) = header.split_at(header.len() - CHECKSUM_LEN);
    if fnv1a32(body).to_be_bytes() != checksum {
        return Err(Rejected::close("vmess header checksum is wrong"));
    }
    if body[0] != VERSION {
        return Err(Rejected::close("vmess header version is not supported"));
    }
    let options = body[34];
    if options & OPTION_CHUNK_STREAM == 0 || options & OPTION_AUTHENTICATED_LENGTH != 0 {
        return Err(Rejected::close("vmess options are not supported"));
    }
    let padding = usize::from(body[35] >> 4);
    let security = body[35] & 0x0f;
    if !matches!(
        security,
        SECURITY_AES_128_GCM | SECURITY_CHACHA20_POLY1305 | SECURITY_NONE
    ) {
        return Err(Rejected::close("vmess security is not supported"));
    }
    let command = body[37];
    if command != COMMAND_TCP && command != COMMAND_UDP {
        return Err(Rejected::close("vmess command is not supported"));
    }
    let mut rest = &body[FIXED_HEADER_LEN..];
    let target = read_port_addr(&mut rest, VMESS).await?;
    if rest.len() != padding {
        return Err(Rejected::close("vmess header length is inconsistent"));
    }
    let mut body_iv = [0u8; 16];
    body_iv.copy_from_slice(&body[1..17]);
    let mut body_key = [0u8; 16];
    body_key.copy_from_slice(&body[17..33]);
    Ok(Request {
        command,
        body_iv,
        body_key,
        response_v: body[33],
        options,
        security,
        target,
    })
}

/// The body AEAD for a security code; `None` for `none`.
fn body_key(security: u8, key: &[u8; 16]) -> Option<LessSafeKey> {
    let unbound = match security {
        SECURITY_AES_128_GCM => UnboundKey::new(&aead::AES_128_GCM, key),
        SECURITY_CHACHA20_POLY1305 => UnboundKey::new(&aead::CHACHA20_POLY1305, &chacha_key(key)),
        _ => return None,
    };
    unbound.ok().map(LessSafeKey::new)
}

/// `seal(len) || seal(V, option 0, command 0, command length 0)`.
fn seal_response_header(key: &[u8; 16], iv: &[u8; 16], response_v: u8) -> Vec<u8> {
    let plain = [response_v, 0, 0, 0];
    let mut length = (plain.len() as u16).to_be_bytes().to_vec();
    seal_aes_gcm(
        &kdf16(key, &[RESPONSE_LENGTH_KEY]),
        &kdf(iv, &[RESPONSE_LENGTH_IV]),
        &[],
        &mut length,
    );
    let mut header = plain.to_vec();
    seal_aes_gcm(
        &kdf16(key, &[RESPONSE_KEY]),
        &kdf(iv, &[RESPONSE_IV]),
        &[],
        &mut header,
    );
    length.extend_from_slice(&header);
    length
}

/// AES-128-GCM open with associated data; `None` on failure.
fn open_with_aad(key: &[u8; 16], nonce: &[u8], aad: &[u8], data: &mut [u8]) -> Option<usize> {
    let key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, key).ok()?);
    let nonce = Nonce::try_assume_unique_for_key(&nonce[..12]).ok()?;
    key.open_in_place(nonce, Aad::from(aad), data)
        .ok()
        .map(|plain| plain.len())
}

fn unix_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use outbound_vmess::crypto::auth_id;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn finds_users_by_auth_id_and_rejects_stale_ones() {
        let inbound = VmessInbound::new();
        inbound.users().add(User::with_uuid("a", UUID)).unwrap();
        inbound
            .users()
            .add(User::with_uuid("b", "6e1bb6b4-2a43-4b5e-9a3a-1f0c3c2c7d10"))
            .unwrap();
        let key = cmd_key(&parse_uuid(UUID).unwrap());
        let fresh = auth_id(&key, unix_time_secs(), [1, 2, 3, 4]);
        let (user, found_key) = inbound.find_user(&fresh).unwrap();
        assert_eq!(user.name(), "a");
        assert_eq!(found_key, key);

        let stale = auth_id(&key, unix_time_secs() - 600, [1, 2, 3, 4]);
        assert!(inbound.find_user(&stale).is_none());
        assert!(inbound.find_user(&[0u8; 16]).is_none());

        inbound.users().remove("a");
        assert!(inbound.find_user(&fresh).is_none());
    }

    #[test]
    fn validates_users() {
        let inbound = VmessInbound::new();
        assert!(inbound.users().add(User::with_uuid("a", "nope")).is_err());
        assert!(inbound.users().add(User::with_password("b", "x")).is_err());
    }

    #[tokio::test]
    async fn header_checks() {
        let mut header = vec![VERSION];
        header.extend_from_slice(&[7u8; 32]);
        header.push(0x42); // V
        header.push(OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING);
        header.push((2 << 4) | SECURITY_AES_128_GCM);
        header.push(0);
        header.push(COMMAND_TCP);
        header.extend_from_slice(&[0, 80, 1, 127, 0, 0, 1]);
        header.extend_from_slice(&[0xaa, 0xbb]);
        let checksum = fnv1a32(&header);
        let mut good = header.clone();
        good.extend_from_slice(&checksum.to_be_bytes());
        let request = parse_header(&good).await.ok().unwrap();
        assert_eq!(request.response_v, 0x42);
        assert_eq!(
            request.target,
            TargetAddr::Ip("127.0.0.1:80".parse().unwrap())
        );

        let mut bad_checksum = header.clone();
        bad_checksum.extend_from_slice(&(checksum ^ 1).to_be_bytes());
        assert!(parse_header(&bad_checksum).await.is_err());

        let mut udp = header.clone();
        udp[37] = COMMAND_UDP;
        let checksum = fnv1a32(&udp);
        udp.extend_from_slice(&checksum.to_be_bytes());
        assert_eq!(parse_header(&udp).await.ok().unwrap().command, COMMAND_UDP);

        let mut mux = header.clone();
        mux[37] = 3;
        let checksum = fnv1a32(&mux);
        mux.extend_from_slice(&checksum.to_be_bytes());
        assert!(parse_header(&mux).await.is_err());
    }
}
