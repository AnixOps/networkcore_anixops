//! ShadowTLS v3 server in front of a protocol inbound.
//!
//! The client runs a real TLS 1.3 handshake with a camouflage site through
//! this server and proves itself in passing: the last four bytes of its
//! ClientHello session id are an HMAC-SHA1, keyed with the password, of the
//! ClientHello with those bytes zeroed. The server relays the handshake
//! record by record to the `handshake` site and marks what comes back: the
//! body of every ApplicationData record is XORed with SHA-256(password ‖
//! ServerRandom) and gets the first four bytes of a running HMAC-SHA1 over
//! the ServerRandom and the bodies so far in front, which tells the client
//! that the server knows the password too.
//!
//! Once the TLS handshake is done the client sends its own records:
//! ApplicationData that starts with a four-byte tag from a second running
//! HMAC (ServerRandom ‖ "C", then each record's data followed by its tag).
//! The first such record ends the relay to the handshake site; from then on
//! both directions carry the wrapped protocol in these records, the server
//! tagging its own with a third HMAC (ServerRandom ‖ "S"). A record whose
//! tag is wrong is answered with what an encrypted alert looks like, and
//! the connection ends.
//!
//! Everything else on the port (no TLS, an unsigned or foreign ClientHello,
//! and in strict mode a handshake site that does not answer in TLS 1.3) is
//! relayed to the handshake site unchanged, so a prober sees that site.
//!
//! The keys come from the latest ServerHello record, so from the one that
//! follows a HelloRetryRequest. Not implemented: versions 1 and 2, a
//! handshake site chosen by server name, and wildcard SNI.

use std::io;
use std::net::SocketAddr;
use std::ops::Range;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use engine_outbound::{BoxFuture, BoxStream, TargetAddr};
use ring::rand::{SecureRandom, SystemRandom};
use ring::{digest, hmac};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::registry::BuildError;
use crate::server::ConnectionContext;
use crate::udp::DatagramInbound;
use crate::users::Validator;
use crate::{Accepted, FallbackSettings, Rejected, StreamInbound, User, UserEntry, UserStore};

/// A TLS record header: type, version and length.
const HEADER: usize = 5;
/// The HMAC bytes in a session id and in front of a record's data.
const TAG: usize = 4;
const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;
const APPLICATION_DATA: u8 = 23;
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
/// Where the random of a hello record starts: after the record header and
/// the message's type, length and version.
const RANDOM_AT: usize = HEADER + 1 + 3 + 2;
const RANDOM: usize = 32;
/// A signing client's session id: 28 random bytes and the tag.
const SESSION_ID: usize = 32;
/// Most data put in one record.
const MAX_DATA: usize = 16 * 1024;
const READ_CHUNK: usize = 16 * 1024;
/// The body of an encrypted TLS 1.3 alert: two bytes, the content type and
/// the AEAD tag.
const ALERT_BODY: usize = 2 + 1 + 16;

/// `"shadow_tls"` in inbound settings. Has no `Debug`: holds passwords.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowTlsSettings {
    /// The protocol version; only 3, which is also the default.
    #[serde(default = "default_version")]
    pub version: u8,
    /// The password of clients that are no user; required without `users`.
    #[serde(default)]
    pub password: Option<String>,
    /// ShadowTLS users by `password`. When the key is present (an empty
    /// list too) they are the inbound's users: the ones added, removed,
    /// limited and charged. The wrapped protocol must then have no users
    /// of its own.
    #[serde(default)]
    pub users: Option<Vec<User>>,
    /// The TLS 1.3 site that answers the handshake, and everything that is
    /// not a ShadowTLS client.
    pub handshake: FallbackSettings,
    /// Serve a client only when the handshake site answered in TLS 1.3.
    #[serde(default)]
    pub strict_mode: bool,
}

fn default_version() -> u8 {
    3
}

/// Puts `inner` behind ShadowTLS when `settings` is set.
pub fn wrap(
    inner: Arc<dyn StreamInbound>,
    settings: Option<&ShadowTlsSettings>,
) -> Result<Arc<dyn StreamInbound>, BuildError> {
    match settings {
        Some(settings) => Ok(Arc::new(ShadowTlsInbound::new(inner, settings)?)),
        None => Ok(inner),
    }
}

/// A protocol inbound behind a ShadowTLS v3 server.
pub struct ShadowTlsInbound {
    inner: Arc<dyn StreamInbound>,
    handshake: TargetAddr,
    strict: bool,
    password: Option<String>,
    /// The ShadowTLS users, when the inbound's users are these.
    users: Option<Arc<UserStore>>,
}

impl ShadowTlsInbound {
    pub fn new(
        inner: Arc<dyn StreamInbound>,
        settings: &ShadowTlsSettings,
    ) -> Result<Self, BuildError> {
        if settings.version != 3 {
            return Err("shadow_tls supports version 3 only");
        }
        let password = settings.password.clone().filter(|p| !p.is_empty());
        let users = match &settings.users {
            Some(users) => {
                // One user table per inbound, and the serve loop must relay
                // the wrapped protocol for the user to be charged.
                if inner.serves_connections() || !inner.users().is_empty() {
                    return Err("shadow_tls users need an inbound without users of its own");
                }
                let validator: Validator = Box::new(|user: &User| match user.password.as_deref() {
                    Some(password) if !password.is_empty() => Ok(()),
                    _ => Err("shadow_tls user password is missing"),
                });
                let store = UserStore::new(Some(validator));
                store.add_all(users.clone())?;
                Some(Arc::new(store))
            }
            None if password.is_none() => return Err("shadow_tls needs a password or users"),
            None => None,
        };
        Ok(Self {
            inner,
            handshake: settings.handshake.target(),
            strict: settings.strict_mode,
            password,
            users,
        })
    }

    /// The password that signed the ClientHello record `hello`, and its
    /// user. Users are tried in name order, then the shared password.
    fn authenticate(&self, hello: &[u8]) -> Option<(String, Option<Arc<UserEntry>>)> {
        let signed = |password: &String| client_hello_signed(hello, password.as_bytes());
        for entry in self.users.iter().flat_map(|users| users.snapshot().1) {
            if entry.user().password.as_ref().is_some_and(signed) {
                let password = entry.user().password.clone().unwrap_or_default();
                return Some((password, Some(entry)));
            }
        }
        let password = self.password.clone().filter(signed)?;
        Some((password, None))
    }

    async fn handshake(
        &self,
        stream: BoxStream,
        context: &ConnectionContext<'_>,
    ) -> io::Result<Handshake> {
        let mut client = Records {
            io: stream,
            buf: Vec::new(),
        };
        // Only a TLS handshake record is waited for in full; whatever else a
        // prober sends reaches the handshake site as it comes.
        while client.buf.len() < HEADER {
            client.fill().await?;
        }
        let hello = match client.buf[0] {
            HANDSHAKE => client.next_record().await?,
            _ => Vec::new(),
        };
        let authenticated = self.authenticate(&hello);
        let Ok(io) = context.connect(&self.handshake).await else {
            return Ok(Handshake::Unreachable);
        };
        let mut server = Records {
            io,
            buf: Vec::new(),
        };
        server.io.write_all(&hello).await?;
        let Some((password, user)) = authenticated else {
            return Ok(Handshake::Relay(client, server));
        };
        let switched =
            relay_handshake(&mut client, &mut server, password.as_bytes(), self.strict).await?;
        Ok(match switched {
            Some((first, keys)) => {
                Handshake::Client(Box::new(ShadowStream::new(client, first, keys)), user)
            }
            None => Handshake::Relay(client, server),
        })
    }
}

/// How the relayed TLS handshake ended.
enum Handshake {
    /// A ShadowTLS client, switched to its data records, and its user.
    Client(BoxStream, Option<Arc<UserEntry>>),
    /// Anything else: the client and the handshake site talk on unchanged.
    Relay(Records, Records),
    /// The handshake site could not be reached, which the context counted.
    Unreachable,
}

impl StreamInbound for ShadowTlsInbound {
    fn protocol(&self) -> &'static str {
        self.inner.protocol()
    }

    fn users(&self) -> &Arc<UserStore> {
        self.users.as_ref().unwrap_or_else(|| self.inner.users())
    }

    fn accept<'a>(
        &'a self,
        _stream: BoxStream,
        _peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        // The serve loop hands ShadowTLS whole connections: it has to reach
        // the handshake site before the protocol sees the client.
        Box::pin(async { Err(Rejected::close("shadow-tls serves whole connections")) })
    }

    fn serves_connections(&self) -> bool {
        true
    }

    fn serve_connection<'a>(
        &'a self,
        stream: BoxStream,
        context: ConnectionContext<'a>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let handshake = tokio::time::timeout(
                context.settings.handshake_timeout,
                self.handshake(stream, &context),
            );
            match handshake.await {
                Ok(Ok(Handshake::Client(stream, Some(user)))) => {
                    let inner = Charged {
                        inner: self.inner.as_ref(),
                        user,
                    };
                    context.handle(stream, &inner).await;
                }
                Ok(Ok(Handshake::Client(stream, None))) => {
                    context.handle(stream, self.inner.as_ref()).await;
                }
                Ok(Ok(Handshake::Relay(mut client, mut server))) => {
                    // What either side sent beyond the records relayed so far.
                    if server.io.write_all(&client.buf).await.is_ok()
                        && client.io.write_all(&server.buf).await.is_ok()
                    {
                        let _ = context
                            .relay_to(None, Some(&self.handshake), &mut client.io, &mut server.io)
                            .await;
                    }
                }
                Ok(Ok(Handshake::Unreachable)) => {}
                Ok(Err(_)) | Err(_) => context.handshake_failed(),
            }
        })
    }

    /// The wrapped protocol's own UDP port, which ShadowTLS is not in front
    /// of; closed when the users are ShadowTLS users, whom it could not
    /// tell apart.
    fn datagram(&self) -> Option<Arc<dyn DatagramInbound>> {
        match self.users {
            Some(_) => None,
            None => self.inner.datagram(),
        }
    }
}

/// The wrapped inbound with its clients charged to the ShadowTLS user that
/// brought them.
struct Charged<'i> {
    inner: &'i dyn StreamInbound,
    user: Arc<UserEntry>,
}

impl StreamInbound for Charged<'_> {
    fn protocol(&self) -> &'static str {
        self.inner.protocol()
    }

    fn users(&self) -> &Arc<UserStore> {
        self.inner.users()
    }

    fn accept<'a>(
        &'a self,
        stream: BoxStream,
        peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(async move {
            let mut accepted = self.inner.accept(stream, peer).await?;
            accepted.user = Some(self.user.clone());
            Ok(accepted)
        })
    }
}

/// One side of the handshake relay: the connection and what was read from
/// it beyond the records taken so far.
struct Records {
    io: BoxStream,
    buf: Vec<u8>,
}

impl Records {
    async fn fill(&mut self) -> io::Result<()> {
        self.buf.reserve(READ_CHUNK);
        match self.io.read_buf(&mut self.buf).await? {
            0 => Err(io::ErrorKind::UnexpectedEof.into()),
            _ => Ok(()),
        }
    }

    /// The next whole record. Cancel safe: a record read in part stays in
    /// `buf`.
    async fn next_record(&mut self) -> io::Result<Vec<u8>> {
        loop {
            if let Some(len) = record_len(&self.buf) {
                let rest = self.buf.split_off(len);
                return Ok(std::mem::replace(&mut self.buf, rest));
            }
            self.fill().await?;
        }
    }
}

/// The length of the record `buf` starts with, once all of it is there.
fn record_len(buf: &[u8]) -> Option<usize> {
    let len = HEADER + usize::from(u16::from_be_bytes([*buf.get(3)?, *buf.get(4)?]));
    (buf.len() >= len).then_some(len)
}

/// Whether the ClientHello record carries the tag `password` gives it: the
/// last four bytes of a 32-byte session id are the HMAC of the message with
/// those bytes zeroed.
fn client_hello_signed(record: &[u8], password: &[u8]) -> bool {
    let session_id_at = RANDOM_AT + RANDOM + 1;
    let tag_at = session_id_at + SESSION_ID - TAG;
    if record.len() < tag_at + TAG
        || record[0] != HANDSHAKE
        || record[HEADER] != CLIENT_HELLO
        || usize::from(record[session_id_at - 1]) != SESSION_ID
    {
        return false;
    }
    let mut mac = mac(password);
    mac.update(&record[HEADER..tag_at]);
    mac.update(&[0; TAG]);
    mac.update(&record[tag_at + TAG..]);
    mac.sign().as_ref()[..TAG] == record[tag_at..tag_at + TAG]
}

/// The ServerRandom of a ServerHello record.
fn server_random(record: &[u8]) -> Option<&[u8]> {
    if record[0] != HANDSHAKE || record.get(HEADER) != Some(&SERVER_HELLO) {
        return None;
    }
    record.get(RANDOM_AT..RANDOM_AT + RANDOM)
}

/// Whether a ServerHello record picks TLS 1.3 in `supported_versions`.
fn selects_tls13(record: &[u8]) -> bool {
    supported_version(record) == Some([3, 4])
}

fn supported_version(record: &[u8]) -> Option<[u8; 2]> {
    let rest = record.get(RANDOM_AT + RANDOM..)?;
    // The session id, then the cipher suite and the compression method.
    let rest = rest.get(1 + usize::from(*rest.first()?) + 3..)?;
    let len = usize::from(u16::from_be_bytes([*rest.first()?, *rest.get(1)?]));
    let mut extensions = rest.get(2..2 + len)?;
    while let [kind_high, kind_low, len_high, len_low, rest @ ..] = extensions {
        let len = usize::from(u16::from_be_bytes([*len_high, *len_low]));
        let body = rest.get(..len)?;
        if [*kind_high, *kind_low] == [0, 43] {
            return body.try_into().ok();
        }
        extensions = &rest[len..];
    }
    None
}

fn mac(password: &[u8]) -> hmac::Context {
    hmac::Context::with_key(&hmac::Key::new(
        hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        password,
    ))
}

/// A running HMAC-SHA1 whose first four bytes so far tag each record.
#[derive(Clone)]
struct Chain(hmac::Context);

impl Chain {
    fn new(password: &[u8], random: &[u8], side: &[u8]) -> Self {
        let mut mac = mac(password);
        mac.update(random);
        mac.update(side);
        Self(mac)
    }

    /// The tag of `data` after everything before it. Data records are
    /// `chained`: their tag goes into the HMAC as well, so two records
    /// cannot be joined into one.
    fn tag(&mut self, data: &[u8], chained: bool) -> [u8; TAG] {
        self.0.update(data);
        let mut tag = [0u8; TAG];
        tag.copy_from_slice(&self.0.clone().sign().as_ref()[..TAG]);
        if chained {
            self.0.update(&tag);
        }
        tag
    }

    /// Whether `record` is a data record of this chain's side, which moves
    /// the chain on; any other record leaves it as it was.
    fn opens(&mut self, record: &[u8]) -> bool {
        if record[0] != APPLICATION_DATA || record.len() < HEADER + TAG {
            return false;
        }
        let mut next = self.clone();
        if next.tag(&record[HEADER + TAG..], true) != record[HEADER..HEADER + TAG] {
            return false;
        }
        *self = next;
        true
    }
}

/// What the password and the ServerRandom give both sides.
struct Keys {
    /// Tags the handshake site's ApplicationData records.
    relayed: Chain,
    /// XORed over the bodies of those records.
    mask: digest::Digest,
    /// Tags the client's data records.
    client: Chain,
    /// Tags ours.
    server: Chain,
}

impl Keys {
    fn new(password: &[u8], random: &[u8]) -> Self {
        let mut mask = digest::Context::new(&digest::SHA256);
        mask.update(password);
        mask.update(random);
        Self {
            relayed: Chain::new(password, random, b""),
            mask: mask.finish(),
            client: Chain::new(password, random, b"C"),
            server: Chain::new(password, random, b"S"),
        }
    }

    /// Marks an ApplicationData record of the handshake site: the body
    /// XORed with the mask, behind its tag.
    fn mark_relayed(&mut self, record: &mut Vec<u8>) {
        let mask = self.mask.as_ref().iter().cycle();
        for (byte, mask) in record[HEADER..].iter_mut().zip(mask) {
            *byte ^= mask;
        }
        let tag = self.relayed.tag(&record[HEADER..], false);
        let end = record.len();
        record.extend_from_slice(&tag);
        record.copy_within(HEADER..end, HEADER + TAG);
        record[HEADER..HEADER + TAG].copy_from_slice(&tag);
        let len = (end - HEADER + TAG) as u16;
        record[3..HEADER].copy_from_slice(&len.to_be_bytes());
    }
}

/// Relays the TLS handshake between `client` and `server` record by record,
/// marking the server's, until the client's first data record, which is
/// returned with the keys of the session. `None` when strict mode refuses
/// the ServerHello, which the client has got by then.
async fn relay_handshake(
    client: &mut Records,
    server: &mut Records,
    password: &[u8],
    strict: bool,
) -> io::Result<Option<(Vec<u8>, Keys)>> {
    let mut keys: Option<Keys> = None;
    loop {
        let (from_client, mut record) = tokio::select! {
            record = client.next_record() => (true, record?),
            record = server.next_record() => (false, record?),
        };
        if from_client {
            if keys.as_mut().is_some_and(|keys| keys.client.opens(&record)) {
                return Ok(keys.map(|keys| (record, keys)));
            }
            server.io.write_all(&record).await?;
            continue;
        }
        if let Some(random) = server_random(&record) {
            if strict && !selects_tls13(&record) {
                client.io.write_all(&record).await?;
                return Ok(None);
            }
            keys = Some(Keys::new(password, random));
        } else if let (APPLICATION_DATA, Some(keys)) = (record[0], &mut keys) {
            keys.mark_relayed(&mut record);
        }
        client.io.write_all(&record).await?;
    }
}

/// What a TLS 1.3 alert looks like on the wire.
fn alert_record() -> [u8; HEADER + ALERT_BODY] {
    let mut record = [0u8; HEADER + ALERT_BODY];
    record[..HEADER].copy_from_slice(&[APPLICATION_DATA, 3, 3, 0, ALERT_BODY as u8]);
    let _ = SystemRandom::new().fill(&mut record[HEADER..]);
    record
}

/// The client connection after the switch: the wrapped protocol's bytes in
/// tagged ApplicationData records, both ways.
struct ShadowStream {
    io: BoxStream,
    /// Client records as received, the first `parsed` bytes checked.
    buf: Vec<u8>,
    parsed: usize,
    /// The part of `buf` that is checked data not read yet.
    data: Range<usize>,
    eof: bool,
    verify: Chain,
    sign: Chain,
    /// Records not yet written out.
    out: Vec<u8>,
    out_pos: usize,
}

impl ShadowStream {
    /// `first` is the client's first data record, already checked.
    fn new(client: Records, mut first: Vec<u8>, keys: Keys) -> Self {
        let parsed = first.len();
        first.extend_from_slice(&client.buf);
        Self {
            io: client.io,
            buf: first,
            parsed,
            data: HEADER + TAG..parsed,
            eof: false,
            verify: keys.client,
            sign: keys.server,
            out: Vec::new(),
            out_pos: 0,
        }
    }

    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.io).poll_write(cx, &self.out[self.out_pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.out_pos += n;
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for ShadowStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.data.is_empty() {
                let n = this.data.len().min(buf.remaining());
                buf.put_slice(&this.buf[this.data.start..this.data.start + n]);
                this.data.start += n;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if let Some(len) = record_len(&this.buf[this.parsed..]) {
                let start = this.parsed;
                this.parsed += len;
                let record = &this.buf[start..this.parsed];
                if this.verify.opens(record) {
                    this.data = start + HEADER + TAG..this.parsed;
                } else if record[0] == ALERT {
                    this.eof = true;
                } else {
                    // Tampered with, replayed or out of order.
                    this.eof = true;
                    this.out.extend_from_slice(&alert_record());
                    let _ = this.poll_drain(cx);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "shadow-tls record failed authentication",
                    )));
                }
                continue;
            }
            this.buf.drain(..this.parsed);
            this.parsed = 0;
            let filled = this.buf.len();
            this.buf.resize(filled + READ_CHUNK, 0);
            let mut read = ReadBuf::new(&mut this.buf[filled..]);
            let polled = Pin::new(&mut this.io).poll_read(cx, &mut read);
            let n = read.filled().len();
            this.buf.truncate(filled + n);
            ready!(polled)?;
            this.eof = n == 0;
        }
    }
}

impl AsyncWrite for ShadowStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        let data = &buf[..buf.len().min(MAX_DATA)];
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let tag = this.sign.tag(data, true);
        this.out.extend_from_slice(&[APPLICATION_DATA, 3, 3]);
        this.out
            .extend_from_slice(&((TAG + data.len()) as u16).to_be_bytes());
        this.out.extend_from_slice(&tag);
        this.out.extend_from_slice(data);
        // The record is committed to `out`; a pending drain finishes on the
        // next call.
        if let Poll::Ready(Err(err)) = this.poll_drain(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The expected tags are the protocol document's rules worked through
    // with another HMAC-SHA1 and SHA-256 implementation.
    const PASSWORD: &[u8] = b"correct horse";

    fn random() -> Vec<u8> {
        (0..32).collect()
    }

    /// A ClientHello record whose session id ends in `tag`.
    fn client_hello(tag: [u8; TAG]) -> Vec<u8> {
        let mut message = vec![CLIENT_HELLO, 0, 0, 0, 3, 3];
        message.extend(32..64u8);
        message.push(SESSION_ID as u8);
        message.extend(100..128u8);
        message.extend_from_slice(&tag);
        // One cipher suite, no compression, no extensions.
        message.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0, 0, 0]);
        message[3] = (message.len() - 4) as u8;
        let mut record = vec![HANDSHAKE, 3, 1, 0, message.len() as u8];
        record.extend_from_slice(&message);
        record
    }

    /// A ServerHello record with the given extensions.
    fn server_hello(extensions: &[u8]) -> Vec<u8> {
        let mut message = vec![SERVER_HELLO, 0, 0, 0, 3, 3];
        message.extend_from_slice(&random());
        message.push(32);
        message.extend(100..132u8);
        message.extend_from_slice(&[0x13, 0x01, 0]);
        if !extensions.is_empty() {
            message.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
            message.extend_from_slice(extensions);
        }
        message[3] = (message.len() - 4) as u8;
        let mut record = vec![HANDSHAKE, 3, 3, 0, message.len() as u8];
        record.extend_from_slice(&message);
        record
    }

    fn data_record(tag: [u8; TAG], data: &[u8]) -> Vec<u8> {
        let mut record = vec![APPLICATION_DATA, 3, 3, 0, (TAG + data.len()) as u8];
        record.extend_from_slice(&tag);
        record.extend_from_slice(data);
        record
    }

    #[test]
    fn checks_the_client_hello_signature() {
        let signed = client_hello([0xff, 0x71, 0x0d, 0x41]);
        assert_eq!(signed.len(), 84);
        assert!(client_hello_signed(&signed, PASSWORD));
        assert!(!client_hello_signed(&signed, b"another password"));
        let other_tag = client_hello([0xff, 0x71, 0x0d, 0x40]);
        assert!(!client_hello_signed(&other_tag, PASSWORD));

        // Every byte of the message is covered, before and after the tag.
        for at in [HEADER, RANDOM_AT, 50, 83] {
            let mut changed = signed.clone();
            changed[at] ^= 1;
            assert!(!client_hello_signed(&changed, PASSWORD), "byte {at}");
        }
        // The record header is not.
        let mut header = signed.clone();
        header[2] = 3;
        assert!(client_hello_signed(&header, PASSWORD));

        let mut other_type = signed.clone();
        other_type[0] = APPLICATION_DATA;
        assert!(!client_hello_signed(&other_type, PASSWORD));
        assert!(!client_hello_signed(&signed[..75], PASSWORD));
        assert!(!client_hello_signed(&[], PASSWORD));
        assert!(!client_hello_signed(&server_hello(&[]), PASSWORD));
    }

    #[test]
    fn reads_the_server_hello() {
        // A key share, then supported_versions.
        let key_share = [0u8, 51, 0, 2, 0, 29];
        let tls13 = server_hello(&[key_share, [0, 43, 0, 2, 3, 4]].concat());
        assert_eq!(server_random(&tls13), Some(&random()[..]));
        assert!(selects_tls13(&tls13));

        // TLS 1.2 servers send no supported_versions, or no extensions.
        let tls12 = server_hello(&key_share);
        assert_eq!(server_random(&tls12), Some(&random()[..]));
        assert!(!selects_tls13(&tls12));
        assert!(!selects_tls13(&server_hello(&[])));
        assert!(!selects_tls13(&server_hello(&[0, 43, 0, 2, 3, 3])));
        // An extension that runs past the end.
        let overrun = server_hello(&[0, 51, 0, 9, 0, 43, 0, 2, 3, 4]);
        assert!(!selects_tls13(&overrun));

        assert_eq!(server_random(&client_hello([0; TAG])), None);
        assert_eq!(server_random(&data_record([0; TAG], b"data")), None);
        assert_eq!(server_random(&[HANDSHAKE, 3, 3, 0, 1, SERVER_HELLO]), None);
    }

    #[test]
    fn finds_whole_records() {
        let record = data_record([1, 2, 3, 4], b"data");
        assert_eq!(record_len(&record), Some(record.len()));
        assert_eq!(record_len(&record[..record.len() - 1]), None);
        assert_eq!(record_len(&record[..4]), None);
        let two = [&record[..], &record[..3]].concat();
        assert_eq!(record_len(&two), Some(record.len()));
    }

    #[test]
    fn tags_follow_the_chains() {
        let mut keys = Keys::new(PASSWORD, &random());
        // Data records feed their tag back, relayed records do not.
        assert_eq!(keys.server.tag(b"hello", true), [0x13, 0xd2, 0x02, 0x55]);
        assert_eq!(keys.relayed.tag(b"hello", false), [0x45, 0x12, 0xc4, 0x27]);
        assert_eq!(keys.relayed.tag(b"world", false), [0x7e, 0x03, 0x0d, 0x9e]);

        let first = data_record([0x15, 0x3d, 0xe3, 0xa8], b"hello");
        let second = data_record([0xe5, 0x37, 0x9b, 0x73], b"world");
        // Out of order, of the other side or not data at all: the chain
        // stays where it was.
        let ours = data_record([0x13, 0xd2, 0x02, 0x55], b"hello");
        let hello = client_hello([0; TAG]);
        let short = [APPLICATION_DATA, 3, 3, 0, 2, 0x15, 0x3d];
        for other in [&second[..], &ours[..], &hello[..], &short[..]] {
            assert!(!keys.client.opens(other));
        }
        assert!(keys.client.opens(&first));
        // A replay, then the record that is due.
        assert!(!keys.client.opens(&first));
        assert!(keys.client.opens(&second));
    }

    #[test]
    fn marks_relayed_application_data() {
        let mut keys = Keys::new(PASSWORD, &random());
        let mut record = vec![APPLICATION_DATA, 3, 3, 0, 40];
        record.extend(0..40u8);
        keys.mark_relayed(&mut record);
        let expected: [u8; 44] = [
            0x1e, 0xfd, 0xa7, 0xd7, 0xe0, 0x1c, 0xb5, 0x1e, 0x1b, 0x50, 0x41, 0x98, 0xbb, 0xa8,
            0xad, 0x65, 0x2e, 0x94, 0xb7, 0xa3, 0xe6, 0x2e, 0x51, 0x1e, 0xb3, 0x7b, 0xc9, 0xad,
            0x5e, 0xe9, 0xf3, 0x31, 0x8d, 0x62, 0x1c, 0x83, 0xc0, 0x3c, 0x95, 0x3e, 0x3b, 0x70,
            0x61, 0xb8,
        ];
        assert_eq!(record[..HEADER], [APPLICATION_DATA, 3, 3, 0, 44]);
        assert_eq!(record[HEADER..], expected);
    }

    #[test]
    fn alerts_look_like_encrypted_records() {
        let alert = alert_record();
        assert_eq!(record_len(&alert), Some(alert.len()));
        assert_eq!(alert[..3], [APPLICATION_DATA, 3, 3]);
        assert_ne!(alert[HEADER..], alert_record()[HEADER..]);
    }
}
