//! TLS 1.3 client handshake: full 1-RTT, or resumed with a session ticket
//! (`psk_dhe_ke`, no 0-RTT). No client auth.

use std::io;
use std::time::{Duration, Instant};

use ml_kem::kem::Decapsulate;
use ml_kem::{Ciphertext, MlKem768};
use ring::hmac;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::cert;
use crate::crypto::{invalid_data, CipherSuite, RecordCipher, MAX_CIPHERTEXT, MAX_PLAINTEXT};
use crate::fingerprint::{
    build_from_spec_with_psk, put_u24, Fingerprint, KeyShareSecrets, PskShape, GROUP_SECP256R1,
    GROUP_X25519, GROUP_X25519_MLKEM768, SESSION_ID_OFFSET,
};
use crate::stream::TlsStream;

const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
pub(crate) const MAX_HANDSHAKE_MESSAGE: usize = 64 * 1024;

/// Client handshake parameters.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Sent as SNI (unless it is an IP literal) and passed to the verifier.
    pub server_name: String,
    pub fingerprint: Fingerprint,
    /// Overrides the fingerprint's ALPN list; `Some(vec![])` sends none.
    pub alpn: Option<Vec<Vec<u8>>>,
}

impl ClientConfig {
    pub fn new(server_name: impl Into<String>, fingerprint: Fingerprint) -> Self {
        Self {
            server_name: server_name.into(),
            fingerprint,
            alpn: None,
        }
    }
}

/// RFC 8446 §4.6.1: a ticket lifetime is at most seven days.
const MAX_TICKET_LIFETIME_SECS: u32 = 7 * 24 * 60 * 60;

/// A TLS 1.3 session ticket together with the pre-shared key it stands for.
/// [`TlsStream::take_session_tickets`] hands out the ones a server sent;
/// [`connect_resuming`] offers one on a later connection to the same server.
#[derive(Clone)]
pub struct SessionTicket {
    /// The ticket as the server sent it; the PSK identity on the wire.
    pub ticket: Vec<u8>,
    /// `HKDF-Expand-Label(resumption_master_secret, "resumption", nonce)`.
    pub psk: Vec<u8>,
    /// Suite of the connection the ticket came from. A resumed connection
    /// must use a suite with the same hash.
    pub suite: CipherSuite,
    pub lifetime_secs: u32,
    pub age_add: u32,
    pub received: Instant,
}

impl SessionTicket {
    /// Whether the ticket is still within its lifetime.
    pub fn usable(&self) -> bool {
        let lifetime = self.lifetime_secs.min(MAX_TICKET_LIFETIME_SECS);
        !self.ticket.is_empty()
            && self.received.elapsed() < Duration::from_secs(u64::from(lifetime))
    }

    /// RFC 8446 §4.2.11.1: age in milliseconds plus `age_add`, modulo 2^32.
    fn obfuscated_age(&self) -> u32 {
        (self.received.elapsed().as_millis() as u32).wrapping_add(self.age_add)
    }
}

/// HMAC key of a resumption PSK binder (RFC 8446 §4.2.11.2).
pub(crate) fn binder_finished_key(suite: CipherSuite, psk: &[u8]) -> Vec<u8> {
    let hash = suite.hash();
    let early_secret = hash.hkdf_extract(&[], psk);
    let binder_key = hash.derive_secret(&early_secret, "res binder", &hash.hash(&[]));
    hash.expand_label(&binder_key, "finished", &[], hash.output_len())
}

/// Data available to [`HandshakeHooks::edit_client_hello`].
pub struct HelloContext<'a> {
    pub random: &'a [u8; 32],
    secrets: &'a KeyShareSecrets,
}

impl HelloContext<'_> {
    /// X25519 between the ClientHello's ephemeral key and `peer_public`.
    pub fn x25519_shared(&self, peer_public: &[u8; 32]) -> io::Result<[u8; 32]> {
        self.secrets.x25519_shared(peer_public)
    }
}

/// Protocol-specific behaviour layered on the handshake.
pub trait HandshakeHooks: Send {
    /// Edits the encoded ClientHello handshake message before it is sent. The
    /// legacy session id occupies bytes `39..71`. When a session ticket is
    /// offered the message ends with the pre_shared_key extension, and its
    /// binder is still zero here: the binder is computed after this hook.
    fn edit_client_hello(
        &mut self,
        _ctx: &HelloContext<'_>,
        _message: &mut [u8],
    ) -> io::Result<()> {
        Ok(())
    }

    /// Decides whether the server certificate chain (leaf first, DER) is
    /// trusted. The handshake additionally checks CertificateVerify with the
    /// leaf key and the Finished MAC.
    fn verify_server_certificates(
        &mut self,
        server_name: &str,
        chain: &[Vec<u8>],
    ) -> io::Result<()>;
}

/// Runs the TLS 1.3 handshake over `io` and returns the established stream.
pub async fn connect<S>(
    io: S,
    config: &ClientConfig,
    hooks: &mut dyn HandshakeHooks,
) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    connect_resuming(io, config, hooks, None).await
}

/// [`connect`], offering `ticket` for resumption when it is still usable and
/// the fingerprint offers `psk_dhe_ke`. The server may accept it (the
/// handshake then has no certificate, [`HandshakeHooks::verify_server_certificates`]
/// is not called and [`TlsStream::resumed`] is true: the server proved it
/// holds the PSK) or decline it, which gives an ordinary full handshake.
/// Only offer a ticket to the server it came from.
pub async fn connect_resuming<S>(
    mut io: S,
    config: &ClientConfig,
    hooks: &mut dyn HandshakeHooks,
    ticket: Option<&SessionTicket>,
) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let spec = config.fingerprint.spec()?;
    let offered = ticket.filter(|ticket| ticket.usable() && spec.offers_psk_dhe_ke());
    let mut hello = build_from_spec_with_psk(
        &spec,
        &config.server_name,
        config.alpn.as_deref(),
        offered.map(|ticket| PskShape {
            identity: &ticket.ticket,
            obfuscated_age: ticket.obfuscated_age(),
            binder_len: ticket.suite.hash().output_len(),
        }),
    )?;
    {
        let ctx = HelloContext {
            random: &hello.random,
            secrets: &hello.secrets,
        };
        hooks.edit_client_hello(&ctx, &mut hello.message)?;
    }
    if let Some(ticket) = offered {
        // The binder covers the ClientHello up to the binders list.
        let hash = ticket.suite.hash();
        let total = hello.message.len();
        let truncated = total
            .checked_sub(hello.psk_binders_len)
            .ok_or_else(|| invalid_data("ClientHello shorter than its PSK binders"))?;
        let binder = hash.hmac(
            &binder_finished_key(ticket.suite, &ticket.psk),
            &hash.hash(&hello.message[..truncated]),
        );
        let start = total
            .checked_sub(binder.len())
            .filter(|start| *start >= truncated)
            .ok_or_else(|| invalid_data("PSK binder does not fit the ClientHello"))?;
        hello.message[start..].copy_from_slice(&binder);
    }
    if hello.message.len() > MAX_PLAINTEXT {
        return Err(invalid_data("ClientHello too large"));
    }
    let mut record = Vec::with_capacity(5 + hello.message.len());
    record.extend_from_slice(&[0x16, 0x03, 0x01]);
    record.extend_from_slice(&(hello.message.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello.message);
    io.write_all(&record).await?;
    io.flush().await?;

    let mut transcript = hello.message.clone();
    let mut handshake = HandshakeBuffer::default();

    let server_hello = loop {
        if let Some(message) = handshake.next_message()? {
            break message;
        }
        let (header, payload) = read_record(&mut io).await?;
        match header[0] {
            0x16 => handshake.push(&payload),
            0x15 => return Err(alert_from_payload(&payload)),
            0x14 => {}
            _ => return Err(invalid_data("unexpected record before ServerHello")),
        }
    };
    if server_hello[0] != 2 {
        return Err(invalid_data("expected TLS ServerHello"));
    }
    let parsed = parse_server_hello(&server_hello[4..])?;
    if parsed.session_id != hello.message[SESSION_ID_OFFSET..SESSION_ID_OFFSET + 32] {
        return Err(invalid_data("ServerHello session id mismatch"));
    }
    if !handshake.is_empty() {
        return Err(invalid_data("unencrypted data after ServerHello"));
    }
    transcript.extend_from_slice(&server_hello);

    let suite = parsed.suite;
    let hash = suite.hash();
    // The server resumes by selecting the one identity that was offered.
    let resumed = match (parsed.selected_psk, offered) {
        (None, _) => None,
        (Some(0), Some(ticket)) if ticket.suite.hash() == hash => Some(ticket),
        _ => {
            return Err(invalid_data(
                "server selected a pre-shared key that was not offered",
            ))
        }
    };
    let shared = shared_secret(&hello.secrets, parsed.group, &parsed.key_share)?;
    let zeros = vec![0u8; hash.output_len()];
    let empty_hash = hash.hash(&[]);
    let early_secret = match resumed {
        Some(ticket) => hash.hkdf_extract(&[], &ticket.psk),
        None => hash.hkdf_extract(&[], &zeros),
    };
    let derived = hash.derive_secret(&early_secret, "derived", &empty_hash);
    let handshake_secret = hash.hkdf_extract(&derived, &shared);
    let hello_hash = hash.hash(&transcript);
    let client_hs = hash.derive_secret(&handshake_secret, "c hs traffic", &hello_hash);
    let server_hs = hash.derive_secret(&handshake_secret, "s hs traffic", &hello_hash);
    let mut server_cipher = RecordCipher::new(suite, &server_hs)?;
    let mut client_cipher = RecordCipher::new(suite, &client_hs)?;

    let mut state = Expect::EncryptedExtensions;
    let mut alpn = None;
    let mut leaf: Vec<u8> = Vec::new();
    loop {
        let message = match handshake.next_message()? {
            Some(message) => message,
            None => {
                let (header, mut payload) = read_record(&mut io).await?;
                match header[0] {
                    0x14 => {}
                    0x17 => match server_cipher.open(&header, &mut payload)? {
                        0x16 => handshake.push(&payload),
                        0x15 => return Err(alert_from_payload(&payload)),
                        _ => {
                            return Err(invalid_data(
                                "unexpected encrypted record during handshake",
                            ))
                        }
                    },
                    0x15 => return Err(alert_from_payload(&payload)),
                    _ => return Err(invalid_data("unexpected record during handshake")),
                }
                continue;
            }
        };
        match (state, message[0]) {
            (Expect::EncryptedExtensions, 8) => {
                alpn = parse_encrypted_extensions(&message[4..])?;
                state = Expect::Certificate;
            }
            (Expect::Certificate, 11) if resumed.is_none() => {
                let chain = parse_certificate(&message[4..])?;
                hooks.verify_server_certificates(&config.server_name, &chain)?;
                leaf = chain.into_iter().next().unwrap_or_default();
                state = Expect::CertificateVerify;
            }
            (Expect::Certificate, 13) => {
                return Err(invalid_data("TLS client certificates are not supported"))
            }
            (Expect::Certificate, 25) => {
                return Err(invalid_data(
                    "compressed TLS certificates are not supported",
                ))
            }
            (Expect::CertificateVerify, 15) => {
                let (scheme, signature) = parse_certificate_verify(&message[4..])?;
                let mut content = vec![0x20u8; 64];
                content.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
                content.extend_from_slice(&hash.hash(&transcript));
                let leaf_fields = cert::parse_leaf(&leaf)
                    .ok_or_else(|| invalid_data("malformed server certificate"))?;
                cert::verify_signature(scheme, &leaf_fields, &content, signature)?;
                state = Expect::Finished;
            }
            // A resumed handshake has no Certificate and CertificateVerify:
            // the Finished MAC, keyed through the PSK, authenticates the server.
            (Expect::Finished, 20) | (Expect::Certificate, 20)
                if state == Expect::Finished || resumed.is_some() =>
            {
                let finished_key =
                    hash.expand_label(&server_hs, "finished", &[], hash.output_len());
                let key = hmac::Key::new(hash.hmac_algorithm(), &finished_key);
                hmac::verify(&key, &hash.hash(&transcript), &message[4..])
                    .map_err(|_| invalid_data("TLS server Finished verification failed"))?;
                transcript.extend_from_slice(&message);
                break;
            }
            _ => return Err(invalid_data("unexpected TLS handshake message")),
        }
        transcript.extend_from_slice(&message);
    }
    if !handshake.is_empty() {
        return Err(invalid_data("handshake data after server Finished"));
    }

    let derived = hash.derive_secret(&handshake_secret, "derived", &empty_hash);
    let master_secret = hash.hkdf_extract(&derived, &zeros);
    let server_finished_hash = hash.hash(&transcript);
    let client_ap = hash.derive_secret(&master_secret, "c ap traffic", &server_finished_hash);
    let server_ap = hash.derive_secret(&master_secret, "s ap traffic", &server_finished_hash);

    // Middlebox-compatibility ChangeCipherSpec, then the client Finished.
    let mut flight = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
    let finished_key = hash.expand_label(&client_hs, "finished", &[], hash.output_len());
    let verify_data = hash.hmac(&finished_key, &server_finished_hash);
    let mut finished = vec![20];
    put_u24(&mut finished, verify_data.len());
    finished.extend_from_slice(&verify_data);
    client_cipher.seal(0x16, &finished, &mut flight)?;
    io.write_all(&flight).await?;
    io.flush().await?;

    transcript.extend_from_slice(&finished);
    let resumption_secret =
        hash.derive_secret(&master_secret, "res master", &hash.hash(&transcript));
    let mut stream = TlsStream::from_secrets(io, suite, client_ap, server_ap, alpn)?;
    stream.set_resumption_secret(resumption_secret);
    stream.set_resumed(resumed.is_some());
    Ok(stream)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    EncryptedExtensions,
    Certificate,
    CertificateVerify,
    Finished,
}

#[derive(Default)]
pub(crate) struct HandshakeBuffer {
    data: Vec<u8>,
}

impl HandshakeBuffer {
    pub(crate) fn push(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub(crate) fn next_message(&mut self) -> io::Result<Option<Vec<u8>>> {
        if self.data.len() < 4 {
            return Ok(None);
        }
        let len = ((self.data[1] as usize) << 16)
            | ((self.data[2] as usize) << 8)
            | self.data[3] as usize;
        if len > MAX_HANDSHAKE_MESSAGE {
            return Err(invalid_data("TLS handshake message too large"));
        }
        if self.data.len() < 4 + len {
            return Ok(None);
        }
        Ok(Some(self.data.drain(..4 + len).collect()))
    }
}

pub(crate) async fn read_record<S: AsyncRead + Unpin>(
    io: &mut S,
) -> io::Result<([u8; 5], Vec<u8>)> {
    let mut header = [0u8; 5];
    io.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > MAX_CIPHERTEXT {
        return Err(invalid_data("TLS record too large"));
    }
    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload).await?;
    Ok((header, payload))
}

/// Big-endian cursor over handshake message bodies.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub(crate) fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        if self.data.len() < n {
            return Err(invalid_data("truncated TLS handshake message"));
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Ok(head)
    }

    pub(crate) fn u8(&mut self) -> io::Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16(&mut self) -> io::Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub(crate) fn u24(&mut self) -> io::Result<usize> {
        let bytes = self.take(3)?;
        Ok(((bytes[0] as usize) << 16) | ((bytes[1] as usize) << 8) | bytes[2] as usize)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

struct ServerHello {
    session_id: Vec<u8>,
    suite: CipherSuite,
    group: u16,
    key_share: Vec<u8>,
    /// `selected_identity` of a pre_shared_key extension.
    selected_psk: Option<u16>,
}

fn parse_server_hello(body: &[u8]) -> io::Result<ServerHello> {
    let mut reader = Reader::new(body);
    if reader.u16()? != 0x0303 {
        return Err(invalid_data("unexpected ServerHello legacy version"));
    }
    if reader.take(32)? == HELLO_RETRY_REQUEST_RANDOM {
        return Err(invalid_data("TLS HelloRetryRequest is not supported"));
    }
    let session_id_len = reader.u8()? as usize;
    let session_id = reader.take(session_id_len)?.to_vec();
    let suite = CipherSuite::from_u16(reader.u16()?)
        .ok_or_else(|| invalid_data("server selected an unsupported cipher suite"))?;
    if reader.u8()? != 0 {
        return Err(invalid_data("server selected TLS compression"));
    }
    let extensions_len = reader.u16()? as usize;
    let mut extensions = Reader::new(reader.take(extensions_len)?);
    let mut version = None;
    let mut key_share = None;
    let mut selected_psk = None;
    while !extensions.is_empty() {
        let ext_type = extensions.u16()?;
        let ext_len = extensions.u16()? as usize;
        let mut data = Reader::new(extensions.take(ext_len)?);
        match ext_type {
            0x0029 => selected_psk = Some(data.u16()?),
            0x002b => version = Some(data.u16()?),
            0x0033 => {
                let group = data.u16()?;
                let len = data.u16()? as usize;
                key_share = Some((group, data.take(len)?.to_vec()));
            }
            _ => {}
        }
    }
    if version != Some(0x0304) {
        return Err(invalid_data("server did not negotiate TLS 1.3"));
    }
    let (group, key_share) =
        key_share.ok_or_else(|| invalid_data("ServerHello without key share"))?;
    Ok(ServerHello {
        session_id,
        suite,
        group,
        key_share,
        selected_psk,
    })
}

fn shared_secret(secrets: &KeyShareSecrets, group: u16, share: &[u8]) -> io::Result<Vec<u8>> {
    match group {
        GROUP_X25519 => {
            let peer: [u8; 32] = share
                .try_into()
                .map_err(|_| invalid_data("invalid X25519 key share"))?;
            Ok(secrets.x25519_shared(&peer)?.to_vec())
        }
        GROUP_X25519_MLKEM768 => {
            if share.len() != MLKEM768_CIPHERTEXT_LEN + 32 {
                return Err(invalid_data("invalid X25519MLKEM768 key share"));
            }
            let mlkem = secrets
                .mlkem768
                .as_ref()
                .ok_or_else(|| invalid_data("server selected X25519MLKEM768 without an offer"))?;
            let ciphertext = Ciphertext::<MlKem768>::try_from(&share[..MLKEM768_CIPHERTEXT_LEN])
                .map_err(|_| invalid_data("invalid ML-KEM ciphertext"))?;
            let mlkem_shared = mlkem
                .decapsulation
                .decapsulate(&ciphertext)
                .map_err(|_| invalid_data("ML-KEM decapsulation failed"))?;
            let peer: [u8; 32] = share[MLKEM768_CIPHERTEXT_LEN..]
                .try_into()
                .map_err(|_| invalid_data("invalid X25519 key share"))?;
            let mut shared = mlkem_shared.as_slice().to_vec();
            shared.extend_from_slice(&secrets.x25519_shared(&peer)?);
            Ok(shared)
        }
        GROUP_SECP256R1 => secrets.secp256r1_shared(share),
        _ => Err(invalid_data(
            "server selected an unsupported key share group",
        )),
    }
}

fn parse_encrypted_extensions(body: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let mut reader = Reader::new(body);
    let len = reader.u16()? as usize;
    let mut extensions = Reader::new(reader.take(len)?);
    let mut alpn = None;
    while !extensions.is_empty() {
        let ext_type = extensions.u16()?;
        let ext_len = extensions.u16()? as usize;
        let data = extensions.take(ext_len)?;
        if ext_type == 0x0010 {
            let mut list = Reader::new(data);
            let list_len = list.u16()? as usize;
            let mut protocols = Reader::new(list.take(list_len)?);
            let name_len = protocols.u8()? as usize;
            alpn = Some(protocols.take(name_len)?.to_vec());
        }
    }
    Ok(alpn)
}

fn parse_certificate(body: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    let mut reader = Reader::new(body);
    let context_len = reader.u8()? as usize;
    reader.take(context_len)?;
    let list_len = reader.u24()?;
    let mut list = Reader::new(reader.take(list_len)?);
    let mut chain = Vec::new();
    while !list.is_empty() {
        let cert_len = list.u24()?;
        chain.push(list.take(cert_len)?.to_vec());
        let ext_len = list.u16()? as usize;
        list.take(ext_len)?;
    }
    if chain.is_empty() {
        return Err(invalid_data("server sent an empty certificate chain"));
    }
    Ok(chain)
}

fn parse_certificate_verify(body: &[u8]) -> io::Result<(u16, &[u8])> {
    let mut reader = Reader::new(body);
    let scheme = reader.u16()?;
    let len = reader.u16()? as usize;
    Ok((scheme, reader.take(len)?))
}

pub(crate) fn alert_from_payload(payload: &[u8]) -> io::Error {
    match payload {
        [_, description] => crate::alert_error(*description),
        _ => invalid_data("malformed TLS alert"),
    }
}
