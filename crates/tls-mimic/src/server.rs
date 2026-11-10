//! TLS 1.3 server handshake (X25519 only): full 1-RTT with an Ed25519
//! certificate, or resumed from a session ticket the caller recognises.
//!
//! Built for REALITY-style servers: the caller reads and inspects the
//! ClientHello first ([`read_client_hello`], [`parse_client_hello`]), decides
//! whether to serve the client itself or hand the consumed bytes to another
//! server, and only then runs [`accept`] or, for a ClientHello that offers a
//! ticket the caller issued ([`parse_psk_offer`]), [`accept_resumed`]. No
//! HelloRetryRequest, 0-RTT or client certificates.

use std::io;

use ring::hmac;
use ring::signature::Ed25519KeyPair;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{fill_random, invalid_data, CipherSuite, RecordCipher, MAX_PLAINTEXT};
use crate::fingerprint::{put_u16, put_u24, GROUP_X25519, GROUP_X25519_MLKEM768};
use crate::handshake::{
    alert_from_payload, binder_finished_key, read_record, HandshakeBuffer, Reader,
    MAX_HANDSHAKE_MESSAGE,
};
use crate::stream::TlsStream;

/// Server preference order.
const SUITES: [CipherSuite; 3] = [
    CipherSuite::Aes128GcmSha256,
    CipherSuite::Chacha20Poly1305Sha256,
    CipherSuite::Aes256GcmSha384,
];
const SCHEME_ED25519: u16 = 0x0807;
const MLKEM768_ENCAPSULATION_LEN: usize = 1184;

/// The fields of a ClientHello a server needs.
#[derive(Clone, Debug)]
pub struct ClientHelloInfo {
    /// Handshake message bytes (type, 24-bit length, body).
    pub message: Vec<u8>,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub server_name: Option<String>,
    pub cipher_suites: Vec<u16>,
    /// The X25519 key share, or the X25519 half of an X25519MLKEM768 share.
    pub x25519_share: Option<[u8; 32]>,
    pub alpn: Vec<Vec<u8>>,
    /// Whether `supported_versions` offers TLS 1.3.
    pub tls13: bool,
}

/// Reads TLS records until one complete ClientHello message arrived. Every
/// byte read is appended to `consumed`, also on error, so the caller can
/// replay the connection to another server.
pub async fn read_client_hello<S: AsyncRead + Unpin>(
    io: &mut S,
    consumed: &mut Vec<u8>,
) -> io::Result<Vec<u8>> {
    let mut handshake = HandshakeBuffer::default();
    loop {
        if let Some(message) = handshake.next_message()? {
            if message[0] != 1 || !handshake.is_empty() {
                return Err(invalid_data("expected a lone TLS ClientHello"));
            }
            return Ok(message);
        }
        if consumed.len() > MAX_HANDSHAKE_MESSAGE {
            return Err(invalid_data("TLS ClientHello too large"));
        }
        let mut header = [0u8; 5];
        read_exact_into(io, &mut header, consumed).await?;
        if header[0] != 0x16 {
            return Err(invalid_data("expected a TLS handshake record"));
        }
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if len == 0 || len > MAX_PLAINTEXT {
            return Err(invalid_data("invalid TLS record length"));
        }
        let mut payload = vec![0u8; len];
        read_exact_into(io, &mut payload, consumed).await?;
        handshake.push(&payload);
    }
}

/// `read_exact` that records what it got even when the stream ends early.
async fn read_exact_into<S: AsyncRead + Unpin>(
    io: &mut S,
    buf: &mut [u8],
    consumed: &mut Vec<u8>,
) -> io::Result<()> {
    use tokio::io::AsyncReadExt;
    let mut filled = 0;
    while filled < buf.len() {
        let n = io.read(&mut buf[filled..]).await?;
        consumed.extend_from_slice(&buf[filled..filled + n]);
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        filled += n;
    }
    Ok(())
}

/// Parses a ClientHello handshake message.
pub fn parse_client_hello(message: &[u8]) -> io::Result<ClientHelloInfo> {
    let mut outer = Reader::new(message);
    if outer.u8()? != 1 {
        return Err(invalid_data("expected TLS ClientHello"));
    }
    let len = outer.u24()?;
    let mut reader = Reader::new(outer.take(len)?);
    reader.u16()?;
    let mut random = [0u8; 32];
    random.copy_from_slice(reader.take(32)?);
    let session_id_len = reader.u8()? as usize;
    let session_id = reader.take(session_id_len)?.to_vec();
    let suites_len = reader.u16()? as usize;
    let mut suites = Reader::new(reader.take(suites_len)?);
    let mut cipher_suites = Vec::new();
    while !suites.is_empty() {
        cipher_suites.push(suites.u16()?);
    }
    let compression_len = reader.u8()? as usize;
    reader.take(compression_len)?;
    let mut info = ClientHelloInfo {
        message: message.to_vec(),
        random,
        session_id,
        server_name: None,
        cipher_suites,
        x25519_share: None,
        alpn: Vec::new(),
        tls13: false,
    };
    if reader.is_empty() {
        return Ok(info);
    }
    let extensions_len = reader.u16()? as usize;
    let mut extensions = Reader::new(reader.take(extensions_len)?);
    let mut hybrid_share = None;
    while !extensions.is_empty() {
        let ext_type = extensions.u16()?;
        let ext_len = extensions.u16()? as usize;
        let mut data = Reader::new(extensions.take(ext_len)?);
        match ext_type {
            0x0000 => {
                let list_len = data.u16()? as usize;
                let mut list = Reader::new(data.take(list_len)?);
                while !list.is_empty() {
                    let name_type = list.u8()?;
                    let name_len = list.u16()? as usize;
                    let name = list.take(name_len)?;
                    if name_type == 0 {
                        info.server_name = std::str::from_utf8(name).ok().map(str::to_owned);
                    }
                }
            }
            0x0010 => {
                let list_len = data.u16()? as usize;
                let mut list = Reader::new(data.take(list_len)?);
                while !list.is_empty() {
                    let protocol_len = list.u8()? as usize;
                    info.alpn.push(list.take(protocol_len)?.to_vec());
                }
            }
            0x002b => {
                let list_len = data.u8()? as usize;
                let mut list = Reader::new(data.take(list_len)?);
                while !list.is_empty() {
                    if list.u16()? == 0x0304 {
                        info.tls13 = true;
                    }
                }
            }
            0x0033 => {
                let list_len = data.u16()? as usize;
                let mut list = Reader::new(data.take(list_len)?);
                while !list.is_empty() {
                    let group = list.u16()?;
                    let share_len = list.u16()? as usize;
                    let share = list.take(share_len)?;
                    match group {
                        GROUP_X25519 if share.len() == 32 => {
                            info.x25519_share = share.try_into().ok();
                        }
                        GROUP_X25519_MLKEM768 if share.len() == MLKEM768_ENCAPSULATION_LEN + 32 => {
                            hybrid_share = share[MLKEM768_ENCAPSULATION_LEN..].try_into().ok();
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    if info.x25519_share.is_none() {
        info.x25519_share = hybrid_share;
    }
    Ok(info)
}

/// The first pre-shared key a ClientHello offers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PskOffer {
    /// The PSK identity: a session ticket, as the client got it.
    pub identity: Vec<u8>,
    pub obfuscated_age: u32,
    pub binder: Vec<u8>,
    /// Length of the binders list at the end of the ClientHello (its two-byte
    /// length included). The binder covers the message up to that list.
    pub binders_len: usize,
}

/// The first PSK identity and binder of a ClientHello, if it offers one and
/// allows `psk_dhe_ke`. pre_shared_key must be the last extension.
pub fn parse_psk_offer(message: &[u8]) -> io::Result<Option<PskOffer>> {
    let mut outer = Reader::new(message);
    if outer.u8()? != 1 {
        return Err(invalid_data("expected TLS ClientHello"));
    }
    let len = outer.u24()?;
    let mut reader = Reader::new(outer.take(len)?);
    reader.take(34)?;
    let session_id_len = reader.u8()? as usize;
    reader.take(session_id_len)?;
    let suites_len = reader.u16()? as usize;
    reader.take(suites_len)?;
    let compression_len = reader.u8()? as usize;
    reader.take(compression_len)?;
    if reader.is_empty() {
        return Ok(None);
    }
    let extensions_len = reader.u16()? as usize;
    let mut extensions = Reader::new(reader.take(extensions_len)?);
    let mut psk_dhe_ke = false;
    let mut offer = None;
    while !extensions.is_empty() {
        let ext_type = extensions.u16()?;
        let ext_len = extensions.u16()? as usize;
        let mut data = Reader::new(extensions.take(ext_len)?);
        match ext_type {
            0x002d => {
                let modes_len = data.u8()? as usize;
                psk_dhe_ke = data.take(modes_len)?.contains(&1);
            }
            0x0029 => {
                if !extensions.is_empty() {
                    return Err(invalid_data("pre_shared_key is not the last extension"));
                }
                let identities_len = data.u16()? as usize;
                let mut identities = Reader::new(data.take(identities_len)?);
                let identity_len = identities.u16()? as usize;
                let identity = identities.take(identity_len)?.to_vec();
                let age = identities.take(4)?;
                let obfuscated_age = u32::from_be_bytes([age[0], age[1], age[2], age[3]]);
                let binders_len = data.u16()? as usize;
                let mut binders = Reader::new(data.take(binders_len)?);
                let binder_len = binders.u8()? as usize;
                let binder = binders.take(binder_len)?.to_vec();
                if !data.is_empty() || identity.is_empty() {
                    return Err(invalid_data("malformed pre_shared_key extension"));
                }
                offer = Some(PskOffer {
                    identity,
                    obfuscated_age,
                    binder,
                    binders_len: binders_len + 2,
                });
            }
            _ => {}
        }
    }
    Ok(offer.filter(|_| psk_dhe_ke))
}

/// Whether `offer`'s binder proves the client holds `psk` (RFC 8446
/// §4.2.11.2). `message` is the ClientHello the offer was parsed from and
/// `suite` the suite of the connection that issued the ticket.
pub fn psk_binder_valid(message: &[u8], offer: &PskOffer, suite: CipherSuite, psk: &[u8]) -> bool {
    let Some(truncated) = message.len().checked_sub(offer.binders_len) else {
        return false;
    };
    let hash = suite.hash();
    let key = hmac::Key::new(hash.hmac_algorithm(), &binder_finished_key(suite, psk));
    hmac::verify(&key, &hash.hash(&message[..truncated]), &offer.binder).is_ok()
}

/// How the server authenticates itself.
#[derive(Clone, Copy)]
enum Auth<'a> {
    Certificate(&'a ServerIdentity<'a>),
    /// Resumption: the pre-shared key behind the ticket the client offered.
    Psk(&'a [u8]),
}

/// The server's certificate and the key that signs CertificateVerify.
pub struct ServerIdentity<'a> {
    /// DER certificates, leaf first; the leaf must hold `signer`'s key.
    pub certificate_chain: &'a [Vec<u8>],
    pub signer: &'a Ed25519KeyPair,
    /// ALPN protocols in server preference order.
    pub alpn: &'a [Vec<u8>],
}

/// Completes the handshake for an already read ClientHello and returns the
/// established stream. Only X25519 key exchange is offered, using the
/// client's X25519 share (see [`ClientHelloInfo::x25519_share`]).
pub async fn accept<S>(
    io: S,
    hello: &ClientHelloInfo,
    identity: &ServerIdentity<'_>,
) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let suite = SUITES
        .into_iter()
        .find(|suite| hello.cipher_suites.contains(&suite.id()))
        .ok_or_else(|| invalid_data("no shared TLS 1.3 cipher suite"))?;
    accept_with(io, hello, suite, identity.alpn, Auth::Certificate(identity)).await
}

/// Completes a resumed handshake (`psk_dhe_ke`): no certificate, the server
/// Finished proves it holds `psk`. The caller found `psk` and `suite` (the
/// suite of the connection that issued the ticket) from the identity in
/// [`parse_psk_offer`]; the binder is checked here. Fails without writing
/// anything when the ClientHello does not offer that key, so the caller can
/// still fall back to [`accept`].
pub async fn accept_resumed<S>(
    io: S,
    hello: &ClientHelloInfo,
    alpn: &[Vec<u8>],
    suite: CipherSuite,
    psk: &[u8],
) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let offer = parse_psk_offer(&hello.message)?
        .ok_or_else(|| invalid_data("client offers no pre-shared key"))?;
    if !hello.cipher_suites.contains(&suite.id())
        || !psk_binder_valid(&hello.message, &offer, suite, psk)
    {
        return Err(invalid_data("TLS PSK binder verification failed"));
    }
    accept_with(io, hello, suite, alpn, Auth::Psk(psk)).await
}

async fn accept_with<S>(
    mut io: S,
    hello: &ClientHelloInfo,
    suite: CipherSuite,
    offered_alpn: &[Vec<u8>],
    auth: Auth<'_>,
) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !hello.tls13 {
        return Err(invalid_data("client does not offer TLS 1.3"));
    }
    let peer = hello
        .x25519_share
        .ok_or_else(|| invalid_data("client sent no X25519 key share"))?;
    let secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let shared = secret.diffie_hellman(&PublicKey::from(peer)).to_bytes();
    if shared.iter().all(|byte| *byte == 0) {
        return Err(invalid_data(
            "X25519 produced a non-contributory shared secret",
        ));
    }
    let alpn = offered_alpn
        .iter()
        .find(|protocol| hello.alpn.contains(protocol))
        .cloned();

    let server_hello = server_hello(
        hello,
        suite,
        &PublicKey::from(&secret).to_bytes(),
        matches!(auth, Auth::Psk(_)),
    )?;
    let mut transcript = hello.message.clone();
    transcript.extend_from_slice(&server_hello);

    let hash = suite.hash();
    let zeros = vec![0u8; hash.output_len()];
    let empty_hash = hash.hash(&[]);
    let early_secret = match auth {
        Auth::Psk(psk) => hash.hkdf_extract(&[], psk),
        Auth::Certificate(_) => hash.hkdf_extract(&[], &zeros),
    };
    let derived = hash.derive_secret(&early_secret, "derived", &empty_hash);
    let handshake_secret = hash.hkdf_extract(&derived, &shared);
    let hello_hash = hash.hash(&transcript);
    let client_hs = hash.derive_secret(&handshake_secret, "c hs traffic", &hello_hash);
    let server_hs = hash.derive_secret(&handshake_secret, "s hs traffic", &hello_hash);
    let mut server_cipher = RecordCipher::new(suite, &server_hs)?;
    let mut client_cipher = RecordCipher::new(suite, &client_hs)?;

    let mut flight = Vec::new();
    let encrypted_extensions = handshake_message(8, &encrypted_extensions(alpn.as_deref()));
    transcript.extend_from_slice(&encrypted_extensions);
    flight.extend_from_slice(&encrypted_extensions);
    if let Auth::Certificate(identity) = auth {
        let certificate = handshake_message(11, &certificate_body(identity.certificate_chain));
        transcript.extend_from_slice(&certificate);
        flight.extend_from_slice(&certificate);

        let mut content = vec![0x20u8; 64];
        content.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
        content.extend_from_slice(&hash.hash(&transcript));
        let signature = identity.signer.sign(&content);
        let mut verify = Vec::new();
        put_u16(&mut verify, SCHEME_ED25519);
        put_u16(&mut verify, signature.as_ref().len() as u16);
        verify.extend_from_slice(signature.as_ref());
        let certificate_verify = handshake_message(15, &verify);
        transcript.extend_from_slice(&certificate_verify);
        flight.extend_from_slice(&certificate_verify);
    }

    let finished_key = hash.expand_label(&server_hs, "finished", &[], hash.output_len());
    let finished = handshake_message(20, &hash.hmac(&finished_key, &hash.hash(&transcript)));
    transcript.extend_from_slice(&finished);
    flight.extend_from_slice(&finished);

    let mut out = Vec::with_capacity(server_hello.len() + flight.len() + 64);
    out.extend_from_slice(&[0x16, 0x03, 0x03]);
    out.extend_from_slice(&(server_hello.len() as u16).to_be_bytes());
    out.extend_from_slice(&server_hello);
    out.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
    for chunk in flight.chunks(MAX_PLAINTEXT) {
        server_cipher.seal(0x16, chunk, &mut out)?;
    }
    io.write_all(&out).await?;
    io.flush().await?;

    let server_finished_hash = hash.hash(&transcript);
    let derived = hash.derive_secret(&handshake_secret, "derived", &empty_hash);
    let master_secret = hash.hkdf_extract(&derived, &zeros);
    let client_ap = hash.derive_secret(&master_secret, "c ap traffic", &server_finished_hash);
    let server_ap = hash.derive_secret(&master_secret, "s ap traffic", &server_finished_hash);

    let mut handshake = HandshakeBuffer::default();
    let client_finished = loop {
        if let Some(message) = handshake.next_message()? {
            break message;
        }
        let (header, mut payload) = read_record(&mut io).await?;
        match header[0] {
            0x14 => {}
            0x17 => match client_cipher.open(&header, &mut payload)? {
                0x16 => handshake.push(&payload),
                0x15 => return Err(alert_from_payload(&payload)),
                _ => return Err(invalid_data("unexpected record before client Finished")),
            },
            0x15 => return Err(alert_from_payload(&payload)),
            _ => return Err(invalid_data("unexpected record before client Finished")),
        }
    };
    if client_finished[0] != 20 || !handshake.is_empty() {
        return Err(invalid_data("expected TLS client Finished"));
    }
    let finished_key = hash.expand_label(&client_hs, "finished", &[], hash.output_len());
    let key = hmac::Key::new(hash.hmac_algorithm(), &finished_key);
    hmac::verify(&key, &server_finished_hash, &client_finished[4..])
        .map_err(|_| invalid_data("TLS client Finished verification failed"))?;

    transcript.extend_from_slice(&client_finished);
    let resumption_secret =
        hash.derive_secret(&master_secret, "res master", &hash.hash(&transcript));
    let mut stream = TlsStream::from_secrets(io, suite, server_ap, client_ap, alpn)?;
    stream.set_resumption_secret(resumption_secret);
    stream.set_resumed(matches!(auth, Auth::Psk(_)));
    Ok(stream)
}

fn server_hello(
    hello: &ClientHelloInfo,
    suite: CipherSuite,
    public: &[u8; 32],
    resumed: bool,
) -> io::Result<Vec<u8>> {
    let mut random = [0u8; 32];
    fill_random(&mut random)?;
    let mut body = Vec::with_capacity(128);
    put_u16(&mut body, 0x0303);
    body.extend_from_slice(&random);
    body.push(hello.session_id.len() as u8);
    body.extend_from_slice(&hello.session_id);
    put_u16(&mut body, suite.id());
    body.push(0);
    let mut extensions = Vec::with_capacity(46);
    put_u16(&mut extensions, 0x002b);
    put_u16(&mut extensions, 2);
    put_u16(&mut extensions, 0x0304);
    put_u16(&mut extensions, 0x0033);
    put_u16(&mut extensions, 36);
    put_u16(&mut extensions, GROUP_X25519);
    put_u16(&mut extensions, 32);
    extensions.extend_from_slice(public);
    if resumed {
        // pre_shared_key: the first (and only considered) identity.
        put_u16(&mut extensions, 0x0029);
        put_u16(&mut extensions, 2);
        put_u16(&mut extensions, 0);
    }
    put_u16(&mut body, extensions.len() as u16);
    body.extend_from_slice(&extensions);
    Ok(handshake_message(2, &body))
}

fn encrypted_extensions(alpn: Option<&[u8]>) -> Vec<u8> {
    let mut extensions = Vec::new();
    if let Some(protocol) = alpn {
        put_u16(&mut extensions, 0x0010);
        put_u16(&mut extensions, (protocol.len() + 3) as u16);
        put_u16(&mut extensions, (protocol.len() + 1) as u16);
        extensions.push(protocol.len() as u8);
        extensions.extend_from_slice(protocol);
    }
    let mut body = Vec::with_capacity(extensions.len() + 2);
    put_u16(&mut body, extensions.len() as u16);
    body.extend_from_slice(&extensions);
    body
}

fn certificate_body(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut list = Vec::new();
    for certificate in chain {
        put_u24(&mut list, certificate.len());
        list.extend_from_slice(certificate);
        put_u16(&mut list, 0);
    }
    let mut body = vec![0];
    put_u24(&mut body, list.len());
    body.extend_from_slice(&list);
    body
}

fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(4 + body.len());
    message.push(kind);
    put_u24(&mut message, body.len());
    message.extend_from_slice(body);
    message
}

/// A minimal self-signed-shaped X.509 certificate for an Ed25519 key. The
/// signature field (the last 64 bytes) is left zero for the caller to fill;
/// REALITY puts an HMAC there instead of a real signature.
pub fn ed25519_certificate_template(public_key: &[u8; 32]) -> Vec<u8> {
    const ALGORITHM: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
    let mut tbs = Vec::new();
    tbs.extend_from_slice(&[0xa0, 0x03, 0x02, 0x01, 0x02]);
    tbs.extend_from_slice(&[0x02, 0x01, 0x01]);
    tbs.extend_from_slice(&ALGORITHM);
    tbs.extend_from_slice(&[0x30, 0x00]);
    let mut validity = Vec::new();
    for time in [b"250101000000Z", b"350101000000Z"] {
        validity.extend_from_slice(&[0x17, 0x0d]);
        validity.extend_from_slice(time);
    }
    tbs.extend_from_slice(&der(0x30, &validity));
    tbs.extend_from_slice(&[0x30, 0x00]);
    let mut key = vec![0x00];
    key.extend_from_slice(public_key);
    let mut spki = ALGORITHM.to_vec();
    spki.extend_from_slice(&der(0x03, &key));
    tbs.extend_from_slice(&der(0x30, &spki));

    let mut certificate = der(0x30, &tbs);
    certificate.extend_from_slice(&ALGORITHM);
    certificate.extend_from_slice(&der(0x03, &[0u8; 65]));
    der(0x30, &certificate)
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match content.len() {
        len @ 0..=0x7f => out.push(len as u8),
        len @ 0x80..=0xff => out.extend_from_slice(&[0x81, len as u8]),
        len => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
    }
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::{parse_leaf, OID_ED25519};
    use crate::fingerprint::{build_client_hello, Fingerprint};

    #[test]
    fn parses_browser_client_hellos() {
        let hello =
            build_client_hello(Fingerprint::Chrome, "example.com", None).expect("client hello");
        let info = parse_client_hello(&hello.message).unwrap();
        assert_eq!(info.random, hello.random);
        assert_eq!(info.server_name.as_deref(), Some("example.com"));
        assert_eq!(info.session_id.len(), 32);
        assert!(info.tls13);
        assert_eq!(info.x25519_share, Some(hello.secrets.x25519_public()));
        assert!(info.cipher_suites.contains(&0x1301));
    }

    #[test]
    fn certificate_template_parses() {
        let certificate = ed25519_certificate_template(&[7u8; 32]);
        let leaf = parse_leaf(&certificate).expect("leaf");
        assert_eq!(leaf.public_key_algorithm, OID_ED25519);
        assert_eq!(leaf.public_key, &[7u8; 32]);
        assert_eq!(leaf.signature, &[0u8; 64]);
        assert_eq!(&certificate[certificate.len() - 64..], &[0u8; 64]);
    }

    struct TrustLeaf(Vec<u8>);

    impl crate::HandshakeHooks for TrustLeaf {
        fn verify_server_certificates(
            &mut self,
            _server_name: &str,
            chain: &[Vec<u8>],
        ) -> io::Result<()> {
            if chain.first() == Some(&self.0) {
                Ok(())
            } else {
                Err(io::ErrorKind::PermissionDenied.into())
            }
        }
    }

    #[tokio::test]
    async fn completes_a_handshake_with_the_client() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public: [u8; 32] = ring::signature::KeyPair::public_key(&signer)
            .as_ref()
            .try_into()
            .unwrap();
        let chain = vec![ed25519_certificate_template(&public)];
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);

        let server_chain = chain.clone();
        let server = tokio::spawn(async move {
            let mut consumed = Vec::new();
            let message = read_client_hello(&mut server_io, &mut consumed)
                .await
                .unwrap();
            let hello = parse_client_hello(&message).unwrap();
            assert_eq!(hello.server_name.as_deref(), Some("reality.test"));
            let identity = ServerIdentity {
                certificate_chain: &server_chain,
                signer: &signer,
                alpn: &[b"h2".to_vec(), b"http/1.1".to_vec()],
            };
            let mut tls = accept(server_io, &hello, &identity).await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello");
            tls.write_all(b"world").await.unwrap();
            tls.flush().await.unwrap();
        });

        let config = crate::ClientConfig::new("reality.test", Fingerprint::Chrome);
        let mut hooks = TrustLeaf(chain[0].clone());
        let mut tls = crate::connect(client_io, &config, &mut hooks)
            .await
            .unwrap();
        assert_eq!(tls.alpn_protocol(), Some(&b"h2"[..]));
        tls.write_all(b"hello").await.unwrap();
        tls.flush().await.unwrap();
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
        server.await.unwrap();
    }

    /// Hooks for a connection that must not see a certificate.
    struct NoCertificate;

    impl crate::HandshakeHooks for NoCertificate {
        fn verify_server_certificates(
            &mut self,
            _server_name: &str,
            _chain: &[Vec<u8>],
        ) -> io::Result<()> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }

    fn test_identity() -> (Ed25519KeyPair, Vec<Vec<u8>>) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public: [u8; 32] = ring::signature::KeyPair::public_key(&signer)
            .as_ref()
            .try_into()
            .unwrap();
        (signer, vec![ed25519_certificate_template(&public)])
    }

    const TICKET: &[u8] = b"an opaque ticket only the server understands";

    /// One full handshake in which the server issues [`TICKET`]. Returns the
    /// ticket as the client stored it and the key the server derived for it.
    async fn full_handshake_with_ticket(
        fingerprint: Fingerprint,
    ) -> (crate::SessionTicket, CipherSuite, Vec<u8>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (signer, chain) = test_identity();
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let server_chain = chain.clone();
        let server = tokio::spawn(async move {
            let mut consumed = Vec::new();
            let message = read_client_hello(&mut server_io, &mut consumed)
                .await
                .unwrap();
            assert_eq!(parse_psk_offer(&message).unwrap(), None);
            let hello = parse_client_hello(&message).unwrap();
            let identity = ServerIdentity {
                certificate_chain: &server_chain,
                signer: &signer,
                alpn: &[b"h2".to_vec()],
            };
            let mut tls = accept(server_io, &hello, &identity).await.unwrap();
            assert!(!tls.resumed());
            let psk = tls
                .queue_session_ticket(3600, 0x0102_0304, &[0, 1], TICKET, 7)
                .unwrap();
            tls.write_all(b"world").await.unwrap();
            tls.flush().await.unwrap();
            (tls.cipher_suite(), psk)
        });

        let config = crate::ClientConfig::new("resume.test", fingerprint);
        let mut hooks = TrustLeaf(chain[0].clone());
        let mut tls = crate::connect(client_io, &config, &mut hooks)
            .await
            .unwrap();
        assert!(!tls.resumed());
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
        let mut tickets = tls.take_session_tickets();
        assert_eq!(tickets.len(), 1);
        assert!(tls.take_session_tickets().is_empty());
        let ticket = tickets.remove(0);
        let (suite, psk) = server.await.unwrap();
        assert_eq!(ticket.ticket, TICKET);
        assert_eq!(ticket.lifetime_secs, 3600);
        assert_eq!(ticket.age_add, 0x0102_0304);
        assert_eq!(ticket.suite, suite);
        // Both ends derive the same key from the ticket nonce
        assert_eq!(ticket.psk, psk);
        assert!(ticket.usable());
        (ticket, suite, psk)
    }

    #[tokio::test]
    async fn resumes_with_a_session_ticket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for fingerprint in [Fingerprint::Chrome, Fingerprint::Safari] {
            let (ticket, suite, psk) = full_handshake_with_ticket(fingerprint).await;
            let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(async move {
                let mut consumed = Vec::new();
                let message = read_client_hello(&mut server_io, &mut consumed)
                    .await
                    .unwrap();
                let offer = parse_psk_offer(&message).unwrap().expect("psk offer");
                assert_eq!(offer.identity, TICKET);
                assert_eq!(offer.binder.len(), suite.hash().output_len());
                assert_eq!(offer.binders_len, offer.binder.len() + 3);
                // pre_shared_key is the last extension: the message ends with the binder
                assert!(message.ends_with(&offer.binder));
                assert!(psk_binder_valid(&message, &offer, suite, &psk));
                assert!(!psk_binder_valid(&message, &offer, suite, &[9u8; 32]));
                let hello = parse_client_hello(&message).unwrap();
                // A wrong key is refused before anything is written
                let (unused, _peer) = tokio::io::duplex(64);
                assert!(
                    accept_resumed(unused, &hello, &[b"h2".to_vec()], suite, &[9u8; 32])
                        .await
                        .is_err()
                );
                let mut tls = accept_resumed(server_io, &hello, &[b"h2".to_vec()], suite, &psk)
                    .await
                    .unwrap();
                assert!(tls.resumed());
                let mut buf = [0u8; 5];
                tls.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"again");
                tls.write_all(b"again").await.unwrap();
                tls.flush().await.unwrap();
            });

            let config = crate::ClientConfig::new("resume.test", fingerprint);
            let mut tls =
                crate::connect_resuming(client_io, &config, &mut NoCertificate, Some(&ticket))
                    .await
                    .unwrap();
            assert!(tls.resumed());
            assert_eq!(tls.alpn_protocol(), Some(&b"h2"[..]));
            tls.write_all(b"again").await.unwrap();
            tls.flush().await.unwrap();
            let mut buf = [0u8; 5];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"again");
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn falls_back_to_a_full_handshake_when_the_ticket_is_declined() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (ticket, _suite, _psk) = full_handshake_with_ticket(Fingerprint::Chrome).await;
        let (signer, chain) = test_identity();
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let server_chain = chain.clone();
        let server = tokio::spawn(async move {
            let mut consumed = Vec::new();
            let message = read_client_hello(&mut server_io, &mut consumed)
                .await
                .unwrap();
            assert!(parse_psk_offer(&message).unwrap().is_some());
            let hello = parse_client_hello(&message).unwrap();
            let identity = ServerIdentity {
                certificate_chain: &server_chain,
                signer: &signer,
                alpn: &[b"h2".to_vec()],
            };
            // The server does not know the ticket: an ordinary full handshake
            let mut tls = accept(server_io, &hello, &identity).await.unwrap();
            tls.write_all(b"world").await.unwrap();
            tls.flush().await.unwrap();
        });

        let config = crate::ClientConfig::new("resume.test", Fingerprint::Chrome);
        let mut hooks = TrustLeaf(chain[0].clone());
        let mut tls = crate::connect_resuming(client_io, &config, &mut hooks, Some(&ticket))
            .await
            .unwrap();
        assert!(!tls.resumed());
        let mut buf = [0u8; 5];
        tls.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn an_expired_ticket_is_not_offered() {
        let (mut ticket, _suite, _psk) = full_handshake_with_ticket(Fingerprint::Chrome).await;
        ticket.lifetime_secs = 0;
        assert!(!ticket.usable());
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let client = tokio::spawn(async move {
            let config = crate::ClientConfig::new("resume.test", Fingerprint::Chrome);
            // The server never answers; only the ClientHello matters here
            let _ = crate::connect_resuming(client_io, &config, &mut NoCertificate, Some(&ticket))
                .await;
        });
        let mut consumed = Vec::new();
        let message = read_client_hello(&mut server_io, &mut consumed)
            .await
            .unwrap();
        assert_eq!(parse_psk_offer(&message).unwrap(), None);
        drop(server_io);
        client.await.unwrap();
    }
}
