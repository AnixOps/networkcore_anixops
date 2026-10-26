//! TLS 1.3 server handshake (full 1-RTT, X25519 only, Ed25519 certificate).
//!
//! Built for REALITY-style servers: the caller reads and inspects the
//! ClientHello first ([`read_client_hello`], [`parse_client_hello`]), decides
//! whether to serve the client itself or hand the consumed bytes to another
//! server, and only then runs [`accept`]. No HelloRetryRequest, resumption,
//! 0-RTT or client certificates.

use std::io;

use ring::hmac;
use ring::signature::Ed25519KeyPair;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::crypto::{fill_random, invalid_data, CipherSuite, RecordCipher, MAX_PLAINTEXT};
use crate::fingerprint::{put_u16, put_u24, GROUP_X25519, GROUP_X25519_MLKEM768};
use crate::handshake::{
    alert_from_payload, read_record, HandshakeBuffer, Reader, MAX_HANDSHAKE_MESSAGE,
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
    mut io: S,
    hello: &ClientHelloInfo,
    identity: &ServerIdentity<'_>,
) -> io::Result<TlsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !hello.tls13 {
        return Err(invalid_data("client does not offer TLS 1.3"));
    }
    let suite = SUITES
        .into_iter()
        .find(|suite| hello.cipher_suites.contains(&suite.id()))
        .ok_or_else(|| invalid_data("no shared TLS 1.3 cipher suite"))?;
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
    let alpn = identity
        .alpn
        .iter()
        .find(|protocol| hello.alpn.contains(protocol))
        .cloned();

    let server_hello = server_hello(hello, suite, &PublicKey::from(&secret).to_bytes())?;
    let mut transcript = hello.message.clone();
    transcript.extend_from_slice(&server_hello);

    let hash = suite.hash();
    let zeros = vec![0u8; hash.output_len()];
    let empty_hash = hash.hash(&[]);
    let early_secret = hash.hkdf_extract(&[], &zeros);
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

    TlsStream::from_secrets(io, suite, server_ap, client_ap, alpn)
}

fn server_hello(
    hello: &ClientHelloInfo,
    suite: CipherSuite,
    public: &[u8; 32],
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
}
