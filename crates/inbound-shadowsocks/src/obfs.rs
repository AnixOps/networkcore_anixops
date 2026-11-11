//! simple-obfs for the Shadowsocks inbounds: the server side of the SIP003
//! plugin pair `obfs-local` / `obfs-server`, built in, so no plugin process
//! runs beside the node. [`ObfsInbound`] undoes the disguise of a client
//! connection and hands the plain stream to the protocol.
//!
//! `http`: the client's first write follows a `GET` request that asks for a
//! WebSocket upgrade, the server's first write a `101 Switching Protocols`
//! response. After the two heads both directions are the raw stream.
//!
//! `tls`: the client's first write travels in the session ticket extension
//! of a fake ClientHello. The server's first write follows a fake
//! ServerHello and ChangeCipherSpec and poses as the encrypted handshake
//! message; everything after is framed as application data records. Nothing
//! is negotiated or encrypted here: Shadowsocks does that inside.
//!
//! The plugin is for TCP only; clients send UDP to the port as plain
//! Shadowsocks packets.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use base64::Engine as _;
use engine_inbound::stream::PrefixedStream;
use engine_inbound::udp::DatagramInbound;
use engine_inbound::{Accepted, Rejected, StreamInbound, UserStore};
use engine_outbound::{BoxFuture, BoxStream};
use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::{fill_random, unix_time_secs};

/// Longest request head accepted before the first payload.
const MAX_HTTP_HEAD: usize = 8 * 1024;
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const CHANGE_CIPHER_SPEC: u8 = 0x14;
const HANDSHAKE: u8 = 0x16;
const APPLICATION_DATA: u8 = 0x17;
const CLIENT_HELLO: u8 = 1;
const SERVER_HELLO: u8 = 2;
const EXT_SERVER_NAME: u16 = 0;
const EXT_SESSION_TICKET: u16 = 35;
const RECORD_HEADER_LEN: usize = 5;
/// Payload bytes per outgoing record, the TLS limit.
const MAX_RECORD: usize = 16 * 1024;

/// `"obfs"` in the shadowsocks inbound settings.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObfsSettings {
    #[serde(rename = "type")]
    pub mode: ObfsMode,
    /// The name clients must send (their `obfs-host`): the `Host` header
    /// in `http` mode, the server name in `tls` mode. Any when empty.
    #[serde(default)]
    pub host: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObfsMode {
    Http,
    Tls,
}

/// A Shadowsocks inbound behind simple-obfs.
pub struct ObfsInbound {
    mode: ObfsMode,
    host: String,
    inner: Arc<dyn StreamInbound>,
}

impl ObfsInbound {
    pub fn new(inner: Arc<dyn StreamInbound>, settings: &ObfsSettings) -> Self {
        Self {
            mode: settings.mode,
            host: settings.host.clone(),
            inner,
        }
    }

    /// Whether `name` (a `Host` header, its port ignored, or a TLS server
    /// name) is the configured host.
    fn host_matches(&self, name: Option<&str>) -> bool {
        if self.host.is_empty() {
            return true;
        }
        name.is_some_and(|name| {
            let name = match name.rsplit_once(':') {
                Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => host,
                _ => name,
            };
            name.eq_ignore_ascii_case(&self.host)
        })
    }

    async fn accept_http(&self, mut stream: BoxStream) -> Result<BoxStream, Rejected> {
        let mut head = Vec::new();
        let mut chunk = [0u8; 4096];
        let end = loop {
            if let Some(at) = head.windows(4).position(|window| window == b"\r\n\r\n") {
                break at + 4;
            }
            let n = stream.read(&mut chunk).await?;
            if n == 0 || head.len() > MAX_HTTP_HEAD {
                return Err(Rejected::hold("obfs http request is invalid", stream));
            }
            head.extend_from_slice(&chunk[..n]);
        };
        // The first payload may arrive with the request.
        let payload = head.split_off(end);
        let request = String::from_utf8_lossy(&head);
        let upgrade = request.starts_with("GET ")
            && header(&request, "upgrade")
                .is_some_and(|value| value.eq_ignore_ascii_case("websocket"));
        if !upgrade || !self.host_matches(header(&request, "host")) {
            return Err(Rejected::hold("obfs http request is invalid", stream));
        }
        let key = header(&request, "sec-websocket-key").unwrap_or_default();
        let accept = digest(
            &SHA1_FOR_LEGACY_USE_ONLY,
            format!("{key}{WEBSOCKET_GUID}").as_bytes(),
        );
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Server: nginx/1.24.0\r\n\
             Date: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\
             \r\n",
            http_date(unix_time_secs()),
            base64::engine::general_purpose::STANDARD.encode(accept)
        );
        // Clients look for the end of the response in their first read, so
        // it leaves in one write with the first payload.
        Ok(Box::new(
            PrefixedStream::new(stream)
                .with_read_prefix(payload)
                .with_write_prefix(response.into_bytes()),
        ))
    }

    async fn accept_tls(&self, mut stream: BoxStream) -> Result<BoxStream, Rejected> {
        let mut header = [0u8; RECORD_HEADER_LEN];
        stream.read_exact(&mut header).await?;
        let mut record = vec![0u8; usize::from(u16::from_be_bytes([header[3], header[4]]))];
        stream.read_exact(&mut record).await?;
        let hello = parse_client_hello(&record)
            .filter(|hello| header[0] == HANDSHAKE && self.host_matches(hello.server_name));
        let Some(hello) = hello else {
            return Err(Rejected::hold("obfs client hello is invalid", stream));
        };
        let framed = TlsObfsStream {
            hello: Some(server_hello(hello.session_id)?),
            inner: stream,
            header: [0; RECORD_HEADER_LEN],
            header_filled: 0,
            remaining: 0,
            out: Vec::new(),
            out_pos: 0,
        };
        Ok(Box::new(
            PrefixedStream::new(Box::new(framed)).with_read_prefix(hello.ticket.to_vec()),
        ))
    }
}

impl StreamInbound for ObfsInbound {
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
            let stream = match self.mode {
                ObfsMode::Http => self.accept_http(stream).await?,
                ObfsMode::Tls => self.accept_tls(stream).await?,
            };
            self.inner.accept(stream, peer).await
        })
    }

    fn datagram(&self) -> Option<Arc<dyn DatagramInbound>> {
        self.inner.datagram()
    }
}

/// The value of header `name` (lower case) in an HTTP request head.
fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim()
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}

/// `secs` since the Unix epoch as an HTTP date, e.g.
/// `Sun, 06 Nov 1994 08:49:37 GMT`.
fn http_date(secs: u64) -> String {
    const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let leap = |year: u64| {
        u64::from(year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)))
    };
    let (mut year, mut day) = (1970, days);
    while day >= 365 + leap(year) {
        day -= 365 + leap(year);
        year += 1;
    }
    let lengths = [31, 28 + leap(year), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0;
    while day >= lengths[month] {
        day -= lengths[month];
        month += 1;
    }
    format!(
        "{}, {:02} {} {year} {:02}:{:02}:{:02} GMT",
        WEEKDAYS[(days % 7) as usize],
        day + 1,
        MONTHS[month],
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// What the server reads from a fake ClientHello.
struct ClientHello<'a> {
    session_id: &'a [u8],
    server_name: Option<&'a str>,
    /// The session ticket: the client's first payload.
    ticket: &'a [u8],
}

/// Splits `len` bytes off the front of `data`.
fn take<'a>(data: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    if data.len() < len {
        return None;
    }
    let (head, rest) = data.split_at(len);
    *data = rest;
    Some(head)
}

/// Splits off a vector that follows its length of `width` bytes.
fn take_vec<'a>(data: &mut &'a [u8], width: usize) -> Option<&'a [u8]> {
    let len = take(data, width)?
        .iter()
        .fold(0, |len, byte| (len << 8) | usize::from(*byte));
    take(data, len)
}

/// Parses the handshake message of a ClientHello record. The message and
/// extension list lengths are not checked: the record bounds both.
fn parse_client_hello(mut data: &[u8]) -> Option<ClientHello<'_>> {
    if take(&mut data, 4)?[0] != CLIENT_HELLO {
        return None;
    }
    // Version and random.
    take(&mut data, 2 + 32)?;
    let session_id = take_vec(&mut data, 1)?;
    // Cipher suites, compression methods, extension list length.
    take_vec(&mut data, 2)?;
    take_vec(&mut data, 1)?;
    take(&mut data, 2)?;
    let (mut server_name, mut ticket) = (None, None);
    while !data.is_empty() {
        let kind = take(&mut data, 2)?;
        let mut value = take_vec(&mut data, 2)?;
        match u16::from_be_bytes([kind[0], kind[1]]) {
            EXT_SESSION_TICKET => ticket = Some(value),
            EXT_SERVER_NAME => {
                // One entry: name type (host_name), then the name.
                let mut list = take_vec(&mut value, 2)?;
                take(&mut list, 1)?;
                server_name = std::str::from_utf8(take_vec(&mut list, 2)?).ok();
            }
            _ => {}
        }
    }
    Some(ClientHello {
        session_id,
        server_name,
        ticket: ticket?,
    })
}

/// The fake ServerHello and ChangeCipherSpec records. Clients skip them by
/// size (96 and 6 bytes), so the layout is fixed: a 32-byte session id (the
/// client's when it has that length) and three extensions.
fn server_hello(session_id: &[u8]) -> io::Result<Vec<u8>> {
    let mut random = [0u8; 28 + 32];
    fill_random(&mut random)?;
    if session_id.len() == 32 {
        random[28..].copy_from_slice(session_id);
    }
    let mut out = vec![HANDSHAKE, 3, 1, 0, 91, SERVER_HELLO, 0, 0, 87, 3, 3];
    out.extend_from_slice(&(unix_time_secs() as u32).to_be_bytes());
    out.extend_from_slice(&random[..28]);
    out.push(32);
    out.extend_from_slice(&random[28..]);
    out.extend_from_slice(SERVER_HELLO_TAIL);
    Ok(out)
}

/// What follows the session id of the fake ServerHello, and the
/// ChangeCipherSpec record.
#[rustfmt::skip]
const SERVER_HELLO_TAIL: &[u8] = &[
    0xcc, 0xa8,              // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    0,                       // no compression
    0, 15,                   // extensions
    0xff, 0x01, 0, 1, 0,     // renegotiation_info
    0, 0x17, 0, 0,           // extended_master_secret
    0, 0x0b, 0, 2, 1, 0,     // ec_point_formats: uncompressed
    CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1,
];

/// The stream after the fake handshake: payload in TLS records.
struct TlsObfsStream {
    inner: BoxStream,
    header: [u8; RECORD_HEADER_LEN],
    header_filled: usize,
    /// Payload bytes of the current incoming record not yet read.
    remaining: usize,
    /// ServerHello and ChangeCipherSpec, until the first write takes them
    /// along.
    hello: Option<Vec<u8>>,
    out: Vec<u8>,
    out_pos: usize,
}

impl TlsObfsStream {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.out[self.out_pos..]))?;
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

impl AsyncRead for TlsObfsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.remaining == 0 {
            while this.header_filled < RECORD_HEADER_LEN {
                let mut head = ReadBuf::new(&mut this.header[this.header_filled..]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut head))?;
                let n = head.filled().len();
                if n == 0 {
                    // The stream may end between records only.
                    return Poll::Ready(match this.header_filled {
                        0 => Ok(()),
                        _ => Err(io::ErrorKind::UnexpectedEof.into()),
                    });
                }
                this.header_filled += n;
            }
            this.header_filled = 0;
            this.remaining = usize::from(u16::from_be_bytes([this.header[3], this.header[4]]));
        }
        let limit = this.remaining.min(buf.remaining());
        let mut payload = ReadBuf::new(buf.initialize_unfilled_to(limit));
        ready!(Pin::new(&mut this.inner).poll_read(cx, &mut payload))?;
        let n = payload.filled().len();
        if n == 0 && limit > 0 {
            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
        }
        buf.advance(n);
        this.remaining -= n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TlsObfsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_RECORD);
        // The first payload completes the fake handshake.
        let kind = match this.hello.take() {
            Some(hello) => {
                this.out = hello;
                HANDSHAKE
            }
            None => APPLICATION_DATA,
        };
        this.out.extend_from_slice(&[kind, 3, 3]);
        this.out.extend_from_slice(&(n as u16).to_be_bytes());
        this.out.extend_from_slice(&buf[..n]);
        // The record is committed to `out`; a pending drain finishes on the
        // next call.
        if let Poll::Ready(Err(err)) = this.poll_drain(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AeadInbound, AeadMethod};
    use tokio::io::AsyncWriteExt;

    fn inbound(mode: ObfsMode, host: &str) -> ObfsInbound {
        let inner = AeadInbound::new(AeadMethod::Aes128Gcm, "secret").unwrap();
        let host = host.to_owned();
        ObfsInbound::new(Arc::new(inner), &ObfsSettings { mode, host })
    }

    fn http_request(host: &str, payload: &str) -> String {
        format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.5.0\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Content-Length: {}\r\n\r\n{payload}",
            payload.len()
        )
    }

    /// A ClientHello record the way obfs clients build it: the payload in
    /// the session ticket, then the server name.
    fn client_hello(ticket: &[u8], host: &str, session_id: [u8; 32]) -> Vec<u8> {
        let mut extensions = vec![0, 35];
        extensions.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
        extensions.extend_from_slice(ticket);
        extensions.extend_from_slice(&[0, 0]);
        extensions.extend_from_slice(&(host.len() as u16 + 5).to_be_bytes());
        extensions.extend_from_slice(&(host.len() as u16 + 3).to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&(host.len() as u16).to_be_bytes());
        extensions.extend_from_slice(host.as_bytes());
        // extended_master_secret
        extensions.extend_from_slice(&[0, 0x17, 0, 0]);

        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.push(32);
        body.extend_from_slice(&session_id);
        body.extend_from_slice(&[0, 2, 0xcc, 0xa8, 1, 0]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut record = vec![HANDSHAKE, 3, 1];
        record.extend_from_slice(&(body.len() as u16 + 4).to_be_bytes());
        record.extend_from_slice(&[CLIENT_HELLO, 0]);
        record.extend_from_slice(&(body.len() as u16).to_be_bytes());
        record.extend_from_slice(&body);
        record
    }

    #[test]
    fn client_hellos_give_the_ticket_the_name_and_the_session_id() {
        let record = client_hello(b"first payload", "cdn.example", [9; 32]);
        let message = &record[RECORD_HEADER_LEN..];
        let hello = parse_client_hello(message).unwrap();
        assert_eq!(hello.ticket, &b"first payload"[..]);
        assert_eq!(hello.server_name, Some("cdn.example"));
        assert_eq!(hello.session_id, &[9u8; 32][..]);

        assert!(parse_client_hello(&message[..message.len() - 1]).is_none());
        let mut server = message.to_vec();
        server[0] = SERVER_HELLO;
        assert!(parse_client_hello(&server).is_none());
        // Without a session ticket there is no payload to start with.
        let plain = [&[CLIENT_HELLO, 0, 0, 40, 3, 3][..], &[0; 38][..]].concat();
        assert!(parse_client_hello(&plain).is_none());
    }

    #[test]
    fn http_dates_are_imf_fixdate() {
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(http_date(4_102_444_799), "Thu, 31 Dec 2099 23:59:59 GMT");
    }

    #[tokio::test]
    async fn http_heads_are_stripped_and_answered_with_the_first_write() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let request = http_request("cdn.example:8388", "first");
        client.write_all(request.as_bytes()).await.unwrap();
        let accepted = inbound(ObfsMode::Http, "CDN.example")
            .accept_http(Box::new(server))
            .await;
        let Ok(mut stream) = accepted else {
            panic!("the request was rejected");
        };
        client.write_all(b" second").await.unwrap();
        let mut got = [0u8; 12];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"first second");

        stream.write_all(b"reply").await.unwrap();
        stream.write_all(b" more").await.unwrap();
        stream.flush().await.unwrap();
        drop(stream);
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 101 Switching Protocols\r\n"));
        // The sample key and accept value of RFC 6455.
        assert!(response.contains("\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"));
        assert!(response.ends_with("\r\n\r\nreply more"));
    }

    #[tokio::test]
    async fn tls_payload_leaves_the_ticket_and_the_records() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let hello = client_hello(b"first", "cdn.example", [9; 32]);
        client.write_all(&hello).await.unwrap();
        client
            .write_all(b"\x17\x03\x03\x00\x04 sec\x17\x03\x03\x00\x00\x17\x03\x03\x00\x03ond")
            .await
            .unwrap();
        let accepted = inbound(ObfsMode::Tls, "")
            .accept_tls(Box::new(server))
            .await;
        let Ok(mut stream) = accepted else {
            panic!("the client hello was rejected");
        };
        let mut got = [0u8; 12];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"first second");

        stream.write_all(b"reply").await.unwrap();
        stream.write_all(b" more").await.unwrap();
        stream.flush().await.unwrap();
        drop(stream);
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        // Clients skip the ServerHello (96 bytes), the ChangeCipherSpec (6)
        // and the type and version of the next record by size.
        assert_eq!(response[..11], [HANDSHAKE, 3, 1, 0, 91, 2, 0, 0, 87, 3, 3]);
        assert_eq!(response[43], 32);
        assert_eq!(response[44..76], [9u8; 32]);
        assert_eq!(response[96..102], [CHANGE_CIPHER_SPEC, 3, 3, 0, 1, 1]);
        assert_eq!(
            response[102..],
            *b"\x16\x03\x03\x00\x05reply\x17\x03\x03\x00\x05 more"
        );
    }

    #[tokio::test]
    async fn other_hosts_and_other_requests_are_held() {
        let requests = [
            http_request("other.example", "x"),
            http_request("cdn.example", "x").replace("websocket", "h2c"),
            http_request("cdn.example", "x").replace("GET", "POST"),
        ];
        for request in requests {
            let (mut client, server) = tokio::io::duplex(4096);
            client.write_all(request.as_bytes()).await.unwrap();
            let accepted = inbound(ObfsMode::Http, "cdn.example")
                .accept_http(Box::new(server))
                .await;
            assert!(accepted.is_err_and(|rejected| rejected.stream.is_some()));
        }

        let (mut client, server) = tokio::io::duplex(4096);
        let hello = client_hello(b"x", "other.example", [0; 32]);
        client.write_all(&hello).await.unwrap();
        let accepted = inbound(ObfsMode::Tls, "cdn.example")
            .accept_tls(Box::new(server))
            .await;
        assert!(accepted.is_err_and(|rejected| rejected.stream.is_some()));
    }
}
