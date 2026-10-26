//! V2Ray-style gRPC ("gun") client transport for outbound protocol crates.
//!
//! [`GrpcConnector::connect`] opens an HTTP/2 connection over an existing
//! stream (plain TCP or TLS negotiated with ALPN `h2`) and starts one
//! bidirectional streaming call to `/<service_name>/Tun`, the method Xray-core
//! and sing-box serve. Each message is a protobuf `Hunk { bytes data = 1; }`
//! in a length-prefixed gRPC frame; the returned byte stream hides the
//! framing, so the proxy protocol above it sees a plain byte stream.
//!
//! Every [`GrpcConnector::connect`] uses its own HTTP/2 connection; the
//! connection task ends with the call. [`server::serve_connection`] is the
//! server side: every call on a client connection becomes one stream.

pub mod server;

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use engine_outbound::BoxStream;
use h2::client::{ResponseFuture, SendRequest};
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Largest `data` put in one message; longer writes are accepted partially.
pub const MAX_MESSAGE_PAYLOAD: usize = 32 * 1024;
/// Largest message accepted from the server.
pub const MAX_INCOMING_MESSAGE: usize = 1024 * 1024;
const STREAM_WINDOW: u32 = 1024 * 1024;
const CONNECTION_WINDOW: u32 = 4 * 1024 * 1024;
const USER_AGENT: &str = "grpc-go/1.66.0";
/// Protobuf tag of `Hunk.data`: field 1, wire type 2 (length-delimited).
const DATA_TAG: u8 = 0x0a;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GrpcSettings {
    /// gRPC service name; the call goes to `/<service_name>/Tun`. A value
    /// starting with `/` is a full custom path (Xray's form), up to an
    /// optional `|`.
    pub service_name: String,
    /// `:authority`; the caller passes the server name when empty.
    pub authority: String,
}

pub struct GrpcConnector {
    uri: http::Uri,
    tls: bool,
}

impl GrpcConnector {
    /// `default_authority` is used when `settings.authority` is empty.
    /// `tls` sets the `:scheme` (`https` or `http`); it does not add TLS.
    pub fn new(settings: &GrpcSettings, default_authority: &str, tls: bool) -> io::Result<Self> {
        let path = tun_path(&settings.service_name)?;
        let authority = if settings.authority.is_empty() {
            default_authority
        } else {
            settings.authority.as_str()
        };
        let scheme = if tls { "https" } else { "http" };
        let uri = format!("{scheme}://{authority}{path}")
            .parse::<http::Uri>()
            .map_err(|_| invalid("grpc authority is invalid"))?;
        if uri.authority().is_none() || uri.path() != path {
            return Err(invalid("grpc authority is invalid"));
        }
        Ok(Self { uri, tls })
    }

    /// The request path, e.g. `/grpc/Tun`.
    pub fn path(&self) -> &str {
        self.uri.path()
    }

    pub fn is_tls(&self) -> bool {
        self.tls
    }

    /// Runs the HTTP/2 handshake on `stream` and opens the streaming call.
    pub async fn connect(&self, stream: BoxStream) -> io::Result<BoxStream> {
        let (send_request, connection) = h2::client::Builder::new()
            .initial_window_size(STREAM_WINDOW)
            .initial_connection_window_size(CONNECTION_WINDOW)
            .handshake::<_, Bytes>(stream)
            .await
            .map_err(h2_error)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut send_request: SendRequest<Bytes> = send_request.ready().await.map_err(h2_error)?;
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(self.uri.clone())
            .header(http::header::CONTENT_TYPE, "application/grpc")
            .header(http::header::TE, "trailers")
            .header(http::header::USER_AGENT, USER_AGENT)
            .body(())
            .map_err(|_| invalid("grpc request is invalid"))?;
        let (response, send) = send_request
            .send_request(request, false)
            .map_err(h2_error)?;
        Ok(Box::new(GrpcStream::new(Some(response), None, send, false)))
    }
}

/// The call path for `service_name`: `/<service_name>/Tun`, or the custom
/// path of a name starting with `/` (Xray's form), up to an optional `|`.
pub fn tun_path(service_name: &str) -> io::Result<String> {
    let path = if let Some(custom) = service_name.strip_prefix('/') {
        let tun = custom.split('|').next().unwrap_or_default();
        format!("/{tun}")
    } else if service_name.contains('/') {
        return Err(invalid("grpc service name is invalid"));
    } else {
        format!("/{service_name}/Tun")
    };
    if !path[1..].split('/').all(|segment| {
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._~".contains(&byte))
    }) {
        return Err(invalid("grpc service name is invalid"));
    }
    Ok(path)
}

/// One `Hunk` message in a gRPC frame.
pub fn encode_message(data: &[u8], out: &mut BytesMut) {
    let mut varint = [0u8; 10];
    let varint_len = encode_varint(data.len() as u64, &mut varint);
    let message_len = 1 + varint_len + data.len();
    out.reserve(5 + message_len);
    out.extend_from_slice(&[0]);
    out.extend_from_slice(&(message_len as u32).to_be_bytes());
    out.extend_from_slice(&[DATA_TAG]);
    out.extend_from_slice(&varint[..varint_len]);
    out.extend_from_slice(data);
}

fn encode_varint(mut value: u64, out: &mut [u8; 10]) -> usize {
    let mut len = 0;
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out[len] = byte;
            return len + 1;
        }
        out[len] = byte | 0x80;
        len += 1;
    }
}

fn decode_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, byte) in buf.iter().enumerate().take(10) {
        value |= u64::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

/// Takes one complete gRPC frame from `frames` and returns its `data`
/// field (empty when absent). `Ok(None)` means more bytes are needed.
pub fn decode_message(frames: &mut BytesMut) -> io::Result<Option<Bytes>> {
    if frames.len() < 5 {
        return Ok(None);
    }
    if frames[0] != 0 {
        return Err(bad("compressed grpc messages are not supported"));
    }
    let length = u32::from_be_bytes([frames[1], frames[2], frames[3], frames[4]]) as usize;
    if length > MAX_INCOMING_MESSAGE {
        return Err(bad("grpc message is too large"));
    }
    if frames.len() < 5 + length {
        return Ok(None);
    }
    frames.advance(5);
    let message = frames.split_to(length).freeze();
    let mut data = Bytes::new();
    let mut rest = &message[..];
    while !rest.is_empty() {
        let (key, key_len) = decode_varint(rest).ok_or_else(|| bad("grpc message is malformed"))?;
        rest = &rest[key_len..];
        let field_end = match key & 7 {
            0 => decode_varint(rest).map(|(_, len)| len),
            1 => Some(8),
            2 => decode_varint(rest).and_then(|(len, len_len)| {
                usize::try_from(len)
                    .ok()
                    .and_then(|len| len.checked_add(len_len))
            }),
            5 => Some(4),
            _ => None,
        }
        .filter(|end| *end <= rest.len())
        .ok_or_else(|| bad("grpc message is malformed"))?;
        if key == u64::from(DATA_TAG) {
            let (_, len_len) = decode_varint(rest).expect("checked above");
            let start = message.len() - rest.len() + len_len;
            data = message.slice(start..message.len() - rest.len() + field_end);
        }
        rest = &rest[field_end..];
    }
    Ok(Some(data))
}

struct GrpcStream {
    response: Option<ResponseFuture>,
    recv: Option<RecvStream>,
    send: SendStream<Bytes>,
    /// Received bytes not yet decoded.
    frames: BytesMut,
    /// Decoded data not yet returned.
    payload: Bytes,
    eof: bool,
    shut: bool,
    /// Server side: the call ends with `grpc-status` trailers.
    server: bool,
}

impl GrpcStream {
    fn new(
        response: Option<ResponseFuture>,
        recv: Option<RecvStream>,
        send: SendStream<Bytes>,
        server: bool,
    ) -> Self {
        Self {
            response,
            recv,
            send,
            frames: BytesMut::new(),
            payload: Bytes::new(),
            eof: false,
            shut: false,
            server,
        }
    }

    /// Waits until the peer's flow control window has room again. A message
    /// is handed to h2 whole once there is any room; h2 sends what it holds
    /// as the window opens, so nothing waits on a flush, and the next write
    /// waits until that message is out.
    fn poll_send_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.send.reserve_capacity(1);
        while self.send.capacity() == 0 {
            match ready!(self.send.poll_capacity(cx)) {
                Some(Ok(_)) => {}
                Some(Err(err)) => return Poll::Ready(Err(h2_error(err))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
        Poll::Ready(Ok(()))
    }

    fn poll_recv_stream(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(response) = self.response.as_mut() {
            let response = ready!(Pin::new(response).poll(cx)).map_err(h2_error)?;
            self.response = None;
            if response.status() != http::StatusCode::OK {
                return Poll::Ready(Err(io::Error::other("grpc server rejected the call")));
            }
            let trailers_only = response.headers().contains_key("grpc-status");
            let recv = response.into_body();
            if trailers_only {
                self.eof = true;
            }
            self.recv = Some(recv);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if !this.payload.is_empty() {
                let n = this.payload.len().min(buf.remaining());
                buf.put_slice(&this.payload[..n]);
                this.payload.advance(n);
                return Poll::Ready(Ok(()));
            }
            if let Some(data) = decode_message(&mut this.frames)? {
                this.payload = data;
                continue;
            }
            if this.eof {
                if !this.frames.is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "grpc stream ended inside a message",
                    )));
                }
                return Poll::Ready(Ok(()));
            }
            ready!(this.poll_recv_stream(cx))?;
            let Some(recv) = this.recv.as_mut() else {
                return Poll::Ready(Ok(()));
            };
            match ready!(recv.poll_data(cx)) {
                Some(Ok(chunk)) => {
                    let _ = recv.flow_control().release_capacity(chunk.len());
                    this.frames.extend_from_slice(&chunk);
                }
                Some(Err(err)) => {
                    // A reset after the server finished counts as the end.
                    if err.reason() == Some(h2::Reason::NO_ERROR) {
                        this.eof = true;
                        continue;
                    }
                    return Poll::Ready(Err(h2_error(err)));
                }
                None => this.eof = true,
            }
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.shut {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(this.poll_send_ready(cx))?;
        let n = buf.len().min(MAX_MESSAGE_PAYLOAD);
        let mut message = BytesMut::new();
        encode_message(&buf[..n], &mut message);
        this.send
            .send_data(message.freeze(), false)
            .map_err(h2_error)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Messages are with h2 once written; its connection task sends them.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.shut {
            this.shut = true;
            if this.server {
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                this.send.send_trailers(trailers).map_err(h2_error)?;
            } else {
                this.send.send_data(Bytes::new(), true).map_err(h2_error)?;
            }
        }
        Poll::Ready(Ok(()))
    }
}

fn h2_error(err: h2::Error) -> io::Error {
    if err.is_io() {
        return err.into_io().expect("is_io");
    }
    io::Error::other(err)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn bad(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_round_trip_and_split_across_reads() {
        let mut frames = BytesMut::new();
        encode_message(b"hello", &mut frames);
        encode_message(&vec![7u8; 300], &mut frames);
        assert_eq!(&frames[..8], &[0, 0, 0, 0, 7, 0x0a, 5, b'h']);
        let mut partial = frames.split_to(3);
        assert!(decode_message(&mut partial).unwrap().is_none());
        partial.unsplit(frames);
        let mut frames = partial;
        assert_eq!(&decode_message(&mut frames).unwrap().unwrap()[..], b"hello");
        assert_eq!(decode_message(&mut frames).unwrap().unwrap().len(), 300);
        assert!(frames.is_empty());
    }

    #[test]
    fn unknown_fields_are_skipped() {
        // field 2 varint 150, then field 1 bytes "ab", then field 3 fixed32.
        let message = [0x10, 0x96, 0x01, 0x0a, 2, b'a', b'b', 0x1d, 1, 2, 3, 4];
        let mut frames = BytesMut::new();
        frames.extend_from_slice(&[0, 0, 0, 0, message.len() as u8]);
        frames.extend_from_slice(&message);
        assert_eq!(&decode_message(&mut frames).unwrap().unwrap()[..], b"ab");

        let mut compressed = BytesMut::from(&[1u8, 0, 0, 0, 0][..]);
        assert!(decode_message(&mut compressed).is_err());
        let mut truncated = BytesMut::from(&[0u8, 0, 0, 0, 3, 0x0a, 9, 1][..]);
        assert!(decode_message(&mut truncated).is_err());
    }

    #[test]
    fn paths_follow_the_service_name() {
        let plain = GrpcConnector::new(&GrpcSettings::default(), "a.example", true);
        assert!(plain.is_err(), "an empty service name has no path segment");
        let named = GrpcConnector::new(
            &GrpcSettings {
                service_name: "grpc-svc".into(),
                authority: String::new(),
            },
            "a.example",
            true,
        )
        .unwrap();
        assert_eq!(named.path(), "/grpc-svc/Tun");
        let custom = GrpcConnector::new(
            &GrpcSettings {
                service_name: "/my/tun|my/multi".into(),
                authority: "front.example".into(),
            },
            "a.example",
            false,
        )
        .unwrap();
        assert_eq!(custom.path(), "/my/tun");
        for bad in ["a b", "a/../b", "x\r\n"] {
            let settings = GrpcSettings {
                service_name: bad.into(),
                authority: String::new(),
            };
            assert!(
                GrpcConnector::new(&settings, "a.example", true).is_err(),
                "{bad}"
            );
        }
    }
}
