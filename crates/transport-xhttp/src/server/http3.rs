//! XHTTP server side over HTTP/3: the requests of the parent module on the
//! streams of one QUIC connection, every request on a task of its own.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use engine_outbound::{BoxFuture, BoxStream};
use tokio::io::{AsyncRead, AsyncReadExt, DuplexStream, ReadBuf};
use transport_quic::quinn;

use super::{Joined, Route, UploadReader, XhttpServer};
use crate::http3::h3_error;
use crate::{STREAM_CHUNK, STREAM_PIPE};

type Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type SendHalf = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type RecvHalf = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;

impl XhttpServer {
    /// Serves the HTTP/3 requests of `connection` until it closes. Every
    /// proxied stream is handed to `call`, whose future runs on the task of
    /// its request and is dropped when the connection closes.
    pub async fn serve_quic<F>(
        self: &Arc<Self>,
        connection: quinn::Connection,
        handshake_timeout: Duration,
        call: F,
    ) -> io::Result<()>
    where
        F: Fn(BoxStream) -> BoxFuture<'static, ()> + Clone + Send + 'static,
    {
        let setup =
            h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection.clone()));
        let mut requests = tokio::time::timeout(handshake_timeout, setup)
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
            .map_err(h3_error)?;
        while let Ok(Some(resolver)) = requests.accept().await {
            let server = self.clone();
            let connection = connection.clone();
            let call = call.clone();
            tokio::spawn(async move {
                let head = tokio::time::timeout(handshake_timeout, resolver.resolve_request());
                if let Ok(Ok((request, stream))) = head.await {
                    server.h3_request(request, stream, connection, call).await;
                }
            });
        }
        Ok(())
    }

    /// Answers one HTTP/3 request; a download or `stream-one` request runs
    /// its proxied stream here.
    async fn h3_request<F>(
        self: &Arc<Self>,
        request: http::Request<()>,
        mut stream: Stream,
        connection: quinn::Connection,
        call: F,
    ) where
        F: Fn(BoxStream) -> BoxFuture<'static, ()>,
    {
        match self.route_request(&request) {
            Route::Reject(status) => respond(stream, self.h2_status(status)).await,
            Route::Download(id) => {
                let Some(upload) = self.take_upload(&id) else {
                    return respond(stream, self.h2_status(409)).await;
                };
                let (pipe, body) = tokio::io::duplex(STREAM_PIPE);
                let proxied = Joined {
                    reader: UploadReader::new(upload),
                    writer: pipe,
                };
                // Made before the response so that the session ends with
                // it whatever happens next.
                let call = self.finish_with(call(Box::new(proxied)), Some(id));
                if stream.send_response(self.h2_download()).await.is_err() {
                    return;
                }
                // The receive half is kept: dropping it tells the client to
                // stop sending on a request it may still be ending.
                let (send, _recv) = stream.split();
                proxy(call, send_body(send, body), connection).await;
            }
            Route::StreamOne => {
                if stream.send_response(self.h2_download()).await.is_err() {
                    return;
                }
                let (send, recv) = stream.split();
                let (pipe, body) = tokio::io::duplex(STREAM_PIPE);
                let proxied = Joined {
                    reader: BodyReader {
                        body: recv,
                        current: Bytes::new(),
                    },
                    writer: pipe,
                };
                proxy(call(Box::new(proxied)), send_body(send, body), connection).await;
            }
            Route::StreamUp(id) => {
                let Some(session) = self.session(&id) else {
                    return respond(stream, self.h2_status(503)).await;
                };
                if stream.send_response(self.h2_status(200)).await.is_err() {
                    return;
                }
                while let Ok(Some(mut chunk)) = stream.recv_data().await {
                    let chunk = chunk.copy_to_bytes(chunk.remaining());
                    if session.push_stream(chunk).await.is_err() {
                        break;
                    }
                }
                session.finish().await;
                let _ = stream.finish().await;
            }
            Route::Packet(id, seq) => {
                let Some(session) = self.session(&id) else {
                    return respond(stream, self.h2_status(503)).await;
                };
                let status = match read_body(&mut stream, self.max_post).await {
                    Ok(Some(body)) => match session.push_packet(seq, body).await {
                        Ok(()) => 200,
                        Err(_) => 500,
                    },
                    Ok(None) => 413,
                    Err(_) => return,
                };
                respond(stream, self.h2_status(status)).await;
            }
        }
    }
}

/// Runs a proxied stream and the copy of its writes into the response body
/// until both ended or the connection closed.
async fn proxy(
    call: BoxFuture<'static, ()>,
    body: impl Future<Output = ()>,
    connection: quinn::Connection,
) {
    tokio::select! {
        _ = async { tokio::join!(call, body) } => {}
        _ = connection.closed() => {}
    }
}

/// Sends what the proxied stream writes to its pipe as the response body,
/// which ends when the pipe is shut down or dropped.
async fn send_body(mut send: SendHalf, mut body: DuplexStream) {
    let mut buf = vec![0u8; STREAM_CHUNK];
    loop {
        match body.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                let chunk = Bytes::copy_from_slice(&buf[..read]);
                if send.send_data(chunk).await.is_err() {
                    return;
                }
            }
        }
    }
    let _ = send.finish().await;
}

/// Answers a request without a response body.
async fn respond(mut stream: Stream, response: http::Response<()>) {
    if stream.send_response(response).await.is_ok() {
        let _ = stream.finish().await;
    }
}

/// `Ok(None)` when the body is larger than `limit`.
async fn read_body(stream: &mut Stream, limit: usize) -> io::Result<Option<Bytes>> {
    let mut data = BytesMut::new();
    while let Some(chunk) = stream.recv_data().await.map_err(h3_error)? {
        if data.len() + chunk.remaining() > limit {
            return Ok(None);
        }
        data.put(chunk);
    }
    Ok(Some(data.freeze()))
}

/// An HTTP/3 request body (`stream-one`).
struct BodyReader {
    body: RecvHalf,
    current: Bytes,
}

impl AsyncRead for BodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        while this.current.is_empty() {
            match ready!(this.body.poll_recv_data(cx)).map_err(h3_error)? {
                Some(mut chunk) => this.current = chunk.copy_to_bytes(chunk.remaining()),
                None => return Poll::Ready(Ok(())),
            }
        }
        let n = this.current.len().min(buf.remaining());
        buf.put_slice(&this.current[..n]);
        this.current.advance(n);
        Poll::Ready(Ok(()))
    }
}
