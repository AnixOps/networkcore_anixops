//! h2mux, the HTTP/2 multiplexer of sing-mux.
//!
//! Behind the session request the connection is HTTP/2 as it is, with no
//! TLS or upgrade of its own. The client opens a stream with a CONNECT
//! request, which is answered 200 before anything is known about the
//! stream: the request body then carries what the client sends, starting
//! with the stream's request, and the response body what it receives,
//! starting with the status. Either side ends its direction by ending its
//! body, and a stream that cannot be served is reset.
//!
//! HTTP/2 brings the flow control: the client's data is held up to a window
//! per stream, which reopens as the relay takes the data, and the server
//! sends within the windows the client grants.

use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use bytes::{Buf, Bytes};
use engine_outbound::{BoxStream, TcpOutbound};
use futures_util::stream::{FuturesUnordered, StreamExt};
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{relay_request, MAX_PAYLOAD, MAX_STREAMS, WINDOW};
use crate::server::{InboundStats, ServeSettings};
use crate::udp::UdpOutbound;
use crate::UserEntry;

/// Serves the streams of an h2mux connection until the client closes it or
/// breaks HTTP/2.
pub(super) async fn relay(
    stream: BoxStream,
    user: &Option<Arc<UserEntry>>,
    outbound: &dyn TcpOutbound,
    udp: Option<&dyn UdpOutbound>,
    settings: &ServeSettings,
    stats: &Arc<InboundStats>,
) {
    // The connection's window holds a full one for every stream, so a
    // stream whose target is behind does not hold back the others.
    let handshake = h2::server::Builder::new()
        .initial_window_size(WINDOW)
        .initial_connection_window_size(MAX_STREAMS as u32 * WINDOW)
        .max_concurrent_streams(MAX_STREAMS as u32)
        .handshake::<_, Bytes>(stream);
    let Ok(Ok(mut connection)) = tokio::time::timeout(settings.handshake_timeout, handshake).await
    else {
        stats.handshake_failed.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let mut running = FuturesUnordered::new();
    loop {
        tokio::select! {
            // Accepting is also what reads and writes the connection.
            request = connection.accept() => {
                let Some(Ok((request, respond))) = request else {
                    break;
                };
                // Streams count until their relay is gone, which may be
                // after HTTP/2 has seen the last of them.
                if let Some(stream) = open(request, respond, running.len() >= MAX_STREAMS) {
                    let user = user.clone();
                    running.push(relay_request(stream, user, outbound, udp, settings, stats));
                }
            }
            Some(()) = running.next(), if !running.is_empty() => {}
        }
    }
}

/// Answers a CONNECT request with 200 and returns its stream. Any other
/// request is refused, and with `full` every one.
fn open(
    request: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    full: bool,
) -> Option<H2Stream> {
    if request.method() != http::Method::CONNECT {
        let mut response = http::Response::new(());
        *response.status_mut() = http::StatusCode::BAD_REQUEST;
        let _ = respond.send_response(response, true);
        return None;
    }
    if full {
        respond.send_reset(h2::Reason::REFUSED_STREAM);
        return None;
    }
    let send = respond.send_response(http::Response::new(()), false).ok()?;
    Some(H2Stream {
        body: request.into_body(),
        chunk: Bytes::new(),
        send,
        shut: false,
    })
}

/// One stream of an h2mux connection, as the relay sees a client
/// connection. Dropped before both bodies have ended, it resets the stream.
struct H2Stream {
    /// The request body.
    body: RecvStream,
    /// Client data the relay has not read yet.
    chunk: Bytes,
    /// The response body.
    send: SendStream<Bytes>,
    /// The response body has ended.
    shut: bool,
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.chunk.is_empty() {
            match ready!(this.body.poll_data(cx)) {
                Some(Ok(chunk)) => this.chunk = chunk,
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                // The client sends nothing more.
                None => return Poll::Ready(Ok(())),
            }
        }
        let n = this.chunk.len().min(buf.remaining());
        buf.put_slice(&this.chunk[..n]);
        this.chunk.advance(n);
        // Reopens the client's window by what the relay has taken.
        let _ = this.body.flow_control().release_capacity(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.send.reserve_capacity(buf.len().min(MAX_PAYLOAD));
        while this.send.capacity() == 0 {
            match ready!(this.send.poll_capacity(cx)) {
                Some(Ok(_)) => {}
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
        let n = this.send.capacity().min(buf.len());
        let data = Bytes::copy_from_slice(&buf[..n]);
        this.send.send_data(data, false).map_err(io::Error::other)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.shut {
            this.shut = true;
            let end = this.send.send_data(Bytes::new(), true);
            end.map_err(io::Error::other)?;
        }
        Poll::Ready(Ok(()))
    }
}
