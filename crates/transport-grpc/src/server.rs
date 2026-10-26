//! gRPC ("gun") server side for inbound protocol crates.
//!
//! [`serve_connection`] runs the HTTP/2 server handshake on an accepted
//! stream (plain TCP or TLS negotiated with ALPN `h2`) and turns every
//! `POST <path>` call with a gRPC content type into a byte stream, the same
//! framing the client side uses. Calls run concurrently on the connection;
//! anything else gets `404`. The call ends with `grpc-status: 0` trailers when
//! the stream is shut down.

use std::future::{poll_fn, Future};
use std::io;
use std::task::Poll;
use std::time::Duration;

use bytes::Bytes;
use engine_outbound::{BoxFuture, BoxStream};
use h2::server::SendResponse;
use h2::RecvStream;

use crate::{h2_error, GrpcStream, CONNECTION_WINDOW, STREAM_WINDOW};

/// Most calls open at once on one client connection.
pub const MAX_CONCURRENT_CALLS: u32 = 256;

/// Serves gRPC calls to `path` on `stream` until the client closes the
/// connection, handing each call to `call` and running the returned futures
/// concurrently. Ends when the connection closes; calls still open then are
/// dropped.
pub async fn serve_connection<'a, F>(
    stream: BoxStream,
    path: &str,
    handshake_timeout: Duration,
    mut call: F,
) -> io::Result<()>
where
    F: FnMut(BoxStream) -> BoxFuture<'a, ()>,
{
    let handshake = h2::server::Builder::new()
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
        .max_concurrent_streams(MAX_CONCURRENT_CALLS)
        .handshake::<_, Bytes>(stream);
    let mut connection = tokio::time::timeout(handshake_timeout, handshake)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
        .map_err(h2_error)?;
    let mut calls: Vec<BoxFuture<'a, ()>> = Vec::new();
    let mut accepting = true;
    poll_fn(|cx| {
        calls.retain_mut(|call| call.as_mut().poll(cx).is_pending());
        while accepting {
            match connection.poll_accept(cx) {
                Poll::Ready(Some(Ok((request, respond)))) => {
                    if let Some(stream) = open_call(request, respond, path) {
                        let mut future = call(stream);
                        if future.as_mut().poll(cx).is_pending() {
                            calls.push(future);
                        }
                    }
                }
                Poll::Ready(Some(Err(_)) | None) => accepting = false,
                Poll::Pending => break,
            }
        }
        if accepting {
            return Poll::Pending;
        }
        // No new calls; keep the connection's I/O going for the open ones.
        if calls.is_empty() || connection.poll_closed(cx).is_ready() {
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    })
    .await
}

fn open_call(
    request: http::Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    path: &str,
) -> Option<BoxStream> {
    let is_call = request.method() == http::Method::POST
        && request.uri().path() == path
        && request
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/grpc"));
    if !is_call {
        let response = http::Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .body(())
            .ok()?;
        let _ = respond.send_response(response, true);
        return None;
    }
    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .body(())
        .ok()?;
    let send = respond.send_response(response, false).ok()?;
    Some(Box::new(GrpcStream::new(
        None,
        Some(request.into_body()),
        send,
        true,
    )))
}
