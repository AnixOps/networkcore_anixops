//! XHTTP over HTTP/3: the same requests as over HTTP/2, on a QUIC
//! connection per proxied stream.
//!
//! Dropping the last request sender closes an HTTP/3 connection, so every
//! task of a session keeps a clone of it until its stream is done.

use std::io;
use std::sync::Arc;

use bytes::{Buf, Bytes};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf};
use transport_quic::QuicConnector;

use crate::{rejected, Chunker, Inner, STREAM_CHUNK};

pub(crate) type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
pub(crate) type SendHalf = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
pub(crate) type RecvHalf = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

/// Completes the QUIC and HTTP/3 handshakes. The connection lives until the
/// last clone of the returned sender is dropped.
pub(crate) async fn connect(quic: &QuicConnector) -> io::Result<Sender> {
    let connection = quic.connect().await?;
    let (mut driver, sender) =
        h3::client::new(h3_quinn::Connection::new(connection.connection.clone()))
            .await
            .map_err(h3_error)?;
    tokio::spawn(async move {
        let _ = driver.wait_idle().await;
        drop(connection);
    });
    Ok(sender)
}

/// Sends the request head and splits the stream into its halves.
pub(crate) async fn request(
    sender: &mut Sender,
    request: http::Request<()>,
) -> io::Result<(SendHalf, RecvHalf)> {
    let stream = sender.send_request(request).await.map_err(h3_error)?;
    Ok(stream.split())
}

/// Waits for a `200` and copies the body into `output`.
pub(crate) async fn copy_response(
    recv: &mut RecvHalf,
    output: &mut (impl AsyncWrite + Unpin),
) -> io::Result<()> {
    let response = recv.recv_response().await.map_err(h3_error)?;
    if response.status() != http::StatusCode::OK {
        return Err(rejected(response.status().as_u16()));
    }
    loop {
        let bytes = match recv.recv_data().await.map_err(h3_error)? {
            Some(mut chunk) => chunk.copy_to_bytes(chunk.remaining()),
            None => return Ok(()),
        };
        output.write_all(&bytes).await?;
    }
}

/// A request without a body: sends its end at once.
pub(crate) async fn get(sender: &mut Sender, request: http::Request<()>) -> io::Result<RecvHalf> {
    let (mut send, recv) = self::request(sender, request).await?;
    send.finish().await.map_err(h3_error)?;
    Ok(recv)
}

pub(crate) async fn packet_upload(
    inner: Arc<Inner>,
    session: String,
    mut sender: Sender,
    mut chunker: Chunker,
) -> io::Result<()> {
    let mut seq = 0u64;
    while let Some(chunk) = chunker.next().await? {
        let target = inner.target(&format!("{session}/{seq}"));
        let request = inner.h2_request(http::Method::POST, &target, Some(chunk.len()))?;
        let (mut send, mut recv) = self::request(&mut sender, request).await?;
        send.send_data(chunk).await.map_err(h3_error)?;
        send.finish().await.map_err(h3_error)?;
        copy_response(&mut recv, &mut tokio::io::sink()).await?;
        seq += 1;
    }
    Ok(())
}

/// Streams the proxied stream's writes as the request body; `_sender` keeps
/// the connection open meanwhile.
pub(crate) async fn stream_upload(
    mut send: SendHalf,
    mut input: ReadHalf<DuplexStream>,
    _sender: Sender,
) -> io::Result<()> {
    let mut buf = vec![0u8; STREAM_CHUNK];
    loop {
        let read = input.read(&mut buf).await?;
        if read == 0 {
            return send.finish().await.map_err(h3_error);
        }
        send.send_data(Bytes::copy_from_slice(&buf[..read]))
            .await
            .map_err(h3_error)?;
    }
}

/// Reads a response to its end, e.g. the padding of a `stream-up` upload.
pub(crate) async fn drain_response(mut recv: RecvHalf, _sender: Sender) -> io::Result<()> {
    copy_response(&mut recv, &mut tokio::io::sink()).await
}

pub(crate) fn h3_error(err: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("http/3: {err}"))
}
