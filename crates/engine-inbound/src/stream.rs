//! Stream helpers for protocol inbounds.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use engine_outbound::BoxStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Wraps a client stream with bytes to replay before reading from it (input
/// a handshake already consumed) and bytes to send before the first write (a
/// response header, kept in the same write as the first payload).
pub struct PrefixedStream {
    inner: BoxStream,
    read_prefix: Vec<u8>,
    read_pos: usize,
    /// Response header not yet merged into `out`.
    write_prefix: Option<Vec<u8>>,
    out: Vec<u8>,
    out_pos: usize,
}

impl PrefixedStream {
    pub fn new(inner: BoxStream) -> Self {
        Self {
            inner,
            read_prefix: Vec::new(),
            read_pos: 0,
            write_prefix: None,
            out: Vec::new(),
            out_pos: 0,
        }
    }

    /// Bytes returned by reads before anything from the inner stream.
    pub fn with_read_prefix(mut self, prefix: Vec<u8>) -> Self {
        self.read_prefix = prefix;
        self.read_pos = 0;
        self
    }

    /// Bytes written before the first payload (or on shutdown, if nothing
    /// was written).
    pub fn with_write_prefix(mut self, prefix: Vec<u8>) -> Self {
        self.write_prefix = (!prefix.is_empty()).then_some(prefix);
        self
    }

    /// Unread replay bytes.
    pub fn buffered(&self) -> &[u8] {
        &self.read_prefix[self.read_pos..]
    }

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

impl AsyncRead for PrefixedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_pos < this.read_prefix.len() {
            let available = &this.read_prefix[this.read_pos..];
            let n = available.len().min(buf.remaining());
            buf.put_slice(&available[..n]);
            this.read_pos += n;
            if this.read_pos == this.read_prefix.len() {
                this.read_prefix = Vec::new();
                this.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        let Some(mut prefix) = this.write_prefix.take() else {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        };
        prefix.extend_from_slice(buf);
        this.out = prefix;
        this.out_pos = 0;
        // The payload is committed to `out`; a pending drain finishes on the
        // next call.
        if let Poll::Ready(Err(err)) = this.poll_drain(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(prefix) = this.write_prefix.take() {
            this.out = prefix;
            this.out_pos = 0;
        }
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn replays_then_reads_and_prefixes_the_first_write() {
        let (client, server) = tokio::io::duplex(1024);
        let mut stream = PrefixedStream::new(Box::new(server))
            .with_read_prefix(b"early".to_vec())
            .with_write_prefix(vec![0, 0]);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        client_write.write_all(b" late").await.unwrap();

        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"early late");

        stream.write_all(b"one").await.unwrap();
        stream.write_all(b"two").await.unwrap();
        stream.flush().await.unwrap();
        let mut out = [0u8; 8];
        client_read.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"\0\0onetwo");
    }

    #[tokio::test]
    async fn shutdown_sends_an_unwritten_prefix() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut stream = PrefixedStream::new(Box::new(server)).with_write_prefix(vec![7, 8]);
        stream.shutdown().await.unwrap();
        let mut out = Vec::new();
        client.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, [7, 8]);
    }
}
