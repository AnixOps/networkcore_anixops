//! The payload padding of NaiveProxy tunnels.
//!
//! The first [`FRAMES`] reads and writes of a tunnel are framed in each
//! direction, which hides the sizes of the first packets (usually a TLS
//! handshake) from an observer:
//!
//! ```text
//! PAYLOAD_LEN (u16, big endian) | PADDING_LEN (u8) | PAYLOAD | PADDING (zeros)
//! ```
//!
//! After them the bytes pass unchanged. [`Padded`] is one end of such a
//! tunnel: it frames what it writes and unframes what it reads, so the
//! server and a client use it alike.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Reads and writes that are framed, in each direction.
pub const FRAMES: usize = 8;
const HEADER_LEN: usize = 3;

pub struct Padded<S> {
    inner: S,
    /// Frames still to read.
    read_frames: usize,
    header: [u8; HEADER_LEN],
    header_len: usize,
    /// What is left of the frame being read.
    payload: usize,
    padding: usize,
    /// Frames still to write, and their padding lengths.
    write_frames: usize,
    paddings: [u8; FRAMES],
    /// A frame not yet written to `inner`.
    out: Vec<u8>,
    out_pos: usize,
}

impl<S> Padded<S> {
    pub fn new(inner: S) -> Self {
        let mut paddings = [0u8; FRAMES];
        let _ = SystemRandom::new().fill(&mut paddings);
        Self {
            inner,
            read_frames: FRAMES,
            header: [0; HEADER_LEN],
            header_len: 0,
            payload: 0,
            padding: 0,
            write_frames: FRAMES,
            paddings,
            out: Vec::new(),
            out_pos: 0,
        }
    }

    /// Counts the frame being read once nothing is left of it.
    fn frame_read(&mut self) {
        if self.payload == 0 && self.padding == 0 {
            self.read_frames -= 1;
        }
    }
}

impl<S: AsyncWrite + Unpin> Padded<S> {
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

/// One frame around `payload`, which is at most `u16::MAX` bytes.
fn frame(payload: &[u8], padding: u8) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len() + usize::from(padding));
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.push(padding);
    frame.extend_from_slice(payload);
    frame.resize(frame.len() + usize::from(padding), 0);
    frame
}

impl<S: AsyncRead + Unpin> AsyncRead for Padded<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.payload > 0 {
                let len = this.payload.min(buf.remaining());
                let mut part = ReadBuf::new(buf.initialize_unfilled_to(len));
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut part))?;
                let n = part.filled().len();
                buf.advance(n);
                this.payload -= n;
                this.frame_read();
                return Poll::Ready(Ok(()));
            }
            if this.padding > 0 {
                let mut skipped = [0u8; u8::MAX as usize];
                let mut part = ReadBuf::new(&mut skipped[..this.padding]);
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut part))?;
                let n = part.filled().len();
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }
                this.padding -= n;
                this.frame_read();
                continue;
            }
            if this.read_frames == 0 {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            let mut part = ReadBuf::new(&mut this.header[this.header_len..]);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut part))?;
            let n = part.filled().len();
            if n == 0 {
                return Poll::Ready(Ok(()));
            }
            this.header_len += n;
            if this.header_len == HEADER_LEN {
                this.header_len = 0;
                this.payload = usize::from(u16::from_be_bytes([this.header[0], this.header[1]]));
                this.padding = usize::from(this.header[2]);
                this.frame_read();
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Padded<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if this.write_frames == 0 || buf.is_empty() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        this.write_frames -= 1;
        let len = buf.len().min(usize::from(u16::MAX));
        this.out = frame(&buf[..len], this.paddings[this.write_frames]);
        // The payload is committed to `out`; a pending drain finishes on the
        // next call.
        if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(len))
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn frames_are_lengths_payload_and_zeros() {
        assert_eq!(frame(b"abc", 2), [0, 3, 2, b'a', b'b', b'c', 0, 0]);
        assert_eq!(frame(&[], 0), [0, 0, 0]);
        let long = frame(&[7; 300], 255);
        assert_eq!(long[..4], [1, 44, 255, 7]);
        assert_eq!(long.len(), 3 + 300 + 255);
        assert!(long[303..].iter().all(|byte| *byte == 0));
    }

    #[tokio::test]
    async fn reads_eight_frames_then_plain_bytes() {
        let (mut client, server) = tokio::io::duplex(64);
        let mut wire = Vec::new();
        let mut expected = Vec::new();
        // Paddings from none to the most, and a frame without payload.
        for (index, padding) in [0u8, 255, 1, 17, 200, 3, 64, 128].into_iter().enumerate() {
            let payload = vec![index as u8 + 1; index * 37 % 100];
            wire.extend_from_slice(&frame(&payload, padding));
            expected.extend_from_slice(&payload);
        }
        // The ninth read is not a frame, whatever it looks like.
        wire.extend_from_slice(&[0, 2, 1, 9, 9, 0]);
        expected.extend_from_slice(&[0, 2, 1, 9, 9, 0]);
        tokio::spawn(async move {
            // Short writes split headers, payloads and paddings across reads.
            for chunk in wire.chunks(5) {
                client.write_all(chunk).await.unwrap();
            }
        });
        let mut payload = Vec::new();
        Padded::new(server).read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, expected);
    }

    #[tokio::test]
    async fn writes_eight_frames_then_plain_bytes() {
        let (client, mut server) = tokio::io::duplex(1 << 16);
        let mut padded = Padded::new(client);
        for index in 0..FRAMES + 2 {
            padded.write_all(&[index as u8; 20]).await.unwrap();
        }
        padded.shutdown().await.unwrap();
        let mut wire = Vec::new();
        server.read_to_end(&mut wire).await.unwrap();
        let mut rest = wire.as_slice();
        for index in 0..FRAMES {
            assert_eq!(rest[..2], [0, 20]);
            let padding = usize::from(rest[2]);
            assert_eq!(rest[3..23], [index as u8; 20]);
            assert!(rest[23..23 + padding].iter().all(|byte| *byte == 0));
            rest = &rest[23 + padding..];
        }
        assert_eq!(rest, [[8u8; 20], [9u8; 20]].concat());
    }

    #[tokio::test]
    async fn two_ends_carry_a_conversation() {
        let (client, server) = tokio::io::duplex(256);
        let (mut client, mut server) = (Padded::new(client), Padded::new(server));
        // Longer than one frame may be.
        let message: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let len = message.len();
        let echo = tokio::spawn(async move {
            let mut received = vec![0u8; len];
            server.read_exact(&mut received).await.unwrap();
            for chunk in received.chunks(3000) {
                server.write_all(chunk).await.unwrap();
            }
            server.flush().await.unwrap();
        });
        client.write_all(&message).await.unwrap();
        client.flush().await.unwrap();
        let mut echoed = vec![0u8; len];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, message);
        echo.await.unwrap();
    }
}
