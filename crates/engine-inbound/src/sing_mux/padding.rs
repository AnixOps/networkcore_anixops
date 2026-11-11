//! sing-mux padding, which hides the sizes a multiplexer starts with.
//!
//! On a connection whose session request asked for it, each side sends the
//! first [`RECORDS`] writes of its multiplexer as records,
//!
//! ```text
//! LENGTH(2) PADDING(2) DATA PADDING-BYTES
//! ```
//!
//! and everything after them as it is. The two directions count their
//! records apart.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use engine_outbound::BoxStream;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The writes of each direction that are records.
const RECORDS: u8 = 16;

/// A padded connection, as the multiplexer on it sees it.
pub(super) struct Padded {
    inner: BoxStream,
    /// Records the client has started.
    read: u8,
    header: [u8; 4],
    header_len: usize,
    /// What is left of the record being read: its data, then its padding.
    data: usize,
    padding: usize,
    /// Records written.
    written: u8,
    /// A record on its way to `inner`.
    out: Vec<u8>,
    out_pos: usize,
}

impl Padded {
    pub(super) fn new(inner: BoxStream) -> Self {
        Self {
            inner,
            read: 0,
            header: [0; 4],
            header_len: 0,
            data: 0,
            padding: 0,
            written: 0,
            out: Vec::new(),
            out_pos: 0,
        }
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

/// How many bytes pad a record: 256 to 767, as the clients choose.
fn padding_len() -> usize {
    let mut random = [0u8; 2];
    let _ = SystemRandom::new().fill(&mut random);
    256 + usize::from(u16::from_be_bytes(random)) % 512
}

impl AsyncRead for Padded {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.data > 0 {
                let n = this.data.min(buf.remaining());
                let mut data = ReadBuf::new(buf.initialize_unfilled_to(n));
                ready!(Pin::new(&mut this.inner).poll_read(cx, &mut data))?;
                let n = data.filled().len();
                buf.advance(n);
                this.data -= n;
                return Poll::Ready(Ok(()));
            }
            if this.padding == 0 && this.read == RECORDS {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
            // Padding to drop, or the header of the next record.
            let mut scratch = [0u8; 512];
            let mut part = if this.padding > 0 {
                ReadBuf::new(&mut scratch[..this.padding.min(512)])
            } else {
                ReadBuf::new(&mut this.header[this.header_len..])
            };
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut part))?;
            let n = part.filled().len();
            if n == 0 {
                // The client closed the connection.
                return Poll::Ready(Ok(()));
            }
            if this.padding > 0 {
                this.padding -= n;
                continue;
            }
            this.header_len += n;
            if this.header_len == this.header.len() {
                this.header_len = 0;
                this.read += 1;
                this.data = usize::from(u16::from_be_bytes([this.header[0], this.header[1]]));
                this.padding = usize::from(u16::from_be_bytes([this.header[2], this.header[3]]));
            }
        }
    }
}

impl AsyncWrite for Padded {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if this.written == RECORDS || buf.is_empty() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        let n = buf.len().min(usize::from(u16::MAX));
        let padding = padding_len();
        this.out.extend_from_slice(&(n as u16).to_be_bytes());
        this.out.extend_from_slice(&(padding as u16).to_be_bytes());
        this.out.extend_from_slice(&buf[..n]);
        this.out.resize(this.out.len() + padding, 0);
        this.written += 1;
        // The bytes are in the record; a pending drain finishes on the next
        // call.
        if let Poll::Ready(Err(error)) = this.poll_drain(cx) {
            return Poll::Ready(Err(error));
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn the_first_records_of_each_direction_are_padded() {
        let (mut client, server) = tokio::io::duplex(64 * 1024);
        let mut stream = Padded::new(Box::new(server));

        // Records with and without data and padding, then plain bytes.
        let (mut sent, mut expected) = (Vec::new(), Vec::new());
        for index in 0..RECORDS {
            let data = vec![index; usize::from(index % 4)];
            let padding = usize::from(index) * 40;
            sent.extend_from_slice(&(data.len() as u16).to_be_bytes());
            sent.extend_from_slice(&(padding as u16).to_be_bytes());
            sent.extend_from_slice(&data);
            sent.resize(sent.len() + padding, 0xee);
            expected.extend(data);
        }
        sent.extend_from_slice(b"plain");
        expected.extend_from_slice(b"plain");
        client.write_all(&sent).await.unwrap();
        let mut received = vec![0u8; expected.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);

        for index in 0..=RECORDS {
            stream.write_all(&[index; 3]).await.unwrap();
        }
        stream.flush().await.unwrap();
        for index in 0..RECORDS {
            let mut header = [0u8; 4];
            client.read_exact(&mut header).await.unwrap();
            assert_eq!(header[..2], [0, 3]);
            let padding = usize::from(u16::from_be_bytes([header[2], header[3]]));
            assert!((256..768).contains(&padding), "{padding}");
            let mut record = vec![0u8; 3 + padding];
            client.read_exact(&mut record).await.unwrap();
            assert_eq!(record[..3], [index; 3]);
        }
        let mut plain = [0u8; 3];
        client.read_exact(&mut plain).await.unwrap();
        assert_eq!(plain, [RECORDS; 3]);
    }
}
