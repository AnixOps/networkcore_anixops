//! Mieru TCP client: one session per connection (spec §4).

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use engine_outbound::{BoxFuture, BoxStream, Dialer, TargetAddr, TcpOutbound};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::crypto::{
    candidate_keys, derive_key, hashed_password, invalid_data, invalid_input, new_nonce,
    random_u32, unix_now,
};
use crate::segment::{Kind, SegmentReader, SegmentWriter, MAX_DATA_PAYLOAD};

pub const PROTOCOL: &str = "mieru";

const READ_CHUNK: usize = 16 * 1024;

/// Client settings. Has no `Debug`: the password is a secret.
#[derive(Clone)]
pub struct MieruOptions {
    pub username: String,
    pub password: String,
    /// Inclusive port range; each connection picks a random port from it
    /// instead of the outbound's port.
    pub port_range: Option<(u16, u16)>,
}

/// Mieru outbound. It holds the hashed password and never prints it.
pub struct MieruOutbound {
    server: String,
    port: u16,
    port_range: Option<(u16, u16)>,
    username: Arc<[u8]>,
    hashed: [u8; 32],
    dialer: Arc<dyn Dialer>,
}

impl MieruOutbound {
    pub fn new(
        server: impl Into<String>,
        port: u16,
        options: MieruOptions,
        dialer: Arc<dyn Dialer>,
    ) -> io::Result<Self> {
        let server = server.into();
        if server.is_empty() || port == 0 {
            return Err(invalid_input("mieru server address is empty"));
        }
        if options.username.is_empty() || options.password.is_empty() {
            return Err(invalid_input("mieru username or password is empty"));
        }
        if let Some((low, high)) = options.port_range {
            if low == 0 || low > high {
                return Err(invalid_input("mieru port range is invalid"));
            }
        }
        Ok(Self {
            server,
            port,
            port_range: options.port_range,
            hashed: hashed_password(options.username.as_bytes(), options.password.as_bytes()),
            username: options.username.into_bytes().into(),
            dialer,
        })
    }

    fn pick_port(&self) -> io::Result<u16> {
        match self.port_range {
            None => Ok(self.port),
            Some((low, high)) => {
                let span = u32::from(high - low) + 1;
                Ok(low + (random_u32()? % span) as u16)
            }
        }
    }

    /// Opens a session to `target`. The open request is on the wire when
    /// this returns; nothing waits for the server's answer.
    pub async fn connect_stream(&self, target: &TargetAddr) -> io::Result<MieruStream> {
        let request = socks_request(target)?;
        let port = self.pick_port()?;
        let inner = self.dialer.dial(&self.server, port).await?;
        let mut stream = MieruStream::new(inner, &self.username, &self.hashed, &request)?;
        stream.flush().await?;
        Ok(stream)
    }
}

impl TcpOutbound for MieruOutbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move { Ok(Box::new(self.connect_stream(target).await?) as BoxStream) })
    }
}

/// SOCKS5 CONNECT request without the greeting: `05 01 00 ATYP ADDR PORT`.
fn socks_request(target: &TargetAddr) -> io::Result<Vec<u8>> {
    let mut out = vec![5, 1, 0];
    match target {
        TargetAddr::Ip(SocketAddr::V4(addr)) => {
            out.push(1);
            out.extend_from_slice(&addr.ip().octets());
        }
        TargetAddr::Ip(SocketAddr::V6(addr)) => {
            out.push(4);
            out.extend_from_slice(&addr.ip().octets());
        }
        TargetAddr::Domain(domain, _) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > 255 {
                return Err(invalid_input("target domain length is out of range"));
            }
            out.push(3);
            out.push(bytes.len() as u8);
            out.extend_from_slice(bytes);
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    Ok(out)
}

/// Length of the SOCKS5 reply at the start of `buf`, or `None` while it is
/// incomplete.
fn socks_reply_len(buf: &[u8]) -> io::Result<Option<usize>> {
    if buf.len() < 5 {
        return Ok(None);
    }
    if buf[0] != 5 {
        return Err(invalid_data("mieru server sent an invalid SOCKS5 reply"));
    }
    let len = match buf[3] {
        1 => 4 + 4 + 2,
        4 => 4 + 16 + 2,
        3 => 4 + 1 + usize::from(buf[4]) + 2,
        _ => return Err(invalid_data("mieru server sent an invalid SOCKS5 reply")),
    };
    Ok((buf.len() >= len).then_some(len))
}

/// A Mieru session over one TCP connection.
pub struct MieruStream {
    inner: BoxStream,
    session_id: u32,
    writer: SegmentWriter,
    reader: SegmentReader,
    out: Vec<u8>,
    out_pos: usize,
    input: Vec<u8>,
    plain: Vec<u8>,
    plain_pos: usize,
    /// The server stream's SOCKS5 reply, until it is complete.
    reply: Option<Vec<u8>>,
    read_eof: bool,
    close_sent: bool,
}

impl MieruStream {
    fn new(
        inner: BoxStream,
        username: &[u8],
        hashed: &[u8; 32],
        request: &[u8],
    ) -> io::Result<Self> {
        let now = unix_now();
        let session_id = loop {
            let id = random_u32()?;
            if id != 0 {
                break id;
            }
        };
        let mut writer =
            SegmentWriter::new(&derive_key(hashed, now), new_nonce(username)?, session_id);
        let mut out = Vec::new();
        writer.write(&mut out, Kind::OpenSessionRequest, request)?;
        Ok(Self {
            inner,
            session_id,
            writer,
            reader: SegmentReader::new(candidate_keys(hashed, now).to_vec()),
            out,
            out_pos: 0,
            input: Vec::new(),
            plain: Vec::new(),
            plain_pos: 0,
            reply: Some(Vec::new()),
            read_eof: false,
            close_sent: false,
        })
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

    /// Hands session payload to the reader, after the SOCKS5 reply.
    fn deliver(&mut self, payload: Vec<u8>) -> io::Result<()> {
        let Some(reply) = self.reply.as_mut() else {
            self.plain = payload;
            self.plain_pos = 0;
            return Ok(());
        };
        reply.extend_from_slice(&payload);
        let Some(len) = socks_reply_len(reply)? else {
            return Ok(());
        };
        if reply[1] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "mieru server could not connect to the target",
            ));
        }
        let mut reply = self.reply.take().expect("pending reply");
        reply.drain(..len);
        self.plain = reply;
        self.plain_pos = 0;
        Ok(())
    }

    /// Processes buffered segments until plaintext is available, the session
    /// ends or more input is needed.
    fn process_input(&mut self) -> io::Result<()> {
        while self.plain_pos >= self.plain.len() && !self.read_eof {
            let Some(segment) = self.reader.next_segment(&mut self.input)? else {
                return Ok(());
            };
            if segment.metadata.session_id != self.session_id {
                return Err(invalid_data("mieru segment belongs to another session"));
            }
            match segment.metadata.kind {
                Kind::OpenSessionResponse => {
                    if segment.metadata.status != 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            "mieru server refused the session",
                        ));
                    }
                    self.deliver(segment.payload)?;
                }
                Kind::DataServerToClient => self.deliver(segment.payload)?,
                Kind::AckServerToClient => {}
                Kind::CloseSessionRequest => {
                    self.writer
                        .write(&mut self.out, Kind::CloseSessionResponse, &[])?;
                    self.read_eof = true;
                }
                Kind::CloseSessionResponse => self.read_eof = true,
                _ => return Err(invalid_data("mieru server sent a client segment")),
            }
        }
        Ok(())
    }
}

impl AsyncRead for MieruStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            this.process_input()?;
            // A close response queued by `process_input` goes out best effort.
            if let Poll::Ready(Err(err)) = this.poll_drain(cx) {
                return Poll::Ready(Err(err));
            }
            if this.plain_pos < this.plain.len() {
                let available = &this.plain[this.plain_pos..];
                let n = available.len().min(buf.remaining());
                buf.put_slice(&available[..n]);
                this.plain_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.read_eof {
                if this.reply.is_some() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "mieru session closed before the target answered",
                    )));
                }
                return Poll::Ready(Ok(()));
            }
            let start = this.input.len();
            this.input.resize(start + READ_CHUNK, 0);
            let mut read_buf = ReadBuf::new(&mut this.input[start..]);
            let polled = Pin::new(&mut this.inner).poll_read(cx, &mut read_buf);
            let n = read_buf.filled().len();
            this.input.truncate(start + n);
            ready!(polled)?;
            if n == 0 {
                if this.input.is_empty() && !this.reader.is_mid_segment() && this.reply.is_none() {
                    this.read_eof = true;
                    continue;
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
        }
    }
}

impl AsyncWrite for MieruStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if this.close_sent {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(MAX_DATA_PAYLOAD);
        this.writer
            .write(&mut this.out, Kind::DataClientToServer, &buf[..n])?;
        // The segment is committed to `out`; a pending drain finishes later.
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

    /// Mieru has no half-close: the session is closed only once the server
    /// stream has ended; before that a shutdown just flushes (spec §4).
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        if !this.read_eof {
            return Pin::new(&mut this.inner).poll_flush(cx);
        }
        if !this.close_sent {
            this.writer
                .write(&mut this.out, Kind::CloseSessionRequest, &[])?;
            this.close_sent = true;
            ready!(this.poll_drain(cx))?;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_request_matches_the_observed_layout() {
        let ip: TargetAddr = "127.0.0.1:29020".parse::<SocketAddr>().unwrap().into();
        assert_eq!(
            socks_request(&ip).unwrap(),
            [5, 1, 0, 1, 127, 0, 0, 1, 0x71, 0x5c]
        );
        let domain = TargetAddr::Domain("localhost".into(), 29020);
        assert_eq!(
            socks_request(&domain).unwrap(),
            b"\x05\x01\x00\x03\x09localhost\x71\x5c"
        );
        assert!(socks_request(&TargetAddr::Domain(String::new(), 1)).is_err());
    }

    #[test]
    fn socks_reply_length_covers_every_address_type() {
        assert_eq!(socks_reply_len(&[5, 0, 0, 1]).unwrap(), None);
        assert_eq!(
            socks_reply_len(&[5, 0, 0, 1, 127, 0, 0, 1, 0xca]).unwrap(),
            None
        );
        assert_eq!(
            socks_reply_len(&[5, 0, 0, 1, 127, 0, 0, 1, 0xca, 0x86, 9]).unwrap(),
            Some(10)
        );
        assert_eq!(
            socks_reply_len(&[5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
                .unwrap(),
            Some(22)
        );
        assert_eq!(
            socks_reply_len(b"\x05\x00\x00\x03\x01a\x00\x50").unwrap(),
            Some(8)
        );
        assert!(socks_reply_len(&[4, 0, 0, 1, 0]).is_err());
        assert!(socks_reply_len(&[5, 0, 0, 9, 0]).is_err());
    }
}
