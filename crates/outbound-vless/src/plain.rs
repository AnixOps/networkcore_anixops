//! VLESS without REALITY: over plain TCP or standard TLS, optionally inside a
//! WebSocket. No Vision flow; the stream carries the VLESS header and then
//! the payload unchanged.

use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use engine_outbound::{BoxFuture, BoxStream, Dialer, TargetAddr, TcpOutbound};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use transport_grpc::GrpcConnector;
use transport_tls::TlsConnector;
use transport_ws::WsConnector;

use crate::protocol::{encode_request_header, Flow};

/// VLESS over TCP or TLS, optionally inside a WebSocket.
pub struct VlessTlsOutbound {
    server: String,
    port: u16,
    uuid: [u8; 16],
    tls: Option<TlsConnector>,
    websocket: Option<WsConnector>,
    grpc: Option<GrpcConnector>,
    dialer: Arc<dyn Dialer>,
}

impl fmt::Debug for VlessTlsOutbound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlessTlsOutbound")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("uuid", &"<redacted>")
            .field("tls", &self.tls.is_some())
            .field("websocket", &self.websocket.is_some())
            .field("grpc", &self.grpc.is_some())
            .finish()
    }
}

impl VlessTlsOutbound {
    /// `tls: None` is VLESS over plain TCP (`security=none`).
    pub fn new(
        server: impl Into<String>,
        port: u16,
        uuid: [u8; 16],
        tls: Option<TlsConnector>,
        dialer: Arc<dyn Dialer>,
    ) -> io::Result<Self> {
        let server = server.into();
        if server.is_empty() || port == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vless server address is empty",
            ));
        }
        Ok(Self {
            server,
            port,
            uuid,
            tls,
            websocket: None,
            grpc: None,
            dialer,
        })
    }

    /// Carries VLESS in a WebSocket (inside TLS when TLS is set).
    pub fn with_websocket(mut self, websocket: WsConnector) -> Self {
        self.websocket = Some(websocket);
        self
    }

    /// Carries the stream in a gRPC (`gun`) call instead of a WebSocket.
    pub fn with_grpc(mut self, grpc: GrpcConnector) -> Self {
        self.grpc = Some(grpc);
        self
    }
}

impl TcpOutbound for VlessTlsOutbound {
    fn protocol(&self) -> &'static str {
        "vless"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let header = encode_request_header(&self.uuid, Flow::None, target)?;
            let mut stream = self.dialer.dial(&self.server, self.port).await?;
            if let Some(tls) = &self.tls {
                stream = tls.connect(stream).await?;
            }
            if let Some(websocket) = &self.websocket {
                stream = websocket.connect(stream).await?;
            }
            if let Some(grpc) = &self.grpc {
                stream = grpc.connect(stream).await?;
            }
            Ok(Box::new(PlainVlessStream {
                inner: stream,
                pending: header,
                written: 0,
                merged: false,
                response: ResponseState::Head {
                    have: 0,
                    head: [0; 2],
                },
            }) as BoxStream)
        })
    }
}

/// The response header (`version`, `addons length`, addons) still to skip.
#[derive(Clone, Copy)]
enum ResponseState {
    Head { have: usize, head: [u8; 2] },
    Addons { left: usize },
    Done,
}

/// Writes the request header together with the first payload, and strips
/// the response header before the first payload byte.
struct PlainVlessStream {
    inner: BoxStream,
    pending: Vec<u8>,
    written: usize,
    merged: bool,
    response: ResponseState,
}

impl PlainVlessStream {
    fn poll_send_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.written < self.pending.len() {
            let n =
                ready!(Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.written..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.written += n;
        }
        if !self.pending.is_empty() {
            self.pending = Vec::new();
            self.written = 0;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_skip_response(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut scratch = [0u8; 255];
            let need = match &self.response {
                ResponseState::Done => return Poll::Ready(Ok(())),
                ResponseState::Head { have, .. } => 2 - have,
                ResponseState::Addons { left } => *left,
            };
            let mut read_buf = ReadBuf::new(&mut scratch[..need]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut read_buf))?;
            let got = read_buf.filled();
            if got.is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "vless server closed before its response header",
                )));
            }
            self.response = match self.response {
                ResponseState::Head { have, mut head } => {
                    head[have..have + got.len()].copy_from_slice(got);
                    let have = have + got.len();
                    if have < 2 {
                        ResponseState::Head { have, head }
                    } else if head[0] != 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "vless server sent an unknown response version",
                        )));
                    } else if head[1] == 0 {
                        ResponseState::Done
                    } else {
                        ResponseState::Addons {
                            left: usize::from(head[1]),
                        }
                    }
                }
                ResponseState::Addons { left } if left > got.len() => ResponseState::Addons {
                    left: left - got.len(),
                },
                ResponseState::Addons { .. } | ResponseState::Done => ResponseState::Done,
            };
        }
    }
}

impl AsyncWrite for PlainVlessStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.merged {
            // Header and first payload in one write, as Xray sends them.
            self.merged = true;
            self.pending.extend_from_slice(buf);
            if let Poll::Ready(Err(err)) = self.poll_send_pending(cx) {
                return Poll::Ready(Err(err));
            }
            return Poll::Ready(Ok(buf.len()));
        }
        ready!(self.poll_send_pending(cx))?;
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_send_pending(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_send_pending(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for PlainVlessStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Server-speaks-first targets: the request must reach the server
        // before any response can arrive.
        if !self.pending.is_empty() {
            self.merged = true;
            ready!(self.poll_send_pending(cx))?;
            ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        }
        ready!(self.poll_skip_response(cx))?;
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
