//! WebSocket, HTTPUpgrade, gRPC and XHTTP server transports between the client
//! connection (or its TLS layer) and the protocol inbound.

use std::net::SocketAddr;
use std::sync::Arc;

use engine_inbound::registry::BuildError;
use engine_inbound::server::ConnectionContext;
use engine_inbound::udp::DatagramInbound;
use engine_inbound::{Accepted, Rejected, StreamInbound, UserStore};
use engine_outbound::{BoxFuture, BoxStream};
use serde::Deserialize;
use transport_ws::server::{
    HttpUpgradeAcceptor, WsAcceptor, WsServerSettings, DEFAULT_MAX_EARLY_DATA,
};
use transport_xhttp::server::XhttpServer;
use transport_xhttp::XhttpSettings;

/// `"transport"` in inbound settings, the server side of the outbound
/// `transport` object.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum TransportSettings {
    /// The protocol directly on TCP (or TLS); the same as no transport.
    Tcp,
    Ws {
        /// Request path, `/` when empty.
        #[serde(default)]
        path: String,
        /// Required `Host` header; any when empty.
        #[serde(default)]
        host: String,
        /// Largest early data accepted in the handshake (Xray `?ed=`); 0
        /// turns it off.
        #[serde(default = "default_max_early_data")]
        max_early_data: usize,
        /// Header carrying early data; `Sec-WebSocket-Protocol` when empty.
        #[serde(default)]
        early_data_header_name: String,
    },
    /// V2Ray/sing-box/Xray `httpupgrade`: a WebSocket-style upgrade
    /// request, then raw bytes. Takes the same members as `ws`.
    #[serde(alias = "http_upgrade")]
    Httpupgrade {
        /// Request path, `/` when empty.
        #[serde(default)]
        path: String,
        /// Required `Host` header; any when empty.
        #[serde(default)]
        host: String,
        /// Largest early data accepted in the handshake; 0 turns it off.
        #[serde(default = "default_max_early_data")]
        max_early_data: usize,
        /// Header carrying early data; `Sec-WebSocket-Protocol` when empty.
        #[serde(default)]
        early_data_header_name: String,
    },
    Grpc {
        /// Calls go to `/<service_name>/Tun`; a name starting with `/` is a
        /// full custom path.
        service_name: String,
    },
    /// Xray XHTTP (SplitHTTP); `splithttp` is its older name. `path`,
    /// `host`, `mode` (which upload modes are accepted), `x_padding_bytes`
    /// and `sc_max_each_post_bytes` apply to the server.
    #[serde(alias = "splithttp")]
    Xhttp(XhttpSettings),
}

fn default_max_early_data() -> usize {
    DEFAULT_MAX_EARLY_DATA
}

impl TransportSettings {
    /// Whether the transport needs HTTP/2, and so ALPN `h2` under TLS.
    pub fn needs_h2(&self) -> bool {
        matches!(self, Self::Grpc { .. })
    }

    /// The ALPN list offered under TLS when none is configured.
    pub fn default_alpn(&self) -> &'static [&'static str] {
        match self {
            Self::Grpc { .. } => &["h2"],
            Self::Xhttp(_) => &["h2", "http/1.1"],
            _ => &[],
        }
    }
}

/// Wraps `inner` in the transport when one other than `tcp` is set.
pub fn wrap_transport(
    inner: Arc<dyn StreamInbound>,
    transport: Option<&TransportSettings>,
) -> Result<Arc<dyn StreamInbound>, BuildError> {
    match transport {
        None | Some(TransportSettings::Tcp) => Ok(inner),
        Some(TransportSettings::Ws {
            path,
            host,
            max_early_data,
            early_data_header_name,
        }) => {
            let acceptor = WsAcceptor::new(&WsServerSettings {
                path: path.clone(),
                host: host.clone(),
                max_early_data: *max_early_data,
                early_data_header_name: early_data_header_name.clone(),
            })
            .map_err(|_| "ws transport path, host or early data header is invalid")?;
            Ok(Arc::new(WsInbound { acceptor, inner }))
        }
        Some(TransportSettings::Httpupgrade {
            path,
            host,
            max_early_data,
            early_data_header_name,
        }) => {
            let acceptor = HttpUpgradeAcceptor::new(&WsServerSettings {
                path: path.clone(),
                host: host.clone(),
                max_early_data: *max_early_data,
                early_data_header_name: early_data_header_name.clone(),
            })
            .map_err(|_| "httpupgrade transport path, host or early data header is invalid")?;
            Ok(Arc::new(HttpUpgradeInbound { acceptor, inner }))
        }
        Some(TransportSettings::Grpc { service_name }) => {
            let path = transport_grpc::tun_path(service_name)
                .map_err(|_| "grpc transport service_name is missing or invalid")?;
            Ok(Arc::new(GrpcInbound { path, inner }))
        }
        Some(TransportSettings::Xhttp(settings)) => {
            let server = XhttpServer::new(settings)
                .map_err(|_| "xhttp transport path, ranges or mode are invalid")?;
            Ok(Arc::new(XhttpInbound { server, inner }))
        }
    }
}

/// A protocol inbound behind a WebSocket server handshake.
pub struct WsInbound {
    acceptor: WsAcceptor,
    inner: Arc<dyn StreamInbound>,
}

impl StreamInbound for WsInbound {
    fn protocol(&self) -> &'static str {
        self.inner.protocol()
    }

    fn users(&self) -> &Arc<UserStore> {
        self.inner.users()
    }

    fn accept<'a>(
        &'a self,
        stream: BoxStream,
        peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(async move {
            let stream = match self.acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(_) => return Err(Rejected::close("websocket handshake failed")),
            };
            self.inner.accept(stream, peer).await
        })
    }

    fn serves_connections(&self) -> bool {
        self.inner.serves_connections()
    }

    fn serve_connection<'a>(
        &'a self,
        stream: BoxStream,
        context: ConnectionContext<'a>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let handshake = tokio::time::timeout(
                context.settings.handshake_timeout,
                self.acceptor.accept(stream),
            );
            match handshake.await {
                Ok(Ok(stream)) => self.inner.serve_connection(stream, context).await,
                _ => context.handshake_failed(),
            }
        })
    }

    fn datagram(&self) -> Option<Arc<dyn DatagramInbound>> {
        self.inner.datagram()
    }
}

/// A protocol inbound behind an HTTPUpgrade handshake.
pub struct HttpUpgradeInbound {
    acceptor: HttpUpgradeAcceptor,
    inner: Arc<dyn StreamInbound>,
}

impl StreamInbound for HttpUpgradeInbound {
    fn protocol(&self) -> &'static str {
        self.inner.protocol()
    }

    fn users(&self) -> &Arc<UserStore> {
        self.inner.users()
    }

    fn accept<'a>(
        &'a self,
        stream: BoxStream,
        peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(async move {
            let stream = match self.acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(_) => return Err(Rejected::close("http upgrade handshake failed")),
            };
            self.inner.accept(stream, peer).await
        })
    }

    fn serves_connections(&self) -> bool {
        self.inner.serves_connections()
    }

    fn serve_connection<'a>(
        &'a self,
        stream: BoxStream,
        context: ConnectionContext<'a>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let handshake = tokio::time::timeout(
                context.settings.handshake_timeout,
                self.acceptor.accept(stream),
            );
            match handshake.await {
                Ok(Ok(stream)) => self.inner.serve_connection(stream, context).await,
                _ => context.handshake_failed(),
            }
        })
    }

    fn datagram(&self) -> Option<Arc<dyn DatagramInbound>> {
        self.inner.datagram()
    }
}

/// A protocol inbound behind gRPC: every call on a client connection is one
/// client stream for `inner`.
pub struct GrpcInbound {
    path: String,
    inner: Arc<dyn StreamInbound>,
}

impl StreamInbound for GrpcInbound {
    fn protocol(&self) -> &'static str {
        self.inner.protocol()
    }

    fn users(&self) -> &Arc<UserStore> {
        self.inner.users()
    }

    fn accept<'a>(
        &'a self,
        _stream: BoxStream,
        _peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        // The serve loop hands gRPC whole connections.
        Box::pin(async { Err(Rejected::close("grpc serves whole connections")) })
    }

    fn serves_connections(&self) -> bool {
        true
    }

    fn serve_connection<'a>(
        &'a self,
        stream: BoxStream,
        context: ConnectionContext<'a>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let inner = self.inner.as_ref();
            let served = transport_grpc::server::serve_connection(
                stream,
                &self.path,
                context.settings.handshake_timeout,
                move |call| Box::pin(context.handle(call, inner)),
            )
            .await;
            if served.is_err() {
                context.handshake_failed();
            }
        })
    }

    fn datagram(&self) -> Option<Arc<dyn DatagramInbound>> {
        self.inner.datagram()
    }
}

/// A protocol inbound behind XHTTP: every download (or `stream-one`
/// request) is one client stream for `inner`; uploads may come over other
/// connections.
pub struct XhttpInbound {
    server: Arc<XhttpServer>,
    inner: Arc<dyn StreamInbound>,
}

impl StreamInbound for XhttpInbound {
    fn protocol(&self) -> &'static str {
        self.inner.protocol()
    }

    fn users(&self) -> &Arc<UserStore> {
        self.inner.users()
    }

    fn accept<'a>(
        &'a self,
        _stream: BoxStream,
        _peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        // The serve loop hands XHTTP whole connections.
        Box::pin(async { Err(Rejected::close("xhttp serves whole connections")) })
    }

    fn serves_connections(&self) -> bool {
        true
    }

    fn serve_connection<'a>(
        &'a self,
        stream: BoxStream,
        context: ConnectionContext<'a>,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let inner = self.inner.as_ref();
            let served = self
                .server
                .serve_connection(stream, context.settings.handshake_timeout, move |call| {
                    Box::pin(context.handle(call, inner))
                })
                .await;
            if served.is_err() {
                context.handshake_failed();
            }
        })
    }

    fn datagram(&self) -> Option<Arc<dyn DatagramInbound>> {
        self.inner.datagram()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_parse_and_validate() {
        let ws: TransportSettings =
            serde_json::from_str(r#"{"type": "ws", "path": "/tunnel"}"#).unwrap();
        assert_eq!(
            ws,
            TransportSettings::Ws {
                path: "/tunnel".into(),
                host: String::new(),
                max_early_data: DEFAULT_MAX_EARLY_DATA,
                early_data_header_name: String::new(),
            }
        );
        let grpc: TransportSettings =
            serde_json::from_str(r#"{"type": "grpc", "service_name": "svc"}"#).unwrap();
        assert!(grpc.needs_h2());
        assert!(serde_json::from_str::<TransportSettings>(r#"{"type": "grpc"}"#).is_err());
        assert!(
            serde_json::from_str::<TransportSettings>(r#"{"type": "ws", "paht": "/"}"#).is_err()
        );
        assert!(serde_json::from_str::<TransportSettings>(r#"{"type": "h3"}"#).is_err());
        for name in ["httpupgrade", "http_upgrade"] {
            let upgrade: TransportSettings = serde_json::from_str(&format!(
                r#"{{"type": "{name}", "path": "/up", "host": "cdn.example"}}"#
            ))
            .unwrap();
            assert_eq!(
                upgrade,
                TransportSettings::Httpupgrade {
                    path: "/up".into(),
                    host: "cdn.example".into(),
                    max_early_data: DEFAULT_MAX_EARLY_DATA,
                    early_data_header_name: String::new(),
                }
            );
            assert!(upgrade.default_alpn().is_empty());
        }
        let xhttp: TransportSettings =
            serde_json::from_str(r#"{"type": "splithttp", "path": "/xh", "mode": "packet-up"}"#)
                .unwrap();
        assert_eq!(xhttp.default_alpn(), ["h2", "http/1.1"]);
        assert!(!xhttp.needs_h2());

        let bad = TransportSettings::Grpc {
            service_name: "a/b".into(),
        };
        let inner: Arc<dyn StreamInbound> = Arc::new(Nothing(Arc::new(UserStore::default())));
        assert!(wrap_transport(inner.clone(), Some(&bad)).is_err());
        let bad = TransportSettings::Ws {
            path: "no-slash".into(),
            host: String::new(),
            max_early_data: 0,
            early_data_header_name: String::new(),
        };
        assert!(wrap_transport(inner.clone(), Some(&bad)).is_err());
        assert!(wrap_transport(inner, Some(&TransportSettings::Tcp)).is_ok());
    }

    struct Nothing(Arc<UserStore>);

    impl StreamInbound for Nothing {
        fn protocol(&self) -> &'static str {
            "nothing"
        }

        fn users(&self) -> &Arc<UserStore> {
            &self.0
        }

        fn accept<'a>(
            &'a self,
            _stream: BoxStream,
            _peer: SocketAddr,
        ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
            Box::pin(async { Err(Rejected::close("nothing")) })
        }
    }
}
