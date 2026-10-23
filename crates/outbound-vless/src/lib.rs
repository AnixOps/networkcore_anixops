//! VLESS outbound with REALITY and XTLS Vision for the embedded engine.
//!
//! The outer connection is a browser-shaped TLS 1.3 handshake from
//! `tls-mimic`, authenticated with REALITY. VLESS runs inside it, optionally
//! with the `xtls-rprx-vision` flow. The outbound implements
//! [`engine_outbound::TcpOutbound`]; [`VlessFactory`] registers it under
//! `"type": "vless"`.

mod factory;
pub mod protocol;
pub mod reality;
mod stream;
pub mod vision;

use std::fmt;
use std::io;
use std::sync::Arc;

use engine_outbound::{BoxFuture, BoxStream, Dialer, TargetAddr, TcpOutbound};
use tls_mimic::ClientConfig;

pub use factory::{VlessFactory, TYPE_NAME};
pub use protocol::{parse_public_key, parse_short_id, parse_uuid, Flow, FLOW_VISION};
pub use reality::{RealityConfig, RealityHooks};
pub use stream::VlessStream;

/// VLESS + REALITY server parameters.
#[derive(Clone, PartialEq, Eq)]
pub struct VlessRealityConfig {
    pub server: String,
    pub port: u16,
    pub uuid: [u8; 16],
    pub flow: Flow,
    pub reality: RealityConfig,
}

impl fmt::Debug for VlessRealityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VlessRealityConfig")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("uuid", &"<redacted>")
            .field("flow", &self.flow)
            .field("reality", &self.reality)
            .finish()
    }
}

/// VLESS over REALITY.
pub struct VlessRealityOutbound {
    config: VlessRealityConfig,
    dialer: Arc<dyn Dialer>,
}

impl VlessRealityOutbound {
    pub fn new(config: VlessRealityConfig, dialer: Arc<dyn Dialer>) -> Self {
        Self { config, dialer }
    }

    pub fn config(&self) -> &VlessRealityConfig {
        &self.config
    }

    /// Connects and returns the concrete stream (for callers that want the
    /// Vision state); [`TcpOutbound::connect`] boxes the same stream.
    pub async fn connect_stream(&self, target: &TargetAddr) -> io::Result<VlessStream<BoxStream>> {
        let config = &self.config;
        let header = protocol::encode_request_header(&config.uuid, config.flow, target)?;
        let transport = self.dialer.dial(&config.server, config.port).await?;
        let tls_config = ClientConfig::new(
            config.reality.server_name.clone(),
            config.reality.fingerprint,
        );
        let mut hooks = RealityHooks::new(&config.reality);
        let tls = tls_mimic::connect(transport, &tls_config, &mut hooks)
            .await
            .map_err(|error| io::Error::new(error.kind(), format!("REALITY handshake: {error}")))?;
        let vision_uuid = (config.flow == Flow::Vision).then_some(config.uuid);
        Ok(VlessStream::new(tls, header, vision_uuid))
    }
}

impl TcpOutbound for VlessRealityOutbound {
    fn protocol(&self) -> &'static str {
        "vless"
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let stream = self.connect_stream(target).await?;
            Ok(Box::new(stream) as BoxStream)
        })
    }
}
