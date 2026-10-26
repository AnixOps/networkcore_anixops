//! Registry entry for `"type": "vmess"` inbound config entries.

use std::sync::Arc;

use engine_inbound::registry::{parse_settings, BuildError, InboundFactory, Settings};
use engine_inbound::{StreamInbound, User};
use inbound_transport::{TlsServerSettings, TransportSettings};
use serde::Deserialize;

use crate::VmessInbound;

pub const TYPE_NAME: &str = "vmess";

/// Has no `Debug`: users carry UUIDs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VmessInboundSettings {
    #[serde(default)]
    users: Vec<User>,
    #[serde(default)]
    tls: Option<TlsServerSettings>,
    /// `{"type": "ws", ...}` or `{"type": "grpc", ...}` between TLS and
    /// the protocol.
    #[serde(default)]
    transport: Option<TransportSettings>,
}

pub struct VmessInboundFactory;

impl InboundFactory for VmessInboundFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(&self, settings: &Settings) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let settings: VmessInboundSettings =
            parse_settings(settings, "vmess inbound settings are missing or invalid")?;
        let inbound = VmessInbound::new();
        inbound.users().add_all(settings.users)?;
        inbound_transport::wrap_all(
            Arc::new(inbound),
            settings.transport.as_ref(),
            settings.tls.as_ref(),
        )
    }
}
