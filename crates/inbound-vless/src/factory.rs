//! Registry entry for `"type": "vless"` inbound config entries.

use std::sync::Arc;

use engine_inbound::registry::{parse_settings, BuildError, InboundFactory, Settings};
use engine_inbound::{FallbackSettings, StreamInbound, User};
use inbound_transport::{TlsServerSettings, TransportSettings};
use serde::Deserialize;

use crate::{RealityInbound, RealitySettings, VlessInbound};

pub const TYPE_NAME: &str = "vless";

/// Has no `Debug`: users carry UUIDs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VlessInboundSettings {
    #[serde(default)]
    users: Vec<User>,
    #[serde(default)]
    tls: Option<TlsServerSettings>,
    /// `{"type": "ws", ...}`, `{"type": "grpc", ...}` or
    /// `{"type": "xhttp", ...}` between TLS and the protocol; with REALITY
    /// only `xhttp`.
    #[serde(default)]
    transport: Option<TransportSettings>,
    #[serde(default)]
    reality: Option<RealitySettings>,
    #[serde(default)]
    fallback: Option<FallbackSettings>,
}

pub struct VlessInboundFactory;

impl InboundFactory for VlessInboundFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(&self, settings: &Settings) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let settings: VlessInboundSettings =
            parse_settings(settings, "vless inbound settings are missing or invalid")?;
        let transport = settings
            .transport
            .as_ref()
            .filter(|transport| **transport != TransportSettings::Tcp);
        // Vision needs the raw connection, so it comes with raw REALITY only.
        let inbound = VlessInbound::with_vision(
            settings.fallback.as_ref().map(FallbackSettings::target),
            settings.reality.is_some() && transport.is_none(),
        );
        inbound.users().add_all(settings.users)?;
        match (&settings.tls, &settings.reality, transport) {
            (Some(_), Some(_), _) => Err("vless inbound takes tls or reality, not both"),
            (None, Some(reality), None) => {
                Ok(Arc::new(RealityInbound::new(Arc::new(inbound), reality)?))
            }
            (None, Some(reality), Some(transport @ TransportSettings::Xhttp(_))) => {
                let inbound = Arc::new(inbound);
                let served = inbound_transport::wrap_transport(inbound.clone(), Some(transport))?;
                Ok(Arc::new(
                    RealityInbound::new(inbound, reality)?.with_transport(served),
                ))
            }
            (_, Some(_), Some(_)) => Err("vless reality inbound takes only the xhttp transport"),
            (tls, None, transport) => {
                inbound_transport::wrap_all(Arc::new(inbound), transport, tls.as_ref())
            }
        }
    }
}
