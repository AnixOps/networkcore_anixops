//! Registry entry for `"type": "vless"` inbound config entries.

use std::sync::Arc;

use engine_inbound::registry::{parse_settings, BuildError, InboundFactory, Settings};
use engine_inbound::{FallbackSettings, StreamInbound, User};
use inbound_transport::TlsServerSettings;
use serde::Deserialize;

use crate::VlessInbound;

pub const TYPE_NAME: &str = "vless";

/// Has no `Debug`: users carry UUIDs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VlessInboundSettings {
    #[serde(default)]
    users: Vec<User>,
    #[serde(default)]
    tls: Option<TlsServerSettings>,
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
        let inbound = VlessInbound::new(settings.fallback.as_ref().map(FallbackSettings::target));
        inbound.users().add_all(settings.users)?;
        inbound_transport::wrap(Arc::new(inbound), settings.tls.as_ref())
    }
}
