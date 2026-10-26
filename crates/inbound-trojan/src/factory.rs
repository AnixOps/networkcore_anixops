//! Registry entry for `"type": "trojan"` inbound config entries.

use std::sync::Arc;

use engine_inbound::registry::{parse_settings, BuildError, InboundFactory, Settings};
use engine_inbound::{FallbackSettings, StreamInbound, User};
use inbound_transport::TlsServerSettings;
use serde::Deserialize;

use crate::TrojanInbound;

pub const TYPE_NAME: &str = "trojan";

/// Has no `Debug`: users carry passwords.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrojanInboundSettings {
    #[serde(default)]
    users: Vec<User>,
    #[serde(default)]
    tls: Option<TlsServerSettings>,
    #[serde(default)]
    fallback: Option<FallbackSettings>,
}

pub struct TrojanInboundFactory;

impl InboundFactory for TrojanInboundFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(&self, settings: &Settings) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let settings: TrojanInboundSettings =
            parse_settings(settings, "trojan inbound settings are missing or invalid")?;
        let inbound = TrojanInbound::new(settings.fallback.as_ref().map(FallbackSettings::target));
        inbound.users().add_all(settings.users)?;
        inbound_transport::wrap(Arc::new(inbound), settings.tls.as_ref())
    }
}
