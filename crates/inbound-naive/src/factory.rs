//! Registry entry for `"type": "naive"` inbound config entries.

use std::sync::Arc;

use engine_inbound::registry::{parse_settings, BuildError, InboundFactory, Settings};
use engine_inbound::{FallbackSettings, StreamInbound, User};
use inbound_transport::TlsServerSettings;
use serde::Deserialize;

use crate::NaiveInbound;

pub const TYPE_NAME: &str = "naive";

/// Has no `Debug`: users carry passwords.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NaiveInboundSettings {
    #[serde(default)]
    users: Vec<User>,
    #[serde(default)]
    tls: Option<TlsServerSettings>,
    #[serde(default)]
    fallback: Option<FallbackSettings>,
}

pub struct NaiveInboundFactory;

impl InboundFactory for NaiveInboundFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(&self, settings: &Settings) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let mut settings: NaiveInboundSettings =
            parse_settings(settings, "naive inbound settings are missing or invalid")?;
        let inbound = NaiveInbound::new(settings.fallback.as_ref().map(FallbackSettings::target));
        inbound.users().add_all(settings.users)?;
        // Clients need HTTP/2; a web server offers HTTP/1.1 as well, and a
        // client that takes it goes to the fallback.
        if let Some(tls) = settings.tls.as_mut().filter(|tls| tls.alpn.is_empty()) {
            tls.alpn = vec!["h2".to_owned(), "http/1.1".to_owned()];
        }
        inbound_transport::wrap(Arc::new(inbound), settings.tls.as_ref())
    }
}
