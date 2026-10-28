//! Registry entry for `"type": "anytls"` inbound config entries.

use std::sync::Arc;

use engine_inbound::registry::{parse_settings, BuildError, InboundFactory, Settings};
use engine_inbound::{FallbackSettings, StreamInbound, User};
use inbound_transport::TlsServerSettings;
use serde::Deserialize;

use crate::{AnyTlsInbound, PaddingScheme};

pub const TYPE_NAME: &str = "anytls";

/// Has no `Debug`: users carry passwords.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnyTlsInboundSettings {
    #[serde(default)]
    users: Vec<User>,
    #[serde(default)]
    tls: Option<TlsServerSettings>,
    /// Lines of the padding scheme; the clients' default when absent.
    #[serde(default)]
    padding_scheme: Option<Vec<String>>,
    #[serde(default)]
    fallback: Option<FallbackSettings>,
}

pub struct AnyTlsInboundFactory;

impl InboundFactory for AnyTlsInboundFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(&self, settings: &Settings) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let settings: AnyTlsInboundSettings =
            parse_settings(settings, "anytls inbound settings are missing or invalid")?;
        let padding = match &settings.padding_scheme {
            Some(lines) => PaddingScheme::new(lines)?,
            None => PaddingScheme::default(),
        };
        let inbound = AnyTlsInbound::new(
            padding,
            settings.fallback.as_ref().map(FallbackSettings::target),
        );
        inbound.users().add_all(settings.users)?;
        inbound_transport::wrap_all(Arc::new(inbound), None, settings.tls.as_ref())
    }
}
