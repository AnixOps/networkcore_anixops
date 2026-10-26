//! Registry entry for `"type": "tuic"` inbound config entries.

use std::sync::Arc;

use engine_inbound::registry::{parse_settings, BuildError, PacketInboundFactory, Settings};
use engine_inbound::{PacketInbound, User};
use inbound_transport::TlsServerSettings;
use serde::Deserialize;
use transport_quic::Congestion;

use crate::TuicInbound;

pub const TYPE_NAME: &str = "tuic";

/// Has no `Debug`: users carry passwords.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TuicInboundSettings {
    #[serde(default)]
    users: Vec<User>,
    tls: TlsServerSettings,
    /// `cubic` (default), `new_reno` or `bbr`.
    #[serde(default)]
    congestion_control: Option<String>,
}

pub struct TuicInboundFactory;

impl PacketInboundFactory for TuicInboundFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(&self, settings: &Settings) -> Result<Arc<dyn PacketInbound>, BuildError> {
        let settings: TuicInboundSettings =
            parse_settings(settings, "tuic inbound settings are missing or invalid")?;
        let congestion = match settings.congestion_control.as_deref() {
            None => Congestion::default(),
            Some(name) => {
                Congestion::from_name(name).ok_or("tuic congestion control is unknown")?
            }
        };
        let inbound = TuicInbound::new(&settings.tls, congestion)?;
        inbound.users().add_all(settings.users)?;
        Ok(Arc::new(inbound))
    }
}
