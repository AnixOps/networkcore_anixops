//! Registry entry for `"type": "hysteria2"` inbound config entries.

use std::sync::Arc;

use engine_inbound::registry::{parse_settings, BuildError, PacketInboundFactory, Settings};
use engine_inbound::{PacketInbound, User};
use inbound_transport::TlsServerSettings;
use serde::Deserialize;
use transport_quic::salamander::Salamander;

use crate::Hysteria2Inbound;

pub const TYPE_NAME: &str = "hysteria2";

/// Has no `Debug`: users carry passwords.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hysteria2InboundSettings {
    #[serde(default)]
    users: Vec<User>,
    tls: TlsServerSettings,
    #[serde(default)]
    obfs: Option<ObfsSettings>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObfsSettings {
    #[serde(rename = "type")]
    kind: String,
    password: String,
}

pub struct Hysteria2InboundFactory;

impl PacketInboundFactory for Hysteria2InboundFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(&self, settings: &Settings) -> Result<Arc<dyn PacketInbound>, BuildError> {
        let settings: Hysteria2InboundSettings = parse_settings(
            settings,
            "hysteria2 inbound settings are missing or invalid",
        )?;
        let salamander = match settings.obfs {
            None => None,
            Some(obfs) if obfs.kind == "salamander" => Some(
                Salamander::new(obfs.password).map_err(|_| "salamander password is too short")?,
            ),
            Some(_) => return Err("hysteria2 obfs type is not supported"),
        };
        let inbound = Hysteria2Inbound::new(&settings.tls, salamander)?;
        inbound.users().add_all(settings.users)?;
        Ok(Arc::new(inbound))
    }
}
