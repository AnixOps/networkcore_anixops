//! Registry entry for `"type": "hysteria2"` config entries.

use std::sync::Arc;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{Dialer, TcpOutbound};
use serde::Deserialize;
use transport_quic::salamander::Salamander;
use transport_tls::TlsSettings;

use crate::Hysteria2Outbound;

pub const TYPE_NAME: &str = "hysteria2";

/// Has no `Debug`: the password is the credential.
#[derive(Deserialize)]
struct Hysteria2Settings {
    server: String,
    port: u16,
    password: String,
    /// SNI; defaults to `server`.
    #[serde(default)]
    server_name: Option<String>,
    /// Defaults to `["h3"]`.
    #[serde(default)]
    alpn: Vec<String>,
    /// Skip certificate verification (`insecure=1`).
    #[serde(default)]
    insecure: bool,
    /// `{"type": "salamander", "password": ...}`; other types fail the build
    /// instead of connecting without obfuscation.
    #[serde(default)]
    obfs: Option<ObfsSettings>,
}

#[derive(Deserialize)]
struct ObfsSettings {
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    password: String,
}

pub struct Hysteria2Factory;

impl OutboundFactory for Hysteria2Factory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    /// The dialer is unused: Hysteria2 runs over its own UDP socket.
    fn build(
        &self,
        settings: &Settings,
        _dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let settings: Hysteria2Settings =
            parse_settings(settings, "hysteria2 settings are missing or invalid")?;
        let salamander = match settings.obfs {
            None => None,
            Some(obfs) if obfs.kind.is_empty() && obfs.password.is_empty() => None,
            Some(obfs) if obfs.kind.eq_ignore_ascii_case("salamander") => Some(
                Salamander::new(obfs.password)
                    .map_err(|_| "hysteria2 salamander password is too short")?,
            ),
            Some(_) => return Err("hysteria2 obfs types other than salamander are not supported"),
        };
        let server_name = settings
            .server_name
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| settings.server.clone());
        let tls = TlsSettings {
            server_name,
            alpn: settings.alpn,
            insecure: settings.insecure,
        };
        let mut outbound =
            Hysteria2Outbound::new(settings.server, settings.port, settings.password, &tls)
                .map_err(|_| "hysteria2 outbound settings are invalid")?;
        if let Some(salamander) = salamander {
            outbound = outbound
                .with_salamander(salamander)
                .map_err(|_| "hysteria2 obfs settings are invalid")?;
        }
        Ok(Arc::new(outbound))
    }
}
