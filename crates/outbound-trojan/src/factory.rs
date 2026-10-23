//! Registry entry for `"type": "trojan"` config entries.

use std::sync::Arc;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{Dialer, TcpOutbound};
use serde::Deserialize;
use transport_tls::TlsSettings;

use crate::TrojanOutbound;

pub const TYPE_NAME: &str = "trojan";

/// Has no `Debug`: the password is the credential.
#[derive(Deserialize)]
struct TrojanSettings {
    server: String,
    port: u16,
    password: String,
    /// SNI; defaults to `server`.
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    alpn: Vec<String>,
    /// Skip certificate verification (`allowInsecure=1`).
    #[serde(default)]
    insecure: bool,
}

pub struct TrojanFactory;

impl OutboundFactory for TrojanFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(
        &self,
        settings: &Settings,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let settings: TrojanSettings =
            parse_settings(settings, "trojan settings are missing or invalid")?;
        let server_name = settings
            .server_name
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| settings.server.clone());
        let tls = TlsSettings {
            server_name,
            alpn: settings.alpn,
            insecure: settings.insecure,
        };
        let outbound = TrojanOutbound::new(
            settings.server,
            settings.port,
            &settings.password,
            &tls,
            dialer,
        )
        .map_err(|_| "trojan outbound settings are invalid")?;
        Ok(Arc::new(outbound))
    }
}
