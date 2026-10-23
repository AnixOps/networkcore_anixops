//! Registry entry for `"type": "trojan"` config entries.

use std::sync::Arc;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{Dialer, TcpOutbound};
use serde::Deserialize;
use transport_tls::TlsSettings;
use transport_ws::{WsConnector, WsSettings};

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
    /// `{"type": "ws", "path": ..., "host": ...}`; plain TLS when absent.
    #[serde(default)]
    transport: Option<TransportSettings>,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum TransportSettings {
    Tcp,
    Ws {
        #[serde(default)]
        path: String,
        /// `Host` header; defaults to the TLS server name.
        #[serde(default)]
        host: String,
    },
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
        let websocket = match settings.transport {
            None | Some(TransportSettings::Tcp) => None,
            Some(TransportSettings::Ws { path, host }) => Some(
                WsConnector::new(
                    &WsSettings {
                        path,
                        host,
                        headers: Vec::new(),
                    },
                    &tls.server_name,
                )
                .map_err(|_| "trojan websocket settings are invalid")?,
            ),
        };
        let mut outbound = TrojanOutbound::new(
            settings.server,
            settings.port,
            &settings.password,
            &tls,
            dialer,
        )
        .map_err(|_| "trojan outbound settings are invalid")?;
        if let Some(websocket) = websocket {
            outbound = outbound.with_websocket(websocket);
        }
        Ok(Arc::new(outbound))
    }
}
