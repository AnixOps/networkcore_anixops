//! Registry entry for `"type": "vmess"` config entries.

use std::sync::Arc;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{Dialer, TcpOutbound};
use serde::Deserialize;
use transport_tls::{TlsConnector, TlsSettings};
use transport_ws::{WsConnector, WsSettings};

use crate::{Security, VmessOutbound};

pub const TYPE_NAME: &str = "vmess";

/// Has no `Debug`: the uuid is the credential.
#[derive(Deserialize)]
struct VmessSettings {
    server: String,
    port: u16,
    uuid: String,
    /// `auto`, `aes-128-gcm` or `chacha20-poly1305`.
    #[serde(default)]
    security: String,
    /// Only 0 (AEAD headers) is supported; legacy MD5 headers are rejected.
    #[serde(default)]
    alter_id: u16,
    #[serde(default)]
    tls: Option<StandardTlsSettings>,
    /// `{"type": "ws", "path": ..., "host": ...}`; raw stream when absent.
    #[serde(default)]
    transport: Option<TransportSettings>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StandardTlsSettings {
    /// SNI; defaults to `server`.
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    alpn: Vec<String>,
    #[serde(default)]
    insecure: bool,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum TransportSettings {
    Tcp,
    Ws {
        #[serde(default)]
        path: String,
        /// `Host` header; defaults to the TLS server name or `server`.
        #[serde(default)]
        host: String,
    },
}

pub struct VmessFactory;

impl OutboundFactory for VmessFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(
        &self,
        settings: &Settings,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let settings: VmessSettings =
            parse_settings(settings, "vmess settings are missing or invalid")?;
        if settings.alter_id != 0 {
            return Err("vmess alter_id other than 0 (legacy headers) is not supported");
        }
        let uuid = parse_uuid(&settings.uuid).ok_or("vmess uuid is invalid")?;
        let security =
            Security::from_name(&settings.security).ok_or("unsupported vmess security")?;
        let tls = settings.tls.map(|tls| TlsSettings {
            server_name: tls
                .server_name
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| settings.server.clone()),
            alpn: tls.alpn,
            insecure: tls.insecure,
        });
        let default_host = tls
            .as_ref()
            .map_or(settings.server.as_str(), |tls| tls.server_name.as_str());
        let websocket = match settings.transport {
            None | Some(TransportSettings::Tcp) => None,
            Some(TransportSettings::Ws { path, host }) => Some(
                WsConnector::new(
                    &WsSettings {
                        path,
                        host,
                        headers: Vec::new(),
                    },
                    default_host,
                )
                .map_err(|_| "vmess websocket settings are invalid")?,
            ),
        };
        let connector = tls
            .as_ref()
            .map(TlsConnector::new)
            .transpose()
            .map_err(|_| "vmess tls settings are invalid")?;
        let mut outbound = VmessOutbound::new(
            settings.server,
            settings.port,
            uuid,
            security,
            connector,
            dialer,
        )
        .map_err(|_| "vmess outbound settings are invalid")?;
        if let Some(websocket) = websocket {
            outbound = outbound.with_websocket(websocket);
        }
        Ok(Arc::new(outbound))
    }
}

/// Hyphenated or plain 32-digit hex UUID.
pub fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let hex: Vec<u8> = text.bytes().filter(|byte| *byte != b'-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in hex.chunks(2).enumerate() {
        let text = std::str::from_utf8(pair).ok()?;
        out[i] = u8::from_str_radix(text, 16).ok()?;
    }
    Some(out)
}
