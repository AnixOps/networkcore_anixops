//! Registry entry for `"type": "tuic"` config entries.

use std::sync::Arc;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{Dialer, TcpOutbound};
use serde::Deserialize;
use transport_quic::Congestion;
use transport_tls::TlsSettings;

use crate::TuicOutbound;

pub const TYPE_NAME: &str = "tuic";

/// Has no `Debug`: the UUID and password are the credentials.
#[derive(Deserialize)]
struct TuicSettings {
    server: String,
    port: u16,
    uuid: String,
    password: String,
    /// SNI; defaults to `server`.
    #[serde(default)]
    server_name: Option<String>,
    /// Defaults to `["h3"]`.
    #[serde(default)]
    alpn: Vec<String>,
    /// Skip certificate verification (`allowInsecure=1`).
    #[serde(default)]
    insecure: bool,
    /// `cubic` (default), `new_reno` or `bbr`.
    #[serde(default)]
    congestion_control: Option<String>,
}

pub struct TuicFactory;

impl OutboundFactory for TuicFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    /// QUIC runs over its own UDP socket, which a `via` cannot carry yet.
    fn supports_via(&self) -> bool {
        false
    }

    /// The dialer is unused: TUIC runs over its own UDP socket.
    fn build(
        &self,
        settings: &Settings,
        _dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let settings: TuicSettings =
            parse_settings(settings, "tuic settings are missing or invalid")?;
        let uuid = parse_uuid(&settings.uuid).ok_or("tuic uuid is invalid")?;
        let congestion = match settings.congestion_control.as_deref() {
            None | Some("") => Congestion::Cubic,
            Some(name) => {
                Congestion::from_name(name).ok_or("tuic congestion control is unknown")?
            }
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
        let outbound = TuicOutbound::new(
            settings.server,
            settings.port,
            uuid,
            settings.password,
            &tls,
            congestion,
        )
        .map_err(|_| "tuic outbound settings are invalid")?;
        Ok(Arc::new(outbound))
    }
}

/// Parses a hyphenated or plain 32-digit hex UUID.
pub fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let hex: Vec<u8> = text.bytes().filter(|byte| *byte != b'-').collect();
    if hex.len() != 32 || !hex.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let nibble = |digit: u8| char::from(digit).to_digit(16).map(|value| value as u8);
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (nibble(hex[2 * i])? << 4) | nibble(hex[2 * i + 1])?;
    }
    Some(out)
}
