//! Registry entry for `"type": "socks"` config entries.

use std::sync::Arc;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{Dialer, TcpOutbound};
use serde::Deserialize;

use crate::{SocksCredentials, SocksOutbound};

pub const TYPE_NAME: &str = "socks";

/// Has no `Debug`: the password is the credential.
#[derive(Deserialize)]
struct SocksSettings {
    server: String,
    port: u16,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

pub struct SocksFactory;

impl OutboundFactory for SocksFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(
        &self,
        settings: &Settings,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let settings: SocksSettings =
            parse_settings(settings, "socks settings are missing or invalid")?;
        let credentials = match (settings.username, settings.password) {
            (None, None) => None,
            (Some(username), Some(password)) => Some(SocksCredentials { username, password }),
            _ => return Err("socks username and password must be set together"),
        };
        let outbound = SocksOutbound::new(settings.server, settings.port, credentials, dialer)
            .map_err(|_| "socks outbound settings are invalid")?;
        Ok(Arc::new(outbound))
    }
}
