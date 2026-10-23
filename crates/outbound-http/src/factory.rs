//! Registry entry for `"type": "http"` config entries.

use std::sync::Arc;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{Dialer, TcpOutbound};
use serde::Deserialize;
use transport_tls::TlsSettings;

use crate::{HttpCredentials, HttpOutbound};

pub const TYPE_NAME: &str = "http";

/// Has no `Debug`: the password is the credential.
#[derive(Deserialize)]
struct HttpSettings {
    server: String,
    port: u16,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    /// HTTPS proxy: talk to the proxy over TLS.
    #[serde(default)]
    tls: bool,
    /// SNI for `tls`; defaults to `server`.
    #[serde(default)]
    server_name: Option<String>,
    /// Skip certificate verification for `tls`.
    #[serde(default)]
    insecure: bool,
}

pub struct HttpFactory;

impl OutboundFactory for HttpFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(
        &self,
        settings: &Settings,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let settings: HttpSettings =
            parse_settings(settings, "http proxy settings are missing or invalid")?;
        let credentials = match (settings.username, settings.password) {
            (None, None) => None,
            (Some(username), password) => Some(HttpCredentials {
                username,
                password: password.unwrap_or_default(),
            }),
            (None, Some(_)) => return Err("http proxy password is set without a username"),
        };
        let tls = settings.tls.then(|| TlsSettings {
            server_name: settings
                .server_name
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| settings.server.clone()),
            alpn: Vec::new(),
            insecure: settings.insecure,
        });
        let outbound = HttpOutbound::new(
            settings.server,
            settings.port,
            credentials,
            tls.as_ref(),
            dialer,
        )
        .map_err(|_| "http proxy outbound settings are invalid")?;
        Ok(Arc::new(outbound))
    }
}
