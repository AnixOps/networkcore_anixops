//! Registry entry for `"type": "shadowsocks"` config entries.

use std::io;
use std::sync::Arc;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{Dialer, TcpOutbound};
use serde::Deserialize;

use crate::{AeadMethod, AeadOutbound, Method, Ss2022Outbound};

pub const TYPE_NAME: &str = "shadowsocks";

/// Has no `Debug`: the password is a key.
#[derive(Deserialize)]
struct ShadowsocksSettings {
    server: String,
    port: u16,
    method: String,
    password: String,
}

pub struct ShadowsocksFactory;

impl OutboundFactory for ShadowsocksFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(
        &self,
        settings: &Settings,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let settings: ShadowsocksSettings =
            parse_settings(settings, "shadowsocks settings are missing or invalid")?;
        let invalid = |err: io::Error| match err.kind() {
            io::ErrorKind::InvalidInput => "shadowsocks outbound settings are invalid",
            _ => "outbound could not be created",
        };
        // `2022-*` methods are SIP022; the rest are SIP004 AEAD methods.
        if settings.method.starts_with("2022-") {
            let method =
                Method::parse(&settings.method).map_err(|_| "unsupported shadowsocks method")?;
            let outbound = Ss2022Outbound::new(
                settings.server,
                settings.port,
                method,
                &settings.password,
                dialer,
            )
            .map_err(invalid)?;
            return Ok(Arc::new(outbound));
        }
        let method =
            AeadMethod::parse(&settings.method).map_err(|_| "unsupported shadowsocks method")?;
        let outbound = AeadOutbound::new(
            settings.server,
            settings.port,
            method,
            &settings.password,
            dialer,
        )
        .map_err(invalid)?;
        Ok(Arc::new(outbound))
    }
}
