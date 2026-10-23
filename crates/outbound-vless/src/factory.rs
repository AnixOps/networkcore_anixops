//! Registry entry for `"type": "vless"` config entries (VLESS over REALITY).

use std::sync::Arc;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{Dialer, TcpOutbound};
use serde::Deserialize;
use tls_mimic::Fingerprint;

use crate::{
    parse_public_key, parse_short_id, parse_uuid, Flow, RealityConfig, VlessRealityConfig,
    VlessRealityOutbound,
};

pub const TYPE_NAME: &str = "vless";

/// Has no `Debug`: the uuid is the credential.
#[derive(Deserialize)]
struct VlessSettings {
    server: String,
    port: u16,
    uuid: String,
    /// Empty for plain VLESS, or `xtls-rprx-vision`.
    #[serde(default)]
    flow: String,
    reality: RealitySettings,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RealitySettings {
    server_name: String,
    public_key: String,
    #[serde(default)]
    short_id: String,
    #[serde(default = "default_fingerprint")]
    fingerprint: String,
}

fn default_fingerprint() -> String {
    "chrome".to_owned()
}

pub struct VlessFactory;

impl OutboundFactory for VlessFactory {
    fn type_name(&self) -> &'static str {
        TYPE_NAME
    }

    fn build(
        &self,
        settings: &Settings,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let settings: VlessSettings =
            parse_settings(settings, "vless settings are missing or invalid")?;
        let config = vless_config(&settings)?;
        Ok(Arc::new(VlessRealityOutbound::new(config, dialer)))
    }
}

fn vless_config(settings: &VlessSettings) -> Result<VlessRealityConfig, BuildError> {
    if settings.server.is_empty() || settings.port == 0 {
        return Err("vless server address is invalid");
    }
    let uuid = parse_uuid(&settings.uuid).map_err(|_| "vless uuid is invalid")?;
    let flow = Flow::from_name(&settings.flow).ok_or("unsupported vless flow")?;
    let reality = &settings.reality;
    if reality.server_name.is_empty() {
        return Err("reality server_name is required");
    }
    let public_key =
        parse_public_key(&reality.public_key).map_err(|_| "reality public_key is invalid")?;
    let short_id = parse_short_id(&reality.short_id).map_err(|_| "reality short_id is invalid")?;
    let fingerprint =
        Fingerprint::from_name(&reality.fingerprint).ok_or("unsupported reality fingerprint")?;
    let mut reality_config = RealityConfig::new(reality.server_name.clone(), public_key, short_id);
    reality_config.fingerprint = fingerprint;
    Ok(VlessRealityConfig {
        server: settings.server.clone(),
        port: settings.port,
        uuid,
        flow,
        reality: reality_config,
    })
}
