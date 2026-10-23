//! Registry entry for `"type": "vless"` config entries: REALITY when
//! `reality` is set, otherwise plain TCP or standard TLS (`tls`), optionally
//! inside a WebSocket (`transport`).

use std::sync::Arc;

use engine_outbound::registry::{parse_settings, BuildError, OutboundFactory, Settings};
use engine_outbound::{Dialer, TcpOutbound};
use serde::Deserialize;
use tls_mimic::Fingerprint;
use transport_grpc::{GrpcConnector, GrpcSettings};
use transport_tls::{TlsConnector, TlsSettings};
use transport_ws::{WsConnector, WsSettings};

use crate::{
    parse_public_key, parse_short_id, parse_uuid, Flow, RealityConfig, VlessRealityConfig,
    VlessRealityOutbound, VlessTlsOutbound,
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
    #[serde(default)]
    reality: Option<RealitySettings>,
    /// Standard TLS; without `reality` and `tls` the connection is plain TCP.
    #[serde(default)]
    tls: Option<StandardTlsSettings>,
    /// `{"type": "ws", "path": ..., "host": ...}` or
    /// `{"type": "grpc", "service_name": ...}`; raw stream when absent.
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
    Grpc {
        /// Call path `/<service_name>/Tun`.
        #[serde(default)]
        service_name: String,
        /// `:authority`; defaults to the TLS server name or `server`.
        #[serde(default)]
        authority: String,
    },
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
        if settings.server.is_empty() || settings.port == 0 {
            return Err("vless server address is invalid");
        }
        let uuid = parse_uuid(&settings.uuid).map_err(|_| "vless uuid is invalid")?;
        let flow = Flow::from_name(&settings.flow).ok_or("unsupported vless flow")?;
        if let Some(reality) = &settings.reality {
            if settings.tls.is_some() {
                return Err("vless reality and tls cannot both be set");
            }
            if !matches!(settings.transport, None | Some(TransportSettings::Tcp)) {
                return Err("vless reality supports only the tcp transport");
            }
            let config = reality_config(&settings, reality, uuid, flow)?;
            return Ok(Arc::new(VlessRealityOutbound::new(config, dialer)));
        }
        if flow != Flow::None {
            return Err("xtls-rprx-vision needs reality in this build");
        }
        Ok(Arc::new(standard_outbound(settings, uuid, dialer)?))
    }
}

fn standard_outbound(
    settings: VlessSettings,
    uuid: [u8; 16],
    dialer: Arc<dyn Dialer>,
) -> Result<VlessTlsOutbound, BuildError> {
    let grpc_transport = matches!(settings.transport, Some(TransportSettings::Grpc { .. }));
    let tls = settings.tls.map(|tls| TlsSettings {
        server_name: tls
            .server_name
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| settings.server.clone()),
        // gRPC needs HTTP/2.
        alpn: if tls.alpn.is_empty() && grpc_transport {
            vec!["h2".to_owned()]
        } else {
            tls.alpn
        },
        insecure: tls.insecure,
    });
    let default_host = tls
        .as_ref()
        .map_or(settings.server.as_str(), |tls| tls.server_name.as_str());
    let mut grpc = None;
    let websocket = match settings.transport {
        None | Some(TransportSettings::Tcp) => None,
        Some(TransportSettings::Grpc {
            service_name,
            authority,
        }) => {
            grpc = Some(
                GrpcConnector::new(
                    &GrpcSettings {
                        service_name,
                        authority,
                    },
                    default_host,
                    tls.is_some(),
                )
                .map_err(|_| "vless grpc settings are invalid")?,
            );
            None
        }
        Some(TransportSettings::Ws { path, host }) => Some(
            WsConnector::new(
                &WsSettings {
                    path,
                    host,
                    headers: Vec::new(),
                },
                default_host,
            )
            .map_err(|_| "vless websocket settings are invalid")?,
        ),
    };
    let connector = tls
        .as_ref()
        .map(TlsConnector::new)
        .transpose()
        .map_err(|_| "vless tls settings are invalid")?;
    let mut outbound =
        VlessTlsOutbound::new(settings.server, settings.port, uuid, connector, dialer)
            .map_err(|_| "vless outbound settings are invalid")?;
    if let Some(websocket) = websocket {
        outbound = outbound.with_websocket(websocket);
    }
    if let Some(grpc) = grpc {
        outbound = outbound.with_grpc(grpc);
    }
    Ok(outbound)
}

fn reality_config(
    settings: &VlessSettings,
    reality: &RealitySettings,
    uuid: [u8; 16],
    flow: Flow,
) -> Result<VlessRealityConfig, BuildError> {
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
