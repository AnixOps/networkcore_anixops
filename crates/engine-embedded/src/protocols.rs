//! The protocols compiled into this build.
//!
//! Each protocol is a crate behind a cargo feature of the same name:
//!
//! | feature       | config `type`  | crate                  |
//! |---------------|----------------|------------------------|
//! | (always)      | `direct`       | this crate             |
//! | `http`        | `http`         | `outbound-http`        |
//! | `hysteria2`   | `hysteria2`    | `outbound-hysteria2`   |
//! | `iwan`        | `iwan`         | `outbound-iwan`        |
//! | `mieru`       | `mieru`        | `outbound-mieru`       |
//! | `shadowsocks` | `shadowsocks`  | `outbound-shadowsocks` |
//! | `snell`       | `snell`        | `outbound-snell`       |
//! | `socks`       | `socks`        | `outbound-socks`       |
//! | `trojan`      | `trojan`       | `outbound-trojan`      |
//! | `tuic`        | `tuic`         | `outbound-tuic`        |
//! | `vless`       | `vless`        | `outbound-vless`       |
//! | `vmess`       | `vmess`        | `outbound-vmess`       |
//! | `wireguard`   | `wireguard`    | this crate + boringtun |
//!
//! A new protocol adds its crate as an optional dependency, a feature, and one
//! `register` call below. A build without a feature rejects that `type` with
//! "outbound type is not supported by this build".
//!
//! A protocol crate that lives outside this repository joins every registry
//! this crate builds through [`register_extra_outbound`], so a downstream
//! build can link this library unchanged and add its own outbounds.

use std::sync::{Arc, RwLock};

use engine_outbound::registry::{OutboundFactory, OutboundRegistry};

use crate::direct::DirectFactory;

/// Factories added with [`register_extra_outbound`], in registration order.
static EXTRA_OUTBOUNDS: RwLock<Vec<Arc<dyn OutboundFactory>>> = RwLock::new(Vec::new());

/// Adds an outbound factory from outside this crate to every registry it
/// builds: the C ABI runtimes, node import support checks, delay tests and
/// the desktop local proxy. A factory for a type that is already registered
/// (a feature protocol or an earlier extra) replaces it. Call it before the
/// first runtime is created; runtimes already built keep their outbounds.
pub fn register_extra_outbound(factory: Arc<dyn OutboundFactory>) {
    let mut extras = EXTRA_OUTBOUNDS
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let name = factory.type_name();
    extras.retain(|extra| extra.type_name() != name);
    extras.push(factory);
}

/// Registry with every TCP outbound enabled by cargo features, plus the ones
/// added with [`register_extra_outbound`].
pub fn default_registry() -> OutboundRegistry {
    let mut registry = OutboundRegistry::new();
    registry.register(Arc::new(DirectFactory));
    #[cfg(feature = "http")]
    registry.register(Arc::new(outbound_http::HttpFactory));
    #[cfg(feature = "hysteria2")]
    registry.register(Arc::new(outbound_hysteria2::Hysteria2Factory));
    #[cfg(feature = "iwan")]
    registry.register(Arc::new(outbound_iwan::IwanFactory));
    #[cfg(feature = "mieru")]
    registry.register(Arc::new(outbound_mieru::MieruFactory));
    #[cfg(feature = "shadowsocks")]
    registry.register(Arc::new(outbound_shadowsocks::ShadowsocksFactory));
    #[cfg(feature = "snell")]
    registry.register(Arc::new(outbound_snell::SnellFactory));
    #[cfg(feature = "socks")]
    registry.register(Arc::new(outbound_socks::SocksFactory));
    #[cfg(feature = "trojan")]
    registry.register(Arc::new(outbound_trojan::TrojanFactory));
    #[cfg(feature = "tuic")]
    registry.register(Arc::new(outbound_tuic::TuicFactory));
    #[cfg(feature = "vless")]
    registry.register(Arc::new(outbound_vless::VlessFactory));
    #[cfg(feature = "vmess")]
    registry.register(Arc::new(outbound_vmess::VmessFactory));
    let extras = EXTRA_OUTBOUNDS
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for factory in extras.iter() {
        registry.register(factory.clone());
    }
    registry
}

/// Every config `type` this build accepts, including packet tunnels.
pub fn supported_types() -> Vec<&'static str> {
    let registry = default_registry();
    #[allow(unused_mut)]
    let mut types: Vec<&'static str> = registry.type_names().collect();
    #[cfg(feature = "wireguard")]
    types.push(crate::wireguard::TYPE_NAME);
    types.sort_unstable();
    types
}
