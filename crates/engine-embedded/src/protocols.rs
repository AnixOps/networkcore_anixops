//! The protocols compiled into this build.
//!
//! Each protocol is a crate behind a cargo feature of the same name:
//!
//! | feature       | config `type`  | crate                  |
//! |---------------|----------------|------------------------|
//! | (always)      | `direct`       | this crate             |
//! | `http`        | `http`         | `outbound-http`        |
//! | `shadowsocks` | `shadowsocks`  | `outbound-shadowsocks` |
//! | `socks`       | `socks`        | `outbound-socks`       |
//! | `trojan`      | `trojan`       | `outbound-trojan`      |
//! | `vless`       | `vless`        | `outbound-vless`       |
//! | `vmess`       | `vmess`        | `outbound-vmess`       |
//! | `wireguard`   | `wireguard`    | this crate + boringtun |
//!
//! A new protocol adds its crate as an optional dependency, a feature, and one
//! `register` call below. A build without a feature rejects that `type` with
//! "outbound type is not supported by this build".

use std::sync::Arc;

use engine_outbound::registry::OutboundRegistry;

use crate::direct::DirectFactory;

/// Registry with every TCP outbound enabled by cargo features.
pub fn default_registry() -> OutboundRegistry {
    let mut registry = OutboundRegistry::new();
    registry.register(Arc::new(DirectFactory));
    #[cfg(feature = "http")]
    registry.register(Arc::new(outbound_http::HttpFactory));
    #[cfg(feature = "shadowsocks")]
    registry.register(Arc::new(outbound_shadowsocks::ShadowsocksFactory));
    #[cfg(feature = "socks")]
    registry.register(Arc::new(outbound_socks::SocksFactory));
    #[cfg(feature = "trojan")]
    registry.register(Arc::new(outbound_trojan::TrojanFactory));
    #[cfg(feature = "vless")]
    registry.register(Arc::new(outbound_vless::VlessFactory));
    #[cfg(feature = "vmess")]
    registry.register(Arc::new(outbound_vmess::VmessFactory));
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
