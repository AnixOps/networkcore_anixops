//! WireGuard as a routable outbound.
//!
//! Each node runs one peer session (boringtun's Noise state machine) on its
//! own UDP socket and a private userspace TCP/IP stack (smoltcp) that holds
//! the interface addresses from `local_address`. TCP connections and UDP
//! flows open inside that stack, so a WireGuard node can sit in rules and
//! policy groups beside every other outbound; the platform's routes are never
//! touched. The whole-device WireGuard tunnel of `engine-embedded` is a
//! separate mode and does not use this crate.
//!
//! - [`config`]: the `"type": "wireguard"` settings.
//! - [`allowed`]: AllowedIPs, applied in both directions (cryptokey routing).
//! - [`dns`]: A/AAAA lookups through the tunnel's DNS servers.
//! - [`WireGuardOutbound`]: the outbound.

pub mod allowed;
pub mod config;
pub mod dns;
mod node;
mod outbound;

pub use allowed::{AllowedIps, IpNet};
pub use config::{decode_key, WireGuardConfig, WireGuardSettings};
pub use outbound::{WireGuardFactory, WireGuardOutbound};

/// Config `type` name of a WireGuard outbound.
pub const TYPE_NAME: &str = "wireguard";
