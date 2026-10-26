//! Mieru client outbound, written only from `docs/protocols/mieru.md`.
//!
//! TCP transport, one session per connection (no multiplexing). The UDP
//! transport, UDP associate, low entropy segments and custom traffic patterns
//! are not implemented.
//!
//! [`segment`] is direction-agnostic, so tests (and a later server inbound)
//! can speak the server side with the same code.
//!
//! [`MieruFactory`] registers the outbound under `"type": "mieru"`.

mod client;
pub mod crypto;
mod factory;
pub mod segment;

pub use client::{MieruOptions, MieruOutbound, PROTOCOL};
pub use factory::{MieruFactory, TYPE_NAME};
