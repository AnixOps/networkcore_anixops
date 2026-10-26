//! Snell client outbound, written only from `docs/protocols/snell.md`.
//!
//! Supports protocol versions 1–4 and 6 (5 runs as 4; its QUIC proxy mode
//! is not implemented), v6 modes `default`, `unshaped` and `unsafe-raw`,
//! `obfs = http` for v1–v4, connection reuse and UDP over TCP (v3+).
//!
//! [`codec`] and [`request`] are direction-agnostic, so a server inbound can
//! reuse the same framing, shaping and request parsing.
//!
//! [`SnellFactory`] registers the outbound under `"type": "snell"`.

mod client;
pub mod codec;
mod crypto;
mod factory;
pub mod obfs;
mod profile;
pub mod request;

pub use client::{
    HttpObfsSettings, SnellOptions, SnellOutbound, SnellStream, SnellUdpReceiver, SnellUdpSender,
    PROTOCOL,
};
pub use codec::{Decoder, Encoder, Frame, Framing, V6Mode};
pub use crypto::CipherKind;
pub use factory::{SnellFactory, TYPE_NAME};
pub use profile::Profile;
