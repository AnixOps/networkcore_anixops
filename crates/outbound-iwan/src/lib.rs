//! Panabit iWAN client, written only from `docs/protocols/iwan.md`.
//!
//! iWAN is a UDP layer-3 tunnel: after an OPEN/OPENACK handshake each datagram
//! carries one IPv4 packet, optionally XOR-masked. The protocol layer does no
//! I/O:
//!
//! - [`packet`]: header, signature, TLVs and every packet type (spec §3, §4, §6).
//! - [`crypto`]: password block and XOR mask (spec §4.2, §6.2).
//! - [`frag`]: IPFRAG reassembly (spec §7).
//! - [`client`]: the session state machine and its timers (spec §5). The
//!   driver feeds it datagrams, TUN packets and one tick per second, and acts
//!   on the [`client::Output`]s it returns.
//! - [`config`]: the `"type": "iwan"` outbound settings (spec §11).
//! - [`IwanOutbound`]: the routable outbound (spec §11). Each node runs the
//!   session on its own UDP socket and a private userspace TCP/IP stack
//!   (smoltcp) whose address is the one from OPENACK; TCP connections and UDP
//!   flows open inside that stack, and domain targets resolve through the
//!   tunnel DNS. The platform's network settings are never touched.
//!
//! iWAN gives no confidentiality or authentication (spec §9): the XOR key is
//! 8 bytes reused on every packet and the signature has no key.

pub mod client;
pub mod config;
pub mod crypto;
pub mod dns;
pub mod frag;
mod node;
mod outbound;
pub mod packet;

pub use client::{Client, ClientConfig, Network, Output, State};
pub use config::{IwanConfig, IwanSettings};
pub use outbound::{IwanFactory, IwanOutbound};

/// Config `type` name of an iWAN outbound.
pub const TYPE_NAME: &str = "iwan";
