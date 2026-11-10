//! Browser-shaped TLS for censorship-resistant outbounds.
//!
//! `tls-mimic` builds ClientHello messages that match a real browser's
//! fingerprint (cipher suites, extension set and order, GREASE, key shares,
//! ECH GREASE) and runs a small TLS 1.3 client on top of them. The
//! fingerprints are data ([`profile`]): Chrome and Safari ship built in and a
//! delivered bundle can replace them at run time ([`install_profiles`]). Unlike general
//! TLS libraries it lets the caller edit the ClientHello and decide trust
//! through [`HandshakeHooks`], which is what REALITY and similar protocols
//! need. It deliberately supports only TLS 1.3: full handshakes and
//! resumption with a session ticket (`psk_dhe_ke`); no TLS 1.2, no 0-RTT and
//! no client certificates. [`server`] has the matching minimal server for
//! REALITY-style inbounds.

pub mod cert;
pub mod crypto;
pub mod fingerprint;
mod handshake;
pub mod profile;
pub mod server;
mod stream;

use std::io;

pub use crypto::{CipherSuite, HashAlg};
pub use fingerprint::{
    build_client_hello, clear_profiles, install_profiles, installed_profiles, ClientHello,
    ClientHelloSpec, Fingerprint, InstalledProfiles, SESSION_ID_OFFSET,
};
pub use handshake::{
    connect, connect_resuming, ClientConfig, HandshakeHooks, HelloContext, SessionTicket,
};
pub use stream::TlsStream;

pub(crate) fn alert_error(description: u8) -> io::Error {
    let kind = match description {
        40 | 42..=46 | 48 | 51 | 116 => io::ErrorKind::PermissionDenied,
        _ => io::ErrorKind::ConnectionAborted,
    };
    io::Error::new(kind, format!("TLS alert {description} from peer"))
}
