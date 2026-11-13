//! Standard TLS client transport for outbound protocols (Trojan, VMess/VLESS
//! over TLS, ...): rustls with the ring provider and Mozilla's WebPKI roots.
//!
//! Browser-shaped ClientHellos and REALITY live in `tls-mimic`; this crate is
//! the plain, verifying client. `insecure` turns certificate verification off
//! for servers with self-signed certificates, as share links allow with
//! `allowInsecure=1`, but still checks the handshake signatures.
//!
//! Sessions resume: every configuration keeps tickets in a [`TicketStore`],
//! and a [`TlsConnector`] counts its handshakes and how many of them
//! resumed ([`TlsStats`]).

pub mod tickets;

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use engine_outbound::BoxStream;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::Resumption;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, HandshakeKind, RootCertStore, SignatureScheme};

pub use tickets::TicketStore;

/// TLS settings of one outbound.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsSettings {
    /// SNI and the name the certificate must match.
    pub server_name: String,
    pub alpn: Vec<String>,
    /// Skip certificate verification.
    pub insecure: bool,
}

/// Handshakes of a [`TlsConnector`].
#[derive(Debug, Default)]
pub struct TlsStats {
    pub handshakes: AtomicU64,
    /// Handshakes that resumed an earlier session.
    pub resumed: AtomicU64,
}

impl TlsStats {
    /// Share of handshakes that resumed, 0 to 1.
    pub fn resumption_rate(&self) -> f64 {
        let handshakes = self.handshakes.load(Ordering::Relaxed);
        if handshakes == 0 {
            return 0.0;
        }
        self.resumed.load(Ordering::Relaxed) as f64 / handshakes as f64
    }

    /// The counters as JSON, for an outbound's health.
    pub fn health_json(&self) -> serde_json::Value {
        serde_json::json!({
            "tls_handshakes": self.handshakes.load(Ordering::Relaxed),
            "tls_resumed": self.resumed.load(Ordering::Relaxed),
            "tls_resumption_rate": (self.resumption_rate() * 1000.0).round() / 1000.0,
        })
    }
}

/// A configured client; cheap to clone and shared by every connection.
#[derive(Clone)]
pub struct TlsConnector {
    connector: tokio_rustls::TlsConnector,
    server_name: ServerName<'static>,
    stats: Arc<TlsStats>,
}

impl TlsConnector {
    pub fn new(settings: &TlsSettings) -> io::Result<Self> {
        let server_name = ServerName::try_from(settings.server_name.clone())
            .map_err(|_| invalid("tls server name is invalid"))?;
        Ok(Self {
            connector: tokio_rustls::TlsConnector::from(Arc::new(client_config(settings)?)),
            server_name,
            stats: Arc::new(TlsStats::default()),
        })
    }

    /// Runs the handshake over `transport` and returns the encrypted stream.
    pub async fn connect(&self, transport: BoxStream) -> io::Result<BoxStream> {
        let stream = self
            .connector
            .connect(self.server_name.clone(), transport)
            .await?;
        self.stats.handshakes.fetch_add(1, Ordering::Relaxed);
        if stream.get_ref().1.handshake_kind() == Some(HandshakeKind::Resumed) {
            self.stats.resumed.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Box::new(stream))
    }

    /// Handshakes so far, shared by every clone.
    pub fn stats(&self) -> &Arc<TlsStats> {
        &self.stats
    }
}

/// The rustls client configuration for `settings` (roots or `insecure`, and
/// ALPN), for transports that run TLS themselves, such as QUIC.
pub fn client_config(settings: &TlsSettings) -> io::Result<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid("tls protocol versions are unavailable"))?;
    let mut config = if settings.insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification(provider)))
            .with_no_client_auth()
    } else {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = settings
        .alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    config.resumption = Resumption::store(Arc::new(TicketStore::new()));
    Ok(config)
}

/// Accepts any certificate but still verifies the handshake signature with
/// the key in it.
#[derive(Debug)]
struct NoCertificateVerification(Arc<CryptoProvider>);

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
