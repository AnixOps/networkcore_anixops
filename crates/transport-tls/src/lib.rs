//! Standard TLS client transport for outbound protocols (Trojan, VMess/VLESS
//! over TLS, ...): rustls with the ring provider and Mozilla's WebPKI roots.
//!
//! Browser-shaped ClientHellos and REALITY live in `tls-mimic`; this crate is
//! the plain, verifying client. `insecure` turns certificate verification off
//! for servers with self-signed certificates, as share links allow with
//! `allowInsecure=1`, but still checks the handshake signatures.

use std::io;
use std::sync::Arc;

use engine_outbound::BoxStream;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// TLS settings of one outbound.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TlsSettings {
    /// SNI and the name the certificate must match.
    pub server_name: String,
    pub alpn: Vec<String>,
    /// Skip certificate verification.
    pub insecure: bool,
}

/// A configured client; cheap to clone and shared by every connection.
#[derive(Clone)]
pub struct TlsConnector {
    connector: tokio_rustls::TlsConnector,
    server_name: ServerName<'static>,
}

impl TlsConnector {
    pub fn new(settings: &TlsSettings) -> io::Result<Self> {
        let server_name = ServerName::try_from(settings.server_name.clone())
            .map_err(|_| invalid("tls server name is invalid"))?;
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
        Ok(Self {
            connector: tokio_rustls::TlsConnector::from(Arc::new(config)),
            server_name,
        })
    }

    /// Runs the handshake over `transport` and returns the encrypted stream.
    pub async fn connect(&self, transport: BoxStream) -> io::Result<BoxStream> {
        let stream = self
            .connector
            .connect(self.server_name.clone(), transport)
            .await?;
        Ok(Box::new(stream))
    }
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
