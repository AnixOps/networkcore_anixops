//! Server-side transports that wrap a protocol inbound.
//!
//! [`TlsInbound`] terminates TLS (rustls, ring provider) and passes the
//! decrypted stream to the protocol. Certificates come from PEM files or
//! inline PEM. File-based certificates are reloaded when the files change, so
//! an ACME client (anix-agent renews with lego) can replace them without a
//! restart; a broken replacement keeps the previous certificate.
//!
//! Protocol factories parse a `"tls"` object into [`TlsServerSettings`] and
//! call [`wrap`].

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use engine_inbound::registry::BuildError;
use engine_inbound::{Accepted, Rejected, StreamInbound, UserStore};
use engine_outbound::{BoxFuture, BoxStream};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use serde::Deserialize;

/// How often certificate files are checked for changes.
const RELOAD_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// TLS settings of one inbound. Either the two paths or the two inline PEM
/// values must be set. Has no `Debug`: `key` is a private key.
#[derive(Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsServerSettings {
    #[serde(default)]
    pub certificate_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
    /// Inline PEM certificate chain.
    #[serde(default)]
    pub certificate: Option<String>,
    /// Inline PEM private key.
    #[serde(default)]
    pub key: Option<String>,
    #[serde(default)]
    pub alpn: Vec<String>,
}

/// Wraps `inner` in TLS when `tls` is set.
pub fn wrap(
    inner: Arc<dyn StreamInbound>,
    tls: Option<&TlsServerSettings>,
) -> Result<Arc<dyn StreamInbound>, BuildError> {
    match tls {
        Some(tls) => Ok(Arc::new(TlsInbound::new(inner, tls)?)),
        None => Ok(inner),
    }
}

/// A protocol inbound behind a TLS server handshake.
pub struct TlsInbound {
    acceptor: tokio_rustls::TlsAcceptor,
    inner: Arc<dyn StreamInbound>,
}

impl TlsInbound {
    pub fn new(
        inner: Arc<dyn StreamInbound>,
        settings: &TlsServerSettings,
    ) -> Result<Self, BuildError> {
        Ok(Self {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(server_config(settings)?)),
            inner,
        })
    }
}

impl StreamInbound for TlsInbound {
    fn protocol(&self) -> &'static str {
        self.inner.protocol()
    }

    fn users(&self) -> &Arc<UserStore> {
        self.inner.users()
    }

    fn accept<'a>(
        &'a self,
        stream: BoxStream,
        peer: SocketAddr,
    ) -> BoxFuture<'a, Result<Accepted, Rejected>> {
        Box::pin(async move {
            let tls = match self.acceptor.accept(stream).await {
                Ok(tls) => tls,
                Err(_) => return Err(Rejected::close("tls handshake failed")),
            };
            self.inner.accept(Box::new(tls), peer).await
        })
    }
}

/// The rustls server configuration for `settings`, for transports that run
/// TLS themselves, such as QUIC.
pub fn server_config(settings: &TlsServerSettings) -> Result<ServerConfig, BuildError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let resolver = CertResolver::new(settings, provider.clone())?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| "tls protocol versions are unavailable")?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = settings
        .alpn
        .iter()
        .map(|protocol| protocol.as_bytes().to_vec())
        .collect();
    Ok(config)
}

enum Source {
    Files { certificate: PathBuf, key: PathBuf },
    Inline,
}

struct Loaded {
    key: Arc<CertifiedKey>,
    modified: Option<(SystemTime, SystemTime)>,
    checked: Instant,
}

/// Serves one certificate; reloads it when its files change.
struct CertResolver {
    source: Source,
    provider: Arc<CryptoProvider>,
    loaded: Mutex<Loaded>,
}

impl fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CertResolver")
    }
}

impl CertResolver {
    fn new(
        settings: &TlsServerSettings,
        provider: Arc<CryptoProvider>,
    ) -> Result<Self, BuildError> {
        let (source, key, modified) = match settings {
            TlsServerSettings {
                certificate_path: Some(certificate),
                key_path: Some(key),
                certificate: None,
                key: None,
                ..
            } => {
                let modified = modified_times(certificate, key);
                let loaded = load_files(certificate, key, &provider)?;
                let source = Source::Files {
                    certificate: certificate.clone(),
                    key: key.clone(),
                };
                (source, loaded, modified)
            }
            TlsServerSettings {
                certificate_path: None,
                key_path: None,
                certificate: Some(certificate),
                key: Some(key),
                ..
            } => (
                Source::Inline,
                certified_key(certificate.as_bytes(), key.as_bytes(), &provider)?,
                None,
            ),
            _ => return Err("tls needs certificate_path and key_path, or certificate and key"),
        };
        Ok(Self {
            source,
            provider,
            loaded: Mutex::new(Loaded {
                key: Arc::new(key),
                modified,
                checked: Instant::now(),
            }),
        })
    }

    fn current(&self) -> Arc<CertifiedKey> {
        let mut loaded = self.loaded.lock().unwrap_or_else(|e| e.into_inner());
        if let Source::Files { certificate, key } = &self.source {
            if loaded.checked.elapsed() >= RELOAD_CHECK_INTERVAL {
                loaded.checked = Instant::now();
                let modified = modified_times(certificate, key);
                if modified.is_some() && modified != loaded.modified {
                    // A half-written or mismatched pair keeps the old
                    // certificate; the next check tries again.
                    if let Ok(fresh) = load_files(certificate, key, &self.provider) {
                        loaded.key = Arc::new(fresh);
                        loaded.modified = modified;
                    }
                }
            }
        }
        loaded.key.clone()
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}

fn modified_times(certificate: &Path, key: &Path) -> Option<(SystemTime, SystemTime)> {
    let modified = |path: &Path| std::fs::metadata(path).and_then(|meta| meta.modified());
    Some((modified(certificate).ok()?, modified(key).ok()?))
}

fn load_files(
    certificate: &Path,
    key: &Path,
    provider: &CryptoProvider,
) -> Result<CertifiedKey, BuildError> {
    let certificate =
        std::fs::read(certificate).map_err(|_| "tls certificate file could not be read")?;
    let key = std::fs::read(key).map_err(|_| "tls key file could not be read")?;
    certified_key(&certificate, &key, provider)
}

fn certified_key(
    certificate: &[u8],
    key: &[u8],
    provider: &CryptoProvider,
) -> Result<CertifiedKey, BuildError> {
    let chain = CertificateDer::pem_slice_iter(certificate)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "tls certificate is not valid PEM")?;
    if chain.is_empty() {
        return Err("tls certificate is empty");
    }
    let key = PrivateKeyDer::from_pem_slice(key).map_err(|_| "tls key is not valid PEM")?;
    CertifiedKey::from_der(chain, key, provider)
        .map_err(|_| "tls key does not match the certificate")
}
