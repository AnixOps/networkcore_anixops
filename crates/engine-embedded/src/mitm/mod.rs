//! HTTPS decryption (MITM) for the packet tunnel, feature `mitm`.
//!
//! The policy text and Loon plugins in the config are imported and merged
//! into one `mitm_anixops` policy; a plugin the policy core refuses is left
//! out. A TCP flow to port 443 whose ClientHello names a host on the merged
//! `[MITM] hostname` list is terminated here with a leaf certificate issued
//! from the device's root (generated and trusted on the Swift side), relayed
//! to the origin over a verifying TLS client, and its HTTP/1.1 messages pass
//! through the same `mitm-policy` / `engine-native` rewrite hook the desktop
//! engines use: URL reject and redirect, header and body rewrites, Map Local.
//!
//! Limits that keep the extension inside its memory budget: bodies above
//! [`MAX_BODY_BYTES`], `text/event-stream` responses and protocol upgrades
//! stop rewriting for the rest of the connection and are relayed as they
//! are. Intercepted requests ask for `Accept-Encoding: identity`, so body
//! rules see plain text. Only HTTP/1.1 is offered to the client.
//!
//! Remote `[Map Local]` bodies (and Quantumult X `echo-response` files) are
//! downloaded by the app and named in `resource_assets`; they are read once
//! here and inlined into the plugin before it is imported.
//!
//! With the `scripts` feature, `[Script]` dispatches run in QuickJS from the
//! consented local copies in `script_assets`, on the blocking pool so a
//! script never stalls the tunnel's single-threaded runtime. Each dispatch
//! gets [`SCRIPT_MEMORY_LIMIT_BYTES`] of heap and at most
//! [`SCRIPT_MAX_TIMEOUT_MS`]. `$httpClient` requests go through the tunnel's
//! dispatcher (see `FlowInterceptor::set_script_outbound`), one HTTP/1.1 request
//! per connection with a [`MAX_BODY_BYTES`] answer.
//!
//! Plugin scripts outside HTTP flows (`cron`, `network-changed`, `generic`,
//! Quantumult X `[task_local]`) run from the same consented copies on the
//! tunnel's runtime (see `scheduler`): cron scripts in local time, the others
//! when the client sends the `network_changed` or `run_script` control
//! command. What any script posts with `$notification` waits for the
//! client's `script_notifications` command.

mod http1;
#[cfg(feature = "scripts")]
mod http_client;
pub mod inspect;
#[cfg(feature = "scripts")]
mod scheduler;

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use control_domain::{
    GrantedPermissions, HookPoint, HttpMitmPhase, MetadataEntry, MitmHostnameDecision,
    MitmPluginService, PluginInstance, PluginManifest, PluginPackage, PluginPermission,
};
use engine_native::{
    NativeHttpMitmPluginHook, NativePlainHttpMessage, NativePlainHttpRewriteReport,
};
#[cfg(feature = "scripts")]
use engine_native::{NativeQuickJsScriptExecutor, NativeQuickJsScriptRuntimeConfig};
use engine_outbound::{BoxFuture, TargetAddr, TcpOutbound};
use mitm_policy::loon_map_local::MAP_LOCAL_REMOTE_DATA_MAX_BYTES;
use mitm_policy::loon_plugin::{import_loon_plugin_with_resources, merged_plugin_source};
use mitm_policy::AnixOpsMitmPluginService;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use self::http1::{Body, Conn, Framing, Head};
use crate::config::MitmConfig;
use crate::tunnel::{FlowInterceptor, InterceptedFlow, TunnelSettings, TunnelStats};

pub const PLUGIN_ID: &str = "networkcore.ios.mitm";
/// Largest request or response body the rewrite hook sees.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_POLICY_BYTES: usize = 512 * 1024;
/// QuickJS heap per script dispatch; the extension's whole budget is ~50 MB.
pub const SCRIPT_MEMORY_LIMIT_BYTES: usize = 8 * 1024 * 1024;
/// Upper bound for a script's own `timeout`.
pub const SCRIPT_MAX_TIMEOUT_MS: usize = 3_000;
const LEAF_CACHE_ENTRIES: usize = 64;
const DECISION_CACHE_ENTRIES: usize = 512;
const HTTPS_PORT: u16 = 443;
const HTTP_PORT: u16 = 80;
/// Request methods of a plain HTTP flow that is taken over. `CONNECT` and
/// unknown methods keep their own path.
const PLAIN_HTTP_METHODS: [&str; 8] = [
    "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "TRACE ",
];

/// Largest total of downloaded `[Map Local]` bodies read at start.
const MAX_RESOURCE_BYTES: usize = 2 * 1024 * 1024;

/// Reads the downloaded resource files. One that is missing, too large or
/// over the total is skipped: its plugin line is then graded unsupported.
fn read_resource_assets(assets: &BTreeMap<String, String>) -> BTreeMap<String, Vec<u8>> {
    let mut total = 0;
    let mut resources = BTreeMap::new();
    for (url, path) in assets {
        let Ok(metadata) = std::fs::metadata(path) else {
            continue;
        };
        let len = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if len > MAP_LOCAL_REMOTE_DATA_MAX_BYTES || total + len > MAX_RESOURCE_BYTES {
            continue;
        }
        if let Ok(body) = std::fs::read(path) {
            if body.len() <= MAP_LOCAL_REMOTE_DATA_MAX_BYTES {
                total += body.len();
                resources.insert(url.clone(), body);
            }
        }
    }
    resources
}

pub struct MitmEngine {
    service: Arc<AnixOpsMitmPluginService>,
    instance: PluginInstance,
    hook: Arc<NativeHttpMitmPluginHook>,
    /// Whether the hook can run scripts, which must leave the runtime thread.
    scripts: bool,
    /// Where script `$httpClient` requests go: the tunnel's dispatcher, so
    /// they follow the same routing as the device's own connections.
    script_outbound: Arc<OnceLock<Arc<dyn TcpOutbound>>>,
    issuer: Issuer<'static, KeyPair>,
    upstream: Arc<ClientConfig>,
    leaves: Mutex<HashMap<String, Arc<ServerConfig>>>,
    decisions: Mutex<HashMap<String, bool>>,
    next_request: AtomicU64,
    /// `[Rule]` lines of the accepted plugins, for the routing model.
    plugin_rules: Vec<config_core::routing::RoutingRule>,
    /// Cron, network-change and generic scripts, and the notifications
    /// every script posts.
    #[cfg(feature = "scripts")]
    scheduler: Option<Arc<scheduler::ScriptScheduler>>,
}

impl MitmEngine {
    /// Validates the policy and the root. Errors are fixed strings: neither
    /// the policy nor key material reaches them.
    pub fn new(config: &MitmConfig) -> Result<Self, &'static str> {
        let total = config.policy.len() + config.plugins.iter().map(String::len).sum::<usize>();
        if total > MAX_POLICY_BYTES {
            return Err("mitm policy is too large");
        }
        let resources = read_resource_assets(&config.resource_assets);
        let imports = std::iter::once(&config.policy)
            .filter(|policy| !policy.trim().is_empty())
            .chain(&config.plugins)
            .map(|text| {
                import_loon_plugin_with_resources(text, &resources)
                    .map_err(|_| "mitm plugin is invalid")
            })
            .collect::<Result<Vec<_>, _>>()?;
        let accepted = imports
            .iter()
            .filter(|import| import.report.policy_load_error.is_none())
            .collect::<Vec<_>>();
        let policy = merged_plugin_source("NetworkCore iOS MITM", &accepted);
        let plugin_rules = accepted
            .iter()
            .flat_map(|import| import.routing_rules())
            .collect();
        let scheduled_scripts = accepted
            .iter()
            .flat_map(|import| import.scheduled_scripts.iter().cloned())
            .collect::<Vec<_>>();
        let certificate = base64::engine::general_purpose::STANDARD
            .decode(config.ca_certificate.trim())
            .map_err(|_| "mitm ca_certificate is not base64")?;
        let key = base64::engine::general_purpose::STANDARD
            .decode(config.ca_private_key.trim())
            .map_err(|_| "mitm ca_private_key is not base64")?;
        let pkcs8 = p256_pkcs8_from_x963(&key).ok_or("mitm ca_private_key is not a P-256 key")?;
        let key = KeyPair::try_from(pkcs8.as_slice())
            .map_err(|_| "mitm ca_private_key is not a P-256 key")?;
        let issuer = Issuer::from_ca_cert_der(&CertificateDer::from(certificate), key)
            .map_err(|_| "mitm ca_certificate is not a certificate")?;

        let service = Arc::new(AnixOpsMitmPluginService::new());
        let package = PluginPackage {
            manifest: PluginManifest {
                id: PLUGIN_ID.to_string(),
                version: "1".to_string(),
                permissions: vec![
                    PluginPermission::ReadRequest,
                    PluginPermission::ModifyRequest,
                    PluginPermission::ReadResponse,
                    PluginPermission::ModifyResponse,
                ],
                hooks: vec![HookPoint::Request, HookPoint::Response],
            },
            source: policy,
        };
        let instance = service
            .load(
                &package,
                &GrantedPermissions {
                    permissions: package.manifest.permissions.clone(),
                },
            )
            .map_err(|_| "mitm policy is invalid")?;
        let upstream = Arc::new(
            transport_tls::client_config(&transport_tls::TlsSettings {
                server_name: String::new(),
                alpn: vec!["http/1.1".to_string()],
                insecure: false,
            })
            .map_err(|_| "mitm upstream TLS is unavailable")?,
        );
        let script_outbound = Arc::new(OnceLock::new());
        let hook = NativeHttpMitmPluginHook::new(instance.clone(), service.clone());
        let scripts = !config.script_assets.is_empty();
        let (hook, executor) = if scripts {
            with_scripts(hook, config, &script_outbound, &upstream)?
        } else {
            (hook, None)
        };
        #[cfg(feature = "scripts")]
        let scheduler = executor
            .map(|executor| Arc::new(scheduler::ScriptScheduler::new(executor, scheduled_scripts)));
        #[cfg(not(feature = "scripts"))]
        let _ = (executor, scheduled_scripts);
        Ok(Self {
            service,
            instance,
            hook: Arc::new(hook),
            scripts,
            script_outbound,
            issuer,
            upstream,
            leaves: Mutex::new(HashMap::new()),
            decisions: Mutex::new(HashMap::new()),
            next_request: AtomicU64::new(1),
            plugin_rules,
            #[cfg(feature = "scripts")]
            scheduler,
        })
    }

    /// Runs the rewrite hook. Script dispatches block, so with scripts the
    /// plan runs on the blocking pool.
    async fn plan(
        &self,
        message: NativePlainHttpMessage,
    ) -> io::Result<NativePlainHttpRewriteReport> {
        if !self.scripts {
            return Ok(self.hook.plan_plain_http(&message));
        }
        let hook = self.hook.clone();
        tokio::task::spawn_blocking(move || hook.plan_plain_http(&message))
            .await
            .map_err(|_| io::Error::other("mitm rewrite failed"))
    }

    /// Replaces the verifying upstream client, e.g. to trust a test origin.
    pub fn with_upstream_config(mut self, config: ClientConfig) -> Self {
        self.upstream = Arc::new(config);
        self
    }

    /// Whether TLS to `host` is intercepted.
    pub fn intercepts(&self, host: &str) -> bool {
        if let Some(decision) = self
            .decisions
            .lock()
            .ok()
            .and_then(|cache| cache.get(host).copied())
        {
            return decision;
        }
        let decision = matches!(
            self.service
                .evaluate_mitm_hostname(&self.instance, host, false),
            Ok(MitmHostnameDecision::Intercept)
        );
        if let Ok(mut cache) = self.decisions.lock() {
            if cache.len() >= DECISION_CACHE_ENTRIES {
                cache.clear();
            }
            cache.insert(host.to_string(), decision);
        }
        decision
    }

    fn leaf_config(&self, host: &str) -> io::Result<Arc<ServerConfig>> {
        if let Some(config) = self
            .leaves
            .lock()
            .ok()
            .and_then(|cache| cache.get(host).cloned())
        {
            return Ok(config);
        }
        let mut params = CertificateParams::new(vec![host.to_string()])
            .map_err(|_| invalid("leaf certificate name is invalid"))?;
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, host);
        params.distinguished_name = name;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(397);
        let key = KeyPair::generate().map_err(|_| invalid("leaf key generation failed"))?;
        let certificate = params
            .signed_by(&key, &self.issuer)
            .map_err(|_| invalid("leaf certificate signing failed"))?;
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|_| invalid("leaf TLS configuration failed"))?
                .with_no_client_auth()
                .with_single_cert(
                    vec![certificate.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
                )
                .map_err(|_| invalid("leaf TLS configuration failed"))?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        if let Ok(mut cache) = self.leaves.lock() {
            if cache.len() >= LEAF_CACHE_ENTRIES {
                cache.clear();
            }
            cache.insert(host.to_string(), config.clone());
        }
        Ok(config)
    }

    /// Terminates the client's TLS, connects to the origin through `outbound`
    /// and relays HTTP/1.1 through the rewrite hook until either side closes.
    /// A plain HTTP flow is relayed as it is, without TLS on either side.
    /// A keep-alive client that sends nothing for `idle_timeout` is closed.
    pub async fn serve_flow(
        &self,
        flow: InterceptedFlow,
        outbound: &dyn TcpOutbound,
        connect_timeout: Duration,
        idle_timeout: Duration,
    ) -> io::Result<()> {
        if !is_tls(&flow.first) {
            return self
                .serve_plain_flow(flow, outbound, connect_timeout, idle_timeout)
                .await;
        }
        let host = flow.host.as_str();
        let target = TargetAddr::Ip(flow.target);
        let acceptor = tokio_rustls::TlsAcceptor::from(self.leaf_config(host)?);
        let client = tokio::time::timeout(
            connect_timeout,
            acceptor.accept(Prefixed::new(flow.inbound, flow.first)),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;

        let remote = tokio::time::timeout(connect_timeout, outbound.connect(&target))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        let server_name =
            ServerName::try_from(host.to_string()).map_err(|_| invalid("invalid server name"))?;
        let origin = tokio_rustls::TlsConnector::from(self.upstream.clone())
            .connect(server_name, remote)
            .await?;

        let authority = authority(host, flow.target.port(), HTTPS_PORT);
        self.relay(
            Conn::new(client, Vec::new()),
            Conn::new(origin, Vec::new()),
            "https",
            &authority,
            idle_timeout,
        )
        .await
    }

    /// Relays a plain HTTP flow through the rewrite hook, so `http://`
    /// rewrites and scripts apply as they do in Loon and Surge.
    async fn serve_plain_flow(
        &self,
        flow: InterceptedFlow,
        outbound: &dyn TcpOutbound,
        connect_timeout: Duration,
        idle_timeout: Duration,
    ) -> io::Result<()> {
        let target = TargetAddr::Ip(flow.target);
        let origin = tokio::time::timeout(connect_timeout, outbound.connect(&target))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        let authority = authority(&flow.host, flow.target.port(), HTTP_PORT);
        self.relay(
            Conn::new(flow.inbound, flow.first),
            Conn::new(origin, Vec::new()),
            "http",
            &authority,
            idle_timeout,
        )
        .await
    }

    async fn relay<C, O>(
        &self,
        mut client: Conn<C>,
        mut origin: Conn<O>,
        scheme: &str,
        authority: &str,
        idle_timeout: Duration,
    ) -> io::Result<()>
    where
        C: AsyncRead + AsyncWrite + Unpin,
        O: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            let Ok(request) = tokio::time::timeout(idle_timeout, client.read_head()).await else {
                return Ok(());
            };
            let Some(request) = request? else {
                return Ok(());
            };
            let (method, path, version) = split_request_line(&request.start_line)?;
            let request_framing = request.framing()?;
            let request_body = match client.read_body(request_framing, MAX_BODY_BYTES).await? {
                Body::Complete(body) => body,
                Body::TooLarge(raw) => {
                    origin.write_all(&request.encode()).await?;
                    origin.write_all(&raw).await?;
                    return passthrough(client, origin).await;
                }
            };
            let url = format!("{scheme}://{authority}{path}");
            let request_id = self
                .next_request
                .fetch_add(1, Ordering::Relaxed)
                .to_string();
            let report = self
                .plan(NativePlainHttpMessage {
                    request_id: request_id.clone(),
                    url: url.clone(),
                    method: Some(method.clone()),
                    phase: HttpMitmPhase::Request,
                    status_code: None,
                    headers: to_metadata(&request.headers),
                    body: request_body,
                })
                .await?;
            let client_close = request.has_token("Connection", "close") || version == "HTTP/1.0";

            if report.terminal_action.is_some() {
                let response = response_head(
                    report.final_status_code.unwrap_or(200),
                    &report.headers,
                    report.redirect_location.as_deref(),
                    report.body.len(),
                    client_close,
                );
                client.write_all(&response.encode()).await?;
                client.write_all(&report.body).await?;
                if client_close {
                    return Ok(());
                }
                continue;
            }

            // A rewrite may change the path; the authority stays the
            // intercepted host.
            let path = report
                .url
                .strip_prefix(&format!("{scheme}://{authority}"))
                .filter(|rest| rest.starts_with('/'))
                .unwrap_or(path.as_str())
                .to_string();
            let had_body = !matches!(request_framing, Framing::Length(0));
            let mut headers = from_metadata(&report.headers);
            remove(&mut headers, "Transfer-Encoding");
            remove(&mut headers, "Content-Length");
            remove(&mut headers, "Accept-Encoding");
            headers.push(("Accept-Encoding".to_string(), "identity".to_string()));
            if had_body || !report.body.is_empty() {
                headers.push(("Content-Length".to_string(), report.body.len().to_string()));
            }
            let upstream_request = Head {
                start_line: format!("{method} {path} HTTP/1.1"),
                headers,
            };
            origin.write_all(&upstream_request.encode()).await?;
            origin.write_all(&report.body).await?;

            // Interim 1xx responses go straight to the client.
            let response = loop {
                let head = tokio::time::timeout(idle_timeout, origin.read_head())
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
                let Some(head) = head else {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                };
                let status = response_status(&head.start_line)?;
                if (100..200).contains(&status) && status != 101 {
                    client.write_all(&head.encode()).await?;
                    continue;
                }
                break head;
            };
            let status = response_status(&response.start_line)?;
            let streaming = status == 101
                || response.header("Content-Type").is_some_and(|value| {
                    value.to_ascii_lowercase().starts_with("text/event-stream")
                });
            if streaming {
                client.write_all(&response.encode()).await?;
                return passthrough(client, origin).await;
            }
            let no_body = method.eq_ignore_ascii_case("HEAD") || status == 204 || status == 304;
            let framing = if no_body {
                Framing::Length(0)
            } else if response.header("Transfer-Encoding").is_none()
                && response.header("Content-Length").is_none()
            {
                Framing::UntilClose
            } else {
                response.framing()?
            };
            let response_body = match origin.read_body(framing, MAX_BODY_BYTES).await? {
                Body::Complete(body) => body,
                Body::TooLarge(raw) => {
                    client.write_all(&response.encode()).await?;
                    client.write_all(&raw).await?;
                    return passthrough(client, origin).await;
                }
            };
            let report = self
                .plan(NativePlainHttpMessage {
                    request_id,
                    url,
                    method: Some(method.clone()),
                    phase: HttpMitmPhase::Response,
                    status_code: Some(status),
                    headers: to_metadata(&response.headers),
                    body: response_body,
                })
                .await?;
            let close = client_close
                || framing == Framing::UntilClose
                || response.has_token("Connection", "close");
            let mut head = response_head(
                report.final_status_code.unwrap_or(status),
                &report.headers,
                report.redirect_location.as_deref(),
                report.body.len(),
                close,
            );
            if no_body {
                // Keep the origin's framing headers for HEAD, 204 and 304.
                head = Head {
                    start_line: head.start_line,
                    headers: from_metadata(&report.headers),
                };
            }
            client.write_all(&head.encode()).await?;
            if !no_body {
                client.write_all(&report.body).await?;
            }
            if close {
                return Ok(());
            }
        }
    }
}

impl FlowInterceptor for MitmEngine {
    /// Script `$httpClient` requests go through `outbound`, set once; until
    /// it is set they fail with an error the script sees.
    fn set_script_outbound(&self, outbound: Arc<dyn TcpOutbound>) {
        let _ = self.script_outbound.set(outbound);
    }

    fn plugin_rules(&self) -> Vec<config_core::routing::RoutingRule> {
        self.plugin_rules.clone()
    }

    #[cfg(feature = "scripts")]
    fn background(self: Arc<Self>) -> Option<BoxFuture<'static, ()>> {
        let scheduler = self
            .scheduler
            .clone()
            .filter(|scheduler| scheduler.has_scripts())?;
        Some(Box::pin(scheduler.run()))
    }

    #[cfg(feature = "scripts")]
    fn script_control(&self, request: &crate::control::ScriptControl) -> Option<serde_json::Value> {
        Some(self.scheduler.as_ref()?.control(request))
    }

    /// HTTPS to a `[MITM]` host is decrypted. Plain HTTP needs no
    /// certificate, so every plain request is relayed through the rewrite
    /// hook, as Loon and Surge apply `http://` rules without a hostname.
    fn claim(&self, first: &[u8], target: SocketAddr) -> Option<String> {
        if is_tls(first) {
            if target.port() != HTTPS_PORT {
                return None;
            }
            let host = crate::sniff::client_hello_server_name(first)?;
            return self.intercepts(&host).then_some(host);
        }
        plain_http_host(first)
    }

    fn serve<'a>(
        &'a self,
        flow: InterceptedFlow,
        outbound: &'a dyn TcpOutbound,
        settings: &'a TunnelSettings,
        stats: &'a TunnelStats,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let served = self
                .serve_flow(
                    flow,
                    outbound,
                    settings.connect_timeout,
                    settings.idle_timeout,
                )
                .await;
            if served.is_err() {
                crate::tunnel::bump(&stats.mitm_failed);
            }
        })
    }
}

/// Whether `first` starts a TLS handshake record.
fn is_tls(first: &[u8]) -> bool {
    first.first() == Some(&0x16)
}

/// The `Host` of a plain HTTP/1.x request that starts in `first`, when its
/// method is one the relay serves.
fn plain_http_host(first: &[u8]) -> Option<String> {
    let method = PLAIN_HTTP_METHODS
        .iter()
        .any(|method| first.starts_with(method.as_bytes()));
    if !method {
        return None;
    }
    crate::sniff::http_host(first)
}

/// `host`, with `:port` when it is not the scheme's default.
fn authority(host: &str, port: u16, default_port: u16) -> String {
    if port == default_port {
        host.to_string()
    } else {
        format!("{host}:{port}")
    }
}

/// Relays raw bytes both ways once rewriting stops, starting with whatever
/// each side had buffered.
async fn passthrough<C, O>(client: Conn<C>, origin: Conn<O>) -> io::Result<()>
where
    C: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    let (client, client_buffered) = client.into_parts();
    let (origin, origin_buffered) = origin.into_parts();
    let mut client = Prefixed::new(client, client_buffered);
    let mut origin = Prefixed::new(origin, origin_buffered);
    tokio::io::copy_bidirectional(&mut client, &mut origin)
        .await
        .map(|_| ())
}

fn split_request_line(line: &str) -> io::Result<(String, String, String)> {
    let mut parts = line.split(' ');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(method), Some(path), Some(version), None)
            if !method.is_empty() && path.starts_with('/') && version.starts_with("HTTP/1.") =>
        {
            Ok((method.to_string(), path.to_string(), version.to_string()))
        }
        _ => Err(invalid("unsupported request line")),
    }
}

fn response_status(line: &str) -> io::Result<u16> {
    let mut parts = line.splitn(3, ' ');
    match (parts.next(), parts.next()) {
        (Some(version), Some(status)) if version.starts_with("HTTP/1.") => status
            .parse::<u16>()
            .ok()
            .filter(|status| (100..1000).contains(status))
            .ok_or_else(|| invalid("invalid status code")),
        _ => Err(invalid("invalid status line")),
    }
}

fn response_head(
    status: u16,
    headers: &[MetadataEntry],
    location: Option<&str>,
    body_len: usize,
    close: bool,
) -> Head {
    let mut headers = from_metadata(headers);
    remove(&mut headers, "Transfer-Encoding");
    remove(&mut headers, "Content-Length");
    remove(&mut headers, "Connection");
    if let Some(location) = location {
        remove(&mut headers, "Location");
        headers.push(("Location".to_string(), location.to_string()));
    }
    headers.push(("Content-Length".to_string(), body_len.to_string()));
    if close {
        headers.push(("Connection".to_string(), "close".to_string()));
    }
    Head {
        start_line: format!("HTTP/1.1 {status} {}", reason(status)),
        headers,
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Status",
    }
}

fn to_metadata(headers: &[(String, String)]) -> Vec<MetadataEntry> {
    headers
        .iter()
        .map(|(key, value)| MetadataEntry {
            key: key.clone(),
            value: value.clone(),
        })
        .collect()
}

fn from_metadata(headers: &[MetadataEntry]) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|entry| (entry.key.clone(), entry.value.clone()))
        .collect()
}

fn remove(headers: &mut Vec<(String, String)>, name: &str) {
    headers.retain(|(key, _)| !key.eq_ignore_ascii_case(name));
}

#[cfg(feature = "scripts")]
fn with_scripts(
    hook: NativeHttpMitmPluginHook,
    config: &MitmConfig,
    outbound: &Arc<OnceLock<Arc<dyn TcpOutbound>>>,
    tls: &Arc<ClientConfig>,
) -> Result<
    (
        NativeHttpMitmPluginHook,
        Option<NativeQuickJsScriptExecutor>,
    ),
    &'static str,
> {
    let executor = NativeQuickJsScriptExecutor::new(NativeQuickJsScriptRuntimeConfig {
        script_assets: config.script_assets.clone(),
        persistent_store_path: config.script_store_path.clone(),
        max_timeout_ms: SCRIPT_MAX_TIMEOUT_MS,
        max_body_bytes: MAX_BODY_BYTES,
        memory_limit_bytes: SCRIPT_MEMORY_LIMIT_BYTES,
    })
    .map_err(|_| "mitm scripts are unavailable")?
    .with_http_client(Arc::new(http_client::TunnelScriptHttpClient::new(
        outbound.clone(),
        tls.clone(),
    )));
    Ok((
        hook.with_quickjs_script_executor(executor.clone()),
        Some(executor),
    ))
}

#[cfg(not(feature = "scripts"))]
fn with_scripts(
    _hook: NativeHttpMitmPluginHook,
    _config: &MitmConfig,
    _outbound: &Arc<OnceLock<Arc<dyn TcpOutbound>>>,
    _tls: &Arc<ClientConfig>,
) -> Result<(NativeHttpMitmPluginHook, Option<()>), &'static str> {
    Err("mitm scripts are not supported by this build")
}

/// PKCS#8 for a P-256 key given as ANSI X9.63 `04 || X || Y || D`, in the
/// exact layout `ring` produces and accepts.
pub fn p256_pkcs8_from_x963(key: &[u8]) -> Option<Vec<u8>> {
    if key.len() != 97 || key[0] != 0x04 {
        return None;
    }
    const PREFIX: [u8; 36] = [
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30,
        0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
    ];
    const PUBLIC_KEY: [u8; 5] = [0xa1, 0x44, 0x03, 0x42, 0x00];
    let mut der = Vec::with_capacity(138);
    der.extend_from_slice(&PREFIX);
    der.extend_from_slice(&key[65..97]);
    der.extend_from_slice(&PUBLIC_KEY);
    der.extend_from_slice(&key[..65]);
    Some(der)
}

/// Reads `prefix` before the wrapped stream; writes go straight through.
struct Prefixed<S> {
    prefix: Vec<u8>,
    offset: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let n = (this.prefix.len() - this.offset).min(buf.remaining());
            buf.put_slice(&this.prefix[this.offset..this.offset + n]);
            this.offset += n;
            if this.offset == this.prefix.len() {
                this.prefix = Vec::new();
                this.offset = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
