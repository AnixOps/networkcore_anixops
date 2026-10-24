//! Local proxy mode for desktop: the same config envelope and outbounds as the
//! packet tunnel, served as a SOCKS5/HTTP mixed inbound on a local port.
//!
//! Applications (or the system proxy setting) send their connections to the
//! listener, so routing rules see the requested domain instead of an IP. The
//! proxy owns one current-thread tokio runtime on a dedicated thread, like
//! [`crate::tunnel::Tunnel`].

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use engine_outbound::registry::OutboundRegistry;
use engine_outbound::{Dialer, TcpDialer, TcpOutbound};
use inbound_mixed::{MixedSettings, MixedStats};
use tokio::sync::oneshot;

use crate::config::RuntimeConfig;
use crate::{protocols, RuntimeError, RuntimeErrorCode};

pub struct LocalProxy {
    profile_id: String,
    protocol: &'static str,
    local_addr: SocketAddr,
    stats: Arc<MixedStats>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl LocalProxy {
    /// Builds the outbound from `config` and starts listening on `listen`.
    /// Port 0 picks a free port; see [`LocalProxy::local_addr`].
    pub fn start(
        config: &[u8],
        listen: SocketAddr,
        settings: MixedSettings,
    ) -> Result<Self, RuntimeError> {
        Self::start_with(
            config,
            listen,
            settings,
            &protocols::default_registry(),
            Arc::new(TcpDialer),
        )
    }

    pub fn start_with(
        config: &[u8],
        listen: SocketAddr,
        settings: MixedSettings,
        registry: &OutboundRegistry,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Self, RuntimeError> {
        let config = RuntimeConfig::from_json(config)?;
        // A routing config keeps its routed outbound to run group health checks.
        let routed = config.build_routed(registry, dialer.clone())?;
        let outbound: Arc<dyn TcpOutbound> = match &routed {
            Some(routed) => routed.clone() as Arc<dyn TcpOutbound>,
            None => config.build_outbound(registry, dialer)?,
        };
        let protocol = outbound.protocol();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| resource("local proxy runtime could not start"))?;
        let listener = {
            let _guard = runtime.enter();
            let std_listener = std::net::TcpListener::bind(listen)
                .map_err(|_| resource("local proxy address could not be bound"))?;
            std_listener
                .set_nonblocking(true)
                .and_then(|()| tokio::net::TcpListener::from_std(std_listener))
                .map_err(|_| resource("local proxy listener could not start"))?
        };
        let local_addr = listener
            .local_addr()
            .map_err(|_| resource("local proxy listener could not start"))?;
        let stats = Arc::new(MixedStats::default());
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let thread_stats = stats.clone();
        let thread = thread::Builder::new()
            .name("networkcore-local-proxy".into())
            .spawn(move || {
                runtime.block_on(async move {
                    let health_checks = async move {
                        match routed {
                            Some(routed) => routed.run_health_checks().await,
                            None => std::future::pending().await,
                        }
                    };
                    tokio::select! {
                        _ = inbound_mixed::serve(listener, outbound, settings, thread_stats) => {}
                        _ = health_checks => {}
                        _ = shutdown_rx => {}
                    }
                });
                runtime.shutdown_timeout(Duration::from_secs(1));
            })
            .map_err(|_| resource("local proxy thread could not start"))?;
        Ok(Self {
            profile_id: config.profile_id,
            protocol,
            local_addr,
            stats,
            shutdown_tx: Some(shutdown_tx),
            thread: Some(thread),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    /// Protocol tag of the outbound, `"routed"` for a routing config.
    pub fn protocol(&self) -> &'static str {
        self.protocol
    }

    pub fn stats(&self) -> &MixedStats {
        &self.stats
    }

    pub fn is_running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }

    /// Stops listening and drops every connection. Idempotent.
    pub fn stop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    /// Blocks until the proxy stops on its own (the listener failed).
    pub fn wait(&mut self) -> io::Result<()> {
        match self.thread.take() {
            Some(thread) => thread
                .join()
                .map_err(|_| io::Error::other("local proxy thread panicked")),
            None => Ok(()),
        }
    }
}

impl Drop for LocalProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

fn resource(message: &'static str) -> RuntimeError {
    RuntimeError::new(RuntimeErrorCode::ResourceExhausted, message)
}
