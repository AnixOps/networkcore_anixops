//! `run-url` on the embedded engine: the subscription's nodes run in this
//! process behind a local SOCKS5/HTTP listener, with no external engine
//! binary to download or start.

use std::net::{SocketAddr, ToSocketAddrs};

use config_core::routing_import::import_subscription_routing;
use config_core::CoreSubscriptionService;
use control_domain::{
    Diagnostic, DiagnosticSeverity, DomainError, RawSubscription, SubscriptionService,
};
use engine_embedded::local_proxy::LocalProxy;
use engine_embedded::nodes::{routing_envelope, single_node_envelope};
use inbound_mixed::MixedSettings;

use super::{
    cli_diagnostic, domain_error_response, read_run_url_subscription_content,
    read_subscription_catalog_source_location, LinuxCliExitCode, LinuxCliResponse,
    RemoteSubscriptionFetcher, CLI_RUN_URL_PARSE_FAILED_CODE,
};

pub const CLI_RUN_URL_EMBEDDED_STARTED_CODE: &str = "cli.linux.run_url.embedded_started";
pub const CLI_RUN_URL_EMBEDDED_STOPPED_CODE: &str = "cli.linux.run_url.embedded_stopped";
pub const CLI_RUN_URL_EMBEDDED_UNSUPPORTED_CODE: &str = "cli.linux.run_url.embedded_unsupported";
pub const CLI_RUN_URL_EMBEDDED_ROUTING_FALLBACK_CODE: &str =
    "cli.linux.run_url.embedded_routing_fallback";
pub const CLI_RUN_URL_EMBEDDED_START_FAILED_CODE: &str = "cli.linux.run_url.embedded_start_failed";
pub const SOURCE_CLI_EMBEDDED_ENGINE: &str = "cli.embedded_engine";

const PROFILE_ID: &str = "cli-run-url";

/// Runs `run-url` on the embedded engine. `wait` is called while the proxy
/// serves and returns when it should stop (the binary waits for SIGINT or
/// SIGTERM).
pub fn run_url_with_embedded_engine<F, W>(
    fetcher: &F,
    url: &str,
    selected_node_id: Option<&str>,
    listen_host: &str,
    listen_port: u16,
    wait: W,
) -> LinuxCliResponse
where
    F: RemoteSubscriptionFetcher,
    W: FnOnce(&mut LocalProxy) -> LinuxCliExitCode,
{
    let content = match read_run_url_subscription_content(url, fetcher) {
        Ok(content) => content,
        Err(error) => return failure(LinuxCliExitCode::ArgumentOrConfig, error),
    };
    let subscription = CoreSubscriptionService::new();
    let raw = RawSubscription {
        source_id: PROFILE_ID.to_string(),
        content,
    };
    let parse_failed = |error: DomainError| {
        failure(
            LinuxCliExitCode::ArgumentOrConfig,
            DomainError::new(CLI_RUN_URL_PARSE_FAILED_CODE, error.message),
        )
    };
    let document = match subscription.parse(&raw) {
        Ok(document) => document,
        Err(error) => return parse_failed(error),
    };
    let catalog = match subscription.normalize(&document) {
        Ok(catalog) => catalog,
        Err(error) => return parse_failed(error),
    };
    let mut diagnostics = document.diagnostics.clone();

    // An explicit node runs alone, otherwise subscription rules and policy
    // groups drive the route.
    let mut routed = None;
    if selected_node_id.is_none() {
        let imported = import_subscription_routing(&raw.content, &catalog.nodes);
        diagnostics.extend(imported.diagnostics);
        if let Some(spec) = imported.spec {
            match routing_envelope(PROFILE_ID, &catalog.nodes, &spec) {
                Ok(envelope) => {
                    let summary = format!(
                        "{} nodes with {} rules and {} policy groups",
                        catalog.nodes.len(),
                        spec.rules.len(),
                        spec.groups.len()
                    );
                    routed = Some((envelope, summary));
                }
                Err(reason) => diagnostics.push(diagnostic(
                    DiagnosticSeverity::Warning,
                    CLI_RUN_URL_EMBEDDED_ROUTING_FALLBACK_CODE,
                    format!(
                        "subscription routing was not applied and run-url uses one node: {reason}"
                    ),
                )),
            }
        }
    }
    let (envelope, summary) = match routed {
        Some(routed) => routed,
        None => match single_node_envelope(PROFILE_ID, &catalog.nodes, selected_node_id) {
            Ok((envelope, node)) => (envelope, format!("node {}", node.id)),
            Err(reason) => {
                return LinuxCliResponse::failure(
                    "run-url",
                    LinuxCliExitCode::ArgumentOrConfig,
                    diagnostic(
                        DiagnosticSeverity::Error,
                        CLI_RUN_URL_EMBEDDED_UNSUPPORTED_CODE,
                        format!("the embedded engine cannot run this node: {reason}"),
                    ),
                )
            }
        },
    };

    let Some(listen) = resolve_listen(listen_host, listen_port) else {
        return start_failed("the listen address is not a local IP address");
    };
    let mut proxy = match LocalProxy::start(envelope.as_bytes(), listen, MixedSettings::default()) {
        Ok(proxy) => proxy,
        Err(error) => return start_failed(error.message),
    };
    diagnostics.push(diagnostic(
        DiagnosticSeverity::Info,
        CLI_RUN_URL_EMBEDDED_STARTED_CODE,
        format!(
            "embedded engine serves SOCKS5/HTTP on {} with {summary}",
            proxy.local_addr()
        ),
    ));
    let exit_code = wait(&mut proxy);
    proxy.stop();
    diagnostics.push(diagnostic(
        DiagnosticSeverity::Info,
        CLI_RUN_URL_EMBEDDED_STOPPED_CODE,
        "embedded engine stopped",
    ));
    let response = LinuxCliResponse::success("run-url").with_diagnostics(diagnostics);
    match exit_code {
        LinuxCliExitCode::Success => response,
        exit_code => LinuxCliResponse {
            ok: false,
            exit_code,
            ..response
        },
    }
}

/// Runs `run-catalog`: resolves the saved source's location, then runs it as
/// `run-url` does.
pub fn run_catalog_with_embedded_engine<F, W>(
    fetcher: &F,
    catalog_path: &str,
    source_id: &str,
    selected_node_id: Option<&str>,
    listen_host: &str,
    listen_port: u16,
    wait: W,
) -> LinuxCliResponse
where
    F: RemoteSubscriptionFetcher,
    W: FnOnce(&mut LocalProxy) -> LinuxCliExitCode,
{
    let mut response = match read_subscription_catalog_source_location(catalog_path, source_id) {
        Ok(location) => run_url_with_embedded_engine(
            fetcher,
            &location,
            selected_node_id,
            listen_host,
            listen_port,
            wait,
        ),
        Err(error) => failure(LinuxCliExitCode::ArgumentOrConfig, error),
    };
    response.command = "run-catalog".to_string();
    response
}

fn resolve_listen(host: &str, port: u16) -> Option<SocketAddr> {
    (host, port).to_socket_addrs().ok()?.next()
}

fn diagnostic(severity: DiagnosticSeverity, code: &str, message: impl Into<String>) -> Diagnostic {
    cli_diagnostic(severity, code, message, SOURCE_CLI_EMBEDDED_ENGINE)
}

fn failure(exit_code: LinuxCliExitCode, error: DomainError) -> LinuxCliResponse {
    domain_error_response("run-url", exit_code, error, SOURCE_CLI_EMBEDDED_ENGINE)
}

fn start_failed(message: &str) -> LinuxCliResponse {
    LinuxCliResponse::failure(
        "run-url",
        LinuxCliExitCode::GeneralFailure,
        diagnostic(
            DiagnosticSeverity::Error,
            CLI_RUN_URL_EMBEDDED_START_FAILED_CODE,
            format!("embedded engine could not start: {message}"),
        ),
    )
}

/// Blocks until SIGINT (exit code 130) or SIGTERM (success, as for a service
/// stop), or until the proxy stops on its own.
pub fn wait_for_stop_signal(proxy: &mut LocalProxy) -> LinuxCliExitCode {
    #[cfg(unix)]
    let signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::signal::SIGINT,
        signal_hook::consts::signal::SIGTERM,
    ]);
    #[cfg(unix)]
    let mut signals = signals.ok();
    loop {
        #[cfg(unix)]
        if let Some(signal) = signals
            .as_mut()
            .and_then(|signals| signals.pending().next())
        {
            return if signal == signal_hook::consts::signal::SIGTERM {
                LinuxCliExitCode::Success
            } else {
                LinuxCliExitCode::Interrupted
            };
        }
        if !proxy.is_running() {
            return LinuxCliExitCode::GeneralFailure;
        }
        std::thread::sleep(STOP_POLL_INTERVAL);
    }
}

const STOP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(200);
