//! `run-url` and `run-catalog` on the embedded engine: unsupported nodes and a
//! real local listener.

use std::net::{TcpListener, TcpStream};

use control_domain::DomainResult;
use networkcore_linux::{
    parse_args, run_catalog_with_embedded_engine, run_url_with_embedded_engine, LinuxCliExitCode,
    RemoteSubscriptionFetcher, CLI_RUN_URL_EMBEDDED_STARTED_CODE,
    CLI_RUN_URL_EMBEDDED_UNSUPPORTED_CODE,
};

/// `ss://` link for a Shadowsocks-2022 node (method and key base64url-encoded).
const SS_2022_LINK: &str =
    "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206QUFFQ0F3UUZCZ2NJQ1FvTERBME9Edz09@192.0.2.10:8388#SS2022";
/// Hysteria2 with Gecko obfuscation, which the embedded engine lacks.
const HYSTERIA2_OBFS_LINK: &str = "hysteria2://hy2-secret@edge.example.test:443?sni=cdn.example.test&obfs=gecko&obfs-password=obfs-secret#Hysteria2";

struct NoRemoteFetch;

impl RemoteSubscriptionFetcher for NoRemoteFetch {
    fn fetch_subscription(&self, _location: &str) -> DomainResult<String> {
        panic!("tests pass subscriptions inline");
    }
}

#[test]
fn the_engine_option_is_gone() {
    assert!(parse_args(["run-url", SS_2022_LINK]).is_ok());
    assert!(parse_args(["run-url", SS_2022_LINK, "--engine", "embedded"]).is_err());
}

#[test]
fn embedded_reports_unsupported_nodes_without_their_secrets() {
    let response = run_url_with_embedded_engine(
        &NoRemoteFetch,
        HYSTERIA2_OBFS_LINK,
        None,
        "127.0.0.1",
        0,
        |_| panic!("the proxy must not start"),
    );
    assert!(!response.ok);
    assert_eq!(response.exit_code, LinuxCliExitCode::ArgumentOrConfig);
    assert_eq!(
        response.diagnostics[0].code,
        CLI_RUN_URL_EMBEDDED_UNSUPPORTED_CODE
    );
    let diagnostics = format!("{:?}", response.diagnostics);
    assert!(!diagnostics.contains("hy2-secret"));
    assert!(!diagnostics.contains("obfs-secret"));
}

#[test]
fn shadowsocks_2022_runs_on_a_local_listener_until_stopped() {
    let response = run_url_with_embedded_engine(
        &NoRemoteFetch,
        SS_2022_LINK,
        None,
        "127.0.0.1",
        0,
        |proxy| {
            assert!(proxy.is_running());
            assert_eq!(proxy.protocol(), "shadowsocks-2022");
            TcpStream::connect(proxy.local_addr()).expect("listener accepts connections");
            LinuxCliExitCode::Interrupted
        },
    );
    assert!(!response.ok);
    assert_eq!(response.exit_code, LinuxCliExitCode::Interrupted);
    assert!(response
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == CLI_RUN_URL_EMBEDDED_STARTED_CODE));
    assert!(!format!("{:?}", response.diagnostics).contains("AAECAwQFBgcICQoLDA0ODw"));
}

#[test]
fn a_busy_listen_port_fails_to_start() {
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let response = run_url_with_embedded_engine(
        &NoRemoteFetch,
        SS_2022_LINK,
        None,
        "127.0.0.1",
        taken.local_addr().unwrap().port(),
        |_| panic!("the proxy must not start"),
    );
    assert!(!response.ok);
    assert_eq!(response.exit_code, LinuxCliExitCode::GeneralFailure);
}

#[test]
fn run_catalog_reports_a_missing_catalog_as_a_config_error() {
    let response = run_catalog_with_embedded_engine(
        &NoRemoteFetch,
        "/nonexistent/networkcore-catalog.json",
        "work",
        None,
        "127.0.0.1",
        0,
        |_| panic!("the proxy must not start"),
    );
    assert!(!response.ok);
    assert_eq!(response.command, "run-catalog");
    assert_eq!(response.exit_code, LinuxCliExitCode::ArgumentOrConfig);
}
