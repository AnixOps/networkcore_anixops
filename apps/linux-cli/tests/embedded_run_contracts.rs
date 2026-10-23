//! `run-url` on the embedded engine: engine selection, fallback and a real
//! local listener.

use std::net::{TcpListener, TcpStream};

use control_domain::DomainResult;
use networkcore_linux::{
    parse_args, run_url_with_embedded_engine, LinuxCliCommand, LinuxCliExitCode, LinuxRunEngine,
    RemoteSubscriptionFetcher, CLI_RUN_URL_EMBEDDED_STARTED_CODE,
    CLI_RUN_URL_EMBEDDED_UNSUPPORTED_CODE,
};

/// `ss://` link for a Shadowsocks-2022 node (method and key base64url-encoded).
const SS_2022_LINK: &str =
    "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206QUFFQ0F3UUZCZ2NJQ1FvTERBME9Edz09@192.0.2.10:8388#SS2022";
/// Hysteria2 with Salamander obfuscation, which the embedded engine lacks.
const HYSTERIA2_OBFS_LINK: &str = "hysteria2://hy2-secret@edge.example.test:443?sni=cdn.example.test&obfs=salamander&obfs-password=obfs-secret#Hysteria2";

struct NoRemoteFetch;

impl RemoteSubscriptionFetcher for NoRemoteFetch {
    fn fetch_subscription(&self, _location: &str) -> DomainResult<String> {
        panic!("tests pass subscriptions inline");
    }
}

#[test]
fn engine_option_parses_and_defaults_to_auto() {
    let engine_of = |args: &[&str]| match parse_args(args.iter().copied()).unwrap() {
        LinuxCliCommand::RunUrl { engine, .. } => engine,
        other => panic!("unexpected command {other:?}"),
    };
    assert_eq!(engine_of(&["run-url", SS_2022_LINK]), LinuxRunEngine::Auto);
    assert_eq!(
        engine_of(&["run-url", SS_2022_LINK, "--engine", "embedded"]),
        LinuxRunEngine::Embedded
    );
    assert_eq!(
        engine_of(&["run-url", SS_2022_LINK, "--engine", "sing-box"]),
        LinuxRunEngine::SingBox
    );
    assert!(parse_args(["run-url", SS_2022_LINK, "--engine", "other"]).is_err());
    assert!(parse_args(["run-url", SS_2022_LINK, "--engine"]).is_err());
}

#[test]
fn auto_falls_back_for_protocols_the_embedded_engine_lacks() {
    let response = run_url_with_embedded_engine(
        &NoRemoteFetch,
        HYSTERIA2_OBFS_LINK,
        None,
        "127.0.0.1",
        0,
        LinuxRunEngine::Auto,
        |_| panic!("the proxy must not start"),
    );
    assert!(response.is_none());
}

#[test]
fn embedded_reports_unsupported_nodes_without_their_secrets() {
    let response = run_url_with_embedded_engine(
        &NoRemoteFetch,
        HYSTERIA2_OBFS_LINK,
        None,
        "127.0.0.1",
        0,
        LinuxRunEngine::Embedded,
        |_| panic!("the proxy must not start"),
    )
    .expect("embedded mode never falls back");
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
        LinuxRunEngine::Auto,
        |proxy| {
            assert!(proxy.is_running());
            assert_eq!(proxy.protocol(), "shadowsocks-2022");
            TcpStream::connect(proxy.local_addr()).expect("listener accepts connections");
            LinuxCliExitCode::Interrupted
        },
    )
    .expect("auto mode runs a supported node");
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
        LinuxRunEngine::Embedded,
        |_| panic!("the proxy must not start"),
    )
    .unwrap();
    assert!(!response.ok);
    assert_eq!(response.exit_code, LinuxCliExitCode::GeneralFailure);
}
