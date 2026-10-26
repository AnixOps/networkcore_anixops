//! `anixcore`: the node kernel.
//!
//! ```text
//! anixcore run -c config.json     start the inbounds and the management API
//! anixcore check -c config.json   parse the config and build every inbound
//! anixcore version
//! ```
//!
//! See `node_runtime::config` for the config format and `node_runtime::api`
//! for the management API.

use std::process::ExitCode;
use std::sync::Arc;

use node_runtime::{api, default_registry, Node, NodeConfig};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("version") | Some("--version") => {
            println!("anixcore {}", env!("CARGO_PKG_VERSION"));
            println!("inbounds: {}", default_registry().type_names().join(", "));
            Ok(())
        }
        Some(command @ ("run" | "check")) => match config_path(&args[1..]) {
            Some(path) => load(path).and_then(|config| start(config, command == "check")),
            None => Err("usage: anixcore run -c <config.json>".to_owned()),
        },
        _ => Err("usage: anixcore run|check -c <config.json> | anixcore version".to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("anixcore: {message}");
            ExitCode::FAILURE
        }
    }
}

fn config_path(args: &[String]) -> Option<&str> {
    match args {
        [flag, path] if flag == "-c" || flag == "--config" => Some(path.as_str()),
        _ => None,
    }
}

fn load(path: &str) -> Result<NodeConfig, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    // Only the position: serde messages can quote values such as passwords.
    serde_json::from_slice(&bytes).map_err(|error| {
        format!(
            "invalid config {path} at line {} column {} ({:?})",
            error.line(),
            error.column(),
            error.classify()
        )
    })
}

fn start(config: NodeConfig, check_only: bool) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("cannot start runtime: {error}"))?;
    runtime.block_on(async move {
        let node = Arc::new(Node::new(default_registry(), config.allow_private_targets));
        for inbound in config.inbounds {
            let tag = inbound.tag.clone();
            let listen = node
                .add_inbound(inbound)
                .await
                .map_err(|error| format!("inbound {tag}: {error}"))?;
            println!("inbound {tag} listening on {listen}");
        }
        if let Some(egress) = &config.egress {
            let status = node
                .apply_egress(egress)
                .await
                .map_err(|error| format!("egress: {error}"))?;
            println!(
                "egress: {} routes, {} relays",
                status.routes.len(),
                status.relays.len()
            );
        }
        if check_only {
            println!("config ok");
            return Ok(());
        }
        if let Some(management) = config.management {
            let listener = tokio::net::TcpListener::bind(management.listen)
                .await
                .map_err(|error| format!("management api: {error}"))?;
            println!("management api listening on {}", management.listen);
            let node = node.clone();
            tokio::spawn(async move {
                if let Err(error) = api::serve(listener, node, management.token).await {
                    eprintln!("anixcore: management api stopped: {error}");
                }
            });
        }
        shutdown_signal().await;
        println!("shutting down");
        Ok(())
    })
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
