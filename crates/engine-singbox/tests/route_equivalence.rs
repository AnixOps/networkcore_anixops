//! Routing equivalence between `RoutingModel::decide` and a real sing-box.
//!
//! The test renders `testdata/routing-snapshot/config.toml` with
//! `render_sing_box_route`, runs it in the sing-box binary named by
//! `NETWORKCORE_SING_BOX_BIN`, and replays every static case of
//! `decisions.json` through the sing-box mixed inbound. Each node and the
//! `direct` tag are local SOCKS5 mocks, so the mock that receives a case's
//! unique destination port shows which outbound sing-box chose. GeoIP rule
//! sets are read from `NETWORKCORE_SING_BOX_RULE_SET_DIR` and the fixture DNS
//! map is served by a sing-box `hosts` DNS server, so no case leaves the host.
//!
//! The dedicated `Routing equivalence (sing-box)` CI job provides both
//! variables and sets `NETWORKCORE_REQUIRE_SING_BOX_EQUIVALENCE=1`; without a
//! binary the workspace test run has nothing to compare and returns early.

use config_core::parse_config_document;
use engine_singbox::{render_sing_box_route, SING_BOX_DIRECT_OUTBOUND_TAG};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const SNAPSHOT_CONFIG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/routing-snapshot/config.toml"
));
const SNAPSHOT_DECISIONS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testdata/routing-snapshot/decisions.json"
));
const FIRST_CASE_PORT: u16 = 20_000;
const ROUTE_WAIT: Duration = Duration::from_secs(3);

struct MockSocks {
    port: u16,
    destination_ports: Arc<Mutex<Vec<u16>>>,
}

fn spawn_mock_socks() -> MockSocks {
    let listener = TcpListener::bind("127.0.0.1:0").expect("mock SOCKS5 listener should bind");
    let port = listener.local_addr().unwrap().port();
    let destination_ports = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&destination_ports);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let recorded = Arc::clone(&recorded);
            thread::spawn(move || {
                if let Some(port) = accept_socks_connect(stream) {
                    recorded.lock().unwrap().push(port);
                }
            });
        }
    });
    MockSocks {
        port,
        destination_ports,
    }
}

/// Completes a no-auth SOCKS5 CONNECT and returns the requested port.
fn accept_socks_connect(mut stream: TcpStream) -> Option<u16> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).ok()?;
    let mut methods = vec![0u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods).ok()?;
    stream.write_all(&[5, 0]).ok()?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).ok()?;
    let address_len = match request[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).ok()?;
            usize::from(len[0])
        }
        _ => return None,
    };
    let mut address = vec![0u8; address_len];
    stream.read_exact(&mut address).ok()?;
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).ok()?;
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).ok()?;
    Some(u16::from_be_bytes(port))
}

/// Sends one SOCKS5 CONNECT through the sing-box mixed inbound.
fn connect_through(proxy_port: u16, domain: Option<&str>, ip: Option<IpAddr>, port: u16) {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", proxy_port)) else {
        return;
    };
    let _ = stream.set_read_timeout(Some(ROUTE_WAIT));
    let mut request = vec![5, 1, 0];
    match (domain, ip) {
        (Some(domain), _) => {
            request.push(3);
            request.push(domain.len() as u8);
            request.extend_from_slice(domain.as_bytes());
        }
        (None, Some(IpAddr::V4(ip))) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        (None, Some(IpAddr::V6(ip))) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
        (None, None) => return,
    }
    request.extend_from_slice(&port.to_be_bytes());

    let mut reply = [0u8; 2];
    if stream.write_all(&[5, 1, 0]).is_err() || stream.read_exact(&mut reply).is_err() {
        return;
    }
    if stream.write_all(&request).is_ok() {
        let mut response = [0u8; 10];
        let _ = stream.read(&mut response);
    }
}

struct SingBoxProcess(Child);

impl Drop for SingBoxProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn unused_loopback_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn expected_tag(outcome: &str) -> Option<String> {
    match outcome {
        "reject" => None,
        "direct" => Some(SING_BOX_DIRECT_OUTBOUND_TAG.to_string()),
        node => Some(
            node.strip_prefix("node:")
                .expect("snapshot outcome is reject, direct, or node:<id>")
                .to_string(),
        ),
    }
}

#[test]
fn sing_box_routes_match_decision_snapshot() {
    let required = std::env::var("NETWORKCORE_REQUIRE_SING_BOX_EQUIVALENCE").as_deref() == Ok("1");
    let Ok(binary) = std::env::var("NETWORKCORE_SING_BOX_BIN") else {
        assert!(
            !required,
            "NETWORKCORE_SING_BOX_BIN must name a sing-box binary"
        );
        return;
    };
    let rule_set_dir = std::env::var("NETWORKCORE_SING_BOX_RULE_SET_DIR")
        .expect("NETWORKCORE_SING_BOX_RULE_SET_DIR must hold the GeoIP .srs rule sets");

    let model = parse_config_document(SNAPSHOT_CONFIG)
        .unwrap()
        .routing
        .expect("snapshot config defines routing");
    let snapshot = serde_json::from_str::<Value>(SNAPSHOT_DECISIONS).unwrap();
    let fragment = render_sing_box_route(&model);

    let mut mocks = BTreeMap::new();
    let mut outbounds = fragment.outbounds.clone();
    for tag in ["hk-1", "jp-1", "us-1", SING_BOX_DIRECT_OUTBOUND_TAG] {
        let mock = spawn_mock_socks();
        outbounds.push(json!({
            "type": "socks",
            "tag": tag,
            "server": "127.0.0.1",
            "server_port": mock.port,
            "version": "5",
        }));
        mocks.insert(tag.to_string(), mock);
    }

    let mut route = fragment.route.clone();
    for rule_set in route["rule_set"].as_array_mut().into_iter().flatten() {
        let tag = rule_set["tag"].as_str().unwrap().to_string();
        *rule_set = json!({
            "type": "local",
            "tag": tag,
            "format": "binary",
            "path": format!("{rule_set_dir}/{tag}.srs"),
        });
    }

    let predefined = snapshot["environment"]["dns"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(domain, ip)| (domain.clone(), json!([ip])))
        .collect::<serde_json::Map<_, _>>();
    let proxy_port = unused_loopback_port();
    let config = json!({
        "log": { "level": "warn" },
        "dns": {
            "servers": [
                { "type": "hosts", "tag": "fixture-hosts", "predefined": predefined }
            ],
            "final": "fixture-hosts",
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": proxy_port,
            }
        ],
        "outbounds": outbounds,
        "route": route,
    });

    let work_dir = std::env::temp_dir().join(format!(
        "networkcore-route-equivalence-{}",
        std::process::id()
    ));
    fs::create_dir_all(&work_dir).unwrap();
    let config_path = work_dir.join("config.json");
    fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();

    let check = Command::new(&binary)
        .arg("check")
        .arg("-c")
        .arg(&config_path)
        .output()
        .expect("sing-box check should start");
    assert!(
        check.status.success(),
        "sing-box rejected the rendered config: {}\n{}",
        String::from_utf8_lossy(&check.stderr),
        serde_json::to_string_pretty(&config).unwrap()
    );

    let log_path: PathBuf = work_dir.join("sing-box.log");
    let mut process = SingBoxProcess(
        Command::new(&binary)
            .arg("run")
            .arg("-c")
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log_path).unwrap())
            .spawn()
            .expect("sing-box run should start"),
    );
    let started = Instant::now();
    while TcpStream::connect(("127.0.0.1", proxy_port)).is_err() {
        if let Ok(Some(status)) = process.0.try_wait() {
            panic!(
                "sing-box exited with {status}: {}",
                fs::read_to_string(&log_path).unwrap_or_default()
            );
        }
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "sing-box mixed inbound did not start"
        );
        thread::sleep(Duration::from_millis(100));
    }

    let mut mismatches = Vec::new();
    let static_cases = snapshot["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|case| !case["live"].as_bool().unwrap_or(false));
    for (index, case) in static_cases.enumerate() {
        let destination_port = FIRST_CASE_PORT + index as u16;
        let ip = case["ip"].as_str().map(|ip| ip.parse::<IpAddr>().unwrap());
        connect_through(proxy_port, case["domain"].as_str(), ip, destination_port);

        let expected = expected_tag(case["expected"]["outcome"].as_str().unwrap());
        let deadline = Instant::now() + ROUTE_WAIT;
        let actual = loop {
            let hit = mocks.iter().find_map(|(tag, mock)| {
                mock.destination_ports
                    .lock()
                    .unwrap()
                    .contains(&destination_port)
                    .then(|| tag.clone())
            });
            if hit.is_some() || Instant::now() >= deadline {
                break hit;
            }
            thread::sleep(Duration::from_millis(50));
        };
        if actual != expected {
            mismatches.push(format!(
                "{}: NetworkCore {:?}, sing-box {:?}",
                case["name"], expected, actual
            ));
        }
    }

    drop(process);
    let log = fs::read_to_string(&log_path).unwrap_or_default();
    let _ = fs::remove_dir_all(&work_dir);
    assert!(
        mismatches.is_empty(),
        "sing-box routing differs from RoutingModel::decide:\n{}\nsing-box log:\n{log}",
        mismatches.join("\n")
    );
}
