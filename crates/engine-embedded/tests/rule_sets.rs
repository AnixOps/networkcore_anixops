//! Rule sets from the config: GEOSITE/GEOIP lists, port rules, and remote
//! lists the engine downloads itself.

use std::sync::Arc;

use config_core::routing::RouteOutcome;
use engine_embedded::config::RuntimeConfig;
use engine_embedded::protocols::default_registry;
use engine_embedded::routing::RoutedOutbound;
use engine_outbound::{TargetAddr, TcpDialer};

fn routed(rules: &str, rule_sets: &str) -> Result<Arc<RoutedOutbound>, String> {
    let config = format!(
        r#"{{"schema_version":1,"profile_id":"p","routing":{{"outbounds":{{"hk":{{"type":"direct"}}}},"rules":[{rules}],"rule_sets":{{{rule_sets}}}}}}}"#
    );
    let config = RuntimeConfig::from_json(config.as_bytes()).map_err(|err| err.to_string())?;
    config
        .build_routed(&default_registry(), Arc::new(TcpDialer))
        .map_err(|err| err.to_string())
        .map(|routed| routed.expect("a routing config"))
}

fn domain(name: &str, port: u16) -> TargetAddr {
    TargetAddr::Domain(name.to_string(), port)
}

fn ip(addr: &str) -> TargetAddr {
    TargetAddr::Ip(addr.parse().unwrap())
}

#[test]
fn geosite_and_geoip_rules_match_their_sets() {
    let routed = routed(
        r#""GEOSITE,google,hk","GEOIP,CN,DIRECT,no-resolve","DST-PORT,22,REJECT","FINAL,hk""#,
        r#""geosite-google":{"domain_suffix":["google.com"],"domain":["g.co"]},"geoip-cn":{"ip_cidr":["1.0.1.0/24"]}"#,
    )
    .unwrap();
    let hk = RouteOutcome::Node("hk".to_string());
    assert_eq!(routed.route(&domain("mail.google.com", 443)), hk);
    assert_eq!(routed.route(&domain("g.co", 443)), hk);
    assert_eq!(routed.route(&ip("1.0.1.7:443")), RouteOutcome::Direct);
    assert_eq!(routed.route(&ip("1.0.2.7:22")), RouteOutcome::Reject);
    assert_eq!(routed.route(&ip("1.0.2.7:443")), hk);

    let status = routed.rule_sets().status();
    assert_eq!(status.len(), 2);
    assert_eq!(status[0].name, "geoip-cn");
    assert_eq!(status[0].source, "inline");
    assert_eq!(status[1].entries, 2);
}

#[test]
fn rules_naming_missing_or_bad_sets_are_rejected() {
    assert!(routed(r#""GEOSITE,google,hk","FINAL,hk""#, "").is_err());
    assert!(routed(
        r#""AND,((RULE-SET,ads),(DST-PORT,443)),REJECT","FINAL,hk""#,
        ""
    )
    .is_err());
    // GEOIP without a list never matches, as before.
    assert!(routed(r#""GEOIP,CN,DIRECT","FINAL,hk""#, "").is_ok());
    for set in [
        r#""ads":{"url":"ftp://example.test/list"}"#,
        r#""ads":{"url":"https://example.test/list","interval_secs":60}"#,
        r#""ads":{"url":"https://example.test/list","format":"yaml"}"#,
        r#""ads":{"url":"https://example.test/list","via":"REJECT"}"#,
        r#""ads":{"url":"https://example.test/list","via":"missing"}"#,
        r#""ads":{"interval_secs":3600}"#,
        r#""ads":{"domain":["bad name"]}"#,
    ] {
        assert!(
            routed(r#""RULE-SET,ads,REJECT","FINAL,hk""#, set).is_err(),
            "{set}"
        );
    }
}

#[cfg(feature = "local-proxy")]
mod remote {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    /// Serves `body` to every request and counts them.
    fn list_server(body: &'static str) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/ads.list", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request);
                counter.fetch_add(1, Ordering::SeqCst);
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        (url, hits)
    }

    fn wait_until(mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done() {
            assert!(Instant::now() < deadline, "timed out");
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn remote_sets_download_and_refresh_on_request() {
        let (url, hits) = list_server("payload:\n  - DOMAIN-SUFFIX,ads.test\n  - '+.track.test'\n");
        let routed = routed(
            r#""RULE-SET,ads,REJECT","FINAL,hk""#,
            &format!(r#""ads":{{"url":"{url}","format":"domain"}}"#),
        )
        .unwrap();
        // Before the first download the set is empty.
        assert_eq!(
            routed.route(&domain("x.ads.test", 443)),
            RouteOutcome::Node("hk".to_string())
        );

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.spawn(routed.clone().run_rule_set_updates());
        wait_until(|| routed.rule_sets().status()[0].updated_at_ms.is_some());
        let status = &routed.rule_sets().status()[0];
        assert_eq!(status.source, "remote");
        assert_eq!(status.entries, 2);
        assert_eq!(status.last_error, None);
        assert_eq!(routed.route(&domain("x.ads.test", 443)), RouteOutcome::Reject);
        assert_eq!(routed.route(&domain("a.track.test", 443)), RouteOutcome::Reject);
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        assert_eq!(routed.rule_sets().refresh_now(), 1);
        wait_until(|| hits.load(Ordering::SeqCst) == 2);
        runtime.shutdown_background();
    }

    #[test]
    fn failed_downloads_keep_the_cached_entries() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/gone", listener.local_addr().unwrap());
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request);
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
            }
        });
        let routed = routed(
            r#""RULE-SET,ads,REJECT","FINAL,hk""#,
            &format!(r#""ads":{{"url":"{url}","domain_suffix":["cached.test"]}}"#),
        )
        .unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.spawn(routed.clone().run_rule_set_updates());
        // The cached copy is not empty, so nothing is due until asked.
        routed.rule_sets().refresh_now();
        wait_until(|| routed.rule_sets().status()[0].last_error.is_some());
        let status = &routed.rule_sets().status()[0];
        assert_eq!(status.last_error, Some("http_status"));
        assert_eq!(status.entries, 1);
        assert_eq!(status.updated_at_ms, None);
        assert_eq!(
            routed.route(&domain("www.cached.test", 443)),
            RouteOutcome::Reject
        );
        runtime.shutdown_background();
    }
}
