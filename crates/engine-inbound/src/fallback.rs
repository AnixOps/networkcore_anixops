//! Conditional fallbacks: where an inbound that fronts for web servers
//! (VLESS, Trojan, AnyTLS) relays a connection that is not its protocol's.
//!
//! `"fallbacks"` in inbound settings is a list of rules. A rule names a
//! destination and up to three conditions on the connection:
//!
//! ```json
//! {"name": "blog.example.com", "alpn": "h2", "path": "/ws",
//!  "dest": "127.0.0.1:8080", "xver": 1}
//! ```
//!
//! - `name`: the server name of the TLS or REALITY handshake in front of
//!   the protocol (case-insensitive).
//! - `alpn`: the ALPN protocol that handshake agreed on.
//! - `path`: the path of the HTTP/1.x request the connection starts with,
//!   without its query.
//! - `dest`: `"host:port"` (an IPv6 address in brackets), or a port on this
//!   host (`8080` or `"8080"`).
//! - `xver`: 1 or 2 writes a PROXY protocol header of that version to the
//!   destination ahead of the client's bytes; 0, the default, writes none.
//!
//! Of the rules whose conditions all hold, the one with the most conditions
//! takes the connection, the earlier one when two have as many. A rule
//! without conditions is the default; the single `"fallback"` setting is
//! that rule. When no rule matches, the connection is held open and drained.
//!
//! The conditions need what the layers in front know ([`ConnInfo`]): the
//! serve loop fills in the addresses, the TLS layer the server name and
//! ALPN. Behind a transport (WebSocket, gRPC, ...) or without TLS only
//! `path` and the default can match.

use std::net::{Ipv4Addr, SocketAddr};

use engine_outbound::{BoxStream, TargetAddr};
use serde::Deserialize;

use crate::proxy_protocol::ProxyProtocol;
use crate::registry::BuildError;
use crate::{fallback_or_hold, Accepted, FallbackSettings, Rejected};

/// What the layers in front of a protocol know about a client connection.
#[derive(Clone, Copy, Debug)]
pub struct ConnInfo<'a> {
    pub peer: SocketAddr,
    /// The address the client reached, when the transport knows it.
    pub local: Option<SocketAddr>,
    /// Server name of the TLS or REALITY handshake in front, if any.
    pub server_name: Option<&'a str>,
    /// ALPN protocol that handshake agreed on.
    pub alpn: Option<&'a [u8]>,
}

impl ConnInfo<'static> {
    /// A connection of which only the peer is known.
    pub fn new(peer: SocketAddr) -> Self {
        Self {
            peer,
            local: None,
            server_name: None,
            alpn: None,
        }
    }
}

impl ConnInfo<'_> {
    /// The same connection behind a TLS handshake that agreed on these.
    pub fn with_tls<'b>(
        self,
        server_name: Option<&'b str>,
        alpn: Option<&'b [u8]>,
    ) -> ConnInfo<'b> {
        ConnInfo {
            peer: self.peer,
            local: self.local,
            server_name,
            alpn,
        }
    }
}

/// One entry of `"fallbacks"` in inbound settings.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FallbackRule {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub alpn: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    pub dest: FallbackDest,
    #[serde(default)]
    pub xver: u8,
}

/// `dest` of a [`FallbackRule`]: a port on this host, or `host:port`.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum FallbackDest {
    Port(u16),
    Address(String),
}

impl FallbackRule {
    /// Where the rule relays to; `None` when `dest` is neither form.
    pub fn target(&self) -> Option<TargetAddr> {
        let local = |port: u16| TargetAddr::Ip(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        match &self.dest {
            FallbackDest::Port(port) => Some(local(*port)),
            FallbackDest::Address(address) => match address.rsplit_once(':') {
                // Only brackets tell the colons of an IPv6 address from the
                // one before the port.
                Some((host, _)) if host.is_empty() || (host.contains(':') && !bracketed(host)) => {
                    None
                }
                Some((host, port)) => Some(TargetAddr::from_host(host, port.parse().ok()?)),
                None => address.parse().ok().map(local),
            },
        }
    }
}

fn bracketed(host: &str) -> bool {
    host.starts_with('[') && host.ends_with(']')
}

struct Rule {
    name: Option<String>,
    alpn: Option<String>,
    path: Option<String>,
    target: TargetAddr,
    proxy_protocol: ProxyProtocol,
}

impl Rule {
    fn new(rule: &FallbackRule) -> Result<Self, BuildError> {
        // As in Xray configs, an empty condition is no condition.
        let set = |value: &Option<String>| value.clone().filter(|value| !value.is_empty());
        let path = set(&rule.path);
        if path.as_ref().is_some_and(|path| !path.starts_with('/')) {
            return Err("fallback path must start with /");
        }
        Ok(Self {
            name: set(&rule.name),
            alpn: set(&rule.alpn),
            path,
            target: rule
                .target()
                .ok_or("fallback dest must be host:port or a port")?,
            proxy_protocol: match rule.xver {
                0 => ProxyProtocol::Off,
                1 => ProxyProtocol::V1,
                2 => ProxyProtocol::V2,
                _ => return Err("fallback xver must be 0, 1 or 2"),
            },
        })
    }

    fn conditions(&self) -> usize {
        [&self.name, &self.alpn, &self.path]
            .into_iter()
            .flatten()
            .count()
    }

    fn matches(&self, conn: &ConnInfo<'_>, path: Option<&str>) -> bool {
        let name = self.name.as_deref().is_none_or(|name| {
            conn.server_name
                .is_some_and(|asked| asked.eq_ignore_ascii_case(name))
        });
        let alpn = self
            .alpn
            .as_deref()
            .is_none_or(|alpn| conn.alpn == Some(alpn.as_bytes()));
        name && alpn && self.path.as_deref().is_none_or(|own| path == Some(own))
    }
}

/// The fallback rules of one inbound; empty when it has none.
#[derive(Default)]
pub struct Fallbacks {
    rules: Vec<Rule>,
}

impl Fallbacks {
    /// The rules of `"fallbacks"`, and `"fallback"` as the rule without
    /// conditions.
    pub fn new(
        default: Option<&FallbackSettings>,
        rules: &[FallbackRule],
    ) -> Result<Self, BuildError> {
        let mut rules = rules.iter().map(Rule::new).collect::<Result<Vec<_>, _>>()?;
        if let Some(default) = default {
            if rules.iter().any(|rule| rule.conditions() == 0) {
                return Err(
                    "fallback and a fallbacks entry without conditions are both the default",
                );
            }
            rules.push(Rule {
                name: None,
                alpn: None,
                path: None,
                target: default.target(),
                proxy_protocol: ProxyProtocol::Off,
            });
        }
        Ok(Self { rules })
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The rule for a connection whose first bytes are `first`.
    fn select(&self, conn: &ConnInfo<'_>, first: &[u8]) -> Option<&Rule> {
        let path = http_path(first);
        // `max_by_key` keeps the last of equals, and the first is wanted.
        self.rules
            .iter()
            .rev()
            .filter(|rule| rule.matches(conn, path))
            .max_by_key(|rule| rule.conditions())
    }

    /// Answers a client that failed authentication: the connection is
    /// relayed to the destination of its rule, starting with the PROXY
    /// protocol header the rule asks for and the bytes already read, and
    /// charged to no user; without a matching rule it is held open and
    /// drained.
    pub fn or_hold(
        &self,
        conn: ConnInfo<'_>,
        consumed: Vec<u8>,
        stream: BoxStream,
        reason: &'static str,
    ) -> Result<Accepted, Rejected> {
        let Some(rule) = self.select(&conn, &consumed) else {
            return Err(Rejected::hold(reason, stream));
        };
        let local = conn
            .local
            .unwrap_or(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        let mut first = rule.proxy_protocol.header(conn.peer, local);
        first.extend_from_slice(&consumed);
        fallback_or_hold(Some(&rule.target), first, stream, reason)
    }
}

/// The path of the HTTP/1.x request `first` starts with
/// (`METHOD SP PATH[?QUERY] SP HTTP/1.x`), without the query.
fn http_path(first: &[u8]) -> Option<&str> {
    let line = first.split(|byte| *byte == b'\r').next()?;
    let mut parts = std::str::from_utf8(line).ok()?.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    let request = !method.is_empty()
        && method.bytes().all(|byte| byte.is_ascii_uppercase())
        && target.starts_with('/')
        && version.starts_with("HTTP/1.");
    request.then(|| target.split_once('?').map_or(target, |(path, _)| path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fallbacks(rules: serde_json::Value) -> Fallbacks {
        let rules: Vec<FallbackRule> = serde_json::from_value(rules).unwrap();
        Fallbacks::new(None, &rules).unwrap()
    }

    fn conn<'a>(server_name: Option<&'a str>, alpn: Option<&'a str>) -> ConnInfo<'a> {
        ConnInfo::new("203.0.113.9:40000".parse().unwrap())
            .with_tls(server_name, alpn.map(str::as_bytes))
    }

    /// The port of the rule that takes the connection.
    fn port(fallbacks: &Fallbacks, conn: ConnInfo<'_>, first: &[u8]) -> Option<u16> {
        fallbacks
            .select(&conn, first)
            .map(|rule| rule.target.port())
    }

    #[test]
    fn reads_the_path_of_an_http1_request() {
        assert_eq!(http_path(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"), Some("/"));
        assert_eq!(http_path(b"POST /ws?ed=2048 HTTP/1.0\r\n"), Some("/ws"));
        assert_eq!(http_path(b"GET /cut HTTP/1.1"), Some("/cut"));
        assert_eq!(http_path(b"GET /cut"), None);
        assert_eq!(http_path(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), None);
        assert_eq!(http_path(b"GET http://a/ HTTP/1.1\r\n"), None);
        assert_eq!(http_path(b"get / HTTP/1.1\r\n"), None);
        assert_eq!(http_path(&[0x16, 0x03, 0x01, 0x02, 0x00]), None);
        assert_eq!(http_path(b""), None);
    }

    #[test]
    fn reads_destinations() {
        let target = |dest: serde_json::Value| {
            serde_json::from_value::<FallbackRule>(serde_json::json!({ "dest": dest }))
                .unwrap()
                .target()
        };
        let ip = |addr: &str| Some(TargetAddr::Ip(addr.parse().unwrap()));
        assert_eq!(target(8080.into()), ip("127.0.0.1:8080"));
        assert_eq!(target("8080".into()), ip("127.0.0.1:8080"));
        assert_eq!(target("192.0.2.1:80".into()), ip("192.0.2.1:80"));
        assert_eq!(target("[2001:db8::1]:80".into()), ip("[2001:db8::1]:80"));
        assert_eq!(
            target("web.example:443".into()),
            Some(TargetAddr::Domain("web.example".into(), 443))
        );
        assert_eq!(target("web.example".into()), None);
        assert_eq!(target(":80".into()), None);
        assert_eq!(target("web.example:http".into()), None);
        // IPv6 addresses without brackets.
        assert_eq!(target("::1".into()), None);
        assert_eq!(target("2001:db8::1".into()), None);
        assert_eq!(target("2001:db8::1:80".into()), None);
    }

    #[test]
    fn the_most_specific_rule_wins() {
        let fallbacks = fallbacks(serde_json::json!([
            {"dest": 1},
            {"alpn": "h2", "dest": 2},
            {"path": "/ws", "dest": 3},
            {"name": "blog.example.com", "dest": 4},
            {"name": "blog.example.com", "alpn": "h2", "dest": 5},
            {"name": "blog.example.com", "path": "/ws", "xver": 2, "dest": 6},
            {"alpn": "http/1.1", "path": "/ws", "dest": 7}
        ]));
        let get = b"GET / HTTP/1.1\r\n\r\n";
        let ws = b"GET /ws?ed=1 HTTP/1.1\r\n\r\n";
        let blog = Some("Blog.Example.com");

        assert_eq!(port(&fallbacks, conn(None, None), b"\x05\x01\x00"), Some(1));
        assert_eq!(port(&fallbacks, conn(Some("other"), None), get), Some(1));
        assert_eq!(port(&fallbacks, conn(None, Some("h2")), b"PRI *"), Some(2));
        assert_eq!(port(&fallbacks, conn(None, None), ws), Some(3));
        assert_eq!(port(&fallbacks, conn(blog, None), get), Some(4));
        assert_eq!(port(&fallbacks, conn(blog, Some("h2")), b"PRI *"), Some(5));
        assert_eq!(port(&fallbacks, conn(blog, None), ws), Some(6));
        assert_eq!(port(&fallbacks, conn(None, Some("http/1.1")), ws), Some(7));
        // Two conditions each: the earlier rule.
        assert_eq!(port(&fallbacks, conn(blog, Some("http/1.1")), ws), Some(6));
        // One condition each.
        assert_eq!(port(&fallbacks, conn(None, Some("h2")), ws), Some(2));
    }

    #[test]
    fn without_a_default_unmatched_connections_are_held() {
        let fallbacks = fallbacks(serde_json::json!([
            {"name": "a.example", "dest": 1},
            {"name": "", "alpn": "", "path": "/x", "dest": 2}
        ]));
        assert!(!fallbacks.is_empty());
        assert_eq!(
            port(&fallbacks, conn(Some("a.example"), None), b""),
            Some(1)
        );
        assert_eq!(port(&fallbacks, conn(Some("b.example"), None), b""), None);
        let get = b"GET /x HTTP/1.1\r\n";
        assert_eq!(
            port(&fallbacks, conn(Some("b.example"), None), get),
            Some(2)
        );
        assert!(Fallbacks::default().is_empty());
        assert_eq!(port(&Fallbacks::default(), conn(None, None), get), None);
    }

    #[test]
    fn the_single_fallback_is_the_default_rule() {
        let single = FallbackSettings {
            server: "127.0.0.1".into(),
            server_port: 9,
        };
        let rules: Vec<FallbackRule> =
            serde_json::from_value(serde_json::json!([{"alpn": "h2", "dest": 2}])).unwrap();
        let fallbacks = Fallbacks::new(Some(&single), &rules).unwrap();
        assert_eq!(port(&fallbacks, conn(None, Some("h2")), b""), Some(2));
        assert_eq!(port(&fallbacks, conn(None, None), b""), Some(9));

        let both: Vec<FallbackRule> =
            serde_json::from_value(serde_json::json!([{"dest": 1}])).unwrap();
        assert!(Fallbacks::new(Some(&single), &both).is_err());
    }

    #[test]
    fn refuses_invalid_rules() {
        for rule in [
            serde_json::json!({"dest": "nowhere"}),
            serde_json::json!({"dest": 80, "xver": 3}),
            serde_json::json!({"dest": 80, "path": "ws"}),
        ] {
            let rule: FallbackRule = serde_json::from_value(rule).unwrap();
            assert!(Fallbacks::new(None, &[rule]).is_err());
        }
        assert!(serde_json::from_value::<FallbackRule>(serde_json::json!({"alpn": "h2"})).is_err());
        assert!(
            serde_json::from_value::<FallbackRule>(serde_json::json!({"dest": 1, "sni": "a"}))
                .is_err()
        );
    }

    #[tokio::test]
    async fn writes_the_proxy_protocol_header_before_the_client_bytes() {
        use tokio::io::AsyncReadExt;

        let fallbacks = fallbacks(serde_json::json!([
            {"dest": 1},
            {"alpn": "h2", "dest": "192.0.2.7:8443", "xver": 1}
        ]));
        let mut info = conn(None, Some("h2"));
        info.local = Some("198.51.100.1:443".parse().unwrap());
        let (client, _server) = tokio::io::duplex(64);
        let Ok(accepted) = fallbacks.or_hold(info, b"PRI".to_vec(), Box::new(client), "not a user")
        else {
            panic!("no rule took the connection");
        };
        assert!(accepted.user.is_none());
        assert_eq!(
            accepted.target,
            TargetAddr::Ip("192.0.2.7:8443".parse().unwrap())
        );
        let expected = b"PROXY TCP4 203.0.113.9 198.51.100.1 40000 443\r\nPRI";
        let mut read = vec![0u8; expected.len()];
        let mut stream = accepted.stream;
        stream.read_exact(&mut read).await.unwrap();
        assert_eq!(read, expected);

        let (client, _server) = tokio::io::duplex(64);
        let held = Fallbacks::default().or_hold(info, Vec::new(), Box::new(client), "not a user");
        assert!(held.is_err_and(|rejected| rejected.stream.is_some()));
    }
}
