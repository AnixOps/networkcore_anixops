//! Share links for nodes: the reverse of [`crate::import_text`], from an
//! outbound entry of the embedded engine back to the text other clients
//! import.
//!
//! Shadowsocks gives a SIP002 `ss://` link (base64url credentials), VLESS and
//! Trojan the common `vless://` / `trojan://` query form, VMess a v2rayN
//! `vmess://` JSON link, Hysteria2 and TUIC their `hysteria2://` / `tuic://`
//! links and Snell, which has no link format, a Surge proxy line. Importing
//! the result gives the same outbound entry back. Errors are fixed text
//! without node values.

use serde_json::{json, Value};

use crate::Unsupported;

/// The share link or line for the node `name` with `outbound`.
pub fn share_link(name: &str, outbound: &Value) -> Result<String, Unsupported> {
    let kind = text(outbound, "type").ok_or("outbound type is missing")?;
    let server = text(outbound, "server").ok_or("outbound server is missing")?;
    let port = outbound["port"]
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .ok_or("outbound port is missing")?;
    let endpoint = Endpoint { server, port };
    match kind {
        "shadowsocks" => shadowsocks(name, &endpoint, outbound),
        "vless" => vless(name, &endpoint, outbound),
        "trojan" => trojan(name, &endpoint, outbound),
        "vmess" => vmess(name, &endpoint, outbound),
        "hysteria2" => hysteria2(name, &endpoint, outbound),
        "tuic" => tuic(name, &endpoint, outbound),
        "snell" => snell(name, &endpoint, outbound),
        _ => Err("this protocol has no share link format"),
    }
}

struct Endpoint<'a> {
    server: &'a str,
    port: u16,
}

impl Endpoint<'_> {
    /// `host:port`, with an IPv6 address in brackets.
    fn authority(&self) -> String {
        if self.server.contains(':') {
            format!("[{}]:{}", self.server, self.port)
        } else {
            format!("{}:{}", self.server, self.port)
        }
    }
}

/// A non-empty string field.
fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value[key]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn flag(value: &Value, key: &str) -> bool {
    value[key].as_bool().unwrap_or(false)
}

/// The `alpn` list joined with commas, if any.
fn alpn(value: &Value) -> Option<String> {
    let list: Vec<&str> = value["alpn"]
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    (!list.is_empty()).then(|| list.join(","))
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn query(pairs: &[(&str, Option<String>)]) -> String {
    let pairs: Vec<String> = pairs
        .iter()
        .filter_map(|(key, value)| Some(format!("{key}={}", encode(value.as_deref()?))))
        .collect();
    if pairs.is_empty() {
        String::new()
    } else {
        format!("?{}", pairs.join("&"))
    }
}

fn fragment(name: &str) -> String {
    match name.trim() {
        "" => String::new(),
        name => format!("#{}", encode(name)),
    }
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64; `url_safe` swaps in `-_` and drops the padding.
fn base64(bytes: &[u8], url_safe: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let triple = chunk.iter().enumerate().fold(0u32, |acc, (index, byte)| {
            acc | (u32::from(*byte) << (16 - 8 * index))
        });
        for index in 0..=chunk.len() {
            let sextet = (triple >> (18 - 6 * index)) & 0x3f;
            let symbol = char::from(BASE64[sextet as usize]);
            out.push(match (url_safe, symbol) {
                (true, '+') => '-',
                (true, '/') => '_',
                _ => symbol,
            });
        }
        if !url_safe {
            for _ in chunk.len()..3 {
                out.push('=');
            }
        }
    }
    out
}

fn shadowsocks(name: &str, endpoint: &Endpoint, outbound: &Value) -> Result<String, Unsupported> {
    let method = text(outbound, "method").ok_or("shadowsocks method is missing")?;
    let password = outbound["password"]
        .as_str()
        .filter(|password| !password.is_empty())
        .ok_or("shadowsocks password is missing")?;
    let userinfo = base64(format!("{method}:{password}").as_bytes(), true);
    Ok(format!(
        "ss://{userinfo}@{}{}",
        endpoint.authority(),
        fragment(name)
    ))
}

/// `security`, `sni`, `alpn` and `allowInsecure` of a standard TLS entry.
fn tls_query(tls: &Value) -> Vec<(&'static str, Option<String>)> {
    if tls.is_null() {
        return vec![("security", Some("none".to_string()))];
    }
    vec![
        ("security", Some("tls".to_string())),
        ("sni", text(tls, "server_name").map(str::to_string)),
        ("alpn", alpn(tls)),
        (
            "allowInsecure",
            flag(tls, "insecure").then(|| "1".to_string()),
        ),
    ]
}

/// `type` and its `path`/`host` or `serviceName`.
fn transport_query(transport: &Value) -> Vec<(&'static str, Option<String>)> {
    match text(transport, "type") {
        Some("ws") => vec![
            ("type", Some("ws".to_string())),
            ("path", text(transport, "path").map(str::to_string)),
            ("host", text(transport, "host").map(str::to_string)),
        ],
        Some("grpc") => vec![
            ("type", Some("grpc".to_string())),
            (
                "serviceName",
                text(transport, "service_name").map(str::to_string),
            ),
        ],
        Some("xhttp" | "splithttp") => vec![
            ("type", Some("xhttp".to_string())),
            ("path", text(transport, "path").map(str::to_string)),
            ("host", text(transport, "host").map(str::to_string)),
            ("mode", text(transport, "mode").map(str::to_string)),
            ("extra", xhttp_extra(transport)),
        ],
        _ => vec![("type", Some("tcp".to_string()))],
    }
}

/// The XHTTP settings beyond path, host and mode, as the `extra` JSON of
/// Xray share links, or `None` when all are defaults.
fn xhttp_extra(transport: &Value) -> Option<String> {
    let mut extra = serde_json::Map::new();
    for (field, key) in [
        ("headers", "headers"),
        ("x_padding_bytes", "xPaddingBytes"),
        ("sc_max_each_post_bytes", "scMaxEachPostBytes"),
        ("sc_min_posts_interval_ms", "scMinPostsIntervalMs"),
        ("no_grpc_header", "noGRPCHeader"),
    ] {
        let value = transport.get(field).or_else(|| transport.get(key));
        match value {
            None | Some(Value::Null) | Some(Value::Bool(false)) => {}
            Some(Value::Object(map)) if map.is_empty() => {}
            Some(value) => {
                extra.insert(key.to_string(), value.clone());
            }
        }
    }
    (!extra.is_empty()).then(|| Value::Object(extra).to_string())
}

fn vless(name: &str, endpoint: &Endpoint, outbound: &Value) -> Result<String, Unsupported> {
    let uuid = text(outbound, "uuid").ok_or("vless uuid is missing")?;
    let mut pairs = vec![("encryption", Some("none".to_string()))];
    let reality = &outbound["reality"];
    if reality.is_object() {
        pairs.extend([
            ("security", Some("reality".to_string())),
            ("sni", text(reality, "server_name").map(str::to_string)),
            ("pbk", text(reality, "public_key").map(str::to_string)),
            ("sid", text(reality, "short_id").map(str::to_string)),
            ("fp", text(reality, "fingerprint").map(str::to_string)),
            ("flow", text(outbound, "flow").map(str::to_string)),
        ]);
        pairs.extend(transport_query(&outbound["transport"]));
    } else {
        pairs.extend(tls_query(&outbound["tls"]));
        pairs.extend(transport_query(&outbound["transport"]));
    }
    Ok(format!(
        "vless://{}@{}{}{}",
        encode(uuid),
        endpoint.authority(),
        query(&pairs),
        fragment(name)
    ))
}

fn trojan(name: &str, endpoint: &Endpoint, outbound: &Value) -> Result<String, Unsupported> {
    let password = outbound["password"]
        .as_str()
        .filter(|password| !password.is_empty())
        .ok_or("trojan password is missing")?;
    // Trojan always runs TLS; its TLS fields sit on the outbound itself.
    let mut pairs = tls_query(outbound);
    pairs.extend(transport_query(&outbound["transport"]));
    Ok(format!(
        "trojan://{}@{}{}{}",
        encode(password),
        endpoint.authority(),
        query(&pairs),
        fragment(name)
    ))
}

fn vmess(name: &str, endpoint: &Endpoint, outbound: &Value) -> Result<String, Unsupported> {
    let uuid = text(outbound, "uuid").ok_or("vmess uuid is missing")?;
    let tls = &outbound["tls"];
    let transport = &outbound["transport"];
    let net = match text(transport, "type") {
        Some("ws") => "ws",
        Some("grpc") => "grpc",
        _ => "tcp",
    };
    let service_name = text(transport, "service_name");
    let mut link = json!({
        "v": "2",
        "ps": name.trim(),
        "add": endpoint.server,
        "port": endpoint.port.to_string(),
        "id": uuid,
        "aid": "0",
        "scy": text(outbound, "security").unwrap_or("auto"),
        "net": net,
        "type": "none",
        "host": text(transport, "host").unwrap_or_default(),
        // v2rayN keeps the gRPC service name in `path`.
        "path": text(transport, "path").or(service_name).unwrap_or_default(),
        "tls": if tls.is_null() { "" } else { "tls" },
    });
    if let Some(service_name) = service_name {
        link["serviceName"] = json!(service_name);
    }
    if !tls.is_null() {
        if let Some(server_name) = text(tls, "server_name") {
            link["sni"] = json!(server_name);
        }
        if let Some(alpn) = alpn(tls) {
            link["alpn"] = json!(alpn);
        }
        if flag(tls, "insecure") {
            link["allowInsecure"] = json!("1");
        }
    }
    let link = serde_json::to_string(&link).map_err(|_| "vmess link could not be encoded")?;
    Ok(format!("vmess://{}", base64(link.as_bytes(), false)))
}

/// `sni`, `alpn` and `insecure` of a QUIC outbound.
fn quic_tls_query(
    outbound: &Value,
    insecure_key: &'static str,
) -> Vec<(&'static str, Option<String>)> {
    vec![
        ("sni", text(outbound, "server_name").map(str::to_string)),
        ("alpn", alpn(outbound)),
        (
            insecure_key,
            flag(outbound, "insecure").then(|| "1".to_string()),
        ),
    ]
}

fn hysteria2(name: &str, endpoint: &Endpoint, outbound: &Value) -> Result<String, Unsupported> {
    let password = outbound["password"]
        .as_str()
        .filter(|password| !password.is_empty())
        .ok_or("hysteria2 password is missing")?;
    let mut pairs = quic_tls_query(outbound, "insecure");
    let obfs = &outbound["obfs"];
    if !obfs.is_null() {
        pairs.push(("obfs", text(obfs, "type").map(str::to_string)));
        pairs.push(("obfs-password", text(obfs, "password").map(str::to_string)));
    }
    Ok(format!(
        "hysteria2://{}@{}{}{}",
        encode(password),
        endpoint.authority(),
        query(&pairs),
        fragment(name)
    ))
}

fn tuic(name: &str, endpoint: &Endpoint, outbound: &Value) -> Result<String, Unsupported> {
    let uuid = text(outbound, "uuid").ok_or("tuic uuid is missing")?;
    let password = outbound["password"]
        .as_str()
        .filter(|password| !password.is_empty())
        .ok_or("tuic password is missing")?;
    let mut pairs = quic_tls_query(outbound, "allow_insecure");
    pairs.push((
        "congestion_control",
        text(outbound, "congestion_control").map(str::to_string),
    ));
    Ok(format!(
        "tuic://{}:{}@{}{}{}",
        encode(uuid),
        encode(password),
        endpoint.authority(),
        query(&pairs),
        fragment(name)
    ))
}

/// A Surge `[Proxy]` line; `,` and `=` in the name become spaces.
fn snell(name: &str, endpoint: &Endpoint, outbound: &Value) -> Result<String, Unsupported> {
    let psk = text(outbound, "psk").ok_or("snell psk is missing")?;
    if psk.contains(',') {
        return Err("snell psk cannot be written as a proxy line");
    }
    let name: String = name
        .trim()
        .chars()
        .map(|c| {
            if matches!(c, ',' | '=' | '\n' | '\r') {
                ' '
            } else {
                c
            }
        })
        .collect();
    let name = if name.trim().is_empty() {
        "Snell".to_string()
    } else {
        name.trim().to_string()
    };
    let mut line = format!(
        "{name} = snell, {}, {}, psk={psk}",
        endpoint.server, endpoint.port
    );
    if let Some(version) = outbound["version"].as_u64() {
        line.push_str(&format!(", version={version}"));
    }
    if let Some(mode) = text(outbound, "mode").filter(|mode| *mode != "default") {
        line.push_str(&format!(", mode={mode}"));
    }
    if let Some(obfs) = text(outbound, "obfs") {
        line.push_str(&format!(", obfs={obfs}"));
        if let Some(host) = text(outbound, "obfs_host") {
            line.push_str(&format!(", obfs-host={host}"));
        }
        if let Some(uri) = text(outbound, "obfs_uri") {
            line.push_str(&format!(", obfs-uri={uri}"));
        }
    }
    if flag(outbound, "reuse") {
        line.push_str(", reuse=true");
    }
    if let Some(userkey) = text(outbound, "userkey") {
        line.push_str(&format!(", userkey={userkey}"));
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard_alphabets() {
        assert_eq!(base64(b"", false), "");
        assert_eq!(base64(b"f", false), "Zg==");
        assert_eq!(base64(b"fo", false), "Zm8=");
        assert_eq!(base64(b"foo", false), "Zm9v");
        assert_eq!(base64(b"foob", true), "Zm9vYg");
        assert_eq!(base64(&[0xfb, 0xff], false), "+/8=");
        assert_eq!(base64(&[0xfb, 0xff], true), "-_8");
    }

    #[test]
    fn values_and_hosts_are_escaped() {
        assert_eq!(encode("a b/c?d=é"), "a%20b%2Fc%3Fd%3D%C3%A9");
        let endpoint = Endpoint {
            server: "2001:db8::1",
            port: 443,
        };
        assert_eq!(endpoint.authority(), "[2001:db8::1]:443");
        assert_eq!(
            query(&[
                ("a", Some("1".into())),
                ("b", None),
                ("c", Some("x y".into()))
            ]),
            "?a=1&c=x%20y"
        );
    }
}
