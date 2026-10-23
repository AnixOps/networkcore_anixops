//! HTTP/1.x proxy requests: `CONNECT host:port` tunnels and absolute-form
//! plain requests (`GET http://host/path HTTP/1.1`).

use std::io;

use engine_outbound::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::{invalid, Credentials, Reply, Request, MAX_HEAD_BYTES};

pub(crate) fn status_response(code: u16, reason: &str) -> String {
    format!("HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

pub(crate) async fn read_request(
    client: &mut TcpStream,
    credentials: Option<&Credentials>,
) -> io::Result<Request> {
    let (head, rest) = read_head(client).await?;
    let text = std::str::from_utf8(&head).map_err(|_| invalid("http head is not utf-8"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let (Some(method), Some(uri), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        reject(client, 400, "Bad Request").await?;
        return Err(invalid("malformed http request line"));
    };
    if !version.starts_with("HTTP/1.") {
        reject(client, 505, "HTTP Version Not Supported").await?;
        return Err(invalid("unsupported http version"));
    }
    let headers: Vec<&str> = lines.take_while(|line| !line.is_empty()).collect();

    if let Some(expected) = credentials {
        if !authorized(&headers, expected) {
            client
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
Proxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
            return Err(invalid("http proxy authentication failed"));
        }
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let Some(target) = parse_authority(uri, None) else {
            reject(client, 400, "Bad Request").await?;
            return Err(invalid("bad connect authority"));
        };
        // Bytes the client sent after the head belong to the tunnel.
        return Ok(Request {
            target,
            initial: rest,
            reply: Reply::HttpConnect,
        });
    }

    let Some(after_scheme) = uri.strip_prefix("http://") else {
        reject(client, 400, "Bad Request").await?;
        return Err(invalid("http proxy request needs an absolute http uri"));
    };
    let (authority, path) = match after_scheme.find('/') {
        Some(index) => after_scheme.split_at(index),
        None => (after_scheme, "/"),
    };
    let Some(target) = parse_authority(authority, Some(80)) else {
        reject(client, 400, "Bad Request").await?;
        return Err(invalid("bad http authority"));
    };

    // Forward in origin form, drop hop-by-hop proxy headers, and close after
    // one response so a keep-alive request for another host cannot reuse this
    // tunnel.
    let mut initial = format!("{method} {path} {version}\r\n").into_bytes();
    for header in headers {
        let name = header.split(':').next().unwrap_or_default().trim();
        if name.eq_ignore_ascii_case("proxy-connection")
            || name.eq_ignore_ascii_case("proxy-authorization")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("keep-alive")
        {
            continue;
        }
        initial.extend_from_slice(header.as_bytes());
        initial.extend_from_slice(b"\r\n");
    }
    initial.extend_from_slice(b"Connection: close\r\n\r\n");
    initial.extend_from_slice(&rest);
    Ok(Request {
        target,
        initial,
        reply: Reply::HttpForward,
    })
}

/// Reads up to and including the blank line. Returns the head without the
/// final `\r\n\r\n` and any bytes read past it.
async fn read_head(client: &mut TcpStream) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = client.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let search_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_head_end(&buf[search_from..]) {
            let end = search_from + pos;
            let rest = buf.split_off(end + 4);
            buf.truncate(end);
            return Ok((buf, rest));
        }
        if buf.len() > MAX_HEAD_BYTES {
            reject(client, 431, "Request Header Fields Too Large").await?;
            return Err(invalid("http request head is too large"));
        }
    }
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Parses `host:port`, `[v6]:port`, or a bare host when `default_port` is set.
fn parse_authority(authority: &str, default_port: Option<u16>) -> Option<TargetAddr> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(port) => port.parse().ok()?,
            None if after.is_empty() => default_port?,
            None => return None,
        };
        (host, port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().ok()?),
            None => (authority, default_port?),
        }
    };
    if host.is_empty() || port == 0 {
        return None;
    }
    Some(match host.parse() {
        Ok(ip) => TargetAddr::from((ip, port)),
        Err(_) => TargetAddr::Domain(host.to_owned(), port),
    })
}

fn authorized(headers: &[&str], expected: &Credentials) -> bool {
    let wanted = basic_token(expected);
    headers.iter().any(|header| {
        let Some((name, value)) = header.split_once(':') else {
            return false;
        };
        if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
            return false;
        }
        match value.trim().split_once(' ') {
            Some((scheme, token)) => scheme.eq_ignore_ascii_case("basic") && token.trim() == wanted,
            None => false,
        }
    })
}

fn basic_token(credentials: &Credentials) -> String {
    base64_encode(format!("{}:{}", credentials.username, credentials.password).as_bytes())
}

/// Standard base64 with padding; small enough not to need a dependency.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(char::from(ALPHABET[(n >> 18) as usize & 63]));
        out.push(char::from(ALPHABET[(n >> 12) as usize & 63]));
        out.push(if chunk.len() > 1 {
            char::from(ALPHABET[(n >> 6) as usize & 63])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(ALPHABET[n as usize & 63])
        } else {
            '='
        });
    }
    out
}

async fn reject(client: &mut TcpStream, code: u16, reason: &str) -> io::Result<()> {
    client
        .write_all(status_response(code, reason).as_bytes())
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorities_parse_hosts_ips_and_default_ports() {
        assert_eq!(
            parse_authority("example.com:443", None),
            Some(TargetAddr::Domain("example.com".into(), 443))
        );
        assert_eq!(
            parse_authority("example.com", Some(80)),
            Some(TargetAddr::Domain("example.com".into(), 80))
        );
        assert_eq!(parse_authority("example.com", None), None);
        assert_eq!(
            parse_authority("[2001:db8::1]:8443", None),
            Some(TargetAddr::Ip("[2001:db8::1]:8443".parse().unwrap()))
        );
        assert_eq!(
            parse_authority("192.0.2.1:80", None),
            Some(TargetAddr::Ip("192.0.2.1:80".parse().unwrap()))
        );
        assert_eq!(parse_authority(":80", None), None);
        assert_eq!(parse_authority("example.com:0", None), None);
        assert_eq!(parse_authority("[::1]x", Some(80)), None);
    }

    #[test]
    fn base64_matches_rfc_4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), expected);
        }
    }
}
