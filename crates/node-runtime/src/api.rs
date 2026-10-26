//! Local management API: HTTP/1.1 with JSON bodies, one request per
//! connection, every request authorized by `Authorization: Bearer <token>`.
//!
//! | Method and path | Body | Answer |
//! | --- | --- | --- |
//! | `GET /v1/status` | | `{"version", "types", "inbounds"}` |
//! | `GET /v1/inbounds` | | `{"inbounds": [InboundInfo]}` |
//! | `POST /v1/inbounds` | inbound config | `{"tag", "listen"}` (201) |
//! | `DELETE /v1/inbounds/{tag}` | | `{}` |
//! | `POST /v1/inbounds/{tag}/users` | `{"users": [User]}` | `{"users": n}` |
//! | `POST /v1/inbounds/{tag}/users/remove` | `{"names": [..]}` | `{"removed": n}` |
//! | `GET /v1/inbounds/{tag}/users` | | `{"names": [..]}` |
//! | `GET /v1/inbounds/{tag}/traffic[?reset=true]` | | `{"traffic": [UserTraffic]}` |
//! | `GET /v1/inbounds/{tag}/online` | | `{"online": [OnlineUser]}` |
//!
//! Adding a user that exists replaces it (and closes its connections when the
//! credentials changed). Errors answer `{"error": "..."}` with 400, 401, 404,
//! 409 or 500.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use engine_inbound::User;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::{InboundConfig, Node, NodeError};

const MAX_HEAD_BYTES: usize = 16 * 1024;
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Serves the management API until the listener fails or the task is
/// dropped.
pub async fn serve(listener: TcpListener, node: Arc<Node>, token: String) -> io::Result<()> {
    if token.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "management token must not be empty",
        ));
    }
    let token: Arc<str> = token.into();
    loop {
        let (stream, _) = listener.accept().await?;
        let node = node.clone();
        let token = token.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(REQUEST_TIMEOUT, connection(stream, &node, &token)).await;
        });
    }
}

struct Request {
    method: String,
    path: String,
    query: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

struct Response {
    status: u16,
    body: Value,
}

impl Response {
    fn ok(body: Value) -> Self {
        Self { status: 200, body }
    }

    fn error(status: u16, message: impl Into<String>) -> Self {
        Self {
            status,
            body: json!({ "error": message.into() }),
        }
    }
}

impl From<NodeError> for Response {
    fn from(error: NodeError) -> Self {
        let status = match &error {
            NodeError::NotFound => 404,
            NodeError::Exists => 409,
            NodeError::Invalid(_) => 400,
            NodeError::Io(_) => 500,
        };
        Response::error(status, error.to_string())
    }
}

async fn connection(mut stream: TcpStream, node: &Node, token: &str) -> io::Result<()> {
    let response = match read_request(&mut stream).await {
        Ok(request) if authorized(&request, token) => route(node, request).await,
        Ok(_) => Response::error(401, "unauthorized"),
        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
            Response::error(400, error.to_string())
        }
        Err(error) => return Err(error),
    };
    write_response(&mut stream, response).await
}

async fn read_request(stream: &mut TcpStream) -> io::Result<Request> {
    let mut buffer = Vec::with_capacity(1024);
    let head_end = loop {
        if let Some(end) = find_head_end(&buffer) {
            break end;
        }
        if buffer.len() > MAX_HEAD_BYTES {
            return Err(invalid("request head too large"));
        }
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        buffer.extend_from_slice(&chunk[..n]);
    };
    let head = std::str::from_utf8(&buffer[..head_end]).map_err(|_| invalid("bad request head"))?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next().unwrap_or_default().split(' ');
    let (Some(method), Some(target), Some(_version)) = (
        request_line.next(),
        request_line.next(),
        request_line.next(),
    ) else {
        return Err(invalid("bad request line"));
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut content_length = 0usize;
    let mut authorization = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().map_err(|_| invalid("bad content-length"))?;
        } else if name.eq_ignore_ascii_case("authorization") {
            authorization = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid("chunked bodies are not supported"));
        }
    }
    if content_length > MAX_BODY_BYTES {
        return Err(invalid("request body too large"));
    }
    let mut body = buffer.split_off(head_end + 4);
    if body.len() > content_length {
        return Err(invalid("request body longer than content-length"));
    }
    let already = body.len();
    body.resize(content_length, 0);
    stream.read_exact(&mut body[already..]).await?;
    Ok(Request {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        authorization,
        body,
    })
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn authorized(request: &Request, token: &str) -> bool {
    let Some(presented) = request
        .authorization
        .as_deref()
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    let (a, b) = (presented.as_bytes(), token.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AddUsers {
    users: Vec<User>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveUsers {
    names: Vec<String>,
}

fn parse<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T, Response> {
    serde_json::from_slice(body).map_err(|error| {
        // Only an authorized caller sees this, and at most its own input.
        Response::error(400, format!("invalid request body: {error}"))
    })
}

async fn route(node: &Node, request: Request) -> Response {
    let segments: Vec<&str> = request
        .path
        .trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let result = match (request.method.as_str(), segments.as_slice()) {
        ("GET", ["v1", "status"]) => Ok(Response::ok(json!({
            "version": env!("CARGO_PKG_VERSION"),
            "types": node.types(),
            "inbounds": node.list().len(),
        }))),
        ("GET", ["v1", "inbounds"]) => Ok(Response::ok(json!({ "inbounds": node.list() }))),
        ("POST", ["v1", "inbounds"]) => match parse::<InboundConfig>(&request.body) {
            Ok(config) => {
                let tag = config.tag.clone();
                node.add_inbound(config).await.map(|listen| Response {
                    status: 201,
                    body: json!({ "tag": tag, "listen": listen }),
                })
            }
            Err(response) => return response,
        },
        ("DELETE", ["v1", "inbounds", tag]) => {
            node.remove_inbound(tag).map(|()| Response::ok(json!({})))
        }
        ("GET", ["v1", "inbounds", tag, "users"]) => node
            .users(tag)
            .map(|users| Response::ok(json!({ "names": users.names() }))),
        ("POST", ["v1", "inbounds", tag, "users"]) => match parse::<AddUsers>(&request.body) {
            Ok(add) => node.users(tag).and_then(|users| {
                let count = add.users.len();
                users
                    .add_all(add.users)
                    .map(|()| Response::ok(json!({ "users": count })))
                    .map_err(NodeError::Invalid)
            }),
            Err(response) => return response,
        },
        ("POST", ["v1", "inbounds", tag, "users", "remove"]) => {
            match parse::<RemoveUsers>(&request.body) {
                Ok(remove) => node.users(tag).map(|users| {
                    let removed = remove
                        .names
                        .iter()
                        .filter(|name| users.remove(name))
                        .count();
                    Response::ok(json!({ "removed": removed }))
                }),
                Err(response) => return response,
            }
        }
        ("GET", ["v1", "inbounds", tag, "traffic"]) => {
            let reset = request
                .query
                .split('&')
                .any(|pair| pair == "reset=true" || pair == "reset=1");
            node.users(tag)
                .map(|users| Response::ok(json!({ "traffic": users.traffic(reset) })))
        }
        ("GET", ["v1", "inbounds", tag, "online"]) => node
            .users(tag)
            .map(|users| Response::ok(json!({ "online": users.online() }))),
        _ => return Response::error(404, "no such endpoint"),
    };
    result.unwrap_or_else(Response::from)
}

async fn write_response(stream: &mut TcpStream, response: Response) -> io::Result<()> {
    let body = response.body.to_string();
    let reason = match response.status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Internal Server Error",
    };
    let head = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    stream.shutdown().await
}
