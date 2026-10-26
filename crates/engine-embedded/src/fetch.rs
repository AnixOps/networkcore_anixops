//! Downloads through an outbound: the plain HTTP/1.1 GET remote rule sets
//! use to refresh while the engine runs.
//!
//! One request per connection, `Connection: close`, no redirects and no
//! compression; the body ends at `Content-Length`, the last chunk of a
//! chunked answer, or the end of the stream. Errors are fixed codes without
//! URLs or payloads.

use std::io;
use std::time::Duration;

use engine_outbound::{BoxStream, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::delay::{tls_for, ProbeUrl};
pub use crate::http1::FetchError;
use crate::http1::{parse_response, MAX_HEAD_BYTES};

/// The body of a `200` answer to a GET of `url` through `outbound`, at most
/// `max_bytes` long, within `timeout`.
pub async fn fetch(
    outbound: &dyn TcpOutbound,
    url: &str,
    timeout: Duration,
    max_bytes: usize,
) -> Result<Vec<u8>, FetchError> {
    let url = ProbeUrl::parse(url).ok_or(FetchError::InvalidUrl)?;
    let tls = tls_for(&url).map_err(|_| FetchError::InvalidUrl)?;
    let exchange = async {
        let mut stream: BoxStream = outbound
            .connect(&url.target())
            .await
            .map_err(|_| FetchError::ConnectFailed)?;
        if let Some(tls) = &tls {
            stream = tls
                .connect(stream)
                .await
                .map_err(|_| FetchError::ConnectFailed)?;
        }
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: networkcore\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            url.path,
            url.host_header()
        );
        let io = |_: io::Error| FetchError::BadResponse;
        stream.write_all(request.as_bytes()).await.map_err(io)?;
        stream.flush().await.map_err(io)?;
        let mut raw = Vec::new();
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            let read = match stream.read(&mut buf).await {
                Ok(read) => read,
                // Many servers reset instead of closing TLS cleanly; what
                // arrived is judged by its framing below.
                Err(_) if !raw.is_empty() => 0,
                Err(_) => return Err(FetchError::BadResponse),
            };
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&buf[..read]);
            if raw.len() > MAX_HEAD_BYTES + max_bytes {
                return Err(FetchError::TooLarge);
            }
        }
        parse_response(&raw, max_bytes)
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .unwrap_or(Err(FetchError::Timeout))
}
