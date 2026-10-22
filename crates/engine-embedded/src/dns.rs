//! DNS forwarding for the tunnel.
//!
//! UDP/53 queries captured from the TUN interface are re-sent as DNS-over-TCP
//! through the active outbound, so DNS needs no UDP relay and resolves on the
//! proxy side.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use engine_outbound::{TargetAddr, TcpOutbound};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Smallest valid DNS message: the fixed header.
const DNS_HEADER_LEN: usize = 12;
/// Upper bound for a query taken from the tunnel (EDNS0 payloads stay below this).
pub const MAX_QUERY_LEN: usize = 4096;

pub async fn query_over_tcp(
    outbound: &dyn TcpOutbound,
    upstream: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    if query.len() < DNS_HEADER_LEN || query.len() > MAX_QUERY_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS query size is out of range",
        ));
    }
    let exchange = async {
        let target = TargetAddr::Ip(upstream);
        let mut stream = outbound.connect(&target).await?;
        let mut message = Vec::with_capacity(2 + query.len());
        message.extend_from_slice(&(query.len() as u16).to_be_bytes());
        message.extend_from_slice(query);
        stream.write_all(&message).await?;
        stream.flush().await?;

        let mut length = [0u8; 2];
        stream.read_exact(&mut length).await?;
        let length = usize::from(u16::from_be_bytes(length));
        if length < DNS_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS response is too short",
            ));
        }
        let mut response = vec![0u8; length];
        stream.read_exact(&mut response).await?;
        if response[..2] != query[..2] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "DNS response id does not match the query",
            ));
        }
        Ok(response)
    };
    tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out"))?
}
