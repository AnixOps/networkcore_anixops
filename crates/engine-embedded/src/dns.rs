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

/// Why a forwarded query or flow failed: the stage and the error kind, never
/// an address or payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OutboundFailure {
    /// The query taken from the tunnel is not a usable DNS message.
    QueryInvalid = 1,
    /// Dialing the proxy server timed out.
    ConnectTimeout,
    ConnectRefused,
    ConnectUnreachable,
    ConnectFailed,
    /// The proxy accepted the connection but no reply arrived in time.
    ReplyTimeout,
    /// The proxy closed or reset the connection before replying.
    ReplyClosed,
    /// The reply failed authentication or did not parse.
    ReplyRejected,
    ReplyFailed,
}

impl OutboundFailure {
    const ALL: [Self; 9] = [
        Self::QueryInvalid,
        Self::ConnectTimeout,
        Self::ConnectRefused,
        Self::ConnectUnreachable,
        Self::ConnectFailed,
        Self::ReplyTimeout,
        Self::ReplyClosed,
        Self::ReplyRejected,
        Self::ReplyFailed,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::QueryInvalid => "query_invalid",
            Self::ConnectTimeout => "connect_timeout",
            Self::ConnectRefused => "connect_refused",
            Self::ConnectUnreachable => "connect_unreachable",
            Self::ConnectFailed => "connect_failed",
            Self::ReplyTimeout => "reply_timeout",
            Self::ReplyClosed => "reply_closed",
            Self::ReplyRejected => "reply_rejected",
            Self::ReplyFailed => "reply_failed",
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|failure| *failure as u8 == code)
    }

    /// Classifies an error from dialing the proxy server.
    pub fn connect(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::TimedOut => Self::ConnectTimeout,
            io::ErrorKind::ConnectionRefused => Self::ConnectRefused,
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
                Self::ConnectUnreachable
            }
            _ => Self::ConnectFailed,
        }
    }

    /// Classifies an error after the proxy connection was open.
    pub fn reply(err: &io::Error) -> Self {
        match err.kind() {
            io::ErrorKind::TimedOut => Self::ReplyTimeout,
            io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe => Self::ReplyClosed,
            io::ErrorKind::InvalidData => Self::ReplyRejected,
            _ => Self::ReplyFailed,
        }
    }
}

pub async fn query_over_tcp(
    outbound: &dyn TcpOutbound,
    upstream: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, OutboundFailure> {
    if query.len() < DNS_HEADER_LEN || query.len() > MAX_QUERY_LEN {
        return Err(OutboundFailure::QueryInvalid);
    }
    let deadline = tokio::time::Instant::now() + timeout;
    let target = TargetAddr::Ip(upstream);
    let mut stream = match tokio::time::timeout_at(deadline, outbound.connect(&target)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return Err(OutboundFailure::connect(&err)),
        Err(_) => return Err(OutboundFailure::ConnectTimeout),
    };
    let exchange = async {
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
    match tokio::time::timeout_at(deadline, exchange).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(err)) => Err(OutboundFailure::reply(&err)),
        Err(_) => Err(OutboundFailure::ReplyTimeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_codes_round_trip() {
        for failure in OutboundFailure::ALL {
            assert_eq!(OutboundFailure::from_code(failure as u8), Some(failure));
        }
        assert_eq!(OutboundFailure::from_code(0), None);
    }

    #[test]
    fn errors_are_classified_by_stage() {
        let eof = io::Error::from(io::ErrorKind::UnexpectedEof);
        let invalid = io::Error::from(io::ErrorKind::InvalidData);
        let refused = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(OutboundFailure::reply(&eof), OutboundFailure::ReplyClosed);
        assert_eq!(
            OutboundFailure::reply(&invalid),
            OutboundFailure::ReplyRejected
        );
        assert_eq!(
            OutboundFailure::connect(&refused),
            OutboundFailure::ConnectRefused
        );
    }
}
