//! UDP egress for inbounds that relay datagrams (Snell UDP over TCP, and
//! later the UDP modes of other protocols).

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use engine_outbound::{BoxFuture, TargetAddr};

/// Opens UDP sessions toward targets; the node's direct outbound implements
/// it with the same private-target policy as TCP.
pub trait UdpOutbound: Send + Sync {
    /// A socket for one client's UDP session.
    fn bind(&self) -> BoxFuture<'_, io::Result<Arc<dyn UdpSession>>>;
}

/// One client's UDP socket. Sources are reported as plain IPv4 or IPv6
/// addresses (never IPv4-mapped IPv6).
pub trait UdpSession: Send + Sync {
    fn send_to<'a>(
        &'a self,
        payload: &'a [u8],
        target: &'a TargetAddr,
    ) -> BoxFuture<'a, io::Result<()>>;

    fn recv_from<'a>(&'a self, buf: &'a mut [u8])
        -> BoxFuture<'a, io::Result<(usize, SocketAddr)>>;
}
