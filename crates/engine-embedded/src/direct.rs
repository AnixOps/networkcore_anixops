//! Direct outbound: connects to the target without a proxy protocol.

use std::io;
use std::sync::Arc;

use engine_outbound::{BoxFuture, BoxStream, Dialer, TargetAddr, TcpOutbound};

pub const PROTOCOL: &str = "direct";

pub struct DirectOutbound {
    dialer: Arc<dyn Dialer>,
}

impl DirectOutbound {
    pub fn new(dialer: Arc<dyn Dialer>) -> Self {
        Self { dialer }
    }
}

impl TcpOutbound for DirectOutbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let host = target.host();
            self.dialer.dial(&host, target.port()).await
        })
    }
}
