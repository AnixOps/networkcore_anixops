//! Rule-based outbound: picks a node per connection with the shared
//! `config-core` routing model.
//!
//! The tunnel only sees destination addresses, so domain rules match only
//! when a caller passes a [`TargetAddr::Domain`]; FakeIP and sniffing are not
//! wired yet, and a domain target that reaches an IP rule without
//! `no-resolve` is rejected because the runtime does not resolve it (the same
//! result sing-box gives for a failed resolve). GeoIP rules never match
//! because the runtime ships no GeoIP database. Policy groups use their
//! static choice (select default or first member); live selection and health
//! checks come later.

use std::collections::BTreeMap;
use std::io;
use std::sync::Arc;

use config_core::routing::{
    RouteOutcome, RouteQuery, RoutingModel, RoutingSpec, StaticRoutingEnvironment,
};
use engine_outbound::{BoxFuture, BoxStream, TargetAddr, TcpOutbound};

use crate::{RuntimeError, RuntimeErrorCode};

pub const PROTOCOL: &str = "routed";

pub struct RoutedOutbound {
    model: RoutingModel,
    direct: Arc<dyn TcpOutbound>,
    nodes: BTreeMap<String, Arc<dyn TcpOutbound>>,
}

impl RoutedOutbound {
    /// Validates `spec` against the node ids in `nodes`. The error message is
    /// fixed so rule text and node settings never reach status or logs.
    pub fn new(
        spec: &RoutingSpec,
        direct: Arc<dyn TcpOutbound>,
        nodes: BTreeMap<String, Arc<dyn TcpOutbound>>,
    ) -> Result<Self, RuntimeError> {
        let node_ids = nodes.keys().cloned().collect();
        let model = RoutingModel::from_spec(spec, &node_ids).map_err(|_| {
            RuntimeError::new(
                RuntimeErrorCode::ConfigRejected,
                "routing rules or policy groups are invalid",
            )
        })?;
        Ok(Self {
            model,
            direct,
            nodes,
        })
    }

    pub fn model(&self) -> &RoutingModel {
        &self.model
    }

    /// Where a connection to `target` goes, before any connect attempt.
    pub fn route(&self, target: &TargetAddr) -> RouteOutcome {
        let query = match target {
            TargetAddr::Ip(addr) => RouteQuery::ip(addr.ip()),
            TargetAddr::Domain(domain, _) => RouteQuery::domain(domain.clone()),
        };
        self.model.decide(&query, &StaticRoutingEnvironment).outcome
    }
}

impl TcpOutbound for RoutedOutbound {
    fn protocol(&self) -> &'static str {
        PROTOCOL
    }

    fn connect<'a>(&'a self, target: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
        Box::pin(async move {
            let outbound = match self.route(target) {
                RouteOutcome::Reject => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "connection rejected by routing rule",
                    ))
                }
                RouteOutcome::Direct => &self.direct,
                RouteOutcome::Node(id) => self.nodes.get(&id).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "routed node is not configured")
                })?,
            };
            outbound.connect(target).await
        })
    }
}
