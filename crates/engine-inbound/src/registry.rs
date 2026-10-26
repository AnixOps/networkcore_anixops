//! Protocol registry: config `type` names mapped to inbound factories.
//!
//! Works like `engine_outbound::registry`: each protocol crate exports one
//! [`InboundFactory`], the kernel registers the factories it was built with
//! (one per cargo feature) and builds inbounds from config entries by `type`.
//! Stream protocols (served on a TCP listener) and packet protocols (QUIC,
//! served on a UDP socket) have separate factory traits.

use std::collections::BTreeMap;
use std::sync::Arc;

pub use engine_outbound::registry::{parse_settings, BuildError, Settings};

use crate::{PacketInbound, StreamInbound};

/// Builds inbounds of one protocol from its settings.
pub trait InboundFactory: Send + Sync {
    /// The config `type` name, e.g. `"shadowsocks"`.
    fn type_name(&self) -> &'static str;

    fn build(&self, settings: &Settings) -> Result<Arc<dyn StreamInbound>, BuildError>;
}

/// Builds packet (UDP socket) inbounds of one protocol from its settings.
pub trait PacketInboundFactory: Send + Sync {
    fn type_name(&self) -> &'static str;

    fn build(&self, settings: &Settings) -> Result<Arc<dyn PacketInbound>, BuildError>;
}

/// An inbound built from config, by transport kind.
#[derive(Clone)]
pub enum Inbound {
    Stream(Arc<dyn StreamInbound>),
    Packet(Arc<dyn PacketInbound>),
}

impl Inbound {
    pub fn protocol(&self) -> &'static str {
        match self {
            Inbound::Stream(inbound) => inbound.protocol(),
            Inbound::Packet(inbound) => inbound.protocol(),
        }
    }

    pub fn users(&self) -> &Arc<crate::UserStore> {
        match self {
            Inbound::Stream(inbound) => inbound.users(),
            Inbound::Packet(inbound) => inbound.users(),
        }
    }
}

#[derive(Clone, Default)]
pub struct InboundRegistry {
    factories: BTreeMap<&'static str, Arc<dyn InboundFactory>>,
    packet_factories: BTreeMap<&'static str, Arc<dyn PacketInboundFactory>>,
}

impl InboundRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `factory`, replacing any factory with the same type name.
    pub fn register(&mut self, factory: Arc<dyn InboundFactory>) -> &mut Self {
        self.factories.insert(factory.type_name(), factory);
        self
    }

    /// Adds a packet `factory`, replacing any factory with the same name.
    pub fn register_packet(&mut self, factory: Arc<dyn PacketInboundFactory>) -> &mut Self {
        self.packet_factories.insert(factory.type_name(), factory);
        self
    }

    /// Removes the factories for `type_name`. Returns whether one was
    /// registered.
    pub fn unregister(&mut self, type_name: &str) -> bool {
        let stream = self.factories.remove(type_name).is_some();
        let packet = self.packet_factories.remove(type_name).is_some();
        stream || packet
    }

    pub fn contains(&self, type_name: &str) -> bool {
        self.factories.contains_key(type_name) || self.packet_factories.contains_key(type_name)
    }

    /// Registered type names in sorted order.
    pub fn type_names(&self) -> Vec<&'static str> {
        let mut names: Vec<_> = self
            .factories
            .keys()
            .chain(self.packet_factories.keys())
            .copied()
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    pub fn build(&self, type_name: &str, settings: &Settings) -> Result<Inbound, BuildError> {
        if let Some(factory) = self.factories.get(type_name) {
            return factory.build(settings).map(Inbound::Stream);
        }
        if let Some(factory) = self.packet_factories.get(type_name) {
            return factory.build(settings).map(Inbound::Packet);
        }
        Err("inbound type is not supported by this build")
    }
}
