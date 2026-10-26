//! Protocol registry: config `type` names mapped to inbound factories.
//!
//! Works like `engine_outbound::registry`: each protocol crate exports one
//! [`InboundFactory`], the kernel registers the factories it was built with
//! (one per cargo feature) and builds inbounds from config entries by `type`.

use std::collections::BTreeMap;
use std::sync::Arc;

pub use engine_outbound::registry::{parse_settings, BuildError, Settings};

use crate::StreamInbound;

/// Builds inbounds of one protocol from its settings.
pub trait InboundFactory: Send + Sync {
    /// The config `type` name, e.g. `"shadowsocks"`.
    fn type_name(&self) -> &'static str;

    fn build(&self, settings: &Settings) -> Result<Arc<dyn StreamInbound>, BuildError>;
}

#[derive(Clone, Default)]
pub struct InboundRegistry {
    factories: BTreeMap<&'static str, Arc<dyn InboundFactory>>,
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

    /// Removes the factory for `type_name`. Returns whether one was registered.
    pub fn unregister(&mut self, type_name: &str) -> bool {
        self.factories.remove(type_name).is_some()
    }

    pub fn contains(&self, type_name: &str) -> bool {
        self.factories.contains_key(type_name)
    }

    /// Registered type names in sorted order.
    pub fn type_names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.factories.keys().copied()
    }

    pub fn build(
        &self,
        type_name: &str,
        settings: &Settings,
    ) -> Result<Arc<dyn StreamInbound>, BuildError> {
        let factory = self
            .factories
            .get(type_name)
            .ok_or("inbound type is not supported by this build")?;
        factory.build(settings)
    }
}
