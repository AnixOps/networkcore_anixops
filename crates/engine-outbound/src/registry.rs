//! Protocol registry: config `type` names mapped to outbound factories.
//!
//! Each protocol crate exports one [`OutboundFactory`]. An engine registers
//! the factories it was built with, usually one per cargo feature, and then
//! builds outbounds from config entries by `type` name. Adding a protocol is a
//! new crate plus one `register` call; removing it is turning its feature off.
//! Nothing outside the protocol crate needs to know its settings.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::{Dialer, TcpOutbound};

/// Protocol-specific settings: every field of a config entry except `type`.
pub type Settings = Map<String, Value>;

/// A fixed, credential-free reason why settings were rejected.
pub type BuildError = &'static str;

/// Builds outbounds of one protocol from its settings.
pub trait OutboundFactory: Send + Sync {
    /// The config `type` name, e.g. `"vless"` or `"shadowsocks"`.
    fn type_name(&self) -> &'static str;

    fn build(
        &self,
        settings: &Settings,
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError>;
}

/// Deserializes `settings` into a protocol's own settings struct.
///
/// The serde error is dropped on purpose: it can quote field values, which
/// may be credentials.
pub fn parse_settings<T: DeserializeOwned>(
    settings: &Settings,
    message: BuildError,
) -> Result<T, BuildError> {
    serde_json::from_value(Value::Object(settings.clone())).map_err(|_| message)
}

#[derive(Clone, Default)]
pub struct OutboundRegistry {
    factories: BTreeMap<&'static str, Arc<dyn OutboundFactory>>,
}

impl OutboundRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `factory`, replacing any factory with the same type name.
    pub fn register(&mut self, factory: Arc<dyn OutboundFactory>) -> &mut Self {
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
        dialer: Arc<dyn Dialer>,
    ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
        let factory = self
            .factories
            .get(type_name)
            .ok_or("outbound type is not supported by this build")?;
        factory.build(settings, dialer)
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use crate::{BoxFuture, BoxStream, TargetAddr, TcpDialer};

    struct Null;

    impl TcpOutbound for Null {
        fn protocol(&self) -> &'static str {
            "null"
        }

        fn connect<'a>(&'a self, _: &'a TargetAddr) -> BoxFuture<'a, io::Result<BoxStream>> {
            Box::pin(async { Err(io::Error::other("null outbound")) })
        }
    }

    struct NullFactory;

    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct NullSettings {
        #[allow(dead_code)]
        tag: Option<String>,
    }

    impl OutboundFactory for NullFactory {
        fn type_name(&self) -> &'static str {
            "null"
        }

        fn build(
            &self,
            settings: &Settings,
            _dialer: Arc<dyn Dialer>,
        ) -> Result<Arc<dyn TcpOutbound>, BuildError> {
            let _: NullSettings = parse_settings(settings, "null settings are invalid")?;
            Ok(Arc::new(Null))
        }
    }

    fn settings(json: &str) -> Settings {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn builds_registered_types_and_rejects_others() {
        let mut registry = OutboundRegistry::new();
        registry.register(Arc::new(NullFactory));
        assert!(registry.contains("null"));
        assert_eq!(registry.type_names().collect::<Vec<_>>(), ["null"]);

        let outbound = registry
            .build("null", &settings("{}"), Arc::new(TcpDialer))
            .unwrap();
        assert_eq!(outbound.protocol(), "null");

        assert_eq!(
            registry
                .build(
                    "null",
                    &settings(r#"{"secret":"hunter2"}"#),
                    Arc::new(TcpDialer)
                )
                .err(),
            Some("null settings are invalid")
        );
        assert!(registry
            .build("vmess", &settings("{}"), Arc::new(TcpDialer))
            .is_err());

        assert!(registry.unregister("null"));
        assert!(!registry.contains("null"));
    }

    #[tokio::test]
    async fn udp_defaults_to_unsupported() {
        let target = TargetAddr::Domain("example.com".into(), 443);
        let result = Null.open_udp(&target).await;
        assert_eq!(
            result.err().map(|err| err.kind()),
            Some(io::ErrorKind::Unsupported)
        );
    }
}
