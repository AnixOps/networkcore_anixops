use platform_windows::system_integration::WindowsServiceState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiPage {
    Home,
    Nodes,
    Subscriptions,
    Settings,
    Diagnostics,
    Advanced,
}

impl UiPage {
    pub const fn title(self) -> &'static str {
        match self {
            Self::Home => "Home",
            Self::Nodes => "Nodes",
            Self::Subscriptions => "Subscriptions",
            Self::Settings => "Settings",
            Self::Diagnostics => "Diagnostics",
            Self::Advanced => "Advanced",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    ConnectionFailed,
    CoreError,
    ConfigurationError,
}

impl ConnectionState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Disconnected => "Not connected",
            Self::Connecting => "Connecting",
            Self::Connected => "Connected",
            Self::Disconnecting => "Disconnecting",
            Self::ConnectionFailed => "Connection failed",
            Self::CoreError => "Core error",
            Self::ConfigurationError => "Configuration error",
        }
    }

    pub const fn is_connected(self) -> bool {
        matches!(self, Self::Connected)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    Connect,
    Disconnect,
    Service,
    CoreInstall,
    NodeCatalogLoad,
    ProfileImport,
    SubscriptionUpdate,
    NodeSwitch,
    DelayTest,
    ConfigurationCheck,
    Diagnostics,
    Startup,
    Advanced,
}

impl OperationKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Connect => "Connecting",
            Self::Disconnect => "Disconnecting",
            Self::Service => "Updating Windows service",
            Self::CoreInstall => "Installing sing-box core",
            Self::NodeCatalogLoad => "Loading nodes",
            Self::ProfileImport => "Importing profile",
            Self::SubscriptionUpdate => "Updating subscription",
            Self::NodeSwitch => "Switching node",
            Self::DelayTest => "Testing delay",
            Self::ConfigurationCheck => "Checking configuration",
            Self::Diagnostics => "Creating diagnostics",
            Self::Startup => "Updating startup settings",
            Self::Advanced => "Applying advanced change",
        }
    }
}

pub const fn can_start_operation(active: Option<OperationKind>) -> bool {
    active.is_none()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeFacts {
    pub service_state: WindowsServiceState,
    pub sing_box_configured: bool,
    pub sing_box_state_recorded_running: bool,
    pub sing_box_process_running: Option<bool>,
    pub system_proxy_enabled: bool,
    pub last_transition: Option<String>,
    pub last_error: Option<String>,
    pub configuration_error: Option<String>,
}

pub fn connection_state(facts: &RuntimeFacts) -> ConnectionState {
    if facts.configuration_error.is_some() {
        return ConnectionState::ConfigurationError;
    }
    if facts.service_state == WindowsServiceState::StartPending {
        return ConnectionState::Connecting;
    }
    if facts.service_state == WindowsServiceState::StopPending {
        return ConnectionState::Disconnecting;
    }
    if facts.last_transition.as_deref() == Some("failed") {
        return if is_configuration_failure(facts.last_error.as_deref()) {
            ConnectionState::ConfigurationError
        } else {
            ConnectionState::CoreError
        };
    }
    if facts.service_state != WindowsServiceState::Running {
        return ConnectionState::Disconnected;
    }
    if !facts.sing_box_configured {
        return ConnectionState::ConfigurationError;
    }
    if !facts.sing_box_state_recorded_running {
        return ConnectionState::Connecting;
    }
    match facts.sing_box_process_running {
        Some(true) if facts.system_proxy_enabled => ConnectionState::Connected,
        Some(true) => ConnectionState::ConnectionFailed,
        Some(false) => ConnectionState::CoreError,
        None => ConnectionState::ConnectionFailed,
    }
}

pub fn user_facing_error(operation: OperationKind, error: &str) -> String {
    let compact = error.trim().replace(['\r', '\n'], " ");
    let action = operation.label();
    let prefix = if is_configuration_failure(Some(&compact)) {
        "Configuration needs attention"
    } else if compact.contains("service") || compact.contains("SCM") {
        "Windows service did not complete the request"
    } else if compact.contains("sing-box") || compact.contains("core") {
        "Proxy core did not complete the request"
    } else if compact.contains("proxy") {
        "System proxy settings were not changed"
    } else if compact.contains("startup") || compact.contains("Run registry") {
        "Windows startup setting was not changed"
    } else {
        "The operation did not complete"
    };
    format!("{action} failed. {prefix}: {compact}. See Diagnostics for technical details.")
}

fn is_configuration_failure(error: Option<&str>) -> bool {
    error.is_some_and(|error| {
        let error = error.to_ascii_lowercase();
        error.contains("configuration")
            || error.contains("config")
            || error.contains("valid json")
            || error.contains("schema")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> RuntimeFacts {
        RuntimeFacts {
            service_state: WindowsServiceState::Running,
            sing_box_configured: true,
            sing_box_state_recorded_running: true,
            sing_box_process_running: Some(true),
            system_proxy_enabled: true,
            last_transition: Some("running".to_string()),
            last_error: None,
            configuration_error: None,
        }
    }

    #[test]
    fn connected_requires_scm_core_process_and_current_proxy() {
        let mut value = facts();
        assert_eq!(connection_state(&value), ConnectionState::Connected);

        value.sing_box_process_running = Some(false);
        assert_eq!(connection_state(&value), ConnectionState::CoreError);

        value.sing_box_process_running = Some(true);
        value.system_proxy_enabled = false;
        assert_eq!(connection_state(&value), ConnectionState::ConnectionFailed);
    }

    #[test]
    fn configuration_failure_is_not_presented_as_connected() {
        let mut value = facts();
        value.last_transition = Some("failed".to_string());
        value.last_error = Some("managed configuration is not valid JSON".to_string());
        assert_eq!(
            connection_state(&value),
            ConnectionState::ConfigurationError
        );
    }

    #[test]
    fn user_errors_keep_detail_for_diagnostics() {
        let message =
            user_facing_error(OperationKind::NodeSwitch, "sing-box selector rejected node");
        assert!(message.contains("Proxy core"));
        assert!(message.contains("Diagnostics"));
    }

    #[test]
    fn startup_errors_are_distinguished_from_service_errors() {
        let message = user_facing_error(
            OperationKind::Startup,
            "the current-user startup entry could not be written",
        );
        assert!(message.contains("Windows startup setting"));
    }

    #[test]
    fn duplicate_operation_is_rejected_until_the_active_operation_completes() {
        assert!(can_start_operation(None));
        assert!(!can_start_operation(Some(
            OperationKind::SubscriptionUpdate
        )));
    }
}
