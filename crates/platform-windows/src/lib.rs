//! Windows platform capability boundary for the first NetworkCore Windows CLI artifact.
//!
//! This crate intentionally reports only read-only artifact/package state. Windows service,
//! driver, installer, system proxy mutation, trust store mutation, script dispatch, and
//! managed daemon lifecycle remain blocked for the v0.1.1 alpha packaging path.

pub mod tunnel_config;
pub mod tunnel_runtime;

pub use config_core::windows_tunnel::{
    WindowsTunnelPlan, WindowsTunnelPlanRequest, WindowsTunnelRouteIntent,
};

pub const WINDOWS_PLATFORM_ADAPTER_STATUS: &str =
    "read-only-artifact-capability-active/system-mutation-blocked";
pub const WINDOWS_CLI_ARTIFACT_GATE: &str = "package-windows-active/system-mutation-blocked";
pub const WINDOWS_CLI_SOURCE_IDENTITY: &str = "apps/windows-cli";
pub const WINDOWS_CLI_PACKAGE_STATUS: &str = "defined";
pub const WINDOWS_CLI_RELEASE_ASSETS_STATUS: &str = "enabled-after-attestation-and-publish-gate";
pub const WINDOWS_SYSTEM_MUTATION_POLICY: &str = "none";
pub const WINDOWS_BLOCKED_STATUS: &str = "blocked";
pub const WINDOWS_DEFERRED_STATUS: &str = "deferred";
pub const WINDOWS_ACTIVE_STATUS: &str = "active";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsFeatureStatus {
    pub name: &'static str,
    pub status: &'static str,
    pub mutation_policy: &'static str,
}

impl WindowsFeatureStatus {
    pub const fn active(name: &'static str) -> Self {
        Self {
            name,
            status: WINDOWS_ACTIVE_STATUS,
            mutation_policy: WINDOWS_SYSTEM_MUTATION_POLICY,
        }
    }

    pub const fn blocked(name: &'static str) -> Self {
        Self {
            name,
            status: WINDOWS_BLOCKED_STATUS,
            mutation_policy: WINDOWS_SYSTEM_MUTATION_POLICY,
        }
    }

    pub const fn deferred(name: &'static str) -> Self {
        Self {
            name,
            status: WINDOWS_DEFERRED_STATUS,
            mutation_policy: WINDOWS_SYSTEM_MUTATION_POLICY,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsPlatformSnapshot {
    pub adapter_status: &'static str,
    pub artifact_gate: &'static str,
    pub source_identity: &'static str,
    pub package_windows: WindowsFeatureStatus,
    pub release_assets: WindowsFeatureStatus,
    pub subscription_compatibility: WindowsFeatureStatus,
    pub service: WindowsFeatureStatus,
    pub driver: WindowsFeatureStatus,
    pub installer: WindowsFeatureStatus,
    pub system_proxy_mutation: WindowsFeatureStatus,
    pub trust_store_mutation: WindowsFeatureStatus,
    pub script_dispatch: WindowsFeatureStatus,
    pub managed_lifecycle: WindowsFeatureStatus,
}

impl WindowsPlatformSnapshot {
    pub const fn alpha_cli_artifact() -> Self {
        Self {
            adapter_status: WINDOWS_PLATFORM_ADAPTER_STATUS,
            artifact_gate: WINDOWS_CLI_ARTIFACT_GATE,
            source_identity: WINDOWS_CLI_SOURCE_IDENTITY,
            package_windows: WindowsFeatureStatus::active("package-windows"),
            release_assets: WindowsFeatureStatus::active("windows-release-assets"),
            subscription_compatibility: WindowsFeatureStatus::deferred(
                "subscription-compatibility",
            ),
            service: WindowsFeatureStatus::blocked("windows-service"),
            driver: WindowsFeatureStatus::blocked("windows-driver"),
            installer: WindowsFeatureStatus::blocked("windows-installer"),
            system_proxy_mutation: WindowsFeatureStatus::blocked("system-proxy-mutation"),
            trust_store_mutation: WindowsFeatureStatus::blocked("system-trust-store-mutation"),
            script_dispatch: WindowsFeatureStatus::blocked("javascript-script-dispatch"),
            managed_lifecycle: WindowsFeatureStatus::blocked("managed-daemon-lifecycle"),
        }
    }
}

pub trait WindowsPlatformCapabilityService {
    fn snapshot(&self) -> WindowsPlatformSnapshot;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ReadOnlyWindowsPlatformCapabilityService;

impl ReadOnlyWindowsPlatformCapabilityService {
    pub const fn new() -> Self {
        Self
    }
}

impl WindowsPlatformCapabilityService for ReadOnlyWindowsPlatformCapabilityService {
    fn snapshot(&self) -> WindowsPlatformSnapshot {
        WindowsPlatformSnapshot::alpha_cli_artifact()
    }
}
