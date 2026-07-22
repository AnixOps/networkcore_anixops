//! Windows platform integration for NetworkCore clients and managed runtime hosts.

pub mod managed;
pub mod system_integration;
pub mod tunnel_config;
pub mod tunnel_runtime;
pub mod tunnel_security;

pub use config_core::windows_tunnel::{
    WindowsTunnelPlan, WindowsTunnelPlanRequest, WindowsTunnelRouteIntent,
};

pub const WINDOWS_PLATFORM_ADAPTER_STATUS: &str = "managed-client-platform-active";
pub const WINDOWS_CLI_ARTIFACT_GATE: &str = "windows-managed-client-active";
pub const WINDOWS_CLI_SOURCE_IDENTITY: &str = "apps/windows-cli";
pub const WINDOWS_CLI_PACKAGE_STATUS: &str = "defined";
pub const WINDOWS_CLI_RELEASE_ASSETS_STATUS: &str = "enabled-after-attestation-and-publish-gate";
pub const WINDOWS_SYSTEM_MUTATION_POLICY: &str = "managed-apply-and-rollback";
pub const WINDOWS_BLOCKED_STATUS: &str = "blocked";
pub const WINDOWS_DEFERRED_STATUS: &str = "deferred";
pub const WINDOWS_ACTIVE_STATUS: &str = "active";
pub const WINDOWS_FOREGROUND_TUNNEL_MUTATION_POLICY: &str =
    "explicit-confirm-external-easytier-only";
pub const WINDOWS_MANAGED_MUTATION_POLICY: &str = "service-owned-managed-apply-and-rollback";

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
    pub foreground_tunnel: WindowsFeatureStatus,
    pub service: WindowsFeatureStatus,
    pub driver: WindowsFeatureStatus,
    pub installer: WindowsFeatureStatus,
    pub system_proxy_mutation: WindowsFeatureStatus,
    pub trust_store_mutation: WindowsFeatureStatus,
    pub script_dispatch: WindowsFeatureStatus,
    pub managed_lifecycle: WindowsFeatureStatus,
}

impl WindowsPlatformSnapshot {
    pub const fn managed_client() -> Self {
        Self {
            adapter_status: WINDOWS_PLATFORM_ADAPTER_STATUS,
            artifact_gate: WINDOWS_CLI_ARTIFACT_GATE,
            source_identity: WINDOWS_CLI_SOURCE_IDENTITY,
            package_windows: WindowsFeatureStatus::active("package-windows"),
            release_assets: WindowsFeatureStatus::active("windows-release-assets"),
            subscription_compatibility: WindowsFeatureStatus::deferred(
                "subscription-compatibility",
            ),
            foreground_tunnel: WindowsFeatureStatus {
                name: "foreground-tunnel",
                status: WINDOWS_ACTIVE_STATUS,
                mutation_policy: WINDOWS_FOREGROUND_TUNNEL_MUTATION_POLICY,
            },
            service: WindowsFeatureStatus {
                name: "windows-service",
                status: WINDOWS_ACTIVE_STATUS,
                mutation_policy: WINDOWS_MANAGED_MUTATION_POLICY,
            },
            driver: WindowsFeatureStatus {
                name: "windows-driver",
                status: WINDOWS_ACTIVE_STATUS,
                mutation_policy: WINDOWS_MANAGED_MUTATION_POLICY,
            },
            installer: WindowsFeatureStatus {
                name: "windows-installer",
                status: WINDOWS_ACTIVE_STATUS,
                mutation_policy: WINDOWS_MANAGED_MUTATION_POLICY,
            },
            system_proxy_mutation: WindowsFeatureStatus {
                name: "system-proxy-mutation",
                status: WINDOWS_ACTIVE_STATUS,
                mutation_policy: WINDOWS_MANAGED_MUTATION_POLICY,
            },
            trust_store_mutation: WindowsFeatureStatus {
                name: "system-trust-store-mutation",
                status: WINDOWS_ACTIVE_STATUS,
                mutation_policy: WINDOWS_MANAGED_MUTATION_POLICY,
            },
            script_dispatch: WindowsFeatureStatus::blocked("javascript-script-dispatch"),
            managed_lifecycle: WindowsFeatureStatus {
                name: "managed-daemon-lifecycle",
                status: WINDOWS_ACTIVE_STATUS,
                mutation_policy: WINDOWS_MANAGED_MUTATION_POLICY,
            },
        }
    }

    pub const fn alpha_cli_artifact() -> Self {
        Self::managed_client()
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
        WindowsPlatformSnapshot::managed_client()
    }
}
