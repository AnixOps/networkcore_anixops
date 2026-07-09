use platform_windows::{
    ReadOnlyWindowsPlatformCapabilityService, WindowsPlatformCapabilityService,
    WINDOWS_ACTIVE_STATUS, WINDOWS_BLOCKED_STATUS, WINDOWS_CLI_ARTIFACT_GATE,
    WINDOWS_CLI_RELEASE_ASSETS_STATUS, WINDOWS_CLI_SOURCE_IDENTITY, WINDOWS_DEFERRED_STATUS,
    WINDOWS_PLATFORM_ADAPTER_STATUS,
};

#[test]
fn windows_platform_snapshot_reports_package_path_active_without_system_mutation() {
    let service = ReadOnlyWindowsPlatformCapabilityService::new();
    let snapshot = service.snapshot();

    assert_eq!(snapshot.adapter_status, WINDOWS_PLATFORM_ADAPTER_STATUS);
    assert_eq!(snapshot.artifact_gate, WINDOWS_CLI_ARTIFACT_GATE);
    assert_eq!(snapshot.source_identity, WINDOWS_CLI_SOURCE_IDENTITY);
    assert_eq!(snapshot.package_windows.status, WINDOWS_ACTIVE_STATUS);
    assert_eq!(snapshot.release_assets.status, WINDOWS_ACTIVE_STATUS);
    assert_eq!(
        snapshot.release_assets.name,
        "windows-release-assets",
        "release assets are enabled only after attestation and publish gates"
    );
    assert_eq!(
        WINDOWS_CLI_RELEASE_ASSETS_STATUS,
        "enabled-after-attestation-and-publish-gate"
    );

    assert_eq!(
        snapshot.subscription_compatibility.status,
        WINDOWS_DEFERRED_STATUS
    );
    assert_eq!(snapshot.service.status, WINDOWS_BLOCKED_STATUS);
    assert_eq!(snapshot.driver.status, WINDOWS_BLOCKED_STATUS);
    assert_eq!(snapshot.installer.status, WINDOWS_BLOCKED_STATUS);
    assert_eq!(snapshot.system_proxy_mutation.status, WINDOWS_BLOCKED_STATUS);
    assert_eq!(snapshot.trust_store_mutation.status, WINDOWS_BLOCKED_STATUS);
    assert_eq!(snapshot.script_dispatch.status, WINDOWS_BLOCKED_STATUS);
    assert_eq!(snapshot.managed_lifecycle.status, WINDOWS_BLOCKED_STATUS);
}
