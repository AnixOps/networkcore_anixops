use config_core::{
    parse_config_document, CoreConfigurationService, CONFIG_MIGRATION_UNSUPPORTED_CODE,
    CONFIG_PARSE_FAILED_CODE, CONFIG_PROFILE_CONFLICT_CODE, CONFIG_PROFILE_EMPTY_CODE,
    CONFIG_PROFILE_MISSING_CODE, CONFIG_SCHEMA_UNSUPPORTED_CODE, CURRENT_SCHEMA_VERSION,
};
use control_domain::{
    ConfigurationService, Diagnostic, OperatingSystem, PlatformCapabilities, SchemaVersion,
};

#[test]
fn normalizes_profile_list_from_minimal_toml() {
    let service = CoreConfigurationService::new();
    let snapshot = service
        .normalize(
            r#"
schema_version = 1
profiles = ["default", "work"]
"#,
            &capabilities(),
        )
        .expect("minimal config should normalize");

    assert_eq!(snapshot.version, SchemaVersion::new(CURRENT_SCHEMA_VERSION));
    assert_eq!(
        snapshot.profiles,
        vec!["default".to_string(), "work".to_string()]
    );
    assert!(snapshot.policies.is_empty());
    assert!(snapshot.dns.is_empty());
    assert!(snapshot.plugins.is_empty());
}

#[test]
fn accepts_singular_profile_shortcut() {
    let document = parse_config_document(
        r#"
schema_version = 1
profile = "default"
"#,
    )
    .expect("singular profile should parse");

    assert_eq!(document.profiles, vec!["default".to_string()]);
}

#[test]
fn missing_profile_returns_stable_diagnostic() {
    let service = CoreConfigurationService::new();

    let diagnostics = service.validate("schema_version = 1", &capabilities());

    assert_diagnostic(&diagnostics, CONFIG_PROFILE_MISSING_CODE);
}

#[test]
fn empty_profile_returns_stable_diagnostic() {
    let service = CoreConfigurationService::new();

    let diagnostics = service.validate("profiles = [\"default\", \"   \"]", &capabilities());

    assert_diagnostic(&diagnostics, CONFIG_PROFILE_EMPTY_CODE);
}

#[test]
fn conflicting_profile_shapes_return_stable_diagnostic() {
    let service = CoreConfigurationService::new();
    let diagnostics = service.validate(
        r#"
profile = "default"
profiles = ["work"]
"#,
        &capabilities(),
    );

    assert_diagnostic(&diagnostics, CONFIG_PROFILE_CONFLICT_CODE);
}

#[test]
fn unsupported_schema_version_returns_domain_error() {
    let service = CoreConfigurationService::new();

    let error = service
        .normalize(
            r#"
schema_version = 2
profiles = ["default"]
"#,
            &capabilities(),
        )
        .expect_err("unsupported schema should fail");

    assert_eq!(error.code, CONFIG_SCHEMA_UNSUPPORTED_CODE);
}

#[test]
fn parse_failure_diagnostic_does_not_leak_secret_values() {
    let service = CoreConfigurationService::new();
    let diagnostics = service.validate(
        r#"
token = "super-secret-token"
profiles = [
"#,
        &capabilities(),
    );

    assert_diagnostic(&diagnostics, CONFIG_PARSE_FAILED_CODE);
    assert!(diagnostics.iter().all(|diagnostic| {
        !diagnostic.message.contains("super-secret-token")
            && !diagnostic.message.contains("token =")
    }));
}

#[test]
fn migrate_preserves_same_version_and_rejects_cross_version() {
    let service = CoreConfigurationService::new();
    let raw_config = "profiles = [\"default\"]";

    let unchanged = service
        .migrate(
            raw_config,
            SchemaVersion::new(CURRENT_SCHEMA_VERSION),
            SchemaVersion::new(CURRENT_SCHEMA_VERSION),
        )
        .expect("same version migration should be identity");

    assert_eq!(unchanged, raw_config);

    let error = service
        .migrate(
            raw_config,
            SchemaVersion::new(CURRENT_SCHEMA_VERSION),
            SchemaVersion::new(CURRENT_SCHEMA_VERSION + 1),
        )
        .expect_err("cross-version migration should be explicit");

    assert_eq!(error.code, CONFIG_MIGRATION_UNSUPPORTED_CODE);
}

fn capabilities() -> PlatformCapabilities {
    PlatformCapabilities {
        os: OperatingSystem::Linux,
        supports_tunnel: true,
        supports_mitm: true,
        supports_embedded_runtime: true,
    }
}

fn assert_diagnostic(diagnostics: &[Diagnostic], code: &str) {
    assert!(
        diagnostics.iter().any(|diagnostic| diagnostic.code == code),
        "missing diagnostic {code}: {diagnostics:?}"
    );
}
