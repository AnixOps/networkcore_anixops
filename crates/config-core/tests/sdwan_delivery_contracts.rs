use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use config_core::sdwan_delivery::{
    normalize_hostname_for_allowed_suffix, DeliveryProfile, SdwanDeliveryVerifier,
    SDWAN_DELIVERY_EXPIRED_CODE, SDWAN_DELIVERY_PAYLOAD_HASH_INVALID_CODE,
};
use serde::Deserialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const MANIFEST: &[u8] =
    include_bytes!("../../../testdata/sdwan-delivery-contract/v1/manifest.json");
const CLIENT_ENVELOPE: &[u8] =
    include_bytes!("../../../testdata/sdwan-delivery-contract/v1/client-envelope.json");
const POP_ENVELOPE: &[u8] =
    include_bytes!("../../../testdata/sdwan-delivery-contract/v1/pop-envelope.json");

#[derive(Debug, Deserialize)]
struct FixtureManifest {
    public_key_base64: String,
    verification_time: String,
    fixtures: Vec<FixtureEntry>,
}

#[derive(Debug, Deserialize)]
struct FixtureEntry {
    file: String,
    expected_signing_input_hex: String,
}

#[test]
fn verifies_controller_client_and_pop_fixtures() {
    let manifest: FixtureManifest = serde_json::from_slice(MANIFEST).expect("fixture manifest");
    let verifier = SdwanDeliveryVerifier::new(
        &STANDARD
            .decode(manifest.public_key_base64)
            .expect("public key"),
    )
    .expect("valid public key");
    let now =
        OffsetDateTime::parse(&manifest.verification_time, &Rfc3339).expect("verification time");

    for fixture in manifest.fixtures {
        let envelope = match fixture.file.as_str() {
            "client-envelope.json" => CLIENT_ENVELOPE,
            "pop-envelope.json" => POP_ENVELOPE,
            _ => panic!("unexpected fixture"),
        };
        let verified = verifier
            .verify_json(envelope, now)
            .expect("controller fixture verifies");
        assert_eq!(
            verified.signing_input_hex(),
            fixture.expected_signing_input_hex
        );
    }
}

#[test]
fn exposes_verified_claims_through_read_only_accessors() {
    let verified = fixture_verifier()
        .verify_json(CLIENT_ENVELOPE, fixture_time())
        .expect("client fixture verifies");

    assert_eq!(verified.bundle_kind(), "client");
    assert_eq!(verified.bundle_id(), "fixture-client-bundle-1");
    assert_eq!(verified.tenant_id(), "fixture-tenant-1");
    assert_eq!(verified.target_id(), "fixture-device-1");
    assert_eq!(verified.sequence(), 1);
    assert_eq!(
        verified.issued_at(),
        OffsetDateTime::parse("2026-07-19T00:00:00Z", &Rfc3339).expect("issued time")
    );
    assert_eq!(
        verified.expires_at(),
        OffsetDateTime::parse("2026-07-19T01:00:00Z", &Rfc3339).expect("expiry time")
    );
    assert_eq!(verified.key_id(), "fixture-ed25519-20260719");
    assert!(std::str::from_utf8(verified.payload())
        .expect("fixture payload is UTF-8")
        .contains("fixture-client-profile-1"));
    assert!(matches!(verified.profile(), DeliveryProfile::Client(_)));
    assert!(!verified.signing_input_hex().is_empty());
}

#[test]
fn rejects_tampered_payload_before_profile_parsing() {
    let verifier = fixture_verifier();
    let mut envelope: serde_json::Value =
        serde_json::from_slice(CLIENT_ENVELOPE).expect("client envelope");
    envelope["payload_base64"] =
        serde_json::Value::String(STANDARD.encode(b"not the signed profile"));
    let error = verifier
        .verify_json(
            &serde_json::to_vec(&envelope).expect("mutated JSON"),
            fixture_time(),
        )
        .expect_err("tamper must fail");
    assert_eq!(error.code, SDWAN_DELIVERY_PAYLOAD_HASH_INVALID_CODE);
}

#[test]
fn rejects_expired_envelope() {
    let error = fixture_verifier()
        .verify_json(
            CLIENT_ENVELOPE,
            OffsetDateTime::parse("2026-07-19T01:00:00Z", &Rfc3339).expect("expired time"),
        )
        .expect_err("expiry must fail");
    assert_eq!(error.code, SDWAN_DELIVERY_EXPIRED_CODE);
}

#[test]
fn normalizes_hostname_only_when_it_matches_an_allowed_suffix_boundary() {
    assert_eq!(
        normalize_hostname_for_allowed_suffix(" Example.COM. ", "example.com"),
        Some("example.com".to_string())
    );
    assert_eq!(
        normalize_hostname_for_allowed_suffix("Api.Example.Com.", "example.com"),
        Some("api.example.com".to_string())
    );
    assert_eq!(
        normalize_hostname_for_allowed_suffix("notexample.com", "example.com"),
        None
    );
    assert_eq!(
        normalize_hostname_for_allowed_suffix("api..example.com", "example.com"),
        None
    );
    assert_eq!(
        normalize_hostname_for_allowed_suffix("api.example.com", ".example.com"),
        None
    );
}

fn fixture_verifier() -> SdwanDeliveryVerifier {
    let manifest: FixtureManifest = serde_json::from_slice(MANIFEST).expect("fixture manifest");
    SdwanDeliveryVerifier::new(
        &STANDARD
            .decode(manifest.public_key_base64)
            .expect("public key"),
    )
    .expect("valid public key")
}

fn fixture_time() -> OffsetDateTime {
    let manifest: FixtureManifest = serde_json::from_slice(MANIFEST).expect("fixture manifest");
    OffsetDateTime::parse(&manifest.verification_time, &Rfc3339).expect("verification time")
}
