use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use config_core::sdwan_delivery::{
    SdwanDeliveryVerifier, SDWAN_DELIVERY_EXPIRED_CODE,
    SDWAN_DELIVERY_PAYLOAD_HASH_INVALID_CODE,
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
    let now = OffsetDateTime::parse(&manifest.verification_time, &Rfc3339)
        .expect("verification time");

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
            verified.signing_input_hex,
            fixture.expected_signing_input_hex
        );
    }
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
