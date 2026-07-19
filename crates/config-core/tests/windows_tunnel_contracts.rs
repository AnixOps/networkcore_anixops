use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use config_core::sdwan_delivery::SdwanDeliveryVerifier;
use config_core::windows_tunnel::{
    plan_windows_tunnel, WindowsTunnelPlanRequest, WINDOWS_TUNNEL_POP_NOT_SELECTED_CODE,
    WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE, WINDOWS_TUNNEL_TARGET_MISMATCH_CODE,
};
use serde::Deserialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const MANIFEST: &[u8] =
    include_bytes!("../../../testdata/sdwan-delivery-contract/v1/easytier-manifest.json");
const CLIENT_ENVELOPE: &[u8] =
    include_bytes!("../../../testdata/sdwan-delivery-contract/v1/easytier-client-envelope.json");
const POP_ENVELOPE: &[u8] =
    include_bytes!("../../../testdata/sdwan-delivery-contract/v1/easytier-pop-envelope.json");

#[derive(Debug, Deserialize)]
struct FixtureManifest {
    public_key_base64: String,
    verification_time: String,
}

fn fixture_manifest() -> FixtureManifest {
    serde_json::from_slice(MANIFEST).expect("EasyTier fixture manifest")
}

fn fixture_time(manifest: &FixtureManifest) -> OffsetDateTime {
    OffsetDateTime::parse(&manifest.verification_time, &Rfc3339)
        .expect("EasyTier fixture verification time")
}

fn verified_fixtures() -> (
    config_core::sdwan_delivery::VerifiedDeliveryEnvelope,
    config_core::sdwan_delivery::VerifiedDeliveryEnvelope,
    OffsetDateTime,
) {
    let manifest = fixture_manifest();
    let now = fixture_time(&manifest);
    let verifier = SdwanDeliveryVerifier::new(
        &STANDARD
            .decode(manifest.public_key_base64)
            .expect("EasyTier fixture public key"),
    )
    .expect("valid EasyTier fixture public key");

    (
        verifier
            .verify_json(CLIENT_ENVELOPE, now)
            .expect("signed EasyTier client envelope"),
        verifier
            .verify_json(POP_ENVELOPE, now)
            .expect("signed EasyTier POP envelope"),
        now,
    )
}

#[test]
fn plans_one_selected_easytier_pop_and_destination_routes() {
    let (client, pop, now) = verified_fixtures();
    let plan = plan_windows_tunnel(WindowsTunnelPlanRequest {
        client: &client,
        pop: &pop,
        device_id: "fixture-device-1",
        selected_pop_id: "pop-a",
        last_client_sequence: None,
        last_pop_sequence: None,
        now,
    })
    .expect("valid EasyTier tunnel plan");

    assert_eq!(plan.selected_pop_id, "pop-a");
    assert_eq!(plan.selected_endpoint, "198.51.100.10:11010");
    assert_eq!(plan.route_intents[0].destination_cidr, "203.0.113.0/24");
    assert!(plan.endpoint_bypass_required);
    assert!(!plan.plan_digest.is_empty());
}

#[test]
fn rejects_client_target_mismatch() {
    let (client, pop, now) = verified_fixtures();
    let error = plan_windows_tunnel(WindowsTunnelPlanRequest {
        client: &client,
        pop: &pop,
        device_id: "other-device",
        selected_pop_id: "pop-a",
        last_client_sequence: None,
        last_pop_sequence: None,
        now,
    })
    .expect_err("target mismatch must be rejected");

    assert_eq!(error.code, WINDOWS_TUNNEL_TARGET_MISMATCH_CODE);
}

#[test]
fn rejects_selected_pop_missing_from_client_delivery() {
    let (client, pop, now) = verified_fixtures();
    let error = plan_windows_tunnel(WindowsTunnelPlanRequest {
        client: &client,
        pop: &pop,
        device_id: "fixture-device-1",
        selected_pop_id: "pop-b",
        last_client_sequence: None,
        last_pop_sequence: None,
        now,
    })
    .expect_err("unknown POP must be rejected");

    assert_eq!(error.code, WINDOWS_TUNNEL_POP_NOT_SELECTED_CODE);
}

#[test]
fn rejects_independent_sequence_replay_for_client_or_pop() {
    let (client, pop, now) = verified_fixtures();
    let client_error = plan_windows_tunnel(WindowsTunnelPlanRequest {
        client: &client,
        pop: &pop,
        device_id: "fixture-device-1",
        selected_pop_id: "pop-a",
        last_client_sequence: Some(client.sequence()),
        last_pop_sequence: None,
        now,
    })
    .expect_err("replayed client sequence must be rejected");
    assert_eq!(client_error.code, WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE);

    let pop_error = plan_windows_tunnel(WindowsTunnelPlanRequest {
        client: &client,
        pop: &pop,
        device_id: "fixture-device-1",
        selected_pop_id: "pop-a",
        last_client_sequence: None,
        last_pop_sequence: Some(pop.sequence()),
        now,
    })
    .expect_err("replayed POP sequence must be rejected");
    assert_eq!(pop_error.code, WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE);
}

#[test]
fn plan_digest_is_stable_and_contains_no_secret() {
    let (client, pop, now) = verified_fixtures();
    let request = WindowsTunnelPlanRequest {
        client: &client,
        pop: &pop,
        device_id: "fixture-device-1",
        selected_pop_id: "pop-a",
        last_client_sequence: None,
        last_pop_sequence: None,
        now,
    };
    let first = plan_windows_tunnel(request).expect("first plan");
    let second = plan_windows_tunnel(request).expect("second plan");

    assert_eq!(first.plan_digest, second.plan_digest);
    assert!(!first.plan_digest.contains("secret"));
    assert!(!first.plan_digest.contains("payload"));
}
