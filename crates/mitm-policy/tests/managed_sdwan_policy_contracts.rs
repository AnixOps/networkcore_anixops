use config_core::sdwan_delivery::{SdwanDeliveryVerifier, VerifiedDeliveryEnvelope};
use control_domain::CertificateTrustState;
use mitm_anixops_sys::{
    policy_capabilities, policy_capability_query_abi_version, POLICY_CAPABILITY_ALL_V1,
    POLICY_CAPABILITY_MITM_DECISION, POLICY_CAPABILITY_QUERY_ABI_VERSION,
    POLICY_CAPABILITY_URL_REWRITE,
};
use mitm_policy::managed_sdwan::{
    ManagedSdwanMitmHostState, ManagedSdwanMitmPolicyGate,
    MANAGED_SDWAN_MITM_BUNDLE_KIND_INVALID_CODE, MANAGED_SDWAN_MITM_CERTIFICATE_UNTRUSTED_CODE,
    MANAGED_SDWAN_MITM_CONSENT_REQUIRED_CODE, MANAGED_SDWAN_MITM_DELIVERY_EXPIRED_CODE,
    MANAGED_SDWAN_MITM_HOSTNAME_NOT_ALLOWED_CODE, MANAGED_SDWAN_MITM_PINNED_TLS_BLOCKED_CODE,
    MANAGED_SDWAN_MITM_QUIC_BLOCKED_CODE,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const CLIENT_ENVELOPE: &[u8] =
    include_bytes!("../../../testdata/sdwan-delivery-contract/v1/client-envelope.json");
const POP_ENVELOPE: &[u8] =
    include_bytes!("../../../testdata/sdwan-delivery-contract/v1/pop-envelope.json");
const FIXTURE_PUBLIC_KEY: [u8; 32] = [
    3, 161, 7, 191, 243, 206, 16, 190, 29, 112, 221, 24, 231, 75, 192, 153, 103, 228, 214, 48, 155,
    165, 13, 95, 29, 220, 134, 100, 18, 85, 49, 184,
];
const FIXTURE_TIME: &str = "2026-07-19T00:05:00Z";

#[test]
fn linked_core_reports_v1_policy_capability_query() {
    assert_eq!(
        policy_capability_query_abi_version(),
        POLICY_CAPABILITY_QUERY_ABI_VERSION
    );

    let capabilities = policy_capabilities();
    assert_eq!(capabilities.bits(), POLICY_CAPABILITY_ALL_V1);
    assert!(capabilities.supports(POLICY_CAPABILITY_MITM_DECISION));
    assert!(capabilities.is_v1_compatible());
}

#[test]
fn admits_verified_client_delivery_with_normalized_allowed_hostname() {
    let required_capabilities = POLICY_CAPABILITY_MITM_DECISION | POLICY_CAPABILITY_URL_REWRITE;
    let gate = ManagedSdwanMitmPolicyGate::from_linked_core(required_capabilities)
        .expect("released core capabilities should admit the gate");

    let grant = gate
        .authorize(
            &client_fixture(),
            "Api.Example.Com.",
            fixture_time(),
            trusted_host_state(),
        )
        .expect("verified client fixture should be admitted");

    assert_eq!(grant.tenant_id, "fixture-tenant-1");
    assert_eq!(grant.bundle_id, "fixture-client-bundle-1");
    assert_eq!(grant.target_id, "fixture-device-1");
    assert_eq!(grant.sequence, 1);
    assert_eq!(grant.normalized_hostname, "api.example.com");
    assert_eq!(grant.granted_capability_flags, required_capabilities);
}

#[test]
fn accepts_exact_and_subdomain_suffixes_without_prefix_matching() {
    let gate = linked_core_gate();

    assert_eq!(
        gate.authorize(
            &client_fixture(),
            "example.com",
            fixture_time(),
            trusted_host_state(),
        )
        .expect("exact suffix should be admitted")
        .normalized_hostname,
        "example.com"
    );
    assert_eq!(
        gate.authorize(
            &client_fixture(),
            "api.example.com",
            fixture_time(),
            trusted_host_state(),
        )
        .expect("subdomain suffix should be admitted")
        .normalized_hostname,
        "api.example.com"
    );

    assert_error_code(
        gate.authorize(
            &client_fixture(),
            "notexample.com",
            fixture_time(),
            trusted_host_state(),
        ),
        MANAGED_SDWAN_MITM_HOSTNAME_NOT_ALLOWED_CODE,
    );
}

#[test]
fn rejects_delivery_or_host_observations_outside_managed_mitm_boundary() {
    let gate = linked_core_gate();

    assert_error_code(
        gate.authorize(
            &pop_fixture(),
            "api.example.com",
            fixture_time(),
            trusted_host_state(),
        ),
        MANAGED_SDWAN_MITM_BUNDLE_KIND_INVALID_CODE,
    );
    assert_error_code(
        gate.authorize(
            &client_fixture(),
            "api.example.com",
            fixture_time(),
            ManagedSdwanMitmHostState {
                consent_granted: false,
                ..trusted_host_state()
            },
        ),
        MANAGED_SDWAN_MITM_CONSENT_REQUIRED_CODE,
    );
    assert_error_code(
        gate.authorize(
            &client_fixture(),
            "api.example.com",
            fixture_time(),
            ManagedSdwanMitmHostState {
                certificate_trust: CertificateTrustState::InstalledUntrusted,
                ..trusted_host_state()
            },
        ),
        MANAGED_SDWAN_MITM_CERTIFICATE_UNTRUSTED_CODE,
    );
    assert_error_code(
        gate.authorize(
            &client_fixture(),
            "api.example.com",
            fixture_time(),
            ManagedSdwanMitmHostState {
                is_quic: true,
                ..trusted_host_state()
            },
        ),
        MANAGED_SDWAN_MITM_QUIC_BLOCKED_CODE,
    );
    assert_error_code(
        gate.authorize(
            &client_fixture(),
            "api.example.com",
            fixture_time(),
            ManagedSdwanMitmHostState {
                pinned_tls_detected: true,
                ..trusted_host_state()
            },
        ),
        MANAGED_SDWAN_MITM_PINNED_TLS_BLOCKED_CODE,
    );
}

#[test]
fn rejects_authorization_at_verified_delivery_expiry() {
    let envelope = client_fixture();

    assert_error_code(
        linked_core_gate().authorize(
            &envelope,
            "api.example.com",
            envelope.expires_at(),
            trusted_host_state(),
        ),
        MANAGED_SDWAN_MITM_DELIVERY_EXPIRED_CODE,
    );
}

#[test]
fn denial_messages_do_not_include_signed_delivery_payload_content() {
    let envelope = client_fixture();
    let payload_text =
        std::str::from_utf8(envelope.payload()).expect("fixture payload should be UTF-8");

    let error = error_from(linked_core_gate().authorize(
        &envelope,
        "notexample.com",
        fixture_time(),
        trusted_host_state(),
    ));

    assert!(!error.message.contains(payload_text));
    assert!(!error.message.contains("ewogICJzY2hlbWFfdmVyc2lvbiI6"));
}

fn linked_core_gate() -> ManagedSdwanMitmPolicyGate {
    ManagedSdwanMitmPolicyGate::from_linked_core(POLICY_CAPABILITY_MITM_DECISION)
        .expect("released core capabilities should admit the gate")
}

fn client_fixture() -> VerifiedDeliveryEnvelope {
    fixture_verifier()
        .verify_json(CLIENT_ENVELOPE, fixture_time())
        .expect("client fixture should verify")
}

fn pop_fixture() -> VerifiedDeliveryEnvelope {
    fixture_verifier()
        .verify_json(POP_ENVELOPE, fixture_time())
        .expect("pop fixture should verify")
}

fn fixture_verifier() -> SdwanDeliveryVerifier {
    SdwanDeliveryVerifier::new(&FIXTURE_PUBLIC_KEY).expect("fixture public key should be valid")
}

fn fixture_time() -> OffsetDateTime {
    OffsetDateTime::parse(FIXTURE_TIME, &Rfc3339).expect("fixture time should parse")
}

fn trusted_host_state() -> ManagedSdwanMitmHostState {
    ManagedSdwanMitmHostState {
        consent_granted: true,
        certificate_trust: CertificateTrustState::Trusted,
        is_quic: false,
        pinned_tls_detected: false,
    }
}

fn assert_error_code<T>(result: Result<T, control_domain::DomainError>, expected_code: &str) {
    assert_eq!(error_from(result).code, expected_code);
}

fn error_from<T>(result: Result<T, control_domain::DomainError>) -> control_domain::DomainError {
    match result {
        Ok(_) => panic!("operation should be denied"),
        Err(error) => error,
    }
}
