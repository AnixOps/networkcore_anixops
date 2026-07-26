# NetworkCore SD-WAN Delivery Verifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make NetworkCore accept only a verified, typed `anixops.sdwan.delivery/v1` client or POP delivery envelope produced by the SD-WAN controller.

**Architecture:** Keep delivery parsing in `config-core`, which remains a pure Rust library with no platform mutation or network I/O. A verifier decodes the exact `payload_base64` bytes, checks their SHA-256 digest, reconstructs the controller's length-prefixed Ed25519 signing input, verifies the signature before parsing the payload, then validates the typed Plan B profile with fail-closed rules. Canonical fixture copies make the Go controller and Rust client contract independently executable in either repository.

**Tech Stack:** Rust 2024 workspace; existing `base64`, `serde`, and `serde_json`; already locked `ring 0.17.14` for Ed25519/SHA-256; already locked `time 0.3.53` with RFC3339 parsing; GitHub Actions only for build and test acceptance.

## Global Constraints

- This feature is one functional commit: `feat: verify signed sdwan delivery envelopes`.
- Do not run `cargo test`, `cargo build`, `cargo run`, or any equivalent local compile/test command; GitHub Actions is the only compiler and test authority for this repository.
- `anixops.sdwan.delivery/v1` is the only accepted envelope and payload schema version.
- Wire payloads use `payload_base64`; verification always hashes and signs its decoded bytes exactly, never a reserialized JSON value.
- Accept only `ed25519`, with the exact signing domain `anixops.sdwan.delivery-signature/v1` and big-endian u32 length-prefixed fields in controller order.
- Verify SHA-256 and Ed25519 before deserializing or validating profile content.
- Require a positive sequence, UTC RFC3339 timestamps, `expires_at > issued_at`, and `expires_at > verification time`.
- A payload kind must match its envelope kind exactly: one `client` or one `pop`, never both or neither.
- Client profiles permit only `ikev2`; MITM requires a nonempty allowlist, explicit consent, blocked QUIC, blocked pinned TLS, and exactly seven metadata-retention days.
- POP routes are fail-closed: at least one route, no `direct_fallback`, a nonempty selector, valid CIDR/protocol/port combinations, nonempty unique hops, and unique optional return hops.
- Do not add private keys, production certificates, packet payload logging, system trust-store changes, or Windows/Linux network mutation.
- Copy only the public SD-WAN contract fixtures from `fac22345ebada4071106da578d28ca176fb6cca7`; no private key or seed is present or permitted.
- All errors use stable `sdwan.delivery.*` codes so callers can display a safe policy outcome without logging payload contents.

## File Structure

- `crates/config-core/src/sdwan_delivery.rs`: pure envelope decoder, signature verifier, typed profiles, and Plan B validation helpers.
- `crates/config-core/src/lib.rs`: exports the delivery module without changing existing configuration/subscription behavior.
- `crates/config-core/tests/sdwan_delivery_contracts.rs`: external contract tests using only the copied public fixture data and controlled byte mutations.
- `crates/config-core/Cargo.toml`: records direct use of the already-locked `ring` and `time` packages.
- `Cargo.lock`: lists `ring` and `time` as direct `config-core` dependencies without changing their locked package versions.
- `testdata/sdwan-delivery-contract/v1/*`: public controller fixtures copied byte-for-byte, with a provenance README.

---

### Task 1: Verify Typed Delivery Envelopes

**Files:**

- Create: `crates/config-core/src/sdwan_delivery.rs`
- Modify: `crates/config-core/src/lib.rs`
- Create: `crates/config-core/tests/sdwan_delivery_contracts.rs`
- Modify: `crates/config-core/Cargo.toml`
- Modify: `Cargo.lock`
- Create: `testdata/sdwan-delivery-contract/v1/README.md`
- Create: `testdata/sdwan-delivery-contract/v1/manifest.json`
- Create: `testdata/sdwan-delivery-contract/v1/client-envelope.json`
- Create: `testdata/sdwan-delivery-contract/v1/pop-envelope.json`

**Interfaces:**

- Produces `config_core::sdwan_delivery::SdwanDeliveryVerifier::new(public_key: &[u8]) -> DomainResult<Self>`.
- Produces `SdwanDeliveryVerifier::verify_json(input: &[u8], now: OffsetDateTime) -> DomainResult<VerifiedDeliveryEnvelope>`.
- Produces public constants `SDWAN_DELIVERY_SCHEMA_V1`, `SDWAN_DELIVERY_SIGNATURE_DOMAIN_V1`, `SDWAN_DELIVERY_SIGNATURE_ALGORITHM`, `SDWAN_DELIVERY_PARSE_FAILED_CODE`, `SDWAN_DELIVERY_PUBLIC_KEY_INVALID_CODE`, `SDWAN_DELIVERY_PAYLOAD_HASH_INVALID_CODE`, `SDWAN_DELIVERY_SIGNATURE_INVALID_CODE`, and `SDWAN_DELIVERY_EXPIRED_CODE`.
- Produces `VerifiedDeliveryEnvelope` with public `bundle_kind`, `bundle_id`, `tenant_id`, `target_id`, `sequence`, `issued_at`, `expires_at`, `key_id`, `payload`, `profile`, and `signing_input_hex` fields.
- Uses `DeliveryProfile`, `ClientDeliveryProfile`, `PopDeliveryProfile`, `DeliveryRoutePolicy`, `DeliveryRouteSelector`, `DeliveryPortRange`, `DeliveryServiceChain`, `DeliveryPopReference`, and `DeliveryMitmProfile` as typed public output values.

- [ ] **Step 1: Copy the public fixture boundary and write the failing contract tests**

Copy `manifest.json`, `client-envelope.json`, and `pop-envelope.json` byte-for-byte from `/root/code/.worktrees/sdwan-plan-b-control/testdata/controlcontract/v1/`. Write the fixture README with source commit `fac22345ebada4071106da578d28ca176fb6cca7`, source path, public-only key statement, and no-private-material statement.

Create `crates/config-core/tests/sdwan_delivery_contracts.rs` around the following concrete behaviors:

```rust
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use config_core::sdwan_delivery::{
    SdwanDeliveryVerifier, SDWAN_DELIVERY_EXPIRED_CODE,
    SDWAN_DELIVERY_PAYLOAD_HASH_INVALID_CODE,
};
use serde::Deserialize;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const MANIFEST: &[u8] = include_bytes!("../../../testdata/sdwan-delivery-contract/v1/manifest.json");
const CLIENT_ENVELOPE: &[u8] = include_bytes!("../../../testdata/sdwan-delivery-contract/v1/client-envelope.json");
const POP_ENVELOPE: &[u8] = include_bytes!("../../../testdata/sdwan-delivery-contract/v1/pop-envelope.json");

#[test]
fn verifies_controller_client_and_pop_fixtures() {
    let manifest: FixtureManifest = serde_json::from_slice(MANIFEST).expect("fixture manifest");
    let verifier = SdwanDeliveryVerifier::new(
        &STANDARD.decode(manifest.public_key_base64).expect("public key"),
    )
    .expect("valid public key");
    let now = OffsetDateTime::parse(&manifest.verification_time, &Rfc3339).expect("verification time");

    for fixture in manifest.fixtures {
        let envelope = match fixture.file.as_str() {
            "client-envelope.json" => CLIENT_ENVELOPE,
            "pop-envelope.json" => POP_ENVELOPE,
            _ => panic!("unexpected fixture"),
        };
        let verified = verifier.verify_json(envelope, now).expect("controller fixture verifies");
        assert_eq!(verified.signing_input_hex, fixture.expected_signing_input_hex);
    }
}

#[test]
fn rejects_tampered_payload_before_profile_parsing() {
    let verifier = fixture_verifier();
    let mut envelope: serde_json::Value = serde_json::from_slice(CLIENT_ENVELOPE).expect("client envelope");
    envelope["payload_base64"] = serde_json::Value::String(STANDARD.encode(b"not the signed profile"));
    let error = verifier.verify_json(&serde_json::to_vec(&envelope).expect("mutated JSON"), fixture_time()).expect_err("tamper must fail");
    assert_eq!(error.code, SDWAN_DELIVERY_PAYLOAD_HASH_INVALID_CODE);
}

#[test]
fn rejects_expired_envelope() {
    let error = fixture_verifier().verify_json(
        CLIENT_ENVELOPE,
        OffsetDateTime::parse("2026-07-19T01:00:00Z", &Rfc3339).expect("expired time"),
    ).expect_err("expiry must fail");
    assert_eq!(error.code, SDWAN_DELIVERY_EXPIRED_CODE);
}
```

Define local `FixtureManifest` and `FixtureEntry` serde structs plus `fixture_verifier()` and `fixture_time()` helpers in the test file. This test must not need an HTTP service, a real CA, or a platform runtime.

- [ ] **Step 2: Preserve the red state without local compilation**

Do not run Cargo locally because `AGENT.md` forbids it. Confirm by inspection that the test imports `config_core::sdwan_delivery`, which does not exist before implementation. Record in the task report that the expected pre-implementation CI failure is unresolved import/module absence, and defer the actual red/green execution to the single GitHub Actions acceptance run after the feature commit.

- [ ] **Step 3: Add the minimal pure verifier implementation**

Create `crates/config-core/src/sdwan_delivery.rs` with this public surface and error codes:

```rust
pub const SDWAN_DELIVERY_SCHEMA_V1: &str = "anixops.sdwan.delivery/v1";
pub const SDWAN_DELIVERY_SIGNATURE_DOMAIN_V1: &str = "anixops.sdwan.delivery-signature/v1";
pub const SDWAN_DELIVERY_SIGNATURE_ALGORITHM: &str = "ed25519";
pub const SDWAN_DELIVERY_PARSE_FAILED_CODE: &str = "sdwan.delivery.parse_failed";
pub const SDWAN_DELIVERY_PUBLIC_KEY_INVALID_CODE: &str = "sdwan.delivery.public_key_invalid";
pub const SDWAN_DELIVERY_PAYLOAD_HASH_INVALID_CODE: &str = "sdwan.delivery.payload_hash_invalid";
pub const SDWAN_DELIVERY_SIGNATURE_INVALID_CODE: &str = "sdwan.delivery.signature_invalid";
pub const SDWAN_DELIVERY_EXPIRED_CODE: &str = "sdwan.delivery.expired";

#[derive(Debug, Clone)]
pub struct SdwanDeliveryVerifier { /* exactly 32 public-key bytes */ }

impl SdwanDeliveryVerifier {
    pub fn new(public_key: &[u8]) -> DomainResult<Self>;
    pub fn verify_json(
        &self,
        input: &[u8],
        now: OffsetDateTime,
    ) -> DomainResult<VerifiedDeliveryEnvelope>;
}
```

Use a private `SignedEnvelopeWire` with `#[serde(deny_unknown_fields)]` and JSON fields exactly named `schema_version`, `bundle_kind`, `bundle_id`, `tenant_id`, `target_id`, `sequence`, `issued_at`, `expires_at`, `key_id`, `payload_base64`, `algorithm`, `payload_sha256`, and `signature`. Trim and reject empty identifier fields; accept lowercase `client` and `pop` only; reject unknown enum values through serde.

Build signing input with the exact field order below, appending every byte slice as `u32::to_be_bytes(length)` followed by the bytes:

```text
anixops.sdwan.delivery-signature/v1
schema_version
bundle_kind
bundle_id
tenant_id
target_id
decimal sequence
issued_at wire string
expires_at wire string
key_id
32-byte SHA-256 payload digest
```

The verification order is mandatory:

```text
deserialize envelope -> check envelope metadata -> base64 decode payload -> decode/hash compare
-> reconstruct signing input -> decode/verify Ed25519 -> parse payload JSON -> bind payload kind and target IDs -> validate Plan B policy fields -> return typed value
```

Use `ring::digest::SHA256` and `ring::signature::ED25519`; compare the lowercase hexadecimal digest exactly. Parse timestamps with `time::format_description::well_known::Rfc3339`; require `UtcOffset::UTC`, `expires_at > issued_at`, and `expires_at > now`. Signature/profile parse failures must not expose decoded payload data in `DomainError.message`.

Validate payload fields exactly as follows:

```text
client: nonempty id/principal_id, transport == ikev2, nonempty POP id/endpoint list,
        endpoint parses with a nonzero port, optional MITM only with a nonempty valid
        ASCII DNS-suffix allowlist, require_consent == true, block_quic == true,
        block_pinned_tls == true, metadata_retention_days == 7.
pop:    nonempty id/principal_id and nonempty routes;
route:  nonempty id, direct_fallback == false, selector has at least one condition,
        CIDR is an IP address followed by a valid prefix, protocol is tcp or udp,
        a port range needs a protocol and has 1 <= start <= end <= 65535;
chain:  nonempty id, nonempty unique hops, optional unique return_hops.
```

Export the module by adding this one line after the crate documentation in `crates/config-core/src/lib.rs`:

```rust
pub mod sdwan_delivery;
```

- [ ] **Step 4: Declare only direct locked dependencies**

Add the following dependencies to `crates/config-core/Cargo.toml` in alphabetical order and add only their names to the existing `config-core` dependency list in `Cargo.lock`:

```toml
ring = "0.17"
time = { version = "0.3", features = ["parsing"] }
```

Do not change the existing resolved `ring 0.17.14` or `time 0.3.53` package entries, and do not regenerate the lock file locally.

- [ ] **Step 5: Inspect, commit, push, and make GitHub Actions the acceptance gate**

Run only non-build local checks:

```bash
git diff --check
git diff -- crates/config-core/src/lib.rs crates/config-core/src/sdwan_delivery.rs crates/config-core/tests/sdwan_delivery_contracts.rs crates/config-core/Cargo.toml Cargo.lock testdata/sdwan-delivery-contract/v1 docs/superpowers/plans/2026-07-19-sdwan-delivery-verifier.md
git status --short
```

Commit all files above as one feature:

```bash
git add crates/config-core/src/lib.rs crates/config-core/src/sdwan_delivery.rs crates/config-core/tests/sdwan_delivery_contracts.rs crates/config-core/Cargo.toml Cargo.lock testdata/sdwan-delivery-contract/v1 docs/superpowers/plans/2026-07-19-sdwan-delivery-verifier.md
git commit -m "feat: verify signed sdwan delivery envelopes"
git push -u origin feat/plan-b-networkcore-windows
gh workflow run CI --repo AnixOps/networkcore_anixops --ref feat/plan-b-networkcore-windows
```

Wait for that exact GitHub Actions run. It must compile the workspace and pass the new fixture tests before another functional feature begins. If it fails, inspect only the CI log, amend the same feature through a new corrective commit, push, and run CI again.
