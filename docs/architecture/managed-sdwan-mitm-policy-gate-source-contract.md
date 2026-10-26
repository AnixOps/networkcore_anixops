# Managed SD-WAN MITM Policy Gate Source Contract

```text
MANAGED_SDWAN_MITM_POLICY_GATE
MITM_ANIXOPS_RELEASE_TAG=v1.4.7
MITM_ANIXOPS_RELEASE_TAG_OBJECT=d339cc17d2fb8b875ffd278edb2f787aa6b5d4f8
MITM_ANIXOPS_RELEASE_COMMIT=ee952234c35ddf36f2c63f8aa20f28ad744bd054
MITM_ANIXOPS_RELEASE_MANIFEST_SHA256=3e224e94ae08bfc1a99cde886f84577ecbd5f246775b984ae477ee80dc9b3aac
```

## Purpose and provenance

`ManagedSdwanMitmPolicyGate` is a pure admission boundary for an already
verified Plan B `VerifiedDeliveryEnvelope`. Its vendored source is pinned by
the listed commit. The annotated release tag, public GitHub Release, and
published manifest are provenance evidence; the commit hash is the source
content pin and the tag alone is not treated as cryptographic immutability.

`VerifiedDeliveryEnvelope` is an opaque immutable verifier capability. Its
claims, payload, profile, and signing input are available only through
read-only accessors; no public constructor, builder, or mutable access path can
claim verifier provenance. Public gate construction is limited to
`ManagedSdwanMitmPolicyGate::from_linked_core`, which snapshots the linked C
core rather than accepting a caller-provided capability snapshot.

The linked C core still reports `0.45.10`. At construction, the gate snapshots
the deterministic process-global policy capability query. It accepts only query
ABI V1, a returned mask wholly inside the released V1 mask, and caller-required
flags wholly inside that same mask. The core must provide
`POLICY_CAPABILITY_MITM_DECISION` and every caller-required flag.

## Admission

Authorization accepts only a verified `bundle_kind == "client"` envelope with
`DeliveryProfile::Client`, matching profile principal and target, and an
explicit MITM profile. The profile must keep `require_consent`, `block_quic`,
and `block_pinned_tls` true.

Every authorization receives a caller-owned current trusted service clock. The
gate rejects an envelope when `now >= envelope.expires_at()` before it can
return a grant; it does not read an ambient clock, query the network, or mutate
host state.

The hostname is normalized only by `config-core` DNS validation and matches
only when it equals an allowed suffix or ends in `.<allowed suffix>`. A prefix
such as `notexample.com` never matches `example.com`. Authorization also
requires explicit consent, `CertificateTrustState::Trusted`, a non-QUIC
observation, and no pinned-TLS observation.

Failures use stable `managed.sdwan.mitm.*` codes. Their messages do not include
the envelope payload or its base64 representation. A successful grant contains
only tenant id, bundle id, target id, sequence, normalized hostname, and the
granted capability flags.

## Verification and non-goals

GitHub Actions builds and tests the linked C ABI, the V1 query contract,
crate-private synthetic fail-closed core snapshots, immutable verifier output,
expiry-at-authorization, signed client/POP fixtures, suffix boundaries,
host-state denials, and payload-redaction behavior. Local machines do not
compile or test this workspace.

This gate does not parse raw delivery JSON, start a proxy, connect to a POP,
execute a script, install or trust a CA, capture traffic, decrypt TLS, mutate
system or browser proxy settings, or activate any platform data plane.
