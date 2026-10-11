# Managed SD-WAN MITM Policy Gate Source Contract

```text
MANAGED_SDWAN_MITM_POLICY_GATE
MITM_ANIXOPS_RELEASE_TAG=v1.4.6
MITM_ANIXOPS_RELEASE_TAG_OBJECT=e1edd61a4a7d7f8c6828f1d791eaa925f2ccc06c
MITM_ANIXOPS_RELEASE_COMMIT=6382f0147e02a8653343571791ef61b8cc885cb1
MITM_ANIXOPS_RELEASE_MANIFEST_SHA256=3922e70f15fd0882b0617507a49ab34e223616937027718d862ba7a764c568fa
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
