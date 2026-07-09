# ADR 0002: Public Engine Adapter First

## Status

Accepted.

## Context

`networkcore-linux v0.1.0-alpha.12` is the latest published Linux CLI artifact
at the time of this ADR status refresh. The release path proves that the
repository can publish a Linux CLI artifact through GitHub Actions. It does not
provide native support for VLESS, Shadowsocks,
Trojan, VMess, Hysteria, TUIC, Reality, WebSocket, gRPC, UDP relay, or full DNS
policy execution.

Maintaining those protocols inside a private protocol engine would introduce a
large compatibility, security, and release burden before the control plane,
subscription model, policy routing, DNS policy, platform adapters, and UI/API
surfaces are mature enough to benefit from it.

The repository already defines `ProxyEngineService` as an adapter port, and ADR
0001 deliberately keeps `sing-box`, `xray-core`, and `mihomo` outside the domain
layer. The next runtime-capability increment should use that adapter boundary
instead of expanding private protocol implementation first.

## Decision

Prioritize public execution engine adapters before private protocol expansion.

The maintained architecture is a three-layer operating model:

1. Control layer: NetworkCore owns configuration normalization, subscription
   ingestion, policy routing intent, DNS policy intent, MITM/plugin permissions,
   platform capability snapshots, audit diagnostics, CLI/API contracts, release
   gates, and user-facing state.
2. Adapter layer: `engine-*` crates translate NetworkCore domain models into a
   concrete execution engine contract, manage lifecycle, reload, status, events,
   logs, config redaction, binary/provenance checks, and rollback boundaries.
3. Execution layer: public engines such as `sing-box` first, then optionally
   `xray-core` and `mihomo`, provide the protocol data plane for VLESS,
   Shadowsocks, Trojan, VMess, Hysteria, and related mature transports.

`engine-native` remains a private execution-engine lane, but private protocol implementation is deferred.
It should continue only as a small, auditable runtime skeleton until a
public-engine adapter exposes a concrete gap that cannot be solved through the
adapter layer.

The first public-engine target is `sing-box` because it covers the highest value
protocol set for early Linux/macOS/Windows use while allowing NetworkCore to
retain ownership of its own normalized configuration and policy model.

## Scope

Immediate scope:

- define a `sing-box` adapter design and source contract;
- keep public engine binaries out of the repository until packaging, licensing,
  checksum, provenance, and release gates are explicitly defined;
- support an operator-provided public engine binary path before bundling any
  third-party binary in NetworkCore release artifacts;
- translate only a minimal NetworkCore config subset into deterministic
  adapter-owned runtime config;
- redact secrets in diagnostics, Step Summary, manifests, release notes, and
  adapter events;
- verify behavior only through GitHub Actions.

Out of scope for the immediate increment:

- native VLESS, Shadowsocks, Trojan, VMess, Hysteria, Reality, TUIC, WebSocket,
  gRPC, QUIC, or UDP protocol implementation in `engine-native`;
- bundling `sing-box`, `xray-core`, `mihomo`, or other public engine binaries in
  the Linux release artifact;
- replacing the public engine's config schema with NetworkCore metadata fields;
- iOS execution through external binaries, because iOS still requires an
  embedded Network Extension-compatible runtime path.

## Rationale

This keeps the project useful sooner while preserving long-term ownership of the
parts that differentiate NetworkCore:

- public engines already carry protocol compatibility and field testing cost;
- NetworkCore can focus on policy, subscriptions, DNS, MITM/plugin permissions,
  platform adapters, observability, and release governance;
- adapter boundaries keep engines replaceable and prevent domain lock-in;
- private protocol implementation can restart later from concrete product gaps
  instead of speculative parity work.

## Consequences

- The completed runtime baseline should keep `sing-box` as the first public
  adapter and move remaining runtime gaps into the P4 integration backlog.
- Roadmap and TODO entries must treat private protocol implementation as
  deferred unless a specific adapter limitation is documented.
- Release artifacts must not include public engine binaries until third-party
  binary packaging gates are added.
- Linux/macOS/Windows can use public engine adapters first.
- iOS remains a separate embedded-runtime problem and must not assume an
  external public engine process.
