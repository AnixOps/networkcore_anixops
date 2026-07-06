# ADR 0001: Initial Core Stack

## Status

Accepted.

## Context

The repository is still in the bootstrap and P1 specification stage. The next implementation step needs a first source stack that can support a reusable control kernel across Linux, macOS, Windows, and iOS while keeping the domain model independent from UI, platform SDKs, and specific proxy engines.

The selected stack must satisfy the constraints in [AGENT.md](../../AGENT.md), [docs/ci-cd-policy.md](../ci-cd-policy.md), and [Control Kernel Domain Specification](control-kernel-domain.md):

- all build, lint, type check, test, security, packaging, and release verification runs in GitHub Actions only;
- the control kernel must be embeddable into platform clients and iOS extension-compatible shapes;
- external engines such as `sing-box`, `xray-core`, and `mihomo` remain adapters rather than domain dependencies;
- the first implementation must be small, reversible, and compatible with a hexagonal architecture.

## Decision

Use Rust as the first implementation stack for the unified control kernel.

The initial source skeleton should be a Rust workspace with a library-first layout. The first crate should model domain contracts and pure logic only; platform integration, proxy engine execution, plugin sandboxing, and client transports should be added later through adapter crates.

Initial workspace direction:

- `crates/control-domain`: domain entities, value objects, errors, and port traits.
- `crates/control-runtime`: orchestration use cases that depend on domain ports, not concrete adapters.
- `crates/platform-*`: future platform capability adapters.
- `crates/engine-*`: future proxy engine adapters.
- `crates/control-api-*`: future control transport adapters.

## Rationale

Rust is the best first fit for this repository because:

- it can produce reusable libraries for Linux, macOS, Windows, and iOS-oriented integration paths;
- it gives memory-safety guarantees that matter for a long-running network control core;
- it supports strict boundaries through crates, traits, and dependency direction;
- it can represent replaceable adapters without forcing a specific runtime into the domain layer;
- it aligns with the existing CI skeleton, which already detects `Cargo.toml` and has Rust build/test jobs ready to activate.

Alternatives considered:

- Go: strong operational tooling and fast iteration, but less aligned with iOS embeddable-library constraints and fine-grained domain boundary enforcement.
- Swift: good for Apple clients, but not suitable as the first cross-platform kernel implementation.
- Node or TypeScript: useful for clients or tooling, but not appropriate for the long-running network core.
- C or C++: portable and embeddable, but higher memory-safety and maintenance risk for the first production-grade core.

## CI/CD Strategy

When the first Rust workspace lands, GitHub Actions must become the source of truth for:

- `cargo test --workspace --all-targets`
- `cargo build --workspace --all-targets`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- dependency and security scanning appropriate for the Rust workspace

These commands must not be run locally as validation. Local work remains limited to editing, reading, Git operations, and static diff checks.

## Consequences

- The next source increment should create only the minimal Rust workspace and domain crate required to activate CI.
- The Rust domain crate must not depend on platform SDKs, proxy engine binaries, UI frameworks, or network process management.
- iOS integration remains a later adapter concern and must still respect Network Extension and signing constraints.
- Release artifacts remain undefined until a real packaging strategy is documented and implemented in GitHub Actions.
