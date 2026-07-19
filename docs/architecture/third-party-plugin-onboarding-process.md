# Third-Party Plugin Onboarding Process

## Purpose

This process is the fixed gate for adding any third-party plugin, plugin
runtime, plugin parser, or plugin compatibility core to NetworkCore.

It applies before code is treated as supported, before client UI exposes the
feature, and before a release notes entry can describe the plugin path as
available.

Current validated example:

- `networkcore.adblock` over the pinned `mitm_anixops` distribution release
  `v1.4.6` source commit, whose linked C core ABI reports `0.45.10`.

Machine-readable governance anchors:

```text
third-party-plugin-onboarding-status=active
THIRD_PARTY_PLUGIN_SOURCE_CONTRACT
THIRD_PARTY_PLUGIN_PINNED_SOURCE
THIRD_PARTY_PLUGIN_LICENSE_NOTICE_GATE
THIRD_PARTY_PLUGIN_PERMISSION_GATE
THIRD_PARTY_PLUGIN_SAFE_WRAPPER_GATE
THIRD_PARTY_PLUGIN_CI_GOVERNANCE_GATE
THIRD_PARTY_PLUGIN_UPGRADE_PROCEDURE
```

## Scope

This process covers third-party code or data formats that enter NetworkCore as
plugin capability, including:

- MITM plugin compatibility cores.
- Loon, Surge, Quantumult X, or similar plugin format adapters.
- Script dispatch runtimes or rule engines used by plugin policy.
- Third-party filter list, rewrite, header, body, DNS, or routing plugin
  packages.
- Any third-party SDK that executes plugin-owned logic or parses plugin-owned
  configuration.

Public proxy execution engines such as `sing-box`, `xray-core`, or `mihomo`
are governed by the public engine adapter process when they only execute proxy
data plane configuration. If they are also used to parse or execute plugin
logic, this plugin onboarding process applies to that part as well.

## Required Sequence

### 1. Intake

Every third-party plugin addition starts with an intake record in the relevant
design or source contract. The intake must identify:

- upstream repository or package source;
- exact release tag, commit, package version, or checksum;
- license and NOTICE obligations;
- expected runtime capability;
- supported platforms;
- network, filesystem, script, certificate, or system mutation risk;
- whether secrets, user traffic, or user-generated scripts can cross the
  boundary.

If license, NOTICE, security review, store review, or account configuration
cannot be completed automatically, the required action must be recorded in
`docs/manual-intervention.md`.

### 2. Source Contract

Before implementation, add or update a source contract under
`docs/architecture/`.

Required source contract fields:

- plugin id or adapter id;
- upstream source and pinned version;
- ownership boundary between NetworkCore and the third-party project;
- accepted input format;
- normalized NetworkCore domain output;
- permission model;
- diagnostics and audit events;
- unsupported or deferred behavior;
- upgrade procedure;
- GitHub Actions verification anchors.

The source contract must include the `THIRD_PARTY_PLUGIN_SOURCE_CONTRACT`
anchor or reference this process by name.

### 3. Pinned Source

Third-party plugin code must be reproducible.

Allowed pinning mechanisms:

- Git submodule pinned to an exact commit and documented tag.
- Package manager lockfile generated in GitHub Actions.
- Vendored source with exact upstream tag, commit, license, and checksum.

Forbidden:

- floating `latest` for compile-time plugin code;
- unpinned source archives;
- checked-in third-party binaries unless a separate artifact policy explicitly
  permits them;
- client-specific parser forks that bypass NetworkCore domain boundaries.

The source contract and CI must prove `THIRD_PARTY_PLUGIN_PINNED_SOURCE`.

### 4. Layering

Third-party plugin functionality must enter through the same layered shape:

1. Raw binding or adapter layer, such as a `*-sys` crate or protocol-specific
   adapter.
2. Safe NetworkCore wrapper that owns lifetimes, errors, limits, and result
   types.
3. Domain or runtime service that applies manifest, permission, platform, and
   certificate gates.
4. Client integration only after the domain service exposes stable behavior.

Clients must not parse third-party plugin formats directly. They import,
enable, disable, or configure plugin packages through NetworkCore-owned
interfaces.

The wrapper must prove `THIRD_PARTY_PLUGIN_SAFE_WRAPPER_GATE` before runtime or
client code depends on it.

### 5. Permission And Safety Gates

Every plugin path must define explicit gates for:

- manifest validation;
- required permissions;
- platform capability;
- certificate or MITM trust state when applicable;
- script execution policy;
- remote script or remote subscription policy;
- input size limits and timeout boundaries;
- stable error, diagnostic, and audit codes.

The gate must prove `THIRD_PARTY_PLUGIN_PERMISSION_GATE`.

### 6. License And NOTICE Gate

Each third-party plugin source must document:

- license source;
- NOTICE requirement;
- release artifact inclusion status;
- whether the third-party code is source-linked, dynamically downloaded,
  executed by the user, or bundled in a NetworkCore artifact.

If artifact inclusion is possible, release eligibility must be blocked until
license and NOTICE obligations are confirmed. This gate proves
`THIRD_PARTY_PLUGIN_LICENSE_NOTICE_GATE`.

### 7. CI Governance

Adding a plugin is incomplete until CI checks the relevant source contract and
source anchors.

Required CI coverage:

- source contract file exists;
- pinned version or package lock is checked;
- wrapper/source anchors are checked;
- contract tests cover accepted, rejected, and deferred behavior;
- dependency audit or equivalent security scan runs in GitHub Actions;
- local build, test, package, and release verification remain forbidden.

This gate proves `THIRD_PARTY_PLUGIN_CI_GOVERNANCE_GATE`.

### 8. Release Boundary

A prerelease or stable release may mention a third-party plugin addition only
after:

- the source contract is committed;
- CI on `main` passes for the same commit;
- release workflow verifies the same-commit CI gate;
- package, checksum, manifest, attestation, release notes, and rollback gates
  pass when an artifact is produced;
- no local build, test, package, or release verification was used.

If live traffic mutation, script execution, platform certificate trust, or
client UI support is deferred, the release notes must say so directly.

## Upgrade Procedure

`THIRD_PARTY_PLUGIN_UPGRADE_PROCEDURE`

For every upstream plugin release:

1. Read upstream release notes, public headers, API/ABI exports, package
   manifests, license files, and security notes.
2. Compare source/API/ABI changes against the existing source contract.
3. Move the pinned source only to the intended tag, commit, version, or
   checksum.
4. Update raw bindings or adapter declarations first.
5. Update the safe wrapper second.
6. Update runtime/domain integration only after wrapper behavior is stable.
7. Update CI governance anchors and contract tests.
8. Update README, ROADMAP, TODO, CHANGELOG, and relevant architecture docs.
9. Push to GitHub and use only GitHub Actions as validation.
10. Release only from a tag or workflow allowed by `.github/workflows/release.yml`.

If an upstream upgrade removes an API, changes ownership rules, changes license
terms, expands script/system/network capability, or cannot be validated in CI,
record the issue in `docs/manual-intervention.md` and do not describe the
plugin path as release-ready.

## Definition Of Done

A third-party plugin addition is done only when all of the following are true:

- `THIRD_PARTY_PLUGIN_SOURCE_CONTRACT` exists for the plugin.
- `THIRD_PARTY_PLUGIN_PINNED_SOURCE` is enforced.
- `THIRD_PARTY_PLUGIN_LICENSE_NOTICE_GATE` is satisfied or blocked with a
  manual marker.
- `THIRD_PARTY_PLUGIN_PERMISSION_GATE` is implemented or explicitly deferred in
  the source contract.
- `THIRD_PARTY_PLUGIN_SAFE_WRAPPER_GATE` is implemented before runtime/client
  ownership.
- `THIRD_PARTY_PLUGIN_CI_GOVERNANCE_GATE` checks the above in GitHub Actions.
- Release notes state the exact supported, unsupported, and deferred behavior.

Partial integrations may be merged as alpha work only when the deferred
behavior is explicit, diagnostic codes are stable, and CI proves the current
contract.
