# sing-box Public Engine Adapter Source Contract

## Purpose

This document defines the first source contract for the `sing-box` public engine
adapter. It follows ADR 0002: NetworkCore keeps the control layer, `engine-*`
crates keep adapter responsibilities, and public execution engines provide the
protocol data plane.

This is the sing-box public engine adapter source contract.

The current increment covers the first usable public-engine path: discover the
official latest `sing-box` release, select the host asset, download it into an
operator-visible cache, verify the GitHub release asset digest when present,
render a deterministic local mixed inbound config for a Shadowsocks
`NodeCatalog`, and expose both `install-sing-box` and foreground `run-url`
through `networkcore-linux`.

## Source Layout

- `crates/engine-singbox`: adapter crate for public `sing-box` contracts.
- `crates/engine-singbox/src/lib.rs`: descriptor, latest release metadata
  parsing, target asset selection, download, checksum, archive extraction,
  local proxy config rendering, foreground process runner, and stable
  diagnostics.
- `crates/engine-singbox/tests/engine_singbox_contracts.rs`: no-network source
  contract tests using injected release metadata and archive bytes.
- `apps/linux-cli/src/lib.rs`: `help`, `install-sing-box`, `run-url`, and
  `sing-box install` command parsing, response mapping, and JSON/text output.
- `apps/linux-cli/src/main.rs`: binary entrypoint wiring that creates the
  GitHub downloader for install/run-url commands and the command process runner
  for foreground `sing-box run`.
- `apps/windows-service/src/lib.rs`: Windows managed service wiring for the
  explicit `sing_box` block, `check -c`, service-owned `run -c`, PID/exit-code
  persistence, and core log redirection.

## Release Metadata Contract

The adapter uses `SING_BOX_LATEST_RELEASE_API_URL`:

`https://api.github.com/repos/SagerNet/sing-box/releases/latest`

The API response must be parsed as release metadata with:

- `tag_name`, normalized by trimming a leading `v`;
- `assets[].name`;
- `assets[].browser_download_url`;
- `assets[].size`;
- `assets[].digest`, when GitHub provides a `sha256:` value.

The adapter must not hard-code the latest `sing-box` version. It may hard-code
the official repository endpoint and asset naming contract because that is the
public-engine adapter boundary.

## Asset Selection

For Linux x64, the preferred official asset order is:

1. `sing-box-{version}-linux-amd64.tar.gz`
2. `sing-box-{version}-linux-amd64-glibc.tar.gz`
3. `sing-box-{version}-linux-amd64-musl.tar.gz`

The same generic-first pattern applies to Linux arm64. macOS uses the official
`darwin-{arch}.tar.gz` assets. Windows asset discovery selects
`windows-{arch}.zip`; the adapter extracts only the exact `sing-box.exe`
basename from stored or deflate-compressed entries and rejects encrypted or
unsupported entries.

Unsupported host OS or CPU values must fail with
`engine.singbox.download.target_unsupported`.

## Download And Cache Contract

`networkcore-linux install-sing-box` downloads into a cache root, then creates:

- `{install_root}/{version}/{target}/downloads/{asset_name}`;
- `{install_root}/{version}/{target}/bin/sing-box`.

`--install-dir <dir>` overrides the cache root. Without `--install-dir`, the
adapter uses `NETWORKCORE_ENGINE_DIR` when set, otherwise an OS-appropriate user
data directory under `networkcore/engines/sing-box`.

If the latest executable is already present and `--force` is not set, the
command must report `downloaded=false` and keep the existing executable. `--force`
redownloads and replaces the cached executable.

## Checksum And Extraction Contract

When the release metadata includes `digest: "sha256:{hex}"`, the adapter must
hash the downloaded archive and require an exact lowercase match before writing
or extracting the executable.

The `.tar.gz` extraction path must only copy an entry whose file name is exactly
`sing-box`. It must not trust archive paths for destination selection and must
not extract arbitrary files from the archive.

On Unix, the extracted executable must be marked `0755`. Permission failures
must be reported as `engine.singbox.download.binary_permission_failed`.

## CLI Contract

The Linux CLI must expose:

- `networkcore-linux help`
- `networkcore-linux --help`
- `networkcore-linux install-sing-box [--install-dir <dir>] [--force]`
- `networkcore-linux run-url <ss://url> [--listen-host <host>] [--listen-port <port>] [--install-dir <dir>] [--force]`
- `networkcore-linux sing-box install [--install-dir <dir>] [--force]`

Missing or unknown commands may still return parse errors, but their text output
must include the command table so users can discover the current command surface.

JSON output must include `sing_box_install` with:

- `version`
- `target`
- `asset_name`
- `asset_url`
- `asset_sha256`
- `archive_path`
- `executable_path`
- `downloaded`

`run-url` JSON output must also include `sing_box_run` with the selected node,
local proxy address, cached executable path, generated config path, and process
exit code. It must not print the generated config JSON because that config
contains outbound credentials.

## Adapter Boundary

This increment does not bundle `sing-box` in NetworkCore release artifacts.
Runtime download is not packaging. Linux release artifacts still contain only
NetworkCore-owned files unless a later third-party binary packaging contract
adds license, NOTICE, checksum, provenance, attestation, rollback, and release
notes gates.

`run-url` still starts `sing-box` as a foreground child process for the current
CLI invocation. The Windows managed service now consumes
`SingBoxManagedProcessSupervisor` through an explicit `managed-config.json`
`sing_box` block: it executes `check -c` before `run -c`, owns one child,
persists PID/exit code, and redirects stdout/stderr to an operator-selected log
path. This managed path requires an already staged Windows executable; the MSI
does not download third-party binaries silently. Cross-process recovery after a
service crash, automatic core install orchestration, hot reload, TUN/DNS/
firewall mutation, and `SingBoxProxyEngineService`'s generic domain lifecycle
remain future adapter work. The Windows path is intentionally separate from
the stateless `ProxyEngineService` trait until that domain port can carry an
explicit executable/config ownership contract.

## Diagnostics

Stable diagnostic anchors include:

- `engine.singbox.download.latest_version_resolved`
- `engine.singbox.download.asset_selected`
- `engine.singbox.download.asset_missing`
- `engine.singbox.download.asset_fetch_failed`
- `engine.singbox.download.checksum_verified`
- `engine.singbox.download.checksum_mismatch`
- `engine.singbox.download.archive_written`
- `engine.singbox.download.extract_failed`
- `engine.singbox.download.binary_ready`
- `engine.singbox.download.binary_already_present`
- `engine.singbox.config.translation_ready`
- `engine.singbox.config.rendered`
- `engine.singbox.process.started`
- `engine.singbox.process.exited`
- `engine.singbox.config.check_failed`
- `engine.singbox.runtime.already_running`
- `cli.linux.sing_box.install_failed`
- `cli.linux.run_url.parse_failed`
- `cli.linux.run_url.config_failed`
- `cli.linux.run_url.process_failed`

## Verification

Local machines must not run build, test, package, or release validation. The
required verification remains GitHub Actions:

- Rust format, lint, test, and build for the workspace.
- Dependency security audit after lockfile generation.
- Repository policy checks for this source contract, `engine-singbox` workspace
  membership, `install-sing-box`/`run-url` CLI anchors, `sing_box_run` response
  fields, config rendering anchors, foreground/managed process supervisor
  anchors, Windows ZIP extraction anchors, and no committed local build or
  package output.
