# Mieru Public Engine Adapter Source Contract

This contract defines the external-core boundary for Mieru. NetworkCore does
not copy Mieru source, statically link GPL-3.0 Mieru code, bundle a Mieru
binary, or silently download one.

## Current Status

`engine-mieru` is source-only and contract-tested. The current slice provides
structured `mierus://` parsing, `Protocol::Mieru` normalization, official-shape
client config rendering, explicit local binary SHA-256 verification, and an
injectable cross-platform child-process supervisor. The Linux CLI exposes
read-only `core list` and explicit local `core install mieru --binary <path>
--sha256 <digest>` verification; it does not download, spawn, or wire Mieru
into the Windows service or system proxy path. Linux CLI also exposes explicit
`core start mieru`/`core stop mieru` controls over a caller-provided config;
these invoke the official client command boundary but do not claim listener
readiness or system proxy mutation.

The adapter's config-file writer requires explicit absolute config and snapshot
paths, preserves an existing config in a non-overwriting snapshot, verifies the
exact bytes written, restores the previous config on write/verification failure,
and uses private `0600` permissions on Unix. Config contents may contain user
credentials, so reports and diagnostics never include the file contents.

## Binary Boundary

The caller must provide an explicit executable path and a complete SHA-256
digest. Verification rejects missing, malformed, or mismatched digests before
the child process is spawned. Release download, when added, may use only the
official repository `enfein/mieru` and must be a separate explicitly
authorized operation. If official release metadata does not provide a
machine-readable digest, automatic download remains disabled.

NetworkCore release artifacts must not contain the Mieru executable. Runtime
provenance must record the verified digest without recording credentials or a
complete share link.

## Share-Link Contract

`mierus://username:password@host:port` is parsed into a controlled node. The
supported query fields are port range, MTU, multiplexing, handshake mode, and
traffic pattern. Passwords remain in engine-owned metadata for configuration
translation but are never included in diagnostics, process logs, or reports.

## Process And Readiness

The supervisor accepts caller-owned arguments, working directory, and bounded
log destination. It reports stopped, running, and failed process state and
cleans up an owned child on drop. A PID alone is not readiness: Linux and
Windows adapters must additionally verify the local SOCKS5 listener, config
acceptance, immediate-exit absence, and any applicable control evidence before
reporting a connected state. UDP support is not claimed until a real Mieru UDP
contract and CI integration evidence exist.

## Future Wiring Gates

Before runtime service activation, add separate contracts for Linux/Windows
lifecycle ownership, bounded logs, abnormal exit cleanup, and explicit rollback
of the NetworkCore-owned local proxy resource. The current config renderer and
listener readiness helper do not by themselves authorize process spawning or
system proxy mutation.
