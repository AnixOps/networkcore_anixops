# Mieru Public Engine Adapter Source Contract

This contract defines the external-core boundary for Mieru. NetworkCore does
not copy Mieru source, statically link GPL-3.0 Mieru code, bundle a Mieru
binary, or silently download one.

## Current Status

`engine-mieru` is source-only and contract-tested. The current slice provides
structured `mierus://` parsing, `Protocol::Mieru` normalization, explicit local
binary SHA-256 verification, and an injectable cross-platform child-process
supervisor. It does not yet wire Mieru into the Linux CLI, Windows service, or
system proxy path.

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

Before CLI or service activation, add separate contracts for generated Mieru
configuration, local SOCKS5 endpoint observation, bounded logs, abnormal exit
cleanup, Windows and Linux lifecycle ownership, and explicit rollback of the
NetworkCore-owned local proxy resource. Do not infer those behaviors from the
current parser or supervisor alone.
