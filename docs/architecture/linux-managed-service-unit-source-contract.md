# Linux Managed Service Unit Source Contract

linux-managed-service-unit-source-contract

The Linux managed-mode unit boundary renders a systemd unit and, after explicit
CLI confirmation, writes it to `/etc/systemd/system`. The platform write primitive
captures a non-overwriting snapshot of an existing unit, replaces the target
atomically, verifies the exact written content, and restores the prior unit when
verification fails. `plan_systemd_unit_removal` returns only the explicit unit
target and preservation boundary. The confirmed CLI removal path stops that
same named unit first, writes a non-overwriting removal snapshot when a unit
exists, then removes only the verified NetworkCore unit file. Installation and
removal never enable a unit, discover other services, or delete the state
directory.

The generated unit requires a non-root service user/group, absolute executable
and state paths, `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
`ProtectHome`, and an explicit `ReadWritePaths` state directory. Restart is
bounded by `Restart=on-failure`, `RestartSec=5s`, `StartLimitBurst=3`, and
`StartLimitIntervalSec=60`; it never uses `Restart=always`.

CLI installation/removal must require `install-service --confirm` or
`uninstall-service --confirm`. Installation snapshots any existing unit before
replacement and verifies the written unit; confirmed removal stops the named
unit, preserves a matching unit snapshot, and preserves user configuration,
subscriptions, and the state directory. A separate `purge --confirm` action is
required for destructive state cleanup and is not implemented by this boundary.
