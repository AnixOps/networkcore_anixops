# Linux Managed Service Unit Source Contract

linux-managed-service-unit-source-contract

The Linux managed-mode unit boundary renders a systemd unit and, after explicit
CLI confirmation, writes it to `/etc/systemd/system`. The platform write primitive
captures a non-overwriting snapshot of an existing unit, replaces the target
atomically, verifies the exact written content, and restores the prior unit when
verification fails. `plan_systemd_unit_removal` still returns only the explicit
unit target and preservation boundary; neither installation nor removal calls
`systemctl`, enables a unit, starts a service, or deletes the state directory.

The generated unit requires a non-root service user/group, absolute executable
and state paths, `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
`ProtectHome`, and an explicit `ReadWritePaths` state directory. Restart is
bounded by `Restart=on-failure`, `RestartSec=5s`, `StartLimitBurst=3`, and
`StartLimitIntervalSec=60`; it never uses `Restart=always`.

CLI installation/removal must require `install-service --confirm` or
`uninstall-service --confirm`. Installation snapshots any existing unit before
replacement and verifies the written unit; removal preserves user configuration
and subscriptions and remains a plan until its own deletion/rollback contract
is activated. Destructive cleanup belongs behind a separate `purge --confirm`
action.
