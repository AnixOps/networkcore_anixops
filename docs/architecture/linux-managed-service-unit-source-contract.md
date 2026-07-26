# Linux Managed Service Unit Source Contract

The first Linux managed-mode increment is a pure systemd unit generation and
removal-plan contract. `platform-linux::systemd::render_systemd_unit` returns
unit text and a plan, while `plan_systemd_unit_removal` returns the explicit
unit target and preservation boundary; neither calls `systemctl`, writes
`/etc/systemd/system`, enables a unit, starts a service, or deletes files.

The generated unit requires a non-root service user/group, absolute executable
and state paths, `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
`ProtectHome`, and an explicit `ReadWritePaths` state directory. Restart is
bounded by `Restart=on-failure`, `RestartSec=5s`, `StartLimitBurst=3`, and
`StartLimitIntervalSec=60`; it never uses `Restart=always`.

CLI installation/removal must require `install-service --confirm` or
`uninstall-service --confirm`, snapshot any existing unit before replacement,
verify the written unit, and preserve user configuration and subscriptions.
Destructive cleanup belongs behind a separate `purge --confirm` action.
