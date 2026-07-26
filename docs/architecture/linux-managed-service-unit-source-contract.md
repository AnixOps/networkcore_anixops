# Linux Managed Service Unit Source Contract

The first Linux managed-mode increment is a pure systemd unit generation
contract. `platform-linux::systemd::render_systemd_unit` returns unit text and
a plan; it does not call `systemctl`, write `/etc/systemd/system`, enable a
unit, or start a service.

The generated unit requires a non-root service user/group, absolute executable
and state paths, `NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`,
`ProtectHome`, and an explicit `ReadWritePaths` state directory. Restart is
bounded by `Restart=on-failure`, `RestartSec=5s`, `StartLimitBurst=3`, and
`StartLimitIntervalSec=60`; it never uses `Restart=always`.

Future CLI installation must require `install-service --confirm`, snapshot any
existing unit before replacement, verify the written unit, and provide an
explicit uninstall path. Uninstall must not remove user configuration or
subscriptions; destructive cleanup belongs behind a separate
`purge --confirm` action.
