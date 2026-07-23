# NetworkCore Windows Installer

`Package.wxs` is the WiX 4.0.6 source for the per-machine NetworkCore MSI.
GitHub Actions supplies the compiled GUI, CLI, and service paths plus a numeric
MSI product version at build time.

The installer:

- installs `networkcore-windows-gui.exe`, `networkcore-windows.exe`, and
  `networkcore-windows-service.exe` under Program Files;
- installs and starts the `AnixOpsNetworkCore` automatic Windows service;
- preserves `managed-config.json` under ProgramData across upgrades;
- creates an AnixOps NetworkCore Start Menu shortcut;
- runs `networkcore-windows-service.exe purge` as LocalSystem after stopping the
  service and before a full uninstall so managed proxy, certificate, driver, and
  tunnel state is removed.

## First run and configuration

The MSI installs the files and starts `AnixOpsNetworkCore`, but the shipped
`managed-config.json` deliberately contains only `null` values. That default is
safe and does not change the system proxy, certificate store, driver state, or
tunnel. Edit this file as Administrator:

`C:\ProgramData\AnixOps\NetworkCore\managed-config.json`

The smallest useful configuration for a local HTTP proxy is:

```json
{
  "schema_version": 1,
  "system_proxy": {
    "enabled": true,
    "server": "127.0.0.1:7890",
    "bypass": "<local>"
  },
  "root_certificate_path": null,
  "driver_package": null,
  "tunnel": null
}
```

Only set `enabled` to `true` when a listener is already running at `server`.
After editing, open the GUI, click `Apply configuration`, then `Restart`.
The service reads this file under `LocalSystem`; paths must be absolute and
readable by that account.

The optional fields are:

- `root_certificate_path`: an existing certificate file that Windows CryptoAPI
  can decode, for example `C:\\ProgramData\\AnixOps\\NetworkCore\\root-ca.cer`.
- `driver_package.inf_path`: the entry-point INF of a signed driver package.
- `tunnel`: all explicit delivery, EasyTier, secret, and state paths required by
  the Windows tunnel command. Leave it `null` until those signed delivery
  artifacts exist.

The GUI shows the current service state and action errors. It writes diagnostics
to `C:\ProgramData\AnixOps\NetworkCore\logs\gui.log` and the service writes to
`service.log`. Errors are always recorded; `Toggle debug` and
`Open log folder` add verbose GUI action/status lines, or launch
`networkcore-windows-gui.exe --debug` to start with verbose logging enabled.

The MSI is built and validated only by GitHub Actions. Do not invoke WiX or
Windows Installer locally.
