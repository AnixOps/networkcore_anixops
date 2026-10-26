# NetworkCore Windows Installer

`Package.wxs` is the WiX 4.0.6 source for the per-machine NetworkCore MSI.
GitHub Actions supplies the compiled GUI, CLI, and service paths plus a numeric
MSI product version at build time.

The installer:

- installs `networkcore-windows-gui.exe`, `networkcore-windows.exe`, and
  `networkcore-windows-service.exe` under Program Files;
- registers the `AnixOpsNetworkCore` automatic Windows service and requests its
  first start without making the MSI wait for the service to reach `Running`;
- preserves `managed-config.json` under ProgramData across upgrades;
- creates an AnixOps NetworkCore Start Menu shortcut;
- runs `networkcore-windows-service.exe purge` as LocalSystem after stopping the
  service and before a full uninstall so managed proxy, certificate, driver, and
  tunnel state is removed.

## Portable package

Each Windows tag release also includes a portable ZIP and its SHA-256 and
manifest files. Extract the ZIP, keep its files together, and run
`networkcore-windows-gui.exe`. Extraction does not register or start a Windows
service. The bundled `README.txt` describes the explicit service install and
removal commands.

## First run and configuration

The MSI installs the files, registers `AnixOpsNetworkCore`, and requests an
asynchronous first start. The service completes its SCM startup handshake before
it applies managed configuration, and the CLI start command returns the
immediately observed SCM state instead of waiting for the runtime. An invalid
previous configuration therefore cannot leave the installer or service request
stuck; the service returns to `Stopped` and records the error in `service.log`.
The GUI Home `Connect` command waits off the UI thread for SCM and the
embedded engine's loopback listener. Only then does it apply the configured
proxy for the interactive user and atomically save that desktop snapshot. The
snapshot is restored before disconnect and after a later observed core/config
failure. The manual GUI `Restore network settings` action restores only a
snapshot owned by that GUI session; it cannot enable an unverified proxy
endpoint.
While the service is running, it polls the embedded engine it runs in-process.
An unexpected engine stop is written to the managed runtime state and
`service.log`; the service stops runtime resources, restores a service-owned
proxy snapshot when the configuration requests it, and returns SCM to `Stopped`
rather than leaving a system proxy pointed at an unavailable listener.
The shipped `managed-config.json` deliberately contains only `null` values.
That default is safe and does not change the system proxy, certificate store,
driver state, or tunnel. The GUI writes this file when a subscription is
imported; it lives at:

`C:\ProgramData\AnixOps\NetworkCore\managed-config.json`

A configuration for the embedded engine as a local proxy looks like:

```json
{
  "schema_version": 2,
  "system_proxy": {
    "enabled": true,
    "server": "127.0.0.1:7890",
    "bypass": "<local>"
  },
  "system_proxy_owner": "service",
  "root_certificate_path": null,
  "driver_package": null,
  "tunnel": null,
  "native_mitm": null,
  "embedded": {
    "enabled": true,
    "envelope_path": "C:\\ProgramData\\AnixOps\\NetworkCore\\embedded\\envelope.json",
    "listen_host": "127.0.0.1",
    "listen_port": 7890
  }
}
```

`system_proxy_owner: "service"` retains the CLI/service behavior. GUI-imported
profiles write `"desktop"` instead, so the interactive GUI owns the exact
current-user proxy snapshot and rollback. `envelope_path` is the embedded
engine's configuration envelope; the GUI generates it from the imported
subscription, the selected node, the routing mode and the policy-group choices.
No third-party proxy binary is downloaded or started.

## GUI profile workflow

1. Enter a subscription URL, a share link, or a local file on the Proxies page
   and import it. The GUI saves the parsed nodes under
   `%ProgramData%\AnixOps\NetworkCore\embedded` and writes the envelope.
2. Install the service once if needed, then use Home `Connect`.
3. Switch nodes, run delay tests, or pick the fastest node; a connected engine
   restarts on the new choice. Subscription rules and policy groups appear on
   the Rules page, where select groups can be switched.

Accepted inputs are `ss://`, `trojan://`, `vless://`, `vmess://`,
`hysteria2://`/`hy2://` and `tuic://` links, Clash YAML `proxies` (with `rules`
and `proxy-groups`), JSON outbound lists, and Surge, Loon or Quantumult X
proxy lines. A node the embedded engine cannot run is reported on import.

`Enable HTTPS MITM` moves the embedded engine's listener to loopback port 7891
and starts the native HTTPS MITM listener on `127.0.0.1:7890`, which the system
proxy points at and which forwards through the engine as its SOCKS upstream.
`Disable HTTPS MITM` moves the engine back to port 7890.

The optional fields are:

- `root_certificate_path`: an existing certificate file that Windows CryptoAPI
  can decode, for example `C:\ProgramData\AnixOps\NetworkCore\root-ca.cer`.
- `driver_package.inf_path`: the entry-point INF of a signed driver package.
- `tunnel`: all explicit delivery, secret, and state paths required by the
  Windows tunnel command. Leave it `null` until those signed delivery artifacts
  exist.
- `embedded`: the embedded engine's envelope path and loopback listener.
- `native_mitm`: a service-owned loopback HTTP proxy, CA certificate/key paths,
  and a local SOCKS upstream. The GUI writes this block when `Enable HTTPS
  MITM` is selected.

`root_certificate_path` only imports an existing certificate into the Windows
LocalMachine ROOT store. The GUI HTTPS MITM action instead creates its own CA,
has the service trust it, and starts the native listener. It handles explicit
HTTP proxy traffic and controlled HTTP/1.1 TLS sessions; HTTP/2, QUIC,
streaming/chunked exchanges, TUN, DNS interception, and remote scripts are not
available.

The GUI shows the current service state and action errors. It writes diagnostics
to `C:\ProgramData\AnixOps\NetworkCore\logs\gui.log` and the service writes to
`service.log`. `Diagnostics` creates and opens `diagnostics.txt`, containing
SCM/runtime status and bounded local log tails; an action failure writes the
same report and shows its path. `networkcore-windows-gui.exe --debug` adds
verbose GUI activity records only.

The MSI and portable ZIP are built and validated only by GitHub Actions. CI
also performs a bounded silent MSI install/uninstall smoke test and confirms
that a deliberately invalid managed configuration cannot block a service start
request. Do not invoke WiX or Windows Installer locally.
