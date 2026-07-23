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
asynchronous first start. It does not wait for a preserved managed configuration
to reach `Running`, so an invalid previous configuration cannot leave the
installer stuck at service startup. The shipped `managed-config.json`
deliberately contains only `null` values. That default is safe and does not
change the system proxy, certificate store, driver state, or tunnel. Edit this
file as Administrator:

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
  "tunnel": null,
  "sing_box": {
    "enabled": true,
    "executable_path": "C:\\Program Files\\AnixOps\\NetworkCore\\bin\\sing-box.exe",
    "config_path": "C:\\ProgramData\\AnixOps\\NetworkCore\\sing-box\\config.json",
    "working_directory": "C:\\ProgramData\\AnixOps\\NetworkCore\\sing-box",
    "log_path": "C:\\ProgramData\\AnixOps\\NetworkCore\\logs\\sing-box.log"
  }
}
```

`sing_box` is optional. When enabled, the service first runs
`sing-box.exe check -c <config_path>`, then starts
`sing-box.exe run -c <config_path>` as a service-owned child process and writes
both stdout and stderr to `log_path`. The MSI does not silently download
third-party binaries. In the GUI, click `Install core` to explicitly download
the official Windows ZIP, verify its published digest when available, and place
the executable under `%ProgramData%\\AnixOps\\NetworkCore`; or stage a verified
Windows `sing-box.exe` and import this managed configuration yourself.

## GUI core and profile workflow

For the normal managed workflow, run the elevated GUI and follow this order:

1. Click `Install core` in the `sing-box profile` section.
2. Enter an explicit local profile file path and optionally a Node ID.
3. Click `Import profile`, then `Install service` and `Start`.

The importer writes `C:\\ProgramData\\AnixOps\\NetworkCore\\sing-box\\config.json`
and updates `managed-config.json` with the verified core path, local mixed proxy
at `127.0.0.1:7890`, service working directory, and core log path. A blank Node
ID selects the first supported node.

The local profile may use the existing supported NodeCatalog inputs, including
an `ss://`, `trojan://`, `vless://`, or `vmess://` node, a supported Clash YAML
`proxies` list, supported sing-box JSON `outbounds`, or supported Surge, Loon,
or Quantumult X proxy lines. Link/catalog inputs render basic Shadowsocks,
Trojan, VLESS, and VMess outbounds. Trojan enables TLS; VLESS and VMess are
basic TCP only. A native sing-box JSON document with top-level `inbounds` or
`outbounds` instead bypasses that renderer and is copied unchanged to the
managed `config.json`, preserving TLS/REALITY/WebSocket/gRPC/multiplex/DNS/
route fields. When the native document has a local or wildcard `mixed`/`http`
inbound, its port is used for the managed system proxy; without one, the import
does not configure a system proxy.

`Enable HTTPS MITM` also supports an imported native sing-box document when it
has a `type: "mixed"`, `tag: "mixed-in"` inbound. The GUI records the original
JSON under `%ProgramData%\\AnixOps\\NetworkCore\\mitm`, changes only that inbound
to loopback port 7891 for the native SOCKS upstream, and restores the snapshot
when HTTPS MITM is disabled. Native documents without that exact controlled
inbound are not changed by the MITM action.

Only set `system_proxy.enabled` to `true` after the configured sing-box inbound
is listening at `server`. After editing, open the GUI, click `Apply configuration`,
then `Restart`.
The service reads this file under `LocalSystem`; paths must be absolute and
readable by that account.

`config_path` points to a second file containing native sing-box JSON. It is not
the managed wrapper above. For a minimal local mixed proxy backed by one
Shadowsocks server, create
`C:\\ProgramData\\AnixOps\\NetworkCore\\sing-box\\config.json`:

```json
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": 7890
    }
  ],
  "outbounds": [
    {
      "type": "shadowsocks",
      "tag": "proxy",
      "server": "YOUR_SERVER_HOST",
      "server_port": 443,
      "method": "aes-256-gcm",
      "password": "YOUR_PASSWORD"
    },
    { "type": "direct", "tag": "direct" }
  ],
  "route": { "final": "proxy" }
}
```

Replace the server, port, method, and password with the values from the node
you control. The service writes schema or credential errors from `sing-box check`
to `log_path`; it does not silently invent a node or enable HTTPS
interception.

The optional fields are:

- `root_certificate_path`: an existing certificate file that Windows CryptoAPI
  can decode, for example `C:\\ProgramData\\AnixOps\\NetworkCore\\root-ca.cer`.
- `driver_package.inf_path`: the entry-point INF of a signed driver package.
- `tunnel`: all explicit delivery, EasyTier, secret, and state paths required by
  the Windows tunnel command. Leave it `null` until those signed delivery
  artifacts exist.
- `sing_box`: explicit executable/config/working-directory/log paths for the
  service-owned sing-box process. This is a proxy core integration, not an
  HTTPS MITM configuration.
- `native_mitm`: a service-owned loopback HTTP proxy, CA certificate/key paths,
  and a local SOCKS upstream. The GUI writes this block when `Enable HTTPS
  MITM` is selected, with native HTTP(S) at `127.0.0.1:7890` and sing-box SOCKS
  at `127.0.0.1:7891`. When a supported native JSON profile is in use, the GUI
  also records its private `sing_box_config_snapshot_path`; do not hand-author
  that path because it is removed after the GUI restores the original profile.

`root_certificate_path` only imports an existing certificate into the Windows
LocalMachine ROOT store. The GUI HTTPS MITM action instead creates its own CA,
has the service trust it, and starts the native listener. It handles explicit
HTTP proxy traffic and controlled HTTP/1.1 TLS sessions; HTTP/2, QUIC,
streaming/chunked exchanges, TUN, DNS interception, and remote scripts are not
available.

The GUI shows the current service state and action errors. It writes diagnostics
to `C:\ProgramData\AnixOps\NetworkCore\logs\gui.log` and the service writes to
`service.log`; sing-box check and runtime stdout/stderr use `sing-box.log`.
Errors are always recorded; `Toggle debug`, `Open log folder`, and `Open core
log` expose GUI and core diagnostics, or launch `networkcore-windows-gui.exe
--debug` to start with verbose logging enabled.

The MSI and portable ZIP are built and validated only by GitHub Actions. CI
also performs a bounded silent MSI install/uninstall smoke test. Do not invoke
WiX or Windows Installer locally.
