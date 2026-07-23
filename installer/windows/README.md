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
it applies managed configuration, and GUI/CLI start commands return the
immediately observed SCM state instead of waiting for the runtime. An invalid
previous configuration therefore cannot leave the installer or Start action
stuck; the service returns to `Stopped` and records the error in `service.log`.
The shipped `managed-config.json` deliberately contains only `null` values.
That default is safe and does not change the system proxy, certificate store,
driver state, or tunnel. Edit this file as Administrator:

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
2. Enter a local profile file path or an `http://`/`https://` subscription URL,
   then click `Load nodes` and select the desired entry. A blank selector uses
   the first supported node.
3. Click `Import profile`, then `Install service` and `Start`. After a successful
   URL import, click `Update URL` to explicitly refresh that saved URL.
4. With the managed service running, click `Load nodes`, choose an imported
   node, optionally replace the HTTPS `Delay URL`, then click `Test delay` for
   one measurement. Click `Switch active` only when that selected node should
   become the runtime selector choice.

The importer writes `C:\\ProgramData\\AnixOps\\NetworkCore\\sing-box\\config.json`
and updates `managed-config.json` with the verified core path, local mixed proxy
at `127.0.0.1:7890`, service working directory, and core log path. A blank Node
ID selects the first supported node.

`Load nodes` reads the local source or HTTP(S) URL only when clicked and does
not modify the managed configuration. It exposes the parsed NodeCatalog names
and stable IDs for deterministic import. For these generated NodeCatalog
profiles, `Import profile` emits all translatable nodes behind a sing-box
`selector`, selects the chosen entry as its default, and exposes the selector
only through a loopback Clash API controller at `127.0.0.1:9091`. `Switch active`
is explicit: it PATCHes the selected node and then reads the controller state
back. `Test delay` is also explicit: it calls the selected generated outbound's
loopback `/delay` endpoint once with the editable HTTPS `Delay URL` (default
`https://www.gstatic.com/generate_204`) and a 10-second timeout, then shows the
returned milliseconds. It neither changes the active selector nor writes the
managed config or restarts the service. These actions require the imported
managed service to be running, never open the controller on the network, and
do not add a Web UI, automatic latency/URLTest, or automatic restart. `Import
profile` and `Update URL` download HTTP(S) URLs
only when clicked; `Update URL` reads the last successfully imported URL. A
failed load, update, import, or runtime switch leaves the current managed
configuration unchanged. Native sing-box JSON stays pass-through and has no
generated node selector. The GUI does not create a background update task, a
subscription catalog/group, a route/rule fetch, or an automatic service restart.

The local profile or downloaded payload may use the existing supported
NodeCatalog inputs, including
an `ss://`, `trojan://`, `vless://`, `vmess://`, `hysteria2://`/`hy2://`, or
`tuic://` node, a supported Clash YAML `proxies` list, supported sing-box JSON
`outbounds`, or supported Surge, Loon, or Quantumult X proxy lines.
Link/catalog inputs render Shadowsocks, Trojan, VLESS, VMess, Hysteria2, and
TUIC outbounds. The explicit local V2Ray share-link subset retains TLS/ALPN/
certificate pins/uTLS, VLESS Vision/REALITY, VMess security/alter-id, and
WebSocket/gRPC/HTTP/HTTPUpgrade/V2Ray-QUIC transport fields. It does not infer
XHTTP, ECH, multiplex, routing, or DNS. Hysteria2 retains the supported
password, port-hopping, obfuscation, and TLS share-link fields; TUIC retains
UUID, optional password, congestion control, and TLS share-link fields. The
generated Hysteria2/TUIC and V2Ray QUIC paths are core proxy traffic and are
not intercepted by the HTTP/1.1 HTTPS MITM listener. A native
sing-box JSON document with top-level `inbounds` or
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
is listening at `server`. After editing, open the elevated GUI, click `Open JSON`
to inspect the selected file, then `Validate`. The validation parses the managed
JSON and, when `sing_box.enabled` is true, runs the same non-mutating
`sing-box.exe check -c <config_path>` used by the service. It does not start the
service or change proxy, certificate, driver, or tunnel state. Click `Apply
configuration`, then `Restart` only after validation succeeds.
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
`Diagnostics` creates and opens `diagnostics.txt`, containing SCM/runtime status
and bounded local log tails; an action failure writes the same report and shows
its path. `Toggle debug` and `networkcore-windows-gui.exe --debug` add verbose
GUI activity records only. To make the core itself verbose, set this explicit
block in the operator-owned sing-box JSON, then run `Validate`:

```json
{
  "log": {
    "level": "debug"
  }
}
```

The service captures that core output in the configured `sing_box.log_path`.

The MSI and portable ZIP are built and validated only by GitHub Actions. CI
also performs a bounded silent MSI install/uninstall smoke test and confirms
that a deliberately invalid managed configuration cannot block a service start
request. Do not invoke WiX or Windows Installer locally.
