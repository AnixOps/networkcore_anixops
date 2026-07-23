# Subscription URL To sing-box Run Source Contract

## Purpose

This contract defines the first usable NetworkCore path from an operator-provided
proxy URL to a local foreground proxy.

The intended architecture remains multi-client and multi-format:

- subscription and URL formats are parsed into NetworkCore domain catalogs;
- clients call the same domain and adapter boundaries instead of parsing engine
  configs themselves;
- execution engine adapters translate domain catalogs into engine-specific
  configs;
- platform clients stay responsible for UI, permissions, lifecycle presentation,
  and platform-specific policy.

## Scope

This increment adds the first Linux CLI path:

`networkcore-linux run-url <ss://url>`

The command must:

1. parse a supported proxy URL through `CoreSubscriptionService`;
2. normalize it into `SubscriptionDocument` and `NodeCatalog`;
3. render a deterministic `sing-box` JSON config from the selected
   `NodeDescriptor`;
4. install or reuse the latest official `sing-box` binary through the existing
   `SingBoxReleaseInstaller`;
5. write that config under the `sing-box` engine cache runtime directory;
6. start `sing-box run -c <config>` in the foreground through an injectable
   `SingBoxProcessRunner`;
7. report the selected node, local proxy address, config path, executable path,
   process exit code, and stable diagnostics without printing secrets.

## Subscription Formats

`CoreSubscriptionService` remains the source of truth for subscription parsing.
The `run-url` foreground path must support these runnable alpha inputs:

- existing NetworkCore subscription TOML `nodes`/`routes`;
- single `ss://` URL;
- plaintext line list containing `ss://` URLs;
- base64 encoded plaintext line list containing `ss://` URLs.

The first public URL parser supports Shadowsocks links using SIP002 style
credentials:

`ss://base64(method:password)@host:port#name`

The normalized node must use:

- `Protocol::Shadowsocks`;
- stable endpoint host and port;
- decoded display name when the URL fragment is present;
- `NODE_METADATA_SHADOWSOCKS_METHOD`;
- `NODE_METADATA_SHADOWSOCKS_PASSWORD`;
- `NODE_METADATA_SOURCE_FORMAT=ss-url`.

Unsupported URL schemes must fail with `subscription.core.link_unsupported`.
Malformed Shadowsocks URLs must fail with
`subscription.core.shadowsocks_link_invalid`. Error messages must not echo raw
subscription content or secrets.

`v0.1.1-alpha.3` starts parser gates beyond the runnable `run-url` surface:
`trojan://password@host:port?...#name` may be imported as `Protocol::Trojan`
with `NODE_METADATA_TROJAN_PASSWORD` and `NODE_METADATA_SOURCE_FORMAT=trojan-url`
inside `SubscriptionDocument`/`NodeCatalog`. `vless://uuid@host:port?...#name`
may be imported as `Protocol::Vless` with `NODE_METADATA_VLESS_UUID` and
`NODE_METADATA_SOURCE_FORMAT=vless-url` inside `SubscriptionDocument`/
`NodeCatalog`. `vmess://base64(json)` may be imported as `Protocol::Vmess`
when the decoded JSON contains `add`, `port`, and `id`; `ps` may provide the
display name, and `NODE_METADATA_VMESS_UUID` plus
`NODE_METADATA_SOURCE_FORMAT=vmess-url` carry catalog metadata. Linux `run-url`
remains Shadowsocks-only.

`v0.2.0-alpha.8` extends the Windows local-profile import path with the current
sing-box/v2rayN QUIC share-link subset. Hysteria2 and TUIC may be imported as
local-file share-link parser gates. `hysteria2://` and `hy2://` links are
normalized as `Protocol::Hysteria2`; they retain the password, optional
`mport` port-hopping range, `sni`, `alpn`, certificate public-key pin,
`insecure`, and `salamander` or `gecko` obfuscation fields. Gecko packet-size
fields are retained when present. `tuic://` links are normalized as
`Protocol::Tuic`; they retain UUID, optional password, `sni`, `alpn`,
`allowInsecure`/`insecure`, and the current `cubic`, `new_reno`, or `bbr`
congestion-control values. These inputs use stable Hysteria2/TUIC and generic
TLS metadata plus `NODE_METADATA_SOURCE_FORMAT=hysteria2-url` or `tuic-url`.
The shared sing-box adapter renders a TLS-enabled outbound for the selected
node. Linux `run-url` remains Shadowsocks-only, and share-link parsing does
not enable remote fetch, TUN, DNS, firewall, transparent capture, or QUIC
MITM.

`v0.2.0-alpha.9` activates a deterministic local-file V2Ray compatibility
subset for the Windows GUI. Trojan, VLESS, and VMess share links now retain
explicit TLS enablement, SNI, insecure, ALPN, certificate public-key pins, and
uTLS fingerprints. VLESS additionally retains Vision flow and REALITY public
key/short-id; VMess retains `security` and `alter_id`. The supported transport
subset is WebSocket, gRPC, HTTP/HTTP2 (`type=http`/`h2`), HTTPUpgrade, and
V2Ray QUIC, with the corresponding host/path/service-name values. The same
subset is normalized from compatible native sing-box Trojan/VLESS/VMess
outbounds for catalog conversion and rendered back into a generated sing-box
config. It does not add remote fetching, multi-node selectors, XHTTP/ECH or
multiplex inference, arbitrary native-field translation, or HTTP/2/HTTP/3 MITM.

Clash YAML may be imported as a catalog-only parser gate when the payload has a
top-level `proxies` list. The initial supported proxy subset reads only
`name`, `type`, `server`, `port`, `cipher`, `password`, and `uuid`; it accepts
`ss`/`shadowsocks`, `trojan`, `vless`, and `vmess` proxy types and maps them to
the corresponding `Protocol` plus the same per-protocol metadata used by URL
imports. Imported Clash nodes must include
`NODE_METADATA_SOURCE_FORMAT=clash-yaml`; unsupported Clash proxy types must
fail with `subscription.core.clash_yaml_unsupported`, and malformed supported
proxies must fail with `subscription.core.clash_yaml_invalid` without echoing
raw subscription content or secrets. Clash `proxy-groups`, `rules`, provider
URLs, transport options, TLS options, UDP flags, and adapter rendering remain
deferred. This does not make Linux `run-url` render or run Clash YAML. The
Windows GUI may consume the basic node catalog through its explicit local-profile
import, but unsupported transport and TLS fields remain absent from generated
config.

sing-box JSON may be imported as a catalog-only parser gate when the payload
has a top-level `outbounds` list. The supported outbound subset reads `type`,
`tag`, `server`, `server_port`, `method`, `password`, and `uuid`; it accepts
`shadowsocks`/`ss`, `trojan`, `vless`, `vmess`, `hysteria2`, and `tuic`
outbound types and maps them to the corresponding `Protocol` plus the same
per-protocol metadata used by URL imports. Trojan/VLESS/VMess additionally read
their retained `flow`, VMess security/alter-id, TLS (including uTLS/REALITY),
and supported V2Ray transport subset. Hysteria2 additionally reads
`server_ports`, `obfs`, and the retained TLS subset; TUIC additionally reads
`congestion_control` and the retained TLS subset. A Hysteria2 `server_ports`
range provides the normalized node endpoint from its first range boundary and
is rendered back as `server_ports`, not as a conflicting `server_port`.
Non-proxy orchestration outbounds such as `direct`,
`block`, `dns`, `selector`, and `urltest` are ignored. Imported sing-box nodes
must include `NODE_METADATA_SOURCE_FORMAT=sing-box-json`; unsupported sing-box
proxy outbounds must fail with `subscription.core.sing_box_json_unsupported`,
and malformed supported outbounds must fail with
`subscription.core.sing_box_json_invalid` without echoing raw subscription
content or secrets. For catalog conversion, only the documented V2Ray-family
and Hysteria2/TUIC subsets are retained; other sing-box TLS, transport,
multiplex, route, DNS, inbound, experimental, and adapter fields remain
deferred. This does not make Linux `run-url` render or run sing-box JSON. A
native sing-box JSON document selected in the Windows GUI still bypasses this
catalog converter and is copied unchanged.

Surge proxy line may be imported as a catalog-only parser gate when the payload
has a `[Proxy]` section. The initial supported line subset reads
`name = type, server, port, key=value...`; it accepts `ss`/`shadowsocks`,
`trojan`, and `vmess` proxy types. Shadowsocks lines read `encrypt-method` (or
`method`) and `password`, Trojan lines read `password`, and VMess lines read
`username` as the VMess UUID. Imported Surge nodes must include
`NODE_METADATA_SOURCE_FORMAT=surge-proxy-line`; unsupported Surge proxy line
types must fail with `subscription.core.surge_proxy_line_unsupported`, and
malformed supported proxy lines must fail with
`subscription.core.surge_proxy_line_invalid` without echoing raw subscription
content or secrets. Surge proxy groups, rules, policy logic, TLS/transport
options, UDP flags, and adapter rendering remain deferred. This does not make
Linux `run-url` render or run Surge. The Windows GUI can use the basic
normalized node through local-profile import only.

Loon proxy line may be imported as a catalog-only parser gate when the payload
has a `[Proxy]` section and uses positional proxy fields. The initial supported
line subset reads `name = type, server, port, ...`; it accepts
`ss`/`shadowsocks`, `trojan`, `vless`, and `vmess` proxy types. Shadowsocks
lines read method and password from positional fields, Trojan lines read
password, VLESS lines read UUID, and VMess lines read UUID from the positional
UUID field. Imported Loon nodes must include
`NODE_METADATA_SOURCE_FORMAT=loon-proxy-line`; unsupported Loon proxy line
types must fail with `subscription.core.loon_proxy_line_unsupported`, and
malformed supported proxy lines must fail with
`subscription.core.loon_proxy_line_invalid` without echoing raw subscription
content or secrets. Loon policy groups, rules, TLS/transport options, UDP
flags, remote proxy providers, and adapter rendering remain deferred. This does
not make Linux `run-url` render or run Loon. The Windows GUI can use the basic
normalized node through local-profile import only.

Quantumult X proxy/server line may be imported as a catalog-only parser gate
when the payload has a `[server_local]` section. The initial supported line
subset reads `protocol=host:port, key=value...`; it accepts
`ss`/`shadowsocks`, `trojan`, `vless`, and `vmess` proxy types. Shadowsocks
lines read `method` and `password`, Trojan lines read `password`, VLESS lines
read `password` or `uuid` as the VLESS UUID, and VMess lines read `password`,
`uuid`, or `username` as the VMess UUID. The `tag` option becomes the catalog
display name when present. Imported Quantumult X nodes must include
`NODE_METADATA_SOURCE_FORMAT=quantumult-x-proxy-line`; unsupported Quantumult X
proxy/server line types must fail with
`subscription.core.quantumult_x_proxy_line_unsupported`, and malformed supported
proxy/server lines must fail with
`subscription.core.quantumult_x_proxy_line_invalid` without echoing raw
subscription content or secrets. Quantumult X `[server_remote]`, policies,
filters, rewrite/task sections, TLS/transport/obfs options, UDP flags, remote
subscription fetching, and adapter rendering remain deferred. This does not
make Linux `run-url` render or run Quantumult X. The Windows GUI can use the
basic normalized node through local-profile import only.

Hysteria v1 and other non-listed formats remain follow-up formats.
They must still enter through `SubscriptionService` and `NodeCatalog`, not
through platform-specific parsers.

## sing-box Translation

The `engine-singbox` crate owns deterministic `NodeCatalog` to `sing-box` JSON
translation. The renderer must produce:

- a `mixed` inbound on the requested local host and port;
- a basic Shadowsocks, Trojan, VLESS, VMess, Hysteria2, or TUIC outbound from
  the selected node;
- a `direct` outbound;
- a route `final` pointing at the selected node tag.

Trojan, VLESS, and VMess render only retained TLS, REALITY, uTLS, Vision,
security/alter-id, and WebSocket/gRPC/HTTP/HTTPUpgrade/V2Ray-QUIC transport
metadata. Hysteria2 and TUIC use a TLS-enabled outbound and only render the
metadata explicitly retained by their parser gate: Hysteria2 password, optional
port-hopping range and obfuscation; TUIC UUID, optional password, and optional
congestion control; both share SNI, ALPN, certificate pin, and insecure TLS
metadata. The renderer must reject unsupported protocols and must not invent
TLS/REALITY/transport/multiplex/route/DNS settings that the NodeCatalog did not
retain.

The renderer must not print generated JSON in normal CLI output because it
contains credentials. It may write the config to the runtime cache for
`sing-box` process execution.

Stable anchors:

- `render_sing_box_local_proxy_config`
- `SingBoxLocalProxyConfigRequest`
- `engine.singbox.config.rendered`
- `NODE_METADATA_SHADOWSOCKS_METHOD`
- `NODE_METADATA_SHADOWSOCKS_PASSWORD`

## Linux CLI Contract

The Linux CLI must expose:

```text
networkcore-linux run-url <ss://url> \
  [--listen-host <host>] \
  [--listen-port <port>] \
  [--install-dir <dir>] \
  [--force] \
  [--format text|json]
```

Defaults:

- `--listen-host`: `127.0.0.1`
- `--listen-port`: `7890`

Text output must include:

- selected node name and id;
- local proxy address;
- config path;
- process exit code.

JSON output must include a `sing_box_run` object with:

- `node_id`
- `node_name`
- `listen_host`
- `listen_port`
- `executable_path`
- `config_path`
- `process_exit_code`

`run-url` is foreground-only. It does not create a daemon, system service,
control socket, TUN device, DNS mutation, firewall rule, certificate, or MITM
state. Cross-process `stop`, background `status`, logs, reload, node selection,
and persisted subscriptions remain follow-up work.

## Verification

Local machines must not run build, test, package, or release validation. GitHub
Actions must verify:

- `control-domain` metadata fields for per-protocol node parameters;
- `config-core` parsing for `ss://`, `trojan://`, `vless://`, `vmess://`,
  `hysteria2://`/`hy2://`, `tuic://`, Clash YAML `proxies`, sing-box JSON
  `outbounds`, Surge `[Proxy]` lines, Loon `[Proxy]` lines, plaintext link
  list, and base64 link list;
- `engine-singbox` deterministic local proxy config rendering;
- `networkcore-linux run-url` parsing, response fields, config writing, and
  injected process runner behavior;
- release packaging after same-commit CI success.
