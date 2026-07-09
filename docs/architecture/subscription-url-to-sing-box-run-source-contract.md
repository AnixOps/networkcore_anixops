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
`NodeCatalog`. VLESS query parameters such as `encryption=none` or `type=tcp`
are accepted by this parser gate but not interpreted as runnable adapter
configuration. `vmess://base64(json)` may be imported as `Protocol::Vmess`
when the decoded JSON contains `add`, `port`, and `id`; `ps` may provide the
display name, and `NODE_METADATA_VMESS_UUID` plus
`NODE_METADATA_SOURCE_FORMAT=vmess-url` carry catalog metadata. VMess transport
fields such as `net`, `tls`, `host`, `path`, `aid`, or `scy` are accepted by
this parser gate but not interpreted as runnable adapter configuration. This
does not make `run-url` render or run Trojan, VLESS, or VMess through
`sing-box`; the initial `engine-singbox` renderer remains Shadowsocks-only
until a later run-preview slice.

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
deferred. This does not make `run-url` render or run Clash YAML through
`sing-box`; the current `engine-singbox` renderer remains Shadowsocks URL path
only until a later run-preview slice.

sing-box JSON may be imported as a catalog-only parser gate when the payload
has a top-level `outbounds` list. The initial supported outbound subset reads
only `type`, `tag`, `server`, `server_port`, `method`, `password`, and `uuid`;
it accepts `shadowsocks`/`ss`, `trojan`, `vless`, and `vmess` outbound types and
maps them to the corresponding `Protocol` plus the same per-protocol metadata
used by URL imports. Non-proxy orchestration outbounds such as `direct`,
`block`, `dns`, `selector`, and `urltest` are ignored. Imported sing-box nodes
must include `NODE_METADATA_SOURCE_FORMAT=sing-box-json`; unsupported sing-box
proxy outbounds must fail with `subscription.core.sing_box_json_unsupported`,
and malformed supported outbounds must fail with
`subscription.core.sing_box_json_invalid` without echoing raw subscription
content or secrets. sing-box TLS, transport, multiplex, route, DNS, inbound,
experimental, and adapter rendering fields remain deferred. This does not make
`run-url` render or run sing-box JSON through `sing-box`; the current
`engine-singbox` renderer remains Shadowsocks URL path only until a later
run-preview slice.

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
`run-url` render or run Surge through `sing-box`; the current `engine-singbox`
renderer remains Shadowsocks URL path only until a later run-preview slice.

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
not make `run-url` render or run Loon through `sing-box`; the current
`engine-singbox` renderer remains Shadowsocks URL path only until a later
run-preview slice.

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
make `run-url` render or run Quantumult X through `sing-box`; the current
`engine-singbox` renderer remains Shadowsocks URL path only until a later
run-preview slice.

Hysteria and other non-listed formats remain follow-up formats.
They must still enter through `SubscriptionService` and `NodeCatalog`, not
through platform-specific parsers.

## sing-box Translation

The `engine-singbox` crate owns deterministic `NodeCatalog` to `sing-box` JSON
translation. The initial renderer must produce:

- a `mixed` inbound on the requested local host and port;
- a Shadowsocks outbound from the selected node;
- a `direct` outbound;
- a route `final` pointing at the selected node tag.

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
- `config-core` parsing for `ss://`, `trojan://`, `vless://`, `vmess://`, Clash YAML `proxies`, sing-box JSON `outbounds`, Surge `[Proxy]` lines, Loon `[Proxy]` lines, plaintext link list, and base64 link list;
- `engine-singbox` deterministic local proxy config rendering;
- `networkcore-linux run-url` parsing, response fields, config writing, and
  injected process runner behavior;
- release packaging after same-commit CI success.
