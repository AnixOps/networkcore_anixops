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
It must support these alpha inputs:

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

VLESS, VMess, Trojan, Hysteria, Clash YAML, sing-box JSON, Surge, Loon, and
Quantumult X remain follow-up formats. They must still enter through
`SubscriptionService` and `NodeCatalog`, not through platform-specific parsers.

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
- `config-core` parsing for `ss://`, plaintext link list, and base64 link list;
- `engine-singbox` deterministic local proxy config rendering;
- `networkcore-linux run-url` parsing, response fields, config writing, and
  injected process runner behavior;
- release packaging after same-commit CI success.
