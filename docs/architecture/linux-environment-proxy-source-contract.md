# Linux Environment Proxy Source Contract

The Linux proxy boundary manages one operator-selected environment file. It is
not a claim that GNOME, NetworkManager, WinINet, browsers, or every shell has
been configured.

## Active Source Boundary

- `platform_linux::proxy::apply_environment_proxy` accepts an absolute target,
  an absolute non-identical snapshot path, a supported `http://`, `https://`,
  `socks5://`, or `socks5h://` URL, and explicit confirmation.
- The target is written as NetworkCore-owned `HTTP_PROXY`, `HTTPS_PROXY`,
  `ALL_PROXY`, and loopback `NO_PROXY` entries.
- Existing target contents are stored in a schema-versioned JSON snapshot before
  replacement. Snapshot and generated files are written with mode `0600` on
  Unix and the generated file is read back for exact verification.
- `rollback_environment_proxy` compares the current file with the exact content
  NetworkCore wrote. An external edit returns
  `platform.linux.proxy.external_change` and is never overwritten.
- A missing original file is removed on rollback; an existing original file is
  restored. The snapshot is retained in both cases.
- `status_environment_proxy` is read-only and requires an explicit path.

## CLI Boundary

`networkcore-linux proxy apply --file <absolute-path> --snapshot
<absolute-path> --url <proxy-url> --confirm` applies the file. `proxy status`
reads one explicit file, and `proxy rollback --confirm` restores its retained
snapshot. Credentials in the URL are never included in response diagnostics.

This contract does not activate a default desktop/system proxy, browser profile,
PAC installation, DNS mutation, or certificate trust mutation.
