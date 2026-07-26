# Subscription Background Refresh Source Contract

`subscription-background-refresh-source-contract=active`

`networkcore-linux subscription refresh start` explicitly refreshes one saved HTTP(S) source. It requires `--catalog`, `--refresh-status`, `--snapshot`, `--source-id`, and `--confirm`; it has no default path or source scan. The fixed minimum interval is 300 seconds. Timeout and the 1 MiB response bound come from `CommandRemoteSubscriptionFetcher`.

The response is parsed and normalized before any write. Success atomically replaces only the selected saved source's runnable catalog content, preserves its HTTP(S) refresh location, and writes the explicit pre-refresh catalog snapshot. Failed fetch or parsing preserves the catalog, node selection, and runtime configuration while recording a redacted failure.

The explicit status contains `source_id`, `last_attempt`, `last_success`, `next_attempt`, `result`, `added_node_count`, `removed_node_count`, `changed_node_count`, `error_redacted`, and a stable redacted `error_code`; it never contains a URL, token, password, or node credential. `subscription refresh status` is read-only and `subscription refresh stop --confirm` is bounded and idempotently records `stopped`. A short-lived exclusive lock derived from the explicit status path rejects concurrent refresh of the same source while allowing the next scheduled attempt. This command does not restart a core, switch nodes, or modify system settings. Scheduling remains external through `next_attempt`.
