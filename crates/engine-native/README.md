# engine-native

`engine-native` is the in-process native proxy execution engine. It implements `ProxyEngineService` with a stable descriptor, structured listener/node/route graph validation, lifecycle, status, events, and foreground lifecycle handoff. `networkcore-linux start` wires this service through the current-process foreground lifecycle path; daemon/control-socket operations remain unavailable.

## Start, stop, and reload

- `assess_native_proxy_engine_start_readiness` is the service-level gate: it records `engine.native.start.runtime_assembly_ready` and returns `Ready` when a valid configuration can produce a native runtime assembly plan.
- `NativeProxyEngineService::start` owns the loopback TCP accept loop across `start`/`status`/`events`/`stop` and returns `engine.native.start.running`, `engine.native.runtime.foreground_handoff_ready`, and `engine.native.runtime.accept_loop_ready` when the runtime is active. The runtime binds and releases real loopback TCP listeners; startup failures produce release reports.
- `reload` releases the current runtime, starts the replacement configuration, and emits `engine.native.reload.running`. If the replacement cannot start, it restores the last successfully started configuration and returns `engine.native.reload.failed`; a failed restoration leaves no runtime and returns `engine.native.reload.rollback_failed`. This is an in-process adapter operation, not a daemon or cross-process reload protocol.

## SOCKS5 accept loop

The accept loop accepts only loopback TCP connections and tracks accepted and relayed connection counts in service-owned runtime state. Each step emits its own diagnostic:

1. Pre-protocol close; read the SOCKS5 greeting version/auth methods; select no-auth or reject unsupported auth; write the method response.
2. Read the command header (unsupported commands are rejected) and the CONNECT IPv4/domain/IPv6 target address.
3. With an injected `NativeHttpMitmPluginHook`, map the CONNECT target to an `HttpMitmEvent`, call the domain `MitmPluginService`, record the `HttpMitmOutcome`, and emit `engine.native.runtime.http_mitm_connect_browser_proof_observed` with a default browser proof token derived from the CONNECT authority plus the local socks5 proxy URL. A `Reject` outcome is applied as a SOCKS5 CONNECT general failure before route/outbound selection. The accept loop is the only native site that applies this CONNECT-level `Reject`; `plan_socks5_connect_http_mitm` stays a plan report with `applied=false`.
4. Otherwise select the configured SOCKS outbound handler (handler handoff), build the upstream SOCKS5 CONNECT request frame and an outbound TCP connection plan in memory, attempt a bounded TCP connection to IP-literal SOCKS outbound endpoints, write the upstream CONNECT request, read and decide on the upstream response, record relay/data-relay/client-success readiness, write the SOCKS5 client success response, and relay finite client/outbound TCP streams in both directions.
5. Rejected, invalid, failed, or incomplete outbound paths report route/outbound as unwired, write a SOCKS5 CONNECT general failure (or HTTP 502) to the client, and close both connections.

## Explicit HTTP proxy listener

`ListenerKind::Http` explicit proxy requests:

- Parse `http://` HTTP/1.x requests and apply live plain HTTP request/response rewrite.
- Establish a standard `HTTP/1.1 200 Connection Established` pass-through tunnel for `CONNECT host:443` through the configured SOCKS outbound (CONNECT tunnel foundation, `NativeTlsMitmFoundationReport`). Before relay, the listener can bounded-peek TLS ClientHello bytes and report SNI without consuming client bytes (`NativeTlsClientHelloObservationReport`).
- `plan_explicit_http_connect_controlled_tls_termination` reports a controlled downstream TLS termination plan (`NativeControlledTlsTerminationPlanReport`) only when the observed ClientHello SNI matches the CONNECT authority; live HTTPS decryption remains disabled in the published artifact.
- `plan_and_apply_https_request_rewrite_preview` (`NativeHttpsRequestRewritePreviewReport`) applies reject, redirect, and request header mutation to caller-provided request-phase `https://` input once that plan is ready; body mutation and JavaScript script dispatch are deferred.
- `plan_and_apply_https_response_rewrite_preview` (`NativeHttpsResponseRewritePreviewReport`) applies response header mutation and guarded response body mutation to caller-provided response-phase `https://` input; live HTTPS response rewrite and JavaScript script dispatch stay disabled.

## Not implemented in the published artifact

BIND/UDP ASSOCIATE execution, long-lived production relay scheduling, UDP, TUN, DNS, live TLS interception, live HTTPS request/response rewrite after CONNECT, full live HTTPS response rewrite, script mutation application, daemon control, platform mutation, background status, cross-process stop, and service installation.

## Current source increment

The published-artifact boundary above remains the public release status. Current `main` additionally has an explicitly gated controlled CONNECT path: `NativeTlsMitmCaMaterial` causes a matching-SNI CONNECT session to receive an authority-bound leaf certificate, terminate downstream TLS with rustls, establish a web-PKI-verified upstream TLS session, bind the decrypted origin-form request back to the CONNECT authority, and apply the existing request/response hook over bounded HTTP/1.1 exchanges. `NativeHttpMitmPluginHook::with_node_script_executor` can execute only explicitly mapped local JavaScript assets through a configured local Node runner; each asset is SHA-256 pinned when the executor is created and rechecked before every dispatch, while body size, timeout, UTF-8, header/output validation, and same-authority URL constraints are enforced. Linux product entrypoints select `LinuxNoNetwork`: a fresh network namespace plus Node permission mode grants read access only to the runner, selected asset, and staged body, with no write, child-process, addon, persistent-store, or network permission, and a 64 MiB V8 old-space cap. `Unrestricted` is reserved for isolated test fixtures; Windows product entrypoints reject script execution until an equivalent no-network sandbox exists. A missing, symbolic-link, unreadable, or changed asset remains fail-open and is never dispatched. Runner startup and timeout failures are likewise fail-open: `script_dispatch_failed` is distinct from a deferred dispatch, and the validated non-script rewrite result remains intact. A controlled CONNECT session permits at most four exchanges and closes on explicit close semantics, terminal rewrite, parse failure, or budget exhaustion. It does not fetch scripts remotely, install CA trust, modify browser/system state, or support unbounded streaming. This source increment is not publicly releasable until GitHub Actions passes the associated build, contract, TLS, and Node-runner checks.

When the decrypted client offers `h2`, the controlled CONNECT session negotiates ALPN with the upstream first and mirrors that choice to the client. An `h2` session runs on the `h2` crate (`h2_mitm.rs`), normalizing every stream into the same bounded `NativePlainHttpMessage` rewrite model; streams with bodies above the bound are relayed without rewrite. `plan_native_udp_mitm_decision` refuses UDP/443 to MITM hostnames so clients fall back to TCP TLS. See `docs/architecture/http2-mitm-design.md`; the `http2_mitm_supported` release marker stays `false` until the lock refresh and real-host acceptance are recorded.

Verification for this crate is performed only by GitHub Actions, following the repository CI/CD policy.
