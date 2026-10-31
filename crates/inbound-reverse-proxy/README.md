# inbound-reverse-proxy

HTTP/1.1 reverse proxy for the node kernel (`"type": "reverse_proxy"`).
A request is matched to a site by its `Host` (exact name, then the longest
`*.` wildcard, then `*`) and to a route by the longest path prefix on
segment boundaries, then sent to one of the route's upstreams with the
`forward` inbound's balancing, health checks and circuit breaker.

```json
{"type": "reverse_proxy", "listen_port": 443,
 "tls": {"certificate_path": "/run/anix/site.crt", "key_path": "/run/anix/site.key"},
 "sites": [{"hosts": ["example.com", "*.example.com"],
            "routes": [{"path": "/api", "strip_prefix": true,
                        "upstreams": [{"server": "10.0.0.2", "server_port": 8080, "weight": 2},
                                      {"server": "10.0.0.3", "server_port": 8080}],
                        "balance": "least_conn", "host_header": "upstream",
                        "headers": {"X-Site": "a"},
                        "health": {"interval_ms": 5000}},
                       {"path": "/", "upstreams": [{"server": "origin.example", "server_port": 3000}],
                        "host": "origin.example"}]}],
 "forwarded_proto": "https"}
```

- TLS is the `tls` setting's job (one certificate covering every site's
  names, reloaded when its files change); set `forwarded_proto` to `https`
  behind it. A plain listener next to it can answer with `308` redirects:
  `{"hosts": ["example.com"], "redirect_https": true}`.
- Upstreams are dialed through the inbound's base outbound, so an origin can
  be reached over an ANX route (`anx-line:<id>`, `egress:<id>`).
- Requests get `X-Forwarded-For` (client appended), `X-Real-IP`,
  `X-Forwarded-Proto` and `X-Forwarded-Host`. `host_header` is `client`
  (default) or `upstream`; `host` sets a fixed one. `headers` are set on
  every request and cannot touch `Host` or framing headers.
- Bodies are streamed as framed (`Content-Length`, chunked, or until close
  for responses). Requests with both `Transfer-Encoding` and
  `Content-Length`, conflicting lengths or a non-chunked transfer coding get
  `400`, so they cannot be smuggled to an upstream. Hop-by-hop headers and
  those named in `Connection` are dropped.
- WebSocket and other upgrades are relayed as raw streams after the
  upstream's `101`. Interim `1xx` responses are passed on.
- Upstream connections are kept alive per client connection while requests
  go to the same route; a bodyless request is retried once on a fresh
  connection when a kept-alive one turns out closed.
- Answers of its own: `421` for an unknown host, `404` when no route
  matches, `502` when no upstream answers, `504` when an upstream takes over
  `upstream_timeout_ms` (default 60000) to start its response, `431` for a
  head over `max_header_bytes` (default 65536). Idle client connections close
  after `idle_timeout_ms` (default 60000).
- `GET /v1/inbounds/{tag}/targets` lists every route's upstreams in order;
  `GET /v1/status` lists the `reverse_proxy` feature.

HTTP/2 to clients is not served yet (TLS ALPN should offer `http/1.1`).
