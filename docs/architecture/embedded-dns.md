# 内嵌引擎 DNS：上游、hosts、按域名分流与 fake-ip 评估

适用范围：`crates/engine-embedded`（iOS 隧道、桌面 local proxy 的嵌入式内核）。代码见 `src/dns.rs`、`src/dns_policy.rs`，配置见 `src/config.rs` 的 `DnsConfig`。

## 现状

隧道把应用发往 UDP/53 的查询截下来，不做 UDP 中继，而是在一条新的 TCP 连接上转发给上游。连接经过出站，所以默认在代理一侧解析。

- 域名规则靠连接首包的 TLS SNI / HTTP `Host` 嗅探匹配，不依赖 DNS 结果（见 `sniff.rs`）。
- 桌面 local proxy 收到的就是域名，连接按域名交给出站，由代理服务器解析。只有命中不带 `no-resolve` 的 IP 规则（`IP-CIDR`、`GEOIP`）时才需要先解析，这次解析也走本节的 DNS 设置（见下文「DNS 泄露核对」），不用系统解析器。

## 配置

```json
"dns": {
  "timeout_ms": 5000,
  "servers": [
    { "name": "remote", "url": "https://dns.google/dns-query" },
    { "name": "cf", "url": "tls://1.1.1.1", "server_name": "cloudflare-dns.com" },
    { "name": "local", "url": "223.5.5.5", "via": "direct" }
  ],
  "default": "remote",
  "hosts": {
    "router.lan": ["192.168.1.1"],
    "*.corp.example": ["10.0.0.1", "fd00::1"]
  },
  "rules": [
    { "domain_suffix": ["cn", "baidu.com"], "server": "local" },
    { "rule_set": "geosite-cn", "server": "local" },
    { "domain": ["api.example.com"], "domain_keyword": ["taobao"], "server": "cf" }
  ]
}
```

### `servers`：上游

每个上游有 `name`、`url` 两个字段，可选 `server_name` 和 `via`，`url` 支持以下写法：

| 写法 | 协议 | 默认端口 |
| --- | --- | --- |
| `1.1.1.1`、`1.1.1.1:53`、`tcp://host[:port]` | DNS over TCP | 53 |
| `tls://host[:port]` | DNS over TLS（RFC 7858，ALPN `dot`） | 853 |
| `https://host[:port][/path]` | DNS over HTTPS（RFC 8484，HTTP/1.1 POST `application/dns-message`，路径默认 `/dns-query`） | 443 |

- 主机写成 IP 时，可用 `server_name` 指定 TLS 证书名，例如 `tls://1.1.1.1` 配 `cloudflare-dns.com`。证书始终校验，没有 insecure 选项。
- 每个查询各用一条连接，一问一答，`Connection: close`。
- `tls://` 和 `https://` 需要 cargo feature `dns-tls`。默认 feature 里已包含它；不带它构建时，这类配置会被拒绝。
- `via` 决定怎么连到上游：
  - `proxy`（默认）：经代理。单出站配置走该出站；规则模式下，规则为上游地址选了某个节点就走那个节点，规则给出 `DIRECT`/`REJECT`（例如 GFW 列表配置的 `FINAL,DIRECT`、国内解析器命中 `GEOIP,CN,DIRECT`）时改走全局模式的目标，不会因为规则而明文直连；全局模式走全局目标；直连模式下走直连。全局目标本身拒绝时不发查询。
  - `direct`：始终直连，适合国内解析器。
- `default` 指定没有规则命中时用的上游，缺省为第一个。
- 不写 `servers` 时保留旧行为：`upstream`（默认 `1.1.1.1:53`）经 TCP 走代理。这时不能写 `default` 和 `rules`。

### `hosts`：本地应答

- 键可以是精确域名，也可以写成 `*.example.com`，后者只匹配子域名。值为 1–8 个地址，最多 1024 条。
- A 查询答 IPv4 地址，AAAA 查询答 IPv6 地址。其他类型返回 NOERROR 空应答。TTL 为 60 秒。
- 命中 hosts 的查询不连接任何上游。

### `rules`：按域名选上游

- 规则按顺序匹配，第一条命中的生效。一条规则可同时写以下条件，任一满足即命中：
  - `domain`：精确域名。
  - `domain_suffix`：该域名及其子域名，可带 `.`、`+.` 前缀。
  - `domain_keyword`：域名包含该关键字。
  - `rule_set`：`routing.rule_sets` 里的一个集合，例如由客户端或远程下载提供的 `geosite-cn`。
- 名字不存在的规则集永远不命中。
- 上限为 64 条规则，所有规则的域名、后缀和关键字合计不超过 4096 个。

### 错误与状态

- 配置错误返回固定文案的 `config_rejected`，文案里不含域名或 URL。
- 统计沿用 `dns_queries`、`dns_failed` 和 `dns_last_failure`。本地应答计入 `dns_queries`。
- `dns_cached`：由缓存（新鲜或过期）应答、或并入同一问题在途查询的次数，同时计入 `dns_queries`。

### 缓存与连接复用

网页一次要解析多个域名，原来每个查询都经代理新建一条上游连接（DoT / DoH 还要一次 TLS 握手），一次解析约 2–3 个代理 RTT。现在（`crates/engine-embedded/src/dns_cache.rs`）：

- 按 `(域名, 类型, 上游, 是否经代理)` 缓存应答。TTL 取应答与权威段记录的最小值，限制在 30 秒到 1 小时；NXDOMAIN 与空应答最多 60 秒。只缓存 NOERROR / NXDOMAIN、未截断、问题与查询一致的应答，SERVFAIL 不缓存。最多 4096 条，满了先丢过期很久的，再丢最早过期的。
- 命中时改写成该查询的 id 与问题（保留应用的大小写），记录 TTL 改为剩余秒数。
- 过期后 1 小时内仍先回旧应答（TTL 30 秒），同时在后台刷新一次（RFC 8767 serve-stale），应用不等上游。
- 同一问题已有查询在途时，新查询并入等待，不再重复发送（每个问题最多 32 个等待者）。
- 上游连接按 `(上游, 出站)` 保留，每个最多 4 条空闲、空闲超过 20 秒不再复用。复用的连接若已被对端关闭，最多花一半超时时间就改用新连接。DoH 改为 HTTP/1.1 keep-alive，只有 `Content-Length` 定长、无多余字节、未要求 `Connection: close` 的应答才保留连接。
- 缓存只在隧道生命周期内，停止隧道即清空；切换节点不清缓存，但空闲连接按出站区分，不会走到旧节点。

## DNS 泄露核对（2026-11）

目标：不出现“在境内明文解析境外域名”的路径。三条路径的结论：

1. **走代理的域名不在本地解析。** 隧道里应用先发 DNS 查询，查询按 `dns` 设置转发，默认上游 `via: proxy`；连接按嗅探到的 SNI/`Host` 匹配域名规则，连到应用拿到的地址。local proxy 收到域名时，连接以域名交给节点，由出口解析。
   - 修复：此前 `via: proxy` 的上游按分流规则选出站，GFW 列表配置（`FINAL,DIRECT`）或把国内解析器 IP 分到 `DIRECT` 的规则会让“经代理”的查询以明文 TCP 53 直连发出，所有域名都受影响。现在规则只能把它分到某个节点，`DIRECT`/`REJECT` 一律改走全局目标（`Dispatcher::dns_outbound`、`RoutedOutbound::dns_outbound`）。
2. **IP 规则先解析时用 `dns` 设置，不用系统解析器。** 域名目标命中不带 `no-resolve` 的 `IP-CIDR`/`GEOIP` 时要先拿到地址。
   - 修复：此前这次解析用 `getaddrinfo`，本机解析器明文收到域名（例如 `GEOSITE,cn,DIRECT`、`GEOIP,cn,DIRECT`、`FINAL,Proxy` 这类常见规则下，local proxy 收到的每个境外域名都会先在本地明文解析一次）。现在用 `PolicyResolver`（`src/dns_resolver.rs`）：hosts 本地应答，DNS 规则选上游，`proxy` 上游按上一条经代理，`direct` 上游直连；结果按 TTL 缓存，最长 10 分钟、最多 1024 条。解析失败仍拒绝连接，不回落到系统解析器。连接本身仍以域名发出。
3. **引导解析只限这些名字。** 仍用系统解析器的只有：节点服务器地址（出站拨号、QUIC、WireGuard 端点）、`via: direct` 上游写成域名时的主机名、分到 `DIRECT` 的连接（包括 `via` 为 `DIRECT` 的远程规则集下载）。`via: proxy` 上游写成域名（如 `https://dns.google/dns-query`）时，名字随连接交给节点，不在本地解析。用户自己把境外域名分到 `DIRECT`、或把 DNS 规则指向 `direct` 上游，属于配置选择，不算泄露。

测试：`tests/dns_leaks.rs`（三条路径各一组）与 `src/dns_policy.rs` 单元测试。

## 不在本次范围

- 不做 fake-ip（见下文）。缓存只缩短真实解析，不省掉首次解析。
- 不支持 UDP 上游：UDP 走代理需要逐个出站的 UDP 支持，且容易被干扰。
- 不做 DoH over HTTP/2。HTTP/1.1 keep-alive 已能复用连接，但同一连接上一次只跑一个查询，并发靠多条连接。
- 不支持 DoQ（DNS over QUIC）。

## fake-ip 评估

### 它解决什么

fake-ip 对每个查询立刻回一个保留网段（通常是 `198.18.0.0/15`）里的假地址，并记下“假地址 → 域名”的映射。应用随后连接假地址时，隧道按映射还原出域名，再按域名选路，把域名交给代理解析。

### 对本项目的收益

1. 首包延迟更低：应用不必等真实 DNS 往返（经代理的 DoH 常要几百毫秒）。
2. 不做嗅探也能拿到域名：非 TLS、非 HTTP 的 TCP 协议（例如 SSH、自定义协议）也能按域名规则分流。目前这类连接只能按 IP 规则匹配。
3. 不泄露 DNS：真实解析在代理端完成，本地上游根本收不到查询。

### 代价与风险

1. 状态与内存：要维护一张有上限、可回收的映射表（LRU）。Network Extension 只有约 50 MB 内存，表的大小和老化策略必须控制。
2. 映射丢失：隧道重启或映射被回收后，应用还缓存着假地址，连接会失败。一般做法是 TTL 设得很短（1 秒），关闭隧道时清空系统 DNS 缓存，但 iOS 不提供这个接口。
3. 例外清单：局域网名、NTP、STUN、captive portal 检测、Apple 推送等域名必须拿到真实地址，需要维护 `fake-ip-filter`。
4. 直连流量也会先拿到假地址，要在隧道里替应用解析真实地址再直连，等于在内核里再实现一个解析器（可复用本次的 `dns_policy`）。
5. 绕过 VPN 的应用（自己指定 DNS 服务器或使用 DoH 的应用）不受影响，也就得不到好处。

### 结论与建议

本次不实现 fake-ip。

- SNI/Host 嗅探已覆盖绝大多数流量（HTTPS、HTTP）的域名规则。
- 本次的 hosts、按域名上游和 `via: direct` 已能解决国内外分流解析和 DNS 污染问题。

建议把 fake-ip 列为 P1 可选模式（`dns.mode: "fake-ip"`，默认仍为现在的 `redir-host` 式转发），实现时需要：

- 有上限的 LRU 映射：建议 65536 条，按最近使用回收。
- 应答 TTL 为 1 秒。
- 默认 `fake-ip-filter`：`*.lan`、`*.local`、`time.*.com`、`*.ntp.org`、`stun.*`、`captive.apple.com`、`*.push.apple.com` 等。
- 直连连接由内核用 `dns_policy` 解析出真实地址再发起。
- 统计里加入映射表大小与回收次数，用于在真机上测内存。
