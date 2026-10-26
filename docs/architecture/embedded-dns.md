# 内嵌引擎 DNS：上游、hosts、按域名分流与 fake-ip 评估

适用范围：`crates/engine-embedded`（iOS 隧道、桌面 local proxy 的嵌入式内核）。代码见 `src/dns.rs`、`src/dns_policy.rs`，配置见 `src/config.rs` 的 `DnsConfig`。

## 现状

隧道把应用发往 UDP/53 的查询截下来，不做 UDP 中继，而是在一条新的 TCP 连接上转发给上游。连接经过出站，所以默认在代理一侧解析。

- 域名规则靠连接首包的 TLS SNI / HTTP `Host` 嗅探匹配，不依赖 DNS 结果（见 `sniff.rs`）。
- 桌面 local proxy 收到的就是域名，由出站或代理服务器解析，不经过这里的 DNS。

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
  - `proxy`（默认）：与应用流量相同，走配置的出站或规则；直连模式下走直连。
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

## 不在本次范围

- 不做 DNS 缓存。iOS 系统解析器自带缓存；应用层缓存要和 fake-ip 一起设计（见下文）。
- 不支持 UDP 上游：UDP 走代理需要逐个出站的 UDP 支持，且容易被干扰。
- 不做 DoH over HTTP/2 和连接复用。HTTP/1.1 一问一答最简单，代价是每个查询都要一次 TLS 握手，后续可加连接池。
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
