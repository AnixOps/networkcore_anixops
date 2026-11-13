# 出站多路复用（`multiplex`）与连接复用

本文件是功能表 P14（无队头阻塞多路复用）和 P16（连接池 + 会话票据复用）的设计说明和验收清单。全部为自研实现，没有引入第三方 mux 代码。

## 目标

- 通用协议（Shadowsocks、Trojan、VLESS、VMess）的客户端可以把多条代理连接复用到少数几条到服务器的连接上，省掉每条连接的 TCP + TLS + 协议握手。
- 同一条复用连接上，大流量（下载、上传）不能拖累小流量（网页请求、API 调用）的 P99 延迟。
- 连接复用率不低于 80%：连接池的流复用率，以及 TLS 会话恢复率。

## 线上格式：sing-mux

复用连接就是节点协议的一条普通连接，目标地址写成 `sp.mux.sing-box.arpa:444`。sing-box、mihomo 和我们自己的 `engine-inbound` 服务端都认这个格式（服务端实现见 `crates/engine-inbound/src/sing_mux.rs`）。

```text
会话请求：VERSION(0) PROTOCOL(1 = yamux)
yamux 帧：VERSION(0) TYPE FLAGS(2) STREAM(4) LENGTH(4)，大端
流请求：  FLAGS(2) ATYP ADDR PORT
流应答：  STATUS（0，或 1 加错误信息），在第一段数据前面
```

客户端（`crates/engine-outbound/src/mux.rs`）始终跑 yamux，不管订阅里写的是 smux、yamux 还是 h2mux：sing-mux 服务端接受客户端选的任何一种，而 yamux 每条流在两个方向都有独立的 256 KiB 窗口，一条流读得慢不会卡住整条连接。smux 没有流控，正好会出这个问题。

## 为什么大流量不拖累小流量

队头阻塞有三层，分别处理：

| 层 | 问题 | 处理 |
| --- | --- | --- |
| 接收窗口 | 一条流的数据没人读，堵住整条连接的读取 | yamux 每流窗口，读到半个窗口就补窗口 |
| 发送队列 | 大流量在共享 FIFO 队列里排了几百 KB，小请求排在后面 | `FairQueue`：每流最多排 2 帧（32 KiB），写出时先发控制帧，再发“最近发得最少”的流 |
| TCP 本身 | 丢包重传期间整条 TCP 上的流都要等 | 无法在 TCP 上消除；需要的节点用 QUIC 协议（TUIC、Hysteria 2、ANX QUIC） |

`FairQueue`（`crates/engine-outbound/src/mux/fair.rs`）按每流“衰减字节数”选下一帧：每个流已发送的字节数每 500 ms 减半，选最小的那个。效果是：

- 新开的短请求、交互式流的字节数接近 0，总能插到正在跑的下载前面，最多等一帧（16 KiB）。
- 两个下载同时跑时按字节平分带宽。
- 下载跑久了不会永远垫底：停一会儿字节数就衰减回来。
- 同一条流的帧始终按入队顺序发出（SYN、请求、数据、FIN 都在流自己的队列里）。

服务端 sing-mux 的 smux/yamux 下行也换成了同一个 `FairQueue`，所以“边下载边开网页”在我们自己的节点上两个方向都受益。h2mux 由 HTTP/2 库自己调度，不变。

新流优先放到流最少、排队字节最少的复用连接上，并且按 `max_connections` 分散到多条连接，进一步减少 TCP 层的相互影响。

剩下的一层是内核发送缓冲：TCP 套接字的发送缓冲里如果已经堆了几 MB 大流量数据，小请求还是要排在后面。这一层需要在承载连接上设置 `TCP_NOTSENT_LOWAT`，留作后续改进（见下文）。

## 连接池

- 新流优先复用已有连接：流数少于 `min_streams`，或连接数已到 `max_connections` 时复用；否则新拨一条，直到 `max_connections`。设了 `max_streams` 时，每条连接最多这么多流，连接按需新开。
- 同一时刻只拨一条新连接，突发的一批流不会各拨一条。
- 没有流的连接空闲 `idle_timeout_secs`（默认 60 秒）后关闭。
- 客户端发 `reset_network`（切换网络、休眠唤醒）时，池里的复用连接全部移出：不再接新流，已有的流照常跑完，最后一条结束后关闭；下一条流重新拨号。
- 每 10 秒没收到任何东西就发 yamux ping；15 秒无应答的连接不再接新流，25 秒无应答直接关闭（覆盖切换网络后旧连接已死的情况）。新流 10 秒没收到 ACK 也会关闭连接。
- UDP 不走复用，仍由原协议自己的 UDP 路径承载。

## TLS 会话票据复用

`transport-tls` 现在给每个客户端配置装一个自研的 `TicketStore`（`crates/transport-tls/src/tickets.rs`），替代 rustls 自带的内存缓存：

- 每个服务器保留 64 张 TLS 1.3 票据（rustls 自带的只留 8 张），最多记 64 个服务器。网页加载时一次开几十条连接，8 张票据只够前 8 条恢复会话。
- 每张票据只用一次（RFC 8446 §C.4），避免两条连接因为同一张票据被关联起来。
- `TlsConnector` 统计握手次数和其中恢复会话的次数。

Trojan、VLESS（TLS）、VMess（TLS）通过新的 `TcpOutbound::reuse_stats` 报告这些计数；复用出站在其上加 `mux` 一项。客户端可以用控制命令 `outbound_reuse` 查看：

```json
{"cmd": "outbound_reuse"}
→ {"outbounds": [{"node": "hk-1", "protocol": "trojan", "reuse": {
    "tls_handshakes": 120, "tls_resumed": 117, "tls_resumption_rate": 0.975,
    "mux": {"protocol": "yamux", "scheduler": "fair", "sessions": 2, "sessions_opened": 3,
            "session_failures": 0, "sessions_dead": 1, "streams_opened": 480,
            "streams_reused": 477, "reuse_rate": 0.994}}}]}
```

`outbound_health` 不变（iOS 客户端按固定字段解析它）。

## 配置

`multiplex` 是出站配置的保留字段，与 `via` 一样不交给协议工厂：

```json
{"type": "trojan", "server": "hk.example", "port": 443, "password": "...",
 "tls": {"server_name": "hk.example"},
 "multiplex": {"enabled": true, "protocol": "h2mux", "max_connections": 4, "min_streams": 4}}
```

| 字段 | 默认 | 说明 |
| --- | --- | --- |
| `enabled` | `true` | `false` 等于不写 |
| `protocol` | — | `smux`/`yamux`/`h2mux`，都按 yamux 跑；其他值拒绝 |
| `max_connections` | 4 | 复用连接上限（最大 32）；不能和 `max_streams` 同时用 |
| `min_streams` | 4 | 一条连接先接这么多流，再开下一条；不能和 `max_streams` 同时用 |
| `max_streams` | — | 每条连接最多流数，连接按需开（上限 32 条） |
| `padding`、`brutal` | — | 接受但不生效（服务端不要求） |
| `idle_timeout_secs` | 60 | 1–3600 |
| `scheduler` | `fair` | `fifo` 只用于对比测试 |

校验规则：

- 只有 `shadowsocks`、`trojan`、`vless`、`vmess` 能写 `multiplex`，其他协议拒绝。
- VLESS 带 `flow`（Vision）不能复用：Vision 要把内层 TLS 直接拼到连接上。
- 节点导入：sing-box 的 `multiplex` 和 Clash 的 `smux`（`max-connections` 等横线写法也认）在 `enabled: true` 时转成上面的对象；写了 `max_streams` 就丢掉与之冲突的另外两项；不适用的协议或带 Vision 的 VLESS 直接忽略，节点照常导入。

## 验收

| 项 | 测试 | 标准 |
| --- | --- | --- |
| P14 小请求 P99 | `crates/engine-inbound/tests/mux_client.rs` `bulk_upload_does_not_raise_small_request_p99`：1 MiB/s 上行被大流量占满，同一条复用连接上开 100 个新流做小请求 | 公平队列 P99 < 150 ms，且不到 FIFO 的一半；大流量仍拿到 ≥ 50% 链路 |
| P14 调度 | `fair.rs` 单测：16 帧大流量排队时小帧第一个发出；两条大流量平分 | 确定性 |
| P16 流复用率 | `mux_client.rs` `streams_reuse_pooled_connections`：50 条顺序 + 50 条并发 | 复用率 ≥ 80%，连接数 ≤ 4 |
| P16 TLS 恢复率 | `crates/transport-tls/tests/resumption.rs`：40 条顺序 + 3 轮 24 条并发 | 恢复率 ≥ 80% |
| 端到端 | `crates/engine-embedded/tests/multiplex.rs`：SS-2022 节点 20 条连接共用一条复用连接 | 复用率 ≥ 90% |

CI 实测数字见 PR 描述。

## A2 会话恢复是否默认开启（结论）

已经默认开启，不需要再改：

- 用户 2026-11-10 拍板“会话恢复默认开”，anx PR #238（main 6f4462f）把客户端 `session_resumption` 默认改成 `true`。
- 服务端只有在节点站点数据里有 dest-probe 测出的恢复参数（`ticket_lifetime`、`resume_flight` 等）时才会签发票据；没测过的 dest 不签，客户端就照常走完整握手，不会出错。这一步是面板/agent 的部署工作，由 agent/control 线程负责。
- 本次没有改 A2 代码。需要注意的是 alpha.19 和客户端 beta.3 还不含 #238，下一版客户端要用 anx ≥ 6f4462f 才真正生效。

## 后续

- 承载连接设置 `TCP_NOTSENT_LOWAT`（Linux/macOS/iOS 都支持），把内核发送缓冲里的排队也压到几十 KB，消除最后一层发送侧队头阻塞。需要给 `Dialer` 加一个按连接设置套接字选项的入口。
- h2mux 客户端（目前统一用 yamux，服务端兼容，不影响使用）。
- sing-mux padding（抗流量分析，需要时再做）。
