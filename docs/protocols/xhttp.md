# XHTTP 传输规格（净室实现用）

状态：草案 v0.1（2026-10-26）。适用：`transport-xhttp`（客户端），以及后续的服务端传输（`inbound-transport`）。

## 0. 本文档的用途与净室规则

XHTTP（旧名 SplitHTTP）是 Xray-core 的 HTTP 传输：把一条代理流拆成普通的 HTTP 请求，可以经过 CDN、反向代理和只放行 HTTP 的网络。Xray-core 是 MPL-2.0，本仓库是 Apache-2.0：

1. 本文档只用自然语言和表格描述线上格式与行为，不包含 Xray 源代码或其逐行翻译。
2. 实现只依据本文档编写；与 Xray 不一致时以 CI 中 Xray 服务端的黑盒互通结果为准，先改本文档再改代码。
3. Xray 二进制只在 CI 中下载运行（`reality-interop.sh`），不随产物分发。

信息来源：Xray 官方文档的 XHTTP 配置说明、公开讨论 XTLS/Xray-core#4113（"XHTTP: Beyond REALITY"）、公开的 Xray 内部机制说明（xray-internals）。凡标注 **[待实测]** 的条目须经互通 CI 确认后才能去掉标注。

## 1. 配置

出站 `transport` 对象（VLESS 非 REALITY）：

```json
{"type": "xhttp", "path": "/xh", "host": "cdn.example", "mode": "auto",
 "headers": {"X-Edge": "1"}, "x_padding_bytes": "100-1000",
 "sc_max_each_post_bytes": 1000000, "sc_min_posts_interval_ms": 30,
 "no_grpc_header": false}
```

- `type` 也接受 `splithttp`。字段同时接受 Xray 的写法（`xPaddingBytes`、`scMaxEachPostBytes`、`scMinPostsIntervalMs`、`noGRPCHeader`），可以直接粘贴 `xhttpSettings`。
- 范围字段可写成数字、`"from-to"` 或 `{"from": a, "to": b}`；每次使用时在范围内取均匀随机值。
- 默认值：`x_padding_bytes` 100–1000，`sc_max_each_post_bytes` 1000000（不小于 1024），`sc_min_posts_interval_ms` 30。
- `path` 规范化为以 `/` 开头和结尾；`?` 之后的查询串原样附在每个请求上。

## 2. HTTP 版本

与 Xray 相同，按 TLS 的 ALPN 配置决定：

| 条件 | 版本 |
| --- | --- |
| 无 TLS | HTTP/1.1 |
| ALPN 恰好为 `http/1.1` | HTTP/1.1 |
| ALPN 恰好为 `h3` | HTTP/3（本实现暂不支持，配置报错） |
| 其他（含空列表） | HTTP/2；空列表时客户端提供 `h2` |

REALITY 上的 XHTTP（Xray 此时用 HTTP/2 和 `stream-one`）暂不支持。

## 3. 会话与模式

客户端为每条代理流生成会话 id（随机 UUID v4 的小写带连字符文本）。下行始终是一个流式响应的 body，原始字节，无额外分帧。

| 模式 | 下行 | 上行 | 本实现支持的版本 |
| --- | --- | --- | --- |
| `packet-up` | `GET {path}{session}` | `POST {path}{session}/{seq}`，`seq` 从 0 起的十进制序号，body 为一段上行数据，带 `Content-Length` | HTTP/1.1、HTTP/2 |
| `stream-up` | `GET {path}{session}` | 一个流式 `POST {path}{session}`，body 即上行流 | HTTP/2 |
| `stream-one` | `POST {path}` 的响应 body | 同一个 `POST {path}` 的请求 body | HTTP/2 |

- `auto`：非 REALITY 时为 `packet-up`。
- `packet-up`：每段上行 body 不超过 `sc_max_each_post_bytes`；相邻两次上传的间隔不小于 `sc_min_posts_interval_ms`。客户端缓冲期间写入的数据会合并成一段。服务端按 `seq` 重排后交给协议层。本实现按顺序逐个发送并等待 `200`。
- 流式 `POST`（`stream-up`、`stream-one`）默认带 `Content-Type: application/grpc`，让 CDN 不缓冲请求 body；`no_grpc_header` 关闭它。
- `stream-up` 的 `POST` 响应 body 可能被服务端周期性写入 `X` 填充以保活，客户端读出丢弃。
- 服务端对各请求返回 `200`；下行响应带 `Cache-Control: no-store`、`X-Accel-Buffering: no`，通常还有 `Content-Type: text/event-stream`。非 `200` 即会话失败。
- HTTP/1.1 下 `packet-up` 使用两条连接：一条承载 `GET`，另一条按 keep-alive 依次承载上行 `POST`（服务端要求关闭时重连）。HTTP/2 下每条代理流使用一条独立连接（暂不实现 Xray 的连接复用 `xmux`）。

## 4. 填充

每个请求带 `Referer: {scheme}://{host}{请求路径}?x_padding=XXX…`，`X` 的个数在 `x_padding_bytes` 范围内随机。`X` 在 HPACK/QPACK 的 Huffman 表里是 8 位码，压缩后长度仍随机。服务端检查该长度落在自己配置的范围内，否则返回 `400`。服务端响应可带 `X-Padding: XXX…` 头，客户端忽略。

Xray 较新版本的可选混淆参数（填充位置、会话/序号位置、上行数据放在头或 cookie 等）默认关闭，本实现暂不支持。**[待实测]** 默认配置下服务端仍按上述 `Referer` 规则校验。

## 5. 请求头

- `Host`/`:authority`：`host`，否则 `headers` 中的 `Host`，否则 TLS 服务器名或服务器地址（非默认端口时带端口）。
- `User-Agent`：默认为桌面 Chrome 的 UA，可由 `headers` 覆盖。
- `headers` 中的其他头原样发送；`Content-Length`、`Transfer-Encoding`、`Connection`、`Referer` 由传输自己生成，配置中的同名项被忽略。

## 6. 互通验证

`REALITY interop (Linux)` 任务启动 Xray 的 VLESS + XHTTP 入站（路径 `/xh`，无 TLS 一个、TLS 且 ALPN `h2`/`http/1.1` 一个），`outbound-vless/tests/xhttp_interop.rs` 依次用以下组合下载 1 MB 并回显 300 KB：无 TLS HTTP/1.1 `packet-up`、TLS HTTP/1.1 `packet-up`、TLS HTTP/2 的 `packet-up`、`stream-up`、`stream-one`。

## 7. 后续

- 服务端传输：`inbound-transport` 的 `xhttp`，同一会话的请求可以分散在多条连接上，需要进程内会话表和 `seq` 重排。
- HTTP/3、REALITY 上的 XHTTP、`xmux` 连接复用、`downloadSettings`（上下行分离到不同服务器）。
- VMess、Trojan 出站接入和订阅链接（`type=xhttp`、`mode`、`extra`）导入。
