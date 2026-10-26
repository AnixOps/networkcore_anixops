# Mieru 协议规格（净室实现用，TCP 客户端）

状态：草案 v0.1（2026-10-26）。适用：`outbound-mieru`（客户端）。

## 0. 来源与净室规则

1. 本文档只依据两类来源。
   - 公开协议说明：enfein/mieru 仓库的 `docs/protocol.md`、`docs/server-install.md` 和 `docs/client-install.md`。
   - 黑盒抓包：CI runner 上让官方 `mieru` 客户端和 `mita` 服务端 v3.39.0 互连，抓下双方流量，再用本次运行生成的测试凭据解密。

   来自抓包的结论标为 **[实测]**。
2. 实现者只读本文档写 Rust 代码。不打开 mieru、mihomo 等 GPL 实现的源码，不移植、不逐行翻译。
3. 互通性以官方 `mita` 的黑盒行为为准。`mita` 只在 CI 中下载运行，不随产物分发。
4. 本文档与官方行为不符时，先改本文档，再改代码。

除特别说明外，所有整数都是大端序。

## 1. 密钥

- `hashed = SHA-256(password || 0x00 || username)`。
- `t` 取 Unix 秒，四舍五入到 120 的整数倍。
- `salt = SHA-256(u64(t))`，`u64(t)` 是 8 字节大端。
- `key = PBKDF2-HMAC-SHA256(hashed, salt, 迭代 64 次, 32 字节)`。

服务端依次尝试 `t - 120`、`t`、`t + 120` 三个 salt，所以双方时钟差不能超过约 4 分钟。两个方向用同一个 key。

AEAD 是 XChaCha20-Poly1305：nonce 24 字节，tag 16 字节，没有附加数据 **[实测]**。

## 2. Nonce

TCP 连接的每个方向都以自己的 24 字节明文 nonce 开头，前面没有任何字节 **[实测]**。也就是说，分段格式里的 “padding 0” 在 TCP 上长度为 0。

- 第 20..24 字节是用户提示，取 `SHA-256(username || nonce[0..16])` 的前 4 字节。客户端和服务端的 nonce 都带这个提示 **[实测]**。
- 官方客户端的 nonce 前 12 字节是可打印 ASCII（0x20..0x7e）**[实测]**。本实现照做，第 12..20 字节填随机数。

同一方向上每做一次 AEAD 运算（加密或解密），都先用当前 nonce，再把整个 24 字节当一个大端整数加 1。第一次运算直接用明文发出的 nonce **[实测]**。同一连接上换了会话，计数也不重置 **[实测]**。

## 3. 分段

一个 TCP 分段依次是：

```
seal(metadata[32])   48 字节
padding 1            长度 = prefix length（只有数据元数据有）
seal(payload)        长度 = payload length + 16；payload 为空时没有这一段
padding 2            长度 = suffix length
```

payload 用元数据之后的下一个 nonce 加密。padding 不加密。

官方两端的 suffix 长度在 0 到约 200 之间，prefix 长度都是 0 **[实测]**。本实现的 padding 用可打印 ASCII：prefix 取 0，suffix 随机取 0–127 字节。

### 3.1 会话元数据（类型 2–5）

| 偏移 | 长度 | 字段 |
| --- | --- | --- |
| 0 | 1 | 类型：2 打开请求，3 打开响应，4 关闭请求，5 关闭响应 |
| 1 | 1 | 0 |
| 2 | 4 | 时间戳，Unix 分钟 |
| 6 | 4 | 会话 ID |
| 10 | 4 | 序号 |
| 14 | 1 | 状态（0 表示成功） |
| 15 | 2 | payload 长度（不超过 1024） |
| 17 | 1 | suffix 长度 |
| 18 | 14 | 0 |

### 3.2 数据元数据（类型 6–9）

| 偏移 | 长度 | 字段 |
| --- | --- | --- |
| 0 | 1 | 类型：6 客户端到服务端的数据，7 服务端到客户端的数据，8 客户端确认，9 服务端确认 |
| 1 | 1 | 0（类型 10/11 在这里放低熵模式） |
| 2 | 4 | 时间戳，Unix 分钟 |
| 6 | 4 | 会话 ID |
| 10 | 4 | 序号 |
| 14 | 4 | 未确认序号 |
| 18 | 2 | 窗口大小 |
| 20 | 1 | 分片号 |
| 21 | 1 | prefix 长度 |
| 22 | 2 | payload 长度（不超过 32768） |
| 24 | 1 | suffix 长度 |
| 25 | 7 | 0（类型 10/11 在这里放低熵字段） |

在 TCP 上，官方两端发的未确认序号都是 0，窗口都是 4096，分片号都是 0，也不发确认分段 **[实测]**。

类型 10/11（低熵编码）本实现不支持，收到时按无效数据处理。

## 4. TCP 会话流程

序号在一个方向上逐段递增 **[实测]**。客户端从打开请求的 0 开始，服务端从打开响应的 0 开始。会话 ID 随机且不为 0。

1. 客户端发 `openSessionRequest`，它的 payload 就是会话字节流的开头。流的开头是一个不带问候的 SOCKS5 请求：`05 01 00 ATYP ADDR PORT` **[实测]**。官方客户端有三种做法 **[实测]**：
   - 标准握手：打开请求只带这个 SOCKS5 请求，然后等服务端的打开响应。
   - 0-RTT 模式（`HANDSHAKE_NO_WAIT`）：打开请求带 SOCKS5 请求加首段数据，最多 1024 字节。
   - 0-RTT 下首次写入很大时：打开请求的 payload 为空，SOCKS5 请求放在第一个数据分段的开头。

   可见服务端是在会话字节流里读请求，不管请求落在哪个分段。
2. 服务端回 `openSessionResponse`，状态 0，没有 payload。随后发数据分段，字节流以 SOCKS5 回复开头：`05 REP 00 ATYP BND.ADDR BND.PORT`。目标连不上或不允许访问时，`REP = 05` **[实测]**。
3. 之后双方用数据分段传输数据。
4. 任一方发 `closeSessionRequest` 结束会话，另一方回 `closeSessionResponse`。抓包里两端各自都发了这两种分段 **[实测]**。

本实现的客户端行为如下。

- 一条 TCP 连接只跑一个会话（不复用）。
- 连接建立后立即发带 SOCKS5 请求的打开请求，不等打开响应就发数据。因为不等应用写入，服务端先说话的协议也能用。
- 收到关闭请求时，先回关闭响应，再当作流结束。
- 应用关闭写方向时，只有在服务端的流已经结束后才发自己的关闭请求；在此之前只做 flush。原因是 Mieru 没有半关闭，提前关闭会话会截掉服务端还没发完的数据。

## 5. 暂不实现

- UDP 传输（每包一个 nonce，分段受 MTU 限制）和 SOCKS5 UDP associate（封装格式为 `00 | u16 长度 | 数据 | ff`）。
- 一条连接上复用多个会话。
- 低熵编码（类型 10/11）和自定义流量模式（`trafficPattern`，即分享链接里的 `traffic-pattern` 参数）。

## 6. 分享链接与 Clash

- 简单分享链接的格式为 `mierus://user:pass@host?profile=…&port=P&protocol=TCP&port=A-B&protocol=UDP&mtu=…&multiplexing=MULTIPLEXING_…&handshake-mode=…&traffic-pattern=…`。
  - `port` 和 `protocol` 成对重复出现，`port` 可以是一个范围。
  - 导入时取第一组 TCP。
  - 本仓库旧的 `host:port` 写法继续接受。
- Clash（mihomo）的 `type: mieru` 条目带这些字段：`server`、`port` 或 `port-range`、`transport`（取 `TCP`）、`username`、`password`、`multiplexing`。
- 标准 `mieru://` 链接是整份客户端配置的 base64 protobuf，不导入。

## 7. 互通测试

`REALITY interop (Linux)` 任务在 runner 上安装 enfein/mieru GitHub release 里的官方 `mita` 包，不分发这个包。然后用 `--ignored` 运行 `outbound-mieru` 的 `mieru_interop` 测试。
