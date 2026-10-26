# Snell 协议规格（净室实现用）

状态：草案 v0.1（2026-10-26）。适用：`outbound-snell`（客户端）与 `inbound-snell`（服务端）。

## 0. 本文档的用途与净室规则

Snell 是 Surge 团队的闭源代理协议。本仓库是 Apache-2.0 内核，实现必须与 GPL 代码隔离：

1. 本文档只用自然语言、表格和常数描述**线上格式、状态机和算法**，不包含任何其他实现的源代码或逐行翻译。
2. 实现者**只读本文档**编写 Rust 代码，不打开 open-snell、sing-snell、mihomo 等 GPL 仓库，也不反编译 Surge / snell-server。
3. 互通性只以官方 snell-server 二进制的黑盒行为为准（CI 中下载运行，不随产物分发）。
4. 本文档发现与官方行为不符时，先改本文档再改代码。

信息来源（事实层面）：

- [S1] Surge 官方：[Snell 发布说明](https://kb.nssurge.com/surge-knowledge-base/release-notes/snell)、[Snell v6 技术介绍](https://nssurge.com/blog/snell-v6/)
- [S2] 公开实现中可观察到的协议事实：open-snell（v1–v3）、sing-snell（v4–v6，其作者称来自对 Surge 6.7.0 / snell-server 的逆向）
- [S3] 官方 snell-server 的黑盒互通（CI，待补充观测记录）

凡标注 **[待实测]** 的条目必须在互通 CI 中确认后才能去掉标注。

## 1. 术语与通用约定

| 名称 | 含义 |
| --- | --- |
| PSK | 预共享密钥，字节串。v6 服务端要求长度 12–255 字节 |
| 方向 | 客户端→服务端（上行）和服务端→客户端（下行）各自独立：各有自己的 salt、密钥、nonce、序号和整形状态 |
| salt | 每个方向首次发送数据时生成的 16 字节随机数，同一 TCP 连接内只发送一次 |
| record / 帧 | 加密分帧的基本单位 |
| 零块（zero chunk） | 载荷长度为 0 的帧，表示"当前逻辑请求在本方向的 EOF" |
| u16be | 2 字节大端无符号整数 |

所有多字节长度字段为大端；nonce 计数器为小端（见 §2）。

## 2. 密码学（v1–v6 共用）

### 2.1 会话密钥

```
k = Argon2id(password = PSK, salt = salt, t = 3, m = 8 KiB, p = 1, 输出 32 字节)
```

- v1：AEAD = ChaCha20-Poly1305，密钥 = k 全部 32 字节。
- v2–v6：AEAD = AES-128-GCM，密钥 = k 的前 16 字节。
- v1–v3 的服务端对首帧先尝试 AES-128-GCM，失败再尝试 ChaCha20-Poly1305（兼容 v1 客户端）。

### 2.2 nonce

nonce 为 12 字节，初始全 0。前 8 字节是小端计数器，后 4 字节恒为 0。**每调用一次 AEAD seal / open，计数器加 1**（帧头和载荷各算一次）。上行和下行各自从 0 开始，同一连接内复用（§4）时不重置。

AEAD tag 长度 16 字节。

## 3. 请求与回复（v1–v6 共用的明文语义）

### 3.1 请求（客户端发出的第一段明文）

| 偏移 | 长度 | 字段 |
| --- | --- | --- |
| 0 | 1 | 请求版本，恒为 `0x01` |
| 1 | 1 | 命令 |
| 2 | 1 | clientID 长度 L（0–255） |
| 3 | L | clientID（多用户服务端的 userkey；单用户为空） |
| 3+L | … | 命令参数 |

命令：

| 值 | 名称 | 参数 |
| --- | --- | --- |
| `0x00` | PING | 无 |
| `0x01` | CONNECT（一次性） | 目标地址 |
| `0x05` | CONNECTv2（可复用） | 目标地址 |
| `0x06` | UDP | 无 |

TCP 目标地址 = 主机字符串长度（1 字节）· 主机字符串 · 端口 u16be。IP 字面量也按字符串写（如 `"1.2.3.4"`、`"2001:db8::1"`，不带方括号）。

客户端行为约定（与官方客户端一致）：

- v4、v5、v6 客户端的 TCP 请求**总是用 `0x05`**，即使未开启复用。
- v1 客户端用 `0x01`；v2/v3 开启复用时用 `0x05`。
- 0-RTT：请求与应用层首段数据放在**同一明文缓冲区**里一次加密发送。v6 首帧载荷超过 0xFFFF 时切成多帧。

服务端读取请求时：命令为 PING 时**不再读取** clientID 字节，直接回 PONG 并关闭连接。

### 3.2 回复（服务端发回的第一段明文）

| 首字节 | 含义 | 后续 |
| --- | --- | --- |
| `0x00` | TUNNEL / READY | TCP：紧跟目标的首段数据（可为空）；UDP：无 |
| `0x01` | PONG | 无 |
| `0x02` | ERROR | 错误码（1 字节）· 消息长度（1 字节）· 消息 |

- TCP 回复是"惰性"的：服务端在收到目标的第一段数据时才发 `0x00`，并把这段数据拼在同一帧里。
- 客户端收到 ERROR 帧时，该帧必须正好是"码 + 长度 + 消息"，不得有尾随字节，否则视为协议错误。
- 已知错误码 [S2]：`0x65` + `"Remote EOF"`：可复用请求中，目标在发出任何数据前就关闭；服务端发送后中止并关闭 TCP。v4/v5 的一次性 CONNECT 用 `0xFF` + `"end of file"`。连接目标失败时，错误码为系统 errno，消息为错误文本，最长 250 字节 **[待实测]**。
- 这种结构化错误让客户端能区分"节点不可用（认证/解密失败、TCP 断开）"与"目标不可达（ERROR 回复）"，健康检查必须利用这一区别。

## 4. 连接复用（CONNECTv2，v2+）

1. 客户端在一条 TCP 连接上发送 `0x05` 请求，之后双向转发数据。
2. 任一方向结束时，发送方写一个**零块**作为该方向的 EOF（相当于半关闭）。
3. 双方都收到对方的零块后，该逻辑请求结束，TCP 连接与加密状态（密钥、nonce、v6 序号与整形状态）全部保留，下一个请求直接作为下一帧发出，**不发新 salt**。
4. 服务端在本方向写完零块后，若客户端仍在发数据，就继续读取并丢弃，直到收到客户端的零块，然后把下一帧当作新请求解析。
5. 客户端在发出零块后若仍收到数据，也读取并丢弃；累计丢弃超过 0x80001 字节就关闭连接。服务端采用相同上限。
6. 客户端连接池参数（参考值）：最多 10 条空闲连接，空闲超过 180 秒关闭，每 20 秒扫描一次。
7. 非复用（`0x01`）请求：服务端在目标 EOF 时直接关闭 TCP，不写零块。

### 4.1 UDP over TCP（v3+）

1. 客户端发送命令 `0x06`（带 clientID，无地址）。**请求必须单独成帧**，同一帧内不能跟随数据报，否则服务端直接断开。
2. 服务端回复 `0x00`。客户端收到回复后才开始发送数据报。
3. 之后每一帧承载**恰好一个**数据报。
   - 上行帧：`0x01` · 地址 · 端口 u16be · 载荷。地址为域名时 = 长度（1–255）· 域名；为 IP 时 = `0x00` · 族字节（`0x04` 表示 IPv4 4 字节，`0x06` 表示 IPv6 16 字节）· IP。
   - 下行帧：族字节（`0x04`/`0x06`）· IP · 端口 u16be · 载荷。下行源地址总是 IP。客户端遇到其他族字节时静默丢弃该帧。
4. 数据报大于单帧最大载荷时直接丢弃，不分片。

## 5. v1–v3 帧格式

```
上行/下行首次：salt(16)
每帧：        seal(u16be 长度 N) ‖ tag(16) ‖ seal(载荷 N 字节) ‖ tag(16)
```

- N 的有效范围 1–0x3FFF；**N = 0 即零块**，此时只有长度部分，没有载荷部分。
- 加密使用 §2 的 AEAD，无附加数据（AAD 为空）。

### 5.1 obfs（v1–v4）

obfs 套在加密流外层，只影响 TCP 首个读写：

- **http**（v1–v4）：客户端首次写入时，在数据前加一个 HTTP 请求头：

  ```
  GET <uri> HTTP/1.1\r\n
  Host: <obfs-host>\r\n
  User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.<9..14>; rv:64.0) Gecko/20100101 Firefox/<22..64>.0\r\n
  Upgrade: websocket\r\n
  Connection: Upgrade\r\n
  Content-Length: <首段数据长度>\r\n
  Sec-WebSocket-Key: <16 随机字节的 base64>\r\n
  \r\n
  ```

  默认 `obfs-host = bing.com`、`uri = /`。User-Agent 中的两个版本号和 WebSocket key 每进程随机取一次。之后的写入原样透传。服务端首次写入时加一个 `HTTP/1.1 101 Switching Protocols` 响应头，包含 `Server: nginx/1.x.y`、`Date`、`Upgrade: websocket`、`Connection: Upgrade`、`Sec-WebSocket-Accept`。双方读取时都丢弃到第一个 `\r\n\r\n`（含）为止，不检查任何头部。
- **tls**（v1–v3）：伪 TLS 1.2 ClientHello，首段载荷（最多 0x400 字节）放进 session ticket 扩展，其余数据封装成 application_data 记录（每条最多 0x4000 字节）。默认 host `cloudfront.net`。格式与 simple-obfs 的 tls1.2_ticket 兼容 **[待实测；第二阶段实现]**。
- v6 取消 obfs，改用 `mode`（§7）。

## 6. v4 / v5 帧格式与整形

### 6.1 帧

```
每方向首次：salt(16)
每帧：      seal(帧头 7 字节) ‖ tag(16) ‖ 填充(P 字节) ‖ seal(载荷 N 字节) ‖ tag(16)
```

帧头明文：

| 偏移 | 长度 | 字段 |
| --- | --- | --- |
| 0 | 1 | 帧版本，恒为 `0x04` |
| 1 | 2 | 保留，写 0 |
| 3 | 2 | 填充长度 P（u16be） |
| 5 | 2 | 载荷长度 N（u16be），0–0x3FFF |

- 帧头和载荷的 AEAD 均无 AAD。
- **N = 0 为零块**：只有帧头，P 必须为 0，没有载荷部分。接收方若在零块之后的同一读缓冲中还有未处理数据，视为错误（"ZERO CHUNK with remaining data"）。
- **交织**：发送方先加密载荷得到密文 C（含 tag），生成填充 P，再对 `i = 0, 2, 4, …, min(|P|, |C|) − 1`（只取偶数下标）交换 `P[i]` 与 `C[i]`。接收方读出 P 与 C 后做同样的交换即可还原，然后解密 C。

### 6.2 发送方分帧（整形）

常数：`FRAME = 1460`，首帧开销 `55`（salt 16 + 帧头 23 + tag 16），后续帧开销 `39`，`MAXP = 0x3FFF`，空闲重置 `31` 秒。

- 每个方向在首次发送时，随机选一个初始填充长度 `PAD0 ∈ [256, 511]`。
- **只有首帧带填充**：首帧载荷非空时 P = PAD0，其余所有帧 P = 0。
- 载荷上限 `limit`：
  - 首帧：`FRAME − 55 − PAD0`（首包恰好落在一个 1460 字节的 MSS 内）。
  - 之后：若距上次写入不足 31 秒且已有记录的上限，就用该上限；否则用 `FRAME − 39`。
  - 每次应用层写调用开始时取一次 limit，并立刻把下次的上限更新为 `min(limit + 1421, MAXP)`；本次调用内的所有分帧都用同一个 limit。写零块时同样推进一次。
- **填充内容（比特配平）**：设密文 C（含 tag）中 1 的个数为 ones（只统计长度向下取整到 4 字节倍数的部分），zeros = 8·|C| − ones。
  - 若 zeros ≤ 0，或 ratio = ones/zeros ∉ (0.5, 1.6)：填充用随机字节。
  - 否则选目标比例 `T = base + r/10`，r 为 [0, 1) 均匀随机；base 在 zeros ≥ ones 时取 1.6，否则取 0.4。
  - 需要的填充 1 比特数 `K = ⌊8·(|P| + |C|) · T/(T+1)⌋ − ones`。若 K ∉ [0, 8·|P|] 就用随机字节，否则把恰好 K 个 1 比特随机打散到填充的 8·|P| 个比特中（均匀洗牌）。比特在字节内按低位在前编号。
  - 效果：首包整体每字节平均 1 比特数约为 4.9 或 2.3，偏离均匀随机数据的 4.0。这一项只影响流量形态，接收方不校验。

### 6.3 v5 的差异

- TCP 线上格式与 v4 相同；v5 服务端兼容 v4 客户端。
- 服务端用 MSS 1460 计算首帧与增长窗口，与 §6.2 一致。
- v5 服务端记录首帧 salt 做防重放（两代各 500000 条的 Bloom 过滤器，误判率 1e-10）；重复时中止并报 "Duplicated salt detected" [S2]。我们的入站必须实现等效的防重放。
- QUIC Proxy Mode（UDP over UDP）**不实现**：官方 v6 已删除该模式。

## 7. v6

### 7.1 模式

| `mode` | 加密 | 整形 | salt 位置 | 帧上限 |
| --- | --- | --- | --- | --- |
| `default` | AES-128-GCM | 画像整形 | 藏在 salt 块中（§7.4） | 0xFFFF |
| `unshaped` | AES-128-GCM | 无 | 首 16 字节 | 0xFFFF |
| `unsafe-raw` | 无 | 无 | 无 | 0xFFFF |

客户端与服务端的 mode 必须一致，否则无法通信。

帧头与 v4 相同（版本 `0x04`、保留 2 字节、P、N），但 N 最大 0xFFFF。

### 7.2 unshaped

```
每方向首次：salt(16)
每帧：      seal(帧头) ‖ tag ‖ seal(载荷) ‖ tag
```

- 无填充：P 必须为 0，保留字节必须为 0，否则视为错误。
- AAD 为空。N = 0 为零块。
- 首帧载荷超过 0xFFFF 时，salt 后连续写多帧。

### 7.3 unsafe-raw

每帧 = 明文帧头 7 字节 ‖ 明文载荷 N 字节。P、保留字节必须为 0。N = 0 为零块。

### 7.4 default：协议画像

画像由 PSK 确定性派生，两端各算一次，与连接无关。

#### 7.4.1 基础函数

以下运算都在 64 位无符号整数上进行，乘法、加法按 2^64 取模。

- `mix64(x)`（SplitMix64 终结函数）：
  `x ^= x >> 30; x *= 0xbf58476d1ce4e5b9; x ^= x >> 27; x *= 0x94d049bb133111eb; x ^= x >> 31`
- `fold(y) = (y ^ (y >> 32))` 的低 32 位。
- `G = 0x9e3779b97f4a7c15`
- `PRF32(ns, label, a, b) = fold(mix64(ns ^ (b·0x589965cc75374cc3 + 0x33a213ec50ffe2e9) ^ (label·G) ^ (a·0xe7037ed1a0b428db + 0x8f3907f7b2b80c35)))`
- `STATIC(label, domain) = PRF32(ns(label), label, 0, domain)`
- `pick(raw, lo, hi) = lo + raw mod (hi − lo + 1)`
- `PRFBYTES(label, a, 长度 n)`：`s = ns(label) ^ (a·0xd6e8feb86659fd93 + 0xb57de1f3f82cb33f) ^ (label·0xa24baed4963ee407) ^ (n·0x165667b19e3779f9 + 0x0d4cd3e7b14a36d7)`；循环：`s += G`，取 `mix64(s)` 的 8 个字节（低字节在前）依次输出，直到输出满 n 字节。

#### 7.4.2 画像密钥与命名空间

```
secret = BLAKE2b-256( SEED ‖ PSK )
SEED   = 8d 41 a7 13 5c e2 09 bb 70 2f d6 94 33 18 c0 6e 4a 91 25 fd b8 03 77 ac   (24 字节)
```

把 secret 拆成 4 个小端 u64：s0..s3。命名空间：

```
NS(label, seed) = mix64( label·0xd6e8feb86659fd93 ^ (seed + 0xa0761d6478bd642f) ^ s0 ^ (s1 + G) ^ rotl(s2, 17) ^ rotr(s3, 11) )
```

| 命名空间 | label | seed |
| --- | --- | --- |
| profile | 5 | 0xb46c2e7d9a1538f1 |
| prefix | 0 | 0x5d9217c083e64ab9 |
| motif | 2 | 0xa71f0c54d8396e2b |
| salt | 3 | 0x3e8a91b52740f6cd |
| mix | 16 | 0xc9f4260b7d1e835a |
| chunk | 21 | 0x62d0b5e19c4a783f |
| write | 28 | 0x917b3c48e6a205d4 |

PRF 标签（label）及其所属命名空间 `ns(label)`：

| label | 名称 | 命名空间 |
| --- | --- | --- |
| 0 | padding | prefix |
| 1 | bit-percent | prefix |
| 2 | motif | motif |
| 3 | mix-offset | mix |
| 5 | profile-id | profile |
| 6 | generator | profile |
| 7 | pad-min | profile |
| 8 | pad-max | profile |
| 9 | pad-count | profile |
| 10 | pad-interval | profile |
| 11 | small-limit | profile |
| 12 | bit-min | profile |
| 13 | bit-max | profile |
| 14 | prefix-min | prefix |
| 15 | prefix-max | prefix |
| 16 | mix-mode | mix |
| 17 | mix-rounds | mix |
| 18 | mix-stride | mix |
| 19 | mix-offset-base | mix |
| 20 | mix-block | mix |
| 21 | chunk-policy | chunk |
| 22 | chunk-initial / first-cap | chunk |
| 23 | chunk-max | chunk |
| 24 | chunk-step | chunk |
| 25 | chunk-jitter | chunk |
| 26 | chunk-bucket | chunk |
| 27 | idle-reset | profile |
| 28 | write-policy | write |
| 29 | write-first | write |
| 30 | write-bucket | write |
| 31 | write-seq | write |
| 32 | write-jitter | write |
| 33 | record-prefix | prefix |
| 34 | payload-pad | prefix |
| 35 | write-target | write |
| 36 | write-jitter-v | write |
| 37 | write-next | write |
| 38 | chunk-size | chunk |
| 39 | chunk-jitter-v | chunk |

注意：salt 命名空间只在 §7.4.4 中直接使用，不经过上表映射；label 3 经上表映射到 mix 命名空间。

域常数：`HS = 0x7053`、`MIXHS = 0x51a7`、`CHUNK0 = 0xf17c`、`EXTRA = 0x2da`。

#### 7.4.3 画像参数

下表中 `S(label, d)` 即 `STATIC(label, d)`；d 省略时为 0。参数按表中顺序计算（后面的参数依赖前面的）。

| 参数 | 计算 |
| --- | --- |
| padMin | pick(S(7), 0x18, 0xa0) |
| padMax | min(padMin + pick(S(8), 0xa0, 0x3c0), EXTRA) |
| hsPrefixMin | pick(S(14, HS), 0x10, 0x60) |
| hsPrefixMax | min(hsPrefixMin + pick(S(15, HS), 0x10, 0xa0), 0x80)；随后 hsPrefixMin = min(hsPrefixMin, hsPrefixMax) |
| saltPrefixLen | pick(S(33, HS), hsPrefixMin, hsPrefixMax) |
| saltBlockLen | 16 + saltPrefixLen |
| hsMixRounds | pick(S(17, MIXHS), 1, 4) |
| hsMixStride | pick(S(18, MIXHS), 0x11, 0xfb) |
| prefixMin | pick(S(14), 0x08, 0x50) |
| prefixMax | min(prefixMin + pick(S(15), 0x10, 0xa0), 0x80)；随后 prefixMin = min(prefixMin, prefixMax) |
| chunkInitial | max(0x60, min(pick(S(22), 0x200, 0x5b4), 0x5b4)) |
| firstRecordCap | max(0x100, min(pick(S(22, CHUNK0), 0x100, 0x300), min(chunkInitial, 0x300))) |
| chunkMax | max(pick(S(23), 0x2000, 0x3fff), chunkInitial) |
| generator | S(6) & 3 |
| padCount | pick(S(9), 2, 8) |
| padInterval | pick(S(10), 2, 0x0b) |
| smallLimit | pick(S(11), 0x60, 0x300) |
| bitMin | pick(S(12), 0x18, 0x29) |
| bitMax | pick(S(13), 0x3a, 0x4c) |
| mixMode | S(16) mod 3 |
| mixRounds | pick(S(17), 1, 3) |
| mixStride | pick(S(18), 2, 13) |
| mixOffsetBase | pick(S(19), 0, 15) |
| mixBlock | pick(S(20), 8, 0x40) |
| chunkPolicy | S(21) mod 3 |
| chunkStep | min(pick(S(24), 0x400, 0x1000), 0xb68) |
| chunkJitter | min(pick(S(25), 0x10, 0xc0), 0xb6) |
| idleResetSec | pick(S(27), 0x0c, 0x5a) |
| writePolicy | S(28) mod 3 |
| writeFirst | pick(S(29), 4, 8) |
| writeJitter | pick(S(32), 0x08, 0x60) |
| writeJitterPct | pick(S(28, 0x504c), 8, 0x30) |
| g1 | pick(S(6, 1), 0x18, 0x80) |
| g2 | pick(S(6, 2), 0x10, 0x60) |
| g3 | pick(S(6, 3), 0x10, 0x60) |
| g4 | pick(S(6, 4), 0x00, 0x09) |
| g5 | pick(S(6, 5), 0x01, 0x08) |
| g6 | pick(S(6, 6), 0x07, 0x17) |
| chunkBuckets[i], i=0..7 | pick(S(26, i), 0x1000, chunkMax) |
| writeBuckets[i], i=0..7 | pick(S(30, i), 0x140, 0x5b4) |
| writeSeq[i], i=0..7 | pick(S(31, i), 0x168, 0x5b4) |

#### 7.4.4 salt 块

每个方向的首帧前有一个 `saltBlockLen` 字节的 salt 块，16 字节 salt 散落其中。

- 置换 PRF：`SP(d, i) = fold(mix64((i·0x589965cc75374cc3 + 0x33a213ec50ffe2e9) ^ (nsSalt ^ 0xdaa66d2c7ddf743f) ^ (d·0xe7037ed1a0b428db + 0x8f3907f7b2b80c35)))`，其中 nsSalt 是 salt 命名空间。
- 置换 perm（长度 L = saltBlockLen）：从恒等排列开始，做 hsMixRounds 轮（至少 1 轮）。第 r 轮（r 从 0 开始）令 d = MIXHS + r，对 i = 0..L−1 依次取 `j = i + SP(d, i) mod (L − i)`，交换 perm[i] 与 perm[j]。
- 掩码：`mask(i) = (i·hsMixStride mod 256) XOR (PRF32(nsSalt, 2, MIXHS, i) 的低 8 位)`。
- 写入：先用 `fill(seq = 0xFFFFFFFF)`（§7.4.6）填满整个 salt 块，再对 i = 0..15 写 `block[perm[i]] = mask(i) XOR salt[i]`。
- 读取：`salt[i] = mask(i) XOR block[perm[i]]`。

#### 7.4.5 default 帧

每个方向维护帧序号 seq，从 0 开始，每发送或接收一帧（含零块）加 1。复用时不重置。

```
[仅首帧] salt 块(saltBlockLen)
前缀(prefixLen(seq))
seal(帧头 7 字节, AAD = 前缀) ‖ tag
填充(P)
[N > 0] seal(载荷 N 字节, AAD = 填充) ‖ tag
```

- `prefixLen(seq) = pick(PRF32(ns(33), 33, seq, 0), prefixMin, prefixMax)`；前缀内容 = fill(seq)。
- 填充内容 = fill(seq)。
- 帧头中的保留字节在 default 模式下接收方忽略。
- **混排**：N > 0 时，载荷加密完成后对 (填充, 密文) 执行混排（§7.4.7）。接收方读出两段后执行同样的混排即可还原，然后以还原后的填充作 AAD 解密载荷。
- N = 0 为零块：可以带填充，接收方读出并丢弃填充，不做混排。
- 接收方只需要 saltBlockLen、salt 块置换、prefixLen 和混排参数就能解码；填充长度从帧头读取。填充内容与长度算法（§7.4.6、§7.4.8）只决定发送方的流量形态，接收方不校验，但实现必须照做，以保持与官方一致的特征分布。

#### 7.4.6 填充内容 fill(seq, n)

先 `out = PRFBYTES(0, seq, n)`，再按 generator 变换每个字节（i 为字节下标，v 为原值）：

- **generator 0（比特比例）**：`bitCount = pick(PRF32(ns(1), 1, seq, 0), bitMin, bitMax)`；`scaled = bitCount·8`；行号 `row = 1`（若 scaled ≤ 0x31），`7`（若 scaled > 0x2ed），否则 `(scaled + 0x32) / 100`。对每个字节：`raw = (v + i) mod 256`；`t = TABLE[row·16 + ((raw XOR v) & 0x0f)]`；输出 `rotl8(t, (raw XOR (v >> 4)) & 7)`。TABLE 见附录 A。
- **generator 1（三段字节区间）**：`b = v mod (g1 + g2 + g3)`。b < g1 时输出 `pick((v + i) mod 256, 0x20, 0x7e)`（可打印字符）；b < g1 + g2 时输出 `pick((v XOR i) mod 256, 0x80, 0xbf)`；否则输出 `pick((v + 7i) mod 256, 0xc0, 0xff)`。
- **generator 2（类数字）**：`low = ((v & 0x0f) + g4 + (i & 1)) mod 10`；`high = (v + ((i & 3) << 4) + 0x30) & 0xf0`；输出 `high | low`。
- **generator 3（重复图案）**：`motif = PRFBYTES(2, seq, 32)`；`motifLen = 4·g5`（为 0 时取 4）；`period = max(g6, 5)`；维护块内偏移 bo（0..period−1 循环）与图案偏移 mo（0..motifLen−1 循环），两者都从 0 开始，每字节后各加 1。bo < period − 3 时输出 `((g5 + 3)·i mod 256) XOR motif[mo mod 32]`；bo < period − 1 时输出 `0x30 | (v mod 10)`；其余位置保持 v。

#### 7.4.7 混排

令 n = min(|填充|, |密文|)，n = 0 时跳过。执行 mixRounds 轮，第 r 轮按 mixMode：

- **0 固定步长**：`stride = max(mixStride + r mod 3, 1)`。stride = 1 时交换全部 0..n−1；否则对 `off = mixOffsetBase mod stride` 起每隔 stride 交换一次。
- **1 交替块**：块大小 B = mixBlock。从 `off = (r & 1)·B` 起，只要 `off + B ≤ n`，就交换 [off, off+B) 区间，然后 `off += 2B`。
- **2 PRF 步长**：`stride = max(mixStride + r mod 3, 1)`；`off = (PRF32(ns(3), 3, seq, r) + mixOffsetBase) mod stride`；stride = 1 时交换全部，否则从 off 起每隔 stride 交换一次。

"交换位置 k"指交换填充[k] 与密文[k]。各轮交换互不依赖，整个过程是对合（执行两次即还原）。

#### 7.4.8 发送方分帧（default）

每方向的状态：seq、chunkSize（初值 0）、上次写入时间（秒）。

**每帧载荷上限**（每生成一帧调用一次，零块也调用）：

1. 若从未写过，或距上次写入超过 idleResetSec 秒，则 chunkSize = chunkInitial；chunkSize 为 0 时也取 chunkInitial。
2. 计算 `limit`：
   - chunkPolicy 0：limit = chunkSize。
   - chunkPolicy 1：limit = chunkBuckets[PRF32(ns(38), 38, seq, chunkSize) mod 8]。
   - chunkPolicy 2：`j = PRF32(ns(39), 39, seq, chunkSize) mod (2·chunkJitter + 1)`，limit = chunkSize + j − chunkJitter。
   - 然后 limit = clamp(limit, 0x40, chunkMax)。
3. seq = 0 时 limit = min(limit, firstRecordCap)。
4. 更新：chunkSize = min(chunkSize + chunkStep, chunkMax)；记录写入时间。
5. 最终 limit = clamp(limit, 1, 0xFFFF)。

一次应用层写入按上限切成多帧，多帧合并成一次 TCP 写。UDP 模式下每个数据报固定一帧，但仍调用一次上限计算（推进状态）。

**填充长度** P（seq、载荷长度 N、前缀长度 pre、首帧时的 saltPrefixLen 与 total = saltBlockLen，非首帧 total = 0）：

1. 若 `seq < padCount`，或 `0 < N ≤ smallLimit`，或 `seq mod padInterval = 0`：P = pick(PRF32(ns(34), 34, seq, N), padMin, padMax)；否则 P = 0。
2. `tag = 16`（N > 0）或 `0`；`frame = total + pre + 23 + P + N + tag`。
3. `target = writeTarget(seq, frame)`；若 target > frame，则 P += min(target − frame, EXTRA)。
4. 首帧（total > 0）时：`base = N + 0x37`（N > 0）或 `N + 0x27`（N = 0）；`threshold = max((base·25 + 0x4a) / 75, 0xc0)`（整数除法）。若 `saltPrefixLen + pre + P < threshold`：令 `t = threshold − saltPrefixLen − pre`，再取 `t = min(t, padMax + EXTRA)`；若 t ≤ 0xfffe 则 P = t。
5. P = min(P, 0xFFFF)。

**writeTarget(seq, frame)**：

1. frame > 0x5b3 时直接返回 min(frame, 0xFFFF)。
2. 初值：seq < writeFirst 时 t = writeSeq[seq]，否则 t = writeBuckets[PRF32(ns(35), 35, seq, frame) mod 8]。
3. writePolicy = 2 时：`j = PRF32(ns(36), 36, seq, 0) mod (2·writeJitter + 1)`，t = max(t + j − writeJitter, 1)。
4. `spread = min(EXTRA, frame·writeJitterPct / 100)`。若 `PRF32(ns(35), 35, seq, spread)` 为偶数：t = min(t + spread, 0xFFFF)；否则若 t > spread/2，则 t −= spread/2。
5. 当 frame > t 时循环：`next = writeBuckets[PRF32(ns(37), 37, seq, t) mod 8]`；若 next ≤ t，则 next = t + padMax，超过 0xFFFF 时直接返回 0xFFFF；t = next。
6. 返回 t。

（writeFirst 最大为 8，writeSeq 恰好 8 项。）

### 7.5 v6 与请求/复用

- 首帧在请求前没有额外握手；服务端用 PSK 和画像直接解析首帧。
- 服务端→客户端方向同样以 salt 块（default）或 salt（unshaped）开始，各自有独立的 seq。
- 服务端的 TCP 回复 `0x00` 与首段数据拼成一帧，最长 0xFFFF − 1 字节数据。

## 8. 配置字段（与 Surge 一致）

| 字段 | 适用 | 说明 |
| --- | --- | --- |
| `psk` | 全部 | 必填 |
| `version` | 全部 | 1–6；5 按 4 处理（不实现 QUIC 代理） |
| `mode` | v6 | `default`（缺省）/ `unshaped` / `unsafe-raw` |
| `obfs` | v1–v4 | `http`；v1–v3 另有 `tls` |
| `obfs-host` | v1–v4 | 缺省 `bing.com`（http）/ `cloudfront.net`（tls） |
| `obfs-uri` | v1–v4 http | 缺省 `/` |
| `reuse` | v2+ | 是否复用连接 |
| `userkey` | 全部 | 多用户服务端的 clientID |

Surge 节点行示例：`name = snell, host, port, psk=xxx, version=6, mode=default, reuse=true`。

## 9. 服务端（inbound-snell）要求

- 单用户：PSK + mode；多用户：同一 PSK，用 clientID 区分用户，未知 clientID 拒绝。
- 解析失败（解密失败、版本错误、命令未知）时直接关闭 TCP，不回复任何字节。关闭时机与已读字节数的关系 **[待实测]**，目标是不被主动探测区分。
- 防重放：记录首帧 salt，重复时关闭（参考 §6.3）。
- PING 立即回 PONG 并关闭；UDP 请求帧后跟数据时关闭。
- 可复用请求结束后按 §4 排空并等待下一个请求。

## 10. 互通测试矩阵

| 官方服务端 | 客户端配置 | 覆盖 |
| --- | --- | --- |
| snell-server v3.x | version=3，obfs 无/http | TCP、复用、UDP |
| snell-server v4.1.1 | version=4，obfs 无/http | TCP、复用、UDP、首包长度 ≤ 1460 |
| snell-server v5.0.1 | version=4 | 与 v4 相同 |
| snell-server v6.0.0rc2 | version=6，三种 mode | TCP、复用、UDP、错误回复、PING |

服务端入站：用本仓库的 `outbound-snell` 覆盖以上配置，并补一个官方客户端（Surge for Mac）的手工验收项。

## 附录 A：generator 0 的 TABLE（128 字节，按行 16 字节）

```
row 0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
row 1: 01 02 04 08 10 20 40 80 01 02 04 08 10 20 40 80
row 2: 03 05 09 11 21 41 81 06 0a 12 22 42 82 0c 18 24
row 3: 07 0b 13 23 43 83 0d 19 31 61 c1 0e 1c 38 70 e0
row 4: 0f 17 27 47 87 1b 33 63 c3 1d 39 71 e1 3c 78 f0
row 5: f8 f4 ec dc bc 7c f2 e6 ce 9e 3e f1 e3 c7 8f 1f
row 6: fc fa f6 ee de be 7e f9 f5 ed dd bd 7d f3 e7 db
row 7: fe fd fb f7 ef df bf 7f fe fd fb f7 ef df bf 7f
```

第 k 行（k = 1..7）的每个值大约含 k 个 1 比特，用于把填充的比特密度推向画像选定的比例。
