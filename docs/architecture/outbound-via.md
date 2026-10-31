# 前置节点（`via`）：经由另一个出站连接节点

本文件是出站链式连接的设计说明和验收清单。Clash 叫 `dialer-proxy`，Surge 叫 `underlying-proxy`，sing-box 叫 `detour`；本内核统一叫 `via`。

## 模型：入口 → 传输 → 出口

每条网络路径都按三段拆分（用户 2026-10-26 定的术语）：

- **入口**：用户流量进入我们网络的地方，比如节点的入站，或 Panabit 的 iWAN 入口。
- **传输**：入口到出口之间的那段，比如本机、ANX-Line 专线、IPLC。
- **出口**：流量离开的地方，大多是 NAT 直出，少数是已经配好 NAT 的独立 IP。

海外直连也是三段，只是三段都在同一台机器上。`via` 的作用是把两条三段式路径串起来：前一条的出口，接到后一条的入口。

## 动机

第一个场景是 Panabit iWAN 线路（`docs/protocols/iwan.md`）：

```text
App ──iWAN──▶ Panabit 入口（国内）══IPLC══▶ Panabit NAT（香港）──公网──▶ 落地机
     └──────────── 落地协议（SS-2022 / VLESS / 以后的 ANX），端到端加密 ────────────┘
```

- 入口和香港 NAT 都是 Panabit 设备，我们不在上面装任何东西。只有 App 和落地机运行我们的代码。
- App 先登录 iWAN 线路（`outbound-iwan`），再经由这条隧道连接落地机。落地机看到的来源地址是香港 NAT 的地址。
- iWAN 本身只有 XOR 掩码，没有完整性保护（iwan.md §9）。隧道里跑的是落地协议的密文，所以 Panabit 和香港到落地机那段公网都看不到明文。
- 只有一层 TCP，从 App 的私有协议栈一直到落地机，不会出现 TCP 套 TCP。
- 规则分流不变：规则选中哪个落地节点就走哪个，每个落地节点都写 `via` 指向线路节点。线路节点本身也可以直接作为“香港出口”被规则选中。

不做：国内中转机方案（用户 2026-10-26 决定只用私有客户端）；服务端 anixcore 的 `egress` 不改。

## 配置形状

`via` 是出站配置的保留字段，不交给协议工厂。它有两种写法：

```json
{
  "routing": {
    "outbounds": {
      "line-hk": {"type": "iwan", "server": "203.0.113.10", "port": 4567,
                  "username": "u", "password": "p", "tcp_buffer_bytes": 524288},
      "land-us": {"type": "shadowsocks", "server": "land-us.example", "port": 8388,
                  "method": "2022-blake3-aes-128-gcm", "password": "...", "via": "line-hk"},
      "land-jp": {"type": "vless", "...": "...", "via": "line-hk"}
    },
    "rules": ["GEOIP,CN,DIRECT", "DOMAIN-SUFFIX,hk,line-hk", "FINAL,land-us"]
  }
}
```

- **节点 id**（字符串）：只用于 `routing`，指向同一 `routing.outbounds` 里的另一个节点。多个落地节点共用同一个线路节点实例。对 iWAN 来说，这意味着共用同一个会话、同一次登录。
- **内联出站**（对象）：形状与出站配置相同，可用于单出站模式（`outbound`）和延迟测试。每次构建都会新建一个实例。

## 校验规则

- `via` 只能指向节点，不能指向策略组、`DIRECT` 或 `REJECT`。
- 指向的节点必须存在，链不能成环，链长（包括节点自身）最多 4 层。
- 单出站模式里 `via` 写节点 id 会被拒绝，因为那里没有其他节点。
- 协议工厂通过 `OutboundFactory::supports_via()` 声明能否经由前置节点。自己开 UDP 套接字的协议（`hysteria2`、`tuic`、`iwan`）返回 `false`，写了 `via` 会被拒绝，避免流量绕过前置节点直接发出。`wireguard` 本来就不能当路由节点。
- 前置节点本身可以是任何 TCP 出站，包括 `iwan`。
- 错误信息只带节点 id，不回显凭据。

## 实现

- `engine-outbound`：
  - `Dialer::open_datagram(host, port) -> UdpFlow`：协议发往服务器的 UDP 走这里。默认实现与原来一样，是一个已 `connect` 的系统 UDP 套接字，所以 NE 替换的拨号器行为不变。
  - `OutboundDialer(Arc<dyn TcpOutbound>)`：`dial` 调用前置节点的 `connect`，`open_datagram` 调用前置节点的 `open_udp`。主机名原样交给前置节点，经由 iWAN 时由隧道 DNS 解析。
  - `OutboundFactory::supports_via()` 默认返回 `true`。
- `outbound-shadowsocks`：UDP（SIP004 和 2022）改为通过 `Dialer::open_datagram` 发送。`outbound-socks` 的 UDP ASSOCIATE 中继也走 `open_datagram`。
- `engine-embedded`：
  - `OutboundConfig` 增加 `via` 字段。
  - `build_routed` 按依赖顺序构建节点，并检查成环和链长；节点用 `OutboundDialer(前置节点)` 作为拨号器。
  - 单出站模式只接受内联 `via`。
- 吞吐：iWAN 私有协议栈每条 TCP 的缓冲默认 64 KiB。跨境 30 ms RTT 下，单连接约 17 Mbps。线路节点应设置 `tcp_buffer_bytes`（上限 1 MiB）；iOS NE 内存有限，默认值不变。

## 以后再做

- QUIC 类协议（`hysteria2`、`tuic`）经由前置节点：需要 quinn 自定义套接字跑在 `UdpFlow` 上。
- `via` 指向策略组，比如在多条 iWAN 线路之间选择。
- 导入：Clash `dialer-proxy`、Surge `underlying-proxy` 映射为 `via`。面板订阅给落地节点写上前置节点。

## 订阅导入

两种写法，导入时都按名字找到前置节点，转成那个节点的 id，写进 `via`：

- **sing-box JSON**：`detour` 是 sing-box 标准的前置写法。`"type": "iwan"` 是 AnixOps 的扩展类型，字段有 `server`、`server_port`、`username`、`password`，可选 `mtu`、`encrypt`。
- **分享链接列表**（面板发给 App 的格式）：
  - 任一链接的查询参数 `via=<前置节点名>` 是 AnixOps 扩展，导入器先取走它，再交给协议自己的解析。`vmess://` 写在 base64 之后，比如 `vmess://<base64>?via=HK%20line`。
  - iWAN 线路写成 `iwan://<用户名>:<口令>@<主机>:<端口>?mtu=1400&encrypt=0#<名字>`，用户名和口令按百分号编码。
  - 旧版 App 不认识 `iwan://`，会跳过它。旧版 App 也会忽略 `via`，于是直连落地机。
  - ANX-A 节点写成 `anx://<64 位十六进制用户密钥>@<主机>:<端口>?sni=<SNI>&pk=<服务器公钥文本>&alpn=h2,http/1.1&fp=chrome#<名字>`，查询值按百分号编码；`sni` 可省，省掉时客户端不发 SNI（服务端直连 IP 的部署）。公开引擎只解析它，输出 `type = "anx"` 出站（可选 `server_name`、`public_key`、`user_key`、可选 `alpn`、`fingerprint`），没有编译 ANX 的构建会把这个节点列为不支持。ANX 出站不走 `via`。

面板继续用分享链接，不改成 sing-box JSON。原因是 App 已经支持的 xhttp 和 WireGuard 链接，在 sing-box JSON 里没有对应写法。

导入时有两种情况会把节点报为无法运行，而不是让它绕开前置节点直接连出：

- `detour` 指向的不是导入的节点。
- 前置节点本身无法运行。

## 验收

- 单元测试：`OutboundDialer` 对 TCP 和 UDP 的转发；配置校验覆盖未知节点、指向策略组、成环、链过长、`supports_via() == false` 和单出站模式下写节点 id。
- 集成测试（`engine-embedded/tests/via_chain.rs`）：
  - 用进程内的 `inbound-iwan` 模拟 Panabit 线路，用进程内的 SS-2022 服务器模拟落地机。
  - 路由节点 `land`（SS-2022，`via: line`）的 TCP 和 UDP 都要到达目标。
  - 线路的入站统计要计入这些流量，证明流量确实经过了 iWAN。
