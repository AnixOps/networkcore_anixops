# Changelog

本文件记录项目可审计变更。格式遵循轻量级 `Keep a Changelog` 风格，但所有验证结论以 GitHub Actions 为准。

## Unreleased

### Changed

- 仓库拆分：客户端连同 git 历史迁到公开仓库 [AnixOps/anixops-net](https://github.com/AnixOps/anixops-net)，本仓库只保留 AnixOps Net 的网络内核（`crates/*`、`apps/anixcore`、`apps/linux-cli`、`apps/windows-cli`、`third_party/mitm_anixops` 与内核文档）。客户端仓库固定引用本仓库的一个内核 commit，并有自己的 CI（UI、Linux GUI、Windows 构建与 MSI、Swift、iOS/macOS Xcode）、`ios-testflight.yml` 和 `release.yml`（Windows MSI 与 portable ZIP，内含由固定内核 commit 构建的 `networkcore-windows` CLI；Linux 桌面 tarball 与 `.deb`）。
  - 删除 `apps/windows-gui`、`apps/windows-service`、`apps/linux-gui`、`apps/ios`、`installer/windows`，workspace 去掉对应 member，`Cargo.lock` 只删去不再使用的依赖。
  - 删除 `ios-testflight.yml`、`refresh-pnpm-lock.yml`、`refresh-windows-icon.yml` 以及 iOS 清单校验、iOS 合同字段、XCFramework 打包和 Windows `windres`/`rc` 兼容 shim 脚本。
  - CI 去掉 Windows GUI 前端、Linux GUI、Windows MSI、Node、Swift、iOS Xcode 和 Apple project smoke 任务，以及对客户端文件的 policy 检查；路径分类器去掉 `node` 组和客户端路径。新增 macOS 任务 “iOS runtime static libraries”：为 `aarch64-apple-ios` 构建 `engine-embedded` 与 `node-import` 静态库并检查两个 C header，iOS/Apple 路径或完整矩阵变化时由 CI summary 要求通过。
  - Release 只发布 Linux CLI 四件套；删除 Linux 桌面客户端、Windows 打包/attestation/release notes/publish eligibility 和 iOS upload readiness 任务，release body 注明客户端由 AnixOps/anixops-net 发布。
  - 客户端文档（iOS App/扩展/上架合同、Windows GUI 日常可用性、Windows managed client 发布合同、Windows 真机冒烟）和客户端人工事项迁到客户端仓库；`ios-embedded-runtime-ffi-boundary-design.md` 作为内核 FFI 边界保留。

### Added

- 面板拦截规则：管理 API 新增 `GET`/`PUT /v1/rules`（`RulesConfig`：`block_domains` 用与分流路由相同的域名匹配写法，`block_protocols` 可选 `bittorrent`、`http`、`tls`，按客户端首包识别）。被拦截的域名（TCP 与 UDP）和协议在所有入站上直接拒绝，转发入站除外；有效规则替换旧规则，任一条无效则整体拒绝（400）并保留旧规则；已建立的连接不受影响。`GET /v1/status` 的 `features` 新增 `block_rules`。

- 用户限速与设备数限制：入站用户新增 `speed_limit`（Mbit/s，上下行各一个令牌桶，用户所有连接共享，最多一秒突发）和 `device_limit`（同时在线的客户端 IP 上限，再来一个新 IP 的连接被拒绝），默认 0 不限。限速作用于经 serve 循环转发的 TCP 流（含 Hysteria2/TUIC 的流和协议自管连接的 `ConnectionContext::relay`），UDP 报文暂不限速；设备数限制作用于 serve 循环和 Snell。`InboundStats` 与 `GET /v1/inbounds` 新增 `device_limited` 计数。

- 常规 Shadowsocks（SIP004 AEAD）服务端入站：`"type": "shadowsocks"` 的 `method` 为 `aes-128-gcm`、`aes-256-gcm` 或 `chacha20-ietf-poly1305` 时建 SIP004 入站（`inbound_shadowsocks::AeadInbound`），2022 方法照旧。始终多用户：用户 `password` 为明文密码（EVP_BytesToKey），可在运行中增删用户、按用户计流量和在线 IP；可选的入站 `password` 是不计入任何用户的匿名密钥。协议不带用户标识，服务端按首个长度块（UDP 为整包）逐个试用户密钥，同一客户端 IP 上次匹配的密钥先试。TCP 已认证 salt 记 10 分钟拒绝重放，认证失败的连接挂起排空。同端口 UDP：会话 = 客户端地址 + 其密钥。测试对本仓库客户端出站与 shadowsocks-rust 客户端（TCP、UDP、多用户）互通。

- 固定目标端口转发入站 `"type": "forward"`（新 crate `inbound-forward`，node-runtime 默认 feature `forward`）：监听端口的 TCP 连接和 UDP 报文原样转到配置的 `server:server_port`，`network` 可选 `tcp`、`udp`、`tcp,udp`（默认）。面板转发规则 = 一个 forward 入站 + `outbound`（anx-node 上如 `anx-line:<link_id>`）。转发目标是运营方配置的，可以是内网地址；forward 只走自己的基础出站，不套用分流 egress 路由；不接受用户。`GET /v1/inbounds/{tag}/traffic` 新增 `inbound` 成员：整个入站自上次 `reset=true` 以来的字节数，与用户流量一起清零，所有入站都有。

- XHTTP 客户端支持 HTTP/3：TLS ALPN 恰好为 `h3` 时，每条代理流走一条 QUIC 连接（`transport-quic`，`h3`/`h3-quinn`），三种模式都支持，VLESS、VMess、Trojan 出站均可用。互通测试新增 Xray 的 VLESS-XHTTP-H3 入站（UDP），覆盖三种模式。服务端 HTTP/3 暂不支持。
- VMess、Trojan 出站支持 XHTTP：`"transport": {"type": "xhttp", ...}`（也接受 `splithttp`），HTTP 版本按 TLS ALPN 选择，与 VLESS 相同。订阅导入和分享链接导出支持 VMess（`net: "xhttp"`、`mode`、`extra`）和 Trojan（`type=xhttp`）的 XHTTP 节点。互通测试新增 Xray 的 VMess、Trojan + XHTTP + TLS 入站（本内核作客户端，四种组合）和 Xray 客户端以 VMess、Trojan + XHTTP 连接本内核入站。
- REALITY 上的 XHTTP：VLESS 出站可同时配置 `reality` 和 `{"type": "xhttp", ...}`（每条连接先做 REALITY 握手再跑 HTTP/2，`auto` 为 `stream-one`，与 Xray 相同）；VLESS 入站可同时配置 `reality` 和 XHTTP 传输，未认证连接照常转给 `handshake` 站点。订阅导入接受 `security=reality&type=xhttp`。互通测试新增 Xray 的 VLESS-REALITY-XHTTP 入站（本内核作客户端）和 Xray 客户端连接本内核同类入站，各三种模式。
- 订阅导入 XHTTP 节点：`vless://` 链接的 `type=xhttp`（或 `splithttp`）连同 `path`、`host`、`mode` 和 `extra` 中的请求头、填充与上传分段设置导入为 VLESS-XHTTP 出站，`xmux` 和仅服务端的设置忽略；`downloadSettings` 和 VMess/Trojan 的 XHTTP 暂标为不支持。分享链接导出写回同样的字段。
- XHTTP 服务端传输：`transport-xhttp` 新增 `server::XhttpServer`（连接以 HTTP/2 前言开头按 HTTP/2/h2c，否则按 HTTP/1.1；入站内共享会话表，同一会话的请求可来自不同连接；`packet-up` 按 `seq` 重排、最多领先 30 段并以延后应答反压，`stream-up`、`stream-one` 走 HTTP/2；检查 Host、路径和 `x_padding` 长度，分别以 `404`/`400` 拒绝；会话 30 秒等不到下载即丢弃）。VLESS、VMess、Trojan 入站的 `transport` 新增 `{"type": "xhttp", ...}`（也接受 `splithttp`），TLS 未配置 ALPN 时提供 `h2` 和 `http/1.1`。客户端互通测试新增 Xray 客户端到本内核 VLESS-XHTTP 入站的五种组合，`transport-xhttp` 新增本实现客户端与服务端的回环测试。
- 自研 XHTTP 传输：新增 `transport-xhttp`（按 [docs/protocols/xhttp.md](docs/protocols/xhttp.md) 净室实现，与 Xray-core XHTTP/SplitHTTP 线上兼容）。HTTP/1.1 支持 `packet-up`，HTTP/2 支持 `packet-up`、`stream-up`、`stream-one`；版本按 TLS ALPN 选择（无 TLS 或仅 `http/1.1` 为 HTTP/1.1，否则 HTTP/2，空 ALPN 时提供 `h2`）；每个请求在 `Referer` 中带随机长度的 `x_padding`。VLESS（非 REALITY）出站支持 `"transport": {"type": "xhttp", "path": ..., "mode": ...}`（也接受 `splithttp` 和 Xray 的字段名）。CI 互通测试新增 Xray-core 的 VLESS-XHTTP 入站（无 TLS 和 TLS 两个），覆盖上述五种组合的下载与回显。服务端传输、HTTP/3、REALITY 上的 XHTTP 和订阅导入后续补上。

- 分享链接列表支持 iWAN 线路和前置节点：新增 `iwan://用户名:口令@主机:端口?mtu=&encrypt=#名字` 链接，任一链接的查询参数 `via=<前置节点名>` 由导入器取走并解析为 `via`（`vmess://` 写在 base64 之后）。面板发给 App 的订阅仍用分享链接。
- 订阅导入支持 iWAN 节点和前置节点：
  - sing-box JSON 新增 AnixOps 扩展类型 `iwan`（`username`、`password`，可选 `mtu`、`encrypt`），对应 `control_domain::Protocol::Iwan` 和 `iwan.*` 元数据。
  - sing-box 的 `detour` 按 tag 解析为节点 id（`proxy.via` 元数据），`node-import` 输出为出站的 `via`。
  - `detour` 指向的不是导入的节点，或前置节点本身无法运行时，该节点报为无法运行。
- 前置节点（代理链）`via`，设计见 `docs/architecture/outbound-via.md`（入口 → 传输 → 出口模型）。
  - `engine-embedded` 的出站配置新增保留字段 `via`：写字符串时指向 `routing.outbounds` 里的另一个节点，多个节点共用同一个实例（同一 iWAN 会话）；写对象时是内联出站，单出站模式只接受这种写法。
  - 节点按依赖顺序构建，拒绝不存在的节点、成环和超过 4 层的链。
  - `engine-outbound` 新增：
    - `OutboundDialer`：把出站当作拨号器使用。
    - `Dialer::open_datagram`：协议发往服务器的 UDP 走这里，默认仍是系统 UDP 套接字。
    - `TargetAddr::from_host`。
    - `OutboundFactory::supports_via`：`hysteria2`、`tuic`、`iwan` 自己开套接字，写 `via` 会被拒绝。
  - Shadowsocks（SIP004/2022）和 SOCKS5 的 UDP 改为经 `open_datagram` 发送，所以经由前置节点时 UDP 也走前置节点。
  - 第一个场景是 App 先登录 Panabit iWAN 线路，再经由它连接落地机。测试用进程内的 `inbound-iwan` 模拟线路及其 NAT 出口，验证 Shadowsocks-2022 落地节点的 TCP 和 UDP。
- iWAN 第三方互通 CI：REALITY interop 作业按 `docs/protocols/iwan.md` §10.2 在固定 commit 9f6a0e3 构建 iwand 客户端（黑盒，只构建运行），由 `.github/scripts/iwan-tun-interop.sh` 在网络命名空间里经 TUN 登录 `anixcore` 的 iWAN 入站：明文与 XOR、动态与固定地址、MTU 协商、网关 ping 与 DNS、按域名的 2 MiB HTTP 下载、超过会话 MTU 的 UDP 回包、管理 API 的在线与计费、SIGTERM 时的 CLOSE，以及错误口令被拒。
- 新增 Panabit iWAN 服务端入站 `inbound-iwan`（`node-runtime` cargo feature `iwan`，默认开启，配置 `"type": "iwan"`），按 `docs/protocols/iwan.md` §12 净室实现，复用 `outbound-iwan` 的包编解码、口令块与 XOR 掩码。一个 UDP 端口服务所有用户：OPEN 校验签名和 TLV，口令块常数时间比较，失败一律回 OPENREJ；成功时 token / session_id 用安全随机数，有效 MTU 取节点与客户端的较小值，OPENACK 带 MTU、分配地址、DNS（网关地址）和加密模式；同一用户或同一源地址再次登录替换旧会话；ECHOREQ 原样回显，CLOSE 移除会话，60 秒无包或用户被删除时会话结束。地址池（`pool`，/8–/30）的第一个可用地址是网关，用户重连拿回原地址，释放 10 分钟后回收；用户可设固定地址（`address`），固定地址不参与动态分配。每个入站一个用户态 TCP/IP 栈（`netstack-smoltcp`）接受任意目的地址，终结出的 TCP 连接和 UDP 流带着所属用户交给节点的路由和出站并按用户计费，因此面板的域名分流（SNI / HTTP Host 嗅探和经节点转发的 DNS 应答映射）对 iWAN 用户同样生效。网关只回应 ping 和 UDP 53（转发到 `dns_upstream`，默认 `1.1.1.1:53`），源地址不是分配地址的包丢弃，用户之间互访默认禁止（`allow_client_to_client`），发往客户端的包按会话 MTU 分片。另有 `mtu`（默认 1400，576–1600）和 `allow_encrypt`（默认 true）。`engine-inbound` 的 `User` 新增可选字段 `username`（客户端填写的登录名，缺省为 `name`）和 `address`（固定隧道地址），`UserStore::with_unique_keys` 让协议声明不可重复的字段：iWAN 的登录名和固定地址在一个入站内唯一，重复的用户（含管理 API 添加）报错拒绝。按真实 Panabit 的行为，OPENREJ 在签名后带 ASCII 原因：口令错误或请求格式错误为 `INVPASS`，地址池耗尽为 `NO_FREEIP_INPOOL`；`outbound-iwan` 的 `Output::Rejected` 带上原因文本，连接错误据此区分口令错误（`PermissionDenied`）和服务端地址池耗尽（`AddrNotAvailable`）。测试用 `outbound-iwan` 当客户端端到端跑 TCP、隧道内 DNS 解析和 UDP，并用原始数据报覆盖拒绝、固定地址、网关 ping、伪造源、重复登录、CLOSE、删除用户和客户端互访。
- 桌面 `PROCESS-NAME`：`engine-embedded` 新增 `process::process_name`，按客户端连接两端地址找出发起连接的本机进程（Linux 读 `/proc/net/tcp{,6}` 与 `/proc/<pid>/fd`，Windows 用 `GetExtendedTcpTable` 的 owner-PID 表与 `QueryFullProcessImageNameW`，macOS 遍历 `proc_pidfdinfo` 的 socket 描述符），名称为可执行文件名。local proxy 只在规则模式且配置含 `PROCESS-NAME`（包括逻辑规则内）时在阻塞线程上查询，结果交给规则匹配并显示在连接列表的新字段 `process`（没有时不输出）。`inbound-mixed` 新增 `ClientConnector`、`ClientAddrs` 与 `serve_clients`，`serve` 不变；`Dispatcher` 新增 `connect_process_flow`、`wants_process`，`RoutedOutbound::route_flow` 新增 `process` 参数与 `uses_process`。新依赖：macOS `libc`，Windows `windows-sys`（IpHelper、Threading）。iOS 隧道无法得知进程，`PROCESS-NAME` 规则在那里不命中。
- 订阅导入的规则补齐：`config-core` 的 `routing_import` 现在保留 `GEOSITE`、`PROCESS-NAME`、`RULE-SET`、Surge `DOMAIN-SET` 和 `AND`/`OR`/`NOT` 规则。Surge/Loon 的规则集 URL、Loon `[Remote Rule]` 与 Clash `rule-providers`（`type: http`）变成新的 `ImportedRouting::rule_sets`（`ImportedRuleSet`：`id`、`url`、`format`、`interval_secs`、`via`），规则改写为 `RULE-SET,<id>,<target>`；`node-import` 的导入结果在 `routing.rule_sets` 中按 engine 配置形状输出这些规则集，新增 `rule_sets_json`。
- 节点分享链接导出：`node-import` 新增 `share_link(name, outbound)` 与 C ABI `networkcore_import_share_link`（输入 JSON `{"name", "outbound"}`，输出 UTF-8 链接；新错误码 `NETWORKCORE_IMPORT_ERR_UNSUPPORTED = 7`，ABI 版本不变）。Shadowsocks 输出 SIP002 `ss://`（base64url 凭据），VLESS/Trojan 输出常见 query 形式（含 REALITY、TLS、WS、gRPC），VMess 输出 v2rayN `vmess://` JSON，Hysteria2 与 TUIC 输出各自链接，Snell 没有链接格式，输出 Surge `[Proxy]` 行；Mieru 暂不支持。测试保证导出再导入得到相同的出站配置与名称。
- 负载均衡策略组与节点名过滤：`config-core` 新增 `PolicyGroupKind::LoadBalance`（`load-balance`，按目的主机在健康成员间做 rendezvous 哈希，同一站点固定一个成员）和 `RoundRobin`（`round-robin`，健康成员轮流），两者与 fallback 一样做健康检查、不接受 `tolerance_ms`；`RoutingEnvironment` 新增 `round_robin`，`engine-embedded` 的 `RoutedOutbound` 提供计数。订阅导入支持 Surge/Loon/Clash 的 `load-balance` 组（`strategy`/`algorithm` 为 `round-robin` 或 `random` 时为轮询），以及 Surge `include-all-proxies` + `policy-regex-filter`、Clash `include-all`/`include-all-proxies` + `filter`/`exclude-filter` 的正则节点过滤（`config-core` 新依赖 `regex`）。
- 新增 Panabit iWAN 出站 `outbound-iwan`（`engine-embedded` cargo feature `iwan`，默认开启，配置 `"type": "iwan"`），只依据 `docs/protocols/iwan.md` 净室实现：协议层是无 I/O 的包编解码（MD5 头签名、TLV、AES-128-ECB 口令块、8 字节 XOR 掩码、ECHO、IPFRAG 重组、不加密的 SEGRT）和 §5 会话状态机；出站层按 §11 做成可分流的逐连接出站，每个节点在首条连接时建立 UDP 会话，自带一个地址取自 OPENACK 的 smoltcp 私有栈，TCP 与 UDP 都在栈内发起，域名经隧道内 DNS（OPENACK 下发或配置 `dns`）解析，空闲 60 秒后发 CLOSE 释放，不修改平台网络设置。互通 CI 在固定 commit 9f6a0e3 构建 `iwand-server` 作黑盒，覆盖握手下发、口令错误、明文与掩码回显、ECHO RTT、CLOSE 后会话移除，以及两个节点经服务端转发的 TCP/UDP。iWAN 没有保密和认证（规格 §9）。
- 可配置 DNS：`engine-embedded` 的 `dns` 段新增 `servers`（具名上游：`tcp://` / 纯 IP、DNS over TLS `tls://`、DNS over HTTPS `https://`，可选 `server_name`，`via` 为 `proxy` 或 `direct`）、`default`、`hosts`（精确域名或 `*.` 子域名，本地应答 A/AAAA）和按域名选上游的 `rules`（`domain`、`domain_suffix`、`domain_keyword`、`rule_set`，首条命中生效）。不写 `servers` 时保持原来的 `upstream` 经 TCP 走代理。DoT/DoH 由新的 cargo feature `dns-tls`（默认开启）提供；HTTP/1.x 响应解析从 `fetch` 移到共用的 `http1` 模块。`Dispatcher` 新增 `direct()`，`TunnelSettings` 的 `dns_upstream`/`dns_timeout` 换成 `dns: Arc<DnsPolicy>`。fake-ip 的评估与建议见 `docs/architecture/embedded-dns.md`（本次不实现）。
- 规则扩展：`config-core` 新增 `GEOSITE`、`DST-PORT`（别名 `DEST-PORT`，端口或范围）、`PROCESS-NAME` 规则和 Surge 写法的 `AND`/`OR`/`NOT` 逻辑规则（可嵌套 8 层，含 IP 子规则时可带 `no-resolve`），`RouteQuery` 新增 `port`、`process`，`RoutingEnvironment` 新增 `geoip_matches`、`geosite_matches`；订阅导入新增 `DST-PORT`。`RuleSet` 新增精确域名与关键字，`RuleSetEntries::parse_list` 读取 Surge/Loon/Clash classical、Clash `payload:` YAML 和纯域名/网段列表。`engine-embedded` 的规则集新增 `domain`、`domain_keyword` 和远程下载（`url`、`format`、`interval_secs`、`via`；`fetch` 模块经出站做 HTTP/1.1 GET），按间隔在后台刷新、失败保留旧内容；`GEOSITE,<c>` 与 `GEOIP,<CC>` 匹配名为 `geosite-<c>`、`geoip-<cc>` 的规则集；规则集上限改为 32 个。运行时控制新增 `rule_sets` 与 `update_rule_sets`。`PROCESS-NAME` 由桌面 local proxy 的进程查询提供（见下条）。
- 模式切换与策略组运行时切换：`engine-embedded` 新增 `connections::Mode`（`rule` / `global` / `direct`），运行时控制新增 `mode`、`set_mode`、`groups`（每组当前成员与成员延迟）和 `select`（切换 select 组，不重启隧道）。配置新增顶层 `mode`（启动模式）与 `routing.global`（全局模式的目标：策略组、节点或 `DIRECT`，缺省第一个策略组，否则第一个节点）；单出站配置同样支持直连模式。`config-core` 的 `RoutingModel` 新增 `route_to`、`group_member`、`target_named`，`PolicyGroupKind` 新增 `as_str`；`RoutedOutbound` 的路由环境实现 `selected_member`，新增 `with_global`、`select`、`groups`、`route_global`。
- 连接记录与实时流量：`engine-embedded` 新增 `connections::Dispatcher`，隧道与桌面 local proxy 的每条 TCP 连接和 UDP 流都经它选路、登记并按连接计数，活动连接与最近 128 条已关闭连接可列出（目标、域名、命中规则、策略组链、出站、起止时间、上下行字节、`rejected` / `connect_failed`），可按 id 或全部关闭。新增运行时控制入口：C ABI `networkcore_ios_runtime_control`（JSON `{"cmd": ...}`，命令 `traffic`、`connections`、`close_connection`、`close_all`，feature set 升为 2），桌面为 `EmbeddedRuntime::control_json` / `LocalProxy::control_json`。隧道从 TCP 首包嗅探 TLS SNI 或 HTTP `Host`（`sniff` 模块，原 `mitm::sni`），连接列表显示该域名，域名规则也按它匹配（IP 规则仍匹配目的地址，连接仍发往原地址），iOS 隧道内的 DOMAIN 类规则因此开始生效。`RuleMatcher` 实现 `Display`，输出不带目标的规则行。
- 服务端 Mux.Cool / XUDP：VLESS 与 VMess 入站支持 mux 命令（3，不带地址）。同一条客户端连接上的 TCP 会话经节点出站连接，UDP 会话（XUDP，Keep 帧携带每个数据报的地址，回包带来源地址）各用一个 UDP 套接字，每条连接最多 128 个会话，New/Keep/End/KeepAlive 与错误 End 照 Xray 处理，全局 ID 忽略。VLESS 的 mux 可不带 flow 或带用户的 flow（Xray 把 Vision 用户的 XUDP 放在 Vision 内）。`engine_inbound::Accepted` 新增 `mux` 字段。反向互通 CI 现在对所有协议测 UDP，包括 Xray 的 VLESS/VMess 与 sing-box 的 VLESS（XUDP）。
- 客户端隧道转发 UDP：`engine-outbound` 的 `TcpOutbound` 新增 `open_udp`，返回发往单一目标的 `UdpFlow`（`DatagramSend` / `DatagramRecv`），不支持 UDP 的协议默认返回 `Unsupported`；`UdpFlow::message_stream` 适配每次读写对应一个数据报的流。`engine-embedded` 隧道把 53 以外端口的 UDP 按（应用套接字，目标）建流转发（最多 256 条，60 秒无流量关闭），回包从应用请求的目标地址发回；出站不支持 UDP 时照旧丢弃，QUIC 回落 TCP。支持 UDP 的出站：`direct`（独立 UDP 套接字）、规则分流与策略组（按目标选路）、VMess、Hysteria2、TUIC、Snell、Trojan（`UDP ASSOCIATE`，包格式 `ATYP ADDR PORT LENGTH CRLF` + 负载）和 VLESS（UDP 命令 2、不带 flow，`u16` 长度前缀，TCP/TLS/WS/gRPC 与 REALITY 均可），每条流一条代理连接；Shadowsocks（SIP004 AEAD 与 Shadowsocks-2022，含 AES 方法的多用户身份头和 ChaCha 方法的 XChaCha20-Poly1305）每条流一个连到服务器的 UDP 套接字，测试对照 shadowsocks-rust 服务端与本仓库入站；SOCKS5 出站使用 `UDP ASSOCIATE`（TCP 连接存续期间有效，中继地址为未指定地址时改用服务器地址，丢弃分片回包）。统计新增 `udp_flows` 与 `udp_failed`。
- 反向互通 CI：`node-runtime` 新增 `client_interop` 测试（`#[ignore]`，由 REALITY interop 作业运行），用 `anixcore` 入站配置起节点，让 Xray-core、sing-box 和官方 Hysteria 客户端经 SOCKS5 连入并回显 256 KiB 数据，同时核对按用户计费。覆盖 VLESS REALITY（含 Vision）、VLESS TLS+WS/gRPC、VMess TCP/WS/TLS+gRPC、Trojan TLS/TLS+WS/TLS+gRPC、Shadowsocks-2022 多用户、Hysteria2（含 salamander）和 TUIC；客户端按名称校验自签证书，不使用 insecure 选项。UDP 也经 SOCKS5 UDP ASSOCIATE 回显（Xray 测 Trojan 与 Shadowsocks；sing-box 测除 VLESS 以外的协议；Hysteria 全测），VLESS 与 Xray VMess 的 UDP 走 XUDP，入站暂不支持，只测 TCP。
- 服务端 WebSocket 与 gRPC 传输：`inbound-transport` 新增 `WsInbound`、`GrpcInbound` 和 `wrap_all`，Trojan、VLESS、VMess 入站配置新增与出站相同的 `transport` 对象（`ws`：`path`、可选 `host` 校验、Xray `?ed=` 早期数据经 `Sec-WebSocket-Protocol` 并回显；`grpc`：`service_name`，同一连接上的多个调用各自作为一条客户端流，最多 256 个并发；`tcp` 等同不设）。其他路径回 `404`、非升级请求回 `400`；TLS 下使用 gRPC 且未配置 `alpn` 时提供 `h2`。`transport-ws` 新增服务端握手 `server::WsAcceptor`（服务端帧不加掩码），`transport-grpc` 新增 `server::serve_connection` 和 `tun_path`；`engine_inbound::server::ConnectionContext` 新增 `handle`，供一条连接承载多条客户端流的传输使用，`TlsInbound` 现在会把 `serves_connections` 和 `datagram` 透传给协议。VLESS REALITY（以及 Vision）不接受 transport。
- 服务端 UDP 转发：`engine-inbound::udp` 在已有的 `UdpOutbound` 之上新增 `DatagramCodec` / `relay_datagrams`（连接内携带的 UDP，按用户计费，空闲两分钟或删除用户时结束），被拒绝的目标只丢弃该包；`PacketInbound::serve` 新增 UDP 出站参数；Trojan 入站支持 `UDP ASSOCIATE`，VLESS 与 VMess 入站支持 UDP 命令（VMess 客户端新增 `connect_udp`）。Hysteria2 入站经 QUIC datagram 转发 UDP（有 UDP 出站时声明 `hysteria-udp: true`，每个客户端会话 ID 一个套接字，分片重组、回包按 datagram 上限分片），Hysteria2 客户端新增 `udp_session`。TUIC 入站支持 UDP（native 模式经 QUIC datagram 并分片、quic 模式经单向流，回包沿用该关联的模式，支持 Dissociate），TUIC 客户端新增 native 模式的 `udp_session`。QUIC 协议共用 `engine_inbound::udp::SessionRelay`（按会话 ID 一个套接字）。Shadowsocks-2022 入站在同一端口提供 UDP（`StreamInbound::datagram`，`node-runtime` 自动绑定同端口 UDP）：AES 方法的分离头与多用户身份头、ChaCha 方法的 XChaCha20-Poly1305，每个客户端会话一个套接字，30 秒时间戳窗口和每会话 1024 包防重放窗口，测试用 shadowsocks-rust 客户端验证单密钥与多用户。
- VLESS 服务端支持 XTLS Vision（`xtls-rprx-vision`，需配合 REALITY）：Vision 用户的连接使用填充帧；内层流量为 TLS 1.3 时，上下行各自在 `direct` 命令后离开外层 TLS，按原始连接拷贝内层记录，与 Xray 一致。客户端请求的 flow 必须与用户配置一致。测试覆盖普通流量、内层 TLS 1.3 直连拷贝和 flow 不匹配的拒绝。
- 新增 Mieru 出站 `outbound-mieru`，cargo feature 为 `mieru`，配置为 `"type": "mieru"`。
  - 只依据 `docs/protocols/mieru.md` 净室实现。规格的来源是公开协议说明，加上 CI 上官方 mieru 客户端与 mita 服务端之间的黑盒抓包，没有阅读或移植上游源码。
  - 支持的部分：TCP 传输，XChaCha20-Poly1305 与按 2 分钟时间槽派生的密钥，带用户提示的 nonce，会话与数据分段、随机填充，每条连接一个会话，可选 `port_range` 端口段（每条连接随机选一个端口）。
  - 暂不支持：UDP 传输、多路复用、低熵分段。
  - 导入：`mierus://` 支持官方简单分享链接格式，即成对的 `port`/`protocol` 参数，端口可以是端口段，`multiplexing` 可取 `MULTIPLEXING_*`；原有的 `host:port` 写法继续可用。另外新增 Clash `type: mieru`（`port` 或 `port-range`、`transport`、`username`、`password`、`multiplexing`）。只有 UDP 的节点会报不支持。
  - 互通 CI 安装官方 mita 发布包（只在 CI 中运行，不随产物分发），测试：按 IP 和按域名拉取、端口段、3 MB 双向回显、服务端先说话场景下的会话建立、不可达目标的拒绝回复，以及错误密码收不到可读数据。
  - 人工验收章节改为内置 Mieru 出站。
- 新增 Snell 出站 `outbound-snell`（cargo feature `snell`，配置 `"type": "snell"`），只依据 `docs/protocols/snell.md` 净室实现：支持 v1–v4 与 v6（v5 按 v4 运行，不实现 QUIC 代理模式），v6 的 `default`（PSK 派生画像整形、salt 块、填充混排）、`unshaped`、`unsafe-raw` 三种模式，v4 首包整形与比特配平，v1–v4 的 `obfs = http`，CONNECTv2 连接复用（最多 10 条空闲、180 秒），以及 crate API 里的 UDP over TCP（v3+）和 PING。帧编解码与请求解析与方向无关，供后续 `inbound-snell` 复用。导入支持 Surge `snell` 节点行和 Clash `type: snell`（`psk`、`version`、`obfs-opts`；缺省 version 为 1），`obfs = tls` 暂报不支持。互通 CI 下载官方 snell-server v4.1.1、v5.0.1、v6.0.0rc2（只在 CI 中运行，不随产物分发）做 TCP、复用、UDP、错误回复和 PING 黑盒测试；v3.0.1 没有可下载的官方构建，暂时跳过。官方 v5.0.1 会把新会话上超过当前帧上限的下行 UDP 数据报截断，互通测试对 v5 的这一项只记录不判失败。
- 新增 Snell 服务端入站 `inbound-snell`（`node-runtime` cargo feature `snell`，默认开启，配置 `"type": "snell"`），复用 `outbound-snell` 的帧编解码与请求解析：支持 v1–v4（v1–v3 自动识别客户端的加密方式，v4 服务端同时接受 v5 客户端）和 v6 三种模式，v1–v4 的 `obfs: "http"`，单用户或按 clientID（Surge `userkey`）区分的多用户，按用户统计流量和在线 IP。解密失败、请求格式错误、未知用户和重放的首个 salt（30 分钟内）直接关闭、不回复；PING 回 PONG；TCP 回复惰性发送，目标连不上或未发数据就关闭时回 ERROR（连接被拒为 `0x06`，未发数据为 `0x65` / `0xFF`）。CONNECTv2 连接按 §4 在同一连接上依次承载多个请求，空闲 240 秒关闭；UDP over TCP（v3+）经节点的 UDP 出口转发。为此 `engine-inbound` 新增 `StreamInbound::serves_connections` / `serve_connection`（由协议自己处理整条连接，经 `server::ConnectionContext` 获取出站、计数和限时）和 `udp::UdpOutbound` UDP 出口接口，`server::serve_with_udp` 传入 UDP 出口；`node-runtime` 的直连出站实现 UDP（双栈套接字，私网目标策略与 TCP 相同）。
- 节点服务端入站（第一步）：新增 `engine-inbound`（服务端入站接口 `StreamInbound`、按名称管理的用户表 `UserStore`、`server::serve` 服务循环和入站 `registry`）和 `inbound-shadowsocks`（Shadowsocks-2022 TCP 服务端）。用户可在运行中增删，删除或替换用户会断开其现有连接；`traffic(reset)` 按用户报告上下行字节（已删除用户未取走的流量保留到下次读取），`online()` 按用户和来源 IP 报告在线连接数，供 anix-agent 这类节点代理驱动。SS-2022 支持三种 2022 方法、单密钥和多用户（iPSK:uPSK 身份头，仅 AES），30 秒时间戳窗口、60 秒盐值防重放，握手失败的连接保持打开并丢弃输入而不是立即关闭。测试用自研客户端和 shadowsocks-rust 客户端连接服务端。同时新增 `inbound-transport`（服务端 TLS，证书文件变化时自动重新加载，坏证书保留旧的）、`inbound-trojan` 和 `inbound-vless`（按用户密码哈希 / UUID 认证，认证失败转给 `fallback` 网站或保持丢弃），以及 `inbound-vmess`（VMess AEAD，aes-128-gcm / chacha20-poly1305 / none，支持 ChunkMasking 和 GlobalPadding，AuthID 120 秒窗口与防重放）。防重放缓存移到 `engine_inbound::replay`。新增 QUIC 类入站接口 `PacketInbound`（registry 按 `Inbound::Stream` / `Inbound::Packet` 区分）、`server::relay_accepted` 和 `transport_quic::server_endpoint`，并新增 `inbound-hysteria2`（自带最小 HTTP/3 与 QPACK 静态表实现处理 `/auth`，认证失败返回 404 伪装成网站，可选 Salamander 混淆）与 `inbound-tuic`（TUIC v5，按 UUID 和 TLS 导出密钥令牌认证，cubic / new_reno / bbr 拥塞控制），删除用户会关闭其 QUIC 连接。`inbound-vless` 新增 REALITY 服务端（`tls-mimic` 新增最小 TLS 1.3 服务端 `tls_mimic::server`）：校验 ClientHello 会话 ID 中的 REALITY 标记（私钥、short id、SNI、时间窗口），通过的客户端拿到绑定认证密钥的临时 Ed25519 证书，其余连接（包括非 TLS 探测）原样转发到伪装站点。新增 `node-runtime` 与节点内核程序 `apps/anixcore`（`anixcore run|check -c config.json`）：按 tag 运行和增删入站，提供带 Bearer 令牌的本地 HTTP/JSON 管理接口（增删入站、增删用户、按用户流量含清零、在线 IP），供 anix-agent 驱动；直连出站默认拒绝回环、内网、CGNAT 和链路本地目标（入站自己的 fallback / REALITY 伪装站点除外），可用 `allow_private_targets` 放开。UDP 转发、VLESS Vision 后续提供。
- 新增 Snell 出站 `outbound-snell`（cargo feature `snell`，配置 `"type": "snell"`），只依据 `docs/protocols/snell.md` 净室实现：支持 v1–v4 与 v6（v5 按 v4 运行，不实现 QUIC 代理模式），v6 的 `default`（PSK 派生画像整形、salt 块、填充混排）、`unshaped`、`unsafe-raw` 三种模式，v4 首包整形与比特配平，v1–v4 的 `obfs = http`，CONNECTv2 连接复用（最多 10 条空闲、180 秒），以及 crate API 里的 UDP over TCP（v3+）和 PING。帧编解码与请求解析与方向无关，供后续 `inbound-snell` 复用。导入支持 Surge `snell` 节点行和 Clash `type: snell`（`psk`、`version`、`obfs-opts`；缺省 version 为 1），`obfs = tls` 暂报不支持。互通 CI 下载官方 snell-server v3.0.1、v4.1.1、v5.0.1、v6.0.0rc2（只在 CI 中运行，不随产物分发）做 TCP、复用、UDP、错误回复和 PING 黑盒测试。
- Linux 图形客户端支持分流模式、订阅规则和策略组：新增共享模块 `engine_embedded::profile`，包含五种分流模式（绕过大陆、GFW 列表、回国、直连、规则）、公共规则列表的地址和解析，以及策略组的当前选择、select 组切换和“节点切换落到主策略组”。订阅带规则和策略组、且全部节点都能运行时，Linux 版用全部节点加订阅规则启动，规则页和首页列出策略组并可切换 select 组成员（连接中会重启引擎）；切换节点会改主策略组的选择，选择按订阅保存。分流模式的规则列表在切换模式或连接前下载到 `$XDG_CONFIG_HOME/anixops-net/rules/`，“刷新规则资源”重新下载。规则页、首页分流模式和策略组卡片不再对 Linux 隐藏；默认模式为“规则”，与之前全部流量走所选节点的行为一致。

### Removed

- Windows 客户端移除第三方内核：服务、托管配置和图形界面不再启动、安装或校验兼容内核和 Mieru 外部内核，节点、策略组、分流模式和 DNS 只走内置引擎。HTTPS 解密改为把本机 MITM（`127.0.0.1:7890`，系统代理指向它）的上游接到内置引擎的本地代理（`127.0.0.1:7891`）。设置页去掉“兼容内核”和“附加协议内核”卡片，规则页去掉策略组 JSON 编辑和 DNS JSON（DNS 卡片固定说明系统 DNS 行为），旧的 Win32 窗口代码一并删除。托管配置和状态文件里的旧字段会被忽略；用兼容内核导入的旧配置需要重新导入订阅。Linux 图形客户端同步去掉对应的占位命令。
- Linux 命令行移除第三方内核：删除 `install-sing-box`/`sing-box install`、`core install|start|stop|status mieru`，以及依赖兼容内核控制接口的 `node switch` 和 `node health`。`run-url` 和 `run-catalog` 只用内置引擎（去掉 `--engine`、`--install-dir`、`--force`、`--binary`、`--sha256`），内置引擎不支持的节点直接报错，不再退回外部内核；`core list` 只列出原生适配器。`mitm browser-capture session-plan` 直接从订阅取第一个节点，不再生成兼容内核配置。
- 删除 `engine-singbox` 和 `engine-mieru` crate、控制域的 `PublicEngineKind`/`PublicEngineRunPlan` 以及 `ProxyEngineKind` 里的第三方内核名称，CI 去掉“Routing equivalence (sing-box)”任务和针对这两个 crate 的守卫；路由行为仍由 `testdata/routing-snapshot/decisions.json` 快照固定。订阅里的 sing-box JSON 和 `mierus://` 链接仍可作为格式导入。
- 文档不再把第三方内核写成当前能力：README、ROADMAP、TODO、功能矩阵、Windows 安装与发布合约、Windows GUI 日常可用性合约和各 crate README 改为描述内置引擎；两份第三方内核 adapter 合约移到 `docs/archive/2026-10-removed-engines/`，对应 CI 文档检查改为新的内置引擎标记。
- Windows 删除前台隧道和外部组网程序适配：`networkcore-windows tunnel prepare-storage|start|status|stop` 命令、托管配置的 `tunnel` 字段和状态的 `tunnel_running`、服务里的隧道启动/停止/回滚、GUI 设置页的 TUN 配置，以及 `platform-windows` 的隧道运行时、安全存储和 `config-core::windows_tunnel` 规划器都已移除；SD-WAN 下发校验只接受 `ikev2` 传输。旧配置里的 `tunnel` 字段会被忽略，旧版本拉起的隧道进程需先用旧版本停止。SD-WAN 组网等 ANX 私有协议重新提供；对应的人工验收计划移到 `docs/archive/2026-10-removed-engines/`。

### Fixed

- `mitm_anixops` 子模块升级到 distribution release `v1.4.7`（`ee95223`）：Node 脚本运行器在 Windows 上替换持久化存储文件时，遇到 `EPERM`、`EACCES` 或 `EBUSY`（文件仍被其他进程占用）会短暂重试。`engine-native` 的 `controlled_tls_connect_session_bounds_persistent_exchanges_over_live_sockets` 在 Windows 上偶发未改写请求体，根因是测试给脚本的 1 秒超时短于 Windows runner 上 Node 冷启动的时间：脚本超时改为 5 秒，测试套接字超时相应放宽到 15 秒。

## v0.2.0 - 2026-10-26

正式版，tag 在 `a636b89`，与通过 Windows/Linux 真机验收的 `v0.2.0-rc.2` 同一提交（`v0.2.0-rc.1` 在 `54adc04`）。以下为自 `v0.2.0-alpha.21` 以来的全部变更。

### Security

- 修复 Actions 依赖审计发现的 RUSTSEC-2026-0385（`ctutils` 掩码生成与 `u128` 比较非常数时间）：将 `ctutils` lock 提升到 `0.4.4`。未添加漏洞忽略规则。
- 修复 Actions 依赖审计发现的 RUSTSEC-2026-0346、RUSTSEC-2026-0347、RUSTSEC-2026-0348、RUSTSEC-2026-0349（`rustls`）、RUSTSEC-2026-0382（`rustls-webpki`）和 RUSTSEC-2026-0381（`webpki-roots`）：将 `rustls` 最低版本与 lock 提升到 `0.23.46`，`rustls-webpki` lock 提升到 `0.103.16`，`webpki-roots` lock 提升到 `1.0.10`。未添加漏洞忽略规则。
- 修复 Actions 依赖审计发现的 [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html)：将 `rustls` 最低版本与 lock 提升到 `0.23.45`，相应 `rustls-webpki` lock 提升到 `0.103.15`。保留依赖审计与全平台 TLS 回归，未添加漏洞忽略规则。

### Added

- iOS/macOS 包隧道也运行 url-test 和 fallback 策略组的健康检查：`EmbeddedRuntime` 对 `routing` 配置保留规则出站，`Tunnel::start_with_background` 在隧道的运行时里跑 `run_health_checks`，测速和本地代理相同（逐成员经各自出站请求组的 URL，最短间隔 30 秒），隧道停止时一起结束。之前隧道里的这类组没有测速结果，一直用第一个成员。
- iOS 隧道支持订阅规则和策略组：`node-import` 的导入结果新增 `routing`（订阅的规则和 select/url-test/fallback 策略组，节点按 id 引用）。只有全部节点都能运行、节点 id 合法、数量不超过引擎上限时才提供；上限常量移到 `node-import`，由引擎共用，`engine_embedded::nodes::routing_envelope` 也改用 `node_import::routing_json`。App 把规则和策略组跟节点列表一起存在钥匙串里，隧道配置里只有一个“按规则分流”的标记。扩展启动时从钥匙串读取节点列表，生成带全部节点的 `routing` 配置；读不到节点列表或运行时拒绝这份配置时，退回只用所选节点，原因记入诊断。新的“规则”页可以开关按订阅规则分流，也可以切换 select 策略组的成员（连接中会自动重连）。按规则分流时，代理页的节点不可点选。刷新订阅时保留规则开关和仍然有效的策略组选择。
- 发布流程加入 Linux 图形客户端：tag 发布新增 `package-linux-gui` 与 `attest-linux-gui` 任务，在 Ubuntu 上构建共用界面和 `anixops-net`，产出 tarball（`bin/`、桌面入口、图标、LICENSE、CHANGELOG、INSTALL.md）和 Debian 包（`/usr/bin/anixops-net`、菜单项与图标，依赖 `libwebkit2gtk-4.1-0`），各带 manifest 与 sha256，统一做 GitHub artifact attestation 后随 Release 发布。`gui` feature 现在包含 `tauri/custom-protocol`，直接 `cargo build --release` 得到的窗口也内嵌界面而不是去连开发服务器。
- Windows 内置引擎支持订阅自带的规则和策略组：导入带 `[Rule]`/`[Proxy Group]` 或 Clash `rules`/`proxy-groups` 的订阅后，节点列表不再为空，新增“规则”分流模式（导入这类订阅时自动选中，只对内置引擎提供）按订阅规则分流；“规则”页列出订阅的策略组，可切换手动选择组的出口（已连接时自动重启内核），节点页切换节点改主策略组的出口，“选择最快节点”只在主策略组成员里挑，刷新订阅保留原选择。其他四种分流模式下 FINAL 的策略组选择同样生效。
- `engine-embedded` 的自动测速组生效：桌面本地代理（Windows 桌面/服务模式、Linux）运行路由配置时在后台对 url-test/fallback 组的每个成员按组的 URL 测速（`RoutedOutbound::run_health_checks`，间隔取各组最短值且不少于 30 秒，单次超时 5 秒），url-test 选延迟最低的成员，fallback 选第一个测通的成员；首次测速完成前用第一个成员。新增 `delay::probe` 在调用方运行时里测一次 URL。iOS 隧道暂不运行测速。
- `engine-embedded` 的规则路由支持 DNS：域名目标遇到未写 `no-resolve` 的 IP 规则时，用系统解析器（`DomainResolver`，默认 `SystemResolver`）解析一次，并用该地址匹配后续 IP 规则；连接本身仍按域名发出，经节点时由节点服务器解析；解析失败拒绝连接（与 sing-box 一致）。此前这类连接一律被拒绝。Windows 设置里的 DNS 卡片在内置引擎下说明这一行为，不再显示只对 sing-box 生效的 DNS JSON。
- iOS 订阅链接、多节点列表与切换：导入框粘贴一个 http(s) 订阅链接时，App 下载订阅（30 秒超时、最多 4 MB，只接受 2xx），保存全部可运行节点并选中第一个；节点列表连同出站参数只存在钥匙串里。代理页列出全部节点，点选即切换，已连接时自动断开并用新节点重连；订阅链接导入的列表支持下拉更新，更新后仍选中原节点（不在列表里时选第一个）。延迟测试在 App 内测 TCP 握手耗时（每批 8 个并发，5 秒超时），Hysteria2、TUIC 等 QUIC 节点标为 UDP、不测。
- iOS 导入接入自研协议栈：新增 `node-import` crate（订阅文本 → 自研引擎出站，不含协议实现和隧道引擎），带 `networkcore_import_*` C 接口，App 只链接它构建出的 `NetworkCoreImport.xcframework`，隧道引擎仍只在扩展里（CI 检查 App 含导入符号、不含 `networkcore_ios_runtime_init`）。App 现在可以粘贴 Trojan、VMess、VLESS（TLS/WS/gRPC）、Shadowsocks AEAD、Hysteria2、TUIC 链接，或订阅内容（base64 链接列表、Clash YAML、JSON 出站配置、Surge/Loon/Quantumult X 节点行），取第一个可运行节点；非 Shadowsocks/REALITY 节点作为通用出站保存，出站参数整体存入钥匙串，隧道配置里只留类型和地址。`engine-embedded::nodes::outbound_for_node` 改为调用 `node_import::outbound_json`。
- Linux 图形客户端（P4）：新增 `apps/linux-gui`（可执行文件 `anixops-net`），复用 Windows 的 Tauri + React 界面和中英文文案，在进程内运行自研引擎，所选节点在 `127.0.0.1:7890` 提供 SOCKS5/HTTP 本地代理。连接时把 GNOME（`gsettings`）或 KDE（`kwriteconfig6/5`）的系统代理指向本地端口，断开、退出或下次启动时改回原来的设置；支持导入订阅链接、分享链接或本地文件，切换节点、延迟测试和选择最快节点，“登录后启动”写入 XDG 自启动项，配置保存在 `$XDG_CONFIG_HOME/anixops-net`（文件权限 0600）。界面根据快照里的 `platform` 隐藏 Windows 服务、附加内核、驱动、TUN、分流规则和 HTTPS 解密等 Linux 版暂未提供的功能。窗口依赖 WebKitGTK，放在 `gui` feature 后面，工作区任务只编译和测试后端；新增 CI 任务“Linux GUI build”在 Ubuntu 上构建共用界面、lint 并编译窗口。AppImage/deb 打包、托盘、TUN 和分流模式留待后续。
- Windows 客户端支持英文界面：中文仍是源语言，界面文案通过 `t()` 在 `i18n-en.ts` 英文表中查找，设置页“外观与语言”可选跟随系统、中文或 English（保存在本机），切换后立即生效；`i18n.test.ts` 检查界面里每条中文都有英文翻译，并禁止模板字符串和裸 JSX 文本里出现未翻译的中文。内核和服务返回的原始提示保持原样。
- macOS 客户端（P4）：新增 SwiftUI 的 `NetworkCoreMac` App 和 `NetworkCoreMacTunnel` 包隧道扩展（复用 iOS 的隧道、导入流程、品牌组件和中英文文案）。主窗口左侧导航为概览、代理、规则、扩展、活动、设置六页，概览页用“路由 N”连接按钮和连接时长；菜单栏常驻图标可随时连接或断开；⌘I 导入节点，⇧⌘C 连接或断开，⌘, 打开设置；支持跟随系统、浅色、深色、纯黑外观和登录后自动打开。节点密钥在 macOS 上写入数据保护钥匙串，App 与扩展通过共享钥匙串组读取。运行时 XCFramework 增加 arm64 + x86_64 的 macOS 切片，CI 无签名构建并检查扩展链接了运行时。规则页和扩展页暂为说明页；签名和 TestFlight 上传见 `docs/manual-intervention.md`。
- iOS 小组件与控制中心开关：新增 `NetworkCoreWidget` 扩展，主屏幕小号/中号小组件和锁屏小组件显示连接状态、当前节点和协议，轻点路由线即可连接或断开；iOS 18 起可在控制中心、锁屏和操作按钮添加“连接 AnixOps Net”开关。小组件直接读取已保存的 VPN 配置（不读取节点密钥），App 内状态变化时立即刷新。TestFlight 上传在配置小组件描述文件前会跳过该扩展（见 `docs/manual-intervention.md`）。
- iOS App 支持英文界面：中文为源语言，新增 `Localizable.xcstrings` 提供全部界面文案、错误提示和开发者模式文案的英文翻译，跟随 iPhone 系统语言切换；代码里拼出的文案改用 `String(localized:)`。
- Windows 客户端在内置引擎下支持节点切换和延迟测试（Phase 2c-3）：`engine-embedded` 新增 `delay::measure_delay`，用配置信封自建出站，测量连接 HTTP(S) URL 并收到响应状态行的耗时（与 Clash `url-test` 口径一致，不经系统代理，错误信息不含节点参数）。单节点导入时保存全部受支持节点的出站（`embedded/nodes.json`）并填充节点列表；切换节点重写配置信封、重新套用当前分流模式，已连接时重启内核；延迟测试和“选择最快节点”在 GUI 进程内进行（每批 16 个并发、单节点 5 秒超时），未连接时也可用。订阅带规则和策略组的配置暂不提供节点列表。
- 自研路由支持 `RULE-SET` 规则集（Phase 2c-2）：`config-core` 新增 `rule_set::RuleSet`（域名后缀哈希查找 + 合并后的网段二分查找，十万级条目每次匹配开销不变；网段只匹配本身就是 IP 的目标，不为它解析域名，与 sing-box 无 resolve 动作的 rule_set 一致），路由规则新增 `RULE-SET,<名称>,<目标>`。`engine-embedded` 配置信封的 `routing.rule_sets` 携带具名列表（最多 16 个、合计 50 万条），引用未配置的规则集会被拒绝。订阅导入仍跳过 `RULE-SET` 行。Windows 客户端在内置引擎下支持全部四种分流模式（绕过大陆、GFW 列表、回国、直连）：导入时保留原始配置信封，切换模式时用下载的规则列表重新生成路由；导入时也会按当前模式生成（规则列表下载失败时退回全局代理并记录日志）。
- Windows 客户端接入自研引擎（Phase 2c-1）：托管配置新增 `embedded`（配置信封路径和回环监听地址，与 sing-box、Mieru 三者只能启用一个），托管状态新增 `embedded_running`、`embedded_listener`、`embedded_last_error`。Windows 服务在进程内启动 `engine-embedded` 本地代理并纳入健康检查和回滚；GUI 桌面模式由 GUI 进程自己运行它，不再需要外部内核进程。未安装 sing-box 时导入订阅会直接生成自研引擎配置（全部节点都支持时带上订阅规则和策略组，否则运行选中或第一个节点），不再要求先安装 sing-box；已安装 sing-box 的现有用法不变。分流模式、DNS、HTTPS 解密和节点切换仍只支持 sing-box 配置，后续补齐后再把 Windows 默认切到自研引擎。
- Hysteria2 支持 Salamander 混淆：`transport-quic` 新增 `salamander` 模块，以包装 quinn UDP 套接字的方式给每个数据报加 8 字节随机 salt，并与 BLAKE2b-256(密码‖salt) 循环异或；接收端支持系统合并的多数据报（GRO）缓冲，过短的数据报直接丢弃，同时把 MTU 探测上限下调 8 字节。配置写法为 `"obfs": {"type": "salamander", "password": ...}`，订阅中带 `obfs=salamander` 的节点现在可由自研引擎运行（`gecko` 仍明确拒绝）。CI 互通新增带混淆的 sing-box 与官方 Hysteria 服务端。
- 自研 TUIC v5 出站：新增 `outbound-tuic`。QUIC 连接建立后在单向流上发送 Authenticate（UUID + 以 UUID 为 label、密码为 context 导出的 32 字节 TLS keying material，密码本身不上线），每个 TCP 连接是一条双向流，以 Connect 命令（域名/IPv4/IPv6 + 端口）开头后直接转发数据；同一出站共享一条连接，断开后自动重连。支持 `congestion_control` `cubic`/`new_reno`/`bbr`。QUIC 客户端部分抽为公共的 `transport-quic`（解析服务器、按地址族绑定 UDP、窗口/keepalive/空闲超时、拥塞控制、`QuicStream`），Hysteria2 改用它。`engine-embedded` 新增 `tuic` feature（默认开启），订阅中的 TUIC v5 节点可由自研引擎直接运行；只有 token 的 TUIC v4 节点明确拒绝，UDP 转发尚未实现。测试包含进程内 TUIC 服务端（用服务端自己的 TLS exporter 校验 token），以及 CI 中对 sing-box TUIC 入站的互通下载与错误密码校验。
- 自研 Hysteria2 出站：新增 `outbound-hysteria2`，基于 `quinn`（QUIC）与 `h3`（HTTP/3）：以 ALPN `h3` 建立 QUIC 连接，`POST https://hysteria/auth` 携带 `Hysteria-Auth` 与随机 `Hysteria-Padding` 认证，服务端返回 233 才算成功（其他状态视为伪装站点并报认证失败）；每个 TCP 连接是一条 QUIC 双向流，请求为 `0x401` + 目标地址 + 随机填充，等待服务端状态后再转发数据。同一出站共享一条已认证连接，断开后自动重连。`transport-tls` 新增 `client_config` 供 QUIC 复用同一套证书校验与 `insecure` 逻辑。`engine-embedded` 新增 `hysteria2` feature（默认开启），订阅中的 Hysteria2 节点可由自研引擎直接运行；Salamander 混淆暂明确拒绝，端口跳跃范围忽略并连接主端口，拥塞控制使用 QUIC 默认算法（未实现 Brutal），UDP 转发尚未实现。测试包含进程内 QUIC/HTTP/3 服务端，以及 CI 中对 sing-box 与官方 Hysteria 服务端的互通下载和错误密码校验。
- Windows 客户端按 AnixOps Net 品牌 VI 重做界面（P2）：左侧导航改为概览、代理、规则、扩展、活动、设置六页，全部中文；概览页用和 iOS 相同的“路由 N”连接按钮（连接中路由线循环生长，连上后点亮琥珀色终点），旁边直接切换分流模式（绕过大陆、GFW 列表、回国、直连），下方是当前节点、内核、系统代理、服务状态卡和策略组、订阅摘要；代理页改为可筛选的节点卡片网格加订阅管理，空状态直接给出导入框；规则页放分流模式、策略组和 DNS，扩展页放 HTTPS 解密、根证书和脚本，活动页放会话详情和诊断报告（逐条请求记录等内核提供数据后再开放）。外观可选跟随系统、浅色、深色和纯黑，标题栏随之切换；成功提示自动消失，错误提示保留；支持 Ctrl+Shift+C 连接或断开，并遵循系统“减少动画”。页面文案不再写 sing-box 等第三方内核名称（Mieru 只在附加内核的说明里出现；内核返回的原始提示暂时保持英文原样）。窗口标题、托盘提示和 Tauri 产品名改为 AnixOps Net；可执行文件名、服务名和安装包名不变。
- iOS App 按 AnixOps Net 品牌 VI 重做界面（P1）：底部五个标签（首页、代理、规则、扩展、设置）；首页连接卡用图标里的“路由 N”做连接按钮，连接中路由线循环生长、连上后点亮琥珀色终点并有触感反馈，显示连接时长；新的三步导入流程（系统粘贴按钮或文件 → 预览协议和打码后的服务器地址 → 完成），预览阶段不保存任何内容；设置里可选跟随系统、浅色、深色和纯黑 OLED 外观；规则和扩展页先说明即将提供的功能，不显示假数据。颜色、圆角和动效时长来自新的 `apps/ios/Design/tokens.json`。App 显示名和 VPN 配置名改为 AnixOps Net。
- Loon 插件 P1 的 `[Map Local]` 与 `[Body Rewrite]`：`[Map Local]`（以及 `[Rewrite]` 里的 `mock-response-body`）命中时直接在本地返回响应、不连源站（新增 `HttpMitmAction::Respond`，数据面终止动作 `local-response`），支持 `data-type` 为 text/json/html/base64/tiny-gif、`status-code` 与 `header`，远程 `data` URL 不拉取；Loon action-first 的 `http-request`/`http-response` body 重写翻译为 core 的 url-first 规则，每对替换一条，同一 URL 的 body 规则按顺序全部应用；jq 行因 core 未编入 jq 而定级 unsupported。
- 自研 gRPC 传输：新增 `transport-grpc`（基于 `h2` 的 V2Ray 风格 gun 客户端：每个连接一次 `/<service_name>/Tun` 双向流调用，数据封装为 protobuf `Hunk` 的 gRPC 帧，按 HTTP/2 流控发送，支持 Xray 的 `/` 自定义路径写法）。VLESS（非 REALITY）、VMess、Trojan 均支持 `"transport": {"type": "grpc", "service_name": ...}`，TLS 未指定 ALPN 时自动使用 `h2`；订阅中的 gRPC 节点现在可由自研引擎直接运行。CI 互通测试新增 Xray-core 与 sing-box 的 VMess-gRPC 入站。
- 自研 Shadowsocks AEAD（SIP004）出站：`outbound-shadowsocks` 新增 `AeadOutbound`，支持 `aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`（别名 `chacha20-poly1305`）：密码经 `EVP_BytesToKey` 得到主密钥，每个方向以随机 salt 和 HKDF-SHA1 派生会话密钥，长度与数据分别 AEAD 封装，目标地址随首包发送（应用先读时单独发送）。`"type": "shadowsocks"` 按 `method` 自动选择 2022 或 AEAD 协议；订阅中的这些旧版 SS 节点现在可由自研引擎直接运行，流加密（如 `aes-256-cfb`、`rc4-md5`）仍明确拒绝。测试使用 shadowsocks-rust 服务端互通。
- 自研 VMess 出站：新增 `outbound-vmess`，实现 VMess AEAD（alterId 0，当前 Xray-core/V2Ray 默认）：AuthID + AES-128-GCM 封装的请求头与首包合并发送，正文为 AES-128-GCM 或 ChaCha20-Poly1305 分块，长度经 SHAKE128 掩码（ChunkStream + ChunkMasking），响应头 AEAD 校验，关闭时发送空块。可跑在明文 TCP、标准 TLS（`transport-tls`）与 WebSocket（`transport-ws`）上。`engine-embedded` 新增 `vmess` feature（默认开启），订阅中 alterId 为 0 的 VMess（TCP/TLS/WS）节点可由自研引擎直接运行；alterId 非 0 的旧版 MD5 头和 `none`/`zero` 加密明确拒绝。测试包含按协议描述独立编写的进程内服务端，以及在 CI 中对真实 Xray-core 与 sing-box VMess 服务端（TCP、WS，两种加密）的互通下载校验。
- VLESS 不再只支持 REALITY：`outbound-vless` 新增 `VlessTlsOutbound`，支持 VLESS over 明文 TCP、标准 TLS（`transport-tls`），以及可选的 WebSocket（`transport-ws`）。请求头与首包合并发送，响应头（含 addons）在第一个数据字节之前剥离。配置写法为 `"tls": {...}` 和/或 `"transport": {"type": "ws"}`；`reality` 不能与 `tls`/ws 同时配置。Vision 流控目前仍要求 REALITY。订阅中的 VLESS-TLS、VLESS-WS(-TLS) 和无加密 VLESS 节点现在可以由自研引擎直接运行。
- 自研 WebSocket 传输层：新增 `transport-ws`（RFC 6455 客户端：握手校验 `Sec-WebSocket-Accept`，每次写入一个带掩码的二进制帧，读取时把数据帧按序拼成字节流，自动回应 ping，close 帧视为流结束；path/Host/自定义头拒绝可注入的字符），测试以独立实现 `tokio-tungstenite` 作为服务端。Trojan 支持 `"transport": {"type": "ws", "path", "host"}`（TLS 内跑 WebSocket），订阅中的 Trojan-WS 节点可由自研引擎直接运行。
- 自研 SOCKS5 与 HTTP 代理出站：新增 `outbound-socks`（RFC 1928 `CONNECT`，可选 RFC 1929 用户名/密码，完整读取应答绑定地址，不吞掉目标先发的数据）与 `outbound-http`（`CONNECT` 隧道，可选 Basic 认证与 TLS（HTTPS 代理，复用 `transport-tls`），响应头逐字节读取到空行为止，目标域名拒绝控制字符以防头注入）；`engine-embedded` 新增 `socks`、`http` feature（默认开启），可作为上游代理或代理链出口，CI 协议 feature 矩阵同步覆盖。测试使用仓库自己的 `inbound-mixed` 作为服务端。
- 自研 Trojan 出站：新增 `transport-tls`（rustls + WebPKI 根证书的标准 TLS 客户端，`insecure` 仅跳过证书校验、仍校验握手签名，可供后续 VMess/VLESS-TLS 复用）与 `outbound-trojan`（SHA-224 密码头与首包合并发送，支持服务端先发数据的目标）；`engine-embedded` 新增 `trojan` feature（默认开启），订阅中的 TCP Trojan 节点可由自研引擎直接运行，`run-url --engine auto` 不再为 Trojan 回退到 sing-box。
- `networkcore-linux run-url` 新增 `--engine auto|embedded|sing-box`（默认 `auto`）：自研引擎（`engine-embedded` 本地代理）能运行订阅时直接在进程内提供 SOCKS5/HTTP 代理，不再下载和启动 sing-box；目前支持 Shadowsocks-2022 与 VLESS + REALITY，全部节点都支持时同时应用订阅规则与策略组；其他协议在 `auto` 下回退到 sing-box，`embedded` 下报告不支持的节点（不含密钥）。`engine-embedded::nodes` 把 `config-core` 节点转换为配置信封，`config-core` 的 `ImportedRouting` 新增 `spec` 字段。
- 自研桌面本地代理：新增 `inbound-mixed` crate（同一端口上的 SOCKS5 `CONNECT`（可选用户名/密码）与 HTTP 代理（`CONNECT` 隧道和绝对 URI 明文请求，可选 `Proxy-Authorization: Basic`），按首字节区分协议，请求头上限 16 KiB，统计不含地址）；`engine-embedded` 新增 `local-proxy` feature 与 `local_proxy::LocalProxy`，用与 iOS 相同的配置信封（单出站或 `routing`）在本地端口提供代理，域名规则可直接匹配。这是替换桌面端外部引擎 mixed 入站的第一步，现有 CLI 与 Windows 服务尚未切换。
- 协议模块化第一步：`engine-outbound` 新增协议注册表（`registry::OutboundRegistry` + `OutboundFactory`），出站按配置里的 `type` 名查找对应协议的工厂构建，协议自己的字段只由协议 crate 解析。Shadowsocks-2022 从 `engine-embedded` 拆为独立的 `outbound-shadowsocks` crate；`engine-embedded` 的每个协议都是一个 cargo feature（`shadowsocks`、`vless`、`wireguard`，默认全开，`direct` 始终内置），关掉 feature 即从构建中去掉该协议，未编入的 `type` 返回 `config_rejected`。`EmbeddedRuntime::with_registry` 可传入自建注册表。新增 CI 任务 `Protocol feature matrix`，逐个单独开启每个协议做 clippy 和 C ABI 契约测试。iOS 侧配置 JSON 不变。
- Loon 插件 P1 脚本：新增 `script-runtime` crate，`$request`/`$response`/`$argument`/`$done`/`$persistentStore`/`$notification`/`$httpClient`/`console`/定时器只在 Rust 里实现一份（`ScriptHost`），JS 引擎只绑定一个宿主函数并执行共享 prelude；桌面端绑定 QuickJS-ng（rquickjs），用 QuickJS 堆上限和中断回调实现 Loon `timeout`/`max-size`。`tests/fixtures/conformance` 是引擎无关的一致性夹具，M4 的 JavaScriptCore 绑定复用同一套。`engine-native` 新增进程内 `NativeQuickJsScriptExecutor`（脚本按 SHA-256 固定、`$httpClient` 默认关闭），请求阶段脚本可用 `$done({response})` 直接返回响应；`networkcore-linux start --enable-script-runtime` 不带 `--script-runner` 时使用 QuickJS，并允许 `--script-store`。Loon 导入器把 `[Script]` `http-request`/`http-response` 行定级为支持。
- iOS App 新增隐藏的开发者模式：在“关于”里连点版本号 7 次开启，显示扩展内存占用、运行时长、运行时 ABI 版本、上次停止原因（含完整 domain/code 链）、格式化的运行状态 JSON（每 2 秒自动刷新）和扩展最近 200 条事件（启动步骤、停止原因、睡眠唤醒、内存压力），并可一键复制不含节点名称、地址和密钥的诊断信息。App 通过 `TunnelAppMessage.diagnostics` 请求诊断，空消息仍返回运行状态 JSON。App 隐私清单声明 UserDefaults（CA92.1）。
- `engine-embedded` 运行状态新增 `dns_last_failure` 与 `tcp_last_failure`：只记录失败阶段和错误类别（如 `connect_timeout`、`reply_closed`、`reply_rejected`），不含地址或内容，用于在真机上区分连不上代理服务器、代理不回应和代理拒绝认证。
- `engine-embedded` 的 Shadowsocks-2022 出站支持多用户 identity header（SIP022 EIH，`iPSK:uPSK` 形式的密码，仅 AES 方法），身份头用 RustCrypto `aes` 分组加密；节点密钥同时接受标准与 URL-safe base64，填充可省略。此前这类节点在 iOS 上导入后启动隧道会被内核拒绝（code 6）。
- iOS 隧道启动失败时，App 显示扩展返回的失败原因，扩展把启停和失败原因写入系统日志（子系统 `networkcore.packet-tunnel`）。

- iOS App 支持导入 `vless://` 分享链接（`security=reality`、TCP、可选 `flow=xtls-rprx-vision`），生成 `engine-embedded` 的 `vless` 出站；uuid 与其他节点密钥一样只存入 Keychain，App 侧配置不含 uuid。`fp` 参数忽略，固定使用 Chrome 指纹。

- Windows Tauri GUI 导入含规则和策略组的订阅时生成路由配置，策略组在原生分组界面中查看和修改默认成员；不含规则或导入失败时保持原来的单选择器配置。

- `engine-embedded` 运行时配置支持 `routing` 段（与 `outbound` 二选一）：多个命名出站加 `config-core` 规则与策略组，`RoutedOutbound` 按连接选择直连、拒绝或节点。iOS App 尚未生成该段，现有配置行为不变。

- 订阅规则与策略组导入：`config-core::routing_import` 从 Surge/Loon `[Proxy Group]`/`[Rule]` 与 Clash `proxy-groups`/`rules` 构建路由模型，不支持的规则和组跳过并警告；`engine-singbox` 新增 `render_sing_box_local_proxy_routing_config`；`networkcore-linux run-url` 未指定 `--node` 时按订阅规则和策略组生成 sing-box 路由，导入失败时退回单节点。

- 路由规则支持 `DOMAIN-KEYWORD`：`config-core` 按域名子串匹配，`engine-singbox` 翻译为 sing-box `domain_keyword`；共享路由快照与 sing-box 等价性测试覆盖该规则。
- `engine-embedded` 新增 WireGuard 模式：用 boringtun 的 Noise 状态机（BSD-3-Clause，不启用 `device` 特性）把 TUN 包直接封装到一个对端，不经过用户态 TCP/IP 栈；附带与进程内 boringtun 对端的回环测试。iOS App 可粘贴单 Peer 的 `wg-quick` 配置导入，私钥和预共享密钥存入钥匙串，隧道地址、路由、DNS 和 MTU 按配置下发。

- iOS 节点密钥改存钥匙串：App 导入 `ss://` 节点时把密钥写入共享 keychain access group（`$(AppIdentifierPrefix)networkcore.shared`），隧道配置只保存 `passwordReference` 和不含密钥的运行时配置；隧道扩展启动时从钥匙串取回密钥再交给内核。

- iOS 隧道扩展接入原生内核（M1a）：CI 在 `macos-26` 上用 `.github/scripts/build-ios-runtime-xcframework.sh` 把 `engine-embedded` 编成 `NetworkCoreRuntime.xcframework`（不提交），只由 `NetworkCorePacketTunnel` 链接；`PacketTunnelProvider` 校验运行时握手后经 C ABI 启动隧道，全量 IPv4/IPv6 路由与 DNS 进隧道；App 可粘贴 Shadowsocks-2022 `ss://` 链接保存为 VPN 配置并连接/断开、查看脱敏运行状态。隧道扩展的隐私清单声明 System Boot Time `35F9.1`。节点密钥暂存于 `providerConfiguration`，仅限内部 TestFlight。

- 新增 `engine-embedded` crate（M1a）：iOS Network Extension 进程内内核。Shadowsocks-2022 TCP 出站（`2022-blake3-aes-128-gcm` / `aes-256-gcm` / `chacha20-poly1305`，基于 `ring` + `blake3` 自实现，暂不支持多用户 identity header），smoltcp 用户态 TCP/IP 栈（`netstack-smoltcp`），UDP/53 经出站转 DNS-over-TCP、其余 UDP 丢弃，按 NE 内存预算设定连接数、窗口与空闲超时上限；`networkcore_ios_*` C ABI 与 `include/networkcore_ios_runtime.h`。与 shadowsocks-rust 服务端的互通测试只作为 Unix dev-dependency，不进入 NE 二进制。尚未接入 Xcode 工程和 PacketTunnelProvider。

- `engine-embedded` 新增 `vless` 出站配置（M1b）：iOS 隧道可使用 VLESS + REALITY（可选 XTLS Vision）节点，配置字段为 `uuid`、`flow` 与 `reality.server_name/public_key/short_id/fingerprint`，非法 uuid、flow、公钥或 short id 在初始化时以 `config_rejected` 拒绝，状态输出不含 uuid、公钥、short id 或服务器地址。App 端 `vless://` 链接导入尚未接入。

- 新增 `tls-mimic` 与 `outbound-vless`（M1b）：`tls-mimic` 生成 Chrome 形态 TLS 1.3 ClientHello（GREASE、扩展逐连接乱序、X25519MLKEM768 + X25519 key share、ECH GREASE、新 ALPS 码位）并提供带 ClientHello 改写与证书信任 hook 的最小 TLS 1.3 客户端；`outbound-vless` 在其上实现 REALITY 客户端认证、VLESS 请求头与 XTLS Vision 填充/直通，并实现 `engine-outbound::TcpOutbound`。新增 `REALITY interop (Linux)` CI job，在 Ubuntu runner 上与 OpenSSL、Xray-core、sing-box 的 REALITY 服务端做互通测试；真实网络下的抗封锁验收记录在 `docs/manual-intervention.md`。

- 新增 `engine-outbound` crate：`engine-embedded` 与各协议 crate 共用的出站接口（`TargetAddr`、`BoxStream`、构造时注入的 `Dialer` 与默认 `TcpDialer`、`TcpOutbound`），只含接口，不含平台代码；UDP 接口待 TUN 层需要时再定义。

- 新增手动触发的 `.github/workflows/ios-testflight.yml`：在 `ios-app-store-connect` protected environment 中以手动签名 archive 并上传到内部 TestFlight；在维护者启用 `ios-upload-workflow-status` 和确认 `ios-upload-internal-confirmation-status` 前 fail closed，不产生 workflow artifact 或 release asset。

- 编写首批维护事件 v1 严格字段/时间/大小/身份校验、JSON 与逐事件批量序列化边界及显式诊断适配器；原始诊断文本不进入适配结果，自动动作契约移除 rollback。新增 Rust 合同与共享 fixture，[源码 CI](https://github.com/AnixOps/networkcore_anixops/actions/runs/35650045804) 的维护合同、三平台全量回归与依赖审计已通过，尚未接入 NetworkCore 实际运行时通信。

- 完成 `v0.1.2-alpha.2` managed foreground event 第十三个 source-only list 切片：新增 `ManagedForegroundSessionEventListRequest`、`ManagedForegroundSessionEventListEntry`、`ManagedForegroundSessionEventListReport` 和 `CommandManagedForegroundSessionEventStore::list_events`，从调用方显式 directory 只读取直接常规 `.json` event record，按路径确定性排序、校验每个候选并输出 event count/entries 与 `liveness_verified=false`；跳过非 JSON、symbolic link 和嵌套目录，损坏或无效候选保留既有稳定读取/校验错误且不修改文件，不接入 `managed-event list` CLI、实时 event stream 或 runtime control；本轮回归已通过，确切 SHA 与 [CI 记录](https://github.com/AnixOps/networkcore_anixops/actions/runs/35650045804) 见交付证据。

Current Windows/Linux Beta release candidate: `v0.2.0-beta.5`. It is in
`pending_manual_acceptance`: the same commit requires GitHub Actions release
validation and protected Windows/Linux system acceptance before it may be
described as production-ready. A maintainer may explicitly authorize a beta tag
to generate candidate artifacts for that acceptance.

```text
current-main-release-state=released
current-main-source-candidate=v0.2.0
current-main-latest-published-tag=v0.2.0
current-main-latest-stable-tag=v0.2.0
current-main-subscription-foreground=embedded-engine-run-url-and-run-catalog-active
current-main-subscription-refresh=explicit-http-single-source-status-stop-active
current-main-subscription-background=linux-systemd-oneshot-timer-and-windows-opt-in-single-source-active
current-main-managed-reload=explicit-foreground-control-socket-active
current-main-linux-node-switch=explicit-loopback-selector-active
current-main-subscription-refresh-scheduling=linux-systemd-oneshot-timer-and-windows-opt-in-single-source-active
current-main-cross-platform-run-plan=public-engine-run-plan-active

- Added the platform-neutral `PublicEngineRunPlan`: SS, Trojan, VLESS, VMess,
  Hysteria2, and TUIC route to sing-box while `mierus://` routes to engine-mieru.
  Linux `run-url` and `run-catalog` now require explicit Mieru binary/digest,
  atomically render config, apply/start, verify official status, and verify its
  loopback listener. Explicit Linux `core start mieru` follows the same
  status/listener order and stops Mieru on failed readback.
  Windows NodeCatalog import uses the same routing plan and an already enabled
  managed Mieru configuration. Failures are redacted, stable, and retain the
  prior configured core.
```

### Changed

- 版本号统一为 `0.2.0`，为 v0.2.0 正式版做准备：工作区 `Cargo.toml`（及 `Cargo.lock` 中的工作区成员）、Windows/Linux 图形客户端的 `tauri.conf.json`、共用界面 `package.json`，以及 iOS/macOS 的 `MARKETING_VERSION`。命令行 `version` 输出和脚本环境字符串随之变为 `0.2.0`。
- `config-core` now parses optional `rules` and `policy_groups` fields into a
  routing model (DOMAIN/DOMAIN-SUFFIX/IP-CIDR/GEOIP/FINAL rules and
  select/url-test/fallback groups), and `engine-singbox` can translate it to a
  sing-box route section. In `v0.2.0-beta.5` no Windows or Linux client uses
  it: a config that sets these fields is accepted, but its rules and groups are
  ignored at runtime. Configs without them behave as before.
- CI validation jobs now restore Rust build caches (registry, git deps, and
  `target/`) and pnpm store caches, and `cargo-audit` installs from a prebuilt
  binary instead of compiling from source on every run. Rust validation jobs
  also set `CARGO_INCREMENTAL=0`. Release workflows are unchanged. The cache policy is recorded in `docs/ci-cd-policy.md` under
  "CI 缓存策略".
- Windows HTTPS MITM now offers an opt-in first-party Bilibili web promotional
  request-blocking trial. It is disabled by default, uses no third-party script
  runtime or response-body rewriting, and records only its fixed policy ID in
  the native MITM startup log. The trial is limited to four independent
  promotional endpoints; HTTP/2, HTTP/3/QUIC, streaming, and full page/video
  ad filtering remain unsupported.

- Linux sandboxed native MITM scripts now pass a fixed 64 MiB V8 old-space cap
  in addition to the existing bounded body and execution timeout limits.

- Linux native MITM scripts now run only in a fresh no-network namespace with
  Node read permission limited to the explicit runner, mapped asset, and staged
  body. Persistent stores and write, child-process, addon, and network access
  are denied; Windows GUI/service reject script execution until an equivalent
  Windows sandbox is available.

- Manual intervention now requires Ubuntu/systemd trust-file lifecycle, bounded
  HTTP/1.1 rewrite, pinning fail-closed, HTTP/2/HTTP/3 exclusion, and local
  script-hash drift evidence before HTTPS MITM is described as operational.

- Linux MITM HTTP rewrite reports now explicitly mark certificate/public-key
  pinning bypass, HTTP/2 MITM, and HTTP/3/QUIC MITM unsupported. These states
  are machine-readable fields and blocked operations; NetworkCore does not
  claim to bypass them.

- The shared native HTTPS MITM Node executor now records a SHA-256 digest for
  every explicitly mapped local script asset at creation and rechecks it before
  each dispatch. Missing, symbolic-link, unreadable, or changed assets remain
  fail-open and never start the Node runner.

- Linux MITM CA artifact creation now writes its private key with Unix `0600`
  permissions at creation time, syncs and reads the mode back before use, and
  removes it when the protected write cannot be verified.
  Explicit Linux TLS MITM start also rejects symbolic links, non-regular keys,
  and key modes other than `0600` before reading private material.

- Windows HTTPS MITM now protects the fixed NetworkCore-owned CA private key
  before committing managed configuration. It rejects reparse paths and ACL
  readback mismatches, revalidates the exact DACL before trust installation and
  during managed runtime health checks, removes the private key on protection failure,
  reports failed certificate or private-key cleanup only after restoring a stopped
  service, revokes the managed CA when a later ACL drift is found, and leaves only
  the generating account plus LocalSystem access with inherited ACL entries removed.

- Windows `Connected` now requires independent SCM, `sing-box check -c`,
  loopback listener, generated selector active-outbound/default readback,
  service-owned PID, and exact current-user proxy evidence. The Service repeats
  bounded listener and selector health checks while running; a failed check
  records the managed failure and follows the existing proxy rollback/stop
  path. This is pending manual Windows/Linux acceptance before the formal
  `v0.2.0-beta.5` tag.

- Windows HTTPS MITM private-key ACL protection now reuses the managed MITM
  directory resolved by the Rust host instead of independently requiring a
  PowerShell `CommonApplicationData` value. The fixed-path, reparse-point,
  owner, and exact ACL checks remain fail-closed.

- Windows profile import now stages a sing-box plan transactionally: it clears
  the mutually exclusive Mieru plan before managed-config commit, and restores
  the prior sing-box JSON if that commit fails. The platform-level double-core
  rejection remains the boundary for externally supplied configuration.

- Windows GUI runtime status now evaluates the selected core. Mieru reaches
  `Connected` only from Service-verified official status plus its exact SOCKS5
  listener and the existing SCM/current-user proxy evidence; it neither
  fabricates a PID nor requires sing-box's selector API.

- 完成 Windows 单 HTTP(S) subscription refresh 状态闭环：GUI 显式启用 hourly refresh 后，持久记录脱敏
  `last_attempt`、`last_success`、`next_attempt`、`result`、节点新增/删除/变化数量与稳定 `error_code`，并在
  Subscriptions 页展示当前状态。手动导入、选择 source 和后台触发共享排他 operation guard；失败保留既有
  config、节点选择和运行配置，错误文本不回显 URL、token 或凭据，也不重启核心或切换节点。

- 完成 Linux managed foreground control socket reload slice：`reload --managed-control-socket <absolute-path> --confirm`
  复用显式路径、owner-only `0600`、两秒 I/O 上限和当前前台进程，成功后调用
  `RuntimeOrchestrator::reload_runtime` 并恢复 lifecycle wait；reload 失败会释放当前 runtime 并让 managed
  recording 进入 `failed`。`managed-status rollback` 仍是显式文件快照恢复，未引入默认 socket、PID/status 或后台控制。
- 完成 Linux managed foreground control socket stop slice：显式 managed `start` 可创建不覆盖已有路径的
  owner-only `0600` Unix socket，`stop --managed-control-socket <absolute-path> --confirm` 通过 bounded
  `stop`/`accepted` 协议进入既有 interruption、runtime release 和 `running -> stopped` 记录路径；默认
  socket、PID fallback、reload、status 与非 Unix fallback 保持 blocked。
- 完成 Linux managed foreground lifecycle recording slice：`start` 在同时提供
  `--managed-status`、`--managed-snapshot` 和 `--managed-events` 时写入 `starting`/`running`/`stopped`/`failed`
  status、非覆盖 snapshot 与 schema version 1 lifecycle events；默认未提供路径时保持 foreground-only 行为，
  记录不声称 PID、端口或 control socket liveness。
- 完成 Linux controlled CONNECT persistent HTTP/1.1 slice：同一 downstream/upstream TLS session 最多
  处理 4 次有界 request/response exchange，保留 keep-alive framing，并在 `Connection: close`、HTTP/1.0
  默认关闭、terminal rewrite、解析失败或预算耗尽时结束；普通明文代理的既有 close 行为不变。
- 完成 Linux persistent subscription catalog 的显式 `subscription update` 纵向切片：HTTP(S)、绝对
  `file://` 和 inline/share-link 候选先经受限 fetch 与 `CoreSubscriptionService` parse/normalize，成功后
  才写不可覆盖 rollback snapshot 和新 location；失败保留旧 catalog，report 只输出脱敏字段、验证节点数及新增/删除/改变节点数量。
- 新增 Linux `node switch` 运行时切片：对 NetworkCore 生成的 loopback sing-box selector 执行显式
  PATCH/readback，写 selection snapshot，并在 selection 写入失败时尝试恢复此前 outbound；非回环
  controller、native JSON、缺少授权和已有 snapshot 均拒绝。
- 新增 Linux `node list` 结构化 NodeCatalog 输出：显式 config-core 解析结果同时进入脱敏 text/JSON
  `node_catalog`，输出稳定节点 id、名称、协议和 tags，并固定只读、无 snapshot、无 endpoint/credential
  泄漏边界；选择和 rollback 不被该命令隐式触发。
- 新增 Linux `node health` loopback selector 证据入口：显式端口执行一次 adapter GET/readback，报告
  当前 outbound、selector tag 和 outbound 数量；只确认 selector readback，不宣称完整代理健康，不修改
  selection 或写 snapshot。

- Linux CLI now exposes explicit Ubuntu-style CA trust-file apply and rollback
  commands with confirmation, snapshot verification, refresh, recovery, and
  external-change conflict protection. Default trust-store discovery, NSS,
  p11-kit, and browser-profile trust mutation remain blocked.

- Linux CLI now exposes `core list` and an explicit local Mieru verification
  command, `core install mieru --binary <path> --sha256 <digest>`. The command
  verifies the operator-provided executable and reports its digest without
  downloading, spawning, or installing a service; Mieru runtime wiring and
  system proxy mutation remain deferred.

- Linux `run-catalog <catalog-path> <source-id>` now resolves one saved
  catalog source into the existing foreground sing-box path. It supports the
  same explicit inline, file, and HTTP(S) inputs as `run-url`, without exposing
  source locations, modifying the catalog, or enabling refresh/background
  runtime behavior.
- Linux `run-url` now accepts `--node-id <id>` to select one normalized
  subscription catalog node for its foreground sing-box invocation. Omission
  retains the first supported-node selection; this does not add persistence or
  runtime node switching.
- Linux `run-url` now accepts an explicitly requested HTTP(S) subscription.
  The foreground request uses a 15-second timeout, five redirect limit,
  successful-response requirement, and 1 MiB UTF-8 response limit before using
  the existing parser and sing-box path. It does not enable background refresh
  or persistent remote subscription state.
- Linux `run-url` now accepts a caller-selected absolute `file://` URI. Its
  UTF-8 contents use the existing subscription parser and foreground sing-box
  path; remote fetching, path discovery, and background refresh remain absent.
- Linux `managed-log` reports now include `returned_byte_count` in text and JSON,
  counting the UTF-8 bytes of returned line contents while excluding discarded
  content and line separators. The explicit-path, 65536-byte file limit,
  bounded-line, and `liveness_verified=false` boundaries are unchanged.
- Linux CLI now exposes `core status mieru --binary <path> --sha256 <digest> --config <path>`
  and routes Mieru start/stop/status through the library entrypoints. Status verifies the
  caller-supplied executable and invokes only the official client's explicit status command;
  it does not claim listener readiness or mutate the system proxy.
- `NativeProxyEngineService::reload` now performs an in-process runtime
  replacement instead of returning an unwired lifecycle error. It retains the
  last successful configuration, restores it when the replacement listener
  cannot start, and reports stable reload/rollback diagnostics without adding a
  daemon or cross-process control protocol.
- Linux CLI now includes an explicit read-only managed foreground log slice:
  `CommandManagedForegroundSessionLogStore::read_tail` and
  `networkcore-linux managed-log <log-file-path> [--tail-lines <1-1000>]`
  read only one caller-selected UTF-8 regular file, cap input at 65536 bytes,
  return a bounded tail report, and keep `liveness_verified=false`. The command
  does not create default paths, search logs, stream live output, or control a
  runtime.
- Windows managed configuration schema 2 introduces an explicit system-proxy
  owner. Existing schema 1 files migrate in memory to `service`, preserving
  CLI/service behavior; GUI profile imports use `desktop`, making the
  interactive session the sole owner of its current-user proxy snapshot.
- Windows GUI connection status now requires the observed current-user proxy
  server and bypass to exactly match the active managed profile, not merely an
  enabled proxy flag.
- The Windows GUI now restores the last successfully generated NodeCatalog
  after restart without re-fetching a local or HTTP(S) subscription, but only
  when the current managed sing-box JSON has the saved exact SHA-256 and its
  loopback selector still has the saved ordered outbound tags. Native JSON and
  externally changed configs stay unhydrated instead of showing stale nodes.
- A successful generated-profile node switch now updates the generated
  sing-box selector's startup default atomically after Clash API readback, so
  the selected node remains active across a service restart. If that config
  commit fails, the GUI requests a rollback to the previously observed active
  outbound and leaves its saved node selection unchanged.
- The Windows GUI now permits one instance per current Windows session. A
  second launch restores the existing tray-hidden window instead of creating a
  competing GUI that could issue duplicate service or proxy operations.
- The Windows GUI now re-adds its notification-area icon when Explorer rebuilds
  the taskbar, including a primary-display DPI rebuild, and refreshes the icon
  from the same runtime state used by the visible window.
- A login-startup launch now registers the shared tray icon and stays hidden
  until the user opens it, avoiding a main-window interruption after sign-in.

### Fixed

- Windows 客户端导入订阅一律走内置引擎：rc.1 里一旦用过设置页的“安装内核”，之后导入就改走 sing-box，内置引擎的分流模式、订阅规则和策略组都不生效。现在装了 sing-box 也先用内置引擎导入，只有 sing-box 原生 JSON 配置和内置引擎一个节点都跑不了的订阅才交给 sing-box。设置页去掉“安装内核”主按钮和“安装并校验内核后再导入配置”的旧文案，改为可选的“兼容内核”卡片（目前只有 HTTPS 解密依赖它）。
- The Linux managed foreground control socket now sets each accepted
  connection back to blocking before its bounded read. On BSD-derived kernels
  such as macOS the accepted socket inherited the listener's non-blocking mode,
  so a request that arrived after `accept` was rejected as unreadable.
- GUI connect now waits in its background task for SCM, the live sing-box PID,
  the configured loopback listener, and the generated NodeCatalog selector API
  before changing the current-user proxy. The proxy snapshot is atomically
  persisted before a successful connection is reported; persistence failure
  restores the proxy and stops the service.
- The Windows service now assigns its sing-box child to a private Windows Job
  Object with kill-on-close semantics. An unexpected Service-process exit
  therefore terminates that owned core instead of leaving its listener behind
  for the next managed start.
- Removed the legacy direct `Enable proxy` controls that bypassed readiness
  checks. `Restore network settings` remains available for a GUI-owned
  snapshot, and a partial Windows proxy write now attempts to restore its
  captured pre-change settings before reporting the failure.
- A profile import now updates GUI desktop state only after managed config
  persistence succeeds. If that persistence fails after the generated
  `config.json` write, the prior managed sing-box config is restored; a failed
  subscription update therefore retains its prior usable profile.
- Interrupted GUI-owned proxy recovery is now attempted once per connection
  cycle. A failed attempt remains visible with explicit restore and diagnostics
  actions instead of being retried by each periodic status refresh.
- Advanced `Restart service` now performs the same preflight and readiness
  checks as daily Connect for a desktop-owned profile. It restores the
  GUI-owned proxy before stopping the core and reapplies it only after the
  restarted service, core, listener, and generated selector are ready.

## v0.2.0-alpha.21 - 2026-07-24

### Added

- Windows GUI now has a system tray with shared real runtime status, node,
  connect/disconnect, refresh, restore-window, and safe-exit actions. Closing
  the main window hides it; explicit exit restores a proxy snapshot only while
  the current setting still exactly matches this GUI session, then stops the
  service before the process ends.
- Settings now controls current-user Windows login startup, auto-connect, and
  one controlled core restart. The Run entry quotes the resolved GUI path,
  refuses conflicting ownership, and MSI uninstall invokes the restricted GUI
  cleanup path; portable packages support the same opt-in setting without
  creating it on extraction.

### Changed

- Windows GUI daily usability has been reorganized into Home, Nodes,
  Subscriptions, Settings, Diagnostics, and Advanced. Runtime connection state
  now combines SCM, service-owned sing-box PID, and current interactive-user
  proxy observations rather than trusting managed JSON or desktop state.
- Service/core/profile/node/delay operations use a single background command
  dispatcher with duplicate-operation protection. Failed HTTP(S) subscription
  updates persist their error while retaining the previous managed profile.

### Fixed

- Windows service now supervises its owned sing-box process after SCM startup.
  An unexpected exit records a durable failed transition and error, rolls back
  runtime resources including the service-owned proxy snapshot, and returns SCM
  to `Stopped` instead of leaving a dead loopback proxy enabled.
- Windows GUI `Start` and `Restart` no longer apply managed system-proxy
  settings before the SCM request. The service remains the single owner of the
  managed runtime proxy snapshot, so an asynchronous core startup failure rolls
  back the actual pre-service settings instead of a GUI-preapplied proxy.
- Windows service startup now completes the SCM `Running` handshake before
  applying managed runtime configuration. GUI/CLI `start` returns the immediate
  observed SCM state instead of waiting up to 30 seconds for runtime readiness;
  invalid configuration is logged and returns the service to `Stopped`. The
  Windows CI smoke test covers this regression path.

### Added
- Linux managed foreground event history now has an explicit bounded audit query:
  `CommandManagedForegroundSessionEventStore::list_event_history` and
  `networkcore-linux managed-event list <event-directory> [--session-id <id>]
  [--event-kind <kind>] [--state <state>] [--cursor <offset>] [--limit <1-100>]`.
  It validates direct regular JSON records before exact filtering, sorts by
  `(recorded_at, event_id, event_path)`, returns offset pages, and caps page,
  directory, and record sizes at 100, 256, and 65536 bytes. It remains an
  explicit read-only history interface, not a liveness check, runtime event
  stream, daemon, or control surface.
- Windows GUI now exposes `Check core` for generated NodeCatalog profiles. It
  makes one read-only loopback Clash API selector request, displays the active
  outbound plus node count, and records the result in the local GUI log. It does
  not persist a node choice, switch the selector, alter managed configuration,
  or change the service lifecycle; native pass-through sing-box JSON remains
  outside this generated selector control surface.
- Windows GUI now exposes an editable HTTPS `Delay URL` and `Test delay` action
  for the selected generated sing-box outbound. It makes one loopback Clash API
  `/proxies/{tag}/delay` request with a 10-second timeout, displays the returned
  milliseconds, and records the action in the local GUI log. It does not change
  the active selector, managed config, or service lifecycle, and does not add
  `urltest`, automatic latency selection, or background measurement.
- NodeCatalog-based Windows profile imports now retain every translatable node
  behind a generated sing-box `selector`. The GUI can explicitly switch the
  active node through a `127.0.0.1:9091` Clash API controller and confirms the
  selected outbound after the switch. Native sing-box JSON remains pass-through;
  no LAN controller, Web UI, `urltest`, automatic latency selection, background
  refresh, or automatic service restart is enabled.
- Windows GUI now exposes `Load nodes` for local profiles and explicit HTTP(S)
  subscription URLs. It shows parsed NodeCatalog names and stable IDs in the
  profile selector without changing managed configuration; import persists the
  selected node. Native sing-box JSON remains pass-through.
- Windows GUI now provides `Update URL` for a successful HTTP(S) `Profile / URL`
  import. It explicitly refetches only that saved URL through the existing
  parser/native JSON pipeline; a failed update retains the current configuration
  and does not trigger a background refresh or service restart.
- Windows GUI `Profile / URL` now accepts an operator-entered HTTP(S)
  subscription URL as well as a local file. Import downloads that payload only
  for the explicit action and reuses the native sing-box JSON/NodeCatalog
  pipeline. It does not add background refresh, subscription catalog/group,
  remote route/rule fetch, or automatic service restart.
- Windows GUI now exposes `Open JSON`, a non-mutating `Validate` action, and
  `Diagnostics`. Validation uses the same managed JSON parsing and
  `sing-box check -c` preflight as the service without starting it or changing
  system state. Diagnostics writes a local status/log-tail report; failed GUI
  actions create the same report and surface its path. GUI debug activity and
  explicit sing-box core debug configuration are now documented separately.
- V2Ray share-link compatibility subset: operator-selected Windows local
  `trojan://`, `vless://`, and `vmess://` profiles, plus catalog-imported
  sing-box outbounds, now retain the explicit TLS, REALITY, uTLS, VLESS Vision,
  VMess security/alter-id, and WebSocket/gRPC/HTTP/HTTPUpgrade/V2Ray QUIC
  fields supported by the managed sing-box renderer. This does not infer
  arbitrary XHTTP/ECH/multiplex transport fields and does not enable HTTP/3
  MITM.
- Hysteria2/TUIC share-link parser gate: operator-selected Windows local profiles
  may now import `hysteria2://`/`hy2://` and `tuic://` nodes, including the
  documented credential, TLS, Hysteria2 port-hopping/obfuscation, and TUIC
  congestion-control fields. The sing-box adapter renders only those retained
  fields into direct QUIC proxy outbounds; this does not enable HTTP/3 MITM.
- Native sing-box JSON catalog import now recognizes Hysteria2 and TUIC
  outbounds. Direct native JSON GUI import remains pass-through and is never
  rewritten by this catalog conversion path.
- Windows GUI can explicitly install the official sing-box Windows core through
  the existing release/digest/extraction adapter, then persist the executable
  path under `%ProgramData%\\AnixOps\\NetworkCore` for the managed service.
- Windows GUI can explicitly import an operator-selected local profile file,
  select a node, render its managed sing-box JSON, and configure the service
  owned core plus `127.0.0.1:7890` system proxy.
- The sing-box adapter renders basic Shadowsocks plus the documented
  Trojan/VLESS/VMess TLS and transport compatibility subset.
- Windows GUI can explicitly enable a service-owned HTTPS MITM path. It
  generates a local CA, moves sing-box to `127.0.0.1:7891` as a SOCKS upstream,
  starts the native HTTP listener on `127.0.0.1:7890`, and installs/removes the
  matching LocalMachine ROOT certificate through the managed lifecycle.
- Windows capability/status output now exposes active controlled HTTPS MITM;
  the service contract test owns the native listener lifecycle and CA trust
  action.
- Windows GUI now detects an operator-selected native sing-box JSON document,
  copies it unchanged into the managed service config, and discovers a local
  `mixed` or `http` inbound for the system proxy. This preserves sing-box-owned
  TLS/REALITY/WebSocket/gRPC/multiplex/routing/DNS fields instead of reducing
  them to the basic node renderer.
- Windows GUI now has an `Open core log` action for the managed sing-box
  `check -c` and runtime stdout/stderr log.
- Native sing-box JSON with an explicit `type: mixed`, `tag: mixed-in` inbound
  can now enter the GUI HTTPS MITM lifecycle. The original JSON is snapshotted
  before only that listener is moved to `127.0.0.1:7891`, then restored when
  HTTPS MITM is disabled.

### Changed

- Windows documentation and release readiness contract now distinguish the
  explicit GUI core install/profile import path from the MSI's non-bundled,
  non-silent third-party-core boundary. Remote subscription fetch,
  XHTTP/ECH/multiplex transport inference, JavaScript dispatch, HTTP/2,
  HTTP/3/QUIC MITM, streaming, and multi-request CONNECT remain unavailable.
- Native sing-box JSON remains pass-through for normal import. The only GUI
  MITM mutation is a documented, reversible rewrite of a native
  `type: mixed`, `tag: mixed-in` listener.

## v0.2.0-alpha.3 - 2026-07-23

### Fixed

- Windows MSI no longer waits for `AnixOpsNetworkCore` to reach `Running` during
  installation. The service start request remains automatic but asynchronous;
  stop and uninstall still wait before `purge` runs.

### Added

- Every Windows tag release now includes an independent portable ZIP containing
  the GUI, service, CLI, inert managed configuration, and portable instructions,
  plus its SHA-256, manifest, manifest SHA-256, and GitHub artifact attestation.
- GitHub Actions now performs bounded silent MSI install/uninstall smoke in the
  Windows validation job, including SCM registration and removal checks.

## v0.2.0-alpha.2 - 2026-07-23

### Added

- Windows managed client follow-up: MSI now uses the WiX standard install-directory
  wizard and completion page; GUI/service diagnostics are persisted under
  `%ProgramData%\\AnixOps\\NetworkCore\\logs`, with GUI debug toggle and
  `networkcore-windows-gui.exe --debug` entrypoint.
- Installer documentation now includes the inert default configuration and a
  minimal system-proxy JSON example, including the required absolute-path rules.
- 开始把 Windows managed client 的 sing-box 支持从 capability 描述推进到真实进程生命周期：新增 `managed-config.json` 的 `sing_box` block，服务启动前执行 `sing-box check -c`，再托管 `sing-box run -c`，持久化 PID/exit code，并将 stdout/stderr 写入显式 core log；adapter 已支持官方 Windows ZIP 中 `sing-box.exe` 的 digest 校验和安全提取。当前 MSI 仍要求操作员显式配置或安装经过验证的 `sing-box.exe`，core install orchestration、订阅 runnable path、MITM data plane 和 reload 继续推进。验证仍只通过 GitHub Actions。

- 固定 `mitm_anixops` distribution release `v1.4.6` 的 source commit `6382f0147e02a8653343571791ef61b8cc885cb1`，保留 linked C core version `0.45.10`，并新增纯 `ManagedSdwanMitmPolicyGate`。它只接收 verifier 产生的不可变 Plan B client delivery capability，公开构造只快照 linked C core，并在每次授权时以调用方提供的受信任当前时钟重新检查 expiry；V1 capability query、client/profile coherence、exact DNS suffix boundary、用户 consent、trusted certificate、非 QUIC 和无 pinned TLS observation 条件全部满足时返回非秘密 admission grant；不启动代理、不连接 POP、不执行脚本、不安装或信任 CA、不改变主机状态。GitHub Actions 覆盖 ABI、拒绝、expiry 和无 payload 泄漏合同。
- 完成 `v0.1.2-alpha.2` managed foreground status `rollback_status` 源切片：新增 `ManagedForegroundSessionStatusRollbackRequest`、`ManagedForegroundSessionStatusRollbackReport` 和 `CommandManagedForegroundSessionStore::rollback_status`，仅在显式 status/snapshot 路径不同、current state 匹配 expected state 且 snapshot session/engine identity 匹配时，将 snapshot 原始 JSON 写回 status record 并保留 snapshot；report 固定 previous/restored state、`snapshot_retained=true` 与 `liveness_verified=false`。stale state 返回 state-conflict，snapshot 无法读取或解析返回 snapshot-read-failed，不控制 runtime；合同测试已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.2` managed foreground status rollback CLI 切片：新增 `LinuxCliCommand::ManagedStatusRollback`、`networkcore-linux managed-status rollback <status-record-path> <snapshot-path> <expected-state>`、`handle_managed_foreground_status_rollback` 和 `managed_foreground_session_status_cli_rolls_back_matching_snapshot` 合同测试，调用同一 expected-state/identity-protected snapshot restore，输出 text/JSON previous/restored state、`snapshot_retained=true` 与 `liveness_verified=false`；stale expected state 保留 state-conflict 且不修改 record 或 snapshot，不检查 live process 或控制 runtime；合同测试已通过 GitHub Actions 全量 CI。

## v0.2.0-alpha.1 - 2026-07-23

### Added

- 发布 Windows managed client：原生 Win32 GUI、SCM service host、schema-versioned ProgramData 配置/状态、signed INF driver package lifecycle、WinINet/WinHTTP system proxy apply/restore、CryptoAPI LocalMachine ROOT certificate apply/remove，以及 WiX 4.0.6 per-machine MSI。
- GitHub Actions 新增 Windows GNU 构建、MSI/WiX validation、checksum、schema-version-2 manifest 和 artifact attestation；GitHub Release 上传 Linux CLI 四件套和 Windows managed-client MSI 四件套。
- Windows service 在 stop/purge 路径执行托管 apply/rollback；JavaScript script dispatch、Windows subscription runnable path 和远程订阅拉取仍不在本版本范围内。
- 历史 `v0.1.1-alpha.2` manual-extract Windows CLI ZIP 保留为审计记录，不再作为当前安装入口。

## v0.1.2-alpha.3 - 2026-07-10

### Added

- 发布 `v0.1.2-alpha.3` 的真实 TLS/session 实现：`engine-native` 在 controlled TLS
  termination plan ready、CONNECT authority/SNI 一致且 CA PEM 可解析时签发 authority-bound、server-auth
  EKU leaf，并建立固定 TLS 1.2/1.3 rustls downstream server 与 web-PKI-verified upstream client；显式
  CA material 沿 engine → accept loop → CONNECT path 传递，在 bounded HTTP/1.1 request/response 上执行
  live rewrite hook。Linux CLI 只有 `start --enable-https-mitm --mitm-ca-cert --mitm-ca-key --confirm` 才
  读取 material，默认保持 pass-through，私钥不进入 `Debug`。
- 同一运行时现接入本地 Node script executor：`NativeNodeScriptExecutor` 只执行显式
  `--script-map <script-url>=<local-file>` 映射的 local asset，要求
  `--enable-script-runtime --script-runner <local-runner> --confirm`；它限制 UTF-8 body、大小、超时、
  headers/status output 和 URL authority，未映射、超时、失败或无效 output 均 fail-open。新增 hook-level
  contract，确认插件 `HttpMitmScriptDispatch` 的输出会写回真实 rewrite report；不下载远程脚本，也不把
  受信本地 Node process 描述为 sandbox。
- Rust CI matrix 现固定 Node 22 并 checkout pinned `mitm_anixops` submodule，以运行 TLS live-socket 和
  local runner 合同；`Cargo.lock`、CI/release `--locked` 规则仍是发行的前置条件。上述内容只有同 commit
  GitHub Actions 全量通过后才可进入后续 alpha 发行，未声称当前本地环境已完成验证。
- 固定可复现发布依赖：`Cargo.lock` 现在受版本控制，CI 的 clippy/test/build 和 tag-release artifact
  build 均使用 `--locked`；dependency audit 先以 `cargo metadata --locked --offline` 验证已提交 lockfile，
  再执行 `cargo audit`；release workflow 不再临时生成 lockfile。该门禁必须由 GitHub Actions 验证后才能进入发行。
- 完成 `v0.1.2-alpha.3` TLS CONNECT authority/SNI hardening：
  `plan_explicit_http_connect_controlled_tls_termination` 现在要求 observed
  ClientHello SNI 与 CONNECT authority 一致，才可报告 controlled downstream
  TLS termination plan ready；不一致或缺失 SNI 必须保持 deferred 并输出稳定
  diagnostics。合同测试和 CI governance anchor 已加入，并已由同 commit GitHub Actions
  全量 CI 验证。
- 完成 `v0.1.2-alpha.1` persistent subscription catalog 首个 source-only 切片：新增 `SubscriptionCatalogAddRequest`、`SubscriptionCatalogAddReport` 和 `CommandSubscriptionCatalogStore::add_source`，使用显式 catalog/snapshot 路径写入 schema version 1 本地 JSON catalog，生成写前 rollback snapshot，拒绝重复 source id，并以 `location_kind`/`location_redacted` 输出脱敏报告；合同测试覆盖 source 持久化、snapshot、secret location 不进入 report 和 duplicate 不覆盖。该增量不执行默认路径扫描、远程/file fetch、节点选择、运行时接入或 managed lifecycle，已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.1` persistent subscription catalog 第二个 source-only `list` 切片：新增 `SubscriptionCatalogListRequest`、`SubscriptionCatalogListEntry`、`SubscriptionCatalogListReport` 和 `CommandSubscriptionCatalogStore::list_sources`，显式读取 schema version 1 本地 JSON catalog，输出 source 数量与脱敏 location kind，不修改 catalog、不执行默认路径扫描、远程/file fetch、节点选择、运行时接入或 managed lifecycle；合同测试已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.1` persistent subscription catalog 第三个 source-only `remove` 切片：新增 `SubscriptionCatalogRemoveRequest`、`SubscriptionCatalogRemoveReport` 和 `CommandSubscriptionCatalogStore::remove_source`，在显式 catalog 中删除 source id，生成写前 snapshot，拒绝不存在的 source id，并输出不含 location 的 report；合同测试已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.1` persistent subscription catalog 第四个 source-only `select` 切片：新增 `SubscriptionCatalogSelectRequest`、`SubscriptionCatalogSelectReport` 和 `CommandSubscriptionCatalogStore::select_source`，从显式 catalog 读取匹配 source id，拒绝不存在的 source id，并输出不含 location 的脱敏 report；合同测试已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.1` persistent subscription catalog 第五个 source-only `update` 切片：新增 `SubscriptionCatalogUpdateRequest`、`SubscriptionCatalogUpdateReport` 和 `CommandSubscriptionCatalogStore::update_source`，更新显式 catalog 中已有 source 的 location，保持 source id，生成写前 snapshot，拒绝不存在的 source id，并输出不含 location 的脱敏 report；合同测试已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.1` persistent subscription catalog 第六个 source-only `rollback` 切片：新增 `SubscriptionCatalogRollbackRequest`、`SubscriptionCatalogRollbackReport` 和 `CommandSubscriptionCatalogStore::rollback_catalog`，将显式指定且已校验的 snapshot 原始 JSON 复原到 catalog，并保留 snapshot；snapshot 缺失或无效时拒绝修改 catalog，report 不含 location；合同测试已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.2` managed foreground status 首个 source-only `read_status` 切片：新增 `ManagedForegroundSessionStatusRequest`、`ManagedForegroundSessionStatusReport` 和 `CommandManagedForegroundSessionStore::read_status`，从显式 schema version 1 JSON record 读取 session id、engine id 和 recorded state，并固定 `liveness_verified=false`；它不验证 live process、不写 record、不接入 CLI 或 runtime control，合同测试已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.2` managed foreground status 第二个 source-only `write_status` 切片：新增 `ManagedForegroundSessionStatusWriteRequest`、`ManagedForegroundSessionStatusWriteReport` 和 `CommandManagedForegroundSessionStore::write_status`，非覆盖写入显式 schema version 1 JSON record，固定 `record_written=true` 与 `liveness_verified=false`；目标路径已存在时拒绝覆盖，不验证 live process、不接入 CLI 或 runtime control，合同测试已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.2` managed foreground status 第三个 source-only `transition_status` 切片：新增 `ManagedForegroundSessionStatusTransitionRequest`、`ManagedForegroundSessionStatusTransitionReport` 和 `CommandManagedForegroundSessionStore::transition_status`，只有 expected state 与显式 schema version 1 JSON record 匹配时才保留原始 record snapshot 并迁移状态；仅允许 `starting -> running/failed` 与 `running -> stopped/failed`，固定 `snapshot_written=true` 与 `liveness_verified=false`；stale expected state 或已存在 snapshot 时拒绝修改 status record，不验证 live process、不接入 CLI 或 runtime control，合同测试已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.2` managed foreground status 第四个只读 CLI 切片：新增 `LinuxCliCommand::ManagedStatus`、`networkcore-linux managed-status <status-record-path>` 和 `handle_managed_foreground_status`，从显式 schema version 1 JSON record 输出 text/JSON recorded state 与 `liveness_verified=false`；record 缺失保留 read-failed 错误，查询不修改 record、不创建 snapshot、不验证 live process，也不接入 CLI 写入/迁移或 runtime control，合同测试已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.2` managed foreground status 第五个 CLI 初始写入切片：新增 `LinuxCliCommand::ManagedStatusInit`、`networkcore-linux managed-status init <status-record-path> <session-id> <engine-id> <state>` 和 `handle_managed_foreground_status_init`，调用 `CommandManagedForegroundSessionStore::write_status` 非覆盖创建显式 schema version 1 JSON record，并输出 text/JSON `record_written=true` 与 `liveness_verified=false`；目标 record 已存在时保留 write-failed 错误且不覆盖原内容，不验证 live process，也不接入 CLI 状态迁移或 runtime control，合同测试已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.2` managed foreground status 第六个 CLI 状态迁移切片：新增 `LinuxCliCommand::ManagedStatusTransition`、`networkcore-linux managed-status transition <status-record-path> <snapshot-path> <expected-state> <next-state>` 和 `handle_managed_foreground_status_transition`，调用 `CommandManagedForegroundSessionStore::transition_status` 执行 expected-state 保护的显式 schema version 1 JSON record 迁移，并输出 text/JSON previous/next state、`snapshot_written=true` 与 `liveness_verified=false`；它只允许 `starting -> running/failed` 与 `running -> stopped/failed`，stale expected state 保留 state-conflict 错误且不修改 record 或创建 snapshot，不验证 live process，也不接入 runtime control，合同测试已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.2` managed foreground event 首个 source-only `read_event` 切片：新增 `ManagedForegroundSessionEventRequest`、`ManagedForegroundSessionEventReport` 和 `CommandManagedForegroundSessionEventStore::read_event`，从显式 schema version 1 JSON record 读取 session/engine/event 标识、允许的 event kind、recorded state 与 recorded_at，固定 `liveness_verified=false`；它不写入或扫描 event、不中转日志、不接入 CLI 或 runtime event stream，合同测试已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.2` managed foreground event 第二个只读 CLI 切片：新增 `LinuxCliCommand::ManagedEvent`、`networkcore-linux managed-event <event-record-path>` 和 `handle_managed_foreground_event`，从显式 schema version 1 JSON event record 输出 text/JSON event id、event kind、recorded state、recorded_at 与 `liveness_verified=false`；record 缺失保留 read-failed 错误，查询不写入、删除、列出或扫描 event，不接入 runtime event stream 或 runtime control，合同测试已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.2` managed foreground event 第三个 source-only `write_event` 切片：新增 `ManagedForegroundSessionEventWriteRequest`、`ManagedForegroundSessionEventWriteReport` 和 `CommandManagedForegroundSessionEventStore::write_event`，非覆盖写入显式 schema version 1 JSON event record，固定 `record_written=true` 与 `liveness_verified=false`；目标路径已存在时拒绝覆盖，不验证 live process、不接入 event CLI 写入或 runtime event stream，合同测试已通过 GitHub Actions 全量 CI。
- 完成 `v0.1.2-alpha.2` managed foreground event 第四个 CLI 初始写入切片：新增 `LinuxCliCommand::ManagedEventInit`、`networkcore-linux managed-event init <event-record-path> <session-id> <engine-id> <event-id> <event-kind> <state> <recorded-at>` 和 `handle_managed_foreground_event_init`，调用 `CommandManagedForegroundSessionEventStore::write_event` 非覆盖创建显式 schema version 1 JSON event record，并输出 text/JSON `record_written=true` 与 `liveness_verified=false`；目标 record 已存在时保留 write-failed 错误且不覆盖原内容，不验证 live process，也不接入 event 列表、实时流或 runtime control，合同测试已通过 GitHub Actions 全量 CI。
- 开始 `v0.1.1-alpha.3` 订阅格式扩展：`CoreSubscriptionService` 新增 Trojan/VLESS/VMess URL parser gates、Clash YAML parser gate、sing-box JSON parser gate、Surge proxy line parser gate、Loon proxy line parser gate 和 Quantumult X proxy/server line parser gate，可把 `trojan://password@host:port?...#name`、`vless://uuid@host:port?...#name`、`vmess://base64(json)`、受支持的 Clash `proxies` 子集、sing-box JSON `outbounds` 子集、Surge/Loon `[Proxy]` line 子集以及 Quantumult X `[server_local]` line 子集归一化为 `Protocol::Trojan`/`Protocol::Vless`/`Protocol::Vmess`/`Protocol::Shadowsocks` 等 `SubscriptionDocument`/`NodeCatalog` 节点，并新增合同测试固定 password/uuid/source-format metadata。Clash YAML、sing-box JSON、Surge、Loon 和 Quantumult X 目前仅作为 catalog import gate，分别使用 `NODE_METADATA_SOURCE_FORMAT=clash-yaml`、`NODE_METADATA_SOURCE_FORMAT=sing-box-json`、`NODE_METADATA_SOURCE_FORMAT=surge-proxy-line`、`NODE_METADATA_SOURCE_FORMAT=loon-proxy-line` 和 `NODE_METADATA_SOURCE_FORMAT=quantumult-x-proxy-line` 固定来源；该增量不启用 `run-url` Trojan/VLESS/VMess/Clash/sing-box JSON/Surge/Loon/Quantumult X 运行、节点选择、远程订阅拉取、文件订阅读取、默认路径扫描、daemon/service 或系统代理 mutation。
- 同步 `v0.1.1-alpha.2` 发布后的 source-of-truth：README、ROADMAP、TODO、Release Strategy、Alpha Release Feature Matrix 和 CI policy 现在把 `v0.1.1-alpha.2` 记录为最新 prerelease/tag release，并把下一步推进到 `v0.1.1-alpha.3` 订阅格式扩展；`v0.1.1-alpha.2` 发布 Linux CLI 四件套和 Windows manual-extract CLI zip 四件套，仍不启用 Windows service、driver、installer、system proxy mutation、system trust store mutation、JavaScript script dispatch 或 managed lifecycle。

## v0.1.1-alpha.2 - 2026-07-10

### Added

- 发布 `v0.1.1-alpha.2` Windows CLI package/publish path：新增 `apps/windows-cli`、`platform-windows`、`package-windows`、`attest-windows`、Windows release notes/rollback gate 和 Windows publish eligibility gate；GitHub Actions tag release 生成并发布 `networkcore-windows` manual-extract zip、sha256、manifest 和 manifest sha256，同时继续发布 Linux CLI 四件套。service、driver、installer、system proxy mutation、system trust store mutation、JavaScript script dispatch 和 managed lifecycle 仍 blocked，订阅格式扩展顺延到 `v0.1.1-alpha.3`。

## v0.1.1-alpha.1 - 2026-07-10

### Added

- 新增 `v0.1.1-alpha.1` Windows CLI artifact source/release contract：新增 Windows CLI artifact source release contract，固定 `windows-latest`、`x86_64-pc-windows-gnu`、zip、sha256、manifest、attestation、release notes、rollback 和 signing policy 的后续边界；release workflow 新增 `windows-cli-artifact-readiness` 只输出 contract-only/blocked summary，继续不定义 `package-windows`、不生成 Windows zip、不上传 Windows release asset，不启用 Windows service、driver、installer、system proxy mutation、system trust store mutation 或 JavaScript script dispatch。

- 同步 `v0.1.1-alpha.1` 发布后的 source-of-truth：README、ROADMAP、TODO、Release Strategy、Alpha Release Feature Matrix、CI policy、`mitm-policy` README 和 Linux browser capture source contract 当时把 `v0.1.1-alpha.1` 记录为 prerelease/tag release，并把下一步推进到 `v0.1.1-alpha.2` Windows CLI package/publish path；`v0.1.1-alpha.1` 仍只发布 Linux CLI 四件套和 Windows contract-only/blocked summary。
- 同步 `v0.1.0` 正式发布后的 source-of-truth：README、ROADMAP、TODO、Release Strategy、Alpha Release Feature Matrix、CI policy、Linux CLI README、`mitm-policy` README 和 Linux browser capture source contract 当时把 `v0.1.0` 记录为已发布 Linux artifact，并把下一步推进到 `v0.1.1-alpha.1` Windows CLI artifact source/release contract；`v0.1.1` 仍不包含 HTTPS rewrite、JavaScript script dispatch、system trust store mutation 或 system proxy mutation。
- 同步 `v0.1.0-rc.1` 发布后的 source-of-truth：README、ROADMAP、TODO、Release Strategy、Alpha Release Feature Matrix、CI policy、Linux CLI README、`mitm-policy` README 和 Linux browser capture source contract 现在把 `v0.1.0-rc.1` 记录为最新已发布 Linux artifact，并把后续 `v0.1.0` 切片推进到正式发布候选。
- 同步 `v0.1.0-alpha.20` 发布后的 source-of-truth：README、ROADMAP、TODO、Release Strategy、Alpha Release Feature Matrix、CI policy、Linux CLI README、`mitm-policy` README 和 Linux browser capture source contract 现在把 `v0.1.0-alpha.20` 记录为最新已发布 Linux artifact，并把后续 `v0.1.0` 切片推进到 `v0.1.0-rc.1` 功能冻结候选。
- 同步 `v0.1.0-alpha.19` 发布后的 source-of-truth：README、ROADMAP、TODO、Release Strategy、Alpha Release Feature Matrix、CI policy、Linux CLI README、`mitm-policy` README 和 Linux browser capture source contract 现在把 `v0.1.0-alpha.19` 记录为最新已发布 Linux artifact，并把后续 `v0.1.0` 切片推进到 alpha.20 release hardening。
- 同步 `v0.1.0-alpha.18` 发布后的 source-of-truth：README、ROADMAP、TODO、Release Strategy、Alpha Release Feature Matrix、CI policy、Linux CLI README 和 `mitm-policy` README 现在把 `v0.1.0-alpha.18` 记录为最新已发布 Linux artifact，并把后续 `v0.1.0` 切片推进到 alpha.19 live browser proof hardening 起。

## v0.1.0 - 2026-07-10

### Added

- 发布 Linux-only explicit HTTPS rewrite preview 正式版：包含 Linux CLI tarball、sha256、manifest 和 manifest sha256；保留 alpha.14 到 rc.1 已发布能力边界，包括 explicit HTTP proxy live plain HTTP data plane、TLS MITM readiness、controlled TLS termination plan/report、caller-provided HTTPS request/response rewrite preview、browser traffic proof hardening、traffic-proof text CONNECT authority 输出，以及 rc.1 HTTPS request preview 回归冻结合同。该版本仍不发布 Windows artifact，不执行 live HTTPS decryption、live CONNECT-stream HTTPS rewrite、system trust store mutation、system proxy mutation 或 JavaScript script dispatch。

## v0.1.0-rc.1 - 2026-07-10

### Added

- 新增 `v0.1.0-rc.1` 回归冻结合同：Linux CLI `mitm http-rewrite preview --confirm --url https://... --phase request` 的合同测试现在明确固定 caller-provided HTTPS request preview 只能输出 preview/reject 边界，继续保持 `tls_decryption_ready=false`、`https_response_rewrite_ready=false`、`script_dispatch_ready=false`，并保留 `decrypt-https` 与 `mutate-live-https-traffic` blocked operations。该增量不启用 live TLS decryption、live CONNECT-stream rewrite、system trust store mutation、system proxy mutation 或 JavaScript script dispatch。

## v0.1.0-alpha.20 - 2026-07-10

### Added

- 新增 `v0.1.0-alpha.20` release hardening：`networkcore-linux mitm browser-capture traffic-proof --confirm [--target-url <url>] [--proxy-scheme http|socks5]` 的 text 输出现在显式打印 CONNECT authority，和 JSON/report 中的 `proof_connect_authority` 对齐。新增合同测试 `mitm_browser_capture_traffic_proof_text_output_includes_connect_authority`，并补充 CI governance 与 source contract anchor。该版本仍不写 browser/system proxy，不安装 system PAC，不生成或安装 CA，不证明 HTTPS MITM 或 rewrite 应用。

## v0.1.0-alpha.19 - 2026-07-09

### Added

- 新增 `v0.1.0-alpha.19` proof binding hardening：`networkcore-linux mitm browser-capture traffic-proof --confirm [--target-url <url>] [--proxy-scheme http|socks5]` 现在输出 `proof_connect_authority`，并要求同一 proof log 行同时包含 proof token、计划 proxy URL 和 CONNECT authority；未绑定时返回 `cli.linux.mitm.browser_capture.traffic_proof.binding_mismatch` 和 `binding_mismatch` report status。新增合同测试 `mitm_browser_capture_traffic_proof_requires_bound_proxy_and_connect_authority`。该版本仍不证明 HTTPS 解密、live rewrite、system trust store mutation 或 system proxy mutation。

## v0.1.0-alpha.18 - 2026-07-09

### Added

- 新增 `v0.1.0-alpha.18` HTTPS response rewrite preview：`engine-native` 新增 `NativeHttpsResponseRewritePreviewReport`、`plan_and_apply_https_response_rewrite_preview`、`engine.native.runtime.http_proxy_https_response_rewrite_preview_ready`、`engine.native.runtime.http_proxy_https_response_rewrite_preview_deferred` 和 `engine.native.runtime.http_proxy_https_response_rewrite_script_deferred`，在 controlled TLS termination plan ready 且输入为 response-phase `https://` message 时预览 response header mutation 和通过 content-type/body-size/buffering guard 的 response body mutation；Linux CLI `http_rewrite` report/JSON 新增 `https_response_rewrite_preview_ready`，同时保持 `https_response_rewrite_ready=false`、`script_dispatch_ready=false` 和 `tls_decryption_ready=false`。新增 `explicit_https_response_rewrite_preview_applies_headers_body_and_defers_script` 合同测试。该版本仍不执行 live HTTPS decryption、live CONNECT 后 HTTPS request/response rewrite、完整 live HTTPS response rewrite、CA trust mutation、browser/system proxy mutation 或 JavaScript script dispatch。

## v0.1.0-alpha.17 - 2026-07-09

### Added

- 新增 `v0.1.0-alpha.17` HTTPS request rewrite preview：`engine-native` 新增 `NativeHttpsRequestRewritePreviewReport`、`plan_and_apply_https_request_rewrite_preview`、`engine.native.runtime.http_proxy_https_request_rewrite_preview_ready`、`engine.native.runtime.http_proxy_https_request_rewrite_preview_deferred` 和 `engine.native.runtime.http_proxy_https_request_rewrite_script_deferred`，在 controlled TLS termination plan ready 且输入为 request-phase `https://` message 时预览 reject、redirect 和 request header mutation；Linux CLI `http_rewrite` report/JSON 新增 `https_request_rewrite_preview_ready`、`https_response_rewrite_ready` 和 `script_dispatch_ready`。新增 `explicit_https_request_rewrite_preview_applies_headers_and_defers_body_and_script` 合同测试。该版本仍不执行 live HTTPS decryption、live CONNECT 后 HTTPS request/response rewrite、HTTPS response rewrite、body mutation、CA trust mutation、browser/system proxy mutation 或 JavaScript script dispatch。
- 同步 `v0.1.0-alpha.16` 发布后的 source-of-truth：README、ROADMAP、TODO、Release Strategy、Alpha Release Feature Matrix、CI policy、Linux CLI README 和 `mitm-policy` README 现在把 `v0.1.0-alpha.16` 记录为最新已发布 Linux artifact，并把后续 `v0.1.0` 切片推进到 alpha.17 HTTPS request rewrite preview 起。

## v0.1.0-alpha.16 - 2026-07-09

### Added

- 新增 `v0.1.0-alpha.16` controlled TLS termination plan：`engine-native` 新增 `NativeControlledTlsTerminationPlanReport`、`plan_explicit_http_connect_controlled_tls_termination`、`engine.native.runtime.http_proxy_tls_termination_plan_ready` 和 `engine.native.runtime.http_proxy_tls_termination_deferred`，在 explicit HTTP `CONNECT` tunnel、bounded ClientHello/SNI observation 和 NetworkCore CA certificate/private key PEM material 同时具备时输出 controlled downstream TLS termination plan；`networkcore-linux mitm http-rewrite plan/preview` 的 report/JSON 新增 `controlled_tls_termination_plan_ready`、`downstream_tls_termination_plan_ready` 和 `upstream_tls_forwarding_ready`，同时保持 `tls_decryption_ready=false`；新增 `explicit_http_connect_tls_termination_plan_keeps_rewrite_deferred`、`explicit_http_connect_tls_termination_plan_defers_without_material_or_hello` 和 `mitm_http_rewrite_plan_reports_controlled_tls_termination_plan_without_decryption` 合同测试。该版本仍不执行 live HTTPS decryption、HTTPS request/response rewrite、CA trust mutation、browser/system proxy mutation 或 JavaScript script dispatch。
- 同步 `v0.1.0-alpha.15` 发布后的 source-of-truth：README、ROADMAP、TODO、Release Strategy、Alpha Release Feature Matrix、CI policy、Linux CLI README、`mitm-policy` README 和相关 source contract 现在把 `v0.1.0-alpha.15` 记录为最新已发布 Linux artifact，并把后续 `v0.1.0` 切片推进到 alpha.16 controlled TLS termination foundation 起。

## v0.1.0-alpha.15 - 2026-07-09

### Added

- 新增 `v0.1.0-alpha.15` certificate material step：`networkcore-linux mitm certificate apply --confirm --cert-file <path> --key-file <path> [--profile-trust-file <path>] --snapshot <path>` 现在生成 TLS 可消费 CA certificate PEM、private key PEM，并把 dedicated profile trust artifact 写成同一 CA PEM copy；新增 `cli.linux.mitm.certificate.material.failed` 诊断、`mitm_certificate_apply_writes_tls_usable_ca_pem_without_trust_store_mutation` 合同测试和 store-level profile CA PEM copy/private key material invariant 拒绝测试。该版本仍不安装或信任 CA，不修改 system/browser/profile trust store，不启用 TLS termination、HTTPS decryption、HTTPS request/response rewrite、browser/system proxy mutation 或 JavaScript script dispatch。
- 新增 `v0.1.0-alpha.15` explicit HTTP CONNECT tunnel step：`engine-native` explicit HTTP proxy `CONNECT host:443` 现在可通过既有 SOCKS outbound primitive 建立标准 `HTTP/1.1 200 Connection Established` tunnel、bounded TLS ClientHello/SNI observation 并进行有限双向 relay；新增 `NativeTlsMitmFoundationReport`、`NativeTlsClientHelloObservationReport`、`plan_explicit_http_connect_tls_mitm_foundation`、`observe_explicit_http_connect_tls_client_hello`、`write_http_connect_established_response`、`engine.native.runtime.http_proxy_tls_foundation_ready`、`engine.native.runtime.http_proxy_tls_client_hello_observed` 和 `engine.native.runtime.http_proxy_tls_connect_tunnel_established` 合同锚点。该版本仍不执行 downstream TLS termination、HTTPS decryption、HTTPS request/response rewrite、CA trust mutation、browser/system proxy mutation 或 JavaScript script dispatch。
- 同步 `v0.1.0-alpha.14` 发布后的 source-of-truth：README、ROADMAP、TODO、Release Strategy、Alpha Release Feature Matrix、CI policy、Linux CLI README 和 `mitm-policy` README 现在把 `v0.1.0-alpha.14` 记录为最新已发布 Linux artifact，并把后续 `v0.1.0` 切片推进到 alpha.15 起。

## v0.1.0-alpha.14 - 2026-07-09

### Added

- 新增 `v0.1.0-alpha.14` Linux explicit HTTP proxy live plain HTTP data plane source 增量：`engine-native` 允许 `ListenerKind::Http` loopback listener 解析 bounded HTTP/1.x explicit proxy request，新增 `NativeExplicitHttpProxyRequest`、`NativePlainHttpProxyResponse`、`read_explicit_http_proxy_request`、`apply_http_mitm_outcome_to_live_plain_http_request`、`serialize_explicit_http_proxy_request_for_upstream` 和 `engine.native.runtime.http_proxy_plain_rewrite_applied` 诊断；真实 `http://` request/response 可在 explicit proxy 路径应用 reject、redirect、header/body rewrite，并经既有 SOCKS outbound primitive 转发。
- `networkcore-linux mitm http-rewrite plan` 的 `MITM_HTTP_TLS_DATA_PLANE_GATE` 推进为 `plain-http-live-data-plane-active/tls-decryption-blocked`，`http_rewrite` report 现在声明 `mutation_ready=true`、`live_traffic_ready=true`、`tls_decryption_ready=false`。本增量仍不解密 HTTPS、不终止 TLS、不安装/信任 CA、不修改 browser/system proxy、system PAC、TUN、DNS 或 firewall，不执行 JavaScript script dispatch。
- 同步 `v0.1.0-alpha.13` 发布后的 source-of-truth：README、ROADMAP、TODO、Release Strategy、Alpha Release Feature Matrix、CI policy、Linux CLI README、`mitm-policy` README 和相关 source contract 现在把 `v0.1.0-alpha.13` 记录为最新已发布 Linux artifact，并把后续 `v0.1.0` 切片推进到 alpha.14 起。

## v0.1.0-alpha.13 - 2026-07-09

### Added

- 新增 `v0.1.0-alpha.13` Linux dedicated profile CA trust foundation 源码切片：`networkcore-linux mitm certificate apply --confirm --cert-file <path> --key-file <path> --profile-trust-file <path> --snapshot <path>` 可将生成的 CA artifact 写入调用方显式指定的 dedicated profile trust artifact 路径，并在 NetworkCore snapshot 中记录 fingerprint 以便 rollback 删除；`certificate_lifecycle` JSON/text report 新增 `profile_trust_file_path`、`profile_trust_content` 和 `profile_trust_fingerprint`。本增量不执行 NSS DB、p11-kit、Firefox trust store、system trust store 或 profile trust state mutation，不解密 HTTPS，也不应用 live HTTP/TLS rewrite。
- 固定 `v0.1.0` 到 `v0.1.2` 的拍板版本节奏：`v0.1.0` 目标为 Linux-only explicit HTTPS rewrite preview，`v0.1.1` 正式引入 Windows CLI artifact 并推进订阅兼容，`v0.1.2` 推进 managed lifecycle，并在 alpha 切片中相继推出 JavaScript script dispatch、system trust store mutation 和 system proxy mutation。该条目只更新规划 source of truth，不代表未发布能力已经进入用户 artifact。

## v0.1.0-alpha.12 - 2026-07-09

### Added

- 新增 Linux MITM plain HTTP rewrite foundation：`engine-native` 提供 `NativePlainHttpMessage`、`NativePlainHttpRewriteReport`、`plan_and_apply_plain_http_mitm` 和 `apply_http_mitm_outcome_to_plain_http_message`，可把 caller-provided HTTP message 映射为 `HttpMitmEvent`，调用 `MitmPluginService::handle_http_mitm_event`，并把 `HttpMitmOutcome` 的 reject、redirect、header mutation 和 body mutation 应用到该合成输入；script dispatch 只记录 deferred，不执行脚本。
- 新增 Linux CLI `networkcore-linux mitm http-rewrite plan` / `preview --confirm --url <url>` 命令面和 `http_rewrite` JSON/text report，输出 source contract、authorization、request、outcome、output headers/body、blocked operations、`mutation_ready=true`、`live_traffic_ready=false` 和 `tls_decryption_ready=false`。
- 新增 [Linux MITM HTTP Rewrite Source Contract](docs/architecture/linux-mitm-http-rewrite-source-contract.md)，并把 `MITM_HTTP_TLS_DATA_PLANE_GATE` 推进为 `plain-http-rewrite-foundation-active/tls-decryption-blocked`。本增量不解密 HTTPS，不安装或信任 CA，不修改 browser/system proxy、system PAC、TUN、DNS、firewall 或路由状态，不拦截真实浏览器/系统流量，也不承诺完整 HTTPS rewrite。

## v0.1.0-alpha.11 - 2026-07-09

### Added

- 新增 Linux MITM certificate artifact lifecycle foundation：`networkcore-linux mitm certificate apply --confirm --cert-file <path> --key-file <path> --snapshot <path>` 可写入调用方显式指定的 NetworkCore certificate/private-key artifact 和 rollback snapshot；`mitm certificate rollback --snapshot <path>` 会在 snapshot fingerprint 仍匹配时删除 NetworkCore 管理的 artifact。新增 `certificate_lifecycle` JSON report、trust-plan blocked operations、`LinuxMitmCertificate*` request/report/outcome 类型、`MitmCertificateArtifactStore`/`CommandMitmCertificateArtifactStore`、诊断 code 和 [Linux MITM Certificate Lifecycle Source Contract](docs/architecture/linux-mitm-certificate-lifecycle-source-contract.md)。本增量只推进 `MITM_CERTIFICATE_LIFECYCLE_GATE=artifact-lifecycle-active/trust-mutation-blocked`，不执行 `update-ca-certificates`、NSS DB、p11-kit、Firefox trust store 或发行版 trust command，不解密 HTTPS，也不应用 HTTP/TLS rewrite。

## v0.1.0-alpha.10 - 2026-07-09

### Added

- 新增授权 dedicated Firefox profile prefs apply/rollback：`networkcore-linux mitm browser-capture apply --confirm --pac-file <path> [--policy-file <path>] [--profile-prefs-file <path>] --snapshot <path>` 现在可写入用户指定 Firefox profile `user.js` 的显式代理设置；`--proxy-scheme socks5` 会写 SOCKS5 proxy 和 remote DNS prefs，rollback 会在未被外部修改时恢复原内容或删除 NetworkCore 新建文件。该增量仍不修改系统代理、system PAC、TUN、DNS、firewall 或 CA，也不承诺静默/全自动 browser hijack、HTTPS 解密或 HTTP/TLS rewrite。
- 固定后续 alpha 切片：`v0.1.0-alpha.11` 只推进 CA artifact lifecycle foundation，不做 HTTPS rewrite；当时规划 `v0.1.0-alpha.12` 作为 HTTP/TLS rewrite 候选切片，后续已由 alpha.12 以 plain HTTP rewrite foundation 发布。CI governance 同步恢复对 `v0.1.0-alpha.9`、`v0.1.0-alpha.10`、`v0.1.0-alpha.11` 和 `v0.1.0-alpha.12` 的逐版本矩阵检查。

## v0.1.0-alpha.9 - 2026-07-09

说明：本节顶部的 `Changed` 条目描述当前仓库状态；下方较早的 `Added` 条目保留了当时增量的
placeholder/blocked 语境时，以 README、ROADMAP、TODO 和对应 source contract 的当前状态说明为准。

### Changed

- `mitm browser-capture traffic-proof --confirm` 现在支持可选 `--target-url <url>`，并在省略 `--proof-token`/`--proof-log` 时使用与 `session-plan`/`launch --confirm` 一致的默认 proof token、`proof_target_url` 和 `MITM_BROWSER_CAPTURE_DEFAULT_PROOF_LOG_PATH`；默认 token 改为由 CONNECT endpoint 和计划 proxy URL 派生，可与 native SOCKS5 CONNECT 诊断对齐，让 dedicated browser proof 会话和后续 proof log 检查更容易关联；该增量仍只读取 operator-provided proof log，不写系统代理、不安装浏览器 policy、system PAC、TUN、DNS、firewall 或 CA。
- 新增 [Alpha Release Feature Matrix](docs/alpha-release-feature-matrix.md)，逐版本记录 `v0.1.0-alpha.1` 到 `v0.1.0-alpha.8` 的已发布能力边界，并把 `v0.1.0-alpha.9`、`v0.1.0-alpha.10`、`v0.1.0-alpha.11` 和 `v0.1.0-alpha.12` 的规划切片写入 README、ROADMAP、TODO、Release Strategy、Linux CLI README、`mitm-policy` README、Linux MITM browser capture source contract、CI policy 和 workflow 静态门禁。
- `networkcore-linux start` 现在通过 `native_proxy_engine_service_with_builtin_mitm_plugin` 注入内置 `networkcore.adblock` MITM hook；`engine-native` 在 SOCKS5 CONNECT 进入 outbound 前调用 `NativeHttpMitmPluginHook`，插件返回 `Reject` 时写 SOCKS5 general failure response 并记录 `engine.native.runtime.http_mitm_connect_reject_applied`，同时输出 `engine.native.runtime.http_mitm_connect_browser_proof_observed` 记录默认 browser proof token、CONNECT target 和本地 socks5 proxy URL。该增量只覆盖 explicit proxy CONNECT 阻断和 proof 诊断，不解密 HTTPS，不安装 CA，不写 browser/system proxy，也不应用 redirect/header/body/script rewrite 到真实 HTTP 请求/响应。
- README、TODO、Linux CLI README、`mitm-policy` README、Linux CLI entrypoint 设计、Linux MITM browser capture source contract、CI policy 和 workflow 现在把当前源码状态同步为 `MITM_BROWSER_CAPTURE_GATE=pac-policy-profile-prefs-active/system-mutation-blocked`：current main 可写 operator-provided NetworkCore PAC artifact、可选 Chromium/Chrome managed proxy policy artifact 和 rollback snapshot，但仍不安装 browser policy、系统代理、system PAC、TUN、DNS、firewall 或 CA 状态。
- README、ROADMAP、TODO、Linux CLI README、`mitm-policy` README 和 Linux CLI entrypoint 设计进一步明确当前仓库阶段只能判定为 P4 Client And Platform Integration；P3 只保留为 completed baseline、历史 TODO 或 CHANGELOG 审计语境，不能再作为当前开发、发布或 source contract 阶段。
- README、ROADMAP、TODO、Linux CLI README、`mitm-policy` README、Linux CLI entrypoint 设计、Linux MITM browser capture source contract 和 CI policy 现在固定 `P4 backlog buckets`：订阅/客户端兼容、MITM 数据面和证书生命周期、浏览器捕获用户闭环；P3 只保留为 completed baseline 或历史条目。
- README、ROADMAP、TODO、Release Strategy 和 Linux artifact 合同文档进一步拆清当前 P4 状态、`v0.1.0-alpha.8` artifact 边界、`mitm browser-capture verify --confirm`/`session-plan`/`--target-url` 已进入可下载 Linux CLI artifact 的语境，以及历史 placeholder 合同字段的审计语境；P3 仅保留为 completed baseline。
- README、ROADMAP、TODO 和相关架构文档现在把阶段入口进一步固定为 P4 Client And Platform Integration；P3 只作为 completed baseline 或历史条目保留，不再作为当前仓库阶段描述。
- README 和 TODO 现在把最新已发布 Linux artifact 同步为 `v0.1.0-alpha.8`，并明确 `mitm browser-capture launch --confirm`、`verify --confirm`、`verify --confirm --target-url <url>`、`session-plan` 和 `--target-url` 已进入当前 Linux CLI artifact 边界，但只启动 dedicated browser profile、探测计划代理端点/目标代理通路或输出脱敏会话计划，不启用 live MITM 或系统代理 mutation。
- Linux artifact release 状态现在统一为 `linux-artifact-release-state=confirmed-release-path`：Release Strategy、Linux license/NOTICE confirmation contract、transition validation contract、pre-release design、manual intervention marker、README、ROADMAP 和 TODO 都记录 license/NOTICE 已 confirmed，但 Linux tag release 仍必须通过同 commit CI、checksum、manifest、attestation、release notes、rollback 和 publish eligibility gates。
- README、ROADMAP、TODO、`mitm-policy` README 和 MITM source contract 现在把 MITM 用户入口状态更新为 `mitm-cli-command-gate-status=partial-active`：Linux CLI 已有 status/diagnostics/certificate-plan/browser-plan 和 browser-capture blocked report 命令面，但 live MITM、CA mutation lifecycle、HTTP/TLS data plane 和 browser capture mutation 仍 deferred/blocked。
- ROADMAP、README 和 TODO 现在把当前阶段统一为 P4 Client And Platform Integration。
- P3 Runtime Capability Baseline 作为已完成 baseline 保留，后续订阅格式、managed lifecycle 和 MITM 真实流量能力作为 P4 集成阶段 backlog 继续推进。
- README、ROADMAP、TODO、`mitm-policy` README 和 MITM source contract 现在明确记录当前仓库源码没有用户可启用的 live MITM：`networkcore-linux mitm status/diagnostics/certificate-plan/browser-plan` 只输出 policy-only 状态、证书计划和浏览器捕获计划，`networkcore-linux mitm browser-capture plan/launch-plan/launch/apply/rollback/verify` 只输出 `browser_capture` manual launch-plan、dedicated-profile launch report、本地代理端点 verify report 和 blocked report，没有 CA 生成/安装/信任 mutation 路径，没有 HTTP/TLS 解密改写数据面，也没有浏览器/系统代理 mutation；后续工作固定为 `MITM_CLI_COMMAND_GATE`、`MITM_CERTIFICATE_LIFECYCLE_GATE`、`MITM_HTTP_TLS_DATA_PLANE_GATE` 和 `MITM_BROWSER_CAPTURE_GATE` 四个门禁。
- README、ROADMAP、TODO、`mitm-policy` README 和 MITM source contract 现在补充 `mitm browser-capture verify --confirm` 的本地代理端点探测边界：该命令只检查计划代理 `http://127.0.0.1:7890` 是否可达，不证明浏览器真实流量、HTTPS MITM 或 rewrite 应用。
- 已完成 runtime baseline 的策略现在固化为 public engine adapter first：NetworkCore 维护控制层，`engine-*` 维护 adapter 层，`sing-box` 等公有执行内核先承担 VLESS、Shadowsocks、Trojan、VMess、Hysteria 等协议数据面；`engine-native` 保留为自研执行内核实验线，但私有协议实现暂缓。
- Release workflow 已完成 Linux CLI 二进制发布路径：首个真实发布路径从 `v0.1.0-alpha.2` 打通，当前最新 GitHub Release 是 `v0.1.0-alpha.8`；对应 tag release 通过 GitHub Actions 生成 lockfile、执行 locked release build、组装 tarball、sha256、manifest 与 manifest sha256，`attest-linux` 生成 GitHub artifact attestation，`publish-eligibility-gate` 聚合发布门禁，tag 触发的 `publish-github-release` 创建 GitHub Release 并上传 Linux assets。
- CI governance 改为检查真实 Linux release job、artifact/attestation/publish gates、iOS upload 阻断、license marker 和本地产物禁止提交，不再要求 `package-linux` 永久保持未定义。
- ROADMAP、README 和 TODO 将 P2 Core Kernel Skeleton 标记为 completed；iOS `Package.swift` manifest-only activation validation contract 已作为 alpha 发布前停止边界补齐。
- Release policy 现在允许 `vMAJOR.MINOR.PATCH-alpha.N` 作为 release 版本；手动 `workflow_dispatch` 只做验证，真实 GitHub Release asset 上传只允许 tag 触发，iOS upload job 仍保持 blocked。
- Release placeholder 与 release summary 现在显式输出 alpha Windows 手工 smoke 测试清单、`docs/manual-intervention.md` confirmed marker、`passed` 结果、Windows 11 24H2 x64 环境、未运行本地构建/测试记录和 `not-produced-placeholder` artifact 状态；该输出只记录用户侧 Windows 手工确认，不替代 GitHub Actions Windows 矩阵。
- `release-ci-gate` 现在在 job 级启用 `actions: read`，通过 GitHub Actions workflow runs API 查询同 repository、同 commit、`main` 分支 completed CI run，并通过 workflow jobs API 校验 `CI summary` job 成功；release summary 输出被选中的 `ci_workflow_name`、`ci_run_id`、`ci_run_url`、`ci_head_sha`、`ci_checked_at` 等字段，activation/execution/API implementation 状态切换为 active，并被当前 Linux CLI artifact 发布路径复用。

### Added

- 新增 source-only native SOCKS5 CONNECT browser proof 诊断：`engine-native` 提供 `native_socks5_connect_browser_capture_proof_token` 和 `browser_capture_proof_token_from_connect_authority`，accept loop 在 MITM hook 处理 CONNECT target 后输出 `ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_BROWSER_PROOF_OBSERVED_CODE`；Linux CLI 默认 proof token 生成规则改为 CONNECT endpoint + proxy URL。该增量让 captured `networkcore-linux start` 诊断日志可以作为 `traffic-proof --proof-log` 输入，但仍不解密 HTTPS、不写系统或浏览器代理状态。
- 新增 source-only browser capture native SOCKS5 proxy scheme：当前 `main` 源码支持 `networkcore-linux mitm browser-capture session-plan/launch/apply/verify/traffic-proof --proxy-scheme socks5`，在 `browser_capture` request/report 中输出 `proxy_scheme=socks5`，生成 `--proxy-server=socks5://127.0.0.1:7890` dedicated browser command、`SOCKS5 127.0.0.1:7890; DIRECT` PAC artifact、socks5 verify request 和 traffic-proof request，用于让显式授权 dedicated 浏览器会话走到 native SOCKS5 CONNECT MITM hook。该增量不在 `v0.1.0-alpha.8` artifact 中，不写系统代理、不安装浏览器 policy、system PAC、TUN、DNS、firewall 或 CA 状态，也不证明 HTTPS MITM 解密或 rewrite 应用。
- 新增 source-only browser capture proof session binding：`mitm browser-capture session-plan` 和 `launch --confirm` 现在可接收 `--proof-token`/`--proof-log`，在 report 中输出 `proof_target_url`、`networkcore_proof_token` 和 `traffic_proof_command`，并把 dedicated 浏览器启动命令的 target URL 替换为带 proof token 的 URL，便于后续 `traffic-proof` 从 operator-provided proof log 验证同一会话。该增量不写系统或浏览器代理状态，不证明 HTTPS MITM 或 rewrite 应用。
- 新增 native SOCKS5 CONNECT MITM plugin hook 源码增量：`engine-native` 提供 `NativeHttpMitmPluginHook`、`plan_socks5_connect_http_mitm`、`ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_APPLIED_CODE` 和 accept loop `Reject` 应用合同；Linux CLI 提供 `native_proxy_engine_service_with_builtin_mitm_plugin` 并在 `networkcore-linux start` 路径加载内置 `networkcore.adblock`。合同测试覆盖 plan 映射和 reject 先于 outbound 生效；验证仍只通过 GitHub Actions。
- 新增 source-only MITM rich mutation plan：`control-domain` 定义 `HttpMitmEvent`、`HttpMitmOutcome`、`HttpMitmAction`、`HttpHeaderMutation`、`HttpBodyMutation`、`HttpMitmScriptDispatch` 和 `MitmPluginService::handle_http_mitm_event`；`mitm-policy` 的 `AnixOpsMitmPluginService` 会保留 loaded plugin source，并把 `mitm_anixops v0.45.10-alpha` 的 URL reject/redirect、header/body rewrite 和 script dispatch 映射为 NetworkCore-owned `HttpMitmOutcome`。该增量只生成 policy plan，不接入 HTTP/TLS 数据面，不生成或安装 CA，不改写真实请求/响应，也不进入 `v0.1.0-alpha.8` artifact。
- 新增 source-only browser capture PAC/browser policy artifact apply/rollback gate：当前 `main` 源码支持 `networkcore-linux mitm browser-capture apply --confirm --pac-file <path> [--policy-file <path>] --snapshot <path>`，通过 `BrowserCapturePacFileStore` 写入 operator-provided NetworkCore PAC 文件、可选 Chromium/Chrome managed proxy policy artifact 和 rollback snapshot，并输出 `LinuxBrowserCapturePacRequest`、`LinuxBrowserCapturePacApplyOutcome`、`cli.linux.mitm.browser_capture.apply.ready`、`pac_file_path`、`pac_url`、`policy_file_path`、`policy_url` 和 `networkcore-created` snapshot；`rollback --snapshot <path>` 读取 NetworkCore snapshot 并删除对应 PAC/policy artifact，输出 `LinuxBrowserCapturePacRollbackOutcome` 和 `cli.linux.mitm.browser_capture.rollback.ready`。该增量不在 `v0.1.0-alpha.8` artifact 中，不安装系统 PAC，不安装 browser policy、系统代理、TUN、DNS、firewall 或 CA，也不证明 live browser traffic、HTTPS MITM 或 rewrite 应用。
- 新增 source-only browser capture traffic proof gate：当前 `main` 源码支持 `networkcore-linux mitm browser-capture traffic-proof --confirm [--target-url <url>] [--proof-token <token>] [--proof-log <path>]`，通过 `BrowserCaptureTrafficProofProbe` 检查 operator-provided proof log 中是否出现 token，并输出 `traffic_proof_report`、`proof-log-token`、proxy URL、target URL、proof target URL、proof token、proof log path 和 `networkcore.adblock` 插件元数据；该增量不在 `v0.1.0-alpha.8` artifact 中，不写系统代理、不安装浏览器 policy、PAC、TUN、DNS、firewall 或 CA 状态，也不证明 HTTPS MITM 解密或 rewrite 应用。
- 新增 browser capture target URL proxy route verify：`networkcore-linux mitm browser-capture verify --confirm --target-url <url>` 会通过 `BrowserCaptureEndpointProbe` 先连接计划代理 `http://127.0.0.1:7890`，再向目标 URL 的 host:port 发起 HTTP CONNECT 探测，成功时输出 `cli.linux.mitm.browser_capture.verify.target_reachable`、`probe=http-connect-target`、`target_url`、`target_reachable` verify report 和 JSON/text 字段；该增量只证明计划代理能打开目标通路，不证明 dedicated browser 真实流量、HTTPS MITM 解密或 rewrite 应用，也不写系统代理、不安装浏览器 policy、PAC、TUN、DNS、firewall 或 CA 状态。
- 新增 browser capture `--target-url <url>` dedicated profile 参数：`networkcore-linux mitm browser-capture session-plan <ss://url> --target-url <url>` 会把目标页面写入脱敏会话计划和 dedicated browser command，`networkcore-linux mitm browser-capture launch --confirm --target-url <url>` 会通过 `BrowserCaptureProcessRunner` 把目标页面作为浏览器参数打开，并在 `LinuxBrowserCaptureLaunchRequest`、`LinuxBrowserCaptureLaunchReport` 和 JSON/text 输出中记录 target URL；该增量不写系统代理、不安装浏览器 policy、PAC、TUN、DNS、firewall 或 CA 状态，也不证明 live browser traffic、HTTPS MITM 或 rewrite 应用。
- 新增 `networkcore-linux mitm browser-capture session-plan <ss://url>` 会话计划入口：Linux CLI 通过 `CoreSubscriptionService` 解析单条订阅链接，复用 `engine-singbox` 本地代理配置渲染合同，输出脱敏 URL 来源、选中节点、本地代理监听、`run-url <subscription-url>` 命令模板、dedicated 浏览器命令、`verify --confirm` 命令、`LinuxBrowserCaptureSessionPlanRequest`、`LinuxBrowserCaptureSessionPlanReport`、`browser_capture.session_plan` JSON 字段和 `networkcore.adblock` 插件元数据；该命令不下载或启动 `sing-box`，不启动浏览器，不写 browser/system proxy、PAC、TUN、DNS、firewall 或 CA 状态，也不证明 live browser traffic 或 HTTPS MITM。
- 新增 `networkcore-linux mitm browser-capture plan/launch-plan/launch/apply/rollback/verify` manual launch-plan、dedicated-profile launch、本地代理端点 verify 与 blocked report 命令面：Linux CLI 输出 `browser_capture` 机器字段、`LinuxBrowserCaptureManualLaunch`、`LinuxBrowserCaptureLaunchReport`、`LinuxBrowserCaptureVerifyReport`、`BrowserCaptureAuthorization`、`BrowserCaptureRollbackSnapshot`、apply/rollback/verify report、`cli.linux.mitm.browser_capture.launch_plan.ready`、verify endpoint diagnostics 和 `cli.linux.mitm.browser_capture.*.blocked` 诊断；`launch-plan` 只输出手动 dedicated-profile 浏览器启动命令模板、计划代理 URL 和 `networkcore.adblock` 插件元数据，`apply --confirm` 只记录显式授权，`rollback --snapshot <path>` 只保留 snapshot 路径，全部不写入 browser/system proxy、PAC、TUN、DNS、firewall 或 CA 状态，也不启用 live browser capture。
- 新增 `networkcore-linux mitm browser-capture launch --confirm`：Linux CLI 通过注入的 `BrowserCaptureProcessRunner` 启动 dedicated browser profile，传入 `--user-data-dir` 和 `--proxy-server=http://127.0.0.1:7890`，并在 `browser_capture.launch_report` 输出 status、pid、profile、proxy、命令参数和 `networkcore.adblock` 插件元数据；缺少 `--confirm` 时返回 `cli.linux.mitm.browser_capture.launch.authorization_required` 且不调用 runner。该命令不写系统代理、不安装浏览器 policy、PAC、TUN、DNS、firewall 或 CA 状态，不验证 live MITM，也不应用 rewrite plan 到真实流量。
- 新增 `networkcore-linux mitm browser-capture verify --confirm` 本地代理端点探针：Linux CLI 通过注入的 `BrowserCaptureEndpointProbe` 对计划代理 `http://127.0.0.1:7890` 做 TCP connect timeout 探测，并在 `browser_capture.verify_report` 输出 status、verified、proxy URL、probe 类型和 `networkcore.adblock` 插件元数据；缺少 `--confirm` 时返回 `cli.linux.mitm.browser_capture.verify.authorization_required` 且不调用 probe，端点不可达时返回 `cli.linux.mitm.browser_capture.verify.proxy_unreachable`。该命令不证明浏览器真实流量捕获、HTTPS MITM 或 rewrite 应用，也不写系统或浏览器状态。
- 新增 Linux MITM Browser Capture Source Contract：固定 `mitm-browser-capture-source-contract-status=active`、当前 `MITM_BROWSER_CAPTURE_GATE=plan-only/mutation-blocked`、`BrowserCaptureEndpointProbe`、`BrowserCaptureAuthorization`、`BrowserCaptureRollbackSnapshot`、apply/rollback/verify 命令面、显式授权、snapshot、rollback、诊断 code 和 CI governance；当前源码只提供 dedicated-profile launch、本地代理端点 verify 和 blocked report，不写入 browser/system proxy、PAC、TUN、DNS、firewall 或 CA 状态，也不启用 live browser capture。
- 新增 `networkcore-linux mitm browser-plan` 入口：Linux CLI 在现有 `mitm_status` JSON 下输出 `browser_plan` 机器字段、默认显式代理计划 `127.0.0.1:7890`、计划步骤、blocked operations、`mutation_ready=false`、`cli.linux.mitm.browser_plan.ready` 和 `cli.linux.mitm.browser_capture_mutation.blocked` 诊断；`MITM_BROWSER_CAPTURE_GATE` 当前为 plan-only，仍不写入浏览器策略、系统代理、PAC、TUN、DNS 或 firewall 状态，也不验证 live browser capture 或执行回滚。
- 新增 Linux artifact release-state consistency CI/release gate，防止文档或 workflow 回退到 license/NOTICE pending placeholder 描述，并要求 release readiness 读取同一 confirmed release path marker。
- 新增 `networkcore-linux mitm certificate-plan` 入口：Linux CLI 在现有 `mitm_status` JSON 下输出 `certificate_plan` 机器字段、当前证书状态、计划步骤、blocked operations、`mutation_ready=false`、`cli.linux.mitm.certificate_plan.ready` 和 `cli.linux.mitm.certificate_mutation.blocked` 诊断；`MITM_CERTIFICATE_LIFECYCLE_GATE` 当前为 plan-only，仍不生成私钥/CA、不安装或信任证书、不撤销或回滚 trust store。
- 新增 `networkcore-linux mitm status` 和 `networkcore-linux mitm diagnostics` 最小 CLI 入口：Linux CLI 通过 `mitm-policy` 加载内置 `networkcore.adblock` policy，输出 `mitm_status` JSON 字段、`MITM_CLI_COMMAND_GATE`/`MITM_CERTIFICATE_LIFECYCLE_GATE`/`MITM_HTTP_TLS_DATA_PLANE_GATE` gate 状态和 browser hijack deferred 诊断；该条目已由后续 `certificate-plan` 与 `browser-plan` 增量扩展，当前 marker 为 `mitm-cli-command-gate-status=partial-active`，真实 CA lifecycle、browser capture mutation 和 HTTP/TLS mutation 仍未启用。
- 新增 Third-Party Plugin Onboarding Process，并把它纳入 CI governance：后续第三方 plugin、plugin parser、script runtime 或兼容核心必须先有 source contract、pinned source、license/NOTICE gate、permission gate、safe wrapper gate、CI governance gate 和 upgrade procedure；现有 `networkcore.adblock` source contract 已挂接该流程。
- 新增 `mitm-policy` safe wrapper 和 NetworkCore MITM plugin adapter：`mitm_anixops` 子模块固定到 `v0.45.10-alpha` (`a3ee0fca6376ddccc333bdfe06ac5b5e75ed23e0`)，`mitm-anixops-sys` 扩展 config/rule diagnostic/MITM/URL rewrite/rewrite plan/header/body chain/script/JQ guard FFI，`mitm-policy` 提供 `AnixOpsMitmPolicyEngine`、`AnixOpsMitmPluginService`、manifest/permission gate、内置 `networkcore.adblock` alpha 去广告插件包、0.45.10 rewrite plan/header/body/script 合同测试和 `mitm.policy.http_event.mutation_deferred` 诊断；该条目后续已由 source-only `HttpMitmOutcome` rich plan 扩展，真实 HTTP/TLS request/response mutation 仍等待数据面应用。
- 新增 `networkcore-linux run-url <ss://url>` 最小可用代理闭环：CLI 通过 `CoreSubscriptionService` 解析单条 Shadowsocks URL、明文 `ss://` 链接列表或 base64 链接列表，归一化为 `NodeCatalog`，由 `engine-singbox` 渲染本地 `mixed` inbound + Shadowsocks outbound JSON，写入 engine runtime cache，并以前台 `sing-box run -c <config>` 启动默认 `127.0.0.1:7890` 本地代理；JSON 输出新增 `sing_box_run`，文本输出显示 node、local proxy、config 和 process exit code。
- `control-domain::NodeDescriptor` 新增通用 `metadata`，并固定 `NODE_METADATA_SHADOWSOCKS_METHOD`、`NODE_METADATA_SHADOWSOCKS_PASSWORD` 和 `NODE_METADATA_SOURCE_FORMAT`，作为多订阅格式进入统一模型后的协议参数承载边界。
- 新增 Subscription URL To sing-box Run source contract，固定多客户端/多订阅格式路线：各种订阅输入先进入 `SubscriptionService`/`NodeCatalog`，再由 engine adapter 生成执行内核配置，平台客户端不直接维护各格式解析器。
- 新增 `engine-singbox` public engine adapter source contract 和源码 crate，覆盖 `sing-box` descriptor identity、官方 GitHub latest release metadata 解析、host asset selection、runtime cache layout、`sha256:` digest 校验、`.tar.gz` 中只提取 `sing-box` executable、Unix `0755` 权限和稳定下载诊断；当前仍不 bundle 第三方 binary，managed daemon/status/logs/reload 仍不在本增量内。
- `networkcore-linux` 新增 `help`/`--help` 命令表，以及 `install-sing-box` 和 `sing-box install` alias；安装命令通过注入的 `GithubSingBoxReleaseInstaller` 自动下载 latest `sing-box`，文本输出展示版本、资产、archive、executable 和 downloaded 状态，JSON 输出新增 `sing_box_install` 机器字段。
- 新增 ADR 0002 Public Engine Adapter First，定义 NetworkCore 控制层、执行内核 adapter 层、公有执行内核层的三层维护框架，固定 `sing-box` 为首个 public engine adapter 目标，要求 operator-provided binary path 优先于捆绑第三方二进制，并明确私有协议实现 deferred。
- 新增 alpha Windows 手工 smoke 测试清单和 marker，固定 `v0.1.0-alpha.1`、release run head SHA、same-commit CI run、release run、placeholder artifact status 的记录方式和 marker update contract；该 marker 不替代 GitHub Actions Windows 矩阵，完成后需要独立更新 confirmed 字段并重新触发 CI/release workflow。
- 新增 P3 `control-runtime` subscription catalog runtime gate 源码合同，提供 `prepare_runtime_request_with_subscription_catalogs`、`start_runtime_with_subscription_catalogs` 和 `reload_runtime_with_subscription_catalogs`，只接受调用方显式传入的 `SubscriptionSource`，把 inline `NodeCatalog.nodes` 编排进 `RuntimeConfigRequest.nodes`，用 `runtime.subscription.node_id_duplicate` 拒绝与 `ConfigSnapshot.nodes`、已有 `RuntimeConfigRequest.nodes` 或其他 catalog nodes 重复的 id，用 `runtime.subscription.rules_deferred` 保持 subscription rules deferred，并继续阻止远程/文件订阅、系统 DNS/TUN mutation、daemon/control socket、release artifact 和本地验证；CI governance 现在静态检查源码 API、诊断 code 和 runtime 合同测试 anchors。
- 新增 iOS `Package.swift` manifest-only activation validation contract，固定未来独立提交引入 `apps/ios/Package.swift` 前的 manifest-only source scan、target list verification、no Swift source before source gate、`macos-26` Swift package validation hook、Xcode project blocked、upload workflow enabled marker blocked、release/upload blocked 和 `ios-package-swift-manifest-only-*` release summary 字段；CI/release governance 现在静态检查该合同和三处 blocked 输出，仍不引入真实 `Package.swift`、Swift source、Swift/Xcode project、Network Extension target、archive/export、签名、TestFlight/App Store upload、App Review submission 或 iOS release asset。
- 新增 P3 Subscription Catalog Runtime Orchestration Design，定义 `CoreSubscriptionService` 产出的 `NodeCatalog` 如何进入 `RuntimeConfigRequest.nodes`，如何与 `ConfigSnapshot.nodes` 和其他 catalog nodes 做重复 id 拒绝，如何保持 `NodeCatalog.rules` deferred，并固定 no remote/file subscription、no system DNS/TUN mutation、no daemon/control socket 和 no release artifact 边界；CI governance 现在静态检查该设计的 runtime/catalog/diagnostic anchors。
- 新增 `config-core::CoreSubscriptionService` 最小 inline subscription parser，实现 `SubscriptionService`，只接受显式 `inline:` source，把最小 subscription TOML `nodes`/`routes` 子集解析为 `SubscriptionDocument` 并归一化为 `NodeCatalog`；远程订阅拉取、文件订阅读取、认证、secret、重复 id 和 listener/node 图校验仍不进入 P2。`control-domain` 与 `config-core` 合同测试覆盖 subscription port、inline fetch、subscription parse、unsupported location 和 secret 不泄露，CI governance 现在静态检查该 P2 完成证据。
- 新增 iOS `Package.swift` source ownership activation preflight contract，固定未来 `apps/ios/Package.swift` 引入前的 target ownership、source directory guard、no Swift source until package gate、`macos-26` Swift package validation hook、Xcode project blocked、upload workflow enabled marker blocked 和 release/upload blocked 输出；CI governance 与 release workflow 现在检查并输出 `ios-package-swift-ownership-*` blocked placeholder 字段，仍不引入真实 `Package.swift`、Swift source、Swift/Xcode project、Network Extension target、archive/export、签名、TestFlight/App Store upload、App Review submission 或 iOS release asset。
- 新增 `apps/ios/README.md` source tree governance placeholder，固定未来 iOS Swift package ownership、source directory guard、`macos-26` source scan hook、no `Package.swift`/no Swift source/no Xcode project boundary 和 upload workflow enabled marker blocked 状态；release workflow 现在把 source tree preflight root status 输出为 `readme-placeholder` 并新增 `ios-source-tree-preflight-readme-placeholder=present`，仍不引入 Swift/Xcode source、archive/export、签名、TestFlight/App Store upload、App Review submission 或 iOS release asset。
- 新增 iOS Swift/Xcode source tree activation preflight contract，定义未来真实 `apps/ios` source tree、`Package.swift`、Xcode project、Network Extension target、`PrivacyInfo.xcprivacy`、entitlement/provisioning、`macos-26` source scan 和 upload workflow enabled marker 的前置门禁；`ios-upload-readiness`、release placeholder 与 release summary 现在输出 `ios-source-tree-preflight-*` blocked placeholder 字段，并继续阻止 Swift/Xcode source、archive/export、签名、TestFlight/App Store upload、App Review submission 或 iOS release asset 进入当前阶段。
- 新增 iOS upload workflow activation validation contract，定义 `ios-upload-readiness` blocked placeholder、release workflow placeholder/summary 字段、`ios-upload-workflow` manual marker 读取、protected environment/manual approval blocked 状态、App Store Connect API secret status `not-read-blocked`、archive/export/upload/submission/release asset blocked 输出和 GitHub Actions 静态门禁；release workflow 现在输出 iOS upload activation safe summary，仍不引入 Swift/Xcode project、`PrivacyInfo.xcprivacy`、ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、真实签名、TestFlight upload、App Store upload、App Review submission 或 iOS release asset。
- 新增 iOS TestFlight/App Store Connect upload workflow source contract，定义后续 archive/export、App Store Connect API、TestFlight group、manual approval、protected environment、build processing status、App Review submission gate、GitHub Actions `macos-26` 验证入口和 `docs/manual-intervention.md` marker；CI governance 现在静态检查该合同、pending/blocked marker 和 archive/export artifact 禁止项，仍不引入 ExportOptions.plist、`.ipa`、`.xcarchive`、`.xcresult`、dSYM bundle、真实签名、TestFlight upload、App Store upload、App Review submission 或 iOS release asset。
- 新增 iOS App Review manual confirmation source contract，定义 App Privacy answers、privacy policy URL、App Review Notes、demo account、demo mode、review attachment、VPN compliance marker、TestFlight group、App Store Connect app record、export compliance、beta app review、App Review submission 和 `docs/manual-intervention.md` 机器可读 marker；CI governance 现在静态检查该合同和 pending/blocked marker，仍不引入 `PrivacyInfo.xcprivacy`、Swift/Xcode project、Network Extension target、真实签名、TestFlight upload、App Store upload 或 iOS release asset。
- 新增 iOS Privacy Manifest source contract，定义后续 `PrivacyInfo.xcprivacy` 文件位置、`NSPrivacyCollectedDataTypes`、`NSPrivacyAccessedAPITypes`、Required Reason API、App Privacy answer source、third-party SDK privacy manifest、SDK signature 和 GitHub Actions `macos-26` 静态验证入口；CI governance 现在静态检查该合同，仍不引入 `PrivacyInfo.xcprivacy`、Swift/Xcode project、Network Extension target、真实签名、TestFlight upload、App Store upload 或 iOS release asset。
- 新增 iOS App Review/privacy release readiness design，定义后续 Privacy Manifest、`PrivacyInfo.xcprivacy`、App Privacy disclosure、privacy policy、App Review Notes、VPN compliance、demo account、review attachment、TestFlight/App Store Connect manual intervention 和 GitHub Actions `macos-26` 静态门禁；CI governance 现在静态检查该设计，并继续阻止 `PrivacyInfo.xcprivacy`、Swift/Xcode project、Network Extension target、真实签名、TestFlight upload、App Store upload 或 iOS release asset 进入当前阶段。
- 新增 iOS entitlement/provisioning source contract，定义后续 `.entitlements`、App ID、Network Extension capability、Provisioning Profile、GitHub Secrets、signing asset redaction、`IosNetworkExtensionEntitlementState` 诊断映射和 GitHub Actions `macos-26` 上的 `swift build`/`swift test`/`xcodebuild` 验证入口；CI governance 现在静态检查该合同，仍不引入 Swift/Xcode project、Network Extension target、Provisioning Profile、签名、TestFlight 上传或 iOS release asset。
- 新增 iOS MITM certificate lifecycle design，定义后续 CA generation、installation prompt、user trust confirmation、`fingerprint_sha256` 校验、expiration/revocation 检测、`CertificateTrustState` mapping、`IosMitmCertificateProbe`/`MitmCertificateStatus` 映射和 GitHub Actions `macos-26` 上的 `swift test`/`xcodebuild` 验证入口；CI governance 现在静态检查该设计，仍不引入 Swift/Xcode project、Network Extension target、configuration profile、CA certificate、private key、entitlement、签名、TestFlight 上传或 iOS release asset。
- 新增 iOS embedded runtime FFI boundary design，定义后续 Rust `staticlib`/XCFramework、`networkcore_ios_*` C ABI symbol、ABI/schema version negotiation、owned string/buffer、opaque runtime handle、panic boundary、error mapping、`IosEmbeddedRuntimeProbe` 映射和 GitHub Actions `macos-26` 上的 `cargo build`/`swift build`/`swift test`/`xcodebuild` 验证入口；CI governance 现在静态检查该设计，仍不引入 Rust FFI crate、Swift/Xcode project、Network Extension target、entitlement、签名、TestFlight 上传或 iOS release asset。
- 新增 iOS Swift/Xcode bridge source contract，定义后续 `Package.swift`、`NetworkCorePacketTunnel`、`PacketTunnelProvider.swift`、`IosPlatformSnapshotDTO`、FFI/DTO handoff、GitHub Actions `macos-26` 上的 `swift build`/`swift test`/`xcodebuild` 验证入口和 signing/provisioning secret 禁止提交规则；CI governance 现在静态检查该合同，仍不引入 Swift/Xcode project、Network Extension target、entitlement、签名、TestFlight 上传或 iOS release asset。
- 新增 iOS Swift/Network Extension bridge design，定义后续 Apple SDK 层如何采集 `NEPacketTunnelProvider`、`NETunnelProviderManager`、App Group、Keychain、embedded runtime 和 MITM 证书状态事实，去敏后映射为 `IosPlatformSnapshot`、`IosNetworkExtensionProbe`、`IosSharedStorageProbe`、`IosEmbeddedRuntimeProbe`、`IosMitmCertificateProbe` 与稳定 `platform.ios.*` diagnostics；CI governance 现在静态检查该设计，仍不引入 Swift/Xcode project、Network Extension target、entitlement、签名、TestFlight 上传或 iOS release asset。
- 新增最小 `platform-ios` crate，提供纯 Rust `StaticIosPlatformCapabilityService`、`IosPlatformSnapshot`、Network Extension/VPN/embedded runtime/MITM certificate/shared storage probe、稳定 `platform.ios.*` diagnostic code 和合同测试；CI governance 现在检查 crate README、workspace 成员、核心源码类型和 iOS 合同测试，仍不引入 Swift/Xcode project、Network Extension target、签名、TestFlight 上传或 iOS release asset。
- 新增 iOS platform adapter source contract，定义 `platform-ios` crate 的纯 Rust source layout、`StaticIosPlatformCapabilityService`/`IosPlatformSnapshot` 规划、`PlatformCapabilityService`/`PlatformCapabilityStatus` 映射、Network Extension entitlement 和 VPN authorization 诊断、MITM 证书状态读取边界、remote script 禁用策略、`macos-26` GitHub Actions 验证入口和 iOS release 阻断条件；CI governance 现在静态检查该合同，仍不引入 Swift/Xcode project、签名或 iOS release asset。
- 新增 iOS Network Extension design，定义 `NEPacketTunnelProvider`/`NETunnelProviderManager` 拓扑、配置下发、App Group/Keychain secret 边界、`PlatformCapabilityService`/`MitmCertificateStatus` 映射、MITM 证书信任、远程脚本禁用、App Review 风险和 `macos-26` GitHub Actions 验证入口；CI governance 现在静态检查该设计，仍不引入 Swift/Xcode project、iOS 签名、TestFlight 上传或 release asset。
- 新增 `mitm-anixops-sys` crate 和 `third_party/mitm_anixops` submodule，Rust CI 现在在 Linux/macOS/Windows Rust build/test 矩阵中编译 vendored `mitm_anixops` C core，并通过 `linked_c_core_reports_pinned_version` 测试调用 `anixops_version()` 验证 NetworkCore 已链接该 C ABI；Windows Rust CI 切换到 GNU target 并安装 MSYS2 MINGW64 `libsystre` 以满足 POSIX regex 依赖。
- 新增 `mitm_anixops` adapter 设计，定义该 C ABI core 在 NetworkCore 中的接入边界、`mitm-anixops-sys`/`mitm-policy` crate 规划、`MitmPluginService` adapter 阶段、真实 rewrite 前的领域 plan 门槛、`engine-native` HTTP/TLS 数据面门槛和 Linux/macOS/Windows/iOS platform adapter 责任，明确在 CI/CD 证明前不得宣称完整全平台 MITM 可用。
- 新增 Release CI gate API implementation plan，定义 `release-ci-gate` 启用 `actions: read` 后的 workflow runs API endpoint、workflow jobs API endpoint、same-sha/main/success run 选择规则、`CI summary` job 校验、输出字段和失败回滚边界；该计划现在由 active API read 实现消费，继续不定义 `package-linux` 或上传 Linux release asset。
- 新增 Release CI gate execution validation contract，定义 release workflow 必须自动读取同 repository、同 commit、`main` 成功 CI run 的 API 字段、`actions: read` 权限、CI summary 成功校验、manual input blocked 和失败边界；`release-ci-gate`、`linux-artifact-readiness`、release placeholder 与 release summary 现在输出 execution active status、required permission、queried API status、same-release-sha、required fields、CI summary success、`package-linux` not-defined 和 release asset blocked 字段，继续不定义 `package-linux` 或上传 Linux release asset。
- 新增 Linux package publish eligibility execution validation contract，定义未来 release notes/rollback execution 完成后必须聚合全部 required gates、校验 `package_publish_eligibility_status=eligible` 前的 required fields、拒绝 missing/unknown/blocked gates 和 publish without eligible；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出 publish eligibility execution blocked status、required job、upstream job、required gates、eligible status field、publish blocking、release asset blocked 和 next action，继续不定义 `publish-eligibility-gate`、`publish-github-release` 或上传 Linux release asset。
- 新增 Linux package release notes/rollback execution validation contract，定义未来 attestation/provenance 完成后必须校验 release notes required fields、rollback required fields、withdrawal-not-overwrite、new-version-tag-required、缺失 rollback summary 阻断和 publish without release notes/rollback 阻断；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出 release notes/rollback execution blocked status、required job、upstream attestation job/status、release notes/rollback fields、withdrawal/replacement policy、publish blocking 和 next action，继续不定义 `post-release-summary`、不创建 GitHub Release 或上传 Linux release asset。
- 新增 Linux package artifact attestation execution validation contract，定义未来 `attest-linux` job 必须从同一 release run workflow artifact bundle 对 archive、archive checksum、manifest 和 manifest checksum 四个 explicit subject files 生成 GitHub artifact attestation/provenance，固定 `actions/attest`、required permissions、blocked action/status、旧 run/外部 artifact 拒绝和 release asset upload blocked 边界；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出 artifact attestation execution blocked status、download source、bundle name、subjects、permissions、attestation/provenance status 和 next action，继续不定义 `attest-linux`、不启用 attestation permissions 或上传 Linux release asset。
- 新增 Linux package workflow artifact bundle upload validation contract，定义未来 `package-linux` job 在 manifest checksum sidecar 完成后必须校验 `dist/linux/${target}/artifacts` 中 archive、archive checksum、manifest 和 manifest checksum 四文件集合，固定同一 release run workflow artifact bundle 名称、retention days、`actions/upload-artifact` blocked 状态和 release asset upload blocked 边界；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出 workflow artifact bundle upload blocked status、source dir、bundle name、required files、same-run requirement、upload action 和 next action，继续不定义 `package-linux`、不上传 workflow artifact 或 Linux release asset。
- 新增 Linux package artifact manifest checksum validation contract，定义未来 `package-linux` job 在 manifest JSON 稳定写入后必须使用 `sha256sum` 计算 `networkcore-linux-${version}-${target}.manifest.json.sha256`、写入 two-space manifest checksum record、校验 manifest checksum sidecar 路径和格式，并继续阻断 workflow artifact/release asset upload；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出 manifest checksum blocked status、algorithm、manifest/checksum name/path、record format 和 next action，继续不定义 `package-linux`、不生成 manifest checksum 文件或上传 Linux release asset。
- 新增 Linux package artifact manifest generation validation contract，定义未来 `package-linux` job 在 archive checksum sidecar 写入后生成 `networkcore-linux-${version}-${target}.manifest.json` 前必须满足的 schema version、artifact kind、manifest name/path、必需 JSON 字段、archive/checksum 交叉引用、失败条件和 manifest checksum/upload blocked 边界；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出 manifest generation blocked status、schema/package fields、manifest/archive/checksum name/path、required fields、cross-check fields 和 next action，继续不定义 `package-linux`、不写 manifest 或上传 Linux release asset。
- 新增 Linux package artifact checksum execution validation contract，定义未来 `package-linux` job 在 archive 创建后必须使用 `sha256sum` 计算 `networkcore-linux-${version}-${target}.tar.gz.sha256`、写入 two-space checksum record、校验 checksum 值格式和 checksum sidecar 路径，并继续阻断 manifest/upload；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出 checksum execution blocked status、algorithm、archive/checksum name/path、record format 和 next action，继续不定义 `package-linux`、不生成 checksum 文件或上传 Linux release asset。
- 新增 Linux package artifact archive creation validation contract，定义未来 `package-linux` job 在 staging file 校验通过后创建 `networkcore-linux-${version}-${target}.tar.gz` 前必须满足的 archive name/path、`tar.gz` 格式、单顶层目录、required files、失败条件和 checksum/manifest/upload blocked 边界；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出 archive creation blocked status、output dir、top-level dir、archive name/path、required files 和 next action，继续不定义 `package-linux`、不创建 archive 或上传 Linux release asset。
- 新增 Linux package artifact staging file validation contract，定义未来 `package-linux` job 在 build output 通过后复制 `bin/networkcore-linux`、`INSTALL.md`、`LICENSE`/可选 `NOTICE` 和 `CHANGELOG.md` 进入 staging 目录前必须满足的来源、目标路径、binary `0755` 权限、失败条件和 archive/upload blocked 边界；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出 staging file blocked status、binary source/destination/permission、install doc、license/changelog source 和 next action，继续不定义 `package-linux`、不创建 archive 或上传 Linux release asset。
- 新增 Linux package artifact build command validation contract，定义未来 `package-linux` job 在 preflight 通过后必须使用的 target 安装策略、`cargo build --locked --release --package networkcore-linux --bin networkcore-linux --target x86_64-unknown-linux-gnu` 命令、binary path 校验和 upload blocked 边界；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出 build command blocked status、target install blocked、cargo args、binary path 和 next action，继续不定义 `package-linux` 或上传 Linux release asset。
- 新增 Linux package artifact job preflight validation contract，定义未来 `package-linux` job 在真实加入 release workflow 前必须满足的 `needs`、license/NOTICE confirmed、release CI gate active、checkout SHA、Rust toolchain、build output、staging root 和 upload blocked 前置顺序；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出 preflight blocked status、required job、required needs、checkout/toolchain/build/staging blocked 和 next action，继续不定义 `package-linux` 或上传 Linux release asset。
- 新增 Linux package release CI gate activation validation contract，定义 `release-ci-gate` 从 placeholder 切换到自动读取同 commit 成功 CI 前必须具备的 `actions-read` 权限、GitHub Actions runs API 查询字段、same-release-sha 校验和失败条件；`release-ci-gate`、`linux-artifact-readiness`、release placeholder 与 release summary 现在输出 activation active status、required permission、queried API status、package-linux not-defined 和 artifact blocked 字段，继续不定义 `package-linux` 或上传 Linux release asset。
- 新增 Linux package license/NOTICE transition validation contract，定义首个 Linux artifact 从 pending 切换到 confirmed 时必须使用的独立人工确认提交字段、`LICENSE`/可选 `NOTICE` 文件存在性检查、artifact files 清单、release workflow future confirmed marker 校验和当前 blocked-pending 状态；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出 transition blocked status、required commit、future confirmed marker、license file check 和 next action，继续不定义 `package-linux` 或上传 Linux release asset。
- 新增 Linux package publish eligibility aggregate contract，汇总首个 Linux artifact 的 license/NOTICE、同 commit CI、runner/toolchain、archive/checksum/manifest、publish/upload、signing/attestation、release notes/rollback eligible/blocked 状态；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出 aggregate blocked status、blocking reason、required gates 和 next action，继续不定义 `package-linux`、`publish-github-release`、`post-release-summary` 或上传 Linux release asset。
- 新增 Linux package release notes/rollback policy binding contract，定义首个 Linux artifact 的 release notes required fields、manual-extract rollback policy、withdrawal-not-overwrite、new-version-tag replacement policy、blocked status 和 publish without rollback 阻断；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出该合同字段，继续不定义 `package-linux`、`publish-github-release`、`post-release-summary` 或上传 Linux release asset。
- 新增 Linux package signing/attestation policy binding contract，定义首个 Linux artifact 的 `unsigned-no-detached-signature` 签名策略、GitHub artifact attestation/provenance required 策略、attestation subjects、provenance reference、blocked status 和 publish without attestation 阻断；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出该合同字段，继续不定义 `package-linux`、`attest-linux`、`sign-linux`、`publish-github-release` 或上传 Linux release asset。
- 新增 Linux package publish/upload boundary contract，定义真实 `package-linux` 前必须遵守的 workflow artifact bundle 名称、upload source dir、required files、retention days、publish job/download source、release asset set、禁止覆盖策略和 blocked status；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出该合同字段，继续不定义 `package-linux`、`publish-github-release` 或上传 Linux release asset。
- 新增 Linux package checksum/manifest checksum contract，定义真实 `package-linux` 前必须使用的 `networkcore-linux-${version}-${target}.tar.gz.sha256`、`networkcore-linux-${version}-${target}.manifest.json`、`networkcore-linux-${version}-${target}.manifest.json.sha256` sidecar 文件命名与路径、`sha256` 计算顺序、checksum record 格式和 manifest 交叉校验字段；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出该合同字段，继续不定义 `package-linux` 或生成 Linux release asset。
- 新增 Linux package archive staging contract，定义真实 `package-linux` 前必须声明的 `dist/linux/${target}` dist dir、staging root、`networkcore-linux-${version}-${target}` 顶层目录、archive output/path、`bin/networkcore-linux` binary archive path、`INSTALL.md` 文档、license/NOTICE confirmed 来源和 `CHANGELOG.md` 文件来源；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出该 archive staging 合同字段，继续不定义 `package-linux` 或生成 Linux release asset。
- 新增 Linux package runner/toolchain/target contract，定义真实 `package-linux` 前必须声明的 `ubuntu-latest` GitHub-hosted runner、Rust `stable`/`minimal` toolchain、`x86_64-unknown-linux-gnu` target triple、`apps/linux-cli` crate、`networkcore-linux` binary、`tar.gz` package format、manual-extract install model 和 no system mutation policy；`linux-artifact-readiness`、release placeholder 与 release summary 现在输出该平台输入合同字段，继续不定义 `package-linux` 或生成 Linux release asset。
- 新增 Release CI success source contract，定义真实 `package-linux` 或其他 artifact job 前必须从 GitHub Actions 读取的同 repository、同 commit、`main` 分支、`completed`/`success` CI run/source 字段；`release-ci-gate` 现在 checkout 仓库、检查该合同，并在 placeholder summary 与 release summary 中输出 `ci_workflow_name`、`ci_workflow_file`、`ci_run_id`、`ci_run_attempt`、`ci_run_url`、`ci_run_status`、`ci_run_conclusion`、`ci_head_sha`、`ci_head_branch`、`ci_event`、`ci_repository` 和 `ci_checked_at` required fields，继续不定义 `package-linux` 或生成 Linux release asset。
- 在 release placeholder summary 中补充 Linux artifact license/NOTICE source contract 状态；`release-placeholder` 现在 checkout 仓库并读取 `docs/manual-intervention.md` 中的 `linux-artifact-license-notice-status=pending`、source contract、`package-linux=blocked` 和 release asset blocked marker，GitHub Step Summary 会输出 source contract、source of truth、pending 状态和 blocked 状态，CI governance 与 `linux-artifact-readiness` 静态检查该 placeholder summary 标识，继续不定义 `package-linux` 或生成 Linux release asset。
- 新增 Linux artifact license/NOTICE confirmation source contract，定义 `docs/manual-intervention.md` 中 pending/confirmed 机器字段、当前 `linux-artifact-license-notice-status=pending` marker、confirmed 后的最小人工确认字段、release readiness 读取边界和 manifest 映射要求；CI governance 与 `linux-artifact-readiness` 现在检查该合同和 pending marker，继续拒绝在 license/NOTICE 与 artifact 门禁完成前定义 `package-linux` 或生成 Linux release asset。
- 在 release placeholder summary 中补充 Linux artifact manifest output contract 摘要；`release-placeholder` 和 `release-summary` 现在显式列出 `artifact_manifest_name`、`artifact_manifest_path`、`artifact_manifest_checksum_file` 和 `artifact_manifest_checksum_value`，CI governance 与 `linux-artifact-readiness` 静态检查该 summary 标识，继续拒绝在 license/NOTICE 与 artifact 门禁完成前定义 `package-linux` 或生成 Linux release asset。
- 新增 Linux package artifact manifest 设计，定义未来 `package-linux` 必须输出 sidecar `networkcore-linux-${version}-${target}.manifest.json`、manifest checksum、archive/checksum/manifest job outputs、JSON schema version、target/version/commit/CI/release metadata、安装模型、system mutation policy、signing/attestation/provenance 状态、回滚字段和文件清单边界；CI governance 与 `linux-artifact-readiness` 现在检查该设计存在和关键 manifest 输出字段，但继续拒绝在 license/NOTICE 与 artifact 门禁完成前定义 `package-linux` 或生成 Linux release asset。
- 在 release workflow 的 `linux-artifact-readiness` gate 中纳入 `networkcore-linux start` foreground stop/release 合同检查；placeholder release 现在静态检查 CLI source cleanup 函数、当前进程内 `stop_runtime` 调用、`cli.linux.start.runtime_stop_failed`、native `engine.native.runtime.accept_loop_stopped`/`engine.native.runtime.released` 诊断和对应合同测试，并显式拒绝在 license/NOTICE 与 artifact 门禁完成前定义 `package-linux` job 或生成 Linux release asset。
- 为 `networkcore-linux start` 前台 interruption 后的 runtime stop/release 诊断聚合补充显式合同；foreground host 返回 `Interrupted` 后会通过当前进程内 `RuntimeOrchestrator::stop_runtime` 停止已启动的 native runtime，聚合 `engine.native.runtime.accept_loop_stopped` 与 `engine.native.runtime.released` 释放诊断，stop 失败时追加稳定 `cli.linux.start.runtime_stop_failed` 诊断，并继续保持 `stop` 命令和后台 `status` 无 daemon/control socket 边界；合同测试覆盖真实 native accept loop 释放、端口可复用和 stop 失败映射。
- 为 `networkcore-linux start` 的 current-process foreground lifecycle 接入真实 Unix OS signal source；默认 `CurrentProcessForegroundLifecycleHost::new()` 在 Unix 上监听 `SIGINT`/`SIGTERM`，将收到的 OS signal 映射为 `cli.linux.start.signal_received` source 诊断、既有 `cli.linux.start.lifecycle_interrupted` warning 和 130 退出码，非 Unix 构建继续保留 parking fallback，并继续保持无 daemon/control socket 边界；合同测试覆盖 SIGINT/SIGTERM 到稳定 interruption 诊断的纯映射。
- 为 `networkcore-linux start` 前台 lifecycle host 新增 signal/interruption 处理源码合同；`CurrentProcessForegroundLifecycleHost` 现在可注入 `ForegroundLifecycleInterruptionSource`，将 interruption 映射为 `cli.linux.start.lifecycle_interrupted` warning 诊断和 130 退出码，并保留 current-process 前台持有的无 daemon/control socket 边界；合同测试覆盖 interruption source 诊断聚合、`cli.linux.start.foreground_only` 保留和 `Interrupted` exit code。
- 将 `networkcore-linux start` binary 接入 `NativeProxyEngineService` 与前台 lifecycle host；二进制入口现在组合 `CoreConfigurationService`、只读 Linux platform service、原生 engine service 和 current-process lifecycle host，`start` 可从有效 listener/node 配置启动当前进程内 loopback TCP accept loop 并进入前台持有路径；合同测试覆盖 `engine.native.start.running`、`engine.native.runtime.foreground_handoff_ready`、`engine.native.runtime.accept_loop_ready` 与 `cli.linux.start.foreground_only` 诊断聚合，`stop` 和后台 `status` 继续保持无 daemon/control socket 边界。
- 在 `engine-native` 中新增 service-owned runtime state 与 foreground lifecycle handoff 源码合同；`NativeProxyEngineService` 现在持有当前进程内的 `NativeRuntimeHandle`，`start` 会从有效配置启动 loopback TCP accept loop 并返回 `engine.native.start.running`、`engine.native.runtime.foreground_handoff_ready` 和 `engine.native.runtime.accept_loop_ready`，重复 `start` 在 runtime 运行中保持幂等，`status`/`events`/`stop` 可观察和释放 runtime，停止路径记录 `engine.native.runtime.accept_loop_stopped` 与 `engine.native.runtime.released`；`networkcore-linux start` binary 继续保持未接线。
- 在 `engine-native` 中新增 service start readiness gate 诊断合同；该增量当时让 `assess_native_proxy_engine_start_readiness` 先复用结构化配置校验，再确认有效配置可生成 native runtime assembly plan 并记录 `engine.native.start.runtime_assembly_ready`，随后用 `engine.native.start.service_runtime_owner_missing` 明确阻断 `NativeProxyEngineService::start` 返回 `Running`，因为 service-owned runtime state 与 foreground lifecycle handoff 尚未接线；`networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT accept loop client success response 与 data relay 接线诊断合同；上游 CONNECT response accepted 后，accept loop 现在记录 relay/data relay/client success response/write plan ready 诊断，写入 client success response frame，随后对有限 TCP stream 执行 client-to-outbound 与 outbound-to-client relay 并记录 `engine.native.runtime.socks5_outbound_connect_data_relay_completed` 或失败诊断；上游 rejected、连接失败或 plan 不完整路径继续写 CONNECT general failure response；`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT data relay 执行诊断合同，`relay_socks5_outbound_connect_data` 可在源码合同边界对有限 `Read`/`Write` stream 执行 client-to-outbound 与 outbound-to-client 复制，返回双向字节数并记录 `engine.native.runtime.socks5_outbound_connect_data_relay_completed` 或 `engine.native.runtime.socks5_outbound_connect_data_relay_failed`；该增量当时仍未接入 accept loop，`NativeProxyEngineService::start` 与 `networkcore-linux start` 保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT client success response write 诊断合同，`write_socks5_outbound_connect_client_success_response` 会基于有效的上游 SOCKS5 CONNECT success response 生成并写入 client success response frame，记录 `engine.native.runtime.socks5_outbound_connect_client_success_response_written` 或 `engine.native.runtime.socks5_outbound_connect_client_success_response_write_failed`；该增量当时仍保持源码合同和单元合同测试边界，双向数据转发、`NativeProxyEngineService::start` 与 `networkcore-linux start` 保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT client success response write plan 诊断合同，`plan_socks5_outbound_connect_client_success_response_write` 覆盖 client success response readiness 的 blocked/rejected 诊断边界；该增量当时仍不写入 SOCKS5 success response、不进行双向数据转发，`NativeProxyEngineService::start` 与 `networkcore-linux start` 保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT client success response readiness 诊断合同，`assess_socks5_outbound_connect_client_success_response_readiness` 覆盖 data relay plan 的 blocked/rejected 诊断边界；该增量当时仍不写入 client success response、不进行双向数据转发，`NativeProxyEngineService::start` 与 `networkcore-linux start` 保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT data relay plan 诊断合同，`plan_socks5_outbound_connect_data_relay` 覆盖 relay readiness 的 blocked/rejected 诊断边界；该增量当时仍不写入 client success response、不进行双向数据转发，`NativeProxyEngineService::start` 与 `networkcore-linux start` 保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT relay readiness 诊断合同，`assess_socks5_outbound_connect_relay_readiness` 覆盖 accepted/rejected 上游 CONNECT response 的 relay readiness 诊断边界；该增量当时仍不写入 client success response、不进行双向数据转发，`NativeProxyEngineService::start` 与 `networkcore-linux start` 保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT response decision 诊断合同，`decide_socks5_outbound_connect_response` 将上游 success reply 归类为 accepted，将非成功或 invalid response 归类为 rejected，并记录 `engine.native.runtime.socks5_outbound_connect_response_accepted` 或 `engine.native.runtime.socks5_outbound_connect_response_rejected`；该增量当时在 response read 后记录 decision，随后仍记录 route/outbound 未接入、向 client 写入 CONNECT general failure response 并关闭 accepted/outbound 连接；SOCKS outbound relay readiness、双向数据转发、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 当时保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT response read 诊断合同，`read_socks5_outbound_connect_response` 读取上游 SOCKS5 response header、bound address 和 bound port，并记录 `engine.native.runtime.socks5_outbound_connect_response_read`、`engine.native.runtime.socks5_outbound_connect_response_invalid` 或 `engine.native.runtime.socks5_outbound_connect_response_read_failed`；该增量当时在 outbound CONNECT request 写入成功后读取上游响应，随后仍记录 route/outbound 未接入、向 client 写入 CONNECT general failure response 并关闭 accepted/outbound 连接；SOCKS outbound CONNECT response decision、双向数据转发、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 当时保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT request write 诊断合同，`write_socks5_outbound_connect_request` 将 connection plan 中已生成的 request frame 写入可用 outbound TCP stream，并记录 `engine.native.runtime.socks5_outbound_connect_request_written` 或 `engine.native.runtime.socks5_outbound_connect_request_write_failed`；该增量当时在 outbound TCP connection attempt 成功后写入上游 SOCKS5 CONNECT request，随后仍记录 route/outbound 未接入、向 client 写入 CONNECT general failure response 并关闭 accepted/outbound 连接；SOCKS outbound CONNECT response 读取、双向数据转发、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 当时保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound TCP connection attempt 诊断合同，`attempt_socks5_outbound_tcp_connection` 基于 connection plan 对 IP endpoint 执行有界 `TcpStream::connect_timeout`，并记录 `engine.native.runtime.socks5_outbound_tcp_connection_attempt_succeeded` 或 `engine.native.runtime.socks5_outbound_tcp_connection_attempt_failed`；该增量当时在 plan 生成后尝试 outbound TCP 连接，随后仍记录 route/outbound 未接入、写入 CONNECT general failure response 并关闭 accepted connection；SOCKS outbound CONNECT request 写入、双向数据转发、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 当时保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound TCP connection plan 诊断合同，`plan_socks5_outbound_tcp_connection` 基于 `ProxyViaSocksOutbound` 与 request frame 记录 outbound handler endpoint、CONNECT 目标和 frame，并记录 `engine.native.runtime.socks5_outbound_tcp_connection_planned` 或 `engine.native.runtime.socks5_outbound_tcp_connection_plan_invalid`；该增量当时在 frame 生成后创建 plan 诊断，随后仍记录 route/outbound 未接入、写入 CONNECT general failure response 并关闭连接；真实 outbound TCP connection attempt、数据转发、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 当时保持未接线。
- 在 `engine-native` 中新增 SOCKS5 outbound CONNECT request frame 生成诊断合同，`build_socks5_outbound_connect_request_frame` 可为 IPv4、domain 和 IPv6 CONNECT 目标生成上游 SOCKS5 request frame，并记录 `engine.native.runtime.socks5_outbound_connect_request_frame_generated` 或 `engine.native.runtime.socks5_outbound_connect_request_frame_invalid`；该增量当时在 route/outbound 行为选择后生成该 frame 的诊断，随后仍记录 route/outbound 未接入、写入 CONNECT general failure response 并关闭连接；真实 outbound TCP 连接、数据转发、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 当时保持未接线。
- 在 `engine-native` 中新增 SOCKS5 CONNECT route/outbound 行为选择诊断合同，accept loop 会在有效 no-auth CONNECT 目标后用当前配置的 SOCKS outbound handler 生成 `NativeSocks5RouteOutboundBehavior::ProxyViaSocksOutbound` 并记录 `engine.native.runtime.socks5_route_outbound_selected`；该增量当时随后仍记录 `engine.native.runtime.socks5_route_outbound_unwired`、写入 CONNECT general failure response 并关闭连接；真实 outbound TCP 连接、SOCKS outbound request frame、数据转发、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 当时保持未接线。
- 在 `engine-native` 中新增 SOCKS5 route/outbound 未接入时的 CONNECT failure response 写入诊断合同，accept loop 会在有效 no-auth CONNECT 目标后记录 `engine.native.runtime.socks5_route_outbound_unwired`，写入 `[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]` 并记录 `engine.native.runtime.socks5_connect_failure_response_written` 或 `engine.native.runtime.socks5_connect_failure_response_write_failed`，随后关闭连接；该增量当时仍没有 route/outbound 行为选择、route/outbound 数据面、SOCKS5 success response 写入、`NativeProxyEngineService::start` 与 `networkcore-linux start` 接线。
- 在 `engine-native` 中新增 SOCKS5 CONNECT 目标地址读取与 route/outbound 未接入拒绝诊断合同，accept loop 会在 no-auth CONNECT 命令头后读取 IPv4、domain 或 IPv6 目标地址和端口并记录 `engine.native.runtime.socks5_connect_target_read`、`engine.native.runtime.socks5_connect_target_invalid` 或 `engine.native.runtime.socks5_connect_target_read_failed`，随后记录 `engine.native.runtime.socks5_route_outbound_unwired` 并关闭连接；该增量当时仍不写入 SOCKS5 failure response，route/outbound 数据面、`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 命令头读取与 unsupported command 拒绝诊断合同，accept loop 会在 no-auth 响应写入后读取 `[VER, CMD, RSV, ATYP]` 命令头并记录 `engine.native.runtime.socks5_command_header_read`、`engine.native.runtime.socks5_command_header_invalid` 或 `engine.native.runtime.socks5_command_header_read_failed`，对非 CONNECT 命令记录 `engine.native.runtime.socks5_command_unsupported`；该增量当时仍关闭连接且不解析 CONNECT 目标地址、不进入 route/outbound 数据面，`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 认证方法响应写入诊断合同，accept loop 会在 auth 方法选择后写入 `[0x05, method]` 响应并记录 `engine.native.runtime.socks5_auth_method_response_written` 或 `engine.native.runtime.socks5_auth_method_response_write_failed`；该增量当时仍关闭连接且不解析 SOCKS5 命令、不进入 route/outbound 数据面，`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 SOCKS5 no-auth 方法选择与 unsupported auth 方法拒绝诊断合同，accept loop 会在读取有效 greeting 后记录 `engine.native.runtime.socks5_auth_method_selected` 或 `engine.native.runtime.socks5_auth_method_unsupported`；该增量当时仍关闭连接且不写入 SOCKS5 方法响应、不进入 route/outbound 数据面，`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增首个 SOCKS5 greeting 版本/认证方法读取诊断合同，accept loop 会在 accepted loopback TCP connection 上读取 greeting 并记录 `engine.native.runtime.socks5_greeting_read`、`engine.native.runtime.socks5_greeting_invalid` 或 `engine.native.runtime.socks5_greeting_read_failed` 诊断，随后仍关闭连接且不进入 route/outbound 数据面；`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 accepted TCP connection 的协议前置关闭诊断合同，accept loop 会在完整 proxy protocol 尚未实现时显式关闭连接并记录 `engine.native.runtime.connection_pre_protocol_closed` 诊断和计数；完整 proxy protocol 解析、route/outbound 数据面、`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增首个 loopback TCP accept loop 源码合同，覆盖受控关闭、accepted connection 计数、runtime release 停止报告和 accept loop ready/stopped 诊断；完整 proxy protocol、route/outbound 数据面、`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 `NativeRuntimeAssemblyPlan`，可从有效 listener/node/route 配置图选择 loopback TCP listener 与 SOCKS outbound handler，并将绑定失败或 lifecycle handoff 失败映射为带资源释放报告的 startup failure；`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增真实 loopback TCP listener 绑定/释放实现，runtime assembly 可持有并释放当前进程内的 listener resource，覆盖绑定失败和端口释放合同测试；`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增首个 native runtime handle 源码合同，覆盖 loopback listener handle、SOCKS outbound handler handoff、启动失败释放报告、runtime events 和 foreground lifecycle handoff status；`NativeProxyEngineService::start` 与 `networkcore-linux start` 继续保持未接线。
- 在 `engine-native` 中新增 listener/node/route 结构化图校验，明确 `ConfigSnapshot.nodes` 与运行请求 nodes 的合并和重复 id 拒绝边界；`networkcore-linux start` 继续保持未接线。
- 在 `config-core` 中解析最小 listener/node/route TOML 子集，将本地 nodes 标准化进 `ConfigSnapshot`，并补充稳定诊断合同测试；`networkcore-linux start` 继续保持未接线。
- 在 `control-domain` 中新增 listener 配置领域类型，将 `ConfigSnapshot` 扩展为显式携带 listeners，并补充合同测试；`networkcore-linux start` 继续保持未接线。
- 新增 Native engine listener/node 配置设计文档，定义原生 runtime handle 前的 listener、node、route、DNS 图、诊断 code 和源码接线门槛，并纳入 CI/release readiness governance；`networkcore-linux start` 继续保持未接线。
- 新增 `networkcore-linux` 前台 lifecycle host 源码合同，覆盖 running handoff、默认 unavailable host、非 running 拒绝和诊断聚合；二进制入口的 `start` 继续保持未接线。
- 新增最小 `engine-native` crate，提供原生 `ProxyEngineService` descriptor、配置拒绝、生命周期诊断和 secret 不泄露合同测试；`networkcore-linux start` 继续保持未接线。
- 新增 Linux native proxy engine start 设计文档，明确首个原生 `ProxyEngineService` adapter、前台 lifecycle host、`networkcore-linux start` 接线门槛和继续保持未接线诊断的条件。
- 新增最小 `config-core` crate，提供纯 TOML 配置服务、schema/profile 解析、secret 不泄露诊断合同测试，并将 `networkcore-linux prepare-config` 接入二进制入口；`start` 继续保持未接线诊断。
- 新增 Linux CLI runtime wiring 设计文档，明确 `prepare-config`/`start` 接入运行层前的配置服务、代理引擎服务和前台生命周期 host 边界，并纳入 CI governance 检查。
- 将 `networkcore-linux capabilities/status/diagnostics` 接入 `HostLinuxReadOnlyProbe`，通过 `PlatformCapabilityService` 输出只读 Linux 平台诊断，并保留 `start` 等运行层命令未接线诊断。
- 在 `platform-linux` 中新增只读 Linux 平台探测服务，提供 `HostLinuxReadOnlyProbe`、可注入 probe 边界、TUN/权限/DNS/service 诊断映射和 `/proc/self/status` 解析合同测试。
- 补充 release workflow 的 `linux-artifact-readiness` job，检查 Linux CLI 源码、platform adapter、安装/回滚设计和 license/NOTICE 人工事项，并继续阻止 release asset 上传。
- 新增 Linux CLI artifact 安装、卸载与回滚设计文档，明确首个 `networkcore-linux` 压缩包的手动解压模型、卸载清单、用户侧回滚和 `package-linux` 前置门禁。
- 补充真实 release artifact 前的 license 或 NOTICE 文本人工确认事项。
- 新增最小 `networkcore-linux` CLI crate，提供命令解析、配置读取抽象、平台能力/status/stop/start 诊断映射和 JSON 输出合同测试。
- 新增最小 `platform-linux` crate，提供 `PlatformCapabilityService` 静态测试替身、Linux 诊断 code 常量和 TUN、权限、DNS、服务管理、证书状态映射合同测试。
- 新增 Linux CLI entrypoint 设计文档，明确首个 `networkcore-linux` 入口的命令、配置加载、启动/停止、状态查询、输出和退出码边界。
- 新增 Linux platform adapter 设计文档，定义 TUN、权限、DNS、服务管理、证书和诊断探测边界。
- 新增 Linux artifact 发布前设计文档，明确首个平台产物的源码、packaging、checksum、签名/证明和回滚前置条件。
- 补充 release rollback contract 占位 job，定义真实 artifact 发布说明必须输出的回滚字段。
- 补充 release signing/attestation contract 占位 job，定义真实平台 artifact 发布前的签名或证明进入条件。
- 补充 release artifact checksum contract 占位 job，定义首个真实 artifact job 的 checksum 输出字段。
- 补充 release-ci-gate 占位 job，记录真实 artifact 前必须关联 `main` CI 成功结果。
- 补充 release workflow summary job，输出 placeholder 发布状态和后续 artifact 门禁。
- 补充 release workflow 发布来源 summary，记录 workflow_dispatch 版本输入、触发事件、ref、commit SHA 和 actor。
- 补充 release workflow 版本格式与触发来源一致性 policy gate，约束手动 placeholder release 来源和 tag 版本。
- 补充 CI summary GitHub Step Summary 表格，汇总项目类型检测开关和关键 job 结果。
- 补充 CI summary 项目类型检测输出，每次记录 Go、Rust、Node、Swift 和 Apple 检测开关。
- 补强 CI summary Go、Node、Swift 和 Apple 条件门禁，显式输出并在对应项目出现时检查语言与平台 job 结果。
- 补强 CI summary Rust 门禁，显式输出并检查 Rust build/test 矩阵结果和 Rust dependency security audit 结果。
- 补充 `control-runtime` MITM gate 权限拒绝诊断顺序合同测试，覆盖平台、证书、manifest 非错误诊断和 runtime 权限拒绝诊断按聚合顺序输出。
- 补充 `control-runtime` MITM gate manifest 错误拒绝诊断顺序合同测试，覆盖平台、证书、manifest 和 runtime 诊断按聚合顺序输出。
- 补充 `control-runtime` MITM gate manifest 错误优先于权限拒绝合同测试，覆盖 manifest 错误会在缺失权限前短路并返回 manifest 错误拒绝原因。
- 补充 `control-runtime` MITM gate manifest 错误拒绝证书诊断保留合同测试，覆盖证书诊断会保留在 manifest 错误拒绝决策输出中。
- 补充 `control-runtime` MITM gate manifest 错误拒绝平台诊断保留合同测试，覆盖平台诊断会保留在 manifest 错误拒绝决策输出中。
- 补充 `control-runtime` MITM gate manifest 错误拒绝审计合同测试，覆盖 manifest 错误拒绝 reason、审计和禁止调用插件 `load`/`handle_http_event`/`audit` 端口。
- 补充 `control-runtime` MITM gate 远程脚本拒绝诊断聚合合同测试，覆盖平台诊断会保留在远程脚本拒绝决策输出中。
- 补充 `control-runtime` MITM gate 证书拒绝诊断聚合合同测试，覆盖证书状态诊断会保留在证书拒绝决策输出中。
- 补充 `control-runtime` MITM gate 权限拒绝诊断聚合合同测试，覆盖 manifest 非错误诊断会保留在权限拒绝决策输出中。
- 补充 `control-runtime` MITM gate 平台诊断拒绝路径合同测试，覆盖平台能力诊断会保留在平台拒绝决策输出中。
- 补充 `control-runtime` MITM gate 平台诊断聚合合同测试，覆盖平台能力与证书诊断会进入允许决策输出。
- 补充 `control-runtime` MITM gate 插件结果诊断聚合合同测试，覆盖插件执行返回 warning/info 诊断会进入允许决策输出。
- 补充 `control-runtime` MITM gate manifest 警告诊断放行合同测试，覆盖 warning/info 诊断不会阻断插件执行且会聚合到输出。
- 补充 `control-runtime` MITM gate 权限拒绝审计合同测试，覆盖缺失权限 reason 和禁止调用插件 `load`/`handle_http_event`/`audit` 端口。
- 补充 `control-runtime` MITM gate 远程脚本未知状态合同测试，覆盖未知状态拒绝原因、诊断、审计和禁止调用插件端口。
- 补充 `control-runtime` MITM gate 证书状态拒绝矩阵合同测试，覆盖证书未安装、已安装未信任、已撤销和未知状态，并确认拒绝路径不会调用插件端口。
- 补充 `control-runtime` MITM gate 平台 MITM 不可用合同测试，覆盖平台拒绝原因和禁止调用插件端口。
- 补充 `control-runtime` MITM gate 审计事件聚合合同测试，覆盖 gate 审计、插件结果审计和 `audit` 端口审计的输出边界。
- 补充 `control-runtime` MITM gate manifest validation 合同测试，覆盖 manifest 诊断拒绝路径。
- 扩展 `control-runtime` MITM gate，新增远程脚本执行禁用拒绝路径，并覆盖插件加载与事件处理端口错误传播。
- 新增 `control-runtime` MITM gate 初始用例，组合平台能力与 MITM 插件端口，并覆盖证书未信任、权限拒绝和授权通过路径。
- 新增最小 `control-runtime` crate，组合配置、平台能力和代理引擎领域端口，并覆盖启动成功、平台拒绝和引擎错误传播路径。
- 新增运行层编排设计文档，定义 `control-runtime` 的职责、生命周期、端口组合和首个源码增量验收条件。
- 在 `control-domain` 中新增平台能力状态、MITM 证书状态和 `PlatformCapabilityService` 领域端口。
- 新增发布策略文档，定义真实平台产物进入 release workflow 前的门禁、矩阵和回滚路径。
- 新增 iOS 平台风险评估，覆盖 Network Extension、证书信任、插件脚本权限和 App Review 门禁。
- 新增 Rust dependency/security scan CI job，在 GitHub Actions 中生成 lockfile 并执行 `cargo audit`。
- 新增可插拔代理执行内核适配接口规格，并在 `control-domain` 中加入 `ProxyEngineService` 领域端口。
- 新增最小 Rust workspace 与 `control-domain` crate，提供领域共享类型、端口 trait、单元测试和集成测试。
- 新增控制内核接口草案，覆盖配置、订阅、策略路由、DNS、MITM 插件和控制 API 的首批契约。
- 新增 ADR 0001，选择 Rust 作为首个统一控制内核实现栈，并记录后续 CI/CD 验证策略。
- 新增统一控制内核领域与架构规格，定义首批上下文、端口和后续源码骨架验收条件。
- 建立 `ROADMAP.md`，明确 bootstrap、架构规格、内核骨架、运行能力和客户端集成阶段。
- 建立 `TODO.md`，记录当前最小增量待办和维护规则。
- 将规划治理文件纳入 README 与 CI policy 约束。

## 2026-07-06

### Added

- 完成 Linux systemd 订阅刷新调度切片：新增 `subscription refresh schedule install/status/stop/uninstall`，安装必须显式提供 catalog/status/snapshot 绝对路径、source ID、>=300 秒间隔、unit base name 和 `--confirm`；生成 NetworkCore-owned oneshot service 与 persistent timer，daemon-reload 后启动并验证 timer。同内容重装幂等，外部修改、非 owned unit 和不完整 pair 均拒绝覆盖或卸载；unit 不包含 URL、token、密码或节点凭据，stop/uninstall 保留最后刷新状态且不重启核心、切换节点或修改系统代理。
- 建立 bootstrap 阶段的代理规范、贡献规则、CI/CD policy、GitHub Actions skeleton 和人工介入记录。
- 完成 Linux 单 source 后台订阅刷新切片：新增显式 `subscription refresh start/status/stop`、固定 300 秒最小间隔、HTTP(S) source 限制、`--confirm` 授权、显式 catalog/status/snapshot 路径、候选 fetch 后 parse/normalize 校验、原子 catalog 替换、失败保留 catalog/选择/运行配置、脱敏状态记录和并发 active 拒绝；不重启核心、不切换节点、不修改系统设置。
