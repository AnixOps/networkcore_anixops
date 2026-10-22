# HTTP/2 MITM 与 QUIC 拒绝设计（M3）

本文是 M3「HTTP/2 MITM」切片的单一设计与验收文档，覆盖 `engine-native` 受控 TLS
会话在 TLS 终止后的 ALPN 协商、HTTP/2 服务端与上游客户端、stream 到有界改写模型的
归一化，以及对 MITM 主机名拒绝 UDP/443 的策略入口。

当前状态：源码与契约测试已就位，等待 GitHub Actions 依赖锁刷新、CI 全绿与真机验收。
`http2_mitm_supported` 与 `http3_quic_mitm_supported` 发布标记继续保持 `false`，直到
`docs/manual-intervention.md` 中「HTTP/2 and HTTP/3 MITM Dependency Lock Refresh」
记录完成。合并等 beta.5 tag 之后。

## ALPN 协商

1. CONNECT 隧道建立后，现有 ClientHello 观察器已经 `peek` 到完整 ClientHello；
   `parse_tls_client_hello_metadata` 现在同时解析 ALPN 扩展（类型 `0x0010`），
   公开入口是 `observe_tls_client_hello_alpn_protocols`。
2. 客户端没有提供 `h2` 时，行为与之前完全相同：同步 rustls、下游和上游都只提供
   `http/1.1`，进入 `run_controlled_tls_http1_exchanges`。
3. 客户端提供 `h2` 时，进入 `h2_mitm::run_controlled_tls_alpn_session`，在每会话一个的
   current-thread Tokio runtime 上：
   - 先用客户端提供的 `h2`/`http/1.1` 子集（保持客户端顺序）完成上游 TLS 握手；
   - 再把上游选中的协议作为下游唯一 ALPN 完成下游握手（上游未选 `h2` 时下游只给
     `http/1.1`）；
   - 两侧都是 `h2` 时运行 HTTP/2 数据面；两侧都是 `http/1.1` 时把 rustls 连接和
     socket 交回阻塞模式，复用原 HTTP/1.1 交换循环；两侧不一致则会话失败。
4. 不做 HTTP/2 ↔ HTTP/1.1 协议转换：客户端只会在上游也支持 `h2` 时看到 `h2`。

诊断码：`engine.native.runtime.http_proxy_tls_alpn_negotiated`。

## HTTP/2 数据面

实现位于 `crates/engine-native/src/h2_mitm.rs`，HTTP/2 framing、HPACK 与流控全部由
维护中的 `h2` crate 提供，不手写协议解析器。

- 服务端：`max_concurrent_streams=32`，header list 上限沿用 16 KiB；每个连接最多接受
  256 个 stream，之后发送 GOAWAY；无活动 stream 时按会话超时（15 秒）优雅关闭。
- 上游客户端：禁用 server push，每个下游 stream 映射到一个上游 stream。
- 每个 stream 独立任务，单 stream 上限 120 秒；插件规划与脚本派发在
  `spawn_blocking` 中执行，不阻塞连接驱动。
- `CONNECT` 方法返回 405；`:authority` 与 CONNECT 目标不一致返回 421，不联系上游、
  不进入插件。

### 归一化到有界改写模型

每个 stream 先构造与 HTTP/1.1 路径同形的 `NativeExplicitHttpProxyRequest`，再经
`explicit_http_proxy_request_to_plain_http_message` /
`plain_http_proxy_response_to_plain_http_message` 进入 `NativeHttpMitmPluginHook`：

- URL 为 `https://<CONNECT authority><path>`，与 HTTP/1.1 一致；
- header 名为小写，首项补 `host`，拆分的 `cookie` 按 RFC 9113 §8.2.3 合并为一项；
- body 完整缓冲到 64 KiB 上限后才规划改写；
- 改写结果转回 HTTP/2 时丢弃连接级 header（`connection`、`keep-alive`、
  `proxy-connection`、`transfer-encoding`、`upgrade`、`host`，以及值不是 `trailers`
  的 `te`）和插件写出的非法 header，并按改写后 body 重算 `content-length`
  （HEAD 与 304 保留原值，1xx/204 去掉）；
- 同主机的 URL 路径改写与 HTTP/1.1 一样生效，跨主机改写被忽略；
- 终止动作（reject/redirect）直接回给客户端，不联系上游；
- trailers 原样透传，满足 gRPC 的 `te: trailers` 与 `grpc-status`。

### 超限 stream 直通

请求或响应 body 超过 64 KiB（声明的 `content-length` 超限，或读取中超限），或 header
值不是 UTF-8 时，该方向不进入插件，按原 header 与 body 流式转发，并记录
`engine.native.runtime.http_proxy_h2_stream_passthrough`。不截断、不部分改写。

## UDP/443 拒绝

- `control-domain` 的 `MitmPluginService` 新增默认方法 `evaluate_mitm_hostname`，返回
  `MitmHostnameDecision::{Bypass, Intercept, RejectQuic}`；默认实现全部 `Bypass`。
- `mitm-policy` 用 `mitm_anixops` C 核心的 `anixops_mitm_evaluate(host, is_quic=1)`
  实现它；数据面只在 MITM CA 已激活时询问，因此以 trusted 证书状态评估。
- `engine-native` 提供 `plan_native_udp_mitm_decision` 与
  `NativeHttpMitmPluginHook::plan_udp_datagram`：只有 UDP/443 视为 QUIC；命中 MITM
  主机名返回 `RejectQuic`，其余放行；策略评估出错时放行并记录警告（拒绝也无法让 TCP
  回落被拦截）。
- 当前 `engine-native` 没有实时 UDP 数据路径（SOCKS5 `UDP ASSOCIATE` 仍按不支持的命令
  拒绝），系统代理模式下浏览器也不会经 HTTP 代理走 QUIC。该入口供 M2 桌面 TUN 与 M4
  iOS NE 的 UDP 路径直接调用。

## 验证

- `crates/engine-native/tests/engine_native_h2_mitm_contracts.rs`：内存双工管道上的
  请求/响应改写、reject 不联系上游、超限直通、421、trailers、stream 预算与 GOAWAY、
  ClientHello ALPN 解析、UDP/443 决策。
- `engine-native` 内的真 socket 测试：客户端与上游都走真实 TLS 时协商出 `h2` 并完成
  一次 stream；上游只支持 `http/1.1` 时回落到原 HTTP/1.1 路径。
- `mitm-policy` 契约：内置广告插件的 `*.doubleclick.net` 在 QUIC 下返回
  `RejectQuic`，TCP 下返回 `Intercept`，其他主机 `Bypass`。
- CI `HTTP/2 MITM fuzz` job（nightly + cargo-fuzz，每个 target 60 秒）：
  `tls_client_hello_alpn`、`h2_mitm_frames`（合法 preface 后任意帧字节）、
  `h2_mitm_requests`（结构化请求，内置广告插件生效，body 上限 256 字节以覆盖直通）。

## 未覆盖

- HTTP/3/QUIC MITM（设计上不做，靠拒绝 UDP/443 迫使回落）。
- HTTP/2 ↔ HTTP/1.1 转换、server push、扩展 CONNECT（WebSocket over h2）。
- 压缩 body 的解压改写；超过 64 KiB 的 body 改写。
- 证书固定的 App 仍会握手失败，不提供绕过。
