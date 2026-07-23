# Alpha Release Feature Matrix

评估时间：2026-07-23。

本文是 alpha 版本能力边界索引。发布事实以 Git tag、GitHub Actions release workflow 和
GitHub Release asset 为准；`main` 中 tag 之后的源码增量不等于用户可下载能力。未发布版本只表达
当前切片目标，不是已经发布的承诺。

## 判定规则

- 已发布版本：必须有对应 Git tag，并且真实用户能力只来自该 tag 的 GitHub Release asset。
- Source-only 增量：已合入 `main` 但尚未打 tag release 的能力，只能按源码状态描述。
- 规划版本：用于说明后续 alpha 切片边界；最终发布内容必须以新 tag、CI、package、attestation、
  publish eligibility 和 GitHub Release 结果为准。
- 浏览器劫持/live MITM 不能只凭命令名判断；必须同时具备显式授权、浏览器/系统捕获策略、可回滚
  mutation、CA lifecycle、HTTP/TLS data plane 和流量证明。

## 已发布 alpha

`v0.2.0-alpha.1` 的完整发布说明位于下方“最新已发布切片”，避免同一版本在索引中重复维护。

### `v0.1.0-alpha.1`

状态：已发布 historical placeholder。

主要特性：

- 建立 alpha 预发布编号和 release placeholder 语境。
- release summary 可记录 Windows 手工 smoke 测试状态、环境、结果和未在本机运行构建/测试的事实。

明确不包含：

- 不包含当前 Linux CLI 真实 artifact 发布路径。
- 不包含 `networkcore-linux` 可下载 Linux tarball、checksum、manifest 或 attestation。
- 不包含 sing-box adapter、订阅运行、MITM 命令面或浏览器捕获。

### `v0.1.0-alpha.2`

状态：已发布；首个真实 Linux CLI artifact release path。

主要特性：

- Linux CLI tarball 发布路径进入 GitHub Actions：`package-linux`、archive、sha256、manifest 和
  manifest sha256。
- release workflow 具备同 commit CI gate、release contract jobs、artifact readiness、attestation、
  release notes/rollback、publish eligibility 和 tag-only GitHub Release asset 上传边界。
- Linux artifact license/NOTICE marker 进入 confirmed 状态，真实 release 继续受 CI 和发布门禁约束。

明确不包含：

- 不安装 daemon/service，不修改系统代理、TUN、DNS、firewall 或证书信任。
- 不包含 sing-box latest installer、`run-url` 或 MITM/browser capture 用户能力。

### `v0.1.0-alpha.3`

状态：已发布。

主要特性：

- 固化 Public Engine Adapter First 策略：NetworkCore 控制层、`engine-*` adapter 层、公有执行内核层三层维护。
- 新增 `engine-singbox` latest release installer 方向。
- `networkcore-linux install-sing-box` / `networkcore-linux sing-box install` 可从官方 GitHub latest release
  选择目标资产、校验 digest、解压并缓存 `sing-box` 可执行文件。

明确不包含：

- 不把第三方 `sing-box` binary 打包进 NetworkCore release artifact。
- 不包含 `run-url` 前台代理闭环、managed lifecycle、daemon/status/logs/reload 或 MITM 数据面。

### `v0.1.0-alpha.4`

状态：已发布。

主要特性：

- 新增 `networkcore-linux run-url <ss://url>` foreground path。
- `CoreSubscriptionService` 可解析单条 Shadowsocks URL、明文链接列表或 base64 链接列表。
- `engine-singbox` 渲染本地 `mixed` inbound 配置，并以前台 `sing-box run -c <config>` 暴露默认本地代理
  `127.0.0.1:7890`。

明确不包含：

- 不包含持久订阅、节点选择、managed status/events/logs/reload/rollback。
- 不包含 VLESS/VMess/Trojan/Clash YAML/sing-box JSON 完整订阅兼容。
- 不包含 MITM、浏览器捕获或系统代理 mutation。

### `v0.1.0-alpha.5`

状态：已发布。

主要特性：

- 接入 `mitm_anixops v0.45.10-alpha`。
- 新增 `mitm-policy` safe wrapper、`AnixOpsMitmPluginService` 和内置 alpha 去广告插件
  `networkcore.adblock`。
- 建立 MITM policy source contract、rewrite plan/header/body chain/script/JQ guard wrapper 合同和第三方插件
  onboarding 流程。

明确不包含：

- 不包含用户可执行的 live MITM。
- 不生成、安装或信任 CA。
- 不解密 HTTPS，不把 reject/redirect/header/body/script rewrite 应用到真实 HTTP 请求/响应。
- 不包含浏览器捕获 CLI 用户闭环。

### `v0.1.0-alpha.6`

状态：已发布。

主要特性：

- `MITM_CLI_COMMAND_GATE` 进入 partial-active：`mitm status`、`mitm diagnostics`、
  `mitm certificate-plan`、`mitm browser-plan`。
- 新增浏览器捕获计划面：`mitm browser-capture plan`、`launch-plan` 和相关 blocked report。
- 新增证书计划、浏览器捕获计划、Linux MITM browser capture source contract、release state consistency
  gate 和 Linux MITM 状态命令 gate。

明确不包含：

- 不启动浏览器。
- 不安装 browser policy，不写系统代理、system PAC、TUN、DNS、firewall 或 CA。
- 不证明浏览器真实流量经过本地代理。
- 不包含 HTTP/TLS 数据面或 HTTPS MITM。

### `v0.1.0-alpha.7`

状态：已发布。

主要特性：

- 新增 `mitm browser-capture launch --confirm` dedicated-profile launch contract。
- 可通过显式授权启动 dedicated browser profile，并传入计划代理参数、profile 目录和浏览器命令参数。
- 输出 `LinuxBrowserCaptureLaunchReport`、pid、profile、proxy、command args 和插件元数据。

明确不包含：

- `launch --confirm` 只启动 dedicated profile，不写系统代理或浏览器 policy。
- 不证明浏览器真实请求已经通过代理。
- 不包含 local proxy endpoint verify、target route verify、traffic proof、PAC artifact mutation、CA 或 HTTPS MITM。

### `v0.1.0-alpha.8`

状态：已发布。

主要特性：

- Linux CLI GitHub Release asset 包含 tarball、sha256、manifest 和 manifest sha256。
- `mitm browser-capture verify --confirm` 可探测计划本地代理端点。
- `mitm browser-capture verify --confirm --target-url <url>` 可用 HTTP CONNECT 探测目标 host:port 代理通路。
- `mitm browser-capture session-plan <ss://url>` 输出脱敏订阅到本地代理、dedicated browser 和 verify 的会话计划。
- `session-plan` 和 `launch --confirm` 支持 `--target-url`，可把目标页面传给 dedicated browser command。

明确不包含：

- 不包含 `traffic-proof` proof-log-token 验证。
- 不包含 PAC artifact apply/rollback。
- 不包含 native SOCKS5 CONNECT MITM plugin reject hook。
- 不写 browser/system proxy、system PAC、TUN、DNS、firewall 或 CA。
- 不证明完整 live browser traffic hijack、HTTPS MITM、CA trust 或 redirect/header/body/script rewrite。

### `v0.1.0-alpha.9`

状态：已发布。

发布时间：2026-07-09；对应 tag release 已通过同 commit CI、release workflow、checksum/manifest、
attestation、release notes/rollback 和 publish eligibility gates。

主要特性：

- `mitm browser-capture traffic-proof --confirm [--target-url <url>] [--proof-token <token>] [--proof-log <path>]`
  proof-log-token 验证入口；省略 token/log 时使用与 `session-plan`/`launch --confirm` 一致的默认
  proof 绑定。
- `mitm browser-capture session-plan` 和 `launch --confirm` 输出 `proof_target_url`、
  `networkcore_proof_token` 与 `traffic_proof_command`，把 dedicated 浏览器打开页面与后续 proof log
  检查串成同一个显式会话；默认 proof token 使用 CONNECT endpoint 与计划 proxy URL 派生，便于与 native
  SOCKS5 CONNECT 层可见信息对齐。
- `mitm browser-capture apply --confirm --pac-file <path> [--policy-file <path>] --snapshot <path>` 和
  `rollback --snapshot <path>` 的 NetworkCore-owned PAC artifact、可选 Chromium/Chrome managed proxy policy artifact 写入和回滚。
- `mitm browser-capture session-plan/launch/apply/verify/traffic-proof --proxy-scheme socks5`
  native plugin proxy mode：browser command 使用 `--proxy-server=socks5://127.0.0.1:7890`，
  PAC artifact 使用 `SOCKS5 127.0.0.1:7890; DIRECT`，policy artifact 使用
  `ProxyServer=socks5://127.0.0.1:7890`，verify/traffic-proof request 记录
  `proxy_scheme=socks5`，让显式授权 dedicated browser 会话走 native SOCKS5 CONNECT hook。
- `control-domain` `HttpMitmEvent`/`HttpMitmOutcome` rich mutation plan。
- `mitm-policy` `MitmPluginService::handle_http_mitm_event` 把 URL reject/redirect、header/body rewrite 和
  script dispatch 映射为 NetworkCore-owned plan。
- `engine-native` `NativeHttpMitmPluginHook` / `plan_socks5_connect_http_mitm` 接入 explicit SOCKS5 CONNECT；
  `networkcore-linux start` 加载内置 `networkcore.adblock` hook，插件返回 `Reject` 时写 SOCKS5 general
  failure response 并跳过 outbound；CONNECT hook 同时输出
  `engine.native.runtime.http_mitm_connect_browser_proof_observed` 诊断，记录默认 browser proof token、
  CONNECT target 和本地 socks5 proxy URL，供 `traffic-proof --proof-log` 读取启动日志时对齐同一显式会话。

明确不承诺：

- 不承诺浏览器/系统代理配置 mutation。
- 不承诺系统 PAC 安装。
- 不承诺 CA 生成/安装/信任。
- 不承诺 HTTPS 解密或 HTTP/TLS redirect/header/body/script rewrite 应用。
- 不承诺完整自动 browser hijack；仍是 explicit proxy / socks5 scheme / proof / PAC/browser policy artifact / CONNECT-level reject 切片。

## 当前发布 alpha 切片

### `v0.1.0-alpha.10`

状态：已发布；`v0.1.0-alpha.10` tag release 切片。

发布日期：2026-07-09；已通过同 commit CI、release workflow、checksum/manifest、
attestation、release notes/rollback 和 publish eligibility gates。

目标特性：

- `mitm browser-capture apply --confirm --pac-file <path> [--policy-file <path>] [--profile-prefs-file <path>] --snapshot <path>` 可在用户指定的 Firefox dedicated profile `user.js` 写入显式代理设置。
- `--profile-prefs-file` 按 `--proxy-scheme http|socks5` 生成 Firefox profile prefs：HTTP 模式写 http/ssl proxy，SOCKS5 模式写 socks/socks_remote_dns，让 dedicated profile 可直接走 native SOCKS5 CONNECT hook。
- `BrowserCapturePacFileStore` snapshot 记录原始 profile prefs 内容、NetworkCore 写入内容和创建状态；`rollback --snapshot <path>` 在文件未被外部修改时恢复原内容或删除 NetworkCore 新建文件，检测到冲突时拒绝覆盖未知变更。
- `browser_capture` JSON/text report 输出 `profile_prefs_file_path`、`profile_prefs_content` 和 rollback report 字段；CI 合同测试覆盖 profile prefs apply/rollback。
- `MITM_BROWSER_CAPTURE_GATE` 推进为 `pac-policy-profile-prefs-active/system-mutation-blocked`：允许显式授权的 caller-selected PAC、policy artifact 和 dedicated profile prefs 文件写入/回滚，但仍不修改系统代理、系统 PAC、TUN、DNS、firewall 或 CA。

明确不承诺：

- 不承诺静默或全自动 browser hijack。
- 不承诺系统级代理配置、system PAC、TUN、DNS 或 firewall mutation。
- 不承诺 CA 生成/安装/信任。
- 不承诺 HTTPS 解密或 HTTP/TLS redirect/header/body/script rewrite 应用。
- 即使 dedicated profile proxy prefs 可回滚写入，也仍不能称为完整 HTTPS MITM 或 request/response rewrite 可用。

## 当前发布 alpha 切片

### `v0.1.0-alpha.11`

状态：已发布；`v0.1.0-alpha.11` tag release 切片，不包含 HTTPS rewrite。

发布日期：2026-07-09；scope 以 Linux CA artifact lifecycle foundation 为核心，固定证书
artifact、private-key artifact、文件所有权、snapshot、rollback 和 trust-plan 边界。

已发布能力：

- 新增 Linux MITM certificate lifecycle source contract，固定 CA artifact、私钥 artifact、snapshot、rollback、
  trust-plan、诊断 code 和 CI governance。
- 新增显式授权的 CA artifact lifecycle 入口：`mitm certificate apply --confirm --cert-file <path> --key-file <path> --snapshot <path>`，写入 operator-provided cert/key artifact 路径并拒绝覆盖未知文件。
- 新增 rollback 入口，通过 NetworkCore snapshot 删除 NetworkCore 管理的 CA artifact。
- 新增 trust-plan 输出，继续不执行 system trust store mutation。
- `MITM_CERTIFICATE_LIFECYCLE_GATE` 从 plan-only 推进到 artifact-lifecycle-active/trust-mutation-blocked。

明确不承诺：

- 不生成或安装系统 trust store mutation。
- 不执行 `update-ca-certificates`、NSS DB、p11-kit、Firefox trust store 或发行版专用信任命令。
- 不解密 HTTPS，不应用 HTTP/TLS redirect/header/body/script rewrite。
- 不把 CA artifact 生成等同于完整 MITM 可用。

### `v0.1.0-alpha.12`

状态：已发布；`v0.1.0-alpha.12` tag release 切片，发布明文 HTTP rewrite foundation，不包含完整 HTTPS rewrite。

发布日期：2026-07-09；scope 以 Linux MITM HTTP rewrite source contract 和显式 caller-provided
plain HTTP preview 为核心，固定 `MITM_HTTP_TLS_DATA_PLANE_GATE=plain-http-rewrite-foundation-active/tls-decryption-blocked`。

已发布能力：

- 新增 Linux MITM HTTP rewrite source contract，固定 `NativePlainHttpMessage`、`NativePlainHttpRewriteReport`、
  `LinuxMitmHttpRewriteReport`、命令面、诊断 code、JSON report 和 CI governance。
- 新增 `engine-native` 明文 HTTP rewrite application：把 caller-provided message 映射为 `HttpMitmEvent`，
  调用 `MitmPluginService::handle_http_mitm_event`，并把 `HttpMitmOutcome` 的 reject、redirect、
  header mutation 和 body mutation 应用到该合成输入。
- 新增 `networkcore-linux mitm http-rewrite plan`，输出 source contract、gate、mutation_ready、
  live_traffic_ready、tls_decryption_ready 和 blocked operations。
- 新增 `networkcore-linux mitm http-rewrite preview --confirm --url <url> [--method <method>] [--phase request|response] [--status-code <code>] [--header <name:value>] [--body <text>]`，
  使用内置 `networkcore.adblock` 计划并应用 outcome 到调用方输入，输出 `http_rewrite` report。
- `HttpMitmScriptDispatch` 仍只记录 `script_dispatch_deferred=true`，不执行脚本。

明确不承诺：

- 不解密 HTTPS，不终止 TLS，不把 preview 输入等同于 live browser traffic。
- 不安装、信任、撤销或回滚 CA trust store。
- 不修改 browser/system proxy、system PAC、TUN、DNS、firewall 或路由状态。
- 不执行 JavaScript plugin script dispatch。
- 不承诺完整自动 browser hijack 或完整 HTTPS rewrite；该能力必须等待后续 alpha 切片。

### `v0.1.0-alpha.13`

状态：已发布；`v0.1.0-alpha.13` tag release 切片，发布 Linux dedicated profile CA trust artifact foundation，不包含系统或浏览器 trust store mutation。

发布日期：2026-07-09；scope 以 Linux MITM certificate lifecycle source contract 的 dedicated profile
trust artifact 为核心，固定 `MITM_CERTIFICATE_LIFECYCLE_GATE=artifact-lifecycle-active/profile-trust-artifact-active/trust-mutation-blocked`。

已发布能力：

- `networkcore-linux mitm certificate apply --confirm --cert-file <path> --key-file <path> [--profile-trust-file <path>] --snapshot <path>` 可把 NetworkCore CA artifact 同步写入调用方显式指定的 dedicated profile trust artifact 路径。
- `certificate_lifecycle` JSON/text report 新增 `profile_trust_file_path`、`profile_trust_content` 和 `profile_trust_fingerprint`。
- rollback snapshot 记录 dedicated profile trust artifact 路径、created flag 和 fingerprint；`mitm certificate rollback --snapshot <path>` 只在 fingerprint 仍匹配时删除 NetworkCore 创建的 profile trust artifact。
- trust plan 新增 `prepare-dedicated-profile-trust-artifact`，certificate lifecycle plan 新增 `write-dedicated-profile-trust-artifact`。

明确不承诺：

- 不执行 NSS DB、p11-kit、Firefox trust store、Chrome/Chromium trust store、系统 trust store 或发行版 trust command mutation。
- 不修改 profile trust state，不静默安装或信任 CA。
- 不解密 HTTPS，不终止 TLS，不拦截真实浏览器或系统流量。
- 不应用 live HTTP/TLS redirect/header/body/script rewrite。

## 已发布切片

### `v0.1.0-alpha.14`

状态：已发布；`v0.1.0-alpha.14` tag release 切片，发布 Linux explicit HTTP proxy live plain HTTP data plane。

当前 artifact 能力：

- Linux explicit HTTP proxy live plain HTTP data plane：`engine-native` 允许 `ListenerKind::Http`
  loopback listener 解析 bounded HTTP/1.x explicit proxy request，并通过 `NativeHttpMitmPluginHook`
  调用 `MitmPluginService::handle_http_mitm_event`。
- 新增 `NativeExplicitHttpProxyRequest`、`NativePlainHttpProxyResponse`、
  `read_explicit_http_proxy_request`、`apply_http_mitm_outcome_to_live_plain_http_request`、
  `serialize_explicit_http_proxy_request_for_upstream` 和
  `engine.native.runtime.http_proxy_plain_rewrite_applied` 诊断。
- 真实 `http://` request/response 可在 explicit proxy 路径应用 reject、redirect、header/body rewrite；
  非 terminal request rewrite 会经既有 SOCKS outbound primitive 转发 upstream，再对 bounded response
  做 response phase rewrite 后返回 client。
- `MITM_HTTP_TLS_DATA_PLANE_GATE` 推进为
  `plain-http-live-data-plane-active/tls-decryption-blocked`，`http_rewrite` report 声明
  `mutation_ready=true`、`live_traffic_ready=true`、`tls_decryption_ready=false`。

明确不承诺：

- 不解密 HTTPS，不终止 TLS，不处理 CONNECT 后的 TLS MITM。
- 不安装、信任、撤销或回滚 CA trust store。
- 不修改 browser/system proxy、system PAC、TUN、DNS、firewall 或路由状态。
- 不执行 JavaScript script dispatch。
- 不承诺 HTTP/2、chunked/streaming body、压缩 response body 或完整通用 HTTP 兼容。
- 不代表 Windows artifact、跨平台 parity 或 managed lifecycle 已进入 release。

## 当前待发布切片

### `v0.2.0-alpha.9`

状态：Windows managed client source slice；必须通过同 commit GitHub Actions CI、
MSI install/uninstall smoke、package、attestation、publish eligibility 和 tag release
后，才可称为用户可下载版本。

主要特性：

- V2Ray share-link compatibility subset：GUI 的 operator-selected local profile
  import 可把 `trojan://`、`vless://`、`vmess://` 及 sing-box outbound catalog
  中明确提供的 TLS、ALPN、certificate pins、uTLS、REALITY、VLESS Vision、VMess
  security/alter-id 和 WebSocket/gRPC/HTTP/HTTPUpgrade/V2Ray QUIC 信息保留到
  managed sing-box outbound。
- 此渲染是确定性的本地文件兼容子集。native sing-box JSON 直通路径不受影响，仍会保留
  NodeCatalog 未覆盖的 sing-box 字段；Hysteria2/TUIC 仍是独立的 direct QUIC proxy
  outbound path。
- V2Ray QUIC transport 与 Hysteria2/TUIC 都是 sing-box 直接代理 core 的数据路径，不进入
  GUI 的 HTTP/1.1 HTTPS MITM listener、CA 或 native `mixed-in` snapshot/restore 生命周期。

明确不包含：

- 不提供 remote subscription fetch、完整多节点 selector、任意 native transport 推断、
  XHTTP、ECH、multiplex 或 Hysteria v1；未由 NodeCatalog 明确保留的字段不由基础 renderer
  猜测或改写。
- 不支持 HTTP/2、HTTP/3/QUIC MITM、chunked/streaming exchange、多 request CONNECT
  session、arbitrary plugin loading、remote script、JavaScript script dispatch、TUN、
  DNS interception、firewall mutation 或 transparent capture。

### `v0.2.0-alpha.8`

状态：Windows managed client source slice；必须通过同 commit GitHub Actions CI、
MSI install/uninstall smoke、package、attestation、publish eligibility 和 tag release
后，才可称为用户可下载版本。

主要特性：

- Hysteria2/TUIC share-link parser gate：GUI 的 operator-selected local profile
  import 现在可将 `hysteria2://`/`hy2://` 与 `tuic://` 分享链接归一化后生成
  sing-box outbound。Hysteria2 保留密码、TLS、
  port hopping 与 `salamander`/`gecko` obfuscation；TUIC 保留 UUID、可选密码、TLS
  和 `cubic`/`new_reno`/`bbr` congestion control。
- native sing-box JSON catalog import 也可识别 Hysteria2/TUIC outbound 的上述受控字段；
  GUI 对带 top-level `inbounds` 或 `outbounds` 的原生 JSON 直通路径仍不会改写 JSON。
- Hysteria2/TUIC 是 sing-box 直接代理 core 的 QUIC 数据路径，不进入 GUI 的 HTTP/1.1
  HTTPS MITM listener、CA 或 native `mixed-in` snapshot/restore 生命周期。

明确不包含：

- 不提供 remote subscription fetch、完整多节点 selector、Hysteria v1、任意 QUIC
  transport 泛化或 HTTP/3 MITM；未由 NodeCatalog 明确保留的 transport、route、DNS
  和 native JSON 字段不会被基础 renderer 推断或改写。
- 不支持 HTTP/2、HTTP/3/QUIC MITM、chunked/streaming exchange、多 request CONNECT
  session、arbitrary plugin loading、remote script、JavaScript script dispatch、TUN、
  DNS interception、firewall mutation 或 transparent capture。

### `v0.2.0-alpha.7`

状态：Windows managed client source slice；必须通过同 commit GitHub Actions CI、
MSI install/uninstall smoke、package、attestation、publish eligibility 和 tag release
后，才可称为用户可下载版本。

主要特性：

- GUI 会把带 top-level `inbounds` 或 `outbounds` 的 operator-selected native sing-box JSON
  原样导入 service-owned `config.json`，不丢弃 TLS/REALITY/WebSocket/gRPC/multiplex/
  route/DNS 字段；local/wildcard `mixed` 或 `http` inbound 会提供系统代理端口，GUI 还可直接
  打开 `sing-box.log` 查看 `check -c` 与 runtime 输出。
- 当 native JSON 明确包含 `type: mixed`、`tag: mixed-in` inbound 时，GUI HTTPS MITM
  会将原始 JSON 保存为 rollback snapshot，只把该 inbound 改为 `127.0.0.1:7891` 的
  SOCKS upstream listener；disable 后恢复原始 JSON 和其本地 mixed/http proxy endpoint。
- GUI 的明确 `Enable HTTPS MITM` 动作生成受管 CA，配置 native HTTP(S) listener
  `127.0.0.1:7890`，并将 GUI 导入的 sing-box mixed inbound 转为本地 SOCKS upstream
  `127.0.0.1:7891`。`Disable HTTPS MITM` 停止 listener、恢复 direct mixed inbound、
  删除受管 ROOT 条目和 CA 私钥。
- Windows service 在启动 sing-box 后启动 native proxy；native path 按 CONNECT
  authority 签发 leaf、终止下游 TLS、以 web PKI 验证上游 TLS，并通过内置 policy hook
  处理一个有界 HTTP/1.1 request/response exchange。
- capability/status 明确报告 `https_mitm: active`；service lifecycle contract 覆盖
  loopback native listener 的 start/stop 和 CA trust action。

明确不包含：

- 不提供 remote subscription fetch 或完整多节点 selector；基础 profile renderer 仍不生成
  advanced transport，但 native sing-box JSON 作为不变的 core config 可保留这些字段。
- 不会改写没有明确 `type: mixed`、`tag: mixed-in` inbound 的 native JSON，也不会改写
  其他 native inbound、outbound、route 或 DNS 字段。
- 不支持 HTTP/2、HTTP/3/QUIC、chunked/streaming exchange、多 request CONNECT session、
  arbitrary plugin loading、remote script、JavaScript script dispatch、TUN、DNS interception、
  firewall mutation 或 transparent capture。

## 最新已发布切片

### `v0.2.0-alpha.6`

Windows managed client release：原生 sing-box JSON 可不经基础 renderer 原样导入
service-owned config，保留 advanced transport、routing 和 DNS 字段，并检测 local/wildcard
`mixed`/`http` inbound 作为系统代理端口；GUI 也提供直接打开 `sing-box.log` 的诊断入口。
该 release 已包含 MSI 与 portable ZIP。

### `v0.2.0-alpha.5`

Windows managed client release：GUI 的明确 HTTPS MITM 操作创建 service-owned CA、配置
`127.0.0.1:7890` native HTTP listener 和 `127.0.0.1:7891` sing-box SOCKS upstream；Windows
service 在 sing-box 启动后处理 controlled HTTP/1.1 TLS exchange，并在 disable 时回滚 ROOT
trust entry、listener 与 CA private key。该 release 已包含 MSI 与 portable ZIP。

### `v0.2.0-alpha.4`

状态：Windows managed client prerelease；用户可下载状态以同名 tag 的
GitHub Actions release workflow 结果为准。

主要特性：

- GUI 新增显式 `Install core`，通过 sing-box 官方 GitHub release metadata
  选择 Windows ZIP，并在发布 asset 提供 digest 时校验 `sha256:` 后提取
  `sing-box.exe` 到 `%ProgramData%\\AnixOps\\NetworkCore`。MSI 和 portable ZIP
  仍不捆绑、也不会静默下载第三方 core。
- GUI 新增显式本地 profile file import。它经 `CoreSubscriptionService` 解析并
  写入服务可用的 `sing-box/config.json` 与 managed `sing_box` block，默认监听
  `127.0.0.1:7890`；空 Node ID 选择首个可渲染节点。
- `engine-singbox` renderer 可生成基础 Shadowsocks、Trojan、VLESS、VMess
  outbound。Trojan 启用 TLS；VLESS/VMess 只生成基础 TCP。REALITY、WebSocket、
  gRPC、TLS/transport/multiplex、route、DNS 与远程订阅拉取仍不在该路径范围。

明确不包含：

- 不提供 remote subscription fetch、完整多节点 selector、advanced transport
  rendering、Windows live HTTPS MITM、动态叶子证书、TLS 解密、rewrite 或
  JavaScript script dispatch。

### `v0.2.0-alpha.3`

状态：Windows managed client prerelease；用户可下载状态以同名 tag 的
GitHub Actions release workflow 结果为准。

主要特性：

- MSI 的首次 service start 改为 asynchronous：安装不会等待
  `AnixOpsNetworkCore` 到达 `Running`，保留的错误配置不会卡住安装界面；stop
  与 uninstall 仍等待并保持 `purge` 回滚顺序。
- 每次 Windows tag release 同时发布 managed-client MSI 四件套与 portable ZIP
  四件套。便携 ZIP 包含 GUI、service、CLI、inert managed config 和 README；
  解压不会注册或启动 service。
- CI 在 WiX validation 之外执行有 120 秒上限的 silent MSI install/uninstall
  smoke，并检查 SCM service 注册和删除。

### `v0.2.0-alpha.2`

状态：Windows managed client prerelease；用户可下载状态以同名 tag 的
GitHub Actions release workflow 结果为准。

主要特性：

- Windows service 可从 `managed-config.json.sing_box` 托管 operator-staged
  `sing-box.exe`，启动前执行 `check -c`，再执行 `run -c`，持久化 PID/exit
  code，并将 core stdout/stderr 写入显式日志。
- Adapter 可选择、校验并安全提取官方 Windows ZIP 中的 `sing-box.exe`；MSI
  不捆绑或静默下载第三方 core。
- GUI 显示 service 与 sing-box 状态/PID/exit code，并提供持久诊断和 debug
  toggle；MSI 使用标准安装目录向导与完成页。
- `root_certificate_path` 仍只负责 LocalMachine ROOT trust-store 生命周期；
  Windows live HTTPS MITM listener、动态叶子证书、TLS 解密和 rewrite 未启用。

### `v0.2.0-alpha.1`

状态：已发布的首个 Windows managed client prerelease；用户可下载 MSI、sha256、schema-version-2 manifest 和 manifest sha256。

主要特性：

- 原生 Win32 GUI、SCM service、WiX 4.0.6 per-machine MSI、signed INF driver package lifecycle、WinINet/WinHTTP system proxy 和 LocalMachine ROOT CA apply/rollback 已进入同一发布切片。
- JavaScript script dispatch、Windows subscription runnable path、远程订阅拉取和默认路径扫描仍 blocked。
- Linux artifact 同步发布；Linux 的历史能力边界继续由 `v0.1.2-alpha.3` source slice 描述。

### `v0.1.2-alpha.3`

状态：已发布的 Linux source slice；用户可下载状态以同名 Git tag 和 GitHub Actions release workflow 结果为准。

主要特性：

- 继承 `v0.1.2-alpha.1` 的 persistent subscription catalog，以及 `v0.1.2-alpha.2` 的显式
  managed status/event record 读写、expected-state transition 和 rollback source 边界。
- Linux `start --enable-https-mitm --mitm-ca-cert <path> --mitm-ca-key <path> --confirm`
  可在 CONNECT authority 与 ClientHello SNI 一致时签发 authority-bound leaf、终止下游 TLS、以
  web-PKI 校验上游 TLS，并在单个有界 HTTP/1.1 request/response exchange 上应用插件 rewrite。
- `start --enable-script-runtime --script-runner <path> --script-map <url>=<local-file> --confirm`
  把显式本地 Node runner 和已映射 local asset 接入 request/response hook；body/timeout/header/status/
  URL authority 均受限，失败 fail-open，不下载远程脚本。脚本是受信本地代码，不宣称 sandbox。
- Linux/Windows 产物继续只由 GitHub Actions 生成、checksum、manifest、attestation 后发布。

明确不包含：

- 不安装或信任 CA，不修改 system/browser proxy、system PAC、TUN、DNS、firewall 或路由状态。
- 受控 TLS 路径仅支持有界 HTTP/1.1 exchange；不承诺 HTTP/2、chunked/streaming、多 request session
  或通用浏览器/system capture 自动化。
- Windows `v0.2.0-alpha.1` 已另行发布 managed-client MSI；历史 `v0.1.1-alpha.2` CLI ZIP 只作审计记录。

### `v0.1.0`

状态：已发布；Linux-only explicit HTTPS rewrite preview 正式版。

当前 artifact 能力：

- 发布 Linux CLI tarball、sha256、manifest 和 manifest sha256。
- 继承 `v0.1.0-alpha.14` 到 `v0.1.0-rc.1` 的已发布能力边界：explicit HTTP proxy live plain HTTP data plane、TLS MITM readiness、controlled TLS termination plan/report、caller-provided HTTPS request/response rewrite preview、browser traffic proof hardening、traffic-proof text CONNECT authority 输出，以及 HTTPS request preview 回归冻结合同。
- 正式版仍固定 `tls_decryption_ready=false`、`https_response_rewrite_ready=false` 和 `script_dispatch_ready=false`，不声称 live TLS decryption、live CONNECT-stream rewrite 或 JavaScript script dispatch。

明确不承诺：

- 不包含 Windows artifact。
- 不执行 live HTTPS decryption、live CONNECT 后 HTTPS request/response rewrite 或完整 live HTTPS response rewrite。
- 不执行 JavaScript script dispatch。
- 不安装、信任、撤销或回滚 system trust store。
- 不修改 browser/system proxy、system PAC、TUN、DNS、firewall 或路由状态。

### `v0.1.0-rc.1`

状态：已发布；`v0.1.0-rc.1` tag release 切片，在 `v0.1.0-alpha.20` Linux release hardening 基础上发布回归冻结候选。

当前 artifact 能力：

- Linux MITM certificate material readiness：`networkcore-linux mitm certificate apply --confirm --cert-file <path> --key-file <path> [--profile-trust-file <path>] --snapshot <path>` 生成 TLS 可消费 CA certificate PEM、private key PEM，并把 dedicated profile trust artifact 写成同一 CA PEM copy；`profile_trust_fingerprint` 与 `cert_fingerprint` 对齐，private key 不进入 profile trust artifact。
- Linux explicit HTTP CONNECT tunnel foundation：`engine-native` 新增 `NativeTlsMitmFoundationReport`、
  `NativeTlsClientHelloObservationReport`、`plan_explicit_http_connect_tls_mitm_foundation`、
  `observe_explicit_http_connect_tls_client_hello`、`write_http_connect_established_response`、
  `engine.native.runtime.http_proxy_tls_foundation_ready`、
  `engine.native.runtime.http_proxy_tls_client_hello_observed` 和
  `engine.native.runtime.http_proxy_tls_connect_tunnel_established`。
- `ListenerKind::Http` explicit proxy `CONNECT host:443` 可经既有 SOCKS outbound primitive
  建立标准 `HTTP/1.1 200 Connection Established` tunnel，并对 CONNECT 后的有限 TCP bytes 做
  bounded ClientHello/SNI observation 和 pass-through relay。
- Linux controlled TLS termination plan foundation：`engine-native` 新增 `NativeControlledTlsTerminationPlanReport`、
  `plan_explicit_http_connect_controlled_tls_termination`、
  `engine.native.runtime.http_proxy_tls_termination_plan_ready` 和
  `engine.native.runtime.http_proxy_tls_termination_deferred`。
- 该 plan 会在 explicit HTTP `CONNECT` tunnel ready、ClientHello/SNI observed、NetworkCore CA certificate PEM
  和 private key PEM material ready 同时成立时，把
  `downstream_tls_termination_plan_ready=true`；同时继续输出
  `live_https_decryption_ready=false`、`https_request_rewrite_ready=false`、
  `https_response_rewrite_ready=false` 和 `script_dispatch_ready=false`。
- Linux CLI `http_rewrite` report/JSON 新增 `controlled_tls_termination_plan_ready`、
  `downstream_tls_termination_plan_ready` 和 `upstream_tls_forwarding_ready`，同时保持
  `tls_decryption_ready=false`。
- 新增合同测试 `explicit_http_connect_tls_termination_plan_keeps_rewrite_deferred`、
  `explicit_http_connect_tls_termination_plan_defers_without_material_or_hello` 和
  `mitm_http_rewrite_plan_reports_controlled_tls_termination_plan_without_decryption`，
  固定 CA material、ClientHello/SNI、deferred path 和 rewrite/script deferred invariant。
- Linux HTTPS request rewrite preview：`engine-native` 新增 `NativeHttpsRequestRewritePreviewReport`、
  `plan_and_apply_https_request_rewrite_preview`、
  `engine.native.runtime.http_proxy_https_request_rewrite_preview_ready`、
  `engine.native.runtime.http_proxy_https_request_rewrite_preview_deferred` 和
  `engine.native.runtime.http_proxy_https_request_rewrite_script_deferred`。
- 当 controlled TLS termination plan ready 且输入为 request-phase `https://` message 时，
  可预览 reject、redirect 和 request header mutation；Linux CLI `http_rewrite`
  report/JSON 新增 `https_request_rewrite_preview_ready=true`、
  `https_response_rewrite_ready=false` 和 `script_dispatch_ready=false`。
- 新增合同测试 `explicit_https_request_rewrite_preview_applies_headers_and_defers_body_and_script`，
  固定 request-phase header mutation 可预览、request-phase body mutation deferred、
  response rewrite 由独立 response-phase preview 处理，以及 JavaScript script dispatch deferred invariant。
- Linux HTTPS response rewrite preview：`engine-native` 新增 `NativeHttpsResponseRewritePreviewReport`、
  `plan_and_apply_https_response_rewrite_preview`、
  `engine.native.runtime.http_proxy_https_response_rewrite_preview_ready`、
  `engine.native.runtime.http_proxy_https_response_rewrite_preview_deferred` 和
  `engine.native.runtime.http_proxy_https_response_rewrite_script_deferred`。
- 当 controlled TLS termination plan ready 且输入为 response-phase `https://` message 时，
  可预览 response header mutation 和 response body mutation；response body mutation 必须通过
  content-type guard、body-size guard 和 bounded buffering guard。
- Linux CLI `http_rewrite` report/JSON 新增 `https_response_rewrite_preview_ready=true`，
  同时继续输出 `https_response_rewrite_ready=false`、`script_dispatch_ready=false` 和
  `tls_decryption_ready=false`。
- 新增合同测试 `explicit_https_response_rewrite_preview_applies_headers_body_and_defers_script`，
  固定 response header/body mutation preview、content-type/body-size/buffering guard 和 JavaScript
  script dispatch deferred invariant。
- Linux live browser proof hardening：`traffic-proof --confirm [--target-url <url>] [--proxy-scheme http|socks5]`
  记录 `proof_connect_authority`，并要求同一 proof log 行同时包含 proof token、计划 proxy URL
  和 CONNECT authority；不满足绑定时返回 `cli.linux.mitm.browser_capture.traffic_proof.binding_mismatch`
  和 `binding_mismatch` report status。
- 新增合同测试 `mitm_browser_capture_traffic_proof_requires_bound_proxy_and_connect_authority`，
  固定 token/proxy/CONNECT authority 同行绑定和 mismatch 诊断。
- Linux release hardening：traffic-proof text 输出显式打印 CONNECT authority，和 JSON/report 中的
  `proof_connect_authority` 对齐，便于不用 JSON 也能人工审计 proof token、计划 proxy URL 和
  CONNECT authority 绑定。
- 新增合同测试 `mitm_browser_capture_traffic_proof_text_output_includes_connect_authority`，
  固定 text CONNECT authority 输出。
- Linux HTTPS request preview 回归冻结：Linux CLI `mitm http-rewrite preview --confirm --url https://... --phase request`
  的合同测试 `mitm_http_rewrite_preview_reports_https_request_preview_without_live_tls_or_script`
  固定 caller-provided HTTPS request preview 只能保持 preview/reject 边界，并继续输出
  `tls_decryption_ready=false`、`https_response_rewrite_ready=false` 和 `script_dispatch_ready=false`。

明确不承诺：

- 尚不执行 live downstream TLS termination，不解密 HTTPS。
- 尚不执行 live CONNECT-stream HTTPS request/response rewrite；HTTPS request/response rewrite 仅限
  caller-provided `https://` preview。
- 尚不把 `https_response_rewrite_ready` 翻为 true；完整 live HTTPS response rewrite 仍 blocked。
- response body mutation 仅限通过 guard 的 caller-provided response preview，不应用到 live CONNECT stream。
- 不执行 JavaScript script dispatch。
- 不安装、信任、撤销或回滚 CA trust store。
- 不修改 browser/system proxy、system PAC、TUN、DNS、firewall 或路由状态。
- 不代表 Windows artifact、跨平台 parity 或 managed lifecycle 已进入 release。

## 当前 main source 状态

当前 Windows source release 切片是 `v0.2.0-alpha.9`，Linux source slice 是 `v0.1.2-alpha.3`，最新 stable artifact 仍是 `v0.1.0`。它保留
`v0.1.1-alpha.2` 的 Linux/Windows package、checksum、manifest、attestation 和 publish gate，并把
受控 TLS HTTP/1.1 rewrite 与 explicit-local Node script runtime 加入 Linux CLI；Windows path 已切换到
managed-client MSI，service、driver、installer、system proxy mutation、system trust store mutation 和 managed lifecycle
已 active，并增加 operator-staged sing-box managed process、非阻塞 MSI service start、受 attestation 的 portable ZIP、GUI-controlled HTTP/1.1 HTTPS MITM/CA lifecycle、native sing-box JSON pass-through import、core-log access、受控 `mixed-in` listener 的 snapshot/restore、Hysteria2/TUIC local-file share-link and native-outbound import，以及本地 V2Ray TLS/REALITY/uTLS/Vision/transport compatibility subset；remote subscription、XHTTP/ECH/multiplex transport inference、HTTP/2/HTTP/3 QUIC MITM、streaming、多 request CONNECT 和 JavaScript script dispatch 仍 blocked。用户可下载状态仍以 tag、同 commit CI、package、attestation、publish eligibility 和 GitHub Release 为准。

## 已拍板后续版本节奏

以下是 `v0.1.0` 到 `v0.1.2` 的规划 source of truth。后续未发布版本只表达切片目标，
最终能力仍必须以新 tag、同 commit CI、package、attestation、publish eligibility 和 GitHub Release
结果为准。

### `v0.1.0`

目标：Linux-only explicit HTTPS rewrite preview。

规划切片：

- `v0.1.0-alpha.14`：Linux explicit HTTP proxy live plain HTTP data plane。已发布；真实 `http://`
  请求可在 dedicated/explicit proxy 路径应用 reject、redirect、header/body rewrite。
- `v0.1.0-alpha.15`：Linux TLS MITM foundation readiness。完成 CONNECT pass-through tunnel、bounded ClientHello/SNI observation、TLS 可消费 CA certificate PEM/private key PEM 和 dedicated profile CA PEM copy；仍不执行 TLS termination、HTTPS decryption 或 JavaScript script dispatch。
- `v0.1.0-alpha.16`：Linux controlled TLS termination foundation。已发布 controlled downstream TLS
  termination plan/report、CA material readiness binding 和诊断，不执行 JavaScript script dispatch。
- `v0.1.0-alpha.17`：Linux HTTPS request rewrite preview。已发布 caller-provided
  HTTPS request reject、redirect 和 request header rewrite preview；response body rewrite 继续独立切片。
- `v0.1.0-alpha.18`：Linux HTTPS response rewrite preview。已发布；加入 response
  header/body rewrite，带 content-type、body size 和 buffering guard；JavaScript script dispatch 仍 deferred。
- `v0.1.0-alpha.19`：Linux live browser proof hardening。已发布；traffic-proof 证据绑定强化包含
  `proof_connect_authority`、同一行 token/proxy/CONNECT authority 校验、`binding_mismatch` 诊断和合同测试。
- `v0.1.0-alpha.20`：Linux release hardening。已发布；traffic-proof text CONNECT authority 输出、
  合同测试和 CI governance anchor 已进入 Linux artifact；功能冻结，只修 CLI UX、JSON 字段、错误码、
  文档、CI governance、release notes 和 rollback 边界。
- `v0.1.0-rc.1`：功能冻结候选版。已发布；HTTPS request preview 回归冻结合同、
  release notes/rollback、同 commit CI、package、attestation 和 publish eligibility 已进入 Linux artifact。
- `v0.1.0`：已发布 Linux-only explicit HTTPS rewrite preview 正式版；继承 rc.1 回归冻结合同，不发布 Windows artifact，不启用 JavaScript script dispatch、system trust store mutation 或 system proxy mutation。

明确不包含：

- 不包含 Windows 正式 artifact。
- 不包含 JavaScript script dispatch。
- 不包含 system trust store mutation。
- 不包含 system/browser proxy mutation 或 system PAC installation。
- 不包含 daemon/service、TUN、DNS 或 firewall mutation。

### `v0.1.1`

目标：正式引入 Windows 版本，并完成订阅兼容主线。

规划切片：

- `v0.1.1-alpha.1`：Windows CLI artifact source/release contract。已发布；定义 Windows runner、
  toolchain、archive 格式、checksum、manifest、attestation、release notes、rollback 和 signing policy；
  本切片只激活合同和 release summary blocked 输出，不生成 Windows CLI zip，不定义 `package-windows`，
  不默认包含 service、driver 或 installer。
- `v0.1.1-alpha.2`：Windows CLI package/publish path。已发布；新增 `apps/windows-cli`
  source identity、`platform-windows` read-only capability boundary、`package-windows`、`attest-windows`
  和 Windows publish eligibility gate，产物只由 GitHub Actions 生成并发布为 manual-extract Windows CLI zip 四件套。
- `v0.1.1-alpha.3`：订阅格式扩展。当前 source 增量接入 Trojan/VLESS/VMess URL parser gates、Clash YAML parser gate、sing-box JSON parser gate、Surge proxy line parser gate、Loon proxy line parser gate 和 Quantumult X proxy/server line parser gate：
  `trojan://password@host:port?...#name`、`vless://uuid@host:port?...#name`、`vmess://base64(json)`、受支持的 Clash
  `proxies` 子集、sing-box JSON `outbounds` 子集、Surge/Loon `[Proxy]` line 子集以及 Quantumult X `[server_local]` line 子集只归一化到 `SubscriptionDocument`/`NodeCatalog`。本切片不包含节点选择、cross-platform run plan、Linux/Windows subscription run preview、远程 fetch、
  文件 load、默认订阅路径扫描或 managed lifecycle。
- `v0.1.1-alpha.4`：节点选择和运行计划。支持按 name/tag/filter 选择节点，输出 cross-platform
  run plan，并保持 secret redaction。
- `v0.1.1-alpha.5`：Linux/Windows subscription run preview。把订阅兼容和节点选择接入
  Linux/Windows CLI 可下载 artifact，仍不引入 daemon/service。
- `v0.1.1-rc.1`：Windows artifact 和订阅兼容功能冻结候选版。
- `v0.1.1`：发布 Linux + Windows CLI artifact，订阅兼容作为主能力。

明确不包含：

- 不包含 Windows service、driver、installer 或系统代理 mutation。
- 不包含 JavaScript script dispatch。
- 不包含 system trust store mutation。
- 不包含 managed daemon lifecycle。

### `v0.1.2`

目标：managed lifecycle，并在 alpha 切片中相继推出 JavaScript script dispatch、system trust store
mutation 和 system proxy mutation。

规划切片：

- `v0.1.2-alpha.1`：persistent subscription catalog。新增 `add/list/remove/select/update/rollback`
  source contract、本地存储、脱敏输出和 rollback snapshot。当前 main 已完成并通过 GitHub Actions
  验证 source-only `add`、`list`、`remove`、`select`、`update` 和 `rollback` 存储切片：显式
  catalog/snapshot 路径、schema version 1、重复 source id 拒绝、写前 snapshot、source-not-found 拒绝、
  snapshot 复原/保留和脱敏 report；
  默认路径、远程/file fetch、runtime startup 和 managed lifecycle 仍 blocked。
- `v0.1.2-alpha.2`：managed foreground lifecycle。当前 main 已完成 source-only `read_status`/`write_status`/
  `transition_status` record 读取/初始非覆盖写入/expected-state 迁移切片：显式 schema version 1 JSON record、
  迁移前原始 record snapshot、`starting -> running/failed` 与 `running -> stopped/failed`、`record_written=true`、
  `snapshot_written=true` 和 `liveness_verified=false`。`networkcore-linux managed-status <status-record-path>` 已只读
  输出同一 record，`networkcore-linux managed-status init <status-record-path> <session-id> <engine-id> <state>` 已非覆盖
  创建 record 并输出 `record_written=true`，`networkcore-linux managed-status transition <status-record-path> <snapshot-path>
  <expected-state> <next-state>` 已在 expected state 匹配时保存原始 snapshot 并输出 `snapshot_written=true`；不验证 live
  process、不接入 runtime control。`CommandManagedForegroundSessionEventStore::read_event` 已读取显式 schema version 1
  event record 的允许 event kind、recorded state 和 recorded_at，写入结果固定 `record_written=true` 与
  `liveness_verified=false`；`networkcore-linux managed-event <event-record-path>` 已只读输出同一 record，`networkcore-linux
  managed-event init <event-record-path> <session-id> <engine-id> <event-id> <event-kind> <state> <recorded-at>` 已非覆盖创建
  record 并输出 `record_written=true`；不扫描 event，不接入实时 stream 或 runtime control。后续新增 managed
  `events/logs/reload` 与 runtime rollback 命令面；仍不默认安装 daemon/service。
  同一 alpha.2 status source 还包含 `CommandManagedForegroundSessionStore::rollback_status`：仅在 explicit
  status/snapshot 路径不同、current expected state 与 snapshot 的 trim 后 session/engine identity 匹配时，恢复
  snapshot 原始内容并保留 snapshot，输出 `snapshot_retained=true` 与 `liveness_verified=false`；
  `networkcore-linux managed-status rollback <status-record-path> <snapshot-path> <expected-state>` 已输出同一
  text/JSON 回滚 report，不检查 live process，也不控制 runtime。
- `v0.1.2-alpha.3`：JavaScript script dispatch + controlled TLS data plane。当前发布切片以
  plugin permission、显式 local runner/script map、timeout/body/URL authority guard、fail-open diagnostics
  和 CI governance 执行受控 dispatch；同一 Linux `start` runtime 在显式 CA/confirm 下完成
  CONNECT authority/SNI-bound TLS termination、web-PKI upstream forwarding 和有界 HTTP/1.1 rewrite。
  local Node code 是受信代码而非 sandbox，禁止远程脚本下载。
- `v0.1.2-alpha.4`：system trust store mutation foundation。显式授权后执行平台 trust store
  apply/detect/revoke/rollback，必须有 snapshot、conflict detection 和 blocked fallback。
- `v0.1.2-alpha.5`：system proxy mutation foundation。显式授权后执行 system proxy/system PAC
  apply/detect/rollback，必须有 snapshot、conflict detection 和 route proof。
- `v0.1.2-alpha.6`：managed MITM session orchestration。把 subscription catalog、managed lifecycle、
  trust/proxy mutation、browser proof 和 rewrite proof 串成一键会话计划与回滚路径。
- `v0.1.2-alpha.7`：cross-platform parity hardening。按 Linux/Windows 能力差异收口输出字段、
  release notes、manual intervention markers 和 rollback docs。
- `v0.1.2-rc.1`：managed lifecycle 功能冻结候选版。
- `v0.1.2`：发布 managed lifecycle 版本。

明确边界：

- system trust store 和 system proxy mutation 必须显式授权、可检测、可回滚，并在无法自动化时写入
  `docs/manual-intervention.md`。
- JavaScript script dispatch 必须先落 permission、sandbox、timeout、audit 和 CI governance，不能直接
  执行无约束远程脚本。
- iOS、macOS GUI、Windows service/installer、daemon/service、TUN/DNS/firewall mutation 仍不作为
  `v0.1.2` 默认承诺，除非后续单独拍板并补 source contract。

## 相关文档

- [Release Strategy](release-strategy.md)
- [Linux MITM Browser Capture Source Contract](architecture/linux-mitm-browser-capture-source-contract.md)
- [Linux MITM HTTP Rewrite Source Contract](architecture/linux-mitm-http-rewrite-source-contract.md)
- [MITM Policy Ad Block Plugin Source Contract](architecture/mitm-policy-ad-block-plugin-source-contract.md)
- [Linux Native Proxy Engine Start Design](architecture/linux-native-proxy-engine-start.md)
- [Roadmap](../ROADMAP.md)
- [TODO](../TODO.md)
