# Alpha Release Feature Matrix

评估时间：2026-07-09。

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

## 最新已发布切片

### `v0.1.0-alpha.16`

状态：已发布；`v0.1.0-alpha.16` tag release 切片，发布 Linux controlled TLS termination foundation。

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

明确不承诺：

- 尚不执行 live downstream TLS termination，不解密 HTTPS。
- 尚不解析 CONNECT 后的 HTTPS request/response，不应用 HTTPS request/response rewrite。
- 不执行 JavaScript script dispatch。
- 不安装、信任、撤销或回滚 CA trust store。
- 不修改 browser/system proxy、system PAC、TUN、DNS、firewall 或路由状态。
- 不代表 Windows artifact、跨平台 parity 或 managed lifecycle 已进入 release。

## 当前 main source 状态

当前 main 与 `v0.1.0-alpha.16` 发布边界对齐。下一步 `v0.1.0-alpha.17` 才推进 Linux HTTPS request rewrite preview；
该后续能力仍必须等待新的 source 增量、tag、同 commit CI、package、attestation、publish eligibility 和 GitHub Release asset 全部通过。

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
- `v0.1.0-alpha.17`：Linux HTTPS request rewrite preview。对 dedicated/explicit HTTPS 请求应用
  reject、redirect 和 request header rewrite，response body rewrite 继续独立切片。
- `v0.1.0-alpha.18`：Linux HTTPS response rewrite preview。加入 response header/body rewrite，
  带 content-type、body size 和 buffering guard；JavaScript script dispatch 仍 deferred。
- `v0.1.0-alpha.19`：Linux live browser proof hardening。把 dedicated browser proof、TLS MITM
  诊断和 rewrite-applied proof 串成可审计 report，并补 rollback/conflict diagnostics。
- `v0.1.0-alpha.20`：Linux release hardening。冻结功能，只修 CLI UX、JSON 字段、错误码、文档、
  CI governance、release notes 和 rollback 边界。
- `v0.1.0-rc.1`：功能冻结候选版；只允许 CI、release、文档和回归修复。
- `v0.1.0`：发布 Linux-only explicit HTTPS rewrite preview artifact。

明确不包含：

- 不包含 Windows 正式 artifact。
- 不包含 JavaScript script dispatch。
- 不包含 system trust store mutation。
- 不包含 system/browser proxy mutation 或 system PAC installation。
- 不包含 daemon/service、TUN、DNS 或 firewall mutation。

### `v0.1.1`

目标：正式引入 Windows 版本，并完成订阅兼容主线。

规划切片：

- `v0.1.1-alpha.1`：Windows CLI artifact source/release contract。定义 Windows runner、
  toolchain、archive 格式、checksum、manifest、attestation、release notes、rollback 和 signing policy；
  优先发布 Windows CLI zip，不默认包含 service、driver 或 installer。
- `v0.1.1-alpha.2`：Windows CLI package/publish path。Release workflow 增加 `package-windows`
  和 publish eligibility gate，产物只由 GitHub Actions 生成。
- `v0.1.1-alpha.3`：订阅格式扩展。接入 VLESS、VMess、Trojan URL 高频子集，以及 Clash YAML、
  sing-box JSON 的 source contract 和 parser gates。
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

- `v0.1.2-alpha.1`：persistent subscription catalog。新增 `add/list/remove/select/update`
  source contract、本地存储、脱敏输出和 rollback snapshot。
- `v0.1.2-alpha.2`：managed foreground lifecycle。新增 managed `status/events/logs/reload/rollback`
  命令面；仍不默认安装 daemon/service。
- `v0.1.2-alpha.3`：JavaScript script dispatch foundation。基于 plugin permission、sandbox/timeout、
  IO guard、audit log 和 CI governance 执行受控 script dispatch。
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
