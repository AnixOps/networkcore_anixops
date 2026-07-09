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

## 当前和后续 alpha 规划

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

状态：规划中；按当前拍板作为首个 HTTP/TLS rewrite 候选切片。

预计窗口（非承诺）：`v0.1.0-alpha.11` 通过 GitHub Actions release 后评估。

目标方向：

- 推进 `MITM_HTTP_TLS_DATA_PLANE_GATE`：把 `mitm-policy` `HttpMitmOutcome` redirect/header/body/script
  rewrite plan 接到真实 HTTP/TLS 请求/响应数据面。
- 以 `v0.1.0-alpha.11` 的 CA artifact lifecycle、显式授权、snapshot 和 rollback 边界为前置条件。
- 继续保持 browser/system proxy、system PAC、TUN、DNS、firewall 和 trust store mutation 独立受控。

明确不承诺：

- 不能跳过 CA trust、HTTP/TLS data plane、授权和 rollback 直接发布完整浏览器流量劫持。
- 若数据面风险过高，`alpha.12` 可只发布 HTTP/TLS data plane source contract 或明文 HTTP rewrite
  foundation，不强行承诺完整 HTTPS rewrite。

## 相关文档

- [Release Strategy](release-strategy.md)
- [Linux MITM Browser Capture Source Contract](architecture/linux-mitm-browser-capture-source-contract.md)
- [MITM Policy Ad Block Plugin Source Contract](architecture/mitm-policy-ad-block-plugin-source-contract.md)
- [Linux Native Proxy Engine Start Design](architecture/linux-native-proxy-engine-start.md)
- [Roadmap](../ROADMAP.md)
- [TODO](../TODO.md)
