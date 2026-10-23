# 规则与策略组模型（M2）

本文件是 M2「规则与策略组模型」的设计说明与验收清单。规则与策略组是 `config-core` 的一等对象，桌面端经 `engine-singbox` 翻译为 sing-box `route`，iOS/macOS NE 内的 `engine-embedded` 直接调用同一模型的决策接口。两条路径共用一份快照夹具，防止行为分叉。

## 范围

- 规则：`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`/`IP-CIDR6`（可带 `no-resolve`）、`GEOIP`、`FINAL`。
- 策略组：`select`、`url-test`、`fallback`。
- 目标：`DIRECT`、`REJECT`、策略组 id、节点 id（保留名大小写不敏感）。
- 非目标：`USER-AGENT`、`URL-REGEX`、`PROCESS-NAME`、远程规则集、`load-balance` 组。

## 配置形状

```toml
profile = "default"
rules = [
  "DOMAIN-SUFFIX,google.com,Proxy",
  "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
  "GEOIP,CN,DIRECT",
  "FINAL,Proxy",
]

[[policy_groups]]
id = "Proxy"
type = "select"            # select | url-test | fallback
members = ["Auto", "hk-1", "DIRECT"]
default = "Auto"           # 仅 select

[[policy_groups]]
id = "Auto"
type = "url-test"
members = ["hk-1", "jp-1"]
url = "https://www.gstatic.com/generate_204"   # 默认值
interval_secs = 300                            # 默认值
tolerance_ms = 50                              # 默认值，仅 url-test
```

`rules` 或 `policy_groups` 任一出现时，`parse_config_document` 产出 `ParsedConfigDocument.routing`；未出现时为 `None`，现有 `routes` 默认动作不受影响。

## 校验规则

- 规则必须以且仅以一条 `FINAL` 结尾；错误信息带规则序号，不回显节点凭据。
- 目标解析顺序：`DIRECT`/`REJECT` → 策略组 id → 节点 id；策略组 id 不得与节点 id、保留名重复。
- 组成员不能是 `REJECT`；只有 `select` 可以包含其他组；`url-test`/`fallback` 成员只能是节点或 `DIRECT`。
- 组之间不得成环；重复成员按首次出现去重。
- 域名统一小写、去掉结尾点；`DOMAIN-SUFFIX` 去掉开头点，匹配自身与全部子域名；`DOMAIN-KEYWORD` 匹配包含该子串的域名。
- CIDR 归一化为网络地址（`10.1.2.3/8` → `10.0.0.0/8`）。

## 决策接口（engine-embedded 使用）

`RoutingModel::decide(&RouteQuery, &dyn RoutingEnvironment) -> RouteResolution`

- `RouteQuery { domain, ip }`：FakeIP/嗅探得到的域名与目的地址。
- `RoutingEnvironment` 提供 GeoIP 查询、DNS 解析、select 当前选择、成员测速结果；全部方法有保守默认值，`StaticRoutingEnvironment` 即无运行时状态。
- 第一条不带 `no-resolve` 的 IP 规则触发一次解析，之后所有 IP 规则使用解析结果，与 sing-box `resolve` 动作一致。解析失败时连接被拒绝（`RouteMatch::ResolveFailed`），与 sing-box 一致，不会落到 `FINAL`；需要远端解析的域名应放在 IP 规则之前用域名规则分流，或给 IP 规则加 `no-resolve`。
- 组选择：`select` 用环境选择 → `default` → 第一个成员；`url-test` 取延迟最低的成员（无结果时取第一个）；`fallback` 取第一个有测速结果的成员（都没有时取第一个）。
- `RouteResolution` 返回命中规则序号或 `FINAL`、规则目标、经过的组路径、最终 `Direct/Reject/Node(id)` 与解析出的地址，可直接用于诊断页。

## sing-box 翻译（engine-singbox）

`render_sing_box_route(&RoutingModel) -> SingBoxRouteFragment { outbounds, route }`

- 规则一对一按序翻译为 rule action（sing-box 1.11+）：`domain`、`domain_suffix`、`domain_keyword`、`ip_cidr`、`rule_set`；`REJECT` 为 `action: reject`，其他为 `action: route` + `outbound`。
- 第一条需要解析的 IP 规则前插入 `{ "action": "resolve" }`。
- `GEOIP,CN` 翻译为 `rule_set: ["geoip-cn"]`，并生成指向 `SagerNet/sing-geoip` 的远程 `.srs` 规则集，经 `direct` 下载。
- `FINAL,<目标>` 写入 `route.final`；`FINAL,REJECT` 追加无条件 `reject` 规则，`final` 为 `direct`。
- `select` → `selector`；`url-test` → `urltest`；`fallback` → `urltest` 且 `tolerance = 65535`。
- 片段只含策略组出站与 `route`；调用方负责节点出站（tag 为节点 id）和 `direct` 出站。

## 已知差异

- sing-box 没有按顺序回落的 fallback 组。翻译结果首次选择的是最快成员，之后只在当前成员失败时切换；`engine-embedded` 实现严格按顺序回落。快照用无测速状态的环境，两边都取第一个成员。
- sing-box 不对目的域名做大小写和结尾点归一化，决策接口会归一化；快照中对应用例标记 `engine_only`，不参与 sing-box 比较。
- 组内 `REJECT` 暂不支持，因为 sing-box 1.13 起移除了 `block` 出站。

## 快照夹具与验收

夹具位于 `testdata/routing-snapshot/`：

| 文件 | 校验方 |
| --- | --- |
| `config.toml` | 两侧共用的输入 |
| `decisions.json` | `crates/config-core/tests/routing_contracts.rs`：静态与带运行时状态两种环境下的逐条决策 |
| `sing-box-route.json` | `crates/engine-singbox/tests/route_contracts.rs`：完整 sing-box 片段 |

修改路由语义时必须同时更新两个快照。验收标准：上述测试在 GitHub Actions 全矩阵中通过。

## 真实 sing-box 等价性测试

CI job `Routing equivalence (sing-box)` 下载最新 sing-box 正式版和 `geoip-cn.srs`，运行 `crates/engine-singbox/tests/route_equivalence.rs`：

- 用 `render_sing_box_route` 渲染夹具，节点和 `direct` 都换成本地 SOCKS5 mock，GeoIP 规则集改为本地文件，夹具 DNS 由 sing-box `hosts` DNS server 提供，整个测试不访问外网目的地。
- 先 `sing-box check`，再 `sing-box run`，把 `decisions.json` 中所有静态用例经 mixed 入站逐条发出；每条用例使用唯一目的端口，收到该端口的 mock 即 sing-box 选中的出站，`REJECT` 要求没有任何 mock 收到。
- 结果与 `RoutingModel::decide` 的快照不一致即失败，并输出 sing-box 日志。带运行时状态（`live`）的用例依赖 select 选择和测速结果，不在此测试中比较。
- 未设置 `NETWORKCORE_SING_BOX_BIN` 时（普通 workspace 测试），该测试没有可比较的对象，直接返回；专用 job 设置 `NETWORKCORE_REQUIRE_SING_BOX_EQUIVALENCE=1`，缺少二进制会失败。

## 订阅导入（config-core `routing_import`）

`import_subscription_routing(content, &nodes) -> ImportedRouting { routing, diagnostics }` 从订阅原文再读一遍规则和策略组，`nodes` 是同一份订阅解析出的节点：

- Surge/Loon：`[Proxy Group]` 行 `名称 = 类型, 成员, 成员, url=..., interval=..., tolerance=...`，`[Rule]` 段规则行。
- Clash YAML：`proxy-groups`（`name`/`type`/`proxies`/`url`/`interval`/`tolerance`）与 `rules`，`MATCH` 视为 `FINAL`。
- 成员和规则目标按代理名称映射到节点 id，策略组 id 保留原名称；`REJECT-TINYGIF` 等 `REJECT-*` 视为 `REJECT`；规则只保留 `no-resolve` 选项。
- 不支持的规则类型、目标未导入的规则、`load-balance`/`relay` 等组、组内 `REJECT`、url-test/fallback 内的组成员都会跳过并给出警告；成员全部被跳过的组也会跳过，引用它的规则随之跳过。`FINAL` 之后的规则忽略。
- 跳过后剩余内容仍无法通过 `RoutingModel::from_spec`（如没有 `FINAL`、组成环）时整体不导入，返回 `None` 和 `config.core.routing_import.invalid` 警告。诊断只包含规则类型、组名和节点名，不包含节点凭据。

## 本地代理接入

- `engine-singbox::render_sing_box_local_proxy_routing_config(request, &model)`：模型引用到的节点按节点 id 作为 tag 渲染（WireGuard 进 `endpoints`），加上策略组出站、`direct` 和 `render_sing_box_route` 的 `route`；未引用的节点不渲染。引用到的节点不能被本地代理渲染时返回错误。报告的节点是 `FINAL` 在无运行时状态时落到的节点。
- Windows Tauri GUI 导入订阅：订阅含规则和策略组且渲染成功时写入路由配置，系统代理指向 `127.0.0.1:7890`，节点列表为空，策略组按原生 sing-box 配置的分组方式（`list_native_groups`/`select_native_group_outbound`）查看和修改默认成员；否则保持原来的选择器配置。HTTPS MITM 导入路径与 Win32 旧界面暂不使用路由。
- `networkcore-linux run-url`：未指定 `--node` 时导入订阅中的规则和策略组，导入成功就用路由配置启动；导入失败或渲染失败时退回原来的单节点配置并给出警告。指定 `--node` 时保持单节点行为。Mieru 节点路径不变。

## engine-embedded 接入

- 运行时配置新增 `routing` 段（与 `outbound` 二选一）：`outbounds` 以节点 id 为键，`rules` 与 `groups` 字段同 `RoutingSpec`/`PolicyGroupSpec`。路由节点必须是 TCP 出站（Shadowsocks-2022、direct）；WireGuard 是包级隧道，只能作为单一 `outbound` 使用。
- `engine_embedded::routing::RoutedOutbound` 对每个连接调用 `decide`，`DIRECT` 走直连出站，`REJECT` 直接失败，节点走对应出站。策略组使用无运行时状态的选择（select 的 `default` 或第一个成员）。
- 隧道目前只拿到目的 IP：域名规则只在调用方传入域名目标时生效（FakeIP/嗅探尚未接入）；域名目标遇到不带 `no-resolve` 的 IP 规则时运行时不解析，按解析失败拒绝；运行时不带 GeoIP 数据库，`GEOIP` 规则不会命中。
- Swift 侧尚未生成 `routing` 段，现有单出站配置行为不变。

后续工作：Windows MITM 导入路径与运行中切换（Clash API）接入路由；engine-embedded 的 FakeIP/嗅探、GeoIP 数据、select 运行时选择与测速；Swift 侧生成 `routing` 段。
