# 规则与策略组模型（M2）

本文件是 M2「规则与策略组模型」的设计说明与验收清单。规则与策略组是 `config-core` 的一等对象，桌面端经 `engine-singbox` 翻译为 sing-box `route`，iOS/macOS NE 内的 `engine-embedded` 直接调用同一模型的决策接口。两条路径共用一份快照夹具，防止行为分叉。

## 范围

- 规则：`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`/`IP-CIDR6`（可带 `no-resolve`）、`GEOIP`、`GEOSITE`、`DST-PORT`（别名 `DEST-PORT`，单个端口或 `起-止`）、`PROCESS-NAME`、`RULE-SET`、逻辑规则 `AND`/`OR`/`NOT`、`FINAL`。
- 逻辑规则采用 Surge 写法：`AND,((DOMAIN-SUFFIX,example.com),(DST-PORT,443)),Proxy`、`NOT,((DOMAIN-KEYWORD,ads)),DIRECT`；子规则不带目标，可以嵌套（最多 8 层），`NOT` 只能有一个子规则。含 IP 子规则的逻辑规则按 IP 规则处理，可带 `no-resolve`。
- 策略组：`select`、`url-test`、`fallback`、`load-balance`（按目的主机一致性哈希）、`round-robin`（轮询）。
- 目标：`DIRECT`、`REJECT`、策略组 id、节点 id（保留名大小写不敏感）。
- 非目标：`USER-AGENT`、`URL-REGEX`、`relay` 组。

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
type = "select"            # select | url-test | fallback | load-balance | round-robin
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
- 组成员不能是 `REJECT`；只有 `select` 可以包含其他组；`url-test`/`fallback`/`load-balance`/`round-robin` 成员只能是节点或 `DIRECT`；只有 `url-test` 可写 `tolerance_ms`。
- 组之间不得成环；重复成员按首次出现去重。
- 域名统一小写、去掉结尾点；`DOMAIN-SUFFIX` 去掉开头点，匹配自身与全部子域名；`DOMAIN-KEYWORD` 匹配包含该子串的域名。
- CIDR 归一化为网络地址（`10.1.2.3/8` → `10.0.0.0/8`）。

## 决策接口（engine-embedded 使用）

`RoutingModel::decide(&RouteQuery, &dyn RoutingEnvironment) -> RouteResolution`

- `RouteQuery { domain, ip, port, process }`：FakeIP/嗅探得到的域名、目的地址、目的端口（`DST-PORT`）与发起连接的本地进程名（`PROCESS-NAME`，大小写不敏感，平台无法得知时为空，规则不命中）。
- `RoutingEnvironment` 提供 GeoIP 查询（`geoip_matches`）、GeoSite 查询（`geosite_matches`）、DNS 解析、select 当前选择、成员测速结果；全部方法有保守默认值，`StaticRoutingEnvironment` 即无运行时状态。
- `RoutingModel::route_to` 跳过规则直接解析一个目标（全局模式），`group_member` 给出组当前选择，`target_named` 按规则目标的方式解析名称。
- `RuleMatcher` 的 `Display` 输出不带目标的规则行，供连接列表显示命中规则。
- 第一条不带 `no-resolve` 的 IP 规则触发一次解析，之后所有 IP 规则使用解析结果，与 sing-box `resolve` 动作一致。解析失败时连接被拒绝（`RouteMatch::ResolveFailed`），与 sing-box 一致，不会落到 `FINAL`；需要远端解析的域名应放在 IP 规则之前用域名规则分流，或给 IP 规则加 `no-resolve`。
- 组选择：`select` 用环境选择 → `default` → 第一个成员；`url-test` 取延迟最低的成员（无结果时取第一个）；`fallback` 取第一个有测速结果的成员（都没有时取第一个）；`load-balance` 在有测速结果的成员（都没有时为全部成员）中按目的域名（无域名时为 IP）做 rendezvous 哈希（FNV-1a），同一主机固定到同一成员，某成员下线时只有原本落在它上面的主机会换成员；`round-robin` 在同样的成员中按 `RoutingEnvironment::round_robin` 计数轮流选择。`group_member`（策略页显示）没有连接时返回第一个健康成员。
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
- 导入的规则类型：`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`/`IP-CIDR6`、`GEOIP`、`DST-PORT`/`DEST-PORT`；`PROCESS-NAME`、`GEOSITE`（需要客户端提供列表）与逻辑规则暂不从订阅导入。
- `load-balance` 组：Clash `strategy` 或 Loon `algorithm` 为 `round-robin`/`random` 时导入为 `round-robin`，其他（`consistent-hashing`、`sticky-sessions`、`pcc`）导入为 `load-balance`。
- 节点名过滤：Surge `include-all-proxies`、Clash `include-all`/`include-all-proxies` 加入全部节点；Surge `policy-regex-filter`、Clash `filter`（可用反引号分隔多个模式）只保留名称匹配的节点，Clash `exclude-filter` 去掉匹配的节点，按订阅中的节点顺序追加在显式成员之后。两者原本作用于外部列表/provider（不导入），所以没有成员的组带过滤器时从全部节点中筛选；有成员且没有 include-all 的组忽略过滤器并警告；正则无法编译（Rust `regex` 语法，不支持环视）时不加节点并警告。
- 不支持的规则类型、目标未导入的规则、`relay` 等组、组内 `REJECT`、url-test/fallback 内的组成员都会跳过并给出警告；成员全部被跳过的组也会跳过，引用它的规则随之跳过。`FINAL` 之后的规则忽略。
- 跳过后剩余内容仍无法通过 `RoutingModel::from_spec`（如没有 `FINAL`、组成环）时整体不导入，返回 `None` 和 `config.core.routing_import.invalid` 警告。诊断只包含规则类型、组名和节点名，不包含节点凭据。

## 本地代理接入

- `engine-singbox::render_sing_box_local_proxy_routing_config(request, &model)`：模型引用到的节点按节点 id 作为 tag 渲染（WireGuard 进 `endpoints`），加上策略组出站、`direct` 和 `render_sing_box_route` 的 `route`；未引用的节点不渲染。引用到的节点不能被本地代理渲染时返回错误。报告的节点是 `FINAL` 在无运行时状态时落到的节点。
- Windows Tauri GUI 导入订阅：订阅含规则和策略组且渲染成功时写入路由配置，系统代理指向 `127.0.0.1:7890`，节点列表为空，策略组按原生 sing-box 配置的分组方式（`list_native_groups`/`select_native_group_outbound`）查看和修改默认成员；否则保持原来的选择器配置。HTTPS MITM 导入路径与 Win32 旧界面暂不使用路由。
- `networkcore-linux run-url`：未指定 `--node` 时导入订阅中的规则和策略组，导入成功就用路由配置启动；导入失败或渲染失败时退回原来的单节点配置并给出警告。指定 `--node` 时保持单节点行为。Mieru 节点路径不变。

## engine-embedded 接入

- 运行时配置新增 `routing` 段（与 `outbound` 二选一）：`outbounds` 以节点 id 为键，`rules` 与 `groups` 字段同 `RoutingSpec`/`PolicyGroupSpec`。路由节点必须是 TCP 出站（Shadowsocks-2022、direct）；WireGuard 是包级隧道，只能作为单一 `outbound` 使用。
- `engine_embedded::routing::RoutedOutbound` 对每个连接调用 `decide`，`DIRECT` 走直连出站，`REJECT` 直接失败，节点走对应出站。select 组先用运行时 `select` 控制命令的选择，再用 `default` 或第一个成员；url-test/fallback/load-balance/round-robin 使用 `run_health_checks` 的测速结果，round-robin 的计数在 `RoutedOutbound` 内。
- 隧道从 TCP 首包嗅探 TLS SNI 或 HTTP `Host`：域名规则按嗅探到的名字匹配，IP 规则仍匹配目的地址，连接仍发往原地址。UDP（含 QUIC）尚不嗅探，FakeIP 未接入。
- 每个连接都带目的端口，`DST-PORT` 规则在隧道和本地代理里都生效。`PROCESS-NAME` 规则已可解析和匹配，但运行时尚未提供进程名（桌面进程查询是后续工作），目前不会命中。
- 规则集（`routing.rule_sets`，最多 32 个，合计 50 万条）：每个集可含 `domain`、`domain_suffix`、`domain_keyword`、`ip_cidr`。`RULE-SET,<name>` 匹配同名集；`GEOSITE,<category>` 匹配名为 `geosite-<category>` 的集（未配置时整个配置被拒绝）；`GEOIP,<CC>` 匹配 `geoip-<cc>`（小写，未配置时与以前一样不命中）。客户端以普通列表提供 GeoSite/GeoIP 数据，例如 MetaCubeX `meta-rules-dat` 的文本规则集。
- 远程规则集：规则集带 `url` 时由内核自己下载（需要 `local-proxy` feature，iOS 与桌面构建都包含），可选 `format`（`suffix`：裸域名匹配自身与子域名，默认；`domain`：裸域名只匹配自身，即 Clash `behavior: domain`）、`interval_secs`（至少 600，默认 86400）和 `via`（经哪个策略组、节点或 `DIRECT` 下载，默认 `DIRECT`）。内联条目作为初始内容（客户端缓存的副本）；初始为空时启动即下载，之后按间隔刷新，失败保留旧内容并在 5 分钟内重试。下载为 HTTP/1.1 GET（不跟随跳转、不压缩，最大 32 MiB，60 秒超时），列表可以是 Surge/Loon/Clash classical 行、Clash `payload:` YAML 或每行一个域名/网段。运行时控制 `rule_sets` 返回每个集的来源、条目数、最近成功时间和最近错误（不含 URL），`update_rule_sets` 立即刷新全部远程集。
- 运行时控制（见 FFI 边界文档 “Runtime Control”）提供连接列表、模式切换（`rule`/`global`/`direct`，全局目标为 `routing.global`）、策略组列表与 select 切换。

后续工作：Windows MITM 导入路径接入路由；engine-embedded 的 FakeIP、UDP/QUIC 嗅探与桌面进程名查询。
