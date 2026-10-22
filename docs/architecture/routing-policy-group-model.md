# 规则与策略组模型（M2）

本文件是 M2「规则与策略组模型」的设计说明与验收清单。规则与策略组是 `config-core` 的一等对象，桌面端经 `engine-singbox` 翻译为 sing-box `route`，iOS/macOS NE 内的 `engine-embedded` 直接调用同一模型的决策接口。两条路径共用一份快照夹具，防止行为分叉。

## 范围

- 规则：`DOMAIN`、`DOMAIN-SUFFIX`、`IP-CIDR`/`IP-CIDR6`（可带 `no-resolve`）、`GEOIP`、`FINAL`。
- 策略组：`select`、`url-test`、`fallback`。
- 目标：`DIRECT`、`REJECT`、策略组 id、节点 id（保留名大小写不敏感）。
- 非目标：`DOMAIN-KEYWORD`、`USER-AGENT`、`URL-REGEX`、`PROCESS-NAME`、远程规则集、`load-balance` 组、Loon `[Rule]` 段整段解析（M3 复用 `parse_rule_line`）。

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
- 域名统一小写、去掉结尾点；`DOMAIN-SUFFIX` 去掉开头点，匹配自身与全部子域名。
- CIDR 归一化为网络地址（`10.1.2.3/8` → `10.0.0.0/8`）。

## 决策接口（engine-embedded 使用）

`RoutingModel::decide(&RouteQuery, &dyn RoutingEnvironment) -> RouteResolution`

- `RouteQuery { domain, ip }`：FakeIP/嗅探得到的域名与目的地址。
- `RoutingEnvironment` 提供 GeoIP 查询、DNS 解析、select 当前选择、成员测速结果；全部方法有保守默认值，`StaticRoutingEnvironment` 即无运行时状态。
- 第一条不带 `no-resolve` 的 IP 规则触发一次解析，之后所有 IP 规则使用解析结果，与 sing-box `resolve` 动作一致。
- 组选择：`select` 用环境选择 → `default` → 第一个成员；`url-test` 取延迟最低的成员（无结果时取第一个）；`fallback` 取第一个有测速结果的成员（都没有时取第一个）。
- `RouteResolution` 返回命中规则序号或 `FINAL`、规则目标、经过的组路径、最终 `Direct/Reject/Node(id)` 与解析出的地址，可直接用于诊断页。

## sing-box 翻译（engine-singbox）

`render_sing_box_route(&RoutingModel) -> SingBoxRouteFragment { outbounds, route }`

- 规则一对一按序翻译为 rule action（sing-box 1.11+）：`domain`、`domain_suffix`、`ip_cidr`、`rule_set`；`REJECT` 为 `action: reject`，其他为 `action: route` + `outbound`。
- 第一条需要解析的 IP 规则前插入 `{ "action": "resolve" }`。
- `GEOIP,CN` 翻译为 `rule_set: ["geoip-cn"]`，并生成指向 `SagerNet/sing-geoip` 的远程 `.srs` 规则集，经 `direct` 下载。
- `FINAL,<目标>` 写入 `route.final`；`FINAL,REJECT` 追加无条件 `reject` 规则，`final` 为 `direct`。
- `select` → `selector`；`url-test` → `urltest`；`fallback` → `urltest` 且 `tolerance = 65535`。
- 片段只含策略组出站与 `route`；调用方负责节点出站（tag 为节点 id）和 `direct` 出站。

## 已知差异

- sing-box 没有按顺序回落的 fallback 组。翻译结果首次选择的是最快成员，之后只在当前成员失败时切换；`engine-embedded` 实现严格按顺序回落。快照用无测速状态的环境，两边都取第一个成员。
- sing-box `resolve` 失败时连接报错；决策接口在解析失败时继续匹配后续规则直至 `FINAL`。
- 组内 `REJECT` 暂不支持，因为 sing-box 1.13 起移除了 `block` 出站。

## 快照夹具与验收

夹具位于 `testdata/routing-snapshot/`：

| 文件 | 校验方 |
| --- | --- |
| `config.toml` | 两侧共用的输入 |
| `decisions.json` | `crates/config-core/tests/routing_contracts.rs`：静态与带运行时状态两种环境下的逐条决策 |
| `sing-box-route.json` | `crates/engine-singbox/tests/route_contracts.rs`：完整 sing-box 片段 |

修改路由语义时必须同时更新两个快照。验收标准：上述测试在 GitHub Actions 全矩阵中通过。

后续工作：把片段接入 `render_sing_box_local_proxy_*` 配置生成；在 Linux CI 上运行真实 sing-box，用同一组 `decisions.json` 用例做端到端等价性测试；`engine-embedded` 接入 `decide`。
