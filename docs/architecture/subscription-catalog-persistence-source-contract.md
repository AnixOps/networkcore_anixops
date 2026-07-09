# Persistent Subscription Catalog Source Contract

本文定义 `v0.1.2-alpha.1` persistent subscription catalog 的前两个源码切片。
它只约束显式本地 catalog 文件的 `add` 和 `list` 操作，后续 `remove`、`select` 和
`update` 必须在本合同基础上逐个增加并分别通过 GitHub Actions 验证。

## Source Of Truth

- `persistent-subscription-catalog-source-contract=active`
- `persistent-subscription-catalog-version-scope=v0.1.2-alpha.1`
- `persistent-subscription-catalog-operation=add`
- `persistent-subscription-catalog-list-operation=list`
- `persistent-subscription-catalog-storage=json`
- `persistent-subscription-catalog-schema-version=1`
- `persistent-subscription-catalog-default-path=blocked`
- `persistent-subscription-catalog-remote-fetch=blocked`
- `persistent-subscription-catalog-file-fetch=blocked`
- `persistent-subscription-catalog-runtime-start=blocked`

## First Operation

首个源码增量提供 `SubscriptionCatalogAddRequest`、`SubscriptionCatalogAddReport` 和
`CommandSubscriptionCatalogStore::add_source`。调用方必须显式提供：

- catalog JSON 文件路径；
- rollback snapshot 文件路径；
- `SubscriptionSource.id`；
- `SubscriptionSource.location`。

catalog 文件不存在时按空 catalog 处理。已存在的 catalog 只允许追加新的 source id；
相同 source id 必须返回稳定的 duplicate 错误，不得覆盖旧 source。

当前 `add` 只保存 source 定义，不执行远程请求、文件订阅读取、解析、节点选择、节点运行、
默认路径扫描、daemon/service、system proxy、system trust store、TUN、DNS 或 firewall mutation。

## Second Operation

第二个源码增量提供 `SubscriptionCatalogListRequest`、`SubscriptionCatalogListEntry`、
`SubscriptionCatalogListReport` 和 `CommandSubscriptionCatalogStore::list_sources`。调用方必须显式
提供 catalog JSON 文件路径。catalog 文件不存在时返回空列表；已存在的 catalog 必须通过 schema
version 和 source 字段校验。

`list` 只读取并生成脱敏报告，不写 catalog、不写 snapshot、不执行远程请求、文件订阅读取、解析、
节点选择、节点运行、默认路径扫描、daemon/service、system proxy、system trust store、TUN、DNS
或 firewall mutation。每个 entry 只输出 source id、location kind 和 `location_redacted=true`，不得
输出完整 location、URL query token、Authorization header、password、private key 或 inline payload。

## Storage Schema

JSON 顶层字段固定为 `schema_version` 和 `sources`：

```json
{
  "schema_version": 1,
  "sources": [
    {"id": "work", "location": "inline:..."}
  ]
}
```

`location` 只用于后续显式 source 解析。CLI report 和 diagnostics 不得输出完整 location、URL
query token、Authorization header、password、private key 或 inline payload；脱敏 report 只输出
source id、location kind 和 `location_redacted=true`。

## Snapshot And Failure Boundary

`add` 写入新 catalog 前必须先写一个不可覆盖的 rollback snapshot，snapshot 保存写入前的完整
catalog JSON。catalog 或 snapshot 路径已存在且不属于本次明确操作时，调用必须拒绝覆盖并返回
稳定错误；写入失败不得报告成功。当前切片只生成 snapshot，不执行 rollback；rollback 操作由
后续独立功能实现。

所有文件路径必须由调用方显式提供。该合同不授权读取用户默认配置目录、环境变量推导路径或
扫描工作区。

## Acceptance Test

第一个合同测试必须证明一次 `add`：

- 将 source 写入 schema version 1 catalog；
- 生成 snapshot；
- report 不包含完整 source location 或 inline payload；
- duplicate source id 不覆盖已有 catalog。

第二个合同测试必须证明一次 `list`：

- 从显式 catalog 路径读取 schema version 1 catalog；
- 返回所有 source id 和数量；
- entry 不包含完整 source location 或 inline payload，并标记 `location_redacted=true`；
- list 不修改 catalog 文件。

测试、构建、格式化、lint 和安全扫描只能在 GitHub Actions 执行。
