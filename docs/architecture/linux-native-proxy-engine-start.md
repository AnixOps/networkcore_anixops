# Linux Native Proxy Engine Start Design

本文定义首个原生代理执行内核源码进入仓库前必须满足的 `ProxyEngineService`
adapter、前台生命周期 host 和 `networkcore-linux start` 接线边界。它承接
[Proxy Engine Adapter Interface](proxy-engine-adapter.md)、
[Linux CLI Runtime Wiring Design](linux-cli-runtime-wiring.md)、
[Linux CLI Entrypoint Design](linux-cli-entrypoint.md) 和
[Linux Platform Adapter Design](linux-platform-adapter.md)。

评估时间：2026-07-06。

## 目标

- 明确首个原生执行内核 adapter 的职责、crate 边界和诊断合同。
- 明确 `networkcore-linux start` 何时可以从稳定 unavailable 诊断进入前台运行模式。
- 防止空壳 adapter、一次性配置校验或测试替身被误认为 runtime 已启动。
- 为后续最小 `engine-native` 源码增量提供可验证、可回滚的接线门槛。

## 非目标

- 不在本文实现 TCP、UDP、TUN、DNS、MITM 或透明代理协议。
- 不在本文实现 daemon、control socket、systemd unit、PID file、installer 或 release artifact。
- 不选择 async runtime、socket 库、packet capture、netlink 或平台代理 SDK。
- 不启动外部 `sing-box`、`xray-core`、`mihomo` 或其他二进制。
- 不在本机运行、构建、测试、打包或试用 CLI。

## 当前源码状态

当前仓库已经具备：

- `control-domain::ProxyEngineService` 领域端口，定义 engine descriptor、配置校验、启动、重载、停止、状态和事件读取。
- `control-runtime::RuntimeOrchestrator::start_runtime`，按平台、配置和引擎校验顺序编排启动。
- `config-core::CoreConfigurationService`，提供只读 TOML schema/profile 配置准备。
- `platform-linux::ReadOnlyLinuxPlatformCapabilityService<HostLinuxReadOnlyProbe>`，提供只读 Linux 平台能力诊断。
- `networkcore-linux` binary 只将 `prepare-config` 接入 `RuntimeOrchestrator`；`start` 仍通过 `UnavailableProxyEngineService` 和 `cli.linux.runtime.unwired` 保持未接线。

该状态是正确的安全边界。原生 engine adapter 和前台 host 未完成前，不得把
`LinuxCliCommand::Start` 路由到二进制入口的 `handle_start`。

## Adapter 边界

后续首个源码边界建议为 `crates/engine-native` 或等价 crate。该 crate 必须：

1. 只依赖 `control-domain` 和实现自身需要的最小运行时依赖。
2. 提供 `NativeProxyEngineService` 或等价类型，实现 `ProxyEngineService`。
3. 通过 `list_engines()` 返回 id 为 `native`、kind 为 `ProxyEngineKind::Native` 的 descriptor。
4. 只声明已经真实实现的 `ProxyEngineCapability`，不得预先声明 TUN、DNS、MITM、HotReload 或 HealthCheck。
5. 将所有 adapter 私有错误映射为稳定 `Diagnostic` 或 `DomainError`，不得向 CLI 泄漏内部错误类型、backtrace、socket path 或敏感配置值。
6. 在没有真实运行句柄前，`start()` 必须返回 `DomainError`，不得返回 `Running`。

首个 adapter 可以先实现严格的配置拒绝和生命周期诊断合同，但它不能被接入
`networkcore-linux start`，除非同时具备前台 host 和真实运行句柄。

## 配置输入边界

`ProxyEngineConfig` 是 adapter 唯一的配置输入：

- `engine_id` 必须匹配 `native` 或后续显式支持的 id。
- `config` 只能使用 `ConfigSnapshot` 中已经标准化的字段，不重新解析原始 TOML。
- `nodes` 和 `metadata` 可作为后续订阅、策略或 listener 信息的输入扩展，但不得让 adapter 自行读取额外配置文件。
- 缺少原生 engine 所需 listener、node、policy 或 DNS 信息时，adapter 必须返回错误诊断，不能启动空 runtime。

推荐稳定诊断 code：

| code | severity | 含义 |
| --- | --- | --- |
| `engine.native.config.engine_id_unsupported` | Error | `ProxyEngineConfig.engine_id` 不是当前 adapter 支持的 id |
| `engine.native.config.listener_missing` | Error | 缺少可启动 listener 或入站入口 |
| `engine.native.config.node_missing` | Error | 缺少可用出站节点或直连策略 |
| `engine.native.config.capability_unsupported` | Error | 配置要求的能力当前 adapter 未实现 |
| `engine.native.config.secret_redacted` | Info | 诊断输出已隐藏敏感配置值 |

## 启动语义

`ProxyEngineService::start` 成功返回 `ProxyEngineLifecycleState::Running` 前必须满足：

1. 平台能力已经由 `RuntimeOrchestrator` 确认为可启动。
2. `validate_config` 没有 Error 级诊断。
3. adapter 已创建当前进程内拥有的运行句柄。
4. 运行句柄已经进入可接收生命周期控制或事件观察的状态。
5. 失败路径能返回稳定 `DomainError`，并通过 CLI 映射为 `cli.linux.start.engine_denied` 或更具体的后续 code。

不得把以下情况视为启动成功：

- 只完成配置解析或配置校验。
- 只创建了 descriptor，没有 runtime 句柄。
- 只返回 `Starting`，但没有后续前台 host 持有进程。
- 只启动外部进程但没有状态、事件和退出诊断合同。
- 在测试替身中返回 `Running` 后直接接入 binary。

推荐启动诊断 code：

| code | severity | 含义 |
| --- | --- | --- |
| `engine.native.start.runtime_unavailable` | Error | 原生运行时尚未实现或不可用 |
| `engine.native.start.bind_failed` | Error | listener 绑定失败 |
| `engine.native.start.lifecycle_failed` | Error | 运行句柄创建或进入运行状态失败 |
| `engine.native.start.running` | Info | 原生 runtime 已进入当前进程前台运行状态 |

## 前台生命周期 Host

前台 host 属于 `apps/linux-cli` 或后续应用层 adapter，不属于 `control-runtime` 或
`control-domain`。它必须：

- 只持有当前进程内的 runtime，不 fork、不 daemonize、不安装服务。
- 在 `ProxyEngineService::start` 返回 running 状态后接管当前进程生命周期。
- 聚合平台、配置、引擎和 host 自身诊断后渲染 CLI 输出。
- 明确普通退出、启动失败、运行中失败和用户中断的退出码。
- 在信号处理设计完成前，不承诺跨进程 `stop`、`reload` 或后台 `status`。
- 不写 systemd unit、PID file、launchd plist、Windows service 或 installer 状态。

推荐 host 诊断 code：

| code | severity | 含义 |
| --- | --- | --- |
| `cli.linux.start.foreground_only` | Info | 当前 `start` 只支持前台模式 |
| `cli.linux.start.lifecycle_host_missing` | Error | binary 尚未接入前台 lifecycle host |
| `cli.linux.start.lifecycle_interrupted` | Warning | 前台运行被用户或平台信号中断 |
| `cli.linux.start.lifecycle_failed` | Error | 前台 host 运行阶段失败 |

## `networkcore-linux start` 接线门槛

二进制入口只有在以下条件全部满足后，才能将 `LinuxCliCommand::Start` 从
`handle_entrypoint` 的 unavailable 路径改为 `handle_start` 或等价前台启动路径：

- `engine-native` 或等价 crate 存在，并有 GitHub Actions 覆盖 format、lint、test、build 和 dependency audit。
- adapter 合同测试覆盖 descriptor、配置拒绝、启动失败、running 状态、status、events 和 secret 不泄露。
- 前台 lifecycle host 有源码或设计合同，覆盖不 daemonize、不安装服务、退出码和诊断聚合。
- CLI 合同测试覆盖 `start` 成功、平台拒绝、配置拒绝、engine 拒绝、host 失败和 JSON 输出。
- `stop` 与后台 `status` 继续保持无 daemon/control socket 诊断，不能因为前台 start 合入而声称支持跨进程控制。
- Linux artifact readiness 与安装/回滚文档继续阻止 release asset，直到 packaging、license/NOTICE 和回滚门禁完成。

未满足任一条件时，binary 必须继续组合 `UnavailableProxyEngineService`，并让
`start` 返回 `cli.linux.runtime.unwired`。

## 验证边界

所有验证只在 GitHub Actions 执行。后续源码增量必须至少覆盖：

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --all-targets`
- `cargo build --workspace --all-targets`
- `cargo generate-lockfile`
- `cargo audit`

本地只允许查看文件、编辑文件、查看 diff、提交、推送和查询 GitHub Actions。

## 后续工作

- 先新增最小 `engine-native` crate 的纯 adapter 合同和诊断测试，但不接入 `networkcore-linux start`。
- 当前 `networkcore-linux start` 继续保持 `cli.linux.runtime.unwired`。
- 在真实前台 host 和原生 runtime 运行句柄完成前，不加入 `package-linux`，也不发布 Linux artifact。
