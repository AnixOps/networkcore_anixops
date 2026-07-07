# Linux CLI Runtime Wiring Design

本文定义 `networkcore-linux prepare-config` 和 `networkcore-linux start`
接入真实运行层前必须满足的配置服务、代理引擎服务和前台生命周期边界。它承接
[Linux CLI Entrypoint Design](linux-cli-entrypoint.md)、
[Control Runtime Orchestration Design](control-runtime-orchestration.md) 和
[Proxy Engine Adapter Interface](proxy-engine-adapter.md)。

评估时间：2026-07-06。

## 目标

- 明确 Linux CLI 二进制入口如何组合 `ConfigReader`、`ConfigurationService`、
  `PlatformCapabilityService`、`ProxyEngineService` 和 `RuntimeOrchestrator`。
- 为 `prepare-config` 从库函数接入二进制入口定义最小安全前置条件。
- 为 `start` 从稳定 unavailable 诊断进入前台运行模式定义阻断门槛。
- 防止 CLI 用测试替身、空壳引擎或一次性校验结果假装 runtime 已经启动。

## 非目标

- 不在本文实现配置 schema、订阅解析、策略路由、DNS 或代理协议。
- 不定义 daemon、systemd unit、PID file、control socket、后台进程或 installer。
- 不选择 async runtime、信号处理库、外部代理内核或平台 SDK。
- 不允许本机运行、构建、测试、打包或试用 CLI。

## 依赖方向

二进制入口可以组合 adapter，但不能把 adapter 细节传入领域层：

1. `apps/linux-cli` 负责参数解析、显式配置读取、响应渲染和退出码。
2. `platform-linux` 继续通过 `PlatformCapabilityService` 提供只读平台状态。
3. 配置实现应位于后续纯配置 crate 或等价 adapter 中，并实现
   `ConfigurationService`；它不得依赖 Linux 文件系统探测或代理进程。
4. 代理执行实现应位于后续 `engine-*` adapter 中，并实现
   `ProxyEngineService`；它不得把原生错误、进程模型或私有配置泄漏给 CLI。
5. `control-runtime` 只编排领域端口，不能依赖 CLI、Linux adapter、engine
   adapter 或前台生命周期 host。

## prepare-config 接线边界

`prepare-config` 是第一个允许从二进制入口接入运行层的配置命令，但必须保持只读：

- 输入配置必须来自用户显式传入的 `--config <path>`。
- `FsConfigReader` 只读取该文件内容，不扫描默认路径、不创建文件、不写回迁移结果。
- 配置服务可以校验、迁移和标准化内存中的原始文本，但不得读取额外文件或发起网络请求。
- 平台能力来自 `ReadOnlyLinuxPlatformCapabilityService<HostLinuxReadOnlyProbe>`。
- 输出可以包含标准化配置 profile、平台状态和诊断，但不得输出 token、密码、私钥、证书私钥或完整订阅 URL secret。
- 失败继续映射到现有 CLI code：路径缺失、读取失败和空配置使用
  `cli.linux.config.*`；领域配置拒绝保留稳定 `DomainError` code，后续如需要再补充
  prepare-config 专用 CLI wrapper code。

首个源码增量可以只接入一个最小纯配置服务，实现稳定 schema 版本、profile
抽取和诊断映射；它不需要也不应启动代理引擎。

## start 接线边界

`start` 只有在以下条件全部满足后才能从
`cli.linux.runtime.unwired` 或更具体的 unavailable 诊断进入前台启动路径：

- 存在非测试替身的 `ConfigurationService` 实现。
- 存在非空壳的 `ProxyEngineService` 实现，能够真实拥有当前进程内的运行生命周期。
- 已定义前台生命周期 host，明确何时进入运行、何时退出、如何聚合退出诊断。
- `start` 成功退出码只在 runtime 确认进入可用运行状态后返回；不能用一次配置校验成功代替启动成功。
- 外部代理二进制进入前，必须已有对应 engine adapter 设计、artifact 依赖来源和 release packaging 边界。

允许的 `start` 数据流：

1. 解析参数并读取显式配置。
2. 通过只读 Linux platform adapter 获取平台状态。
3. 调用 `RuntimeOrchestrator::prepare_config` 或等价配置准备路径。
4. 构造 `ProxyEngineConfig` 并调用 `ProxyEngineService::validate_config`。
5. 在平台、配置和引擎均允许后，调用 `ProxyEngineService::start`。
6. 由前台生命周期 host 持有当前进程，不 fork、不 daemonize、不安装服务。
7. 聚合平台、配置、引擎和 CLI 生命周期诊断后渲染输出。

## 前台生命周期 host

前台 host 属于 CLI 或后续应用层 adapter，不属于 `control-runtime`：

- 它只管理当前进程内 runtime，不停止其他进程。
- 它不得写 systemd unit、PID file、launchd plist、Windows service 或 installer 状态。
- 在信号处理设计完成前，不承诺跨进程 `stop`、`reload` 或后台状态查询。
- 如果引擎 adapter 需要事件循环、文件描述符、任务调度或信号处理，必须先补充 adapter 设计和 GitHub Actions 验证。
- 进程退出时必须把可展示错误转换为 `Diagnostic`，并保持 CLI exit code 稳定。

## 诊断顺序

CLI 接线后的诊断应保持可预测顺序：

1. 参数和配置读取诊断。
2. 平台能力诊断。
3. 配置校验和标准化诊断。
4. 引擎配置校验诊断。
5. 启动或前台生命周期诊断。

错误路径不得吞掉前序诊断。任何 adapter 私有错误必须映射为稳定领域或 CLI
diagnostic code。

## 验收条件

后续源码接线必须满足：

- `prepare-config` 接入二进制入口前，配置服务有合同测试覆盖成功、空配置、非法配置、平台拒绝诊断保留和 secret 不输出边界。
- `start` 接入二进制入口前，按 [Linux Native Proxy Engine Start Design](linux-native-proxy-engine-start.md) 完成代理引擎 adapter 合同测试，覆盖配置拒绝、启动失败、运行状态和诊断传播。
- 前台生命周期 host 按 [Linux Native Proxy Engine Start Design](linux-native-proxy-engine-start.md) 完成设计或源码合同，明确不 daemonize、不安装服务、不修改系统配置。
- `.github/workflows/ci.yml` 必须在 GitHub Actions 中验证新增源码的 format、lint、test、build 和 dependency audit。
- 不在本机运行 CLI、构建、测试或打包验证。

## 后续工作

- `config-core` 已提供最小纯配置服务，`networkcore-linux prepare-config` 已接入二进制入口；后续配置扩展继续保持纯内存解析和 secret 不泄露边界。
- `networkcore-linux start` 已接入 `NativeProxyEngineService` 和 current-process foreground lifecycle host；前台 lifecycle 已具备可注入 signal/interruption 合同、Unix `SIGINT`/`SIGTERM` OS signal source、`cli.linux.start.signal_received`/`cli.linux.start.lifecycle_interrupted` 诊断、130 退出码映射，以及 interruption 后通过当前进程内 `RuntimeOrchestrator::stop_runtime` 聚合 native runtime stop/release 诊断的合同。
- Linux artifact readiness/release gate 已纳入 foreground stop/release 合同检查、artifact manifest 输出合同、license/NOTICE confirmation source contract、license/NOTICE transition validation contract、release placeholder license/NOTICE pending 状态 summary、release CI success source contract、release CI gate activation validation contract、package runner/toolchain/target contract、archive staging contract、checksum/manifest checksum contract、publish/upload boundary contract、signing/attestation policy binding contract、release notes/rollback policy binding contract 和 publish eligibility aggregate contract；当前 pending marker 与 CI activation placeholder 继续阻止 `package-linux`。
- 下一步补充 Linux package artifact job preflight validation contract，仍不生成 artifact。
- daemon/control socket、service install、DNS/TUN mutation 或 release artifact 进入前，继续先补设计和回滚合同。
