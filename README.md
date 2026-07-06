# networkcore_AnixOps

`networkcore_AnixOps` 是面向全平台网络内核、MITM 插件兼容和客户端体系的规划与实现仓库。

## 目标

- 构建 Linux、macOS、Windows、iOS 可用的统一网络控制内核。
- 优先支持本仓库内核，同时保留 `sing-box`、`xray-core`、`mihomo` 等多内核适配能力。
- 支持类似 Loon、Quantumult X 的 MITM 插件系统，优先兼容 Loon 插件格式的高频子集。
- 建设全平台客户端，重点验证 iOS Network Extension、MITM、插件脚本、App Review 的可操作性。

## 工作方式

本仓库执行严格的 CI/CD 优先策略：

- 本机只写代码和文档。
- 所有测试、构建、编译、打包、发布验证均由 GitHub Actions 完成。
- 本地不运行构建或测试命令。
- GitHub Actions 未打通前，需要人工介入的事项记录在 `docs/manual-intervention.md`。

详细规则见：

- [AGENT.md](AGENT.md)
- [docs/ci-cd-policy.md](docs/ci-cd-policy.md)
- [docs/release-strategy.md](docs/release-strategy.md)
- [docs/architecture/control-kernel-domain.md](docs/architecture/control-kernel-domain.md)
- [docs/architecture/control-kernel-interfaces.md](docs/architecture/control-kernel-interfaces.md)
- [docs/architecture/proxy-engine-adapter.md](docs/architecture/proxy-engine-adapter.md)
- [docs/architecture/control-runtime-orchestration.md](docs/architecture/control-runtime-orchestration.md)
- [docs/architecture/ios-platform-risk-assessment.md](docs/architecture/ios-platform-risk-assessment.md)
- [docs/architecture/linux-artifact-pre-release-design.md](docs/architecture/linux-artifact-pre-release-design.md)
- [docs/architecture/linux-platform-adapter.md](docs/architecture/linux-platform-adapter.md)
- [docs/architecture/linux-cli-entrypoint.md](docs/architecture/linux-cli-entrypoint.md)
- [docs/architecture/linux-cli-runtime-wiring.md](docs/architecture/linux-cli-runtime-wiring.md)
- [docs/architecture/native-engine-listener-node-config.md](docs/architecture/native-engine-listener-node-config.md)
- [docs/architecture/linux-native-proxy-engine-start.md](docs/architecture/linux-native-proxy-engine-start.md)
- [docs/architecture/linux-cli-artifact-installation-rollback.md](docs/architecture/linux-cli-artifact-installation-rollback.md)
- [docs/architecture/adr-0001-initial-core-stack.md](docs/architecture/adr-0001-initial-core-stack.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [ROADMAP.md](ROADMAP.md)
- [TODO.md](TODO.md)
- [CHANGELOG.md](CHANGELOG.md)

## 当前状态

补充说明：`engine-native` 已新增 service-owned runtime state 与 foreground lifecycle handoff 源码合同；有效配置可让 `NativeProxyEngineService::start` 在当前进程内持有 loopback TCP accept loop runtime 并返回 `Running`，`status`/`events`/`stop` 可观察和释放该 runtime。`networkcore-linux start` binary 仍未接入，继续保持 `cli.linux.runtime.unwired`。

当前仓库处于 P2 初始内核骨架阶段，已建立协作规范、规划治理入口、架构规格、运行层编排设计、发布策略、iOS 平台风险评估、Linux artifact 发布前设计、Linux platform adapter 设计、Linux CLI entrypoint 设计、Linux CLI runtime wiring 设计、Native engine listener/node 配置设计、Linux native proxy engine start 设计、Linux CLI artifact 安装/卸载/回滚设计、Rust 首选栈决策、最小 `control-domain` crate、control-domain listener 配置领域类型、最小 `control-runtime` crate、最小 `config-core` crate、config-core listener/node/route TOML 解析、最小 `engine-native` crate、engine-native listener/node/route 图校验、engine-native native runtime handle 源码合同、engine-native loopback TCP listener 绑定/释放、engine-native runtime assembly plan 源码合同、engine-native loopback TCP accept loop 受控关闭源码合同、engine-native service-owned runtime state 与 foreground lifecycle handoff 源码合同、engine-native accepted TCP connection 协议前置关闭诊断合同、engine-native SOCKS5 greeting 版本/认证方法读取诊断合同、engine-native SOCKS5 no-auth 方法选择/unsupported auth 方法拒绝诊断合同、engine-native SOCKS5 认证方法响应写入诊断合同、engine-native SOCKS5 命令头读取/unsupported command 拒绝诊断合同、engine-native SOCKS5 CONNECT 目标地址读取、route/outbound 行为选择、SOCKS outbound CONNECT request frame 生成、SOCKS outbound TCP connection plan、SOCKS outbound TCP connection attempt、SOCKS outbound CONNECT request write、SOCKS outbound CONNECT response read、SOCKS outbound CONNECT response decision、SOCKS outbound CONNECT relay readiness、SOCKS outbound CONNECT data relay plan、SOCKS outbound CONNECT data relay execution、SOCKS outbound CONNECT client success response readiness、SOCKS outbound CONNECT client success response write plan、SOCKS outbound CONNECT client success response write、accept loop client success response 与有限 data relay 接线、未接入拒绝与 CONNECT failure response 写入诊断合同、最小 `platform-linux` crate、最小 `networkcore-linux` CLI crate、MITM gate 初始门禁用例、平台 MITM 不可用拒绝路径、证书状态拒绝矩阵、证书诊断拒绝保留路径、manifest 诊断拒绝路径、manifest 错误拒绝审计边界、manifest 错误优先于权限拒绝路径、manifest 错误拒绝平台诊断保留路径、manifest 错误拒绝证书诊断保留路径、manifest 错误拒绝诊断顺序路径、manifest 非错误诊断聚合路径、manifest 诊断权限拒绝保留路径、权限拒绝诊断顺序路径、插件结果诊断聚合路径、平台诊断聚合路径、平台诊断拒绝保留路径、远程脚本执行拒绝路径、远程脚本诊断拒绝保留路径、远程脚本未知状态拒绝路径、Linux 诊断映射合同测试、Linux 只读平台探测服务、Linux CLI 只读平台探测接线、Linux CLI `prepare-config` 运行层接线、Linux CLI 前台 lifecycle host 源码合同、Linux CLI 命令解析、配置读取、平台拒绝、stop/status 和 JSON 输出合同测试、权限拒绝审计边界、审计事件聚合边界、平台能力状态类型、Rust 依赖安全扫描 CI、Rust build/test summary 门禁、Go/Node/Swift/Apple 条件 summary 门禁、CI 项目类型检测输出、GitHub Step Summary 表格、Linux artifact readiness gate、release placeholder summary、release source summary、release source policy gate、release CI gate placeholder、release artifact checksum contract、release signing/attestation contract 和 release rollback contract。后续实现必须先补齐对应规格或设计说明，并通过 CI/CD 验证。

## 源码布局

- [apps/linux-cli](apps/linux-cli)：`networkcore-linux` CLI 入口的首批命令解析、配置读取边界、只读平台探测接线、`prepare-config` 运行层接线、前台 lifecycle host 源码合同和诊断输出。
- [crates/config-core](crates/config-core)：统一控制内核的首批纯配置解析和标准化服务，当前覆盖 schema/profile 与最小 listener/node/route TOML 子集。
- [crates/control-domain](crates/control-domain)：统一控制内核的首批领域类型与端口 trait。
- [crates/control-runtime](crates/control-runtime)：组合领域端口的首批纯运行层编排用例。
- [crates/engine-native](crates/engine-native)：原生代理执行内核的首批 adapter 合同、listener/node/route 图校验、native runtime handle 源码合同、loopback TCP listener 绑定/释放、runtime assembly plan、loopback TCP accept loop 受控关闭合同、service-owned runtime state 与 foreground lifecycle handoff 源码合同、accepted TCP connection 协议前置关闭诊断合同、SOCKS5 greeting 版本/认证方法读取诊断合同、SOCKS5 no-auth 方法选择/unsupported auth 方法拒绝诊断合同、SOCKS5 认证方法响应写入诊断合同、SOCKS5 命令头读取/unsupported command 拒绝诊断合同、SOCKS5 CONNECT 目标地址读取、route/outbound 行为选择、SOCKS outbound CONNECT request frame 生成、SOCKS outbound TCP connection plan、SOCKS outbound TCP connection attempt、SOCKS outbound CONNECT request write、SOCKS outbound CONNECT response read、SOCKS outbound CONNECT response decision、SOCKS outbound CONNECT relay readiness、SOCKS outbound CONNECT data relay plan、SOCKS outbound CONNECT data relay execution、SOCKS outbound CONNECT client success response readiness、SOCKS outbound CONNECT client success response write plan、SOCKS outbound CONNECT client success response write、accept loop client success response 与有限 data relay 接线、未接入拒绝与 CONNECT failure response 写入诊断合同、配置拒绝和生命周期诊断。
- [crates/platform-linux](crates/platform-linux)：Linux 平台能力 adapter 的首批只读诊断映射、测试替身和 host probe 服务。
