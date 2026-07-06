# Linux Platform Adapter Design

本文件定义后续 Linux platform adapter crate 或等价模块落地前必须遵守的能力探测、权限、DNS、服务管理和诊断边界。它承接 [Control Kernel Domain Specification](control-kernel-domain.md)、[Control Runtime Orchestration Design](control-runtime-orchestration.md) 和 [Linux Artifact Pre-Release Design](linux-artifact-pre-release-design.md)，用于防止 Linux 系统 API 泄漏到领域层或运行编排层。

评估时间：2026-07-06。

## 目标

- 定义 Linux adapter 如何实现 `PlatformCapabilityService`，并把 Linux 能力映射为领域可消费的 `PlatformCapabilityStatus`。
- 明确 TUN、权限、DNS、服务管理、证书和诊断探测边界。
- 保持 `control-domain` 与 `control-runtime` 不依赖 Linux 文件系统、capability、systemd、NetworkManager 或 iproute2 细节。
- 为后续 Linux CLI、daemon 和 release artifact 提供源码前置设计。

## 非目标

- 不在本阶段实现 `platform-linux` crate、CLI、daemon、systemd unit、installer 或 release artifact。
- 不在本机探测 `/dev/net/tun`、capability、DNS 配置、systemd 状态或证书信任。
- 不修改路由、DNS、防火墙、证书信任、systemd unit 或内核参数。
- 不假设所有 Linux 发行版都存在 systemd、NetworkManager、resolved、iptables、nftables 或相同 CA trust store。

## 架构位置

Linux adapter 必须位于后续平台 adapter 层，例如 `crates/platform-linux` 或等价 crate。依赖方向必须保持：

1. `control-domain` 定义 `PlatformCapabilityService`、`PlatformCapabilityStatus`、`PlatformFeatureState` 和诊断类型。
2. `control-runtime` 只调用 `PlatformCapabilityService` 并聚合诊断。
3. Linux adapter 依赖 `control-domain`，可以被 Linux CLI、daemon 或测试替身注入到 `control-runtime`。
4. Linux adapter 可以在自身边界内使用 Linux 文件系统、capability、netlink、systemd、resolved、NetworkManager 或证书命令，但不得把这些类型暴露给领域层。

首个 Linux adapter 应保持 library-first，优先提供只读能力探测和测试替身。任何会修改系统状态的操作必须单独设计并由用户明确触发。

## 能力映射

Linux adapter 初始只负责报告能力状态，不负责自动启用能力：

| 领域字段 | Linux 映射 | 初始策略 |
| --- | --- | --- |
| `os` | 固定为 `OperatingSystem::Linux` | adapter 内部设置，不从上层传入 |
| `tunnel` | `/dev/net/tun` 存在性、可读写性、`CAP_NET_ADMIN` 或 root 权限 | 缺失或权限不足时返回 `Unavailable` |
| `mitm` | 用户配置、证书状态、平台策略和插件权限组合后的 MITM 可用性 | 默认不可自动启用，必须保留诊断 |
| `embedded_runtime` | 本进程可加载或链接核心运行时的能力 | CLI 阶段通常为 `Available`，daemon/动态库另行设计 |
| `remote_script_execution` | 平台是否允许执行已授权插件脚本 | Linux 可表达为 `Available`，但仍受插件权限和配置门禁约束 |
| `mitm_certificate` | CA 文件、fingerprint、trust store 状态和撤销状态 | 不安装证书，只报告 `NotInstalled`、`InstalledUntrusted`、`Trusted`、`Revoked` 或 `Unknown` |
| `diagnostics` | Linux 探测警告、权限不足、发行版差异和不可判定状态 | 使用稳定 `platform.linux.*` code |

## TUN 探测边界

TUN 探测必须是只读或最小副作用：

- 可以检查 `/dev/net/tun` 是否存在以及当前进程是否具备打开设备的权限。
- 可以检查当前有效用户、Linux capability、容器限制或 runner 限制是否可能阻止 TUN。
- 不应创建持久 TUN 设备，不应配置 IP、路由、MTU 或防火墙规则。
- 不应在探测阶段执行需要修改系统状态的 `ip tuntap add`、`ip link set` 或等价命令。
- 无法判定时返回 `PlatformFeatureState::Unknown`，并输出可展示诊断。

推荐诊断：

| code | severity | 含义 |
| --- | --- | --- |
| `platform.linux.tun.device_missing` | Error | `/dev/net/tun` 不存在或不可访问 |
| `platform.linux.tun.permission_denied` | Error | 当前进程缺少打开 TUN 所需权限 |
| `platform.linux.tun.cap_net_admin_missing` | Warning | 缺少后续配置 TUN 或路由通常需要的 capability |
| `platform.linux.tun.probe_unknown` | Warning | 容器、sandbox 或发行版差异导致无法可靠判断 |

## 权限边界

Linux adapter 必须把权限作为能力诊断返回，而不是尝试提权：

- 不调用 `sudo`、`pkexec`、setuid helper 或交互式授权弹窗。
- 不自动写入 capability，例如不执行 `setcap cap_net_admin+ep`。
- 不假设以 root 运行就是可接受部署形态；root/capability 要求必须进入安装和运行说明。
- 所有权限不足都映射为稳定诊断，供 CLI 或 UI 展示后由用户决定是否处理。

推荐诊断：

| code | severity | 含义 |
| --- | --- | --- |
| `platform.linux.permission.not_root` | Info | 当前进程不是 root，仅作为诊断事实 |
| `platform.linux.permission.capability_missing` | Warning | 缺少某项 Linux capability |
| `platform.linux.permission.elevation_required` | Error | 后续操作需要额外授权才能继续 |
| `platform.linux.permission.probe_failed` | Warning | 权限探测失败但不应阻断所有能力 |

## DNS 边界

首个 Linux adapter 不自动修改系统 DNS。DNS 探测只用于诊断和后续设计：

- 可以识别 `/etc/resolv.conf` 是普通文件、符号链接、systemd-resolved stub，或由 NetworkManager 管理。
- 可以报告 systemd-resolved、NetworkManager 或其他 DNS 管理方式是否可见。
- 不写入 `/etc/resolv.conf`，不调用 `resolvectl dns`、`nmcli connection modify` 或等价修改命令。
- 后续如需要接管 DNS，必须先设计可撤销的配置、冲突检测和回滚步骤。

推荐诊断：

| code | severity | 含义 |
| --- | --- | --- |
| `platform.linux.dns.manager_detected` | Info | 检测到 DNS 管理器，例如 resolved 或 NetworkManager |
| `platform.linux.dns.resolv_conf_readonly` | Warning | `/etc/resolv.conf` 不可写或不应由本进程写入 |
| `platform.linux.dns.manager_unknown` | Warning | 无法可靠识别 DNS 管理方式 |
| `platform.linux.dns.mutation_not_supported` | Info | 当前 adapter 只读探测，不支持自动修改 DNS |

## 服务管理边界

Linux daemon 模式和服务管理必须独立设计。adapter 探测阶段不得假设 systemd 一定存在：

- 可以只读识别 systemd、OpenRC、runit、容器 init 或无 init 环境。
- 不安装、启用、启动、停止或修改 service unit。
- 不写入 `/etc/systemd/system`、用户 systemd 目录或 init 脚本目录。
- 后续 system service 必须定义安装、升级、卸载、日志和回滚流程。

推荐诊断：

| code | severity | 含义 |
| --- | --- | --- |
| `platform.linux.service.systemd_detected` | Info | 检测到 systemd 可用 |
| `platform.linux.service.manager_unknown` | Warning | 无法确认服务管理器 |
| `platform.linux.service.unsupported_environment` | Warning | 当前环境不适合安装或管理 daemon |
| `platform.linux.service.mutation_not_supported` | Info | 当前 adapter 不执行服务安装或管理 |

## 证书边界

MITM CA 证书在 Linux 上必须显式授权和可撤销：

- adapter 可以只读检查项目管理的 CA 文件、fingerprint 和常见 trust store 状态。
- 不自动复制证书到 `/usr/local/share/ca-certificates`、NSS DB、p11-kit、Firefox profile 或其他 trust store。
- 不自动执行 `update-ca-certificates`、`trust anchor`、`certutil` 或发行版专用信任命令。
- 证书安装、信任、撤销和浏览器 profile 兼容性必须作为后续单独设计。

推荐诊断：

| code | severity | 含义 |
| --- | --- | --- |
| `platform.linux.mitm_certificate.not_installed` | Warning | 未发现项目 MITM CA |
| `platform.linux.mitm_certificate.installed_untrusted` | Warning | 已发现 CA 但系统或应用未信任 |
| `platform.linux.mitm_certificate.trusted` | Info | 已确认 CA 被目标 trust store 信任 |
| `platform.linux.mitm_certificate.revoked` | Error | CA 被标记为撤销或不应继续使用 |
| `platform.linux.mitm_certificate.probe_unknown` | Warning | 证书信任状态无法可靠判断 |

## 路由与防火墙边界

首个 Linux adapter 不修改路由、防火墙或透明代理规则：

- 可以报告是否可能需要 `CAP_NET_ADMIN`、iproute2、nftables 或 policy routing 支持。
- 不执行 `ip route`、`ip rule`、`iptables`、`nft`、`sysctl` 或等价修改命令。
- 透明代理、TProxy、redirect、mark 和 policy routing 必须在后续代理/网络执行设计中单独建模。

## 诊断契约

Linux adapter 输出的 `Diagnostic` 必须满足：

- `code` 稳定，使用 `platform.linux.<area>.<reason>` 前缀。
- `source` 指向领域能力字段或 Linux 探测区域，例如 `platform.tunnel`、`platform.dns`、`platform.service`、`platform.mitm_certificate`。
- `message` 面向用户或日志解释，不要求上层解析。
- Error 级别表示当前能力不可用；Warning 表示可继续但需要展示；Info 表示事实记录。
- adapter 私有错误必须转换为 `DomainError` 或 `Diagnostic`，不能暴露 Linux crate、syscall 或命令库错误类型。

## 首个源码增量验收条件

创建 Linux adapter 源码前必须满足：

- 本设计文档保持在 README、ROADMAP、Release Strategy 和 CI policy 中可发现。
- 后续 `platform-linux` 或等价 crate 只依赖 `control-domain` 和必要的 Linux 探测依赖，不依赖 `control-runtime` 的具体实现细节。
- 提供纯测试替身覆盖 TUN 可用、TUN 缺失、权限不足、DNS 管理器未知、服务管理器未知和证书状态矩阵。
- GitHub Actions 中 Rust format、lint、test、build 和 dependency audit 通过。
- 不在本机执行 Linux 能力探测、构建、测试或打包验证。

## 后续工作

- 补充 Linux CLI entrypoint 设计文档，明确首个可运行入口、配置加载、启动/停止和状态查询边界。
- Linux adapter 源码落地时，同步更新 `docs/release-strategy.md`、`README.md`、`CHANGELOG.md` 和 `TODO.md`。
- Linux artifact 进入 release workflow 前，仍必须满足 [Linux Artifact Pre-Release Design](linux-artifact-pre-release-design.md) 的 packaging、checksum、签名/证明和回滚契约。
