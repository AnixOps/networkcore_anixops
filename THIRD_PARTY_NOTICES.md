# Third-Party Notices

NetworkCore 源码以 Apache-2.0 发布。本文件说明仓库会调用、但不包含也不分发的外部执行内核，以及它们的移除计划。

## 外部执行内核

下列程序不 vendor 进本仓库，也不打包进 Linux tarball、Windows MSI 或 portable ZIP。它们只在用户显式安装或指定可执行文件路径后，作为独立子进程运行；NetworkCore 只生成其配置并管理进程生命周期，不链接其代码。

| 程序 | 上游 | 许可证 | 仓库中的适配代码 | 平台 |
| --- | --- | --- | --- | --- |
| sing-box | https://github.com/SagerNet/sing-box | GPL-3.0-or-later，附加条款：衍生作品不得使用其名称或暗示关联 | `crates/engine-singbox` | Linux、Windows |
| Mieru | https://github.com/enfein/mieru | GPL-3.0 | `crates/engine-mieru` | Linux、Windows |
| EasyTier | https://github.com/EasyTier/EasyTier | LGPL-3.0 | `apps/windows-cli`、`crates/platform-windows`、`crates/config-core/src/windows_tunnel.rs` | Windows |

NetworkCore 与上述项目没有隶属或合作关系。仓库中出现的这些名称只用于说明调用的是哪个外部程序。

iOS Network Extension 不使用上述任何程序，数据面由仓库内自研的 Rust 内核实现。

## 仅用于 CI 的互通测试服务端

`REALITY interop (Linux)` CI job 在 GitHub Actions runner 上临时下载 Xray-core（https://github.com/XTLS/Xray-core ，MPL-2.0）与 sing-box 的官方 release 二进制，只作为本机回环上的 REALITY 测试服务端，用来验证 `crates/outbound-vless` 的协议互通。它们不进入仓库、不进入任何发布产物；`tls-mimic` 与 `outbound-vless` 是按协议行为独立编写的 Rust 实现，不包含两者的代码。

## 订阅格式名称

Clash、Surge、Loon、Quantumult X、V2Ray 等名称只用于描述兼容的订阅或配置格式，仓库不包含这些产品的代码。

## Rust 与前端依赖

`Cargo.lock` 和 `apps/windows-gui/ui/pnpm-lock.yaml` 列出的开源依赖按各自许可证使用，发布产物的完整依赖许可证清单以 lockfile 为准。

## 静态链接的 C 代码

`crates/script-runtime` 通过 rquickjs（https://github.com/DelSkayn/rquickjs ，MIT）把 QuickJS-ng（https://github.com/quickjs-ng/quickjs ，MIT）编译进桌面端二进制，用于运行 Loon `[Script]` 脚本。二者以 crates.io 源码包形式由 Cargo 获取，不 vendor 进本仓库；发布产物需要附带其 MIT 许可证文本。iOS 不链接 QuickJS，M4 改用系统 JavaScriptCore。

## 自有子模块

`third_party/mitm_anixops` 指向 AnixOps 自有仓库 https://github.com/AnixOps/mitm_anixops，不属于第三方代码。

## 移除计划

2026-10-22 决定：外部执行内核暂时保留，由自研内核分阶段替换。

1. M0（v0.2.0-beta.5）：不改动，桌面数据面继续使用 sing-box 与 Mieru。
2. M2 起：自研内核接入桌面端，与 sing-box 跑路由一致性 CI。
3. 自研内核覆盖桌面端所需协议后：删除 `engine-singbox`、`engine-mieru` 及相关 UI、文档和 CI 守卫。
4. EasyTier 隧道在桌面 TUN 由自研内核提供后同步移除或替换。
