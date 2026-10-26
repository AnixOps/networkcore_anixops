# Third-Party Notices

NetworkCore 源码以 Apache-2.0 发布。本文件说明仓库涉及的第三方名称与代码来源，以及已移除外部执行内核的记录。

## 外部执行内核

仓库不再托管、启动或调用任何第三方执行内核；所有平台的数据面由仓库内自研的 Rust 引擎实现。

## 仅用于 CI 的互通测试服务端

`REALITY interop (Linux)` CI job 在 GitHub Actions runner 上临时下载 Xray-core（https://github.com/XTLS/Xray-core ，MPL-2.0）与 sing-box 的官方 release 二进制，只作为本机回环上的 REALITY 测试服务端，用来验证 `crates/outbound-vless` 的协议互通。它们不进入仓库、不进入任何发布产物；`tls-mimic` 与 `outbound-vless` 是按协议行为独立编写的 Rust 实现，不包含两者的代码。

## 订阅格式名称

Clash、Surge、Loon、Quantumult X、V2Ray 等名称只用于描述兼容的订阅或配置格式，仓库不包含这些产品的代码。

## Rust 与前端依赖

`Cargo.lock` 和 `apps/windows-gui/ui/pnpm-lock.yaml` 列出的开源依赖按各自许可证使用，发布产物的完整依赖许可证清单以 lockfile 为准。

Rust 依赖的许可证由 CI `rust-security-audit` job 中的 `cargo deny check licenses` 按根目录 `deny.toml` 白名单检查：只允许宽松许可证和文件级 copyleft 的 MPL-2.0，拒绝 GPL、AGPL、仅 LGPL、SSPL 以及源码可见类许可证。这样闭源的 App Store 客户端可以链接本仓库内核。

## 静态链接的 C 代码

`crates/script-runtime` 通过 rquickjs（https://github.com/DelSkayn/rquickjs ，MIT）把 QuickJS-ng（https://github.com/quickjs-ng/quickjs ，MIT）编译进桌面端二进制，用于运行 Loon `[Script]` 脚本。二者以 crates.io 源码包形式由 Cargo 获取，不 vendor 进本仓库；发布产物需要附带其 MIT 许可证文本。iOS 不链接 QuickJS，M4 改用系统 JavaScriptCore。

## 自有子模块

`third_party/mitm_anixops` 指向 AnixOps 自有仓库 https://github.com/AnixOps/mitm_anixops，不属于第三方代码。

## 移除记录

2026-10-26：`engine-singbox`、`engine-mieru` 及相关 UI、命令、文档和 CI 守卫已删除，桌面端改用自研嵌入式引擎。订阅里的 sing-box JSON 和 `mierus://` 链接仍可作为格式导入。同日删除 Windows 前台隧道及其外部组网程序适配（`tunnel` 命令、托管隧道配置、隧道运行时与安全存储），SD-WAN 组网等 ANX 私有协议提供。
