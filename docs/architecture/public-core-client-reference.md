# Public Core Client Reference

评估基线：2026-07-23。

本文记录 NetworkCore 对公开项目的工程借鉴边界。它不是第三方项目的
功能承诺，也不把外部代码复制进本仓库。

## sing-box

官方项目：

- https://github.com/SagerNet/sing-box
- https://sing-box.sagernet.org/configuration/
- https://sing-box.sagernet.org/configuration/inbound/
- https://sing-box.sagernet.org/configuration/log/

采用的经验：

- sing-box 作为独立 public core 进程，由客户端负责版本、资产、配置和
  生命周期，而不是把协议实现复制进 GUI。
- 配置先写入明确的 JSON 文件，再执行 `sing-box check -c`，检查通过后才
  执行 `sing-box run -c`。
- `mixed` inbound 是 Windows 系统代理的第一条本地入口；TUN、DNS、路由
  和防火墙是单独的权限/回滚边界。
- core stdout/stderr、退出码、PID 和配置路径必须进入诊断记录。
- sing-box 的 certificate 配置用于上游信任材料，不等于浏览器 HTTPS MITM。

当前实现映射：

- `crates/engine-singbox` 负责官方 release metadata、资产选择、digest 校验、
  `.tar.gz`/Windows `.zip` 可执行文件提取和 managed process supervisor。
- `apps/windows-service` 消费 supervisor，并由
  `managed-config.json.sing_box` 提供显式 executable/config/working-directory/log
  路径。
- Windows MSI 不隐式下载或捆绑第三方 core；下载和安装 orchestration 需要独立
  的版本/许可证/回滚合同。

## v2rayN

官方项目：

- https://github.com/2dust/v2rayN
- https://github.com/2dust/v2rayN/wiki/Release-files-introduction
- https://github.com/2dust/v2rayN/wiki/FAQ

采用的经验：

- GUI 管理多个外部 core，不把 Xray、sing-box、mihomo 的 JSON 混为一种
  schema。
- core 文件、配置、GUI 日志和 core 日志分目录保存。
- 启动失败必须保留 core 原始输出，并在 GUI 中显示具体诊断，而不是只显示
  “启动失败”。
- 统一内部节点模型之后，按 core 类型生成各自的原生配置；订阅解析器不能
  直接假设目标 core 的字段名称。

当前实现映射：

- NetworkCore 已有 `config-core` `NodeCatalog`，sing-box renderer 仍从
  Shadowsocks 最小路径开始。
- Windows GUI 读取 managed state，显示 service 与 sing-box PID/退出码；日志
  位于 `%ProgramData%\\AnixOps\\NetworkCore\\logs`。
- VLESS/Trojan/VMess/Clash/sing-box JSON 等 parser gate 尚未等价于
  Windows runnable path。

## MITM 边界

sing-box 和 v2rayN 的核心职责是代理、路由、DNS、TUN 和连接生命周期；完整
HTTPS MITM 还需要 CA 生成、按 authority 签发叶子证书、下游 TLS 终止、上游
TLS 重建、HTTP/2/HTTP/1.1/WebSocket 处理、证书回滚和用户授权。

因此 NetworkCore 保持两层：

    Windows system proxy / TUN
              |
              v
    MITM listener (独立数据面与 CA 生命周期)
              |
              v
    sing-box mixed/HTTP/SOCKS outbound

当前 Windows `root_certificate_path` 只执行 LocalMachine ROOT 导入；它不会
创建 MITM listener，也不会自动解密 HTTPS。Windows MITM 必须在后续变更中把
listener、动态证书、显式授权、浏览器/系统信任和 rollback 一起接入 service。

“Suger”未找到与该目标对应的权威代理客户端；当前按用户给出的 SagerNet
sing-box 项目处理，避免把无关的 Suger SaaS/GitHub 集成产品当成代理参考。
