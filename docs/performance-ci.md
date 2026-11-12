# 性能与长稳 CI

性能指标只在 GitHub Actions 上测量（见 [CI/CD policy](ci-cd-policy.md)）。下表是可脚本化的门槛：任何一项不达标，对应 job 失败。

| 指标 | 门槛 | 工具 | Workflow / Job | 何时运行 |
| --- | --- | --- | --- | --- |
| R2 规则决策 | 1 万条规则，单次决策 p99 ≤ 50 µs | `crates/config-core/examples/rule_bench.rs` | `perf.yml` / Rule decision benchmark | 改动 config-core 或引擎的 PR、手动 |
| F2 并发连接 | 5000 条 TCP 同时建立并各回显 1 字节（redirect、ss2022 两种出站） | `tunnel_bench scale` | `perf.yml` / Tunnel scale | 同上 |
| F3 UDP 会话 | 10 万个 UDP 流同时打开，进程 RSS ≤ 300 MiB | `tunnel_bench udp-sessions` | `perf.yml` / Tunnel scale | 同上 |
| F7 长稳 | 预热后 RSS 斜率 ≤ 1 MiB/h，连接失败率 ≤ 0.1%，结束无残留流与 fd | `tunnel_bench soak` | `soak.yml` | 每周六 5.5 h（托管 runner）；24 h 手动选自托管 runner |
| C4 IPC 模糊测试 | `networkcore_ios_runtime_control` 不 panic、回答必为 JSON 对象、错误码在文档集合内 | `crates/engine-embedded/fuzz` 的 `runtime_control` | `ci.yml` / HTTP/2 MITM fuzz | 每个 Rust PR（30 s）、main（60 s） |

`perf.yml` 的隧道基准（base 对 head）仍只做信息展示，不设门槛。

## 说明

- 规则决策走 `RoutingModel::decide_indexed`：DOMAIN 与 DOMAIN-SUFFIX 规则用哈希表查找，其余规则按顺序尝试，结果与逐条 `decide` 完全一致（`crates/config-core/tests/rule_index_contracts.rs`）。基准里 10% 的查询不命中任何规则，是最坏情况（走完全部非域名规则、解析一次域名、落到 FINAL）。
- UDP 流上限由配置 `limits.max_udp_flows` 决定（默认 256，iOS 内存预算不变）；测 10 万流时基准自行调高。
- 长稳的 RSS 斜率是去掉前 15% 采样后的最小二乘斜率，每 60 s 采样一次；完整曲线在 job summary 和 artifact `tunnel-soak` 里。
- 24 h 长稳需要自托管 runner，准备步骤见 [manual-intervention.md](manual-intervention.md)。
- 手动调整门槛：`perf.yml` 的 `max_rule_p99_us`、`concurrent`、`udp_flows`、`max_udp_rss_mb` 输入；`soak.yml` 的 `hours`、`max_slope_mb_per_h` 输入。

## 首次结果（2026-11-13，GitHub 托管 ubuntu runner）

- R2：1 万条规则 p99 约 35 µs（runner 之间约有 2 倍波动）。
- F2：5000 并发全部回显成功，redirect / ss2022 回显 p99 约 3 ms，隧道进程约 52 KiB/连接。
- F3：10 万 UDP 流 RSS 222 MiB（约 2.2 KiB/流）。此前每流两个任务加一个 tokio mpsc 通道，是 4.2 KiB/流、417 MiB；现在每流一个任务、按需分配的队列，打开流的 future 用完即释放。
