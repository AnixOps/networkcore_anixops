# Linux Package Artifact Build Command Validation Contract

本文定义首个 Linux `package-linux` job 在未来真实执行 build step 前必须满足的 build
command 验证合同。当前仍是 placeholder；本文只固定未来 target 安装策略、cargo build
命令、binary path 校验、失败条件和继续不上传 artifact 的边界，不定义 `package-linux`
job、不安装 target、不构建、不打包、不上传 artifact。

评估时间：2026-07-07。

## 目标

- 固定首个 Linux CLI artifact 的 GitHub Actions build command，不接受手写或本地产物。
- 明确 Rust target 安装必须发生在 preflight 通过之后、cargo build 之前。
- 固定 binary package、bin name、target triple 和 build output path。
- 防止 maintainer 从 runner cache、旧 workflow artifact、本机 target 目录或手动上传文件跳过 build。
- 在 build command 未激活时继续阻止 staging、archive、workflow artifact 和 GitHub Release asset。

## 非目标

- 不实现 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux`、
  `post-release-summary` 或等价 job。
- 不运行 `rustup target add`、`cargo build`、`cargo test`、`cargo package`、`cargo install`、
  `strip`、archive、checksum、manifest、attestation、release notes 或 upload step。
- 不修改 Cargo workspace、Cargo.lock、crate metadata 或 release profile。
- 不完成 license/NOTICE 人工确认。
- 不启用 release CI gate 的 GitHub API 读取。
- 不把 runner 本地绝对路径、Cargo cache、target 目录、secret、token、环境变量原文、
  GitHub API response 原文或未公开安全公告细节写入 manifest、release notes 或 Step Summary。

## Source Of Truth

首个 Linux package artifact build command 输入必须来自本文档、
[Linux Package Artifact Job Preflight Validation Contract](linux-package-artifact-job-preflight-validation-contract.md)、
[Linux Package Runner Toolchain Target Contract](linux-package-runner-toolchain-target-contract.md)、
[Linux Package Archive Staging Contract](linux-package-archive-staging-contract.md)、
[Linux Package Artifact Manifest Design](linux-package-artifact-manifest.md)、
[Release CI Success Source Contract](release-ci-success-source-contract.md)、
`apps/linux-cli/Cargo.toml`、workspace `Cargo.toml` 和 release workflow 中的显式常量。

当前 placeholder 固定为：

| 字段 | 值 |
| --- | --- |
| `package_artifact_build_command_contract` | `present` |
| `package_artifact_build_command_status` | `blocked-placeholder` |
| `package_artifact_build_command_source` | `linux-artifact-readiness` |
| `package_artifact_build_command_current_mode` | `contract-only-no-build` |
| `package_artifact_build_command_required_job` | `package-linux` |
| `package_artifact_build_command_job_status` | `not-defined` |
| `package_artifact_build_command_preflight_status` | `blocked-placeholder` |
| `package_artifact_build_command_target_install` | `blocked-before-preflight` |
| `package_artifact_build_command_rust_toolchain` | `stable` |
| `package_artifact_build_command_rust_profile` | `minimal` |
| `package_artifact_build_command_target` | `x86_64-unknown-linux-gnu` |
| `package_artifact_build_command_package` | `networkcore-linux` |
| `package_artifact_build_command_binary` | `networkcore-linux` |
| `package_artifact_build_command_cargo_args` | `build,--locked,--release,--package,networkcore-linux,--bin,networkcore-linux,--target,x86_64-unknown-linux-gnu` |
| `package_artifact_build_command_binary_path` | `target/x86_64-unknown-linux-gnu/release/networkcore-linux` |
| `package_artifact_build_command_binary_path_check` | `blocked-before-build` |
| `package_artifact_build_command_build_output` | `blocked` |
| `package_artifact_build_command_upload` | `blocked` |
| `package_artifact_build_command_next_action` | `license-notice-ci-preflight-before-build` |

`blocked-placeholder` 表示 release workflow 已记录未来 build command 的验证要求，但当前
release 仍不得创建 job、安装 target 或执行 build step。

## Future Build Command

未来真实 `package-linux` job 必须在 preflight 通过后按以下顺序执行：

```bash
rustup target add x86_64-unknown-linux-gnu --toolchain stable
cargo build --locked --release --package networkcore-linux --bin networkcore-linux --target x86_64-unknown-linux-gnu
test -f target/x86_64-unknown-linux-gnu/release/networkcore-linux
test -x target/x86_64-unknown-linux-gnu/release/networkcore-linux
```

字段规则：

| 字段 | 要求 |
| --- | --- |
| `rustup target add` | 只能在 preflight active、checkout SHA verified、toolchain stable/minimal 后执行 |
| `cargo build` | 必须包含 `--locked`、`--release`、`--package networkcore-linux`、`--bin networkcore-linux` 和 `--target x86_64-unknown-linux-gnu` |
| package | 必须来自 `apps/linux-cli/Cargo.toml` 的 `name = "networkcore-linux"` |
| binary | 必须来自 `apps/linux-cli/Cargo.toml` 的 `[[bin]] name = "networkcore-linux"` |
| target | 必须等于 runner/toolchain/target contract 的 `x86_64-unknown-linux-gnu` |
| binary path | 必须为 workspace 相对路径 `target/x86_64-unknown-linux-gnu/release/networkcore-linux` |
| binary path check | 必须确认文件存在、可执行，且不是 symlink 到 workspace 外部路径 |
| build output | 只能作为同一 `package-linux` job 的 staging 输入 |
| upload | build command 不得直接上传 workflow artifact 或 release asset |

真实 job 可以在 build 前使用 GitHub Actions cache 下载依赖缓存，但不得从 cache 中读取
`target/.../networkcore-linux` 作为发布 binary。build output 必须由当前 release run 的
build step 生成。

## Failure Boundary

真实 build command gate 必须在以下情况失败，并且不得执行 staging、archive、checksum、
manifest、workflow artifact upload 或 release asset upload：

- preflight status 不是 `active`。
- license/NOTICE 仍为 pending，或 release CI gate 仍为 placeholder。
- checkout SHA 与 release SHA 不一致。
- `apps/linux-cli/Cargo.toml` 不存在，或 package/bin name 不等于 `networkcore-linux`。
- build command 缺少 `--locked`、`--release`、`--package`、`--bin` 或 `--target`。
- target install 缺失，或 target triple 与合同不一致。
- binary path 不存在、不可执行、是目录、指向 workspace 外部，或来自旧 run/cache/本机产物。
- build output path 与 archive staging contract 的 `package_binary_source_path` 不一致。
- build 后立即上传 artifact，绕过 staging、checksum、manifest、signing/attestation、
  release notes/rollback 或 publish eligibility gates。

失败时 release workflow 必须失败在 `package-linux` 内或之前，不得创建 publish job 可消费的 artifact。

## Release Workflow 边界

当前 placeholder release 只能：

- 检查本文档存在和标题。
- 检查本文档包含 current placeholder fields、future build command、binary path 和 failure boundary。
- 检查 `apps/linux-cli/Cargo.toml` 声明 `networkcore-linux` package 和 bin。
- 在 `linux-artifact-readiness`、release placeholder 和 release summary 中输出 build command
  validation contract。
- 标记 `linux-package-artifact-build-command-contract=present`。
- 标记 `linux-package-artifact-build-command-status=blocked-placeholder`。
- 标记 `linux-package-artifact-build-command-required-job=package-linux`。
- 标记 `linux-package-artifact-build-command-job-status=not-defined`。
- 标记 `linux-package-artifact-build-command-preflight=blocked-placeholder`。
- 标记 `linux-package-artifact-build-command-target-install=blocked-before-preflight`。
- 标记 `linux-package-artifact-build-command-cargo-args=build,--locked,--release,--package,networkcore-linux,--bin,networkcore-linux,--target,x86_64-unknown-linux-gnu`。
- 标记 `linux-package-artifact-build-command-binary-path=target/x86_64-unknown-linux-gnu/release/networkcore-linux`。
- 标记 `linux-package-artifact-build-command-binary-path-check=blocked-before-build`。
- 标记 `linux-package-artifact-build-command-build-output=blocked`。
- 标记 `linux-package-artifact-build-command-upload=blocked`。
- 标记 `linux-package-artifact-build-command-next-action=license-notice-ci-preflight-before-build`。
- 继续不定义 `package-linux`、`publish-github-release`、`attest-linux`、`sign-linux` 或
  `post-release-summary`。

## Manifest Binding

真实 manifest 必须能追溯到 build command 输出：

```json
{
  "build": {
    "contract": "docs/architecture/linux-package-artifact-build-command-validation-contract.md",
    "toolchain": "stable",
    "profile": "minimal",
    "target": "x86_64-unknown-linux-gnu",
    "package": "networkcore-linux",
    "binary": "networkcore-linux",
    "command": [
      "cargo",
      "build",
      "--locked",
      "--release",
      "--package",
      "networkcore-linux",
      "--bin",
      "networkcore-linux",
      "--target",
      "x86_64-unknown-linux-gnu"
    ],
    "binary_path": "target/x86_64-unknown-linux-gnu/release/networkcore-linux"
  }
}
```

manifest 不得写入 runner 本地绝对路径、Cargo cache path、token、secret、GitHub API response
原文、私钥、用户配置、维护者私有身份或未公开安全公告细节。

## 验收条件

- 本文档保持在 README、ROADMAP、Release Strategy、Linux package artifact job preflight
  validation contract、Linux package runner/toolchain/target contract、Linux package archive staging
  contract、Linux package artifact staging file validation contract、Linux package manifest 设计、
  Linux CLI artifact 安装/回滚设计和 CI policy 中可发现。
- `.github/workflows/ci.yml` governance 检查本文档存在、标题和 release workflow placeholder 输出字段。
- `.github/workflows/release.yml` 的 `linux-artifact-readiness` 检查本文档存在、标题、placeholder
  fields、future build command、binary path、failure boundary、Cargo package/bin name 和
  `package-linux` 未定义状态。
- release placeholder 和 release summary 输出 build command status、required job、preflight blocked、
  target install blocked、cargo args、binary path、binary path check、build output blocked、upload blocked
  和 next action。
- 当前不生成 artifact、不定义 `package-linux`、不定义 `publish-github-release`、不上传 workflow
  artifact、不上传 release asset、不在本机执行测试、构建、打包或发布。

## 后续工作

- 在 license/NOTICE 人工确认、release CI gate activation 和 artifact job preflight 激活前，
  继续保持 `package-linux` 未定义。
- Linux package artifact staging file validation contract、Linux package artifact archive creation validation contract 和 Linux package artifact checksum execution validation contract 已定义；Linux package artifact manifest generation validation contract、Linux package artifact manifest checksum validation contract、Linux package workflow artifact bundle upload validation contract、Linux package artifact attestation execution validation contract、Linux package release notes/rollback execution validation contract 和 Linux package publish eligibility execution validation contract 已定义；release CI gate execution validation contract 已定义；下一步可以补充 release CI gate API implementation plan，仍不发布 release asset。
