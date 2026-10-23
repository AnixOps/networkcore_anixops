# 文档索引

按主题列出 `docs/` 下全部文档。项目概览见 [README](../README.md)，阶段与计划见 [ROADMAP](../ROADMAP.md) 和 [TODO](../TODO.md)。

## 治理、发布与运维

- [CI/CD Policy](ci-cd-policy.md)：本地与 GitHub Actions 的职责、按改动范围选择验证任务
- [Release Strategy](release-strategy.md)：tag 发布门禁、产物矩阵与回滚
- [Alpha Release Feature Matrix](alpha-release-feature-matrix.md)：每个 alpha/beta/rc/stable 版本的能力边界
- [Manual Intervention List](manual-intervention.md)：需要人工处理的事项
- [Alpha Windows Smoke Test](alpha-windows-smoke-test.md)：Windows 真机冒烟步骤
- [P0 维护手册](MAINTENANCE_P0.md)、[交付证据](P4_EXECUTION_STATUS.md)、[维护事件 schema](contracts/maintenance-event.schema.json) 与 [fixture](contracts/maintenance-event.fixture.json)
- [归档](archive/README.md)：已完成的历史计划与设计

## 架构与决策

- [ADR 0001: Initial Core Stack](architecture/adr-0001-initial-core-stack.md)
- [ADR 0002: Public Engine Adapter First](architecture/adr-0002-public-engine-adapter-first.md)
- [Control Kernel Domain Specification](architecture/control-kernel-domain.md)
- [Control Kernel Interface Draft](architecture/control-kernel-interfaces.md)
- [Control Runtime Orchestration Design](architecture/control-runtime-orchestration.md)
- [Proxy Engine Adapter Interface](architecture/proxy-engine-adapter.md)
- [规则与策略组模型（M2）](architecture/routing-policy-group-model.md)
- [Public Core Client Reference](architecture/public-core-client-reference.md)

## 公有执行内核与订阅

- [sing-box Public Engine Adapter Source Contract](architecture/sing-box-public-engine-adapter-source-contract.md)
- [Mieru Public Engine Adapter Source Contract](architecture/mieru-public-engine-adapter-source-contract.md)
- [Subscription URL To sing-box Run Source Contract](architecture/subscription-url-to-sing-box-run-source-contract.md)
- [Subscription Catalog Runtime Orchestration Design](architecture/subscription-catalog-runtime-orchestration.md)
- [Persistent Subscription Catalog Source Contract](architecture/subscription-catalog-persistence-source-contract.md)
- [Subscription Background Refresh Source Contract](architecture/subscription-background-refresh-source-contract.md)

## 原生引擎与 managed 会话

- [Native Engine Listener And Node Config Design](architecture/native-engine-listener-node-config.md)
- [Linux Native Proxy Engine Start Design](architecture/linux-native-proxy-engine-start.md)
- [Managed Foreground Session Status Source Contract](architecture/managed-foreground-session-status-source-contract.md)
- [Managed Foreground Session Event Source Contract](architecture/managed-foreground-session-event-source-contract.md)
- [Managed Foreground Session Log Source Contract](architecture/managed-foreground-session-log-source-contract.md)

## MITM 与插件

- [mitm_anixops Adapter Design](architecture/mitm-anixops-adapter.md)
- [MITM Policy Ad Block Plugin Source Contract](architecture/mitm-policy-ad-block-plugin-source-contract.md)
- [Managed SD-WAN MITM Policy Gate Source Contract](architecture/managed-sdwan-mitm-policy-gate-source-contract.md)
- [Third-Party Plugin Onboarding Process](architecture/third-party-plugin-onboarding-process.md)
- [Linux MITM Certificate Lifecycle Source Contract](architecture/linux-mitm-certificate-lifecycle-source-contract.md)
- [Linux MITM Browser Capture Source Contract](architecture/linux-mitm-browser-capture-source-contract.md)
- [Linux MITM HTTP Rewrite Source Contract](architecture/linux-mitm-http-rewrite-source-contract.md)
- [Linux Trust-File Source Contract](architecture/linux-trust-file-source-contract.md)

## Linux 平台与 CLI

- [Linux Platform Adapter Design](architecture/linux-platform-adapter.md)
- [Linux CLI Entrypoint Design](architecture/linux-cli-entrypoint.md)
- [Linux CLI Runtime Wiring Design](architecture/linux-cli-runtime-wiring.md)
- [Linux CLI Artifact Installation And Rollback Design](architecture/linux-cli-artifact-installation-rollback.md)
- [Linux Environment Proxy Source Contract](architecture/linux-environment-proxy-source-contract.md)
- [Linux Managed Service Unit Source Contract](architecture/linux-managed-service-unit-source-contract.md)
- [Linux Managed Control Socket Source Contract](architecture/linux-managed-control-socket-source-contract.md)
- [Linux Managed Runtime Health Source Contract](architecture/linux-managed-runtime-health-source-contract.md)

## Windows

- [Windows Managed Client Source Release Contract](architecture/windows-managed-client-source-release-contract.md)
- [Windows GUI Daily Usability](architecture/windows-gui-daily-usability.md)
- [Windows CLI Artifact Source Release Contract](architecture/windows-cli-artifact-source-release-contract.md)
- [Windows Stage 4 POP Peer Manual Acceptance](architecture/windows-stage-4-pop-peer-manual-acceptance.md)

## iOS

- [iOS Platform Risk Assessment](architecture/ios-platform-risk-assessment.md)
- [iOS Network Extension Design](architecture/ios-network-extension-design.md)
- [iOS Platform Adapter Source Contract](architecture/ios-platform-adapter-source-contract.md)
- [iOS Swift Network Extension Bridge Design](architecture/ios-swift-network-extension-bridge-design.md)
- [iOS Swift Xcode Bridge Source Contract](architecture/ios-swift-xcode-bridge-source-contract.md)
- [iOS Embedded Runtime FFI Boundary Design](architecture/ios-embedded-runtime-ffi-boundary-design.md)
- [iOS MITM Certificate Lifecycle Design](architecture/ios-mitm-certificate-lifecycle-design.md)
- [iOS Entitlement Provisioning Source Contract](architecture/ios-entitlement-provisioning-source-contract.md)
- [iOS App Review Privacy Release Readiness Design](architecture/ios-app-review-privacy-release-readiness-design.md)
- [iOS Privacy Manifest Source Contract](architecture/ios-privacy-manifest-source-contract.md)
- [iOS App Review Manual Confirmation Source Contract](architecture/ios-app-review-manual-confirmation-source-contract.md)
- [iOS TestFlight App Store Connect Upload Workflow Source Contract](architecture/ios-testflight-app-store-connect-upload-workflow-source-contract.md)
- [iOS Upload Workflow Activation Validation Contract](architecture/ios-upload-workflow-activation-validation-contract.md)
- [iOS Swift Xcode Source Tree Activation Preflight Contract](architecture/ios-swift-xcode-source-tree-activation-preflight-contract.md)
- [iOS Package.swift Source Ownership Activation Preflight Contract](architecture/ios-package-swift-source-ownership-activation-preflight-contract.md)
- [iOS Package.swift Manifest-Only Activation Validation Contract](architecture/ios-package-swift-manifest-only-activation-validation-contract.md)

## Linux 发布流水线合同

- [Linux Artifact License Notice Confirmation Design](architecture/linux-artifact-license-notice-confirmation.md)
- [Linux Artifact Pre-Release Design](architecture/linux-artifact-pre-release-design.md)
- [Linux Package Archive Staging Contract](architecture/linux-package-archive-staging-contract.md)
- [Linux Package Artifact Archive Creation Validation Contract](architecture/linux-package-artifact-archive-creation-validation-contract.md)
- [Linux Package Artifact Attestation Execution Validation Contract](architecture/linux-package-artifact-attestation-execution-validation-contract.md)
- [Linux Package Artifact Build Command Validation Contract](architecture/linux-package-artifact-build-command-validation-contract.md)
- [Linux Package Artifact Checksum Execution Validation Contract](architecture/linux-package-artifact-checksum-execution-validation-contract.md)
- [Linux Package Artifact Job Preflight Validation Contract](architecture/linux-package-artifact-job-preflight-validation-contract.md)
- [Linux Package Artifact Manifest Design](architecture/linux-package-artifact-manifest.md)
- [Linux Package Artifact Manifest Checksum Validation Contract](architecture/linux-package-artifact-manifest-checksum-validation-contract.md)
- [Linux Package Artifact Manifest Generation Validation Contract](architecture/linux-package-artifact-manifest-generation-validation-contract.md)
- [Linux Package Artifact Staging File Validation Contract](architecture/linux-package-artifact-staging-file-validation-contract.md)
- [Linux Package Checksum Manifest Contract](architecture/linux-package-checksum-manifest-contract.md)
- [Linux Package License Notice Transition Validation Contract](architecture/linux-package-license-notice-transition-validation-contract.md)
- [Linux Package Publish Eligibility Aggregate Contract](architecture/linux-package-publish-eligibility-aggregate-contract.md)
- [Linux Package Publish Eligibility Execution Validation Contract](architecture/linux-package-publish-eligibility-execution-validation-contract.md)
- [Linux Package Publish Upload Boundary Contract](architecture/linux-package-publish-upload-boundary-contract.md)
- [Linux Package Release CI Gate Activation Validation Contract](architecture/linux-package-release-ci-gate-activation-validation-contract.md)
- [Linux Package Release Notes Rollback Execution Validation Contract](architecture/linux-package-release-notes-rollback-execution-validation-contract.md)
- [Linux Package Release Notes Rollback Policy Binding Contract](architecture/linux-package-release-notes-rollback-policy-binding-contract.md)
- [Linux Package Runner Toolchain Target Contract](architecture/linux-package-runner-toolchain-target-contract.md)
- [Linux Package Signing Attestation Policy Binding Contract](architecture/linux-package-signing-attestation-policy-binding-contract.md)
- [Linux Package Workflow Artifact Bundle Upload Validation Contract](architecture/linux-package-workflow-artifact-bundle-upload-validation-contract.md)
- [Release CI Gate API Implementation Plan](architecture/release-ci-gate-api-implementation-plan.md)
- [Release CI Gate Execution Validation Contract](architecture/release-ci-gate-execution-validation-contract.md)
- [Release CI Success Source Contract](architecture/release-ci-success-source-contract.md)
