//! Linux CLI entrypoint contracts for NetworkCore.
//!
//! The crate contains command parsing, response mapping, config I/O boundaries,
//! and foreground runtime handoff. Daemon control, service installation, and
//! release packaging are deliberately outside this first source increment.

use config_core::CoreSubscriptionService;
use control_domain::{
    CertificateTrustState, ConfigurationService, Diagnostic, DiagnosticSeverity, DomainError,
    DomainResult, GrantedPermissions, HttpMitmAction, HttpMitmPhase, MetadataEntry,
    MitmPluginService, OperatingSystem, PlatformCapabilityService, PlatformCapabilityStatus,
    PlatformFeatureState, ProxyEngineConfig, ProxyEngineDescriptor, ProxyEngineEvent,
    ProxyEngineLifecycleState, ProxyEngineService, ProxyEngineStatus, RawSubscription,
    SubscriptionService, SubscriptionSource,
};
use control_runtime::{RuntimeConfigRequest, RuntimeOperationResult, RuntimeOrchestrator};
use engine_singbox::{
    default_sing_box_install_root, render_sing_box_local_proxy_config, SingBoxInstallReport,
    SingBoxInstallRequest, SingBoxLocalProxyConfigRequest, SingBoxProcessRunRequest,
    SingBoxProcessRunner, SingBoxReleaseInstaller, SingBoxTarget,
};
use mitm_policy::{
    builtin_ad_block_plugin_package, AnixOpsMitmPluginService, AnixOpsMitmPolicyEngine,
    MITM_POLICY_AD_BLOCK_PLUGIN_ID,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::Signals,
};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

pub const COMMAND_NAME: &str = "networkcore-linux";
pub const DEFAULT_ENGINE_ID: &str = "native";

pub const CLI_COMMAND_MISSING_CODE: &str = "cli.linux.command.missing";
pub const CLI_ARGUMENT_UNKNOWN_CODE: &str = "cli.linux.argument.unknown";
pub const CLI_ARGUMENT_VALUE_MISSING_CODE: &str = "cli.linux.argument.value_missing";
pub const CLI_OUTPUT_FORMAT_UNSUPPORTED_CODE: &str = "cli.linux.output.format_unsupported";
pub const CLI_CONFIG_PATH_MISSING_CODE: &str = "cli.linux.config.path_missing";
pub const CLI_CONFIG_READ_FAILED_CODE: &str = "cli.linux.config.read_failed";
pub const CLI_CONFIG_EMPTY_CODE: &str = "cli.linux.config.empty";
pub const CLI_START_PLATFORM_DENIED_CODE: &str = "cli.linux.start.platform_denied";
pub const CLI_START_CONFIG_DENIED_CODE: &str = "cli.linux.start.config_denied";
pub const CLI_START_ENGINE_DENIED_CODE: &str = "cli.linux.start.engine_denied";
pub const CLI_START_FOREGROUND_ONLY_CODE: &str = "cli.linux.start.foreground_only";
pub const CLI_START_LIFECYCLE_HOST_MISSING_CODE: &str = "cli.linux.start.lifecycle_host_missing";
pub const CLI_START_LIFECYCLE_INTERRUPTED_CODE: &str = "cli.linux.start.lifecycle_interrupted";
pub const CLI_START_LIFECYCLE_FAILED_CODE: &str = "cli.linux.start.lifecycle_failed";
pub const CLI_START_RUNTIME_STOP_FAILED_CODE: &str = "cli.linux.start.runtime_stop_failed";
pub const CLI_START_SIGNAL_RECEIVED_CODE: &str = "cli.linux.start.signal_received";
pub const CLI_START_SIGNAL_SOURCE_FAILED_CODE: &str = "cli.linux.start.signal_source_failed";
pub const CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE: &str =
    "cli.linux.subscription_catalog.path_missing";
pub const CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_PATH_MISSING_CODE: &str =
    "cli.linux.subscription_catalog.snapshot_path_missing";
pub const CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_READ_FAILED_CODE: &str =
    "cli.linux.subscription_catalog.snapshot_read_failed";
pub const CLI_SUBSCRIPTION_CATALOG_PATH_CONFLICT_CODE: &str =
    "cli.linux.subscription_catalog.path_conflict";
pub const CLI_SUBSCRIPTION_CATALOG_SOURCE_ID_EMPTY_CODE: &str =
    "cli.linux.subscription_catalog.source_id_empty";
pub const CLI_SUBSCRIPTION_CATALOG_SOURCE_LOCATION_EMPTY_CODE: &str =
    "cli.linux.subscription_catalog.source_location_empty";
pub const CLI_SUBSCRIPTION_CATALOG_READ_FAILED_CODE: &str =
    "cli.linux.subscription_catalog.read_failed";
pub const CLI_SUBSCRIPTION_CATALOG_SCHEMA_UNSUPPORTED_CODE: &str =
    "cli.linux.subscription_catalog.schema_unsupported";
pub const CLI_SUBSCRIPTION_CATALOG_SOURCE_INVALID_CODE: &str =
    "cli.linux.subscription_catalog.source_invalid";
pub const CLI_SUBSCRIPTION_CATALOG_DUPLICATE_SOURCE_ID_CODE: &str =
    "cli.linux.subscription_catalog.duplicate_source_id";
pub const CLI_SUBSCRIPTION_CATALOG_SOURCE_NOT_FOUND_CODE: &str =
    "cli.linux.subscription_catalog.source_not_found";
pub const CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE: &str =
    "cli.linux.subscription_catalog.snapshot_write_failed";
pub const CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE: &str =
    "cli.linux.subscription_catalog.write_failed";
pub const CLI_STOP_UNAVAILABLE_WITHOUT_DAEMON_CODE: &str =
    "cli.linux.stop.unavailable_without_daemon";
pub const CLI_STATUS_NO_RUNTIME_CONTEXT_CODE: &str = "cli.linux.status.no_runtime_context";
pub const CLI_STATUS_PLATFORM_ONLY_CODE: &str = "cli.linux.status.platform_only";
pub const CLI_RUNTIME_UNWIRED_CODE: &str = "cli.linux.runtime.unwired";
pub const CLI_SING_BOX_INSTALL_FAILED_CODE: &str = "cli.linux.sing_box.install_failed";
pub const CLI_RUN_URL_PARSE_FAILED_CODE: &str = "cli.linux.run_url.parse_failed";
pub const CLI_RUN_URL_CONFIG_FAILED_CODE: &str = "cli.linux.run_url.config_failed";
pub const CLI_RUN_URL_CONFIG_WRITE_FAILED_CODE: &str = "cli.linux.run_url.config_write_failed";
pub const CLI_RUN_URL_PROCESS_FAILED_CODE: &str = "cli.linux.run_url.process_failed";
pub const CLI_MITM_POLICY_READY_CODE: &str = "cli.linux.mitm.policy_ready";
pub const CLI_MITM_CLI_GATE_PARTIAL_CODE: &str = "cli.linux.mitm.cli_gate.partial";
pub const CLI_MITM_CERTIFICATE_PLAN_READY_CODE: &str = "cli.linux.mitm.certificate_plan.ready";
pub const CLI_MITM_CERTIFICATE_GATE_DEFERRED_CODE: &str =
    "cli.linux.mitm.certificate_gate.deferred";
pub const CLI_MITM_CERTIFICATE_MUTATION_BLOCKED_CODE: &str =
    "cli.linux.mitm.certificate_mutation.blocked";
pub const CLI_MITM_CERTIFICATE_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.mitm.certificate.authorization_required";
pub const CLI_MITM_CERTIFICATE_APPLY_BLOCKED_CODE: &str =
    "cli.linux.mitm.certificate.apply.blocked";
pub const CLI_MITM_CERTIFICATE_APPLY_READY_CODE: &str = "cli.linux.mitm.certificate.apply.ready";
pub const CLI_MITM_CERTIFICATE_APPLY_CONFIG_MISSING_CODE: &str =
    "cli.linux.mitm.certificate.apply.config_missing";
pub const CLI_MITM_CERTIFICATE_MATERIAL_FAILED_CODE: &str =
    "cli.linux.mitm.certificate.material.failed";
pub const CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE: &str =
    "cli.linux.mitm.certificate.artifact.write_failed";
pub const CLI_MITM_CERTIFICATE_SNAPSHOT_WRITE_FAILED_CODE: &str =
    "cli.linux.mitm.certificate.snapshot.write_failed";
pub const CLI_MITM_CERTIFICATE_SNAPSHOT_READ_FAILED_CODE: &str =
    "cli.linux.mitm.certificate.snapshot.read_failed";
pub const CLI_MITM_CERTIFICATE_ROLLBACK_BLOCKED_CODE: &str =
    "cli.linux.mitm.certificate.rollback.blocked";
pub const CLI_MITM_CERTIFICATE_ROLLBACK_READY_CODE: &str =
    "cli.linux.mitm.certificate.rollback.ready";
pub const CLI_MITM_CERTIFICATE_ROLLBACK_FAILED_CODE: &str =
    "cli.linux.mitm.certificate.rollback.failed";
pub const CLI_MITM_DATA_PLANE_GATE_DEFERRED_CODE: &str = "cli.linux.mitm.data_plane_gate.deferred";
pub const CLI_MITM_BROWSER_PLAN_READY_CODE: &str = "cli.linux.mitm.browser_plan.ready";
pub const CLI_MITM_BROWSER_CAPTURE_MUTATION_BLOCKED_CODE: &str =
    "cli.linux.mitm.browser_capture_mutation.blocked";
pub const CLI_MITM_BROWSER_CAPTURE_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.mitm.browser_capture.authorization_required";
pub const CLI_MITM_BROWSER_CAPTURE_LAUNCH_PLAN_READY_CODE: &str =
    "cli.linux.mitm.browser_capture.launch_plan.ready";
pub const CLI_MITM_BROWSER_CAPTURE_LAUNCH_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.mitm.browser_capture.launch.authorization_required";
pub const CLI_MITM_BROWSER_CAPTURE_LAUNCH_STARTED_CODE: &str =
    "cli.linux.mitm.browser_capture.launch.started";
pub const CLI_MITM_BROWSER_CAPTURE_LAUNCH_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.launch.failed";
pub const CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_READY_CODE: &str =
    "cli.linux.mitm.browser_capture.session_plan.ready";
pub const CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_URL_PARSE_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.session_plan.url_parse_failed";
pub const CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_CONFIG_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.session_plan.config_failed";
pub const CLI_MITM_BROWSER_CAPTURE_APPLY_BLOCKED_CODE: &str =
    "cli.linux.mitm.browser_capture.apply.blocked";
pub const CLI_MITM_BROWSER_CAPTURE_APPLY_READY_CODE: &str =
    "cli.linux.mitm.browser_capture.apply.ready";
pub const CLI_MITM_BROWSER_CAPTURE_APPLY_CONFIG_MISSING_CODE: &str =
    "cli.linux.mitm.browser_capture.apply.config_missing";
pub const CLI_MITM_BROWSER_CAPTURE_PAC_WRITE_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.pac.write_failed";
pub const CLI_MITM_BROWSER_CAPTURE_POLICY_WRITE_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.policy.write_failed";
pub const CLI_MITM_BROWSER_CAPTURE_PROFILE_PREFS_WRITE_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.profile_prefs.write_failed";
pub const CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_WRITE_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.snapshot.write_failed";
pub const CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_READ_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.snapshot.read_failed";
pub const CLI_MITM_BROWSER_CAPTURE_ROLLBACK_BLOCKED_CODE: &str =
    "cli.linux.mitm.browser_capture.rollback.blocked";
pub const CLI_MITM_BROWSER_CAPTURE_ROLLBACK_READY_CODE: &str =
    "cli.linux.mitm.browser_capture.rollback.ready";
pub const CLI_MITM_BROWSER_CAPTURE_ROLLBACK_FAILED_CODE: &str =
    "cli.linux.mitm.browser_capture.rollback.failed";
pub const CLI_MITM_BROWSER_CAPTURE_VERIFY_BLOCKED_CODE: &str =
    "cli.linux.mitm.browser_capture.verify.blocked";
pub const CLI_MITM_BROWSER_CAPTURE_VERIFY_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.mitm.browser_capture.verify.authorization_required";
pub const CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_REACHABLE_CODE: &str =
    "cli.linux.mitm.browser_capture.verify.proxy_reachable";
pub const CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE: &str =
    "cli.linux.mitm.browser_capture.verify.proxy_unreachable";
pub const CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_REACHABLE_CODE: &str =
    "cli.linux.mitm.browser_capture.verify.target_reachable";
pub const CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE: &str =
    "cli.linux.mitm.browser_capture.verify.target_invalid";
pub const CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BLOCKED_CODE: &str =
    "cli.linux.mitm.browser_capture.traffic_proof.blocked";
pub const CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.mitm.browser_capture.traffic_proof.authorization_required";
pub const CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_OBSERVED_CODE: &str =
    "cli.linux.mitm.browser_capture.traffic_proof.observed";
pub const CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_MISSING_CODE: &str =
    "cli.linux.mitm.browser_capture.traffic_proof.missing";
pub const CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_LOG_UNREADABLE_CODE: &str =
    "cli.linux.mitm.browser_capture.traffic_proof.log_unreadable";
pub const CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BINDING_MISMATCH_CODE: &str =
    "cli.linux.mitm.browser_capture.traffic_proof.binding_mismatch";
pub const CLI_MITM_HTTP_REWRITE_AUTHORIZATION_REQUIRED_CODE: &str =
    "cli.linux.mitm.http_rewrite.authorization_required";
pub const CLI_MITM_HTTP_REWRITE_PLAN_READY_CODE: &str = "cli.linux.mitm.http_rewrite.plan.ready";
pub const CLI_MITM_HTTP_REWRITE_APPLY_READY_CODE: &str = "cli.linux.mitm.http_rewrite.apply.ready";
pub const CLI_MITM_HTTP_REWRITE_CONFIG_MISSING_CODE: &str =
    "cli.linux.mitm.http_rewrite.config_missing";
pub const CLI_MITM_HTTP_REWRITE_TLS_BLOCKED_CODE: &str = "cli.linux.mitm.http_rewrite.tls_blocked";
pub const CLI_MITM_BROWSER_HIJACK_DEFERRED_CODE: &str = "cli.linux.mitm.browser_hijack.deferred";

pub const MITM_CLI_COMMAND_GATE: &str = "MITM_CLI_COMMAND_GATE";
pub const MITM_CERTIFICATE_LIFECYCLE_GATE: &str = "MITM_CERTIFICATE_LIFECYCLE_GATE";
pub const MITM_HTTP_TLS_DATA_PLANE_GATE: &str = "MITM_HTTP_TLS_DATA_PLANE_GATE";
pub const MITM_BROWSER_CAPTURE_GATE: &str = "MITM_BROWSER_CAPTURE_GATE";
pub const MITM_CLI_COMMAND_GATE_STATUS: &str = "partial-active";
pub const MITM_CERTIFICATE_LIFECYCLE_GATE_STATUS: &str =
    "artifact-lifecycle-active/profile-trust-artifact-active/trust-mutation-blocked";
pub const MITM_HTTP_TLS_DATA_PLANE_GATE_STATUS: &str =
    "plain-http-live-data-plane-active/tls-decryption-blocked";
pub const MITM_BROWSER_CAPTURE_GATE_STATUS: &str =
    "pac-policy-profile-prefs-active/system-mutation-blocked";
pub const MITM_BROWSER_HIJACK_STATUS: &str = "deferred";
pub const MITM_CERTIFICATE_PLAN_STATUS: &str = "artifact-lifecycle-active";
pub const MITM_CERTIFICATE_MUTATION_READY: bool = false;
pub const MITM_CERTIFICATE_LIFECYCLE_SOURCE_CONTRACT_STATUS: &str = "active";
pub const MITM_CERTIFICATE_ARTIFACT_SUBJECT: &str = "NetworkCore Local MITM CA";
pub const MITM_BROWSER_PLAN_STATUS: &str = "plan-only";
pub const MITM_BROWSER_CAPTURE_MUTATION_READY: bool = false;
pub const MITM_BROWSER_CAPTURE_PROXY_HOST: &str = "127.0.0.1";
pub const MITM_BROWSER_CAPTURE_PROXY_PORT: u16 = 7890;
pub const MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME: &str = "http";
pub const MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME: &str = "socks5";
pub const MITM_BROWSER_CAPTURE_MODE: &str = "explicit-proxy";
pub const MITM_BROWSER_CAPTURE_SOURCE_CONTRACT_STATUS: &str = "active";
pub const MITM_BROWSER_CAPTURE_DEFAULT_BROWSER: &str = "chromium";
pub const MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR: &str =
    "/tmp/networkcore-browser-capture-profile";
pub const MITM_BROWSER_CAPTURE_DEFAULT_PROOF_LOG_PATH: &str =
    "/tmp/networkcore-browser-capture-proof.log";
pub const MITM_BROWSER_CAPTURE_PROOF_QUERY_PARAM: &str = "networkcore_proof_token";
pub const MITM_HTTP_REWRITE_SOURCE_CONTRACT_STATUS: &str = "active";
pub const MITM_HTTP_REWRITE_MUTATION_READY: bool = true;
pub const MITM_HTTP_REWRITE_LIVE_TRAFFIC_READY: bool = true;
pub const MITM_HTTP_REWRITE_TLS_DECRYPTION_READY: bool = false;
pub const MITM_HTTP_REWRITE_CONTROLLED_TLS_TERMINATION_PLAN_READY: bool = true;
pub const MITM_HTTP_REWRITE_DOWNSTREAM_TLS_TERMINATION_PLAN_READY: bool = true;
pub const MITM_HTTP_REWRITE_UPSTREAM_TLS_FORWARDING_READY: bool = true;
pub const MITM_HTTP_REWRITE_HTTPS_REQUEST_REWRITE_PREVIEW_READY: bool = true;
pub const MITM_HTTP_REWRITE_HTTPS_RESPONSE_REWRITE_PREVIEW_READY: bool = true;
pub const MITM_HTTP_REWRITE_HTTPS_RESPONSE_REWRITE_READY: bool = false;
pub const MITM_HTTP_REWRITE_SCRIPT_DISPATCH_READY: bool = false;
pub const MITM_HTTP_REWRITE_DEFAULT_METHOD: &str = "GET";
pub const MITM_HTTP_REWRITE_DEFAULT_PHASE: &str = "request";
pub const MITM_USER_FACING_STAGE: &str = "policy-only";
pub const MITM_USER_FACING_READY: bool = false;

pub const SOURCE_CLI_ARGUMENT: &str = "cli.argument";
pub const SOURCE_CLI_CONFIG: &str = "cli.config";
pub const SOURCE_CLI_HELP: &str = "cli.help";
pub const SOURCE_CLI_MITM: &str = "cli.mitm";
pub const SOURCE_CLI_SING_BOX: &str = "cli.sing_box";
pub const SOURCE_CLI_START: &str = "cli.start";
pub const SOURCE_CLI_STOP: &str = "cli.stop";
pub const SOURCE_CLI_STATUS: &str = "cli.status";
pub const SOURCE_CLI_RUNTIME: &str = "cli.runtime";
pub const SUBSCRIPTION_CATALOG_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

impl OutputFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxCliExitCode {
    Success,
    GeneralFailure,
    ArgumentOrConfig,
    ConfigValidation,
    PlatformDenied,
    EngineDenied,
    Unavailable,
    Interrupted,
}

impl LinuxCliExitCode {
    pub const fn code(self) -> i32 {
        match self {
            Self::Success => 0,
            Self::GeneralFailure => 1,
            Self::ArgumentOrConfig => 2,
            Self::ConfigValidation => 3,
            Self::PlatformDenied => 4,
            Self::EngineDenied => 5,
            Self::Unavailable => 6,
            Self::Interrupted => 130,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxCliCommand {
    Help {
        format: OutputFormat,
    },
    Version {
        format: OutputFormat,
    },
    Capabilities {
        format: OutputFormat,
    },
    PrepareConfig {
        config_path: Option<String>,
        format: OutputFormat,
    },
    Start {
        config_path: Option<String>,
        format: OutputFormat,
    },
    Stop {
        format: OutputFormat,
    },
    Status {
        format: OutputFormat,
    },
    Diagnostics {
        format: OutputFormat,
    },
    MitmStatus {
        format: OutputFormat,
    },
    MitmDiagnostics {
        format: OutputFormat,
    },
    MitmCertificatePlan {
        format: OutputFormat,
    },
    MitmCertificateApply {
        cert_file_path: Option<String>,
        key_file_path: Option<String>,
        profile_trust_file_path: Option<String>,
        snapshot_path: Option<String>,
        confirm: bool,
        format: OutputFormat,
    },
    MitmCertificateRollback {
        snapshot_path: Option<String>,
        format: OutputFormat,
    },
    MitmBrowserPlan {
        format: OutputFormat,
    },
    MitmBrowserCapturePlan {
        proxy_scheme: String,
        format: OutputFormat,
    },
    MitmBrowserCaptureLaunchPlan {
        proxy_scheme: String,
        format: OutputFormat,
    },
    MitmBrowserCaptureSessionPlan {
        url: String,
        browser: String,
        profile_dir: String,
        target_url: Option<String>,
        proof_token: Option<String>,
        proof_log_path: Option<String>,
        proxy_scheme: String,
        listen_host: String,
        listen_port: u16,
        format: OutputFormat,
    },
    MitmBrowserCaptureLaunch {
        browser: String,
        profile_dir: String,
        target_url: Option<String>,
        proof_token: Option<String>,
        proof_log_path: Option<String>,
        proxy_scheme: String,
        confirm: bool,
        format: OutputFormat,
    },
    MitmBrowserCaptureApply {
        pac_file_path: Option<String>,
        policy_file_path: Option<String>,
        profile_prefs_file_path: Option<String>,
        snapshot_path: Option<String>,
        proxy_scheme: String,
        confirm: bool,
        format: OutputFormat,
    },
    MitmBrowserCaptureRollback {
        snapshot_path: Option<String>,
        format: OutputFormat,
    },
    MitmBrowserCaptureVerify {
        target_url: Option<String>,
        proxy_scheme: String,
        confirm: bool,
        format: OutputFormat,
    },
    MitmBrowserCaptureTrafficProof {
        target_url: Option<String>,
        proof_token: Option<String>,
        proof_log_path: Option<String>,
        proxy_scheme: String,
        confirm: bool,
        format: OutputFormat,
    },
    MitmHttpRewritePlan {
        format: OutputFormat,
    },
    MitmHttpRewritePreview {
        url: Option<String>,
        method: String,
        phase: String,
        status_code: Option<u16>,
        headers: Vec<String>,
        body: Option<String>,
        confirm: bool,
        format: OutputFormat,
    },
    InstallSingBox {
        install_dir: Option<String>,
        force: bool,
        format: OutputFormat,
    },
    RunUrl {
        url: String,
        listen_host: String,
        listen_port: u16,
        install_dir: Option<String>,
        force: bool,
        format: OutputFormat,
    },
}

impl LinuxCliCommand {
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Help { .. } => "help",
            Self::Version { .. } => "version",
            Self::Capabilities { .. } => "capabilities",
            Self::PrepareConfig { .. } => "prepare-config",
            Self::Start { .. } => "start",
            Self::Stop { .. } => "stop",
            Self::Status { .. } => "status",
            Self::Diagnostics { .. } => "diagnostics",
            Self::MitmStatus { .. } => "mitm status",
            Self::MitmDiagnostics { .. } => "mitm diagnostics",
            Self::MitmCertificatePlan { .. } => "mitm certificate-plan",
            Self::MitmCertificateApply { .. } => "mitm certificate apply",
            Self::MitmCertificateRollback { .. } => "mitm certificate rollback",
            Self::MitmBrowserPlan { .. } => "mitm browser-plan",
            Self::MitmBrowserCapturePlan { .. } => "mitm browser-capture plan",
            Self::MitmBrowserCaptureLaunchPlan { .. } => "mitm browser-capture launch-plan",
            Self::MitmBrowserCaptureSessionPlan { .. } => "mitm browser-capture session-plan",
            Self::MitmBrowserCaptureLaunch { .. } => "mitm browser-capture launch",
            Self::MitmBrowserCaptureApply { .. } => "mitm browser-capture apply",
            Self::MitmBrowserCaptureRollback { .. } => "mitm browser-capture rollback",
            Self::MitmBrowserCaptureVerify { .. } => "mitm browser-capture verify",
            Self::MitmBrowserCaptureTrafficProof { .. } => "mitm browser-capture traffic-proof",
            Self::MitmHttpRewritePlan { .. } => "mitm http-rewrite plan",
            Self::MitmHttpRewritePreview { .. } => "mitm http-rewrite preview",
            Self::InstallSingBox { .. } => "install-sing-box",
            Self::RunUrl { .. } => "run-url",
        }
    }

    pub const fn format(&self) -> OutputFormat {
        match self {
            Self::Help { format }
            | Self::Version { format }
            | Self::Capabilities { format }
            | Self::PrepareConfig { format, .. }
            | Self::Start { format, .. }
            | Self::Stop { format }
            | Self::Status { format }
            | Self::Diagnostics { format }
            | Self::MitmStatus { format }
            | Self::MitmDiagnostics { format }
            | Self::MitmCertificatePlan { format }
            | Self::MitmCertificateApply { format, .. }
            | Self::MitmCertificateRollback { format, .. }
            | Self::MitmBrowserPlan { format, .. }
            | Self::MitmBrowserCapturePlan { format, .. }
            | Self::MitmBrowserCaptureLaunchPlan { format, .. }
            | Self::MitmBrowserCaptureSessionPlan { format, .. }
            | Self::MitmBrowserCaptureLaunch { format, .. }
            | Self::MitmBrowserCaptureApply { format, .. }
            | Self::MitmBrowserCaptureRollback { format, .. }
            | Self::MitmBrowserCaptureVerify { format, .. }
            | Self::MitmBrowserCaptureTrafficProof { format, .. }
            | Self::MitmHttpRewritePlan { format }
            | Self::MitmHttpRewritePreview { format, .. }
            | Self::InstallSingBox { format, .. }
            | Self::RunUrl { format, .. } => *format,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxCliParseError {
    diagnostic: Box<Diagnostic>,
}

impl LinuxCliParseError {
    pub fn new(diagnostic: Diagnostic) -> Self {
        Self {
            diagnostic: Box::new(diagnostic),
        }
    }

    pub fn diagnostic(&self) -> &Diagnostic {
        self.diagnostic.as_ref()
    }

    pub fn into_diagnostic(self) -> Diagnostic {
        *self.diagnostic
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxCliResponse {
    pub ok: bool,
    pub command: String,
    pub exit_code: LinuxCliExitCode,
    pub diagnostics: Vec<Diagnostic>,
    pub platform: Option<PlatformCapabilityStatus>,
    pub config_profiles: Vec<String>,
    pub version: Option<String>,
    pub help: Option<String>,
    pub sing_box_install: Option<LinuxSingBoxInstallStatus>,
    pub sing_box_run: Option<LinuxSingBoxRunStatus>,
    pub mitm_status: Option<LinuxMitmStatus>,
    pub certificate_lifecycle: Option<LinuxMitmCertificateLifecycleReport>,
    pub browser_capture: Option<LinuxBrowserCaptureReport>,
    pub http_rewrite: Option<LinuxMitmHttpRewriteReport>,
}

impl LinuxCliResponse {
    pub fn success(command: impl Into<String>) -> Self {
        Self {
            ok: true,
            command: command.into(),
            exit_code: LinuxCliExitCode::Success,
            diagnostics: Vec::new(),
            platform: None,
            config_profiles: Vec::new(),
            version: None,
            help: None,
            sing_box_install: None,
            sing_box_run: None,
            mitm_status: None,
            certificate_lifecycle: None,
            browser_capture: None,
            http_rewrite: None,
        }
    }

    pub fn failure(
        command: impl Into<String>,
        exit_code: LinuxCliExitCode,
        diagnostic: Diagnostic,
    ) -> Self {
        Self {
            ok: false,
            command: command.into(),
            exit_code,
            diagnostics: vec![diagnostic],
            platform: None,
            config_profiles: Vec::new(),
            version: None,
            help: None,
            sing_box_install: None,
            sing_box_run: None,
            mitm_status: None,
            certificate_lifecycle: None,
            browser_capture: None,
            http_rewrite: None,
        }
    }

    pub fn with_platform(mut self, platform: PlatformCapabilityStatus) -> Self {
        self.platform = Some(platform);
        self
    }

    pub fn with_config_profiles(mut self, profiles: Vec<String>) -> Self {
        self.config_profiles = profiles;
        self
    }

    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }

    pub fn with_sing_box_install(mut self, install: LinuxSingBoxInstallStatus) -> Self {
        self.sing_box_install = Some(install);
        self
    }

    pub fn with_sing_box_run(mut self, run: LinuxSingBoxRunStatus) -> Self {
        self.sing_box_run = Some(run);
        self
    }

    pub fn with_mitm_status(mut self, status: LinuxMitmStatus) -> Self {
        self.mitm_status = Some(status);
        self
    }

    pub fn with_certificate_lifecycle(
        mut self,
        report: LinuxMitmCertificateLifecycleReport,
    ) -> Self {
        self.certificate_lifecycle = Some(report);
        self
    }

    pub fn with_browser_capture(mut self, report: LinuxBrowserCaptureReport) -> Self {
        self.browser_capture = Some(report);
        self
    }

    pub fn with_http_rewrite(mut self, report: LinuxMitmHttpRewriteReport) -> Self {
        self.http_rewrite = Some(report);
        self
    }

    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSingBoxInstallStatus {
    pub version: String,
    pub target: String,
    pub asset_name: String,
    pub asset_url: String,
    pub asset_sha256: Option<String>,
    pub archive_path: String,
    pub executable_path: String,
    pub downloaded: bool,
}

impl From<SingBoxInstallReport> for LinuxSingBoxInstallStatus {
    fn from(report: SingBoxInstallReport) -> Self {
        Self {
            version: report.version,
            target: report.target.directory_name(),
            asset_name: report.asset_name,
            asset_url: report.asset_url,
            asset_sha256: report.asset_sha256,
            archive_path: report.archive_path.display().to_string(),
            executable_path: report.executable_path.display().to_string(),
            downloaded: report.downloaded,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxSingBoxRunStatus {
    pub node_id: String,
    pub node_name: String,
    pub listen_host: String,
    pub listen_port: u16,
    pub executable_path: String,
    pub config_path: String,
    pub process_exit_code: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmStatus {
    pub stage: String,
    pub user_facing_ready: bool,
    pub browser_hijack: String,
    pub platform_mitm_available: bool,
    pub certificate_state: String,
    pub certificate_plan: LinuxMitmCertificatePlan,
    pub browser_plan: LinuxMitmBrowserPlan,
    pub policy: LinuxMitmPolicyStatus,
    pub gates: Vec<LinuxMitmGateStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificatePlan {
    pub status: String,
    pub mutation_ready: bool,
    pub current_state: String,
    pub subject: Option<String>,
    pub fingerprint_sha256: Option<String>,
    pub required_steps: Vec<LinuxMitmCertificatePlanStep>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificatePlanStep {
    pub id: String,
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxMitmCertificateLifecycleAction {
    Apply,
    Rollback,
}

impl LinuxMitmCertificateLifecycleAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Rollback => "rollback",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmCertificateAuthorization {
    pub confirmed: bool,
    pub source: String,
    pub scope: String,
    pub gate: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmCertificateRollbackSnapshot {
    pub path: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateTrustPlan {
    pub status: String,
    pub mutation_ready: bool,
    pub required_steps: Vec<LinuxMitmCertificatePlanStep>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateArtifactRequest {
    pub cert_file_path: String,
    pub key_file_path: String,
    pub profile_trust_file_path: Option<String>,
    pub snapshot_path: String,
    pub subject: String,
    pub artifact_version: u8,
    pub cert_content: String,
    pub key_content: String,
    pub profile_trust_content: Option<String>,
    pub cert_fingerprint: String,
    pub key_fingerprint: String,
    pub profile_trust_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateArtifactApplyOutcome {
    pub rollback_snapshot: MitmCertificateRollbackSnapshot,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateArtifactRollbackOutcome {
    pub cert_file_path: String,
    pub key_file_path: String,
    pub profile_trust_file_path: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateLifecycleRequest {
    pub action: LinuxMitmCertificateLifecycleAction,
    pub artifact: Option<LinuxMitmCertificateArtifactRequest>,
    pub authorization: Option<MitmCertificateAuthorization>,
    pub rollback_snapshot: Option<MitmCertificateRollbackSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateApplyReport {
    pub status: String,
    pub applied: bool,
    pub authorization: MitmCertificateAuthorization,
    pub cert_file_path: Option<String>,
    pub key_file_path: Option<String>,
    pub profile_trust_file_path: Option<String>,
    pub rollback_snapshot: Option<MitmCertificateRollbackSnapshot>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateRollbackReport {
    pub status: String,
    pub rolled_back: bool,
    pub cert_file_path: Option<String>,
    pub key_file_path: Option<String>,
    pub profile_trust_file_path: Option<String>,
    pub rollback_snapshot: Option<MitmCertificateRollbackSnapshot>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmCertificateLifecycleReport {
    pub action: String,
    pub source_contract_status: String,
    pub gate: String,
    pub gate_status: String,
    pub mutation_ready: bool,
    pub request: LinuxMitmCertificateLifecycleRequest,
    pub plan: LinuxMitmCertificatePlan,
    pub trust_plan: LinuxMitmCertificateTrustPlan,
    pub apply_report: Option<LinuxMitmCertificateApplyReport>,
    pub rollback_report: Option<LinuxMitmCertificateRollbackReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmBrowserPlan {
    pub status: String,
    pub mutation_ready: bool,
    pub current_capture: String,
    pub planned_capture_mode: String,
    pub planned_proxy_host: String,
    pub planned_proxy_port: u16,
    pub required_steps: Vec<LinuxMitmBrowserPlanStep>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmBrowserPlanStep {
    pub id: String,
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxBrowserCaptureAction {
    Plan,
    LaunchPlan,
    SessionPlan,
    Launch,
    Apply,
    Rollback,
    Verify,
    TrafficProof,
}

impl LinuxBrowserCaptureAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::LaunchPlan => "launch-plan",
            Self::SessionPlan => "session-plan",
            Self::Launch => "launch",
            Self::Apply => "apply",
            Self::Rollback => "rollback",
            Self::Verify => "verify",
            Self::TrafficProof => "traffic-proof",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureRequest {
    pub action: LinuxBrowserCaptureAction,
    pub session: Option<LinuxBrowserCaptureSessionPlanRequest>,
    pub launch: Option<LinuxBrowserCaptureLaunchRequest>,
    pub pac: Option<LinuxBrowserCapturePacRequest>,
    pub verify: Option<LinuxBrowserCaptureVerifyRequest>,
    pub traffic_proof: Option<LinuxBrowserCaptureTrafficProofRequest>,
    pub authorization: Option<BrowserCaptureAuthorization>,
    pub rollback_snapshot: Option<BrowserCaptureRollbackSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureSessionPlanRequest {
    pub url_source: String,
    pub browser: String,
    pub profile_dir: String,
    pub target_url: Option<String>,
    pub proof_target_url: Option<String>,
    pub proof_token: String,
    pub proof_log_path: String,
    pub proxy_scheme: String,
    pub listen_host: String,
    pub listen_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserCaptureAuthorization {
    pub confirmed: bool,
    pub source: String,
    pub scope: String,
    pub gate: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserCaptureRollbackSnapshot {
    pub path: String,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCapturePlan {
    pub status: String,
    pub mutation_ready: bool,
    pub current_capture: String,
    pub planned_capture_mode: String,
    pub planned_proxy_scheme: String,
    pub planned_proxy_host: String,
    pub planned_proxy_port: u16,
    pub manual_launch: LinuxBrowserCaptureManualLaunch,
    pub required_steps: Vec<LinuxMitmBrowserPlanStep>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureManualLaunch {
    pub status: String,
    pub proxy_scheme: String,
    pub proxy_url: String,
    pub profile_strategy: String,
    pub plugin_engine: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub browser_commands: Vec<LinuxBrowserCaptureLaunchCommand>,
    pub manual_steps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureLaunchCommand {
    pub browser: String,
    pub executable: String,
    pub args: Vec<String>,
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureLaunchRequest {
    pub browser: String,
    pub profile_dir: String,
    pub target_url: Option<String>,
    pub proof_target_url: Option<String>,
    pub proof_token: String,
    pub proof_log_path: String,
    pub traffic_proof_command: String,
    pub proxy_scheme: String,
    pub proxy_url: String,
    pub command: LinuxBrowserCaptureLaunchCommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureLaunchOutcome {
    pub pid: u32,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCapturePacRequest {
    pub proxy_host: String,
    pub proxy_port: u16,
    pub proxy_scheme: String,
    pub proxy_url: String,
    pub pac_file_path: String,
    pub snapshot_path: String,
    pub pac_url: String,
    pub pac_content: String,
    pub policy_file_path: Option<String>,
    pub policy_url: Option<String>,
    pub policy_content: Option<String>,
    pub profile_prefs_file_path: Option<String>,
    pub profile_prefs_content: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCapturePacApplyOutcome {
    pub rollback_snapshot: BrowserCaptureRollbackSnapshot,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCapturePacRollbackOutcome {
    pub pac_file_path: String,
    pub policy_file_path: Option<String>,
    pub profile_prefs_file_path: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureVerifyRequest {
    pub proxy_host: String,
    pub proxy_port: u16,
    pub proxy_scheme: String,
    pub proxy_url: String,
    pub target_url: Option<String>,
    pub probe: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureVerifyOutcome {
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureTrafficProofRequest {
    pub proxy_host: String,
    pub proxy_port: u16,
    pub proxy_scheme: String,
    pub proxy_url: String,
    pub target_url: Option<String>,
    pub proof_connect_authority: Option<String>,
    pub proof_target_url: Option<String>,
    pub proof_token: String,
    pub proof_log_path: String,
    pub probe: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureTrafficProofOutcome {
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureLaunchReport {
    pub status: String,
    pub launched: bool,
    pub pid: Option<u32>,
    pub request: LinuxBrowserCaptureLaunchRequest,
    pub plugin_engine: String,
    pub plugin_id: String,
    pub plugin_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureApplyReport {
    pub status: String,
    pub applied: bool,
    pub authorization: BrowserCaptureAuthorization,
    pub pac_file_path: Option<String>,
    pub pac_url: Option<String>,
    pub policy_file_path: Option<String>,
    pub policy_url: Option<String>,
    pub profile_prefs_file_path: Option<String>,
    pub rollback_snapshot: Option<BrowserCaptureRollbackSnapshot>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureRollbackReport {
    pub status: String,
    pub rolled_back: bool,
    pub pac_file_path: Option<String>,
    pub policy_file_path: Option<String>,
    pub profile_prefs_file_path: Option<String>,
    pub rollback_snapshot: Option<BrowserCaptureRollbackSnapshot>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureVerifyReport {
    pub status: String,
    pub verified: bool,
    pub request: LinuxBrowserCaptureVerifyRequest,
    pub plugin_engine: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureTrafficProofReport {
    pub status: String,
    pub proven: bool,
    pub request: LinuxBrowserCaptureTrafficProofRequest,
    pub plugin_engine: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureSessionPlanReport {
    pub status: String,
    pub url_source: String,
    pub node_id: String,
    pub node_name: String,
    pub target_url: Option<String>,
    pub proof_target_url: Option<String>,
    pub proof_token: String,
    pub proof_log_path: String,
    pub listen_host: String,
    pub listen_port: u16,
    pub proxy_scheme: String,
    pub proxy_url: String,
    pub run_command: String,
    pub browser_command: LinuxBrowserCaptureLaunchCommand,
    pub verify_command: String,
    pub traffic_proof_command: String,
    pub plugin_engine: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub required_steps: Vec<String>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBrowserCaptureReport {
    pub action: String,
    pub source_contract_status: String,
    pub gate: String,
    pub gate_status: String,
    pub mutation_ready: bool,
    pub request: LinuxBrowserCaptureRequest,
    pub plan: LinuxBrowserCapturePlan,
    pub session_plan: Option<LinuxBrowserCaptureSessionPlanReport>,
    pub launch_report: Option<LinuxBrowserCaptureLaunchReport>,
    pub apply_report: Option<LinuxBrowserCaptureApplyReport>,
    pub rollback_report: Option<LinuxBrowserCaptureRollbackReport>,
    pub verify_report: Option<LinuxBrowserCaptureVerifyReport>,
    pub traffic_proof_report: Option<LinuxBrowserCaptureTrafficProofReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmHttpRewriteAuthorization {
    pub confirmed: bool,
    pub source: String,
    pub scope: String,
    pub gate: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmHttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmHttpRewriteRequest {
    pub url: Option<String>,
    pub method: String,
    pub phase: String,
    pub status_code: Option<u16>,
    pub headers: Vec<LinuxMitmHttpHeader>,
    pub body: Option<String>,
    pub authorization: Option<LinuxMitmHttpRewriteAuthorization>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmHttpRewriteOutcomeReport {
    pub planned: bool,
    pub applied: bool,
    pub action: String,
    pub terminal_action: Option<String>,
    pub final_status_code: Option<u16>,
    pub redirect_location: Option<String>,
    pub header_mutation_count: usize,
    pub body_mutated: bool,
    pub script_dispatch_deferred: bool,
    pub output_headers: Vec<LinuxMitmHttpHeader>,
    pub output_body: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmHttpRewriteReport {
    pub action: String,
    pub source_contract_status: String,
    pub gate: String,
    pub gate_status: String,
    pub mutation_ready: bool,
    pub live_traffic_ready: bool,
    pub tls_decryption_ready: bool,
    pub controlled_tls_termination_plan_ready: bool,
    pub downstream_tls_termination_plan_ready: bool,
    pub upstream_tls_forwarding_ready: bool,
    pub https_request_rewrite_preview_ready: bool,
    pub https_response_rewrite_preview_ready: bool,
    pub https_response_rewrite_ready: bool,
    pub script_dispatch_ready: bool,
    pub request: LinuxMitmHttpRewriteRequest,
    pub outcome: Option<LinuxMitmHttpRewriteOutcomeReport>,
    pub blocked_operations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmPolicyStatus {
    pub engine: String,
    pub engine_version: String,
    pub plugin_id: String,
    pub plugin_version: String,
    pub plugin_loaded: bool,
    pub mitm_pattern_count: usize,
    pub rewrite_rule_count: usize,
    pub script_rule_count: usize,
    pub argument_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxMitmGateStatus {
    pub gate: String,
    pub status: String,
    pub reason: String,
}

pub fn native_proxy_engine_service_with_builtin_mitm_plugin(
) -> DomainResult<engine_native::NativeProxyEngineService> {
    let package = builtin_ad_block_plugin_package();
    let service = AnixOpsMitmPluginService::new();
    let instance = service.load(
        &package,
        &GrantedPermissions {
            permissions: package.manifest.permissions.clone(),
        },
    )?;
    let hook = engine_native::NativeHttpMitmPluginHook::new(instance, Arc::new(service));

    Ok(engine_native::NativeProxyEngineService::new().with_http_mitm_hook(hook))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigReadError {
    pub message: String,
}

impl ConfigReadError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub trait ConfigReader {
    fn read_config(&self, path: &str) -> Result<String, ConfigReadError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FsConfigReader;

impl ConfigReader for FsConfigReader {
    fn read_config(&self, path: &str) -> Result<String, ConfigReadError> {
        std::fs::read_to_string(path).map_err(|error| ConfigReadError::new(error.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogAddRequest {
    pub catalog_path: String,
    pub snapshot_path: String,
    pub source: SubscriptionSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogAddReport {
    pub catalog_path: String,
    pub snapshot_path: String,
    pub source_id: String,
    pub source_count: usize,
    pub location_kind: String,
    pub location_redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogListRequest {
    pub catalog_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogListEntry {
    pub source_id: String,
    pub location_kind: String,
    pub location_redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogListReport {
    pub catalog_path: String,
    pub source_count: usize,
    pub sources: Vec<SubscriptionCatalogListEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogSelectRequest {
    pub catalog_path: String,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogSelectReport {
    pub catalog_path: String,
    pub source_id: String,
    pub location_kind: String,
    pub location_redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogUpdateRequest {
    pub catalog_path: String,
    pub snapshot_path: String,
    pub source_id: String,
    pub location: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogUpdateReport {
    pub catalog_path: String,
    pub snapshot_path: String,
    pub source_id: String,
    pub source_count: usize,
    pub location_kind: String,
    pub location_redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogRollbackRequest {
    pub catalog_path: String,
    pub snapshot_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogRollbackReport {
    pub catalog_path: String,
    pub snapshot_path: String,
    pub source_count: usize,
    pub snapshot_retained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogRemoveRequest {
    pub catalog_path: String,
    pub snapshot_path: String,
    pub source_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCatalogRemoveReport {
    pub catalog_path: String,
    pub snapshot_path: String,
    pub source_id: String,
    pub source_count: usize,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandSubscriptionCatalogStore;

impl CommandSubscriptionCatalogStore {
    pub const fn new() -> Self {
        Self
    }

    pub fn add_source(
        &self,
        request: &SubscriptionCatalogAddRequest,
    ) -> DomainResult<SubscriptionCatalogAddReport> {
        let catalog_path = required_subscription_catalog_path(
            &request.catalog_path,
            CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE,
            "subscription catalog path cannot be empty",
        )?;
        let snapshot_path = required_subscription_catalog_path(
            &request.snapshot_path,
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_PATH_MISSING_CODE,
            "subscription catalog snapshot path cannot be empty",
        )?;
        if catalog_path == snapshot_path {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_PATH_CONFLICT_CODE,
                "subscription catalog and rollback snapshot paths must differ",
            ));
        }
        if std::path::Path::new(&snapshot_path).exists() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
                "refusing to overwrite an existing subscription catalog rollback snapshot",
            ));
        }

        let source_id = request.source.id.trim();
        if source_id.is_empty() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_ID_EMPTY_CODE,
                "subscription catalog source id cannot be empty",
            ));
        }
        let source_location = request.source.location.trim();
        if source_location.is_empty() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_LOCATION_EMPTY_CODE,
                "subscription catalog source location cannot be empty",
            ));
        }

        let (mut catalog, previous_catalog) = read_subscription_catalog_file(&catalog_path)?;
        if catalog
            .sources
            .iter()
            .any(|source| source.id.trim() == source_id)
        {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_DUPLICATE_SOURCE_ID_CODE,
                format!("subscription catalog source id already exists: {source_id}"),
            ));
        }

        catalog.sources.push(SubscriptionCatalogSourceFile {
            id: source_id.to_string(),
            location: source_location.to_string(),
        });
        let snapshot_json = serde_json::to_string_pretty(&previous_catalog).map_err(|error| {
            DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
                format!("failed to render subscription catalog rollback snapshot: {error}"),
            )
        })?;
        let catalog_json = serde_json::to_string_pretty(&catalog).map_err(|error| {
            DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
                format!("failed to render subscription catalog: {error}"),
            )
        })?;

        write_new_file(
            &snapshot_path,
            snapshot_json.as_bytes(),
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
            "subscription catalog rollback snapshot",
        )?;
        write_replace_file(
            &catalog_path,
            catalog_json.as_bytes(),
            CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
            "subscription catalog",
        )?;

        Ok(SubscriptionCatalogAddReport {
            catalog_path,
            snapshot_path,
            source_id: source_id.to_string(),
            source_count: catalog.sources.len(),
            location_kind: subscription_catalog_location_kind(source_location).to_string(),
            location_redacted: true,
        })
    }

    pub fn list_sources(
        &self,
        request: &SubscriptionCatalogListRequest,
    ) -> DomainResult<SubscriptionCatalogListReport> {
        let catalog_path = required_subscription_catalog_path(
            &request.catalog_path,
            CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE,
            "subscription catalog path cannot be empty",
        )?;
        let (catalog, _) = read_subscription_catalog_file(&catalog_path)?;
        let sources = catalog
            .sources
            .iter()
            .map(|source| SubscriptionCatalogListEntry {
                source_id: source.id.trim().to_string(),
                location_kind: subscription_catalog_location_kind(source.location.trim())
                    .to_string(),
                location_redacted: true,
            })
            .collect::<Vec<_>>();

        Ok(SubscriptionCatalogListReport {
            catalog_path,
            source_count: sources.len(),
            sources,
        })
    }

    pub fn select_source(
        &self,
        request: &SubscriptionCatalogSelectRequest,
    ) -> DomainResult<SubscriptionCatalogSelectReport> {
        let catalog_path = required_subscription_catalog_path(
            &request.catalog_path,
            CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE,
            "subscription catalog path cannot be empty",
        )?;
        let source_id = request.source_id.trim();
        if source_id.is_empty() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_ID_EMPTY_CODE,
                "subscription catalog source id cannot be empty",
            ));
        }

        let (catalog, _) = read_subscription_catalog_file(&catalog_path)?;
        let source = catalog
            .sources
            .iter()
            .find(|source| source.id.trim() == source_id)
            .ok_or_else(|| {
                DomainError::new(
                    CLI_SUBSCRIPTION_CATALOG_SOURCE_NOT_FOUND_CODE,
                    format!("subscription catalog source id was not found: {source_id}"),
                )
            })?;

        Ok(SubscriptionCatalogSelectReport {
            catalog_path,
            source_id: source.id.trim().to_string(),
            location_kind: subscription_catalog_location_kind(source.location.trim()).to_string(),
            location_redacted: true,
        })
    }

    pub fn update_source(
        &self,
        request: &SubscriptionCatalogUpdateRequest,
    ) -> DomainResult<SubscriptionCatalogUpdateReport> {
        let catalog_path = required_subscription_catalog_path(
            &request.catalog_path,
            CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE,
            "subscription catalog path cannot be empty",
        )?;
        let snapshot_path = required_subscription_catalog_path(
            &request.snapshot_path,
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_PATH_MISSING_CODE,
            "subscription catalog snapshot path cannot be empty",
        )?;
        if catalog_path == snapshot_path {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_PATH_CONFLICT_CODE,
                "subscription catalog and rollback snapshot paths must differ",
            ));
        }
        if std::path::Path::new(&snapshot_path).exists() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
                "refusing to overwrite an existing subscription catalog rollback snapshot",
            ));
        }

        let source_id = request.source_id.trim();
        if source_id.is_empty() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_ID_EMPTY_CODE,
                "subscription catalog source id cannot be empty",
            ));
        }
        let location = request.location.trim();
        if location.is_empty() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_LOCATION_EMPTY_CODE,
                "subscription catalog source location cannot be empty",
            ));
        }

        let (mut catalog, previous_catalog) = read_subscription_catalog_file(&catalog_path)?;
        let source = catalog
            .sources
            .iter_mut()
            .find(|source| source.id.trim() == source_id)
            .ok_or_else(|| {
                DomainError::new(
                    CLI_SUBSCRIPTION_CATALOG_SOURCE_NOT_FOUND_CODE,
                    format!("subscription catalog source id was not found: {source_id}"),
                )
            })?;
        source.location = location.to_string();

        let snapshot_json = serde_json::to_string_pretty(&previous_catalog).map_err(|error| {
            DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
                format!("failed to render subscription catalog rollback snapshot: {error}"),
            )
        })?;
        let catalog_json = serde_json::to_string_pretty(&catalog).map_err(|error| {
            DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
                format!("failed to render subscription catalog: {error}"),
            )
        })?;

        write_new_file(
            &snapshot_path,
            snapshot_json.as_bytes(),
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
            "subscription catalog rollback snapshot",
        )?;
        write_replace_file(
            &catalog_path,
            catalog_json.as_bytes(),
            CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
            "subscription catalog",
        )?;

        Ok(SubscriptionCatalogUpdateReport {
            catalog_path,
            snapshot_path,
            source_id: source_id.to_string(),
            source_count: catalog.sources.len(),
            location_kind: subscription_catalog_location_kind(location).to_string(),
            location_redacted: true,
        })
    }

    pub fn rollback_catalog(
        &self,
        request: &SubscriptionCatalogRollbackRequest,
    ) -> DomainResult<SubscriptionCatalogRollbackReport> {
        let catalog_path = required_subscription_catalog_path(
            &request.catalog_path,
            CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE,
            "subscription catalog path cannot be empty",
        )?;
        let snapshot_path = required_subscription_catalog_path(
            &request.snapshot_path,
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_PATH_MISSING_CODE,
            "subscription catalog snapshot path cannot be empty",
        )?;
        if catalog_path == snapshot_path {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_PATH_CONFLICT_CODE,
                "subscription catalog and rollback snapshot paths must differ",
            ));
        }

        let (snapshot, snapshot_contents) =
            read_required_subscription_catalog_snapshot_file(&snapshot_path)?;
        write_replace_file(
            &catalog_path,
            snapshot_contents.as_bytes(),
            CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
            "subscription catalog",
        )?;

        Ok(SubscriptionCatalogRollbackReport {
            catalog_path,
            snapshot_path,
            source_count: snapshot.sources.len(),
            snapshot_retained: true,
        })
    }

    pub fn remove_source(
        &self,
        request: &SubscriptionCatalogRemoveRequest,
    ) -> DomainResult<SubscriptionCatalogRemoveReport> {
        let catalog_path = required_subscription_catalog_path(
            &request.catalog_path,
            CLI_SUBSCRIPTION_CATALOG_PATH_MISSING_CODE,
            "subscription catalog path cannot be empty",
        )?;
        let snapshot_path = required_subscription_catalog_path(
            &request.snapshot_path,
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_PATH_MISSING_CODE,
            "subscription catalog snapshot path cannot be empty",
        )?;
        if catalog_path == snapshot_path {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_PATH_CONFLICT_CODE,
                "subscription catalog and rollback snapshot paths must differ",
            ));
        }
        if std::path::Path::new(&snapshot_path).exists() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
                "refusing to overwrite an existing subscription catalog rollback snapshot",
            ));
        }

        let source_id = request.source_id.trim();
        if source_id.is_empty() {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_ID_EMPTY_CODE,
                "subscription catalog source id cannot be empty",
            ));
        }

        let (mut catalog, previous_catalog) = read_subscription_catalog_file(&catalog_path)?;
        let source_exists = catalog
            .sources
            .iter()
            .any(|source| source.id.trim() == source_id);
        if !source_exists {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SOURCE_NOT_FOUND_CODE,
                format!("subscription catalog source id was not found: {source_id}"),
            ));
        }
        catalog
            .sources
            .retain(|source| source.id.trim() != source_id);

        let snapshot_json = serde_json::to_string_pretty(&previous_catalog).map_err(|error| {
            DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
                format!("failed to render subscription catalog rollback snapshot: {error}"),
            )
        })?;
        let catalog_json = serde_json::to_string_pretty(&catalog).map_err(|error| {
            DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
                format!("failed to render subscription catalog: {error}"),
            )
        })?;

        write_new_file(
            &snapshot_path,
            snapshot_json.as_bytes(),
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_WRITE_FAILED_CODE,
            "subscription catalog rollback snapshot",
        )?;
        write_replace_file(
            &catalog_path,
            catalog_json.as_bytes(),
            CLI_SUBSCRIPTION_CATALOG_WRITE_FAILED_CODE,
            "subscription catalog",
        )?;

        Ok(SubscriptionCatalogRemoveReport {
            catalog_path,
            snapshot_path,
            source_id: source_id.to_string(),
            source_count: catalog.sources.len(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubscriptionCatalogFile {
    schema_version: u32,
    sources: Vec<SubscriptionCatalogSourceFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubscriptionCatalogSourceFile {
    id: String,
    location: String,
}

fn required_subscription_catalog_path(
    path: &str,
    code: &'static str,
    message: &'static str,
) -> DomainResult<String> {
    let path = path.trim();
    if path.is_empty() {
        return Err(DomainError::new(code, message));
    }
    Ok(path.to_string())
}

fn read_subscription_catalog_file(
    path: &str,
) -> DomainResult<(SubscriptionCatalogFile, SubscriptionCatalogFile)> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let empty = SubscriptionCatalogFile {
                schema_version: SUBSCRIPTION_CATALOG_SCHEMA_VERSION,
                sources: Vec::new(),
            };
            return Ok((empty.clone(), empty));
        }
        Err(error) => {
            return Err(DomainError::new(
                CLI_SUBSCRIPTION_CATALOG_READ_FAILED_CODE,
                format!("failed to read subscription catalog {path}: {error}"),
            ));
        }
    };
    let catalog = serde_json::from_str::<SubscriptionCatalogFile>(&contents).map_err(|error| {
        DomainError::new(
            CLI_SUBSCRIPTION_CATALOG_READ_FAILED_CODE,
            format!("failed to parse subscription catalog {path}: {error}"),
        )
    })?;
    let catalog = validate_subscription_catalog_file(catalog)?;
    Ok((catalog.clone(), catalog))
}

fn read_required_subscription_catalog_snapshot_file(
    path: &str,
) -> DomainResult<(SubscriptionCatalogFile, String)> {
    let contents = std::fs::read_to_string(path).map_err(|error| {
        DomainError::new(
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_READ_FAILED_CODE,
            format!("failed to read subscription catalog rollback snapshot {path}: {error}"),
        )
    })?;
    let catalog = serde_json::from_str::<SubscriptionCatalogFile>(&contents).map_err(|error| {
        DomainError::new(
            CLI_SUBSCRIPTION_CATALOG_SNAPSHOT_READ_FAILED_CODE,
            format!("failed to parse subscription catalog rollback snapshot {path}: {error}"),
        )
    })?;
    Ok((validate_subscription_catalog_file(catalog)?, contents))
}

fn validate_subscription_catalog_file(
    catalog: SubscriptionCatalogFile,
) -> DomainResult<SubscriptionCatalogFile> {
    if catalog.schema_version != SUBSCRIPTION_CATALOG_SCHEMA_VERSION {
        return Err(DomainError::new(
            CLI_SUBSCRIPTION_CATALOG_SCHEMA_UNSUPPORTED_CODE,
            "subscription catalog schema version is unsupported",
        ));
    }
    if catalog
        .sources
        .iter()
        .any(|source| source.id.trim().is_empty() || source.location.trim().is_empty())
    {
        return Err(DomainError::new(
            CLI_SUBSCRIPTION_CATALOG_SOURCE_INVALID_CODE,
            "subscription catalog contains an empty source id or location",
        ));
    }
    Ok(catalog)
}

fn subscription_catalog_location_kind(location: &str) -> &'static str {
    if location.starts_with("inline:") {
        "inline"
    } else if location.starts_with("http://") || location.starts_with("https://") {
        "remote"
    } else if location.starts_with("file:") {
        "file"
    } else {
        "other"
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableProxyEngineService;

impl UnavailableProxyEngineService {
    pub const fn new() -> Self {
        Self
    }
}

impl ProxyEngineService for UnavailableProxyEngineService {
    fn list_engines(&self) -> Vec<ProxyEngineDescriptor> {
        Vec::new()
    }

    fn validate_config(&self, _engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
        vec![cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_RUNTIME_UNWIRED_CODE,
            "linux proxy engine adapter is not wired",
            SOURCE_CLI_RUNTIME,
        )]
    }

    fn start(&self, _engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        Err(unavailable_engine_error())
    }

    fn reload(&self, _engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        Err(unavailable_engine_error())
    }

    fn stop(&self, _engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        Err(unavailable_engine_error())
    }

    fn status(&self, _engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        Err(unavailable_engine_error())
    }

    fn events(&self, _engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
        Err(unavailable_engine_error())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundLifecycleRequest {
    pub engine_status: ProxyEngineStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundLifecycleOutcome {
    pub exit_code: LinuxCliExitCode,
    pub diagnostics: Vec<Diagnostic>,
}

impl ForegroundLifecycleOutcome {
    pub fn success(diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            exit_code: LinuxCliExitCode::Success,
            diagnostics,
        }
    }

    pub fn failure(exit_code: LinuxCliExitCode, diagnostic: Diagnostic) -> Self {
        Self {
            exit_code,
            diagnostics: vec![diagnostic],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForegroundLifecycleInterruption {
    pub reason: String,
    pub diagnostics: Vec<Diagnostic>,
}

impl ForegroundLifecycleInterruption {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
            diagnostics: Vec::new(),
        }
    }

    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }
}

pub trait ForegroundLifecycleHost {
    fn run_foreground(&self, request: &ForegroundLifecycleRequest) -> ForegroundLifecycleOutcome;
}

pub trait ForegroundLifecycleInterruptionSource {
    fn wait_for_interruption(
        &self,
        request: &ForegroundLifecycleRequest,
    ) -> ForegroundLifecycleInterruption;
}

pub trait BrowserCaptureProcessRunner {
    fn launch(
        &self,
        request: &LinuxBrowserCaptureLaunchRequest,
    ) -> DomainResult<LinuxBrowserCaptureLaunchOutcome>;
}

pub trait BrowserCaptureEndpointProbe {
    fn verify_proxy_endpoint(
        &self,
        request: &LinuxBrowserCaptureVerifyRequest,
    ) -> DomainResult<LinuxBrowserCaptureVerifyOutcome>;
}

pub trait BrowserCaptureTrafficProofProbe {
    fn verify_traffic_proof(
        &self,
        request: &LinuxBrowserCaptureTrafficProofRequest,
    ) -> DomainResult<LinuxBrowserCaptureTrafficProofOutcome>;
}

pub trait BrowserCapturePacFileStore {
    fn apply_pac_file(
        &self,
        request: &LinuxBrowserCapturePacRequest,
    ) -> DomainResult<LinuxBrowserCapturePacApplyOutcome>;

    fn rollback_pac_file(
        &self,
        snapshot: &BrowserCaptureRollbackSnapshot,
    ) -> DomainResult<LinuxBrowserCapturePacRollbackOutcome>;
}

pub trait MitmCertificateArtifactStore {
    fn apply_certificate_artifact(
        &self,
        request: &LinuxMitmCertificateArtifactRequest,
    ) -> DomainResult<LinuxMitmCertificateArtifactApplyOutcome>;

    fn rollback_certificate_artifact(
        &self,
        snapshot: &MitmCertificateRollbackSnapshot,
    ) -> DomainResult<LinuxMitmCertificateArtifactRollbackOutcome>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandBrowserCaptureProcessRunner;

impl CommandBrowserCaptureProcessRunner {
    pub const fn new() -> Self {
        Self
    }
}

impl BrowserCaptureProcessRunner for CommandBrowserCaptureProcessRunner {
    fn launch(
        &self,
        request: &LinuxBrowserCaptureLaunchRequest,
    ) -> DomainResult<LinuxBrowserCaptureLaunchOutcome> {
        let child = std::process::Command::new(&request.command.executable)
            .args(&request.command.args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .map_err(|error| {
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_LAUNCH_FAILED_CODE,
                    format!(
                        "failed to launch browser capture profile with {}: {error}",
                        request.command.executable
                    ),
                )
            })?;

        Ok(LinuxBrowserCaptureLaunchOutcome {
            pid: child.id(),
            diagnostics: vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_LAUNCH_STARTED_CODE,
                "browser capture dedicated profile process was started with an explicit proxy argument",
                SOURCE_CLI_MITM,
            )],
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandBrowserCaptureEndpointProbe;

impl CommandBrowserCaptureEndpointProbe {
    pub const fn new() -> Self {
        Self
    }
}

impl BrowserCaptureEndpointProbe for CommandBrowserCaptureEndpointProbe {
    fn verify_proxy_endpoint(
        &self,
        request: &LinuxBrowserCaptureVerifyRequest,
    ) -> DomainResult<LinuxBrowserCaptureVerifyOutcome> {
        let target = request
            .target_url
            .as_deref()
            .map(parse_browser_capture_target_endpoint)
            .transpose()?;
        let address = format!("{}:{}", request.proxy_host, request.proxy_port);
        let mut addrs = address.as_str().to_socket_addrs().map_err(|error| {
            DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                format!("failed to resolve browser capture proxy endpoint {address}: {error}"),
            )
        })?;
        let socket_addr = addrs.next().ok_or_else(|| {
            DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                format!("browser capture proxy endpoint {address} did not resolve"),
            )
        })?;

        let mut stream =
            TcpStream::connect_timeout(&socket_addr, Duration::from_secs(2)).map_err(|error| {
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                    format!(
                        "browser capture planned proxy endpoint {} is not reachable: {error}",
                        request.proxy_url
                    ),
                )
            })?;
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|error| {
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                    format!(
                        "failed to set browser capture proxy read timeout for {}: {error}",
                        request.proxy_url
                    ),
                )
            })?;
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .map_err(|error| {
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                    format!(
                        "failed to set browser capture proxy write timeout for {}: {error}",
                        request.proxy_url
                    ),
                )
            })?;

        if let (Some(target_url), Some(target)) = (&request.target_url, target) {
            let authority = target.authority();
            let connect_request = format!(
                "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: networkcore-linux-browser-capture-verify\r\nProxy-Connection: close\r\n\r\n"
            );
            stream
                .write_all(connect_request.as_bytes())
                .map_err(|error| {
                    DomainError::new(
                        CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                        format!(
                            "failed to write browser capture target probe through {} for {target_url}: {error}",
                            request.proxy_url
                        ),
                    )
                })?;
            let mut buffer = [0_u8; 512];
            let byte_count = stream.read(&mut buffer).map_err(|error| {
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                    format!(
                        "failed to read browser capture target probe response through {} for {target_url}: {error}",
                        request.proxy_url
                    ),
                )
            })?;
            let response = String::from_utf8_lossy(&buffer[..byte_count]);
            let status_line = response.lines().next().unwrap_or_default();
            if !status_line.contains(" 200 ") && !status_line.ends_with(" 200") {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_UNREACHABLE_CODE,
                    format!(
                        "browser capture proxy {} did not open a CONNECT tunnel to {target_url}: {status_line}",
                        request.proxy_url
                    ),
                ));
            }

            return Ok(LinuxBrowserCaptureVerifyOutcome {
                diagnostics: vec![cli_diagnostic(
                    DiagnosticSeverity::Info,
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_REACHABLE_CODE,
                    format!(
                        "browser capture planned proxy endpoint {} can open a target tunnel to {target_url}",
                        request.proxy_url
                    ),
                    SOURCE_CLI_MITM,
                )],
            });
        }

        Ok(LinuxBrowserCaptureVerifyOutcome {
            diagnostics: vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_VERIFY_PROXY_REACHABLE_CODE,
                format!(
                    "browser capture planned proxy endpoint {} is reachable",
                    request.proxy_url
                ),
                SOURCE_CLI_MITM,
            )],
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandBrowserCaptureTrafficProofProbe;

impl CommandBrowserCaptureTrafficProofProbe {
    pub const fn new() -> Self {
        Self
    }
}

impl BrowserCaptureTrafficProofProbe for CommandBrowserCaptureTrafficProofProbe {
    fn verify_traffic_proof(
        &self,
        request: &LinuxBrowserCaptureTrafficProofRequest,
    ) -> DomainResult<LinuxBrowserCaptureTrafficProofOutcome> {
        let proof_log = std::fs::read_to_string(&request.proof_log_path).map_err(|error| {
            DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_LOG_UNREADABLE_CODE,
                format!(
                    "failed to read browser capture traffic proof log {}: {error}",
                    request.proof_log_path
                ),
            )
        })?;

        let token_observed = proof_log.contains(&request.proof_token);
        if !token_observed {
            return Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_MISSING_CODE,
                "browser capture traffic proof token was not observed in the proof log",
            ));
        }
        if let Some(authority) = &request.proof_connect_authority {
            let bound_line_observed = proof_log.lines().any(|line| {
                line.contains(&request.proof_token)
                    && line.contains(&request.proxy_url)
                    && line.contains(authority)
            });
            if !bound_line_observed {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BINDING_MISMATCH_CODE,
                    format!(
                        "browser capture proof token was observed, but no proof log line bound it to proxy {} and CONNECT authority {authority}",
                        request.proxy_url
                    ),
                ));
            }
        }

        let observed_message = if request.proof_connect_authority.is_some() {
            "browser capture proof token was observed in the proof log with the expected proxy and CONNECT authority binding"
        } else {
            "browser capture proof token was observed in the proof log"
        };

        Ok(LinuxBrowserCaptureTrafficProofOutcome {
            diagnostics: vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_OBSERVED_CODE,
                observed_message,
                SOURCE_CLI_MITM,
            )],
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandBrowserCapturePacFileStore;

impl CommandBrowserCapturePacFileStore {
    pub const fn new() -> Self {
        Self
    }
}

impl BrowserCapturePacFileStore for CommandBrowserCapturePacFileStore {
    fn apply_pac_file(
        &self,
        request: &LinuxBrowserCapturePacRequest,
    ) -> DomainResult<LinuxBrowserCapturePacApplyOutcome> {
        if std::path::Path::new(&request.pac_file_path).exists() {
            return Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_PAC_WRITE_FAILED_CODE,
                format!(
                    "refusing to overwrite existing browser capture PAC file {}",
                    request.pac_file_path
                ),
            ));
        }
        if std::path::Path::new(&request.snapshot_path).exists() {
            return Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_WRITE_FAILED_CODE,
                format!(
                    "refusing to overwrite existing browser capture rollback snapshot {}",
                    request.snapshot_path
                ),
            ));
        }
        if let Some(policy_file_path) = &request.policy_file_path {
            if std::path::Path::new(policy_file_path).exists() {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_POLICY_WRITE_FAILED_CODE,
                    format!(
                        "refusing to overwrite existing browser capture policy file {policy_file_path}"
                    ),
                ));
            }
        }
        let profile_prefs_previous_content = request
            .profile_prefs_file_path
            .as_ref()
            .map(|path| match std::fs::read_to_string(path) {
                Ok(contents) => Ok(Some(contents)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_PROFILE_PREFS_WRITE_FAILED_CODE,
                    format!("failed to read browser capture profile prefs file {path}: {error}"),
                )),
            })
            .transpose()?
            .flatten();

        let snapshot = BrowserCapturePacSnapshotFile {
            version: 1,
            kind: BROWSER_CAPTURE_PAC_SNAPSHOT_KIND.to_string(),
            pac_file_path: request.pac_file_path.clone(),
            pac_url: request.pac_url.clone(),
            created_file: true,
            policy_file_path: request.policy_file_path.clone(),
            policy_url: request.policy_url.clone(),
            created_policy_file: request.policy_file_path.is_some(),
            profile_prefs_file_path: request.profile_prefs_file_path.clone(),
            created_profile_prefs_file: request.profile_prefs_file_path.is_some()
                && profile_prefs_previous_content.is_none(),
            previous_profile_prefs_content: profile_prefs_previous_content,
            applied_profile_prefs_content: request.profile_prefs_content.clone(),
        };

        let snapshot_json = serde_json::to_string_pretty(&snapshot).map_err(|error| {
            DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_WRITE_FAILED_CODE,
                format!(
                    "failed to render browser capture PAC snapshot {}: {error}",
                    request.snapshot_path
                ),
            )
        })?;
        write_new_file(
            &request.snapshot_path,
            snapshot_json.as_bytes(),
            CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_WRITE_FAILED_CODE,
            "browser capture PAC snapshot",
        )?;

        write_new_file(
            &request.pac_file_path,
            request.pac_content.as_bytes(),
            CLI_MITM_BROWSER_CAPTURE_PAC_WRITE_FAILED_CODE,
            "browser capture PAC file",
        )?;
        if let (Some(policy_file_path), Some(policy_content)) =
            (&request.policy_file_path, &request.policy_content)
        {
            write_new_file(
                policy_file_path,
                policy_content.as_bytes(),
                CLI_MITM_BROWSER_CAPTURE_POLICY_WRITE_FAILED_CODE,
                "browser capture browser policy file",
            )?;
        }
        if let (Some(profile_prefs_file_path), Some(profile_prefs_content)) = (
            &request.profile_prefs_file_path,
            &request.profile_prefs_content,
        ) {
            write_replace_file(
                profile_prefs_file_path,
                profile_prefs_content.as_bytes(),
                CLI_MITM_BROWSER_CAPTURE_PROFILE_PREFS_WRITE_FAILED_CODE,
                "browser capture Firefox profile prefs file",
            )?;
        }

        let policy_message = request
            .policy_file_path
            .as_ref()
            .map(|path| format!(" and browser policy file {path}"))
            .unwrap_or_default();
        let profile_prefs_message = request
            .profile_prefs_file_path
            .as_ref()
            .map(|path| format!(" and Firefox profile prefs file {path}"))
            .unwrap_or_default();
        Ok(LinuxBrowserCapturePacApplyOutcome {
            rollback_snapshot: BrowserCaptureRollbackSnapshot {
                path: request.snapshot_path.clone(),
                status: "networkcore-created".to_string(),
            },
            diagnostics: vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_APPLY_READY_CODE,
                format!(
                    "browser capture PAC file {}{}{} was written with planned proxy {}",
                    request.pac_file_path, policy_message, profile_prefs_message, request.proxy_url
                ),
                SOURCE_CLI_MITM,
            )],
        })
    }

    fn rollback_pac_file(
        &self,
        snapshot: &BrowserCaptureRollbackSnapshot,
    ) -> DomainResult<LinuxBrowserCapturePacRollbackOutcome> {
        let snapshot_json = std::fs::read_to_string(&snapshot.path).map_err(|error| {
            DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_READ_FAILED_CODE,
                format!(
                    "failed to read browser capture PAC snapshot {}: {error}",
                    snapshot.path
                ),
            )
        })?;
        let snapshot_file: BrowserCapturePacSnapshotFile = serde_json::from_str(&snapshot_json)
            .map_err(|error| {
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_READ_FAILED_CODE,
                    format!(
                        "failed to parse browser capture PAC snapshot {}: {error}",
                        snapshot.path
                    ),
                )
            })?;
        if snapshot_file.kind != BROWSER_CAPTURE_PAC_SNAPSHOT_KIND || !snapshot_file.created_file {
            return Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_READ_FAILED_CODE,
                "browser capture rollback snapshot is not a NetworkCore PAC snapshot",
            ));
        }

        match std::fs::remove_file(&snapshot_file.pac_file_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_ROLLBACK_FAILED_CODE,
                    format!(
                        "failed to remove browser capture PAC file {}: {error}",
                        snapshot_file.pac_file_path
                    ),
                ));
            }
        }
        if snapshot_file.created_policy_file {
            let Some(policy_file_path) = snapshot_file.policy_file_path.as_ref() else {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_READ_FAILED_CODE,
                    "browser capture rollback snapshot is missing the policy file path",
                ));
            };
            match std::fs::remove_file(policy_file_path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(DomainError::new(
                        CLI_MITM_BROWSER_CAPTURE_ROLLBACK_FAILED_CODE,
                        format!(
                            "failed to remove browser capture policy file {policy_file_path}: {error}"
                        ),
                    ));
                }
            }
        }
        if let Some(profile_prefs_file_path) = snapshot_file.profile_prefs_file_path.as_ref() {
            let Some(applied_content) = snapshot_file.applied_profile_prefs_content.as_ref() else {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_READ_FAILED_CODE,
                    "browser capture rollback snapshot is missing applied profile prefs content",
                ));
            };
            match std::fs::read_to_string(profile_prefs_file_path) {
                Ok(current_content) if current_content != *applied_content => {
                    return Err(DomainError::new(
                        CLI_MITM_BROWSER_CAPTURE_ROLLBACK_FAILED_CODE,
                        format!(
                            "refusing to rollback browser capture profile prefs file {profile_prefs_file_path} because it changed after apply"
                        ),
                    ));
                }
                Ok(_) => {
                    rollback_profile_prefs_file(
                        profile_prefs_file_path,
                        snapshot_file.created_profile_prefs_file,
                        snapshot_file.previous_profile_prefs_content.as_deref(),
                    )?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if !snapshot_file.created_profile_prefs_file {
                        rollback_profile_prefs_file(
                            profile_prefs_file_path,
                            false,
                            snapshot_file.previous_profile_prefs_content.as_deref(),
                        )?;
                    }
                }
                Err(error) => {
                    return Err(DomainError::new(
                        CLI_MITM_BROWSER_CAPTURE_ROLLBACK_FAILED_CODE,
                        format!(
                            "failed to read browser capture profile prefs file {profile_prefs_file_path}: {error}"
                        ),
                    ));
                }
            }
        }

        Ok(LinuxBrowserCapturePacRollbackOutcome {
            pac_file_path: snapshot_file.pac_file_path.clone(),
            policy_file_path: snapshot_file.policy_file_path.clone(),
            profile_prefs_file_path: snapshot_file.profile_prefs_file_path.clone(),
            diagnostics: vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_ROLLBACK_READY_CODE,
                format!(
                    "browser capture PAC file {}, optional policy artifact, and optional profile prefs were restored from snapshot {}",
                    snapshot_file.pac_file_path, snapshot.path
                ),
                SOURCE_CLI_MITM,
            )],
        })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableBrowserCapturePacFileStore;

impl UnavailableBrowserCapturePacFileStore {
    pub const fn new() -> Self {
        Self
    }
}

impl BrowserCapturePacFileStore for UnavailableBrowserCapturePacFileStore {
    fn apply_pac_file(
        &self,
        _request: &LinuxBrowserCapturePacRequest,
    ) -> DomainResult<LinuxBrowserCapturePacApplyOutcome> {
        Err(DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_APPLY_BLOCKED_CODE,
            "browser capture PAC file store is not wired",
        ))
    }

    fn rollback_pac_file(
        &self,
        _snapshot: &BrowserCaptureRollbackSnapshot,
    ) -> DomainResult<LinuxBrowserCapturePacRollbackOutcome> {
        Err(DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_ROLLBACK_BLOCKED_CODE,
            "browser capture PAC file store is not wired",
        ))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CommandMitmCertificateArtifactStore;

impl CommandMitmCertificateArtifactStore {
    pub const fn new() -> Self {
        Self
    }
}

impl MitmCertificateArtifactStore for CommandMitmCertificateArtifactStore {
    fn apply_certificate_artifact(
        &self,
        request: &LinuxMitmCertificateArtifactRequest,
    ) -> DomainResult<LinuxMitmCertificateArtifactApplyOutcome> {
        validate_mitm_certificate_artifact_request(request)?;

        if std::path::Path::new(&request.cert_file_path).exists() {
            return Err(DomainError::new(
                CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
                format!(
                    "refusing to overwrite existing MITM certificate artifact {}",
                    request.cert_file_path
                ),
            ));
        }
        if std::path::Path::new(&request.key_file_path).exists() {
            return Err(DomainError::new(
                CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
                format!(
                    "refusing to overwrite existing MITM private key artifact {}",
                    request.key_file_path
                ),
            ));
        }
        if let Some(profile_trust_file_path) = &request.profile_trust_file_path {
            if std::path::Path::new(profile_trust_file_path).exists() {
                return Err(DomainError::new(
                    CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
                    format!(
                        "refusing to overwrite existing MITM dedicated profile trust artifact {}",
                        profile_trust_file_path
                    ),
                ));
            }
        }
        if std::path::Path::new(&request.snapshot_path).exists() {
            return Err(DomainError::new(
                CLI_MITM_CERTIFICATE_SNAPSHOT_WRITE_FAILED_CODE,
                format!(
                    "refusing to overwrite existing MITM certificate rollback snapshot {}",
                    request.snapshot_path
                ),
            ));
        }

        let snapshot = MitmCertificateArtifactSnapshotFile {
            version: 1,
            kind: MITM_CERTIFICATE_ARTIFACT_SNAPSHOT_KIND.to_string(),
            cert_file_path: request.cert_file_path.clone(),
            key_file_path: request.key_file_path.clone(),
            profile_trust_file_path: request.profile_trust_file_path.clone(),
            subject: request.subject.clone(),
            created_cert_file: true,
            created_key_file: true,
            created_profile_trust_file: request.profile_trust_file_path.is_some(),
            applied_cert_fingerprint: request.cert_fingerprint.clone(),
            applied_key_fingerprint: request.key_fingerprint.clone(),
            applied_profile_trust_fingerprint: request.profile_trust_fingerprint.clone(),
        };
        let snapshot_json = serde_json::to_string_pretty(&snapshot).map_err(|error| {
            DomainError::new(
                CLI_MITM_CERTIFICATE_SNAPSHOT_WRITE_FAILED_CODE,
                format!(
                    "failed to render MITM certificate artifact snapshot {}: {error}",
                    request.snapshot_path
                ),
            )
        })?;

        write_new_file(
            &request.snapshot_path,
            snapshot_json.as_bytes(),
            CLI_MITM_CERTIFICATE_SNAPSHOT_WRITE_FAILED_CODE,
            "MITM certificate artifact snapshot",
        )?;
        write_new_file(
            &request.cert_file_path,
            request.cert_content.as_bytes(),
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM certificate artifact",
        )?;
        write_new_file(
            &request.key_file_path,
            request.key_content.as_bytes(),
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM private key artifact",
        )?;
        if let (Some(profile_trust_file_path), Some(profile_trust_content)) = (
            &request.profile_trust_file_path,
            &request.profile_trust_content,
        ) {
            write_new_file(
                profile_trust_file_path,
                profile_trust_content.as_bytes(),
                CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
                "MITM dedicated profile trust artifact",
            )?;
        }

        Ok(LinuxMitmCertificateArtifactApplyOutcome {
            rollback_snapshot: MitmCertificateRollbackSnapshot {
                path: request.snapshot_path.clone(),
                status: "networkcore-created".to_string(),
            },
            diagnostics: vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_CERTIFICATE_APPLY_READY_CODE,
                format!(
                    "MITM certificate artifact {} and private key artifact {} were written with profile trust artifact {} and system trust-store mutation blocked",
                    request.cert_file_path,
                    request.key_file_path,
                    request
                        .profile_trust_file_path
                        .as_deref()
                        .unwrap_or("not-requested")
                ),
                SOURCE_CLI_MITM,
            )],
        })
    }

    fn rollback_certificate_artifact(
        &self,
        snapshot: &MitmCertificateRollbackSnapshot,
    ) -> DomainResult<LinuxMitmCertificateArtifactRollbackOutcome> {
        let snapshot_json = std::fs::read_to_string(&snapshot.path).map_err(|error| {
            DomainError::new(
                CLI_MITM_CERTIFICATE_SNAPSHOT_READ_FAILED_CODE,
                format!(
                    "failed to read MITM certificate artifact snapshot {}: {error}",
                    snapshot.path
                ),
            )
        })?;
        let snapshot_file: MitmCertificateArtifactSnapshotFile =
            serde_json::from_str(&snapshot_json).map_err(|error| {
                DomainError::new(
                    CLI_MITM_CERTIFICATE_SNAPSHOT_READ_FAILED_CODE,
                    format!(
                        "failed to parse MITM certificate artifact snapshot {}: {error}",
                        snapshot.path
                    ),
                )
            })?;
        if snapshot_file.kind != MITM_CERTIFICATE_ARTIFACT_SNAPSHOT_KIND
            || !snapshot_file.created_cert_file
            || !snapshot_file.created_key_file
        {
            return Err(DomainError::new(
                CLI_MITM_CERTIFICATE_SNAPSHOT_READ_FAILED_CODE,
                "MITM certificate rollback snapshot is not a NetworkCore certificate artifact snapshot",
            ));
        }

        rollback_mitm_certificate_artifact_file(
            &snapshot_file.cert_file_path,
            &snapshot_file.applied_cert_fingerprint,
            "MITM certificate artifact",
        )?;
        rollback_mitm_certificate_artifact_file(
            &snapshot_file.key_file_path,
            &snapshot_file.applied_key_fingerprint,
            "MITM private key artifact",
        )?;
        if snapshot_file.created_profile_trust_file {
            let (Some(profile_trust_file_path), Some(applied_profile_trust_fingerprint)) = (
                snapshot_file.profile_trust_file_path.as_deref(),
                snapshot_file.applied_profile_trust_fingerprint.as_deref(),
            ) else {
                return Err(DomainError::new(
                    CLI_MITM_CERTIFICATE_SNAPSHOT_READ_FAILED_CODE,
                    "MITM certificate rollback snapshot is missing dedicated profile trust artifact fields",
                ));
            };
            rollback_mitm_certificate_artifact_file(
                profile_trust_file_path,
                applied_profile_trust_fingerprint,
                "MITM dedicated profile trust artifact",
            )?;
        }

        Ok(LinuxMitmCertificateArtifactRollbackOutcome {
            cert_file_path: snapshot_file.cert_file_path.clone(),
            key_file_path: snapshot_file.key_file_path.clone(),
            profile_trust_file_path: snapshot_file.profile_trust_file_path.clone(),
            diagnostics: vec![cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_CERTIFICATE_ROLLBACK_READY_CODE,
                format!(
                    "MITM certificate artifact {} and private key artifact {} were removed from NetworkCore snapshot {}; profile trust artifact {}",
                    snapshot_file.cert_file_path,
                    snapshot_file.key_file_path,
                    snapshot.path,
                    snapshot_file
                        .profile_trust_file_path
                        .as_deref()
                        .unwrap_or("not-requested")
                ),
                SOURCE_CLI_MITM,
            )],
        })
    }
}

fn validate_mitm_certificate_artifact_request(
    request: &LinuxMitmCertificateArtifactRequest,
) -> DomainResult<()> {
    if request.artifact_version != 2 {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM certificate artifact request must use artifact version 2",
        ));
    }
    if !request.cert_content.contains("-----BEGIN CERTIFICATE-----")
        || !request.cert_content.contains("-----END CERTIFICATE-----")
    {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM certificate artifact request must contain CA certificate PEM content",
        ));
    }
    if request.cert_content.contains("-----BEGIN PRIVATE KEY-----") {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM certificate artifact request must not contain private key material",
        ));
    }
    if !request.key_content.contains("-----BEGIN PRIVATE KEY-----")
        || !request.key_content.contains("-----END PRIVATE KEY-----")
    {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM certificate artifact request must contain private key PEM content",
        ));
    }
    let Some(profile_trust_file_path) = &request.profile_trust_file_path else {
        return Ok(());
    };
    let Some(profile_trust_content) = &request.profile_trust_content else {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            format!(
                "MITM dedicated profile CA PEM copy request is missing content for {}",
                profile_trust_file_path
            ),
        ));
    };
    let Some(profile_trust_fingerprint) = &request.profile_trust_fingerprint else {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            format!(
                "MITM dedicated profile CA PEM copy request is missing fingerprint for {}",
                profile_trust_file_path
            ),
        ));
    };
    if profile_trust_content.contains("-----BEGIN PRIVATE KEY-----")
        || profile_trust_content == &request.key_content
    {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM dedicated profile CA PEM copy must not contain private key material",
        ));
    }
    if profile_trust_content != &request.cert_content {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM dedicated profile CA PEM copy must match certificate PEM content",
        ));
    }
    if profile_trust_fingerprint != &request.cert_fingerprint {
        return Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ARTIFACT_WRITE_FAILED_CODE,
            "MITM dedicated profile CA PEM copy fingerprint must match certificate fingerprint",
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableMitmCertificateArtifactStore;

impl UnavailableMitmCertificateArtifactStore {
    pub const fn new() -> Self {
        Self
    }
}

impl MitmCertificateArtifactStore for UnavailableMitmCertificateArtifactStore {
    fn apply_certificate_artifact(
        &self,
        _request: &LinuxMitmCertificateArtifactRequest,
    ) -> DomainResult<LinuxMitmCertificateArtifactApplyOutcome> {
        Err(DomainError::new(
            CLI_MITM_CERTIFICATE_APPLY_BLOCKED_CODE,
            "MITM certificate artifact store is not wired",
        ))
    }

    fn rollback_certificate_artifact(
        &self,
        _snapshot: &MitmCertificateRollbackSnapshot,
    ) -> DomainResult<LinuxMitmCertificateArtifactRollbackOutcome> {
        Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ROLLBACK_BLOCKED_CODE,
            "MITM certificate artifact store is not wired",
        ))
    }
}

const BROWSER_CAPTURE_PAC_SNAPSHOT_KIND: &str = "networkcore-linux-browser-capture-pac";
const MITM_CERTIFICATE_ARTIFACT_SNAPSHOT_KIND: &str = "networkcore-linux-mitm-certificate-artifact";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrowserCapturePacSnapshotFile {
    version: u8,
    kind: String,
    pac_file_path: String,
    pac_url: String,
    created_file: bool,
    #[serde(default)]
    policy_file_path: Option<String>,
    #[serde(default)]
    policy_url: Option<String>,
    #[serde(default)]
    created_policy_file: bool,
    #[serde(default)]
    profile_prefs_file_path: Option<String>,
    #[serde(default)]
    created_profile_prefs_file: bool,
    #[serde(default)]
    previous_profile_prefs_content: Option<String>,
    #[serde(default)]
    applied_profile_prefs_content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MitmCertificateArtifactSnapshotFile {
    version: u8,
    kind: String,
    cert_file_path: String,
    key_file_path: String,
    #[serde(default)]
    profile_trust_file_path: Option<String>,
    subject: String,
    created_cert_file: bool,
    created_key_file: bool,
    #[serde(default)]
    created_profile_trust_file: bool,
    applied_cert_fingerprint: String,
    applied_key_fingerprint: String,
    #[serde(default)]
    applied_profile_trust_fingerprint: Option<String>,
}

fn rollback_mitm_certificate_artifact_file(
    path: &str,
    expected_fingerprint: &str,
    description: &str,
) -> DomainResult<()> {
    match std::fs::read_to_string(path) {
        Ok(current_content)
            if stable_content_fingerprint(&current_content) != expected_fingerprint =>
        {
            Err(DomainError::new(
                CLI_MITM_CERTIFICATE_ROLLBACK_FAILED_CODE,
                format!("refusing to rollback {description} {path} because it changed after apply"),
            ))
        }
        Ok(_) => match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(DomainError::new(
                CLI_MITM_CERTIFICATE_ROLLBACK_FAILED_CODE,
                format!("failed to remove {description} {path}: {error}"),
            )),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DomainError::new(
            CLI_MITM_CERTIFICATE_ROLLBACK_FAILED_CODE,
            format!("failed to read {description} {path}: {error}"),
        )),
    }
}

fn write_parent_dir(path: &str, error_code: &'static str) -> DomainResult<()> {
    let parent = std::path::Path::new(path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent).map_err(|error| {
            DomainError::new(
                error_code,
                format!("failed to create parent directory for {path}: {error}"),
            )
        })?;
    }
    Ok(())
}

fn write_new_file(
    path: &str,
    contents: &[u8],
    error_code: &'static str,
    description: &str,
) -> DomainResult<()> {
    write_parent_dir(path, error_code)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            DomainError::new(
                error_code,
                format!("failed to create {description} {path}: {error}"),
            )
        })?;
    file.write_all(contents).map_err(|error| {
        DomainError::new(
            error_code,
            format!("failed to write {description} {path}: {error}"),
        )
    })
}

fn write_replace_file(
    path: &str,
    contents: &[u8],
    error_code: &'static str,
    description: &str,
) -> DomainResult<()> {
    write_parent_dir(path, error_code)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|error| {
            DomainError::new(
                error_code,
                format!("failed to open {description} {path}: {error}"),
            )
        })?;
    file.write_all(contents).map_err(|error| {
        DomainError::new(
            error_code,
            format!("failed to write {description} {path}: {error}"),
        )
    })
}

fn rollback_profile_prefs_file(
    path: &str,
    created_by_networkcore: bool,
    previous_content: Option<&str>,
) -> DomainResult<()> {
    if created_by_networkcore {
        match std::fs::remove_file(path) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_ROLLBACK_FAILED_CODE,
                    format!("failed to remove browser capture profile prefs file {path}: {error}"),
                ));
            }
        }
    }

    let Some(previous_content) = previous_content else {
        return Err(DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_SNAPSHOT_READ_FAILED_CODE,
            "browser capture rollback snapshot is missing previous profile prefs content",
        ));
    };
    write_replace_file(
        path,
        previous_content.as_bytes(),
        CLI_MITM_BROWSER_CAPTURE_ROLLBACK_FAILED_CODE,
        "browser capture Firefox profile prefs file",
    )
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableBrowserCaptureTrafficProofProbe;

impl UnavailableBrowserCaptureTrafficProofProbe {
    pub const fn new() -> Self {
        Self
    }
}

impl BrowserCaptureTrafficProofProbe for UnavailableBrowserCaptureTrafficProofProbe {
    fn verify_traffic_proof(
        &self,
        _request: &LinuxBrowserCaptureTrafficProofRequest,
    ) -> DomainResult<LinuxBrowserCaptureTrafficProofOutcome> {
        Err(DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BLOCKED_CODE,
            "browser capture traffic proof probe is not wired",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BrowserCaptureTargetEndpoint {
    host: String,
    port: u16,
    bracketed: bool,
}

impl BrowserCaptureTargetEndpoint {
    fn authority(&self) -> String {
        if self.bracketed {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn parse_browser_capture_target_endpoint(
    target_url: &str,
) -> DomainResult<BrowserCaptureTargetEndpoint> {
    let Some((scheme, remainder)) = target_url.split_once("://") else {
        return Err(DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
            "browser capture target URL must include http:// or https://",
        ));
    };
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => {
            return Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
                "browser capture target URL scheme must be http or https",
            ));
        }
    };
    let authority = remainder
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    if authority.is_empty() {
        return Err(DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
            "browser capture target URL is missing a host",
        ));
    }

    let (host, port, bracketed) = if let Some(rest) = authority.strip_prefix('[') {
        let Some((host, after_host)) = rest.split_once(']') else {
            return Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
                "browser capture target IPv6 host is missing a closing bracket",
            ));
        };
        let port = if let Some(port) = after_host.strip_prefix(':') {
            parse_browser_capture_target_port(port)?
        } else if after_host.is_empty() {
            default_port
        } else {
            return Err(DomainError::new(
                CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
                "browser capture target IPv6 host has an invalid suffix",
            ));
        };
        (host.to_string(), port, true)
    } else {
        let mut parts = authority.split(':');
        let host = parts.next().unwrap_or_default();
        let port = match (parts.next(), parts.next()) {
            (None, None) => default_port,
            (Some(port), None) => parse_browser_capture_target_port(port)?,
            _ => {
                return Err(DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
                    "browser capture target URL host with multiple colons must use IPv6 brackets",
                ));
            }
        };
        (host.to_string(), port, false)
    };

    if host.is_empty() {
        return Err(DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
            "browser capture target URL is missing a host",
        ));
    }

    Ok(BrowserCaptureTargetEndpoint {
        host,
        port,
        bracketed,
    })
}

fn parse_browser_capture_target_port(port: &str) -> DomainResult<u16> {
    port.parse::<u16>().map_err(|_| {
        DomainError::new(
            CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE,
            "browser capture target URL port must be a valid TCP port",
        )
    })
}

#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableForegroundLifecycleHost;

impl UnavailableForegroundLifecycleHost {
    pub const fn new() -> Self {
        Self
    }
}

impl ForegroundLifecycleHost for UnavailableForegroundLifecycleHost {
    fn run_foreground(&self, _request: &ForegroundLifecycleRequest) -> ForegroundLifecycleOutcome {
        ForegroundLifecycleOutcome::failure(
            LinuxCliExitCode::Unavailable,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_START_LIFECYCLE_HOST_MISSING_CODE,
                "linux foreground lifecycle host is not wired",
                SOURCE_CLI_START,
            ),
        )
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ParkingForegroundLifecycleInterruptionSource;

impl ParkingForegroundLifecycleInterruptionSource {
    pub const fn new() -> Self {
        Self
    }
}

impl ForegroundLifecycleInterruptionSource for ParkingForegroundLifecycleInterruptionSource {
    fn wait_for_interruption(
        &self,
        _request: &ForegroundLifecycleRequest,
    ) -> ForegroundLifecycleInterruption {
        loop {
            thread::park();
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, Default)]
pub struct OsSignalForegroundLifecycleInterruptionSource;

#[cfg(unix)]
impl OsSignalForegroundLifecycleInterruptionSource {
    pub const fn new() -> Self {
        Self
    }

    pub fn interruption_for_signal(signal: i32) -> ForegroundLifecycleInterruption {
        foreground_os_signal_interruption(signal)
    }
}

#[cfg(unix)]
impl ForegroundLifecycleInterruptionSource for OsSignalForegroundLifecycleInterruptionSource {
    fn wait_for_interruption(
        &self,
        _request: &ForegroundLifecycleRequest,
    ) -> ForegroundLifecycleInterruption {
        let mut signals = match Signals::new([SIGINT, SIGTERM]) {
            Ok(signals) => signals,
            Err(error) => {
                return ForegroundLifecycleInterruption::new("os-signal-source-failed")
                    .with_diagnostics(vec![cli_diagnostic(
                        DiagnosticSeverity::Error,
                        CLI_START_SIGNAL_SOURCE_FAILED_CODE,
                        format!("failed to register foreground OS signal source: {error}"),
                        SOURCE_CLI_START,
                    )]);
            }
        };

        if let Some(signal) = signals.forever().next() {
            return Self::interruption_for_signal(signal);
        }

        ForegroundLifecycleInterruption::new("os-signal-source-closed").with_diagnostics(vec![
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_START_SIGNAL_SOURCE_FAILED_CODE,
                "foreground OS signal source closed before receiving an interruption",
                SOURCE_CLI_START,
            ),
        ])
    }
}

#[cfg(unix)]
pub type DefaultForegroundLifecycleInterruptionSource =
    OsSignalForegroundLifecycleInterruptionSource;

#[cfg(not(unix))]
pub type DefaultForegroundLifecycleInterruptionSource =
    ParkingForegroundLifecycleInterruptionSource;

#[derive(Debug, Clone, Copy, Default)]
pub struct CurrentProcessForegroundLifecycleHost<I = DefaultForegroundLifecycleInterruptionSource> {
    interruption_source: I,
}

impl CurrentProcessForegroundLifecycleHost<DefaultForegroundLifecycleInterruptionSource> {
    pub const fn new() -> Self {
        Self {
            interruption_source: DefaultForegroundLifecycleInterruptionSource::new(),
        }
    }
}

impl<I> CurrentProcessForegroundLifecycleHost<I> {
    pub const fn with_interruption_source(interruption_source: I) -> Self {
        Self {
            interruption_source,
        }
    }
}

impl<I> ForegroundLifecycleHost for CurrentProcessForegroundLifecycleHost<I>
where
    I: ForegroundLifecycleInterruptionSource,
{
    fn run_foreground(&self, request: &ForegroundLifecycleRequest) -> ForegroundLifecycleOutcome {
        let interruption = self.interruption_source.wait_for_interruption(request);
        let mut diagnostics = interruption.diagnostics;
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Warning,
            CLI_START_LIFECYCLE_INTERRUPTED_CODE,
            format!(
                "linux foreground runtime was interrupted: {}",
                interruption.reason
            ),
            SOURCE_CLI_START,
        ));

        ForegroundLifecycleOutcome {
            exit_code: LinuxCliExitCode::Interrupted,
            diagnostics,
        }
    }
}

#[cfg(unix)]
fn foreground_os_signal_interruption(signal: i32) -> ForegroundLifecycleInterruption {
    let signal_name = foreground_os_signal_name(signal);

    ForegroundLifecycleInterruption::new(signal_name.clone()).with_diagnostics(vec![
        cli_diagnostic(
            DiagnosticSeverity::Warning,
            CLI_START_SIGNAL_RECEIVED_CODE,
            format!("foreground OS signal {signal_name} interrupted linux runtime"),
            SOURCE_CLI_START,
        ),
    ])
}

#[cfg(unix)]
fn foreground_os_signal_name(signal: i32) -> String {
    match signal {
        SIGINT => "SIGINT".to_string(),
        SIGTERM => "SIGTERM".to_string(),
        _ => format!("signal-{signal}"),
    }
}

#[derive(Debug, Default)]
struct ParsedOptions {
    browser: Option<String>,
    config_path: Option<String>,
    profile_dir: Option<String>,
    profile_prefs_file_path: Option<String>,
    url: Option<String>,
    method: Option<String>,
    phase: Option<String>,
    status_code: Option<u16>,
    headers: Vec<String>,
    body: Option<String>,
    target_url: Option<String>,
    cert_file_path: Option<String>,
    key_file_path: Option<String>,
    profile_trust_file_path: Option<String>,
    pac_file_path: Option<String>,
    policy_file_path: Option<String>,
    proof_token: Option<String>,
    proof_log_path: Option<String>,
    proxy_scheme: Option<String>,
    install_dir: Option<String>,
    listen_host: Option<String>,
    listen_port: Option<u16>,
    snapshot_path: Option<String>,
    confirm: bool,
    force: bool,
    format: OutputFormat,
}

pub fn parse_args<I, S>(args: I) -> Result<LinuxCliCommand, LinuxCliParseError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into);
    let Some(command) = args.next() else {
        return Err(parse_error(
            CLI_COMMAND_MISSING_CODE,
            "missing linux CLI command; run networkcore-linux help",
        ));
    };
    let rest = args.collect::<Vec<_>>();

    match command.as_str() {
        "help" | "--help" | "-h" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Help {
                format: options.format,
            })
        }
        "version" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Version {
                format: options.format,
            })
        }
        "capabilities" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Capabilities {
                format: options.format,
            })
        }
        "prepare-config" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::PrepareConfig {
                config_path: options.config_path,
                format: options.format,
            })
        }
        "start" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Start {
                config_path: options.config_path,
                format: options.format,
            })
        }
        "stop" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Stop {
                format: options.format,
            })
        }
        "status" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Status {
                format: options.format,
            })
        }
        "diagnostics" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::Diagnostics {
                format: options.format,
            })
        }
        "mitm" => parse_mitm_command(&rest),
        "install-sing-box" | "install-singbox" => {
            let options = parse_options(&rest)?;
            Ok(LinuxCliCommand::InstallSingBox {
                install_dir: options.install_dir,
                force: options.force,
                format: options.format,
            })
        }
        "run-url" => parse_run_url_command(&rest),
        "sing-box" => parse_sing_box_command(&rest),
        _ => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown linux CLI command: {command}; run networkcore-linux help"),
        )),
    }
}

pub fn handle_parse_error(diagnostic: Diagnostic) -> LinuxCliResponse {
    let show_help = diagnostic.code == CLI_COMMAND_MISSING_CODE
        || diagnostic.code == CLI_ARGUMENT_UNKNOWN_CODE
        || diagnostic.code == CLI_OUTPUT_FORMAT_UNSUPPORTED_CODE;
    let response =
        LinuxCliResponse::failure("parse", LinuxCliExitCode::ArgumentOrConfig, diagnostic);
    if show_help {
        response.with_help(cli_help_text())
    } else {
        response
    }
}

pub fn handle_entrypoint_skeleton(command: LinuxCliCommand) -> LinuxCliResponse {
    match command {
        LinuxCliCommand::Help { .. } => handle_help(),
        LinuxCliCommand::Version { .. } => handle_version(),
        LinuxCliCommand::Stop { .. } => handle_stop(),
        other => handle_unwired_command(other.name()),
    }
}

pub fn handle_entrypoint<P>(command: LinuxCliCommand, platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    match command {
        LinuxCliCommand::Help { .. } => handle_help(),
        LinuxCliCommand::Version { .. } => handle_version(),
        LinuxCliCommand::Capabilities { .. } => handle_capabilities(platform),
        LinuxCliCommand::Status { .. } => handle_status(platform),
        LinuxCliCommand::Diagnostics { .. } => handle_diagnostics(platform),
        LinuxCliCommand::MitmStatus { .. } => handle_mitm_status(platform),
        LinuxCliCommand::MitmDiagnostics { .. } => handle_mitm_diagnostics(platform),
        LinuxCliCommand::MitmCertificatePlan { .. } => handle_mitm_certificate_plan(platform),
        LinuxCliCommand::MitmCertificateApply {
            cert_file_path,
            key_file_path,
            profile_trust_file_path,
            snapshot_path,
            confirm,
            ..
        } => {
            let store = UnavailableMitmCertificateArtifactStore::new();
            handle_mitm_certificate_apply_with_store(
                platform,
                &store,
                cert_file_path.as_deref(),
                key_file_path.as_deref(),
                profile_trust_file_path.as_deref(),
                snapshot_path.as_deref(),
                confirm,
            )
        }
        LinuxCliCommand::MitmCertificateRollback { snapshot_path, .. } => {
            let store = UnavailableMitmCertificateArtifactStore::new();
            handle_mitm_certificate_rollback_with_store(platform, &store, snapshot_path)
        }
        LinuxCliCommand::MitmBrowserPlan { .. } => handle_mitm_browser_plan(platform),
        LinuxCliCommand::MitmBrowserCapturePlan { proxy_scheme, .. } => {
            handle_mitm_browser_capture_plan_with_proxy_scheme(platform, &proxy_scheme)
        }
        LinuxCliCommand::MitmBrowserCaptureLaunchPlan { proxy_scheme, .. } => {
            handle_mitm_browser_capture_launch_plan_with_proxy_scheme(platform, &proxy_scheme)
        }
        LinuxCliCommand::MitmBrowserCaptureSessionPlan {
            url,
            browser,
            profile_dir,
            target_url,
            proof_token,
            proof_log_path,
            proxy_scheme,
            listen_host,
            listen_port,
            ..
        } => handle_mitm_browser_capture_session_plan_with_proxy_scheme(
            platform,
            &url,
            &browser,
            &profile_dir,
            target_url.as_deref(),
            proof_token.as_deref(),
            proof_log_path.as_deref(),
            &proxy_scheme,
            &listen_host,
            listen_port,
        ),
        LinuxCliCommand::MitmBrowserCaptureLaunch { .. } => {
            handle_mitm_browser_capture_launch_unwired()
        }
        LinuxCliCommand::MitmBrowserCaptureApply {
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_apply_with_proxy_scheme(platform, &proxy_scheme, confirm),
        LinuxCliCommand::MitmBrowserCaptureRollback { snapshot_path, .. } => {
            handle_mitm_browser_capture_rollback(platform, snapshot_path)
        }
        LinuxCliCommand::MitmBrowserCaptureVerify {
            target_url,
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_verify_with_proxy_scheme(
            platform,
            target_url.as_deref(),
            &proxy_scheme,
            confirm,
        ),
        LinuxCliCommand::MitmBrowserCaptureTrafficProof {
            target_url,
            proof_token,
            proof_log_path,
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_traffic_proof_with_proxy_scheme(
            platform,
            target_url.as_deref(),
            proof_token.as_deref(),
            proof_log_path.as_deref(),
            &proxy_scheme,
            confirm,
        ),
        LinuxCliCommand::MitmHttpRewritePlan { .. } => handle_mitm_http_rewrite_plan(platform),
        LinuxCliCommand::MitmHttpRewritePreview {
            url,
            method,
            phase,
            status_code,
            headers,
            body,
            confirm,
            ..
        } => handle_mitm_http_rewrite_preview(
            platform,
            url.as_deref(),
            &method,
            &phase,
            status_code,
            &headers,
            body.as_deref(),
            confirm,
        ),
        LinuxCliCommand::Stop { .. } => handle_stop(),
        other => handle_unwired_command(other.name()),
    }
}

pub fn handle_entrypoint_with_browser_capture_runner<P, B>(
    command: LinuxCliCommand,
    platform: &P,
    browser_runner: &B,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    B: BrowserCaptureProcessRunner,
{
    match command {
        LinuxCliCommand::MitmBrowserCaptureLaunch {
            browser,
            profile_dir,
            target_url,
            proof_token,
            proof_log_path,
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_launch_with_proxy_scheme(
            platform,
            browser_runner,
            &browser,
            &profile_dir,
            target_url.as_deref(),
            proof_token.as_deref(),
            proof_log_path.as_deref(),
            &proxy_scheme,
            confirm,
        ),
        other => handle_entrypoint(other, platform),
    }
}

pub fn handle_entrypoint_with_browser_capture_io<P, B, V>(
    command: LinuxCliCommand,
    platform: &P,
    browser_runner: &B,
    endpoint_probe: &V,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    B: BrowserCaptureProcessRunner,
    V: BrowserCaptureEndpointProbe,
{
    let traffic_proof_probe = UnavailableBrowserCaptureTrafficProofProbe::new();
    let pac_store = UnavailableBrowserCapturePacFileStore::new();
    handle_entrypoint_with_browser_capture_all_io(
        command,
        platform,
        browser_runner,
        endpoint_probe,
        &traffic_proof_probe,
        &pac_store,
    )
}

pub fn handle_entrypoint_with_certificate_lifecycle_io<P, S>(
    command: LinuxCliCommand,
    platform: &P,
    certificate_store: &S,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    S: MitmCertificateArtifactStore,
{
    match command {
        LinuxCliCommand::MitmCertificateApply {
            cert_file_path,
            key_file_path,
            profile_trust_file_path,
            snapshot_path,
            confirm,
            ..
        } => handle_mitm_certificate_apply_with_store(
            platform,
            certificate_store,
            cert_file_path.as_deref(),
            key_file_path.as_deref(),
            profile_trust_file_path.as_deref(),
            snapshot_path.as_deref(),
            confirm,
        ),
        LinuxCliCommand::MitmCertificateRollback { snapshot_path, .. } => {
            handle_mitm_certificate_rollback_with_store(platform, certificate_store, snapshot_path)
        }
        other => handle_entrypoint(other, platform),
    }
}

pub fn handle_entrypoint_with_browser_capture_all_io<P, B, V, T, S>(
    command: LinuxCliCommand,
    platform: &P,
    browser_runner: &B,
    endpoint_probe: &V,
    traffic_proof_probe: &T,
    pac_store: &S,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    B: BrowserCaptureProcessRunner,
    V: BrowserCaptureEndpointProbe,
    T: BrowserCaptureTrafficProofProbe,
    S: BrowserCapturePacFileStore,
{
    match command {
        LinuxCliCommand::MitmBrowserCaptureLaunch {
            browser,
            profile_dir,
            target_url,
            proof_token,
            proof_log_path,
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_launch_with_proxy_scheme(
            platform,
            browser_runner,
            &browser,
            &profile_dir,
            target_url.as_deref(),
            proof_token.as_deref(),
            proof_log_path.as_deref(),
            &proxy_scheme,
            confirm,
        ),
        LinuxCliCommand::MitmBrowserCaptureVerify {
            target_url,
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_verify_with_probe_and_proxy_scheme(
            platform,
            endpoint_probe,
            target_url.as_deref(),
            &proxy_scheme,
            confirm,
        ),
        LinuxCliCommand::MitmBrowserCaptureTrafficProof {
            target_url,
            proof_token,
            proof_log_path,
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_traffic_proof_with_probe_and_proxy_scheme(
            platform,
            traffic_proof_probe,
            target_url.as_deref(),
            proof_token.as_deref(),
            proof_log_path.as_deref(),
            &proxy_scheme,
            confirm,
        ),
        LinuxCliCommand::MitmBrowserCaptureApply {
            pac_file_path,
            policy_file_path,
            profile_prefs_file_path,
            snapshot_path,
            proxy_scheme,
            confirm,
            ..
        } => handle_mitm_browser_capture_apply_with_store_and_profile_prefs_and_proxy_scheme(
            platform,
            pac_store,
            pac_file_path.as_deref(),
            policy_file_path.as_deref(),
            profile_prefs_file_path.as_deref(),
            snapshot_path.as_deref(),
            &proxy_scheme,
            confirm,
        ),
        LinuxCliCommand::MitmBrowserCaptureRollback { snapshot_path, .. } => {
            handle_mitm_browser_capture_rollback_with_store(platform, pac_store, snapshot_path)
        }
        other => handle_entrypoint(other, platform),
    }
}

pub fn handle_entrypoint_with_runtime<C, P, E, R>(
    command: LinuxCliCommand,
    platform: &P,
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
{
    match command {
        LinuxCliCommand::PrepareConfig { config_path, .. } => {
            handle_prepare_config(orchestrator, reader, config_path.as_deref())
        }
        other => handle_entrypoint(other, platform),
    }
}

pub fn handle_entrypoint_with_runtime_and_lifecycle<C, P, E, R, H>(
    command: LinuxCliCommand,
    platform: &P,
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
    lifecycle_host: &H,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
    H: ForegroundLifecycleHost,
{
    match command {
        LinuxCliCommand::PrepareConfig { config_path, .. } => {
            handle_prepare_config(orchestrator, reader, config_path.as_deref())
        }
        LinuxCliCommand::Start { config_path, .. } => {
            handle_start_foreground(orchestrator, reader, config_path.as_deref(), lifecycle_host)
        }
        other => handle_entrypoint(other, platform),
    }
}

pub fn handle_entrypoint_with_runtime_lifecycle_and_sing_box<C, P, E, R, H, I, S>(
    command: LinuxCliCommand,
    platform: &P,
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
    lifecycle_host: &H,
    sing_box_installer: &I,
    sing_box_runner: &S,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
    H: ForegroundLifecycleHost,
    I: SingBoxReleaseInstaller,
    S: SingBoxProcessRunner,
{
    match command {
        LinuxCliCommand::InstallSingBox {
            install_dir, force, ..
        } => handle_install_sing_box(sing_box_installer, install_dir.as_deref(), force),
        LinuxCliCommand::RunUrl {
            url,
            listen_host,
            listen_port,
            install_dir,
            force,
            ..
        } => handle_run_url_with_sing_box(
            sing_box_installer,
            sing_box_runner,
            &url,
            &listen_host,
            listen_port,
            install_dir.as_deref(),
            force,
        ),
        other => handle_entrypoint_with_runtime_and_lifecycle(
            other,
            platform,
            orchestrator,
            reader,
            lifecycle_host,
        ),
    }
}

pub fn handle_help() -> LinuxCliResponse {
    LinuxCliResponse::success("help").with_help(cli_help_text())
}

pub fn handle_version() -> LinuxCliResponse {
    LinuxCliResponse::success("version").with_version(env!("CARGO_PKG_VERSION"))
}

pub fn handle_capabilities<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    match platform.status() {
        Ok(status) => {
            let diagnostics = platform_diagnostics(&status);
            LinuxCliResponse::success("capabilities")
                .with_diagnostics(diagnostics)
                .with_platform(status)
        }
        Err(error) => domain_error_response(
            "capabilities",
            LinuxCliExitCode::GeneralFailure,
            error,
            SOURCE_CLI_RUNTIME,
        ),
    }
}

pub fn handle_prepare_config<C, P, E, R>(
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
    config_path: Option<&str>,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
{
    let raw_config = match read_required_config("prepare-config", reader, config_path) {
        Ok(raw_config) => raw_config,
        Err(response) => return *response,
    };

    match orchestrator.prepare_config(&raw_config) {
        Ok(prepared) => LinuxCliResponse::success("prepare-config")
            .with_diagnostics(prepared.diagnostics)
            .with_platform(prepared.platform)
            .with_config_profiles(prepared.config.profiles),
        Err(error) => domain_error_response(
            "prepare-config",
            LinuxCliExitCode::ConfigValidation,
            error,
            SOURCE_CLI_CONFIG,
        ),
    }
}

pub fn handle_start<C, P, E, R>(
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
    config_path: Option<&str>,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
{
    let raw_config = match read_required_config("start", reader, config_path) {
        Ok(raw_config) => raw_config,
        Err(response) => return *response,
    };

    let request = RuntimeConfigRequest::new(DEFAULT_ENGINE_ID, raw_config);
    match orchestrator.start_runtime(request) {
        Ok(result) => LinuxCliResponse::success("start")
            .with_diagnostics(result.diagnostics)
            .with_platform(result.platform),
        Err(error) => start_error_response(error),
    }
}

pub fn handle_start_foreground<C, P, E, R, H>(
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    reader: &R,
    config_path: Option<&str>,
    lifecycle_host: &H,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    R: ConfigReader,
    H: ForegroundLifecycleHost,
{
    let raw_config = match read_required_config("start", reader, config_path) {
        Ok(raw_config) => raw_config,
        Err(response) => return *response,
    };

    let request = RuntimeConfigRequest::new(DEFAULT_ENGINE_ID, raw_config);
    match orchestrator.start_runtime(request) {
        Ok(result) => {
            handle_foreground_lifecycle_with_runtime_stop(result, orchestrator, lifecycle_host)
        }
        Err(error) => start_error_response(error),
    }
}

pub fn handle_foreground_lifecycle<H>(
    operation: RuntimeOperationResult,
    host: &H,
) -> LinuxCliResponse
where
    H: ForegroundLifecycleHost,
{
    let RuntimeOperationResult {
        platform,
        engine_status,
        mut diagnostics,
        ..
    } = operation;

    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_START_FOREGROUND_ONLY_CODE,
        "linux start is limited to the current foreground process",
        SOURCE_CLI_START,
    ));

    if engine_status.state != ProxyEngineLifecycleState::Running {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_START_LIFECYCLE_FAILED_CODE,
            "linux runtime did not enter running state before foreground hosting",
            SOURCE_CLI_START,
        ));

        return LinuxCliResponse {
            ok: false,
            command: "start".to_string(),
            exit_code: LinuxCliExitCode::GeneralFailure,
            diagnostics,
            platform: Some(platform),
            config_profiles: Vec::new(),
            version: None,
            help: None,
            sing_box_install: None,
            sing_box_run: None,
            mitm_status: None,
            certificate_lifecycle: None,
            browser_capture: None,
            http_rewrite: None,
        };
    }

    let request = ForegroundLifecycleRequest { engine_status };
    let outcome = host.run_foreground(&request);
    let ok = outcome.exit_code == LinuxCliExitCode::Success;
    diagnostics.extend(outcome.diagnostics);

    LinuxCliResponse {
        ok,
        command: "start".to_string(),
        exit_code: outcome.exit_code,
        diagnostics,
        platform: Some(platform),
        config_profiles: Vec::new(),
        version: None,
        help: None,
        sing_box_install: None,
        sing_box_run: None,
        mitm_status: None,
        certificate_lifecycle: None,
        browser_capture: None,
        http_rewrite: None,
    }
}

pub fn handle_foreground_lifecycle_with_runtime_stop<C, P, E, H>(
    operation: RuntimeOperationResult,
    orchestrator: &RuntimeOrchestrator<C, P, E>,
    host: &H,
) -> LinuxCliResponse
where
    C: ConfigurationService,
    P: PlatformCapabilityService,
    E: ProxyEngineService,
    H: ForegroundLifecycleHost,
{
    let engine_id = operation.engine_status.engine_id.clone();
    let mut response = handle_foreground_lifecycle(operation, host);
    if response.exit_code != LinuxCliExitCode::Interrupted {
        return response;
    }

    match orchestrator.stop_runtime(&engine_id) {
        Ok(stop_status) => response.diagnostics.extend(stop_status.diagnostics),
        Err(error) => response.diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_START_RUNTIME_STOP_FAILED_CODE,
            format!(
                "failed to stop linux runtime after foreground interruption: {}",
                error.message
            ),
            SOURCE_CLI_START,
        )),
    }

    response
}

pub fn handle_stop() -> LinuxCliResponse {
    LinuxCliResponse::failure(
        "stop",
        LinuxCliExitCode::Unavailable,
        cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_STOP_UNAVAILABLE_WITHOUT_DAEMON_CODE,
            "linux stop is unavailable without a daemon or control socket",
            SOURCE_CLI_STOP,
        ),
    )
}

pub fn handle_status<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    match platform.status() {
        Ok(status) => {
            let mut diagnostics = platform_diagnostics(&status);
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Warning,
                CLI_STATUS_NO_RUNTIME_CONTEXT_CODE,
                "no runtime context is available for linux status",
                SOURCE_CLI_STATUS,
            ));
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_STATUS_PLATFORM_ONLY_CODE,
                "linux status output is limited to platform capability context",
                SOURCE_CLI_STATUS,
            ));

            LinuxCliResponse::success("status")
                .with_diagnostics(diagnostics)
                .with_platform(status)
        }
        Err(error) => domain_error_response(
            "status",
            LinuxCliExitCode::GeneralFailure,
            error,
            SOURCE_CLI_STATUS,
        ),
    }
}

pub fn handle_diagnostics<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    match platform.status() {
        Ok(status) => LinuxCliResponse::success("diagnostics")
            .with_diagnostics(platform_diagnostics(&status))
            .with_platform(status),
        Err(error) => domain_error_response(
            "diagnostics",
            LinuxCliExitCode::GeneralFailure,
            error,
            SOURCE_CLI_RUNTIME,
        ),
    }
}

pub fn handle_mitm_status<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_status_inner("mitm status", platform)
}

pub fn handle_mitm_diagnostics<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_status_inner("mitm diagnostics", platform)
}

pub fn handle_mitm_certificate_plan<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_status_inner("mitm certificate-plan", platform)
}

pub fn handle_mitm_certificate_apply<P>(platform: &P, confirm: bool) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    let store = UnavailableMitmCertificateArtifactStore::new();
    handle_mitm_certificate_apply_with_store(platform, &store, None, None, None, None, confirm)
}

pub fn handle_mitm_certificate_apply_with_store<P, S>(
    platform: &P,
    certificate_store: &S,
    cert_file_path: Option<&str>,
    key_file_path: Option<&str>,
    profile_trust_file_path: Option<&str>,
    snapshot_path: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    S: MitmCertificateArtifactStore,
{
    let command = "mitm certificate apply";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let authorization = MitmCertificateAuthorization {
        confirmed: confirm,
        source: if confirm {
            "cli --confirm".to_string()
        } else {
            "missing --confirm".to_string()
        },
        scope:
            "linux MITM certificate, private key, and optional dedicated profile trust artifacts"
                .to_string(),
        gate: MITM_CERTIFICATE_LIFECYCLE_GATE.to_string(),
    };
    let mut report = build_linux_mitm_certificate_lifecycle_report(
        LinuxMitmCertificateLifecycleAction::Apply,
        &platform_status,
        Some(authorization.clone()),
        None,
    );

    if !confirm {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_CERTIFICATE_AUTHORIZATION_REQUIRED_CODE,
            "MITM certificate artifact apply requires --confirm; no certificate or private key artifact was written",
            SOURCE_CLI_MITM,
        ));
        report.apply_report = Some(LinuxMitmCertificateApplyReport {
            status: "authorization_required".to_string(),
            applied: false,
            authorization,
            cert_file_path: cert_file_path.map(ToString::to_string),
            key_file_path: key_file_path.map(ToString::to_string),
            profile_trust_file_path: profile_trust_file_path.map(ToString::to_string),
            rollback_snapshot: snapshot_path.map(|path| MitmCertificateRollbackSnapshot {
                path: path.to_string(),
                status: "operator-provided".to_string(),
            }),
            blocked_operations: report.trust_plan.blocked_operations.clone(),
        });
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::Unavailable,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_certificate_lifecycle(report)
                .with_diagnostics(diagnostics)
        };
    }

    let (Some(cert_file_path), Some(key_file_path), Some(snapshot_path)) =
        (cert_file_path, key_file_path, snapshot_path)
    else {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_CERTIFICATE_APPLY_CONFIG_MISSING_CODE,
            "MITM certificate artifact apply requires --cert-file <path>, --key-file <path>, and --snapshot <path>",
            SOURCE_CLI_MITM,
        ));
        report.apply_report = Some(LinuxMitmCertificateApplyReport {
            status: "config_missing".to_string(),
            applied: false,
            authorization,
            cert_file_path: cert_file_path.map(ToString::to_string),
            key_file_path: key_file_path.map(ToString::to_string),
            profile_trust_file_path: profile_trust_file_path.map(ToString::to_string),
            rollback_snapshot: snapshot_path.map(|path| MitmCertificateRollbackSnapshot {
                path: path.to_string(),
                status: "operator-provided".to_string(),
            }),
            blocked_operations: report.trust_plan.blocked_operations.clone(),
        });
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::ArgumentOrConfig,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_certificate_lifecycle(report)
                .with_diagnostics(diagnostics)
        };
    };

    let artifact_request = match build_linux_mitm_certificate_artifact_request(
        cert_file_path,
        key_file_path,
        profile_trust_file_path,
        snapshot_path,
    ) {
        Ok(artifact_request) => artifact_request,
        Err(error) => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                error.code,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.apply_report = Some(LinuxMitmCertificateApplyReport {
                status: "failed".to_string(),
                applied: false,
                authorization,
                cert_file_path: Some(cert_file_path.to_string()),
                key_file_path: Some(key_file_path.to_string()),
                profile_trust_file_path: profile_trust_file_path.map(ToString::to_string),
                rollback_snapshot: Some(MitmCertificateRollbackSnapshot {
                    path: snapshot_path.to_string(),
                    status: "operator-provided".to_string(),
                }),
                blocked_operations: report.trust_plan.blocked_operations.clone(),
            });
            return LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::Unavailable,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_certificate_lifecycle(report)
                    .with_diagnostics(diagnostics)
            };
        }
    };
    report.request.artifact = Some(artifact_request.clone());

    match certificate_store.apply_certificate_artifact(&artifact_request) {
        Ok(outcome) => {
            diagnostics.extend(outcome.diagnostics);
            report.apply_report = Some(LinuxMitmCertificateApplyReport {
                status: "applied".to_string(),
                applied: true,
                authorization,
                cert_file_path: Some(artifact_request.cert_file_path.clone()),
                key_file_path: Some(artifact_request.key_file_path.clone()),
                profile_trust_file_path: artifact_request.profile_trust_file_path.clone(),
                rollback_snapshot: Some(outcome.rollback_snapshot),
                blocked_operations: report.trust_plan.blocked_operations.clone(),
            });
            LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_certificate_lifecycle(report)
                .with_diagnostics(diagnostics)
        }
        Err(error) => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                error.code,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.apply_report = Some(LinuxMitmCertificateApplyReport {
                status: "failed".to_string(),
                applied: false,
                authorization,
                cert_file_path: Some(artifact_request.cert_file_path.clone()),
                key_file_path: Some(artifact_request.key_file_path.clone()),
                profile_trust_file_path: artifact_request.profile_trust_file_path.clone(),
                rollback_snapshot: Some(MitmCertificateRollbackSnapshot {
                    path: artifact_request.snapshot_path,
                    status: "operator-provided".to_string(),
                }),
                blocked_operations: report.trust_plan.blocked_operations.clone(),
            });
            LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::Unavailable,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_certificate_lifecycle(report)
                    .with_diagnostics(diagnostics)
            }
        }
    }
}

pub fn handle_mitm_certificate_rollback<P>(
    platform: &P,
    snapshot_path: Option<String>,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    let store = UnavailableMitmCertificateArtifactStore::new();
    handle_mitm_certificate_rollback_with_store(platform, &store, snapshot_path)
}

pub fn handle_mitm_certificate_rollback_with_store<P, S>(
    platform: &P,
    certificate_store: &S,
    snapshot_path: Option<String>,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    S: MitmCertificateArtifactStore,
{
    let command = "mitm certificate rollback";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let Some(snapshot_path) = snapshot_path else {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_CERTIFICATE_ROLLBACK_BLOCKED_CODE,
            "MITM certificate artifact rollback requires --snapshot <path>",
            SOURCE_CLI_MITM,
        ));
        let report = build_linux_mitm_certificate_lifecycle_report(
            LinuxMitmCertificateLifecycleAction::Rollback,
            &platform_status,
            None,
            None,
        );
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::ArgumentOrConfig,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_certificate_lifecycle(report)
                .with_diagnostics(diagnostics)
        };
    };

    let rollback_snapshot = MitmCertificateRollbackSnapshot {
        path: snapshot_path,
        status: "operator-provided".to_string(),
    };
    let mut report = build_linux_mitm_certificate_lifecycle_report(
        LinuxMitmCertificateLifecycleAction::Rollback,
        &platform_status,
        None,
        Some(rollback_snapshot.clone()),
    );

    match certificate_store.rollback_certificate_artifact(&rollback_snapshot) {
        Ok(outcome) => {
            diagnostics.extend(outcome.diagnostics);
            report.rollback_report = Some(LinuxMitmCertificateRollbackReport {
                status: "rolled_back".to_string(),
                rolled_back: true,
                cert_file_path: Some(outcome.cert_file_path),
                key_file_path: Some(outcome.key_file_path),
                profile_trust_file_path: outcome.profile_trust_file_path,
                rollback_snapshot: Some(MitmCertificateRollbackSnapshot {
                    status: "networkcore-restored".to_string(),
                    ..rollback_snapshot
                }),
                blocked_operations: report.trust_plan.blocked_operations.clone(),
            });
            LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_certificate_lifecycle(report)
                .with_diagnostics(diagnostics)
        }
        Err(error) => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                error.code,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.rollback_report = Some(LinuxMitmCertificateRollbackReport {
                status: "failed".to_string(),
                rolled_back: false,
                cert_file_path: None,
                key_file_path: None,
                profile_trust_file_path: None,
                rollback_snapshot: Some(rollback_snapshot),
                blocked_operations: report.trust_plan.blocked_operations.clone(),
            });
            LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::Unavailable,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_certificate_lifecycle(report)
                    .with_diagnostics(diagnostics)
            }
        }
    }
}

pub fn handle_mitm_browser_plan<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_status_inner("mitm browser-plan", platform)
}

pub fn handle_mitm_browser_capture_plan<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_plan_with_proxy_scheme(
        platform,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
    )
}

pub fn handle_mitm_browser_capture_plan_with_proxy_scheme<P>(
    platform: &P,
    proxy_scheme: &str,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_inner(
        "mitm browser-capture plan",
        platform,
        LinuxBrowserCaptureAction::Plan,
        false,
        None,
        None,
        None,
        None,
        Some(proxy_scheme),
    )
}

pub fn handle_mitm_browser_capture_launch_plan<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_launch_plan_with_proxy_scheme(
        platform,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
    )
}

pub fn handle_mitm_browser_capture_launch_plan_with_proxy_scheme<P>(
    platform: &P,
    proxy_scheme: &str,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_inner(
        "mitm browser-capture launch-plan",
        platform,
        LinuxBrowserCaptureAction::LaunchPlan,
        false,
        None,
        None,
        None,
        None,
        Some(proxy_scheme),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn handle_mitm_browser_capture_session_plan<P>(
    platform: &P,
    url: &str,
    browser: &str,
    profile_dir: &str,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    listen_host: &str,
    listen_port: u16,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_session_plan_with_proxy_scheme(
        platform,
        url,
        browser,
        profile_dir,
        target_url,
        proof_token,
        proof_log_path,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        listen_host,
        listen_port,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn handle_mitm_browser_capture_session_plan_with_proxy_scheme<P>(
    platform: &P,
    url: &str,
    browser: &str,
    profile_dir: &str,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    proxy_scheme: &str,
    listen_host: &str,
    listen_port: u16,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    let command = "mitm browser-capture session-plan";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let subscription = CoreSubscriptionService::new();
    let raw_subscription = RawSubscription {
        source_id: "cli-browser-capture-session-plan".to_string(),
        content: url.to_string(),
    };
    let document = match subscription.parse(&raw_subscription) {
        Ok(document) => document,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::ArgumentOrConfig,
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_URL_PARSE_FAILED_CODE,
                    error.message,
                ),
                SOURCE_CLI_MITM,
            );
        }
    };
    let catalog = match subscription.normalize(&document) {
        Ok(catalog) => catalog,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::ArgumentOrConfig,
                DomainError::new(
                    CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_URL_PARSE_FAILED_CODE,
                    error.message,
                ),
                SOURCE_CLI_MITM,
            );
        }
    };
    let generated_config =
        match render_sing_box_local_proxy_config(&SingBoxLocalProxyConfigRequest {
            nodes: catalog.nodes,
            selected_node_id: None,
            listen_host: listen_host.to_string(),
            listen_port,
        }) {
            Ok(config) => config,
            Err(error) => {
                return domain_error_response(
                    command,
                    LinuxCliExitCode::ArgumentOrConfig,
                    DomainError::new(
                        CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_CONFIG_FAILED_CODE,
                        error.message,
                    ),
                    SOURCE_CLI_MITM,
                );
            }
        };

    diagnostics.extend(document.diagnostics.clone());
    diagnostics.extend(generated_config.diagnostics.clone());
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_READY_CODE,
        "browser capture session plan is ready; no proxy process, browser process, or system state was changed",
        SOURCE_CLI_MITM,
    ));

    let plan = build_linux_browser_capture_plan_with_proxy_scheme(
        &platform_status,
        &mitm_status.policy,
        &generated_config.listen_host,
        generated_config.listen_port,
        proxy_scheme,
    );
    let launch_request = build_linux_browser_capture_launch_request(
        browser,
        profile_dir,
        target_url,
        proof_token,
        proof_log_path,
        &plan,
    );
    let verify_request = build_linux_browser_capture_verify_request(&plan, target_url);
    let traffic_proof_request = build_linux_browser_capture_traffic_proof_request(
        &plan,
        target_url,
        Some(&launch_request.proof_token),
        Some(&launch_request.proof_log_path),
    );
    let session_request = LinuxBrowserCaptureSessionPlanRequest {
        url_source: "cli-argument-redacted".to_string(),
        browser: browser.to_string(),
        profile_dir: profile_dir.to_string(),
        target_url: target_url.map(ToString::to_string),
        proof_target_url: launch_request.proof_target_url.clone(),
        proof_token: launch_request.proof_token.clone(),
        proof_log_path: launch_request.proof_log_path.clone(),
        proxy_scheme: plan.planned_proxy_scheme.clone(),
        listen_host: generated_config.listen_host.clone(),
        listen_port: generated_config.listen_port,
    };
    let session_plan = build_linux_browser_capture_session_plan_report(
        session_request.clone(),
        generated_config.selected_node_id,
        generated_config.selected_node_name,
        launch_request.command.clone(),
        verify_request.proxy_url.clone(),
        traffic_proof_request.clone(),
        &mitm_status.policy,
        plan.blocked_operations.clone(),
    );
    let request = LinuxBrowserCaptureRequest {
        action: LinuxBrowserCaptureAction::SessionPlan,
        session: Some(session_request),
        launch: Some(launch_request),
        pac: None,
        verify: Some(verify_request),
        traffic_proof: Some(traffic_proof_request),
        authorization: None,
        rollback_snapshot: None,
    };
    let mut report = build_linux_browser_capture_report(
        LinuxBrowserCaptureAction::SessionPlan,
        &platform_status,
        &mitm_status.policy,
        None,
        None,
        None,
        None,
        None,
    );
    report.request = request;
    report.plan = plan;
    report.session_plan = Some(session_plan);

    LinuxCliResponse::success(command)
        .with_platform(platform_status)
        .with_mitm_status(mitm_status)
        .with_browser_capture(report)
        .with_diagnostics(diagnostics)
}

#[allow(clippy::too_many_arguments)]
pub fn handle_mitm_browser_capture_launch<P, B>(
    platform: &P,
    browser_runner: &B,
    browser: &str,
    profile_dir: &str,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    B: BrowserCaptureProcessRunner,
{
    handle_mitm_browser_capture_launch_with_proxy_scheme(
        platform,
        browser_runner,
        browser,
        profile_dir,
        target_url,
        proof_token,
        proof_log_path,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        confirm,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn handle_mitm_browser_capture_launch_with_proxy_scheme<P, B>(
    platform: &P,
    browser_runner: &B,
    browser: &str,
    profile_dir: &str,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    B: BrowserCaptureProcessRunner,
{
    let command = "mitm browser-capture launch";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let authorization = BrowserCaptureAuthorization {
        confirmed: confirm,
        source: if confirm {
            "cli --confirm".to_string()
        } else {
            "missing --confirm".to_string()
        },
        scope: "linux dedicated browser profile launch".to_string(),
        gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
    };
    let mut report = build_linux_browser_capture_report_with_proxy_scheme(
        LinuxBrowserCaptureAction::Launch,
        &platform_status,
        &mitm_status.policy,
        Some(authorization),
        None,
        None,
        None,
        None,
        proxy_scheme,
    );
    let launch_request = build_linux_browser_capture_launch_request(
        browser,
        profile_dir,
        target_url,
        proof_token,
        proof_log_path,
        &report.plan,
    );
    let traffic_proof_request = build_linux_browser_capture_traffic_proof_request(
        &report.plan,
        target_url,
        Some(&launch_request.proof_token),
        Some(&launch_request.proof_log_path),
    );
    report.request.launch = Some(launch_request.clone());
    report.request.traffic_proof = Some(traffic_proof_request);

    if !confirm {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_BROWSER_CAPTURE_LAUNCH_AUTHORIZATION_REQUIRED_CODE,
            "browser capture launch requires --confirm before starting a dedicated browser profile",
            SOURCE_CLI_MITM,
        ));
        report.launch_report = Some(build_linux_browser_capture_launch_report(
            "authorization_required",
            false,
            None,
            launch_request,
            &mitm_status.policy,
        ));
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::Unavailable,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        };
    }

    match browser_runner.launch(&launch_request) {
        Ok(outcome) => {
            let LinuxBrowserCaptureLaunchOutcome {
                pid,
                diagnostics: runner_diagnostics,
            } = outcome;
            diagnostics.extend(runner_diagnostics);
            report.launch_report = Some(build_linux_browser_capture_launch_report(
                "started",
                true,
                Some(pid),
                launch_request,
                &mitm_status.policy,
            ));
            LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        }
        Err(error) => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MITM_BROWSER_CAPTURE_LAUNCH_FAILED_CODE,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.launch_report = Some(build_linux_browser_capture_launch_report(
                "failed",
                false,
                None,
                launch_request,
                &mitm_status.policy,
            ));
            LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::GeneralFailure,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_browser_capture(report)
                    .with_diagnostics(diagnostics)
            }
        }
    }
}

fn handle_mitm_browser_capture_launch_unwired() -> LinuxCliResponse {
    LinuxCliResponse::failure(
        "mitm browser-capture launch",
        LinuxCliExitCode::Unavailable,
        cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_BROWSER_CAPTURE_LAUNCH_FAILED_CODE,
            "browser capture process runner is not wired",
            SOURCE_CLI_MITM,
        ),
    )
}

pub fn handle_mitm_browser_capture_apply<P>(platform: &P, confirm: bool) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_apply_with_proxy_scheme(
        platform,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        confirm,
    )
}

pub fn handle_mitm_browser_capture_apply_with_proxy_scheme<P>(
    platform: &P,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_inner(
        "mitm browser-capture apply",
        platform,
        LinuxBrowserCaptureAction::Apply,
        confirm,
        None,
        None,
        None,
        None,
        Some(proxy_scheme),
    )
}

pub fn handle_mitm_browser_capture_apply_with_store<P, S>(
    platform: &P,
    pac_store: &S,
    pac_file_path: Option<&str>,
    policy_file_path: Option<&str>,
    snapshot_path: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    S: BrowserCapturePacFileStore,
{
    handle_mitm_browser_capture_apply_with_store_and_profile_prefs_and_proxy_scheme(
        platform,
        pac_store,
        pac_file_path,
        policy_file_path,
        None,
        snapshot_path,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        confirm,
    )
}

pub fn handle_mitm_browser_capture_apply_with_store_and_proxy_scheme<P, S>(
    platform: &P,
    pac_store: &S,
    pac_file_path: Option<&str>,
    policy_file_path: Option<&str>,
    snapshot_path: Option<&str>,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    S: BrowserCapturePacFileStore,
{
    handle_mitm_browser_capture_apply_with_store_and_profile_prefs_and_proxy_scheme(
        platform,
        pac_store,
        pac_file_path,
        policy_file_path,
        None,
        snapshot_path,
        proxy_scheme,
        confirm,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn handle_mitm_browser_capture_apply_with_store_and_profile_prefs_and_proxy_scheme<P, S>(
    platform: &P,
    pac_store: &S,
    pac_file_path: Option<&str>,
    policy_file_path: Option<&str>,
    profile_prefs_file_path: Option<&str>,
    snapshot_path: Option<&str>,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    S: BrowserCapturePacFileStore,
{
    let command = "mitm browser-capture apply";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let authorization = BrowserCaptureAuthorization {
        confirmed: confirm,
        source: if confirm {
            "cli --confirm".to_string()
        } else {
            "missing --confirm".to_string()
        },
        scope: "linux browser capture PAC/browser policy artifacts".to_string(),
        gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
    };
    let mut report = build_linux_browser_capture_report_with_proxy_scheme(
        LinuxBrowserCaptureAction::Apply,
        &platform_status,
        &mitm_status.policy,
        Some(authorization.clone()),
        None,
        None,
        None,
        None,
        proxy_scheme,
    );

    if !confirm {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_BROWSER_CAPTURE_AUTHORIZATION_REQUIRED_CODE,
            "browser capture apply requires --confirm; no browser capture PAC or policy artifact was written",
            SOURCE_CLI_MITM,
        ));
        report.apply_report = Some(LinuxBrowserCaptureApplyReport {
            status: "authorization_required".to_string(),
            applied: false,
            authorization,
            pac_file_path: pac_file_path.map(ToString::to_string),
            pac_url: pac_file_path.map(browser_capture_pac_file_url),
            policy_file_path: policy_file_path.map(ToString::to_string),
            policy_url: policy_file_path.map(browser_capture_pac_file_url),
            profile_prefs_file_path: profile_prefs_file_path.map(ToString::to_string),
            rollback_snapshot: snapshot_path.map(|path| BrowserCaptureRollbackSnapshot {
                path: path.to_string(),
                status: "operator-provided".to_string(),
            }),
            blocked_operations: report.plan.blocked_operations.clone(),
        });
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::Unavailable,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        };
    }

    let (Some(pac_file_path), Some(snapshot_path)) = (pac_file_path, snapshot_path) else {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_BROWSER_CAPTURE_APPLY_CONFIG_MISSING_CODE,
            "browser capture apply requires --pac-file <path> and --snapshot <path>",
            SOURCE_CLI_MITM,
        ));
        report.apply_report = Some(LinuxBrowserCaptureApplyReport {
            status: "config_missing".to_string(),
            applied: false,
            authorization,
            pac_file_path: pac_file_path.map(ToString::to_string),
            pac_url: pac_file_path.map(browser_capture_pac_file_url),
            policy_file_path: policy_file_path.map(ToString::to_string),
            policy_url: policy_file_path.map(browser_capture_pac_file_url),
            profile_prefs_file_path: profile_prefs_file_path.map(ToString::to_string),
            rollback_snapshot: snapshot_path.map(|path| BrowserCaptureRollbackSnapshot {
                path: path.to_string(),
                status: "operator-provided".to_string(),
            }),
            blocked_operations: report.plan.blocked_operations.clone(),
        });
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::ArgumentOrConfig,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        };
    };

    let pac_request = build_linux_browser_capture_pac_request(
        &report.plan,
        pac_file_path,
        policy_file_path,
        profile_prefs_file_path,
        snapshot_path,
    );
    report.request.pac = Some(pac_request.clone());

    match pac_store.apply_pac_file(&pac_request) {
        Ok(outcome) => {
            diagnostics.extend(outcome.diagnostics);
            report.apply_report = Some(LinuxBrowserCaptureApplyReport {
                status: "applied".to_string(),
                applied: true,
                authorization,
                pac_file_path: Some(pac_request.pac_file_path.clone()),
                pac_url: Some(pac_request.pac_url.clone()),
                policy_file_path: pac_request.policy_file_path.clone(),
                policy_url: pac_request.policy_url.clone(),
                profile_prefs_file_path: pac_request.profile_prefs_file_path.clone(),
                rollback_snapshot: Some(outcome.rollback_snapshot),
                blocked_operations: report.plan.blocked_operations.clone(),
            });
            LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        }
        Err(error) => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                error.code,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.apply_report = Some(LinuxBrowserCaptureApplyReport {
                status: "failed".to_string(),
                applied: false,
                authorization,
                pac_file_path: Some(pac_request.pac_file_path.clone()),
                pac_url: Some(pac_request.pac_url.clone()),
                policy_file_path: pac_request.policy_file_path.clone(),
                policy_url: pac_request.policy_url.clone(),
                profile_prefs_file_path: pac_request.profile_prefs_file_path.clone(),
                rollback_snapshot: Some(BrowserCaptureRollbackSnapshot {
                    path: pac_request.snapshot_path,
                    status: "operator-provided".to_string(),
                }),
                blocked_operations: report.plan.blocked_operations.clone(),
            });
            LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::Unavailable,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_browser_capture(report)
                    .with_diagnostics(diagnostics)
            }
        }
    }
}

pub fn handle_mitm_browser_capture_rollback<P>(
    platform: &P,
    snapshot_path: Option<String>,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_inner(
        "mitm browser-capture rollback",
        platform,
        LinuxBrowserCaptureAction::Rollback,
        false,
        snapshot_path,
        None,
        None,
        None,
        None,
    )
}

pub fn handle_mitm_browser_capture_rollback_with_store<P, S>(
    platform: &P,
    pac_store: &S,
    snapshot_path: Option<String>,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    S: BrowserCapturePacFileStore,
{
    let command = "mitm browser-capture rollback";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let Some(snapshot_path) = snapshot_path else {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_BROWSER_CAPTURE_ROLLBACK_BLOCKED_CODE,
            "browser capture rollback requires --snapshot <path>",
            SOURCE_CLI_MITM,
        ));
        let report = build_linux_browser_capture_report(
            LinuxBrowserCaptureAction::Rollback,
            &platform_status,
            &mitm_status.policy,
            None,
            None,
            None,
            None,
            None,
        );
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::ArgumentOrConfig,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        };
    };

    let rollback_snapshot = BrowserCaptureRollbackSnapshot {
        path: snapshot_path,
        status: "operator-provided".to_string(),
    };
    let mut report = build_linux_browser_capture_report(
        LinuxBrowserCaptureAction::Rollback,
        &platform_status,
        &mitm_status.policy,
        None,
        Some(rollback_snapshot.clone()),
        None,
        None,
        None,
    );

    match pac_store.rollback_pac_file(&rollback_snapshot) {
        Ok(outcome) => {
            diagnostics.extend(outcome.diagnostics);
            report.rollback_report = Some(LinuxBrowserCaptureRollbackReport {
                status: "rolled_back".to_string(),
                rolled_back: true,
                pac_file_path: Some(outcome.pac_file_path),
                policy_file_path: outcome.policy_file_path,
                profile_prefs_file_path: outcome.profile_prefs_file_path,
                rollback_snapshot: Some(BrowserCaptureRollbackSnapshot {
                    status: "networkcore-restored".to_string(),
                    ..rollback_snapshot
                }),
                blocked_operations: report.plan.blocked_operations.clone(),
            });
            LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        }
        Err(error) => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                error.code,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.rollback_report = Some(LinuxBrowserCaptureRollbackReport {
                status: "failed".to_string(),
                rolled_back: false,
                pac_file_path: None,
                policy_file_path: None,
                profile_prefs_file_path: None,
                rollback_snapshot: Some(rollback_snapshot),
                blocked_operations: report.plan.blocked_operations.clone(),
            });
            LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::Unavailable,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_browser_capture(report)
                    .with_diagnostics(diagnostics)
            }
        }
    }
}

pub fn handle_mitm_browser_capture_verify<P>(
    platform: &P,
    target_url: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_verify_with_proxy_scheme(
        platform,
        target_url,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        confirm,
    )
}

pub fn handle_mitm_browser_capture_verify_with_proxy_scheme<P>(
    platform: &P,
    target_url: Option<&str>,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_inner(
        "mitm browser-capture verify",
        platform,
        LinuxBrowserCaptureAction::Verify,
        confirm,
        None,
        target_url,
        None,
        None,
        Some(proxy_scheme),
    )
}

pub fn handle_mitm_browser_capture_verify_with_probe<P, V>(
    platform: &P,
    endpoint_probe: &V,
    target_url: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    V: BrowserCaptureEndpointProbe,
{
    handle_mitm_browser_capture_verify_with_probe_and_proxy_scheme(
        platform,
        endpoint_probe,
        target_url,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        confirm,
    )
}

pub fn handle_mitm_browser_capture_verify_with_probe_and_proxy_scheme<P, V>(
    platform: &P,
    endpoint_probe: &V,
    target_url: Option<&str>,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    V: BrowserCaptureEndpointProbe,
{
    let command = "mitm browser-capture verify";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let authorization = BrowserCaptureAuthorization {
        confirmed: confirm,
        source: if confirm {
            "cli --confirm".to_string()
        } else {
            "missing --confirm".to_string()
        },
        scope: "linux browser capture local proxy endpoint verify".to_string(),
        gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
    };
    let mut report = build_linux_browser_capture_report_with_proxy_scheme(
        LinuxBrowserCaptureAction::Verify,
        &platform_status,
        &mitm_status.policy,
        Some(authorization),
        None,
        target_url,
        None,
        None,
        proxy_scheme,
    );
    let verify_request = report
        .request
        .verify
        .clone()
        .expect("verify action should build a verify request");

    if !confirm {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_BROWSER_CAPTURE_VERIFY_AUTHORIZATION_REQUIRED_CODE,
            "browser capture verify requires --confirm before probing the planned local proxy endpoint",
            SOURCE_CLI_MITM,
        ));
        report.verify_report = Some(build_linux_browser_capture_verify_report(
            "authorization_required",
            false,
            verify_request,
            &mitm_status.policy,
            report.plan.blocked_operations.clone(),
        ));
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::Unavailable,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        };
    }

    match endpoint_probe.verify_proxy_endpoint(&verify_request) {
        Ok(outcome) => {
            diagnostics.extend(outcome.diagnostics);
            let status = if verify_request.target_url.is_some() {
                "target_reachable"
            } else {
                "proxy_reachable"
            };
            report.verify_report = Some(build_linux_browser_capture_verify_report(
                status,
                true,
                verify_request,
                &mitm_status.policy,
                report.plan.blocked_operations.clone(),
            ));
            LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        }
        Err(error) => {
            let status = if error.code == CLI_MITM_BROWSER_CAPTURE_VERIFY_TARGET_INVALID_CODE {
                "target_invalid"
            } else {
                "proxy_unreachable"
            };
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                error.code,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.verify_report = Some(build_linux_browser_capture_verify_report(
                status,
                false,
                verify_request,
                &mitm_status.policy,
                report.plan.blocked_operations.clone(),
            ));
            LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::Unavailable,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_browser_capture(report)
                    .with_diagnostics(diagnostics)
            }
        }
    }
}

pub fn handle_mitm_browser_capture_traffic_proof<P>(
    platform: &P,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_traffic_proof_with_proxy_scheme(
        platform,
        target_url,
        proof_token,
        proof_log_path,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        confirm,
    )
}

pub fn handle_mitm_browser_capture_traffic_proof_with_proxy_scheme<P>(
    platform: &P,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    handle_mitm_browser_capture_inner(
        "mitm browser-capture traffic-proof",
        platform,
        LinuxBrowserCaptureAction::TrafficProof,
        confirm,
        None,
        target_url,
        proof_token,
        proof_log_path,
        Some(proxy_scheme),
    )
}

pub fn handle_mitm_browser_capture_traffic_proof_with_probe<P, T>(
    platform: &P,
    traffic_proof_probe: &T,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    T: BrowserCaptureTrafficProofProbe,
{
    handle_mitm_browser_capture_traffic_proof_with_probe_and_proxy_scheme(
        platform,
        traffic_proof_probe,
        target_url,
        proof_token,
        proof_log_path,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
        confirm,
    )
}

pub fn handle_mitm_browser_capture_traffic_proof_with_probe_and_proxy_scheme<P, T>(
    platform: &P,
    traffic_proof_probe: &T,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    proxy_scheme: &str,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
    T: BrowserCaptureTrafficProofProbe,
{
    let command = "mitm browser-capture traffic-proof";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let authorization = BrowserCaptureAuthorization {
        confirmed: confirm,
        source: if confirm {
            "cli --confirm".to_string()
        } else {
            "missing --confirm".to_string()
        },
        scope: "linux browser capture traffic proof".to_string(),
        gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
    };
    let mut report = build_linux_browser_capture_report_with_proxy_scheme(
        LinuxBrowserCaptureAction::TrafficProof,
        &platform_status,
        &mitm_status.policy,
        Some(authorization),
        None,
        target_url,
        proof_token,
        proof_log_path,
        proxy_scheme,
    );
    let proof_request = report
        .request
        .traffic_proof
        .clone()
        .expect("traffic-proof action should build a traffic proof request");

    if !confirm {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_AUTHORIZATION_REQUIRED_CODE,
            "browser capture traffic proof requires --confirm before reading proof evidence",
            SOURCE_CLI_MITM,
        ));
        report.traffic_proof_report = Some(build_linux_browser_capture_traffic_proof_report(
            "authorization_required",
            false,
            proof_request,
            &mitm_status.policy,
            report.plan.blocked_operations.clone(),
        ));
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::Unavailable,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        };
    }

    match traffic_proof_probe.verify_traffic_proof(&proof_request) {
        Ok(outcome) => {
            diagnostics.extend(outcome.diagnostics);
            report.traffic_proof_report = Some(build_linux_browser_capture_traffic_proof_report(
                "observed",
                true,
                proof_request,
                &mitm_status.policy,
                report.plan.blocked_operations.clone(),
            ));
            LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_browser_capture(report)
                .with_diagnostics(diagnostics)
        }
        Err(error) => {
            let status = if error.code == CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_MISSING_CODE {
                "missing"
            } else if error.code == CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_LOG_UNREADABLE_CODE {
                "log_unreadable"
            } else if error.code == CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BINDING_MISMATCH_CODE {
                "binding_mismatch"
            } else {
                "blocked"
            };
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                error.code,
                error.message,
                SOURCE_CLI_MITM,
            ));
            report.traffic_proof_report = Some(build_linux_browser_capture_traffic_proof_report(
                status,
                false,
                proof_request,
                &mitm_status.policy,
                report.plan.blocked_operations.clone(),
            ));
            LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::Unavailable,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_browser_capture(report)
                    .with_diagnostics(diagnostics)
            }
        }
    }
}

pub fn handle_mitm_http_rewrite_plan<P>(platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    let command = "mitm http-rewrite plan";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_MITM_HTTP_REWRITE_PLAN_READY_CODE,
        "plain HTTP rewrite data-plane is active for explicit HTTP proxy requests and explicit preview inputs",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_HTTP_REWRITE_TLS_BLOCKED_CODE,
        "TLS decryption and live HTTPS rewrite remain blocked until CA trust and TLS interception are active",
        SOURCE_CLI_MITM,
    ));
    let report = build_linux_mitm_http_rewrite_report("plan", None, None);

    LinuxCliResponse::success(command)
        .with_platform(platform_status)
        .with_mitm_status(mitm_status)
        .with_http_rewrite(report)
        .with_diagnostics(diagnostics)
}

#[allow(clippy::too_many_arguments)]
pub fn handle_mitm_http_rewrite_preview<P>(
    platform: &P,
    url: Option<&str>,
    method: &str,
    phase: &str,
    status_code: Option<u16>,
    raw_headers: &[String],
    body: Option<&str>,
    confirm: bool,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    let command = "mitm http-rewrite preview";
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let authorization = LinuxMitmHttpRewriteAuthorization {
        confirmed: confirm,
        source: if confirm {
            "cli --confirm".to_string()
        } else {
            "missing --confirm".to_string()
        },
        scope: "linux plain HTTP rewrite preview".to_string(),
        gate: MITM_HTTP_TLS_DATA_PLANE_GATE.to_string(),
    };
    let parsed_headers = match parse_http_rewrite_header_values(raw_headers) {
        Ok(headers) => headers,
        Err(diagnostic) => {
            diagnostics.push(diagnostic);
            let report = build_linux_mitm_http_rewrite_report(
                "preview",
                Some(build_linux_mitm_http_rewrite_request(
                    url,
                    method,
                    phase,
                    status_code,
                    Vec::new(),
                    body,
                    Some(authorization),
                )),
                None,
            );
            return LinuxCliResponse {
                ok: false,
                exit_code: LinuxCliExitCode::ArgumentOrConfig,
                ..LinuxCliResponse::success(command)
                    .with_platform(platform_status)
                    .with_mitm_status(mitm_status)
                    .with_http_rewrite(report)
                    .with_diagnostics(diagnostics)
            };
        }
    };
    let request = build_linux_mitm_http_rewrite_request(
        url,
        method,
        phase,
        status_code,
        parsed_headers.clone(),
        body,
        Some(authorization.clone()),
    );

    if !confirm {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_HTTP_REWRITE_AUTHORIZATION_REQUIRED_CODE,
            "plain HTTP rewrite preview requires --confirm before applying a plugin outcome to caller-provided input",
            SOURCE_CLI_MITM,
        ));
        let report = build_linux_mitm_http_rewrite_report("preview", Some(request), None);
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::Unavailable,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_http_rewrite(report)
                .with_diagnostics(diagnostics)
        };
    }

    let Some(url) = url else {
        diagnostics.push(cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_MITM_HTTP_REWRITE_CONFIG_MISSING_CODE,
            "plain HTTP rewrite preview requires --url <url>",
            SOURCE_CLI_MITM,
        ));
        let report = build_linux_mitm_http_rewrite_report("preview", Some(request), None);
        return LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::ArgumentOrConfig,
            ..LinuxCliResponse::success(command)
                .with_platform(platform_status)
                .with_mitm_status(mitm_status)
                .with_http_rewrite(report)
                .with_diagnostics(diagnostics)
        };
    };

    let package = builtin_ad_block_plugin_package();
    let service = AnixOpsMitmPluginService::new();
    let instance = match service.load(
        &package,
        &GrantedPermissions {
            permissions: package.manifest.permissions.clone(),
        },
    ) {
        Ok(instance) => instance,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };
    let message = engine_native::NativePlainHttpMessage {
        request_id: "linux-cli-http-rewrite-preview".to_string(),
        url: url.to_string(),
        method: Some(method.to_string()),
        phase: http_rewrite_phase_from_name(phase),
        status_code,
        headers: parsed_headers,
        body: body.unwrap_or_default().as_bytes().to_vec(),
    };
    let native_report =
        engine_native::plan_and_apply_plain_http_mitm(&message, &instance, &service);
    diagnostics.extend(native_report.diagnostics.clone());
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_MITM_HTTP_REWRITE_APPLY_READY_CODE,
        "plain HTTP rewrite preview applied the plugin outcome to caller-provided input; explicit HTTP proxy live traffic uses the native plain HTTP data plane",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_HTTP_REWRITE_TLS_BLOCKED_CODE,
        "TLS decryption and live HTTPS rewrite remain blocked until CA trust and TLS interception are active",
        SOURCE_CLI_MITM,
    ));
    let outcome = build_linux_mitm_http_rewrite_outcome_report(&native_report);
    let report = build_linux_mitm_http_rewrite_report("preview", Some(request), Some(outcome));

    LinuxCliResponse::success(command)
        .with_platform(platform_status)
        .with_mitm_status(mitm_status)
        .with_http_rewrite(report)
        .with_diagnostics(diagnostics)
}

fn build_linux_mitm_http_rewrite_report(
    action: &str,
    request: Option<LinuxMitmHttpRewriteRequest>,
    outcome: Option<LinuxMitmHttpRewriteOutcomeReport>,
) -> LinuxMitmHttpRewriteReport {
    LinuxMitmHttpRewriteReport {
        action: action.to_string(),
        source_contract_status: MITM_HTTP_REWRITE_SOURCE_CONTRACT_STATUS.to_string(),
        gate: MITM_HTTP_TLS_DATA_PLANE_GATE.to_string(),
        gate_status: MITM_HTTP_TLS_DATA_PLANE_GATE_STATUS.to_string(),
        mutation_ready: MITM_HTTP_REWRITE_MUTATION_READY,
        live_traffic_ready: MITM_HTTP_REWRITE_LIVE_TRAFFIC_READY,
        tls_decryption_ready: MITM_HTTP_REWRITE_TLS_DECRYPTION_READY,
        controlled_tls_termination_plan_ready:
            MITM_HTTP_REWRITE_CONTROLLED_TLS_TERMINATION_PLAN_READY,
        downstream_tls_termination_plan_ready:
            MITM_HTTP_REWRITE_DOWNSTREAM_TLS_TERMINATION_PLAN_READY,
        upstream_tls_forwarding_ready: MITM_HTTP_REWRITE_UPSTREAM_TLS_FORWARDING_READY,
        https_request_rewrite_preview_ready: MITM_HTTP_REWRITE_HTTPS_REQUEST_REWRITE_PREVIEW_READY,
        https_response_rewrite_preview_ready:
            MITM_HTTP_REWRITE_HTTPS_RESPONSE_REWRITE_PREVIEW_READY,
        https_response_rewrite_ready: MITM_HTTP_REWRITE_HTTPS_RESPONSE_REWRITE_READY,
        script_dispatch_ready: MITM_HTTP_REWRITE_SCRIPT_DISPATCH_READY,
        request: request.unwrap_or_else(|| {
            build_linux_mitm_http_rewrite_request(
                None,
                MITM_HTTP_REWRITE_DEFAULT_METHOD,
                MITM_HTTP_REWRITE_DEFAULT_PHASE,
                None,
                Vec::new(),
                None,
                None,
            )
        }),
        outcome,
        blocked_operations: linux_mitm_http_rewrite_blocked_operations(),
    }
}

fn build_linux_mitm_http_rewrite_request(
    url: Option<&str>,
    method: &str,
    phase: &str,
    status_code: Option<u16>,
    headers: Vec<MetadataEntry>,
    body: Option<&str>,
    authorization: Option<LinuxMitmHttpRewriteAuthorization>,
) -> LinuxMitmHttpRewriteRequest {
    LinuxMitmHttpRewriteRequest {
        url: url.map(ToString::to_string),
        method: method.to_string(),
        phase: phase.to_string(),
        status_code,
        headers: headers
            .iter()
            .map(linux_mitm_http_header_from_metadata)
            .collect(),
        body: body.map(ToString::to_string),
        authorization,
    }
}

fn build_linux_mitm_http_rewrite_outcome_report(
    report: &engine_native::NativePlainHttpRewriteReport,
) -> LinuxMitmHttpRewriteOutcomeReport {
    let outcome = report.outcome.as_ref();
    LinuxMitmHttpRewriteOutcomeReport {
        planned: outcome.is_some(),
        applied: report.applied,
        action: outcome
            .map(|outcome| http_mitm_action_name(&outcome.action))
            .unwrap_or_else(|| "failed".to_string()),
        terminal_action: report.terminal_action.clone(),
        final_status_code: report.final_status_code,
        redirect_location: report.redirect_location.clone(),
        header_mutation_count: outcome
            .map(|outcome| outcome.header_mutations.len())
            .unwrap_or_default(),
        body_mutated: outcome
            .and_then(|outcome| outcome.body_mutation.as_ref())
            .is_some(),
        script_dispatch_deferred: report.script_dispatch_deferred,
        output_headers: report
            .headers
            .iter()
            .map(linux_mitm_http_header_from_metadata)
            .collect(),
        output_body: Some(String::from_utf8_lossy(&report.body).to_string()),
    }
}

fn parse_http_rewrite_header_values(values: &[String]) -> Result<Vec<MetadataEntry>, Diagnostic> {
    values
        .iter()
        .map(|value| {
            let Some((name, header_value)) = value.split_once(':') else {
                return Err(cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "--header must use Name: Value format",
                    SOURCE_CLI_ARGUMENT,
                ));
            };
            let name = name.trim();
            if name.is_empty() {
                return Err(cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "--header name must not be empty",
                    SOURCE_CLI_ARGUMENT,
                ));
            }
            Ok(MetadataEntry {
                key: name.to_string(),
                value: header_value.trim().to_string(),
            })
        })
        .collect()
}

fn linux_mitm_http_header_from_metadata(header: &MetadataEntry) -> LinuxMitmHttpHeader {
    LinuxMitmHttpHeader {
        name: header.key.clone(),
        value: header.value.clone(),
    }
}

fn http_rewrite_phase_from_name(phase: &str) -> HttpMitmPhase {
    if phase.eq_ignore_ascii_case("response") {
        HttpMitmPhase::Response
    } else {
        HttpMitmPhase::Request
    }
}

fn http_mitm_action_name(action: &HttpMitmAction) -> String {
    match action {
        HttpMitmAction::Continue => "continue",
        HttpMitmAction::Redirect { .. } => "redirect",
        HttpMitmAction::Reject { .. } => "reject",
    }
    .to_string()
}

fn linux_mitm_http_rewrite_blocked_operations() -> Vec<String> {
    [
        "decrypt-https",
        "terminate-tls",
        "install-ca",
        "trust-ca",
        "mutate-live-https-traffic",
        "mutate-browser-or-system-capture",
        "mutate-system-proxy",
        "mutate-system-pac",
        "mutate-tun",
        "mutate-dns",
        "mutate-firewall",
    ]
    .iter()
    .map(|operation| (*operation).to_string())
    .collect()
}

fn handle_mitm_status_inner<P>(command: &'static str, platform: &P) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    match build_linux_mitm_status(&platform_status) {
        Ok((status, diagnostics)) => LinuxCliResponse::success(command)
            .with_platform(platform_status)
            .with_mitm_status(status)
            .with_diagnostics(diagnostics),
        Err(error) => domain_error_response(
            command,
            LinuxCliExitCode::GeneralFailure,
            error,
            SOURCE_CLI_MITM,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_mitm_browser_capture_inner<P>(
    command: &'static str,
    platform: &P,
    action: LinuxBrowserCaptureAction,
    confirm: bool,
    snapshot_path: Option<String>,
    target_url: Option<&str>,
    traffic_proof_token: Option<&str>,
    traffic_proof_log_path: Option<&str>,
    proxy_scheme: Option<&str>,
) -> LinuxCliResponse
where
    P: PlatformCapabilityService,
{
    let platform_status = match platform.status() {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let (mitm_status, mut diagnostics) = match build_linux_mitm_status(&platform_status) {
        Ok(status) => status,
        Err(error) => {
            return domain_error_response(
                command,
                LinuxCliExitCode::GeneralFailure,
                error,
                SOURCE_CLI_MITM,
            );
        }
    };

    let authorization = match action {
        LinuxBrowserCaptureAction::Apply => Some(BrowserCaptureAuthorization {
            confirmed: confirm,
            source: if confirm {
                "cli --confirm".to_string()
            } else {
                "missing --confirm".to_string()
            },
            scope: "linux explicit browser proxy capture".to_string(),
            gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
        }),
        LinuxBrowserCaptureAction::Verify => Some(BrowserCaptureAuthorization {
            confirmed: confirm,
            source: if confirm {
                "cli --confirm".to_string()
            } else {
                "missing --confirm".to_string()
            },
            scope: "linux browser capture local proxy endpoint verify".to_string(),
            gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
        }),
        LinuxBrowserCaptureAction::TrafficProof => Some(BrowserCaptureAuthorization {
            confirmed: confirm,
            source: if confirm {
                "cli --confirm".to_string()
            } else {
                "missing --confirm".to_string()
            },
            scope: "linux browser capture traffic proof".to_string(),
            gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
        }),
        _ => None,
    };
    let rollback_snapshot = snapshot_path.map(|path| BrowserCaptureRollbackSnapshot {
        path,
        status: "operator-provided".to_string(),
    });

    match action {
        LinuxBrowserCaptureAction::Plan => {}
        LinuxBrowserCaptureAction::LaunchPlan => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Info,
                CLI_MITM_BROWSER_CAPTURE_LAUNCH_PLAN_READY_CODE,
                "browser capture manual launch plan is available; no browser or system state was changed",
                SOURCE_CLI_MITM,
            ));
        }
        LinuxBrowserCaptureAction::SessionPlan => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MITM_BROWSER_CAPTURE_SESSION_PLAN_CONFIG_FAILED_CODE,
                "browser capture session-plan requires a subscription URL and the dedicated session-plan handler",
                SOURCE_CLI_MITM,
            ));
        }
        LinuxBrowserCaptureAction::Launch => {}
        LinuxBrowserCaptureAction::Apply => {
            if !confirm {
                diagnostics.push(cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_MITM_BROWSER_CAPTURE_AUTHORIZATION_REQUIRED_CODE,
                    "browser capture apply requires --confirm; no browser or system state was changed",
                    SOURCE_CLI_MITM,
                ));
            }
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MITM_BROWSER_CAPTURE_APPLY_BLOCKED_CODE,
                "browser capture apply is blocked until certificate lifecycle, HTTP/TLS data plane, and rollback snapshot support are active",
                SOURCE_CLI_MITM,
            ));
        }
        LinuxBrowserCaptureAction::Rollback => {
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MITM_BROWSER_CAPTURE_ROLLBACK_BLOCKED_CODE,
                "browser capture rollback is blocked until a NetworkCore-created rollback snapshot exists",
                SOURCE_CLI_MITM,
            ));
        }
        LinuxBrowserCaptureAction::Verify => {
            if !confirm {
                diagnostics.push(cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_MITM_BROWSER_CAPTURE_VERIFY_AUTHORIZATION_REQUIRED_CODE,
                    "browser capture verify requires --confirm before probing the planned local proxy endpoint",
                    SOURCE_CLI_MITM,
                ));
            }
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MITM_BROWSER_CAPTURE_VERIFY_BLOCKED_CODE,
                "browser capture verify endpoint probing is blocked because no BrowserCaptureEndpointProbe is wired",
                SOURCE_CLI_MITM,
            ));
        }
        LinuxBrowserCaptureAction::TrafficProof => {
            if !confirm {
                diagnostics.push(cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_AUTHORIZATION_REQUIRED_CODE,
                    "browser capture traffic proof requires --confirm before reading proof evidence",
                    SOURCE_CLI_MITM,
                ));
            }
            diagnostics.push(cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_MITM_BROWSER_CAPTURE_TRAFFIC_PROOF_BLOCKED_CODE,
                "browser capture traffic proof is blocked because no BrowserCaptureTrafficProofProbe is wired",
                SOURCE_CLI_MITM,
            ));
        }
    }

    let report = build_linux_browser_capture_report_with_proxy_scheme(
        action,
        &platform_status,
        &mitm_status.policy,
        authorization,
        rollback_snapshot,
        target_url,
        traffic_proof_token,
        traffic_proof_log_path,
        proxy_scheme.unwrap_or(MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME),
    );
    let mut response = LinuxCliResponse::success(command)
        .with_platform(platform_status)
        .with_mitm_status(mitm_status)
        .with_browser_capture(report)
        .with_diagnostics(diagnostics);

    if !matches!(
        action,
        LinuxBrowserCaptureAction::Plan | LinuxBrowserCaptureAction::LaunchPlan
    ) {
        response.ok = false;
        response.exit_code = LinuxCliExitCode::Unavailable;
    }

    response
}

fn build_linux_mitm_status(
    platform_status: &PlatformCapabilityStatus,
) -> DomainResult<(LinuxMitmStatus, Vec<Diagnostic>)> {
    let package = builtin_ad_block_plugin_package();
    let mut engine = AnixOpsMitmPolicyEngine::new()?;
    let report = engine.load_config(&package.source)?;
    let service = AnixOpsMitmPluginService::new();
    let instance = service.load(
        &package,
        &GrantedPermissions {
            permissions: package.manifest.permissions.clone(),
        },
    )?;

    let mut diagnostics = platform_diagnostics(platform_status);
    diagnostics.extend(report.diagnostics.clone());
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_MITM_POLICY_READY_CODE,
        "mitm policy engine loaded built-in networkcore.adblock plugin",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_MITM_CLI_GATE_PARTIAL_CODE,
        "MITM_CLI_COMMAND_GATE is partially active for status, diagnostics, certificate plan, browser plan, and browser capture reports",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_MITM_CERTIFICATE_PLAN_READY_CODE,
        "MITM certificate lifecycle plan is available for artifact apply and rollback inspection",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_CERTIFICATE_GATE_DEFERRED_CODE,
        "MITM_CERTIFICATE_LIFECYCLE_GATE allows NetworkCore-owned artifact apply/rollback, while system trust-store mutation remains blocked",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_CERTIFICATE_MUTATION_BLOCKED_CODE,
        "MITM certificate trust mutation is blocked; the CLI does not install, trust, revoke, or mutate system trust store state",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_DATA_PLANE_GATE_DEFERRED_CODE,
        "MITM_HTTP_TLS_DATA_PLANE_GATE allows explicit plain HTTP live data-plane rewrite, while TLS decryption and live HTTPS mutation remain blocked",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Info,
        CLI_MITM_BROWSER_PLAN_READY_CODE,
        "MITM browser capture plan is available for CLI inspection",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_BROWSER_CAPTURE_MUTATION_BLOCKED_CODE,
        "MITM browser capture system mutation is blocked; the CLI only writes operator-provided NetworkCore PAC and browser policy artifacts and does not install browser policy, system proxy, system PAC, TUN, DNS, or firewall state",
        SOURCE_CLI_MITM,
    ));
    diagnostics.push(cli_diagnostic(
        DiagnosticSeverity::Warning,
        CLI_MITM_BROWSER_HIJACK_DEFERRED_CODE,
        "browser hijack is deferred until certificate lifecycle, HTTP/TLS data plane, and browser capture gates are active",
        SOURCE_CLI_MITM,
    ));

    let status = LinuxMitmStatus {
        stage: MITM_USER_FACING_STAGE.to_string(),
        user_facing_ready: MITM_USER_FACING_READY,
        browser_hijack: MITM_BROWSER_HIJACK_STATUS.to_string(),
        platform_mitm_available: platform_status.mitm_available(),
        certificate_state: certificate_state_name(platform_status.mitm_certificate.state)
            .to_string(),
        certificate_plan: build_linux_mitm_certificate_plan(platform_status),
        browser_plan: build_linux_mitm_browser_plan(platform_status),
        policy: LinuxMitmPolicyStatus {
            engine: "mitm_anixops".to_string(),
            engine_version: report.version,
            plugin_id: instance.manifest.id,
            plugin_version: instance.manifest.version,
            plugin_loaded: true,
            mitm_pattern_count: report.mitm_pattern_count,
            rewrite_rule_count: report.rewrite_rule_count,
            script_rule_count: report.script_rule_count,
            argument_count: report.argument_count,
        },
        gates: vec![
            LinuxMitmGateStatus {
                gate: MITM_CLI_COMMAND_GATE.to_string(),
                status: MITM_CLI_COMMAND_GATE_STATUS.to_string(),
                reason: "MITM planning command surface is active".to_string(),
            },
            LinuxMitmGateStatus {
                gate: MITM_CERTIFICATE_LIFECYCLE_GATE.to_string(),
                status: MITM_CERTIFICATE_LIFECYCLE_GATE_STATUS.to_string(),
                reason: "certificate artifact apply and rollback are available; system trust-store mutation remains blocked".to_string(),
            },
            LinuxMitmGateStatus {
                gate: MITM_HTTP_TLS_DATA_PLANE_GATE.to_string(),
                status: MITM_HTTP_TLS_DATA_PLANE_GATE_STATUS.to_string(),
                reason: "explicit plain HTTP proxy live data plane and caller-provided preview are available; TLS decryption and live HTTPS mutation remain blocked".to_string(),
            },
            LinuxMitmGateStatus {
                gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
                status: MITM_BROWSER_CAPTURE_GATE_STATUS.to_string(),
                reason: "browser capture PAC and browser policy artifact apply is available; proxy/browser/system mutation remains blocked".to_string(),
            },
        ],
    };

    debug_assert_eq!(status.policy.plugin_id, MITM_POLICY_AD_BLOCK_PLUGIN_ID);

    Ok((status, diagnostics))
}

fn build_linux_mitm_browser_plan(
    platform_status: &PlatformCapabilityStatus,
) -> LinuxMitmBrowserPlan {
    let trust_satisfied = platform_status.mitm_certificate.is_trusted();

    LinuxMitmBrowserPlan {
        status: MITM_BROWSER_PLAN_STATUS.to_string(),
        mutation_ready: MITM_BROWSER_CAPTURE_MUTATION_READY,
        current_capture: "not_configured".to_string(),
        planned_capture_mode: MITM_BROWSER_CAPTURE_MODE.to_string(),
        planned_proxy_host: MITM_BROWSER_CAPTURE_PROXY_HOST.to_string(),
        planned_proxy_port: MITM_BROWSER_CAPTURE_PROXY_PORT,
        required_steps: vec![
            LinuxMitmBrowserPlanStep {
                id: "load-mitm-policy".to_string(),
                status: "active".to_string(),
                reason: "built-in networkcore.adblock policy can be loaded".to_string(),
            },
            LinuxMitmBrowserPlanStep {
                id: "verify-certificate-trust".to_string(),
                status: certificate_trust_step_status(trust_satisfied).to_string(),
                reason: certificate_verify_step_reason(platform_status.mitm_certificate.state)
                    .to_string(),
            },
            LinuxMitmBrowserPlanStep {
                id: "start-http-tls-mitm-proxy".to_string(),
                status: "blocked".to_string(),
                reason: "HTTP/TLS MITM proxy data plane is not wired".to_string(),
            },
            LinuxMitmBrowserPlanStep {
                id: "write-networkcore-pac-artifact".to_string(),
                status: "active".to_string(),
                reason: "browser-capture apply can write an operator-provided NetworkCore PAC file and rollback snapshot".to_string(),
            },
            LinuxMitmBrowserPlanStep {
                id: "write-browser-policy-artifact".to_string(),
                status: "active".to_string(),
                reason: "browser-capture apply can write an operator-provided Chromium/Chrome managed proxy policy artifact and rollback snapshot".to_string(),
            },
            LinuxMitmBrowserPlanStep {
                id: "configure-browser-explicit-proxy".to_string(),
                status: "blocked".to_string(),
                reason: "browser policy installation and browser proxy configuration mutation are not implemented".to_string(),
            },
            LinuxMitmBrowserPlanStep {
                id: "verify-browser-traffic-capture".to_string(),
                status: "blocked".to_string(),
                reason: "no live browser traffic capture probe is available".to_string(),
            },
            LinuxMitmBrowserPlanStep {
                id: "rollback-browser-capture".to_string(),
                status: "blocked".to_string(),
                reason: "browser/system proxy mutation rollback is not implemented".to_string(),
            },
        ],
        blocked_operations: vec![
            "start-mitm-proxy".to_string(),
            "write-system-proxy".to_string(),
            "install-browser-policy".to_string(),
            "install-system-pac".to_string(),
            "configure-tun-capture".to_string(),
            "configure-dns-capture".to_string(),
            "configure-firewall-capture".to_string(),
            "verify-live-browser-capture".to_string(),
            "rollback-browser-capture".to_string(),
        ],
    }
}

#[allow(clippy::too_many_arguments)]
fn build_linux_browser_capture_report(
    action: LinuxBrowserCaptureAction,
    platform_status: &PlatformCapabilityStatus,
    policy: &LinuxMitmPolicyStatus,
    authorization: Option<BrowserCaptureAuthorization>,
    rollback_snapshot: Option<BrowserCaptureRollbackSnapshot>,
    target_url: Option<&str>,
    traffic_proof_token: Option<&str>,
    traffic_proof_log_path: Option<&str>,
) -> LinuxBrowserCaptureReport {
    build_linux_browser_capture_report_with_proxy_scheme(
        action,
        platform_status,
        policy,
        authorization,
        rollback_snapshot,
        target_url,
        traffic_proof_token,
        traffic_proof_log_path,
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_linux_browser_capture_report_with_proxy_scheme(
    action: LinuxBrowserCaptureAction,
    platform_status: &PlatformCapabilityStatus,
    policy: &LinuxMitmPolicyStatus,
    authorization: Option<BrowserCaptureAuthorization>,
    rollback_snapshot: Option<BrowserCaptureRollbackSnapshot>,
    target_url: Option<&str>,
    traffic_proof_token: Option<&str>,
    traffic_proof_log_path: Option<&str>,
    proxy_scheme: &str,
) -> LinuxBrowserCaptureReport {
    let plan = build_linux_browser_capture_plan_with_proxy_scheme(
        platform_status,
        policy,
        MITM_BROWSER_CAPTURE_PROXY_HOST,
        MITM_BROWSER_CAPTURE_PROXY_PORT,
        proxy_scheme,
    );
    let verify_request = if action == LinuxBrowserCaptureAction::Verify {
        Some(build_linux_browser_capture_verify_request(
            &plan, target_url,
        ))
    } else {
        None
    };
    let traffic_proof_request = if action == LinuxBrowserCaptureAction::TrafficProof {
        Some(build_linux_browser_capture_traffic_proof_request(
            &plan,
            target_url,
            traffic_proof_token,
            traffic_proof_log_path,
        ))
    } else {
        None
    };
    let request = LinuxBrowserCaptureRequest {
        action,
        session: None,
        launch: None,
        pac: None,
        verify: verify_request.clone(),
        traffic_proof: traffic_proof_request.clone(),
        authorization: authorization.clone(),
        rollback_snapshot: rollback_snapshot.clone(),
    };
    let blocked_operations = plan.blocked_operations.clone();
    let apply_report = if action == LinuxBrowserCaptureAction::Apply {
        authorization.clone().map(|authorization| {
            let status = if authorization.confirmed {
                "blocked"
            } else {
                "authorization_required"
            };
            LinuxBrowserCaptureApplyReport {
                status: status.to_string(),
                applied: false,
                authorization,
                pac_file_path: None,
                pac_url: None,
                policy_file_path: None,
                policy_url: None,
                profile_prefs_file_path: None,
                rollback_snapshot: None,
                blocked_operations: blocked_operations.clone(),
            }
        })
    } else {
        None
    };
    let rollback_report = if action == LinuxBrowserCaptureAction::Rollback {
        Some(LinuxBrowserCaptureRollbackReport {
            status: "blocked".to_string(),
            rolled_back: false,
            pac_file_path: None,
            policy_file_path: None,
            profile_prefs_file_path: None,
            rollback_snapshot: rollback_snapshot.clone(),
            blocked_operations: blocked_operations.clone(),
        })
    } else {
        None
    };
    let verify_report = if action == LinuxBrowserCaptureAction::Verify {
        verify_request.map(|request| {
            build_linux_browser_capture_verify_report(
                "blocked",
                false,
                request,
                policy,
                blocked_operations.clone(),
            )
        })
    } else {
        None
    };
    let traffic_proof_report = if action == LinuxBrowserCaptureAction::TrafficProof {
        traffic_proof_request.map(|request| {
            build_linux_browser_capture_traffic_proof_report(
                "blocked",
                false,
                request,
                policy,
                blocked_operations.clone(),
            )
        })
    } else {
        None
    };

    LinuxBrowserCaptureReport {
        action: action.as_str().to_string(),
        source_contract_status: MITM_BROWSER_CAPTURE_SOURCE_CONTRACT_STATUS.to_string(),
        gate: MITM_BROWSER_CAPTURE_GATE.to_string(),
        gate_status: MITM_BROWSER_CAPTURE_GATE_STATUS.to_string(),
        mutation_ready: MITM_BROWSER_CAPTURE_MUTATION_READY,
        request,
        plan,
        session_plan: None,
        launch_report: None,
        apply_report,
        rollback_report,
        verify_report,
        traffic_proof_report,
    }
}

fn build_linux_browser_capture_plan_with_proxy_scheme(
    platform_status: &PlatformCapabilityStatus,
    policy: &LinuxMitmPolicyStatus,
    proxy_host: &str,
    proxy_port: u16,
    proxy_scheme: &str,
) -> LinuxBrowserCapturePlan {
    let mitm_plan = build_linux_mitm_browser_plan(platform_status);
    let mitm_plan = LinuxMitmBrowserPlan {
        planned_proxy_host: proxy_host.to_string(),
        planned_proxy_port: proxy_port,
        ..mitm_plan
    };
    let manual_launch = build_linux_browser_capture_manual_launch(&mitm_plan, policy, proxy_scheme);
    LinuxBrowserCapturePlan {
        status: mitm_plan.status,
        mutation_ready: mitm_plan.mutation_ready,
        current_capture: mitm_plan.current_capture,
        planned_capture_mode: mitm_plan.planned_capture_mode,
        planned_proxy_scheme: proxy_scheme.to_string(),
        planned_proxy_host: mitm_plan.planned_proxy_host,
        planned_proxy_port: mitm_plan.planned_proxy_port,
        manual_launch,
        required_steps: mitm_plan.required_steps,
        blocked_operations: mitm_plan.blocked_operations,
    }
}

fn build_linux_browser_capture_manual_launch(
    mitm_plan: &LinuxMitmBrowserPlan,
    policy: &LinuxMitmPolicyStatus,
    proxy_scheme: &str,
) -> LinuxBrowserCaptureManualLaunch {
    let proxy_url = browser_capture_proxy_url(
        proxy_scheme,
        &mitm_plan.planned_proxy_host,
        mitm_plan.planned_proxy_port,
    );

    LinuxBrowserCaptureManualLaunch {
        status: "manual-launch-plan-ready".to_string(),
        proxy_scheme: proxy_scheme.to_string(),
        proxy_url: proxy_url.clone(),
        profile_strategy: "dedicated-temporary-profile".to_string(),
        plugin_engine: policy.engine.clone(),
        plugin_id: policy.plugin_id.clone(),
        plugin_version: policy.plugin_version.clone(),
        browser_commands: default_linux_browser_capture_launch_commands(&proxy_url),
        manual_steps: vec![
            "start the planned local MITM proxy endpoint before launching the browser".to_string(),
            "launch a dedicated browser profile with an explicit proxy argument".to_string(),
            "close the dedicated browser profile to leave the manual capture session".to_string(),
        ],
    }
}

fn default_linux_browser_capture_launch_commands(
    proxy_url: &str,
) -> Vec<LinuxBrowserCaptureLaunchCommand> {
    ["chromium", "google-chrome", "microsoft-edge"]
        .into_iter()
        .map(|browser| {
            build_linux_browser_capture_launch_command(
                browser,
                browser,
                MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR,
                proxy_url,
                None,
            )
        })
        .collect()
}

fn browser_capture_proxy_url(proxy_scheme: &str, proxy_host: &str, proxy_port: u16) -> String {
    format!("{proxy_scheme}://{proxy_host}:{proxy_port}")
}

fn build_linux_browser_capture_launch_request(
    browser: &str,
    profile_dir: &str,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
    plan: &LinuxBrowserCapturePlan,
) -> LinuxBrowserCaptureLaunchRequest {
    let proxy_url = browser_capture_proxy_url(
        &plan.planned_proxy_scheme,
        &plan.planned_proxy_host,
        plan.planned_proxy_port,
    );
    let resolved_proof_token =
        resolve_browser_capture_proof_token(proof_token, target_url, &proxy_url);
    let resolved_proof_log_path = proof_log_path
        .unwrap_or(MITM_BROWSER_CAPTURE_DEFAULT_PROOF_LOG_PATH)
        .to_string();
    let proof_target_url = target_url
        .map(|target_url| browser_capture_proof_target_url(target_url, &resolved_proof_token));
    let browser_target_url = proof_target_url.as_deref().or(target_url);
    let command = build_linux_browser_capture_launch_command(
        browser,
        browser,
        profile_dir,
        &proxy_url,
        browser_target_url,
    );

    LinuxBrowserCaptureLaunchRequest {
        browser: browser.to_string(),
        profile_dir: profile_dir.to_string(),
        target_url: target_url.map(ToString::to_string),
        proof_target_url,
        proof_token: resolved_proof_token.clone(),
        proof_log_path: resolved_proof_log_path.clone(),
        traffic_proof_command: build_linux_browser_capture_traffic_proof_command(
            target_url,
            &resolved_proof_token,
            &resolved_proof_log_path,
            &plan.planned_proxy_scheme,
        ),
        proxy_scheme: plan.planned_proxy_scheme.clone(),
        proxy_url,
        command,
    }
}

fn build_linux_browser_capture_verify_request(
    plan: &LinuxBrowserCapturePlan,
    target_url: Option<&str>,
) -> LinuxBrowserCaptureVerifyRequest {
    LinuxBrowserCaptureVerifyRequest {
        proxy_host: plan.planned_proxy_host.clone(),
        proxy_port: plan.planned_proxy_port,
        proxy_scheme: plan.planned_proxy_scheme.clone(),
        proxy_url: browser_capture_proxy_url(
            &plan.planned_proxy_scheme,
            &plan.planned_proxy_host,
            plan.planned_proxy_port,
        ),
        target_url: target_url.map(ToString::to_string),
        probe: if target_url.is_some() {
            "http-connect-target"
        } else {
            "tcp-connect-timeout"
        }
        .to_string(),
    }
}

fn build_linux_browser_capture_pac_request(
    plan: &LinuxBrowserCapturePlan,
    pac_file_path: &str,
    policy_file_path: Option<&str>,
    profile_prefs_file_path: Option<&str>,
    snapshot_path: &str,
) -> LinuxBrowserCapturePacRequest {
    let proxy_url = browser_capture_proxy_url(
        &plan.planned_proxy_scheme,
        &plan.planned_proxy_host,
        plan.planned_proxy_port,
    );
    let policy_url = policy_file_path.map(browser_capture_pac_file_url);
    let policy_content = policy_file_path.map(|_| {
        browser_capture_chromium_policy_content(
            &plan.planned_proxy_scheme,
            &plan.planned_proxy_host,
            plan.planned_proxy_port,
        )
    });
    let profile_prefs_content = profile_prefs_file_path.map(|_| {
        browser_capture_firefox_user_js_content(
            &plan.planned_proxy_scheme,
            &plan.planned_proxy_host,
            plan.planned_proxy_port,
        )
    });
    LinuxBrowserCapturePacRequest {
        proxy_host: plan.planned_proxy_host.clone(),
        proxy_port: plan.planned_proxy_port,
        proxy_scheme: plan.planned_proxy_scheme.clone(),
        proxy_url,
        pac_file_path: pac_file_path.to_string(),
        snapshot_path: snapshot_path.to_string(),
        pac_url: browser_capture_pac_file_url(pac_file_path),
        pac_content: browser_capture_pac_content(
            &plan.planned_proxy_scheme,
            &plan.planned_proxy_host,
            plan.planned_proxy_port,
        ),
        policy_file_path: policy_file_path.map(ToString::to_string),
        policy_url,
        policy_content,
        profile_prefs_file_path: profile_prefs_file_path.map(ToString::to_string),
        profile_prefs_content,
    }
}

fn browser_capture_pac_file_url(path: &str) -> String {
    format!("file://{path}")
}

fn browser_capture_pac_content(proxy_scheme: &str, proxy_host: &str, proxy_port: u16) -> String {
    let pac_proxy_type = if proxy_scheme == MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME {
        "SOCKS5"
    } else {
        "PROXY"
    };
    format!(
        "function FindProxyForURL(url, host) {{\n  return \"{pac_proxy_type} {proxy_host}:{proxy_port}; DIRECT\";\n}}\n"
    )
}

#[derive(Serialize)]
struct BrowserCaptureChromiumPolicyFile<'a> {
    #[serde(rename = "ProxyMode")]
    proxy_mode: &'a str,
    #[serde(rename = "ProxyServer")]
    proxy_server: String,
    #[serde(rename = "ProxyBypassList")]
    proxy_bypass_list: &'a str,
}

fn browser_capture_chromium_policy_content(
    proxy_scheme: &str,
    proxy_host: &str,
    proxy_port: u16,
) -> String {
    let policy = BrowserCaptureChromiumPolicyFile {
        proxy_mode: "fixed_servers",
        proxy_server: browser_capture_proxy_url(proxy_scheme, proxy_host, proxy_port),
        proxy_bypass_list: "<-loopback>",
    };
    let mut json = serde_json::to_string_pretty(&policy)
        .expect("browser capture chromium policy serialization should be infallible");
    json.push('\n');
    json
}

fn browser_capture_firefox_user_js_content(
    proxy_scheme: &str,
    proxy_host: &str,
    proxy_port: u16,
) -> String {
    if proxy_scheme == MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME {
        return format!(
            "// NetworkCore browser capture managed proxy settings.\n\
             user_pref(\"network.proxy.type\", 1);\n\
             user_pref(\"network.proxy.socks\", \"{proxy_host}\");\n\
             user_pref(\"network.proxy.socks_port\", {proxy_port});\n\
             user_pref(\"network.proxy.socks_version\", 5);\n\
             user_pref(\"network.proxy.socks_remote_dns\", true);\n\
             user_pref(\"network.proxy.http\", \"\");\n\
             user_pref(\"network.proxy.http_port\", 0);\n\
             user_pref(\"network.proxy.ssl\", \"\");\n\
             user_pref(\"network.proxy.ssl_port\", 0);\n"
        );
    }

    format!(
        "// NetworkCore browser capture managed proxy settings.\n\
         user_pref(\"network.proxy.type\", 1);\n\
         user_pref(\"network.proxy.http\", \"{proxy_host}\");\n\
         user_pref(\"network.proxy.http_port\", {proxy_port});\n\
         user_pref(\"network.proxy.ssl\", \"{proxy_host}\");\n\
         user_pref(\"network.proxy.ssl_port\", {proxy_port});\n\
         user_pref(\"network.proxy.share_proxy_settings\", true);\n\
         user_pref(\"network.proxy.no_proxies_on\", \"\");\n"
    )
}

fn build_linux_browser_capture_verify_command(
    target_url: Option<&str>,
    proxy_scheme: &str,
) -> String {
    let mut args = vec![
        "networkcore-linux".to_string(),
        "mitm".to_string(),
        "browser-capture".to_string(),
        "verify".to_string(),
        "--confirm".to_string(),
    ];
    if proxy_scheme != MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME {
        args.push("--proxy-scheme".to_string());
        args.push(proxy_scheme.to_string());
    }
    if let Some(target_url) = target_url {
        args.push("--target-url".to_string());
        args.push(target_url.to_string());
    }

    args.into_iter()
        .map(|arg| shell_display_arg(&arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn build_linux_browser_capture_traffic_proof_command(
    target_url: Option<&str>,
    proof_token: &str,
    proof_log_path: &str,
    proxy_scheme: &str,
) -> String {
    let mut args = vec![
        "networkcore-linux".to_string(),
        "mitm".to_string(),
        "browser-capture".to_string(),
        "traffic-proof".to_string(),
        "--confirm".to_string(),
    ];
    if proxy_scheme != MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME {
        args.push("--proxy-scheme".to_string());
        args.push(proxy_scheme.to_string());
    }
    if let Some(target_url) = target_url {
        args.push("--target-url".to_string());
        args.push(target_url.to_string());
    }
    args.extend([
        "--proof-token".to_string(),
        proof_token.to_string(),
        "--proof-log".to_string(),
        proof_log_path.to_string(),
    ]);
    args.into_iter()
        .map(|arg| shell_display_arg(&arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn resolve_browser_capture_proof_token(
    proof_token: Option<&str>,
    target_url: Option<&str>,
    proxy_url: &str,
) -> String {
    if let Some(proof_token) = proof_token {
        return proof_token.to_string();
    }

    let proof_source = target_url
        .and_then(|target_url| {
            parse_browser_capture_target_endpoint(target_url)
                .ok()
                .map(|endpoint| format!("connect:{}|proxy:{proxy_url}", endpoint.authority()))
        })
        .unwrap_or_else(|| format!("target:no-target|proxy:{proxy_url}"));
    browser_capture_proof_token_from_source(&proof_source)
}

fn browser_capture_proof_token_from_source(source: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in source.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("networkcore-browser-proof-{hash:016x}")
}

fn browser_capture_proof_target_url(target_url: &str, proof_token: &str) -> String {
    let (base, fragment) = match target_url.split_once('#') {
        Some((base, fragment)) => (base, Some(fragment)),
        None => (target_url, None),
    };
    let separator = if base.ends_with('?') || base.ends_with('&') {
        ""
    } else if base.contains('?') {
        "&"
    } else {
        "?"
    };
    let mut proof_url = format!(
        "{base}{separator}{MITM_BROWSER_CAPTURE_PROOF_QUERY_PARAM}={}",
        browser_capture_url_query_encode(proof_token)
    );
    if let Some(fragment) = fragment {
        proof_url.push('#');
        proof_url.push_str(fragment);
    }
    proof_url
}

fn browser_capture_url_query_encode(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            encoded.push(ch);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn build_linux_browser_capture_launch_command(
    browser: &str,
    executable: &str,
    profile_dir: &str,
    proxy_url: &str,
    target_url: Option<&str>,
) -> LinuxBrowserCaptureLaunchCommand {
    let mut args = vec![
        format!("--user-data-dir={profile_dir}"),
        format!("--proxy-server={proxy_url}"),
    ];
    if let Some(target_url) = target_url {
        args.push(target_url.to_string());
    }
    let command = std::iter::once(executable.to_string())
        .chain(args.iter().cloned())
        .map(|arg| shell_display_arg(&arg))
        .collect::<Vec<_>>()
        .join(" ");

    LinuxBrowserCaptureLaunchCommand {
        browser: browser.to_string(),
        executable: executable.to_string(),
        args,
        command,
    }
}

fn shell_display_arg(arg: &str) -> String {
    if arg
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/' | ':' | '='))
    {
        return arg.to_string();
    }

    format!("'{}'", arg.replace('\'', "'\\''"))
}

fn build_linux_browser_capture_launch_report(
    status: &str,
    launched: bool,
    pid: Option<u32>,
    request: LinuxBrowserCaptureLaunchRequest,
    policy: &LinuxMitmPolicyStatus,
) -> LinuxBrowserCaptureLaunchReport {
    LinuxBrowserCaptureLaunchReport {
        status: status.to_string(),
        launched,
        pid,
        request,
        plugin_engine: policy.engine.clone(),
        plugin_id: policy.plugin_id.clone(),
        plugin_version: policy.plugin_version.clone(),
    }
}

fn build_linux_browser_capture_verify_report(
    status: &str,
    verified: bool,
    request: LinuxBrowserCaptureVerifyRequest,
    policy: &LinuxMitmPolicyStatus,
    blocked_operations: Vec<String>,
) -> LinuxBrowserCaptureVerifyReport {
    LinuxBrowserCaptureVerifyReport {
        status: status.to_string(),
        verified,
        request,
        plugin_engine: policy.engine.clone(),
        plugin_id: policy.plugin_id.clone(),
        plugin_version: policy.plugin_version.clone(),
        blocked_operations,
    }
}

fn build_linux_browser_capture_traffic_proof_request(
    plan: &LinuxBrowserCapturePlan,
    target_url: Option<&str>,
    proof_token: Option<&str>,
    proof_log_path: Option<&str>,
) -> LinuxBrowserCaptureTrafficProofRequest {
    let proxy_url = browser_capture_proxy_url(
        &plan.planned_proxy_scheme,
        &plan.planned_proxy_host,
        plan.planned_proxy_port,
    );
    let resolved_proof_token =
        resolve_browser_capture_proof_token(proof_token, target_url, &proxy_url);
    let resolved_proof_log_path = proof_log_path
        .unwrap_or(MITM_BROWSER_CAPTURE_DEFAULT_PROOF_LOG_PATH)
        .to_string();
    let proof_target_url = target_url
        .map(|target_url| browser_capture_proof_target_url(target_url, &resolved_proof_token));
    let proof_connect_authority = target_url.and_then(|target_url| {
        parse_browser_capture_target_endpoint(target_url)
            .ok()
            .map(|endpoint| endpoint.authority())
    });

    LinuxBrowserCaptureTrafficProofRequest {
        proxy_host: plan.planned_proxy_host.clone(),
        proxy_port: plan.planned_proxy_port,
        proxy_scheme: plan.planned_proxy_scheme.clone(),
        proxy_url,
        target_url: target_url.map(ToString::to_string),
        proof_connect_authority,
        proof_target_url,
        proof_token: resolved_proof_token,
        proof_log_path: resolved_proof_log_path,
        probe: "proof-log-token".to_string(),
    }
}

fn build_linux_browser_capture_traffic_proof_report(
    status: &str,
    proven: bool,
    request: LinuxBrowserCaptureTrafficProofRequest,
    policy: &LinuxMitmPolicyStatus,
    blocked_operations: Vec<String>,
) -> LinuxBrowserCaptureTrafficProofReport {
    LinuxBrowserCaptureTrafficProofReport {
        status: status.to_string(),
        proven,
        request,
        plugin_engine: policy.engine.clone(),
        plugin_id: policy.plugin_id.clone(),
        plugin_version: policy.plugin_version.clone(),
        blocked_operations,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_linux_browser_capture_session_plan_report(
    request: LinuxBrowserCaptureSessionPlanRequest,
    node_id: String,
    node_name: String,
    browser_command: LinuxBrowserCaptureLaunchCommand,
    proxy_url: String,
    traffic_proof_request: LinuxBrowserCaptureTrafficProofRequest,
    policy: &LinuxMitmPolicyStatus,
    blocked_operations: Vec<String>,
) -> LinuxBrowserCaptureSessionPlanReport {
    let target_url = request.target_url;
    let proof_target_url = request.proof_target_url;
    let verify_command =
        build_linux_browser_capture_verify_command(target_url.as_deref(), &request.proxy_scheme);
    let traffic_proof_command = build_linux_browser_capture_traffic_proof_command(
        target_url.as_deref(),
        &traffic_proof_request.proof_token,
        &traffic_proof_request.proof_log_path,
        &request.proxy_scheme,
    );

    LinuxBrowserCaptureSessionPlanReport {
        status: "ready".to_string(),
        url_source: request.url_source,
        node_id,
        node_name,
        target_url,
        proof_target_url,
        proof_token: traffic_proof_request.proof_token,
        proof_log_path: traffic_proof_request.proof_log_path,
        listen_host: request.listen_host.clone(),
        listen_port: request.listen_port,
        proxy_scheme: request.proxy_scheme,
        proxy_url,
        run_command: format!(
            "networkcore-linux run-url <subscription-url> --listen-host {} --listen-port {}",
            request.listen_host, request.listen_port
        ),
        browser_command,
        verify_command,
        traffic_proof_command,
        plugin_engine: policy.engine.clone(),
        plugin_id: policy.plugin_id.clone(),
        plugin_version: policy.plugin_version.clone(),
        required_steps: vec![
            "start the local proxy with run-url using the same subscription URL".to_string(),
            "launch the dedicated browser profile with the planned explicit proxy".to_string(),
            "verify the local proxy endpoint before relying on browser traffic capture".to_string(),
            "inspect the proxy proof log with the generated traffic-proof command".to_string(),
            "close the dedicated browser profile and stop the foreground proxy to leave the session"
                .to_string(),
        ],
        blocked_operations,
    }
}

fn build_linux_mitm_certificate_plan(
    platform_status: &PlatformCapabilityStatus,
) -> LinuxMitmCertificatePlan {
    let current_state = certificate_state_name(platform_status.mitm_certificate.state);
    let trust_satisfied = platform_status.mitm_certificate.is_trusted();

    LinuxMitmCertificatePlan {
        status: MITM_CERTIFICATE_PLAN_STATUS.to_string(),
        mutation_ready: MITM_CERTIFICATE_MUTATION_READY,
        current_state: current_state.to_string(),
        subject: platform_status.mitm_certificate.subject.clone(),
        fingerprint_sha256: platform_status.mitm_certificate.fingerprint_sha256.clone(),
        required_steps: vec![
            LinuxMitmCertificatePlanStep {
                id: "probe-certificate-state".to_string(),
                status: "active".to_string(),
                reason: "read-only platform certificate state is available".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "write-local-ca-artifact".to_string(),
                status: "active".to_string(),
                reason: "certificate apply can write operator-provided NetworkCore cert/key artifact paths with rollback snapshot".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "snapshot-ca-artifact".to_string(),
                status: "active".to_string(),
                reason: "certificate apply records NetworkCore ownership and content fingerprints before artifact rollback".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "write-dedicated-profile-trust-artifact".to_string(),
                status: "active".to_string(),
                reason: "certificate apply can optionally copy the generated CA artifact to an operator-provided dedicated profile trust artifact path with rollback snapshot".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "install-user-trust".to_string(),
                status: certificate_trust_step_status(trust_satisfied).to_string(),
                reason: certificate_trust_step_reason(platform_status.mitm_certificate.state)
                    .to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "verify-trust".to_string(),
                status: certificate_trust_step_status(trust_satisfied).to_string(),
                reason: certificate_verify_step_reason(platform_status.mitm_certificate.state)
                    .to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "rollback-ca-artifact".to_string(),
                status: "active".to_string(),
                reason: "certificate rollback can remove NetworkCore-created cert/key artifacts when the snapshot fingerprint still matches".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "rollback-trust".to_string(),
                status: "blocked".to_string(),
                reason: "certificate trust store rollback command is not implemented".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "connect-http-tls-data-plane".to_string(),
                status: "blocked".to_string(),
                reason: "HTTP/TLS interception data plane is not wired to the MITM policy engine"
                    .to_string(),
            },
        ],
        blocked_operations: vec![
            "install-ca".to_string(),
            "trust-ca".to_string(),
            "update-ca-certificates".to_string(),
            "mutate-nss-db".to_string(),
            "mutate-p11-kit".to_string(),
            "mutate-firefox-trust-store".to_string(),
            "revoke-ca".to_string(),
            "rollback-trust-store".to_string(),
            "decrypt-https".to_string(),
            "mutate-live-http".to_string(),
            "configure-browser-proxy".to_string(),
        ],
    }
}

fn build_linux_mitm_certificate_lifecycle_report(
    action: LinuxMitmCertificateLifecycleAction,
    platform_status: &PlatformCapabilityStatus,
    authorization: Option<MitmCertificateAuthorization>,
    rollback_snapshot: Option<MitmCertificateRollbackSnapshot>,
) -> LinuxMitmCertificateLifecycleReport {
    let plan = build_linux_mitm_certificate_plan(platform_status);
    let trust_plan = build_linux_mitm_certificate_trust_plan(platform_status);
    let request = LinuxMitmCertificateLifecycleRequest {
        action,
        artifact: None,
        authorization: authorization.clone(),
        rollback_snapshot: rollback_snapshot.clone(),
    };
    let apply_report = if action == LinuxMitmCertificateLifecycleAction::Apply {
        authorization.clone().map(|authorization| {
            let status = if authorization.confirmed {
                "blocked"
            } else {
                "authorization_required"
            };
            LinuxMitmCertificateApplyReport {
                status: status.to_string(),
                applied: false,
                authorization,
                cert_file_path: None,
                key_file_path: None,
                profile_trust_file_path: None,
                rollback_snapshot: None,
                blocked_operations: trust_plan.blocked_operations.clone(),
            }
        })
    } else {
        None
    };
    let rollback_report = if action == LinuxMitmCertificateLifecycleAction::Rollback {
        Some(LinuxMitmCertificateRollbackReport {
            status: "blocked".to_string(),
            rolled_back: false,
            cert_file_path: None,
            key_file_path: None,
            profile_trust_file_path: None,
            rollback_snapshot: rollback_snapshot.clone(),
            blocked_operations: trust_plan.blocked_operations.clone(),
        })
    } else {
        None
    };

    LinuxMitmCertificateLifecycleReport {
        action: action.as_str().to_string(),
        source_contract_status: MITM_CERTIFICATE_LIFECYCLE_SOURCE_CONTRACT_STATUS.to_string(),
        gate: MITM_CERTIFICATE_LIFECYCLE_GATE.to_string(),
        gate_status: MITM_CERTIFICATE_LIFECYCLE_GATE_STATUS.to_string(),
        mutation_ready: MITM_CERTIFICATE_MUTATION_READY,
        request,
        plan,
        trust_plan,
        apply_report,
        rollback_report,
    }
}

fn build_linux_mitm_certificate_trust_plan(
    platform_status: &PlatformCapabilityStatus,
) -> LinuxMitmCertificateTrustPlan {
    let trust_satisfied = platform_status.mitm_certificate.is_trusted();

    LinuxMitmCertificateTrustPlan {
        status: "trust-mutation-blocked".to_string(),
        mutation_ready: MITM_CERTIFICATE_MUTATION_READY,
        required_steps: vec![
            LinuxMitmCertificatePlanStep {
                id: "detect-platform-trust".to_string(),
                status: certificate_trust_step_status(trust_satisfied).to_string(),
                reason: certificate_verify_step_reason(platform_status.mitm_certificate.state)
                    .to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "prepare-system-trust-store-mutation".to_string(),
                status: "blocked".to_string(),
                reason: "system trust-store mutation is intentionally excluded from this alpha slice".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "prepare-dedicated-profile-trust-artifact".to_string(),
                status: "active".to_string(),
                reason: "profile-local CA trust artifact generation is available for caller-selected dedicated profile paths without mutating trust stores".to_string(),
            },
            LinuxMitmCertificatePlanStep {
                id: "prepare-browser-trust-store-mutation".to_string(),
                status: "blocked".to_string(),
                reason: "NSS DB, p11-kit, Firefox trust store, and browser-specific trust mutation are blocked".to_string(),
            },
        ],
        blocked_operations: vec![
            "install-ca".to_string(),
            "trust-ca".to_string(),
            "update-ca-certificates".to_string(),
            "mutate-nss-db".to_string(),
            "mutate-p11-kit".to_string(),
            "mutate-firefox-trust-store".to_string(),
            "revoke-ca".to_string(),
            "rollback-trust-store".to_string(),
        ],
    }
}

fn build_linux_mitm_certificate_artifact_request(
    cert_file_path: &str,
    key_file_path: &str,
    profile_trust_file_path: Option<&str>,
    snapshot_path: &str,
) -> DomainResult<LinuxMitmCertificateArtifactRequest> {
    let subject = MITM_CERTIFICATE_ARTIFACT_SUBJECT.to_string();
    let ca_material = generate_mitm_certificate_ca_pem_material(&subject)?;
    let cert_content = ca_material.cert_pem;
    let key_content = ca_material.key_pem;
    let profile_trust_content = profile_trust_file_path.map(|_| cert_content.clone());

    Ok(LinuxMitmCertificateArtifactRequest {
        cert_file_path: cert_file_path.to_string(),
        key_file_path: key_file_path.to_string(),
        profile_trust_file_path: profile_trust_file_path.map(ToString::to_string),
        snapshot_path: snapshot_path.to_string(),
        subject,
        artifact_version: 2,
        cert_fingerprint: stable_content_fingerprint(&cert_content),
        key_fingerprint: stable_content_fingerprint(&key_content),
        profile_trust_fingerprint: profile_trust_content
            .as_deref()
            .map(stable_content_fingerprint),
        cert_content,
        key_content,
        profile_trust_content,
    })
}

struct MitmCertificateCaPemMaterial {
    cert_pem: String,
    key_pem: String,
}

fn generate_mitm_certificate_ca_pem_material(
    subject: &str,
) -> DomainResult<MitmCertificateCaPemMaterial> {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, subject);
    distinguished_name.push(DnType::OrganizationName, "AnixOps NetworkCore");

    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let key_pair = KeyPair::generate().map_err(|error| {
        DomainError::new(
            CLI_MITM_CERTIFICATE_MATERIAL_FAILED_CODE,
            format!("failed to generate MITM CA private key material: {error}"),
        )
    })?;
    let certificate = params.self_signed(&key_pair).map_err(|error| {
        DomainError::new(
            CLI_MITM_CERTIFICATE_MATERIAL_FAILED_CODE,
            format!("failed to generate self-signed MITM CA certificate material: {error}"),
        )
    })?;

    Ok(MitmCertificateCaPemMaterial {
        cert_pem: certificate.pem(),
        key_pem: key_pair.serialize_pem(),
    })
}

fn stable_content_fingerprint(source: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in source.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn certificate_trust_step_status(trust_satisfied: bool) -> &'static str {
    if trust_satisfied {
        "satisfied"
    } else {
        "blocked"
    }
}

fn certificate_trust_step_reason(state: CertificateTrustState) -> &'static str {
    match state {
        CertificateTrustState::Trusted => "platform reports a trusted MITM certificate",
        CertificateTrustState::InstalledUntrusted => {
            "certificate is installed but the Linux trust path is not active"
        }
        CertificateTrustState::NotInstalled => "certificate is not installed",
        CertificateTrustState::Revoked => "certificate is revoked",
        CertificateTrustState::Unknown => "certificate trust state is unknown",
    }
}

fn certificate_verify_step_reason(state: CertificateTrustState) -> &'static str {
    match state {
        CertificateTrustState::Trusted => "read-only platform probe reports trusted state",
        CertificateTrustState::InstalledUntrusted => "trusted state cannot be verified yet",
        CertificateTrustState::NotInstalled => "no installed certificate is available to verify",
        CertificateTrustState::Revoked => "revoked certificate cannot be verified for MITM use",
        CertificateTrustState::Unknown => "certificate trust state probe is inconclusive",
    }
}

pub fn handle_install_sing_box<I>(
    installer: &I,
    install_dir: Option<&str>,
    force: bool,
) -> LinuxCliResponse
where
    I: SingBoxReleaseInstaller,
{
    let target = match SingBoxTarget::current() {
        Ok(target) => target,
        Err(error) => {
            return domain_error_response(
                "install-sing-box",
                LinuxCliExitCode::Unavailable,
                error,
                SOURCE_CLI_SING_BOX,
            );
        }
    };
    let install_root = install_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(default_sing_box_install_root);
    let request = SingBoxInstallRequest {
        install_root,
        target,
        force,
    };

    match installer.install_latest(&request) {
        Ok(report) => {
            let diagnostics = report.diagnostics.clone();
            LinuxCliResponse::success("install-sing-box")
                .with_diagnostics(diagnostics)
                .with_sing_box_install(LinuxSingBoxInstallStatus::from(report))
        }
        Err(error) => LinuxCliResponse::failure(
            "install-sing-box",
            LinuxCliExitCode::GeneralFailure,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_SING_BOX_INSTALL_FAILED_CODE,
                error.message,
                SOURCE_CLI_SING_BOX,
            ),
        ),
    }
}

pub fn handle_run_url_with_sing_box<I, S>(
    installer: &I,
    runner: &S,
    url: &str,
    listen_host: &str,
    listen_port: u16,
    install_dir: Option<&str>,
    force: bool,
) -> LinuxCliResponse
where
    I: SingBoxReleaseInstaller,
    S: SingBoxProcessRunner,
{
    let install_root = install_dir
        .map(std::path::PathBuf::from)
        .unwrap_or_else(default_sing_box_install_root);
    let subscription = CoreSubscriptionService::new();
    let raw_subscription = RawSubscription {
        source_id: "cli-run-url".to_string(),
        content: url.to_string(),
    };
    let document = match subscription.parse(&raw_subscription) {
        Ok(document) => document,
        Err(error) => {
            return domain_error_response(
                "run-url",
                LinuxCliExitCode::ArgumentOrConfig,
                DomainError::new(CLI_RUN_URL_PARSE_FAILED_CODE, error.message),
                SOURCE_CLI_SING_BOX,
            );
        }
    };
    let catalog = match subscription.normalize(&document) {
        Ok(catalog) => catalog,
        Err(error) => {
            return domain_error_response(
                "run-url",
                LinuxCliExitCode::ArgumentOrConfig,
                DomainError::new(CLI_RUN_URL_PARSE_FAILED_CODE, error.message),
                SOURCE_CLI_SING_BOX,
            );
        }
    };
    let generated_config =
        match render_sing_box_local_proxy_config(&SingBoxLocalProxyConfigRequest {
            nodes: catalog.nodes,
            selected_node_id: None,
            listen_host: listen_host.to_string(),
            listen_port,
        }) {
            Ok(config) => config,
            Err(error) => {
                return domain_error_response(
                    "run-url",
                    LinuxCliExitCode::ArgumentOrConfig,
                    DomainError::new(CLI_RUN_URL_CONFIG_FAILED_CODE, error.message),
                    SOURCE_CLI_SING_BOX,
                );
            }
        };
    let target = match SingBoxTarget::current() {
        Ok(target) => target,
        Err(error) => {
            return domain_error_response(
                "run-url",
                LinuxCliExitCode::Unavailable,
                error,
                SOURCE_CLI_SING_BOX,
            );
        }
    };
    let install_request = SingBoxInstallRequest {
        install_root: install_root.clone(),
        target,
        force,
    };
    let install_report = match installer.install_latest(&install_request) {
        Ok(report) => report,
        Err(error) => {
            return LinuxCliResponse::failure(
                "run-url",
                LinuxCliExitCode::GeneralFailure,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_SING_BOX_INSTALL_FAILED_CODE,
                    error.message,
                    SOURCE_CLI_SING_BOX,
                ),
            );
        }
    };
    let config_path = sing_box_run_config_path(&install_root, &generated_config.selected_node_id);
    if let Err(error) = write_sing_box_run_config(&config_path, &generated_config.json) {
        return LinuxCliResponse::failure(
            "run-url",
            LinuxCliExitCode::GeneralFailure,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_RUN_URL_CONFIG_WRITE_FAILED_CODE,
                error.message,
                SOURCE_CLI_SING_BOX,
            ),
        );
    }

    let run_request = SingBoxProcessRunRequest {
        executable_path: install_report.executable_path.clone(),
        config_path: config_path.clone(),
    };
    let run_report = match runner.run(&run_request) {
        Ok(report) => report,
        Err(error) => {
            return LinuxCliResponse::failure(
                "run-url",
                LinuxCliExitCode::GeneralFailure,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_RUN_URL_PROCESS_FAILED_CODE,
                    error.message,
                    SOURCE_CLI_SING_BOX,
                ),
            );
        }
    };
    let mut diagnostics = install_report.diagnostics.clone();
    diagnostics.extend(document.diagnostics.clone());
    diagnostics.extend(generated_config.diagnostics.clone());
    diagnostics.extend(run_report.diagnostics.clone());
    let run_status = LinuxSingBoxRunStatus {
        node_id: generated_config.selected_node_id,
        node_name: generated_config.selected_node_name,
        listen_host: generated_config.listen_host,
        listen_port: generated_config.listen_port,
        executable_path: install_report.executable_path.display().to_string(),
        config_path: config_path.display().to_string(),
        process_exit_code: run_report.exit_code,
    };

    let response = LinuxCliResponse::success("run-url")
        .with_diagnostics(diagnostics)
        .with_sing_box_install(LinuxSingBoxInstallStatus::from(install_report))
        .with_sing_box_run(run_status);

    match run_report.exit_code {
        Some(0) => response,
        Some(130) => LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::Interrupted,
            ..response
        },
        _ => LinuxCliResponse {
            ok: false,
            exit_code: LinuxCliExitCode::GeneralFailure,
            ..response
        },
    }
}

pub fn render_response(response: &LinuxCliResponse, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => render_text_response(response),
        OutputFormat::Json => render_json_response(response),
    }
}

pub fn cli_diagnostic(
    severity: DiagnosticSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
    source: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(severity, code, message, Some(source.into()))
}

fn parse_options(args: &[String]) -> Result<ParsedOptions, LinuxCliParseError> {
    let mut options = ParsedOptions::default();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "--config" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--config requires a path value",
                    ));
                };
                options.config_path = Some(value.clone());
            }
            "--browser" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--browser requires a browser executable value",
                    ));
                };
                options.browser = Some(value.clone());
            }
            "--profile-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--profile-dir requires a dedicated profile directory path value",
                    ));
                };
                options.profile_dir = Some(value.clone());
            }
            "--url" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--url requires an HTTP/TLS rewrite target URL",
                    ));
                };
                options.url = Some(value.clone());
            }
            "--method" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--method requires an HTTP method value",
                    ));
                };
                options.method = Some(value.to_ascii_uppercase());
            }
            "--phase" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--phase requires request or response",
                    ));
                };
                options.phase = Some(parse_http_rewrite_phase_name(value)?);
            }
            "--status-code" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--status-code requires a numeric HTTP status code",
                    ));
                };
                options.status_code = Some(parse_http_status_code(value)?);
            }
            "--header" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--header requires a Name: Value header",
                    ));
                };
                options.headers.push(value.clone());
            }
            "--body" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--body requires a plain HTTP body value",
                    ));
                };
                options.body = Some(value.clone());
            }
            "--target-url" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--target-url requires a browser target URL value",
                    ));
                };
                options.target_url = Some(value.clone());
            }
            "--cert-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--cert-file requires a MITM certificate artifact path",
                    ));
                };
                options.cert_file_path = Some(value.clone());
            }
            "--key-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--key-file requires a MITM private key artifact path",
                    ));
                };
                options.key_file_path = Some(value.clone());
            }
            "--profile-trust-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--profile-trust-file requires a dedicated profile trust artifact path",
                    ));
                };
                options.profile_trust_file_path = Some(value.clone());
            }
            "--pac-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--pac-file requires a browser capture PAC file path",
                    ));
                };
                options.pac_file_path = Some(value.clone());
            }
            "--policy-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--policy-file requires a browser policy file path",
                    ));
                };
                options.policy_file_path = Some(value.clone());
            }
            "--profile-prefs-file" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--profile-prefs-file requires a Firefox dedicated profile user.js path",
                    ));
                };
                options.profile_prefs_file_path = Some(value.clone());
            }
            "--proof-token" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--proof-token requires a browser traffic proof token value",
                    ));
                };
                options.proof_token = Some(value.clone());
            }
            "--proof-log" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--proof-log requires a browser traffic proof log path",
                    ));
                };
                options.proof_log_path = Some(value.clone());
            }
            "--proxy-scheme" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--proxy-scheme requires http or socks5",
                    ));
                };
                options.proxy_scheme = Some(parse_browser_capture_proxy_scheme(value)?);
            }
            "--install-dir" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--install-dir requires a directory path value",
                    ));
                };
                options.install_dir = Some(value.clone());
            }
            "--force" => {
                options.force = true;
            }
            "--confirm" => {
                options.confirm = true;
            }
            "--snapshot" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--snapshot requires a rollback snapshot path value",
                    ));
                };
                options.snapshot_path = Some(value.clone());
            }
            "--listen-host" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--listen-host requires an address value",
                    ));
                };
                options.listen_host = Some(value.clone());
            }
            "--listen-port" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--listen-port requires a port value",
                    ));
                };
                options.listen_port = Some(parse_listen_port(value)?);
            }
            "--format" => {
                index += 1;
                let Some(value) = args.get(index) else {
                    return Err(parse_error(
                        CLI_ARGUMENT_VALUE_MISSING_CODE,
                        "--format requires text or json",
                    ));
                };
                options.format = parse_output_format(value)?;
            }
            unknown => {
                return Err(parse_error(
                    CLI_ARGUMENT_UNKNOWN_CODE,
                    format!("unknown linux CLI argument: {unknown}"),
                ));
            }
        }

        index += 1;
    }

    Ok(options)
}

fn parse_run_url_command(args: &[String]) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(url) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "run-url requires a proxy URL argument",
        ));
    };
    if url.starts_with("--") {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "run-url requires a proxy URL before options",
        ));
    }
    let options = parse_options(&args[1..])?;

    Ok(LinuxCliCommand::RunUrl {
        url: url.clone(),
        listen_host: options
            .listen_host
            .unwrap_or_else(|| "127.0.0.1".to_string()),
        listen_port: options.listen_port.unwrap_or(7890),
        install_dir: options.install_dir,
        force: options.force,
        format: options.format,
    })
}

fn parse_mitm_command(args: &[String]) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(subcommand) = args.first() else {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmStatus {
            format: options.format,
        });
    };

    if subcommand.starts_with("--") {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmStatus {
            format: options.format,
        });
    }

    match subcommand.as_str() {
        "status" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmStatus {
                format: options.format,
            })
        }
        "diagnostics" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmDiagnostics {
                format: options.format,
            })
        }
        "certificate-plan" | "cert-plan" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmCertificatePlan {
                format: options.format,
            })
        }
        "certificate" | "cert" => parse_mitm_certificate_command(&args[1..]),
        "browser-plan" | "browser-capture-plan" | "hijack-plan" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserPlan {
                format: options.format,
            })
        }
        "browser-capture" => parse_mitm_browser_capture_command(&args[1..]),
        "http-rewrite" | "https-rewrite" | "tls-rewrite" => {
            parse_mitm_http_rewrite_command(&args[1..])
        }
        unknown => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown mitm subcommand: {unknown}; run networkcore-linux help"),
        )),
    }
}

fn parse_mitm_certificate_command(args: &[String]) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(subcommand) = args.first() else {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmCertificatePlan {
            format: options.format,
        });
    };

    if subcommand.starts_with("--") {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmCertificatePlan {
            format: options.format,
        });
    }

    match subcommand.as_str() {
        "plan" | "certificate-plan" | "cert-plan" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmCertificatePlan {
                format: options.format,
            })
        }
        "apply" | "generate" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmCertificateApply {
                cert_file_path: options.cert_file_path,
                key_file_path: options.key_file_path,
                profile_trust_file_path: options.profile_trust_file_path,
                snapshot_path: options.snapshot_path,
                confirm: options.confirm,
                format: options.format,
            })
        }
        "rollback" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmCertificateRollback {
                snapshot_path: options.snapshot_path,
                format: options.format,
            })
        }
        unknown => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown mitm certificate subcommand: {unknown}; run networkcore-linux help"),
        )),
    }
}

fn parse_mitm_browser_capture_command(
    args: &[String],
) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(subcommand) = args.first() else {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmBrowserCapturePlan {
            proxy_scheme: options
                .proxy_scheme
                .unwrap_or_else(default_browser_capture_proxy_scheme),
            format: options.format,
        });
    };

    if subcommand.starts_with("--") {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmBrowserCapturePlan {
            proxy_scheme: options
                .proxy_scheme
                .unwrap_or_else(default_browser_capture_proxy_scheme),
            format: options.format,
        });
    }

    match subcommand.as_str() {
        "plan" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserCapturePlan {
                proxy_scheme: options
                    .proxy_scheme
                    .unwrap_or_else(default_browser_capture_proxy_scheme),
                format: options.format,
            })
        }
        "launch-plan" | "manual-launch" | "hijack-launch-plan" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserCaptureLaunchPlan {
                proxy_scheme: options
                    .proxy_scheme
                    .unwrap_or_else(default_browser_capture_proxy_scheme),
                format: options.format,
            })
        }
        "session-plan" | "capture-session-plan" => {
            let Some(url) = args.get(1) else {
                return Err(parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "mitm browser-capture session-plan requires a proxy URL argument",
                ));
            };
            if url.starts_with("--") {
                return Err(parse_error(
                    CLI_ARGUMENT_VALUE_MISSING_CODE,
                    "mitm browser-capture session-plan requires a proxy URL before options",
                ));
            }
            let options = parse_options(&args[2..])?;
            Ok(LinuxCliCommand::MitmBrowserCaptureSessionPlan {
                url: url.clone(),
                browser: options
                    .browser
                    .unwrap_or_else(|| MITM_BROWSER_CAPTURE_DEFAULT_BROWSER.to_string()),
                profile_dir: options
                    .profile_dir
                    .unwrap_or_else(|| MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR.to_string()),
                target_url: options.target_url,
                proof_token: options.proof_token,
                proof_log_path: options.proof_log_path,
                proxy_scheme: options
                    .proxy_scheme
                    .unwrap_or_else(default_browser_capture_proxy_scheme),
                listen_host: options
                    .listen_host
                    .unwrap_or_else(|| MITM_BROWSER_CAPTURE_PROXY_HOST.to_string()),
                listen_port: options
                    .listen_port
                    .unwrap_or(MITM_BROWSER_CAPTURE_PROXY_PORT),
                format: options.format,
            })
        }
        "launch" | "hijack" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserCaptureLaunch {
                browser: options
                    .browser
                    .unwrap_or_else(|| MITM_BROWSER_CAPTURE_DEFAULT_BROWSER.to_string()),
                profile_dir: options
                    .profile_dir
                    .unwrap_or_else(|| MITM_BROWSER_CAPTURE_DEFAULT_PROFILE_DIR.to_string()),
                target_url: options.target_url,
                proof_token: options.proof_token,
                proof_log_path: options.proof_log_path,
                proxy_scheme: options
                    .proxy_scheme
                    .unwrap_or_else(default_browser_capture_proxy_scheme),
                confirm: options.confirm,
                format: options.format,
            })
        }
        "apply" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserCaptureApply {
                pac_file_path: options.pac_file_path,
                policy_file_path: options.policy_file_path,
                profile_prefs_file_path: options.profile_prefs_file_path,
                snapshot_path: options.snapshot_path,
                proxy_scheme: options
                    .proxy_scheme
                    .unwrap_or_else(default_browser_capture_proxy_scheme),
                confirm: options.confirm,
                format: options.format,
            })
        }
        "rollback" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserCaptureRollback {
                snapshot_path: options.snapshot_path,
                format: options.format,
            })
        }
        "verify" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserCaptureVerify {
                target_url: options.target_url,
                proxy_scheme: options
                    .proxy_scheme
                    .unwrap_or_else(default_browser_capture_proxy_scheme),
                confirm: options.confirm,
                format: options.format,
            })
        }
        "traffic-proof" | "proof" | "verify-traffic" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmBrowserCaptureTrafficProof {
                target_url: options.target_url,
                proof_token: options.proof_token,
                proof_log_path: options.proof_log_path,
                proxy_scheme: options
                    .proxy_scheme
                    .unwrap_or_else(default_browser_capture_proxy_scheme),
                confirm: options.confirm,
                format: options.format,
            })
        }
        unknown => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!(
                "unknown mitm browser-capture subcommand: {unknown}; run networkcore-linux help"
            ),
        )),
    }
}

fn parse_mitm_http_rewrite_command(args: &[String]) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(subcommand) = args.first() else {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmHttpRewritePlan {
            format: options.format,
        });
    };

    if subcommand.starts_with("--") {
        let options = parse_options(args)?;
        return Ok(LinuxCliCommand::MitmHttpRewritePlan {
            format: options.format,
        });
    }

    match subcommand.as_str() {
        "plan" | "status" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmHttpRewritePlan {
                format: options.format,
            })
        }
        "preview" | "apply" | "dry-run" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::MitmHttpRewritePreview {
                url: options.url,
                method: options
                    .method
                    .unwrap_or_else(|| MITM_HTTP_REWRITE_DEFAULT_METHOD.to_string()),
                phase: options
                    .phase
                    .unwrap_or_else(|| MITM_HTTP_REWRITE_DEFAULT_PHASE.to_string()),
                status_code: options.status_code,
                headers: options.headers,
                body: options.body,
                confirm: options.confirm,
                format: options.format,
            })
        }
        unknown => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown mitm http-rewrite subcommand: {unknown}; run networkcore-linux help"),
        )),
    }
}

fn parse_sing_box_command(args: &[String]) -> Result<LinuxCliCommand, LinuxCliParseError> {
    let Some(subcommand) = args.first() else {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "sing-box requires a subcommand; run networkcore-linux help",
        ));
    };

    match subcommand.as_str() {
        "install" => {
            let options = parse_options(&args[1..])?;
            Ok(LinuxCliCommand::InstallSingBox {
                install_dir: options.install_dir,
                force: options.force,
                format: options.format,
            })
        }
        unknown => Err(parse_error(
            CLI_ARGUMENT_UNKNOWN_CODE,
            format!("unknown sing-box subcommand: {unknown}; run networkcore-linux help"),
        )),
    }
}

fn parse_listen_port(value: &str) -> Result<u16, LinuxCliParseError> {
    let parsed = value.parse::<u16>().map_err(|_| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "--listen-port must be between 1 and 65535",
        )
    })?;
    if parsed == 0 {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "--listen-port must be between 1 and 65535",
        ));
    }

    Ok(parsed)
}

fn parse_http_status_code(value: &str) -> Result<u16, LinuxCliParseError> {
    let parsed = value.parse::<u16>().map_err(|_| {
        parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "--status-code must be between 100 and 599",
        )
    })?;
    if !(100..=599).contains(&parsed) {
        return Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "--status-code must be between 100 and 599",
        ));
    }

    Ok(parsed)
}

fn parse_http_rewrite_phase_name(value: &str) -> Result<String, LinuxCliParseError> {
    let normalized = value.to_ascii_lowercase();
    match normalized.as_str() {
        "request" | "response" => Ok(normalized),
        _ => Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            "--phase must be request or response",
        )),
    }
}

fn default_browser_capture_proxy_scheme() -> String {
    MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME.to_string()
}

fn parse_browser_capture_proxy_scheme(value: &str) -> Result<String, LinuxCliParseError> {
    let normalized = value.to_ascii_lowercase();
    match normalized.as_str() {
        MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME
        | MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME => Ok(normalized),
        _ => Err(parse_error(
            CLI_ARGUMENT_VALUE_MISSING_CODE,
            format!(
                "--proxy-scheme must be {} or {}",
                MITM_BROWSER_CAPTURE_DEFAULT_PROXY_SCHEME,
                MITM_BROWSER_CAPTURE_NATIVE_PLUGIN_PROXY_SCHEME
            ),
        )),
    }
}

pub const fn cli_help_text() -> &'static str {
    concat!(
        "NetworkCore Linux CLI\n",
        "\n",
        "Usage:\n",
        "  networkcore-linux help [--format text|json]\n",
        "  networkcore-linux version [--format text|json]\n",
        "  networkcore-linux capabilities [--format text|json]\n",
        "  networkcore-linux prepare-config --config <path> [--format text|json]\n",
        "  networkcore-linux start --config <path> [--format text|json]\n",
        "  networkcore-linux stop [--format text|json]\n",
        "  networkcore-linux status [--format text|json]\n",
        "  networkcore-linux diagnostics [--format text|json]\n",
        "  networkcore-linux mitm [status|diagnostics|certificate-plan|browser-plan] [--format text|json]\n",
        "  networkcore-linux mitm certificate [plan|apply|rollback] [--cert-file <path>] [--key-file <path>] [--profile-trust-file <path>] [--confirm] [--snapshot <path>] [--format text|json]\n",
        "  networkcore-linux mitm browser-capture [plan|launch-plan|session-plan|launch|apply|rollback|verify|traffic-proof] [<ss://url>] [--browser <executable>] [--profile-dir <dir>] [--target-url <url>] [--proxy-scheme http|socks5] [--listen-host <host>] [--listen-port <port>] [--pac-file <path>] [--policy-file <path>] [--profile-prefs-file <path>] [--proof-token <token>] [--proof-log <path>] [--confirm] [--snapshot <path>] [--format text|json]\n",
        "  networkcore-linux mitm http-rewrite [plan|preview] [--url <url>] [--method <method>] [--phase request|response] [--status-code <code>] [--header <name:value>] [--body <text>] [--confirm] [--format text|json]\n",
        "  networkcore-linux install-sing-box [--install-dir <dir>] [--force] [--format text|json]\n",
        "  networkcore-linux run-url <ss://url> [--listen-host <host>] [--listen-port <port>] [--install-dir <dir>] [--force] [--format text|json]\n",
        "  networkcore-linux sing-box install [--install-dir <dir>] [--force] [--format text|json]\n",
        "\n",
        "Commands:\n",
        "  help              Show this command table.\n",
        "  version           Print the networkcore-linux version.\n",
        "  capabilities      Report read-only Linux platform capabilities.\n",
        "  prepare-config    Read and normalize a NetworkCore TOML config.\n",
        "  start             Start the current foreground runtime from a config.\n",
        "  stop              Report that daemon stop is unavailable in this build.\n",
        "  status            Report platform-only status without a daemon context.\n",
        "  diagnostics       Print platform diagnostics.\n",
        "  mitm              Report MITM plugin policy status, certificate/browser plans, and deferred browser hijack gates.\n",
        "  install-sing-box  Download the latest official sing-box archive and cache its executable.\n",
        "  run-url           Parse a proxy URL, render sing-box config, and run a local foreground proxy.\n",
        "\n",
        "Options:\n",
        "  --config <path>       Config file for prepare-config and start.\n",
        "  --browser <exe>       Browser executable for mitm browser-capture session-plan/launch. Defaults to chromium.\n",
        "  --profile-dir <dir>   Dedicated browser profile directory for mitm browser-capture session-plan/launch.\n",
        "  --target-url <url>    Optional page URL to open in the dedicated browser capture profile.\n",
        "  --url <url>           HTTP/TLS rewrite preview target URL for mitm http-rewrite preview.\n",
        "  --method <method>     HTTP method for mitm http-rewrite preview. Defaults to GET.\n",
        "  --phase <phase>       HTTP MITM phase for mitm http-rewrite preview: request or response.\n",
        "  --status-code <code>  HTTP response status code for response-phase rewrite preview.\n",
        "  --header <name:value> Plain HTTP header input for rewrite preview; repeat for multiple headers.\n",
        "  --body <text>         Plain HTTP body input for rewrite preview.\n",
        "  --proxy-scheme <mode> Browser explicit proxy scheme for browser-capture. Defaults to http; socks5 targets the native SOCKS5 CONNECT MITM hook.\n",
        "  --cert-file <path>    Certificate artifact path for mitm certificate apply.\n",
        "  --key-file <path>     Private key artifact path for mitm certificate apply.\n",
        "  --profile-trust-file <path> Dedicated profile CA trust artifact path for mitm certificate apply.\n",
        "  --pac-file <path>     PAC file path for mitm browser-capture apply.\n",
        "  --policy-file <path>  Chromium/Chrome managed proxy policy file artifact for mitm browser-capture apply.\n",
        "  --profile-prefs-file <path> Firefox dedicated profile user.js path for reversible browser-capture apply.\n",
        "  --proof-token <token> Browser traffic proof token expected in a proof log.\n",
        "  --proof-log <path>    Browser traffic proof log path to inspect after an operator-driven visit.\n",
        "  --install-dir <dir>   Engine cache root for install-sing-box.\n",
        "  --listen-host <host>  Local proxy listen address for run-url. Defaults to 127.0.0.1.\n",
        "  --listen-port <port>  Local proxy listen port for run-url. Defaults to 7890.\n",
        "  --force               Redownload and replace an existing cached sing-box executable.\n",
        "  --format text|json    Output format. Defaults to text.\n",
    )
}

fn parse_output_format(value: &str) -> Result<OutputFormat, LinuxCliParseError> {
    match value {
        "text" => Ok(OutputFormat::Text),
        "json" => Ok(OutputFormat::Json),
        _ => Err(parse_error(
            CLI_OUTPUT_FORMAT_UNSUPPORTED_CODE,
            format!("unsupported linux CLI output format: {value}"),
        )),
    }
}

fn parse_error(code: impl Into<String>, message: impl Into<String>) -> LinuxCliParseError {
    LinuxCliParseError::new(cli_diagnostic(
        DiagnosticSeverity::Error,
        code,
        message,
        SOURCE_CLI_ARGUMENT,
    ))
}

fn read_required_config<R>(
    command: &'static str,
    reader: &R,
    config_path: Option<&str>,
) -> Result<String, Box<LinuxCliResponse>>
where
    R: ConfigReader,
{
    let Some(path) = config_path else {
        return Err(Box::new(LinuxCliResponse::failure(
            command,
            LinuxCliExitCode::ArgumentOrConfig,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_CONFIG_PATH_MISSING_CODE,
                "linux CLI command requires --config <path>",
                SOURCE_CLI_CONFIG,
            ),
        )));
    };

    let raw_config = match reader.read_config(path) {
        Ok(raw_config) => raw_config,
        Err(error) => {
            return Err(Box::new(LinuxCliResponse::failure(
                command,
                LinuxCliExitCode::ArgumentOrConfig,
                cli_diagnostic(
                    DiagnosticSeverity::Error,
                    CLI_CONFIG_READ_FAILED_CODE,
                    format!("failed to read linux config {path}: {}", error.message),
                    SOURCE_CLI_CONFIG,
                ),
            )));
        }
    };

    if raw_config.trim().is_empty() {
        return Err(Box::new(LinuxCliResponse::failure(
            command,
            LinuxCliExitCode::ArgumentOrConfig,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_CONFIG_EMPTY_CODE,
                "linux CLI config is empty",
                SOURCE_CLI_CONFIG,
            ),
        )));
    }

    Ok(raw_config)
}

fn sing_box_run_config_path(install_root: &std::path::Path, node_id: &str) -> std::path::PathBuf {
    install_root
        .join("runtime")
        .join(format!("run-url-{}.json", sanitize_path_segment(node_id)))
}

fn write_sing_box_run_config(path: &std::path::Path, content: &str) -> Result<(), ConfigReadError> {
    let parent = path
        .parent()
        .ok_or_else(|| ConfigReadError::new("sing-box config path has no parent directory"))?;
    std::fs::create_dir_all(parent).map_err(|error| ConfigReadError::new(error.to_string()))?;
    std::fs::write(path, content).map_err(|error| ConfigReadError::new(error.to_string()))
}

fn sanitize_path_segment(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let sanitized = sanitized.trim_matches('-');

    if sanitized.is_empty() {
        "node".to_string()
    } else {
        sanitized.to_string()
    }
}

fn start_error_response(error: DomainError) -> LinuxCliResponse {
    if error.code.starts_with("runtime.platform.") {
        return LinuxCliResponse::failure(
            "start",
            LinuxCliExitCode::PlatformDenied,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_START_PLATFORM_DENIED_CODE,
                error.message,
                SOURCE_CLI_START,
            ),
        );
    }

    if error.code.starts_with("runtime.config.") {
        return LinuxCliResponse::failure(
            "start",
            LinuxCliExitCode::ConfigValidation,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_START_CONFIG_DENIED_CODE,
                error.message,
                SOURCE_CLI_START,
            ),
        );
    }

    if error.code.starts_with("runtime.engine") || error.code.starts_with("engine.") {
        return LinuxCliResponse::failure(
            "start",
            LinuxCliExitCode::EngineDenied,
            cli_diagnostic(
                DiagnosticSeverity::Error,
                CLI_START_ENGINE_DENIED_CODE,
                error.message,
                SOURCE_CLI_START,
            ),
        );
    }

    domain_error_response(
        "start",
        LinuxCliExitCode::GeneralFailure,
        error,
        SOURCE_CLI_START,
    )
}

fn domain_error_response(
    command: &'static str,
    exit_code: LinuxCliExitCode,
    error: DomainError,
    source: &'static str,
) -> LinuxCliResponse {
    LinuxCliResponse::failure(
        command,
        exit_code,
        cli_diagnostic(DiagnosticSeverity::Error, error.code, error.message, source),
    )
}

fn handle_unwired_command(command: &'static str) -> LinuxCliResponse {
    LinuxCliResponse::failure(
        command,
        LinuxCliExitCode::Unavailable,
        cli_diagnostic(
            DiagnosticSeverity::Error,
            CLI_RUNTIME_UNWIRED_CODE,
            "linux CLI runtime wiring is not available for this command",
            SOURCE_CLI_RUNTIME,
        ),
    )
}

fn unavailable_engine_error() -> DomainError {
    DomainError::new(
        CLI_RUNTIME_UNWIRED_CODE,
        "linux proxy engine adapter is not wired",
    )
}

fn platform_diagnostics(status: &PlatformCapabilityStatus) -> Vec<Diagnostic> {
    let mut diagnostics = status.diagnostics.clone();
    diagnostics.extend(status.mitm_certificate.diagnostics.clone());
    diagnostics
}

fn render_text_response(response: &LinuxCliResponse) -> String {
    if response.ok && response.command == "help" {
        return response
            .help
            .clone()
            .unwrap_or_else(|| cli_help_text().to_string());
    }

    let state = if response.ok { "ok" } else { "error" };
    let mut lines = vec![format!("{}: {state}", response.command)];

    if let Some(install) = &response.sing_box_install {
        lines.push(format!("sing-box version: {}", install.version));
        lines.push(format!("target: {}", install.target));
        lines.push(format!("asset: {}", install.asset_name));
        if let Some(sha256) = &install.asset_sha256 {
            lines.push(format!("sha256: {sha256}"));
        }
        lines.push(format!("archive: {}", install.archive_path));
        lines.push(format!("executable: {}", install.executable_path));
        lines.push(format!("downloaded: {}", install.downloaded));
    }

    if let Some(run) = &response.sing_box_run {
        lines.push(format!("node: {} ({})", run.node_name, run.node_id));
        lines.push(format!(
            "local proxy: {}:{}",
            run.listen_host, run.listen_port
        ));
        lines.push(format!("config: {}", run.config_path));
        lines.push(format!("process exit code: {:?}", run.process_exit_code));
    }

    if let Some(mitm) = &response.mitm_status {
        lines.push(format!("mitm stage: {}", mitm.stage));
        lines.push(format!(
            "user-facing mitm ready: {}",
            mitm.user_facing_ready
        ));
        lines.push(format!("browser hijack: {}", mitm.browser_hijack));
        lines.push(format!(
            "platform mitm available: {}",
            mitm.platform_mitm_available
        ));
        lines.push(format!("certificate state: {}", mitm.certificate_state));
        lines.push(format!(
            "certificate plan: {} mutation_ready={}",
            mitm.certificate_plan.status, mitm.certificate_plan.mutation_ready
        ));
        lines.push(format!(
            "certificate plan current state: {}",
            mitm.certificate_plan.current_state
        ));
        if let Some(subject) = &mitm.certificate_plan.subject {
            lines.push(format!("certificate subject: {subject}"));
        }
        if let Some(fingerprint_sha256) = &mitm.certificate_plan.fingerprint_sha256 {
            lines.push(format!(
                "certificate fingerprint sha256: {fingerprint_sha256}"
            ));
        }
        for step in &mitm.certificate_plan.required_steps {
            lines.push(format!(
                "certificate step {}: {} ({})",
                step.id, step.status, step.reason
            ));
        }
        for operation in &mitm.certificate_plan.blocked_operations {
            lines.push(format!("certificate blocked operation: {operation}"));
        }
        lines.push(format!(
            "browser plan: {} mutation_ready={}",
            mitm.browser_plan.status, mitm.browser_plan.mutation_ready
        ));
        lines.push(format!(
            "browser capture: {}",
            mitm.browser_plan.current_capture
        ));
        lines.push(format!(
            "browser planned mode: {}",
            mitm.browser_plan.planned_capture_mode
        ));
        lines.push(format!(
            "browser planned proxy: {}:{}",
            mitm.browser_plan.planned_proxy_host, mitm.browser_plan.planned_proxy_port
        ));
        for step in &mitm.browser_plan.required_steps {
            lines.push(format!(
                "browser step {}: {} ({})",
                step.id, step.status, step.reason
            ));
        }
        for operation in &mitm.browser_plan.blocked_operations {
            lines.push(format!("browser blocked operation: {operation}"));
        }
        lines.push(format!(
            "policy engine: {} {}",
            mitm.policy.engine, mitm.policy.engine_version
        ));
        lines.push(format!(
            "plugin: {} {} loaded={}",
            mitm.policy.plugin_id, mitm.policy.plugin_version, mitm.policy.plugin_loaded
        ));
        lines.push(format!(
            "rules: mitm={} rewrite={} script={} arguments={}",
            mitm.policy.mitm_pattern_count,
            mitm.policy.rewrite_rule_count,
            mitm.policy.script_rule_count,
            mitm.policy.argument_count
        ));
        for gate in &mitm.gates {
            lines.push(format!(
                "gate {}: {} ({})",
                gate.gate, gate.status, gate.reason
            ));
        }
    }

    if let Some(certificate) = &response.certificate_lifecycle {
        lines.push(format!(
            "certificate lifecycle {}: {} mutation_ready={}",
            certificate.action, certificate.gate_status, certificate.mutation_ready
        ));
        lines.push(format!(
            "certificate lifecycle source contract: {}",
            certificate.source_contract_status
        ));
        lines.push(format!(
            "certificate lifecycle plan: {}",
            certificate.plan.status
        ));
        lines.push(format!(
            "certificate trust plan: {} mutation_ready={}",
            certificate.trust_plan.status, certificate.trust_plan.mutation_ready
        ));
        if let Some(authorization) = &certificate.request.authorization {
            lines.push(format!(
                "certificate authorization: confirmed={} source={} scope={}",
                authorization.confirmed, authorization.source, authorization.scope
            ));
        }
        if let Some(artifact) = &certificate.request.artifact {
            lines.push(format!(
                "certificate artifact request: cert={} key={} profile_trust={} snapshot={} subject={}",
                artifact.cert_file_path,
                artifact.key_file_path,
                artifact
                    .profile_trust_file_path
                    .as_deref()
                    .unwrap_or("not-requested"),
                artifact.snapshot_path,
                artifact.subject
            ));
            lines.push(format!(
                "certificate artifact fingerprints: cert={} key={} profile_trust={}",
                artifact.cert_fingerprint,
                artifact.key_fingerprint,
                artifact
                    .profile_trust_fingerprint
                    .as_deref()
                    .unwrap_or("not-requested")
            ));
        }
        if let Some(snapshot) = &certificate.request.rollback_snapshot {
            lines.push(format!(
                "certificate rollback snapshot: {} ({})",
                snapshot.path, snapshot.status
            ));
        }
        if let Some(report) = &certificate.apply_report {
            lines.push(format!(
                "certificate apply: {} applied={}",
                report.status, report.applied
            ));
            if let Some(cert_file_path) = &report.cert_file_path {
                lines.push(format!("certificate artifact file: {cert_file_path}"));
            }
            if let Some(key_file_path) = &report.key_file_path {
                lines.push(format!("certificate key artifact file: {key_file_path}"));
            }
            if let Some(profile_trust_file_path) = &report.profile_trust_file_path {
                lines.push(format!(
                    "certificate dedicated profile trust artifact file: {profile_trust_file_path}"
                ));
            }
            if let Some(snapshot) = &report.rollback_snapshot {
                lines.push(format!(
                    "certificate apply rollback snapshot: {} ({})",
                    snapshot.path, snapshot.status
                ));
            }
        }
        if let Some(report) = &certificate.rollback_report {
            lines.push(format!(
                "certificate rollback: {} rolled_back={}",
                report.status, report.rolled_back
            ));
            if let Some(cert_file_path) = &report.cert_file_path {
                lines.push(format!(
                    "certificate rollback artifact file: {cert_file_path}"
                ));
            }
            if let Some(key_file_path) = &report.key_file_path {
                lines.push(format!(
                    "certificate rollback key artifact file: {key_file_path}"
                ));
            }
            if let Some(profile_trust_file_path) = &report.profile_trust_file_path {
                lines.push(format!(
                    "certificate rollback dedicated profile trust artifact file: {profile_trust_file_path}"
                ));
            }
            if let Some(snapshot) = &report.rollback_snapshot {
                lines.push(format!(
                    "certificate rollback snapshot: {} ({})",
                    snapshot.path, snapshot.status
                ));
            }
        }
        for operation in &certificate.trust_plan.blocked_operations {
            lines.push(format!("certificate trust blocked operation: {operation}"));
        }
    }

    if let Some(capture) = &response.browser_capture {
        lines.push(format!(
            "browser capture {}: {} mutation_ready={}",
            capture.action, capture.gate_status, capture.mutation_ready
        ));
        lines.push(format!(
            "browser capture source contract: {}",
            capture.source_contract_status
        ));
        lines.push(format!(
            "browser capture planned proxy: {}:{}",
            capture.plan.planned_proxy_host, capture.plan.planned_proxy_port
        ));
        lines.push(format!(
            "browser capture planned proxy scheme: {}",
            capture.plan.planned_proxy_scheme
        ));
        lines.push(format!(
            "browser capture manual launch: {} proxy={}",
            capture.plan.manual_launch.status, capture.plan.manual_launch.proxy_url
        ));
        lines.push(format!(
            "browser capture plugin: {} {} via {}",
            capture.plan.manual_launch.plugin_id,
            capture.plan.manual_launch.plugin_version,
            capture.plan.manual_launch.plugin_engine
        ));
        for command in &capture.plan.manual_launch.browser_commands {
            lines.push(format!(
                "browser launch command {}: {}",
                command.browser, command.command
            ));
        }
        for step in &capture.plan.manual_launch.manual_steps {
            lines.push(format!("browser launch step: {step}"));
        }
        if let Some(session) = &capture.session_plan {
            lines.push(format!(
                "browser capture session plan: {} node={} proxy={}",
                session.status, session.node_name, session.proxy_url
            ));
            lines.push(format!(
                "browser capture session local proxy: {}:{}",
                session.listen_host, session.listen_port
            ));
            lines.push(format!(
                "browser capture session proxy scheme: {}",
                session.proxy_scheme
            ));
            if let Some(target_url) = &session.target_url {
                lines.push(format!("browser capture session target URL: {target_url}"));
            }
            if let Some(proof_target_url) = &session.proof_target_url {
                lines.push(format!(
                    "browser capture session proof target URL: {proof_target_url}"
                ));
            }
            lines.push(format!(
                "browser capture session proof token: {}",
                session.proof_token
            ));
            lines.push(format!(
                "browser capture session proof log: {}",
                session.proof_log_path
            ));
            lines.push(format!(
                "browser capture session run command: {}",
                session.run_command
            ));
            lines.push(format!(
                "browser capture session browser command: {}",
                session.browser_command.command
            ));
            lines.push(format!(
                "browser capture session verify command: {}",
                session.verify_command
            ));
            lines.push(format!(
                "browser capture session traffic-proof command: {}",
                session.traffic_proof_command
            ));
            for step in &session.required_steps {
                lines.push(format!("browser capture session step: {step}"));
            }
        }
        if let Some(authorization) = &capture.request.authorization {
            lines.push(format!(
                "browser capture authorization: confirmed={} source={} scope={}",
                authorization.confirmed, authorization.source, authorization.scope
            ));
        }
        if let Some(snapshot) = &capture.request.rollback_snapshot {
            lines.push(format!(
                "browser capture rollback snapshot: {} ({})",
                snapshot.path, snapshot.status
            ));
        }
        if let Some(report) = &capture.launch_report {
            lines.push(format!(
                "browser capture launch: {} launched={} pid={}",
                report.status,
                report.launched,
                report
                    .pid
                    .map(|pid| pid.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ));
            lines.push(format!(
                "browser capture launch command: {}",
                report.request.command.command
            ));
            if let Some(target_url) = &report.request.target_url {
                lines.push(format!("browser capture launch target URL: {target_url}"));
            }
            if let Some(proof_target_url) = &report.request.proof_target_url {
                lines.push(format!(
                    "browser capture launch proof target URL: {proof_target_url}"
                ));
            }
            lines.push(format!(
                "browser capture launch proof token: {}",
                report.request.proof_token
            ));
            lines.push(format!(
                "browser capture launch proof log: {}",
                report.request.proof_log_path
            ));
            lines.push(format!(
                "browser capture launch traffic-proof command: {}",
                report.request.traffic_proof_command
            ));
            lines.push(format!(
                "browser capture launch profile: {} proxy={}",
                report.request.profile_dir, report.request.proxy_url
            ));
        }
        if let Some(report) = &capture.apply_report {
            lines.push(format!(
                "browser capture apply: {} applied={}",
                report.status, report.applied
            ));
            if let Some(pac_file_path) = &report.pac_file_path {
                lines.push(format!("browser capture PAC file: {pac_file_path}"));
            }
            if let Some(pac_url) = &report.pac_url {
                lines.push(format!("browser capture PAC URL: {pac_url}"));
            }
            if let Some(policy_file_path) = &report.policy_file_path {
                lines.push(format!(
                    "browser capture browser policy file: {policy_file_path}"
                ));
            }
            if let Some(policy_url) = &report.policy_url {
                lines.push(format!("browser capture browser policy URL: {policy_url}"));
            }
            if let Some(profile_prefs_file_path) = &report.profile_prefs_file_path {
                lines.push(format!(
                    "browser capture Firefox profile prefs file: {profile_prefs_file_path}"
                ));
            }
            if let Some(snapshot) = &report.rollback_snapshot {
                lines.push(format!(
                    "browser capture apply rollback snapshot: {} ({})",
                    snapshot.path, snapshot.status
                ));
            }
        }
        if let Some(report) = &capture.rollback_report {
            lines.push(format!(
                "browser capture rollback: {} rolled_back={}",
                report.status, report.rolled_back
            ));
            if let Some(pac_file_path) = &report.pac_file_path {
                lines.push(format!(
                    "browser capture rollback PAC file: {pac_file_path}"
                ));
            }
            if let Some(policy_file_path) = &report.policy_file_path {
                lines.push(format!(
                    "browser capture rollback browser policy file: {policy_file_path}"
                ));
            }
            if let Some(profile_prefs_file_path) = &report.profile_prefs_file_path {
                lines.push(format!(
                    "browser capture rollback Firefox profile prefs file: {profile_prefs_file_path}"
                ));
            }
            if let Some(snapshot) = &report.rollback_snapshot {
                lines.push(format!(
                    "browser capture rollback snapshot: {} ({})",
                    snapshot.path, snapshot.status
                ));
            }
        }
        if let Some(report) = &capture.verify_report {
            lines.push(format!(
                "browser capture verify: {} verified={} proxy={} probe={}",
                report.status, report.verified, report.request.proxy_url, report.request.probe
            ));
            if let Some(target_url) = &report.request.target_url {
                lines.push(format!("browser capture verify target URL: {target_url}"));
            }
        }
        if let Some(report) = &capture.traffic_proof_report {
            lines.push(format!(
                "browser capture traffic proof: {} proven={} proxy={} proof_log={} probe={}",
                report.status,
                report.proven,
                report.request.proxy_url,
                report.request.proof_log_path,
                report.request.probe
            ));
            if let Some(target_url) = &report.request.target_url {
                lines.push(format!(
                    "browser capture traffic proof target URL: {target_url}"
                ));
            }
            if let Some(proof_target_url) = &report.request.proof_target_url {
                lines.push(format!(
                    "browser capture traffic proof target proof URL: {proof_target_url}"
                ));
            }
            if let Some(proof_connect_authority) = &report.request.proof_connect_authority {
                lines.push(format!(
                    "browser capture traffic proof CONNECT authority: {proof_connect_authority}"
                ));
            }
            lines.push(format!(
                "browser capture traffic proof token: {}",
                report.request.proof_token
            ));
        }
    }

    if let Some(rewrite) = &response.http_rewrite {
        lines.push(format!(
            "http rewrite {}: {} mutation_ready={} live_traffic_ready={} tls_decryption_ready={} controlled_tls_termination_plan_ready={} downstream_tls_termination_plan_ready={} upstream_tls_forwarding_ready={} https_request_rewrite_preview_ready={} https_response_rewrite_preview_ready={} https_response_rewrite_ready={} script_dispatch_ready={}",
            rewrite.action,
            rewrite.gate_status,
            rewrite.mutation_ready,
            rewrite.live_traffic_ready,
            rewrite.tls_decryption_ready,
            rewrite.controlled_tls_termination_plan_ready,
            rewrite.downstream_tls_termination_plan_ready,
            rewrite.upstream_tls_forwarding_ready,
            rewrite.https_request_rewrite_preview_ready,
            rewrite.https_response_rewrite_preview_ready,
            rewrite.https_response_rewrite_ready,
            rewrite.script_dispatch_ready
        ));
        lines.push(format!(
            "http rewrite source contract: {}",
            rewrite.source_contract_status
        ));
        if let Some(url) = &rewrite.request.url {
            lines.push(format!("http rewrite request URL: {url}"));
        }
        lines.push(format!(
            "http rewrite request: method={} phase={} status_code={}",
            rewrite.request.method,
            rewrite.request.phase,
            rewrite
                .request
                .status_code
                .map(|status| status.to_string())
                .unwrap_or_else(|| "none".to_string())
        ));
        if let Some(authorization) = &rewrite.request.authorization {
            lines.push(format!(
                "http rewrite authorization: confirmed={} source={} scope={}",
                authorization.confirmed, authorization.source, authorization.scope
            ));
        }
        if let Some(outcome) = &rewrite.outcome {
            lines.push(format!(
                "http rewrite outcome: planned={} applied={} action={} terminal={} final_status={}",
                outcome.planned,
                outcome.applied,
                outcome.action,
                outcome
                    .terminal_action
                    .clone()
                    .unwrap_or_else(|| "none".to_string()),
                outcome
                    .final_status_code
                    .map(|status| status.to_string())
                    .unwrap_or_else(|| "none".to_string())
            ));
            if let Some(location) = &outcome.redirect_location {
                lines.push(format!("http rewrite redirect location: {location}"));
            }
            lines.push(format!(
                "http rewrite mutations: headers={} body_mutated={} script_dispatch_deferred={}",
                outcome.header_mutation_count,
                outcome.body_mutated,
                outcome.script_dispatch_deferred
            ));
            for header in &outcome.output_headers {
                lines.push(format!(
                    "http rewrite output header: {}: {}",
                    header.name, header.value
                ));
            }
            if let Some(body) = &outcome.output_body {
                lines.push(format!("http rewrite output body: {body}"));
            }
        }
        for operation in &rewrite.blocked_operations {
            lines.push(format!("http rewrite blocked operation: {operation}"));
        }
    }

    for diagnostic in &response.diagnostics {
        lines.push(format!(
            "{} {}: {}",
            severity_name(diagnostic.severity),
            diagnostic.code,
            diagnostic.message
        ));
    }

    if let Some(help) = &response.help {
        lines.push(String::new());
        lines.push(help.clone());
    }

    lines.join("\n")
}

fn render_json_response(response: &LinuxCliResponse) -> String {
    let dto = JsonCliResponse::from(response);
    serde_json::to_string(&dto).expect("CLI response serialization should not fail")
}

fn severity_name(severity: DiagnosticSeverity) -> &'static str {
    match severity {
        DiagnosticSeverity::Info => "info",
        DiagnosticSeverity::Warning => "warning",
        DiagnosticSeverity::Error => "error",
    }
}

fn os_name(os: OperatingSystem) -> &'static str {
    match os {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Macos => "macos",
        OperatingSystem::Windows => "windows",
        OperatingSystem::Ios => "ios",
        OperatingSystem::Unknown => "unknown",
    }
}

fn certificate_state_name(state: CertificateTrustState) -> &'static str {
    match state {
        CertificateTrustState::NotInstalled => "not_installed",
        CertificateTrustState::InstalledUntrusted => "installed_untrusted",
        CertificateTrustState::Trusted => "trusted",
        CertificateTrustState::Revoked => "revoked",
        CertificateTrustState::Unknown => "unknown",
    }
}

#[derive(Serialize)]
struct JsonCliResponse {
    ok: bool,
    command: String,
    exit_code: i32,
    diagnostics: Vec<JsonDiagnostic>,
    platform: Option<JsonPlatform>,
    config_profiles: Vec<String>,
    version: Option<String>,
    help: Option<String>,
    sing_box_install: Option<JsonSingBoxInstallStatus>,
    sing_box_run: Option<JsonSingBoxRunStatus>,
    mitm_status: Option<JsonMitmStatus>,
    certificate_lifecycle: Option<JsonMitmCertificateLifecycleReport>,
    browser_capture: Option<JsonBrowserCaptureReport>,
    http_rewrite: Option<JsonMitmHttpRewriteReport>,
}

impl From<&LinuxCliResponse> for JsonCliResponse {
    fn from(response: &LinuxCliResponse) -> Self {
        Self {
            ok: response.ok,
            command: response.command.clone(),
            exit_code: response.exit_code.code(),
            diagnostics: response
                .diagnostics
                .iter()
                .map(JsonDiagnostic::from)
                .collect(),
            platform: response.platform.as_ref().map(JsonPlatform::from),
            config_profiles: response.config_profiles.clone(),
            version: response.version.clone(),
            help: response.help.clone(),
            sing_box_install: response
                .sing_box_install
                .as_ref()
                .map(JsonSingBoxInstallStatus::from),
            sing_box_run: response
                .sing_box_run
                .as_ref()
                .map(JsonSingBoxRunStatus::from),
            mitm_status: response.mitm_status.as_ref().map(JsonMitmStatus::from),
            certificate_lifecycle: response
                .certificate_lifecycle
                .as_ref()
                .map(JsonMitmCertificateLifecycleReport::from),
            browser_capture: response
                .browser_capture
                .as_ref()
                .map(JsonBrowserCaptureReport::from),
            http_rewrite: response
                .http_rewrite
                .as_ref()
                .map(JsonMitmHttpRewriteReport::from),
        }
    }
}

#[derive(Serialize)]
struct JsonSingBoxInstallStatus {
    version: String,
    target: String,
    asset_name: String,
    asset_url: String,
    asset_sha256: Option<String>,
    archive_path: String,
    executable_path: String,
    downloaded: bool,
}

impl From<&LinuxSingBoxInstallStatus> for JsonSingBoxInstallStatus {
    fn from(status: &LinuxSingBoxInstallStatus) -> Self {
        Self {
            version: status.version.clone(),
            target: status.target.clone(),
            asset_name: status.asset_name.clone(),
            asset_url: status.asset_url.clone(),
            asset_sha256: status.asset_sha256.clone(),
            archive_path: status.archive_path.clone(),
            executable_path: status.executable_path.clone(),
            downloaded: status.downloaded,
        }
    }
}

#[derive(Serialize)]
struct JsonSingBoxRunStatus {
    node_id: String,
    node_name: String,
    listen_host: String,
    listen_port: u16,
    executable_path: String,
    config_path: String,
    process_exit_code: Option<i32>,
}

impl From<&LinuxSingBoxRunStatus> for JsonSingBoxRunStatus {
    fn from(status: &LinuxSingBoxRunStatus) -> Self {
        Self {
            node_id: status.node_id.clone(),
            node_name: status.node_name.clone(),
            listen_host: status.listen_host.clone(),
            listen_port: status.listen_port,
            executable_path: status.executable_path.clone(),
            config_path: status.config_path.clone(),
            process_exit_code: status.process_exit_code,
        }
    }
}

#[derive(Serialize)]
struct JsonMitmStatus {
    stage: String,
    user_facing_ready: bool,
    browser_hijack: String,
    platform_mitm_available: bool,
    certificate_state: String,
    certificate_plan: JsonMitmCertificatePlan,
    browser_plan: JsonMitmBrowserPlan,
    policy: JsonMitmPolicyStatus,
    gates: Vec<JsonMitmGateStatus>,
}

impl From<&LinuxMitmStatus> for JsonMitmStatus {
    fn from(status: &LinuxMitmStatus) -> Self {
        Self {
            stage: status.stage.clone(),
            user_facing_ready: status.user_facing_ready,
            browser_hijack: status.browser_hijack.clone(),
            platform_mitm_available: status.platform_mitm_available,
            certificate_state: status.certificate_state.clone(),
            certificate_plan: JsonMitmCertificatePlan::from(&status.certificate_plan),
            browser_plan: JsonMitmBrowserPlan::from(&status.browser_plan),
            policy: JsonMitmPolicyStatus::from(&status.policy),
            gates: status.gates.iter().map(JsonMitmGateStatus::from).collect(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmBrowserPlan {
    status: String,
    mutation_ready: bool,
    current_capture: String,
    planned_capture_mode: String,
    planned_proxy_host: String,
    planned_proxy_port: u16,
    required_steps: Vec<JsonMitmBrowserPlanStep>,
    blocked_operations: Vec<String>,
}

impl From<&LinuxMitmBrowserPlan> for JsonMitmBrowserPlan {
    fn from(plan: &LinuxMitmBrowserPlan) -> Self {
        Self {
            status: plan.status.clone(),
            mutation_ready: plan.mutation_ready,
            current_capture: plan.current_capture.clone(),
            planned_capture_mode: plan.planned_capture_mode.clone(),
            planned_proxy_host: plan.planned_proxy_host.clone(),
            planned_proxy_port: plan.planned_proxy_port,
            required_steps: plan
                .required_steps
                .iter()
                .map(JsonMitmBrowserPlanStep::from)
                .collect(),
            blocked_operations: plan.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmBrowserPlanStep {
    id: String,
    status: String,
    reason: String,
}

impl From<&LinuxMitmBrowserPlanStep> for JsonMitmBrowserPlanStep {
    fn from(step: &LinuxMitmBrowserPlanStep) -> Self {
        Self {
            id: step.id.clone(),
            status: step.status.clone(),
            reason: step.reason.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmCertificateLifecycleReport {
    action: String,
    source_contract_status: String,
    gate: String,
    gate_status: String,
    mutation_ready: bool,
    request: JsonMitmCertificateLifecycleRequest,
    plan: JsonMitmCertificatePlan,
    trust_plan: JsonMitmCertificateTrustPlan,
    apply_report: Option<JsonMitmCertificateApplyReport>,
    rollback_report: Option<JsonMitmCertificateRollbackReport>,
}

impl From<&LinuxMitmCertificateLifecycleReport> for JsonMitmCertificateLifecycleReport {
    fn from(report: &LinuxMitmCertificateLifecycleReport) -> Self {
        Self {
            action: report.action.clone(),
            source_contract_status: report.source_contract_status.clone(),
            gate: report.gate.clone(),
            gate_status: report.gate_status.clone(),
            mutation_ready: report.mutation_ready,
            request: JsonMitmCertificateLifecycleRequest::from(&report.request),
            plan: JsonMitmCertificatePlan::from(&report.plan),
            trust_plan: JsonMitmCertificateTrustPlan::from(&report.trust_plan),
            apply_report: report
                .apply_report
                .as_ref()
                .map(JsonMitmCertificateApplyReport::from),
            rollback_report: report
                .rollback_report
                .as_ref()
                .map(JsonMitmCertificateRollbackReport::from),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmCertificateLifecycleRequest {
    action: String,
    artifact: Option<JsonMitmCertificateArtifactRequest>,
    authorization: Option<JsonMitmCertificateAuthorization>,
    rollback_snapshot: Option<JsonMitmCertificateRollbackSnapshot>,
}

impl From<&LinuxMitmCertificateLifecycleRequest> for JsonMitmCertificateLifecycleRequest {
    fn from(request: &LinuxMitmCertificateLifecycleRequest) -> Self {
        Self {
            action: request.action.as_str().to_string(),
            artifact: request
                .artifact
                .as_ref()
                .map(JsonMitmCertificateArtifactRequest::from),
            authorization: request
                .authorization
                .as_ref()
                .map(JsonMitmCertificateAuthorization::from),
            rollback_snapshot: request
                .rollback_snapshot
                .as_ref()
                .map(JsonMitmCertificateRollbackSnapshot::from),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmCertificateArtifactRequest {
    cert_file_path: String,
    key_file_path: String,
    profile_trust_file_path: Option<String>,
    snapshot_path: String,
    subject: String,
    artifact_version: u8,
    cert_content: String,
    key_content: String,
    profile_trust_content: Option<String>,
    cert_fingerprint: String,
    key_fingerprint: String,
    profile_trust_fingerprint: Option<String>,
}

impl From<&LinuxMitmCertificateArtifactRequest> for JsonMitmCertificateArtifactRequest {
    fn from(request: &LinuxMitmCertificateArtifactRequest) -> Self {
        Self {
            cert_file_path: request.cert_file_path.clone(),
            key_file_path: request.key_file_path.clone(),
            profile_trust_file_path: request.profile_trust_file_path.clone(),
            snapshot_path: request.snapshot_path.clone(),
            subject: request.subject.clone(),
            artifact_version: request.artifact_version,
            cert_content: request.cert_content.clone(),
            key_content: request.key_content.clone(),
            profile_trust_content: request.profile_trust_content.clone(),
            cert_fingerprint: request.cert_fingerprint.clone(),
            key_fingerprint: request.key_fingerprint.clone(),
            profile_trust_fingerprint: request.profile_trust_fingerprint.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmCertificateAuthorization {
    confirmed: bool,
    source: String,
    scope: String,
    gate: String,
}

impl From<&MitmCertificateAuthorization> for JsonMitmCertificateAuthorization {
    fn from(authorization: &MitmCertificateAuthorization) -> Self {
        Self {
            confirmed: authorization.confirmed,
            source: authorization.source.clone(),
            scope: authorization.scope.clone(),
            gate: authorization.gate.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmCertificateRollbackSnapshot {
    path: String,
    status: String,
}

impl From<&MitmCertificateRollbackSnapshot> for JsonMitmCertificateRollbackSnapshot {
    fn from(snapshot: &MitmCertificateRollbackSnapshot) -> Self {
        Self {
            path: snapshot.path.clone(),
            status: snapshot.status.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmCertificateTrustPlan {
    status: String,
    mutation_ready: bool,
    required_steps: Vec<JsonMitmCertificatePlanStep>,
    blocked_operations: Vec<String>,
}

impl From<&LinuxMitmCertificateTrustPlan> for JsonMitmCertificateTrustPlan {
    fn from(plan: &LinuxMitmCertificateTrustPlan) -> Self {
        Self {
            status: plan.status.clone(),
            mutation_ready: plan.mutation_ready,
            required_steps: plan
                .required_steps
                .iter()
                .map(JsonMitmCertificatePlanStep::from)
                .collect(),
            blocked_operations: plan.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmCertificateApplyReport {
    status: String,
    applied: bool,
    authorization: JsonMitmCertificateAuthorization,
    cert_file_path: Option<String>,
    key_file_path: Option<String>,
    profile_trust_file_path: Option<String>,
    rollback_snapshot: Option<JsonMitmCertificateRollbackSnapshot>,
    blocked_operations: Vec<String>,
}

impl From<&LinuxMitmCertificateApplyReport> for JsonMitmCertificateApplyReport {
    fn from(report: &LinuxMitmCertificateApplyReport) -> Self {
        Self {
            status: report.status.clone(),
            applied: report.applied,
            authorization: JsonMitmCertificateAuthorization::from(&report.authorization),
            cert_file_path: report.cert_file_path.clone(),
            key_file_path: report.key_file_path.clone(),
            profile_trust_file_path: report.profile_trust_file_path.clone(),
            rollback_snapshot: report
                .rollback_snapshot
                .as_ref()
                .map(JsonMitmCertificateRollbackSnapshot::from),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmCertificateRollbackReport {
    status: String,
    rolled_back: bool,
    cert_file_path: Option<String>,
    key_file_path: Option<String>,
    profile_trust_file_path: Option<String>,
    rollback_snapshot: Option<JsonMitmCertificateRollbackSnapshot>,
    blocked_operations: Vec<String>,
}

impl From<&LinuxMitmCertificateRollbackReport> for JsonMitmCertificateRollbackReport {
    fn from(report: &LinuxMitmCertificateRollbackReport) -> Self {
        Self {
            status: report.status.clone(),
            rolled_back: report.rolled_back,
            cert_file_path: report.cert_file_path.clone(),
            key_file_path: report.key_file_path.clone(),
            profile_trust_file_path: report.profile_trust_file_path.clone(),
            rollback_snapshot: report
                .rollback_snapshot
                .as_ref()
                .map(JsonMitmCertificateRollbackSnapshot::from),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureReport {
    action: String,
    source_contract_status: String,
    gate: String,
    gate_status: String,
    mutation_ready: bool,
    request: JsonBrowserCaptureRequest,
    plan: JsonBrowserCapturePlan,
    session_plan: Option<JsonBrowserCaptureSessionPlanReport>,
    launch_report: Option<JsonBrowserCaptureLaunchReport>,
    apply_report: Option<JsonBrowserCaptureApplyReport>,
    rollback_report: Option<JsonBrowserCaptureRollbackReport>,
    verify_report: Option<JsonBrowserCaptureVerifyReport>,
    traffic_proof_report: Option<JsonBrowserCaptureTrafficProofReport>,
}

impl From<&LinuxBrowserCaptureReport> for JsonBrowserCaptureReport {
    fn from(report: &LinuxBrowserCaptureReport) -> Self {
        Self {
            action: report.action.clone(),
            source_contract_status: report.source_contract_status.clone(),
            gate: report.gate.clone(),
            gate_status: report.gate_status.clone(),
            mutation_ready: report.mutation_ready,
            request: JsonBrowserCaptureRequest::from(&report.request),
            plan: JsonBrowserCapturePlan::from(&report.plan),
            session_plan: report
                .session_plan
                .as_ref()
                .map(JsonBrowserCaptureSessionPlanReport::from),
            launch_report: report
                .launch_report
                .as_ref()
                .map(JsonBrowserCaptureLaunchReport::from),
            apply_report: report
                .apply_report
                .as_ref()
                .map(JsonBrowserCaptureApplyReport::from),
            rollback_report: report
                .rollback_report
                .as_ref()
                .map(JsonBrowserCaptureRollbackReport::from),
            verify_report: report
                .verify_report
                .as_ref()
                .map(JsonBrowserCaptureVerifyReport::from),
            traffic_proof_report: report
                .traffic_proof_report
                .as_ref()
                .map(JsonBrowserCaptureTrafficProofReport::from),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureRequest {
    action: String,
    session: Option<JsonBrowserCaptureSessionPlanRequest>,
    launch: Option<JsonBrowserCaptureLaunchRequest>,
    pac: Option<JsonBrowserCapturePacRequest>,
    verify: Option<JsonBrowserCaptureVerifyRequest>,
    traffic_proof: Option<JsonBrowserCaptureTrafficProofRequest>,
    authorization: Option<JsonBrowserCaptureAuthorization>,
    rollback_snapshot: Option<JsonBrowserCaptureRollbackSnapshot>,
}

impl From<&LinuxBrowserCaptureRequest> for JsonBrowserCaptureRequest {
    fn from(request: &LinuxBrowserCaptureRequest) -> Self {
        Self {
            action: request.action.as_str().to_string(),
            session: request
                .session
                .as_ref()
                .map(JsonBrowserCaptureSessionPlanRequest::from),
            launch: request
                .launch
                .as_ref()
                .map(JsonBrowserCaptureLaunchRequest::from),
            pac: request.pac.as_ref().map(JsonBrowserCapturePacRequest::from),
            verify: request
                .verify
                .as_ref()
                .map(JsonBrowserCaptureVerifyRequest::from),
            traffic_proof: request
                .traffic_proof
                .as_ref()
                .map(JsonBrowserCaptureTrafficProofRequest::from),
            authorization: request
                .authorization
                .as_ref()
                .map(JsonBrowserCaptureAuthorization::from),
            rollback_snapshot: request
                .rollback_snapshot
                .as_ref()
                .map(JsonBrowserCaptureRollbackSnapshot::from),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCapturePacRequest {
    proxy_host: String,
    proxy_port: u16,
    proxy_scheme: String,
    proxy_url: String,
    pac_file_path: String,
    snapshot_path: String,
    pac_url: String,
    pac_content: String,
    policy_file_path: Option<String>,
    policy_url: Option<String>,
    policy_content: Option<String>,
    profile_prefs_file_path: Option<String>,
    profile_prefs_content: Option<String>,
}

impl From<&LinuxBrowserCapturePacRequest> for JsonBrowserCapturePacRequest {
    fn from(request: &LinuxBrowserCapturePacRequest) -> Self {
        Self {
            proxy_host: request.proxy_host.clone(),
            proxy_port: request.proxy_port,
            proxy_scheme: request.proxy_scheme.clone(),
            proxy_url: request.proxy_url.clone(),
            pac_file_path: request.pac_file_path.clone(),
            snapshot_path: request.snapshot_path.clone(),
            pac_url: request.pac_url.clone(),
            pac_content: request.pac_content.clone(),
            policy_file_path: request.policy_file_path.clone(),
            policy_url: request.policy_url.clone(),
            policy_content: request.policy_content.clone(),
            profile_prefs_file_path: request.profile_prefs_file_path.clone(),
            profile_prefs_content: request.profile_prefs_content.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureSessionPlanRequest {
    url_source: String,
    browser: String,
    profile_dir: String,
    target_url: Option<String>,
    proof_target_url: Option<String>,
    proof_token: String,
    proof_log_path: String,
    proxy_scheme: String,
    listen_host: String,
    listen_port: u16,
}

impl From<&LinuxBrowserCaptureSessionPlanRequest> for JsonBrowserCaptureSessionPlanRequest {
    fn from(request: &LinuxBrowserCaptureSessionPlanRequest) -> Self {
        Self {
            url_source: request.url_source.clone(),
            browser: request.browser.clone(),
            profile_dir: request.profile_dir.clone(),
            target_url: request.target_url.clone(),
            proof_target_url: request.proof_target_url.clone(),
            proof_token: request.proof_token.clone(),
            proof_log_path: request.proof_log_path.clone(),
            proxy_scheme: request.proxy_scheme.clone(),
            listen_host: request.listen_host.clone(),
            listen_port: request.listen_port,
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureSessionPlanReport {
    status: String,
    url_source: String,
    node_id: String,
    node_name: String,
    target_url: Option<String>,
    proof_target_url: Option<String>,
    proof_token: String,
    proof_log_path: String,
    listen_host: String,
    listen_port: u16,
    proxy_scheme: String,
    proxy_url: String,
    run_command: String,
    browser_command: JsonBrowserCaptureLaunchCommand,
    verify_command: String,
    traffic_proof_command: String,
    plugin_engine: String,
    plugin_id: String,
    plugin_version: String,
    required_steps: Vec<String>,
    blocked_operations: Vec<String>,
}

impl From<&LinuxBrowserCaptureSessionPlanReport> for JsonBrowserCaptureSessionPlanReport {
    fn from(report: &LinuxBrowserCaptureSessionPlanReport) -> Self {
        Self {
            status: report.status.clone(),
            url_source: report.url_source.clone(),
            node_id: report.node_id.clone(),
            node_name: report.node_name.clone(),
            target_url: report.target_url.clone(),
            proof_target_url: report.proof_target_url.clone(),
            proof_token: report.proof_token.clone(),
            proof_log_path: report.proof_log_path.clone(),
            listen_host: report.listen_host.clone(),
            listen_port: report.listen_port,
            proxy_scheme: report.proxy_scheme.clone(),
            proxy_url: report.proxy_url.clone(),
            run_command: report.run_command.clone(),
            browser_command: JsonBrowserCaptureLaunchCommand::from(&report.browser_command),
            verify_command: report.verify_command.clone(),
            traffic_proof_command: report.traffic_proof_command.clone(),
            plugin_engine: report.plugin_engine.clone(),
            plugin_id: report.plugin_id.clone(),
            plugin_version: report.plugin_version.clone(),
            required_steps: report.required_steps.clone(),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureVerifyRequest {
    proxy_host: String,
    proxy_port: u16,
    proxy_scheme: String,
    proxy_url: String,
    target_url: Option<String>,
    probe: String,
}

impl From<&LinuxBrowserCaptureVerifyRequest> for JsonBrowserCaptureVerifyRequest {
    fn from(request: &LinuxBrowserCaptureVerifyRequest) -> Self {
        Self {
            proxy_host: request.proxy_host.clone(),
            proxy_port: request.proxy_port,
            proxy_scheme: request.proxy_scheme.clone(),
            proxy_url: request.proxy_url.clone(),
            target_url: request.target_url.clone(),
            probe: request.probe.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureTrafficProofRequest {
    proxy_host: String,
    proxy_port: u16,
    proxy_scheme: String,
    proxy_url: String,
    target_url: Option<String>,
    proof_connect_authority: Option<String>,
    proof_target_url: Option<String>,
    proof_token: String,
    proof_log_path: String,
    probe: String,
}

impl From<&LinuxBrowserCaptureTrafficProofRequest> for JsonBrowserCaptureTrafficProofRequest {
    fn from(request: &LinuxBrowserCaptureTrafficProofRequest) -> Self {
        Self {
            proxy_host: request.proxy_host.clone(),
            proxy_port: request.proxy_port,
            proxy_scheme: request.proxy_scheme.clone(),
            proxy_url: request.proxy_url.clone(),
            target_url: request.target_url.clone(),
            proof_connect_authority: request.proof_connect_authority.clone(),
            proof_target_url: request.proof_target_url.clone(),
            proof_token: request.proof_token.clone(),
            proof_log_path: request.proof_log_path.clone(),
            probe: request.probe.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureAuthorization {
    confirmed: bool,
    source: String,
    scope: String,
    gate: String,
}

impl From<&BrowserCaptureAuthorization> for JsonBrowserCaptureAuthorization {
    fn from(authorization: &BrowserCaptureAuthorization) -> Self {
        Self {
            confirmed: authorization.confirmed,
            source: authorization.source.clone(),
            scope: authorization.scope.clone(),
            gate: authorization.gate.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureRollbackSnapshot {
    path: String,
    status: String,
}

impl From<&BrowserCaptureRollbackSnapshot> for JsonBrowserCaptureRollbackSnapshot {
    fn from(snapshot: &BrowserCaptureRollbackSnapshot) -> Self {
        Self {
            path: snapshot.path.clone(),
            status: snapshot.status.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCapturePlan {
    status: String,
    mutation_ready: bool,
    current_capture: String,
    planned_capture_mode: String,
    planned_proxy_scheme: String,
    planned_proxy_host: String,
    planned_proxy_port: u16,
    manual_launch: JsonBrowserCaptureManualLaunch,
    required_steps: Vec<JsonMitmBrowserPlanStep>,
    blocked_operations: Vec<String>,
}

impl From<&LinuxBrowserCapturePlan> for JsonBrowserCapturePlan {
    fn from(plan: &LinuxBrowserCapturePlan) -> Self {
        Self {
            status: plan.status.clone(),
            mutation_ready: plan.mutation_ready,
            current_capture: plan.current_capture.clone(),
            planned_capture_mode: plan.planned_capture_mode.clone(),
            planned_proxy_scheme: plan.planned_proxy_scheme.clone(),
            planned_proxy_host: plan.planned_proxy_host.clone(),
            planned_proxy_port: plan.planned_proxy_port,
            manual_launch: JsonBrowserCaptureManualLaunch::from(&plan.manual_launch),
            required_steps: plan
                .required_steps
                .iter()
                .map(JsonMitmBrowserPlanStep::from)
                .collect(),
            blocked_operations: plan.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureManualLaunch {
    status: String,
    proxy_scheme: String,
    proxy_url: String,
    profile_strategy: String,
    plugin_engine: String,
    plugin_id: String,
    plugin_version: String,
    browser_commands: Vec<JsonBrowserCaptureLaunchCommand>,
    manual_steps: Vec<String>,
}

impl From<&LinuxBrowserCaptureManualLaunch> for JsonBrowserCaptureManualLaunch {
    fn from(plan: &LinuxBrowserCaptureManualLaunch) -> Self {
        Self {
            status: plan.status.clone(),
            proxy_scheme: plan.proxy_scheme.clone(),
            proxy_url: plan.proxy_url.clone(),
            profile_strategy: plan.profile_strategy.clone(),
            plugin_engine: plan.plugin_engine.clone(),
            plugin_id: plan.plugin_id.clone(),
            plugin_version: plan.plugin_version.clone(),
            browser_commands: plan
                .browser_commands
                .iter()
                .map(JsonBrowserCaptureLaunchCommand::from)
                .collect(),
            manual_steps: plan.manual_steps.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureLaunchCommand {
    browser: String,
    executable: String,
    args: Vec<String>,
    command: String,
}

impl From<&LinuxBrowserCaptureLaunchCommand> for JsonBrowserCaptureLaunchCommand {
    fn from(command: &LinuxBrowserCaptureLaunchCommand) -> Self {
        Self {
            browser: command.browser.clone(),
            executable: command.executable.clone(),
            args: command.args.clone(),
            command: command.command.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureLaunchRequest {
    browser: String,
    profile_dir: String,
    target_url: Option<String>,
    proof_target_url: Option<String>,
    proof_token: String,
    proof_log_path: String,
    traffic_proof_command: String,
    proxy_scheme: String,
    proxy_url: String,
    command: JsonBrowserCaptureLaunchCommand,
}

impl From<&LinuxBrowserCaptureLaunchRequest> for JsonBrowserCaptureLaunchRequest {
    fn from(request: &LinuxBrowserCaptureLaunchRequest) -> Self {
        Self {
            browser: request.browser.clone(),
            profile_dir: request.profile_dir.clone(),
            target_url: request.target_url.clone(),
            proof_target_url: request.proof_target_url.clone(),
            proof_token: request.proof_token.clone(),
            proof_log_path: request.proof_log_path.clone(),
            traffic_proof_command: request.traffic_proof_command.clone(),
            proxy_scheme: request.proxy_scheme.clone(),
            proxy_url: request.proxy_url.clone(),
            command: JsonBrowserCaptureLaunchCommand::from(&request.command),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureLaunchReport {
    status: String,
    launched: bool,
    pid: Option<u32>,
    request: JsonBrowserCaptureLaunchRequest,
    plugin_engine: String,
    plugin_id: String,
    plugin_version: String,
}

impl From<&LinuxBrowserCaptureLaunchReport> for JsonBrowserCaptureLaunchReport {
    fn from(report: &LinuxBrowserCaptureLaunchReport) -> Self {
        Self {
            status: report.status.clone(),
            launched: report.launched,
            pid: report.pid,
            request: JsonBrowserCaptureLaunchRequest::from(&report.request),
            plugin_engine: report.plugin_engine.clone(),
            plugin_id: report.plugin_id.clone(),
            plugin_version: report.plugin_version.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureApplyReport {
    status: String,
    applied: bool,
    authorization: JsonBrowserCaptureAuthorization,
    pac_file_path: Option<String>,
    pac_url: Option<String>,
    policy_file_path: Option<String>,
    policy_url: Option<String>,
    profile_prefs_file_path: Option<String>,
    rollback_snapshot: Option<JsonBrowserCaptureRollbackSnapshot>,
    blocked_operations: Vec<String>,
}

impl From<&LinuxBrowserCaptureApplyReport> for JsonBrowserCaptureApplyReport {
    fn from(report: &LinuxBrowserCaptureApplyReport) -> Self {
        Self {
            status: report.status.clone(),
            applied: report.applied,
            authorization: JsonBrowserCaptureAuthorization::from(&report.authorization),
            pac_file_path: report.pac_file_path.clone(),
            pac_url: report.pac_url.clone(),
            policy_file_path: report.policy_file_path.clone(),
            policy_url: report.policy_url.clone(),
            profile_prefs_file_path: report.profile_prefs_file_path.clone(),
            rollback_snapshot: report
                .rollback_snapshot
                .as_ref()
                .map(JsonBrowserCaptureRollbackSnapshot::from),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureRollbackReport {
    status: String,
    rolled_back: bool,
    pac_file_path: Option<String>,
    policy_file_path: Option<String>,
    profile_prefs_file_path: Option<String>,
    rollback_snapshot: Option<JsonBrowserCaptureRollbackSnapshot>,
    blocked_operations: Vec<String>,
}

impl From<&LinuxBrowserCaptureRollbackReport> for JsonBrowserCaptureRollbackReport {
    fn from(report: &LinuxBrowserCaptureRollbackReport) -> Self {
        Self {
            status: report.status.clone(),
            rolled_back: report.rolled_back,
            pac_file_path: report.pac_file_path.clone(),
            policy_file_path: report.policy_file_path.clone(),
            profile_prefs_file_path: report.profile_prefs_file_path.clone(),
            rollback_snapshot: report
                .rollback_snapshot
                .as_ref()
                .map(JsonBrowserCaptureRollbackSnapshot::from),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureVerifyReport {
    status: String,
    verified: bool,
    request: JsonBrowserCaptureVerifyRequest,
    plugin_engine: String,
    plugin_id: String,
    plugin_version: String,
    blocked_operations: Vec<String>,
}

impl From<&LinuxBrowserCaptureVerifyReport> for JsonBrowserCaptureVerifyReport {
    fn from(report: &LinuxBrowserCaptureVerifyReport) -> Self {
        Self {
            status: report.status.clone(),
            verified: report.verified,
            request: JsonBrowserCaptureVerifyRequest::from(&report.request),
            plugin_engine: report.plugin_engine.clone(),
            plugin_id: report.plugin_id.clone(),
            plugin_version: report.plugin_version.clone(),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonBrowserCaptureTrafficProofReport {
    status: String,
    proven: bool,
    request: JsonBrowserCaptureTrafficProofRequest,
    plugin_engine: String,
    plugin_id: String,
    plugin_version: String,
    blocked_operations: Vec<String>,
}

impl From<&LinuxBrowserCaptureTrafficProofReport> for JsonBrowserCaptureTrafficProofReport {
    fn from(report: &LinuxBrowserCaptureTrafficProofReport) -> Self {
        Self {
            status: report.status.clone(),
            proven: report.proven,
            request: JsonBrowserCaptureTrafficProofRequest::from(&report.request),
            plugin_engine: report.plugin_engine.clone(),
            plugin_id: report.plugin_id.clone(),
            plugin_version: report.plugin_version.clone(),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmHttpRewriteReport {
    action: String,
    source_contract_status: String,
    gate: String,
    gate_status: String,
    mutation_ready: bool,
    live_traffic_ready: bool,
    tls_decryption_ready: bool,
    controlled_tls_termination_plan_ready: bool,
    downstream_tls_termination_plan_ready: bool,
    upstream_tls_forwarding_ready: bool,
    https_request_rewrite_preview_ready: bool,
    https_response_rewrite_preview_ready: bool,
    https_response_rewrite_ready: bool,
    script_dispatch_ready: bool,
    request: JsonMitmHttpRewriteRequest,
    outcome: Option<JsonMitmHttpRewriteOutcomeReport>,
    blocked_operations: Vec<String>,
}

impl From<&LinuxMitmHttpRewriteReport> for JsonMitmHttpRewriteReport {
    fn from(report: &LinuxMitmHttpRewriteReport) -> Self {
        Self {
            action: report.action.clone(),
            source_contract_status: report.source_contract_status.clone(),
            gate: report.gate.clone(),
            gate_status: report.gate_status.clone(),
            mutation_ready: report.mutation_ready,
            live_traffic_ready: report.live_traffic_ready,
            tls_decryption_ready: report.tls_decryption_ready,
            controlled_tls_termination_plan_ready: report.controlled_tls_termination_plan_ready,
            downstream_tls_termination_plan_ready: report.downstream_tls_termination_plan_ready,
            upstream_tls_forwarding_ready: report.upstream_tls_forwarding_ready,
            https_request_rewrite_preview_ready: report.https_request_rewrite_preview_ready,
            https_response_rewrite_preview_ready: report.https_response_rewrite_preview_ready,
            https_response_rewrite_ready: report.https_response_rewrite_ready,
            script_dispatch_ready: report.script_dispatch_ready,
            request: JsonMitmHttpRewriteRequest::from(&report.request),
            outcome: report
                .outcome
                .as_ref()
                .map(JsonMitmHttpRewriteOutcomeReport::from),
            blocked_operations: report.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmHttpRewriteRequest {
    url: Option<String>,
    method: String,
    phase: String,
    status_code: Option<u16>,
    headers: Vec<JsonMitmHttpHeader>,
    body: Option<String>,
    authorization: Option<JsonMitmHttpRewriteAuthorization>,
}

impl From<&LinuxMitmHttpRewriteRequest> for JsonMitmHttpRewriteRequest {
    fn from(request: &LinuxMitmHttpRewriteRequest) -> Self {
        Self {
            url: request.url.clone(),
            method: request.method.clone(),
            phase: request.phase.clone(),
            status_code: request.status_code,
            headers: request
                .headers
                .iter()
                .map(JsonMitmHttpHeader::from)
                .collect(),
            body: request.body.clone(),
            authorization: request
                .authorization
                .as_ref()
                .map(JsonMitmHttpRewriteAuthorization::from),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmHttpRewriteAuthorization {
    confirmed: bool,
    source: String,
    scope: String,
    gate: String,
}

impl From<&LinuxMitmHttpRewriteAuthorization> for JsonMitmHttpRewriteAuthorization {
    fn from(authorization: &LinuxMitmHttpRewriteAuthorization) -> Self {
        Self {
            confirmed: authorization.confirmed,
            source: authorization.source.clone(),
            scope: authorization.scope.clone(),
            gate: authorization.gate.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmHttpHeader {
    name: String,
    value: String,
}

impl From<&LinuxMitmHttpHeader> for JsonMitmHttpHeader {
    fn from(header: &LinuxMitmHttpHeader) -> Self {
        Self {
            name: header.name.clone(),
            value: header.value.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmHttpRewriteOutcomeReport {
    planned: bool,
    applied: bool,
    action: String,
    terminal_action: Option<String>,
    final_status_code: Option<u16>,
    redirect_location: Option<String>,
    header_mutation_count: usize,
    body_mutated: bool,
    script_dispatch_deferred: bool,
    output_headers: Vec<JsonMitmHttpHeader>,
    output_body: Option<String>,
}

impl From<&LinuxMitmHttpRewriteOutcomeReport> for JsonMitmHttpRewriteOutcomeReport {
    fn from(outcome: &LinuxMitmHttpRewriteOutcomeReport) -> Self {
        Self {
            planned: outcome.planned,
            applied: outcome.applied,
            action: outcome.action.clone(),
            terminal_action: outcome.terminal_action.clone(),
            final_status_code: outcome.final_status_code,
            redirect_location: outcome.redirect_location.clone(),
            header_mutation_count: outcome.header_mutation_count,
            body_mutated: outcome.body_mutated,
            script_dispatch_deferred: outcome.script_dispatch_deferred,
            output_headers: outcome
                .output_headers
                .iter()
                .map(JsonMitmHttpHeader::from)
                .collect(),
            output_body: outcome.output_body.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmCertificatePlan {
    status: String,
    mutation_ready: bool,
    current_state: String,
    subject: Option<String>,
    fingerprint_sha256: Option<String>,
    required_steps: Vec<JsonMitmCertificatePlanStep>,
    blocked_operations: Vec<String>,
}

impl From<&LinuxMitmCertificatePlan> for JsonMitmCertificatePlan {
    fn from(plan: &LinuxMitmCertificatePlan) -> Self {
        Self {
            status: plan.status.clone(),
            mutation_ready: plan.mutation_ready,
            current_state: plan.current_state.clone(),
            subject: plan.subject.clone(),
            fingerprint_sha256: plan.fingerprint_sha256.clone(),
            required_steps: plan
                .required_steps
                .iter()
                .map(JsonMitmCertificatePlanStep::from)
                .collect(),
            blocked_operations: plan.blocked_operations.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmCertificatePlanStep {
    id: String,
    status: String,
    reason: String,
}

impl From<&LinuxMitmCertificatePlanStep> for JsonMitmCertificatePlanStep {
    fn from(step: &LinuxMitmCertificatePlanStep) -> Self {
        Self {
            id: step.id.clone(),
            status: step.status.clone(),
            reason: step.reason.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonMitmPolicyStatus {
    engine: String,
    engine_version: String,
    plugin_id: String,
    plugin_version: String,
    plugin_loaded: bool,
    mitm_pattern_count: usize,
    rewrite_rule_count: usize,
    script_rule_count: usize,
    argument_count: usize,
}

impl From<&LinuxMitmPolicyStatus> for JsonMitmPolicyStatus {
    fn from(status: &LinuxMitmPolicyStatus) -> Self {
        Self {
            engine: status.engine.clone(),
            engine_version: status.engine_version.clone(),
            plugin_id: status.plugin_id.clone(),
            plugin_version: status.plugin_version.clone(),
            plugin_loaded: status.plugin_loaded,
            mitm_pattern_count: status.mitm_pattern_count,
            rewrite_rule_count: status.rewrite_rule_count,
            script_rule_count: status.script_rule_count,
            argument_count: status.argument_count,
        }
    }
}

#[derive(Serialize)]
struct JsonMitmGateStatus {
    gate: String,
    status: String,
    reason: String,
}

impl From<&LinuxMitmGateStatus> for JsonMitmGateStatus {
    fn from(status: &LinuxMitmGateStatus) -> Self {
        Self {
            gate: status.gate.clone(),
            status: status.status.clone(),
            reason: status.reason.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonDiagnostic {
    severity: &'static str,
    code: String,
    message: String,
    source: Option<String>,
}

impl From<&Diagnostic> for JsonDiagnostic {
    fn from(diagnostic: &Diagnostic) -> Self {
        Self {
            severity: severity_name(diagnostic.severity),
            code: diagnostic.code.clone(),
            message: diagnostic.message.clone(),
            source: diagnostic.source.clone(),
        }
    }
}

#[derive(Serialize)]
struct JsonPlatform {
    os: &'static str,
    tunnel: JsonFeatureState,
    mitm: JsonFeatureState,
    embedded_runtime: JsonFeatureState,
    remote_script_execution: JsonFeatureState,
    mitm_certificate: JsonCertificateStatus,
}

impl From<&PlatformCapabilityStatus> for JsonPlatform {
    fn from(status: &PlatformCapabilityStatus) -> Self {
        Self {
            os: os_name(status.os),
            tunnel: JsonFeatureState::from(&status.tunnel),
            mitm: JsonFeatureState::from(&status.mitm),
            embedded_runtime: JsonFeatureState::from(&status.embedded_runtime),
            remote_script_execution: JsonFeatureState::from(&status.remote_script_execution),
            mitm_certificate: JsonCertificateStatus::from(status),
        }
    }
}

#[derive(Serialize)]
struct JsonFeatureState {
    state: &'static str,
    reason: Option<String>,
}

impl From<&PlatformFeatureState> for JsonFeatureState {
    fn from(state: &PlatformFeatureState) -> Self {
        match state {
            PlatformFeatureState::Available => Self {
                state: "available",
                reason: None,
            },
            PlatformFeatureState::Unavailable { reason } => Self {
                state: "unavailable",
                reason: Some(reason.clone()),
            },
            PlatformFeatureState::Unknown => Self {
                state: "unknown",
                reason: state.denial_reason().map(ToString::to_string),
            },
        }
    }
}

#[derive(Serialize)]
struct JsonCertificateStatus {
    state: &'static str,
    subject: Option<String>,
    fingerprint_sha256: Option<String>,
}

impl From<&PlatformCapabilityStatus> for JsonCertificateStatus {
    fn from(status: &PlatformCapabilityStatus) -> Self {
        Self {
            state: certificate_state_name(status.mitm_certificate.state),
            subject: status.mitm_certificate.subject.clone(),
            fingerprint_sha256: status.mitm_certificate.fingerprint_sha256.clone(),
        }
    }
}
