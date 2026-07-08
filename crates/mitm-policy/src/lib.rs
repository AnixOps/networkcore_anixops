//! Safe `mitm_anixops` policy adapter for NetworkCore.
//!
//! This crate owns the first domain-facing MITM policy boundary. It can load
//! plugin text through the pinned C ABI, expose stable diagnostics, and provide
//! an alpha built-in ad-block plugin package. It does not apply live
//! request/response mutations yet.

use control_domain::{
    AuditDecision, AuditEvent, CertificateTrustState, Diagnostic, DiagnosticSeverity, DomainError,
    DomainResult, GrantedPermissions, HookPoint, HttpEvent, MitmPluginService, PluginInstance,
    PluginManifest, PluginPackage, PluginPermission, PluginResult,
};
use mitm_anixops_sys as sys;
use std::cell::Cell;
use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int};
use std::ptr::NonNull;

pub const SOURCE_MITM_POLICY: &str = "mitm.policy";

pub const MITM_POLICY_AD_BLOCK_PLUGIN_ID: &str = "networkcore.adblock";
pub const MITM_POLICY_ENGINE_ALLOC_FAILED_CODE: &str = "mitm.policy.engine.alloc_failed";
pub const MITM_POLICY_INPUT_NUL_BYTE_CODE: &str = "mitm.policy.input.nul_byte";
pub const MITM_POLICY_CONFIG_LOADED_CODE: &str = "mitm.policy.config.loaded";
pub const MITM_POLICY_CONFIG_PARSE_FAILED_CODE: &str = "mitm.policy.config.parse_failed";
pub const MITM_POLICY_RULE_ACCEPTED_CODE: &str = "mitm.policy.rule.accepted";
pub const MITM_POLICY_RULE_IGNORED_CODE: &str = "mitm.policy.rule.ignored";
pub const MITM_POLICY_RULE_REJECTED_CODE: &str = "mitm.policy.rule.rejected";
pub const MITM_POLICY_EVALUATION_FAILED_CODE: &str = "mitm.policy.evaluation.failed";
pub const MITM_POLICY_HEADER_LIST_CAPACITY_CODE: &str = "mitm.policy.header_list.capacity";
pub const MITM_POLICY_MANIFEST_ID_EMPTY_CODE: &str = "mitm.policy.manifest.id_empty";
pub const MITM_POLICY_MANIFEST_HOOK_MISSING_CODE: &str = "mitm.policy.manifest.hook_missing";
pub const MITM_POLICY_MANIFEST_PERMISSION_MISSING_CODE: &str =
    "mitm.policy.manifest.permission_missing";
pub const MITM_POLICY_PERMISSION_DENIED_CODE: &str = "mitm.policy.permission.denied";
pub const MITM_POLICY_HTTP_EVENT_MUTATION_DEFERRED_CODE: &str =
    "mitm.policy.http_event.mutation_deferred";
pub const MITM_POLICY_HTTP_EVENT_MUTATION_DEFERRED_MESSAGE: &str = concat!(
    "mitm_anixops policy loaded, but request/response mutation is deferred until ",
    "NetworkCore has a MITM mutation model and HTTP/TLS data plane",
);

pub const BUILTIN_AD_BLOCK_PLUGIN_SOURCE: &str = concat!(
    "[Plugin]\n",
    "name = NetworkCore Builtin Ad Block\n",
    "desc = Alpha ad blocking policy pack\n",
    "\n",
    "[URL Rewrite]\n",
    "^https?://.*doubleclick\\.net/ reject\n",
    "^https?://.*googlesyndication\\.com/ reject\n",
    "^https?://.*google-analytics\\.com/ reject\n",
    "^https?://.*adservice\\.google\\.com/ reject\n",
    "^https?://.*adsystem\\.com/ reject\n",
    "\n",
    "[MITM]\n",
    "enable = true\n",
    "hostname = %APPEND% *.doubleclick.net, *.googlesyndication.com, ",
    "*.google-analytics.com, *.adservice.google.com, *.adsystem.com\n",
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyLoadReport {
    pub version: String,
    pub mitm_pattern_count: usize,
    pub rewrite_rule_count: usize,
    pub script_rule_count: usize,
    pub argument_count: usize,
    pub rule_diagnostics: Vec<MitmPolicyRuleDiagnostic>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitmPolicyRuleDiagnosticStatus {
    Accepted,
    Ignored,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyRuleDiagnostic {
    pub status: MitmPolicyRuleDiagnosticStatus,
    pub line: usize,
    pub section: String,
    pub action: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitmPolicyPhase {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitmPolicyMitmDecisionType {
    Bypass,
    Intercept,
    RejectQuic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyMitmDecision {
    pub decision: MitmPolicyMitmDecisionType,
    pub reason: String,
    pub matched_pattern: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitmPolicyRewriteAction {
    None,
    Redirect,
    Reject,
    BodyMutation,
    HeaderMutation,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyRewriteResult {
    pub action: MitmPolicyRewriteAction,
    pub status_code: i32,
    pub rule_index: i32,
    pub matched_pattern: String,
    pub value: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyBodyRewriteChain {
    pub rewrites: Vec<MitmPolicyRewriteResult>,
    pub rewritten: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyHeaderRewriteResult {
    pub action: MitmPolicyRewriteAction,
    pub phase: MitmPolicyPhase,
    pub rule_index: i32,
    pub matched_pattern: String,
    pub header_name: String,
    pub value: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyHeaderField {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyHeaderList {
    pub fields: Vec<MitmPolicyHeaderField>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MitmPolicyScriptKind {
    None,
    HttpRequest,
    HttpResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyScriptDispatch {
    pub kind: MitmPolicyScriptKind,
    pub phase: MitmPolicyPhase,
    pub requires_body: bool,
    pub timeout_ms: usize,
    pub max_size: usize,
    pub rule_index: i32,
    pub matched_pattern: String,
    pub script_path: String,
    pub tag: String,
    pub argument: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MitmPolicyRewritePlan {
    pub phase: MitmPolicyPhase,
    pub body_available: bool,
    pub requires_body: bool,
    pub rewrite: MitmPolicyRewriteResult,
    pub header_rewrites: Vec<MitmPolicyHeaderRewriteResult>,
    pub header_rewrite_truncated: bool,
    pub script: MitmPolicyScriptDispatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MitmPolicyLastError {
    status: c_int,
    line: usize,
    message: String,
}

pub struct AnixOpsMitmPolicyEngine {
    raw: NonNull<sys::AnixOpsEngine>,
    _not_sync: PhantomData<Cell<()>>,
}

impl AnixOpsMitmPolicyEngine {
    pub fn new() -> DomainResult<Self> {
        let raw = unsafe { sys::anixops_engine_new() };
        let raw = NonNull::new(raw).ok_or_else(|| {
            DomainError::new(
                MITM_POLICY_ENGINE_ALLOC_FAILED_CODE,
                "mitm_anixops engine allocation failed",
            )
        })?;

        Ok(Self {
            raw,
            _not_sync: PhantomData,
        })
    }

    pub fn load_config(&mut self, config_text: &str) -> DomainResult<MitmPolicyLoadReport> {
        let config = CString::new(config_text).map_err(|_| {
            DomainError::new(
                MITM_POLICY_INPUT_NUL_BYTE_CODE,
                "mitm plugin config contains an unsupported nul byte",
            )
        })?;

        let status = unsafe {
            sys::anixops_engine_clear(self.raw.as_ptr());
            sys::anixops_engine_load_config(self.raw.as_ptr(), config.as_ptr())
        };
        let rule_diagnostics = self.rule_diagnostics();

        if status != sys::ANIXOPS_OK {
            let last_error = self.last_error();
            let message = if last_error.message.is_empty() || last_error.message == "ok" {
                status_message(last_error.status)
            } else {
                last_error.message
            };
            return Err(DomainError::new(
                MITM_POLICY_CONFIG_PARSE_FAILED_CODE,
                format!(
                    "mitm_anixops config load failed at line {}: {}",
                    last_error.line, message
                ),
            ));
        }

        let mut diagnostics = vec![mitm_policy_diagnostic(
            DiagnosticSeverity::Info,
            MITM_POLICY_CONFIG_LOADED_CODE,
            "mitm_anixops policy config loaded",
        )];
        diagnostics.extend(rule_diagnostics.iter().map(rule_diagnostic_to_domain));

        let mitm_pattern_count =
            unsafe { sys::anixops_engine_mitm_pattern_count(self.raw.as_ptr()) };
        let rewrite_rule_count =
            unsafe { sys::anixops_engine_rewrite_rule_count(self.raw.as_ptr()) };
        let script_rule_count = unsafe { sys::anixops_engine_script_rule_count(self.raw.as_ptr()) };
        let argument_count = unsafe { sys::anixops_engine_argument_count(self.raw.as_ptr()) };

        Ok(MitmPolicyLoadReport {
            version: sys::version().to_string(),
            mitm_pattern_count,
            rewrite_rule_count,
            script_rule_count,
            argument_count,
            rule_diagnostics,
            diagnostics,
        })
    }

    pub fn set_jq_max_input_bytes(&mut self, max_input_bytes: usize) -> DomainResult<()> {
        let status = unsafe {
            sys::anixops_engine_set_jq_max_input_bytes(self.raw.as_ptr(), max_input_bytes)
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        Ok(())
    }

    pub fn jq_max_input_bytes(&self) -> usize {
        unsafe { sys::anixops_engine_jq_max_input_bytes(self.raw.as_ptr()) }
    }

    pub fn set_certificate_trust_state(&mut self, state: CertificateTrustState) {
        let state = match state {
            CertificateTrustState::NotInstalled => sys::AnixOpsCertState::NotInstalled,
            CertificateTrustState::InstalledUntrusted => sys::AnixOpsCertState::InstalledUntrusted,
            CertificateTrustState::Trusted => sys::AnixOpsCertState::Trusted,
            CertificateTrustState::Revoked => sys::AnixOpsCertState::Revoked,
            CertificateTrustState::Unknown => sys::AnixOpsCertState::Unknown,
        };

        unsafe { sys::anixops_engine_set_cert_state(self.raw.as_ptr(), state) };
    }

    pub fn evaluate_mitm(
        &self,
        hostname: &str,
        is_quic: bool,
    ) -> DomainResult<MitmPolicyMitmDecision> {
        let hostname = CString::new(hostname).map_err(|_| {
            DomainError::new(
                MITM_POLICY_INPUT_NUL_BYTE_CODE,
                "mitm hostname contains an unsupported nul byte",
            )
        })?;
        let mut out = MaybeUninit::<sys::AnixOpsMitmDecision>::uninit();
        let status = unsafe {
            sys::anixops_mitm_evaluate(
                self.raw.as_ptr(),
                hostname.as_ptr(),
                if is_quic { 1 } else { 0 },
                out.as_mut_ptr(),
            )
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        let out = unsafe { out.assume_init() };
        Ok(MitmPolicyMitmDecision {
            decision: match out.decision {
                sys::AnixOpsMitmDecisionType::Bypass => MitmPolicyMitmDecisionType::Bypass,
                sys::AnixOpsMitmDecisionType::Intercept => MitmPolicyMitmDecisionType::Intercept,
                sys::AnixOpsMitmDecisionType::RejectQuic => MitmPolicyMitmDecisionType::RejectQuic,
            },
            reason: format!("{:?}", out.reason),
            matched_pattern: ffi_string(&out.matched_pattern),
            message: ffi_string(&out.message),
        })
    }

    pub fn evaluate_url_rewrite(
        &self,
        url: &str,
        phase: MitmPolicyPhase,
    ) -> DomainResult<MitmPolicyRewriteResult> {
        let url = CString::new(url).map_err(|_| {
            DomainError::new(
                MITM_POLICY_INPUT_NUL_BYTE_CODE,
                "mitm URL contains an unsupported nul byte",
            )
        })?;
        let mut out = MaybeUninit::<sys::AnixOpsRewriteResult>::uninit();
        let status = unsafe {
            sys::anixops_rewrite_evaluate_url(
                self.raw.as_ptr(),
                url.as_ptr(),
                phase.into(),
                out.as_mut_ptr(),
            )
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        let out = unsafe { out.assume_init() };
        Ok(rewrite_result_from_sys(&out))
    }

    pub fn apply_body_chain(
        &self,
        url: &str,
        phase: MitmPolicyPhase,
        body: &str,
    ) -> DomainResult<(String, MitmPolicyBodyRewriteChain)> {
        let url = c_string(url, "mitm URL contains an unsupported nul byte")?;
        let body = c_string(body, "mitm body contains an unsupported nul byte")?;
        let mut out_body = vec![0 as c_char; body.as_bytes().len() + sys::ANIXOPS_VALUE_CAP];
        let mut out_chain = empty_body_rewrite_chain();
        let status = unsafe {
            sys::anixops_rewrite_apply_body_chain(
                self.raw.as_ptr(),
                url.as_ptr(),
                phase.into(),
                body.as_ptr(),
                out_body.as_mut_ptr(),
                out_body.len(),
                &mut out_chain,
            )
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        Ok((
            ffi_string(&out_body),
            body_rewrite_chain_from_sys(&out_chain),
        ))
    }

    pub fn evaluate_named_header(
        &self,
        url: &str,
        phase: MitmPolicyPhase,
        start_index: usize,
        header_name: &str,
        current_header_value: &str,
    ) -> DomainResult<MitmPolicyHeaderRewriteResult> {
        let url = c_string(url, "mitm URL contains an unsupported nul byte")?;
        let header_name = c_string(
            header_name,
            "mitm header name contains an unsupported nul byte",
        )?;
        let current_header_value = c_string(
            current_header_value,
            "mitm header value contains an unsupported nul byte",
        )?;
        let mut out = MaybeUninit::<sys::AnixOpsHeaderRewriteResult>::uninit();
        let status = unsafe {
            sys::anixops_rewrite_evaluate_named_header(
                self.raw.as_ptr(),
                url.as_ptr(),
                phase.into(),
                start_index,
                header_name.as_ptr(),
                current_header_value.as_ptr(),
                out.as_mut_ptr(),
            )
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        let out = unsafe { out.assume_init() };
        Ok(header_rewrite_result_from_sys(&out))
    }

    pub fn apply_headers(
        &self,
        url: &str,
        phase: MitmPolicyPhase,
        headers: &[MitmPolicyHeaderField],
    ) -> DomainResult<(MitmPolicyHeaderList, MitmPolicyRewritePlan)> {
        let url = c_string(url, "mitm URL contains an unsupported nul byte")?;
        let headers = header_list_to_sys(headers)?;
        let mut out_headers = empty_header_list();
        let mut out_plan = empty_rewrite_plan();
        let status = unsafe {
            sys::anixops_rewrite_apply_headers(
                self.raw.as_ptr(),
                url.as_ptr(),
                phase.into(),
                &headers,
                &mut out_headers,
                &mut out_plan,
            )
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        Ok((
            header_list_from_sys(&out_headers),
            rewrite_plan_from_sys(&out_plan),
        ))
    }

    pub fn evaluate_script(
        &self,
        url: &str,
        phase: MitmPolicyPhase,
    ) -> DomainResult<MitmPolicyScriptDispatch> {
        let url = c_string(url, "mitm URL contains an unsupported nul byte")?;
        let mut out = MaybeUninit::<sys::AnixOpsScriptResult>::uninit();
        let status = unsafe {
            sys::anixops_script_evaluate_url(
                self.raw.as_ptr(),
                url.as_ptr(),
                phase.into(),
                out.as_mut_ptr(),
            )
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        let out = unsafe { out.assume_init() };
        Ok(script_dispatch_from_sys(&out))
    }

    pub fn build_rewrite_plan(
        &self,
        url: &str,
        phase: MitmPolicyPhase,
        body: &str,
    ) -> DomainResult<(MitmPolicyRewritePlan, String)> {
        let url = c_string(url, "mitm URL contains an unsupported nul byte")?;
        let body = c_string(body, "mitm body contains an unsupported nul byte")?;
        let mut out_body = vec![0 as c_char; body.as_bytes().len() + sys::ANIXOPS_VALUE_CAP];
        let mut out_plan = empty_rewrite_plan();
        let status = unsafe {
            sys::anixops_rewrite_build_plan(
                self.raw.as_ptr(),
                url.as_ptr(),
                phase.into(),
                body.as_ptr(),
                out_body.as_mut_ptr(),
                out_body.len(),
                std::ptr::null(),
                &mut out_plan,
            )
        };
        if status != sys::ANIXOPS_OK {
            return Err(evaluation_error(status));
        }

        Ok((rewrite_plan_from_sys(&out_plan), ffi_string(&out_body)))
    }

    fn rule_diagnostics(&self) -> Vec<MitmPolicyRuleDiagnostic> {
        let count = unsafe { sys::anixops_engine_rule_diagnostic_count(self.raw.as_ptr()) };
        let mut diagnostics = Vec::with_capacity(count);

        for index in 0..count {
            let mut out = MaybeUninit::<sys::AnixOpsRuleDiagnostic>::uninit();
            let status = unsafe {
                sys::anixops_engine_copy_rule_diagnostic(self.raw.as_ptr(), index, out.as_mut_ptr())
            };
            if status != sys::ANIXOPS_OK {
                continue;
            }

            let out = unsafe { out.assume_init() };
            diagnostics.push(MitmPolicyRuleDiagnostic {
                status: match out.status {
                    sys::AnixOpsRuleDiagnosticStatus::Accepted => {
                        MitmPolicyRuleDiagnosticStatus::Accepted
                    }
                    sys::AnixOpsRuleDiagnosticStatus::Ignored => {
                        MitmPolicyRuleDiagnosticStatus::Ignored
                    }
                    sys::AnixOpsRuleDiagnosticStatus::Rejected => {
                        MitmPolicyRuleDiagnosticStatus::Rejected
                    }
                },
                line: out.line,
                section: ffi_string(&out.section),
                action: ffi_string(&out.action),
                message: ffi_string(&out.message),
            });
        }

        diagnostics
    }

    fn last_error(&self) -> MitmPolicyLastError {
        let mut status = sys::ANIXOPS_OK;
        let mut line = 0usize;
        let mut message = [0 as c_char; sys::ANIXOPS_MESSAGE_CAP];
        let rc = unsafe {
            sys::anixops_engine_copy_last_error(
                self.raw.as_ptr(),
                &mut status,
                &mut line,
                message.as_mut_ptr(),
                message.len(),
            )
        };

        if rc != sys::ANIXOPS_OK {
            return MitmPolicyLastError {
                status: rc,
                line: 0,
                message: status_message(rc),
            };
        }

        MitmPolicyLastError {
            status,
            line,
            message: ffi_string(&message),
        }
    }
}

impl Drop for AnixOpsMitmPolicyEngine {
    fn drop(&mut self) {
        unsafe { sys::anixops_engine_free(self.raw.as_ptr()) };
    }
}

impl From<MitmPolicyPhase> for sys::AnixOpsPhase {
    fn from(value: MitmPolicyPhase) -> Self {
        match value {
            MitmPolicyPhase::Request => Self::Request,
            MitmPolicyPhase::Response => Self::Response,
        }
    }
}

impl From<sys::AnixOpsPhase> for MitmPolicyPhase {
    fn from(value: sys::AnixOpsPhase) -> Self {
        match value {
            sys::AnixOpsPhase::Request => Self::Request,
            sys::AnixOpsPhase::Response => Self::Response,
        }
    }
}

impl From<sys::AnixOpsRewriteAction> for MitmPolicyRewriteAction {
    fn from(value: sys::AnixOpsRewriteAction) -> Self {
        match value {
            sys::AnixOpsRewriteAction::None => Self::None,
            sys::AnixOpsRewriteAction::Redirect301
            | sys::AnixOpsRewriteAction::Redirect302
            | sys::AnixOpsRewriteAction::Redirect303
            | sys::AnixOpsRewriteAction::Redirect307
            | sys::AnixOpsRewriteAction::Redirect308 => Self::Redirect,
            sys::AnixOpsRewriteAction::Reject
            | sys::AnixOpsRewriteAction::Reject200
            | sys::AnixOpsRewriteAction::RejectImg
            | sys::AnixOpsRewriteAction::RejectVideo
            | sys::AnixOpsRewriteAction::RejectDict
            | sys::AnixOpsRewriteAction::RejectArray => Self::Reject,
            sys::AnixOpsRewriteAction::MockRequestBody
            | sys::AnixOpsRewriteAction::MockResponseBody
            | sys::AnixOpsRewriteAction::RequestBodyReplaceRegex
            | sys::AnixOpsRewriteAction::ResponseBodyReplaceRegex
            | sys::AnixOpsRewriteAction::RequestBodyJsonReplace
            | sys::AnixOpsRewriteAction::ResponseBodyJsonReplace
            | sys::AnixOpsRewriteAction::RequestBodyJq
            | sys::AnixOpsRewriteAction::ResponseBodyJq => Self::BodyMutation,
            sys::AnixOpsRewriteAction::HeaderReplace
            | sys::AnixOpsRewriteAction::HeaderAdd
            | sys::AnixOpsRewriteAction::HeaderReplaceRegex
            | sys::AnixOpsRewriteAction::ResponseHeaderDel
            | sys::AnixOpsRewriteAction::ResponseHeaderReplace
            | sys::AnixOpsRewriteAction::ResponseHeaderAdd
            | sys::AnixOpsRewriteAction::ResponseHeaderReplaceRegex
            | sys::AnixOpsRewriteAction::HeaderDel => Self::HeaderMutation,
        }
    }
}

impl From<sys::AnixOpsScriptKind> for MitmPolicyScriptKind {
    fn from(value: sys::AnixOpsScriptKind) -> Self {
        match value {
            sys::AnixOpsScriptKind::None => Self::None,
            sys::AnixOpsScriptKind::HttpRequest => Self::HttpRequest,
            sys::AnixOpsScriptKind::HttpResponse => Self::HttpResponse,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct AnixOpsMitmPluginService;

impl AnixOpsMitmPluginService {
    pub const fn new() -> Self {
        Self
    }
}

impl MitmPluginService for AnixOpsMitmPluginService {
    fn validate_manifest(&self, plugin_manifest: &PluginManifest) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        if plugin_manifest.id.trim().is_empty() {
            diagnostics.push(mitm_policy_diagnostic(
                DiagnosticSeverity::Error,
                MITM_POLICY_MANIFEST_ID_EMPTY_CODE,
                "MITM plugin manifest id cannot be empty",
            ));
        }

        if plugin_manifest.hooks.is_empty() {
            diagnostics.push(mitm_policy_diagnostic(
                DiagnosticSeverity::Error,
                MITM_POLICY_MANIFEST_HOOK_MISSING_CODE,
                "MITM plugin manifest must declare request or response hooks",
            ));
        }

        let can_read_http = plugin_manifest.permissions.iter().any(|permission| {
            matches!(
                permission,
                PluginPermission::ReadRequest | PluginPermission::ReadResponse
            )
        });
        if !can_read_http {
            diagnostics.push(mitm_policy_diagnostic(
                DiagnosticSeverity::Error,
                MITM_POLICY_MANIFEST_PERMISSION_MISSING_CODE,
                "MITM plugin manifest must request request or response read permission",
            ));
        }

        diagnostics
    }

    fn load(
        &self,
        plugin_package: &PluginPackage,
        granted_permissions: &GrantedPermissions,
    ) -> DomainResult<PluginInstance> {
        reject_error_diagnostics(
            self.validate_manifest(&plugin_package.manifest),
            "MITM plugin manifest is invalid",
        )?;

        for permission in &plugin_package.manifest.permissions {
            if !permission_granted(granted_permissions, permission) {
                return Err(DomainError::new(
                    MITM_POLICY_PERMISSION_DENIED_CODE,
                    "MITM plugin requested a permission that was not granted",
                ));
            }
        }

        let mut engine = AnixOpsMitmPolicyEngine::new()?;
        engine.load_config(&plugin_package.source)?;

        Ok(PluginInstance {
            manifest: plugin_package.manifest.clone(),
        })
    }

    fn handle_http_event(
        &self,
        plugin_instance: &PluginInstance,
        http_event: &HttpEvent,
    ) -> DomainResult<PluginResult> {
        Ok(PluginResult {
            audits: vec![AuditEvent {
                actor: plugin_instance.manifest.id.clone(),
                action: "mitm.policy.handle_http_event".to_string(),
                decision: AuditDecision::Allowed,
                reason: Some(format!(
                    "request {} accepted by policy adapter; live HTTP mutation is deferred",
                    http_event.request_id
                )),
            }],
            diagnostics: vec![mitm_policy_diagnostic(
                DiagnosticSeverity::Warning,
                MITM_POLICY_HTTP_EVENT_MUTATION_DEFERRED_CODE,
                MITM_POLICY_HTTP_EVENT_MUTATION_DEFERRED_MESSAGE,
            )],
        })
    }

    fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent> {
        plugin_result.audits.clone()
    }
}

pub fn builtin_ad_block_plugin_package() -> PluginPackage {
    PluginPackage {
        manifest: PluginManifest {
            id: MITM_POLICY_AD_BLOCK_PLUGIN_ID.to_string(),
            version: "0.1.0-alpha".to_string(),
            permissions: vec![
                PluginPermission::ReadRequest,
                PluginPermission::ModifyRequest,
                PluginPermission::ReadResponse,
                PluginPermission::ModifyResponse,
            ],
            hooks: vec![HookPoint::Request, HookPoint::Response],
        },
        source: BUILTIN_AD_BLOCK_PLUGIN_SOURCE.to_string(),
    }
}

pub fn mitm_policy_diagnostic(
    severity: DiagnosticSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(
        severity,
        code,
        message,
        Some(SOURCE_MITM_POLICY.to_string()),
    )
}

fn reject_error_diagnostics(diagnostics: Vec<Diagnostic>, message: &str) -> DomainResult<()> {
    if let Some(diagnostic) = diagnostics
        .iter()
        .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    {
        return Err(DomainError::new(diagnostic.code.clone(), message));
    }

    Ok(())
}

fn permission_granted(
    granted_permissions: &GrantedPermissions,
    permission: &PluginPermission,
) -> bool {
    granted_permissions
        .permissions
        .iter()
        .any(|granted| granted == permission)
}

fn c_string(value: &str, message: &'static str) -> DomainResult<CString> {
    CString::new(value).map_err(|_| DomainError::new(MITM_POLICY_INPUT_NUL_BYTE_CODE, message))
}

fn rewrite_result_from_sys(result: &sys::AnixOpsRewriteResult) -> MitmPolicyRewriteResult {
    MitmPolicyRewriteResult {
        action: result.action.into(),
        status_code: result.status_code,
        rule_index: result.rule_index,
        matched_pattern: ffi_string(&result.matched_pattern),
        value: ffi_string(&result.value),
        message: ffi_string(&result.message),
    }
}

fn body_rewrite_chain_from_sys(chain: &sys::AnixOpsBodyRewriteChain) -> MitmPolicyBodyRewriteChain {
    let count = chain.rewrite_count.min(sys::ANIXOPS_BODY_CHAIN_CAP);
    let rewrites = chain
        .rewrites
        .iter()
        .take(count)
        .map(rewrite_result_from_sys)
        .collect();

    MitmPolicyBodyRewriteChain {
        rewrites,
        rewritten: chain.rewritten != 0,
        truncated: chain.truncated != 0,
    }
}

fn header_rewrite_result_from_sys(
    result: &sys::AnixOpsHeaderRewriteResult,
) -> MitmPolicyHeaderRewriteResult {
    MitmPolicyHeaderRewriteResult {
        action: result.action.into(),
        phase: result.phase.into(),
        rule_index: result.rule_index,
        matched_pattern: ffi_string(&result.matched_pattern),
        header_name: ffi_string(&result.header_name),
        value: ffi_string(&result.value),
        message: ffi_string(&result.message),
    }
}

fn header_list_to_sys(headers: &[MitmPolicyHeaderField]) -> DomainResult<sys::AnixOpsHeaderList> {
    if headers.len() > sys::ANIXOPS_HEADER_LIST_CAP {
        return Err(DomainError::new(
            MITM_POLICY_HEADER_LIST_CAPACITY_CODE,
            "mitm header list exceeds the C ABI capacity",
        ));
    }

    let mut out = empty_header_list();
    out.count = headers.len();
    for (index, field) in headers.iter().enumerate() {
        if write_str_to_buf(&mut out.fields[index].name, &field.name) {
            out.truncated = 1;
        }
        if write_str_to_buf(&mut out.fields[index].value, &field.value) {
            out.truncated = 1;
        }
    }

    Ok(out)
}

fn header_list_from_sys(headers: &sys::AnixOpsHeaderList) -> MitmPolicyHeaderList {
    let count = headers.count.min(sys::ANIXOPS_HEADER_LIST_CAP);
    let fields = headers
        .fields
        .iter()
        .take(count)
        .map(|field| MitmPolicyHeaderField {
            name: ffi_string(&field.name),
            value: ffi_string(&field.value),
        })
        .collect();

    MitmPolicyHeaderList {
        fields,
        truncated: headers.truncated != 0,
    }
}

fn script_dispatch_from_sys(result: &sys::AnixOpsScriptResult) -> MitmPolicyScriptDispatch {
    MitmPolicyScriptDispatch {
        kind: result.kind.into(),
        phase: result.phase.into(),
        requires_body: result.requires_body != 0,
        timeout_ms: result.timeout_ms,
        max_size: result.max_size,
        rule_index: result.rule_index,
        matched_pattern: ffi_string(&result.matched_pattern),
        script_path: ffi_string(&result.script_path),
        tag: ffi_string(&result.tag),
        argument: ffi_string(&result.argument),
        message: ffi_string(&result.message),
    }
}

fn rewrite_plan_from_sys(plan: &sys::AnixOpsRewritePlan) -> MitmPolicyRewritePlan {
    let count = plan.header_rewrite_count.min(sys::ANIXOPS_PLAN_HEADER_CAP);
    let header_rewrites = plan
        .header_rewrites
        .iter()
        .take(count)
        .map(header_rewrite_result_from_sys)
        .collect();

    MitmPolicyRewritePlan {
        phase: plan.phase.into(),
        body_available: plan.body_available != 0,
        requires_body: plan.requires_body != 0,
        rewrite: rewrite_result_from_sys(&plan.rewrite),
        header_rewrites,
        header_rewrite_truncated: plan.header_rewrite_truncated != 0,
        script: script_dispatch_from_sys(&plan.script),
    }
}

fn rule_diagnostic_to_domain(diagnostic: &MitmPolicyRuleDiagnostic) -> Diagnostic {
    let (severity, code) = match diagnostic.status {
        MitmPolicyRuleDiagnosticStatus::Accepted => {
            (DiagnosticSeverity::Info, MITM_POLICY_RULE_ACCEPTED_CODE)
        }
        MitmPolicyRuleDiagnosticStatus::Ignored => {
            (DiagnosticSeverity::Warning, MITM_POLICY_RULE_IGNORED_CODE)
        }
        MitmPolicyRuleDiagnosticStatus::Rejected => {
            (DiagnosticSeverity::Error, MITM_POLICY_RULE_REJECTED_CODE)
        }
    };

    mitm_policy_diagnostic(
        severity,
        code,
        format!(
            "mitm_anixops {} rule at line {} in {}: {}",
            match diagnostic.status {
                MitmPolicyRuleDiagnosticStatus::Accepted => "accepted",
                MitmPolicyRuleDiagnosticStatus::Ignored => "ignored",
                MitmPolicyRuleDiagnosticStatus::Rejected => "rejected",
            },
            diagnostic.line,
            diagnostic.section,
            diagnostic.message
        ),
    )
}

fn evaluation_error(status: c_int) -> DomainError {
    DomainError::new(
        MITM_POLICY_EVALUATION_FAILED_CODE,
        format!("mitm_anixops evaluation failed: {}", status_message(status)),
    )
}

fn status_message(status: c_int) -> String {
    let message = unsafe { CStr::from_ptr(sys::anixops_status_message(status)) };
    message.to_string_lossy().into_owned()
}

fn ffi_string(buffer: &[c_char]) -> String {
    let value = unsafe { CStr::from_ptr(buffer.as_ptr()) };
    value.to_string_lossy().into_owned()
}

fn write_str_to_buf(buffer: &mut [c_char], value: &str) -> bool {
    for slot in buffer.iter_mut() {
        *slot = 0;
    }
    if buffer.is_empty() {
        return !value.is_empty();
    }

    let bytes = value.as_bytes();
    let copy_len = bytes.len().min(buffer.len() - 1);
    for (index, byte) in bytes.iter().take(copy_len).enumerate() {
        buffer[index] = *byte as c_char;
    }

    bytes.len() >= buffer.len()
}

fn empty_rewrite_result() -> sys::AnixOpsRewriteResult {
    sys::AnixOpsRewriteResult {
        action: sys::AnixOpsRewriteAction::None,
        status_code: 0,
        rule_index: 0,
        matched_pattern: [0 as c_char; sys::ANIXOPS_PATTERN_CAP],
        value: [0 as c_char; sys::ANIXOPS_VALUE_CAP],
        message: [0 as c_char; sys::ANIXOPS_MESSAGE_CAP],
    }
}

fn empty_body_rewrite_chain() -> sys::AnixOpsBodyRewriteChain {
    sys::AnixOpsBodyRewriteChain {
        rewrite_count: 0,
        rewritten: 0,
        truncated: 0,
        rewrites: [empty_rewrite_result(); sys::ANIXOPS_BODY_CHAIN_CAP],
    }
}

fn empty_header_rewrite_result() -> sys::AnixOpsHeaderRewriteResult {
    sys::AnixOpsHeaderRewriteResult {
        action: sys::AnixOpsRewriteAction::None,
        phase: sys::AnixOpsPhase::Request,
        rule_index: 0,
        matched_pattern: [0 as c_char; sys::ANIXOPS_PATTERN_CAP],
        header_name: [0 as c_char; sys::ANIXOPS_PATTERN_CAP],
        value: [0 as c_char; sys::ANIXOPS_VALUE_CAP],
        message: [0 as c_char; sys::ANIXOPS_MESSAGE_CAP],
    }
}

fn empty_header_field() -> sys::AnixOpsHeaderField {
    sys::AnixOpsHeaderField {
        name: [0 as c_char; sys::ANIXOPS_PATTERN_CAP],
        value: [0 as c_char; sys::ANIXOPS_VALUE_CAP],
    }
}

fn empty_header_list() -> sys::AnixOpsHeaderList {
    sys::AnixOpsHeaderList {
        count: 0,
        truncated: 0,
        fields: [empty_header_field(); sys::ANIXOPS_HEADER_LIST_CAP],
    }
}

fn empty_script_result() -> sys::AnixOpsScriptResult {
    sys::AnixOpsScriptResult {
        kind: sys::AnixOpsScriptKind::None,
        phase: sys::AnixOpsPhase::Request,
        requires_body: 0,
        timeout_ms: 0,
        max_size: 0,
        rule_index: 0,
        matched_pattern: [0 as c_char; sys::ANIXOPS_PATTERN_CAP],
        script_path: [0 as c_char; sys::ANIXOPS_VALUE_CAP],
        tag: [0 as c_char; sys::ANIXOPS_VALUE_CAP],
        argument: [0 as c_char; sys::ANIXOPS_ARGUMENT_CAP],
        message: [0 as c_char; sys::ANIXOPS_MESSAGE_CAP],
    }
}

fn empty_rewrite_plan() -> sys::AnixOpsRewritePlan {
    sys::AnixOpsRewritePlan {
        phase: sys::AnixOpsPhase::Request,
        body_available: 0,
        requires_body: 0,
        rewrite: empty_rewrite_result(),
        header_rewrite_count: 0,
        header_rewrite_truncated: 0,
        header_rewrites: [empty_header_rewrite_result(); sys::ANIXOPS_PLAN_HEADER_CAP],
        script: empty_script_result(),
    }
}
