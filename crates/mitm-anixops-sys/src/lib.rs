//! Unsafe Rust bindings for the vendored `mitm_anixops` C ABI.
//!
//! This crate deliberately exposes only the low-level ABI surface. Safe policy
//! abstractions belong in the `mitm-policy` adapter crate.

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};

pub const ANIXOPS_PATTERN_CAP: usize = 256;
pub const ANIXOPS_VALUE_CAP: usize = 2048;
pub const ANIXOPS_ARGUMENT_CAP: usize = 4096;
pub const ANIXOPS_MESSAGE_CAP: usize = 256;

pub const ANIXOPS_OK: c_int = 0;
pub const ANIXOPS_ERR_INVALID_ARGUMENT: c_int = -1;
pub const ANIXOPS_ERR_OUT_OF_MEMORY: c_int = -2;
pub const ANIXOPS_ERR_REGEX: c_int = -3;
pub const ANIXOPS_ERR_CAPACITY: c_int = -4;
pub const ANIXOPS_ERR_PARSE: c_int = -5;

#[repr(C)]
pub struct AnixOpsEngine {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsCertState {
    Unknown = 0,
    NotInstalled = 1,
    InstalledUntrusted = 2,
    Trusted = 3,
    Revoked = 4,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsMitmDecisionType {
    Bypass = 0,
    Intercept = 1,
    RejectQuic = 2,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsMitmReason {
    None = 0,
    Disabled = 1,
    EmptyHost = 2,
    CertNotTrusted = 3,
    DenyHost = 4,
    NoHostMatch = 5,
    QuicDisabledForMitm = 6,
    Allowed = 7,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsPhase {
    Request = 0,
    Response = 1,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsCompatProfile {
    Portable = 0,
    LoonStrict = 1,
    SurgeStrict = 2,
    QuantumultXStrict = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsRuleDiagnosticStatus {
    Accepted = 1,
    Ignored = 2,
    Rejected = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnixOpsRewriteAction {
    None = 0,
    Redirect302 = 1,
    Redirect307 = 2,
    Reject = 3,
    Reject200 = 4,
    RejectImg = 5,
    RejectVideo = 6,
    RejectDict = 7,
    RejectArray = 8,
    MockRequestBody = 9,
    MockResponseBody = 10,
    RequestBodyReplaceRegex = 11,
    ResponseBodyReplaceRegex = 12,
    HeaderReplace = 13,
    HeaderAdd = 14,
    HeaderReplaceRegex = 15,
    ResponseHeaderDel = 16,
    ResponseHeaderReplace = 17,
    ResponseHeaderAdd = 18,
    ResponseHeaderReplaceRegex = 19,
    RequestBodyJsonReplace = 20,
    ResponseBodyJsonReplace = 21,
    Redirect301 = 22,
    Redirect303 = 23,
    Redirect308 = 24,
    HeaderDel = 25,
    RequestBodyJq = 26,
    ResponseBodyJq = 27,
}

#[repr(C)]
pub struct AnixOpsMitmDecision {
    pub decision: AnixOpsMitmDecisionType,
    pub reason: AnixOpsMitmReason,
    pub matched_pattern: [c_char; ANIXOPS_PATTERN_CAP],
    pub message: [c_char; ANIXOPS_MESSAGE_CAP],
}

#[repr(C)]
pub struct AnixOpsRewriteResult {
    pub action: AnixOpsRewriteAction,
    pub status_code: c_int,
    pub rule_index: c_int,
    pub matched_pattern: [c_char; ANIXOPS_PATTERN_CAP],
    pub value: [c_char; ANIXOPS_VALUE_CAP],
    pub message: [c_char; ANIXOPS_MESSAGE_CAP],
}

#[repr(C)]
pub struct AnixOpsRuleDiagnostic {
    pub status: AnixOpsRuleDiagnosticStatus,
    pub profile: AnixOpsCompatProfile,
    pub line: usize,
    pub section: [c_char; ANIXOPS_PATTERN_CAP],
    pub action: [c_char; ANIXOPS_PATTERN_CAP],
    pub message: [c_char; ANIXOPS_MESSAGE_CAP],
}

unsafe extern "C" {
    pub fn anixops_version() -> *const c_char;
    pub fn anixops_status_message(status: c_int) -> *const c_char;
    pub fn anixops_engine_new() -> *mut AnixOpsEngine;
    pub fn anixops_engine_free(engine: *mut AnixOpsEngine);
    pub fn anixops_engine_clear(engine: *mut AnixOpsEngine);
    pub fn anixops_engine_copy_last_error(
        engine: *const AnixOpsEngine,
        out_status: *mut c_int,
        out_line: *mut usize,
        out_message: *mut c_char,
        out_message_cap: usize,
    ) -> c_int;
    pub fn anixops_engine_set_compat_profile(
        engine: *mut AnixOpsEngine,
        profile: AnixOpsCompatProfile,
    ) -> c_int;
    pub fn anixops_engine_rule_diagnostic_count(engine: *const AnixOpsEngine) -> usize;
    pub fn anixops_engine_copy_rule_diagnostic(
        engine: *const AnixOpsEngine,
        index: usize,
        out_diagnostic: *mut AnixOpsRuleDiagnostic,
    ) -> c_int;
    pub fn anixops_engine_load_config(
        engine: *mut AnixOpsEngine,
        config_text: *const c_char,
    ) -> c_int;
    pub fn anixops_engine_set_cert_state(engine: *mut AnixOpsEngine, state: AnixOpsCertState);
    pub fn anixops_mitm_evaluate(
        engine: *const AnixOpsEngine,
        hostname: *const c_char,
        is_quic: c_int,
        out_decision: *mut AnixOpsMitmDecision,
    ) -> c_int;
    pub fn anixops_rewrite_evaluate_url(
        engine: *const AnixOpsEngine,
        url: *const c_char,
        phase: AnixOpsPhase,
        out_result: *mut AnixOpsRewriteResult,
    ) -> c_int;
    pub fn anixops_engine_mitm_pattern_count(engine: *const AnixOpsEngine) -> usize;
    pub fn anixops_engine_rewrite_rule_count(engine: *const AnixOpsEngine) -> usize;
    pub fn anixops_engine_script_rule_count(engine: *const AnixOpsEngine) -> usize;
    pub fn anixops_engine_argument_count(engine: *const AnixOpsEngine) -> usize;
}

/// Returns the version reported by the linked `mitm_anixops` C core.
pub fn version() -> &'static str {
    // SAFETY: `anixops_version` returns a non-null pointer to a static
    // NUL-terminated string owned by the C library.
    let version = unsafe { CStr::from_ptr(anixops_version()) };
    version
        .to_str()
        .expect("mitm_anixops version must be valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linked_c_core_reports_pinned_version() {
        assert_eq!(version(), "0.41.0");
    }

    #[test]
    fn low_level_engine_loads_minimal_config() {
        let config = std::ffi::CString::new(concat!(
            "[URL Rewrite]\n",
            "^https://ads\\.example\\.test reject\n",
            "[MITM]\n",
            "hostname = ads.example.test\n",
        ))
        .expect("fixture must not contain nul bytes");

        // SAFETY: the C engine pointer is checked for null, the config is a
        // valid NUL-terminated string, and the engine is freed exactly once.
        unsafe {
            let engine = anixops_engine_new();
            assert!(!engine.is_null());
            assert_eq!(anixops_engine_load_config(engine, config.as_ptr()), ANIXOPS_OK);
            assert_eq!(anixops_engine_rewrite_rule_count(engine), 1);
            assert_eq!(anixops_engine_mitm_pattern_count(engine), 1);
            anixops_engine_free(engine);
        }
    }
}
