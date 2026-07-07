//! Unsafe Rust bindings for the vendored `mitm_anixops` C ABI.
//!
//! This crate deliberately exposes only the first proven ABI surface. Safe
//! policy abstractions belong in a later adapter crate.

use std::ffi::CStr;
use std::os::raw::c_char;

unsafe extern "C" {
    fn anixops_version() -> *const c_char;
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
        assert_eq!(version(), "0.3.0");
    }
}
