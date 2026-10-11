//! Pure admission gate for applying released MITM policy capabilities to a
//! previously verified Plan B SD-WAN client delivery envelope.

use config_core::sdwan_delivery::{
    normalize_hostname_for_allowed_suffix, DeliveryProfile, VerifiedDeliveryEnvelope,
};
use control_domain::{CertificateTrustState, DomainError, DomainResult};
use mitm_anixops_sys::{
    policy_capabilities, policy_capability_query_abi_version, POLICY_CAPABILITY_ALL_V1,
    POLICY_CAPABILITY_MITM_DECISION, POLICY_CAPABILITY_QUERY_ABI_VERSION,
};
use time::OffsetDateTime;

pub const MANAGED_SDWAN_MITM_CORE_QUERY_ABI_UNSUPPORTED_CODE: &str =
    "managed.sdwan.mitm.core_query_abi_unsupported";
pub const MANAGED_SDWAN_MITM_CORE_CAPABILITY_UNKNOWN_CODE: &str =
    "managed.sdwan.mitm.core_capability_unknown";
pub const MANAGED_SDWAN_MITM_REQUIRED_CAPABILITY_UNKNOWN_CODE: &str =
    "managed.sdwan.mitm.required_capability_unknown";
pub const MANAGED_SDWAN_MITM_CORE_CAPABILITY_MISSING_CODE: &str =
    "managed.sdwan.mitm.core_capability_missing";
pub const MANAGED_SDWAN_MITM_BUNDLE_KIND_INVALID_CODE: &str =
    "managed.sdwan.mitm.bundle_kind_invalid";
pub const MANAGED_SDWAN_MITM_PROFILE_PRINCIPAL_TARGET_MISMATCH_CODE: &str =
    "managed.sdwan.mitm.profile_principal_target_mismatch";
pub const MANAGED_SDWAN_MITM_MITM_PROFILE_MISSING_CODE: &str =
    "managed.sdwan.mitm.mitm_profile_missing";
pub const MANAGED_SDWAN_MITM_PROFILE_INVARIANT_INVALID_CODE: &str =
    "managed.sdwan.mitm.profile_invariant_invalid";
pub const MANAGED_SDWAN_MITM_CONSENT_REQUIRED_CODE: &str = "managed.sdwan.mitm.consent_required";
pub const MANAGED_SDWAN_MITM_CERTIFICATE_UNTRUSTED_CODE: &str =
    "managed.sdwan.mitm.certificate_untrusted";
pub const MANAGED_SDWAN_MITM_QUIC_BLOCKED_CODE: &str = "managed.sdwan.mitm.quic_blocked";
pub const MANAGED_SDWAN_MITM_PINNED_TLS_BLOCKED_CODE: &str =
    "managed.sdwan.mitm.pinned_tls_blocked";
pub const MANAGED_SDWAN_MITM_HOSTNAME_NOT_ALLOWED_CODE: &str =
    "managed.sdwan.mitm.hostname_not_allowed";
pub const MANAGED_SDWAN_MITM_DELIVERY_EXPIRED_CODE: &str = "managed.sdwan.mitm.delivery_expired";

/// Process-global C-core query values captured at gate construction time.
///
/// The linked core query is deterministic for the process. Capturing it once
/// gives every authorization decision a stable, auditable capability basis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ManagedSdwanMitmPolicyCoreSnapshot {
    pub(crate) query_abi_version: u32,
    pub(crate) capability_flags: u64,
}

impl ManagedSdwanMitmPolicyCoreSnapshot {
    pub(crate) fn from_linked_core() -> Self {
        Self::new(
            policy_capability_query_abi_version(),
            policy_capabilities().bits(),
        )
    }

    pub(crate) const fn new(query_abi_version: u32, capability_flags: u64) -> Self {
        Self {
            query_abi_version,
            capability_flags,
        }
    }
}

/// Immutable, pure gate for managed SD-WAN client MITM policy admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedSdwanMitmPolicyGate {
    core: ManagedSdwanMitmPolicyCoreSnapshot,
    required_capabilities: u64,
}

impl ManagedSdwanMitmPolicyGate {
    pub fn from_linked_core(required_capabilities: u64) -> DomainResult<Self> {
        Self::new(
            ManagedSdwanMitmPolicyCoreSnapshot::from_linked_core(),
            required_capabilities,
        )
    }

    pub(crate) fn new(
        core: ManagedSdwanMitmPolicyCoreSnapshot,
        required_capabilities: u64,
    ) -> DomainResult<Self> {
        if core.query_abi_version != POLICY_CAPABILITY_QUERY_ABI_VERSION {
            return Err(managed_error(
                MANAGED_SDWAN_MITM_CORE_QUERY_ABI_UNSUPPORTED_CODE,
                "linked MITM policy capability query ABI is unsupported",
            ));
        }
        if core.capability_flags & !POLICY_CAPABILITY_ALL_V1 != 0 {
            return Err(managed_error(
                MANAGED_SDWAN_MITM_CORE_CAPABILITY_UNKNOWN_CODE,
                "linked MITM policy capability query contains unknown flags",
            ));
        }
        if required_capabilities & !POLICY_CAPABILITY_ALL_V1 != 0 {
            return Err(managed_error(
                MANAGED_SDWAN_MITM_REQUIRED_CAPABILITY_UNKNOWN_CODE,
                "managed MITM policy requires unknown capability flags",
            ));
        }

        let required_capabilities = POLICY_CAPABILITY_MITM_DECISION | required_capabilities;
        if core.capability_flags & required_capabilities != required_capabilities {
            return Err(managed_error(
                MANAGED_SDWAN_MITM_CORE_CAPABILITY_MISSING_CODE,
                "linked MITM policy capability query does not satisfy managed admission",
            ));
        }

        Ok(Self {
            core,
            required_capabilities,
        })
    }

    /// Authorizes one immutable verified delivery using a caller-supplied
    /// current trusted service clock.
    pub fn authorize(
        &self,
        envelope: &VerifiedDeliveryEnvelope,
        hostname: &str,
        now: OffsetDateTime,
        host_state: ManagedSdwanMitmHostState,
    ) -> DomainResult<ManagedSdwanMitmPolicyGrant> {
        if now >= envelope.expires_at() {
            return Err(managed_error(
                MANAGED_SDWAN_MITM_DELIVERY_EXPIRED_CODE,
                "managed MITM admission requires a current verified delivery",
            ));
        }
        if envelope.bundle_kind() != "client" {
            return Err(managed_error(
                MANAGED_SDWAN_MITM_BUNDLE_KIND_INVALID_CODE,
                "managed MITM admission requires a verified client delivery",
            ));
        }

        let DeliveryProfile::Client(profile) = envelope.profile() else {
            return Err(managed_error(
                MANAGED_SDWAN_MITM_BUNDLE_KIND_INVALID_CODE,
                "managed MITM admission requires a client delivery profile",
            ));
        };
        if profile.principal_id != envelope.target_id() {
            return Err(managed_error(
                MANAGED_SDWAN_MITM_PROFILE_PRINCIPAL_TARGET_MISMATCH_CODE,
                "managed MITM client profile target does not match its principal",
            ));
        }
        let Some(mitm) = profile.mitm.as_ref() else {
            return Err(managed_error(
                MANAGED_SDWAN_MITM_MITM_PROFILE_MISSING_CODE,
                "managed MITM admission requires an explicit MITM profile",
            ));
        };
        if !mitm.require_consent || !mitm.block_quic || !mitm.block_pinned_tls {
            return Err(managed_error(
                MANAGED_SDWAN_MITM_PROFILE_INVARIANT_INVALID_CODE,
                "managed MITM profile does not preserve required safety invariants",
            ));
        }
        if !host_state.consent_granted {
            return Err(managed_error(
                MANAGED_SDWAN_MITM_CONSENT_REQUIRED_CODE,
                "managed MITM admission requires user consent",
            ));
        }
        if host_state.certificate_trust != CertificateTrustState::Trusted {
            return Err(managed_error(
                MANAGED_SDWAN_MITM_CERTIFICATE_UNTRUSTED_CODE,
                "managed MITM admission requires a trusted certificate",
            ));
        }
        if host_state.is_quic {
            return Err(managed_error(
                MANAGED_SDWAN_MITM_QUIC_BLOCKED_CODE,
                "managed MITM admission blocks QUIC observations",
            ));
        }
        if host_state.pinned_tls_detected {
            return Err(managed_error(
                MANAGED_SDWAN_MITM_PINNED_TLS_BLOCKED_CODE,
                "managed MITM admission blocks pinned TLS observations",
            ));
        }

        let normalized_hostname = mitm
            .allowed_domain_suffixes
            .iter()
            .find_map(|suffix| normalize_hostname_for_allowed_suffix(hostname, suffix))
            .ok_or_else(|| {
                managed_error(
                    MANAGED_SDWAN_MITM_HOSTNAME_NOT_ALLOWED_CODE,
                    "managed MITM hostname is outside the approved suffix boundary",
                )
            })?;

        Ok(ManagedSdwanMitmPolicyGrant {
            tenant_id: envelope.tenant_id().to_string(),
            bundle_id: envelope.bundle_id().to_string(),
            target_id: envelope.target_id().to_string(),
            sequence: envelope.sequence(),
            normalized_hostname,
            granted_capability_flags: self.core.capability_flags & self.required_capabilities,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedSdwanMitmHostState {
    pub consent_granted: bool,
    pub certificate_trust: CertificateTrustState,
    pub is_quic: bool,
    pub pinned_tls_detected: bool,
}

/// Non-secret evidence recorded only after managed MITM admission succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSdwanMitmPolicyGrant {
    pub tenant_id: String,
    pub bundle_id: String,
    pub target_id: String,
    pub sequence: u64,
    pub normalized_hostname: String,
    pub granted_capability_flags: u64,
}

fn managed_error(code: &'static str, message: &'static str) -> DomainError {
    DomainError::new(code, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mitm_anixops_sys::POLICY_CAPABILITY_URL_REWRITE;

    #[test]
    fn rejects_synthetic_core_snapshots_outside_released_contract() {
        assert_error_code(
            ManagedSdwanMitmPolicyGate::new(
                ManagedSdwanMitmPolicyCoreSnapshot::new(2, POLICY_CAPABILITY_ALL_V1),
                POLICY_CAPABILITY_MITM_DECISION,
            ),
            MANAGED_SDWAN_MITM_CORE_QUERY_ABI_UNSUPPORTED_CODE,
        );
        assert_error_code(
            ManagedSdwanMitmPolicyGate::new(
                ManagedSdwanMitmPolicyCoreSnapshot::new(
                    POLICY_CAPABILITY_QUERY_ABI_VERSION,
                    POLICY_CAPABILITY_ALL_V1 | (1_u64 << 63),
                ),
                POLICY_CAPABILITY_MITM_DECISION,
            ),
            MANAGED_SDWAN_MITM_CORE_CAPABILITY_UNKNOWN_CODE,
        );
        assert_error_code(
            ManagedSdwanMitmPolicyGate::new(
                ManagedSdwanMitmPolicyCoreSnapshot::new(
                    POLICY_CAPABILITY_QUERY_ABI_VERSION,
                    POLICY_CAPABILITY_MITM_DECISION,
                ),
                POLICY_CAPABILITY_URL_REWRITE,
            ),
            MANAGED_SDWAN_MITM_CORE_CAPABILITY_MISSING_CODE,
        );
        assert_error_code(
            ManagedSdwanMitmPolicyGate::new(
                ManagedSdwanMitmPolicyCoreSnapshot::new(
                    POLICY_CAPABILITY_QUERY_ABI_VERSION,
                    POLICY_CAPABILITY_ALL_V1,
                ),
                1_u64 << 63,
            ),
            MANAGED_SDWAN_MITM_REQUIRED_CAPABILITY_UNKNOWN_CODE,
        );
    }

    fn assert_error_code(result: DomainResult<ManagedSdwanMitmPolicyGate>, expected_code: &str) {
        let error = result.expect_err("synthetic core snapshot should be rejected");
        assert_eq!(error.code, expected_code);
    }
}
