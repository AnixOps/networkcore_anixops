//! Pure planning for the first Windows EasyTier tunnel slice.
//!
//! This module turns two already verified delivery envelopes into a redacted,
//! deterministic plan. It deliberately does not start processes, change routes,
//! read secrets, or perform any platform work.

use control_domain::{DomainError, DomainResult};
use ring::digest;
use time::OffsetDateTime;

use crate::sdwan_delivery::{
    DeliveryProfile, VerifiedDeliveryEnvelope, SDWAN_DELIVERY_TRANSPORT_EASYTIER,
};

pub const WINDOWS_TUNNEL_DELIVERY_INVALID_CODE: &str = "windows.tunnel.delivery_invalid";
pub const WINDOWS_TUNNEL_DELIVERY_EXPIRED_CODE: &str = "windows.tunnel.delivery_expired";
pub const WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE: &str = "windows.tunnel.sequence_replayed";
pub const WINDOWS_TUNNEL_TARGET_MISMATCH_CODE: &str = "windows.tunnel.target_mismatch";
pub const WINDOWS_TUNNEL_TENANT_MISMATCH_CODE: &str = "windows.tunnel.tenant_mismatch";
pub const WINDOWS_TUNNEL_TRANSPORT_UNSUPPORTED_CODE: &str =
    "windows.tunnel.transport_unsupported";
pub const WINDOWS_TUNNEL_POP_NOT_SELECTED_CODE: &str = "windows.tunnel.pop_not_selected";
pub const WINDOWS_TUNNEL_ROUTE_SELECTOR_UNSUPPORTED_CODE: &str =
    "windows.tunnel.route_selector_unsupported";
pub const WINDOWS_TUNNEL_SERVICE_CHAIN_INVALID_CODE: &str =
    "windows.tunnel.service_chain_invalid";

/// Compatibility alias for callers that describe a malformed envelope as a bundle error.
pub const WINDOWS_TUNNEL_BUNDLE_INVALID_CODE: &str = WINDOWS_TUNNEL_DELIVERY_INVALID_CODE;

/// Inputs required to derive a Windows EasyTier tunnel plan.
#[derive(Debug, Clone, Copy)]
pub struct WindowsTunnelPlanRequest<'a> {
    pub client: &'a VerifiedDeliveryEnvelope,
    pub pop: &'a VerifiedDeliveryEnvelope,
    pub device_id: &'a str,
    pub selected_pop_id: &'a str,
    pub last_client_sequence: Option<u64>,
    pub last_pop_sequence: Option<u64>,
    pub now: OffsetDateTime,
}

/// One IPv4 destination route to expose through the selected entry POP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsTunnelRouteIntent {
    pub route_id: String,
    pub destination_cidr: String,
    pub service_chain_id: String,
    pub direct_fallback: bool,
}

/// Secret-free instructions for a foreground EasyTier session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsTunnelPlan {
    pub session_id: String,
    pub tenant_id: String,
    pub client_bundle_id: String,
    pub pop_bundle_id: String,
    pub client_sequence: u64,
    pub pop_sequence: u64,
    pub selected_pop_id: String,
    pub selected_endpoint: String,
    pub route_intents: Vec<WindowsTunnelRouteIntent>,
    pub endpoint_bypass_required: bool,
    pub plan_digest: String,
}

/// Validates identity, replay floors, transport, POP selection, and route shape.
///
/// The two envelopes must have been produced by
/// [`crate::sdwan_delivery::SdwanDeliveryVerifier`]. Since
/// `VerifiedDeliveryEnvelope` is opaque, this function cannot be called with an
/// unverified payload or a caller-supplied secret.
pub fn plan_windows_tunnel(
    request: WindowsTunnelPlanRequest<'_>,
) -> DomainResult<WindowsTunnelPlan> {
    if request.client.bundle_kind() != "client" || request.pop.bundle_kind() != "pop" {
        return Err(tunnel_error(
            WINDOWS_TUNNEL_DELIVERY_INVALID_CODE,
            "delivery bundle kinds do not match the Windows tunnel contract",
        ));
    }

    if request.client.expires_at() <= request.now || request.pop.expires_at() <= request.now {
        return Err(tunnel_error(
            WINDOWS_TUNNEL_DELIVERY_EXPIRED_CODE,
            "one or more delivery bundles are expired",
        ));
    }

    if request
        .last_client_sequence
        .is_some_and(|floor| request.client.sequence() <= floor)
        || request
            .last_pop_sequence
            .is_some_and(|floor| request.pop.sequence() <= floor)
    {
        return Err(tunnel_error(
            WINDOWS_TUNNEL_SEQUENCE_REPLAYED_CODE,
            "delivery sequence is not newer than the persisted floor",
        ));
    }

    if request.client.tenant_id() != request.pop.tenant_id() {
        return Err(tunnel_error(
            WINDOWS_TUNNEL_TENANT_MISMATCH_CODE,
            "client and POP delivery tenants do not match",
        ));
    }

    if request.client.target_id() != request.device_id {
        return Err(tunnel_error(
            WINDOWS_TUNNEL_TARGET_MISMATCH_CODE,
            "client delivery target does not match the requested device",
        ));
    }

    let client_profile = match request.client.profile() {
        DeliveryProfile::Client(profile) => profile,
        DeliveryProfile::Pop(_) => {
            return Err(tunnel_error(
                WINDOWS_TUNNEL_DELIVERY_INVALID_CODE,
                "client delivery profile is not a client profile",
            ));
        }
    };
    if client_profile.transport != SDWAN_DELIVERY_TRANSPORT_EASYTIER {
        return Err(tunnel_error(
            WINDOWS_TUNNEL_TRANSPORT_UNSUPPORTED_CODE,
            "Windows tunnel planning accepts only the EasyTier transport",
        ));
    }

    let selected_pop = client_profile
        .pops
        .iter()
        .find(|pop| pop.id == request.selected_pop_id)
        .ok_or_else(|| {
            tunnel_error(
                WINDOWS_TUNNEL_POP_NOT_SELECTED_CODE,
                "selected POP is absent from the client delivery",
            )
        })?;

    if request.pop.target_id() != request.selected_pop_id {
        return Err(tunnel_error(
            WINDOWS_TUNNEL_POP_NOT_SELECTED_CODE,
            "POP delivery target does not match the selected POP",
        ));
    }

    let pop_profile = match request.pop.profile() {
        DeliveryProfile::Pop(profile) => profile,
        DeliveryProfile::Client(_) => {
            return Err(tunnel_error(
                WINDOWS_TUNNEL_DELIVERY_INVALID_CODE,
                "POP delivery profile is not a POP profile",
            ));
        }
    };
    if pop_profile.principal_id != request.selected_pop_id {
        return Err(tunnel_error(
            WINDOWS_TUNNEL_POP_NOT_SELECTED_CODE,
            "POP delivery principal does not match the selected POP",
        ));
    }

    let mut route_intents = Vec::with_capacity(pop_profile.routes.len());
    for route in &pop_profile.routes {
        let selector = &route.selector;
        let Some(destination_cidr) = selector.destination_cidr.as_ref() else {
            return Err(tunnel_error(
                WINDOWS_TUNNEL_ROUTE_SELECTOR_UNSUPPORTED_CODE,
                "Windows system routes require a destination CIDR",
            ));
        };
        if selector.source_cidr.is_some()
            || selector.domain_suffix.is_some()
            || selector.traffic_class.is_some()
            || selector.protocol.is_some()
            || selector.ports.is_some()
        {
            return Err(tunnel_error(
                WINDOWS_TUNNEL_ROUTE_SELECTOR_UNSUPPORTED_CODE,
                "route selector contains fields outside the Windows system-route contract",
            ));
        }
        if route.id.trim().is_empty()
            || route.chain.id.trim().is_empty()
            || route.chain.hops.is_empty()
        {
            return Err(tunnel_error(
                WINDOWS_TUNNEL_SERVICE_CHAIN_INVALID_CODE,
                "route service-chain metadata is incomplete",
            ));
        }

        route_intents.push(WindowsTunnelRouteIntent {
            route_id: route.id.clone(),
            destination_cidr: destination_cidr.clone(),
            service_chain_id: route.chain.id.clone(),
            direct_fallback: route.direct_fallback,
        });
    }

    if route_intents.is_empty() {
        return Err(tunnel_error(
            WINDOWS_TUNNEL_SERVICE_CHAIN_INVALID_CODE,
            "POP delivery contains no route intents",
        ));
    }

    let plan_digest = build_plan_digest(&request, selected_pop.endpoint.as_str(), &route_intents)?;
    let session_id = format!("windows-easytier-{}", &plan_digest[..16]);

    Ok(WindowsTunnelPlan {
        session_id,
        tenant_id: request.client.tenant_id().to_string(),
        client_bundle_id: request.client.bundle_id().to_string(),
        pop_bundle_id: request.pop.bundle_id().to_string(),
        client_sequence: request.client.sequence(),
        pop_sequence: request.pop.sequence(),
        selected_pop_id: request.selected_pop_id.to_string(),
        selected_endpoint: selected_pop.endpoint.clone(),
        route_intents,
        endpoint_bypass_required: true,
        plan_digest,
    })
}

fn build_plan_digest(
    request: &WindowsTunnelPlanRequest<'_>,
    selected_endpoint: &str,
    route_intents: &[WindowsTunnelRouteIntent],
) -> DomainResult<String> {
    let mut canonical = Vec::new();
    append_digest_field(&mut canonical, b"anixops.windows.easytier-plan/v1")?;
    append_digest_field(&mut canonical, request.client.tenant_id().as_bytes())?;
    append_digest_field(&mut canonical, request.client.bundle_id().as_bytes())?;
    append_digest_field(&mut canonical, request.pop.bundle_id().as_bytes())?;
    append_digest_field(&mut canonical, request.client.sequence().to_string().as_bytes())?;
    append_digest_field(&mut canonical, request.pop.sequence().to_string().as_bytes())?;
    append_digest_field(&mut canonical, request.device_id.as_bytes())?;
    append_digest_field(&mut canonical, request.selected_pop_id.as_bytes())?;
    append_digest_field(&mut canonical, selected_endpoint.as_bytes())?;
    append_digest_field(&mut canonical, SDWAN_DELIVERY_TRANSPORT_EASYTIER.as_bytes())?;
    append_digest_field(&mut canonical, request.client.signing_input_hex().as_bytes())?;
    append_digest_field(&mut canonical, request.pop.signing_input_hex().as_bytes())?;
    append_digest_field(&mut canonical, route_intents.len().to_string().as_bytes())?;
    for route in route_intents {
        append_digest_field(&mut canonical, route.route_id.as_bytes())?;
        append_digest_field(&mut canonical, route.destination_cidr.as_bytes())?;
        append_digest_field(&mut canonical, route.service_chain_id.as_bytes())?;
        append_digest_field(&mut canonical, route.direct_fallback.to_string().as_bytes())?;
    }

    Ok(lowercase_hex(digest::digest(&digest::SHA256, &canonical).as_ref()))
}

fn append_digest_field(output: &mut Vec<u8>, field: &[u8]) -> DomainResult<()> {
    let field_length = u32::try_from(field.len()).map_err(|_| {
        tunnel_error(
            WINDOWS_TUNNEL_DELIVERY_INVALID_CODE,
            "delivery metadata is too large to plan safely",
        )
    })?;
    output.extend_from_slice(&field_length.to_be_bytes());
    output.extend_from_slice(field);
    Ok(())
}

fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    value
}

fn tunnel_error(code: &str, message: &str) -> DomainError {
    DomainError::new(code, message)
}
