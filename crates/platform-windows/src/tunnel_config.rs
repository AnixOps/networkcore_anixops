//! EasyTier configuration rendering and redacted foreground-session state.
//!
//! The renderer is deliberately pure: it validates the already-planned route
//! metadata and returns strings. Process execution, secret-file reads, and route
//! mutations belong to the later lifecycle adapter.

use config_core::windows_tunnel::WindowsTunnelPlan;
use ring::digest;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Component, Path, PathBuf};

use control_domain::{DomainError, DomainResult};

pub const WINDOWS_TUNNEL_STATE_SCHEMA_VERSION: u32 = 3;
pub const WINDOWS_TUNNEL_CONFIG_INVALID_CODE: &str = "windows.tunnel.config_invalid";
pub const WINDOWS_TUNNEL_EASYTIER_BINARY_INVALID_CODE: &str =
    "windows.tunnel.easytier_binary_invalid";
pub const WINDOWS_TUNNEL_BINARY_HASH_INVALID_CODE: &str =
    WINDOWS_TUNNEL_EASYTIER_BINARY_INVALID_CODE;
pub const WINDOWS_TUNNEL_STATE_INVALID_CODE: &str = "windows.tunnel.state_invalid";
pub const WINDOWS_TUNNEL_STATE_SCHEMA_UNSUPPORTED_CODE: &str =
    "windows.tunnel.state_schema_unsupported";
pub const WINDOWS_TUNNEL_STATE_IO_CODE: &str = "windows.tunnel.state_io_failed";

/// Inputs for one redacted EasyTier configuration artifact.
#[derive(Clone, PartialEq, Eq)]
pub struct EasyTierConfigRequest<'a> {
    pub plan: &'a WindowsTunnelPlan,
    pub network_name: &'a str,
    pub network_secret: &'a str,
    pub virtual_ipv4: Option<&'a str>,
}

impl fmt::Debug for EasyTierConfigRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EasyTierConfigRequest")
            .field("plan", &self.plan)
            .field("network_name", &self.network_name)
            .field("network_secret", &"[redacted]")
            .field("virtual_ipv4", &self.virtual_ipv4)
            .finish()
    }
}

/// Raw and redacted TOML plus the destination route CIDRs copied from the plan.
#[derive(Clone, PartialEq, Eq)]
pub struct EasyTierConfigArtifact {
    pub toml: String,
    pub redacted_toml: String,
    pub route_cidrs: Vec<String>,
}

impl fmt::Debug for EasyTierConfigArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EasyTierConfigArtifact")
            .field("toml", &"[redacted]")
            .field("redacted_toml", &self.redacted_toml)
            .field("route_cidrs", &self.route_cidrs)
            .finish()
    }
}

/// Produces a minimal EasyTier TOML configuration for the selected POP.
pub fn render_easytier_config(
    request: EasyTierConfigRequest<'_>,
) -> DomainResult<EasyTierConfigArtifact> {
    let network_name = required_text(request.network_name, "network name")?;
    let network_secret = required_text(request.network_secret, "network secret")?;
    let endpoint = required_text(&request.plan.selected_endpoint, "selected endpoint")?;
    let virtual_ipv4 = request.virtual_ipv4.map(parse_virtual_ipv4).transpose()?;

    if request.plan.route_intents.is_empty() {
        return Err(config_error("tunnel plan contains no route intents"));
    }

    let route_cidrs = request
        .plan
        .route_intents
        .iter()
        .map(|route| required_text(&route.destination_cidr, "route destination CIDR"))
        .collect::<DomainResult<Vec<_>>>()?;

    let peer_uri = format!("tcp://{endpoint}");
    let raw_config = EasyTierTomlConfig {
        network_identity: EasyTierNetworkIdentity {
            network_name: network_name.clone(),
            network_secret: network_secret.clone(),
        },
        ipv4: virtual_ipv4.clone(),
        peer: vec![EasyTierPeer {
            uri: peer_uri.clone(),
        }],
        routes: route_cidrs.clone(),
    };
    let redacted_config = EasyTierTomlConfig {
        network_identity: EasyTierNetworkIdentity {
            network_name,
            network_secret: "[redacted]".to_string(),
        },
        ipv4: virtual_ipv4,
        peer: vec![EasyTierPeer { uri: peer_uri }],
        routes: route_cidrs.clone(),
    };

    let toml =
        toml::to_string(&raw_config).map_err(|_| config_error("EasyTier TOML is invalid"))?;
    let redacted_toml = toml::to_string(&redacted_config)
        .map_err(|_| config_error("redacted EasyTier TOML is invalid"))?;

    Ok(EasyTierConfigArtifact {
        toml,
        redacted_toml,
        route_cidrs,
    })
}

/// Verifies a file against a lower-case SHA-256 pin without exposing its bytes.
pub fn verify_file_sha256(path: &Path, expected_lower_hex: &str) -> DomainResult<()> {
    if !is_lowercase_sha256(expected_lower_hex) {
        return Err(binary_error(
            "EasyTier binary SHA-256 pin is not lower-case hex",
        ));
    }

    let bytes = fs::read(path).map_err(|_| binary_error("EasyTier binary cannot be read"))?;
    let actual = lowercase_hex(digest::digest(&digest::SHA256, &bytes).as_ref());
    if actual != expected_lower_hex {
        return Err(binary_error("EasyTier binary SHA-256 pin does not match"));
    }

    Ok(())
}

/// Lifecycle states persisted in a session record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsTunnelLifecycleState {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

/// One exact route tuple retained for endpoint-bypass or virtual-route ownership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsRouteSnapshotEntry {
    pub destination_cidr: String,
    pub gateway: Option<String>,
    pub interface_index: Option<u32>,
    pub metric: Option<u32>,
}

/// Explicit paths and pins used by a later EasyTier process adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EasyTierLaunchSpec {
    pub session_id: String,
    pub binary_path: PathBuf,
    pub cli_path: PathBuf,
    pub config_path: PathBuf,
    pub expected_version: String,
    pub expected_sha256: String,
}

/// Ownership token for a process started by one tunnel session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedProcessHandle {
    pub session_id: String,
    pub process_id: u32,
    pub creation_marker: String,
}

/// Secret-free runtime proof retained for a recoverable foreground session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTunnelRuntimeOwnership {
    pub process: OwnedProcessHandle,
    pub binary_sha256: String,
    pub cli_file_name: String,
    pub route_cidrs: Vec<String>,
    pub virtual_route_snapshot: Vec<WindowsRouteSnapshotEntry>,
}

/// Redacted state retained for status, stop ownership, and audit output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTunnelState {
    pub schema_version: u32,
    pub session_id: String,
    pub plan_digest: String,
    pub selected_pop_id: String,
    pub selected_endpoint: String,
    pub state: WindowsTunnelLifecycleState,
    pub config_path: String,
    pub last_client_sequence: u64,
    pub last_pop_sequence: u64,
    pub client_bundle_id: String,
    pub client_sequence: u64,
    pub pop_bundle_id: String,
    pub pop_sequence: u64,
    pub easytier_version: String,
    pub route_snapshot: Vec<WindowsRouteSnapshotEntry>,
    pub rollback_status: String,
    pub runtime_ownership: WindowsTunnelRuntimeOwnership,
}

/// Serializes a validated state record with deterministic field order.
pub fn serialize_tunnel_state(state: &WindowsTunnelState) -> DomainResult<String> {
    validate_state(state)?;
    serde_json::to_string_pretty(state)
        .map_err(|_| state_error("tunnel state could not be serialized"))
}

/// Parses and validates a persisted state record.
pub fn deserialize_tunnel_state(input: &[u8]) -> DomainResult<WindowsTunnelState> {
    let value: serde_json::Value =
        serde_json::from_slice(input).map_err(|_| state_error("tunnel state JSON is invalid"))?;
    let schema_version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| state_error("tunnel state schema is invalid"))?;
    if schema_version != u64::from(WINDOWS_TUNNEL_STATE_SCHEMA_VERSION) {
        return Err(DomainError::new(
            WINDOWS_TUNNEL_STATE_SCHEMA_UNSUPPORTED_CODE,
            "tunnel state schema is unsupported",
        ));
    }
    let state: WindowsTunnelState =
        serde_json::from_value(value).map_err(|_| state_error("tunnel state JSON is invalid"))?;
    validate_state(&state)?;
    Ok(state)
}

/// Writes a validated state record to an explicit path.
pub fn write_tunnel_state(path: &Path, state: &WindowsTunnelState) -> DomainResult<()> {
    let serialized = serialize_tunnel_state(state)?;
    fs::write(path, serialized).map_err(|_| state_io_error("tunnel state could not be written"))
}

/// Reads and validates a state record from an explicit path.
pub fn read_tunnel_state(path: &Path) -> DomainResult<WindowsTunnelState> {
    let input = fs::read(path).map_err(|_| state_io_error("tunnel state could not be read"))?;
    deserialize_tunnel_state(&input)
}

#[derive(Debug, Serialize)]
struct EasyTierTomlConfig {
    network_identity: EasyTierNetworkIdentity,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv4: Option<String>,
    peer: Vec<EasyTierPeer>,
    routes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct EasyTierNetworkIdentity {
    network_name: String,
    network_secret: String,
}

#[derive(Debug, Serialize)]
struct EasyTierPeer {
    uri: String,
}

fn parse_virtual_ipv4(value: &str) -> DomainResult<String> {
    let value = required_text(value, "virtual IPv4")?;
    value
        .parse::<Ipv4Addr>()
        .map(|address| address.to_string())
        .map_err(|_| config_error("virtual IPv4 is invalid"))
}

fn required_text(value: &str, field: &str) -> DomainResult<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(config_error(field));
    }
    Ok(value.to_string())
}

fn validate_state(state: &WindowsTunnelState) -> DomainResult<()> {
    if state.schema_version != WINDOWS_TUNNEL_STATE_SCHEMA_VERSION {
        return Err(DomainError::new(
            WINDOWS_TUNNEL_STATE_SCHEMA_UNSUPPORTED_CODE,
            "tunnel state schema is unsupported",
        ));
    }
    if !is_normalized_required_text(&state.session_id)
        || !is_normalized_required_text(&state.plan_digest)
        || !is_normalized_required_text(&state.selected_pop_id)
        || !is_normalized_required_text(&state.selected_endpoint)
        || !is_safe_tunnel_file_name(&state.config_path)
        || !is_normalized_required_text(&state.rollback_status)
        || !is_normalized_required_text(&state.client_bundle_id)
        || !is_normalized_required_text(&state.pop_bundle_id)
        || !is_normalized_required_text(&state.easytier_version)
        || state.last_client_sequence != state.client_sequence
        || state.last_pop_sequence != state.pop_sequence
    {
        return Err(state_error("tunnel state contains an empty required field"));
    }
    if !is_normalized_required_text(&state.runtime_ownership.process.session_id)
        || state.runtime_ownership.process.session_id != state.session_id
        || state.runtime_ownership.process.process_id == 0
        || !is_normalized_required_text(&state.runtime_ownership.process.creation_marker)
        || !is_lowercase_sha256(&state.runtime_ownership.binary_sha256)
        || !is_safe_tunnel_file_name(&state.runtime_ownership.cli_file_name)
        || state.runtime_ownership.route_cidrs.is_empty()
        || state
            .runtime_ownership
            .route_cidrs
            .iter()
            .any(|cidr| !is_normalized_destination_cidr(cidr))
        || !has_exact_owned_destination_routes(
            &state.runtime_ownership.virtual_route_snapshot,
            &state.runtime_ownership.route_cidrs,
        )
    {
        return Err(state_error("tunnel state ownership metadata is invalid"));
    }
    Ok(())
}

fn is_normalized_required_text(value: &str) -> bool {
    !value.trim().is_empty() && value == value.trim()
}

fn is_normalized_destination_cidr(value: &str) -> bool {
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    let maximum_prefix = match address {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    prefix <= maximum_prefix && value == format!("{address}/{prefix}")
}

fn is_normalized_ip_address(value: &str) -> bool {
    value
        .parse::<IpAddr>()
        .map(|address| value == address.to_string())
        .unwrap_or(false)
}

fn has_exact_owned_destination_routes(
    routes: &[WindowsRouteSnapshotEntry],
    expected_destination_cidrs: &[String],
) -> bool {
    if routes.len() != expected_destination_cidrs.len() {
        return false;
    }

    let expected = expected_destination_cidrs
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if expected.len() != expected_destination_cidrs.len() {
        return false;
    }

    let mut observed = BTreeSet::new();
    routes.iter().all(|route| {
        let gateway = route.gateway.as_deref();
        let has_normalized_gateway = gateway.is_some_and(is_normalized_ip_address);
        is_normalized_destination_cidr(&route.destination_cidr)
            && expected.contains(route.destination_cidr.as_str())
            && has_normalized_gateway
            && route.interface_index.is_some_and(|index| index != 0)
            && route.metric.is_some()
            && observed.insert(route.destination_cidr.as_str())
    })
}

pub(crate) fn is_safe_tunnel_file_name(value: &str) -> bool {
    if value.is_empty()
        || value != value.trim()
        || value
            .chars()
            .any(|character| matches!(character, '/' | '\\' | ':' | '\0'))
    {
        return false;
    }

    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

fn config_error(message: &str) -> DomainError {
    DomainError::new(WINDOWS_TUNNEL_CONFIG_INVALID_CODE, message)
}

fn binary_error(message: &str) -> DomainError {
    DomainError::new(WINDOWS_TUNNEL_EASYTIER_BINARY_INVALID_CODE, message)
}

fn state_error(message: &str) -> DomainError {
    DomainError::new(WINDOWS_TUNNEL_STATE_INVALID_CODE, message)
}

fn state_io_error(message: &str) -> DomainError {
    DomainError::new(WINDOWS_TUNNEL_STATE_IO_CODE, message)
}
