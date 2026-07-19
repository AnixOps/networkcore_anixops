//! EasyTier configuration rendering and redacted foreground-session state.
//!
//! The renderer is deliberately pure: it validates the already-planned route
//! metadata and returns strings. Process execution, secret-file reads, and route
//! mutations belong to the later lifecycle adapter.

use config_core::windows_tunnel::WindowsTunnelPlan;
use ring::digest;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use control_domain::{DomainError, DomainResult};

pub const WINDOWS_TUNNEL_STATE_SCHEMA_VERSION: u32 = 1;
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
    if expected_lower_hex.len() != 64
        || !expected_lower_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
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

/// One physical route captured before a session-owned route is added.
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
    pub binary_path: PathBuf,
    pub cli_path: PathBuf,
    pub config_path: PathBuf,
    pub expected_version: String,
    pub expected_sha256: String,
}

/// Ownership token for a process started by one tunnel session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedProcessHandle {
    pub session_id: String,
    pub process_id: u32,
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
    pub route_snapshot: Vec<WindowsRouteSnapshotEntry>,
    pub rollback_status: String,
}

/// Serializes a validated state record with deterministic field order.
pub fn serialize_tunnel_state(state: &WindowsTunnelState) -> DomainResult<String> {
    validate_state(state)?;
    serde_json::to_string_pretty(state)
        .map_err(|_| state_error("tunnel state could not be serialized"))
}

/// Parses and validates a persisted state record.
pub fn deserialize_tunnel_state(input: &[u8]) -> DomainResult<WindowsTunnelState> {
    let state: WindowsTunnelState =
        serde_json::from_slice(input).map_err(|_| state_error("tunnel state JSON is invalid"))?;
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
    if state.session_id.trim().is_empty()
        || state.plan_digest.trim().is_empty()
        || state.selected_pop_id.trim().is_empty()
        || state.selected_endpoint.trim().is_empty()
        || state.config_path.trim().is_empty()
        || state.rollback_status.trim().is_empty()
    {
        return Err(state_error("tunnel state contains an empty required field"));
    }
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
