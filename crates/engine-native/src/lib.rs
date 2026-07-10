//! Native proxy engine adapter contracts for NetworkCore.
//!
//! This crate intentionally exposes descriptor, validation, lifecycle
//! diagnostics, and resource-backed runtime handle contracts for the
//! current-process foreground runtime path.

use control_domain::{
    AuditEvent, Diagnostic, DiagnosticSeverity, DomainError, DomainResult, Endpoint,
    HttpHeaderMutation, HttpHeaderMutationOperation, HttpMitmAction, HttpMitmEvent,
    HttpMitmOutcome, HttpMitmPhase, HttpMitmScriptDispatch, HttpMitmScriptKind, ListenerDescriptor,
    ListenerKind, ListenerNetwork, ListenerRoute, MetadataEntry, MitmPluginService, NodeDescriptor,
    PluginInstance, Protocol, ProxyEngineConfig, ProxyEngineDescriptor, ProxyEngineEvent,
    ProxyEngineEventKind, ProxyEngineKind, ProxyEngineLifecycleState, ProxyEngineService,
    ProxyEngineStatus, RouteAction, RuleSet,
};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const DEFAULT_NATIVE_ENGINE_ID: &str = "native";

pub const SOURCE_ENGINE_NATIVE_CONFIG: &str = "engine.native.config";
pub const SOURCE_ENGINE_NATIVE_LIFECYCLE: &str = "engine.native.lifecycle";
pub const SOURCE_ENGINE_NATIVE_MITM: &str = "engine.native.mitm";
pub const SOURCE_ENGINE_NATIVE_RUNTIME: &str = "engine.native.runtime";

pub const ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE: &str =
    "engine.native.config.engine_id_unsupported";
pub const ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE: &str =
    "engine.native.config.listener_missing";
pub const ENGINE_NATIVE_CONFIG_LISTENER_ID_DUPLICATE_CODE: &str =
    "engine.native.config.listener_id_duplicate";
pub const ENGINE_NATIVE_CONFIG_LISTENER_BIND_INVALID_CODE: &str =
    "engine.native.config.listener_bind_invalid";
pub const ENGINE_NATIVE_CONFIG_LISTENER_KIND_UNSUPPORTED_CODE: &str =
    "engine.native.config.listener_kind_unsupported";
pub const ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE: &str = "engine.native.config.node_missing";
pub const ENGINE_NATIVE_CONFIG_NODE_ID_DUPLICATE_CODE: &str =
    "engine.native.config.node_id_duplicate";
pub const ENGINE_NATIVE_CONFIG_NODE_PROTOCOL_UNSUPPORTED_CODE: &str =
    "engine.native.config.node_protocol_unsupported";
pub const ENGINE_NATIVE_CONFIG_ROUTE_ID_DUPLICATE_CODE: &str =
    "engine.native.config.route_id_duplicate";
pub const ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE: &str =
    "engine.native.config.route_target_missing";
pub const ENGINE_NATIVE_CONFIG_ROUTE_EMPTY_CODE: &str = "engine.native.config.route_empty";
pub const ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE: &str =
    "engine.native.start.runtime_unavailable";
pub const ENGINE_NATIVE_START_RUNTIME_ASSEMBLY_READY_CODE: &str =
    "engine.native.start.runtime_assembly_ready";
pub const ENGINE_NATIVE_START_SERVICE_RUNTIME_OWNER_MISSING_CODE: &str =
    "engine.native.start.service_runtime_owner_missing";
pub const ENGINE_NATIVE_START_RUNNING_CODE: &str = "engine.native.start.running";
pub const ENGINE_NATIVE_START_BIND_FAILED_CODE: &str = "engine.native.start.bind_failed";
pub const ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE: &str = "engine.native.start.lifecycle_failed";
pub const ENGINE_NATIVE_RUNTIME_LISTENER_DISABLED_CODE: &str =
    "engine.native.runtime.listener_disabled";
pub const ENGINE_NATIVE_RUNTIME_LISTENER_NON_LOOPBACK_CODE: &str =
    "engine.native.runtime.listener_non_loopback";
pub const ENGINE_NATIVE_RUNTIME_LISTENER_UNSUPPORTED_CODE: &str =
    "engine.native.runtime.listener_unsupported";
pub const ENGINE_NATIVE_RUNTIME_OUTBOUND_ENDPOINT_INVALID_CODE: &str =
    "engine.native.runtime.outbound_endpoint_invalid";
pub const ENGINE_NATIVE_RUNTIME_OUTBOUND_UNSUPPORTED_CODE: &str =
    "engine.native.runtime.outbound_unsupported";
pub const ENGINE_NATIVE_RUNTIME_RESOURCE_MISSING_CODE: &str =
    "engine.native.runtime.resource_missing";
pub const ENGINE_NATIVE_RUNTIME_RELEASED_CODE: &str = "engine.native.runtime.released";
pub const ENGINE_NATIVE_RUNTIME_FOREGROUND_HANDOFF_READY_CODE: &str =
    "engine.native.runtime.foreground_handoff_ready";
pub const ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_READY_CODE: &str =
    "engine.native.runtime.accept_loop_ready";
pub const ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_STOPPED_CODE: &str =
    "engine.native.runtime.accept_loop_stopped";
pub const ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE: &str =
    "engine.native.runtime.connection_pre_protocol_closed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_CODE: &str =
    "engine.native.runtime.socks5_greeting_read";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_INVALID_CODE: &str =
    "engine.native.runtime.socks5_greeting_invalid";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_FAILED_CODE: &str =
    "engine.native.runtime.socks5_greeting_read_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_SELECTED_CODE: &str =
    "engine.native.runtime.socks5_auth_method_selected";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_UNSUPPORTED_CODE: &str =
    "engine.native.runtime.socks5_auth_method_unsupported";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_RESPONSE_WRITTEN_CODE: &str =
    "engine.native.runtime.socks5_auth_method_response_written";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_RESPONSE_WRITE_FAILED_CODE: &str =
    "engine.native.runtime.socks5_auth_method_response_write_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_READ_CODE: &str =
    "engine.native.runtime.socks5_command_header_read";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_INVALID_CODE: &str =
    "engine.native.runtime.socks5_command_header_invalid";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_READ_FAILED_CODE: &str =
    "engine.native.runtime.socks5_command_header_read_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_UNSUPPORTED_CODE: &str =
    "engine.native.runtime.socks5_command_unsupported";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_CODE: &str =
    "engine.native.runtime.socks5_connect_target_read";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_INVALID_CODE: &str =
    "engine.native.runtime.socks5_connect_target_invalid";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_FAILED_CODE: &str =
    "engine.native.runtime.socks5_connect_target_read_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_SELECTED_CODE: &str =
    "engine.native.runtime.socks5_route_outbound_selected";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_GENERATED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_request_frame_generated";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_INVALID_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_request_frame_invalid";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_PLANNED_CODE: &str =
    "engine.native.runtime.socks5_outbound_tcp_connection_planned";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_PLAN_INVALID_CODE: &str =
    "engine.native.runtime.socks5_outbound_tcp_connection_plan_invalid";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_SUCCEEDED_CODE: &str =
    "engine.native.runtime.socks5_outbound_tcp_connection_attempt_succeeded";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_FAILED_CODE: &str =
    "engine.native.runtime.socks5_outbound_tcp_connection_attempt_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_request_written";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITE_FAILED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_request_write_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_READ_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_response_read";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_INVALID_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_response_invalid";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_READ_FAILED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_response_read_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_ACCEPTED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_response_accepted";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_REJECTED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_response_rejected";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_READY_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_relay_ready";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_UNWIRED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_relay_unwired";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_REJECTED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_relay_rejected";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_READY_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_data_relay_plan_ready";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_UNWIRED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_data_relay_plan_unwired";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_REJECTED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_data_relay_plan_rejected";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_COMPLETED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_data_relay_completed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_FAILED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_data_relay_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_READY_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_client_success_response_ready";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_UNWIRED_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_client_success_response_unwired";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_REJECTED_CODE:
    &str = "engine.native.runtime.socks5_outbound_connect_client_success_response_rejected";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_READY_CODE:
    &str = "engine.native.runtime.socks5_outbound_connect_client_success_response_write_plan_ready";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_UNWIRED_CODE:
    &str = "engine.native.runtime.socks5_outbound_connect_client_success_response_write_plan_unwired";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_REJECTED_CODE:
    &str = "engine.native.runtime.socks5_outbound_connect_client_success_response_write_plan_rejected";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITTEN_CODE: &str =
    "engine.native.runtime.socks5_outbound_connect_client_success_response_written";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_FAILED_CODE:
    &str = "engine.native.runtime.socks5_outbound_connect_client_success_response_write_failed";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_UNWIRED_CODE: &str =
    "engine.native.runtime.socks5_route_outbound_unwired";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITTEN_CODE: &str =
    "engine.native.runtime.socks5_connect_failure_response_written";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITE_FAILED_CODE: &str =
    "engine.native.runtime.socks5_connect_failure_response_write_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_EVENT_PLANNED_CODE: &str =
    "engine.native.runtime.http_mitm_connect_event_planned";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_READY_CODE: &str =
    "engine.native.runtime.http_mitm_connect_plan_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_FAILED_CODE: &str =
    "engine.native.runtime.http_mitm_connect_plan_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_NOT_APPLIED_CODE: &str =
    "engine.native.runtime.http_mitm_connect_plan_not_applied";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_APPLIED_CODE: &str =
    "engine.native.runtime.http_mitm_connect_reject_applied";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_RESPONSE_WRITTEN_CODE: &str =
    "engine.native.runtime.http_mitm_connect_reject_response_written";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_RESPONSE_WRITE_FAILED_CODE: &str =
    "engine.native.runtime.http_mitm_connect_reject_response_write_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_BROWSER_PROOF_OBSERVED_CODE: &str =
    "engine.native.runtime.http_mitm_connect_browser_proof_observed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_EVENT_PLANNED_CODE: &str =
    "engine.native.runtime.http_mitm_plain_event_planned";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_PLAN_READY_CODE: &str =
    "engine.native.runtime.http_mitm_plain_plan_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_PLAN_FAILED_CODE: &str =
    "engine.native.runtime.http_mitm_plain_plan_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_TERMINAL_ACTION_APPLIED_CODE: &str =
    "engine.native.runtime.http_mitm_plain_terminal_action_applied";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_HEADER_MUTATION_APPLIED_CODE: &str =
    "engine.native.runtime.http_mitm_plain_header_mutation_applied";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_BODY_MUTATION_APPLIED_CODE: &str =
    "engine.native.runtime.http_mitm_plain_body_mutation_applied";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_SCRIPT_DISPATCH_DEFERRED_CODE: &str =
    "engine.native.runtime.http_mitm_plain_script_dispatch_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_REWRITE_NOOP_CODE: &str =
    "engine.native.runtime.http_mitm_plain_rewrite_noop";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_READ_CODE: &str =
    "engine.native.runtime.http_proxy_plain_request_read";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_INVALID_CODE: &str =
    "engine.native.runtime.http_proxy_plain_request_invalid";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_READ_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_plain_request_read_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CONNECT_TLS_BLOCKED_CODE: &str =
    "engine.native.runtime.http_proxy_plain_connect_tls_blocked";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_FOUNDATION_READY_CODE: &str =
    "engine.native.runtime.http_proxy_tls_foundation_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_ESTABLISHED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_connect_tunnel_established";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_connect_tunnel_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CLIENT_HELLO_OBSERVED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_client_hello_observed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CLIENT_HELLO_DEFERRED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_client_hello_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SNI_AUTHORITY_MATCHED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_sni_authority_matched";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SNI_AUTHORITY_MISMATCH_CODE: &str =
    "engine.native.runtime.http_proxy_tls_sni_authority_mismatch";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_PLAN_READY_CODE: &str =
    "engine.native.runtime.http_proxy_tls_termination_plan_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_DEFERRED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_termination_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_ISSUED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_leaf_certificate_issued";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_DEFERRED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_leaf_certificate_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_leaf_certificate_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SERVER_CONFIG_READY_CODE: &str =
    "engine.native.runtime.http_proxy_tls_server_config_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SERVER_CONFIG_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_server_config_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_UPSTREAM_CONFIG_READY_CODE: &str =
    "engine.native.runtime.http_proxy_tls_upstream_config_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_UPSTREAM_CONFIG_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_upstream_config_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_READY_CODE: &str =
    "engine.native.runtime.http_proxy_tls_session_decryption_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_tls_session_decryption_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_EXECUTED_CODE: &str =
    "engine.native.runtime.http_script_executed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_DEFERRED_CODE: &str =
    "engine.native.runtime.http_script_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_FAILED_CODE: &str =
    "engine.native.runtime.http_script_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_URL_MUTATION_BLOCKED_CODE: &str =
    "engine.native.runtime.http_script_url_mutation_blocked";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_PREVIEW_READY_CODE: &str =
    "engine.native.runtime.http_proxy_https_request_rewrite_preview_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_PREVIEW_DEFERRED_CODE: &str =
    "engine.native.runtime.http_proxy_https_request_rewrite_preview_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_SCRIPT_DEFERRED_CODE: &str =
    "engine.native.runtime.http_proxy_https_request_rewrite_script_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_PREVIEW_READY_CODE: &str =
    "engine.native.runtime.http_proxy_https_response_rewrite_preview_ready";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_PREVIEW_DEFERRED_CODE: &str =
    "engine.native.runtime.http_proxy_https_response_rewrite_preview_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_SCRIPT_DEFERRED_CODE: &str =
    "engine.native.runtime.http_proxy_https_response_rewrite_script_deferred";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REWRITE_APPLIED_CODE: &str =
    "engine.native.runtime.http_proxy_plain_rewrite_applied";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITTEN_CODE: &str =
    "engine.native.runtime.http_proxy_plain_upstream_request_written";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITE_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_plain_upstream_request_write_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_CODE: &str =
    "engine.native.runtime.http_proxy_plain_upstream_response_read";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_plain_upstream_response_read_failed";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE: &str =
    "engine.native.runtime.http_proxy_plain_client_response_written";
pub const ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITE_FAILED_CODE: &str =
    "engine.native.runtime.http_proxy_plain_client_response_write_failed";

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_METHOD_NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
const SOCKS5_AUTH_METHOD_NO_ACCEPTABLE_METHODS: u8 = 0xff;
const SOCKS5_COMMAND_CONNECT: u8 = 0x01;
const SOCKS5_REPLY_SUCCEEDED: u8 = 0x00;
const SOCKS5_REPLY_GENERAL_FAILURE: u8 = 0x01;
const SOCKS5_RESERVED: u8 = 0x00;
const SOCKS5_ADDRESS_TYPE_IPV4: u8 = 0x01;
const SOCKS5_ADDRESS_TYPE_DOMAIN_NAME: u8 = 0x03;
const SOCKS5_ADDRESS_TYPE_IPV6: u8 = 0x04;
const SOCKS5_CONNECT_FAILURE_RESPONSE: [u8; 10] = [
    SOCKS5_VERSION,
    SOCKS5_REPLY_GENERAL_FAILURE,
    SOCKS5_RESERVED,
    SOCKS5_ADDRESS_TYPE_IPV4,
    0,
    0,
    0,
    0,
    0,
    0,
];
const ACCEPTED_CONNECTION_READ_TIMEOUT_MS: u64 = 100;
const OUTBOUND_CONNECTION_ATTEMPT_TIMEOUT_MS: u64 = 100;
const OUTBOUND_CONNECT_REQUEST_WRITE_TIMEOUT_MS: u64 = 100;
const OUTBOUND_CONNECT_RESPONSE_READ_TIMEOUT_MS: u64 = 100;
const TLS_CLIENT_HELLO_PEEK_MAX_BYTES: usize = 16 * 1024 + 5;
const TLS_CLIENT_HELLO_OBSERVATION_TIMEOUT_MS: u64 = 1000;
const TLS_CLIENT_HELLO_OBSERVATION_POLL_MS: u64 = 5;
const CONTROLLED_TLS_SESSION_TIMEOUT_MS: u64 = 15_000;
const CONTROLLED_TLS_SOCKET_READ_TIMEOUT_MS: u64 = 1000;
const MAX_CONCURRENT_ACCEPTED_CONNECTIONS: usize = 64;
const HTTP_PROXY_MAX_HEADER_BYTES: usize = 16 * 1024;
const HTTP_PROXY_MAX_BODY_BYTES: usize = 64 * 1024;
const SCRIPT_RUNTIME_DEFAULT_TIMEOUT_MS: usize = 5000;
const SCRIPT_RUNTIME_HARD_MAX_TIMEOUT_MS: usize = 30_000;
static SCRIPT_RUNTIME_TEMP_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

struct NativeBoundedRead<'a, R> {
    reader: &'a mut R,
    deadline: Instant,
}

impl<'a, R> NativeBoundedRead<'a, R> {
    fn new(reader: &'a mut R, timeout: Duration) -> Self {
        Self {
            reader,
            deadline: Instant::now() + timeout,
        }
    }
}

impl<R> Read for NativeBoundedRead<'_, R>
where
    R: Read,
{
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if Instant::now() >= self.deadline {
                return Err(std::io::Error::new(
                    ErrorKind::TimedOut,
                    "native bounded HTTP read timed out",
                ));
            }
            match self.reader.read(buffer) {
                Err(error)
                    if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                {
                    continue
                }
                result => return result,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopbackListenerHandle {
    pub listener_id: String,
    pub bind_host: String,
    pub bind_port: u16,
    pub kind: ListenerKind,
    pub network: ListenerNetwork,
}

impl LoopbackListenerHandle {
    pub fn from_descriptor(listener: &ListenerDescriptor) -> DomainResult<Self> {
        if !listener.enabled {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_LISTENER_DISABLED_CODE,
                "disabled listeners cannot own native runtime handles",
            ));
        }

        if listener.bind.host.trim().is_empty() || listener.bind.port == 0 {
            return Err(runtime_error(
                ENGINE_NATIVE_CONFIG_LISTENER_BIND_INVALID_CODE,
                "native runtime listener bind host and port must be explicit",
            ));
        }

        if !is_loopback_host(&listener.bind.host) {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_LISTENER_NON_LOOPBACK_CODE,
                "first native runtime listener handle must bind to loopback",
            ));
        }

        if listener.network != ListenerNetwork::Tcp
            || !listener_runtime_kind_supported(&listener.kind)
        {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_LISTENER_UNSUPPORTED_CODE,
                "first native runtime listener handle only supports tcp loopback listeners",
            ));
        }

        Ok(Self {
            listener_id: listener.id.clone(),
            bind_host: listener.bind.host.clone(),
            bind_port: listener.bind.port,
            kind: listener.kind.clone(),
            network: listener.network,
        })
    }
}

#[derive(Debug)]
pub struct BoundLoopbackTcpListenerHandle {
    listener: TcpListener,
    contract: LoopbackListenerHandle,
    local_host: String,
    local_port: u16,
}

impl BoundLoopbackTcpListenerHandle {
    pub fn bind(contract: LoopbackListenerHandle) -> DomainResult<Self> {
        if contract.bind_host.trim().is_empty() || contract.bind_port == 0 {
            return Err(runtime_error(
                ENGINE_NATIVE_CONFIG_LISTENER_BIND_INVALID_CODE,
                "native runtime listener bind host and port must be explicit",
            ));
        }

        if !is_loopback_host(&contract.bind_host) {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_LISTENER_NON_LOOPBACK_CODE,
                "native loopback tcp listener bind requires a loopback address",
            ));
        }

        if contract.network != ListenerNetwork::Tcp
            || !listener_runtime_kind_supported(&contract.kind)
        {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_LISTENER_UNSUPPORTED_CODE,
                "native loopback tcp listener only supports tcp loopback listeners",
            ));
        }

        let listener = TcpListener::bind((contract.bind_host.as_str(), contract.bind_port))
            .map_err(|_| {
                runtime_error(
                    ENGINE_NATIVE_START_BIND_FAILED_CODE,
                    "failed to bind native loopback tcp listener",
                )
            })?;
        let local_addr = listener.local_addr().map_err(|_| {
            runtime_error(
                ENGINE_NATIVE_START_BIND_FAILED_CODE,
                "failed to inspect native loopback tcp listener address",
            )
        })?;

        Ok(Self {
            listener,
            contract,
            local_host: local_addr.ip().to_string(),
            local_port: local_addr.port(),
        })
    }

    pub fn listener_id(&self) -> &str {
        &self.contract.listener_id
    }

    pub fn bind_host(&self) -> &str {
        &self.contract.bind_host
    }

    pub fn bind_port(&self) -> u16 {
        self.contract.bind_port
    }

    pub fn local_host(&self) -> &str {
        &self.local_host
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn release(self) -> BoundLoopbackTcpListenerReleaseReport {
        let Self {
            listener,
            contract,
            local_host,
            local_port,
        } = self;
        drop(listener);

        BoundLoopbackTcpListenerReleaseReport {
            listener_id: contract.listener_id,
            bind_host: contract.bind_host,
            bind_port: contract.bind_port,
            local_host,
            local_port,
            diagnostics: vec![runtime_info(
                ENGINE_NATIVE_RUNTIME_RELEASED_CODE,
                "native loopback tcp listener was released",
            )],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundLoopbackTcpListenerReleaseReport {
    pub listener_id: String,
    pub bind_host: String,
    pub bind_port: u16,
    pub local_host: String,
    pub local_port: u16,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug)]
pub struct NativeLoopbackTcpAcceptLoopHandle {
    listener_id: String,
    outbound_handler_id: String,
    local_host: String,
    local_port: u16,
    accepted_connections: Arc<AtomicUsize>,
    pre_protocol_closed_connections: Arc<AtomicUsize>,
    relayed_connections: Arc<AtomicUsize>,
    shutdown_tx: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<NativeLoopbackTcpAcceptLoopShutdownReport>>,
}

impl NativeLoopbackTcpAcceptLoopHandle {
    pub fn start(
        listener: BoundLoopbackTcpListenerHandle,
        outbound_handler: NativeOutboundHandlerHandle,
    ) -> DomainResult<Self> {
        Self::start_with_http_mitm_hook_and_tls_mitm_ca_material(
            listener,
            outbound_handler,
            None,
            None,
        )
    }

    pub fn start_with_http_mitm_hook(
        listener: BoundLoopbackTcpListenerHandle,
        outbound_handler: NativeOutboundHandlerHandle,
        http_mitm_hook: Option<NativeHttpMitmPluginHook>,
    ) -> DomainResult<Self> {
        Self::start_with_http_mitm_hook_and_tls_mitm_ca_material(
            listener,
            outbound_handler,
            http_mitm_hook,
            None,
        )
    }

    pub fn start_with_http_mitm_hook_and_tls_mitm_ca_material(
        listener: BoundLoopbackTcpListenerHandle,
        outbound_handler: NativeOutboundHandlerHandle,
        http_mitm_hook: Option<NativeHttpMitmPluginHook>,
        tls_mitm_ca_material: Option<NativeTlsMitmCaMaterial>,
    ) -> DomainResult<Self> {
        let BoundLoopbackTcpListenerHandle {
            listener,
            contract,
            local_host,
            local_port,
        } = listener;

        listener.set_nonblocking(true).map_err(|_| {
            runtime_error(
                ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE,
                "failed to configure native loopback tcp accept loop",
            )
        })?;

        let listener_id = contract.listener_id;
        let listener_kind = contract.kind;
        let outbound_handler_id = outbound_handler.node_id.clone();
        let accepted_connections = Arc::new(AtomicUsize::new(0));
        let accepted_connections_for_worker = Arc::clone(&accepted_connections);
        let pre_protocol_closed_connections = Arc::new(AtomicUsize::new(0));
        let pre_protocol_closed_connections_for_worker =
            Arc::clone(&pre_protocol_closed_connections);
        let relayed_connections = Arc::new(AtomicUsize::new(0));
        let relayed_connections_for_worker = Arc::clone(&relayed_connections);
        let (shutdown_tx, shutdown_rx) = mpsc::channel();
        let worker_listener_id = listener_id.clone();
        let worker_outbound_handler_id = outbound_handler_id.clone();
        let worker_local_host = local_host.clone();

        let worker = thread::spawn(move || {
            run_loopback_tcp_accept_loop(
                listener,
                shutdown_rx,
                accepted_connections_for_worker,
                pre_protocol_closed_connections_for_worker,
                relayed_connections_for_worker,
                NativeLoopbackTcpAcceptLoopIdentity {
                    listener_id: worker_listener_id,
                    listener_kind,
                    outbound_handler_id: worker_outbound_handler_id,
                    outbound_handler,
                    http_mitm_hook,
                    tls_mitm_ca_material,
                    local_host: worker_local_host,
                    local_port,
                },
            )
        });

        Ok(Self {
            listener_id,
            outbound_handler_id,
            local_host,
            local_port,
            accepted_connections,
            pre_protocol_closed_connections,
            relayed_connections,
            shutdown_tx: Some(shutdown_tx),
            worker: Some(worker),
        })
    }

    pub fn listener_id(&self) -> &str {
        &self.listener_id
    }

    pub fn outbound_handler_id(&self) -> &str {
        &self.outbound_handler_id
    }

    pub fn local_host(&self) -> &str {
        &self.local_host
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn accepted_connections(&self) -> usize {
        self.accepted_connections.load(Ordering::SeqCst)
    }

    pub fn pre_protocol_closed_connections(&self) -> usize {
        self.pre_protocol_closed_connections.load(Ordering::SeqCst)
    }

    pub fn relayed_connections(&self) -> usize {
        self.relayed_connections.load(Ordering::SeqCst)
    }

    pub fn shutdown(mut self) -> NativeLoopbackTcpAcceptLoopShutdownReport {
        self.shutdown_inner()
    }

    fn shutdown_inner(&mut self) -> NativeLoopbackTcpAcceptLoopShutdownReport {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }

        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(report) => report,
                Err(_) => NativeLoopbackTcpAcceptLoopShutdownReport {
                    listener_id: self.listener_id.clone(),
                    outbound_handler_id: self.outbound_handler_id.clone(),
                    local_host: self.local_host.clone(),
                    local_port: self.local_port,
                    accepted_connections: self.accepted_connections(),
                    pre_protocol_closed_connections: self.pre_protocol_closed_connections(),
                    relayed_connections: self.relayed_connections(),
                    diagnostics: vec![engine_diagnostic(
                        DiagnosticSeverity::Error,
                        ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE,
                        "native loopback tcp accept loop worker failed during shutdown",
                        SOURCE_ENGINE_NATIVE_RUNTIME,
                    )],
                },
            }
        } else {
            NativeLoopbackTcpAcceptLoopShutdownReport {
                listener_id: self.listener_id.clone(),
                outbound_handler_id: self.outbound_handler_id.clone(),
                local_host: self.local_host.clone(),
                local_port: self.local_port,
                accepted_connections: self.accepted_connections(),
                pre_protocol_closed_connections: self.pre_protocol_closed_connections(),
                relayed_connections: self.relayed_connections(),
                diagnostics: vec![runtime_info(
                    ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_STOPPED_CODE,
                    "native loopback tcp accept loop was already stopped",
                )],
            }
        }
    }
}

impl Drop for NativeLoopbackTcpAcceptLoopHandle {
    fn drop(&mut self) {
        if self.worker.is_some() {
            let _ = self.shutdown_inner();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeLoopbackTcpAcceptLoopShutdownReport {
    pub listener_id: String,
    pub outbound_handler_id: String,
    pub local_host: String,
    pub local_port: u16,
    pub accepted_connections: usize,
    pub pre_protocol_closed_connections: usize,
    pub relayed_connections: usize,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeNodeScriptRuntimeConfig {
    pub node_binary: String,
    pub runner_path: String,
    pub script_assets: BTreeMap<String, String>,
    pub persistent_store_path: Option<String>,
    pub max_timeout_ms: usize,
    pub max_body_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeHttpScriptExecutionReport {
    pub executed: bool,
    pub applied: bool,
    pub url: Option<String>,
    pub headers: Option<Vec<MetadataEntry>>,
    pub body: Option<Vec<u8>>,
    pub status_code: Option<u16>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone)]
pub struct NativeNodeScriptExecutor {
    config: NativeNodeScriptRuntimeConfig,
}

impl NativeNodeScriptExecutor {
    pub fn new(config: NativeNodeScriptRuntimeConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &NativeNodeScriptRuntimeConfig {
        &self.config
    }

    pub fn execute(
        &self,
        dispatch: &HttpMitmScriptDispatch,
        message: &NativePlainHttpMessage,
    ) -> NativeHttpScriptExecutionReport {
        if !script_dispatch_matches_message(dispatch, message) {
            return script_execution_deferred(
                "native HTTP script dispatch phase does not match the intercepted message",
            );
        }
        if dispatch.max_size > 0 && message.body.len() > dispatch.max_size {
            return script_execution_deferred(
                "native HTTP script dispatch body exceeds the rule max-size limit",
            );
        }
        if self.config.max_body_bytes > 0 && message.body.len() > self.config.max_body_bytes {
            return script_execution_deferred(
                "native HTTP script dispatch body exceeds the runtime max-size limit",
            );
        }
        if std::str::from_utf8(&message.body).is_err() {
            return script_execution_deferred(
                "native HTTP script dispatch requires a UTF-8 buffered body",
            );
        }
        let Some(script_asset_path) = self.config.script_assets.get(&dispatch.script_path) else {
            return script_execution_deferred(
                "native HTTP script dispatch has no explicitly configured local script asset",
            );
        };
        if self.config.node_binary.trim().is_empty()
            || self.config.runner_path.trim().is_empty()
            || script_asset_path.trim().is_empty()
        {
            return script_execution_deferred(
                "native HTTP script runtime requires explicit node, runner, and local asset paths",
            );
        }
        if !std::path::Path::new(&self.config.runner_path).is_file()
            || !std::path::Path::new(script_asset_path).is_file()
        {
            return script_execution_deferred(
                "native HTTP script runtime runner or mapped local asset is unavailable",
            );
        }

        let body_path = match write_script_runtime_body(&message.body) {
            Ok(body_path) => body_path,
            Err(()) => {
                return script_execution_failed(
                    "native HTTP script runtime could not securely stage a buffered body",
                )
            }
        };
        let execution = self.execute_staged(dispatch, message, script_asset_path, &body_path);
        let _ = std::fs::remove_file(&body_path);
        execution
    }

    fn execute_staged(
        &self,
        dispatch: &HttpMitmScriptDispatch,
        message: &NativePlainHttpMessage,
        script_asset_path: &str,
        body_path: &std::path::Path,
    ) -> NativeHttpScriptExecutionReport {
        let request_headers = match serde_json::to_string(&script_headers_to_map(&message.headers))
        {
            Ok(headers) => headers,
            Err(_) => {
                return script_execution_failed(
                    "native HTTP script runtime could not encode request headers",
                )
            }
        };
        let timeout_ms = bounded_script_timeout(dispatch.timeout_ms, self.config.max_timeout_ms);
        let mut command = Command::new(&self.config.node_binary);
        command
            .arg(&self.config.runner_path)
            .arg("--script")
            .arg(script_asset_path)
            .arg("--url")
            .arg(&message.url)
            .arg("--argument")
            .arg(&dispatch.argument)
            .arg("--body")
            .arg(body_path)
            .arg("--phase")
            .arg(script_phase_name(message.phase))
            .arg("--method")
            .arg(message.method.as_deref().unwrap_or("GET"))
            .arg("--timeoutMs")
            .arg(timeout_ms.to_string())
            .arg("--requestHeaders")
            .arg(request_headers)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let HttpMitmPhase::Response = message.phase {
            let response_headers =
                match serde_json::to_string(&script_headers_to_map(&message.headers)) {
                    Ok(headers) => headers,
                    Err(_) => {
                        return script_execution_failed(
                            "native HTTP script runtime could not encode response headers",
                        )
                    }
                };
            command
                .arg("--status")
                .arg(message.status_code.unwrap_or(200).to_string())
                .arg("--responseHeaders")
                .arg(response_headers);
        }
        if let Some(store_path) = self.config.persistent_store_path.as_deref() {
            command.arg("--store").arg(store_path);
        }

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                return script_execution_failed(
                    "native HTTP script runtime could not start the configured node runner",
                )
            }
        };
        let started_at = Instant::now();
        let output = loop {
            match child.try_wait() {
                Ok(Some(_)) => match child.wait_with_output() {
                    Ok(output) => break output,
                    Err(_) => {
                        return script_execution_failed(
                            "native HTTP script runtime could not collect runner output",
                        )
                    }
                },
                Ok(None) if started_at.elapsed() >= Duration::from_millis(timeout_ms) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return script_execution_failed("native HTTP script runtime timed out");
                }
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return script_execution_failed(
                        "native HTTP script runtime could not monitor the runner process",
                    );
                }
            }
        };
        if !output.status.success() {
            return script_execution_failed(
                "native HTTP script runtime runner exited unsuccessfully",
            );
        }
        let output = match String::from_utf8(output.stdout) {
            Ok(output) => output,
            Err(_) => {
                return script_execution_failed(
                    "native HTTP script runtime returned non-UTF-8 output",
                )
            }
        };
        let result = match serde_json::from_str::<NativeNodeScriptDone>(&output) {
            Ok(result) => result,
            Err(_) => {
                return script_execution_failed("native HTTP script runtime returned invalid JSON")
            }
        };
        let headers = match result.headers {
            Some(headers) => match script_headers_from_map(headers) {
                Some(headers) => Some(headers),
                None => {
                    return script_execution_failed(
                        "native HTTP script runtime returned invalid headers",
                    )
                }
            },
            None => None,
        };
        let status_code = match result.status {
            Some(status_code)
                if message.phase == HttpMitmPhase::Response
                    && (100..=599).contains(&status_code) =>
            {
                Some(status_code)
            }
            Some(_) => {
                return script_execution_failed(
                    "native HTTP script runtime returned an unsupported status mutation",
                )
            }
            None => None,
        };
        let body = result.body.map(String::into_bytes);
        let applied =
            result.url.is_some() || headers.is_some() || body.is_some() || status_code.is_some();

        NativeHttpScriptExecutionReport {
            executed: true,
            applied,
            url: result.url,
            headers,
            body,
            status_code,
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_EXECUTED_CODE,
                "native HTTP script runtime completed a locally mapped script dispatch",
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        }
    }
}

#[derive(Debug, Deserialize)]
struct NativeNodeScriptDone {
    url: Option<String>,
    headers: Option<BTreeMap<String, String>>,
    body: Option<String>,
    status: Option<u16>,
}

#[derive(Clone)]
pub struct NativeHttpMitmPluginHook {
    plugin_instance: PluginInstance,
    plugin_service: Arc<dyn MitmPluginService + Send + Sync>,
    script_executor: Option<NativeNodeScriptExecutor>,
}

impl NativeHttpMitmPluginHook {
    pub fn new(
        plugin_instance: PluginInstance,
        plugin_service: Arc<dyn MitmPluginService + Send + Sync>,
    ) -> Self {
        Self {
            plugin_instance,
            plugin_service,
            script_executor: None,
        }
    }

    pub fn with_node_script_executor(mut self, executor: NativeNodeScriptExecutor) -> Self {
        self.script_executor = Some(executor);
        self
    }

    pub fn script_executor_enabled(&self) -> bool {
        self.script_executor.is_some()
    }

    pub fn plugin_instance(&self) -> &PluginInstance {
        &self.plugin_instance
    }

    pub fn plan_socks5_connect(
        &self,
        request_id: impl Into<String>,
        target: &NativeSocks5ConnectTarget,
    ) -> NativeSocks5ConnectHttpMitmPlanReport {
        plan_socks5_connect_http_mitm(
            request_id,
            target,
            &self.plugin_instance,
            self.plugin_service.as_ref(),
        )
    }

    pub fn plan_plain_http(
        &self,
        message: &NativePlainHttpMessage,
    ) -> NativePlainHttpRewriteReport {
        let mut report = plan_and_apply_plain_http_mitm(
            message,
            &self.plugin_instance,
            self.plugin_service.as_ref(),
        );
        if let Some(script_executor) = self.script_executor.as_ref() {
            apply_node_script_dispatch_to_plain_http_rewrite_report(
                &mut report,
                message,
                script_executor,
            );
        }
        report
    }
}

impl fmt::Debug for NativeHttpMitmPluginHook {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeHttpMitmPluginHook")
            .field("plugin_id", &self.plugin_instance.manifest.id)
            .field("plugin_version", &self.plugin_instance.manifest.version)
            .field(
                "script_executor",
                &self.script_executor.as_ref().map(|_| "[configured]"),
            )
            .finish_non_exhaustive()
    }
}

fn apply_node_script_dispatch_to_plain_http_rewrite_report(
    report: &mut NativePlainHttpRewriteReport,
    original_message: &NativePlainHttpMessage,
    script_executor: &NativeNodeScriptExecutor,
) {
    let Some(dispatch) = report
        .outcome
        .as_ref()
        .and_then(|outcome| outcome.script_dispatch.as_ref())
    else {
        return;
    };
    if report.terminal_action.is_some() {
        return;
    }

    let script_message = NativePlainHttpMessage {
        request_id: original_message.request_id.clone(),
        url: report.url.clone(),
        method: original_message.method.clone(),
        phase: original_message.phase,
        status_code: report.final_status_code,
        headers: report.headers.clone(),
        body: report.body.clone(),
    };
    let execution = script_executor.execute(dispatch, &script_message);
    report.diagnostics.extend(execution.diagnostics.clone());
    if !execution.executed {
        return;
    }

    report.script_dispatch_executed = true;
    report.script_dispatch_deferred = false;
    if let Some(url) = execution.url {
        if script_url_mutation_preserves_authority(&report.url, &url) {
            report.url = url;
            report.applied = true;
        } else {
            report.diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Warning,
                ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_URL_MUTATION_BLOCKED_CODE,
                "native HTTP script runtime ignored a cross-authority or scheme-changing URL mutation",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
        }
    }
    if let Some(headers) = execution.headers {
        report.headers = headers;
        report.applied = true;
    }
    if let Some(body) = execution.body {
        report.body = body;
        report.applied = true;
    }
    if let Some(status_code) = execution.status_code {
        report.final_status_code = Some(status_code);
        report.applied = true;
    }
}

fn script_dispatch_matches_message(
    dispatch: &HttpMitmScriptDispatch,
    message: &NativePlainHttpMessage,
) -> bool {
    matches!(
        (dispatch.kind, dispatch.phase, message.phase),
        (
            HttpMitmScriptKind::Request,
            HttpMitmPhase::Request,
            HttpMitmPhase::Request
        ) | (
            HttpMitmScriptKind::Response,
            HttpMitmPhase::Response,
            HttpMitmPhase::Response
        )
    )
}

fn script_execution_deferred(message: &'static str) -> NativeHttpScriptExecutionReport {
    NativeHttpScriptExecutionReport {
        executed: false,
        applied: false,
        url: None,
        headers: None,
        body: None,
        status_code: None,
        diagnostics: vec![engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_DEFERRED_CODE,
            message,
            SOURCE_ENGINE_NATIVE_MITM,
        )],
    }
}

fn script_execution_failed(message: &'static str) -> NativeHttpScriptExecutionReport {
    NativeHttpScriptExecutionReport {
        executed: false,
        applied: false,
        url: None,
        headers: None,
        body: None,
        status_code: None,
        diagnostics: vec![engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_FAILED_CODE,
            message,
            SOURCE_ENGINE_NATIVE_MITM,
        )],
    }
}

fn script_headers_to_map(headers: &[MetadataEntry]) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for header in headers {
        values.insert(header.key.clone(), header.value.clone());
    }
    values
}

fn script_headers_from_map(headers: BTreeMap<String, String>) -> Option<Vec<MetadataEntry>> {
    let mut values = Vec::with_capacity(headers.len());
    for (key, value) in headers {
        if key.trim().is_empty()
            || key.contains('\r')
            || key.contains('\n')
            || value.contains('\r')
            || value.contains('\n')
        {
            return None;
        }
        values.push(MetadataEntry { key, value });
    }
    Some(values)
}

fn script_phase_name(phase: HttpMitmPhase) -> &'static str {
    match phase {
        HttpMitmPhase::Request => "request",
        HttpMitmPhase::Response => "response",
    }
}

fn bounded_script_timeout(rule_timeout_ms: usize, runtime_max_timeout_ms: usize) -> usize {
    let requested = if rule_timeout_ms == 0 {
        SCRIPT_RUNTIME_DEFAULT_TIMEOUT_MS
    } else {
        rule_timeout_ms
    };
    let runtime_max_timeout_ms = if runtime_max_timeout_ms == 0 {
        SCRIPT_RUNTIME_HARD_MAX_TIMEOUT_MS
    } else {
        runtime_max_timeout_ms.min(SCRIPT_RUNTIME_HARD_MAX_TIMEOUT_MS)
    };
    requested.min(runtime_max_timeout_ms).max(1)
}

fn write_script_runtime_body(body: &[u8]) -> Result<std::path::PathBuf, ()> {
    for _ in 0..16 {
        let sequence = SCRIPT_RUNTIME_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "networkcore-script-body-{}-{sequence}.tmp",
            std::process::id()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&path);
        let Ok(mut file) = file else {
            continue;
        };
        if file.write_all(body).is_ok() && file.flush().is_ok() {
            return Ok(path);
        }
        let _ = std::fs::remove_file(&path);
        return Err(());
    }
    Err(())
}

fn script_url_mutation_preserves_authority(current_url: &str, updated_url: &str) -> bool {
    let Some((current_scheme, current_target)) = parse_script_absolute_url(current_url) else {
        return false;
    };
    let Some((updated_scheme, updated_target)) = parse_script_absolute_url(updated_url) else {
        return false;
    };
    current_scheme == updated_scheme
        && current_target
            .target_host
            .eq_ignore_ascii_case(&updated_target.target_host)
        && current_target.target_port == updated_target.target_port
}

fn parse_script_absolute_url(url: &str) -> Option<(&'static str, ParsedExplicitHttpProxyTarget)> {
    if let Some(rest) = url.strip_prefix("https://") {
        return parse_absolute_http_proxy_target("https", rest, 443)
            .map(|target| ("https", target));
    }
    if let Some(rest) = url.strip_prefix("http://") {
        return parse_absolute_http_proxy_target("http", rest, 80).map(|target| ("http", target));
    }
    None
}

#[derive(Clone, PartialEq, Eq)]
pub struct NativeTlsMitmCaMaterial {
    certificate_pem: String,
    private_key_pem: String,
}

impl NativeTlsMitmCaMaterial {
    pub fn new(certificate_pem: impl Into<String>, private_key_pem: impl Into<String>) -> Self {
        Self {
            certificate_pem: certificate_pem.into(),
            private_key_pem: private_key_pem.into(),
        }
    }

    fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }

    fn certificate_pem_ready(&self) -> bool {
        !self.certificate_pem.trim().is_empty()
    }

    fn private_key_pem_ready(&self) -> bool {
        !self.private_key_pem.trim().is_empty()
    }
}

impl fmt::Debug for NativeTlsMitmCaMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeTlsMitmCaMaterial")
            .field("certificate_pem", &"[redacted]")
            .field("private_key_pem", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone)]
struct NativeLoopbackTcpAcceptLoopIdentity {
    listener_id: String,
    listener_kind: ListenerKind,
    outbound_handler_id: String,
    outbound_handler: NativeOutboundHandlerHandle,
    http_mitm_hook: Option<NativeHttpMitmPluginHook>,
    tls_mitm_ca_material: Option<NativeTlsMitmCaMaterial>,
    local_host: String,
    local_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5Greeting {
    pub version: u8,
    pub auth_methods: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5GreetingReadReport {
    pub greeting: Option<NativeSocks5Greeting>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5AuthMethodDecision {
    NoAuthenticationRequired,
    NoAcceptableMethods,
}

impl NativeSocks5AuthMethodDecision {
    pub const fn method_code(self) -> u8 {
        match self {
            Self::NoAuthenticationRequired => SOCKS5_AUTH_METHOD_NO_AUTHENTICATION_REQUIRED,
            Self::NoAcceptableMethods => SOCKS5_AUTH_METHOD_NO_ACCEPTABLE_METHODS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5AuthMethodSelectionReport {
    pub decision: NativeSocks5AuthMethodDecision,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5AuthMethodResponseWriteReport {
    pub response: [u8; 2],
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5CommandHeader {
    pub version: u8,
    pub command: u8,
    pub reserved: u8,
    pub address_type: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5CommandHeaderReadReport {
    pub command_header: Option<NativeSocks5CommandHeader>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5CommandDecision {
    Connect,
    UnsupportedCommand,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5CommandSupportReport {
    pub decision: NativeSocks5CommandDecision,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeSocks5Address {
    Ipv4([u8; 4]),
    DomainName(String),
    Ipv6([u8; 16]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5ConnectTarget {
    pub address: NativeSocks5Address,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5ConnectTargetReadReport {
    pub target: Option<NativeSocks5ConnectTarget>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5ConnectHttpMitmPlanReport {
    pub request_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub url: String,
    pub event: HttpMitmEvent,
    pub outcome: Option<HttpMitmOutcome>,
    pub applied: bool,
    pub audits: Vec<AuditEvent>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTlsMitmFoundationReport {
    pub request_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub target_url: String,
    pub connect_tunnel_ready: bool,
    pub downstream_tls_termination_ready: bool,
    pub upstream_tls_forwarding_ready: bool,
    pub https_request_rewrite_ready: bool,
    pub https_response_rewrite_ready: bool,
    pub script_dispatch_ready: bool,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTlsClientHelloObservationReport {
    pub request_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub client_hello_observed: bool,
    pub sni_hostname: Option<String>,
    pub tls_record_version: Option<String>,
    pub tls_handshake_version: Option<String>,
    pub downstream_tls_termination_ready: bool,
    pub https_request_rewrite_ready: bool,
    pub https_response_rewrite_ready: bool,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeControlledTlsTerminationPlanReport {
    pub request_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub target_url: String,
    pub connect_tunnel_ready: bool,
    pub client_hello_observed: bool,
    pub sni_hostname: Option<String>,
    pub tls_record_version: Option<String>,
    pub tls_handshake_version: Option<String>,
    pub ca_certificate_pem_ready: bool,
    pub ca_private_key_pem_ready: bool,
    pub downstream_tls_termination_plan_ready: bool,
    pub upstream_tls_forwarding_ready: bool,
    pub live_https_decryption_ready: bool,
    pub https_request_rewrite_ready: bool,
    pub https_response_rewrite_ready: bool,
    pub script_dispatch_ready: bool,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct NativeTlsLeafCertificateMaterial {
    pub authority: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub certificate_der: Vec<u8>,
    pub private_key_der: Vec<u8>,
}

impl fmt::Debug for NativeTlsLeafCertificateMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeTlsLeafCertificateMaterial")
            .field("authority", &self.authority)
            .field("certificate_pem", &"[redacted]")
            .field("private_key_pem", &"[redacted]")
            .field("certificate_der", &"[redacted]")
            .field("private_key_der", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTlsLeafCertificateIssueReport {
    pub authority: String,
    pub issued: bool,
    pub material: Option<NativeTlsLeafCertificateMaterial>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone)]
pub struct NativeTlsServerConfigBuildReport {
    pub authority: String,
    pub server_config_ready: bool,
    pub server_config: Option<Arc<ServerConfig>>,
    pub diagnostics: Vec<Diagnostic>,
}

impl fmt::Debug for NativeTlsServerConfigBuildReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeTlsServerConfigBuildReport")
            .field("authority", &self.authority)
            .field("server_config_ready", &self.server_config_ready)
            .field(
                "server_config",
                &self.server_config.as_ref().map(|_| "[configured]"),
            )
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

#[derive(Clone)]
pub struct NativeTlsUpstreamClientConfigBuildReport {
    pub client_config_ready: bool,
    pub client_config: Option<Arc<ClientConfig>>,
    pub diagnostics: Vec<Diagnostic>,
}

impl fmt::Debug for NativeTlsUpstreamClientConfigBuildReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeTlsUpstreamClientConfigBuildReport")
            .field("client_config_ready", &self.client_config_ready)
            .field(
                "client_config",
                &self.client_config.as_ref().map(|_| "[configured]"),
            )
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeHttpsRequestRewritePreviewReport {
    pub request_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub target_url: String,
    pub controlled_tls_termination_plan_ready: bool,
    pub https_request_rewrite_preview_ready: bool,
    pub applied: bool,
    pub terminal_action: Option<String>,
    pub final_status_code: Option<u16>,
    pub redirect_location: Option<String>,
    pub header_mutation_count: usize,
    pub body_mutation_deferred: bool,
    pub https_response_rewrite_preview_ready: bool,
    pub https_response_rewrite_ready: bool,
    pub script_dispatch_ready: bool,
    pub script_dispatch_deferred: bool,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeHttpsResponseRewritePreviewReport {
    pub request_id: String,
    pub target_host: String,
    pub target_port: u16,
    pub target_url: String,
    pub controlled_tls_termination_plan_ready: bool,
    pub https_response_rewrite_preview_ready: bool,
    pub applied: bool,
    pub terminal_action: Option<String>,
    pub final_status_code: Option<u16>,
    pub redirect_location: Option<String>,
    pub header_mutation_count: usize,
    pub content_type: Option<String>,
    pub content_type_guard_ready: bool,
    pub body_size_bytes: usize,
    pub body_size_limit_bytes: usize,
    pub body_buffering_guard_ready: bool,
    pub body_mutated: bool,
    pub body_mutation_deferred: bool,
    pub https_request_rewrite_preview_ready: bool,
    pub https_response_rewrite_ready: bool,
    pub script_dispatch_ready: bool,
    pub script_dispatch_deferred: bool,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePlainHttpMessage {
    pub request_id: String,
    pub url: String,
    pub method: Option<String>,
    pub phase: HttpMitmPhase,
    pub status_code: Option<u16>,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePlainHttpRewriteApplication {
    pub applied: bool,
    pub terminal_action: Option<String>,
    pub final_status_code: Option<u16>,
    pub redirect_location: Option<String>,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
    pub script_dispatch_deferred: bool,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePlainHttpRewriteReport {
    pub request_id: String,
    pub url: String,
    pub event: HttpMitmEvent,
    pub outcome: Option<HttpMitmOutcome>,
    pub applied: bool,
    pub terminal_action: Option<String>,
    pub final_status_code: Option<u16>,
    pub redirect_location: Option<String>,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
    pub script_dispatch_deferred: bool,
    pub script_dispatch_executed: bool,
    pub audits: Vec<AuditEvent>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeExplicitHttpProxyRequest {
    pub request_id: String,
    pub method: String,
    pub target_url: String,
    pub target_host: String,
    pub target_port: u16,
    pub origin_path: String,
    pub version: String,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeExplicitHttpProxyRequestReadReport {
    pub request: Option<NativeExplicitHttpProxyRequest>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePlainHttpProxyResponse {
    pub version: String,
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: Vec<MetadataEntry>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePlainHttpProxyResponseReadReport {
    pub response: Option<NativePlainHttpProxyResponse>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativePlainHttpProxyWriteReport {
    pub bytes: Vec<u8>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5RouteOutboundDecision {
    Unwired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeSocks5RouteOutboundBehavior {
    ProxyViaSocksOutbound {
        target: NativeSocks5ConnectTarget,
        outbound_handler: NativeOutboundHandlerHandle,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5RouteOutboundSelectionReport {
    pub behavior: NativeSocks5RouteOutboundBehavior,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectRequestFrameReport {
    pub frame: Vec<u8>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundTcpConnectionPlan {
    pub outbound_handler_id: String,
    pub outbound_endpoint: Endpoint,
    pub target: NativeSocks5ConnectTarget,
    pub request_frame: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundTcpConnectionPlanReport {
    pub plan: Option<NativeSocks5OutboundTcpConnectionPlan>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug)]
pub struct NativeSocks5OutboundTcpConnectionAttemptReport {
    pub stream: Option<TcpStream>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectRequestWriteReport {
    pub request_frame: Vec<u8>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectResponse {
    pub version: u8,
    pub reply: u8,
    pub reserved: u8,
    pub address_type: u8,
    pub bound_address: NativeSocks5Address,
    pub bound_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectResponseReadReport {
    pub response: Option<NativeSocks5OutboundConnectResponse>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5OutboundConnectResponseDecision {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectResponseDecisionReport {
    pub decision: NativeSocks5OutboundConnectResponseDecision,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5OutboundConnectRelayReadiness {
    Ready,
    Blocked,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectRelayReadinessReport {
    pub readiness: NativeSocks5OutboundConnectRelayReadiness,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5OutboundConnectDataRelayPlanDecision {
    Ready,
    Blocked,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectDataRelayPlanReport {
    pub decision: NativeSocks5OutboundConnectDataRelayPlanDecision,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectDataRelayReport {
    pub client_to_outbound_bytes: u64,
    pub outbound_to_client_bytes: u64,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5OutboundConnectClientSuccessResponseReadiness {
    Ready,
    Blocked,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectClientSuccessResponseReadinessReport {
    pub readiness: NativeSocks5OutboundConnectClientSuccessResponseReadiness,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision {
    Ready,
    Blocked,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectClientSuccessResponseWritePlanReport {
    pub decision: NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5OutboundConnectClientSuccessResponseWriteReport {
    pub response_frame: Vec<u8>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5RouteOutboundReport {
    pub decision: NativeSocks5RouteOutboundDecision,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeSocks5ConnectFailureResponseWriteReport {
    pub response: [u8; 10],
    pub diagnostics: Vec<Diagnostic>,
}

pub fn read_socks5_greeting<R>(reader: &mut R) -> NativeSocks5GreetingReadReport
where
    R: Read,
{
    let mut header = [0_u8; 2];
    if reader.read_exact(&mut header).is_err() {
        return NativeSocks5GreetingReadReport {
            greeting: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_FAILED_CODE,
                "native SOCKS5 greeting header could not be read",
            )],
        };
    }

    let version = header[0];
    let method_count = header[1] as usize;

    if version != SOCKS5_VERSION {
        return NativeSocks5GreetingReadReport {
            greeting: Some(NativeSocks5Greeting {
                version,
                auth_methods: Vec::new(),
            }),
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_INVALID_CODE,
                "native SOCKS5 greeting version is unsupported",
            )],
        };
    }

    if method_count == 0 {
        return NativeSocks5GreetingReadReport {
            greeting: Some(NativeSocks5Greeting {
                version,
                auth_methods: Vec::new(),
            }),
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_INVALID_CODE,
                "native SOCKS5 greeting must advertise at least one auth method",
            )],
        };
    }

    let mut auth_methods = vec![0_u8; method_count];
    if reader.read_exact(&mut auth_methods).is_err() {
        return NativeSocks5GreetingReadReport {
            greeting: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_FAILED_CODE,
                "native SOCKS5 greeting auth methods could not be read",
            )],
        };
    }

    NativeSocks5GreetingReadReport {
        greeting: Some(NativeSocks5Greeting {
            version,
            auth_methods,
        }),
        diagnostics: vec![runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_CODE,
            "native SOCKS5 greeting version and auth methods were read",
        )],
    }
}

pub fn select_socks5_auth_method(
    greeting: &NativeSocks5Greeting,
) -> NativeSocks5AuthMethodSelectionReport {
    if greeting.version == SOCKS5_VERSION
        && greeting
            .auth_methods
            .contains(&SOCKS5_AUTH_METHOD_NO_AUTHENTICATION_REQUIRED)
    {
        return NativeSocks5AuthMethodSelectionReport {
            decision: NativeSocks5AuthMethodDecision::NoAuthenticationRequired,
            diagnostics: vec![runtime_info(
                ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_SELECTED_CODE,
                "native SOCKS5 no-auth method was selected",
            )],
        };
    }

    NativeSocks5AuthMethodSelectionReport {
        decision: NativeSocks5AuthMethodDecision::NoAcceptableMethods,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_UNSUPPORTED_CODE,
            "native SOCKS5 greeting does not advertise a supported auth method",
        )],
    }
}

pub fn write_socks5_auth_method_response<W>(
    writer: &mut W,
    decision: NativeSocks5AuthMethodDecision,
) -> NativeSocks5AuthMethodResponseWriteReport
where
    W: Write,
{
    let response = [SOCKS5_VERSION, decision.method_code()];
    let diagnostic = if writer.write_all(&response).is_ok() {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_RESPONSE_WRITTEN_CODE,
            "native SOCKS5 auth method response was written",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_RESPONSE_WRITE_FAILED_CODE,
            "native SOCKS5 auth method response could not be written",
        )
    };

    NativeSocks5AuthMethodResponseWriteReport {
        response,
        diagnostics: vec![diagnostic],
    }
}

pub fn read_socks5_command_header<R>(reader: &mut R) -> NativeSocks5CommandHeaderReadReport
where
    R: Read,
{
    let mut header = [0_u8; 4];
    if reader.read_exact(&mut header).is_err() {
        return NativeSocks5CommandHeaderReadReport {
            command_header: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_READ_FAILED_CODE,
                "native SOCKS5 command header could not be read",
            )],
        };
    }

    let command_header = NativeSocks5CommandHeader {
        version: header[0],
        command: header[1],
        reserved: header[2],
        address_type: header[3],
    };
    let diagnostic = if socks5_command_header_valid(&command_header) {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_READ_CODE,
            "native SOCKS5 command header was read",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_INVALID_CODE,
            "native SOCKS5 command header is invalid",
        )
    };

    NativeSocks5CommandHeaderReadReport {
        command_header: Some(command_header),
        diagnostics: vec![diagnostic],
    }
}

pub fn reject_unsupported_socks5_command(
    command_header: &NativeSocks5CommandHeader,
) -> NativeSocks5CommandSupportReport {
    if command_header.command == SOCKS5_COMMAND_CONNECT {
        return NativeSocks5CommandSupportReport {
            decision: NativeSocks5CommandDecision::Connect,
            diagnostics: Vec::new(),
        };
    }

    NativeSocks5CommandSupportReport {
        decision: NativeSocks5CommandDecision::UnsupportedCommand,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_UNSUPPORTED_CODE,
            "native SOCKS5 command is not supported",
        )],
    }
}

pub fn read_socks5_connect_target<R>(
    reader: &mut R,
    command_header: &NativeSocks5CommandHeader,
) -> NativeSocks5ConnectTargetReadReport
where
    R: Read,
{
    if !socks5_command_header_valid(command_header)
        || command_header.command != SOCKS5_COMMAND_CONNECT
    {
        return NativeSocks5ConnectTargetReadReport {
            target: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_INVALID_CODE,
                "native SOCKS5 CONNECT target requires a valid CONNECT command header",
            )],
        };
    }

    let address = match command_header.address_type {
        SOCKS5_ADDRESS_TYPE_IPV4 => {
            let mut address = [0_u8; 4];
            if reader.read_exact(&mut address).is_err() {
                return socks5_connect_target_read_failed(
                    "native SOCKS5 CONNECT IPv4 target address could not be read",
                );
            }
            NativeSocks5Address::Ipv4(address)
        }
        SOCKS5_ADDRESS_TYPE_DOMAIN_NAME => {
            let mut length = [0_u8; 1];
            if reader.read_exact(&mut length).is_err() {
                return socks5_connect_target_read_failed(
                    "native SOCKS5 CONNECT domain length could not be read",
                );
            }
            if length[0] == 0 {
                return NativeSocks5ConnectTargetReadReport {
                    target: None,
                    diagnostics: vec![runtime_warning(
                        ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_INVALID_CODE,
                        "native SOCKS5 CONNECT domain target cannot be empty",
                    )],
                };
            }

            let mut domain_name = vec![0_u8; length[0] as usize];
            if reader.read_exact(&mut domain_name).is_err() {
                return socks5_connect_target_read_failed(
                    "native SOCKS5 CONNECT domain target could not be read",
                );
            }

            match String::from_utf8(domain_name) {
                Ok(domain_name) => NativeSocks5Address::DomainName(domain_name),
                Err(_) => {
                    return NativeSocks5ConnectTargetReadReport {
                        target: None,
                        diagnostics: vec![runtime_warning(
                            ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_INVALID_CODE,
                            "native SOCKS5 CONNECT domain target must be valid UTF-8",
                        )],
                    };
                }
            }
        }
        SOCKS5_ADDRESS_TYPE_IPV6 => {
            let mut address = [0_u8; 16];
            if reader.read_exact(&mut address).is_err() {
                return socks5_connect_target_read_failed(
                    "native SOCKS5 CONNECT IPv6 target address could not be read",
                );
            }
            NativeSocks5Address::Ipv6(address)
        }
        _ => {
            return NativeSocks5ConnectTargetReadReport {
                target: None,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_INVALID_CODE,
                    "native SOCKS5 CONNECT target address type is unsupported",
                )],
            };
        }
    };

    let mut port = [0_u8; 2];
    if reader.read_exact(&mut port).is_err() {
        return socks5_connect_target_read_failed(
            "native SOCKS5 CONNECT target port could not be read",
        );
    }

    let target = NativeSocks5ConnectTarget {
        address,
        port: u16::from_be_bytes(port),
    };
    let diagnostic = if socks5_connect_target_valid(&target) {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_CODE,
            "native SOCKS5 CONNECT target address and port were read",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_INVALID_CODE,
            "native SOCKS5 CONNECT target address or port is invalid",
        )
    };

    NativeSocks5ConnectTargetReadReport {
        target: Some(target),
        diagnostics: vec![diagnostic],
    }
}

pub fn plan_socks5_connect_http_mitm(
    request_id: impl Into<String>,
    target: &NativeSocks5ConnectTarget,
    plugin_instance: &PluginInstance,
    plugin_service: &dyn MitmPluginService,
) -> NativeSocks5ConnectHttpMitmPlanReport {
    let request_id = request_id.into();
    let target_host = socks5_target_host(target);
    let target_port = target.port;
    let url = socks5_connect_http_mitm_url(target);
    let host_header = socks5_target_header_authority(target);
    let event = HttpMitmEvent {
        request_id: request_id.clone(),
        url: url.clone(),
        method: Some("CONNECT".to_string()),
        phase: HttpMitmPhase::Request,
        status_code: None,
        headers: vec![
            MetadataEntry {
                key: "host".to_string(),
                value: host_header,
            },
            MetadataEntry {
                key: "networkcore.connect_target_host".to_string(),
                value: target_host.clone(),
            },
            MetadataEntry {
                key: "networkcore.connect_target_port".to_string(),
                value: target_port.to_string(),
            },
        ],
        body: Vec::new(),
    };
    let mut diagnostics = vec![engine_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_EVENT_PLANNED_CODE,
        "native SOCKS5 CONNECT target was mapped to a rich HTTP MITM event",
        SOURCE_ENGINE_NATIVE_MITM,
    )];

    match plugin_service.handle_http_mitm_event(plugin_instance, &event) {
        Ok(outcome) => {
            let audits = outcome.audits.clone();
            let plan_requires_application = http_mitm_outcome_requires_application(&outcome);
            diagnostics.extend(outcome.diagnostics.clone());
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_READY_CODE,
                "native SOCKS5 CONNECT MITM plugin plan was produced",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
            if plan_requires_application {
                diagnostics.push(engine_diagnostic(
                    DiagnosticSeverity::Warning,
                    ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_NOT_APPLIED_CODE,
                    "native HTTP/TLS data plane has not applied the MITM plugin plan yet",
                    SOURCE_ENGINE_NATIVE_MITM,
                ));
            }

            NativeSocks5ConnectHttpMitmPlanReport {
                request_id,
                target_host,
                target_port,
                url,
                event,
                outcome: Some(outcome),
                applied: false,
                audits,
                diagnostics,
            }
        }
        Err(_error) => {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_FAILED_CODE,
                "native SOCKS5 CONNECT MITM plugin plan failed",
                SOURCE_ENGINE_NATIVE_MITM,
            ));

            NativeSocks5ConnectHttpMitmPlanReport {
                request_id,
                target_host,
                target_port,
                url,
                event,
                outcome: None,
                applied: false,
                audits: Vec::new(),
                diagnostics,
            }
        }
    }
}

pub fn plan_explicit_http_connect_tls_mitm_foundation(
    request: &NativeExplicitHttpProxyRequest,
) -> NativeTlsMitmFoundationReport {
    let connect_request = request.method.eq_ignore_ascii_case("CONNECT");
    let target_url = if request.target_url.starts_with("https://") {
        request.target_url.clone()
    } else {
        let authority = http_url_authority(&request.target_host, request.target_port, 443);
        format!("https://{authority}/")
    };
    let mut diagnostics = Vec::new();

    if connect_request {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_FOUNDATION_READY_CODE,
            "native explicit HTTP proxy CONNECT TLS foundation can establish a bounded tunnel through the configured SOCKS outbound",
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    } else {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CONNECT_TLS_BLOCKED_CODE,
            "native explicit HTTP proxy TLS foundation requires a CONNECT request",
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    }

    NativeTlsMitmFoundationReport {
        request_id: request.request_id.clone(),
        target_host: request.target_host.clone(),
        target_port: request.target_port,
        target_url,
        connect_tunnel_ready: connect_request,
        downstream_tls_termination_ready: false,
        upstream_tls_forwarding_ready: connect_request,
        https_request_rewrite_ready: false,
        https_response_rewrite_ready: false,
        script_dispatch_ready: false,
        diagnostics,
    }
}

pub fn observe_explicit_http_connect_tls_client_hello(
    request: &NativeExplicitHttpProxyRequest,
    client_hello: &[u8],
) -> NativeTlsClientHelloObservationReport {
    let metadata = parse_tls_client_hello_metadata(client_hello);
    let (client_hello_observed, sni_hostname, tls_record_version, tls_handshake_version) =
        match metadata {
            Some(metadata) => (
                true,
                metadata.sni_hostname,
                Some(metadata.tls_record_version),
                Some(metadata.tls_handshake_version),
            ),
            None => (false, None, None, None),
        };
    let diagnostic = if client_hello_observed {
        engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CLIENT_HELLO_OBSERVED_CODE,
            "native explicit HTTP proxy CONNECT TLS ClientHello was observed before pass-through relay",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    } else {
        engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CLIENT_HELLO_DEFERRED_CODE,
            "native explicit HTTP proxy CONNECT TLS ClientHello was not available in the bounded pre-relay peek",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    };

    NativeTlsClientHelloObservationReport {
        request_id: request.request_id.clone(),
        target_host: request.target_host.clone(),
        target_port: request.target_port,
        client_hello_observed,
        sni_hostname,
        tls_record_version,
        tls_handshake_version,
        downstream_tls_termination_ready: false,
        https_request_rewrite_ready: false,
        https_response_rewrite_ready: false,
        diagnostics: vec![diagnostic],
    }
}

pub fn plan_explicit_http_connect_controlled_tls_termination(
    request: &NativeExplicitHttpProxyRequest,
    foundation: &NativeTlsMitmFoundationReport,
    client_hello: &NativeTlsClientHelloObservationReport,
    ca_certificate_pem_ready: bool,
    ca_private_key_pem_ready: bool,
) -> NativeControlledTlsTerminationPlanReport {
    let sni_authority_matches = client_hello.client_hello_observed
        && tls_sni_matches_connect_authority(
            &request.target_host,
            client_hello.sni_hostname.as_deref(),
        );
    let downstream_tls_termination_plan_ready = request.method.eq_ignore_ascii_case("CONNECT")
        && foundation.connect_tunnel_ready
        && foundation.upstream_tls_forwarding_ready
        && client_hello.client_hello_observed
        && sni_authority_matches
        && ca_certificate_pem_ready
        && ca_private_key_pem_ready;
    let mut diagnostics = Vec::new();
    if client_hello.client_hello_observed {
        diagnostics.push(engine_diagnostic(
            if sni_authority_matches {
                DiagnosticSeverity::Info
            } else {
                DiagnosticSeverity::Warning
            },
            if sni_authority_matches {
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SNI_AUTHORITY_MATCHED_CODE
            } else {
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SNI_AUTHORITY_MISMATCH_CODE
            },
            if sni_authority_matches {
                "native explicit HTTP proxy CONNECT authority matches the observed TLS SNI hostname"
            } else {
                "native explicit HTTP proxy CONNECT controlled TLS termination is deferred because the observed TLS SNI hostname does not match the CONNECT authority"
            },
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    }
    diagnostics.push(if downstream_tls_termination_plan_ready {
        engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_PLAN_READY_CODE,
            "native explicit HTTP proxy CONNECT controlled TLS termination plan is ready with observed ClientHello and NetworkCore CA material",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    } else {
        engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_DEFERRED_CODE,
            "native explicit HTTP proxy CONNECT controlled TLS termination is deferred until CONNECT tunnel, ClientHello, matching authority, and NetworkCore CA material are all ready",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    });

    NativeControlledTlsTerminationPlanReport {
        request_id: request.request_id.clone(),
        target_host: request.target_host.clone(),
        target_port: request.target_port,
        target_url: foundation.target_url.clone(),
        connect_tunnel_ready: foundation.connect_tunnel_ready,
        client_hello_observed: client_hello.client_hello_observed,
        sni_hostname: client_hello.sni_hostname.clone(),
        tls_record_version: client_hello.tls_record_version.clone(),
        tls_handshake_version: client_hello.tls_handshake_version.clone(),
        ca_certificate_pem_ready,
        ca_private_key_pem_ready,
        downstream_tls_termination_plan_ready,
        upstream_tls_forwarding_ready: foundation.upstream_tls_forwarding_ready,
        live_https_decryption_ready: false,
        https_request_rewrite_ready: false,
        https_response_rewrite_ready: false,
        script_dispatch_ready: false,
        diagnostics,
    }
}

pub fn issue_controlled_tls_termination_leaf_certificate(
    termination_plan: &NativeControlledTlsTerminationPlanReport,
    ca_certificate_pem: &str,
    ca_private_key_pem: &str,
) -> NativeTlsLeafCertificateIssueReport {
    let authority = termination_plan
        .target_host
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let sni_authority_matches =
        tls_sni_matches_connect_authority(&authority, termination_plan.sni_hostname.as_deref());
    let certificate_issue_ready = termination_plan.downstream_tls_termination_plan_ready
        && termination_plan.ca_certificate_pem_ready
        && termination_plan.ca_private_key_pem_ready
        && sni_authority_matches
        && !authority.is_empty();

    if !certificate_issue_ready {
        return NativeTlsLeafCertificateIssueReport {
            authority,
            issued: false,
            material: None,
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_DEFERRED_CODE,
                "native explicit HTTP proxy CONNECT leaf certificate issuance is deferred until the controlled TLS plan, CA material, and matching authority are ready",
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        };
    }

    let material = (|| {
        let issuer_key = KeyPair::from_pem(ca_private_key_pem).map_err(|error| {
            format!("NetworkCore CA private key could not be parsed for leaf issuance: {error}")
        })?;
        let issuer = Issuer::from_ca_cert_pem(ca_certificate_pem, issuer_key).map_err(|error| {
            format!("NetworkCore CA certificate could not be parsed for leaf issuance: {error}")
        })?;
        let mut leaf_params = CertificateParams::new(vec![authority.clone()]).map_err(|error| {
            format!("TLS leaf certificate authority could not be encoded: {error}")
        })?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, authority.clone());
        distinguished_name.push(DnType::OrganizationName, "AnixOps NetworkCore");
        leaf_params.distinguished_name = distinguished_name;
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let leaf_key = KeyPair::generate()
            .map_err(|error| format!("TLS leaf private key could not be generated: {error}"))?;
        let leaf_certificate = leaf_params.signed_by(&leaf_key, &issuer).map_err(|error| {
            format!("TLS leaf certificate could not be signed by the NetworkCore CA: {error}")
        })?;

        Ok::<NativeTlsLeafCertificateMaterial, String>(NativeTlsLeafCertificateMaterial {
            authority: authority.clone(),
            certificate_pem: leaf_certificate.pem(),
            private_key_pem: leaf_key.serialize_pem(),
            certificate_der: leaf_certificate.der().as_ref().to_vec(),
            private_key_der: leaf_key.serialize_der(),
        })
    })();

    match material {
        Ok(material) => NativeTlsLeafCertificateIssueReport {
            authority,
            issued: true,
            material: Some(material),
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_ISSUED_CODE,
                "native explicit HTTP proxy CONNECT issued an authority-bound TLS leaf certificate from the configured NetworkCore CA",
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        },
        Err(error) => NativeTlsLeafCertificateIssueReport {
            authority,
            issued: false,
            material: None,
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_FAILED_CODE,
                error,
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        },
    }
}

pub fn build_controlled_tls_termination_server_config(
    material: &NativeTlsLeafCertificateMaterial,
) -> NativeTlsServerConfigBuildReport {
    let authority = material
        .authority
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let server_config = (|| {
        if authority.is_empty()
            || material.certificate_der.is_empty()
            || material.private_key_der.is_empty()
        {
            return Err("controlled TLS server configuration requires authority-bound leaf certificate and private key material".to_string());
        }

        let certificate_chain = vec![CertificateDer::from(material.certificate_der.clone())];
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.private_key_der.clone()));
        let mut server_config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|error| format!("controlled TLS protocol configuration failed: {error}"))?
                .with_no_client_auth()
                .with_single_cert(certificate_chain, private_key)
                .map_err(|error| {
                    format!("controlled TLS server certificate configuration failed: {error}")
                })?;
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(server_config))
    })();

    match server_config {
        Ok(server_config) => NativeTlsServerConfigBuildReport {
            authority,
            server_config_ready: true,
            server_config: Some(server_config),
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SERVER_CONFIG_READY_CODE,
                "native explicit HTTP proxy CONNECT built a rustls downstream server configuration from authority-bound leaf material",
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        },
        Err(error) => NativeTlsServerConfigBuildReport {
            authority,
            server_config_ready: false,
            server_config: None,
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SERVER_CONFIG_FAILED_CODE,
                error,
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        },
    }
}

pub fn build_controlled_tls_upstream_client_config() -> NativeTlsUpstreamClientConfigBuildReport {
    let client_config = (|| {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if roots.is_empty() {
            return Err(
                "controlled TLS upstream configuration has no trusted web PKI roots".to_string(),
            );
        }

        let mut client_config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|error| {
                    format!("controlled TLS upstream protocol configuration failed: {error}")
                })?
                .with_root_certificates(roots)
                .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Arc::new(client_config))
    })();

    match client_config {
        Ok(client_config) => NativeTlsUpstreamClientConfigBuildReport {
            client_config_ready: true,
            client_config: Some(client_config),
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_UPSTREAM_CONFIG_READY_CODE,
                "native explicit HTTP proxy CONNECT built a rustls upstream client configuration with web PKI roots",
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        },
        Err(error) => NativeTlsUpstreamClientConfigBuildReport {
            client_config_ready: false,
            client_config: None,
            diagnostics: vec![engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_UPSTREAM_CONFIG_FAILED_CODE,
                error,
                SOURCE_ENGINE_NATIVE_MITM,
            )],
        },
    }
}

pub fn plan_and_apply_https_request_rewrite_preview(
    termination_plan: &NativeControlledTlsTerminationPlanReport,
    message: &NativePlainHttpMessage,
    outcome: &HttpMitmOutcome,
) -> NativeHttpsRequestRewritePreviewReport {
    let request_phase = matches!(message.phase, HttpMitmPhase::Request);
    let https_target = message.url.to_ascii_lowercase().starts_with("https://");
    let preview_ready = termination_plan.downstream_tls_termination_plan_ready
        && termination_plan.upstream_tls_forwarding_ready
        && request_phase
        && https_target;
    let mut diagnostics = Vec::new();

    if !preview_ready {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_PREVIEW_DEFERRED_CODE,
            "native explicit HTTP proxy HTTPS request rewrite preview is deferred until controlled TLS termination plan and request-phase HTTPS input are ready",
            SOURCE_ENGINE_NATIVE_MITM,
        ));

        return NativeHttpsRequestRewritePreviewReport {
            request_id: message.request_id.clone(),
            target_host: termination_plan.target_host.clone(),
            target_port: termination_plan.target_port,
            target_url: termination_plan.target_url.clone(),
            controlled_tls_termination_plan_ready: termination_plan
                .downstream_tls_termination_plan_ready,
            https_request_rewrite_preview_ready: false,
            applied: false,
            terminal_action: None,
            final_status_code: message.status_code,
            redirect_location: None,
            header_mutation_count: 0,
            body_mutation_deferred: outcome.body_mutation.is_some(),
            https_response_rewrite_preview_ready: false,
            https_response_rewrite_ready: false,
            script_dispatch_ready: false,
            script_dispatch_deferred: outcome.script_dispatch.is_some(),
            headers: message.headers.clone(),
            body: message.body.clone(),
            diagnostics,
        };
    }

    diagnostics.push(engine_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_PREVIEW_READY_CODE,
        "native explicit HTTP proxy HTTPS request rewrite preview is ready for reject, redirect, and request header mutation",
        SOURCE_ENGINE_NATIVE_MITM,
    ));

    let mut headers = message.headers.clone();
    let mut body = message.body.clone();
    let mut applied = false;
    let mut terminal_action = None;
    let mut final_status_code = message.status_code;
    let mut redirect_location = None;

    match &outcome.action {
        HttpMitmAction::Continue => {}
        HttpMitmAction::Reject { status_code } => {
            applied = true;
            terminal_action = Some("reject".to_string());
            final_status_code = Some(*status_code);
            headers.clear();
            set_plain_http_header(&mut headers, "Content-Length", "0");
            body.clear();
        }
        HttpMitmAction::Redirect {
            status_code,
            location,
        } => {
            applied = true;
            terminal_action = Some("redirect".to_string());
            final_status_code = Some(*status_code);
            redirect_location = Some(location.clone());
            set_plain_http_header(&mut headers, "Location", location);
            set_plain_http_header(&mut headers, "Content-Length", "0");
            body.clear();
        }
    }

    let mut header_mutation_count = 0;
    if terminal_action.is_none() {
        header_mutation_count =
            apply_plain_http_header_mutations(&mut headers, &outcome.header_mutations);
        applied = applied || header_mutation_count > 0;
    }

    let body_mutation_deferred = outcome.body_mutation.is_some();
    let script_dispatch_deferred = outcome.script_dispatch.is_some();
    if script_dispatch_deferred {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_SCRIPT_DEFERRED_CODE,
            "native explicit HTTP proxy HTTPS request rewrite preview recorded script dispatch but JavaScript execution remains deferred",
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    }

    NativeHttpsRequestRewritePreviewReport {
        request_id: message.request_id.clone(),
        target_host: termination_plan.target_host.clone(),
        target_port: termination_plan.target_port,
        target_url: termination_plan.target_url.clone(),
        controlled_tls_termination_plan_ready: termination_plan
            .downstream_tls_termination_plan_ready,
        https_request_rewrite_preview_ready: true,
        applied,
        terminal_action,
        final_status_code,
        redirect_location,
        header_mutation_count,
        body_mutation_deferred,
        https_response_rewrite_preview_ready: false,
        https_response_rewrite_ready: false,
        script_dispatch_ready: false,
        script_dispatch_deferred,
        headers,
        body,
        diagnostics,
    }
}

pub fn plan_and_apply_https_response_rewrite_preview(
    termination_plan: &NativeControlledTlsTerminationPlanReport,
    message: &NativePlainHttpMessage,
    outcome: &HttpMitmOutcome,
) -> NativeHttpsResponseRewritePreviewReport {
    let response_phase = matches!(message.phase, HttpMitmPhase::Response);
    let https_target = message.url.to_ascii_lowercase().starts_with("https://");
    let preview_ready = termination_plan.downstream_tls_termination_plan_ready
        && termination_plan.upstream_tls_forwarding_ready
        && response_phase
        && https_target;
    let mut diagnostics = Vec::new();

    if !preview_ready {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_PREVIEW_DEFERRED_CODE,
            "native explicit HTTP proxy HTTPS response rewrite preview is deferred until controlled TLS termination plan and response-phase HTTPS input are ready",
            SOURCE_ENGINE_NATIVE_MITM,
        ));

        return NativeHttpsResponseRewritePreviewReport {
            request_id: message.request_id.clone(),
            target_host: termination_plan.target_host.clone(),
            target_port: termination_plan.target_port,
            target_url: termination_plan.target_url.clone(),
            controlled_tls_termination_plan_ready: termination_plan
                .downstream_tls_termination_plan_ready,
            https_response_rewrite_preview_ready: false,
            applied: false,
            terminal_action: None,
            final_status_code: message.status_code,
            redirect_location: None,
            header_mutation_count: 0,
            content_type: plain_http_header_value(&message.headers, "Content-Type"),
            content_type_guard_ready: https_response_body_content_type_guard_ready(
                &message.headers,
            ),
            body_size_bytes: message.body.len(),
            body_size_limit_bytes: HTTP_PROXY_MAX_BODY_BYTES,
            body_buffering_guard_ready: https_response_body_buffering_guard_ready(
                &message.body,
                outcome
                    .body_mutation
                    .as_ref()
                    .map(|mutation| mutation.body.as_slice()),
            ),
            body_mutated: false,
            body_mutation_deferred: outcome.body_mutation.is_some(),
            https_request_rewrite_preview_ready: false,
            https_response_rewrite_ready: false,
            script_dispatch_ready: false,
            script_dispatch_deferred: outcome.script_dispatch.is_some(),
            headers: message.headers.clone(),
            body: message.body.clone(),
            diagnostics,
        };
    }

    diagnostics.push(engine_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_PREVIEW_READY_CODE,
        "native explicit HTTP proxy HTTPS response rewrite preview is ready for reject, redirect, response header mutation, and response body mutation",
        SOURCE_ENGINE_NATIVE_MITM,
    ));

    let mut headers = message.headers.clone();
    let mut body = message.body.clone();
    let mut applied = false;
    let mut terminal_action = None;
    let mut final_status_code = message.status_code;
    let mut redirect_location = None;
    let mut body_mutated = false;
    let mut body_mutation_deferred = outcome.body_mutation.is_some();

    match &outcome.action {
        HttpMitmAction::Continue => {}
        HttpMitmAction::Reject { status_code } => {
            applied = true;
            terminal_action = Some("reject".to_string());
            final_status_code = Some(*status_code);
            headers.clear();
            set_plain_http_header(&mut headers, "Content-Length", "0");
            body.clear();
        }
        HttpMitmAction::Redirect {
            status_code,
            location,
        } => {
            applied = true;
            terminal_action = Some("redirect".to_string());
            final_status_code = Some(*status_code);
            redirect_location = Some(location.clone());
            set_plain_http_header(&mut headers, "Location", location);
            set_plain_http_header(&mut headers, "Content-Length", "0");
            body.clear();
        }
    }

    let mut header_mutation_count = 0;
    if terminal_action.is_none() {
        header_mutation_count =
            apply_plain_http_header_mutations(&mut headers, &outcome.header_mutations);
        applied = applied || header_mutation_count > 0;

        let content_type_guard_ready = https_response_body_content_type_guard_ready(&headers);
        let body_buffering_guard_ready = https_response_body_buffering_guard_ready(
            &message.body,
            outcome
                .body_mutation
                .as_ref()
                .map(|mutation| mutation.body.as_slice()),
        );
        if let Some(body_mutation) = &outcome.body_mutation {
            if content_type_guard_ready && body_buffering_guard_ready {
                applied = true;
                body_mutated = true;
                body_mutation_deferred = false;
                body = body_mutation.body.clone();
            }
        }
    }

    let content_type = plain_http_header_value(&headers, "Content-Type");
    let content_type_guard_ready = https_response_body_content_type_guard_ready(&headers);
    let body_buffering_guard_ready = https_response_body_buffering_guard_ready(
        &message.body,
        outcome
            .body_mutation
            .as_ref()
            .map(|mutation| mutation.body.as_slice()),
    );
    let script_dispatch_deferred = outcome.script_dispatch.is_some();
    if script_dispatch_deferred {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_SCRIPT_DEFERRED_CODE,
            "native explicit HTTP proxy HTTPS response rewrite preview recorded script dispatch but JavaScript execution remains deferred",
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    }

    NativeHttpsResponseRewritePreviewReport {
        request_id: message.request_id.clone(),
        target_host: termination_plan.target_host.clone(),
        target_port: termination_plan.target_port,
        target_url: termination_plan.target_url.clone(),
        controlled_tls_termination_plan_ready: termination_plan
            .downstream_tls_termination_plan_ready,
        https_response_rewrite_preview_ready: true,
        applied,
        terminal_action,
        final_status_code,
        redirect_location,
        header_mutation_count,
        content_type,
        content_type_guard_ready,
        body_size_bytes: message.body.len(),
        body_size_limit_bytes: HTTP_PROXY_MAX_BODY_BYTES,
        body_buffering_guard_ready,
        body_mutated,
        body_mutation_deferred,
        https_request_rewrite_preview_ready: true,
        https_response_rewrite_ready: false,
        script_dispatch_ready: false,
        script_dispatch_deferred,
        headers,
        body,
        diagnostics,
    }
}

pub fn reject_unwired_socks5_route_outbound(
    _target: &NativeSocks5ConnectTarget,
) -> NativeSocks5RouteOutboundReport {
    NativeSocks5RouteOutboundReport {
        decision: NativeSocks5RouteOutboundDecision::Unwired,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_UNWIRED_CODE,
            "native SOCKS5 CONNECT route and outbound data plane are not wired",
        )],
    }
}

pub fn select_socks5_route_outbound_behavior(
    target: &NativeSocks5ConnectTarget,
    outbound_handler: &NativeOutboundHandlerHandle,
) -> NativeSocks5RouteOutboundSelectionReport {
    NativeSocks5RouteOutboundSelectionReport {
        behavior: NativeSocks5RouteOutboundBehavior::ProxyViaSocksOutbound {
            target: target.clone(),
            outbound_handler: outbound_handler.clone(),
        },
        diagnostics: vec![runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_SELECTED_CODE,
            "native SOCKS5 CONNECT route selected the configured outbound handler",
        )],
    }
}

pub fn build_socks5_outbound_connect_request_frame(
    behavior: &NativeSocks5RouteOutboundBehavior,
) -> NativeSocks5OutboundConnectRequestFrameReport {
    let NativeSocks5RouteOutboundBehavior::ProxyViaSocksOutbound { target, .. } = behavior;

    if let Some(frame) = socks5_outbound_connect_request_frame_bytes(target) {
        return NativeSocks5OutboundConnectRequestFrameReport {
            frame,
            diagnostics: vec![runtime_info(
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_GENERATED_CODE,
                "native SOCKS5 outbound CONNECT request frame was generated",
            )],
        };
    }

    NativeSocks5OutboundConnectRequestFrameReport {
        frame: Vec::new(),
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_INVALID_CODE,
            "native SOCKS5 outbound CONNECT request frame target is invalid",
        )],
    }
}

pub fn plan_socks5_outbound_tcp_connection(
    behavior: &NativeSocks5RouteOutboundBehavior,
    request_frame: &[u8],
) -> NativeSocks5OutboundTcpConnectionPlanReport {
    let NativeSocks5RouteOutboundBehavior::ProxyViaSocksOutbound {
        target,
        outbound_handler,
    } = behavior;

    if outbound_handler.protocol != Protocol::Socks
        || outbound_handler.endpoint.host.trim().is_empty()
        || outbound_handler.endpoint.port == 0
        || request_frame.is_empty()
    {
        return NativeSocks5OutboundTcpConnectionPlanReport {
            plan: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_PLAN_INVALID_CODE,
                "native SOCKS5 outbound TCP connection plan is invalid",
            )],
        };
    }

    NativeSocks5OutboundTcpConnectionPlanReport {
        plan: Some(NativeSocks5OutboundTcpConnectionPlan {
            outbound_handler_id: outbound_handler.node_id.clone(),
            outbound_endpoint: outbound_handler.endpoint.clone(),
            target: target.clone(),
            request_frame: request_frame.to_vec(),
        }),
        diagnostics: vec![runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_PLANNED_CODE,
            "native SOCKS5 outbound TCP connection plan was created",
        )],
    }
}

pub fn attempt_socks5_outbound_tcp_connection(
    plan: &NativeSocks5OutboundTcpConnectionPlan,
) -> NativeSocks5OutboundTcpConnectionAttemptReport {
    let Some(socket_addr) = endpoint_socket_addr(&plan.outbound_endpoint) else {
        return NativeSocks5OutboundTcpConnectionAttemptReport {
            stream: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_FAILED_CODE,
                "native SOCKS5 outbound TCP connection attempt requires an IP endpoint",
            )],
        };
    };

    match TcpStream::connect_timeout(
        &socket_addr,
        Duration::from_millis(OUTBOUND_CONNECTION_ATTEMPT_TIMEOUT_MS),
    ) {
        Ok(stream) => NativeSocks5OutboundTcpConnectionAttemptReport {
            stream: Some(stream),
            diagnostics: vec![runtime_info(
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_SUCCEEDED_CODE,
                "native SOCKS5 outbound TCP connection attempt succeeded",
            )],
        },
        Err(_) => NativeSocks5OutboundTcpConnectionAttemptReport {
            stream: None,
            diagnostics: vec![runtime_warning(
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_FAILED_CODE,
                "native SOCKS5 outbound TCP connection attempt failed",
            )],
        },
    }
}

pub fn write_socks5_outbound_connect_request<W>(
    writer: &mut W,
    plan: &NativeSocks5OutboundTcpConnectionPlan,
) -> NativeSocks5OutboundConnectRequestWriteReport
where
    W: Write,
{
    let request_frame = plan.request_frame.clone();
    let diagnostic = if request_frame.is_empty() {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITE_FAILED_CODE,
            "native SOCKS5 outbound CONNECT request requires a non-empty frame",
        )
    } else if writer.write_all(&request_frame).is_ok() {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE,
            "native SOCKS5 outbound CONNECT request was written",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITE_FAILED_CODE,
            "native SOCKS5 outbound CONNECT request could not be written",
        )
    };

    NativeSocks5OutboundConnectRequestWriteReport {
        request_frame,
        diagnostics: vec![diagnostic],
    }
}

pub fn read_socks5_outbound_connect_response<R>(
    reader: &mut R,
) -> NativeSocks5OutboundConnectResponseReadReport
where
    R: Read,
{
    let mut header = [0_u8; 4];
    if reader.read_exact(&mut header).is_err() {
        return socks5_outbound_connect_response_read_failed(
            "native SOCKS5 outbound CONNECT response header could not be read",
        );
    }

    let version = header[0];
    let reply = header[1];
    let reserved = header[2];
    let address_type = header[3];
    let bound_address = match address_type {
        SOCKS5_ADDRESS_TYPE_IPV4 => {
            let mut address = [0_u8; 4];
            if reader.read_exact(&mut address).is_err() {
                return socks5_outbound_connect_response_read_failed(
                    "native SOCKS5 outbound CONNECT response IPv4 bound address could not be read",
                );
            }
            NativeSocks5Address::Ipv4(address)
        }
        SOCKS5_ADDRESS_TYPE_DOMAIN_NAME => {
            let mut length = [0_u8; 1];
            if reader.read_exact(&mut length).is_err() {
                return socks5_outbound_connect_response_read_failed(
                    "native SOCKS5 outbound CONNECT response domain length could not be read",
                );
            }
            if length[0] == 0 {
                return NativeSocks5OutboundConnectResponseReadReport {
                    response: None,
                    diagnostics: vec![runtime_warning(
                        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_INVALID_CODE,
                        "native SOCKS5 outbound CONNECT response domain bound address cannot be empty",
                    )],
                };
            }

            let mut domain_name = vec![0_u8; length[0] as usize];
            if reader.read_exact(&mut domain_name).is_err() {
                return socks5_outbound_connect_response_read_failed(
                    "native SOCKS5 outbound CONNECT response domain bound address could not be read",
                );
            }

            match String::from_utf8(domain_name) {
                Ok(domain_name) => NativeSocks5Address::DomainName(domain_name),
                Err(_) => {
                    return NativeSocks5OutboundConnectResponseReadReport {
                        response: None,
                        diagnostics: vec![runtime_warning(
                            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_INVALID_CODE,
                            "native SOCKS5 outbound CONNECT response domain bound address must be valid UTF-8",
                        )],
                    };
                }
            }
        }
        SOCKS5_ADDRESS_TYPE_IPV6 => {
            let mut address = [0_u8; 16];
            if reader.read_exact(&mut address).is_err() {
                return socks5_outbound_connect_response_read_failed(
                    "native SOCKS5 outbound CONNECT response IPv6 bound address could not be read",
                );
            }
            NativeSocks5Address::Ipv6(address)
        }
        _ => {
            return NativeSocks5OutboundConnectResponseReadReport {
                response: None,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_INVALID_CODE,
                    "native SOCKS5 outbound CONNECT response address type is unsupported",
                )],
            };
        }
    };

    let mut bound_port = [0_u8; 2];
    if reader.read_exact(&mut bound_port).is_err() {
        return socks5_outbound_connect_response_read_failed(
            "native SOCKS5 outbound CONNECT response bound port could not be read",
        );
    }

    let response = NativeSocks5OutboundConnectResponse {
        version,
        reply,
        reserved,
        address_type,
        bound_address,
        bound_port: u16::from_be_bytes(bound_port),
    };
    let diagnostic = if socks5_outbound_connect_response_valid(&response) {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_READ_CODE,
            "native SOCKS5 outbound CONNECT response was read",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_INVALID_CODE,
            "native SOCKS5 outbound CONNECT response is invalid or not successful",
        )
    };

    NativeSocks5OutboundConnectResponseReadReport {
        response: Some(response),
        diagnostics: vec![diagnostic],
    }
}

pub fn decide_socks5_outbound_connect_response(
    response: &NativeSocks5OutboundConnectResponse,
) -> NativeSocks5OutboundConnectResponseDecisionReport {
    if socks5_outbound_connect_response_valid(response) {
        return NativeSocks5OutboundConnectResponseDecisionReport {
            decision: NativeSocks5OutboundConnectResponseDecision::Accepted,
            diagnostics: vec![runtime_info(
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_ACCEPTED_CODE,
                "native SOCKS5 outbound CONNECT response accepted the upstream request",
            )],
        };
    }

    NativeSocks5OutboundConnectResponseDecisionReport {
        decision: NativeSocks5OutboundConnectResponseDecision::Rejected,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_REJECTED_CODE,
            "native SOCKS5 outbound CONNECT response rejected the upstream request or is invalid",
        )],
    }
}

pub fn assess_socks5_outbound_connect_relay_readiness(
    decision: NativeSocks5OutboundConnectResponseDecision,
) -> NativeSocks5OutboundConnectRelayReadinessReport {
    match decision {
        NativeSocks5OutboundConnectResponseDecision::Accepted => {
            NativeSocks5OutboundConnectRelayReadinessReport {
                readiness: NativeSocks5OutboundConnectRelayReadiness::Ready,
                diagnostics: vec![runtime_info(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_READY_CODE,
                    "native SOCKS5 outbound CONNECT relay is ready after upstream acceptance",
                )],
            }
        }
        NativeSocks5OutboundConnectResponseDecision::Rejected => {
            NativeSocks5OutboundConnectRelayReadinessReport {
                readiness: NativeSocks5OutboundConnectRelayReadiness::Rejected,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_REJECTED_CODE,
                    "native SOCKS5 outbound CONNECT relay is blocked by upstream rejection",
                )],
            }
        }
    }
}

pub fn plan_socks5_outbound_connect_data_relay(
    readiness: NativeSocks5OutboundConnectRelayReadiness,
) -> NativeSocks5OutboundConnectDataRelayPlanReport {
    match readiness {
        NativeSocks5OutboundConnectRelayReadiness::Ready => {
            NativeSocks5OutboundConnectDataRelayPlanReport {
                decision: NativeSocks5OutboundConnectDataRelayPlanDecision::Ready,
                diagnostics: vec![runtime_info(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_READY_CODE,
                    "native SOCKS5 outbound CONNECT data relay plan is ready",
                )],
            }
        }
        NativeSocks5OutboundConnectRelayReadiness::Blocked => {
            NativeSocks5OutboundConnectDataRelayPlanReport {
                decision: NativeSocks5OutboundConnectDataRelayPlanDecision::Blocked,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_UNWIRED_CODE,
                    "native SOCKS5 outbound CONNECT data relay plan is not wired after upstream acceptance",
                )],
            }
        }
        NativeSocks5OutboundConnectRelayReadiness::Rejected => {
            NativeSocks5OutboundConnectDataRelayPlanReport {
                decision: NativeSocks5OutboundConnectDataRelayPlanDecision::Rejected,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_REJECTED_CODE,
                    "native SOCKS5 outbound CONNECT data relay plan is blocked by upstream rejection",
                )],
            }
        }
    }
}

pub fn relay_socks5_outbound_connect_data<CR, OW, OR, CW>(
    client_reader: &mut CR,
    outbound_writer: &mut OW,
    outbound_reader: &mut OR,
    client_writer: &mut CW,
) -> NativeSocks5OutboundConnectDataRelayReport
where
    CR: Read,
    OW: Write,
    OR: Read,
    CW: Write,
{
    let client_to_outbound_result =
        relay_socks5_outbound_connect_data_direction(client_reader, outbound_writer);
    let outbound_to_client_result =
        relay_socks5_outbound_connect_data_direction(outbound_reader, client_writer);
    let client_to_outbound_bytes = client_to_outbound_result.as_ref().copied().unwrap_or(0);
    let outbound_to_client_bytes = outbound_to_client_result.as_ref().copied().unwrap_or(0);

    let diagnostic = if client_to_outbound_result.is_ok() && outbound_to_client_result.is_ok() {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_COMPLETED_CODE,
            "native SOCKS5 outbound CONNECT data relay completed for both directions",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_FAILED_CODE,
            "native SOCKS5 outbound CONNECT data relay failed in at least one direction",
        )
    };

    NativeSocks5OutboundConnectDataRelayReport {
        client_to_outbound_bytes,
        outbound_to_client_bytes,
        diagnostics: vec![diagnostic],
    }
}

pub fn assess_socks5_outbound_connect_client_success_response_readiness(
    data_relay_plan: NativeSocks5OutboundConnectDataRelayPlanDecision,
) -> NativeSocks5OutboundConnectClientSuccessResponseReadinessReport {
    match data_relay_plan {
        NativeSocks5OutboundConnectDataRelayPlanDecision::Ready => {
            NativeSocks5OutboundConnectClientSuccessResponseReadinessReport {
                readiness: NativeSocks5OutboundConnectClientSuccessResponseReadiness::Ready,
                diagnostics: vec![runtime_info(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_READY_CODE,
                    "native SOCKS5 outbound CONNECT client success response is ready",
                )],
            }
        }
        NativeSocks5OutboundConnectDataRelayPlanDecision::Blocked => {
            NativeSocks5OutboundConnectClientSuccessResponseReadinessReport {
                readiness: NativeSocks5OutboundConnectClientSuccessResponseReadiness::Blocked,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_UNWIRED_CODE,
                    "native SOCKS5 outbound CONNECT client success response is not ready because data relay is not wired",
                )],
            }
        }
        NativeSocks5OutboundConnectDataRelayPlanDecision::Rejected => {
            NativeSocks5OutboundConnectClientSuccessResponseReadinessReport {
                readiness: NativeSocks5OutboundConnectClientSuccessResponseReadiness::Rejected,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_REJECTED_CODE,
                    "native SOCKS5 outbound CONNECT client success response is blocked by upstream rejection",
                )],
            }
        }
    }
}

pub fn plan_socks5_outbound_connect_client_success_response_write(
    readiness: NativeSocks5OutboundConnectClientSuccessResponseReadiness,
) -> NativeSocks5OutboundConnectClientSuccessResponseWritePlanReport {
    match readiness {
        NativeSocks5OutboundConnectClientSuccessResponseReadiness::Ready => {
            NativeSocks5OutboundConnectClientSuccessResponseWritePlanReport {
                decision: NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision::Ready,
                diagnostics: vec![runtime_info(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_READY_CODE,
                    "native SOCKS5 outbound CONNECT client success response write plan is ready",
                )],
            }
        }
        NativeSocks5OutboundConnectClientSuccessResponseReadiness::Blocked => {
            NativeSocks5OutboundConnectClientSuccessResponseWritePlanReport {
                decision:
                    NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision::Blocked,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_UNWIRED_CODE,
                    "native SOCKS5 outbound CONNECT client success response write plan is not wired",
                )],
            }
        }
        NativeSocks5OutboundConnectClientSuccessResponseReadiness::Rejected => {
            NativeSocks5OutboundConnectClientSuccessResponseWritePlanReport {
                decision:
                    NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision::Rejected,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_REJECTED_CODE,
                    "native SOCKS5 outbound CONNECT client success response write plan is blocked by upstream rejection",
                )],
            }
        }
    }
}

pub fn write_socks5_outbound_connect_client_success_response<W>(
    writer: &mut W,
    response: &NativeSocks5OutboundConnectResponse,
) -> NativeSocks5OutboundConnectClientSuccessResponseWriteReport
where
    W: Write,
{
    let response_frame =
        socks5_outbound_connect_client_success_response_frame(response).unwrap_or_default();
    let diagnostic = if response_frame.is_empty() {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_FAILED_CODE,
            "native SOCKS5 outbound CONNECT client success response requires a valid upstream success response",
        )
    } else if writer.write_all(&response_frame).is_ok() {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITTEN_CODE,
            "native SOCKS5 outbound CONNECT client success response was written",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_FAILED_CODE,
            "native SOCKS5 outbound CONNECT client success response could not be written",
        )
    };

    NativeSocks5OutboundConnectClientSuccessResponseWriteReport {
        response_frame,
        diagnostics: vec![diagnostic],
    }
}

pub fn write_unwired_socks5_connect_failure_response<W>(
    writer: &mut W,
) -> NativeSocks5ConnectFailureResponseWriteReport
where
    W: Write,
{
    let response = SOCKS5_CONNECT_FAILURE_RESPONSE;
    let diagnostic = if writer.write_all(&response).is_ok() {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITTEN_CODE,
            "native SOCKS5 CONNECT failure response was written for unwired route and outbound handling",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITE_FAILED_CODE,
            "native SOCKS5 CONNECT failure response could not be written",
        )
    };

    NativeSocks5ConnectFailureResponseWriteReport {
        response,
        diagnostics: vec![diagnostic],
    }
}

pub fn plan_and_apply_plain_http_mitm(
    message: &NativePlainHttpMessage,
    plugin_instance: &PluginInstance,
    plugin_service: &dyn MitmPluginService,
) -> NativePlainHttpRewriteReport {
    let event = plain_http_message_to_mitm_event(message);
    let mut diagnostics = vec![engine_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_EVENT_PLANNED_CODE,
        "native plain HTTP message was mapped to a rich HTTP MITM event",
        SOURCE_ENGINE_NATIVE_MITM,
    )];

    match plugin_service.handle_http_mitm_event(plugin_instance, &event) {
        Ok(outcome) => {
            let audits = outcome.audits.clone();
            diagnostics.extend(outcome.diagnostics.clone());
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_PLAN_READY_CODE,
                "native plain HTTP MITM plugin plan was produced",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
            let application = apply_http_mitm_outcome_to_plain_http_message(message, &outcome);
            diagnostics.extend(application.diagnostics.clone());

            NativePlainHttpRewriteReport {
                request_id: message.request_id.clone(),
                url: message.url.clone(),
                event,
                outcome: Some(outcome),
                applied: application.applied,
                terminal_action: application.terminal_action,
                final_status_code: application.final_status_code,
                redirect_location: application.redirect_location,
                headers: application.headers,
                body: application.body,
                script_dispatch_deferred: application.script_dispatch_deferred,
                script_dispatch_executed: false,
                audits,
                diagnostics,
            }
        }
        Err(_error) => {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_PLAN_FAILED_CODE,
                "native plain HTTP MITM plugin plan failed",
                SOURCE_ENGINE_NATIVE_MITM,
            ));

            NativePlainHttpRewriteReport {
                request_id: message.request_id.clone(),
                url: message.url.clone(),
                event,
                outcome: None,
                applied: false,
                terminal_action: None,
                final_status_code: message.status_code,
                redirect_location: None,
                headers: message.headers.clone(),
                body: message.body.clone(),
                script_dispatch_deferred: false,
                script_dispatch_executed: false,
                audits: Vec::new(),
                diagnostics,
            }
        }
    }
}

pub fn apply_http_mitm_outcome_to_plain_http_message(
    message: &NativePlainHttpMessage,
    outcome: &HttpMitmOutcome,
) -> NativePlainHttpRewriteApplication {
    let mut headers = message.headers.clone();
    let mut body = message.body.clone();
    let mut applied = false;
    let mut terminal_action = None;
    let mut final_status_code = message.status_code;
    let mut redirect_location = None;
    let mut script_dispatch_deferred = false;
    let mut diagnostics = Vec::new();

    match &outcome.action {
        HttpMitmAction::Continue => {}
        HttpMitmAction::Reject { status_code } => {
            applied = true;
            terminal_action = Some("reject".to_string());
            final_status_code = Some(*status_code);
            redirect_location = None;
            headers.clear();
            set_plain_http_header(&mut headers, "Content-Length", "0");
            body.clear();
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_TERMINAL_ACTION_APPLIED_CODE,
                "native plain HTTP data plane applied a reject terminal action",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
        }
        HttpMitmAction::Redirect {
            status_code,
            location,
        } => {
            applied = true;
            terminal_action = Some("redirect".to_string());
            final_status_code = Some(*status_code);
            redirect_location = Some(location.clone());
            set_plain_http_header(&mut headers, "Location", location);
            set_plain_http_header(&mut headers, "Content-Length", "0");
            body.clear();
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_TERMINAL_ACTION_APPLIED_CODE,
                "native plain HTTP data plane applied a redirect terminal action",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
        }
    }

    if terminal_action.is_none() {
        let header_mutations_applied =
            apply_plain_http_header_mutations(&mut headers, &outcome.header_mutations);
        if header_mutations_applied > 0 {
            applied = true;
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_HEADER_MUTATION_APPLIED_CODE,
                format!(
                    "native plain HTTP data plane applied {header_mutations_applied} header mutation(s)"
                ),
                SOURCE_ENGINE_NATIVE_MITM,
            ));
        }

        if let Some(body_mutation) = &outcome.body_mutation {
            applied = true;
            body = body_mutation.body.clone();
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_BODY_MUTATION_APPLIED_CODE,
                "native plain HTTP data plane applied a body mutation",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
        }
    }

    if outcome.script_dispatch.is_some() {
        script_dispatch_deferred = true;
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_SCRIPT_DISPATCH_DEFERRED_CODE,
            "native plain HTTP data plane recorded script dispatch but script execution remains deferred",
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    }

    if !applied && !script_dispatch_deferred {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_REWRITE_NOOP_CODE,
            "native plain HTTP data plane found no rewrite mutation to apply",
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    }

    NativePlainHttpRewriteApplication {
        applied,
        terminal_action,
        final_status_code,
        redirect_location,
        headers,
        body,
        script_dispatch_deferred,
        diagnostics,
    }
}

pub fn write_http_mitm_rejected_socks5_connect_failure_response<W>(
    writer: &mut W,
) -> NativeSocks5ConnectFailureResponseWriteReport
where
    W: Write,
{
    let response = SOCKS5_CONNECT_FAILURE_RESPONSE;
    let diagnostic = if writer.write_all(&response).is_ok() {
        engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_RESPONSE_WRITTEN_CODE,
            "native SOCKS5 CONNECT failure response was written for MITM plugin rejection",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    } else {
        engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_RESPONSE_WRITE_FAILED_CODE,
            "native SOCKS5 CONNECT failure response could not be written for MITM plugin rejection",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    };

    NativeSocks5ConnectFailureResponseWriteReport {
        response,
        diagnostics: vec![diagnostic],
    }
}

pub fn read_explicit_http_proxy_request<R>(
    reader: &mut R,
) -> NativeExplicitHttpProxyRequestReadReport
where
    R: Read,
{
    let header_bytes = match read_http_header_bytes(reader) {
        Some(header_bytes) => header_bytes,
        None => return explicit_http_proxy_request_read_failed(),
    };
    let header_text = match String::from_utf8(header_bytes) {
        Ok(header_text) => header_text,
        Err(_) => {
            return explicit_http_proxy_request_invalid(
                "native explicit HTTP proxy request header must be valid UTF-8",
            );
        }
    };
    let (request_line, headers) = match parse_http_start_line_and_headers(&header_text) {
        Some(parsed) => parsed,
        None => {
            return explicit_http_proxy_request_invalid(
                "native explicit HTTP proxy request header is invalid",
            );
        }
    };
    let mut request_parts = request_line.split_whitespace();
    let Some(method) = request_parts.next() else {
        return explicit_http_proxy_request_invalid(
            "native explicit HTTP proxy request method is missing",
        );
    };
    let Some(target) = request_parts.next() else {
        return explicit_http_proxy_request_invalid(
            "native explicit HTTP proxy request target is missing",
        );
    };
    let Some(version) = request_parts.next() else {
        return explicit_http_proxy_request_invalid(
            "native explicit HTTP proxy request version is missing",
        );
    };
    if request_parts.next().is_some() || !version.starts_with("HTTP/") {
        return explicit_http_proxy_request_invalid(
            "native explicit HTTP proxy request line is invalid",
        );
    }
    let body_len = match http_content_length(&headers, HTTP_PROXY_MAX_BODY_BYTES) {
        Ok(body_len) => body_len,
        Err(()) => {
            return explicit_http_proxy_request_invalid(
                "native explicit HTTP proxy request body framing is unsupported",
            );
        }
    };
    let mut body = vec![0_u8; body_len];
    if body_len > 0 && reader.read_exact(&mut body).is_err() {
        return explicit_http_proxy_request_read_failed();
    }
    let Some(parsed_target) = parse_explicit_http_proxy_target(method, target, &headers) else {
        return explicit_http_proxy_request_invalid(
            "native explicit HTTP proxy request target is unsupported",
        );
    };

    let request = NativeExplicitHttpProxyRequest {
        request_id: format!("native-http-proxy:{}:{}", method, parsed_target.target_url),
        method: method.to_string(),
        target_url: parsed_target.target_url,
        target_host: parsed_target.target_host,
        target_port: parsed_target.target_port,
        origin_path: parsed_target.origin_path,
        version: version.to_string(),
        headers,
        body,
    };

    NativeExplicitHttpProxyRequestReadReport {
        request: Some(request),
        diagnostics: vec![runtime_info(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_READ_CODE,
            "native explicit HTTP proxy request was read",
        )],
    }
}

pub fn read_https_connect_http_request<R>(
    reader: &mut R,
    connect_request: &NativeExplicitHttpProxyRequest,
) -> NativeExplicitHttpProxyRequestReadReport
where
    R: Read,
{
    let mut read_report = read_explicit_http_proxy_request(reader);
    let Some(request) = read_report.request.as_mut() else {
        return read_report;
    };

    let connect_host = connect_request
        .target_host
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let request_host = request
        .target_host
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if request.method.eq_ignore_ascii_case("CONNECT")
        || connect_host.is_empty()
        || request_host != connect_host
    {
        return explicit_http_proxy_request_invalid(
            "native controlled TLS CONNECT request authority must match the decrypted HTTP Host authority",
        );
    }

    let authority = http_url_authority(
        &connect_request.target_host,
        connect_request.target_port,
        443,
    );
    request.target_host = connect_request.target_host.clone();
    request.target_port = connect_request.target_port;
    request.target_url = format!("https://{authority}{}", request.origin_path);
    request.request_id = format!(
        "native-https-connect:{}:{}",
        request.method, request.target_url
    );
    read_report.diagnostics.push(engine_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_READY_CODE,
        "native explicit HTTP proxy CONNECT decrypted a bounded HTTP/1.1 request bound to the CONNECT authority",
        SOURCE_ENGINE_NATIVE_MITM,
    ));
    read_report
}

pub fn read_plain_http_proxy_response<R>(reader: &mut R) -> NativePlainHttpProxyResponseReadReport
where
    R: Read,
{
    let header_bytes = match read_http_header_bytes(reader) {
        Some(header_bytes) => header_bytes,
        None => {
            return NativePlainHttpProxyResponseReadReport {
                response: None,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_FAILED_CODE,
                    "native plain HTTP proxy upstream response could not be read",
                )],
            };
        }
    };
    let header_text = match String::from_utf8(header_bytes) {
        Ok(header_text) => header_text,
        Err(_) => {
            return NativePlainHttpProxyResponseReadReport {
                response: None,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_FAILED_CODE,
                    "native plain HTTP proxy upstream response header must be valid UTF-8",
                )],
            };
        }
    };
    let (status_line, headers) = match parse_http_start_line_and_headers(&header_text) {
        Some(parsed) => parsed,
        None => {
            return NativePlainHttpProxyResponseReadReport {
                response: None,
                diagnostics: vec![runtime_warning(
                    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_FAILED_CODE,
                    "native plain HTTP proxy upstream response header is invalid",
                )],
            };
        }
    };
    let mut status_parts = status_line.splitn(3, ' ');
    let Some(version) = status_parts.next() else {
        return plain_http_proxy_response_read_failed();
    };
    let Some(status_code) = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
    else {
        return plain_http_proxy_response_read_failed();
    };
    if !version.starts_with("HTTP/") {
        return plain_http_proxy_response_read_failed();
    }
    let reason_phrase = status_parts.next().unwrap_or("").to_string();
    let body_len = match http_content_length(&headers, HTTP_PROXY_MAX_BODY_BYTES) {
        Ok(body_len) => body_len,
        Err(()) => return plain_http_proxy_response_read_failed(),
    };
    let mut body = vec![0_u8; body_len];
    if body_len > 0 && reader.read_exact(&mut body).is_err() {
        return plain_http_proxy_response_read_failed();
    }

    NativePlainHttpProxyResponseReadReport {
        response: Some(NativePlainHttpProxyResponse {
            version: version.to_string(),
            status_code,
            reason_phrase,
            headers,
            body,
        }),
        diagnostics: vec![runtime_info(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_CODE,
            "native plain HTTP proxy upstream response was read",
        )],
    }
}

pub fn apply_http_mitm_outcome_to_live_plain_http_request(
    request: &NativeExplicitHttpProxyRequest,
    outcome: &HttpMitmOutcome,
) -> NativePlainHttpRewriteApplication {
    let message = explicit_http_proxy_request_to_plain_http_message(request);
    apply_http_mitm_outcome_to_plain_http_message(&message, outcome)
}

pub fn serialize_explicit_http_proxy_request_for_upstream(
    request: &NativeExplicitHttpProxyRequest,
    rewrite_report: &NativePlainHttpRewriteReport,
) -> Vec<u8> {
    let origin_path = parse_script_absolute_url(&rewrite_report.url)
        .filter(|(_, target)| {
            target
                .target_host
                .eq_ignore_ascii_case(&request.target_host)
                && target.target_port == request.target_port
        })
        .map(|(_, target)| target.origin_path)
        .unwrap_or_else(|| request.origin_path.clone());
    let mut headers = rewrite_report.headers.clone();
    headers.retain(|header| !header.key.eq_ignore_ascii_case("Proxy-Connection"));
    set_plain_http_header(
        &mut headers,
        "Host",
        &http_host_header_authority(&request.target_host, request.target_port),
    );
    set_plain_http_header(&mut headers, "Connection", "close");
    if !rewrite_report.body.is_empty()
        || headers
            .iter()
            .any(|header| header.key.eq_ignore_ascii_case("Content-Length"))
    {
        set_plain_http_header(
            &mut headers,
            "Content-Length",
            &rewrite_report.body.len().to_string(),
        );
    }

    let mut bytes =
        format!("{} {} {}\r\n", request.method, origin_path, request.version).into_bytes();
    write_http_headers_to_bytes(&mut bytes, &headers);
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(&rewrite_report.body);
    bytes
}

pub fn serialize_plain_http_proxy_response(
    version: &str,
    rewrite_report: &NativePlainHttpRewriteReport,
) -> Vec<u8> {
    let status_code = rewrite_report.final_status_code.unwrap_or(200);
    let mut headers = rewrite_report.headers.clone();
    if let Some(location) = &rewrite_report.redirect_location {
        set_plain_http_header(&mut headers, "Location", location);
    }
    set_plain_http_header(&mut headers, "Connection", "close");
    set_plain_http_header(
        &mut headers,
        "Content-Length",
        &rewrite_report.body.len().to_string(),
    );

    let mut bytes = format!(
        "{} {} {}\r\n",
        normalized_http_version(version),
        status_code,
        http_reason_phrase(status_code)
    )
    .into_bytes();
    write_http_headers_to_bytes(&mut bytes, &headers);
    bytes.extend_from_slice(b"\r\n");
    bytes.extend_from_slice(&rewrite_report.body);
    bytes
}

pub fn write_plain_http_proxy_upstream_request<W>(
    writer: &mut W,
    bytes: Vec<u8>,
) -> NativePlainHttpProxyWriteReport
where
    W: Write,
{
    let diagnostic = if writer.write_all(&bytes).is_ok() {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITTEN_CODE,
            "native plain HTTP proxy upstream request was written",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITE_FAILED_CODE,
            "native plain HTTP proxy upstream request could not be written",
        )
    };

    NativePlainHttpProxyWriteReport {
        bytes,
        diagnostics: vec![diagnostic],
    }
}

pub fn write_plain_http_proxy_client_response<W>(
    writer: &mut W,
    bytes: Vec<u8>,
) -> NativePlainHttpProxyWriteReport
where
    W: Write,
{
    let diagnostic = if writer.write_all(&bytes).is_ok() {
        runtime_info(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
            "native plain HTTP proxy client response was written",
        )
    } else {
        runtime_warning(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITE_FAILED_CODE,
            "native plain HTTP proxy client response could not be written",
        )
    };

    NativePlainHttpProxyWriteReport {
        bytes,
        diagnostics: vec![diagnostic],
    }
}

pub fn write_http_connect_established_response<W>(
    writer: &mut W,
    version: &str,
) -> NativePlainHttpProxyWriteReport
where
    W: Write,
{
    let bytes = format!(
        "{} 200 Connection Established\r\nProxy-Agent: NetworkCore\r\n\r\n",
        normalized_http_version(version)
    )
    .into_bytes();
    let diagnostic = if writer.write_all(&bytes).is_ok() {
        engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_ESTABLISHED_CODE,
            "native explicit HTTP proxy CONNECT tunnel was established through the configured SOCKS outbound",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    } else {
        engine_diagnostic(
            DiagnosticSeverity::Warning,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_FAILED_CODE,
            "native explicit HTTP proxy CONNECT tunnel response could not be written",
            SOURCE_ENGINE_NATIVE_MITM,
        )
    };

    NativePlainHttpProxyWriteReport {
        bytes,
        diagnostics: vec![diagnostic],
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeOutboundHandlerHandle {
    pub node_id: String,
    pub protocol: Protocol,
    pub endpoint: Endpoint,
}

impl NativeOutboundHandlerHandle {
    pub fn from_node(node: &NodeDescriptor) -> DomainResult<Self> {
        if node.endpoint.host.trim().is_empty() || node.endpoint.port == 0 {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_OUTBOUND_ENDPOINT_INVALID_CODE,
                "native runtime outbound endpoint host and port must be explicit",
            ));
        }

        if !outbound_runtime_protocol_supported(&node.protocol) {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_OUTBOUND_UNSUPPORTED_CODE,
                "first native runtime outbound handler only declares socks node handoff",
            ));
        }

        Ok(Self {
            node_id: node.id.clone(),
            protocol: node.protocol.clone(),
            endpoint: node.endpoint.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeRuntimeAssemblyPlan {
    engine_id: String,
    listener: LoopbackListenerHandle,
    outbound_handler: NativeOutboundHandlerHandle,
}

impl NativeRuntimeAssemblyPlan {
    pub fn from_config(engine_config: &ProxyEngineConfig) -> DomainResult<Self> {
        ensure_native_engine_id(&engine_config.engine_id)?;
        ensure_native_config_has_no_errors(engine_config)?;

        let mut first_error = None;
        for listener_descriptor in enabled_listeners(&engine_config.config.listeners) {
            let listener = match LoopbackListenerHandle::from_descriptor(listener_descriptor) {
                Ok(listener) => listener,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            let node = match select_runtime_node(engine_config, listener_descriptor) {
                Ok(node) => node,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            let outbound_handler = match NativeOutboundHandlerHandle::from_node(node) {
                Ok(outbound_handler) => outbound_handler,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };

            return Ok(Self {
                engine_id: engine_config.engine_id.clone(),
                listener,
                outbound_handler,
            });
        }

        Err(first_error.unwrap_or_else(|| {
            runtime_error(
                ENGINE_NATIVE_RUNTIME_RESOURCE_MISSING_CODE,
                "native runtime assembly plan requires a loopback tcp listener and socks outbound handler",
            )
        }))
    }

    pub fn engine_id(&self) -> &str {
        &self.engine_id
    }

    pub fn listener(&self) -> &LoopbackListenerHandle {
        &self.listener
    }

    pub fn outbound_handler(&self) -> &NativeOutboundHandlerHandle {
        &self.outbound_handler
    }

    pub fn into_unbound_assembly(self) -> NativeRuntimeAssembly {
        NativeRuntimeAssembly::new(self.engine_id)
            .with_listener(self.listener)
            .with_outbound_handler(self.outbound_handler)
    }

    pub fn bind_loopback_listener(
        self,
    ) -> Result<NativeRuntimeAssembly, Box<NativeRuntimeStartupFailure>> {
        let Self {
            engine_id,
            listener,
            outbound_handler,
        } = self;
        let release_listener = listener.clone();

        match BoundLoopbackTcpListenerHandle::bind(listener) {
            Ok(bound_listener) => Ok(NativeRuntimeAssembly::new(engine_id)
                .with_bound_listener(bound_listener)
                .with_outbound_handler(outbound_handler)),
            Err(error) => Err(Box::new(
                NativeRuntimeAssembly::new(engine_id)
                    .with_listener(release_listener)
                    .with_outbound_handler(outbound_handler)
                    .fail(error.code.clone(), error.message.clone()),
            )),
        }
    }

    pub fn start_loopback_accept_loop(
        self,
    ) -> Result<NativeRuntimeAssembly, Box<NativeRuntimeStartupFailure>> {
        self.start_loopback_accept_loop_with_http_mitm_hook(None)
    }

    pub fn start_loopback_accept_loop_with_http_mitm_hook(
        self,
        http_mitm_hook: Option<NativeHttpMitmPluginHook>,
    ) -> Result<NativeRuntimeAssembly, Box<NativeRuntimeStartupFailure>> {
        self.start_loopback_accept_loop_with_http_mitm_hook_and_tls_mitm_ca_material(
            http_mitm_hook,
            None,
        )
    }

    pub fn start_loopback_accept_loop_with_http_mitm_hook_and_tls_mitm_ca_material(
        self,
        http_mitm_hook: Option<NativeHttpMitmPluginHook>,
        tls_mitm_ca_material: Option<NativeTlsMitmCaMaterial>,
    ) -> Result<NativeRuntimeAssembly, Box<NativeRuntimeStartupFailure>> {
        let Self {
            engine_id,
            listener,
            outbound_handler,
        } = self;
        let release_listener = listener.clone();
        let release_outbound_handler = outbound_handler.clone();

        let bound_listener = match BoundLoopbackTcpListenerHandle::bind(listener) {
            Ok(bound_listener) => bound_listener,
            Err(error) => {
                return Err(Box::new(
                    NativeRuntimeAssembly::new(engine_id)
                        .with_listener(release_listener)
                        .with_outbound_handler(outbound_handler)
                        .fail(error.code.clone(), error.message.clone()),
                ));
            }
        };

        match NativeLoopbackTcpAcceptLoopHandle::start_with_http_mitm_hook_and_tls_mitm_ca_material(
            bound_listener,
            outbound_handler,
            http_mitm_hook,
            tls_mitm_ca_material,
        ) {
            Ok(accept_loop) => {
                Ok(NativeRuntimeAssembly::new(engine_id).with_accept_loop(accept_loop))
            }
            Err(error) => Err(Box::new(
                NativeRuntimeAssembly::new(engine_id)
                    .with_listener(release_listener)
                    .with_outbound_handler(release_outbound_handler)
                    .fail(error.code.clone(), error.message.clone()),
            )),
        }
    }
}

#[derive(Debug)]
pub struct NativeRuntimeHandle {
    engine_id: String,
    listeners: Vec<LoopbackListenerHandle>,
    bound_listeners: Vec<BoundLoopbackTcpListenerHandle>,
    accept_loops: Vec<NativeLoopbackTcpAcceptLoopHandle>,
    outbound_handlers: Vec<NativeOutboundHandlerHandle>,
    events: Vec<ProxyEngineEvent>,
}

impl NativeRuntimeHandle {
    pub fn listeners(&self) -> &[LoopbackListenerHandle] {
        &self.listeners
    }

    pub fn bound_listeners(&self) -> &[BoundLoopbackTcpListenerHandle] {
        &self.bound_listeners
    }

    pub fn accept_loops(&self) -> &[NativeLoopbackTcpAcceptLoopHandle] {
        &self.accept_loops
    }

    pub fn outbound_handlers(&self) -> &[NativeOutboundHandlerHandle] {
        &self.outbound_handlers
    }

    pub fn events(&self) -> &[ProxyEngineEvent] {
        &self.events
    }

    pub fn foreground_handoff_status(&self) -> ProxyEngineStatus {
        let mut diagnostics = vec![runtime_info(
            ENGINE_NATIVE_RUNTIME_FOREGROUND_HANDOFF_READY_CODE,
            "native runtime handle is ready for foreground lifecycle handoff",
        )];
        if !self.accept_loops.is_empty() {
            diagnostics.push(runtime_info(
                ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_READY_CODE,
                "native loopback tcp accept loop is ready",
            ));
        }

        ProxyEngineStatus {
            engine_id: self.engine_id.clone(),
            state: ProxyEngineLifecycleState::Running,
            diagnostics,
        }
    }

    pub fn release(self) -> NativeRuntimeReleaseReport {
        release_report(
            NativeRuntimeReleaseResources {
                engine_id: self.engine_id,
                listeners: self.listeners,
                bound_listeners: self.bound_listeners,
                accept_loops: self.accept_loops,
                outbound_handlers: self.outbound_handlers,
                events: self.events,
            },
            ProxyEngineEventKind::Stopped,
            Vec::new(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeRuntimeReleaseReport {
    pub engine_id: String,
    pub listener_ids: Vec<String>,
    pub outbound_handler_ids: Vec<String>,
    pub diagnostics: Vec<Diagnostic>,
    pub events: Vec<ProxyEngineEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeRuntimeStartupFailure {
    pub error: DomainError,
    pub release: NativeRuntimeReleaseReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeProxyEngineStartReadiness {
    Ready,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeProxyEngineStartReadinessReport {
    pub readiness: NativeProxyEngineStartReadiness,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug)]
pub struct NativeRuntimeAssembly {
    engine_id: String,
    listeners: Vec<LoopbackListenerHandle>,
    bound_listeners: Vec<BoundLoopbackTcpListenerHandle>,
    accept_loops: Vec<NativeLoopbackTcpAcceptLoopHandle>,
    outbound_handlers: Vec<NativeOutboundHandlerHandle>,
    events: Vec<ProxyEngineEvent>,
}

impl NativeRuntimeAssembly {
    pub fn new(engine_id: impl Into<String>) -> Self {
        Self {
            engine_id: engine_id.into(),
            listeners: Vec::new(),
            bound_listeners: Vec::new(),
            accept_loops: Vec::new(),
            outbound_handlers: Vec::new(),
            events: Vec::new(),
        }
    }

    pub fn with_listener(mut self, listener: LoopbackListenerHandle) -> Self {
        self.listeners.push(listener);
        self
    }

    pub fn with_bound_listener(mut self, listener: BoundLoopbackTcpListenerHandle) -> Self {
        self.bound_listeners.push(listener);
        self
    }

    pub fn with_accept_loop(mut self, accept_loop: NativeLoopbackTcpAcceptLoopHandle) -> Self {
        self.accept_loops.push(accept_loop);
        self
    }

    pub fn with_outbound_handler(mut self, outbound_handler: NativeOutboundHandlerHandle) -> Self {
        self.outbound_handlers.push(outbound_handler);
        self
    }

    pub fn finish(mut self) -> DomainResult<NativeRuntimeHandle> {
        ensure_native_engine_id(&self.engine_id)?;

        let has_listener_resource = !self.listeners.is_empty()
            || !self.bound_listeners.is_empty()
            || !self.accept_loops.is_empty();
        let has_outbound_resource =
            !self.outbound_handlers.is_empty() || !self.accept_loops.is_empty();

        if !has_listener_resource || !has_outbound_resource {
            return Err(runtime_error(
                ENGINE_NATIVE_RUNTIME_RESOURCE_MISSING_CODE,
                "native runtime handle requires at least one listener and outbound handler",
            ));
        }

        let mut diagnostics = vec![runtime_info(
            ENGINE_NATIVE_RUNTIME_FOREGROUND_HANDOFF_READY_CODE,
            "native runtime handle is ready for foreground lifecycle handoff",
        )];
        if !self.accept_loops.is_empty() {
            diagnostics.push(runtime_info(
                ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_READY_CODE,
                "native loopback tcp accept loop is ready",
            ));
        }

        self.events.push(runtime_event(
            &self.engine_id,
            ProxyEngineEventKind::Started,
            diagnostics,
        ));

        Ok(NativeRuntimeHandle {
            engine_id: self.engine_id,
            listeners: self.listeners,
            bound_listeners: self.bound_listeners,
            accept_loops: self.accept_loops,
            outbound_handlers: self.outbound_handlers,
            events: self.events,
        })
    }

    pub fn fail(
        self,
        code: impl Into<String>,
        message: impl Into<String>,
    ) -> NativeRuntimeStartupFailure {
        let error = DomainError::new(code, message);
        let failure_diagnostic = engine_diagnostic(
            DiagnosticSeverity::Error,
            error.code.clone(),
            error.message.clone(),
            SOURCE_ENGINE_NATIVE_RUNTIME,
        );
        let release = release_report(
            NativeRuntimeReleaseResources {
                engine_id: self.engine_id,
                listeners: self.listeners,
                bound_listeners: self.bound_listeners,
                accept_loops: self.accept_loops,
                outbound_handlers: self.outbound_handlers,
                events: self.events,
            },
            ProxyEngineEventKind::Failed,
            vec![failure_diagnostic],
        );

        NativeRuntimeStartupFailure { error, release }
    }
}

#[derive(Debug, Clone, Default)]
pub struct NativeProxyEngineService {
    runtime: Arc<Mutex<Option<NativeRuntimeHandle>>>,
    lifecycle_events: Arc<Mutex<Vec<ProxyEngineEvent>>>,
    http_mitm_hook: Option<NativeHttpMitmPluginHook>,
    tls_mitm_ca_material: Option<NativeTlsMitmCaMaterial>,
}

impl NativeProxyEngineService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_http_mitm_hook(mut self, hook: NativeHttpMitmPluginHook) -> Self {
        self.http_mitm_hook = Some(hook);
        self
    }

    pub fn with_tls_mitm_ca_material(mut self, material: NativeTlsMitmCaMaterial) -> Self {
        self.tls_mitm_ca_material = Some(material);
        self
    }

    pub fn http_mitm_hook_enabled(&self) -> bool {
        self.http_mitm_hook.is_some()
    }

    pub fn tls_mitm_ca_material_enabled(&self) -> bool {
        self.tls_mitm_ca_material.is_some()
    }

    pub fn http_mitm_script_executor_enabled(&self) -> bool {
        match self.http_mitm_hook.as_ref() {
            Some(hook) => hook.script_executor_enabled(),
            None => false,
        }
    }

    fn runtime_state(
        &self,
    ) -> DomainResult<std::sync::MutexGuard<'_, Option<NativeRuntimeHandle>>> {
        self.runtime.lock().map_err(|_| lifecycle_state_error())
    }

    fn lifecycle_event_state(
        &self,
    ) -> DomainResult<std::sync::MutexGuard<'_, Vec<ProxyEngineEvent>>> {
        self.lifecycle_events
            .lock()
            .map_err(|_| lifecycle_state_error())
    }

    fn record_events(&self, events: Vec<ProxyEngineEvent>) -> DomainResult<()> {
        if events.is_empty() {
            return Ok(());
        }

        self.lifecycle_event_state()?.extend(events);
        Ok(())
    }
}

pub fn assess_native_proxy_engine_start_readiness(
    engine_config: &ProxyEngineConfig,
) -> NativeProxyEngineStartReadinessReport {
    let service = NativeProxyEngineService::new();
    let mut diagnostics = service.validate_config(engine_config);
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    {
        return NativeProxyEngineStartReadinessReport {
            readiness: NativeProxyEngineStartReadiness::Blocked,
            diagnostics,
        };
    }

    match NativeRuntimeAssemblyPlan::from_config(engine_config) {
        Ok(_plan) => {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_START_RUNTIME_ASSEMBLY_READY_CODE,
                "native runtime assembly plan is ready for service start evaluation",
                SOURCE_ENGINE_NATIVE_LIFECYCLE,
            ));
            return NativeProxyEngineStartReadinessReport {
                readiness: NativeProxyEngineStartReadiness::Ready,
                diagnostics,
            };
        }
        Err(error) => diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Error,
            error.code,
            error.message,
            SOURCE_ENGINE_NATIVE_RUNTIME,
        )),
    }

    NativeProxyEngineStartReadinessReport {
        readiness: NativeProxyEngineStartReadiness::Blocked,
        diagnostics,
    }
}

impl ProxyEngineService for NativeProxyEngineService {
    fn list_engines(&self) -> Vec<ProxyEngineDescriptor> {
        vec![ProxyEngineDescriptor {
            id: DEFAULT_NATIVE_ENGINE_ID.to_string(),
            kind: ProxyEngineKind::Native,
            version: None,
            capabilities: Vec::new(),
        }]
    }

    fn validate_config(&self, engine_config: &ProxyEngineConfig) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();

        if engine_config.engine_id != DEFAULT_NATIVE_ENGINE_ID {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE,
                "native proxy engine only supports the native engine id",
                SOURCE_ENGINE_NATIVE_CONFIG,
            ));
        }

        validate_listeners(engine_config, &mut diagnostics);
        validate_nodes(engine_config, &mut diagnostics);
        validate_routes(engine_config, &mut diagnostics);

        diagnostics
    }

    fn start(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(&engine_config.engine_id)?;
        let readiness = assess_native_proxy_engine_start_readiness(engine_config);
        if readiness.readiness == NativeProxyEngineStartReadiness::Blocked {
            let diagnostic = readiness
                .diagnostics
                .into_iter()
                .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
                .unwrap_or_else(|| {
                    engine_diagnostic(
                        DiagnosticSeverity::Error,
                        ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE,
                        "native proxy runtime service start is unavailable",
                        SOURCE_ENGINE_NATIVE_LIFECYCLE,
                    )
                });

            return Err(domain_error(diagnostic.code, diagnostic.message));
        }

        {
            let runtime = self.runtime_state()?;
            if let Some(runtime) = runtime.as_ref() {
                return Ok(running_status(runtime));
            }
        }

        let plan = NativeRuntimeAssemblyPlan::from_config(engine_config)?;
        let assembly = match plan
            .start_loopback_accept_loop_with_http_mitm_hook_and_tls_mitm_ca_material(
                self.http_mitm_hook.clone(),
                self.tls_mitm_ca_material.clone(),
            ) {
            Ok(assembly) => assembly,
            Err(failure) => {
                let NativeRuntimeStartupFailure { error, release } = *failure;
                let _ = self.record_events(release.events);
                return Err(error);
            }
        };
        let handle = assembly.finish()?;
        let status = running_status(&handle);
        let start_events = handle.events().to_vec();

        let mut runtime = self.runtime_state()?;
        if let Some(existing_runtime) = runtime.as_ref() {
            let status = running_status(existing_runtime);
            drop(runtime);
            let _ = handle.release();
            return Ok(status);
        }

        self.lifecycle_event_state()?.extend(start_events);
        *runtime = Some(handle);

        Ok(status)
    }

    fn reload(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(&engine_config.engine_id)?;

        Err(domain_error(
            ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE,
            "native proxy runtime service lifecycle is not wired yet",
        ))
    }

    fn stop(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(engine_id)?;

        let handle = {
            let mut runtime = self.runtime_state()?;
            runtime.take()
        };
        let Some(handle) = handle else {
            return Ok(stopped_status(engine_id));
        };

        let release = handle.release();
        let release_event = release.events.last().cloned();
        let status = ProxyEngineStatus {
            engine_id: release.engine_id.clone(),
            state: ProxyEngineLifecycleState::Stopped,
            diagnostics: release.diagnostics.clone(),
        };
        if let Some(release_event) = release_event {
            self.record_events(vec![release_event])?;
        }

        Ok(status)
    }

    fn status(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(engine_id)?;

        {
            let runtime = self.runtime_state()?;
            if let Some(runtime) = runtime.as_ref() {
                return Ok(runtime.foreground_handoff_status());
            }
        }

        Ok(stopped_status(engine_id))
    }

    fn events(&self, engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
        ensure_native_engine_id(engine_id)?;

        Ok(self.lifecycle_event_state()?.clone())
    }
}

fn running_status(handle: &NativeRuntimeHandle) -> ProxyEngineStatus {
    let mut status = handle.foreground_handoff_status();
    status.diagnostics.push(engine_diagnostic(
        DiagnosticSeverity::Info,
        ENGINE_NATIVE_START_RUNNING_CODE,
        "native proxy runtime is running in the current process",
        SOURCE_ENGINE_NATIVE_LIFECYCLE,
    ));
    status
}

fn stopped_status(engine_id: &str) -> ProxyEngineStatus {
    ProxyEngineStatus {
        engine_id: engine_id.to_string(),
        state: ProxyEngineLifecycleState::Stopped,
        diagnostics: Vec::new(),
    }
}

fn lifecycle_state_error() -> DomainError {
    domain_error(
        ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE,
        "native proxy runtime lifecycle state is unavailable",
    )
}

fn validate_listeners(engine_config: &ProxyEngineConfig, diagnostics: &mut Vec<Diagnostic>) {
    let listeners = &engine_config.config.listeners;
    let enabled_listeners = enabled_listeners(listeners);

    if enabled_listeners.is_empty() {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE,
            "native proxy engine requires at least one enabled listener",
        ));
    }

    if has_duplicate_ids(listeners.iter().map(|listener| listener.id.as_str())) {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_LISTENER_ID_DUPLICATE_CODE,
            "native proxy listener ids must be unique",
        ));
    }

    if enabled_listeners
        .iter()
        .any(|listener| listener.bind.host.trim().is_empty() || listener.bind.port == 0)
    {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_LISTENER_BIND_INVALID_CODE,
            "native proxy listener bind host and port must be explicit",
        ));
    }

    if enabled_listeners
        .iter()
        .any(|listener| !listener_kind_supported(&listener.kind))
    {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_LISTENER_KIND_UNSUPPORTED_CODE,
            "native proxy listener handlers are not implemented yet",
        ));
    }
}

fn validate_nodes(engine_config: &ProxyEngineConfig, diagnostics: &mut Vec<Diagnostic>) {
    let nodes = effective_nodes(engine_config);

    if nodes.is_empty() {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE,
            "native proxy engine requires at least one typed outbound node",
        ));
    }

    if has_duplicate_ids(nodes.iter().map(|node| node.id.as_str())) {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_NODE_ID_DUPLICATE_CODE,
            "native proxy node ids must be unique across config and runtime request nodes",
        ));
    }

    if nodes
        .iter()
        .any(|node| !node_protocol_supported(&node.protocol))
    {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_NODE_PROTOCOL_UNSUPPORTED_CODE,
            "native proxy outbound protocols are not implemented yet",
        ));
    }
}

fn validate_routes(engine_config: &ProxyEngineConfig, diagnostics: &mut Vec<Diagnostic>) {
    let route_sets = &engine_config.config.policies;
    let enabled_listeners = enabled_listeners(&engine_config.config.listeners);
    let node_ids = effective_node_ids(engine_config);
    let mut target_missing = false;
    let mut has_executable_proxy_route = false;

    if has_duplicate_ids(route_sets.iter().map(|route_set| route_set.id.as_str())) {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_ROUTE_ID_DUPLICATE_CODE,
            "native proxy route ids must be unique",
        ));
    }

    for listener in &enabled_listeners {
        match &listener.route {
            ListenerRoute::RuleSet { rule_set_id } => {
                let Some(route_set) = route_sets
                    .iter()
                    .find(|route_set| route_set.id == *rule_set_id)
                else {
                    target_missing = true;
                    continue;
                };
                let route_result = validate_route_set(route_set, &node_ids);
                target_missing |= route_result.target_missing;
                has_executable_proxy_route |= route_result.has_executable_proxy_route;
            }
            ListenerRoute::DefaultAction(action) => {
                let action_result = validate_route_action(action, &node_ids);
                target_missing |= action_result.target_missing;
                has_executable_proxy_route |= action_result.has_executable_proxy_route;
            }
        }
    }

    for route_set in route_sets {
        for rule in &route_set.rules {
            target_missing |= validate_route_action(&rule.action, &node_ids).target_missing;
        }
        target_missing |=
            validate_route_action(&route_set.default_action, &node_ids).target_missing;
    }

    if target_missing {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE,
            "native proxy routes must reference existing rule sets and nodes",
        ));
    }

    if !enabled_listeners.is_empty() && !has_executable_proxy_route {
        diagnostics.push(config_error(
            ENGINE_NATIVE_CONFIG_ROUTE_EMPTY_CODE,
            "native proxy listeners must have at least one proxy route to a typed node",
        ));
    }
}

fn ensure_native_engine_id(engine_id: &str) -> DomainResult<()> {
    if engine_id == DEFAULT_NATIVE_ENGINE_ID {
        return Ok(());
    }

    Err(domain_error(
        ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE,
        "native proxy engine only supports the native engine id",
    ))
}

#[derive(Debug, Clone, Copy, Default)]
struct RouteValidation {
    target_missing: bool,
    has_executable_proxy_route: bool,
}

fn validate_route_set(route_set: &RuleSet, node_ids: &BTreeSet<String>) -> RouteValidation {
    let mut validation = RouteValidation::default();

    for rule in &route_set.rules {
        validation = validation.combine(validate_route_action(&rule.action, node_ids));
    }

    validation.combine(validate_route_action(&route_set.default_action, node_ids))
}

fn validate_route_action(action: &RouteAction, node_ids: &BTreeSet<String>) -> RouteValidation {
    match action {
        RouteAction::Proxy { node_id } if node_ids.contains(node_id) => RouteValidation {
            target_missing: false,
            has_executable_proxy_route: true,
        },
        RouteAction::Proxy { .. } => RouteValidation {
            target_missing: true,
            has_executable_proxy_route: false,
        },
        RouteAction::Direct | RouteAction::Reject => RouteValidation::default(),
    }
}

impl RouteValidation {
    fn combine(self, other: Self) -> Self {
        Self {
            target_missing: self.target_missing || other.target_missing,
            has_executable_proxy_route: self.has_executable_proxy_route
                || other.has_executable_proxy_route,
        }
    }
}

fn enabled_listeners(listeners: &[ListenerDescriptor]) -> Vec<&ListenerDescriptor> {
    listeners
        .iter()
        .filter(|listener| listener.enabled)
        .collect()
}

fn effective_nodes(engine_config: &ProxyEngineConfig) -> Vec<&NodeDescriptor> {
    engine_config
        .config
        .nodes
        .iter()
        .chain(engine_config.nodes.iter())
        .collect()
}

fn ensure_native_config_has_no_errors(engine_config: &ProxyEngineConfig) -> DomainResult<()> {
    let service = NativeProxyEngineService::new();
    if let Some(diagnostic) = service
        .validate_config(engine_config)
        .into_iter()
        .find(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
    {
        return Err(domain_error(diagnostic.code, diagnostic.message));
    }

    Ok(())
}

fn select_runtime_node<'a>(
    engine_config: &'a ProxyEngineConfig,
    listener: &ListenerDescriptor,
) -> DomainResult<&'a NodeDescriptor> {
    let node_id = select_runtime_proxy_node_id(&listener.route, &engine_config.config.policies)?;
    effective_nodes(engine_config)
        .into_iter()
        .find(|node| node.id == node_id)
        .ok_or_else(|| {
            runtime_error(
                ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE,
                "native runtime assembly plan route must reference an existing node",
            )
        })
}

fn select_runtime_proxy_node_id<'a>(
    route: &'a ListenerRoute,
    route_sets: &'a [RuleSet],
) -> DomainResult<&'a str> {
    let node_id = match route {
        ListenerRoute::DefaultAction(action) => proxy_node_id(action),
        ListenerRoute::RuleSet { rule_set_id } => {
            let route_set = route_sets
                .iter()
                .find(|route_set| route_set.id == *rule_set_id)
                .ok_or_else(|| {
                    runtime_error(
                        ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE,
                        "native runtime assembly plan route set must exist",
                    )
                })?;
            route_set
                .rules
                .iter()
                .find_map(|rule| proxy_node_id(&rule.action))
                .or_else(|| proxy_node_id(&route_set.default_action))
        }
    };

    node_id.ok_or_else(|| {
        runtime_error(
            ENGINE_NATIVE_RUNTIME_RESOURCE_MISSING_CODE,
            "native runtime assembly plan requires a proxy route to a socks outbound node",
        )
    })
}

fn proxy_node_id(action: &RouteAction) -> Option<&str> {
    match action {
        RouteAction::Proxy { node_id } => Some(node_id),
        RouteAction::Direct | RouteAction::Reject => None,
    }
}

fn effective_node_ids(engine_config: &ProxyEngineConfig) -> BTreeSet<String> {
    effective_nodes(engine_config)
        .into_iter()
        .map(|node| node.id.clone())
        .collect()
}

fn has_duplicate_ids<'a>(mut ids: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    ids.any(|id| !seen.insert(id))
}

fn listener_kind_supported(kind: &ListenerKind) -> bool {
    listener_runtime_kind_supported(kind)
}

fn node_protocol_supported(protocol: &Protocol) -> bool {
    outbound_runtime_protocol_supported(protocol)
}

fn listener_runtime_kind_supported(kind: &ListenerKind) -> bool {
    matches!(
        kind,
        ListenerKind::LocalTcp | ListenerKind::Socks | ListenerKind::Http
    )
}

fn outbound_runtime_protocol_supported(protocol: &Protocol) -> bool {
    matches!(protocol, Protocol::Socks)
}

fn socks5_command_header_valid(command_header: &NativeSocks5CommandHeader) -> bool {
    command_header.version == SOCKS5_VERSION
        && command_header.reserved == SOCKS5_RESERVED
        && matches!(
            command_header.address_type,
            SOCKS5_ADDRESS_TYPE_IPV4 | SOCKS5_ADDRESS_TYPE_DOMAIN_NAME | SOCKS5_ADDRESS_TYPE_IPV6
        )
}

fn socks5_connect_target_valid(target: &NativeSocks5ConnectTarget) -> bool {
    target.port != 0
        && match &target.address {
            NativeSocks5Address::Ipv4(_) | NativeSocks5Address::Ipv6(_) => true,
            NativeSocks5Address::DomainName(domain_name) => !domain_name.trim().is_empty(),
        }
}

fn socks5_target_host(target: &NativeSocks5ConnectTarget) -> String {
    match &target.address {
        NativeSocks5Address::Ipv4(address) => {
            format!(
                "{}.{}.{}.{}",
                address[0], address[1], address[2], address[3]
            )
        }
        NativeSocks5Address::DomainName(domain_name) => domain_name.clone(),
        NativeSocks5Address::Ipv6(address) => Ipv6Addr::from(*address).to_string(),
    }
}

fn socks5_target_url_authority(target: &NativeSocks5ConnectTarget) -> String {
    let default_port = target.port == 80 || target.port == 443;
    match &target.address {
        NativeSocks5Address::Ipv6(address) => {
            let host = Ipv6Addr::from(*address);
            if default_port {
                format!("[{host}]")
            } else {
                format!("[{host}]:{}", target.port)
            }
        }
        _ if default_port => socks5_target_host(target),
        _ => format!("{}:{}", socks5_target_host(target), target.port),
    }
}

fn socks5_target_header_authority(target: &NativeSocks5ConnectTarget) -> String {
    match &target.address {
        NativeSocks5Address::Ipv6(address) => {
            format!("[{}]:{}", Ipv6Addr::from(*address), target.port)
        }
        _ => format!("{}:{}", socks5_target_host(target), target.port),
    }
}

pub fn native_socks5_connect_browser_capture_proof_token(
    target: &NativeSocks5ConnectTarget,
    proxy_scheme: &str,
    proxy_host: &str,
    proxy_port: u16,
) -> String {
    let proxy_url = format!("{proxy_scheme}://{proxy_host}:{proxy_port}");
    browser_capture_proof_token_from_connect_authority(
        &socks5_target_header_authority(target),
        &proxy_url,
    )
}

pub fn browser_capture_proof_token_from_connect_authority(
    connect_authority: &str,
    proxy_url: &str,
) -> String {
    browser_capture_proof_token_from_source(&format!(
        "connect:{connect_authority}|proxy:{proxy_url}"
    ))
}

fn browser_capture_proof_token_from_source(source: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in source.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("networkcore-browser-proof-{hash:016x}")
}

fn socks5_connect_http_mitm_url(target: &NativeSocks5ConnectTarget) -> String {
    let scheme = if target.port == 443 { "https" } else { "http" };
    format!("{scheme}://{}/", socks5_target_url_authority(target))
}

fn socks5_connect_http_mitm_request_id(target: &NativeSocks5ConnectTarget) -> String {
    format!(
        "native-socks5-connect:{}:{}",
        socks5_target_host(target),
        target.port
    )
}

fn http_mitm_outcome_requires_application(outcome: &HttpMitmOutcome) -> bool {
    outcome.action != HttpMitmAction::Continue
        || !outcome.header_mutations.is_empty()
        || outcome.body_mutation.is_some()
        || outcome.script_dispatch.is_some()
}

fn http_mitm_outcome_rejects(outcome: &HttpMitmOutcome) -> bool {
    matches!(&outcome.action, HttpMitmAction::Reject { .. })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedExplicitHttpProxyTarget {
    target_url: String,
    target_host: String,
    target_port: u16,
    origin_path: String,
}

fn explicit_http_proxy_request_to_plain_http_message(
    request: &NativeExplicitHttpProxyRequest,
) -> NativePlainHttpMessage {
    NativePlainHttpMessage {
        request_id: request.request_id.clone(),
        url: request.target_url.clone(),
        method: Some(request.method.clone()),
        phase: HttpMitmPhase::Request,
        status_code: None,
        headers: request.headers.clone(),
        body: request.body.clone(),
    }
}

fn plain_http_proxy_response_to_plain_http_message(
    request: &NativeExplicitHttpProxyRequest,
    response: &NativePlainHttpProxyResponse,
) -> NativePlainHttpMessage {
    NativePlainHttpMessage {
        request_id: format!("{}:response", request.request_id),
        url: request.target_url.clone(),
        method: Some(request.method.clone()),
        phase: HttpMitmPhase::Response,
        status_code: Some(response.status_code),
        headers: response.headers.clone(),
        body: response.body.clone(),
    }
}

fn passthrough_plain_http_rewrite_report(
    message: &NativePlainHttpMessage,
) -> NativePlainHttpRewriteReport {
    NativePlainHttpRewriteReport {
        request_id: message.request_id.clone(),
        url: message.url.clone(),
        event: plain_http_message_to_mitm_event(message),
        outcome: None,
        applied: false,
        terminal_action: None,
        final_status_code: message.status_code,
        redirect_location: None,
        headers: message.headers.clone(),
        body: message.body.clone(),
        script_dispatch_deferred: false,
        script_dispatch_executed: false,
        audits: Vec::new(),
        diagnostics: Vec::new(),
    }
}

fn read_http_header_bytes<R>(reader: &mut R) -> Option<Vec<u8>>
where
    R: Read,
{
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];

    while header.len() < HTTP_PROXY_MAX_HEADER_BYTES {
        match reader.read(&mut byte) {
            Ok(1) => {
                header.push(byte[0]);
                if header.ends_with(b"\r\n\r\n") {
                    header.truncate(header.len().saturating_sub(4));
                    return Some(header);
                }
            }
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
    }

    None
}

fn parse_http_start_line_and_headers(header_text: &str) -> Option<(&str, Vec<MetadataEntry>)> {
    let mut lines = header_text.split("\r\n");
    let start_line = lines.next()?.trim();
    if start_line.is_empty() {
        return None;
    }

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        let name = name.trim();
        if name.is_empty() || name.contains('\r') || name.contains('\n') {
            return None;
        }
        headers.push(MetadataEntry {
            key: name.to_string(),
            value: value.trim().to_string(),
        });
    }

    Some((start_line, headers))
}

fn http_content_length(headers: &[MetadataEntry], max_len: usize) -> Result<usize, ()> {
    if headers.iter().any(|header| {
        header.key.eq_ignore_ascii_case("Transfer-Encoding") && !header.value.trim().is_empty()
    }) {
        return Err(());
    }

    let mut content_length = None;
    for header in headers
        .iter()
        .filter(|header| header.key.eq_ignore_ascii_case("Content-Length"))
    {
        if content_length.is_some() {
            return Err(());
        }
        let value = header.value.trim().parse::<usize>().map_err(|_| ())?;
        if value > max_len {
            return Err(());
        }
        content_length = Some(value);
    }

    Ok(content_length.unwrap_or(0))
}

fn parse_explicit_http_proxy_target(
    method: &str,
    target: &str,
    headers: &[MetadataEntry],
) -> Option<ParsedExplicitHttpProxyTarget> {
    if method.eq_ignore_ascii_case("CONNECT") {
        let (target_host, target_port) = parse_http_authority(target, 443)?;
        let authority = http_url_authority(&target_host, target_port, 443);
        return Some(ParsedExplicitHttpProxyTarget {
            target_url: format!("https://{authority}/"),
            target_host,
            target_port,
            origin_path: String::new(),
        });
    }

    if let Some(rest) = target.strip_prefix("http://") {
        return parse_absolute_http_proxy_target("http", rest, 80);
    }
    if let Some(rest) = target.strip_prefix("https://") {
        return parse_absolute_http_proxy_target("https", rest, 443);
    }

    if target.starts_with('/') {
        let host = headers
            .iter()
            .find(|header| header.key.eq_ignore_ascii_case("Host"))?
            .value
            .trim();
        let (target_host, target_port) = parse_http_authority(host, 80)?;
        let authority = http_url_authority(&target_host, target_port, 80);
        return Some(ParsedExplicitHttpProxyTarget {
            target_url: format!("http://{authority}{target}"),
            target_host,
            target_port,
            origin_path: target.to_string(),
        });
    }

    None
}

fn parse_absolute_http_proxy_target(
    scheme: &str,
    rest: &str,
    default_port: u16,
) -> Option<ParsedExplicitHttpProxyTarget> {
    let path_start = rest
        .find('/')
        .or_else(|| rest.find('?'))
        .unwrap_or(rest.len());
    let authority = &rest[..path_start];
    let raw_path = &rest[path_start..];
    let origin_path = if raw_path.is_empty() {
        "/".to_string()
    } else if raw_path.starts_with('?') {
        format!("/{raw_path}")
    } else {
        raw_path.to_string()
    };
    let (target_host, target_port) = parse_http_authority(authority, default_port)?;
    let authority = http_url_authority(&target_host, target_port, default_port);

    Some(ParsedExplicitHttpProxyTarget {
        target_url: format!("{scheme}://{authority}{origin_path}"),
        target_host,
        target_port,
        origin_path,
    })
}

fn parse_http_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    let authority = authority.trim();
    if authority.is_empty() || authority.contains('/') || authority.contains('@') {
        return None;
    }

    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let suffix = &rest[end + 1..];
        let port = if suffix.is_empty() {
            default_port
        } else {
            let port = suffix.strip_prefix(':')?;
            parse_http_port(port)?
        };
        (host, port)
    } else {
        match authority.split_once(':') {
            Some((host, port)) if !port.contains(':') => (host, parse_http_port(port)?),
            Some(_) => return None,
            None => (authority, default_port),
        }
    };

    if host.trim().is_empty() || port == 0 {
        return None;
    }

    Some((host.to_string(), port))
}

fn parse_http_port(port: &str) -> Option<u16> {
    let port = port.trim().parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

fn http_url_authority(host: &str, port: u16, default_port: u16) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    if port == default_port {
        host
    } else {
        format!("{host}:{port}")
    }
}

fn http_host_header_authority(host: &str, port: u16) -> String {
    http_url_authority(host, port, 80)
}

fn explicit_http_proxy_request_to_socks5_target(
    request: &NativeExplicitHttpProxyRequest,
) -> NativeSocks5ConnectTarget {
    let address = match request.target_host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => NativeSocks5Address::Ipv4(address.octets()),
        Ok(IpAddr::V6(address)) => NativeSocks5Address::Ipv6(address.octets()),
        Err(_) => NativeSocks5Address::DomainName(request.target_host.clone()),
    };

    NativeSocks5ConnectTarget {
        address,
        port: request.target_port,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TlsClientHelloMetadata {
    sni_hostname: Option<String>,
    tls_record_version: String,
    tls_handshake_version: String,
}

fn parse_tls_client_hello_metadata(bytes: &[u8]) -> Option<TlsClientHelloMetadata> {
    if *bytes.first()? != 0x16 {
        return None;
    }

    let tls_record_version = format_tls_version(*bytes.get(1)?, *bytes.get(2)?);
    let record_len = u16::from_be_bytes([*bytes.get(3)?, *bytes.get(4)?]) as usize;
    let record_end = 5_usize.checked_add(record_len)?;
    if bytes.len() < record_end {
        return None;
    }

    let handshake = &bytes[5..record_end];
    if handshake.len() < 4 || handshake[0] != 0x01 {
        return None;
    }

    let handshake_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize;
    let handshake_end = 4_usize.checked_add(handshake_len)?;
    if handshake.len() < handshake_end {
        return None;
    }

    let body = &handshake[4..handshake_end];
    if body.len() < 34 {
        return None;
    }

    let tls_handshake_version = format_tls_version(body[0], body[1]);
    let mut cursor = 34_usize;

    let session_id_len = *body.get(cursor)? as usize;
    cursor = cursor.checked_add(1)?.checked_add(session_id_len)?;
    if cursor > body.len() || cursor.checked_add(2)? > body.len() {
        return None;
    }

    let cipher_suites_len = u16::from_be_bytes([body[cursor], body[cursor + 1]]) as usize;
    cursor = cursor.checked_add(2)?.checked_add(cipher_suites_len)?;
    if cursor >= body.len() {
        return None;
    }

    let compression_methods_len = body[cursor] as usize;
    cursor = cursor
        .checked_add(1)?
        .checked_add(compression_methods_len)?;
    if cursor > body.len() {
        return None;
    }

    let sni_hostname = parse_tls_client_hello_sni_extension(&body[cursor..]);

    Some(TlsClientHelloMetadata {
        sni_hostname,
        tls_record_version,
        tls_handshake_version,
    })
}

fn parse_tls_client_hello_sni_extension(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }

    let extensions_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let extensions_end = 2_usize.checked_add(extensions_len)?;
    if bytes.len() < extensions_end {
        return None;
    }

    let extensions = &bytes[2..extensions_end];
    let mut cursor = 0_usize;
    while cursor.checked_add(4)? <= extensions.len() {
        let extension_type = u16::from_be_bytes([extensions[cursor], extensions[cursor + 1]]);
        let extension_len =
            u16::from_be_bytes([extensions[cursor + 2], extensions[cursor + 3]]) as usize;
        cursor = cursor.checked_add(4)?;
        let extension_end = cursor.checked_add(extension_len)?;
        if extension_end > extensions.len() {
            return None;
        }

        if extension_type == 0x0000 {
            return parse_tls_server_name_extension(&extensions[cursor..extension_end]);
        }

        cursor = extension_end;
    }

    None
}

fn parse_tls_server_name_extension(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }

    let names_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    let names_end = 2_usize.checked_add(names_len)?;
    if bytes.len() < names_end {
        return None;
    }

    let mut cursor = 2_usize;
    while cursor.checked_add(3)? <= names_end {
        let name_type = bytes[cursor];
        let name_len = u16::from_be_bytes([bytes[cursor + 1], bytes[cursor + 2]]) as usize;
        cursor = cursor.checked_add(3)?;
        let name_end = cursor.checked_add(name_len)?;
        if name_end > names_end {
            return None;
        }

        if name_type == 0x00 {
            let hostname = std::str::from_utf8(&bytes[cursor..name_end]).ok()?;
            let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
            if tls_sni_hostname_valid(&hostname) {
                return Some(hostname);
            }
            return None;
        }

        cursor = name_end;
    }

    None
}

fn tls_sni_hostname_valid(hostname: &str) -> bool {
    !hostname.is_empty()
        && hostname.len() <= 253
        && !hostname.starts_with('.')
        && !hostname.ends_with('.')
        && hostname
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

fn tls_sni_matches_connect_authority(connect_host: &str, sni_hostname: Option<&str>) -> bool {
    let connect_host = connect_host.trim_end_matches('.').to_ascii_lowercase();
    let Some(sni_hostname) = sni_hostname else {
        return false;
    };
    !connect_host.is_empty()
        && connect_host == sni_hostname.trim_end_matches('.').to_ascii_lowercase()
}

fn format_tls_version(major: u8, minor: u8) -> String {
    match (major, minor) {
        (0x03, 0x01) => "TLS 1.0".to_string(),
        (0x03, 0x02) => "TLS 1.1".to_string(),
        (0x03, 0x03) => "TLS 1.2".to_string(),
        (0x03, 0x04) => "TLS 1.3".to_string(),
        _ => format!("0x{major:02x}{minor:02x}"),
    }
}

fn write_http_headers_to_bytes(bytes: &mut Vec<u8>, headers: &[MetadataEntry]) {
    for header in headers.iter().filter(|header| http_header_safe(header)) {
        bytes.extend_from_slice(header.key.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(header.value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
}

fn http_header_safe(header: &MetadataEntry) -> bool {
    !header.key.trim().is_empty()
        && !header.key.contains('\r')
        && !header.key.contains('\n')
        && !header.value.contains('\r')
        && !header.value.contains('\n')
}

fn normalized_http_version(version: &str) -> &str {
    if version.starts_with("HTTP/") {
        version
    } else {
        "HTTP/1.1"
    }
}

fn http_reason_phrase(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        502 => "Bad Gateway",
        501 => "Not Implemented",
        _ => "NetworkCore",
    }
}

fn plain_http_status_response(version: &str, status_code: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "{} {} {}\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        normalized_http_version(version),
        status_code,
        http_reason_phrase(status_code),
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn explicit_http_proxy_request_read_failed() -> NativeExplicitHttpProxyRequestReadReport {
    NativeExplicitHttpProxyRequestReadReport {
        request: None,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_READ_FAILED_CODE,
            "native explicit HTTP proxy request could not be read",
        )],
    }
}

fn explicit_http_proxy_request_invalid(
    message: &'static str,
) -> NativeExplicitHttpProxyRequestReadReport {
    NativeExplicitHttpProxyRequestReadReport {
        request: None,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_INVALID_CODE,
            message,
        )],
    }
}

fn plain_http_proxy_response_read_failed() -> NativePlainHttpProxyResponseReadReport {
    NativePlainHttpProxyResponseReadReport {
        response: None,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_FAILED_CODE,
            "native plain HTTP proxy upstream response could not be read",
        )],
    }
}

fn plain_http_message_to_mitm_event(message: &NativePlainHttpMessage) -> HttpMitmEvent {
    HttpMitmEvent {
        request_id: message.request_id.clone(),
        url: message.url.clone(),
        method: message.method.clone(),
        phase: message.phase,
        status_code: message.status_code,
        headers: message.headers.clone(),
        body: message.body.clone(),
    }
}

fn apply_plain_http_header_mutations(
    headers: &mut Vec<MetadataEntry>,
    mutations: &[HttpHeaderMutation],
) -> usize {
    let mut applied = 0;

    for mutation in mutations {
        if apply_plain_http_header_mutation(headers, mutation) {
            applied += 1;
        }
    }

    applied
}

fn apply_plain_http_header_mutation(
    headers: &mut Vec<MetadataEntry>,
    mutation: &HttpHeaderMutation,
) -> bool {
    match mutation.operation {
        HttpHeaderMutationOperation::Add => {
            let Some(value) = mutation.value.as_ref() else {
                return false;
            };
            headers.push(MetadataEntry {
                key: mutation.name.clone(),
                value: value.clone(),
            });
            true
        }
        HttpHeaderMutationOperation::Replace => {
            let Some(value) = mutation.value.as_ref() else {
                return false;
            };
            let mut replaced = false;
            for header in headers
                .iter_mut()
                .filter(|header| header.key.eq_ignore_ascii_case(&mutation.name))
            {
                header.value = value.clone();
                replaced = true;
            }
            replaced
        }
        HttpHeaderMutationOperation::Delete => {
            let original_len = headers.len();
            headers.retain(|header| !header.key.eq_ignore_ascii_case(&mutation.name));
            headers.len() != original_len
        }
        HttpHeaderMutationOperation::Set => {
            let Some(value) = mutation.value.as_ref() else {
                return false;
            };
            set_plain_http_header(headers, &mutation.name, value);
            true
        }
    }
}

fn set_plain_http_header(headers: &mut Vec<MetadataEntry>, name: &str, value: &str) {
    headers.retain(|header| !header.key.eq_ignore_ascii_case(name));
    headers.push(MetadataEntry {
        key: name.to_string(),
        value: value.to_string(),
    });
}

fn plain_http_header_value(headers: &[MetadataEntry], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|header| header.key.eq_ignore_ascii_case(name))
        .map(|header| header.value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn https_response_body_content_type_guard_ready(headers: &[MetadataEntry]) -> bool {
    plain_http_header_value(headers, "Content-Type")
        .as_deref()
        .map(https_response_body_content_type_supported)
        .unwrap_or(false)
}

fn https_response_body_content_type_supported(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

    media_type.starts_with("text/")
        || media_type == "application/json"
        || media_type == "application/javascript"
        || media_type == "application/x-javascript"
        || media_type == "application/xml"
        || media_type == "application/xhtml+xml"
        || media_type == "application/x-www-form-urlencoded"
        || media_type.ends_with("+json")
        || media_type.ends_with("+xml")
}

fn https_response_body_buffering_guard_ready(
    input_body: &[u8],
    output_body: Option<&[u8]>,
) -> bool {
    input_body.len() <= HTTP_PROXY_MAX_BODY_BYTES
        && output_body
            .map(|body| body.len() <= HTTP_PROXY_MAX_BODY_BYTES)
            .unwrap_or(true)
}

fn socks5_outbound_connect_response_valid(response: &NativeSocks5OutboundConnectResponse) -> bool {
    response.version == SOCKS5_VERSION
        && response.reply == SOCKS5_REPLY_SUCCEEDED
        && response.reserved == SOCKS5_RESERVED
        && match (response.address_type, &response.bound_address) {
            (SOCKS5_ADDRESS_TYPE_IPV4, NativeSocks5Address::Ipv4(_)) => true,
            (SOCKS5_ADDRESS_TYPE_IPV6, NativeSocks5Address::Ipv6(_)) => true,
            (SOCKS5_ADDRESS_TYPE_DOMAIN_NAME, NativeSocks5Address::DomainName(domain_name)) => {
                !domain_name.trim().is_empty() && domain_name.len() <= u8::MAX as usize
            }
            _ => false,
        }
}

fn relay_socks5_outbound_connect_data_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<u64>
where
    R: Read,
    W: Write,
{
    let bytes = std::io::copy(reader, writer)?;
    writer.flush()?;

    Ok(bytes)
}

fn socks5_outbound_connect_client_success_response_frame(
    response: &NativeSocks5OutboundConnectResponse,
) -> Option<Vec<u8>> {
    if !socks5_outbound_connect_response_valid(response) {
        return None;
    }

    let mut frame = vec![SOCKS5_VERSION, SOCKS5_REPLY_SUCCEEDED, SOCKS5_RESERVED];
    match &response.bound_address {
        NativeSocks5Address::Ipv4(address) => {
            frame.push(SOCKS5_ADDRESS_TYPE_IPV4);
            frame.extend_from_slice(address);
        }
        NativeSocks5Address::DomainName(domain_name) => {
            let domain_name = domain_name.as_bytes();
            frame.push(SOCKS5_ADDRESS_TYPE_DOMAIN_NAME);
            frame.push(domain_name.len() as u8);
            frame.extend_from_slice(domain_name);
        }
        NativeSocks5Address::Ipv6(address) => {
            frame.push(SOCKS5_ADDRESS_TYPE_IPV6);
            frame.extend_from_slice(address);
        }
    }
    frame.extend_from_slice(&response.bound_port.to_be_bytes());

    Some(frame)
}

fn socks5_outbound_connect_request_frame_bytes(
    target: &NativeSocks5ConnectTarget,
) -> Option<Vec<u8>> {
    if !socks5_connect_target_valid(target) {
        return None;
    }

    let mut frame = vec![SOCKS5_VERSION, SOCKS5_COMMAND_CONNECT, SOCKS5_RESERVED];
    match &target.address {
        NativeSocks5Address::Ipv4(address) => {
            frame.push(SOCKS5_ADDRESS_TYPE_IPV4);
            frame.extend_from_slice(address);
        }
        NativeSocks5Address::DomainName(domain_name) => {
            let domain_name = domain_name.as_bytes();
            if domain_name.len() > u8::MAX as usize {
                return None;
            }
            frame.push(SOCKS5_ADDRESS_TYPE_DOMAIN_NAME);
            frame.push(domain_name.len() as u8);
            frame.extend_from_slice(domain_name);
        }
        NativeSocks5Address::Ipv6(address) => {
            frame.push(SOCKS5_ADDRESS_TYPE_IPV6);
            frame.extend_from_slice(address);
        }
    }
    frame.extend_from_slice(&target.port.to_be_bytes());

    Some(frame)
}

fn endpoint_socket_addr(endpoint: &Endpoint) -> Option<SocketAddr> {
    if endpoint.port == 0 {
        return None;
    }

    endpoint
        .host
        .trim()
        .parse::<IpAddr>()
        .ok()
        .map(|host| SocketAddr::new(host, endpoint.port))
}

fn socks5_connect_target_read_failed(message: &'static str) -> NativeSocks5ConnectTargetReadReport {
    NativeSocks5ConnectTargetReadReport {
        target: None,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_FAILED_CODE,
            message,
        )],
    }
}

fn socks5_outbound_connect_response_read_failed(
    message: &'static str,
) -> NativeSocks5OutboundConnectResponseReadReport {
    NativeSocks5OutboundConnectResponseReadReport {
        response: None,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_READ_FAILED_CODE,
            message,
        )],
    }
}

fn relay_socks5_outbound_connect_tcp_streams(
    client_stream: &TcpStream,
    outbound_stream: &TcpStream,
) -> NativeSocks5OutboundConnectDataRelayReport {
    let Ok(mut client_reader) = client_stream.try_clone() else {
        return socks5_outbound_connect_data_relay_failed();
    };
    let Ok(mut outbound_writer) = outbound_stream.try_clone() else {
        return socks5_outbound_connect_data_relay_failed();
    };
    let Ok(mut outbound_reader) = outbound_stream.try_clone() else {
        return socks5_outbound_connect_data_relay_failed();
    };
    let Ok(mut client_writer) = client_stream.try_clone() else {
        return socks5_outbound_connect_data_relay_failed();
    };

    let _ = client_reader.set_read_timeout(Some(Duration::from_millis(
        ACCEPTED_CONNECTION_READ_TIMEOUT_MS,
    )));
    let _ = outbound_reader.set_read_timeout(Some(Duration::from_millis(
        OUTBOUND_CONNECT_RESPONSE_READ_TIMEOUT_MS,
    )));
    let _ = outbound_writer.set_write_timeout(Some(Duration::from_millis(
        OUTBOUND_CONNECT_REQUEST_WRITE_TIMEOUT_MS,
    )));

    relay_socks5_outbound_connect_data(
        &mut client_reader,
        &mut outbound_writer,
        &mut outbound_reader,
        &mut client_writer,
    )
}

fn socks5_outbound_connect_data_relay_failed() -> NativeSocks5OutboundConnectDataRelayReport {
    NativeSocks5OutboundConnectDataRelayReport {
        client_to_outbound_bytes: 0,
        outbound_to_client_bytes: 0,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_FAILED_CODE,
            "native SOCKS5 outbound CONNECT data relay stream handles could not be prepared",
        )],
    }
}

fn diagnostics_contain_code(diagnostics: &[Diagnostic], code: &str) -> bool {
    diagnostics.iter().any(|diagnostic| diagnostic.code == code)
}

fn diagnostics_contain_client_success_written(diagnostics: &[Diagnostic]) -> bool {
    diagnostics_contain_code(
        diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITTEN_CODE,
    )
}

fn diagnostics_contain_data_relay_completed(diagnostics: &[Diagnostic]) -> bool {
    diagnostics_contain_code(
        diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_COMPLETED_CODE,
    )
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    host.parse::<IpAddr>()
        .map(|address| address.is_loopback())
        .unwrap_or(false)
}

fn run_loopback_tcp_accept_loop(
    listener: TcpListener,
    shutdown_rx: mpsc::Receiver<()>,
    accepted_connections: Arc<AtomicUsize>,
    pre_protocol_closed_connections: Arc<AtomicUsize>,
    relayed_connections: Arc<AtomicUsize>,
    identity: NativeLoopbackTcpAcceptLoopIdentity,
) -> NativeLoopbackTcpAcceptLoopShutdownReport {
    let mut diagnostics = Vec::new();
    let mut connection_workers = Vec::new();

    loop {
        collect_finished_connection_workers(&mut connection_workers, &mut diagnostics);
        match shutdown_rx.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
            Err(mpsc::TryRecvError::Empty) => {}
        }

        match listener.accept() {
            Ok((stream, _)) => {
                accepted_connections.fetch_add(1, Ordering::SeqCst);
                if connection_workers.len() >= MAX_CONCURRENT_ACCEPTED_CONNECTIONS {
                    let _ = stream.shutdown(Shutdown::Both);
                    pre_protocol_closed_connections.fetch_add(1, Ordering::SeqCst);
                    diagnostics.push(runtime_warning(
                        ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE,
                        "native loopback tcp accept loop reached the bounded concurrent connection limit",
                    ));
                    continue;
                }
                let worker_identity = identity.clone();
                let worker_pre_protocol_closed_connections =
                    Arc::clone(&pre_protocol_closed_connections);
                let worker_relayed_connections = Arc::clone(&relayed_connections);
                connection_workers.push(thread::spawn(move || {
                    if worker_identity.listener_kind == ListenerKind::Http {
                        handle_plain_http_proxy_accepted_connection(
                            stream,
                            worker_pre_protocol_closed_connections.as_ref(),
                            worker_relayed_connections.as_ref(),
                            &worker_identity.outbound_handler,
                            worker_identity.http_mitm_hook.as_ref(),
                            worker_identity.tls_mitm_ca_material.as_ref(),
                        )
                    } else {
                        read_socks5_greeting_and_close_accepted_connection(
                            stream,
                            worker_pre_protocol_closed_connections.as_ref(),
                            worker_relayed_connections.as_ref(),
                            &worker_identity.outbound_handler,
                            worker_identity.http_mitm_hook.as_ref(),
                            &worker_identity.local_host,
                            worker_identity.local_port,
                        )
                    }
                }));
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                diagnostics.push(engine_diagnostic(
                    DiagnosticSeverity::Error,
                    ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE,
                    "native loopback tcp accept loop failed while accepting connections",
                    SOURCE_ENGINE_NATIVE_RUNTIME,
                ));
                break;
            }
        }
    }

    join_connection_workers(&mut connection_workers, &mut diagnostics);

    diagnostics.push(runtime_info(
        ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_STOPPED_CODE,
        "native loopback tcp accept loop stopped",
    ));

    NativeLoopbackTcpAcceptLoopShutdownReport {
        listener_id: identity.listener_id,
        outbound_handler_id: identity.outbound_handler_id,
        local_host: identity.local_host,
        local_port: identity.local_port,
        accepted_connections: accepted_connections.load(Ordering::SeqCst),
        pre_protocol_closed_connections: pre_protocol_closed_connections.load(Ordering::SeqCst),
        relayed_connections: relayed_connections.load(Ordering::SeqCst),
        diagnostics,
    }
}

fn collect_finished_connection_workers(
    connection_workers: &mut Vec<JoinHandle<Vec<Diagnostic>>>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut pending_workers = Vec::new();
    for worker in std::mem::take(connection_workers) {
        if worker.is_finished() {
            collect_connection_worker(worker, diagnostics);
        } else {
            pending_workers.push(worker);
        }
    }
    *connection_workers = pending_workers;
}

fn join_connection_workers(
    connection_workers: &mut Vec<JoinHandle<Vec<Diagnostic>>>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for worker in std::mem::take(connection_workers) {
        collect_connection_worker(worker, diagnostics);
    }
}

fn collect_connection_worker(
    worker: JoinHandle<Vec<Diagnostic>>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    match worker.join() {
        Ok(connection_diagnostics) => diagnostics.extend(connection_diagnostics),
        Err(_) => diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Error,
            ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE,
            "native loopback tcp connection worker terminated unexpectedly",
            SOURCE_ENGINE_NATIVE_RUNTIME,
        )),
    }
}

fn handle_plain_http_proxy_accepted_connection(
    mut stream: TcpStream,
    pre_protocol_closed_connections: &AtomicUsize,
    relayed_connections: &AtomicUsize,
    outbound_handler: &NativeOutboundHandlerHandle,
    http_mitm_hook: Option<&NativeHttpMitmPluginHook>,
    tls_mitm_ca_material: Option<&NativeTlsMitmCaMaterial>,
) -> Vec<Diagnostic> {
    let mut connection_handled = false;
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(
        ACCEPTED_CONNECTION_READ_TIMEOUT_MS,
    )));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(
        OUTBOUND_CONNECT_REQUEST_WRITE_TIMEOUT_MS,
    )));

    let read_report = read_explicit_http_proxy_request(&mut stream);
    let mut diagnostics = read_report.diagnostics;
    if let Some(request) = read_report.request.as_ref() {
        if request.method.eq_ignore_ascii_case("CONNECT") {
            let (forwarded, forward_diagnostics) = forward_http_connect_tunnel_via_socks_outbound(
                &mut stream,
                request,
                outbound_handler,
                http_mitm_hook,
                tls_mitm_ca_material,
            );
            connection_handled = forwarded;
            diagnostics.extend(forward_diagnostics);
        } else if request.target_url.starts_with("https://") {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Warning,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CONNECT_TLS_BLOCKED_CODE,
                "native explicit HTTP proxy https absolute-form handling remains blocked; use CONNECT for the TLS foundation path",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
            let response = plain_http_status_response(
                &request.version,
                501,
                b"NetworkCore explicit HTTP proxy only accepts HTTPS through CONNECT in this release.\n",
            );
            let write_report = write_plain_http_proxy_client_response(&mut stream, response);
            connection_handled = diagnostics_contain_code(
                &write_report.diagnostics,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
            );
            diagnostics.extend(write_report.diagnostics);
        } else {
            let request_message = explicit_http_proxy_request_to_plain_http_message(request);
            let request_rewrite_report = http_mitm_hook
                .map(|hook| hook.plan_plain_http(&request_message))
                .unwrap_or_else(|| passthrough_plain_http_rewrite_report(&request_message));
            diagnostics.extend(request_rewrite_report.diagnostics.clone());
            record_plain_http_live_rewrite_diagnostic(&mut diagnostics, &request_rewrite_report);

            if request_rewrite_report.terminal_action.is_some() {
                let response =
                    serialize_plain_http_proxy_response(&request.version, &request_rewrite_report);
                let write_report = write_plain_http_proxy_client_response(&mut stream, response);
                connection_handled = diagnostics_contain_code(
                    &write_report.diagnostics,
                    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
                );
                diagnostics.extend(write_report.diagnostics);
            } else {
                let (forwarded, forward_diagnostics) =
                    forward_plain_http_proxy_request_via_socks_outbound(
                        &mut stream,
                        request,
                        &request_rewrite_report,
                        outbound_handler,
                        http_mitm_hook,
                    );
                connection_handled = forwarded;
                diagnostics.extend(forward_diagnostics);
            }
        }
    }

    let _ = stream.shutdown(Shutdown::Both);
    if connection_handled {
        relayed_connections.fetch_add(1, Ordering::SeqCst);
    } else {
        pre_protocol_closed_connections.fetch_add(1, Ordering::SeqCst);
        diagnostics.push(runtime_info(
            ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE,
            "native loopback tcp connection was closed before route and outbound handling",
        ));
    }

    diagnostics
}

fn forward_plain_http_proxy_request_via_socks_outbound(
    client_stream: &mut TcpStream,
    request: &NativeExplicitHttpProxyRequest,
    request_rewrite_report: &NativePlainHttpRewriteReport,
    outbound_handler: &NativeOutboundHandlerHandle,
    http_mitm_hook: Option<&NativeHttpMitmPluginHook>,
) -> (bool, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let target = explicit_http_proxy_request_to_socks5_target(request);
    let route_selection_report = select_socks5_route_outbound_behavior(&target, outbound_handler);
    diagnostics.extend(route_selection_report.diagnostics);
    let frame_report =
        build_socks5_outbound_connect_request_frame(&route_selection_report.behavior);
    diagnostics.extend(frame_report.diagnostics);
    let plan_report =
        plan_socks5_outbound_tcp_connection(&route_selection_report.behavior, &frame_report.frame);
    diagnostics.extend(plan_report.diagnostics);

    if let Some(plan) = plan_report.plan.as_ref() {
        let NativeSocks5OutboundTcpConnectionAttemptReport {
            stream: outbound_stream,
            diagnostics: attempt_diagnostics,
        } = attempt_socks5_outbound_tcp_connection(plan);
        diagnostics.extend(attempt_diagnostics);
        if let Some(mut outbound_stream) = outbound_stream {
            let _ = outbound_stream.set_write_timeout(Some(Duration::from_millis(
                OUTBOUND_CONNECT_REQUEST_WRITE_TIMEOUT_MS,
            )));
            let write_report = write_socks5_outbound_connect_request(&mut outbound_stream, plan);
            let connect_request_written = diagnostics_contain_code(
                &write_report.diagnostics,
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE,
            );
            diagnostics.extend(write_report.diagnostics);
            if connect_request_written {
                let _ = outbound_stream.set_read_timeout(Some(Duration::from_millis(
                    OUTBOUND_CONNECT_RESPONSE_READ_TIMEOUT_MS,
                )));
                let read_report = read_socks5_outbound_connect_response(&mut outbound_stream);
                let response = read_report.response;
                diagnostics.extend(read_report.diagnostics);
                if let Some(response) = response.as_ref() {
                    let decision_report = decide_socks5_outbound_connect_response(response);
                    let decision = decision_report.decision;
                    diagnostics.extend(decision_report.diagnostics);
                    let readiness_report = assess_socks5_outbound_connect_relay_readiness(decision);
                    let readiness = readiness_report.readiness;
                    diagnostics.extend(readiness_report.diagnostics);
                    let data_relay_plan_report = plan_socks5_outbound_connect_data_relay(readiness);
                    let data_relay_plan = data_relay_plan_report.decision;
                    diagnostics.extend(data_relay_plan_report.diagnostics);

                    if data_relay_plan == NativeSocks5OutboundConnectDataRelayPlanDecision::Ready {
                        let request_bytes = serialize_explicit_http_proxy_request_for_upstream(
                            request,
                            request_rewrite_report,
                        );
                        let upstream_write_report = write_plain_http_proxy_upstream_request(
                            &mut outbound_stream,
                            request_bytes,
                        );
                        let upstream_request_written = diagnostics_contain_code(
                            &upstream_write_report.diagnostics,
                            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITTEN_CODE,
                        );
                        diagnostics.extend(upstream_write_report.diagnostics);
                        if upstream_request_written {
                            let response_read_report =
                                read_plain_http_proxy_response(&mut outbound_stream);
                            let upstream_response = response_read_report.response;
                            diagnostics.extend(response_read_report.diagnostics);
                            if let Some(upstream_response) = upstream_response.as_ref() {
                                let response_message =
                                    plain_http_proxy_response_to_plain_http_message(
                                        request,
                                        upstream_response,
                                    );
                                let response_rewrite_report = http_mitm_hook
                                    .map(|hook| hook.plan_plain_http(&response_message))
                                    .unwrap_or_else(|| {
                                        passthrough_plain_http_rewrite_report(&response_message)
                                    });
                                diagnostics.extend(response_rewrite_report.diagnostics.clone());
                                record_plain_http_live_rewrite_diagnostic(
                                    &mut diagnostics,
                                    &response_rewrite_report,
                                );
                                let client_response = serialize_plain_http_proxy_response(
                                    &upstream_response.version,
                                    &response_rewrite_report,
                                );
                                let client_write_report = write_plain_http_proxy_client_response(
                                    client_stream,
                                    client_response,
                                );
                                let client_response_written = diagnostics_contain_code(
                                    &client_write_report.diagnostics,
                                    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
                                );
                                diagnostics.extend(client_write_report.diagnostics);
                                let _ = outbound_stream.shutdown(Shutdown::Both);
                                return (client_response_written, diagnostics);
                            }
                        }
                    }
                }
            }
            let _ = outbound_stream.shutdown(Shutdown::Both);
        }
    }

    let response = plain_http_status_response(
        &request.version,
        502,
        b"NetworkCore plain HTTP proxy could not reach the configured SOCKS outbound.\n",
    );
    let write_report = write_plain_http_proxy_client_response(client_stream, response);
    let response_written = diagnostics_contain_code(
        &write_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
    );
    diagnostics.extend(write_report.diagnostics);

    (response_written, diagnostics)
}

fn run_controlled_tls_connect_http_exchange(
    client_stream: &TcpStream,
    outbound_stream: TcpStream,
    connect_request: &NativeExplicitHttpProxyRequest,
    downstream_server_config: Arc<ServerConfig>,
    upstream_client_config: Arc<ClientConfig>,
    http_mitm_hook: Option<&NativeHttpMitmPluginHook>,
) -> (bool, Vec<Diagnostic>) {
    let mut diagnostics = Vec::new();
    let exchange = (|| -> Result<bool, String> {
        let session_timeout = Duration::from_millis(CONTROLLED_TLS_SESSION_TIMEOUT_MS);
        let _ = client_stream.set_read_timeout(Some(Duration::from_millis(
            CONTROLLED_TLS_SOCKET_READ_TIMEOUT_MS,
        )));
        let _ = client_stream.set_write_timeout(Some(session_timeout));
        let _ = outbound_stream.set_read_timeout(Some(Duration::from_millis(
            CONTROLLED_TLS_SOCKET_READ_TIMEOUT_MS,
        )));
        let _ = outbound_stream.set_write_timeout(Some(session_timeout));
        let client_tls_stream = client_stream.try_clone().map_err(|error| {
            format!("controlled TLS client stream could not be cloned: {error}")
        })?;
        let downstream_connection =
            ServerConnection::new(downstream_server_config).map_err(|error| {
                format!("controlled TLS downstream session could not initialize: {error}")
            })?;
        let mut downstream_tls = StreamOwned::new(downstream_connection, client_tls_stream);

        let decrypted_request_report = {
            let mut bounded_reader = NativeBoundedRead::new(&mut downstream_tls, session_timeout);
            read_https_connect_http_request(&mut bounded_reader, connect_request)
        };
        diagnostics.extend(decrypted_request_report.diagnostics);
        let decrypted_request = decrypted_request_report.request.ok_or_else(|| {
            "controlled TLS downstream session could not read a bounded decrypted HTTP request"
                .to_string()
        })?;

        let request_message = explicit_http_proxy_request_to_plain_http_message(&decrypted_request);
        let request_rewrite_report = http_mitm_hook
            .map(|hook| hook.plan_plain_http(&request_message))
            .unwrap_or_else(|| passthrough_plain_http_rewrite_report(&request_message));
        diagnostics.extend(request_rewrite_report.diagnostics.clone());
        record_plain_http_live_rewrite_diagnostic(&mut diagnostics, &request_rewrite_report);

        if request_rewrite_report.terminal_action.is_some() {
            let client_response = serialize_plain_http_proxy_response(
                &decrypted_request.version,
                &request_rewrite_report,
            );
            let client_write_report =
                write_plain_http_proxy_client_response(&mut downstream_tls, client_response);
            let response_written = diagnostics_contain_code(
                &client_write_report.diagnostics,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
            );
            diagnostics.extend(client_write_report.diagnostics);
            return Ok(response_written);
        }

        let server_name = ServerName::try_from(connect_request.target_host.as_str())
            .map_err(|error| format!("controlled TLS upstream authority is invalid: {error}"))?
            .to_owned();
        let upstream_connection = ClientConnection::new(upstream_client_config, server_name)
            .map_err(|error| {
                format!("controlled TLS upstream session could not initialize: {error}")
            })?;
        let mut upstream_tls = StreamOwned::new(upstream_connection, outbound_stream);
        let upstream_request = serialize_explicit_http_proxy_request_for_upstream(
            &decrypted_request,
            &request_rewrite_report,
        );
        let upstream_write_report =
            write_plain_http_proxy_upstream_request(&mut upstream_tls, upstream_request);
        let upstream_request_written = diagnostics_contain_code(
            &upstream_write_report.diagnostics,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITTEN_CODE,
        );
        diagnostics.extend(upstream_write_report.diagnostics);
        if !upstream_request_written {
            return Err("controlled TLS upstream request write failed".to_string());
        }

        let upstream_response_report = {
            let mut bounded_reader = NativeBoundedRead::new(&mut upstream_tls, session_timeout);
            read_plain_http_proxy_response(&mut bounded_reader)
        };
        diagnostics.extend(upstream_response_report.diagnostics.clone());
        let upstream_response = upstream_response_report.response.ok_or_else(|| {
            "controlled TLS upstream session could not read a bounded HTTP response".to_string()
        })?;
        let response_message =
            plain_http_proxy_response_to_plain_http_message(&decrypted_request, &upstream_response);
        let response_rewrite_report = http_mitm_hook
            .map(|hook| hook.plan_plain_http(&response_message))
            .unwrap_or_else(|| passthrough_plain_http_rewrite_report(&response_message));
        diagnostics.extend(response_rewrite_report.diagnostics.clone());
        record_plain_http_live_rewrite_diagnostic(&mut diagnostics, &response_rewrite_report);
        let client_response = serialize_plain_http_proxy_response(
            &upstream_response.version,
            &response_rewrite_report,
        );
        let client_write_report =
            write_plain_http_proxy_client_response(&mut downstream_tls, client_response);
        let response_written = diagnostics_contain_code(
            &client_write_report.diagnostics,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
        );
        diagnostics.extend(client_write_report.diagnostics);
        Ok(response_written)
    })();

    match exchange {
        Ok(response_written) => {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Info,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_READY_CODE,
                "native explicit HTTP proxy CONNECT completed a controlled TLS HTTP/1.1 request/response exchange",
                SOURCE_ENGINE_NATIVE_MITM,
            ));
            (response_written, diagnostics)
        }
        Err(error) => {
            diagnostics.push(engine_diagnostic(
                DiagnosticSeverity::Error,
                ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_FAILED_CODE,
                error,
                SOURCE_ENGINE_NATIVE_MITM,
            ));
            (false, diagnostics)
        }
    }
}

fn forward_http_connect_tunnel_via_socks_outbound(
    client_stream: &mut TcpStream,
    request: &NativeExplicitHttpProxyRequest,
    outbound_handler: &NativeOutboundHandlerHandle,
    http_mitm_hook: Option<&NativeHttpMitmPluginHook>,
    tls_mitm_ca_material: Option<&NativeTlsMitmCaMaterial>,
) -> (bool, Vec<Diagnostic>) {
    let foundation_report = plan_explicit_http_connect_tls_mitm_foundation(request);
    let mut diagnostics = foundation_report.diagnostics.clone();
    let target = explicit_http_proxy_request_to_socks5_target(request);
    let route_selection_report = select_socks5_route_outbound_behavior(&target, outbound_handler);
    diagnostics.extend(route_selection_report.diagnostics);
    let frame_report =
        build_socks5_outbound_connect_request_frame(&route_selection_report.behavior);
    diagnostics.extend(frame_report.diagnostics);
    let plan_report =
        plan_socks5_outbound_tcp_connection(&route_selection_report.behavior, &frame_report.frame);
    diagnostics.extend(plan_report.diagnostics);

    if let Some(plan) = plan_report.plan.as_ref() {
        let NativeSocks5OutboundTcpConnectionAttemptReport {
            stream: outbound_stream,
            diagnostics: attempt_diagnostics,
        } = attempt_socks5_outbound_tcp_connection(plan);
        diagnostics.extend(attempt_diagnostics);
        if let Some(mut outbound_stream) = outbound_stream {
            let _ = outbound_stream.set_write_timeout(Some(Duration::from_millis(
                OUTBOUND_CONNECT_REQUEST_WRITE_TIMEOUT_MS,
            )));
            let write_report = write_socks5_outbound_connect_request(&mut outbound_stream, plan);
            let connect_request_written = diagnostics_contain_code(
                &write_report.diagnostics,
                ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE,
            );
            diagnostics.extend(write_report.diagnostics);
            if connect_request_written {
                let _ = outbound_stream.set_read_timeout(Some(Duration::from_millis(
                    OUTBOUND_CONNECT_RESPONSE_READ_TIMEOUT_MS,
                )));
                let read_report = read_socks5_outbound_connect_response(&mut outbound_stream);
                let response = read_report.response;
                diagnostics.extend(read_report.diagnostics);
                if let Some(response) = response.as_ref() {
                    let decision_report = decide_socks5_outbound_connect_response(response);
                    let decision = decision_report.decision;
                    diagnostics.extend(decision_report.diagnostics);
                    let readiness_report = assess_socks5_outbound_connect_relay_readiness(decision);
                    let readiness = readiness_report.readiness;
                    diagnostics.extend(readiness_report.diagnostics);
                    let data_relay_plan_report = plan_socks5_outbound_connect_data_relay(readiness);
                    let data_relay_plan = data_relay_plan_report.decision;
                    diagnostics.extend(data_relay_plan_report.diagnostics);

                    if data_relay_plan == NativeSocks5OutboundConnectDataRelayPlanDecision::Ready {
                        let connect_response = write_http_connect_established_response(
                            client_stream,
                            &request.version,
                        );
                        let tunnel_established = diagnostics_contain_code(
                            &connect_response.diagnostics,
                            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_ESTABLISHED_CODE,
                        );
                        diagnostics.extend(connect_response.diagnostics);
                        if tunnel_established {
                            let wait_for_complete_client_hello = tls_mitm_ca_material.is_some();
                            let client_hello_report =
                                observe_http_connect_tls_client_hello_from_stream(
                                    client_stream,
                                    request,
                                    wait_for_complete_client_hello,
                                );
                            diagnostics.extend(client_hello_report.diagnostics.clone());
                            if let Some(tls_mitm_ca_material) = tls_mitm_ca_material {
                                let termination_plan =
                                    plan_explicit_http_connect_controlled_tls_termination(
                                        request,
                                        &foundation_report,
                                        &client_hello_report,
                                        tls_mitm_ca_material.certificate_pem_ready(),
                                        tls_mitm_ca_material.private_key_pem_ready(),
                                    );
                                diagnostics.extend(termination_plan.diagnostics.clone());
                                let leaf_certificate_report =
                                    issue_controlled_tls_termination_leaf_certificate(
                                        &termination_plan,
                                        tls_mitm_ca_material.certificate_pem(),
                                        tls_mitm_ca_material.private_key_pem(),
                                    );
                                diagnostics.extend(leaf_certificate_report.diagnostics.clone());
                                let Some(leaf_certificate_material) =
                                    leaf_certificate_report.material.as_ref()
                                else {
                                    let _ = outbound_stream.shutdown(Shutdown::Both);
                                    return (false, diagnostics);
                                };
                                let downstream_config_report =
                                    build_controlled_tls_termination_server_config(
                                        leaf_certificate_material,
                                    );
                                diagnostics.extend(downstream_config_report.diagnostics.clone());
                                let Some(downstream_server_config) =
                                    downstream_config_report.server_config
                                else {
                                    let _ = outbound_stream.shutdown(Shutdown::Both);
                                    return (false, diagnostics);
                                };
                                let upstream_config_report =
                                    build_controlled_tls_upstream_client_config();
                                diagnostics.extend(upstream_config_report.diagnostics.clone());
                                let Some(upstream_client_config) =
                                    upstream_config_report.client_config
                                else {
                                    let _ = outbound_stream.shutdown(Shutdown::Both);
                                    return (false, diagnostics);
                                };
                                let (exchange_completed, exchange_diagnostics) =
                                    run_controlled_tls_connect_http_exchange(
                                        client_stream,
                                        outbound_stream,
                                        request,
                                        downstream_server_config,
                                        upstream_client_config,
                                        http_mitm_hook,
                                    );
                                diagnostics.extend(exchange_diagnostics);
                                return (exchange_completed, diagnostics);
                            }
                            let relay_report = relay_socks5_outbound_connect_tcp_streams(
                                client_stream,
                                &outbound_stream,
                            );
                            let tunnel_relayed =
                                diagnostics_contain_data_relay_completed(&relay_report.diagnostics);
                            diagnostics.extend(relay_report.diagnostics);
                            let _ = outbound_stream.shutdown(Shutdown::Both);
                            return (tunnel_relayed, diagnostics);
                        }
                    }
                }
            }
            let _ = outbound_stream.shutdown(Shutdown::Both);
        }
    }

    diagnostics.push(engine_diagnostic(
        DiagnosticSeverity::Warning,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_FAILED_CODE,
        "native explicit HTTP proxy CONNECT tunnel could not be established through the configured SOCKS outbound",
        SOURCE_ENGINE_NATIVE_MITM,
    ));
    let response = plain_http_status_response(
        &request.version,
        502,
        b"NetworkCore explicit HTTP CONNECT tunnel could not reach the configured SOCKS outbound.\n",
    );
    let write_report = write_plain_http_proxy_client_response(client_stream, response);
    let response_written = diagnostics_contain_code(
        &write_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
    );
    diagnostics.extend(write_report.diagnostics);

    (response_written, diagnostics)
}

fn observe_http_connect_tls_client_hello_from_stream(
    client_stream: &TcpStream,
    request: &NativeExplicitHttpProxyRequest,
    wait_for_complete_client_hello: bool,
) -> NativeTlsClientHelloObservationReport {
    let mut buffer = [0_u8; TLS_CLIENT_HELLO_PEEK_MAX_BYTES];
    let prior_timeout = client_stream.read_timeout().ok().flatten();
    if wait_for_complete_client_hello {
        let _ = client_stream.set_read_timeout(Some(Duration::from_millis(
            ACCEPTED_CONNECTION_READ_TIMEOUT_MS,
        )));
    }
    let started_at = Instant::now();
    let report = loop {
        let bytes = match client_stream.peek(&mut buffer) {
            Ok(bytes_read) => &buffer[..bytes_read],
            Err(error) if error.kind() == ErrorKind::WouldBlock => &buffer[..0],
            Err(error) if error.kind() == ErrorKind::TimedOut => &buffer[..0],
            Err(_) => &buffer[..0],
        };
        let report = observe_explicit_http_connect_tls_client_hello(request, bytes);
        if report.client_hello_observed
            || !wait_for_complete_client_hello
            || started_at.elapsed()
                >= Duration::from_millis(TLS_CLIENT_HELLO_OBSERVATION_TIMEOUT_MS)
        {
            break report;
        }
        thread::sleep(Duration::from_millis(TLS_CLIENT_HELLO_OBSERVATION_POLL_MS));
    };
    if wait_for_complete_client_hello {
        let _ = client_stream.set_read_timeout(prior_timeout);
    }

    report
}

fn record_plain_http_live_rewrite_diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    rewrite_report: &NativePlainHttpRewriteReport,
) {
    if rewrite_report.applied || rewrite_report.script_dispatch_deferred {
        diagnostics.push(engine_diagnostic(
            DiagnosticSeverity::Info,
            ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REWRITE_APPLIED_CODE,
            "native explicit HTTP proxy applied a plain HTTP MITM rewrite report",
            SOURCE_ENGINE_NATIVE_MITM,
        ));
    }
}

fn read_socks5_greeting_and_close_accepted_connection(
    mut stream: TcpStream,
    pre_protocol_closed_connections: &AtomicUsize,
    relayed_connections: &AtomicUsize,
    outbound_handler: &NativeOutboundHandlerHandle,
    http_mitm_hook: Option<&NativeHttpMitmPluginHook>,
    local_host: &str,
    local_port: u16,
) -> Vec<Diagnostic> {
    let mut connection_relayed = false;
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(
        ACCEPTED_CONNECTION_READ_TIMEOUT_MS,
    )));
    let read_report = read_socks5_greeting(&mut stream);
    let mut diagnostics = read_report.diagnostics;
    if let Some(greeting) = read_report
        .greeting
        .as_ref()
        .filter(|greeting| greeting.version == SOCKS5_VERSION && !greeting.auth_methods.is_empty())
    {
        let selection_report = select_socks5_auth_method(greeting);
        let decision = selection_report.decision;
        diagnostics.extend(selection_report.diagnostics);
        diagnostics.extend(write_socks5_auth_method_response(&mut stream, decision).diagnostics);
        if decision == NativeSocks5AuthMethodDecision::NoAuthenticationRequired {
            let NativeSocks5CommandHeaderReadReport {
                command_header,
                diagnostics: command_diagnostics,
            } = read_socks5_command_header(&mut stream);
            diagnostics.extend(command_diagnostics);
            if let Some(command_header) = command_header
                .as_ref()
                .filter(|command_header| socks5_command_header_valid(command_header))
            {
                let support_report = reject_unsupported_socks5_command(command_header);
                let command_decision = support_report.decision;
                diagnostics.extend(support_report.diagnostics);
                if command_decision == NativeSocks5CommandDecision::Connect {
                    let NativeSocks5ConnectTargetReadReport {
                        target,
                        diagnostics: target_diagnostics,
                    } = read_socks5_connect_target(&mut stream, command_header);
                    diagnostics.extend(target_diagnostics);
                    if let Some(target) = target
                        .as_ref()
                        .filter(|target| socks5_connect_target_valid(target))
                    {
                        let mut rejected_by_http_mitm = false;
                        if let Some(hook) = http_mitm_hook {
                            let mitm_plan_report = hook.plan_socks5_connect(
                                socks5_connect_http_mitm_request_id(target),
                                target,
                            );
                            let browser_capture_proof_token =
                                native_socks5_connect_browser_capture_proof_token(
                                    target, "socks5", local_host, local_port,
                                );
                            rejected_by_http_mitm = mitm_plan_report
                                .outcome
                                .as_ref()
                                .map(http_mitm_outcome_rejects)
                                .unwrap_or(false);
                            diagnostics.extend(mitm_plan_report.diagnostics);
                            diagnostics.push(engine_diagnostic(
                                DiagnosticSeverity::Info,
                                ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_BROWSER_PROOF_OBSERVED_CODE,
                                format!(
                                    "native SOCKS5 CONNECT browser capture proof token {browser_capture_proof_token} observed for target {} via socks5://{}:{}",
                                    socks5_target_header_authority(target),
                                    local_host,
                                    local_port
                                ),
                                SOURCE_ENGINE_NATIVE_MITM,
                            ));
                            if rejected_by_http_mitm {
                                diagnostics.push(engine_diagnostic(
                                    DiagnosticSeverity::Info,
                                    ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_APPLIED_CODE,
                                    "native SOCKS5 CONNECT was rejected by the MITM plugin plan",
                                    SOURCE_ENGINE_NATIVE_MITM,
                                ));
                                let failure_response_report =
                                    write_http_mitm_rejected_socks5_connect_failure_response(
                                        &mut stream,
                                    );
                                diagnostics.extend(failure_response_report.diagnostics);
                            }
                        }

                        if !rejected_by_http_mitm {
                            let mut failure_response_required = true;
                            let route_selection_report =
                                select_socks5_route_outbound_behavior(target, outbound_handler);
                            diagnostics.extend(route_selection_report.diagnostics);
                            let frame_report = build_socks5_outbound_connect_request_frame(
                                &route_selection_report.behavior,
                            );
                            diagnostics.extend(frame_report.diagnostics);
                            let plan_report = plan_socks5_outbound_tcp_connection(
                                &route_selection_report.behavior,
                                &frame_report.frame,
                            );
                            diagnostics.extend(plan_report.diagnostics);
                            if let Some(plan) = plan_report.plan.as_ref() {
                                let NativeSocks5OutboundTcpConnectionAttemptReport {
                                    stream: outbound_stream,
                                    diagnostics: attempt_diagnostics,
                                } = attempt_socks5_outbound_tcp_connection(plan);
                                diagnostics.extend(attempt_diagnostics);
                                if let Some(mut outbound_stream) = outbound_stream {
                                    let _ = outbound_stream.set_write_timeout(Some(
                                        Duration::from_millis(
                                            OUTBOUND_CONNECT_REQUEST_WRITE_TIMEOUT_MS,
                                        ),
                                    ));
                                    let write_report = write_socks5_outbound_connect_request(
                                        &mut outbound_stream,
                                        plan,
                                    );
                                    let connect_request_written =
                                        write_report.diagnostics.iter().any(|diagnostic| {
                                            diagnostic.code
                                                == ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE
                                        });
                                    diagnostics.extend(write_report.diagnostics);
                                    if connect_request_written {
                                        let _ = outbound_stream.set_read_timeout(Some(
                                            Duration::from_millis(
                                                OUTBOUND_CONNECT_RESPONSE_READ_TIMEOUT_MS,
                                            ),
                                        ));
                                        let read_report = read_socks5_outbound_connect_response(
                                            &mut outbound_stream,
                                        );
                                        let response = read_report.response;
                                        diagnostics.extend(read_report.diagnostics);
                                        if let Some(response) = response.as_ref() {
                                            let decision_report =
                                                decide_socks5_outbound_connect_response(response);
                                            let decision = decision_report.decision;
                                            diagnostics.extend(decision_report.diagnostics);
                                            let readiness_report =
                                                assess_socks5_outbound_connect_relay_readiness(
                                                    decision,
                                                );
                                            let readiness = readiness_report.readiness;
                                            diagnostics.extend(readiness_report.diagnostics);
                                            let data_relay_plan_report =
                                                plan_socks5_outbound_connect_data_relay(readiness);
                                            let data_relay_plan = data_relay_plan_report.decision;
                                            diagnostics.extend(data_relay_plan_report.diagnostics);
                                            let client_success_readiness_report =
                                                assess_socks5_outbound_connect_client_success_response_readiness(
                                                    data_relay_plan,
                                                );
                                            let client_success_readiness =
                                                client_success_readiness_report.readiness;
                                            diagnostics.extend(
                                                client_success_readiness_report.diagnostics,
                                            );
                                            let write_plan_report =
                                                plan_socks5_outbound_connect_client_success_response_write(
                                                    client_success_readiness,
                                                );
                                            let write_plan = write_plan_report.decision;
                                            diagnostics.extend(write_plan_report.diagnostics);
                                            let write_plan_ready = matches!(
                                                write_plan,
                                                NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision::Ready
                                            );
                                            if write_plan_ready {
                                                failure_response_required = false;
                                                let client_success_write_report =
                                                    write_socks5_outbound_connect_client_success_response(
                                                        &mut stream,
                                                        response,
                                                    );
                                                let client_success_write_diagnostics =
                                                    client_success_write_report.diagnostics;
                                                let client_success_response_written =
                                                    diagnostics_contain_client_success_written(
                                                        &client_success_write_diagnostics,
                                                    );
                                                diagnostics
                                                    .extend(client_success_write_diagnostics);
                                                if client_success_response_written {
                                                    let data_relay_report =
                                                        relay_socks5_outbound_connect_tcp_streams(
                                                            &stream,
                                                            &outbound_stream,
                                                        );
                                                    let data_relay_diagnostics =
                                                        data_relay_report.diagnostics;
                                                    connection_relayed =
                                                        diagnostics_contain_data_relay_completed(
                                                            &data_relay_diagnostics,
                                                        );
                                                    diagnostics.extend(data_relay_diagnostics);
                                                }
                                            }
                                        }
                                    }
                                    let _ = outbound_stream.shutdown(Shutdown::Both);
                                }
                            }
                            if failure_response_required {
                                diagnostics.extend(
                                    reject_unwired_socks5_route_outbound(target).diagnostics,
                                );
                                let failure_response_report =
                                    write_unwired_socks5_connect_failure_response(&mut stream);
                                diagnostics.extend(failure_response_report.diagnostics);
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
    if connection_relayed {
        relayed_connections.fetch_add(1, Ordering::SeqCst);
    } else {
        pre_protocol_closed_connections.fetch_add(1, Ordering::SeqCst);

        diagnostics.push(runtime_info(
            ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE,
            "native loopback tcp connection was closed before route and outbound handling",
        ));
    }

    diagnostics
}

#[derive(Debug)]
struct NativeRuntimeReleaseResources {
    engine_id: String,
    listeners: Vec<LoopbackListenerHandle>,
    bound_listeners: Vec<BoundLoopbackTcpListenerHandle>,
    accept_loops: Vec<NativeLoopbackTcpAcceptLoopHandle>,
    outbound_handlers: Vec<NativeOutboundHandlerHandle>,
    events: Vec<ProxyEngineEvent>,
}

fn release_report(
    resources: NativeRuntimeReleaseResources,
    event_kind: ProxyEngineEventKind,
    mut diagnostics: Vec<Diagnostic>,
) -> NativeRuntimeReleaseReport {
    let NativeRuntimeReleaseResources {
        engine_id,
        listeners,
        bound_listeners,
        accept_loops,
        outbound_handlers,
        mut events,
    } = resources;
    let mut listener_ids = listeners
        .into_iter()
        .map(|listener| listener.listener_id)
        .collect::<Vec<_>>();
    listener_ids.extend(
        bound_listeners
            .into_iter()
            .map(|listener| listener.release().listener_id),
    );
    let mut outbound_handler_ids = outbound_handlers
        .into_iter()
        .map(|outbound_handler| outbound_handler.node_id)
        .collect::<Vec<_>>();
    for accept_loop in accept_loops {
        let report = accept_loop.shutdown();
        listener_ids.push(report.listener_id);
        outbound_handler_ids.push(report.outbound_handler_id);
        diagnostics.extend(report.diagnostics);
    }

    diagnostics.push(runtime_info(
        ENGINE_NATIVE_RUNTIME_RELEASED_CODE,
        "native runtime handles were released",
    ));
    events.push(runtime_event(&engine_id, event_kind, diagnostics.clone()));

    NativeRuntimeReleaseReport {
        engine_id,
        listener_ids,
        outbound_handler_ids,
        diagnostics,
        events,
    }
}

fn runtime_error(code: impl Into<String>, message: impl Into<String>) -> DomainError {
    DomainError::new(code, message)
}

fn runtime_info(code: impl Into<String>, message: impl Into<String>) -> Diagnostic {
    engine_diagnostic(
        DiagnosticSeverity::Info,
        code,
        message,
        SOURCE_ENGINE_NATIVE_RUNTIME,
    )
}

fn runtime_warning(code: impl Into<String>, message: impl Into<String>) -> Diagnostic {
    engine_diagnostic(
        DiagnosticSeverity::Warning,
        code,
        message,
        SOURCE_ENGINE_NATIVE_RUNTIME,
    )
}

fn runtime_event(
    engine_id: &str,
    kind: ProxyEngineEventKind,
    diagnostics: Vec<Diagnostic>,
) -> ProxyEngineEvent {
    ProxyEngineEvent {
        engine_id: engine_id.to_string(),
        kind,
        diagnostics,
    }
}

fn domain_error(code: impl Into<String>, message: impl Into<String>) -> DomainError {
    DomainError::new(code, message)
}

fn config_error(code: impl Into<String>, message: impl Into<String>) -> Diagnostic {
    engine_diagnostic(
        DiagnosticSeverity::Error,
        code,
        message,
        SOURCE_ENGINE_NATIVE_CONFIG,
    )
}

fn engine_diagnostic(
    severity: DiagnosticSeverity,
    code: impl Into<String>,
    message: impl Into<String>,
    source: impl Into<String>,
) -> Diagnostic {
    Diagnostic::new(severity, code, message, Some(source.into()))
}

#[cfg(all(test, unix))]
mod script_runtime_security_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn script_runtime_body_staging_uses_owner_only_permissions() {
        let path = write_script_runtime_body(b"sensitive script body")
            .expect("script runtime body should stage securely");
        let mode = std::fs::metadata(&path)
            .expect("script runtime body metadata should be readable")
            .permissions()
            .mode()
            & 0o777;
        let _ = std::fs::remove_file(&path);

        assert_eq!(mode, 0o600);
    }
}

#[cfg(test)]
mod controlled_tls_session_tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose,
    };
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
        ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    };
    use std::collections::BTreeMap;
    use std::io::{Cursor, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn controlled_tls_connect_exchange_decrypts_forwards_and_executes_scripts_over_live_sockets() {
        let script_runtime_root = std::env::temp_dir().join(format!(
            "networkcore-controlled-tls-script-contract-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&script_runtime_root);
        std::fs::create_dir_all(&script_runtime_root)
            .expect("controlled TLS script runtime directory should be created");
        let script_url = "https://scripts.networkcore.test/controlled-tls.js".to_string();
        let mut script_assets = BTreeMap::new();
        script_assets.insert(
            script_url.clone(),
            format!(
                "{}/../../third_party/mitm_anixops/mitm_anixops/tests/fixtures/runner_replay_script.js",
                env!("CARGO_MANIFEST_DIR")
            ),
        );
        let http_mitm_hook = NativeHttpMitmPluginHook::new(
            PluginInstance {
                manifest: PluginManifest {
                    id: "networkcore.controlled-tls-script".to_string(),
                    version: "0.1.0".to_string(),
                    permissions: vec![
                        PluginPermission::ReadRequest,
                        PluginPermission::ModifyRequest,
                        PluginPermission::ReadResponse,
                        PluginPermission::ModifyResponse,
                        PluginPermission::PersistentStorage,
                    ],
                    hooks: vec![HookPoint::Request, HookPoint::Response],
                },
                loaded_source: None,
            },
            Arc::new(ControlledTlsScriptDispatchingMitmPluginService { script_url }),
        )
        .with_node_script_executor(NativeNodeScriptExecutor::new(
            NativeNodeScriptRuntimeConfig {
                node_binary: "node".to_string(),
                runner_path: format!(
                    "{}/../../third_party/mitm_anixops/mitm_anixops/e2e/script_runtime/anixops_runner.js",
                    env!("CARGO_MANIFEST_DIR")
                ),
                script_assets,
                persistent_store_path: Some(
                    script_runtime_root.join("store.json").display().to_string(),
                ),
                max_timeout_ms: 5000,
                max_body_bytes: 4096,
            },
        ));
        let (mitm_ca_certificate_pem, mitm_ca_private_key_pem, mitm_ca_der) = test_ca_material();
        let (mitm_leaf_certificate_der, mitm_leaf_private_key_der) = issue_test_leaf(
            &mitm_ca_certificate_pem,
            &mitm_ca_private_key_pem,
            "example.com",
        );
        let downstream_material = NativeTlsLeafCertificateMaterial {
            authority: "example.com".to_string(),
            certificate_pem: String::new(),
            private_key_pem: String::new(),
            certificate_der: mitm_leaf_certificate_der,
            private_key_der: mitm_leaf_private_key_der,
        };
        let downstream_server_config =
            build_controlled_tls_termination_server_config(&downstream_material)
                .server_config
                .expect("test MITM leaf material should build a downstream server config");

        let (upstream_ca_certificate_pem, upstream_ca_private_key_pem, upstream_ca_der) =
            test_ca_material();
        let (upstream_leaf_certificate_der, upstream_leaf_private_key_der) = issue_test_leaf(
            &upstream_ca_certificate_pem,
            &upstream_ca_private_key_pem,
            "example.com",
        );
        let upstream_server_config =
            test_server_config(upstream_leaf_certificate_der, upstream_leaf_private_key_der);
        let upstream_client_config = test_client_config(upstream_ca_der);

        let upstream_listener =
            TcpListener::bind("127.0.0.1:0").expect("test upstream listener should bind");
        let upstream_address = upstream_listener
            .local_addr()
            .expect("test upstream listener should expose local address");
        let upstream_worker = thread::spawn(move || {
            let (stream, _) = upstream_listener
                .accept()
                .expect("test upstream should accept proxy TLS connection");
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
            let connection = ServerConnection::new(upstream_server_config)
                .expect("test upstream TLS connection should initialize");
            let mut tls_stream = StreamOwned::new(connection, stream);
            let request = read_explicit_http_proxy_request(&mut tls_stream)
                .request
                .expect("test upstream should receive decrypted HTTP request");
            assert_eq!(request.origin_path, "/resource");
            assert!(std::str::from_utf8(&request.body)
                .expect("script-mutated upstream request body should be UTF-8")
                .contains("requestRuntime"));
            let response_body = b"{\"from\":\"upstream\"}";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                std::str::from_utf8(response_body)
                    .expect("test upstream response body should be UTF-8"),
            );
            tls_stream
                .write_all(response.as_bytes())
                .expect("test upstream should write HTTPS response");
            tls_stream
                .flush()
                .expect("test upstream should flush HTTPS response");
        });

        let proxy_listener =
            TcpListener::bind("127.0.0.1:0").expect("test proxy listener should bind");
        let proxy_address = proxy_listener
            .local_addr()
            .expect("test proxy listener should expose local address");
        let downstream_client_config = test_client_config(mitm_ca_der);
        let downstream_client = thread::spawn(move || {
            let stream = TcpStream::connect(proxy_address)
                .expect("test TLS client should connect to controlled proxy session");
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
            let server_name = ServerName::try_from("example.com")
                .expect("test server name should parse")
                .to_owned();
            let connection = ClientConnection::new(downstream_client_config, server_name)
                .expect("test TLS client connection should initialize");
            let mut tls_stream = StreamOwned::new(connection, stream);
            tls_stream
                .write_all(b"GET /resource HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .expect("test TLS client should write HTTP request");
            tls_stream
                .flush()
                .expect("test TLS client should flush HTTP request");
            let response = read_plain_http_proxy_response(&mut tls_stream)
                .response
                .expect("test TLS client should receive HTTP response");
            assert_eq!(response.status_code, 202);
            assert!(std::str::from_utf8(&response.body)
                .expect("script-mutated client response body should be UTF-8")
                .contains("responseRuntime"));
        });

        let (proxy_stream, _) = proxy_listener
            .accept()
            .expect("test proxy should accept controlled TLS client connection");
        let _ = proxy_stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = proxy_stream.set_write_timeout(Some(Duration::from_secs(5)));
        let outbound_stream = TcpStream::connect(upstream_address)
            .expect("test proxy should connect to upstream TLS server");
        let mut connect_request = Cursor::new(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec(),
        );
        let connect_request = read_explicit_http_proxy_request(&mut connect_request)
            .request
            .expect("test CONNECT request should parse");
        let (exchange_completed, diagnostics) = run_controlled_tls_connect_http_exchange(
            &proxy_stream,
            outbound_stream,
            &connect_request,
            downstream_server_config,
            upstream_client_config,
            Some(&http_mitm_hook),
        );

        assert!(exchange_completed);
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_READY_CODE
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.code == ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_EXECUTED_CODE
        }));
        downstream_client
            .join()
            .expect("test TLS client thread should finish");
        upstream_worker
            .join()
            .expect("test upstream TLS thread should finish");
        std::fs::remove_dir_all(&script_runtime_root)
            .expect("controlled TLS script runtime directory should be removed");
    }

    struct ControlledTlsScriptDispatchingMitmPluginService {
        script_url: String,
    }

    impl MitmPluginService for ControlledTlsScriptDispatchingMitmPluginService {
        fn validate_manifest(&self, _plugin_manifest: &PluginManifest) -> Vec<Diagnostic> {
            Vec::new()
        }

        fn load(
            &self,
            plugin_package: &PluginPackage,
            _granted_permissions: &GrantedPermissions,
        ) -> DomainResult<PluginInstance> {
            Ok(PluginInstance {
                manifest: plugin_package.manifest.clone(),
                loaded_source: None,
            })
        }

        fn handle_http_event(
            &self,
            _plugin_instance: &PluginInstance,
            _http_event: &HttpEvent,
        ) -> DomainResult<PluginResult> {
            Ok(PluginResult {
                audits: Vec::new(),
                diagnostics: Vec::new(),
            })
        }

        fn handle_http_mitm_event(
            &self,
            plugin_instance: &PluginInstance,
            http_event: &HttpMitmEvent,
        ) -> DomainResult<HttpMitmOutcome> {
            assert_eq!(
                plugin_instance.manifest.id,
                "networkcore.controlled-tls-script"
            );
            assert_eq!(http_event.url, "https://example.com/resource");

            let kind = match http_event.phase {
                HttpMitmPhase::Request => HttpMitmScriptKind::Request,
                HttpMitmPhase::Response => HttpMitmScriptKind::Response,
            };
            Ok(HttpMitmOutcome {
                action: HttpMitmAction::Continue,
                header_mutations: Vec::new(),
                body_mutation: None,
                script_dispatch: Some(HttpMitmScriptDispatch {
                    kind,
                    phase: http_event.phase,
                    requires_body: true,
                    timeout_ms: 1000,
                    max_size: 1024,
                    script_path: self.script_url.clone(),
                    tag: "controlled-tls-script".to_string(),
                    argument: "Mode=controlled-tls".to_string(),
                }),
                audits: Vec::new(),
                diagnostics: Vec::new(),
            })
        }

        fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent> {
            plugin_result.audits.clone()
        }
    }

    fn test_ca_material() -> (String, String, Vec<u8>) {
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "NetworkCore controlled TLS test CA");
        distinguished_name.push(DnType::OrganizationName, "AnixOps NetworkCore");
        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key_pair = KeyPair::generate().expect("test CA key should generate");
        let certificate = params
            .self_signed(&key_pair)
            .expect("test CA certificate should self-sign");
        (
            certificate.pem(),
            key_pair.serialize_pem(),
            certificate.der().as_ref().to_vec(),
        )
    }

    fn issue_test_leaf(
        ca_certificate_pem: &str,
        ca_private_key_pem: &str,
        host: &str,
    ) -> (Vec<u8>, Vec<u8>) {
        let issuer_key =
            KeyPair::from_pem(ca_private_key_pem).expect("test CA private key should parse");
        let issuer = Issuer::from_ca_cert_pem(ca_certificate_pem, issuer_key)
            .expect("test CA certificate should parse");
        let mut params = CertificateParams::new(vec![host.to_string()])
            .expect("test leaf authority should encode");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key_pair = KeyPair::generate().expect("test leaf key should generate");
        let certificate = params
            .signed_by(&key_pair, &issuer)
            .expect("test leaf should sign");
        (
            certificate.der().as_ref().to_vec(),
            key_pair.serialize_der(),
        )
    }

    fn test_server_config(certificate_der: Vec<u8>, private_key_der: Vec<u8>) -> Arc<ServerConfig> {
        let mut config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .expect("test rustls provider should support TLS 1.2 and TLS 1.3")
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(certificate_der)],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key_der)),
                )
                .expect("test leaf key should match test leaf certificate");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    fn test_client_config(certificate_der: Vec<u8>) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(certificate_der))
            .expect("test CA should be a valid trust anchor");
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .expect("test rustls provider should support TLS 1.2 and TLS 1.3")
                .with_root_certificates(roots)
                .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }
}
