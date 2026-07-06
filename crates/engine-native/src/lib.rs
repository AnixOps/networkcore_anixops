//! Native proxy engine adapter contracts for NetworkCore.
//!
//! This crate intentionally exposes descriptor, validation, lifecycle
//! diagnostics, and source-level handle contracts until a real resource-backed
//! in-process runtime handle exists.

use control_domain::{
    Diagnostic, DiagnosticSeverity, DomainError, DomainResult, Endpoint, ListenerDescriptor,
    ListenerKind, ListenerNetwork, ListenerRoute, NodeDescriptor, Protocol, ProxyEngineConfig,
    ProxyEngineDescriptor, ProxyEngineEvent, ProxyEngineEventKind, ProxyEngineKind,
    ProxyEngineLifecycleState, ProxyEngineService, ProxyEngineStatus, RouteAction, RuleSet,
};
use std::collections::BTreeSet;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub const DEFAULT_NATIVE_ENGINE_ID: &str = "native";

pub const SOURCE_ENGINE_NATIVE_CONFIG: &str = "engine.native.config";
pub const SOURCE_ENGINE_NATIVE_LIFECYCLE: &str = "engine.native.lifecycle";
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
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_UNWIRED_CODE: &str =
    "engine.native.runtime.socks5_route_outbound_unwired";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITTEN_CODE: &str =
    "engine.native.runtime.socks5_connect_failure_response_written";
pub const ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITE_FAILED_CODE: &str =
    "engine.native.runtime.socks5_connect_failure_response_write_failed";

const SOCKS5_VERSION: u8 = 0x05;
const SOCKS5_AUTH_METHOD_NO_AUTHENTICATION_REQUIRED: u8 = 0x00;
const SOCKS5_AUTH_METHOD_NO_ACCEPTABLE_METHODS: u8 = 0xff;
const SOCKS5_COMMAND_CONNECT: u8 = 0x01;
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
    shutdown_tx: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<NativeLoopbackTcpAcceptLoopShutdownReport>>,
}

impl NativeLoopbackTcpAcceptLoopHandle {
    pub fn start(
        listener: BoundLoopbackTcpListenerHandle,
        outbound_handler: NativeOutboundHandlerHandle,
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
        let outbound_handler_id = outbound_handler.node_id;
        let accepted_connections = Arc::new(AtomicUsize::new(0));
        let accepted_connections_for_worker = Arc::clone(&accepted_connections);
        let pre_protocol_closed_connections = Arc::new(AtomicUsize::new(0));
        let pre_protocol_closed_connections_for_worker =
            Arc::clone(&pre_protocol_closed_connections);
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
                NativeLoopbackTcpAcceptLoopIdentity {
                    listener_id: worker_listener_id,
                    outbound_handler_id: worker_outbound_handler_id,
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
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Clone)]
struct NativeLoopbackTcpAcceptLoopIdentity {
    listener_id: String,
    outbound_handler_id: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeSocks5RouteOutboundDecision {
    Unwired,
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

#[derive(Debug, Clone, Copy, Default)]
pub struct NativeProxyEngineService;

impl NativeProxyEngineService {
    pub const fn new() -> Self {
        Self
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

        Err(domain_error(
            ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE,
            "native proxy runtime handle is not implemented yet",
        ))
    }

    fn reload(&self, engine_config: &ProxyEngineConfig) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(&engine_config.engine_id)?;

        Err(domain_error(
            ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE,
            "native proxy runtime handle is not implemented yet",
        ))
    }

    fn stop(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(engine_id)?;

        Ok(stopped_status(engine_id))
    }

    fn status(&self, engine_id: &str) -> DomainResult<ProxyEngineStatus> {
        ensure_native_engine_id(engine_id)?;

        Ok(stopped_status(engine_id))
    }

    fn events(&self, engine_id: &str) -> DomainResult<Vec<ProxyEngineEvent>> {
        ensure_native_engine_id(engine_id)?;

        Ok(Vec::new())
    }
}

fn stopped_status(engine_id: &str) -> ProxyEngineStatus {
    ProxyEngineStatus {
        engine_id: engine_id.to_string(),
        state: ProxyEngineLifecycleState::Stopped,
        diagnostics: Vec::new(),
    }
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
    matches!(kind, ListenerKind::LocalTcp | ListenerKind::Socks)
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

fn socks5_connect_target_read_failed(message: &'static str) -> NativeSocks5ConnectTargetReadReport {
    NativeSocks5ConnectTargetReadReport {
        target: None,
        diagnostics: vec![runtime_warning(
            ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_FAILED_CODE,
            message,
        )],
    }
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
    identity: NativeLoopbackTcpAcceptLoopIdentity,
) -> NativeLoopbackTcpAcceptLoopShutdownReport {
    let mut diagnostics = Vec::new();

    loop {
        match shutdown_rx.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
            Err(mpsc::TryRecvError::Empty) => {}
        }

        match listener.accept() {
            Ok((stream, _)) => {
                accepted_connections.fetch_add(1, Ordering::SeqCst);
                diagnostics.extend(read_socks5_greeting_and_close_accepted_connection(
                    stream,
                    &pre_protocol_closed_connections,
                ));
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
        diagnostics,
    }
}

fn read_socks5_greeting_and_close_accepted_connection(
    mut stream: TcpStream,
    pre_protocol_closed_connections: &AtomicUsize,
) -> Vec<Diagnostic> {
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
                        diagnostics
                            .extend(reject_unwired_socks5_route_outbound(target).diagnostics);
                        let failure_response_report =
                            write_unwired_socks5_connect_failure_response(&mut stream);
                        diagnostics.extend(failure_response_report.diagnostics);
                    }
                }
            }
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
    pre_protocol_closed_connections.fetch_add(1, Ordering::SeqCst);

    diagnostics.push(runtime_info(
        ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE,
        "native loopback tcp connection was closed before route and outbound handling",
    ));

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
