use control_domain::{
    AuditDecision, AuditEvent, ConfigSnapshot, Diagnostic, DiagnosticSeverity, DomainResult,
    Endpoint, GrantedPermissions, HookPoint, HttpBodyMutation, HttpEvent, HttpHeaderMutation,
    HttpHeaderMutationOperation, HttpMitmAction, HttpMitmEvent, HttpMitmOutcome, HttpMitmPhase,
    HttpMitmScriptDispatch, HttpMitmScriptKind, ListenerBind, ListenerDescriptor, ListenerKind,
    ListenerNetwork, ListenerRoute, MetadataEntry, MitmPluginService, NodeDescriptor,
    PluginInstance, PluginManifest, PluginPackage, PluginPermission, PluginResult, Protocol,
    ProxyEngineConfig, ProxyEngineEventKind, ProxyEngineKind, ProxyEngineLifecycleState,
    ProxyEngineService, RouteAction, RuleSet, SchemaVersion,
};
use engine_native::{
    apply_http_mitm_outcome_to_live_plain_http_request,
    apply_http_mitm_outcome_to_plain_http_message, assess_native_proxy_engine_start_readiness,
    assess_socks5_outbound_connect_client_success_response_readiness,
    assess_socks5_outbound_connect_relay_readiness, attempt_socks5_outbound_tcp_connection,
    browser_capture_proof_token_from_connect_authority,
    build_controlled_tls_termination_server_config, build_controlled_tls_upstream_client_config,
    build_socks5_outbound_connect_request_frame, decide_socks5_outbound_connect_response,
    issue_controlled_tls_termination_leaf_certificate,
    native_socks5_connect_browser_capture_proof_token,
    observe_explicit_http_connect_tls_client_hello, plan_and_apply_https_request_rewrite_preview,
    plan_and_apply_https_response_rewrite_preview, plan_and_apply_plain_http_mitm,
    plan_explicit_http_connect_controlled_tls_termination,
    plan_explicit_http_connect_tls_mitm_foundation, plan_socks5_connect_http_mitm,
    plan_socks5_outbound_connect_client_success_response_write,
    plan_socks5_outbound_connect_data_relay, plan_socks5_outbound_tcp_connection,
    read_explicit_http_proxy_request, read_https_connect_http_request, read_socks5_command_header,
    read_socks5_connect_target, read_socks5_greeting, read_socks5_outbound_connect_response,
    reject_unsupported_socks5_command, reject_unwired_socks5_route_outbound,
    relay_socks5_outbound_connect_data, select_socks5_auth_method,
    select_socks5_route_outbound_behavior, serialize_explicit_http_proxy_request_for_upstream,
    serialize_plain_http_proxy_response, write_http_connect_established_response,
    write_socks5_auth_method_response, write_socks5_outbound_connect_client_success_response,
    write_socks5_outbound_connect_request, write_unwired_socks5_connect_failure_response,
    BoundLoopbackTcpListenerHandle, LoopbackListenerHandle, NativeExplicitHttpProxyRequest,
    NativeHttpMitmPluginHook, NativeLoopbackTcpAcceptLoopHandle, NativeNodeScriptExecutor,
    NativeNodeScriptRuntimeConfig, NativeOutboundHandlerHandle, NativePlainHttpMessage,
    NativePlainHttpRewriteReport, NativeProxyEngineService, NativeProxyEngineStartReadiness,
    NativeRuntimeAssembly, NativeRuntimeAssemblyPlan, NativeSocks5Address,
    NativeSocks5AuthMethodDecision, NativeSocks5CommandDecision, NativeSocks5CommandHeader,
    NativeSocks5ConnectTarget, NativeSocks5Greeting,
    NativeSocks5OutboundConnectClientSuccessResponseReadiness,
    NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision,
    NativeSocks5OutboundConnectDataRelayPlanDecision, NativeSocks5OutboundConnectRelayReadiness,
    NativeSocks5OutboundConnectResponse, NativeSocks5OutboundConnectResponseDecision,
    NativeSocks5OutboundTcpConnectionPlan, NativeSocks5RouteOutboundBehavior,
    NativeSocks5RouteOutboundDecision, DEFAULT_NATIVE_ENGINE_ID,
    ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE,
    ENGINE_NATIVE_CONFIG_LISTENER_BIND_INVALID_CODE,
    ENGINE_NATIVE_CONFIG_LISTENER_ID_DUPLICATE_CODE,
    ENGINE_NATIVE_CONFIG_LISTENER_KIND_UNSUPPORTED_CODE,
    ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE, ENGINE_NATIVE_CONFIG_NODE_ID_DUPLICATE_CODE,
    ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE, ENGINE_NATIVE_CONFIG_NODE_PROTOCOL_UNSUPPORTED_CODE,
    ENGINE_NATIVE_CONFIG_ROUTE_EMPTY_CODE, ENGINE_NATIVE_CONFIG_ROUTE_ID_DUPLICATE_CODE,
    ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE, ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_READY_CODE,
    ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_STOPPED_CODE,
    ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE,
    ENGINE_NATIVE_RUNTIME_FOREGROUND_HANDOFF_READY_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_BROWSER_PROOF_OBSERVED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_EVENT_PLANNED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_NOT_APPLIED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_READY_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_APPLIED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_RESPONSE_WRITTEN_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_BODY_MUTATION_APPLIED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_EVENT_PLANNED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_HEADER_MUTATION_APPLIED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_PLAN_READY_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_SCRIPT_DISPATCH_DEFERRED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_TERMINAL_ACTION_APPLIED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_PREVIEW_READY_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_SCRIPT_DEFERRED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_PREVIEW_READY_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_SCRIPT_DEFERRED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CONNECT_TLS_BLOCKED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_READ_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REWRITE_APPLIED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITTEN_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CLIENT_HELLO_DEFERRED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CLIENT_HELLO_OBSERVED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_ESTABLISHED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_FOUNDATION_READY_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_DEFERRED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_ISSUED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SERVER_CONFIG_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SERVER_CONFIG_READY_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_READY_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SNI_AUTHORITY_MATCHED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SNI_AUTHORITY_MISMATCH_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_DEFERRED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_PLAN_READY_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_UPSTREAM_CONFIG_READY_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_DEFERRED_CODE,
    ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_EXECUTED_CODE, ENGINE_NATIVE_RUNTIME_LISTENER_DISABLED_CODE,
    ENGINE_NATIVE_RUNTIME_LISTENER_NON_LOOPBACK_CODE,
    ENGINE_NATIVE_RUNTIME_OUTBOUND_ENDPOINT_INVALID_CODE,
    ENGINE_NATIVE_RUNTIME_OUTBOUND_UNSUPPORTED_CODE, ENGINE_NATIVE_RUNTIME_RELEASED_CODE,
    ENGINE_NATIVE_RUNTIME_RESOURCE_MISSING_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_RESPONSE_WRITE_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_RESPONSE_WRITTEN_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_SELECTED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_UNSUPPORTED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_INVALID_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_READ_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_READ_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_UNSUPPORTED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITE_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITTEN_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_INVALID_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_INVALID_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_READY_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_REJECTED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_UNWIRED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_READY_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_REJECTED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_UNWIRED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITTEN_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_COMPLETED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_READY_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_REJECTED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_UNWIRED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_READY_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_REJECTED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_GENERATED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_INVALID_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITE_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_ACCEPTED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_INVALID_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_READ_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_READ_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_REJECTED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_SUCCEEDED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_PLANNED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_PLAN_INVALID_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_SELECTED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_UNWIRED_CODE, ENGINE_NATIVE_START_BIND_FAILED_CODE,
    ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE, ENGINE_NATIVE_START_RUNNING_CODE,
    ENGINE_NATIVE_START_RUNTIME_ASSEMBLY_READY_CODE, ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE,
    ENGINE_NATIVE_START_SERVICE_RUNTIME_OWNER_MISSING_CODE,
};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, ClientConnection, RootCertStore, ServerConnection,
};
use std::collections::BTreeMap;
use std::io::{self, Cursor, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

#[test]
fn lists_native_descriptor_without_unimplemented_capabilities() {
    let service = NativeProxyEngineService::new();

    let descriptors = service.list_engines();

    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0].id, DEFAULT_NATIVE_ENGINE_ID);
    assert_eq!(descriptors[0].kind, ProxyEngineKind::Native);
    assert!(descriptors[0].version.is_none());
    assert!(descriptors[0].capabilities.is_empty());
}

#[test]
fn validate_config_rejects_unsupported_engine_id_with_stable_diagnostic() {
    let service = NativeProxyEngineService::new();
    let engine_config = config("external", Vec::new());

    let diagnostics = service.validate_config(&engine_config);

    assert_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE,
    );
    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE);
    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE);
}

#[test]
fn validate_config_does_not_leak_metadata_secret_values() {
    let service = NativeProxyEngineService::new();
    let mut engine_config = config(DEFAULT_NATIVE_ENGINE_ID, Vec::new());
    engine_config.metadata.push(MetadataEntry {
        key: "token".to_string(),
        value: "super-secret-token".to_string(),
    });

    let diagnostics = service.validate_config(&engine_config);

    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE);
    assert!(diagnostics.iter().all(|diagnostic| {
        !diagnostic.message.contains("super-secret-token") && !diagnostic.message.contains("token")
    }));
}

#[test]
fn validate_config_uses_config_snapshot_nodes_for_route_targets() {
    let service = NativeProxyEngineService::new();
    let engine_config = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        vec![node()],
        Vec::new(),
        vec![listener(
            "loopback-socks",
            ListenerRoute::RuleSet {
                rule_set_id: "default-route".to_string(),
            },
        )],
        vec![route_set(
            "default-route",
            RouteAction::Proxy {
                node_id: "node-1".to_string(),
            },
        )],
    );

    let diagnostics = service.validate_config(&engine_config);

    assert_no_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE);
    assert_no_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE);
    assert_no_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE);
    assert_no_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_ROUTE_EMPTY_CODE);
    assert_no_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_LISTENER_KIND_UNSUPPORTED_CODE,
    );
    assert_no_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_NODE_PROTOCOL_UNSUPPORTED_CODE,
    );
}

#[test]
fn validate_config_uses_runtime_request_nodes_for_route_targets() {
    let service = NativeProxyEngineService::new();
    let engine_config = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        Vec::new(),
        vec![node()],
        vec![listener(
            "loopback-socks",
            ListenerRoute::DefaultAction(RouteAction::Proxy {
                node_id: "node-1".to_string(),
            }),
        )],
        Vec::new(),
    );

    let diagnostics = service.validate_config(&engine_config);

    assert_no_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE);
    assert_no_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE);
    assert_no_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_ROUTE_EMPTY_CODE);
    assert_no_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_LISTENER_KIND_UNSUPPORTED_CODE,
    );
    assert_no_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_NODE_PROTOCOL_UNSUPPORTED_CODE,
    );
}

#[test]
fn validate_config_accepts_http_listener_for_socks_outbound() {
    let service = NativeProxyEngineService::new();
    let engine_config = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        vec![node()],
        Vec::new(),
        vec![http_listener_with_bind(
            "http-loopback",
            "127.0.0.1",
            1080,
            ListenerRoute::DefaultAction(RouteAction::Proxy {
                node_id: "node-1".to_string(),
            }),
        )],
        Vec::new(),
    );

    let diagnostics = service.validate_config(&engine_config);

    assert_no_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_LISTENER_KIND_UNSUPPORTED_CODE,
    );
    assert_no_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_NODE_PROTOCOL_UNSUPPORTED_CODE,
    );
}

#[test]
fn validate_config_still_rejects_http_outbound_protocol() {
    let service = NativeProxyEngineService::new();
    let engine_config = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        vec![NodeDescriptor {
            protocol: Protocol::Http,
            ..node()
        }],
        Vec::new(),
        vec![ListenerDescriptor {
            kind: ListenerKind::Http,
            ..listener(
                "http-loopback",
                ListenerRoute::DefaultAction(RouteAction::Proxy {
                    node_id: "node-1".to_string(),
                }),
            )
        }],
        Vec::new(),
    );

    let diagnostics = service.validate_config(&engine_config);

    assert_no_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_LISTENER_KIND_UNSUPPORTED_CODE,
    );
    assert_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_NODE_PROTOCOL_UNSUPPORTED_CODE,
    );
}

#[test]
fn validate_config_reports_duplicate_graph_ids() {
    let service = NativeProxyEngineService::new();
    let engine_config = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        vec![node()],
        vec![node()],
        vec![
            listener(
                "loopback-socks",
                ListenerRoute::RuleSet {
                    rule_set_id: "default-route".to_string(),
                },
            ),
            listener(
                "loopback-socks",
                ListenerRoute::RuleSet {
                    rule_set_id: "fallback-route".to_string(),
                },
            ),
        ],
        vec![
            route_set("default-route", RouteAction::Direct),
            route_set("default-route", RouteAction::Reject),
        ],
    );

    let diagnostics = service.validate_config(&engine_config);

    assert_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_LISTENER_ID_DUPLICATE_CODE,
    );
    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_NODE_ID_DUPLICATE_CODE);
    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_ROUTE_ID_DUPLICATE_CODE);
}

#[test]
fn validate_config_reports_missing_route_and_node_targets() {
    let service = NativeProxyEngineService::new();
    let engine_config = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        Vec::new(),
        Vec::new(),
        vec![
            listener(
                "missing-route",
                ListenerRoute::RuleSet {
                    rule_set_id: "absent-route".to_string(),
                },
            ),
            listener(
                "missing-node",
                ListenerRoute::DefaultAction(RouteAction::Proxy {
                    node_id: "absent-node".to_string(),
                }),
            ),
        ],
        Vec::new(),
    );

    let diagnostics = service.validate_config(&engine_config);

    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_NODE_MISSING_CODE);
    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_ROUTE_TARGET_MISSING_CODE);
    assert_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_ROUTE_EMPTY_CODE);
}

#[test]
fn validate_config_reports_disabled_and_invalid_listener_boundaries() {
    let service = NativeProxyEngineService::new();
    let disabled_only = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        vec![node()],
        Vec::new(),
        vec![disabled_listener("disabled-loopback")],
        Vec::new(),
    );

    let disabled_diagnostics = service.validate_config(&disabled_only);

    assert_diagnostic(
        &disabled_diagnostics,
        ENGINE_NATIVE_CONFIG_LISTENER_MISSING_CODE,
    );

    let invalid_bind = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        vec![node()],
        Vec::new(),
        vec![listener_with_bind(
            "bad-bind",
            "",
            0,
            ListenerRoute::DefaultAction(RouteAction::Direct),
        )],
        Vec::new(),
    );

    let invalid_bind_diagnostics = service.validate_config(&invalid_bind);

    assert_diagnostic(
        &invalid_bind_diagnostics,
        ENGINE_NATIVE_CONFIG_LISTENER_BIND_INVALID_CODE,
    );
}

#[test]
fn start_readiness_allows_service_owned_runtime_lifecycle() {
    let port = unused_loopback_port();
    let service = NativeProxyEngineService::new();
    let engine_config = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        vec![node()],
        Vec::new(),
        vec![local_tcp_listener_with_bind(
            "service-start-loopback-local-tcp",
            "127.0.0.1",
            port,
            ListenerRoute::DefaultAction(RouteAction::Proxy {
                node_id: "node-1".to_string(),
            }),
        )],
        Vec::new(),
    );

    let readiness = assess_native_proxy_engine_start_readiness(&engine_config);

    assert_eq!(readiness.readiness, NativeProxyEngineStartReadiness::Ready);
    assert_diagnostic(
        &readiness.diagnostics,
        ENGINE_NATIVE_START_RUNTIME_ASSEMBLY_READY_CODE,
    );
    assert_no_diagnostic(
        &readiness.diagnostics,
        ENGINE_NATIVE_START_SERVICE_RUNTIME_OWNER_MISSING_CODE,
    );
    assert_no_diagnostic(
        &readiness.diagnostics,
        ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE,
    );

    let status = service
        .start(&engine_config)
        .expect("service start should own the native runtime");

    assert_eq!(status.state, ProxyEngineLifecycleState::Running);
    assert_diagnostic(&status.diagnostics, ENGINE_NATIVE_START_RUNNING_CODE);
    assert_diagnostic(
        &status.diagnostics,
        ENGINE_NATIVE_RUNTIME_FOREGROUND_HANDOFF_READY_CODE,
    );
    assert_diagnostic(
        &status.diagnostics,
        ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_READY_CODE,
    );

    let stopped = service
        .stop(DEFAULT_NATIVE_ENGINE_ID)
        .expect("service stop should release the native runtime");

    assert_eq!(stopped.state, ProxyEngineLifecycleState::Stopped);
    assert_diagnostic(
        &stopped.diagnostics,
        ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_STOPPED_CODE,
    );
}

#[test]
fn runtime_handle_contract_builds_foreground_handoff_status() {
    let listener = LoopbackListenerHandle::from_descriptor(&local_tcp_listener(
        "loopback-local-tcp",
        ListenerRoute::DefaultAction(RouteAction::Proxy {
            node_id: "node-1".to_string(),
        }),
    ))
    .expect("loopback tcp listener handle should be representable");
    let outbound = NativeOutboundHandlerHandle::from_node(&node())
        .expect("socks outbound handler handle should be representable");

    let handle = NativeRuntimeAssembly::new(DEFAULT_NATIVE_ENGINE_ID)
        .with_listener(listener)
        .with_outbound_handler(outbound)
        .finish()
        .expect("runtime handle contract should finish with required resources");

    assert_eq!(handle.listeners()[0].listener_id, "loopback-local-tcp");
    assert_eq!(handle.outbound_handlers()[0].node_id, "node-1");
    let handoff_status = handle.foreground_handoff_status();
    assert_eq!(handoff_status.state, ProxyEngineLifecycleState::Running);
    assert_diagnostic(
        &handoff_status.diagnostics,
        ENGINE_NATIVE_RUNTIME_FOREGROUND_HANDOFF_READY_CODE,
    );
    assert_eq!(handle.events()[0].kind, ProxyEngineEventKind::Started);
}

#[test]
fn runtime_handle_contract_binds_and_releases_loopback_tcp_listener() {
    let port = unused_loopback_port();
    let listener = LoopbackListenerHandle::from_descriptor(&local_tcp_listener_with_bind(
        "bound-loopback-local-tcp",
        "127.0.0.1",
        port,
        ListenerRoute::DefaultAction(RouteAction::Proxy {
            node_id: "node-1".to_string(),
        }),
    ))
    .expect("loopback tcp listener handle should be representable");
    let bound_listener = BoundLoopbackTcpListenerHandle::bind(listener)
        .expect("loopback tcp listener should bind on an available port");
    let outbound = NativeOutboundHandlerHandle::from_node(&node())
        .expect("socks outbound handler handle should be representable");

    assert_eq!(bound_listener.listener_id(), "bound-loopback-local-tcp");
    assert_eq!(bound_listener.bind_host(), "127.0.0.1");
    assert_eq!(bound_listener.bind_port(), port);
    assert_eq!(bound_listener.local_port(), port);

    let handle = NativeRuntimeAssembly::new(DEFAULT_NATIVE_ENGINE_ID)
        .with_bound_listener(bound_listener)
        .with_outbound_handler(outbound)
        .finish()
        .expect("runtime handle should own the bound loopback listener");

    assert!(handle.listeners().is_empty());
    assert_eq!(
        handle.bound_listeners()[0].listener_id(),
        "bound-loopback-local-tcp"
    );
    assert_eq!(handle.bound_listeners()[0].local_port(), port);

    let release = handle.release();

    assert_eq!(
        release.listener_ids,
        vec!["bound-loopback-local-tcp".to_string()]
    );
    assert_diagnostic(&release.diagnostics, ENGINE_NATIVE_RUNTIME_RELEASED_CODE);

    let rebound = TcpListener::bind(("127.0.0.1", port))
        .expect("released loopback tcp listener port should be reusable");
    drop(rebound);
}

#[test]
fn runtime_accept_loop_contract_accepts_loopback_tcp_connection_and_shuts_down() {
    let port = unused_loopback_port();
    let listener = LoopbackListenerHandle::from_descriptor(&local_tcp_listener_with_bind(
        "accept-loopback-local-tcp",
        "127.0.0.1",
        port,
        ListenerRoute::DefaultAction(RouteAction::Proxy {
            node_id: "node-1".to_string(),
        }),
    ))
    .expect("loopback tcp listener handle should be representable");
    let bound_listener = BoundLoopbackTcpListenerHandle::bind(listener)
        .expect("loopback tcp listener should bind on an available port");
    let mut outbound_node = node();
    outbound_node.endpoint.host = "outbound.example".to_string();
    let outbound = NativeOutboundHandlerHandle::from_node(&outbound_node)
        .expect("socks outbound handler handle should be representable");

    let accept_loop = NativeLoopbackTcpAcceptLoopHandle::start(bound_listener, outbound)
        .expect("loopback tcp accept loop should start from bound resources");

    assert_eq!(accept_loop.listener_id(), "accept-loopback-local-tcp");
    assert_eq!(accept_loop.outbound_handler_id(), "node-1");
    assert_eq!(accept_loop.local_host(), "127.0.0.1");
    assert_eq!(accept_loop.local_port(), port);

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .expect("loopback tcp accept loop should accept local connections");
    stream
        .write_all(&[
            0x05, 0x02, 0x00, 0x02, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb,
        ])
        .expect("test client should send a SOCKS5 greeting, CONNECT header, and target");
    wait_until_accept_count(&accept_loop, 1);
    wait_until_pre_protocol_closed_count(&accept_loop, 1);
    drop(stream);

    let report = accept_loop.shutdown();

    assert_eq!(report.listener_id, "accept-loopback-local-tcp");
    assert_eq!(report.outbound_handler_id, "node-1");
    assert_eq!(report.local_host, "127.0.0.1");
    assert_eq!(report.local_port, port);
    assert!(report.accepted_connections >= 1);
    assert!(report.pre_protocol_closed_connections >= 1);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_SELECTED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_RESPONSE_WRITTEN_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_READ_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_SELECTED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_GENERATED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_PLANNED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_FAILED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_UNWIRED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITTEN_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_STOPPED_CODE,
    );
}

#[test]
fn runtime_accept_loop_contract_writes_client_success_response_and_relays_finite_data() {
    let port = unused_loopback_port();
    let outbound_listener =
        TcpListener::bind(("127.0.0.1", 0)).expect("test outbound listener should bind");
    outbound_listener
        .set_nonblocking(true)
        .expect("test outbound listener should support nonblocking accept");
    let outbound_port = outbound_listener
        .local_addr()
        .expect("test outbound listener should have a local address")
        .port();
    let client_payload = b"client relay payload".to_vec();
    let outbound_payload = b"outbound relay payload".to_vec();
    let (frame_tx, frame_rx) = mpsc::channel();
    let (payload_tx, payload_rx) = mpsc::channel();
    let worker_client_payload = client_payload.clone();
    let worker_outbound_payload = outbound_payload.clone();
    let outbound_worker = thread::spawn(move || {
        for _ in 0..100 {
            match outbound_listener.accept() {
                Ok((mut outbound_stream, _)) => {
                    outbound_stream
                        .set_nonblocking(false)
                        .expect("captured outbound stream should use blocking reads");
                    outbound_stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .expect("captured outbound stream should accept a read timeout");
                    let mut request_frame = [0_u8; 10];
                    outbound_stream
                        .read_exact(&mut request_frame)
                        .expect("outbound stream should receive the SOCKS5 CONNECT request frame");
                    frame_tx
                        .send(request_frame.to_vec())
                        .expect("captured outbound frame should be reported to the test");
                    outbound_stream
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38])
                        .expect("outbound stream should send the SOCKS5 CONNECT response frame");
                    let mut relayed_payload = vec![0_u8; worker_client_payload.len()];
                    outbound_stream
                        .read_exact(&mut relayed_payload)
                        .expect("outbound stream should receive client relay payload");
                    payload_tx
                        .send(relayed_payload)
                        .expect("relayed client payload should be reported to the test");
                    outbound_stream
                        .write_all(&worker_outbound_payload)
                        .expect("outbound stream should send relay payload to client");
                    outbound_stream
                        .shutdown(Shutdown::Write)
                        .expect("outbound stream should close the relay write side");
                    return;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("test outbound listener failed while accepting: {error}"),
            }
        }

        panic!("test outbound listener did not receive a connection");
    });
    let listener = LoopbackListenerHandle::from_descriptor(&local_tcp_listener_with_bind(
        "outbound-write-accept-loopback-local-tcp",
        "127.0.0.1",
        port,
        ListenerRoute::DefaultAction(RouteAction::Proxy {
            node_id: "node-1".to_string(),
        }),
    ))
    .expect("loopback tcp listener handle should be representable");
    let bound_listener = BoundLoopbackTcpListenerHandle::bind(listener)
        .expect("loopback tcp listener should bind on an available port");
    let outbound = NativeOutboundHandlerHandle::from_node(&NodeDescriptor {
        endpoint: Endpoint {
            host: "127.0.0.1".to_string(),
            port: outbound_port,
        },
        ..node()
    })
    .expect("socks outbound handler handle should be representable");
    let accept_loop = NativeLoopbackTcpAcceptLoopHandle::start(bound_listener, outbound)
        .expect("loopback tcp accept loop should start from bound resources");

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .expect("loopback tcp accept loop should accept local connections");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("test client should support a read timeout");
    stream
        .write_all(&[
            0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb,
        ])
        .expect("test client should send a SOCKS5 greeting, CONNECT header, and IPv4 target");
    stream
        .write_all(&client_payload)
        .expect("test client should send finite relay payload");
    stream
        .shutdown(Shutdown::Write)
        .expect("test client should close the relay write side");
    wait_until_accept_count(&accept_loop, 1);
    wait_until_relayed_count(&accept_loop, 1);
    let mut client_received = Vec::new();
    stream
        .read_to_end(&mut client_received)
        .expect("test client should read the success response and outbound relay payload");
    let outbound_frame = frame_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("accept loop should write the outbound SOCKS5 CONNECT request frame");
    let relayed_payload = payload_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("accept loop should relay client payload to outbound");
    drop(stream);

    let report = accept_loop.shutdown();
    outbound_worker
        .join()
        .expect("outbound frame capture worker should finish");

    assert_eq!(
        outbound_frame,
        vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb]
    );
    assert_eq!(relayed_payload, client_payload);
    let mut expected_client_received =
        vec![0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38];
    expected_client_received.extend(outbound_payload);
    assert_eq!(client_received, expected_client_received);
    assert!(report.relayed_connections >= 1);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_SUCCEEDED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_READ_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_ACCEPTED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_READY_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_READY_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_READY_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_READY_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITTEN_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_COMPLETED_CODE,
    );
    assert_no_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE,
    );
    assert_no_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_UNWIRED_CODE,
    );
    assert_no_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITTEN_CODE,
    );
}

#[test]
fn runtime_accept_loop_contract_reports_unsupported_socks5_auth_methods_before_close() {
    let port = unused_loopback_port();
    let listener = LoopbackListenerHandle::from_descriptor(&local_tcp_listener_with_bind(
        "unsupported-auth-accept-loopback-local-tcp",
        "127.0.0.1",
        port,
        ListenerRoute::DefaultAction(RouteAction::Proxy {
            node_id: "node-1".to_string(),
        }),
    ))
    .expect("loopback tcp listener handle should be representable");
    let bound_listener = BoundLoopbackTcpListenerHandle::bind(listener)
        .expect("loopback tcp listener should bind on an available port");
    let outbound = NativeOutboundHandlerHandle::from_node(&node())
        .expect("socks outbound handler handle should be representable");

    let accept_loop = NativeLoopbackTcpAcceptLoopHandle::start(bound_listener, outbound)
        .expect("loopback tcp accept loop should start from bound resources");

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .expect("loopback tcp accept loop should accept local connections");
    stream
        .write_all(&[0x05, 0x01, 0x02])
        .expect("test client should send a SOCKS5 greeting without no-auth support");
    wait_until_accept_count(&accept_loop, 1);
    wait_until_pre_protocol_closed_count(&accept_loop, 1);
    drop(stream);

    let report = accept_loop.shutdown();

    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_UNSUPPORTED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_RESPONSE_WRITTEN_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE,
    );
}

#[test]
fn runtime_accept_loop_contract_reports_unsupported_socks5_command_before_close() {
    let port = unused_loopback_port();
    let listener = LoopbackListenerHandle::from_descriptor(&local_tcp_listener_with_bind(
        "unsupported-command-accept-loopback-local-tcp",
        "127.0.0.1",
        port,
        ListenerRoute::DefaultAction(RouteAction::Proxy {
            node_id: "node-1".to_string(),
        }),
    ))
    .expect("loopback tcp listener handle should be representable");
    let bound_listener = BoundLoopbackTcpListenerHandle::bind(listener)
        .expect("loopback tcp listener should bind on an available port");
    let outbound = NativeOutboundHandlerHandle::from_node(&node())
        .expect("socks outbound handler handle should be representable");

    let accept_loop = NativeLoopbackTcpAcceptLoopHandle::start(bound_listener, outbound)
        .expect("loopback tcp accept loop should start from bound resources");

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .expect("loopback tcp accept loop should accept local connections");
    stream
        .write_all(&[0x05, 0x01, 0x00, 0x05, 0x02, 0x00, 0x01])
        .expect("test client should send a SOCKS5 greeting and unsupported command header");
    wait_until_accept_count(&accept_loop, 1);
    wait_until_pre_protocol_closed_count(&accept_loop, 1);
    drop(stream);

    let report = accept_loop.shutdown();

    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_SELECTED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_RESPONSE_WRITTEN_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_READ_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_UNSUPPORTED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE,
    );
}

#[test]
fn socks5_greeting_contract_reads_version_and_auth_methods() {
    let mut reader = Cursor::new(vec![0x05, 0x02, 0x00, 0x02]);

    let report = read_socks5_greeting(&mut reader);

    let greeting = report
        .greeting
        .expect("valid SOCKS5 greeting should be parsed");
    assert_eq!(greeting.version, 0x05);
    assert_eq!(greeting.auth_methods, vec![0x00, 0x02]);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_CODE,
    );
}

#[test]
fn socks5_greeting_contract_reports_invalid_version_and_incomplete_methods() {
    let mut unsupported_version = Cursor::new(vec![0x04, 0x01, 0x00]);

    let unsupported_report = read_socks5_greeting(&mut unsupported_version);

    let unsupported_greeting = unsupported_report
        .greeting
        .expect("unsupported version should still report the observed version");
    assert_eq!(unsupported_greeting.version, 0x04);
    assert!(unsupported_greeting.auth_methods.is_empty());
    assert_diagnostic(
        &unsupported_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_INVALID_CODE,
    );

    let mut incomplete_methods = Cursor::new(vec![0x05, 0x02, 0x00]);

    let incomplete_report = read_socks5_greeting(&mut incomplete_methods);

    assert!(incomplete_report.greeting.is_none());
    assert_diagnostic(
        &incomplete_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_GREETING_READ_FAILED_CODE,
    );
}

#[test]
fn socks5_auth_method_contract_selects_no_auth_method() {
    let greeting = NativeSocks5Greeting {
        version: 0x05,
        auth_methods: vec![0x02, 0x00],
    };

    let report = select_socks5_auth_method(&greeting);

    assert_eq!(
        report.decision,
        NativeSocks5AuthMethodDecision::NoAuthenticationRequired
    );
    assert_eq!(report.decision.method_code(), 0x00);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_SELECTED_CODE,
    );
}

#[test]
fn socks5_auth_method_contract_rejects_unsupported_auth_methods() {
    let greeting = NativeSocks5Greeting {
        version: 0x05,
        auth_methods: vec![0x02, 0x80],
    };

    let report = select_socks5_auth_method(&greeting);

    assert_eq!(
        report.decision,
        NativeSocks5AuthMethodDecision::NoAcceptableMethods
    );
    assert_eq!(report.decision.method_code(), 0xff);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_UNSUPPORTED_CODE,
    );
}

#[test]
fn socks5_auth_method_response_contract_writes_selected_method_response() {
    let mut writer = Vec::new();

    let report = write_socks5_auth_method_response(
        &mut writer,
        NativeSocks5AuthMethodDecision::NoAuthenticationRequired,
    );

    assert_eq!(writer, vec![0x05, 0x00]);
    assert_eq!(report.response, [0x05, 0x00]);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_RESPONSE_WRITTEN_CODE,
    );
}

#[test]
fn socks5_auth_method_response_contract_reports_write_failure() {
    let mut writer = FailingWriter;

    let report = write_socks5_auth_method_response(
        &mut writer,
        NativeSocks5AuthMethodDecision::NoAcceptableMethods,
    );

    assert_eq!(report.response, [0x05, 0xff]);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_AUTH_METHOD_RESPONSE_WRITE_FAILED_CODE,
    );
}

#[test]
fn socks5_connect_failure_response_contract_writes_general_failure_for_unwired_route_outbound() {
    let mut writer = Vec::new();

    let report = write_unwired_socks5_connect_failure_response(&mut writer);

    assert_eq!(writer, vec![0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    assert_eq!(report.response, [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITTEN_CODE,
    );
}

#[test]
fn socks5_connect_failure_response_contract_reports_write_failure() {
    let mut writer = FailingWriter;

    let report = write_unwired_socks5_connect_failure_response(&mut writer);

    assert_eq!(report.response, [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_FAILURE_RESPONSE_WRITE_FAILED_CODE,
    );
}

#[test]
fn socks5_command_header_contract_reads_connect_header() {
    let mut reader = Cursor::new(vec![0x05, 0x01, 0x00, 0x03]);

    let report = read_socks5_command_header(&mut reader);

    let diagnostics = report.diagnostics;
    let command_header = report
        .command_header
        .expect("valid SOCKS5 command header should be parsed");
    assert_eq!(command_header.version, 0x05);
    assert_eq!(command_header.command, 0x01);
    assert_eq!(command_header.reserved, 0x00);
    assert_eq!(command_header.address_type, 0x03);
    assert_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_READ_CODE,
    );

    let support_report = reject_unsupported_socks5_command(&command_header);

    assert_eq!(
        support_report.decision,
        NativeSocks5CommandDecision::Connect
    );
    assert_no_diagnostic(
        &support_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_UNSUPPORTED_CODE,
    );
}

#[test]
fn socks5_command_header_contract_reports_invalid_and_incomplete_header() {
    let mut invalid_reserved = Cursor::new(vec![0x05, 0x01, 0x01, 0x01]);

    let invalid_report = read_socks5_command_header(&mut invalid_reserved);

    let invalid_diagnostics = invalid_report.diagnostics;
    let invalid_header = invalid_report
        .command_header
        .expect("invalid SOCKS5 command header should still report observed bytes");
    assert_eq!(invalid_header.reserved, 0x01);
    assert_diagnostic(
        &invalid_diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_INVALID_CODE,
    );

    let mut incomplete_header = Cursor::new(vec![0x05, 0x01, 0x00]);

    let incomplete_report = read_socks5_command_header(&mut incomplete_header);

    assert!(incomplete_report.command_header.is_none());
    assert_diagnostic(
        &incomplete_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_HEADER_READ_FAILED_CODE,
    );
}

#[test]
fn socks5_command_contract_rejects_unsupported_commands() {
    let command_header = NativeSocks5CommandHeader {
        version: 0x05,
        command: 0x02,
        reserved: 0x00,
        address_type: 0x01,
    };

    let report = reject_unsupported_socks5_command(&command_header);

    assert_eq!(
        report.decision,
        NativeSocks5CommandDecision::UnsupportedCommand
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_COMMAND_UNSUPPORTED_CODE,
    );
}

#[test]
fn socks5_connect_target_contract_reads_domain_target_and_rejects_unwired_route_outbound() {
    let command_header = NativeSocks5CommandHeader {
        version: 0x05,
        command: 0x01,
        reserved: 0x00,
        address_type: 0x03,
    };
    let mut reader = Cursor::new(vec![
        0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01, 0xbb,
    ]);

    let report = read_socks5_connect_target(&mut reader, &command_header);

    let diagnostics = report.diagnostics;
    let target = report
        .target
        .expect("valid SOCKS5 domain CONNECT target should be parsed");
    assert_eq!(
        target.address,
        NativeSocks5Address::DomainName("example.com".to_string())
    );
    assert_eq!(target.port, 443);
    assert_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_CODE,
    );

    let route_report = reject_unwired_socks5_route_outbound(&target);

    assert_eq!(
        route_report.decision,
        NativeSocks5RouteOutboundDecision::Unwired
    );
    assert_diagnostic(
        &route_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_UNWIRED_CODE,
    );
}

#[test]
fn socks5_connect_http_mitm_plan_contract_maps_connect_target_to_plugin_plan_without_applying() {
    let target = NativeSocks5ConnectTarget {
        address: NativeSocks5Address::DomainName("pubads.g.doubleclick.net".to_string()),
        port: 443,
    };
    let plugin_instance = PluginInstance {
        manifest: PluginManifest {
            id: "networkcore.adblock".to_string(),
            version: "0.1.0".to_string(),
            permissions: vec![
                PluginPermission::ReadRequest,
                PluginPermission::ModifyRequest,
            ],
            hooks: vec![HookPoint::Request],
        },
        loaded_source: None,
    };
    let plugin_service = RejectingMitmPluginService;

    let report =
        plan_socks5_connect_http_mitm("connect-req-1", &target, &plugin_instance, &plugin_service);

    assert_eq!(report.request_id, "connect-req-1");
    assert_eq!(report.target_host, "pubads.g.doubleclick.net");
    assert_eq!(report.target_port, 443);
    assert_eq!(report.url, "https://pubads.g.doubleclick.net/");
    assert_eq!(report.event.request_id, "connect-req-1");
    assert_eq!(report.event.method.as_deref(), Some("CONNECT"));
    assert_eq!(report.event.url, "https://pubads.g.doubleclick.net/");
    assert_eq!(
        report
            .event
            .headers
            .iter()
            .find(|header| header.key == "host")
            .map(|header| header.value.as_str()),
        Some("pubads.g.doubleclick.net:443")
    );
    assert_eq!(
        report
            .outcome
            .expect("plugin plan should be present")
            .action,
        HttpMitmAction::Reject { status_code: 403 }
    );
    assert!(!report.applied);
    assert_eq!(report.audits.len(), 1);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_EVENT_PLANNED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_READY_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_NOT_APPLIED_CODE,
    );
}

#[test]
fn plain_http_rewrite_application_applies_header_body_and_defers_script_dispatch() {
    let message = NativePlainHttpMessage {
        request_id: "plain-http-1".to_string(),
        url: "https://api.networkcore.example/v1".to_string(),
        method: Some("GET".to_string()),
        phase: HttpMitmPhase::Response,
        status_code: Some(200),
        headers: vec![
            MetadataEntry {
                key: "X-Replace".to_string(),
                value: "old".to_string(),
            },
            MetadataEntry {
                key: "X-Remove".to_string(),
                value: "yes".to_string(),
            },
        ],
        body: b"from=1".to_vec(),
    };
    let outcome = HttpMitmOutcome {
        action: HttpMitmAction::Continue,
        header_mutations: vec![
            HttpHeaderMutation {
                operation: HttpHeaderMutationOperation::Add,
                name: "X-Add".to_string(),
                value: Some("added".to_string()),
            },
            HttpHeaderMutation {
                operation: HttpHeaderMutationOperation::Replace,
                name: "x-replace".to_string(),
                value: Some("new".to_string()),
            },
            HttpHeaderMutation {
                operation: HttpHeaderMutationOperation::Delete,
                name: "x-remove".to_string(),
                value: None,
            },
            HttpHeaderMutation {
                operation: HttpHeaderMutationOperation::Set,
                name: "X-Set".to_string(),
                value: Some("set".to_string()),
            },
        ],
        body_mutation: Some(HttpBodyMutation {
            body: b"to=1".to_vec(),
            truncated: false,
        }),
        script_dispatch: Some(HttpMitmScriptDispatch {
            kind: HttpMitmScriptKind::Response,
            phase: HttpMitmPhase::Response,
            requires_body: true,
            timeout_ms: 4000,
            max_size: 2048,
            script_path: "https://scripts.example/networkcore-response.js".to_string(),
            tag: "networkcore.response".to_string(),
            argument: "Mode=rust".to_string(),
        }),
        audits: Vec::new(),
        diagnostics: Vec::new(),
    };

    let application = apply_http_mitm_outcome_to_plain_http_message(&message, &outcome);

    assert!(application.applied);
    assert_eq!(application.final_status_code, Some(200));
    assert_eq!(application.body, b"to=1".to_vec());
    assert_eq!(
        application
            .headers
            .iter()
            .find(|header| header.key == "X-Replace")
            .map(|header| header.value.as_str()),
        Some("new")
    );
    assert_eq!(
        application
            .headers
            .iter()
            .find(|header| header.key == "X-Add")
            .map(|header| header.value.as_str()),
        Some("added")
    );
    assert!(application
        .headers
        .iter()
        .all(|header| !header.key.eq_ignore_ascii_case("X-Remove")));
    assert_eq!(
        application
            .headers
            .iter()
            .find(|header| header.key == "X-Set")
            .map(|header| header.value.as_str()),
        Some("set")
    );
    assert!(application.script_dispatch_deferred);
    assert_diagnostic(
        &application.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_HEADER_MUTATION_APPLIED_CODE,
    );
    assert_diagnostic(
        &application.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_BODY_MUTATION_APPLIED_CODE,
    );
    assert_diagnostic(
        &application.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_SCRIPT_DISPATCH_DEFERRED_CODE,
    );
}

#[test]
fn node_script_executor_runs_explicit_local_asset_with_persistent_store() {
    let root = std::env::temp_dir().join(format!(
        "networkcore-node-script-runtime-contract-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("script runtime test directory should be created");
    let runner_path = format!(
        "{}/../../third_party/mitm_anixops/mitm_anixops/e2e/script_runtime/anixops_runner.js",
        env!("CARGO_MANIFEST_DIR")
    );
    let script_path = format!(
        "{}/../../third_party/mitm_anixops/mitm_anixops/tests/fixtures/runner_replay_script.js",
        env!("CARGO_MANIFEST_DIR")
    );
    let script_url = "https://scripts.networkcore.test/replay.js".to_string();
    let mut script_assets = BTreeMap::new();
    script_assets.insert(script_url.clone(), script_path);
    let executor = NativeNodeScriptExecutor::new(NativeNodeScriptRuntimeConfig {
        node_binary: "node".to_string(),
        runner_path,
        script_assets,
        persistent_store_path: Some(root.join("store.json").display().to_string()),
        max_timeout_ms: 5000,
        max_body_bytes: 4096,
    });
    let request_dispatch = HttpMitmScriptDispatch {
        kind: HttpMitmScriptKind::Request,
        phase: HttpMitmPhase::Request,
        requires_body: true,
        timeout_ms: 1000,
        max_size: 1024,
        script_path: script_url.clone(),
        tag: "runtime.request".to_string(),
        argument: "Mode=networkcore".to_string(),
    };
    let request = NativePlainHttpMessage {
        request_id: "node-runtime-request".to_string(),
        url: "https://api.networkcore.test/v1".to_string(),
        method: Some("POST".to_string()),
        phase: HttpMitmPhase::Request,
        status_code: None,
        headers: vec![MetadataEntry {
            key: "Content-Type".to_string(),
            value: "application/json".to_string(),
        }],
        body: b"{}".to_vec(),
    };

    let request_execution = executor.execute(&request_dispatch, &request);

    assert!(request_execution.executed);
    assert!(request_execution.applied);
    assert!(String::from_utf8(
        request_execution
            .body
            .expect("request script should return a body mutation")
    )
    .expect("request script body should remain UTF-8")
    .contains("requestRuntime"));
    assert_diagnostic(
        &request_execution.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_EXECUTED_CODE,
    );

    let response_dispatch = HttpMitmScriptDispatch {
        kind: HttpMitmScriptKind::Response,
        phase: HttpMitmPhase::Response,
        requires_body: true,
        timeout_ms: 1000,
        max_size: 1024,
        script_path: script_url,
        tag: "runtime.response".to_string(),
        argument: "Mode=networkcore".to_string(),
    };
    let response = NativePlainHttpMessage {
        request_id: "node-runtime-response".to_string(),
        url: "https://api.networkcore.test/v1".to_string(),
        method: Some("POST".to_string()),
        phase: HttpMitmPhase::Response,
        status_code: Some(200),
        headers: vec![MetadataEntry {
            key: "Content-Type".to_string(),
            value: "application/json".to_string(),
        }],
        body: b"{\"from\":\"upstream\"}".to_vec(),
    };

    let response_execution = executor.execute(&response_dispatch, &response);

    assert!(response_execution.executed);
    assert_eq!(response_execution.status_code, Some(202));
    assert!(String::from_utf8(
        response_execution
            .body
            .expect("response script should return a body mutation")
    )
    .expect("response script body should remain UTF-8")
    .contains("responseRuntime"));

    let unmapped = NativeNodeScriptExecutor::new(NativeNodeScriptRuntimeConfig {
        node_binary: "node".to_string(),
        runner_path: executor.config().runner_path.clone(),
        script_assets: BTreeMap::new(),
        persistent_store_path: None,
        max_timeout_ms: 1000,
        max_body_bytes: 1024,
    })
    .execute(&request_dispatch, &request);
    assert!(!unmapped.executed);
    assert_diagnostic(
        &unmapped.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_DEFERRED_CODE,
    );

    std::fs::remove_dir_all(&root).expect("script runtime test directory should be removed");
}

#[test]
fn native_http_mitm_hook_applies_locally_mapped_script_dispatch() {
    let root = std::env::temp_dir().join(format!(
        "networkcore-node-script-hook-contract-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("script hook test directory should be created");
    let runner_path = format!(
        "{}/../../third_party/mitm_anixops/mitm_anixops/e2e/script_runtime/anixops_runner.js",
        env!("CARGO_MANIFEST_DIR")
    );
    let script_path = format!(
        "{}/../../third_party/mitm_anixops/mitm_anixops/tests/fixtures/runner_replay_script.js",
        env!("CARGO_MANIFEST_DIR")
    );
    let script_url = "https://scripts.networkcore.test/hook-replay.js".to_string();
    let mut script_assets = BTreeMap::new();
    script_assets.insert(script_url.clone(), script_path);
    let hook = NativeHttpMitmPluginHook::new(
        plugin_instance("networkcore.script"),
        Arc::new(ScriptDispatchingMitmPluginService { script_url }),
    )
    .with_node_script_executor(NativeNodeScriptExecutor::new(
        NativeNodeScriptRuntimeConfig {
            node_binary: "node".to_string(),
            runner_path,
            script_assets,
            persistent_store_path: Some(root.join("store.json").display().to_string()),
            max_timeout_ms: 5000,
            max_body_bytes: 4096,
        },
    ));
    let message = NativePlainHttpMessage {
        request_id: "node-runtime-hook-request".to_string(),
        url: "https://api.networkcore.test/v1".to_string(),
        method: Some("POST".to_string()),
        phase: HttpMitmPhase::Request,
        status_code: None,
        headers: vec![MetadataEntry {
            key: "Content-Type".to_string(),
            value: "application/json".to_string(),
        }],
        body: b"{}".to_vec(),
    };

    let report = hook.plan_plain_http(&message);

    assert!(report.applied);
    assert!(report.script_dispatch_executed);
    assert!(!report.script_dispatch_deferred);
    assert!(String::from_utf8(report.body)
        .expect("script hook body should remain UTF-8")
        .contains("requestRuntime"));
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_SCRIPT_EXECUTED_CODE,
    );

    std::fs::remove_dir_all(&root).expect("script hook test directory should be removed");
}

#[test]
fn plain_http_rewrite_plan_applies_plugin_reject_to_terminal_response() {
    let plugin_instance = PluginInstance {
        manifest: PluginManifest {
            id: "networkcore.adblock".to_string(),
            version: "0.1.0".to_string(),
            permissions: vec![
                PluginPermission::ReadRequest,
                PluginPermission::ModifyRequest,
            ],
            hooks: vec![HookPoint::Request],
        },
        loaded_source: None,
    };
    let message = NativePlainHttpMessage {
        request_id: "plain-http-ad-1".to_string(),
        url: "https://pubads.g.doubleclick.net/pagead/id".to_string(),
        method: Some("GET".to_string()),
        phase: HttpMitmPhase::Request,
        status_code: None,
        headers: Vec::new(),
        body: Vec::new(),
    };

    let report = plan_and_apply_plain_http_mitm(
        &message,
        &plugin_instance,
        &PlainHttpRejectingMitmPluginService,
    );

    assert!(report.applied);
    assert_eq!(report.terminal_action.as_deref(), Some("reject"));
    assert_eq!(report.final_status_code, Some(403));
    assert_eq!(report.body, Vec::<u8>::new());
    assert_eq!(
        report
            .headers
            .iter()
            .find(|header| header.key == "Content-Length")
            .map(|header| header.value.as_str()),
        Some("0")
    );
    assert_eq!(
        report
            .outcome
            .expect("plain HTTP plugin plan should be present")
            .action,
        HttpMitmAction::Reject { status_code: 403 }
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_EVENT_PLANNED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_PLAN_READY_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_TERMINAL_ACTION_APPLIED_CODE,
    );
}

#[test]
fn plain_http_proxy_request_parser_maps_absolute_form_to_native_plain_http_message() {
    let mut request = Cursor::new(
        b"POST http://example.com:8080/api/path?x=1 HTTP/1.1\r\nHost: ignored.example\r\nContent-Length: 4\r\n\r\nbody"
            .to_vec(),
    );

    let report = read_explicit_http_proxy_request(&mut request);
    let parsed = report
        .request
        .expect("explicit HTTP proxy request should parse");

    assert_eq!(parsed.method, "POST");
    assert_eq!(parsed.target_url, "http://example.com:8080/api/path?x=1");
    assert_eq!(parsed.target_host, "example.com");
    assert_eq!(parsed.target_port, 8080);
    assert_eq!(parsed.origin_path, "/api/path?x=1");
    assert_eq!(parsed.version, "HTTP/1.1");
    assert_eq!(parsed.body, b"body".to_vec());
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_READ_CODE,
    );
}

#[test]
fn explicit_http_connect_tls_foundation_report_keeps_https_rewrite_deferred() {
    let mut request =
        Cursor::new(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec());

    let read_report = read_explicit_http_proxy_request(&mut request);
    let parsed = read_report
        .request
        .expect("explicit HTTP CONNECT request should parse");
    let foundation_report = plan_explicit_http_connect_tls_mitm_foundation(&parsed);

    assert_eq!(parsed.method, "CONNECT");
    assert_eq!(parsed.target_url, "https://example.com/");
    assert_eq!(parsed.target_host, "example.com");
    assert_eq!(parsed.target_port, 443);
    assert!(foundation_report.connect_tunnel_ready);
    assert!(foundation_report.upstream_tls_forwarding_ready);
    assert!(!foundation_report.downstream_tls_termination_ready);
    assert!(!foundation_report.https_request_rewrite_ready);
    assert!(!foundation_report.https_response_rewrite_ready);
    assert!(!foundation_report.script_dispatch_ready);
    assert_diagnostic(
        &foundation_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_FOUNDATION_READY_CODE,
    );
}

#[test]
fn explicit_http_connect_tls_client_hello_observation_extracts_sni_without_enabling_rewrite() {
    let mut request =
        Cursor::new(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec());

    let read_report = read_explicit_http_proxy_request(&mut request);
    let parsed = read_report
        .request
        .expect("explicit HTTP CONNECT request should parse");
    let observation_report = observe_explicit_http_connect_tls_client_hello(
        &parsed,
        &tls_client_hello_with_sni("Example.COM"),
    );

    assert!(observation_report.client_hello_observed);
    assert_eq!(
        observation_report.sni_hostname.as_deref(),
        Some("example.com")
    );
    assert_eq!(
        observation_report.tls_record_version.as_deref(),
        Some("TLS 1.2")
    );
    assert_eq!(
        observation_report.tls_handshake_version.as_deref(),
        Some("TLS 1.2")
    );
    assert!(!observation_report.downstream_tls_termination_ready);
    assert!(!observation_report.https_request_rewrite_ready);
    assert!(!observation_report.https_response_rewrite_ready);
    assert_diagnostic(
        &observation_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CLIENT_HELLO_OBSERVED_CODE,
    );
}

#[test]
fn explicit_http_connect_tls_termination_plan_keeps_rewrite_deferred() {
    let mut request =
        Cursor::new(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec());

    let read_report = read_explicit_http_proxy_request(&mut request);
    let parsed = read_report
        .request
        .expect("explicit HTTP CONNECT request should parse");
    let foundation_report = plan_explicit_http_connect_tls_mitm_foundation(&parsed);
    let observation_report = observe_explicit_http_connect_tls_client_hello(
        &parsed,
        &tls_client_hello_with_sni("Example.COM"),
    );

    let termination_plan = plan_explicit_http_connect_controlled_tls_termination(
        &parsed,
        &foundation_report,
        &observation_report,
        true,
        true,
    );

    assert!(termination_plan.connect_tunnel_ready);
    assert!(termination_plan.client_hello_observed);
    assert_eq!(
        termination_plan.sni_hostname.as_deref(),
        Some("example.com")
    );
    assert!(termination_plan.ca_certificate_pem_ready);
    assert!(termination_plan.ca_private_key_pem_ready);
    assert!(termination_plan.downstream_tls_termination_plan_ready);
    assert!(termination_plan.upstream_tls_forwarding_ready);
    assert!(!termination_plan.live_https_decryption_ready);
    assert!(!termination_plan.https_request_rewrite_ready);
    assert!(!termination_plan.https_response_rewrite_ready);
    assert!(!termination_plan.script_dispatch_ready);
    assert_diagnostic(
        &termination_plan.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SNI_AUTHORITY_MATCHED_CODE,
    );
    assert_diagnostic(
        &termination_plan.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_PLAN_READY_CODE,
    );
}

#[test]
fn controlled_tls_termination_issues_authority_bound_leaf_certificate() {
    let mut request =
        Cursor::new(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec());

    let parsed = read_explicit_http_proxy_request(&mut request)
        .request
        .expect("explicit HTTP CONNECT request should parse");
    let foundation_report = plan_explicit_http_connect_tls_mitm_foundation(&parsed);
    let observation_report = observe_explicit_http_connect_tls_client_hello(
        &parsed,
        &tls_client_hello_with_sni("example.com"),
    );
    let termination_plan = plan_explicit_http_connect_controlled_tls_termination(
        &parsed,
        &foundation_report,
        &observation_report,
        true,
        true,
    );
    let (ca_certificate_pem, ca_private_key_pem, _) = test_ca_pem_material();

    let issue_report = issue_controlled_tls_termination_leaf_certificate(
        &termination_plan,
        &ca_certificate_pem,
        &ca_private_key_pem,
    );

    assert!(issue_report.issued);
    assert_eq!(issue_report.authority, "example.com");
    let material = issue_report
        .material
        .as_ref()
        .expect("ready controlled TLS plan should issue leaf material");
    assert_eq!(material.authority, "example.com");
    assert!(material
        .certificate_pem
        .contains("-----BEGIN CERTIFICATE-----"));
    assert!(material
        .private_key_pem
        .contains("-----BEGIN PRIVATE KEY-----"));
    assert!(!format!("{material:?}").contains(&material.private_key_pem));
    assert_diagnostic(
        &issue_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_ISSUED_CODE,
    );
}

#[test]
fn controlled_tls_server_config_performs_authenticated_handshake_and_decrypts_request() {
    let mut request =
        Cursor::new(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec());

    let parsed = read_explicit_http_proxy_request(&mut request)
        .request
        .expect("explicit HTTP CONNECT request should parse");
    let foundation_report = plan_explicit_http_connect_tls_mitm_foundation(&parsed);
    let observation_report = observe_explicit_http_connect_tls_client_hello(
        &parsed,
        &tls_client_hello_with_sni("example.com"),
    );
    let termination_plan = plan_explicit_http_connect_controlled_tls_termination(
        &parsed,
        &foundation_report,
        &observation_report,
        true,
        true,
    );
    let (ca_certificate_pem, ca_private_key_pem, ca_certificate_der) = test_ca_pem_material();
    let issue_report = issue_controlled_tls_termination_leaf_certificate(
        &termination_plan,
        &ca_certificate_pem,
        &ca_private_key_pem,
    );
    let leaf_material = issue_report
        .material
        .as_ref()
        .expect("ready controlled TLS plan should issue leaf material");
    let server_config_report = build_controlled_tls_termination_server_config(leaf_material);

    assert!(server_config_report.server_config_ready);
    assert_eq!(server_config_report.authority, "example.com");
    assert_diagnostic(
        &server_config_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SERVER_CONFIG_READY_CODE,
    );

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_certificate_der))
        .expect("test CA should be a valid rustls trust anchor");
    let client_config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .expect("ring provider should support TLS 1.2 and TLS 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
    let server_name = ServerName::try_from("example.com")
        .expect("test server name should parse")
        .to_owned();
    let mut client = ClientConnection::new(Arc::new(client_config), server_name)
        .expect("client connection should initialize");
    let mut server = ServerConnection::new(
        server_config_report
            .server_config
            .expect("ready server configuration should be available"),
    )
    .expect("server connection should initialize");

    complete_tls_handshake(&mut client, &mut server);
    let expected_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    client
        .writer()
        .write_all(expected_request)
        .expect("client should accept plaintext request");
    let mut encrypted_request = Vec::new();
    client
        .write_tls(&mut encrypted_request)
        .expect("client should emit encrypted request bytes");
    server
        .read_tls(&mut Cursor::new(encrypted_request))
        .expect("server should receive encrypted request bytes");
    server
        .process_new_packets()
        .expect("server should decrypt the authenticated request");
    let mut plaintext_request = vec![0; expected_request.len()];
    server
        .reader()
        .read_exact(&mut plaintext_request)
        .expect("server should expose decrypted request bytes");
    assert_eq!(plaintext_request.as_slice(), expected_request);
}

#[test]
fn controlled_tls_server_config_refuses_empty_leaf_material() {
    let invalid_material = engine_native::NativeTlsLeafCertificateMaterial {
        authority: "example.com".to_string(),
        certificate_pem: String::new(),
        private_key_pem: String::new(),
        certificate_der: Vec::new(),
        private_key_der: Vec::new(),
    };

    let server_config_report = build_controlled_tls_termination_server_config(&invalid_material);

    assert!(!server_config_report.server_config_ready);
    assert!(server_config_report.server_config.is_none());
    assert_diagnostic(
        &server_config_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SERVER_CONFIG_FAILED_CODE,
    );
}

#[test]
fn controlled_tls_connect_request_rebinds_origin_form_to_connect_authority() {
    let mut connect_request =
        Cursor::new(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec());
    let connect_request = read_explicit_http_proxy_request(&mut connect_request)
        .request
        .expect("explicit HTTP CONNECT request should parse");
    let mut decrypted_request = Cursor::new(
        b"GET /catalog?source=direct HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
            .to_vec(),
    );

    let request_report = read_https_connect_http_request(&mut decrypted_request, &connect_request);
    let request = request_report
        .request
        .expect("decrypted origin-form request should bind to CONNECT authority");

    assert_eq!(request.target_host, "example.com");
    assert_eq!(request.target_port, 443);
    assert_eq!(
        request.target_url,
        "https://example.com/catalog?source=direct"
    );
    assert_diagnostic(
        &request_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SESSION_DECRYPTION_READY_CODE,
    );
}

#[test]
fn controlled_tls_connect_request_refuses_mismatched_decrypted_host_authority() {
    let mut connect_request =
        Cursor::new(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec());
    let connect_request = read_explicit_http_proxy_request(&mut connect_request)
        .request
        .expect("explicit HTTP CONNECT request should parse");
    let mut decrypted_request =
        Cursor::new(b"GET / HTTP/1.1\r\nHost: other.example\r\n\r\n".to_vec());

    let request_report = read_https_connect_http_request(&mut decrypted_request, &connect_request);

    assert!(request_report.request.is_none());
}

#[test]
fn controlled_tls_upstream_client_config_uses_web_pki_roots() {
    let client_config_report = build_controlled_tls_upstream_client_config();

    assert!(client_config_report.client_config_ready);
    assert!(client_config_report.client_config.is_some());
    assert_diagnostic(
        &client_config_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_UPSTREAM_CONFIG_READY_CODE,
    );
}

#[test]
fn controlled_tls_termination_leaf_certificate_refuses_invalid_or_mismatched_inputs() {
    let mut request =
        Cursor::new(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec());

    let parsed = read_explicit_http_proxy_request(&mut request)
        .request
        .expect("explicit HTTP CONNECT request should parse");
    let foundation_report = plan_explicit_http_connect_tls_mitm_foundation(&parsed);
    let matching_observation = observe_explicit_http_connect_tls_client_hello(
        &parsed,
        &tls_client_hello_with_sni("example.com"),
    );
    let ready_plan = plan_explicit_http_connect_controlled_tls_termination(
        &parsed,
        &foundation_report,
        &matching_observation,
        true,
        true,
    );

    let invalid_ca_report = issue_controlled_tls_termination_leaf_certificate(
        &ready_plan,
        "not a certificate",
        "not a private key",
    );
    assert!(!invalid_ca_report.issued);
    assert!(invalid_ca_report.material.is_none());
    assert_diagnostic(
        &invalid_ca_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_FAILED_CODE,
    );

    let mismatched_observation = observe_explicit_http_connect_tls_client_hello(
        &parsed,
        &tls_client_hello_with_sni("other.example"),
    );
    let mismatched_plan = plan_explicit_http_connect_controlled_tls_termination(
        &parsed,
        &foundation_report,
        &mismatched_observation,
        true,
        true,
    );
    let deferred_report = issue_controlled_tls_termination_leaf_certificate(
        &mismatched_plan,
        "not a certificate",
        "not a private key",
    );
    assert!(!deferred_report.issued);
    assert!(deferred_report.material.is_none());
    assert_diagnostic(
        &deferred_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_LEAF_CERTIFICATE_DEFERRED_CODE,
    );
}

#[test]
fn explicit_http_connect_tls_termination_plan_defers_when_sni_disagrees_with_authority() {
    let mut request =
        Cursor::new(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec());

    let read_report = read_explicit_http_proxy_request(&mut request);
    let parsed = read_report
        .request
        .expect("explicit HTTP CONNECT request should parse");
    let foundation_report = plan_explicit_http_connect_tls_mitm_foundation(&parsed);
    let observation_report = observe_explicit_http_connect_tls_client_hello(
        &parsed,
        &tls_client_hello_with_sni("other.example"),
    );

    let termination_plan = plan_explicit_http_connect_controlled_tls_termination(
        &parsed,
        &foundation_report,
        &observation_report,
        true,
        true,
    );

    assert!(termination_plan.connect_tunnel_ready);
    assert!(termination_plan.client_hello_observed);
    assert_eq!(
        termination_plan.sni_hostname.as_deref(),
        Some("other.example")
    );
    assert!(!termination_plan.downstream_tls_termination_plan_ready);
    assert!(!termination_plan.live_https_decryption_ready);
    assert_diagnostic(
        &termination_plan.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_SNI_AUTHORITY_MISMATCH_CODE,
    );
    assert_diagnostic(
        &termination_plan.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_DEFERRED_CODE,
    );
}

#[test]
fn explicit_http_connect_tls_termination_plan_defers_without_material_or_hello() {
    let mut request =
        Cursor::new(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec());

    let read_report = read_explicit_http_proxy_request(&mut request);
    let parsed = read_report
        .request
        .expect("explicit HTTP CONNECT request should parse");
    let foundation_report = plan_explicit_http_connect_tls_mitm_foundation(&parsed);
    let observation_report = observe_explicit_http_connect_tls_client_hello(&parsed, b"");

    let termination_plan = plan_explicit_http_connect_controlled_tls_termination(
        &parsed,
        &foundation_report,
        &observation_report,
        true,
        false,
    );

    assert!(termination_plan.connect_tunnel_ready);
    assert!(!termination_plan.client_hello_observed);
    assert_eq!(termination_plan.sni_hostname, None);
    assert!(termination_plan.ca_certificate_pem_ready);
    assert!(!termination_plan.ca_private_key_pem_ready);
    assert!(!termination_plan.downstream_tls_termination_plan_ready);
    assert!(termination_plan.upstream_tls_forwarding_ready);
    assert!(!termination_plan.live_https_decryption_ready);
    assert!(!termination_plan.https_request_rewrite_ready);
    assert!(!termination_plan.https_response_rewrite_ready);
    assert!(!termination_plan.script_dispatch_ready);
    assert_diagnostic(
        &termination_plan.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_TERMINATION_DEFERRED_CODE,
    );
}

#[test]
fn explicit_https_request_rewrite_preview_applies_headers_and_defers_body_and_script() {
    let mut request =
        Cursor::new(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec());

    let read_report = read_explicit_http_proxy_request(&mut request);
    let parsed = read_report
        .request
        .expect("explicit HTTP CONNECT request should parse");
    let foundation_report = plan_explicit_http_connect_tls_mitm_foundation(&parsed);
    let observation_report = observe_explicit_http_connect_tls_client_hello(
        &parsed,
        &tls_client_hello_with_sni("example.com"),
    );
    let termination_plan = plan_explicit_http_connect_controlled_tls_termination(
        &parsed,
        &foundation_report,
        &observation_report,
        true,
        true,
    );
    let message = NativePlainHttpMessage {
        request_id: "https-request-1".to_string(),
        url: "https://example.com/path".to_string(),
        method: Some("GET".to_string()),
        phase: HttpMitmPhase::Request,
        status_code: None,
        headers: vec![MetadataEntry {
            key: "X-Original".to_string(),
            value: "old".to_string(),
        }],
        body: b"request-body".to_vec(),
    };
    let outcome = HttpMitmOutcome {
        action: HttpMitmAction::Continue,
        header_mutations: vec![HttpHeaderMutation {
            operation: HttpHeaderMutationOperation::Set,
            name: "X-Request-Rewrite".to_string(),
            value: Some("ready".to_string()),
        }],
        body_mutation: Some(HttpBodyMutation {
            body: b"mutated-body".to_vec(),
            truncated: false,
        }),
        script_dispatch: Some(HttpMitmScriptDispatch {
            kind: HttpMitmScriptKind::Request,
            phase: HttpMitmPhase::Request,
            requires_body: true,
            timeout_ms: 4000,
            max_size: 2048,
            script_path: "https://scripts.example/request.js".to_string(),
            tag: "networkcore.request".to_string(),
            argument: "Mode=preview".to_string(),
        }),
        audits: Vec::new(),
        diagnostics: Vec::new(),
    };

    let preview =
        plan_and_apply_https_request_rewrite_preview(&termination_plan, &message, &outcome);

    assert!(preview.controlled_tls_termination_plan_ready);
    assert!(preview.https_request_rewrite_preview_ready);
    assert!(preview.applied);
    assert_eq!(preview.header_mutation_count, 1);
    assert_eq!(
        preview
            .headers
            .iter()
            .find(|header| header.key == "X-Request-Rewrite")
            .map(|header| header.value.as_str()),
        Some("ready")
    );
    assert_eq!(preview.body, b"request-body".to_vec());
    assert!(preview.body_mutation_deferred);
    assert!(!preview.https_response_rewrite_preview_ready);
    assert!(!preview.https_response_rewrite_ready);
    assert!(!preview.script_dispatch_ready);
    assert!(preview.script_dispatch_deferred);
    assert_diagnostic(
        &preview.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_PREVIEW_READY_CODE,
    );
    assert_diagnostic(
        &preview.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_REQUEST_REWRITE_SCRIPT_DEFERRED_CODE,
    );
}

#[test]
fn explicit_https_response_rewrite_preview_applies_headers_body_and_defers_script() {
    let mut request =
        Cursor::new(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".to_vec());

    let read_report = read_explicit_http_proxy_request(&mut request);
    let parsed = read_report
        .request
        .expect("explicit HTTP CONNECT request should parse");
    let foundation_report = plan_explicit_http_connect_tls_mitm_foundation(&parsed);
    let observation_report = observe_explicit_http_connect_tls_client_hello(
        &parsed,
        &tls_client_hello_with_sni("example.com"),
    );
    let termination_plan = plan_explicit_http_connect_controlled_tls_termination(
        &parsed,
        &foundation_report,
        &observation_report,
        true,
        true,
    );
    let message = NativePlainHttpMessage {
        request_id: "https-response-1".to_string(),
        url: "https://example.com/path".to_string(),
        method: Some("GET".to_string()),
        phase: HttpMitmPhase::Response,
        status_code: Some(200),
        headers: vec![
            MetadataEntry {
                key: "Content-Type".to_string(),
                value: "text/plain; charset=utf-8".to_string(),
            },
            MetadataEntry {
                key: "X-Original".to_string(),
                value: "old".to_string(),
            },
            MetadataEntry {
                key: "X-Remove".to_string(),
                value: "yes".to_string(),
            },
        ],
        body: b"response-body".to_vec(),
    };
    let outcome = HttpMitmOutcome {
        action: HttpMitmAction::Continue,
        header_mutations: vec![
            HttpHeaderMutation {
                operation: HttpHeaderMutationOperation::Set,
                name: "X-Response-Rewrite".to_string(),
                value: Some("ready".to_string()),
            },
            HttpHeaderMutation {
                operation: HttpHeaderMutationOperation::Delete,
                name: "X-Remove".to_string(),
                value: None,
            },
        ],
        body_mutation: Some(HttpBodyMutation {
            body: b"mutated-response".to_vec(),
            truncated: false,
        }),
        script_dispatch: Some(HttpMitmScriptDispatch {
            kind: HttpMitmScriptKind::Response,
            phase: HttpMitmPhase::Response,
            requires_body: true,
            timeout_ms: 4000,
            max_size: 2048,
            script_path: "https://scripts.example/response.js".to_string(),
            tag: "networkcore.response".to_string(),
            argument: "Mode=preview".to_string(),
        }),
        audits: Vec::new(),
        diagnostics: Vec::new(),
    };

    let preview =
        plan_and_apply_https_response_rewrite_preview(&termination_plan, &message, &outcome);

    assert!(preview.controlled_tls_termination_plan_ready);
    assert!(preview.https_response_rewrite_preview_ready);
    assert!(preview.applied);
    assert_eq!(preview.header_mutation_count, 2);
    assert_eq!(
        preview
            .headers
            .iter()
            .find(|header| header.key == "X-Response-Rewrite")
            .map(|header| header.value.as_str()),
        Some("ready")
    );
    assert!(preview
        .headers
        .iter()
        .all(|header| !header.key.eq_ignore_ascii_case("X-Remove")));
    assert_eq!(
        preview.content_type.as_deref(),
        Some("text/plain; charset=utf-8")
    );
    assert!(preview.content_type_guard_ready);
    assert_eq!(preview.body_size_bytes, b"response-body".len());
    assert!(preview.body_size_limit_bytes >= preview.body_size_bytes);
    assert!(preview.body_buffering_guard_ready);
    assert_eq!(preview.body, b"mutated-response".to_vec());
    assert!(preview.body_mutated);
    assert!(!preview.body_mutation_deferred);
    assert!(!preview.https_response_rewrite_ready);
    assert!(!preview.script_dispatch_ready);
    assert!(preview.script_dispatch_deferred);
    assert_diagnostic(
        &preview.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_PREVIEW_READY_CODE,
    );
    assert_diagnostic(
        &preview.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_HTTPS_RESPONSE_REWRITE_SCRIPT_DEFERRED_CODE,
    );
}

#[test]
fn write_http_connect_established_response_writes_empty_tunnel_response() {
    let mut response = Vec::new();

    let report = write_http_connect_established_response(&mut response, "HTTP/1.1");

    assert_eq!(
        String::from_utf8(response).expect("CONNECT response should be UTF-8"),
        "HTTP/1.1 200 Connection Established\r\nProxy-Agent: NetworkCore\r\n\r\n"
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_ESTABLISHED_CODE,
    );
}

#[test]
fn plain_http_proxy_request_rewrite_serializes_origin_form_for_upstream() {
    let request = NativeExplicitHttpProxyRequest {
        request_id: "native-http-proxy:POST:http://example.com/upload".to_string(),
        method: "POST".to_string(),
        target_url: "http://example.com/upload".to_string(),
        target_host: "example.com".to_string(),
        target_port: 80,
        origin_path: "/upload".to_string(),
        version: "HTTP/1.1".to_string(),
        headers: vec![
            MetadataEntry {
                key: "Host".to_string(),
                value: "example.com".to_string(),
            },
            MetadataEntry {
                key: "Content-Length".to_string(),
                value: "3".to_string(),
            },
        ],
        body: b"old".to_vec(),
    };
    let outcome = HttpMitmOutcome {
        action: HttpMitmAction::Continue,
        header_mutations: vec![HttpHeaderMutation {
            operation: HttpHeaderMutationOperation::Set,
            name: "X-NetworkCore-Rewritten".to_string(),
            value: Some("request".to_string()),
        }],
        body_mutation: Some(HttpBodyMutation {
            body: b"new".to_vec(),
            truncated: false,
        }),
        script_dispatch: None,
        audits: Vec::new(),
        diagnostics: Vec::new(),
    };

    let application = apply_http_mitm_outcome_to_live_plain_http_request(&request, &outcome);
    let rewrite_report = NativePlainHttpRewriteReport {
        request_id: request.request_id.clone(),
        url: request.target_url.clone(),
        event: HttpMitmEvent {
            request_id: request.request_id.clone(),
            url: request.target_url.clone(),
            method: Some(request.method.clone()),
            phase: HttpMitmPhase::Request,
            status_code: None,
            headers: request.headers.clone(),
            body: request.body.clone(),
        },
        outcome: Some(outcome),
        applied: application.applied,
        terminal_action: application.terminal_action,
        final_status_code: application.final_status_code,
        redirect_location: application.redirect_location,
        headers: application.headers,
        body: application.body,
        script_dispatch_deferred: application.script_dispatch_deferred,
        script_dispatch_executed: false,
        audits: Vec::new(),
        diagnostics: application.diagnostics,
    };

    let upstream = String::from_utf8(serialize_explicit_http_proxy_request_for_upstream(
        &request,
        &rewrite_report,
    ))
    .expect("upstream request should remain valid UTF-8");

    assert!(upstream.starts_with("POST /upload HTTP/1.1\r\n"));
    assert!(upstream.contains("Host: example.com\r\n"));
    assert!(upstream.contains("Connection: close\r\n"));
    assert!(upstream.contains("Content-Length: 3\r\n"));
    assert!(upstream.contains("X-NetworkCore-Rewritten: request\r\n"));
    assert!(upstream.ends_with("\r\n\r\nnew"));
    assert_diagnostic(
        &rewrite_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_HEADER_MUTATION_APPLIED_CODE,
    );
    assert_diagnostic(
        &rewrite_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_BODY_MUTATION_APPLIED_CODE,
    );
}

#[test]
fn plain_http_proxy_response_header_and_body_rewrite_returns_modified_response() {
    let rewrite_report = NativePlainHttpRewriteReport {
        request_id: "native-http-proxy:GET:http://origin.example/response:response".to_string(),
        url: "http://origin.example/response".to_string(),
        event: HttpMitmEvent {
            request_id: "native-http-proxy:GET:http://origin.example/response:response".to_string(),
            url: "http://origin.example/response".to_string(),
            method: Some("GET".to_string()),
            phase: HttpMitmPhase::Response,
            status_code: Some(200),
            headers: vec![MetadataEntry {
                key: "Content-Length".to_string(),
                value: "3".to_string(),
            }],
            body: b"old".to_vec(),
        },
        outcome: None,
        applied: true,
        terminal_action: None,
        final_status_code: Some(200),
        redirect_location: None,
        headers: vec![MetadataEntry {
            key: "X-NetworkCore-Rewritten".to_string(),
            value: "response".to_string(),
        }],
        body: b"response-new".to_vec(),
        script_dispatch_deferred: false,
        script_dispatch_executed: false,
        audits: Vec::new(),
        diagnostics: Vec::new(),
    };

    let response = String::from_utf8(serialize_plain_http_proxy_response(
        "HTTP/1.1",
        &rewrite_report,
    ))
    .expect("serialized response should be valid UTF-8");

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("X-NetworkCore-Rewritten: response\r\n"));
    assert!(response.contains("Connection: close\r\n"));
    assert!(response.contains("Content-Length: 12\r\n"));
    assert!(response.ends_with("\r\n\r\nresponse-new"));
}

#[test]
fn socks5_connect_browser_capture_proof_token_uses_connect_authority_and_proxy_url() {
    let target = NativeSocks5ConnectTarget {
        address: NativeSocks5Address::DomainName("example.com".to_string()),
        port: 443,
    };

    let token =
        native_socks5_connect_browser_capture_proof_token(&target, "socks5", "127.0.0.1", 7890);

    assert!(token.starts_with("networkcore-browser-proof-"));
    assert_eq!(
        token,
        browser_capture_proof_token_from_connect_authority(
            "example.com:443",
            "socks5://127.0.0.1:7890"
        )
    );
}

#[test]
fn runtime_accept_loop_contract_applies_mitm_connect_reject_before_outbound() {
    let port = unused_loopback_port();
    let listener = LoopbackListenerHandle::from_descriptor(&local_tcp_listener_with_bind(
        "mitm-reject-accept-loopback-local-tcp",
        "127.0.0.1",
        port,
        ListenerRoute::DefaultAction(RouteAction::Proxy {
            node_id: "node-1".to_string(),
        }),
    ))
    .expect("loopback tcp listener handle should be representable");
    let bound_listener = BoundLoopbackTcpListenerHandle::bind(listener)
        .expect("loopback tcp listener should bind on an available port");
    let outbound = NativeOutboundHandlerHandle::from_node(&NodeDescriptor {
        endpoint: Endpoint {
            host: "127.0.0.1".to_string(),
            port: unused_loopback_port(),
        },
        ..node()
    })
    .expect("socks outbound handler handle should be representable");
    let plugin_instance = PluginInstance {
        manifest: PluginManifest {
            id: "networkcore.adblock".to_string(),
            version: "0.1.0".to_string(),
            permissions: vec![
                PluginPermission::ReadRequest,
                PluginPermission::ModifyRequest,
            ],
            hooks: vec![HookPoint::Request],
        },
        loaded_source: None,
    };
    let http_mitm_hook =
        NativeHttpMitmPluginHook::new(plugin_instance, Arc::new(RejectingMitmPluginService));

    let accept_loop = NativeLoopbackTcpAcceptLoopHandle::start_with_http_mitm_hook(
        bound_listener,
        outbound,
        Some(http_mitm_hook),
    )
    .expect("loopback tcp accept loop should start with a MITM plugin hook");

    let mut request = vec![0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03];
    request.push("pubads.g.doubleclick.net".len() as u8);
    request.extend_from_slice(b"pubads.g.doubleclick.net");
    request.extend_from_slice(&[0x01, 0xbb]);

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .expect("loopback tcp accept loop should accept local connections");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("test client should support a read timeout");
    stream
        .write_all(&request)
        .expect("test client should send a SOCKS5 CONNECT request to an ad domain");

    let mut method_response = [0_u8; 2];
    stream
        .read_exact(&mut method_response)
        .expect("test client should read the SOCKS5 no-auth method response");
    let mut failure_response = [0_u8; 10];
    stream
        .read_exact(&mut failure_response)
        .expect("test client should read the MITM reject SOCKS5 failure response");
    wait_until_accept_count(&accept_loop, 1);
    wait_until_pre_protocol_closed_count(&accept_loop, 1);
    drop(stream);

    let report = accept_loop.shutdown();

    assert_eq!(method_response, [0x05, 0x00]);
    assert_eq!(failure_response, [0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_EVENT_PLANNED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_READY_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_PLAN_NOT_APPLIED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_BROWSER_PROOF_OBSERVED_CODE,
    );
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_BROWSER_PROOF_OBSERVED_CODE
            && diagnostic.message.contains("networkcore-browser-proof-")
            && diagnostic.message.contains("pubads.g.doubleclick.net:443")
    }));
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_APPLIED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_CONNECT_REJECT_RESPONSE_WRITTEN_CODE,
    );
    assert_no_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_SELECTED_CODE,
    );
    assert_no_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_PLANNED_CODE,
    );
    assert_no_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_UNWIRED_CODE,
    );
}

#[test]
fn runtime_accept_loop_contract_applies_plain_http_reject_for_http_listener() {
    let port = unused_loopback_port();
    let listener = LoopbackListenerHandle::from_descriptor(&http_listener_with_bind(
        "mitm-plain-http-reject-loopback",
        "127.0.0.1",
        port,
        ListenerRoute::DefaultAction(RouteAction::Proxy {
            node_id: "node-1".to_string(),
        }),
    ))
    .expect("HTTP loopback listener handle should be representable");
    let bound_listener = BoundLoopbackTcpListenerHandle::bind(listener)
        .expect("HTTP loopback listener should bind on an available port");
    let outbound = NativeOutboundHandlerHandle::from_node(&NodeDescriptor {
        endpoint: Endpoint {
            host: "127.0.0.1".to_string(),
            port: unused_loopback_port(),
        },
        ..node()
    })
    .expect("socks outbound handler handle should be representable");
    let http_mitm_hook = NativeHttpMitmPluginHook::new(
        plugin_instance("networkcore.adblock"),
        Arc::new(PlainHttpProxyRejectingMitmPluginService),
    );
    let accept_loop = NativeLoopbackTcpAcceptLoopHandle::start_with_http_mitm_hook(
        bound_listener,
        outbound,
        Some(http_mitm_hook),
    )
    .expect("HTTP loopback accept loop should start with a MITM plugin hook");

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .expect("HTTP loopback accept loop should accept local connections");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("test client should support a read timeout");
    stream
        .write_all(
            b"GET http://pubads.g.doubleclick.net/pagead/id HTTP/1.1\r\nHost: pubads.g.doubleclick.net\r\n\r\n",
        )
        .expect("test client should send an explicit HTTP proxy request");
    stream
        .shutdown(Shutdown::Write)
        .expect("test client should close the request write side");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("test client should read the HTTP reject response");
    wait_until_accept_count(&accept_loop, 1);
    wait_until_relayed_count(&accept_loop, 1);
    drop(stream);

    let report = accept_loop.shutdown();
    let response_text =
        String::from_utf8(response).expect("HTTP reject response should be valid UTF-8");

    assert!(response_text.starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert!(response_text.contains("Content-Length: 0\r\n"));
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_READ_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_TERMINAL_ACTION_APPLIED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REWRITE_APPLIED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
    );
    assert_no_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_FAILED_CODE,
    );
    assert_no_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE,
    );
}

#[test]
fn http_accept_loop_processes_a_second_connection_while_the_first_is_stalled() {
    let port = unused_loopback_port();
    let listener = LoopbackListenerHandle::from_descriptor(&http_listener_with_bind(
        "mitm-concurrent-http-loopback",
        "127.0.0.1",
        port,
        ListenerRoute::DefaultAction(RouteAction::Proxy {
            node_id: "node-1".to_string(),
        }),
    ))
    .expect("HTTP loopback listener handle should be representable");
    let bound_listener = BoundLoopbackTcpListenerHandle::bind(listener)
        .expect("HTTP loopback listener should bind on an available port");
    let outbound = NativeOutboundHandlerHandle::from_node(&NodeDescriptor {
        endpoint: Endpoint {
            host: "127.0.0.1".to_string(),
            port: unused_loopback_port(),
        },
        ..node()
    })
    .expect("socks outbound handler handle should be representable");
    let http_mitm_hook = NativeHttpMitmPluginHook::new(
        plugin_instance("networkcore.adblock"),
        Arc::new(PlainHttpProxyRejectingMitmPluginService),
    );
    let accept_loop = NativeLoopbackTcpAcceptLoopHandle::start_with_http_mitm_hook(
        bound_listener,
        outbound,
        Some(http_mitm_hook),
    )
    .expect("HTTP loopback accept loop should start with a MITM plugin hook");

    let (stalled_started_tx, stalled_started_rx) = mpsc::channel();
    let stalled_client = thread::spawn(move || {
        let mut stream = TcpStream::connect(("127.0.0.1", port))
            .expect("stalled client should connect to HTTP loopback listener");
        stream
            .set_nodelay(true)
            .expect("stalled client should disable Nagle buffering");
        stream
            .write_all(b"GET x")
            .expect("stalled client should begin an incomplete HTTP request");
        stalled_started_tx
            .send(())
            .expect("stalled client start should be reported");
        for _ in 0..100 {
            stream
                .write_all(b"x")
                .expect("stalled client should keep the first request incomplete");
            thread::sleep(Duration::from_millis(20));
        }
        let _ = stream.shutdown(Shutdown::Both);
    });
    stalled_started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("stalled client should begin first connection");
    wait_until_accept_count(&accept_loop, 1);

    let mut second_stream = TcpStream::connect(("127.0.0.1", port))
        .expect("second client should connect while the first request is stalled");
    second_stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("second client should support a bounded read timeout");
    second_stream
        .write_all(
            b"GET http://pubads.g.doubleclick.net/pagead/id HTTP/1.1\r\nHost: pubads.g.doubleclick.net\r\n\r\n",
        )
        .expect("second client should send a rejectable HTTP request");
    second_stream
        .shutdown(Shutdown::Write)
        .expect("second client should close its request write side");
    let mut response = Vec::new();
    second_stream
        .read_to_end(&mut response)
        .expect("second client should receive a response before the stalled request completes");
    drop(second_stream);

    stalled_client
        .join()
        .expect("stalled client worker should finish");
    wait_until_accept_count(&accept_loop, 2);
    let report = accept_loop.shutdown();

    assert!(String::from_utf8(response)
        .expect("second client response should be UTF-8")
        .starts_with("HTTP/1.1 403 Forbidden\r\n"));
    assert_eq!(report.accepted_connections, 2);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
    );
}

#[test]
fn plain_http_proxy_request_header_and_body_rewrite_forwards_via_socks_outbound() {
    let outbound_listener =
        TcpListener::bind(("127.0.0.1", 0)).expect("test outbound listener should bind");
    outbound_listener
        .set_nonblocking(true)
        .expect("test outbound listener should support nonblocking accept");
    let outbound_port = outbound_listener
        .local_addr()
        .expect("test outbound listener should have a local address")
        .port();
    let (frame_tx, frame_rx) = mpsc::channel();
    let (request_tx, request_rx) = mpsc::channel();
    let outbound_worker = thread::spawn(move || {
        for _ in 0..100 {
            match outbound_listener.accept() {
                Ok((mut outbound_stream, _)) => {
                    outbound_stream
                        .set_nonblocking(false)
                        .expect("captured outbound stream should use blocking reads");
                    outbound_stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .expect("captured outbound stream should accept a read timeout");
                    let request_frame = read_test_socks5_connect_frame(&mut outbound_stream);
                    frame_tx
                        .send(request_frame)
                        .expect("captured outbound frame should be reported to the test");
                    outbound_stream
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38])
                        .expect("outbound stream should send the SOCKS5 CONNECT response frame");
                    let upstream_request = read_test_http_message(&mut outbound_stream);
                    request_tx
                        .send(upstream_request)
                        .expect("captured upstream request should be reported to the test");
                    outbound_stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nold",
                        )
                        .expect("outbound stream should send a finite HTTP response");
                    outbound_stream
                        .shutdown(Shutdown::Write)
                        .expect("outbound stream should close the response write side");
                    return;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("test outbound listener failed while accepting: {error}"),
            }
        }

        panic!("test outbound listener did not receive a connection");
    });
    let port = unused_loopback_port();
    let listener = LoopbackListenerHandle::from_descriptor(&http_listener_with_bind(
        "mitm-plain-http-rewrite-loopback",
        "127.0.0.1",
        port,
        ListenerRoute::DefaultAction(RouteAction::Proxy {
            node_id: "node-1".to_string(),
        }),
    ))
    .expect("HTTP loopback listener handle should be representable");
    let bound_listener = BoundLoopbackTcpListenerHandle::bind(listener)
        .expect("HTTP loopback listener should bind on an available port");
    let outbound = NativeOutboundHandlerHandle::from_node(&NodeDescriptor {
        endpoint: Endpoint {
            host: "127.0.0.1".to_string(),
            port: outbound_port,
        },
        ..node()
    })
    .expect("socks outbound handler handle should be representable");
    let http_mitm_hook = NativeHttpMitmPluginHook::new(
        plugin_instance("networkcore.rewrite"),
        Arc::new(PlainHttpProxyRewriteMitmPluginService),
    );
    let accept_loop = NativeLoopbackTcpAcceptLoopHandle::start_with_http_mitm_hook(
        bound_listener,
        outbound,
        Some(http_mitm_hook),
    )
    .expect("HTTP loopback accept loop should start with a MITM plugin hook");

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .expect("HTTP loopback accept loop should accept local connections");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("test client should support a read timeout");
    stream
        .write_all(
            b"POST http://origin.example/upload HTTP/1.1\r\nHost: origin.example\r\nContent-Length: 3\r\n\r\nold",
        )
        .expect("test client should send an explicit HTTP proxy request");
    stream
        .shutdown(Shutdown::Write)
        .expect("test client should close the request write side");
    let mut client_response = Vec::new();
    stream
        .read_to_end(&mut client_response)
        .expect("test client should read the rewritten HTTP response");
    wait_until_accept_count(&accept_loop, 1);
    wait_until_relayed_count(&accept_loop, 1);
    drop(stream);

    let outbound_frame = frame_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("accept loop should write the outbound SOCKS5 CONNECT frame");
    let upstream_request = request_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("outbound should receive the rewritten HTTP request");
    let report = accept_loop.shutdown();
    outbound_worker
        .join()
        .expect("outbound frame capture worker should finish");
    let response_text =
        String::from_utf8(client_response).expect("client response should be valid UTF-8");

    let mut expected_frame = vec![0x05, 0x01, 0x00, 0x03, "origin.example".len() as u8];
    expected_frame.extend_from_slice(b"origin.example");
    expected_frame.extend_from_slice(&[0x00, 0x50]);
    assert_eq!(outbound_frame, expected_frame);
    assert!(upstream_request.starts_with("POST /upload HTTP/1.1\r\n"));
    assert!(upstream_request.contains("Host: origin.example\r\n"));
    assert!(upstream_request.contains("X-NetworkCore-Rewritten: request\r\n"));
    assert!(upstream_request.contains("Content-Length: 3\r\n"));
    assert!(upstream_request.ends_with("\r\n\r\nnew"));
    assert!(response_text.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response_text.contains("X-NetworkCore-Rewritten: response\r\n"));
    assert!(response_text.contains("Content-Length: 12\r\n"));
    assert!(response_text.ends_with("\r\n\r\nresponse-new"));
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REQUEST_READ_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_REQUEST_WRITTEN_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_UPSTREAM_RESPONSE_READ_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CLIENT_RESPONSE_WRITTEN_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_HEADER_MUTATION_APPLIED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_MITM_PLAIN_BODY_MUTATION_APPLIED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_REWRITE_APPLIED_CODE,
    );
    assert_no_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE,
    );
}

#[test]
fn plain_http_proxy_connect_method_establishes_tls_foundation_tunnel_via_socks_outbound() {
    let outbound_listener =
        TcpListener::bind(("127.0.0.1", 0)).expect("test outbound listener should bind");
    outbound_listener
        .set_nonblocking(true)
        .expect("test outbound listener should support nonblocking accept");
    let outbound_port = outbound_listener
        .local_addr()
        .expect("test outbound listener should have a local address")
        .port();
    let (frame_tx, frame_rx) = mpsc::channel();
    let (payload_tx, payload_rx) = mpsc::channel();
    let outbound_worker = thread::spawn(move || {
        for _ in 0..100 {
            match outbound_listener.accept() {
                Ok((mut outbound_stream, _)) => {
                    outbound_stream
                        .set_nonblocking(false)
                        .expect("captured outbound stream should use blocking reads");
                    outbound_stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .expect("captured outbound stream should accept a read timeout");
                    let request_frame = read_test_socks5_connect_frame(&mut outbound_stream);
                    frame_tx
                        .send(request_frame)
                        .expect("captured outbound frame should be reported to the test");
                    outbound_stream
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38])
                        .expect("outbound stream should send the SOCKS5 CONNECT response frame");
                    let mut tunneled_payload = [0_u8; 16];
                    outbound_stream
                        .read_exact(&mut tunneled_payload)
                        .expect("outbound should receive finite CONNECT tunnel bytes");
                    payload_tx
                        .send(tunneled_payload.to_vec())
                        .expect("captured tunnel payload should be reported to the test");
                    outbound_stream
                        .write_all(b"tls-server-hello")
                        .expect("outbound should send finite tunnel response bytes");
                    outbound_stream
                        .shutdown(Shutdown::Write)
                        .expect("outbound stream should close the response write side");
                    return;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("test outbound listener failed while accepting: {error}"),
            }
        }

        panic!("test outbound listener did not receive a connection");
    });
    let port = unused_loopback_port();
    let listener = LoopbackListenerHandle::from_descriptor(&http_listener_with_bind(
        "mitm-http-connect-tls-foundation-loopback",
        "127.0.0.1",
        port,
        ListenerRoute::DefaultAction(RouteAction::Proxy {
            node_id: "node-1".to_string(),
        }),
    ))
    .expect("HTTP loopback listener handle should be representable");
    let bound_listener = BoundLoopbackTcpListenerHandle::bind(listener)
        .expect("HTTP loopback listener should bind on an available port");
    let outbound = NativeOutboundHandlerHandle::from_node(&NodeDescriptor {
        endpoint: Endpoint {
            host: "127.0.0.1".to_string(),
            port: outbound_port,
        },
        ..node()
    })
    .expect("socks outbound handler handle should be representable");
    let accept_loop = NativeLoopbackTcpAcceptLoopHandle::start(bound_listener, outbound)
        .expect("HTTP loopback accept loop should start");

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .expect("HTTP loopback accept loop should accept local connections");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("test client should support a read timeout");
    stream
        .write_all(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\ntls-client-hello",
        )
        .expect("test client should send an explicit HTTP CONNECT request and tunnel payload");
    stream
        .shutdown(Shutdown::Write)
        .expect("test client should close the request write side");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .expect("test client should read the HTTP TLS blocked response");
    wait_until_accept_count(&accept_loop, 1);
    wait_until_relayed_count(&accept_loop, 1);
    drop(stream);

    let outbound_frame = frame_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("accept loop should write the outbound SOCKS5 CONNECT frame");
    let tunneled_payload = payload_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("outbound should receive finite tunnel bytes");
    let report = accept_loop.shutdown();
    outbound_worker
        .join()
        .expect("outbound frame capture worker should finish");
    let response_text =
        String::from_utf8(response).expect("HTTP CONNECT tunnel response should be valid UTF-8");

    let mut expected_frame = vec![0x05, 0x01, 0x00, 0x03, "example.com".len() as u8];
    expected_frame.extend_from_slice(b"example.com");
    expected_frame.extend_from_slice(&[0x01, 0xbb]);
    assert_eq!(outbound_frame, expected_frame);
    assert_eq!(tunneled_payload, b"tls-client-hello".to_vec());
    assert!(response_text.starts_with("HTTP/1.1 200 Connection Established\r\n"));
    assert!(response_text.contains("Proxy-Agent: NetworkCore\r\n\r\n"));
    assert!(response_text.ends_with("tls-server-hello"));
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_FOUNDATION_READY_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CONNECT_TUNNEL_ESTABLISHED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_TLS_CLIENT_HELLO_DEFERRED_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE,
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_COMPLETED_CODE,
    );
    assert_no_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_HTTP_PROXY_PLAIN_CONNECT_TLS_BLOCKED_CODE,
    );
    assert_no_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_CONNECTION_PRE_PROTOCOL_CLOSED_CODE,
    );
}

#[test]
fn socks5_route_outbound_behavior_contract_selects_configured_socks_handler_without_connecting() {
    let target = NativeSocks5ConnectTarget {
        address: NativeSocks5Address::DomainName("example.com".to_string()),
        port: 443,
    };
    let outbound_handler = NativeOutboundHandlerHandle::from_node(&node())
        .expect("socks node should become an outbound handler");

    let report = select_socks5_route_outbound_behavior(&target, &outbound_handler);

    let NativeSocks5RouteOutboundBehavior::ProxyViaSocksOutbound {
        target: selected_target,
        outbound_handler: selected_handler,
    } = report.behavior;
    assert_eq!(selected_target, target);
    assert_eq!(selected_handler.node_id, "node-1");
    assert_eq!(selected_handler.protocol, Protocol::Socks);
    assert_eq!(selected_handler.endpoint.host, "127.0.0.1");
    assert_eq!(selected_handler.endpoint.port, 1080);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_SELECTED_CODE,
    );

    let route_report = reject_unwired_socks5_route_outbound(&selected_target);

    assert_eq!(
        route_report.decision,
        NativeSocks5RouteOutboundDecision::Unwired
    );
    assert_diagnostic(
        &route_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_ROUTE_OUTBOUND_UNWIRED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_request_frame_contract_generates_domain_frame_without_connecting() {
    let target = NativeSocks5ConnectTarget {
        address: NativeSocks5Address::DomainName("example.com".to_string()),
        port: 443,
    };
    let outbound_handler = NativeOutboundHandlerHandle::from_node(&node())
        .expect("socks node should become an outbound handler");
    let selection_report = select_socks5_route_outbound_behavior(&target, &outbound_handler);

    let frame_report = build_socks5_outbound_connect_request_frame(&selection_report.behavior);

    assert_eq!(
        frame_report.frame,
        vec![
            0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c',
            b'o', b'm', 0x01, 0xbb,
        ]
    );
    assert_diagnostic(
        &frame_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_GENERATED_CODE,
    );
}

#[test]
fn socks5_outbound_tcp_connection_plan_contract_records_endpoint_and_frame_without_connecting() {
    let target = NativeSocks5ConnectTarget {
        address: NativeSocks5Address::DomainName("example.com".to_string()),
        port: 443,
    };
    let outbound_handler = NativeOutboundHandlerHandle::from_node(&node())
        .expect("socks node should become an outbound handler");
    let selection_report = select_socks5_route_outbound_behavior(&target, &outbound_handler);
    let frame_report = build_socks5_outbound_connect_request_frame(&selection_report.behavior);

    let plan_report =
        plan_socks5_outbound_tcp_connection(&selection_report.behavior, &frame_report.frame);

    let plan = plan_report
        .plan
        .expect("valid SOCKS outbound selection and frame should create a connection plan");
    assert_eq!(plan.outbound_handler_id, "node-1");
    assert_eq!(plan.outbound_endpoint.host, "127.0.0.1");
    assert_eq!(plan.outbound_endpoint.port, 1080);
    assert_eq!(plan.target, target);
    assert_eq!(plan.request_frame, frame_report.frame);
    assert_diagnostic(
        &plan_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_PLANNED_CODE,
    );
}

#[test]
fn socks5_outbound_tcp_connection_plan_contract_reports_invalid_public_input() {
    let target = NativeSocks5ConnectTarget {
        address: NativeSocks5Address::DomainName("example.com".to_string()),
        port: 443,
    };
    let invalid_protocol_behavior = NativeSocks5RouteOutboundBehavior::ProxyViaSocksOutbound {
        target: target.clone(),
        outbound_handler: NativeOutboundHandlerHandle {
            node_id: "http-node".to_string(),
            protocol: Protocol::Http,
            endpoint: Endpoint {
                host: "127.0.0.1".to_string(),
                port: 1080,
            },
        },
    };

    let invalid_protocol_report =
        plan_socks5_outbound_tcp_connection(&invalid_protocol_behavior, &[0x05]);

    assert!(invalid_protocol_report.plan.is_none());
    assert_diagnostic(
        &invalid_protocol_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_PLAN_INVALID_CODE,
    );

    let outbound_handler = NativeOutboundHandlerHandle::from_node(&node())
        .expect("socks node should become an outbound handler");
    let empty_frame_behavior = NativeSocks5RouteOutboundBehavior::ProxyViaSocksOutbound {
        target,
        outbound_handler,
    };

    let empty_frame_report = plan_socks5_outbound_tcp_connection(&empty_frame_behavior, &[]);

    assert!(empty_frame_report.plan.is_none());
    assert_diagnostic(
        &empty_frame_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_PLAN_INVALID_CODE,
    );
}

#[test]
fn socks5_outbound_tcp_connection_attempt_contract_connects_without_relaying_data() {
    let outbound_listener =
        TcpListener::bind(("127.0.0.1", 0)).expect("test outbound listener should bind");
    let outbound_port = outbound_listener
        .local_addr()
        .expect("test outbound listener should have a local address")
        .port();
    let target = NativeSocks5ConnectTarget {
        address: NativeSocks5Address::DomainName("example.com".to_string()),
        port: 443,
    };
    let outbound_handler = NativeOutboundHandlerHandle::from_node(&NodeDescriptor {
        endpoint: Endpoint {
            host: "127.0.0.1".to_string(),
            port: outbound_port,
        },
        ..node()
    })
    .expect("socks node should become an outbound handler");
    let selection_report = select_socks5_route_outbound_behavior(&target, &outbound_handler);
    let frame_report = build_socks5_outbound_connect_request_frame(&selection_report.behavior);
    let plan_report =
        plan_socks5_outbound_tcp_connection(&selection_report.behavior, &frame_report.frame);
    let plan = plan_report
        .plan
        .expect("valid SOCKS outbound selection and frame should create a connection plan");

    let attempt_report = attempt_socks5_outbound_tcp_connection(&plan);

    assert!(attempt_report.stream.is_some());
    assert_diagnostic(
        &attempt_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_SUCCEEDED_CODE,
    );
}

#[test]
fn socks5_outbound_tcp_connection_attempt_contract_reports_invalid_public_endpoint() {
    let plan = NativeSocks5OutboundTcpConnectionPlan {
        outbound_handler_id: "node-1".to_string(),
        outbound_endpoint: Endpoint {
            host: "outbound.example".to_string(),
            port: 1080,
        },
        target: NativeSocks5ConnectTarget {
            address: NativeSocks5Address::DomainName("example.com".to_string()),
            port: 443,
        },
        request_frame: vec![0x05],
    };

    let attempt_report = attempt_socks5_outbound_tcp_connection(&plan);

    assert!(attempt_report.stream.is_none());
    assert_diagnostic(
        &attempt_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_TCP_CONNECTION_ATTEMPT_FAILED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_request_write_contract_writes_planned_frame_without_relaying_data() {
    let plan = NativeSocks5OutboundTcpConnectionPlan {
        outbound_handler_id: "node-1".to_string(),
        outbound_endpoint: Endpoint {
            host: "127.0.0.1".to_string(),
            port: 1080,
        },
        target: NativeSocks5ConnectTarget {
            address: NativeSocks5Address::Ipv4([127, 0, 0, 1]),
            port: 443,
        },
        request_frame: vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb],
    };
    let mut writer = Vec::new();

    let report = write_socks5_outbound_connect_request(&mut writer, &plan);

    assert_eq!(writer, plan.request_frame);
    assert_eq!(report.request_frame, plan.request_frame);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE,
    );
}

#[test]
fn socks5_outbound_connect_request_write_contract_reports_invalid_public_input() {
    let plan = NativeSocks5OutboundTcpConnectionPlan {
        outbound_handler_id: "node-1".to_string(),
        outbound_endpoint: Endpoint {
            host: "127.0.0.1".to_string(),
            port: 1080,
        },
        target: NativeSocks5ConnectTarget {
            address: NativeSocks5Address::Ipv4([127, 0, 0, 1]),
            port: 443,
        },
        request_frame: vec![0x05],
    };
    let mut failing_writer = FailingWriter;

    let failed_report = write_socks5_outbound_connect_request(&mut failing_writer, &plan);

    assert_eq!(failed_report.request_frame, plan.request_frame);
    assert_diagnostic(
        &failed_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITE_FAILED_CODE,
    );

    let empty_frame_plan = NativeSocks5OutboundTcpConnectionPlan {
        request_frame: Vec::new(),
        ..plan
    };
    let mut empty_frame_writer = Vec::new();

    let empty_frame_report =
        write_socks5_outbound_connect_request(&mut empty_frame_writer, &empty_frame_plan);

    assert!(empty_frame_writer.is_empty());
    assert!(empty_frame_report.request_frame.is_empty());
    assert_diagnostic(
        &empty_frame_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITE_FAILED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_response_read_contract_reads_success_ipv4_response_without_relay() {
    let mut reader = Cursor::new(vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38]);

    let report = read_socks5_outbound_connect_response(&mut reader);

    let diagnostics = report.diagnostics;
    let response = report
        .response
        .expect("valid SOCKS5 outbound CONNECT response should be parsed");
    assert_eq!(response.version, 0x05);
    assert_eq!(response.reply, 0x00);
    assert_eq!(response.reserved, 0x00);
    assert_eq!(response.address_type, 0x01);
    assert_eq!(
        response.bound_address,
        NativeSocks5Address::Ipv4([127, 0, 0, 1])
    );
    assert_eq!(response.bound_port, 1080);
    assert_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_READ_CODE,
    );
}

#[test]
fn socks5_outbound_connect_response_read_contract_reports_failure_reply_and_incomplete_response() {
    let mut failure_reply = Cursor::new(vec![0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);

    let failure_report = read_socks5_outbound_connect_response(&mut failure_reply);

    let failure_diagnostics = failure_report.diagnostics;
    let failure_response = failure_report
        .response
        .expect("complete SOCKS5 failure response should still report observed bytes");
    assert_eq!(failure_response.reply, 0x05);
    assert_diagnostic(
        &failure_diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_INVALID_CODE,
    );

    let mut incomplete_response = Cursor::new(vec![0x05, 0x00, 0x00, 0x01, 127]);

    let incomplete_report = read_socks5_outbound_connect_response(&mut incomplete_response);

    assert!(incomplete_report.response.is_none());
    assert_diagnostic(
        &incomplete_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_READ_FAILED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_response_decision_contract_accepts_success_response_without_relay() {
    let mut reader = Cursor::new(vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38]);
    let read_report = read_socks5_outbound_connect_response(&mut reader);
    let response = read_report
        .response
        .expect("valid SOCKS5 outbound CONNECT response should be parsed");

    let decision_report = decide_socks5_outbound_connect_response(&response);

    assert_eq!(
        decision_report.decision,
        NativeSocks5OutboundConnectResponseDecision::Accepted
    );
    assert_diagnostic(
        &decision_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_ACCEPTED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_response_decision_contract_rejects_failure_or_invalid_response() {
    let mut failure_reply = Cursor::new(vec![0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    let failure_read_report = read_socks5_outbound_connect_response(&mut failure_reply);
    let failure_response = failure_read_report
        .response
        .expect("complete SOCKS5 failure response should still report observed bytes");

    let failure_decision_report = decide_socks5_outbound_connect_response(&failure_response);

    assert_eq!(
        failure_decision_report.decision,
        NativeSocks5OutboundConnectResponseDecision::Rejected
    );
    assert_diagnostic(
        &failure_decision_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_REJECTED_CODE,
    );

    let mut invalid_reserved = Cursor::new(vec![0x05, 0x00, 0x01, 0x01, 0, 0, 0, 0, 0, 0]);
    let invalid_read_report = read_socks5_outbound_connect_response(&mut invalid_reserved);
    let invalid_response = invalid_read_report
        .response
        .expect("complete invalid SOCKS5 response should still report observed bytes");

    let invalid_decision_report = decide_socks5_outbound_connect_response(&invalid_response);

    assert_eq!(
        invalid_decision_report.decision,
        NativeSocks5OutboundConnectResponseDecision::Rejected
    );
    assert_diagnostic(
        &invalid_decision_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RESPONSE_REJECTED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_relay_readiness_contract_marks_accepted_response_ready() {
    let mut reader = Cursor::new(vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38]);
    let read_report = read_socks5_outbound_connect_response(&mut reader);
    let response = read_report
        .response
        .expect("valid SOCKS5 outbound CONNECT response should be parsed");
    let decision_report = decide_socks5_outbound_connect_response(&response);

    let readiness_report = assess_socks5_outbound_connect_relay_readiness(decision_report.decision);

    assert_eq!(
        readiness_report.readiness,
        NativeSocks5OutboundConnectRelayReadiness::Ready
    );
    assert_diagnostic(
        &readiness_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_READY_CODE,
    );
}

#[test]
fn socks5_outbound_connect_relay_readiness_contract_rejects_rejected_response() {
    let mut failure_reply = Cursor::new(vec![0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
    let failure_read_report = read_socks5_outbound_connect_response(&mut failure_reply);
    let failure_response = failure_read_report
        .response
        .expect("complete SOCKS5 failure response should still report observed bytes");
    let decision_report = decide_socks5_outbound_connect_response(&failure_response);

    let readiness_report = assess_socks5_outbound_connect_relay_readiness(decision_report.decision);

    assert_eq!(
        readiness_report.readiness,
        NativeSocks5OutboundConnectRelayReadiness::Rejected
    );
    assert_diagnostic(
        &readiness_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_REJECTED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_data_relay_plan_contract_accepts_ready_relay() {
    let report =
        plan_socks5_outbound_connect_data_relay(NativeSocks5OutboundConnectRelayReadiness::Ready);

    assert_eq!(
        report.decision,
        NativeSocks5OutboundConnectDataRelayPlanDecision::Ready
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_READY_CODE,
    );
}

#[test]
fn socks5_outbound_connect_data_relay_plan_contract_blocks_unwired_relay_before_success_response() {
    let report =
        plan_socks5_outbound_connect_data_relay(NativeSocks5OutboundConnectRelayReadiness::Blocked);

    assert_eq!(
        report.decision,
        NativeSocks5OutboundConnectDataRelayPlanDecision::Blocked
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_UNWIRED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_data_relay_plan_contract_rejects_rejected_relay() {
    let report = plan_socks5_outbound_connect_data_relay(
        NativeSocks5OutboundConnectRelayReadiness::Rejected,
    );

    assert_eq!(
        report.decision,
        NativeSocks5OutboundConnectDataRelayPlanDecision::Rejected
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_PLAN_REJECTED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_data_relay_contract_copies_bidirectional_streams() {
    let client_payload = b"client payload".to_vec();
    let outbound_payload = b"outbound payload".to_vec();
    let mut client_reader = Cursor::new(client_payload.clone());
    let mut outbound_writer = Vec::new();
    let mut outbound_reader = Cursor::new(outbound_payload.clone());
    let mut client_writer = Vec::new();

    let report = relay_socks5_outbound_connect_data(
        &mut client_reader,
        &mut outbound_writer,
        &mut outbound_reader,
        &mut client_writer,
    );

    assert_eq!(outbound_writer, client_payload);
    assert_eq!(client_writer, outbound_payload);
    assert_eq!(
        report.client_to_outbound_bytes,
        outbound_writer.len() as u64
    );
    assert_eq!(report.outbound_to_client_bytes, client_writer.len() as u64);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_COMPLETED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_data_relay_contract_reports_direction_failure() {
    let outbound_payload = b"outbound payload".to_vec();
    let mut client_reader = Cursor::new(b"client payload".to_vec());
    let mut outbound_writer = FailingWriter;
    let mut outbound_reader = Cursor::new(outbound_payload.clone());
    let mut client_writer = Vec::new();

    let report = relay_socks5_outbound_connect_data(
        &mut client_reader,
        &mut outbound_writer,
        &mut outbound_reader,
        &mut client_writer,
    );

    assert_eq!(report.client_to_outbound_bytes, 0);
    assert_eq!(client_writer, outbound_payload);
    assert_eq!(report.outbound_to_client_bytes, client_writer.len() as u64);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_DATA_RELAY_FAILED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_client_success_response_readiness_contract_accepts_ready_data_relay() {
    let report = assess_socks5_outbound_connect_client_success_response_readiness(
        NativeSocks5OutboundConnectDataRelayPlanDecision::Ready,
    );

    assert_eq!(
        report.readiness,
        NativeSocks5OutboundConnectClientSuccessResponseReadiness::Ready
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_READY_CODE,
    );
}

#[test]
fn socks5_outbound_connect_client_success_response_readiness_contract_blocks_unwired_data_relay() {
    let report = assess_socks5_outbound_connect_client_success_response_readiness(
        NativeSocks5OutboundConnectDataRelayPlanDecision::Blocked,
    );

    assert_eq!(
        report.readiness,
        NativeSocks5OutboundConnectClientSuccessResponseReadiness::Blocked
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_UNWIRED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_client_success_response_readiness_contract_rejects_rejected_plan() {
    let report = assess_socks5_outbound_connect_client_success_response_readiness(
        NativeSocks5OutboundConnectDataRelayPlanDecision::Rejected,
    );

    assert_eq!(
        report.readiness,
        NativeSocks5OutboundConnectClientSuccessResponseReadiness::Rejected
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_REJECTED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_client_success_response_write_plan_contract_accepts_ready_readiness() {
    let report = plan_socks5_outbound_connect_client_success_response_write(
        NativeSocks5OutboundConnectClientSuccessResponseReadiness::Ready,
    );

    assert_eq!(
        report.decision,
        NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision::Ready
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_READY_CODE,
    );
}

#[test]
fn socks5_outbound_connect_client_success_response_write_plan_contract_blocks_unwired_readiness() {
    let report = plan_socks5_outbound_connect_client_success_response_write(
        NativeSocks5OutboundConnectClientSuccessResponseReadiness::Blocked,
    );

    assert_eq!(
        report.decision,
        NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision::Blocked
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_UNWIRED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_client_success_response_write_plan_contract_rejects_rejected_readiness()
{
    let report = plan_socks5_outbound_connect_client_success_response_write(
        NativeSocks5OutboundConnectClientSuccessResponseReadiness::Rejected,
    );

    assert_eq!(
        report.decision,
        NativeSocks5OutboundConnectClientSuccessResponseWritePlanDecision::Rejected
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_PLAN_REJECTED_CODE,
    );
}

#[test]
fn socks5_client_success_response_write_contract_writes_success_frame() {
    let mut writer = Vec::new();
    let response = NativeSocks5OutboundConnectResponse {
        version: 0x05,
        reply: 0x00,
        reserved: 0x00,
        address_type: 0x01,
        bound_address: NativeSocks5Address::Ipv4([127, 0, 0, 1]),
        bound_port: 1080,
    };

    let report = write_socks5_outbound_connect_client_success_response(&mut writer, &response);

    assert_eq!(
        writer,
        vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38]
    );
    assert_eq!(report.response_frame, writer);
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITTEN_CODE,
    );
}

#[test]
fn socks5_client_success_response_write_contract_reports_write_failure() {
    let mut writer = FailingWriter;
    let response = NativeSocks5OutboundConnectResponse {
        version: 0x05,
        reply: 0x00,
        reserved: 0x00,
        address_type: 0x01,
        bound_address: NativeSocks5Address::Ipv4([127, 0, 0, 1]),
        bound_port: 1080,
    };

    let report = write_socks5_outbound_connect_client_success_response(&mut writer, &response);

    assert_eq!(
        report.response_frame,
        vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38]
    );
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_FAILED_CODE,
    );
}

#[test]
fn socks5_client_success_response_write_contract_rejects_invalid_response() {
    let mut writer = Vec::new();
    let response = NativeSocks5OutboundConnectResponse {
        version: 0x05,
        reply: 0x05,
        reserved: 0x00,
        address_type: 0x01,
        bound_address: NativeSocks5Address::Ipv4([127, 0, 0, 1]),
        bound_port: 1080,
    };

    let report = write_socks5_outbound_connect_client_success_response(&mut writer, &response);

    assert!(writer.is_empty());
    assert!(report.response_frame.is_empty());
    assert_diagnostic(
        &report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_CLIENT_SUCCESS_RESPONSE_WRITE_FAILED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_request_frame_contract_generates_ip_frames() {
    let outbound_handler = NativeOutboundHandlerHandle::from_node(&node())
        .expect("socks node should become an outbound handler");
    let ipv4_target = NativeSocks5ConnectTarget {
        address: NativeSocks5Address::Ipv4([127, 0, 0, 1]),
        port: 80,
    };
    let ipv4_behavior = NativeSocks5RouteOutboundBehavior::ProxyViaSocksOutbound {
        target: ipv4_target,
        outbound_handler: outbound_handler.clone(),
    };
    let ipv4_report = build_socks5_outbound_connect_request_frame(&ipv4_behavior);

    assert_eq!(
        ipv4_report.frame,
        vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50]
    );
    assert_diagnostic(
        &ipv4_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_GENERATED_CODE,
    );

    let mut ipv6_address = [0_u8; 16];
    ipv6_address[15] = 1;
    let ipv6_target = NativeSocks5ConnectTarget {
        address: NativeSocks5Address::Ipv6(ipv6_address),
        port: 443,
    };
    let ipv6_behavior = NativeSocks5RouteOutboundBehavior::ProxyViaSocksOutbound {
        target: ipv6_target,
        outbound_handler,
    };
    let ipv6_report = build_socks5_outbound_connect_request_frame(&ipv6_behavior);
    let mut expected_ipv6_frame = vec![0x05, 0x01, 0x00, 0x04];
    expected_ipv6_frame.extend_from_slice(&ipv6_address);
    expected_ipv6_frame.extend_from_slice(&443_u16.to_be_bytes());

    assert_eq!(ipv6_report.frame, expected_ipv6_frame);
    assert_diagnostic(
        &ipv6_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_GENERATED_CODE,
    );
}

#[test]
fn socks5_outbound_connect_request_frame_contract_reports_invalid_public_target_input() {
    let outbound_handler = NativeOutboundHandlerHandle::from_node(&node())
        .expect("socks node should become an outbound handler");
    let oversized_domain_behavior = NativeSocks5RouteOutboundBehavior::ProxyViaSocksOutbound {
        target: NativeSocks5ConnectTarget {
            address: NativeSocks5Address::DomainName("a".repeat(256)),
            port: 443,
        },
        outbound_handler,
    };

    let frame_report = build_socks5_outbound_connect_request_frame(&oversized_domain_behavior);

    assert!(frame_report.frame.is_empty());
    assert_diagnostic(
        &frame_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_INVALID_CODE,
    );
}

#[test]
fn socks5_connect_target_contract_reads_ipv4_and_ipv6_targets() {
    let ipv4_header = NativeSocks5CommandHeader {
        version: 0x05,
        command: 0x01,
        reserved: 0x00,
        address_type: 0x01,
    };
    let mut ipv4_reader = Cursor::new(vec![127, 0, 0, 1, 0x00, 0x50]);

    let ipv4_report = read_socks5_connect_target(&mut ipv4_reader, &ipv4_header);

    let ipv4_diagnostics = ipv4_report.diagnostics;
    let ipv4_target = ipv4_report
        .target
        .expect("valid SOCKS5 IPv4 CONNECT target should be parsed");
    assert_eq!(
        ipv4_target.address,
        NativeSocks5Address::Ipv4([127, 0, 0, 1])
    );
    assert_eq!(ipv4_target.port, 80);
    assert_diagnostic(
        &ipv4_diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_CODE,
    );

    let ipv6_header = NativeSocks5CommandHeader {
        version: 0x05,
        command: 0x01,
        reserved: 0x00,
        address_type: 0x04,
    };
    let mut ipv6_reader = Cursor::new(vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb,
    ]);

    let ipv6_report = read_socks5_connect_target(&mut ipv6_reader, &ipv6_header);

    let ipv6_diagnostics = ipv6_report.diagnostics;
    let ipv6_target = ipv6_report
        .target
        .expect("valid SOCKS5 IPv6 CONNECT target should be parsed");
    assert_eq!(
        ipv6_target.address,
        NativeSocks5Address::Ipv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    );
    assert_eq!(ipv6_target.port, 443);
    assert_diagnostic(
        &ipv6_diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_CODE,
    );
}

#[test]
fn socks5_connect_target_contract_reports_invalid_and_incomplete_targets() {
    let domain_header = NativeSocks5CommandHeader {
        version: 0x05,
        command: 0x01,
        reserved: 0x00,
        address_type: 0x03,
    };
    let mut empty_domain = Cursor::new(vec![0x00]);

    let empty_domain_report = read_socks5_connect_target(&mut empty_domain, &domain_header);

    assert!(empty_domain_report.target.is_none());
    assert_diagnostic(
        &empty_domain_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_INVALID_CODE,
    );

    let ipv4_header = NativeSocks5CommandHeader {
        version: 0x05,
        command: 0x01,
        reserved: 0x00,
        address_type: 0x01,
    };
    let mut incomplete_ipv4 = Cursor::new(vec![127, 0, 0]);

    let incomplete_report = read_socks5_connect_target(&mut incomplete_ipv4, &ipv4_header);

    assert!(incomplete_report.target.is_none());
    assert_diagnostic(
        &incomplete_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_READ_FAILED_CODE,
    );

    let mut zero_port = Cursor::new(vec![127, 0, 0, 1, 0x00, 0x00]);

    let zero_port_report = read_socks5_connect_target(&mut zero_port, &ipv4_header);

    let zero_port_diagnostics = zero_port_report.diagnostics;
    let zero_port_target = zero_port_report
        .target
        .expect("invalid port target should still report observed address");
    assert_eq!(zero_port_target.port, 0);
    assert_diagnostic(
        &zero_port_diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_CONNECT_TARGET_INVALID_CODE,
    );
}

#[test]
fn runtime_handle_contract_releases_accept_loop_on_runtime_release() {
    let port = unused_loopback_port();
    let listener = LoopbackListenerHandle::from_descriptor(&local_tcp_listener_with_bind(
        "release-accept-loopback-local-tcp",
        "127.0.0.1",
        port,
        ListenerRoute::DefaultAction(RouteAction::Proxy {
            node_id: "node-1".to_string(),
        }),
    ))
    .expect("loopback tcp listener handle should be representable");
    let bound_listener = BoundLoopbackTcpListenerHandle::bind(listener)
        .expect("loopback tcp listener should bind on an available port");
    let outbound = NativeOutboundHandlerHandle::from_node(&node())
        .expect("socks outbound handler handle should be representable");
    let accept_loop = NativeLoopbackTcpAcceptLoopHandle::start(bound_listener, outbound)
        .expect("loopback tcp accept loop should start from bound resources");

    let handle = NativeRuntimeAssembly::new(DEFAULT_NATIVE_ENGINE_ID)
        .with_accept_loop(accept_loop)
        .finish()
        .expect("runtime handle should own the loopback tcp accept loop");

    assert!(handle.listeners().is_empty());
    assert!(handle.bound_listeners().is_empty());
    assert!(handle.outbound_handlers().is_empty());
    assert_eq!(
        handle.accept_loops()[0].listener_id(),
        "release-accept-loopback-local-tcp"
    );
    assert_eq!(handle.accept_loops()[0].outbound_handler_id(), "node-1");
    assert_eq!(handle.accept_loops()[0].local_port(), port);
    assert_diagnostic(
        &handle.events()[0].diagnostics,
        ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_READY_CODE,
    );
    assert_diagnostic(
        &handle.foreground_handoff_status().diagnostics,
        ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_READY_CODE,
    );

    let release = handle.release();

    assert_eq!(
        release.listener_ids,
        vec!["release-accept-loopback-local-tcp".to_string()]
    );
    assert_eq!(release.outbound_handler_ids, vec!["node-1".to_string()]);
    assert_diagnostic(
        &release.diagnostics,
        ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_STOPPED_CODE,
    );
    assert_diagnostic(&release.diagnostics, ENGINE_NATIVE_RUNTIME_RELEASED_CODE);

    let rebound = TcpListener::bind(("127.0.0.1", port))
        .expect("runtime release should stop the accept loop and free the loopback tcp port");
    drop(rebound);
}

#[test]
fn runtime_handle_contract_reports_loopback_tcp_bind_failure() {
    let guard = TcpListener::bind(("127.0.0.1", 0))
        .expect("test should reserve an ephemeral loopback tcp port");
    let port = guard
        .local_addr()
        .expect("reserved listener should expose its local address")
        .port();
    let listener = LoopbackListenerHandle::from_descriptor(&local_tcp_listener_with_bind(
        "busy-loopback-local-tcp",
        "127.0.0.1",
        port,
        ListenerRoute::DefaultAction(RouteAction::Direct),
    ))
    .expect("loopback tcp listener handle should be representable");

    let error = BoundLoopbackTcpListenerHandle::bind(listener)
        .expect_err("binding an already reserved loopback port should fail");

    assert_eq!(error.code, ENGINE_NATIVE_START_BIND_FAILED_CODE);
    drop(guard);
}

#[test]
fn runtime_assembly_plan_selects_loopback_tcp_listener_and_socks_outbound_from_config_graph() {
    let port = unused_loopback_port();
    let service = NativeProxyEngineService::new();
    let engine_config = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        vec![node()],
        Vec::new(),
        vec![local_tcp_listener_with_bind(
            "plan-loopback-local-tcp",
            "127.0.0.1",
            port,
            ListenerRoute::RuleSet {
                rule_set_id: "runtime-route".to_string(),
            },
        )],
        vec![route_set(
            "runtime-route",
            RouteAction::Proxy {
                node_id: "node-1".to_string(),
            },
        )],
    );

    let diagnostics = service.validate_config(&engine_config);

    assert_no_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_LISTENER_KIND_UNSUPPORTED_CODE,
    );
    assert_no_diagnostic(
        &diagnostics,
        ENGINE_NATIVE_CONFIG_NODE_PROTOCOL_UNSUPPORTED_CODE,
    );
    assert_no_diagnostic(&diagnostics, ENGINE_NATIVE_CONFIG_ROUTE_EMPTY_CODE);

    let plan = NativeRuntimeAssemblyPlan::from_config(&engine_config)
        .expect("valid graph should produce a native runtime assembly plan");

    assert_eq!(plan.engine_id(), DEFAULT_NATIVE_ENGINE_ID);
    assert_eq!(plan.listener().listener_id, "plan-loopback-local-tcp");
    assert_eq!(plan.listener().bind_port, port);
    assert_eq!(plan.outbound_handler().node_id, "node-1");
    assert_eq!(plan.outbound_handler().protocol, Protocol::Socks);

    let handle = plan
        .bind_loopback_listener()
        .expect("available loopback listener should bind into an assembly")
        .finish()
        .expect("bound assembly should finish with listener and outbound resources");

    assert!(handle.listeners().is_empty());
    assert_eq!(
        handle.bound_listeners()[0].listener_id(),
        "plan-loopback-local-tcp"
    );
    assert_eq!(handle.bound_listeners()[0].local_port(), port);
    assert_eq!(handle.outbound_handlers()[0].node_id, "node-1");

    let release = handle.release();

    assert_eq!(
        release.listener_ids,
        vec!["plan-loopback-local-tcp".to_string()]
    );
    assert_diagnostic(&release.diagnostics, ENGINE_NATIVE_RUNTIME_RELEASED_CODE);

    let rebound = TcpListener::bind(("127.0.0.1", port))
        .expect("runtime assembly plan release should free the loopback tcp port");
    drop(rebound);
}

#[test]
fn runtime_assembly_plan_reports_bind_failure_with_release_boundary() {
    let guard = TcpListener::bind(("127.0.0.1", 0))
        .expect("test should reserve an ephemeral loopback tcp port");
    let port = guard
        .local_addr()
        .expect("reserved listener should expose its local address")
        .port();
    let engine_config = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        vec![node()],
        Vec::new(),
        vec![local_tcp_listener_with_bind(
            "busy-plan-loopback-local-tcp",
            "127.0.0.1",
            port,
            ListenerRoute::DefaultAction(RouteAction::Proxy {
                node_id: "node-1".to_string(),
            }),
        )],
        Vec::new(),
    );
    let plan = NativeRuntimeAssemblyPlan::from_config(&engine_config)
        .expect("valid graph should produce a native runtime assembly plan");

    let failure = plan
        .bind_loopback_listener()
        .expect_err("busy loopback listener should produce startup failure");

    assert_eq!(failure.error.code, ENGINE_NATIVE_START_BIND_FAILED_CODE);
    assert_eq!(
        failure.release.listener_ids,
        vec!["busy-plan-loopback-local-tcp".to_string()]
    );
    assert_eq!(
        failure.release.outbound_handler_ids,
        vec!["node-1".to_string()]
    );
    assert_diagnostic(
        &failure.release.diagnostics,
        ENGINE_NATIVE_RUNTIME_RELEASED_CODE,
    );
    assert_eq!(failure.release.events[0].kind, ProxyEngineEventKind::Failed);

    drop(guard);
}

#[test]
fn runtime_assembly_plan_releases_bound_listener_when_lifecycle_handoff_fails() {
    let port = unused_loopback_port();
    let engine_config = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        vec![node()],
        Vec::new(),
        vec![local_tcp_listener_with_bind(
            "handoff-failure-loopback-local-tcp",
            "127.0.0.1",
            port,
            ListenerRoute::DefaultAction(RouteAction::Proxy {
                node_id: "node-1".to_string(),
            }),
        )],
        Vec::new(),
    );
    let assembly = NativeRuntimeAssemblyPlan::from_config(&engine_config)
        .expect("valid graph should produce a native runtime assembly plan")
        .bind_loopback_listener()
        .expect("available loopback listener should bind into an assembly");

    let failure = assembly.fail(
        ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE,
        "failed to hand off native runtime to foreground lifecycle host",
    );

    assert_eq!(
        failure.error.code,
        ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE
    );
    assert_eq!(
        failure.release.listener_ids,
        vec!["handoff-failure-loopback-local-tcp".to_string()]
    );
    assert_eq!(
        failure.release.outbound_handler_ids,
        vec!["node-1".to_string()]
    );
    assert_diagnostic(
        &failure.release.diagnostics,
        ENGINE_NATIVE_RUNTIME_RELEASED_CODE,
    );

    let rebound = TcpListener::bind(("127.0.0.1", port))
        .expect("failed handoff release should free the loopback tcp port");
    drop(rebound);
}

#[test]
fn runtime_handle_contract_rejects_non_loopback_listener() {
    let listener = local_tcp_listener_with_bind(
        "public-local-tcp",
        "0.0.0.0",
        1080,
        ListenerRoute::DefaultAction(RouteAction::Direct),
    );

    let error = LoopbackListenerHandle::from_descriptor(&listener)
        .expect_err("public bind must not become a native runtime handle");

    assert_eq!(error.code, ENGINE_NATIVE_RUNTIME_LISTENER_NON_LOOPBACK_CODE);
}

#[test]
fn runtime_handle_contract_reports_disabled_invalid_and_missing_resources() {
    let disabled_error =
        LoopbackListenerHandle::from_descriptor(&disabled_listener("disabled-loopback"))
            .expect_err("disabled listeners must not become runtime handles");

    assert_eq!(
        disabled_error.code,
        ENGINE_NATIVE_RUNTIME_LISTENER_DISABLED_CODE
    );

    let invalid_endpoint = NodeDescriptor {
        endpoint: Endpoint {
            host: "".to_string(),
            port: 0,
        },
        ..node()
    };
    let endpoint_error = NativeOutboundHandlerHandle::from_node(&invalid_endpoint)
        .expect_err("invalid outbound endpoint must not become a handler handle");

    assert_eq!(
        endpoint_error.code,
        ENGINE_NATIVE_RUNTIME_OUTBOUND_ENDPOINT_INVALID_CODE
    );

    let missing_error = NativeRuntimeAssembly::new(DEFAULT_NATIVE_ENGINE_ID)
        .finish()
        .expect_err("runtime assembly must require listener and outbound handles");

    assert_eq!(
        missing_error.code,
        ENGINE_NATIVE_RUNTIME_RESOURCE_MISSING_CODE
    );
}

#[test]
fn runtime_handle_contract_rejects_unsupported_outbound_protocol() {
    let node = NodeDescriptor {
        protocol: Protocol::Http,
        ..node()
    };

    let error = NativeOutboundHandlerHandle::from_node(&node)
        .expect_err("unsupported outbound protocol must not become a handler handle");

    assert_eq!(error.code, ENGINE_NATIVE_RUNTIME_OUTBOUND_UNSUPPORTED_CODE);
}

#[test]
fn runtime_handle_contract_rejects_unsupported_engine_id() {
    let listener = LoopbackListenerHandle::from_descriptor(&local_tcp_listener(
        "loopback-local-tcp",
        ListenerRoute::DefaultAction(RouteAction::Proxy {
            node_id: "node-1".to_string(),
        }),
    ))
    .expect("loopback tcp listener handle should be representable");
    let outbound = NativeOutboundHandlerHandle::from_node(&node())
        .expect("socks outbound handler handle should be representable");

    let error = NativeRuntimeAssembly::new("external")
        .with_listener(listener)
        .with_outbound_handler(outbound)
        .finish()
        .expect_err("native runtime handles must keep the native engine id");

    assert_eq!(error.code, ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE);
}

#[test]
fn runtime_handle_contract_releases_acquired_resources_on_start_failure() {
    let listener = LoopbackListenerHandle::from_descriptor(&local_tcp_listener(
        "loopback-local-tcp",
        ListenerRoute::DefaultAction(RouteAction::Proxy {
            node_id: "node-1".to_string(),
        }),
    ))
    .expect("loopback tcp listener handle should be representable");
    let outbound = NativeOutboundHandlerHandle::from_node(&node())
        .expect("socks outbound handler handle should be representable");

    let failure = NativeRuntimeAssembly::new(DEFAULT_NATIVE_ENGINE_ID)
        .with_listener(listener)
        .with_outbound_handler(outbound)
        .fail(
            "engine.native.start.bind_failed",
            "failed to bind loopback listener",
        );

    assert_eq!(failure.error.code, "engine.native.start.bind_failed");
    assert_eq!(
        failure.release.listener_ids,
        vec!["loopback-local-tcp".to_string()]
    );
    assert_eq!(
        failure.release.outbound_handler_ids,
        vec!["node-1".to_string()]
    );
    assert_diagnostic(
        &failure.release.diagnostics,
        ENGINE_NATIVE_RUNTIME_RELEASED_CODE,
    );
    assert_eq!(failure.release.events[0].kind, ProxyEngineEventKind::Failed);
}

#[test]
fn service_start_owns_runtime_state_for_status_events_and_stop() {
    let port = unused_loopback_port();
    let service = NativeProxyEngineService::new();
    let engine_config = graph_config(
        DEFAULT_NATIVE_ENGINE_ID,
        vec![node()],
        Vec::new(),
        vec![local_tcp_listener_with_bind(
            "service-owned-loopback-local-tcp",
            "127.0.0.1",
            port,
            ListenerRoute::DefaultAction(RouteAction::Proxy {
                node_id: "node-1".to_string(),
            }),
        )],
        Vec::new(),
    );

    let started = service
        .start(&engine_config)
        .expect("service start should own the loopback accept loop runtime");

    assert_eq!(started.state, ProxyEngineLifecycleState::Running);
    assert_diagnostic(&started.diagnostics, ENGINE_NATIVE_START_RUNNING_CODE);
    assert_diagnostic(
        &started.diagnostics,
        ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_READY_CODE,
    );

    let second_start = service
        .start(&engine_config)
        .expect("service start should be idempotent while runtime is running");

    assert_eq!(second_start.state, ProxyEngineLifecycleState::Running);
    assert_diagnostic(&second_start.diagnostics, ENGINE_NATIVE_START_RUNNING_CODE);

    let status = service
        .status(DEFAULT_NATIVE_ENGINE_ID)
        .expect("running service status should be inspectable");

    assert_eq!(status.state, ProxyEngineLifecycleState::Running);
    assert_diagnostic(
        &status.diagnostics,
        ENGINE_NATIVE_RUNTIME_FOREGROUND_HANDOFF_READY_CODE,
    );
    assert_diagnostic(
        &status.diagnostics,
        ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_READY_CODE,
    );

    let events = service
        .events(DEFAULT_NATIVE_ENGINE_ID)
        .expect("running service events should be inspectable");

    assert!(events
        .iter()
        .any(|event| event.kind == ProxyEngineEventKind::Started));

    let stopped = service
        .stop(DEFAULT_NATIVE_ENGINE_ID)
        .expect("service stop should release the loopback accept loop runtime");

    assert_eq!(stopped.state, ProxyEngineLifecycleState::Stopped);
    assert_diagnostic(
        &stopped.diagnostics,
        ENGINE_NATIVE_RUNTIME_ACCEPT_LOOP_STOPPED_CODE,
    );
    assert_diagnostic(&stopped.diagnostics, ENGINE_NATIVE_RUNTIME_RELEASED_CODE);

    let stopped_status = service
        .status(DEFAULT_NATIVE_ENGINE_ID)
        .expect("stopped service status should be inspectable");

    assert_eq!(stopped_status.state, ProxyEngineLifecycleState::Stopped);

    let events_after_stop = service
        .events(DEFAULT_NATIVE_ENGINE_ID)
        .expect("stopped service events should remain inspectable");

    assert!(events_after_stop
        .iter()
        .any(|event| event.kind == ProxyEngineEventKind::Started));
    assert!(events_after_stop
        .iter()
        .any(|event| event.kind == ProxyEngineEventKind::Stopped));

    let rebound = TcpListener::bind(("127.0.0.1", port))
        .expect("service stop should free the loopback tcp port");
    drop(rebound);
}

#[test]
fn status_and_stop_remain_stopped_without_runtime_handle() {
    let service = NativeProxyEngineService::new();

    let status = service
        .status(DEFAULT_NATIVE_ENGINE_ID)
        .expect("native status should be inspectable");
    let stopped = service
        .stop(DEFAULT_NATIVE_ENGINE_ID)
        .expect("native stop should be idempotent before runtime exists");

    assert_eq!(status.state, ProxyEngineLifecycleState::Stopped);
    assert_eq!(stopped.state, ProxyEngineLifecycleState::Stopped);
    assert!(status.diagnostics.is_empty());
    assert!(stopped.diagnostics.is_empty());
}

#[test]
fn events_are_empty_until_runtime_handle_exists() {
    let service = NativeProxyEngineService::new();

    let events = service
        .events(DEFAULT_NATIVE_ENGINE_ID)
        .expect("native events should be inspectable");

    assert!(events.is_empty());
}

#[test]
fn unsupported_engine_id_rejects_lifecycle_calls() {
    let service = NativeProxyEngineService::new();

    let error = service
        .status("external")
        .expect_err("unsupported engine id should fail lifecycle calls");

    assert_eq!(error.code, ENGINE_NATIVE_CONFIG_ENGINE_ID_UNSUPPORTED_CODE);
}

fn config(engine_id: &str, request_nodes: Vec<NodeDescriptor>) -> ProxyEngineConfig {
    graph_config(engine_id, Vec::new(), request_nodes, Vec::new(), Vec::new())
}

fn graph_config(
    engine_id: &str,
    config_nodes: Vec<NodeDescriptor>,
    request_nodes: Vec<NodeDescriptor>,
    listeners: Vec<ListenerDescriptor>,
    policies: Vec<RuleSet>,
) -> ProxyEngineConfig {
    ProxyEngineConfig {
        engine_id: engine_id.to_string(),
        config: ConfigSnapshot {
            version: SchemaVersion::new(1),
            profiles: vec!["default".to_string()],
            listeners,
            nodes: config_nodes,
            policies,
            dns: Vec::new(),
            plugins: Vec::new(),
        },
        nodes: request_nodes,
        metadata: Vec::new(),
    }
}

fn listener(id: &str, route: ListenerRoute) -> ListenerDescriptor {
    listener_with_bind(id, "127.0.0.1", 1080, route)
}

fn local_tcp_listener(id: &str, route: ListenerRoute) -> ListenerDescriptor {
    local_tcp_listener_with_bind(id, "127.0.0.1", 1080, route)
}

fn disabled_listener(id: &str) -> ListenerDescriptor {
    ListenerDescriptor {
        enabled: false,
        ..listener(id, ListenerRoute::DefaultAction(RouteAction::Direct))
    }
}

fn listener_with_bind(id: &str, host: &str, port: u16, route: ListenerRoute) -> ListenerDescriptor {
    ListenerDescriptor {
        id: id.to_string(),
        enabled: true,
        kind: ListenerKind::Socks,
        bind: ListenerBind {
            host: host.to_string(),
            port,
        },
        network: ListenerNetwork::Tcp,
        route,
        tags: Vec::new(),
        metadata: Vec::new(),
    }
}

fn local_tcp_listener_with_bind(
    id: &str,
    host: &str,
    port: u16,
    route: ListenerRoute,
) -> ListenerDescriptor {
    ListenerDescriptor {
        kind: ListenerKind::LocalTcp,
        ..listener_with_bind(id, host, port, route)
    }
}

fn http_listener_with_bind(
    id: &str,
    host: &str,
    port: u16,
    route: ListenerRoute,
) -> ListenerDescriptor {
    ListenerDescriptor {
        kind: ListenerKind::Http,
        ..listener_with_bind(id, host, port, route)
    }
}

fn route_set(id: &str, default_action: RouteAction) -> RuleSet {
    RuleSet {
        id: id.to_string(),
        rules: Vec::new(),
        default_action,
    }
}

fn node() -> NodeDescriptor {
    NodeDescriptor {
        id: "node-1".to_string(),
        name: "node 1".to_string(),
        protocol: Protocol::Socks,
        endpoint: Endpoint {
            host: "127.0.0.1".to_string(),
            port: 1080,
        },
        tags: Vec::new(),
        metadata: Vec::new(),
    }
}

fn assert_diagnostic(diagnostics: &[Diagnostic], code: &str) {
    assert!(
        diagnostics.iter().any(|diagnostic| diagnostic.code == code),
        "missing diagnostic {code}: {diagnostics:?}"
    );
}

fn assert_no_diagnostic(diagnostics: &[Diagnostic], code: &str) {
    assert!(
        diagnostics.iter().all(|diagnostic| diagnostic.code != code),
        "unexpected diagnostic {code}: {diagnostics:?}"
    );
}

fn complete_tls_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
    for _ in 0..16 {
        let mut client_to_server = Vec::new();
        client
            .write_tls(&mut client_to_server)
            .expect("client should emit TLS handshake bytes");
        if !client_to_server.is_empty() {
            server
                .read_tls(&mut Cursor::new(client_to_server))
                .expect("server should receive TLS handshake bytes");
            server
                .process_new_packets()
                .expect("server should process TLS handshake bytes");
        }

        let mut server_to_client = Vec::new();
        server
            .write_tls(&mut server_to_client)
            .expect("server should emit TLS handshake bytes");
        if !server_to_client.is_empty() {
            client
                .read_tls(&mut Cursor::new(server_to_client))
                .expect("client should receive TLS handshake bytes");
            client
                .process_new_packets()
                .expect("client should process TLS handshake bytes");
        }

        if !client.is_handshaking() && !server.is_handshaking() {
            return;
        }
    }

    panic!("client/server TLS handshake did not complete within bounded exchanges");
}

fn test_ca_pem_material() -> (String, String, Vec<u8>) {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "NetworkCore engine-native test CA");
    distinguished_name.push(DnType::OrganizationName, "AnixOps NetworkCore");

    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];

    let key_pair = KeyPair::generate().expect("test CA private key should generate");
    let certificate = params
        .self_signed(&key_pair)
        .expect("test CA certificate should self-sign");
    (
        certificate.pem(),
        key_pair.serialize_pem(),
        certificate.der().as_ref().to_vec(),
    )
}

fn tls_client_hello_with_sni(hostname: &str) -> Vec<u8> {
    let hostname = hostname.as_bytes();
    let mut server_name = Vec::new();
    push_test_u16(&mut server_name, 1 + 2 + hostname.len());
    server_name.push(0x00);
    push_test_u16(&mut server_name, hostname.len());
    server_name.extend_from_slice(hostname);

    let mut extensions = Vec::new();
    push_test_u16(&mut extensions, 0x0000);
    push_test_u16(&mut extensions, server_name.len());
    extensions.extend_from_slice(&server_name);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0_u8; 32]);
    body.push(0x00);
    push_test_u16(&mut body, 2);
    body.extend_from_slice(&[0x13, 0x01]);
    body.push(1);
    body.push(0);
    push_test_u16(&mut body, extensions.len());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![0x01];
    push_test_u24(&mut handshake, body.len());
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x03];
    push_test_u16(&mut record, handshake.len());
    record.extend_from_slice(&handshake);
    record
}

fn push_test_u16(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend_from_slice(&(value as u16).to_be_bytes());
}

fn push_test_u24(bytes: &mut Vec<u8>, value: usize) {
    bytes.push(((value >> 16) & 0xff) as u8);
    bytes.push(((value >> 8) & 0xff) as u8);
    bytes.push((value & 0xff) as u8);
}

fn plugin_instance(id: &str) -> PluginInstance {
    PluginInstance {
        manifest: PluginManifest {
            id: id.to_string(),
            version: "0.1.0".to_string(),
            permissions: vec![
                PluginPermission::ReadRequest,
                PluginPermission::ModifyRequest,
            ],
            hooks: vec![HookPoint::Request],
        },
        loaded_source: None,
    }
}

fn read_test_socks5_connect_frame(stream: &mut TcpStream) -> Vec<u8> {
    let mut frame = Vec::new();
    let mut header = [0_u8; 4];
    stream
        .read_exact(&mut header)
        .expect("outbound stream should receive SOCKS5 CONNECT header");
    frame.extend_from_slice(&header);
    match header[3] {
        0x01 => {
            let mut address_and_port = [0_u8; 6];
            stream
                .read_exact(&mut address_and_port)
                .expect("outbound stream should receive IPv4 CONNECT target");
            frame.extend_from_slice(&address_and_port);
        }
        0x03 => {
            let mut length = [0_u8; 1];
            stream
                .read_exact(&mut length)
                .expect("outbound stream should receive domain target length");
            frame.push(length[0]);
            let mut domain_and_port = vec![0_u8; length[0] as usize + 2];
            stream
                .read_exact(&mut domain_and_port)
                .expect("outbound stream should receive domain CONNECT target");
            frame.extend_from_slice(&domain_and_port);
        }
        0x04 => {
            let mut address_and_port = [0_u8; 18];
            stream
                .read_exact(&mut address_and_port)
                .expect("outbound stream should receive IPv6 CONNECT target");
            frame.extend_from_slice(&address_and_port);
        }
        _ => panic!("unexpected SOCKS5 address type {}", header[3]),
    }
    frame
}

fn read_test_http_message(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream
            .read_exact(&mut byte)
            .expect("HTTP message header should be readable");
        bytes.push(byte[0]);
    }
    let header_text = String::from_utf8(bytes.clone()).expect("HTTP header should be UTF-8");
    let content_length = header_text
        .split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("Content-Length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0);
    let mut body = vec![0_u8; content_length];
    if content_length > 0 {
        stream
            .read_exact(&mut body)
            .expect("HTTP message body should be readable");
        bytes.extend_from_slice(&body);
    }
    String::from_utf8(bytes).expect("HTTP message should be valid UTF-8")
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "intentional test writer failure",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct PlainHttpRejectingMitmPluginService;

impl MitmPluginService for PlainHttpRejectingMitmPluginService {
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
        assert_eq!(plugin_instance.manifest.id, "networkcore.adblock");
        assert_eq!(http_event.method.as_deref(), Some("GET"));
        assert_eq!(http_event.url, "https://pubads.g.doubleclick.net/pagead/id");

        Ok(HttpMitmOutcome {
            action: HttpMitmAction::Reject { status_code: 403 },
            header_mutations: Vec::new(),
            body_mutation: None,
            script_dispatch: None,
            audits: vec![AuditEvent {
                actor: "networkcore.adblock".to_string(),
                action: "mitm.policy.plan_http_mitm_event".to_string(),
                decision: AuditDecision::Allowed,
                reason: Some("plain HTTP test reject plan".to_string()),
            }],
            diagnostics: vec![Diagnostic::new(
                DiagnosticSeverity::Info,
                "test.mitm.plain.plan.ready",
                "test plain HTTP MITM plan ready",
                Some("test.mitm".to_string()),
            )],
        })
    }

    fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent> {
        plugin_result.audits.clone()
    }
}

struct PlainHttpProxyRejectingMitmPluginService;

impl MitmPluginService for PlainHttpProxyRejectingMitmPluginService {
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
        assert_eq!(plugin_instance.manifest.id, "networkcore.adblock");
        assert_eq!(http_event.method.as_deref(), Some("GET"));
        assert_eq!(http_event.phase, HttpMitmPhase::Request);
        assert_eq!(http_event.url, "http://pubads.g.doubleclick.net/pagead/id");

        Ok(HttpMitmOutcome {
            action: HttpMitmAction::Reject { status_code: 403 },
            header_mutations: Vec::new(),
            body_mutation: None,
            script_dispatch: None,
            audits: Vec::new(),
            diagnostics: Vec::new(),
        })
    }

    fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent> {
        plugin_result.audits.clone()
    }
}

struct PlainHttpProxyRewriteMitmPluginService;

impl MitmPluginService for PlainHttpProxyRewriteMitmPluginService {
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
        assert_eq!(plugin_instance.manifest.id, "networkcore.rewrite");
        assert_eq!(http_event.url, "http://origin.example/upload");

        let (header_value, body) = match http_event.phase {
            HttpMitmPhase::Request => {
                assert_eq!(http_event.method.as_deref(), Some("POST"));
                ("request", b"new".to_vec())
            }
            HttpMitmPhase::Response => {
                assert_eq!(http_event.status_code, Some(200));
                ("response", b"response-new".to_vec())
            }
        };

        Ok(HttpMitmOutcome {
            action: HttpMitmAction::Continue,
            header_mutations: vec![HttpHeaderMutation {
                operation: HttpHeaderMutationOperation::Set,
                name: "X-NetworkCore-Rewritten".to_string(),
                value: Some(header_value.to_string()),
            }],
            body_mutation: Some(HttpBodyMutation {
                body,
                truncated: false,
            }),
            script_dispatch: None,
            audits: Vec::new(),
            diagnostics: Vec::new(),
        })
    }

    fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent> {
        plugin_result.audits.clone()
    }
}

struct ScriptDispatchingMitmPluginService {
    script_url: String,
}

impl MitmPluginService for ScriptDispatchingMitmPluginService {
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
        assert_eq!(plugin_instance.manifest.id, "networkcore.script");
        assert_eq!(http_event.phase, HttpMitmPhase::Request);
        assert_eq!(http_event.method.as_deref(), Some("POST"));

        Ok(HttpMitmOutcome {
            action: HttpMitmAction::Continue,
            header_mutations: Vec::new(),
            body_mutation: None,
            script_dispatch: Some(HttpMitmScriptDispatch {
                kind: HttpMitmScriptKind::Request,
                phase: HttpMitmPhase::Request,
                requires_body: true,
                timeout_ms: 1000,
                max_size: 1024,
                script_path: self.script_url.clone(),
                tag: "runtime.hook".to_string(),
                argument: "Mode=hook".to_string(),
            }),
            audits: Vec::new(),
            diagnostics: Vec::new(),
        })
    }

    fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent> {
        plugin_result.audits.clone()
    }
}

struct RejectingMitmPluginService;

impl MitmPluginService for RejectingMitmPluginService {
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
        assert_eq!(plugin_instance.manifest.id, "networkcore.adblock");
        assert_eq!(http_event.method.as_deref(), Some("CONNECT"));
        assert_eq!(http_event.url, "https://pubads.g.doubleclick.net/");

        Ok(HttpMitmOutcome {
            action: HttpMitmAction::Reject { status_code: 403 },
            header_mutations: Vec::new(),
            body_mutation: None,
            script_dispatch: None,
            audits: vec![AuditEvent {
                actor: "networkcore.adblock".to_string(),
                action: "mitm.policy.plan_http_mitm_event".to_string(),
                decision: AuditDecision::Allowed,
                reason: Some("test reject plan".to_string()),
            }],
            diagnostics: vec![Diagnostic::new(
                DiagnosticSeverity::Info,
                "test.mitm.plan.ready",
                "test MITM plan ready",
                Some("test.mitm".to_string()),
            )],
        })
    }

    fn audit(&self, plugin_result: &PluginResult) -> Vec<AuditEvent> {
        plugin_result.audits.clone()
    }
}

fn wait_until_accept_count(
    accept_loop: &NativeLoopbackTcpAcceptLoopHandle,
    expected_connections: usize,
) {
    for _ in 0..100 {
        if accept_loop.accepted_connections() >= expected_connections {
            return;
        }

        thread::sleep(Duration::from_millis(10));
    }

    panic!(
        "accept loop observed {} connections, expected at least {expected_connections}",
        accept_loop.accepted_connections()
    );
}

fn wait_until_pre_protocol_closed_count(
    accept_loop: &NativeLoopbackTcpAcceptLoopHandle,
    expected_connections: usize,
) {
    for _ in 0..100 {
        if accept_loop.pre_protocol_closed_connections() >= expected_connections {
            return;
        }

        thread::sleep(Duration::from_millis(10));
    }

    panic!(
        "accept loop pre-protocol closed {} connections, expected at least {expected_connections}",
        accept_loop.pre_protocol_closed_connections()
    );
}

fn wait_until_relayed_count(
    accept_loop: &NativeLoopbackTcpAcceptLoopHandle,
    expected_connections: usize,
) {
    for _ in 0..500 {
        if accept_loop.relayed_connections() >= expected_connections {
            return;
        }

        thread::sleep(Duration::from_millis(10));
    }

    panic!(
        "accept loop relayed {} connections, expected at least {expected_connections}",
        accept_loop.relayed_connections()
    );
}

fn unused_loopback_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .expect("test should allocate an ephemeral loopback tcp port");
    let port = listener
        .local_addr()
        .expect("ephemeral listener should expose its local address")
        .port();
    drop(listener);
    port
}
