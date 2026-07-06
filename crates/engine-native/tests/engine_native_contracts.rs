use control_domain::{
    ConfigSnapshot, Diagnostic, Endpoint, ListenerBind, ListenerDescriptor, ListenerKind,
    ListenerNetwork, ListenerRoute, MetadataEntry, NodeDescriptor, Protocol, ProxyEngineConfig,
    ProxyEngineEventKind, ProxyEngineKind, ProxyEngineLifecycleState, ProxyEngineService,
    RouteAction, RuleSet, SchemaVersion,
};
use engine_native::{
    attempt_socks5_outbound_tcp_connection, build_socks5_outbound_connect_request_frame,
    assess_socks5_outbound_connect_relay_readiness, decide_socks5_outbound_connect_response,
    plan_socks5_outbound_tcp_connection, read_socks5_command_header, read_socks5_connect_target,
    read_socks5_greeting, read_socks5_outbound_connect_response, reject_unsupported_socks5_command,
    reject_unwired_socks5_route_outbound, select_socks5_auth_method,
    select_socks5_route_outbound_behavior, write_socks5_auth_method_response,
    write_socks5_outbound_connect_request, write_unwired_socks5_connect_failure_response,
    BoundLoopbackTcpListenerHandle, LoopbackListenerHandle, NativeLoopbackTcpAcceptLoopHandle,
    NativeOutboundHandlerHandle, NativeProxyEngineService, NativeRuntimeAssembly,
    NativeRuntimeAssemblyPlan, NativeSocks5Address, NativeSocks5AuthMethodDecision,
    NativeSocks5CommandDecision, NativeSocks5CommandHeader, NativeSocks5ConnectTarget,
    NativeSocks5Greeting, NativeSocks5OutboundConnectResponseDecision,
    NativeSocks5OutboundConnectRelayReadiness, NativeSocks5OutboundTcpConnectionPlan,
    NativeSocks5RouteOutboundBehavior, NativeSocks5RouteOutboundDecision, DEFAULT_NATIVE_ENGINE_ID,
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
    ENGINE_NATIVE_RUNTIME_LISTENER_DISABLED_CODE, ENGINE_NATIVE_RUNTIME_LISTENER_NON_LOOPBACK_CODE,
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
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_GENERATED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_FRAME_INVALID_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITE_FAILED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_REQUEST_WRITTEN_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_REJECTED_CODE,
    ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_UNWIRED_CODE,
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
    ENGINE_NATIVE_START_LIFECYCLE_FAILED_CODE, ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE,
};
use std::io::{self, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
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
fn validate_config_reports_unimplemented_listener_and_node_protocols() {
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

    assert_diagnostic(
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
fn start_rejects_until_real_runtime_handle_exists() {
    let service = NativeProxyEngineService::new();
    let engine_config = config(DEFAULT_NATIVE_ENGINE_ID, vec![node()]);

    let error = service
        .start(&engine_config)
        .expect_err("native runtime handle is intentionally unavailable");

    assert_eq!(error.code, ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE);
}

#[test]
fn runtime_handle_contract_builds_foreground_handoff_without_service_start_wiring() {
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

    let service = NativeProxyEngineService::new();
    let engine_config = config(DEFAULT_NATIVE_ENGINE_ID, vec![node()]);
    let error = service
        .start(&engine_config)
        .expect_err("service start remains intentionally unavailable");

    assert_eq!(error.code, ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE);
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
fn runtime_accept_loop_contract_checks_socks5_outbound_relay_readiness_before_unwired_failure() {
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
    let (frame_tx, frame_rx) = mpsc::channel();
    let outbound_worker = thread::spawn(move || {
        for _ in 0..100 {
            match outbound_listener.accept() {
                Ok((mut outbound_stream, _)) => {
                    outbound_stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
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
        .write_all(&[
            0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb,
        ])
        .expect("test client should send a SOCKS5 greeting, CONNECT header, and IPv4 target");
    wait_until_accept_count(&accept_loop, 1);
    wait_until_pre_protocol_closed_count(&accept_loop, 1);
    let outbound_frame = frame_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("accept loop should write the outbound SOCKS5 CONNECT request frame");
    drop(stream);

    let report = accept_loop.shutdown();
    outbound_worker
        .join()
        .expect("outbound frame capture worker should finish");

    assert_eq!(
        outbound_frame,
        vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb]
    );
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
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_UNWIRED_CODE,
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
fn socks5_outbound_connect_relay_readiness_contract_blocks_accepted_response_without_relay() {
    let mut reader = Cursor::new(vec![0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38]);
    let read_report = read_socks5_outbound_connect_response(&mut reader);
    let response = read_report
        .response
        .expect("valid SOCKS5 outbound CONNECT response should be parsed");
    let decision_report = decide_socks5_outbound_connect_response(&response);

    let readiness_report =
        assess_socks5_outbound_connect_relay_readiness(decision_report.decision);

    assert_eq!(
        readiness_report.readiness,
        NativeSocks5OutboundConnectRelayReadiness::Blocked
    );
    assert_diagnostic(
        &readiness_report.diagnostics,
        ENGINE_NATIVE_RUNTIME_SOCKS5_OUTBOUND_CONNECT_RELAY_UNWIRED_CODE,
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

    let readiness_report =
        assess_socks5_outbound_connect_relay_readiness(decision_report.decision);

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

    let start_error = service
        .start(&engine_config)
        .expect_err("service start remains intentionally unavailable");

    assert_eq!(
        start_error.code,
        ENGINE_NATIVE_START_RUNTIME_UNAVAILABLE_CODE
    );

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
