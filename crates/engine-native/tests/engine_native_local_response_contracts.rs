//! Contracts for `HttpMitmAction::Respond` (Loon `[Map Local]`) on the plain
//! HTTP data plane.

use control_domain::{HttpMitmAction, HttpMitmOutcome, HttpMitmPhase, MetadataEntry};
use engine_native::{
    apply_http_mitm_outcome_to_plain_http_message, NativePlainHttpMessage,
    LOCAL_RESPONSE_TERMINAL_ACTION,
};

#[test]
fn respond_action_replaces_the_request_with_a_local_response() {
    let message = NativePlainHttpMessage {
        request_id: "map-local".to_string(),
        url: "https://api.networkcore.test/v1/ads".to_string(),
        method: Some("GET".to_string()),
        phase: HttpMitmPhase::Request,
        status_code: None,
        headers: vec![MetadataEntry {
            key: "Host".to_string(),
            value: "api.networkcore.test".to_string(),
        }],
        body: Vec::new(),
    };
    let outcome = HttpMitmOutcome {
        action: HttpMitmAction::Respond {
            status_code: 200,
            headers: vec![
                MetadataEntry {
                    key: "Content-Type".to_string(),
                    value: "application/json".to_string(),
                },
                MetadataEntry {
                    key: "Content-Length".to_string(),
                    value: "999".to_string(),
                },
            ],
            body: br#"{"ads":[]}"#.to_vec(),
        },
        header_mutations: Vec::new(),
        body_mutation: None,
        script_dispatch: None,
        audits: Vec::new(),
        diagnostics: Vec::new(),
    };

    let application = apply_http_mitm_outcome_to_plain_http_message(&message, &outcome);

    assert!(application.applied);
    assert_eq!(
        application.terminal_action.as_deref(),
        Some(LOCAL_RESPONSE_TERMINAL_ACTION)
    );
    assert_eq!(application.final_status_code, Some(200));
    assert_eq!(application.body, br#"{"ads":[]}"#);
    let headers = application
        .headers
        .iter()
        .map(|header| (header.key.as_str(), header.value.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        headers,
        vec![
            ("Content-Type", "application/json"),
            ("Content-Length", "10")
        ]
    );
}
