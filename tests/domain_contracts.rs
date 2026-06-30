use oci_email_delivery_mcp::{
    tests_support::FixtureBackend, EventsRequest, MetricsRequest, OciEmailBackend,
    SuppressionsRequest, TraceMessageRequest,
};

#[test]
fn status_contract_is_redacted_and_no_send() {
    let backend = FixtureBackend;
    let report = backend
        .status(&oci_email_delivery_mcp::StatusRequest {
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("fixture status: {err}"));
    let payload =
        serde_json::to_string(&report).unwrap_or_else(|err| panic!("serialize status: {err}"));

    assert!(!report.send_authorized);
    assert!(payload.contains("ocid1.tenancy:fixture"));
    assert!(!payload.contains("ocid1.tenancy.oc1"));
    assert!(!payload.contains("@example.com"));
}

#[test]
fn metrics_contract_includes_stop_thresholds_and_missing_metric_findings() {
    let backend = FixtureBackend;
    let report = backend
        .metrics(&MetricsRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            resource_id: None,
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("fixture metrics: {err}"));

    assert_eq!(report.namespace, "oci_emaildelivery");
    assert_eq!(report.thresholds.hard_bounce_pause_percent, 0.55);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "metric_unavailable_hard_bounced"));
}

#[test]
fn events_contract_does_not_return_raw_recipient_or_message_id() {
    let backend = FixtureBackend;
    let report = backend
        .events(&EventsRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            action: Some("relay".to_string()),
            message_id: Some("message@example.com".to_string()),
            header_name: None,
            header_value: None,
            receiving_domain: Some("example.net".to_string()),
            source_domain: Some("example.com".to_string()),
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("fixture events: {err}"));
    let payload =
        serde_json::to_string(&report).unwrap_or_else(|err| panic!("serialize events: {err}"));

    assert!(!report.events[0].raw_payload_returned);
    assert!(!payload.contains("message@example.com"));
    assert!(!payload.contains("person@example.net"));
}

#[test]
fn trace_requires_a_redacted_criteria_shape() {
    let backend = FixtureBackend;
    let report = backend
        .trace_message(&TraceMessageRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            message_id: Some("message@example.com".to_string()),
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("fixture trace: {err}"));

    assert_eq!(report.criteria.message_id_hash, Some("fixture".to_string()));
    assert!(!report.events.events[0].raw_payload_returned);
}

#[test]
fn suppressions_contract_uses_hash_and_domain_only() {
    let backend = FixtureBackend;
    let report = backend
        .suppressions(&SuppressionsRequest {
            time_created_greater_than_or_equal_to: None,
            time_created_less_than: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("fixture suppressions: {err}"));
    let payload = serde_json::to_string(&report)
        .unwrap_or_else(|err| panic!("serialize suppressions: {err}"));

    assert_eq!(
        report.suppressions[0].recipient_domain,
        Some("example.com".to_string())
    );
    assert_eq!(
        report.suppressions[0].recipient_hash,
        Some("fixture".to_string())
    );
    assert!(!payload.contains("person@example.com"));
}
