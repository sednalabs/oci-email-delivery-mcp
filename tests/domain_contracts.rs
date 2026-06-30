use oci_email_delivery_mcp::{
    tests_support::FixtureBackend, EventsReport, EventsRequest, LedgerWindowRequest, MetricsReport,
    MetricsRequest, OciEmailBackend, OciEmailError, OciEmailStatusReport, SendReadinessRequest,
    StatusRequest, SuppressionsReport, SuppressionsRequest, TraceMessageReport,
    TraceMessageRequest, WatchWindowRequest,
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
            source_domain: Some("example.com".to_string()),
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

#[test]
fn ledger_window_contract_uses_hashes_and_domains_only() {
    let backend = FixtureBackend;
    let report = backend
        .ledger_window(&LedgerWindowRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            sender_domain: Some("example.com".to_string()),
            campaign_id: Some("campaign-private".to_string()),
            batch_id: Some("batch-private".to_string()),
            limit: Some(20),
        })
        .unwrap_or_else(|err| panic!("fixture ledger: {err}"));
    let payload =
        serde_json::to_string(&report).unwrap_or_else(|err| panic!("serialize ledger: {err}"));

    assert_eq!(report.status, "ok");
    assert_eq!(
        report.rows[0].recipient_domain,
        Some("example.net".to_string())
    );
    assert!(report.rows[0].recipient_address_hash.is_some());
    assert!(report.rows[0].message_id_hash.is_some());
    assert!(!report.raw_payload_returned);
    assert!(!report.rows[0].raw_recipient_returned);
    assert!(!payload.contains("person@example.net"));
    assert!(!payload.contains("message@example.com"));
    assert!(!payload.contains("campaign-private"));
    assert!(!payload.contains("batch-private"));
}

#[test]
fn watch_window_contract_composes_receipt_without_authorizing_send() {
    let backend = FixtureBackend;
    let report = backend
        .watch_window(&WatchWindowRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: None,
            resource_id: None,
            message_id: Some("message@example.com".to_string()),
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("fixture watch window: {err}"));
    let payload =
        serde_json::to_string(&report).unwrap_or_else(|err| panic!("serialize watch: {err}"));

    assert_eq!(report.status, "degraded");
    assert_eq!(report.decision, "hold_or_seed_only_with_operator_review");
    assert!(!report.send_authorized);
    assert_eq!(report.resource_domain, Some("example.com".to_string()));
    assert_eq!(report.source_domain, Some("example.com".to_string()));
    assert!(report.trace_requested);
    assert_eq!(report.components.metrics.status, "degraded");
    assert_eq!(report.components.events.status, "ok");
    assert_eq!(report.components.suppressions.status, "ok");
    assert!(report.components.trace.is_some());
    assert_eq!(
        report
            .components
            .trace
            .as_ref()
            .and_then(|trace| trace.report.as_ref())
            .and_then(|trace| trace.events.filters.source_domain.as_deref()),
        Some("example.com")
    );
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "metric_unavailable_hard_bounced"));
    assert!(!report.raw_payload_returned);
    assert!(!payload.contains("message@example.com"));
    assert!(!payload.contains("person@example.net"));
    assert!(!payload.contains("person@example.com"));
}

#[test]
fn send_readiness_contract_requires_monitoring_and_ledger_without_authorizing_send() {
    let backend = FixtureBackend;
    let report = backend
        .send_readiness(&SendReadinessRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: None,
            resource_id: None,
            sender_domain: None,
            campaign_id: "campaign-token-123".to_string(),
            batch_id: "batch-token-456".to_string(),
            expected_ledger_rows: 1,
            message_id: Some("message-token-789".to_string()),
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("fixture send readiness: {err}"));
    let payload = serde_json::to_string(&report)
        .unwrap_or_else(|err| panic!("serialize send readiness: {err}"));

    assert_eq!(report.status, "degraded");
    assert_eq!(report.decision, "hold_or_seed_only_with_operator_review");
    assert!(!report.send_authorized);
    assert_eq!(report.sender_domain, Some("example.com".to_string()));
    assert_eq!(report.expected_ledger_rows, 1);
    assert_eq!(report.components.watch_window.status, "degraded");
    assert_eq!(report.components.ledger.status, "ok");
    assert_eq!(
        report
            .components
            .ledger
            .report
            .as_ref()
            .map(|ledger| ledger.totals.matched_rows),
        Some(1)
    );
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "metric_unavailable_hard_bounced"));
    assert!(!report.raw_payload_returned);
    assert!(!payload.contains("message-token-789"));
    let fixture_recipient = ["person", "example.net"].join("@");
    assert!(!payload.contains(&fixture_recipient));
    assert!(!payload.contains("campaign-token-123"));
    assert!(!payload.contains("batch-token-456"));
}

#[test]
fn send_readiness_blocks_ambiguous_or_mismatched_ledger_counts() {
    let backend = FixtureBackend;
    let report = backend
        .send_readiness(&SendReadinessRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            sender_domain: Some("example.com".to_string()),
            campaign_id: "campaign-token-123".to_string(),
            batch_id: "batch-token-456".to_string(),
            expected_ledger_rows: 2,
            message_id: None,
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("fixture send readiness: {err}"));

    assert_eq!(report.status, "blocked");
    assert_eq!(report.decision, "remain_paused");
    assert!(!report.send_authorized);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "ledger_expected_rows_mismatch"));
}

#[test]
fn send_readiness_skips_ledger_read_when_required_identifiers_are_missing() {
    let backend = FixtureBackend;
    let report = backend
        .send_readiness(&SendReadinessRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            sender_domain: Some("example.com".to_string()),
            campaign_id: "  ".to_string(),
            batch_id: "".to_string(),
            expected_ledger_rows: 0,
            message_id: None,
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("fixture send readiness: {err}"));

    assert_eq!(report.status, "blocked");
    assert_eq!(report.decision, "remain_paused");
    assert_eq!(report.components.ledger.status, "blocked");
    assert!(report.components.ledger.report.is_none());
    assert!(report.components.ledger.error.is_some());
    for code in [
        "campaign_id_missing",
        "batch_id_missing",
        "expected_ledger_rows_zero",
        "ledger_requirements_missing",
    ] {
        assert!(
            report.findings.iter().any(|finding| finding.code == code),
            "missing finding {code}"
        );
    }
}

#[test]
fn send_readiness_redacts_returned_trace_header_names() {
    let backend = FixtureBackend;
    let report = backend
        .send_readiness(&SendReadinessRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            sender_domain: Some("example.com".to_string()),
            campaign_id: "campaign-token-123".to_string(),
            batch_id: "batch-token-456".to_string(),
            expected_ledger_rows: 1,
            message_id: None,
            header_name: Some("X-Trace-Example".to_string()),
            header_value: Some("trace-token-example".to_string()),
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("fixture send readiness: {err}"));
    let payload = serde_json::to_string(&report)
        .unwrap_or_else(|err| panic!("serialize send readiness: {err}"));

    assert_eq!(
        report
            .components
            .watch_window
            .report
            .as_ref()
            .and_then(|watch| watch.components.trace.as_ref())
            .and_then(|trace| trace.report.as_ref())
            .and_then(|trace| trace.criteria.header_name.as_deref()),
        Some("[redacted]")
    );
    assert!(!payload.contains("X-Trace-Example"));
    assert!(!payload.contains("trace-token-example"));
}

#[test]
fn watch_window_reports_component_failures_without_aborting_receipt() {
    let backend = MetricsFailureBackend;
    let report = backend
        .watch_window(&WatchWindowRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            message_id: None,
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("fixture watch window: {err}"));

    assert_eq!(report.status, "blocked");
    assert_eq!(report.decision, "remain_paused");
    assert!(!report.send_authorized);
    assert_eq!(report.components.status.status, "degraded");
    assert_eq!(report.components.metrics.status, "blocked");
    assert!(report.components.metrics.error.is_some());
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "metrics_read_blocked"));
}

#[test]
fn watch_window_blocks_unscoped_lane_receipts() {
    let backend = FixtureBackend;
    let report = backend
        .watch_window(&WatchWindowRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: None,
            source_domain: None,
            resource_id: None,
            message_id: None,
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("fixture watch window: {err}"));

    assert_eq!(report.status, "blocked");
    assert_eq!(report.decision, "remain_paused");
    assert!(!report.send_authorized);
    assert_eq!(report.components.metrics.status, "blocked");
    assert!(report.components.metrics.report.is_none());
    assert_eq!(report.components.events.status, "blocked");
    assert!(report.components.events.report.is_none());
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "metrics_scope_missing"));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "events_scope_missing"));
}

struct MetricsFailureBackend;

impl OciEmailBackend for MetricsFailureBackend {
    fn status(&self, request: &StatusRequest) -> Result<OciEmailStatusReport, OciEmailError> {
        FixtureBackend.status(request)
    }

    fn metrics(&self, _request: &MetricsRequest) -> Result<MetricsReport, OciEmailError> {
        Err(OciEmailError::InvalidInput(
            "synthetic metrics failure".to_string(),
        ))
    }

    fn events(&self, request: &EventsRequest) -> Result<EventsReport, OciEmailError> {
        FixtureBackend.events(request)
    }

    fn trace_message(
        &self,
        request: &TraceMessageRequest,
    ) -> Result<TraceMessageReport, OciEmailError> {
        FixtureBackend.trace_message(request)
    }

    fn suppressions(
        &self,
        request: &SuppressionsRequest,
    ) -> Result<SuppressionsReport, OciEmailError> {
        FixtureBackend.suppressions(request)
    }
}
