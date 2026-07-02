use oci_email_delivery_mcp::{
    tests_support::FixtureBackend, EventFilters, EventsReport, EventsRequest, LedgerRowSummary,
    LedgerWindowFilters, LedgerWindowReport, LedgerWindowRequest, LedgerWindowTotals,
    LoggingEnablementPlanRequest, LoggingStatusRequest, MetricsReport, MetricsRequest,
    OciEmailBackend, OciEmailError, OciEmailStatusReport, SendReadinessRequest, StatusRequest,
    SuppressionsReport, SuppressionsRequest, TraceCriteria, TraceMessageReport,
    TraceMessageRequest, TraceabilityAuditRequest, WatchWindowRequest,
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
    assert!(payload.contains("[redacted-ocid:tenancy:fixture]"));
    assert!(!payload.contains("ocid1."));
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
fn watch_window_normalizes_iso_interval_before_metrics_read() {
    let backend = EchoIntervalBackend;
    let report = backend
        .watch_window(&WatchWindowRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T00:05:00Z".to_string(),
            interval: Some("PT1M".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            message_id: None,
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("watch window: {err}"));

    assert_eq!(report.interval, "1m");
    assert_eq!(report.components.metrics.report.unwrap().interval, "1m");
}

#[test]
fn watch_window_blocks_invalid_interval_before_metrics_backend() {
    let backend = EchoIntervalBackend;
    let report = backend
        .watch_window(&WatchWindowRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T00:05:00Z".to_string(),
            interval: Some("PT2M".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            message_id: None,
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("watch window: {err}"));

    assert_eq!(report.status, "blocked");
    assert_eq!(report.components.metrics.status, "blocked");
    assert!(report.components.metrics.report.is_none());
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "metrics_interval_invalid"));
    assert!(report
        .components
        .metrics
        .error
        .as_ref()
        .is_some_and(|error| error.error == "invalid_input"));
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
fn logging_status_contract_is_read_only_and_redacted() {
    let backend = FixtureBackend;
    let report = backend
        .logging_status(&LoggingStatusRequest {
            compartment_id: None,
            resource_domain: None,
            resource_id: Some("ocid1.emaildomain.oc1.example".to_string()),
            limit: Some(20),
        })
        .unwrap_or_else(|err| panic!("fixture logging status: {err}"));
    let payload = serde_json::to_string(&report)
        .unwrap_or_else(|err| panic!("serialize logging status: {err}"));

    assert_eq!(report.status, "ok");
    assert!(!report.send_authorized);
    assert!(report.requested_resource_id.present);
    assert_eq!(report.email_delivery_log_count, 1);
    assert_eq!(report.active_email_delivery_log_count, 1);
    assert_eq!(report.matching_requested_resource_log_count, 1);
    assert_eq!(report.active_matching_requested_resource_log_count, 1);
    assert!(!report.email_delivery_logs[0].raw_payload_returned);
    assert!(report.email_delivery_logs[0].source_resource.present);
    assert!(!payload.contains("ocid1."));
    assert!(!payload.contains("Email Delivery"));
}

#[test]
fn logging_enablement_plan_is_read_only_and_redacted() {
    let backend = FixtureBackend;
    let report = backend
        .logging_enablement_plan(&LoggingEnablementPlanRequest {
            compartment_id: None,
            resource_domain: None,
            resource_id: Some("ocid1.emaildomain.oc1.example".to_string()),
            limit: Some(20),
        })
        .unwrap_or_else(|err| panic!("fixture logging enablement plan: {err}"));
    let payload = serde_json::to_string(&report)
        .unwrap_or_else(|err| panic!("serialize logging enablement plan: {err}"));

    assert_eq!(report.status, "already_visible_no_apply_needed");
    assert_eq!(report.decision, "already_visible_no_apply_needed");
    assert!(!report.send_authorized);
    assert!(!report.provider_mutation_authorized);
    assert!(!report.provider_mutation_required);
    assert_eq!(
        report.required_log_categories,
        vec![
            "emaildelivery.emaildomain.outboundaccepted",
            "emaildelivery.emaildomain.outboundrelayed"
        ]
    );
    assert!(report.requested_resource_id.present);
    assert_eq!(report.current_logging.status, "ok");
    assert!(!report.raw_payload_returned);
    assert!(!payload.contains("ocid1."));
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
    assert_eq!(report.returned, 2);
    assert_eq!(report.totals.hard_bounce, 1);
    assert!(report
        .totals
        .by_reason
        .iter()
        .any(|item| item.key == "hardbounce" && item.count == 1));
    assert!(report
        .totals
        .by_reason
        .iter()
        .any(|item| item.key == "complaint" && item.count == 1));
    assert!(report
        .totals
        .by_recipient_domain
        .iter()
        .any(|item| item.key == "example.com" && item.count == 1));
    assert!(report
        .totals
        .by_recipient_domain
        .iter()
        .any(|item| item.key == "example.net" && item.count == 1));
    assert!(!payload.contains("person@example.com"));
    assert!(!payload.contains("person@example.net"));
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
    assert_eq!(report.components.logging.status, "ok");
    assert_eq!(
        report
            .components
            .logging
            .report
            .as_ref()
            .map(|logging| logging.active_matching_requested_resource_log_count),
        Some(1)
    );
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
fn traceability_audit_distinguishes_exact_overlap_from_aggregate_pressure() {
    let backend = FixtureBackend;
    let report = backend
        .traceability_audit(&TraceabilityAuditRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            sender_domain: None,
            campaign_id: None,
            batch_id: None,
            expected_ledger_rows: Some(1),
            message_id: Some("message-token-789".to_string()),
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("fixture traceability audit: {err}"));
    let payload = serde_json::to_string(&report)
        .unwrap_or_else(|err| panic!("serialize traceability audit: {err}"));

    assert!(report.exact_message_traceable);
    assert!(!report.aggregate_only);
    assert!(!report.send_authorized);
    assert_eq!(report.summary.log_events_returned, 1);
    assert_eq!(report.summary.trace_events_returned, Some(1));
    assert_eq!(report.summary.ledger_rows_matched, 1);
    assert!(report.summary.ledger_trace_key_overlap);
    assert!(report.summary.recipient_hash_overlap);
    assert!(report.summary.single_ledger_row_overlap);
    assert_eq!(report.components.ledger.status, "ok");
    assert!(!report
        .findings
        .iter()
        .any(|finding| finding.code == "traceability_aggregate_only"));
    assert!(!payload.contains("message-token-789"));
    assert!(!payload.contains("campaign-private"));
    assert!(!payload.contains("batch-private"));
    let fixture_recipient = ["person", "example.net"].join("@");
    assert!(!payload.contains(&fixture_recipient));
}

#[test]
fn traceability_audit_blocks_when_metrics_exist_but_logs_and_ledger_do_not_match() {
    let backend = AggregateOnlyBackend;
    let report = backend
        .traceability_audit(&TraceabilityAuditRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            sender_domain: Some("example.com".to_string()),
            campaign_id: None,
            batch_id: None,
            expected_ledger_rows: Some(1),
            message_id: Some("message-token-789".to_string()),
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("aggregate-only traceability audit: {err}"));

    assert_eq!(report.status, "blocked");
    assert_eq!(report.decision, "remain_paused");
    assert!(!report.exact_message_traceable);
    assert!(report.aggregate_only);
    assert_eq!(report.summary.aggregate_accepted, Some(10.0));
    assert_eq!(report.summary.log_events_returned, 0);
    assert_eq!(report.summary.trace_events_returned, Some(0));
    assert_eq!(report.summary.ledger_rows_matched, 0);
    for code in [
        "traceability_no_log_events",
        "traceability_no_trace_events",
        "traceability_no_ledger_rows",
        "traceability_expected_ledger_rows_mismatch",
        "traceability_aggregate_only",
    ] {
        assert!(
            report.findings.iter().any(|finding| finding.code == code),
            "missing finding {code}"
        );
    }
}

#[test]
fn traceability_audit_requires_requested_trace_recipient_overlap() {
    let backend = MismatchedTraceRecipientBackend;
    let report = backend
        .traceability_audit(&TraceabilityAuditRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            sender_domain: Some("example.com".to_string()),
            campaign_id: None,
            batch_id: None,
            expected_ledger_rows: Some(1),
            message_id: Some("message-token-789".to_string()),
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("mismatched trace recipient audit: {err}"));

    assert_eq!(report.status, "blocked");
    assert_eq!(report.decision, "remain_paused");
    assert!(!report.exact_message_traceable);
    assert!(report.aggregate_only);
    assert!(report.summary.ledger_trace_key_overlap);
    assert!(!report.summary.recipient_hash_overlap);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "traceability_no_recipient_hash_overlap"));
}

#[test]
fn traceability_audit_requires_requested_trace_key_overlap() {
    let backend = MismatchedTraceKeyBackend;
    let report = backend
        .traceability_audit(&TraceabilityAuditRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            sender_domain: Some("example.com".to_string()),
            campaign_id: None,
            batch_id: None,
            expected_ledger_rows: Some(1),
            message_id: Some("message-token-789".to_string()),
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("mismatched trace key audit: {err}"));

    assert_eq!(report.status, "blocked");
    assert_eq!(report.decision, "remain_paused");
    assert!(!report.exact_message_traceable);
    assert!(report.aggregate_only);
    assert!(!report.summary.ledger_trace_key_overlap);
    assert!(report.summary.recipient_hash_overlap);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "traceability_no_ledger_trace_key_overlap"));
}

#[test]
fn traceability_audit_requires_same_ledger_row_for_trace_and_recipient_overlap() {
    let backend = SplitLedgerOverlapBackend;
    let report = backend
        .traceability_audit(&TraceabilityAuditRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            sender_domain: Some("example.com".to_string()),
            campaign_id: None,
            batch_id: None,
            expected_ledger_rows: Some(2),
            message_id: Some("message-token-789".to_string()),
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("split ledger overlap audit: {err}"));

    assert_eq!(report.status, "blocked");
    assert_eq!(report.decision, "remain_paused");
    assert!(!report.exact_message_traceable);
    assert!(report.aggregate_only);
    assert!(report.summary.ledger_trace_key_overlap);
    assert!(report.summary.recipient_hash_overlap);
    assert!(!report.summary.single_ledger_row_overlap);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "traceability_no_single_ledger_row_overlap"));
}

#[test]
fn traceability_audit_blocks_explicit_zero_expected_rows() {
    let backend = FixtureBackend;
    let report = backend
        .traceability_audit(&TraceabilityAuditRequest {
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            interval: Some("1h".to_string()),
            resource_domain: Some("example.com".to_string()),
            source_domain: Some("example.com".to_string()),
            resource_id: None,
            sender_domain: Some("example.com".to_string()),
            campaign_id: None,
            batch_id: None,
            expected_ledger_rows: Some(0),
            message_id: Some("message-token-789".to_string()),
            header_name: None,
            header_value: None,
            limit: Some(20),
            compartment_id: None,
        })
        .unwrap_or_else(|err| panic!("zero-row traceability audit: {err}"));

    assert_eq!(report.status, "blocked");
    assert_eq!(report.decision, "remain_paused");
    assert!(!report.exact_message_traceable);
    assert!(report.aggregate_only);
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.code == "traceability_expected_ledger_rows_zero"));
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
    assert_eq!(report.components.logging.status, "ok");
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
    assert_eq!(report.components.logging.status, "blocked");
    assert!(report.components.logging.report.is_none());
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

    fn logging_status(
        &self,
        request: &LoggingStatusRequest,
    ) -> Result<oci_email_delivery_mcp::LoggingStatusReport, OciEmailError> {
        FixtureBackend.logging_status(request)
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

struct EchoIntervalBackend;

impl OciEmailBackend for EchoIntervalBackend {
    fn status(&self, request: &StatusRequest) -> Result<OciEmailStatusReport, OciEmailError> {
        FixtureBackend.status(request)
    }

    fn metrics(&self, request: &MetricsRequest) -> Result<MetricsReport, OciEmailError> {
        let mut report = FixtureBackend.metrics(request)?;
        report.interval = request.interval.clone().unwrap_or_else(|| "1h".to_string());
        Ok(report)
    }

    fn logging_status(
        &self,
        request: &LoggingStatusRequest,
    ) -> Result<oci_email_delivery_mcp::LoggingStatusReport, OciEmailError> {
        FixtureBackend.logging_status(request)
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

struct AggregateOnlyBackend;

impl OciEmailBackend for AggregateOnlyBackend {
    fn status(&self, request: &StatusRequest) -> Result<OciEmailStatusReport, OciEmailError> {
        FixtureBackend.status(request)
    }

    fn metrics(&self, request: &MetricsRequest) -> Result<MetricsReport, OciEmailError> {
        FixtureBackend.metrics(request)
    }

    fn logging_status(
        &self,
        request: &LoggingStatusRequest,
    ) -> Result<oci_email_delivery_mcp::LoggingStatusReport, OciEmailError> {
        FixtureBackend.logging_status(request)
    }

    fn events(&self, request: &EventsRequest) -> Result<EventsReport, OciEmailError> {
        Ok(empty_events(
            &request.start_time,
            &request.end_time,
            request.source_domain.clone(),
        ))
    }

    fn trace_message(
        &self,
        request: &TraceMessageRequest,
    ) -> Result<TraceMessageReport, OciEmailError> {
        Ok(TraceMessageReport {
            status: "ok".to_string(),
            criteria: TraceCriteria {
                message_id_hash: request.message_id.as_ref().map(|_| "unmatched".to_string()),
                header_name: request.header_name.clone(),
                header_value_hash: request
                    .header_value
                    .as_ref()
                    .map(|_| "unmatched".to_string()),
            },
            events: empty_events(
                &request.start_time,
                &request.end_time,
                request.source_domain.clone(),
            ),
        })
    }

    fn suppressions(
        &self,
        request: &SuppressionsRequest,
    ) -> Result<SuppressionsReport, OciEmailError> {
        FixtureBackend.suppressions(request)
    }

    fn ledger_window(
        &self,
        request: &LedgerWindowRequest,
    ) -> Result<LedgerWindowReport, OciEmailError> {
        Ok(LedgerWindowReport {
            status: "ok".to_string(),
            start_time: request.start_time.clone(),
            end_time: request.end_time.clone(),
            filters: LedgerWindowFilters {
                sender_domain: request.sender_domain.clone(),
                campaign_hash: None,
                batch_hash: None,
            },
            limit: request.limit.unwrap_or(20),
            totals: LedgerWindowTotals {
                scanned_rows: 0,
                matched_rows: 0,
                returned_rows: 0,
                invalid_rows: 0,
                rows_capped: false,
                missing_trace_key_count: 0,
                missing_recipient_key_count: 0,
            },
            sender_domains: Vec::new(),
            campaigns: Vec::new(),
            batches: Vec::new(),
            rows: Vec::new(),
            findings: Vec::new(),
            evidence: Vec::new(),
            raw_payload_returned: false,
        })
    }
}

struct MismatchedTraceRecipientBackend;

impl OciEmailBackend for MismatchedTraceRecipientBackend {
    fn status(&self, request: &StatusRequest) -> Result<OciEmailStatusReport, OciEmailError> {
        FixtureBackend.status(request)
    }

    fn metrics(&self, request: &MetricsRequest) -> Result<MetricsReport, OciEmailError> {
        FixtureBackend.metrics(request)
    }

    fn logging_status(
        &self,
        request: &LoggingStatusRequest,
    ) -> Result<oci_email_delivery_mcp::LoggingStatusReport, OciEmailError> {
        FixtureBackend.logging_status(request)
    }

    fn events(&self, request: &EventsRequest) -> Result<EventsReport, OciEmailError> {
        FixtureBackend.events(request)
    }

    fn trace_message(
        &self,
        request: &TraceMessageRequest,
    ) -> Result<TraceMessageReport, OciEmailError> {
        let mut report = FixtureBackend.trace_message(request)?;
        for event in &mut report.events.events {
            event.recipient_hash = Some("trace-recipient-only".to_string());
        }
        Ok(report)
    }

    fn suppressions(
        &self,
        request: &SuppressionsRequest,
    ) -> Result<SuppressionsReport, OciEmailError> {
        FixtureBackend.suppressions(request)
    }

    fn ledger_window(
        &self,
        request: &LedgerWindowRequest,
    ) -> Result<LedgerWindowReport, OciEmailError> {
        FixtureBackend.ledger_window(request)
    }
}

struct MismatchedTraceKeyBackend;

impl OciEmailBackend for MismatchedTraceKeyBackend {
    fn status(&self, request: &StatusRequest) -> Result<OciEmailStatusReport, OciEmailError> {
        FixtureBackend.status(request)
    }

    fn metrics(&self, request: &MetricsRequest) -> Result<MetricsReport, OciEmailError> {
        FixtureBackend.metrics(request)
    }

    fn logging_status(
        &self,
        request: &LoggingStatusRequest,
    ) -> Result<oci_email_delivery_mcp::LoggingStatusReport, OciEmailError> {
        FixtureBackend.logging_status(request)
    }

    fn events(&self, request: &EventsRequest) -> Result<EventsReport, OciEmailError> {
        FixtureBackend.events(request)
    }

    fn trace_message(
        &self,
        request: &TraceMessageRequest,
    ) -> Result<TraceMessageReport, OciEmailError> {
        let mut report = FixtureBackend.trace_message(request)?;
        report.criteria.message_id_hash = Some("trace-key-only".to_string());
        report.criteria.header_value_hash = None;
        Ok(report)
    }

    fn suppressions(
        &self,
        request: &SuppressionsRequest,
    ) -> Result<SuppressionsReport, OciEmailError> {
        FixtureBackend.suppressions(request)
    }

    fn ledger_window(
        &self,
        request: &LedgerWindowRequest,
    ) -> Result<LedgerWindowReport, OciEmailError> {
        FixtureBackend.ledger_window(request)
    }
}

struct SplitLedgerOverlapBackend;

impl OciEmailBackend for SplitLedgerOverlapBackend {
    fn status(&self, request: &StatusRequest) -> Result<OciEmailStatusReport, OciEmailError> {
        FixtureBackend.status(request)
    }

    fn metrics(&self, request: &MetricsRequest) -> Result<MetricsReport, OciEmailError> {
        FixtureBackend.metrics(request)
    }

    fn logging_status(
        &self,
        request: &LoggingStatusRequest,
    ) -> Result<oci_email_delivery_mcp::LoggingStatusReport, OciEmailError> {
        FixtureBackend.logging_status(request)
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

    fn ledger_window(
        &self,
        request: &LedgerWindowRequest,
    ) -> Result<LedgerWindowReport, OciEmailError> {
        Ok(LedgerWindowReport {
            status: "ok".to_string(),
            start_time: request.start_time.clone(),
            end_time: request.end_time.clone(),
            filters: LedgerWindowFilters {
                sender_domain: request.sender_domain.clone(),
                campaign_hash: None,
                batch_hash: None,
            },
            limit: request.limit.unwrap_or(20),
            totals: LedgerWindowTotals {
                scanned_rows: 2,
                matched_rows: 2,
                returned_rows: 2,
                invalid_rows: 0,
                rows_capped: false,
                missing_trace_key_count: 0,
                missing_recipient_key_count: 0,
            },
            sender_domains: vec!["example.com".to_string()],
            campaigns: Vec::new(),
            batches: Vec::new(),
            rows: vec![
                LedgerRowSummary {
                    submitted_at: Some("2026-06-30T00:10:00Z".to_string()),
                    provider_hash: Some("fixture".to_string()),
                    campaign_hash: None,
                    batch_hash: None,
                    sender_domain: Some("example.com".to_string()),
                    recipient_domain: Some("example.net".to_string()),
                    recipient_address_hash: Some("other-recipient".to_string()),
                    recipient_id_hash: None,
                    message_id_hash: Some("fixture".to_string()),
                    correlation_id_hash: None,
                    template_version_hash: None,
                    subject_hash: None,
                    raw_recipient_returned: false,
                },
                LedgerRowSummary {
                    submitted_at: Some("2026-06-30T00:11:00Z".to_string()),
                    provider_hash: Some("fixture".to_string()),
                    campaign_hash: None,
                    batch_hash: None,
                    sender_domain: Some("example.com".to_string()),
                    recipient_domain: Some("example.net".to_string()),
                    recipient_address_hash: Some("fixture".to_string()),
                    recipient_id_hash: None,
                    message_id_hash: Some("other-message".to_string()),
                    correlation_id_hash: None,
                    template_version_hash: None,
                    subject_hash: None,
                    raw_recipient_returned: false,
                },
            ],
            findings: Vec::new(),
            evidence: Vec::new(),
            raw_payload_returned: false,
        })
    }
}

fn empty_events(start_time: &str, end_time: &str, source_domain: Option<String>) -> EventsReport {
    EventsReport {
        status: "ok".to_string(),
        start_time: start_time.to_string(),
        end_time: end_time.to_string(),
        filters: EventFilters {
            action: None,
            message_id_hash: None,
            header_name: None,
            header_value_hash: None,
            receiving_domain: None,
            source_domain,
        },
        limit: 20,
        provider_returned: 0,
        source_domain_matched: 0,
        returned: 0,
        events: Vec::new(),
        findings: Vec::new(),
        evidence: Vec::new(),
    }
}
