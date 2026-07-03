use crate::{
    config::OciEmailConfig,
    error::OciEmailError,
    redact::{email_domain, is_host_token, redact_email, redact_sensitive_text, short_hash},
    response::{
        EmailDeliveryLogSummary, EmailEventSummary, EventCount, EventCounts, EventFilters,
        EventsReport, EventsRequest, Evidence, LedgerRowSummary, LedgerWindowReport,
        LedgerWindowRequest, LogGroupSummary, LoggingEnablementPlanReport,
        LoggingEnablementPlanRequest, LoggingStatusReport, LoggingStatusRequest, MetricRates,
        MetricResult, MetricTotals, MetricsFilters, MetricsReport, MetricsRequest,
        OciEmailStatusReport, QueryProbe, ReadinessFinding, RedactedIdentifier,
        SendReadinessComponents, SendReadinessReport, SendReadinessRequest, SnapshotArtifactReport,
        SnapshotArtifactRequest, StatusRequest, StopThresholds, SuppressionCount,
        SuppressionDeltaComponents, SuppressionDeltaReport, SuppressionDeltaRequest,
        SuppressionDeltaSummary, SuppressionSummary, SuppressionTotals, SuppressionsReport,
        SuppressionsRequest, ToolCallOutcome, TraceCriteria, TraceMessageReport,
        TraceMessageRequest, TraceabilityAuditComponents, TraceabilityAuditReport,
        TraceabilityAuditRequest, TraceabilitySummary, WatchWindowComponents, WatchWindowReport,
        WatchWindowRequest, DEFAULT_EVENT_LIMIT, DEFAULT_LOGGING_STATUS_LIMIT,
        DEFAULT_SUPPRESSION_LIMIT, HARD_EVENT_LIMIT, HARD_LOGGING_STATUS_LIMIT,
        HARD_SUPPRESSION_LIMIT,
    },
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    process::Command,
    sync::Arc,
};

const NAMESPACE: &str = "oci_emaildelivery";
const SUPPRESSION_DOMAIN_BUCKET_LIMIT: usize = 50;
const SUPPRESSION_FETCH_PAGE_SIZE: u32 = 1000;
const SMTP_STATUS_MAX_CHARS: usize = 240;

const STANDARD_METRICS: &[(&str, &str)] = &[
    ("accepted", "EmailsAccepted"),
    ("relayed", "EmailsRelayed"),
    ("hard_bounced", "EmailsHardBounced"),
    ("soft_bounced", "EmailsSoftBounced"),
    ("suppressed", "EmailsSuppressed"),
    ("complaints", "EmailComplaints"),
    ("blocklisted", "EmailsBlocklist"),
    ("list_unsubscribed", "EmailsListUnsubscribed"),
    ("opened", "EmailsOpened"),
    ("clicked", "EmailsClicked"),
];

pub trait OciEmailBackend: Send + Sync {
    fn status(
        &self,
        request: &EventsSafeStatusRequest,
    ) -> Result<OciEmailStatusReport, OciEmailError>;
    fn metrics(&self, request: &MetricsRequest) -> Result<MetricsReport, OciEmailError>;
    fn events(&self, request: &EventsRequest) -> Result<EventsReport, OciEmailError>;
    fn logging_status(
        &self,
        _request: &LoggingStatusRequest,
    ) -> Result<LoggingStatusReport, OciEmailError> {
        Err(OciEmailError::Config(
            "OCI Logging service-log status is not available for this backend".to_string(),
        ))
    }
    fn logging_enablement_plan(
        &self,
        request: &LoggingEnablementPlanRequest,
    ) -> Result<LoggingEnablementPlanReport, OciEmailError> {
        Ok(compose_logging_enablement_plan(self, request))
    }
    fn trace_message(
        &self,
        request: &TraceMessageRequest,
    ) -> Result<TraceMessageReport, OciEmailError>;
    fn suppressions(
        &self,
        request: &SuppressionsRequest,
    ) -> Result<SuppressionsReport, OciEmailError>;

    fn suppression_delta(
        &self,
        request: &SuppressionDeltaRequest,
    ) -> Result<SuppressionDeltaReport, OciEmailError> {
        validate_utc_window(&request.start_time, &request.end_time)?;
        Ok(compose_suppression_delta(self, request))
    }

    fn watch_window(
        &self,
        request: &WatchWindowRequest,
    ) -> Result<WatchWindowReport, OciEmailError> {
        Ok(compose_watch_window(self, request))
    }

    fn send_readiness(
        &self,
        request: &SendReadinessRequest,
    ) -> Result<SendReadinessReport, OciEmailError> {
        Ok(compose_send_readiness(self, request))
    }

    fn traceability_audit(
        &self,
        request: &TraceabilityAuditRequest,
    ) -> Result<TraceabilityAuditReport, OciEmailError> {
        Ok(compose_traceability_audit(self, request))
    }

    fn snapshot_artifact(
        &self,
        _request: &SnapshotArtifactRequest,
    ) -> Result<SnapshotArtifactReport, OciEmailError> {
        Err(OciEmailError::Config(
            "private monitoring snapshot artifacts are not available for this backend".to_string(),
        ))
    }

    fn ledger_window(
        &self,
        _request: &LedgerWindowRequest,
    ) -> Result<LedgerWindowReport, OciEmailError> {
        Err(OciEmailError::Config(
            "local send-ledger reads are not available for this backend".to_string(),
        ))
    }
}

pub type EventsSafeStatusRequest = crate::response::StatusRequest;

#[derive(Clone)]
pub struct LiveOciEmailBackend {
    config: OciEmailConfig,
    runner: Arc<dyn OciCliRunner>,
}

impl LiveOciEmailBackend {
    pub fn new(config: OciEmailConfig) -> Self {
        let runner = Arc::new(ProcessOciCliRunner::new(config.clone()));
        Self { config, runner }
    }

    pub fn with_runner(config: OciEmailConfig, runner: Arc<dyn OciCliRunner>) -> Self {
        Self { config, runner }
    }

    fn compartment_id(&self, override_value: Option<&str>) -> Result<String, OciEmailError> {
        if let Some(value) = override_value.filter(|value| !value.is_empty()) {
            return Ok(value.to_string());
        }
        self.config.resolve_compartment_id()
    }
}

impl OciEmailBackend for LiveOciEmailBackend {
    fn status(
        &self,
        request: &EventsSafeStatusRequest,
    ) -> Result<OciEmailStatusReport, OciEmailError> {
        let compartment_id = self.compartment_id(request.compartment_id.as_deref())?;
        let sender_args = vec![
            "email".to_string(),
            "sender".to_string(),
            "list".to_string(),
            "--compartment-id".to_string(),
            compartment_id.clone(),
            "--limit".to_string(),
            "100".to_string(),
        ];
        let domain_args = vec![
            "email".to_string(),
            "domain".to_string(),
            "list".to_string(),
            "--compartment-id".to_string(),
            compartment_id.clone(),
            "--limit".to_string(),
            "100".to_string(),
        ];
        let suppression_args = vec![
            "email".to_string(),
            "suppression".to_string(),
            "list".to_string(),
            "--compartment-id".to_string(),
            compartment_id.clone(),
            "--limit".to_string(),
            "1".to_string(),
        ];

        let sender_json = self.runner.run_json(&sender_args)?;
        let domain_json = self.runner.run_json(&domain_args)?;
        let suppression_probe = match self.runner.run_optional_json(&suppression_args) {
            Ok(value) => QueryProbe {
                status: "ok".to_string(),
                item_count: json_items(&value).len(),
                note: value
                    .is_null()
                    .then(|| "OCI CLI returned empty stdout for suppression list".to_string()),
            },
            Err(error) => QueryProbe {
                status: "blocked".to_string(),
                item_count: 0,
                note: Some(error.redacted_message()),
            },
        };

        let sender_items = json_items(&sender_json);
        let domain_items = json_items(&domain_json);
        let mut sender_domains = BTreeSet::new();
        let mut active_sender_count = 0;
        for item in &sender_items {
            if string_field(item, "lifecycle-state")
                .is_some_and(|state| state.eq_ignore_ascii_case("ACTIVE"))
            {
                active_sender_count += 1;
            }
            if let Some(domain) = string_field(item, "email-address").and_then(email_domain) {
                sender_domains.insert(domain);
            }
        }
        let mut active_email_domain_count = 0;
        for item in &domain_items {
            if string_field(item, "lifecycle-state")
                .is_some_and(|state| state.eq_ignore_ascii_case("ACTIVE"))
            {
                active_email_domain_count += 1;
            }
        }

        let mut findings = Vec::new();
        if active_sender_count == 0 {
            findings.push(finding(
                "blocker",
                "no_active_sender",
                "No ACTIVE approved sender was visible to the selected OCI profile.",
            ));
        }
        if active_email_domain_count == 0 {
            findings.push(finding(
                "warning",
                "no_active_email_domain",
                "No ACTIVE Email Domain was visible; Email Delivery logs usually require domain logging to be enabled.",
            ));
        }
        if suppression_probe.status != "ok" {
            findings.push(finding(
                "blocker",
                "suppression_query_blocked",
                "Suppression list readback is blocked, so clean-audience reconciliation is not proven.",
            ));
        } else if suppression_probe.note.is_some() {
            findings.push(finding(
                "warning",
                "suppression_query_empty_stdout",
                "Suppression list readback returned empty stdout; treat this as no sample, not full absence proof.",
            ));
        }

        let status = if findings.iter().any(|item| item.severity == "blocker") {
            "blocked"
        } else if findings.is_empty() {
            "ready"
        } else {
            "degraded"
        };

        Ok(OciEmailStatusReport {
            status: status.to_string(),
            send_authorized: false,
            profile: self.config.profile.clone(),
            region: self
                .config
                .region
                .clone()
                .or_else(|| self.config.read_profile_value("region").ok().flatten()),
            compartment: RedactedIdentifier::from_optional(Some(&compartment_id)),
            approved_sender_count: sender_items.len(),
            active_sender_count,
            sender_domains: sender_domains.into_iter().collect(),
            email_domain_count: domain_items.len(),
            active_email_domain_count,
            suppression_query: suppression_probe,
            findings,
            evidence: vec![
                Evidence::new("oci_cli", "email sender list", false),
                Evidence::new("oci_cli", "email domain list", false),
                Evidence::new("oci_cli", "email suppression list", false),
            ],
        })
    }

    fn metrics(&self, request: &MetricsRequest) -> Result<MetricsReport, OciEmailError> {
        let interval = normalize_interval(request.interval.as_deref())?;
        validate_time(&request.start_time, "start_time")?;
        validate_time(&request.end_time, "end_time")?;
        if let Some(domain) = request.resource_domain.as_deref() {
            validate_domain(domain, "resource_domain")?;
        }
        if let Some(resource_id) = request.resource_id.as_deref() {
            safe_query_value(resource_id).map_err(|_| {
                OciEmailError::InvalidInput(
                    "resource_id contains unsupported query syntax".to_string(),
                )
            })?;
        }

        let compartment_id = self.compartment_id(request.compartment_id.as_deref())?;
        let definitions = self.metric_definitions(&compartment_id)?;
        let definition_set = definitions
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let mut available_keys = BTreeSet::new();
        let mut metrics = Vec::new();
        let mut totals = MetricTotals::default();
        let mut findings = Vec::new();

        for (key, oci_name) in STANDARD_METRICS {
            let query = metric_query(
                oci_name,
                &interval,
                request.resource_domain.as_deref(),
                request.resource_id.as_deref(),
            );
            let output_query = metric_query_for_output(
                oci_name,
                &interval,
                request.resource_domain.as_deref(),
                request.resource_id.as_deref(),
            );
            if !definition_set.contains(oci_name) {
                metrics.push(MetricResult {
                    key: (*key).to_string(),
                    oci_name: (*oci_name).to_string(),
                    status: "unavailable".to_string(),
                    query: output_query,
                    total: 0.0,
                    point_count: 0,
                    series_count: 0,
                    note: Some("Metric definition is not currently visible in OCI.".to_string()),
                });
                if *key == "accepted" {
                    findings.push(finding(
                        "blocker",
                        "metric_unavailable_accepted",
                        "Accepted-email metric is not currently visible; delivery rates and stop gates cannot be interpreted.",
                    ));
                } else if is_stop_gate_metric_key(key) {
                    findings.push(finding(
                        "warning",
                        &format!("metric_unavailable_{key}"),
                        "A stop-gate metric is not currently visible; do not treat this as proof of zero events.",
                    ));
                }
                continue;
            }

            let args = vec![
                "monitoring".to_string(),
                "metric-data".to_string(),
                "summarize-metrics-data".to_string(),
                "--compartment-id".to_string(),
                compartment_id.clone(),
                "--namespace".to_string(),
                NAMESPACE.to_string(),
                "--query-text".to_string(),
                query.clone(),
                "--start-time".to_string(),
                request.start_time.clone(),
                "--end-time".to_string(),
                request.end_time.clone(),
            ];
            let value = self.runner.run_optional_json(&args)?;
            let (total, point_count, series_count) = metric_total(&value);
            assign_metric_total(&mut totals, key, total);
            available_keys.insert((*key).to_string());
            if value.is_null() || point_count == 0 {
                if *key == "accepted" {
                    findings.push(finding(
                        "blocker",
                        "metric_no_datapoints_accepted",
                        "Accepted-email metric returned no usable datapoints; delivery rates and stop gates cannot be interpreted for this window.",
                    ));
                } else if is_stop_gate_metric_key(key) {
                    findings.push(finding(
                        "warning",
                        &format!("metric_no_datapoints_{key}"),
                        "A stop-gate metric returned no usable datapoints; do not treat this as proof of zero events.",
                    ));
                }
            }
            metrics.push(MetricResult {
                key: (*key).to_string(),
                oci_name: (*oci_name).to_string(),
                status: "ok".to_string(),
                query: output_query,
                total,
                point_count,
                series_count,
                note: value
                    .is_null()
                    .then(|| "OCI CLI returned empty stdout for this metric query.".to_string()),
            });
        }

        let rates = metric_rates(&totals, &available_keys);
        let thresholds = StopThresholds::from_config(&self.config);
        if let Some(rate) = rates.hard_bounce_rate {
            let percent = rate * 100.0;
            if percent >= thresholds.hard_bounce_hard_stop_percent {
                findings.push(finding(
                    "blocker",
                    "hard_bounce_hard_stop",
                    "Hard bounce rate is at or above the configured hard-stop threshold.",
                ));
            } else if percent >= thresholds.hard_bounce_throttle_or_pause_percent {
                findings.push(finding(
                    "blocker",
                    "hard_bounce_throttle_or_pause",
                    "Hard bounce rate is at or above the configured throttle-or-pause threshold.",
                ));
            } else if percent >= thresholds.hard_bounce_pause_percent {
                findings.push(finding(
                    "blocker",
                    "hard_bounce_pause",
                    "Hard bounce rate is at or above the configured pause threshold.",
                ));
            } else if percent >= thresholds.hard_bounce_warn_percent {
                findings.push(finding(
                    "warning",
                    "hard_bounce_warn",
                    "Hard bounce rate is at or above the configured warning threshold.",
                ));
            }
        }

        let status = if findings.iter().any(|item| item.severity == "blocker") {
            "blocked"
        } else if findings.is_empty() {
            "ok"
        } else {
            "degraded"
        };

        Ok(MetricsReport {
            status: status.to_string(),
            namespace: NAMESPACE.to_string(),
            start_time: request.start_time.clone(),
            end_time: request.end_time.clone(),
            interval,
            filters: MetricsFilters {
                resource_domain: request.resource_domain.clone(),
                resource_id: RedactedIdentifier::from_optional(request.resource_id.as_deref()),
            },
            metric_definitions_seen: definitions,
            metrics,
            totals,
            rates,
            thresholds,
            findings,
            evidence: vec![
                Evidence::new("oci_cli", "monitoring metric list", false),
                Evidence::new(
                    "oci_cli",
                    "monitoring metric-data summarize-metrics-data",
                    false,
                ),
            ],
        })
    }

    fn events(&self, request: &EventsRequest) -> Result<EventsReport, OciEmailError> {
        self.events_inner(request)
    }

    fn logging_status(
        &self,
        request: &LoggingStatusRequest,
    ) -> Result<LoggingStatusReport, OciEmailError> {
        if let Some(resource_domain) = request.resource_domain.as_deref() {
            validate_domain(resource_domain, "resource_domain")?;
        }
        if let Some(resource_id) = request.resource_id.as_deref() {
            safe_query_value(resource_id).map_err(|_| {
                OciEmailError::InvalidInput(
                    "resource_id contains unsupported identifier characters".to_string(),
                )
            })?;
        }
        let compartment_id = self.compartment_id(request.compartment_id.as_deref())?;
        let limit = cap_limit(
            request.limit.unwrap_or(DEFAULT_LOGGING_STATUS_LIMIT),
            HARD_LOGGING_STATUS_LIMIT,
        );
        let mut findings = Vec::new();
        let mut resolved_resource_id = request.resource_id.clone();
        let mut domain_lookup_attempted = false;
        let mut domain_lookup_capped = false;
        if let Some(resource_domain) = request.resource_domain.as_deref() {
            domain_lookup_attempted = true;
            let domain_args = vec![
                "email".to_string(),
                "domain".to_string(),
                "list".to_string(),
                "--compartment-id".to_string(),
                compartment_id.clone(),
                "--limit".to_string(),
                limit.to_string(),
            ];
            let domain_json = self.runner.run_optional_json(&domain_args)?;
            let domain_items = json_items(&domain_json);
            domain_lookup_capped = rows_may_be_capped(domain_items.len(), limit);
            if let Some(domain_item) = domain_items.iter().find(|item| {
                string_field_any(item, &["domain-name", "domainName", "name"])
                    .is_some_and(|value| value.eq_ignore_ascii_case(resource_domain))
            }) {
                if string_field(domain_item, "lifecycle-state")
                    .is_some_and(|state| !state.eq_ignore_ascii_case("ACTIVE"))
                {
                    findings.push(finding(
                        "blocker",
                        "logging_requested_resource_domain_not_active",
                        "The requested Email Domain is visible, but it is not ACTIVE.",
                    ));
                }
                if let Some(id) = string_field(domain_item, "id") {
                    if request
                        .resource_id
                        .as_deref()
                        .is_some_and(|requested_id| requested_id != id)
                    {
                        findings.push(finding(
                            "blocker",
                            "logging_requested_resource_scope_mismatch",
                            "The supplied resource_id does not match the visible Email Domain resolved from resource_domain.",
                        ));
                    } else {
                        resolved_resource_id = Some(id.to_string());
                    }
                } else {
                    findings.push(finding(
                        "blocker",
                        "logging_requested_resource_domain_missing_id",
                        "The requested Email Domain was visible, but OCI did not return a resource id to match against service logs.",
                    ));
                }
            } else {
                findings.push(finding(
                    "blocker",
                    "logging_requested_resource_domain_not_visible",
                    "No visible Email Domain matched the requested resource_domain.",
                ));
            }
        }
        let log_group_args = vec![
            "logging".to_string(),
            "log-group".to_string(),
            "list".to_string(),
            "--compartment-id".to_string(),
            compartment_id.clone(),
            "--limit".to_string(),
            limit.to_string(),
        ];
        let log_group_json = self.runner.run_optional_json(&log_group_args)?;
        let log_group_items = json_items(&log_group_json);
        let log_groups = log_group_items
            .iter()
            .map(|item| log_group_summary(item))
            .collect::<Vec<_>>();
        let mut email_delivery_logs = Vec::new();
        let mut service_log_count = 0usize;
        let mut service_rows_capped = false;
        let mut log_list_attempted = false;

        for group in &log_group_items {
            let Some(log_group_id) = string_field(group, "id") else {
                continue;
            };
            log_list_attempted = true;
            let log_args = vec![
                "logging".to_string(),
                "log".to_string(),
                "list".to_string(),
                "--log-group-id".to_string(),
                log_group_id.to_string(),
                "--log-type".to_string(),
                "SERVICE".to_string(),
                "--source-service".to_string(),
                "emaildelivery".to_string(),
                "--limit".to_string(),
                limit.to_string(),
            ];
            let log_json = self.runner.run_optional_json(&log_args)?;
            let logs = json_items(&log_json);
            service_log_count += logs.len();
            service_rows_capped |= rows_may_be_capped(logs.len(), limit);
            email_delivery_logs.extend(
                logs.into_iter()
                    .filter(|item| is_email_delivery_service_log(item))
                    .map(|item| email_delivery_log_summary(item, log_group_id)),
            );
        }

        let active_email_delivery_log_count = email_delivery_logs
            .iter()
            .filter(|item| {
                item.lifecycle_state
                    .as_deref()
                    .is_some_and(|state| state.eq_ignore_ascii_case("ACTIVE"))
            })
            .count();
        let requested_resource_redacted = resolved_resource_id
            .as_deref()
            .map(crate::redact::redact_ocid);
        let matching_requested_resource_log_count = requested_resource_redacted
            .as_deref()
            .map(|redacted_resource_id| {
                email_delivery_logs
                    .iter()
                    .filter(|item| {
                        item.source_resource.redacted.as_deref() == Some(redacted_resource_id)
                    })
                    .count()
            })
            .unwrap_or(0);
        let active_matching_requested_resource_log_count = requested_resource_redacted
            .as_deref()
            .map(|redacted_resource_id| {
                email_delivery_logs
                    .iter()
                    .filter(|item| {
                        item.source_resource.redacted.as_deref() == Some(redacted_resource_id)
                    })
                    .filter(|item| {
                        item.lifecycle_state
                            .as_deref()
                            .is_some_and(|state| state.eq_ignore_ascii_case("ACTIVE"))
                    })
                    .count()
            })
            .unwrap_or(0);
        let log_group_rows_capped = rows_may_be_capped(log_groups.len(), limit);
        if log_groups.is_empty() {
            findings.push(finding(
                "blocker",
                "logging_no_log_groups_visible",
                "No OCI Logging log groups were visible to the selected profile; Email Delivery log configuration is not proven.",
            ));
        }
        if email_delivery_logs.is_empty() {
            findings.push(finding(
                "blocker",
                "logging_no_email_delivery_service_logs",
                "No Email Delivery service logs were visible; exact OCI event traceability is not configured or not readable by this profile.",
            ));
        } else if active_email_delivery_log_count == 0 {
            findings.push(finding(
                "blocker",
                "logging_no_active_email_delivery_service_logs",
                "Email Delivery service logs were visible, but none were ACTIVE.",
            ));
        }
        if resolved_resource_id.is_some() {
            if matching_requested_resource_log_count == 0 {
                findings.push(finding(
                    "blocker",
                    "logging_requested_resource_not_visible",
                    "No visible Email Delivery service log matched the requested resource id.",
                ));
            } else if active_matching_requested_resource_log_count == 0 {
                findings.push(finding(
                    "blocker",
                    "logging_requested_resource_not_active",
                    "Email Delivery service logs matched the requested resource id, but none were ACTIVE.",
                ));
            }
        }
        if domain_lookup_capped {
            findings.push(finding(
                "warning",
                "logging_email_domains_capped",
                "Email Domain listing returned the requested limit; raise the limit before treating a missing resource_domain match as complete.",
            ));
        }
        if log_group_rows_capped {
            findings.push(finding(
                "warning",
                "logging_log_groups_capped",
                "Log group listing returned the requested limit; raise the limit before treating the log-group inventory as complete.",
            ));
        }
        if service_rows_capped {
            findings.push(finding(
                "warning",
                "logging_service_logs_capped",
                "Service log listing returned the requested limit for at least one log group; raise the limit before treating the log inventory as complete.",
            ));
        }

        let status = if findings.iter().any(|item| item.severity == "blocker") {
            "blocked"
        } else if findings.is_empty() {
            "ok"
        } else {
            "degraded"
        };
        let mut evidence = Vec::new();
        if domain_lookup_attempted {
            evidence.push(Evidence::new(
                "oci_cli",
                "email domain list",
                domain_lookup_capped,
            ));
        }
        evidence.push(Evidence::new(
            "oci_cli",
            "logging log-group list",
            log_group_rows_capped,
        ));
        if log_list_attempted {
            evidence.push(Evidence::new(
                "oci_cli",
                "logging log list",
                service_rows_capped,
            ));
        }

        Ok(LoggingStatusReport {
            status: status.to_string(),
            send_authorized: false,
            compartment: RedactedIdentifier::from_optional(Some(&compartment_id)),
            resource_domain: request.resource_domain.clone(),
            requested_resource_id: RedactedIdentifier::from_optional(
                resolved_resource_id.as_deref(),
            ),
            limit,
            log_group_count: log_groups.len(),
            service_log_count,
            email_delivery_log_count: email_delivery_logs.len(),
            active_email_delivery_log_count,
            matching_requested_resource_log_count,
            active_matching_requested_resource_log_count,
            log_groups,
            email_delivery_logs,
            findings,
            evidence,
            raw_payload_returned: false,
        })
    }

    fn trace_message(
        &self,
        request: &TraceMessageRequest,
    ) -> Result<TraceMessageReport, OciEmailError> {
        if request.message_id.as_deref().unwrap_or_default().is_empty()
            && (request
                .header_name
                .as_deref()
                .unwrap_or_default()
                .is_empty()
                || request
                    .header_value
                    .as_deref()
                    .unwrap_or_default()
                    .is_empty())
        {
            return Err(OciEmailError::InvalidInput(
                "trace requires message_id or both header_name and header_value".to_string(),
            ));
        }
        let events_request = EventsRequest {
            start_time: request.start_time.clone(),
            end_time: request.end_time.clone(),
            action: None,
            message_id: request.message_id.clone(),
            header_name: request.header_name.clone(),
            header_value: request.header_value.clone(),
            receiving_domain: None,
            source_domain: request.source_domain.clone(),
            limit: request.limit,
            compartment_id: request.compartment_id.clone(),
        };
        let events = self.events_inner(&events_request)?;
        Ok(TraceMessageReport {
            status: events.status.clone(),
            criteria: TraceCriteria {
                message_id_hash: request.message_id.as_deref().map(short_hash),
                header_name: request.header_name.clone(),
                header_value_hash: request.header_value.as_deref().map(short_hash),
            },
            events,
        })
    }

    fn suppressions(
        &self,
        request: &SuppressionsRequest,
    ) -> Result<SuppressionsReport, OciEmailError> {
        let compartment_id = self.compartment_id(request.compartment_id.as_deref())?;
        let limit = cap_limit(
            request.limit.unwrap_or(DEFAULT_SUPPRESSION_LIMIT),
            HARD_SUPPRESSION_LIMIT,
        );
        if let Some(value) = request.time_created_greater_than_or_equal_to.as_deref() {
            validate_time(value, "time_created_greater_than_or_equal_to")?;
        }
        if let Some(value) = request.time_created_less_than.as_deref() {
            validate_time(value, "time_created_less_than")?;
        }

        let mut args = vec![
            "email".to_string(),
            "suppression".to_string(),
            "list".to_string(),
            "--compartment-id".to_string(),
            compartment_id,
            "--all".to_string(),
            "--page-size".to_string(),
            SUPPRESSION_FETCH_PAGE_SIZE.to_string(),
        ];
        if let Some(value) = request.time_created_greater_than_or_equal_to.as_deref() {
            args.push("--time-created-greater-than-or-equal-to".to_string());
            args.push(value.to_string());
        }
        if let Some(value) = request.time_created_less_than.as_deref() {
            args.push("--time-created-less-than".to_string());
            args.push(value.to_string());
        }
        let value = self.runner.run_optional_json(&args)?;
        let all_suppressions = json_items(&value)
            .into_iter()
            .map(suppression_summary)
            .collect::<Vec<_>>();
        let suppressions = all_suppressions
            .iter()
            .take(limit as usize)
            .cloned()
            .collect::<Vec<_>>();
        let mut findings = Vec::new();
        let rows_capped = all_suppressions.len() > suppressions.len();
        if value.is_null() {
            findings.push(finding(
                "warning",
                "empty_suppression_stdout",
                "OCI CLI returned empty stdout for suppression list; treat as no sample, not as a full absence proof.",
            ));
        }
        let count_state = suppression_count_state(value.is_null(), false);
        let (oldest_time_created, newest_time_created) = suppression_time_bounds(&all_suppressions);
        let totals = suppression_totals(&all_suppressions);
        Ok(SuppressionsReport {
            status: if findings.is_empty() {
                "ok".to_string()
            } else {
                "degraded".to_string()
            },
            limit,
            returned: suppressions.len(),
            total_matched: all_suppressions.len(),
            rows_capped,
            count_state,
            oldest_time_created,
            newest_time_created,
            totals,
            suppressions,
            findings,
            evidence: vec![Evidence::new(
                "oci_cli",
                "email suppression list",
                rows_capped,
            )],
        })
    }

    fn ledger_window(
        &self,
        request: &LedgerWindowRequest,
    ) -> Result<LedgerWindowReport, OciEmailError> {
        crate::ledger::ledger_window(&self.config, request)
    }

    fn snapshot_artifact(
        &self,
        request: &SnapshotArtifactRequest,
    ) -> Result<SnapshotArtifactReport, OciEmailError> {
        crate::snapshot::snapshot_artifact(&self.config, self, request)
    }
}

impl LiveOciEmailBackend {
    fn metric_definitions(&self, compartment_id: &str) -> Result<Vec<String>, OciEmailError> {
        let args = vec![
            "monitoring".to_string(),
            "metric".to_string(),
            "list".to_string(),
            "--compartment-id".to_string(),
            compartment_id.to_string(),
            "--namespace".to_string(),
            NAMESPACE.to_string(),
        ];
        let value = self.runner.run_optional_json(&args)?;
        let mut names = json_items(&value)
            .into_iter()
            .filter_map(|item| string_field(item, "name").map(ToString::to_string))
            .collect::<Vec<_>>();
        names.sort();
        names.dedup();
        Ok(names)
    }

    fn events_inner(&self, request: &EventsRequest) -> Result<EventsReport, OciEmailError> {
        validate_time(&request.start_time, "start_time")?;
        validate_time(&request.end_time, "end_time")?;
        validate_event_request(request)?;
        let compartment_id = self.compartment_id(request.compartment_id.as_deref())?;
        let limit = cap_limit(
            request.limit.unwrap_or(DEFAULT_EVENT_LIMIT),
            HARD_EVENT_LIMIT,
        );
        let search_query = build_search_query(&compartment_id, request)?;
        let args = vec![
            "logging-search".to_string(),
            "search-logs".to_string(),
            "--time-start".to_string(),
            request.start_time.clone(),
            "--time-end".to_string(),
            request.end_time.clone(),
            "--search-query".to_string(),
            search_query,
            "--limit".to_string(),
            limit.to_string(),
        ];
        let value = self.runner.run_optional_json(&args)?;
        let raw_events = log_results(&value)
            .into_iter()
            .map(email_event_summary)
            .collect::<Vec<_>>();
        let rows_capped = rows_may_be_capped(raw_events.len(), limit);
        let provider_returned = raw_events.len();
        let events = raw_events
            .into_iter()
            .filter(|event| event_matches_source_domain(event, request.source_domain.as_deref()))
            .collect::<Vec<_>>();
        let source_domain_matched = events.len();
        let counts = event_counts(&events);
        let mut findings = Vec::new();
        if events.is_empty() {
            findings.push(finding(
                "warning",
                "no_log_events_returned",
                "No Email Delivery log events matched this window/filter; this does not prove logging is enabled.",
            ));
        }
        if provider_returned > 0 && request.source_domain.is_some() && source_domain_matched == 0 {
            findings.push(finding(
                "warning",
                "source_domain_post_filter_no_match",
                "Email Delivery log events were returned by the provider query, but none matched the requested source domain after redacted summary parsing.",
            ));
        }
        if rows_capped {
            findings.push(finding(
                "warning",
                "event_results_capped",
                "Log search returned the requested limit; narrow the time window or filters before treating the event set as complete.",
            ));
        }
        Ok(EventsReport {
            status: if findings.is_empty() {
                "ok".to_string()
            } else {
                "degraded".to_string()
            },
            start_time: request.start_time.clone(),
            end_time: request.end_time.clone(),
            filters: EventFilters {
                action: request.action.clone(),
                message_id_hash: request.message_id.as_deref().map(short_hash),
                header_name: request.header_name.clone(),
                header_value_hash: request.header_value.as_deref().map(short_hash),
                receiving_domain: request.receiving_domain.clone(),
                source_domain: request.source_domain.clone(),
            },
            limit,
            provider_returned,
            source_domain_matched,
            returned: events.len(),
            counts,
            events,
            findings,
            evidence: vec![Evidence::new(
                "oci_cli",
                "logging-search search-logs",
                rows_capped,
            )],
        })
    }
}

pub trait OciCliRunner: Send + Sync {
    fn run_json(&self, args: &[String]) -> Result<Value, OciEmailError>;

    fn run_optional_json(&self, args: &[String]) -> Result<Value, OciEmailError> {
        self.run_json(args)
    }
}

#[derive(Debug, Clone)]
pub struct ProcessOciCliRunner {
    config: OciEmailConfig,
}

impl ProcessOciCliRunner {
    pub fn new(config: OciEmailConfig) -> Self {
        Self { config }
    }
}

impl OciCliRunner for ProcessOciCliRunner {
    fn run_json(&self, args: &[String]) -> Result<Value, OciEmailError> {
        let mut full_args = args.to_vec();
        full_args.extend([
            "--profile".to_string(),
            self.config.profile.clone(),
            "--output".to_string(),
            "json".to_string(),
            "--no-retry".to_string(),
            "--connection-timeout".to_string(),
            "10".to_string(),
            "--read-timeout".to_string(),
            "45".to_string(),
        ]);
        if let Some(region) = &self.config.region {
            full_args.push("--region".to_string());
            full_args.push(region.clone());
        }

        let output = Command::new(&self.config.cli_bin)
            .args(&full_args)
            .output()
            .map_err(|err| OciEmailError::Cli {
                command: command_label(args),
                status: None,
                stderr: redact_sensitive_text(&err.to_string()),
            })?;
        if !output.status.success() {
            return Err(OciEmailError::Cli {
                command: command_label(args),
                status: output.status.code(),
                stderr: redact_sensitive_text(&String::from_utf8_lossy(&output.stderr)),
            });
        }
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if stdout.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_str(&stdout).map_err(|err| OciEmailError::Json {
            context: command_label(args),
            message: err.to_string(),
        })
    }
}

fn command_label(args: &[String]) -> String {
    args.iter()
        .take(3)
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" ")
}

fn json_items(value: &Value) -> Vec<&Value> {
    if let Some(items) = value.get("data").and_then(Value::as_array) {
        return items.iter().collect();
    }
    if let Some(items) = value
        .get("data")
        .and_then(|data| data.get("items"))
        .and_then(Value::as_array)
    {
        return items.iter().collect();
    }
    Vec::new()
}

fn log_results(value: &Value) -> Vec<&Value> {
    value
        .get("data")
        .and_then(|data| data.get("results"))
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn string_field_any<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| string_field(value, key))
}

fn nested_string<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cursor = value;
    for key in path {
        cursor = cursor.get(*key)?;
    }
    cursor.as_str()
}

fn finding(severity: &str, code: &str, message: &str) -> ReadinessFinding {
    ReadinessFinding {
        severity: severity.to_string(),
        code: code.to_string(),
        message: message.to_string(),
    }
}

fn compose_logging_enablement_plan<B: OciEmailBackend + ?Sized>(
    backend: &B,
    request: &LoggingEnablementPlanRequest,
) -> LoggingEnablementPlanReport {
    let status_request = LoggingStatusRequest {
        compartment_id: request.compartment_id.clone(),
        resource_domain: request.resource_domain.clone(),
        resource_id: request.resource_id.clone(),
        limit: request.limit,
    };
    let current_status_result = backend.logging_status(&status_request);
    let mut findings = Vec::new();
    let status = match &current_status_result {
        Ok(report) if report.status == "ok" && report.requested_resource_id.present => {
            findings.push(finding(
                "info",
                "logging_already_visible",
                "Active OCI Email Delivery service logs are already visible to this profile; no log-enable apply is needed before post-enable proof.",
            ));
            "already_visible_no_apply_needed"
        }
        Ok(report) if report.status == "ok" => {
            findings.push(finding(
                "warning",
                "logging_plan_resource_id_missing",
                "Active OCI Email Delivery service logs are visible, but no Email Domain resource id or resolvable resource_domain was supplied; resource-specific readiness is not proven.",
            ));
            "review_required"
        }
        Ok(report) if report.findings.iter().any(is_logging_target_scope_blocker) => {
            findings.push(finding(
                "blocker",
                "logging_enablement_target_scope_unresolved",
                "The requested Email Domain scope is not resolved; fix resource_domain, resource_id, or compartment before planning an OCI logging configuration change.",
            ));
            "blocked"
        }
        Ok(report)
            if report
                .findings
                .iter()
                .any(|item| item.severity == "blocker") =>
        {
            findings.push(finding(
                "blocker",
                "logging_enablement_approval_required",
                "OCI Email Delivery service-log visibility is blocked; enabling or making service logs visible is an OCI configuration mutation and requires explicit operator approval.",
            ));
            "approval_required"
        }
        Ok(_) => {
            findings.push(finding(
                "warning",
                "logging_enablement_review_required",
                "OCI Email Delivery service-log visibility is degraded; review capped or partial logging evidence before any enablement decision.",
            ));
            "review_required"
        }
        Err(_) => {
            findings.push(finding(
                "blocker",
                "logging_status_unavailable",
                "Current logging status could not be read; the enablement plan cannot prove the target logging state.",
            ));
            "blocked"
        }
    };
    let compartment = current_status_result
        .as_ref()
        .map(|report| report.compartment.clone())
        .unwrap_or_else(|_| RedactedIdentifier::from_optional(request.compartment_id.as_deref()));
    let requested_resource_id = current_status_result
        .as_ref()
        .map(|report| report.requested_resource_id.clone())
        .unwrap_or_else(|_| RedactedIdentifier::from_optional(request.resource_id.as_deref()));
    let provider_mutation_required = matches!(status, "approval_required");
    let current_logging = match current_status_result {
        Ok(report) => ToolCallOutcome::ok(report.status.clone(), report),
        Err(error) => ToolCallOutcome::blocked(error),
    };

    LoggingEnablementPlanReport {
        status: status.to_string(),
        decision: status.to_string(),
        send_authorized: false,
        provider_mutation_required,
        provider_mutation_authorized: false,
        compartment,
        resource_domain: request.resource_domain.clone(),
        requested_resource_id,
        required_log_categories: vec![
            "emaildelivery.emaildomain.outboundaccepted".to_string(),
            "emaildelivery.emaildomain.outboundrelayed".to_string(),
        ],
        required_permissions: vec![
            "EMAIL_DOMAIN_UPDATE for the Email Domain resource".to_string(),
            "OCI Logging permissions for the target log group and service logs".to_string(),
        ],
        operator_steps: vec![
            "Confirm the target OCI Email Domain and compartment; if the expected domain is not visible, switch to the owning compartment.".to_string(),
            "Create or select an OCI Logging log group in the intended compartment.".to_string(),
            "Enable Email Delivery service logs for the Email Domain resource before any seed or cohort send.".to_string(),
            "Enable both required categories: outbound accepted and outbound relayed.".to_string(),
            "Keep raw OCIDs, log names, provider JSON, and recipient data in private evidence only.".to_string(),
        ],
        post_enable_gates: vec![
            "Re-run oci_email_logging_status with the Email Domain resource_domain or resource_id and require an ACTIVE matching Email Delivery service log.".to_string(),
            "Run a bounded seed/proof window with a stored local ledger row and a message id or non-PII correlation header.".to_string(),
            "Use oci_email_traceability_audit for that window and require exact traceability, not aggregate-only delivery pressure.".to_string(),
            "Treat capped logging reads, absent log events, unavailable stop-gate metrics, or missing ledger trace keys as not ready.".to_string(),
        ],
        current_logging,
        findings,
        evidence: vec![Evidence::new(
            "mcp_composed_read",
            "oci_email_logging_status plus static logging enablement guidance",
            false,
        )],
        raw_payload_returned: false,
    }
}

fn is_logging_target_scope_blocker(finding: &ReadinessFinding) -> bool {
    matches!(
        finding.code.as_str(),
        "logging_requested_resource_scope_mismatch"
            | "logging_requested_resource_domain_not_visible"
            | "logging_requested_resource_domain_missing_id"
            | "logging_requested_resource_domain_not_active"
    )
}

fn compose_watch_window<B: OciEmailBackend + ?Sized>(
    backend: &B,
    request: &WatchWindowRequest,
) -> WatchWindowReport {
    let (interval, interval_error) = match normalize_interval(request.interval.as_deref()) {
        Ok(interval) => (interval, None),
        Err(error) => (
            request.interval.clone().unwrap_or_else(|| "1h".to_string()),
            Some(error),
        ),
    };
    let requested_resource_domain = non_empty_request_value(&request.resource_domain);
    let requested_source_domain = non_empty_request_value(&request.source_domain);
    let resource_id = non_empty_request_value(&request.resource_id);
    let resource_domain = requested_resource_domain
        .clone()
        .or_else(|| requested_source_domain.clone());
    let source_domain = requested_source_domain
        .clone()
        .or_else(|| requested_resource_domain.clone());
    let mut findings = Vec::new();
    let mut evidence = Vec::new();
    let metrics_scope_missing = resource_domain.is_none() && resource_id.is_none();
    let events_scope_missing = source_domain.is_none();
    if metrics_scope_missing {
        findings.push(finding(
            "blocker",
            "metrics_scope_missing",
            "Watch-window metrics are not scoped to a resource domain or resource id; do not use a compartment-wide metric receipt for lane readiness.",
        ));
    }
    if events_scope_missing {
        findings.push(finding(
            "blocker",
            "events_scope_missing",
            "Watch-window log reads are not scoped to a source domain; do not use a compartment-wide event receipt for lane readiness.",
        ));
    }

    let status = match backend.status(&StatusRequest {
        compartment_id: request.compartment_id.clone(),
    }) {
        Ok(report) => {
            findings.extend(report.findings.clone());
            evidence.extend(report.evidence.clone());
            ToolCallOutcome::ok(report.status.clone(), report)
        }
        Err(error) => component_blocked(
            &mut findings,
            "status_read_blocked",
            "OCI Email Delivery status read failed; profile, sender, domain, and suppression visibility are not proven.",
            error,
        ),
    };

    let logging = if metrics_scope_missing {
        ToolCallOutcome::blocked(OciEmailError::InvalidInput(
            "watch_window requires resource_domain or resource_id before reading logging status"
                .to_string(),
        ))
    } else {
        match backend.logging_status(&LoggingStatusRequest {
            compartment_id: request.compartment_id.clone(),
            resource_domain: resource_domain.clone(),
            resource_id: resource_id.clone(),
            limit: request.limit,
        }) {
            Ok(report) => {
                findings.extend(report.findings.clone());
                evidence.extend(report.evidence.clone());
                ToolCallOutcome::ok(report.status.clone(), report)
            }
            Err(error) => component_blocked(
                &mut findings,
                "logging_status_blocked",
                "OCI Email Delivery service-log status read failed; logging configuration visibility is not proven for this window.",
                error,
            ),
        }
    };

    let metrics = if metrics_scope_missing {
        ToolCallOutcome::blocked(OciEmailError::InvalidInput(
            "watch_window requires resource_domain or resource_id before reading metrics"
                .to_string(),
        ))
    } else if let Some(error) = interval_error {
        component_blocked(
            &mut findings,
            "metrics_interval_invalid",
            "Watch-window metrics interval is invalid; stop-gate counters are not proven for this window.",
            error,
        )
    } else {
        match backend.metrics(&MetricsRequest {
            start_time: request.start_time.clone(),
            end_time: request.end_time.clone(),
            interval: Some(interval.clone()),
            resource_domain: resource_domain.clone(),
            resource_id: resource_id.clone(),
            compartment_id: request.compartment_id.clone(),
        }) {
            Ok(report) => {
                findings.extend(report.findings.clone());
                evidence.extend(report.evidence.clone());
                ToolCallOutcome::ok(report.status.clone(), report)
            }
            Err(error) => component_blocked(
                &mut findings,
                "metrics_read_blocked",
                "OCI Monitoring metrics read failed; stop-gate counters are not proven for this window.",
                error,
            ),
        }
    };

    let events = if events_scope_missing {
        ToolCallOutcome::blocked(OciEmailError::InvalidInput(
            "watch_window requires source_domain before reading log events".to_string(),
        ))
    } else {
        match backend.events(&EventsRequest {
            start_time: request.start_time.clone(),
            end_time: request.end_time.clone(),
            action: None,
            message_id: None,
            header_name: None,
            header_value: None,
            receiving_domain: None,
            source_domain: source_domain.clone(),
            limit: request.limit,
            compartment_id: request.compartment_id.clone(),
        }) {
            Ok(report) => {
                findings.extend(report.findings.clone());
                evidence.extend(report.evidence.clone());
                ToolCallOutcome::ok(report.status.clone(), report)
            }
            Err(error) => component_blocked(
                &mut findings,
                "events_read_blocked",
                "OCI Email Delivery log event read failed; event ingestion is not proven for this window.",
                error,
            ),
        }
    };

    let trace_requested = trace_requested(request);
    let trace = trace_requested.then(|| {
        if events_scope_missing {
            return ToolCallOutcome::blocked(OciEmailError::InvalidInput(
                "watch_window requires source_domain before tracing a message".to_string(),
            ));
        }
        match backend.trace_message(&TraceMessageRequest {
            start_time: request.start_time.clone(),
            end_time: request.end_time.clone(),
            message_id: request.message_id.clone(),
            header_name: request.header_name.clone(),
            header_value: request.header_value.clone(),
            source_domain: source_domain.clone(),
            limit: request.limit,
            compartment_id: request.compartment_id.clone(),
        }) {
            Ok(report) => {
                findings.extend(report.events.findings.clone());
                evidence.extend(report.events.evidence.clone());
                ToolCallOutcome::ok(report.status.clone(), report)
            }
            Err(error) => component_blocked(
                &mut findings,
                "trace_read_blocked",
                "Seed/proof trace read failed; message-level correlation is not proven for this window.",
                error,
            ),
        }
    });

    let suppressions = match backend.suppressions(&SuppressionsRequest {
        time_created_greater_than_or_equal_to: Some(request.start_time.clone()),
        time_created_less_than: Some(request.end_time.clone()),
        limit: request.limit,
        compartment_id: request.compartment_id.clone(),
    }) {
        Ok(report) => {
            findings.extend(report.findings.clone());
            evidence.extend(report.evidence.clone());
            ToolCallOutcome::ok(report.status.clone(), report)
        }
        Err(error) => component_blocked(
            &mut findings,
            "suppressions_read_blocked",
            "OCI suppression read failed; clean-audience reconciliation is not proven for this window.",
            error,
        ),
    };

    let components = WatchWindowComponents {
        status,
        logging,
        metrics,
        events,
        trace,
        suppressions,
    };
    let status = watch_status(&components, &findings);
    let decision = match status.as_str() {
        "blocked" => "remain_paused".to_string(),
        "degraded" => "hold_or_seed_only_with_operator_review".to_string(),
        _ => "monitoring_window_clean_no_send_authorization".to_string(),
    };

    WatchWindowReport {
        status,
        decision,
        send_authorized: false,
        start_time: request.start_time.clone(),
        end_time: request.end_time.clone(),
        interval,
        resource_domain,
        source_domain,
        trace_requested,
        components,
        findings,
        evidence,
        raw_payload_returned: false,
    }
}

fn compose_suppression_delta<B: OciEmailBackend + ?Sized>(
    backend: &B,
    request: &SuppressionDeltaRequest,
) -> SuppressionDeltaReport {
    let mut findings = Vec::new();
    let mut evidence = Vec::new();

    let post_active = match backend.suppressions(&SuppressionsRequest {
        time_created_greater_than_or_equal_to: None,
        time_created_less_than: None,
        limit: request.limit,
        compartment_id: request.compartment_id.clone(),
    }) {
        Ok(report) => {
            findings.extend(report.findings.clone());
            evidence.extend(report.evidence.clone());
            ToolCallOutcome::ok(report.status.clone(), report)
        }
        Err(error) => component_blocked(
            &mut findings,
            "suppression_delta_post_active_read_blocked",
            "Full active suppression read failed; post-window active suppression state is not proven.",
            error,
        ),
    };

    let window_new = match backend.suppressions(&SuppressionsRequest {
        time_created_greater_than_or_equal_to: Some(request.start_time.clone()),
        time_created_less_than: Some(request.end_time.clone()),
        limit: request.limit,
        compartment_id: request.compartment_id.clone(),
    }) {
        Ok(report) => {
            findings.extend(report.findings.clone());
            evidence.extend(report.evidence.clone());
            ToolCallOutcome::ok(report.status.clone(), report)
        }
        Err(error) => component_blocked(
            &mut findings,
            "suppression_delta_window_read_blocked",
            "Bounded suppression delta read failed; new active suppressions for this window are not proven.",
            error,
        ),
    };

    let summary =
        suppression_delta_summary(post_active.report.as_ref(), window_new.report.as_ref());
    add_suppression_delta_findings(&mut findings, &summary, &post_active, &window_new);
    let status = suppression_delta_status(&findings, &post_active, &window_new);
    let decision = match status.as_str() {
        "blocked" => "suppression_delta_blocked".to_string(),
        "degraded" => "suppression_delta_incomplete_no_clean_proof".to_string(),
        _ => "suppression_delta_clean_no_send_authorization".to_string(),
    };

    SuppressionDeltaReport {
        status,
        decision,
        send_authorized: false,
        start_time: request.start_time.clone(),
        end_time: request.end_time.clone(),
        summary,
        components: SuppressionDeltaComponents {
            post_active,
            window_new,
        },
        findings,
        evidence,
        raw_payload_returned: false,
    }
}

fn suppression_delta_summary(
    post_active: Option<&SuppressionsReport>,
    window_new: Option<&SuppressionsReport>,
) -> SuppressionDeltaSummary {
    let post_active_total = post_active.map(|report| report.total_matched).unwrap_or(0);
    let window_new_active = window_new.map(|report| report.total_matched).unwrap_or(0);
    let post_active_complete = post_active
        .map(|report| report.count_state == "complete")
        .unwrap_or(false);
    let window_new_complete = window_new
        .map(|report| report.count_state == "complete")
        .unwrap_or(false);
    let active_outside_window_total = (post_active_complete && window_new_complete)
        .then(|| post_active_total.saturating_sub(window_new_active));
    let window_new_hard_bounce = window_new
        .map(|report| report.totals.hard_bounce)
        .unwrap_or(0);
    let window_new_complaint = window_new
        .map(|report| suppression_reason_count(&report.totals, "complaint"))
        .unwrap_or(0);
    let window_new_other =
        window_new_active.saturating_sub(window_new_hard_bounce + window_new_complaint);

    SuppressionDeltaSummary {
        post_active_total,
        post_active_count_state: post_active
            .map(|report| report.count_state.clone())
            .unwrap_or_else(|| "unavailable".to_string()),
        active_outside_window_total,
        window_new_active,
        window_new_count_state: window_new
            .map(|report| report.count_state.clone())
            .unwrap_or_else(|| "unavailable".to_string()),
        window_new_hard_bounce,
        window_new_complaint,
        window_new_other,
        newest_active_time_created: post_active
            .and_then(|report| report.newest_time_created.clone()),
        newest_window_time_created: window_new
            .and_then(|report| report.newest_time_created.clone()),
    }
}

fn add_suppression_delta_findings(
    findings: &mut Vec<ReadinessFinding>,
    summary: &SuppressionDeltaSummary,
    post_active: &ToolCallOutcome<SuppressionsReport>,
    window_new: &ToolCallOutcome<SuppressionsReport>,
) {
    if summary.window_new_hard_bounce > 0 {
        findings.push(finding(
            "blocker",
            "suppression_delta_new_hard_bounce",
            "New active hard-bounce suppressions were created in this window; clean-audience reconciliation is not proven.",
        ));
    }
    if summary.window_new_complaint > 0 {
        findings.push(finding(
            "blocker",
            "suppression_delta_new_complaint",
            "New active complaint suppressions were created in this window; clean-audience reconciliation is not proven.",
        ));
    }
    if summary.window_new_other > 0 {
        findings.push(finding(
            "warning",
            "suppression_delta_new_other",
            "New active suppressions with non-hard-bounce and non-complaint reasons were created in this window; operator review is required before treating the audience as clean.",
        ));
    }
    if post_active
        .report
        .as_ref()
        .is_some_and(|report| report.count_state != "complete")
    {
        findings.push(finding(
            "warning",
            "suppression_delta_post_active_incomplete",
            "Full active suppression read was capped or degraded; total active suppression state is a lower bound or unavailable.",
        ));
    }
    if window_new
        .report
        .as_ref()
        .is_some_and(|report| report.count_state != "complete")
    {
        findings.push(finding(
            "warning",
            "suppression_delta_window_incomplete",
            "Bounded suppression read was capped or degraded; absence of new suppressions is not proven for this window.",
        ));
    }
}

fn suppression_delta_status(
    findings: &[ReadinessFinding],
    post_active: &ToolCallOutcome<SuppressionsReport>,
    window_new: &ToolCallOutcome<SuppressionsReport>,
) -> String {
    if findings.iter().any(|item| item.severity == "blocker")
        || component_blocked_status(post_active)
        || component_blocked_status(window_new)
    {
        return "blocked".to_string();
    }
    if !findings.is_empty()
        || component_degraded_status(post_active)
        || component_degraded_status(window_new)
    {
        return "degraded".to_string();
    }
    "ok".to_string()
}

fn compose_send_readiness<B: OciEmailBackend + ?Sized>(
    backend: &B,
    request: &SendReadinessRequest,
) -> SendReadinessReport {
    let watch_request = WatchWindowRequest {
        start_time: request.start_time.clone(),
        end_time: request.end_time.clone(),
        interval: request.interval.clone(),
        resource_domain: request.resource_domain.clone(),
        source_domain: request.source_domain.clone(),
        resource_id: request.resource_id.clone(),
        message_id: request.message_id.clone(),
        header_name: request.header_name.clone(),
        header_value: request.header_value.clone(),
        limit: request.limit,
        compartment_id: request.compartment_id.clone(),
    };
    let mut watch_report = compose_watch_window(backend, &watch_request);
    redact_watch_trace_header_names_for_readiness(&mut watch_report);
    let mut findings = watch_report.findings.clone();
    let mut evidence = watch_report.evidence.clone();
    let sender_domain = non_empty_request_value(&request.sender_domain)
        .or_else(|| watch_report.source_domain.clone())
        .or_else(|| watch_report.resource_domain.clone());
    let campaign_id = non_empty_string(&request.campaign_id);
    let batch_id = non_empty_string(&request.batch_id);
    let campaign_hash = campaign_id.as_deref().map(short_hash);
    let batch_hash = batch_id.as_deref().map(short_hash);

    if campaign_id.is_none() {
        findings.push(finding(
            "blocker",
            "campaign_id_missing",
            "Send-readiness receipts require campaign_id so local ledger proof cannot pass on a sender-domain-only row count.",
        ));
    }
    if batch_id.is_none() {
        findings.push(finding(
            "blocker",
            "batch_id_missing",
            "Send-readiness receipts require batch_id so local ledger proof cannot pass on a sender-domain-only row count.",
        ));
    }
    if request.expected_ledger_rows == 0 {
        findings.push(finding(
            "blocker",
            "expected_ledger_rows_zero",
            "Send-readiness receipts require at least one expected local ledger row.",
        ));
    }

    let ledger_requirements_ready =
        campaign_id.is_some() && batch_id.is_some() && request.expected_ledger_rows > 0;
    let ledger = if !ledger_requirements_ready {
        component_blocked(
            &mut findings,
            "ledger_requirements_missing",
            "Local send-ledger read skipped because campaign_id, batch_id, and expected_ledger_rows must all be present before a send-readiness receipt can read ledger rows.",
            OciEmailError::InvalidInput(
                "send_readiness requires campaign_id, batch_id, and expected_ledger_rows before reading the local send ledger".to_string(),
            ),
        )
    } else if let Some(sender_domain_value) = sender_domain.clone() {
        match backend.ledger_window(&LedgerWindowRequest {
            start_time: request.start_time.clone(),
            end_time: request.end_time.clone(),
            sender_domain: Some(sender_domain_value),
            campaign_id,
            batch_id,
            message_id: request.message_id.clone(),
            correlation_id: request.header_value.clone(),
            limit: request.limit,
        }) {
            Ok(report) => {
                findings.extend(report.findings.clone());
                add_send_readiness_ledger_findings(&mut findings, &report, request);
                evidence.extend(report.evidence.clone());
                ToolCallOutcome::ok(report.status.clone(), report)
            }
            Err(error) => component_blocked(
                &mut findings,
                "ledger_read_blocked",
                "Local send-ledger read failed; pre-submission ledger proof is not available for this window.",
                error,
            ),
        }
    } else {
        component_blocked(
            &mut findings,
            "ledger_scope_missing",
            "Send-readiness receipts require sender_domain, source_domain, or resource_domain before reading the local send ledger.",
            OciEmailError::InvalidInput(
                "send_readiness requires sender_domain, source_domain, or resource_domain before reading the local send ledger".to_string(),
            ),
        )
    };

    let status = send_readiness_status(&watch_report, &ledger, &findings);
    let decision = match status.as_str() {
        "blocked" => "remain_paused".to_string(),
        "degraded" => "hold_or_seed_only_with_operator_review".to_string(),
        _ => "monitoring_and_ledger_ready_no_send_authorization".to_string(),
    };
    let interval = watch_report.interval.clone();
    let resource_domain = watch_report.resource_domain.clone();
    let source_domain = watch_report.source_domain.clone();
    let trace_requested = watch_report.trace_requested;

    SendReadinessReport {
        status,
        decision,
        send_authorized: false,
        start_time: request.start_time.clone(),
        end_time: request.end_time.clone(),
        interval,
        resource_domain,
        source_domain,
        sender_domain,
        campaign_hash,
        batch_hash,
        expected_ledger_rows: request.expected_ledger_rows,
        trace_requested,
        components: SendReadinessComponents {
            watch_window: ToolCallOutcome::ok(watch_report.status.clone(), watch_report),
            ledger,
        },
        findings,
        evidence,
        raw_payload_returned: false,
    }
}

fn compose_traceability_audit<B: OciEmailBackend + ?Sized>(
    backend: &B,
    request: &TraceabilityAuditRequest,
) -> TraceabilityAuditReport {
    let watch_request = WatchWindowRequest {
        start_time: request.start_time.clone(),
        end_time: request.end_time.clone(),
        interval: request.interval.clone(),
        resource_domain: request.resource_domain.clone(),
        source_domain: request.source_domain.clone(),
        resource_id: request.resource_id.clone(),
        message_id: request.message_id.clone(),
        header_name: request.header_name.clone(),
        header_value: request.header_value.clone(),
        limit: request.limit,
        compartment_id: request.compartment_id.clone(),
    };
    let mut watch_report = compose_watch_window(backend, &watch_request);
    redact_watch_trace_header_names_for_readiness(&mut watch_report);
    let mut findings = watch_report.findings.clone();
    let mut evidence = watch_report.evidence.clone();
    let sender_domain = non_empty_request_value(&request.sender_domain)
        .or_else(|| watch_report.source_domain.clone())
        .or_else(|| watch_report.resource_domain.clone());
    let campaign_id = request.campaign_id.as_deref().and_then(non_empty_string);
    let batch_id = request.batch_id.as_deref().and_then(non_empty_string);
    let expected_rows = request.expected_ledger_rows.filter(|value| *value > 0);
    let expected_rows_zero = request.expected_ledger_rows == Some(0);
    if expected_rows_zero {
        findings.push(finding(
            "blocker",
            "traceability_expected_ledger_rows_zero",
            "Traceability audits cannot prove an exact message when expected_ledger_rows is explicitly zero.",
        ));
    }

    let ledger = match sender_domain.clone() {
        Some(sender_domain) => match backend.ledger_window(&LedgerWindowRequest {
            start_time: request.start_time.clone(),
            end_time: request.end_time.clone(),
            sender_domain: Some(sender_domain),
            campaign_id,
            batch_id,
            message_id: request.message_id.clone(),
            correlation_id: request.header_value.clone(),
            limit: request.limit,
        }) {
            Ok(report) => {
                findings.extend(report.findings.clone());
                evidence.extend(report.evidence.clone());
                ToolCallOutcome::ok(report.status.clone(), report)
            }
            Err(error) => component_blocked(
                &mut findings,
                "ledger_read_blocked",
                "Local send-ledger read failed; exact traceability cannot be proven for this audit window.",
                error,
            ),
        },
        None => component_blocked(
            &mut findings,
            "ledger_scope_missing",
            "Traceability audits require sender_domain, source_domain, or resource_domain before reading the local send ledger.",
            OciEmailError::InvalidInput(
                "traceability_audit requires sender_domain, source_domain, or resource_domain before reading the local send ledger".to_string(),
            ),
        ),
    };

    if let Some(report) = ledger.report.as_ref() {
        if let Some(expected) = expected_rows {
            let matched = report.totals.matched_rows as u64;
            if matched != expected {
                findings.push(finding(
                    "blocker",
                    "traceability_expected_ledger_rows_mismatch",
                    "Local send-ledger matched row count does not equal expected_ledger_rows; exact message traceability is not proven for this audit window.",
                ));
            }
        }
        if report.totals.matched_rows == 0 {
            findings.push(finding(
                "blocker",
                "traceability_no_ledger_rows",
                "No local send-ledger rows matched this audit window and filters; exact message traceability is not proven.",
            ));
        }
        if report.totals.invalid_rows > 0 {
            findings.push(finding(
                "blocker",
                "ledger_invalid_rows_block_traceability",
                "Local send-ledger contains invalid rows in this window; narrow or repair the ledger before traceability proof.",
            ));
        }
        if report.totals.rows_capped {
            findings.push(finding(
                "blocker",
                "ledger_rows_capped_block_traceability",
                "Local send-ledger rows were capped; narrow the window before traceability proof.",
            ));
        }
        if report.totals.missing_trace_key_count > 0 {
            findings.push(finding(
                "blocker",
                "ledger_missing_trace_keys_block_traceability",
                "Local send-ledger rows are missing message or correlation identifiers needed for exact OCI traceability.",
            ));
        }
        if report.totals.missing_recipient_key_count > 0 {
            findings.push(finding(
                "blocker",
                "ledger_missing_recipient_keys_block_traceability",
                "Local send-ledger rows are missing recipient hashes needed for recipient-level reconciliation.",
            ));
        }
    }

    let trace_requested = watch_report.trace_requested;
    let ledger_trace_key_overlap = ledger_trace_key_overlap(ledger.report.as_ref(), &watch_report);
    let recipient_hash_overlap = recipient_hash_overlap(ledger.report.as_ref(), &watch_report);
    let single_ledger_row_overlap =
        single_ledger_row_overlap(ledger.report.as_ref(), &watch_report);
    let log_events_returned = log_events_returned(&watch_report);
    let trace_events_returned = trace_events_returned(&watch_report);
    let ledger_exact_ready = ledger.report.as_ref().is_some_and(|report| {
        report.totals.matched_rows > 0
            && report.totals.invalid_rows == 0
            && !report.totals.rows_capped
            && report.totals.missing_trace_key_count == 0
            && report.totals.missing_recipient_key_count == 0
    });
    let exact_message_traceable = trace_requested
        && !expected_rows_zero
        && trace_events_returned.is_some_and(|returned| returned > 0)
        && ledger_exact_ready
        && ledger_trace_key_overlap
        && recipient_hash_overlap
        && single_ledger_row_overlap;
    let aggregate_only = !exact_message_traceable;
    if !trace_requested {
        findings.push(finding(
            "blocker",
            "traceability_trace_criteria_missing",
            "No message id or correlation header trace was requested; exact message traceability cannot be proven from aggregate metrics.",
        ));
    }
    if log_events_returned == 0 {
        findings.push(finding(
            "blocker",
            "traceability_no_log_events",
            "OCI Email Delivery logs returned no events for this audit window; aggregate metrics are not exact message proof.",
        ));
    }
    if trace_requested && trace_events_returned.unwrap_or(0) == 0 {
        findings.push(finding(
            "blocker",
            "traceability_no_trace_events",
            "The requested message or correlation trace returned no OCI Email Delivery log events.",
        ));
    }
    if trace_requested
        && ledger
            .report
            .as_ref()
            .is_some_and(|report| report.totals.matched_rows > 0)
        && !ledger_trace_key_overlap
    {
        findings.push(finding(
            "blocker",
            "traceability_no_ledger_trace_key_overlap",
            "Requested message or correlation trace did not overlap the local send-ledger trace keys.",
        ));
    }
    if trace_requested
        && ledger
            .report
            .as_ref()
            .is_some_and(|report| report.totals.matched_rows > 0)
        && log_events_returned > 0
        && !recipient_hash_overlap
    {
        findings.push(finding(
            "blocker",
            "traceability_no_recipient_hash_overlap",
            "OCI log events did not overlap local send-ledger recipient hashes; recipient-level traceability is not proven.",
        ));
    }
    if trace_requested
        && ledger_trace_key_overlap
        && recipient_hash_overlap
        && !single_ledger_row_overlap
    {
        findings.push(finding(
            "blocker",
            "traceability_no_single_ledger_row_overlap",
            "No single local send-ledger row overlapped both the requested OCI trace key and recipient hash; exact message-to-recipient traceability is not proven.",
        ));
    }
    if aggregate_only {
        findings.push(finding(
            "warning",
            "traceability_aggregate_only",
            "This audit has aggregate delivery pressure but not exact message-to-recipient traceability across OCI logs and the local ledger.",
        ));
    }

    let summary = traceability_summary(&watch_report, ledger.report.as_ref());
    let status = traceability_status(&watch_report, &ledger, &findings, exact_message_traceable);
    let decision = match status.as_str() {
        "blocked" => "remain_paused".to_string(),
        "degraded" => "hold_or_seed_only_with_operator_review".to_string(),
        _ => "exact_traceability_ready_no_send_authorization".to_string(),
    };
    let interval = watch_report.interval.clone();
    let resource_domain = watch_report.resource_domain.clone();
    let source_domain = watch_report.source_domain.clone();

    TraceabilityAuditReport {
        status,
        decision,
        send_authorized: false,
        start_time: request.start_time.clone(),
        end_time: request.end_time.clone(),
        interval,
        resource_domain,
        source_domain,
        sender_domain,
        expected_ledger_rows: request.expected_ledger_rows,
        trace_requested,
        exact_message_traceable,
        aggregate_only,
        summary,
        components: TraceabilityAuditComponents {
            watch_window: ToolCallOutcome::ok(watch_report.status.clone(), watch_report),
            ledger,
        },
        findings,
        evidence,
        raw_payload_returned: false,
    }
}

fn traceability_summary(
    watch_report: &WatchWindowReport,
    ledger_report: Option<&LedgerWindowReport>,
) -> TraceabilitySummary {
    let metrics = watch_report
        .components
        .metrics
        .report
        .as_ref()
        .map(|report| &report.totals);
    TraceabilitySummary {
        aggregate_accepted: metrics.map(|totals| totals.accepted),
        aggregate_relayed: metrics.map(|totals| totals.relayed),
        aggregate_hard_bounced: metrics.map(|totals| totals.hard_bounced),
        aggregate_suppressed: metrics.map(|totals| totals.suppressed),
        log_events_returned: log_events_returned(watch_report),
        trace_events_returned: trace_events_returned(watch_report),
        ledger_rows_matched: ledger_report
            .map(|report| report.totals.matched_rows)
            .unwrap_or(0),
        ledger_rows_capped: ledger_report
            .map(|report| report.totals.rows_capped)
            .unwrap_or(false),
        ledger_trace_key_overlap: ledger_trace_key_overlap(ledger_report, watch_report),
        recipient_hash_overlap: recipient_hash_overlap(ledger_report, watch_report),
        single_ledger_row_overlap: single_ledger_row_overlap(ledger_report, watch_report),
    }
}

fn trace_events_returned(watch_report: &WatchWindowReport) -> Option<usize> {
    watch_report
        .components
        .trace
        .as_ref()
        .and_then(|trace| trace.report.as_ref())
        .map(|report| report.events.returned)
}

fn log_events_returned(watch_report: &WatchWindowReport) -> usize {
    let events_returned = watch_report
        .components
        .events
        .report
        .as_ref()
        .map(|report| report.returned)
        .unwrap_or(0);
    let trace_events_returned = trace_events_returned(watch_report).unwrap_or(0);
    events_returned.max(trace_events_returned)
}

fn ledger_trace_key_overlap(
    ledger_report: Option<&LedgerWindowReport>,
    watch_report: &WatchWindowReport,
) -> bool {
    let Some(ledger_report) = ledger_report else {
        return false;
    };
    ledger_report
        .rows
        .iter()
        .any(|row| ledger_row_trace_key_overlap(row, watch_report))
}

fn recipient_hash_overlap(
    ledger_report: Option<&LedgerWindowReport>,
    watch_report: &WatchWindowReport,
) -> bool {
    let Some(ledger_report) = ledger_report else {
        return false;
    };
    ledger_report
        .rows
        .iter()
        .any(|row| ledger_row_recipient_hash_overlap(row, watch_report))
}

fn single_ledger_row_overlap(
    ledger_report: Option<&LedgerWindowReport>,
    watch_report: &WatchWindowReport,
) -> bool {
    let Some(ledger_report) = ledger_report else {
        return false;
    };
    ledger_report.rows.iter().any(|row| {
        ledger_row_trace_key_overlap(row, watch_report)
            && ledger_row_recipient_hash_overlap(row, watch_report)
    })
}

fn ledger_row_trace_key_overlap(row: &LedgerRowSummary, watch_report: &WatchWindowReport) -> bool {
    let trace = watch_report
        .components
        .trace
        .as_ref()
        .and_then(|trace| trace.report.as_ref());
    if let Some(trace) = trace {
        return row
            .message_id_hash
            .as_ref()
            .is_some_and(|hash| trace.criteria.message_id_hash.as_ref() == Some(hash))
            || row
                .correlation_id_hash
                .as_ref()
                .is_some_and(|hash| trace.criteria.header_value_hash.as_ref() == Some(hash));
    }
    watch_report
        .components
        .events
        .report
        .as_ref()
        .is_some_and(|events| {
            events.events.iter().any(|event| {
                row.message_id_hash
                    .as_ref()
                    .is_some_and(|hash| event.message_id_hash.as_ref() == Some(hash))
            })
        })
}

fn ledger_row_recipient_hash_overlap(
    row: &LedgerRowSummary,
    watch_report: &WatchWindowReport,
) -> bool {
    let trace_report = watch_report
        .components
        .trace
        .as_ref()
        .and_then(|trace| trace.report.as_ref());
    [
        row.recipient_address_hash.as_ref(),
        row.recipient_id_hash.as_ref(),
    ]
    .into_iter()
    .flatten()
    .any(|hash| match trace_report {
        Some(trace) => trace_recipient_hash_overlap(hash, trace),
        None => watch_report
            .components
            .events
            .report
            .as_ref()
            .is_some_and(|events| {
                events
                    .events
                    .iter()
                    .any(|event| event.recipient_hash.as_ref() == Some(hash))
            }),
    })
}

fn trace_recipient_hash_overlap(hash: &str, trace: &TraceMessageReport) -> bool {
    trace
        .events
        .events
        .iter()
        .any(|event| event.recipient_hash.as_deref() == Some(hash))
}

fn traceability_status(
    watch_report: &WatchWindowReport,
    ledger: &ToolCallOutcome<LedgerWindowReport>,
    findings: &[ReadinessFinding],
    exact_message_traceable: bool,
) -> String {
    if findings.iter().any(|item| item.severity == "blocker")
        || watch_report.status == "blocked"
        || component_blocked_status(ledger)
    {
        return "blocked".to_string();
    }
    if !exact_message_traceable
        || !findings.is_empty()
        || !matches!(watch_report.status.as_str(), "ok" | "ready")
        || component_degraded_status(ledger)
    {
        return "degraded".to_string();
    }
    "ok".to_string()
}

fn add_send_readiness_ledger_findings(
    findings: &mut Vec<ReadinessFinding>,
    report: &LedgerWindowReport,
    request: &SendReadinessRequest,
) {
    let expected = request.expected_ledger_rows;
    let matched = report.totals.matched_rows as u64;
    if expected > 0 && matched != expected {
        findings.push(finding(
            "blocker",
            "ledger_expected_rows_mismatch",
            "Local send-ledger matched row count does not equal expected_ledger_rows; do not treat this send window as traceable.",
        ));
    }
    if report.totals.invalid_rows > 0 {
        findings.push(finding(
            "blocker",
            "ledger_invalid_rows_block_readiness",
            "Local send-ledger contains invalid rows in this window; narrow or repair the ledger before send readiness.",
        ));
    }
    if report.totals.rows_capped {
        findings.push(finding(
            "blocker",
            "ledger_rows_capped_block_readiness",
            "Local send-ledger rows were capped; narrow the window before send readiness.",
        ));
    }
    if report.totals.missing_trace_key_count > 0 {
        findings.push(finding(
            "blocker",
            "ledger_missing_trace_keys_block_readiness",
            "Local send-ledger rows are missing message or correlation identifiers needed for OCI traceability.",
        ));
    }
    if report.totals.missing_recipient_key_count > 0 {
        findings.push(finding(
            "blocker",
            "ledger_missing_recipient_keys_block_readiness",
            "Local send-ledger rows are missing recipient hashes needed for clean-audience reconciliation.",
        ));
    }
}

fn redact_watch_trace_header_names_for_readiness(report: &mut WatchWindowReport) {
    let Some(trace) = report.components.trace.as_mut() else {
        return;
    };
    let Some(trace_report) = trace.report.as_mut() else {
        return;
    };
    trace_report.criteria.header_name = trace_report
        .criteria
        .header_name
        .take()
        .map(|_| "[redacted]".to_string());
    trace_report.events.filters.header_name = trace_report
        .events
        .filters
        .header_name
        .take()
        .map(|_| "[redacted]".to_string());
}

fn send_readiness_status(
    watch_report: &WatchWindowReport,
    ledger: &ToolCallOutcome<LedgerWindowReport>,
    findings: &[ReadinessFinding],
) -> String {
    if findings.iter().any(|item| item.severity == "blocker")
        || watch_report.status == "blocked"
        || component_blocked_status(ledger)
    {
        return "blocked".to_string();
    }
    if !findings.is_empty()
        || !matches!(watch_report.status.as_str(), "ok" | "ready")
        || component_degraded_status(ledger)
    {
        return "degraded".to_string();
    }
    "ok".to_string()
}

fn non_empty_request_value(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn non_empty_string(value: &str) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn component_blocked<T>(
    findings: &mut Vec<ReadinessFinding>,
    code: &str,
    message: &str,
    error: OciEmailError,
) -> ToolCallOutcome<T> {
    findings.push(finding("blocker", code, message));
    ToolCallOutcome::blocked(error)
}

fn trace_requested(request: &WatchWindowRequest) -> bool {
    !request.message_id.as_deref().unwrap_or_default().is_empty()
        || !request
            .header_name
            .as_deref()
            .unwrap_or_default()
            .is_empty()
        || !request
            .header_value
            .as_deref()
            .unwrap_or_default()
            .is_empty()
}

fn watch_status(components: &WatchWindowComponents, findings: &[ReadinessFinding]) -> String {
    if findings.iter().any(|item| item.severity == "blocker")
        || component_blocked_status(&components.status)
        || component_blocked_status(&components.logging)
        || component_blocked_status(&components.metrics)
        || component_blocked_status(&components.events)
        || components
            .trace
            .as_ref()
            .is_some_and(component_blocked_status)
        || component_blocked_status(&components.suppressions)
    {
        return "blocked".to_string();
    }
    if !findings.is_empty()
        || component_degraded_status(&components.status)
        || component_degraded_status(&components.logging)
        || component_degraded_status(&components.metrics)
        || component_degraded_status(&components.events)
        || components
            .trace
            .as_ref()
            .is_some_and(component_degraded_status)
        || component_degraded_status(&components.suppressions)
    {
        return "degraded".to_string();
    }
    "ok".to_string()
}

fn component_blocked_status<T>(component: &ToolCallOutcome<T>) -> bool {
    component.status == "blocked"
}

fn component_degraded_status<T>(component: &ToolCallOutcome<T>) -> bool {
    !matches!(component.status.as_str(), "ok" | "ready")
}

fn metric_query(
    metric: &str,
    interval: &str,
    resource_domain: Option<&str>,
    resource_id: Option<&str>,
) -> String {
    let mut filters = Vec::new();
    if let Some(domain) = resource_domain {
        filters.push(format!("resourceDomain = \"{domain}\""));
    }
    if let Some(id) = resource_id {
        filters.push(format!("resourceId = \"{id}\""));
    }
    if filters.is_empty() {
        format!("{metric}[{interval}].sum()")
    } else {
        format!("{metric}[{interval}]{{{}}}.sum()", filters.join(", "))
    }
}

fn metric_query_for_output(
    metric: &str,
    interval: &str,
    resource_domain: Option<&str>,
    resource_id: Option<&str>,
) -> String {
    let redacted_resource_id = resource_id.map(crate::redact::redact_ocid);
    metric_query(
        metric,
        interval,
        resource_domain,
        redacted_resource_id.as_deref(),
    )
}

fn metric_total(value: &Value) -> (f64, usize, usize) {
    let mut total = 0.0;
    let mut points = 0;
    let series = json_items(value);
    for item in &series {
        let Some(datapoints) = item.get("aggregated-datapoints").and_then(Value::as_array) else {
            continue;
        };
        for point in datapoints {
            if let Some(value) = point.get("value").and_then(Value::as_f64) {
                total += value;
                points += 1;
            }
        }
    }
    (total, points, series.len())
}

fn assign_metric_total(totals: &mut MetricTotals, key: &str, total: f64) {
    match key {
        "accepted" => totals.accepted = total,
        "relayed" => totals.relayed = total,
        "hard_bounced" => totals.hard_bounced = total,
        "soft_bounced" => totals.soft_bounced = total,
        "suppressed" => totals.suppressed = total,
        "complaints" => totals.complaints = total,
        "blocklisted" => totals.blocklisted = total,
        "list_unsubscribed" => totals.list_unsubscribed = total,
        "opened" => totals.opened = total,
        "clicked" => totals.clicked = total,
        _ => {}
    }
}

fn metric_rates(totals: &MetricTotals, available_keys: &BTreeSet<String>) -> MetricRates {
    MetricRates {
        relay_rate: ratio_if_known(
            totals.relayed,
            totals.accepted,
            available_keys,
            "relayed",
            "accepted",
        ),
        hard_bounce_rate: ratio_if_known(
            totals.hard_bounced,
            totals.accepted,
            available_keys,
            "hard_bounced",
            "accepted",
        ),
        soft_bounce_rate: ratio_if_known(
            totals.soft_bounced,
            totals.accepted,
            available_keys,
            "soft_bounced",
            "accepted",
        ),
        complaint_rate: ratio_if_known(
            totals.complaints,
            totals.accepted,
            available_keys,
            "complaints",
            "accepted",
        ),
        blocklist_rate: ratio_if_known(
            totals.blocklisted,
            totals.accepted,
            available_keys,
            "blocklisted",
            "accepted",
        ),
        unsubscribe_rate: ratio_if_known(
            totals.list_unsubscribed,
            totals.relayed,
            available_keys,
            "list_unsubscribed",
            "relayed",
        ),
    }
}

fn is_stop_gate_metric_key(key: &str) -> bool {
    matches!(
        key,
        "hard_bounced" | "soft_bounced" | "suppressed" | "complaints" | "blocklisted"
    )
}

fn ratio_if_known(
    numerator: f64,
    denominator: f64,
    available_keys: &BTreeSet<String>,
    numerator_key: &str,
    denominator_key: &str,
) -> Option<f64> {
    if !available_keys.contains(numerator_key) || !available_keys.contains(denominator_key) {
        return None;
    }
    ratio(numerator, denominator)
}

fn ratio(numerator: f64, denominator: f64) -> Option<f64> {
    (denominator > 0.0).then_some(numerator / denominator)
}

fn suppression_summary(value: &Value) -> SuppressionSummary {
    let email = string_field(value, "email-address")
        .or_else(|| string_field(value, "emailAddress"))
        .or_else(|| string_field(value, "recipient"));
    SuppressionSummary {
        time_created: string_field(value, "time-created")
            .or_else(|| string_field(value, "timeCreated"))
            .map(ToString::to_string),
        reason: string_field(value, "reason").map(redact_sensitive_text),
        recipient_redacted: email.map(redact_email),
        recipient_domain: email.and_then(email_domain),
        recipient_hash: email.map(short_hash),
        raw_payload_returned: false,
    }
}

fn log_group_summary(value: &Value) -> LogGroupSummary {
    LogGroupSummary {
        log_group_id: RedactedIdentifier::from_optional(string_field(value, "id")),
        display_name_hash: string_field(value, "display-name")
            .or_else(|| string_field(value, "displayName"))
            .map(short_hash),
        lifecycle_state: lifecycle_state(value),
        raw_payload_returned: false,
    }
}

fn email_delivery_log_summary(
    value: &Value,
    fallback_log_group_id: &str,
) -> EmailDeliveryLogSummary {
    let source = value
        .get("configuration")
        .and_then(|configuration| configuration.get("source"));
    let log_group_id = string_field(value, "log-group-id")
        .or_else(|| string_field(value, "logGroupId"))
        .unwrap_or(fallback_log_group_id);
    let source_resource = source
        .and_then(|source| {
            string_field(source, "resource")
                .or_else(|| string_field(source, "source-resource"))
                .or_else(|| string_field(source, "sourceResource"))
        })
        .or_else(|| string_field(value, "source-resource"))
        .or_else(|| string_field(value, "sourceResource"));

    EmailDeliveryLogSummary {
        log_id: RedactedIdentifier::from_optional(string_field(value, "id")),
        log_group_id: RedactedIdentifier::from_optional(Some(log_group_id)),
        display_name_hash: string_field(value, "display-name")
            .or_else(|| string_field(value, "displayName"))
            .map(short_hash),
        lifecycle_state: lifecycle_state(value),
        source_service: source_service(value).map(|service| service.to_ascii_lowercase()),
        source_resource: RedactedIdentifier::from_optional(source_resource),
        source_category: source
            .and_then(|source| {
                string_field(source, "category")
                    .or_else(|| string_field(source, "source-category"))
                    .or_else(|| string_field(source, "sourceCategory"))
            })
            .or_else(|| string_field(value, "source-category"))
            .or_else(|| string_field(value, "sourceCategory"))
            .map(redact_sensitive_text),
        source_kind: source
            .and_then(|source| string_field(source, "kind"))
            .or_else(|| string_field(value, "source-kind"))
            .or_else(|| string_field(value, "sourceKind"))
            .map(redact_sensitive_text),
        raw_payload_returned: false,
    }
}

fn is_email_delivery_service_log(value: &Value) -> bool {
    let service_is_email_delivery = source_service(value).is_none_or(|service| {
        service
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .collect::<String>()
            .eq_ignore_ascii_case("emaildelivery")
    });
    let log_type_is_service = string_field(value, "log-type")
        .or_else(|| string_field(value, "logType"))
        .is_none_or(|log_type| log_type.eq_ignore_ascii_case("SERVICE"));
    service_is_email_delivery && log_type_is_service
}

fn source_service(value: &Value) -> Option<&str> {
    value
        .get("configuration")
        .and_then(|configuration| configuration.get("source"))
        .and_then(|source| {
            string_field(source, "service")
                .or_else(|| string_field(source, "source-service"))
                .or_else(|| string_field(source, "sourceService"))
        })
        .or_else(|| string_field(value, "source-service"))
        .or_else(|| string_field(value, "sourceService"))
}

fn lifecycle_state(value: &Value) -> Option<String> {
    string_field(value, "lifecycle-state")
        .or_else(|| string_field(value, "lifecycleState"))
        .map(redact_sensitive_text)
}

fn suppression_totals(suppressions: &[SuppressionSummary]) -> SuppressionTotals {
    let mut by_reason = BTreeMap::<String, usize>::new();
    let mut by_recipient_domain = BTreeMap::<String, usize>::new();
    let mut hard_bounce = 0usize;
    for suppression in suppressions {
        if let Some(reason) = suppression.reason.as_deref().and_then(normalize_reason_key) {
            if is_hard_bounce_reason(&reason) {
                hard_bounce += 1;
            }
            *by_reason.entry(reason).or_default() += 1;
        }
        if let Some(domain) = suppression
            .recipient_domain
            .as_deref()
            .and_then(normalize_summary_key)
        {
            *by_recipient_domain.entry(domain).or_default() += 1;
        }
    }
    let (by_recipient_domain, by_recipient_domain_omitted) =
        capped_counts_from_map(by_recipient_domain, SUPPRESSION_DOMAIN_BUCKET_LIMIT);
    SuppressionTotals {
        hard_bounce,
        by_reason: counts_from_map(by_reason),
        by_recipient_domain,
        by_recipient_domain_omitted,
    }
}

fn suppression_count_state(empty_stdout: bool, rows_capped: bool) -> String {
    if empty_stdout {
        "no_sample".to_string()
    } else if rows_capped {
        "lower_bound".to_string()
    } else {
        "complete".to_string()
    }
}

fn suppression_time_bounds(
    suppressions: &[SuppressionSummary],
) -> (Option<String>, Option<String>) {
    let mut oldest_time: Option<&str> = None;
    let mut newest_time: Option<&str> = None;
    for time in suppressions
        .iter()
        .filter_map(|suppression| suppression.time_created.as_deref())
    {
        if oldest_time.is_none_or(|oldest| time < oldest) {
            oldest_time = Some(time);
        }
        if newest_time.is_none_or(|newest| time > newest) {
            newest_time = Some(time);
        }
    }
    (
        oldest_time.map(ToString::to_string),
        newest_time.map(ToString::to_string),
    )
}

fn suppression_reason_count(totals: &SuppressionTotals, reason: &str) -> usize {
    totals
        .by_reason
        .iter()
        .find(|item| item.key == reason)
        .map(|item| item.count)
        .unwrap_or(0)
}

fn normalize_summary_key(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    (!normalized.is_empty()).then_some(normalized)
}

fn normalize_reason_key(value: &str) -> Option<String> {
    let normalized = normalize_summary_key(value)?;
    if is_hard_bounce_reason(&normalized) {
        Some("hardbounce".to_string())
    } else {
        Some(normalized)
    }
}

fn is_hard_bounce_reason(reason: &str) -> bool {
    reason
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>()
        == "hardbounce"
}

fn counts_from_map(map: BTreeMap<String, usize>) -> Vec<SuppressionCount> {
    map.into_iter()
        .map(|(key, count)| SuppressionCount { key, count })
        .collect()
}

fn capped_counts_from_map(
    map: BTreeMap<String, usize>,
    limit: usize,
) -> (Vec<SuppressionCount>, usize) {
    let total_buckets = map.len();
    let mut counts = counts_from_map(map);
    counts.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.key.cmp(&right.key))
    });
    let omitted = total_buckets.saturating_sub(limit);
    counts.truncate(limit);
    (counts, omitted)
}

fn email_event_summary(value: &Value) -> EmailEventSummary {
    let record = event_record(value);
    let data = record.get("data").unwrap_or(record);
    let log_type = string_field(record, "type").map(ToString::to_string);
    let email = nested_string(data, &["recipient"])
        .or_else(|| nested_string(data, &["recipientAddress"]))
        .or_else(|| nested_string(data, &["emailAddress"]));
    let message_id = nested_string(data, &["messageId"])
        .or_else(|| nested_string(data, &["message-id"]))
        .or_else(|| nested_string(value, &["messageId"]));
    EmailEventSummary {
        datetime: string_field(value, "datetime")
            .or_else(|| string_field(record, "datetime"))
            .or_else(|| string_field(record, "time"))
            .map(ToString::to_string),
        log_type,
        action: string_field(data, "action").map(ToString::to_string),
        source_domain: email_event_source_domain(record, data),
        receiving_domain: string_field(data, "receivingDomain")
            .filter(|value| is_host_token(value))
            .map(|value| value.to_ascii_lowercase()),
        recipient_domain: email.and_then(email_domain),
        recipient_hash: email.map(short_hash),
        message_id_hash: message_id.map(short_hash),
        error_type: nested_string(data, &["errorType"]).map(redact_sensitive_text),
        bounce_category: nested_string(data, &["bounceCategory"]).map(redact_sensitive_text),
        smtp_status: nested_string(data, &["smtpStatus"]).map(summarize_smtp_status),
        raw_payload_returned: false,
    }
}

fn event_counts(events: &[EmailEventSummary]) -> EventCounts {
    let mut by_action = BTreeMap::<&str, usize>::new();
    let mut recipient_hashes = BTreeSet::<&str>::new();
    let mut message_id_hashes = BTreeSet::<&str>::new();
    let mut recipient_message_pairs = BTreeSet::<(&str, &str)>::new();
    let mut action_recipient_message_keys = BTreeSet::<(&str, &str, &str)>::new();
    let mut events_with_recipient_hash = 0;
    let mut events_with_message_id_hash = 0;
    let mut events_with_recipient_message_pair = 0;
    let mut events_with_action_recipient_message_key = 0;

    for event in events {
        let action = event.action.as_deref().unwrap_or("unknown");
        *by_action.entry(action).or_default() += 1;

        if let Some(recipient_hash) = event.recipient_hash.as_deref() {
            events_with_recipient_hash += 1;
            recipient_hashes.insert(recipient_hash);
        }
        if let Some(message_id_hash) = event.message_id_hash.as_deref() {
            events_with_message_id_hash += 1;
            message_id_hashes.insert(message_id_hash);
        }
        if let (Some(recipient_hash), Some(message_id_hash)) = (
            event.recipient_hash.as_deref(),
            event.message_id_hash.as_deref(),
        ) {
            events_with_recipient_message_pair += 1;
            recipient_message_pairs.insert((recipient_hash, message_id_hash));
            events_with_action_recipient_message_key += 1;
            action_recipient_message_keys.insert((action, recipient_hash, message_id_hash));
        }
    }

    let distinct_recipient_hashes = recipient_hashes.len();
    let distinct_message_id_hashes = message_id_hashes.len();
    let distinct_recipient_message_pairs = recipient_message_pairs.len();
    let distinct_action_recipient_message_keys = action_recipient_message_keys.len();

    EventCounts {
        by_action: by_action
            .into_iter()
            .map(|(key, count)| EventCount {
                key: key.to_string(),
                count,
            })
            .collect(),
        events_with_recipient_hash,
        distinct_recipient_hashes,
        duplicate_recipient_hash_events: events_with_recipient_hash
            .saturating_sub(distinct_recipient_hashes),
        events_with_message_id_hash,
        distinct_message_id_hashes,
        duplicate_message_id_hash_events: events_with_message_id_hash
            .saturating_sub(distinct_message_id_hashes),
        events_with_recipient_message_pair,
        distinct_recipient_message_pairs,
        duplicate_recipient_message_pair_events: events_with_recipient_message_pair
            .saturating_sub(distinct_recipient_message_pairs),
        events_with_action_recipient_message_key,
        distinct_action_recipient_message_keys,
        duplicate_action_recipient_message_key_events: events_with_action_recipient_message_key
            .saturating_sub(distinct_action_recipient_message_keys),
    }
}

fn summarize_smtp_status(value: &str) -> String {
    let redacted = redact_sensitive_text(value);
    let without_diagnostic = redacted
        .to_ascii_lowercase()
        .find("[begindiagnosticdata]")
        .map(|index| {
            format!(
                "{} [diagnostic-data-redacted]",
                redacted[..index].trim_end()
            )
        })
        .unwrap_or(redacted);
    truncate_summary(
        &collapse_whitespace(&without_diagnostic),
        SMTP_STATUS_MAX_CHARS,
    )
}

fn collapse_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_summary(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let suffix = " ...[truncated]";
    let prefix_len = max_chars.saturating_sub(suffix.chars().count());
    let prefix = value.chars().take(prefix_len).collect::<String>();
    format!("{prefix}{suffix}")
}

fn event_record(value: &Value) -> &Value {
    value
        .get("data")
        .and_then(|data| data.get("logContent"))
        .or_else(|| value.get("logContent"))
        .unwrap_or(value)
}

fn build_search_query(
    compartment_id: &str,
    request: &EventsRequest,
) -> Result<String, OciEmailError> {
    let mut filters =
        vec!["type='com.oraclecloud.emaildelivery.emaildomain.outbound*'".to_string()];
    if let Some(action) = request.action.as_deref() {
        filters.push(format!("data.action='{}'", safe_query_value(action)?));
    }
    if let Some(message_id) = request.message_id.as_deref() {
        filters.push(format!(
            "data.messageId='{}'",
            safe_query_value(message_id)?
        ));
    }
    if let (Some(name), Some(value)) = (
        request.header_name.as_deref(),
        request.header_value.as_deref(),
    ) {
        validate_header_name(name)?;
        filters.push(format!(
            "data.headers.\"{}\"='{}'",
            name.to_ascii_lowercase(),
            safe_query_value(value)?
        ));
    }
    if let Some(domain) = request.receiving_domain.as_deref() {
        validate_domain(domain, "receiving_domain")?;
        filters.push(format!(
            "data.receivingDomain='{}'",
            safe_query_value(domain)?
        ));
    }
    Ok(format!(
        "search \"{}\" | {} | sort by datetime desc",
        safe_query_value(compartment_id)?,
        filters.join(" and ")
    ))
}

fn validate_event_request(request: &EventsRequest) -> Result<(), OciEmailError> {
    if let Some(action) = request.action.as_deref() {
        let allowed = [
            "accept",
            "relay",
            "bounce",
            "complaint",
            "open",
            "click",
            "unsubscribe",
        ];
        if !allowed.contains(&action) {
            return Err(OciEmailError::InvalidInput(format!(
                "unsupported action {action}; expected one of {}",
                allowed.join(", ")
            )));
        }
    }
    if request.header_name.is_some() != request.header_value.is_some() {
        return Err(OciEmailError::InvalidInput(
            "header_name and header_value must be provided together".to_string(),
        ));
    }
    if let Some(name) = request.header_name.as_deref() {
        validate_header_name(name)?;
    }
    if let Some(domain) = request.receiving_domain.as_deref() {
        validate_domain(domain, "receiving_domain")?;
    }
    if let Some(domain) = request.source_domain.as_deref() {
        validate_domain(domain, "source_domain")?;
    }
    for (label, value) in [
        ("message_id", request.message_id.as_deref()),
        ("header_value", request.header_value.as_deref()),
    ] {
        if let Some(value) = value {
            safe_query_value(value).map_err(|_| {
                OciEmailError::InvalidInput(format!("{label} contains unsupported query syntax"))
            })?;
        }
    }
    Ok(())
}

fn email_event_source_domain(record: &Value, data: &Value) -> Option<String> {
    string_field(data, "sender")
        .and_then(email_domain)
        .or_else(|| string_field(data, "envelopeSender").and_then(email_domain))
        .or_else(|| string_field(data, "envelope-sender").and_then(email_domain))
        .or_else(|| {
            string_field(data, "sourceDomain")
                .filter(|value| is_host_token(value))
                .or_else(|| {
                    string_field(data, "source-domain").filter(|value| is_host_token(value))
                })
                .or_else(|| string_field(data, "senderDomain").filter(|value| is_host_token(value)))
                .or_else(|| {
                    string_field(data, "sender-domain").filter(|value| is_host_token(value))
                })
                .map(|value| value.to_ascii_lowercase())
        })
        .or_else(|| {
            string_field(record, "source")
                .filter(|value| is_host_token(value))
                .map(|value| value.to_ascii_lowercase())
        })
}

fn event_matches_source_domain(event: &EmailEventSummary, source_domain: Option<&str>) -> bool {
    let Some(source_domain) = source_domain else {
        return true;
    };
    event
        .source_domain
        .as_deref()
        .is_some_and(|value| value.eq_ignore_ascii_case(source_domain))
}

fn validate_header_name(value: &str) -> Result<(), OciEmailError> {
    let valid = !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-');
    if valid {
        Ok(())
    } else {
        Err(OciEmailError::InvalidInput(
            "header_name may contain only ASCII letters, digits, and hyphens".to_string(),
        ))
    }
}

fn validate_domain(value: &str, label: &str) -> Result<(), OciEmailError> {
    if is_host_token(value) {
        Ok(())
    } else {
        Err(OciEmailError::InvalidInput(format!(
            "{label} must be a valid domain token"
        )))
    }
}

fn normalize_interval(value: Option<&str>) -> Result<String, OciEmailError> {
    let raw = value.unwrap_or("1h").trim();
    let normalized = match raw.to_ascii_uppercase().as_str() {
        "1M" | "PT1M" => "1m",
        "5M" | "PT5M" => "5m",
        "15M" | "PT15M" => "15m",
        "30M" | "PT30M" => "30m",
        "1H" | "PT1H" => "1h",
        "1D" | "P1D" => "1d",
        _ => {
            return Err(OciEmailError::InvalidInput(
                "interval must be one of 1m, 5m, 15m, 30m, 1h, 1d, PT1M, PT5M, PT15M, PT30M, PT1H, or P1D".to_string(),
            ));
        }
    };
    Ok(normalized.to_string())
}

fn validate_time(value: &str, label: &str) -> Result<(), OciEmailError> {
    let valid = !value.is_empty()
        && value.len() <= 40
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | ':' | '.' | 'T' | 'Z'));
    if valid {
        Ok(())
    } else {
        Err(OciEmailError::InvalidInput(format!(
            "{label} must be an RFC3339-like UTC timestamp"
        )))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ParsedUtcTime {
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    nanos: u32,
}

fn validate_utc_window(start_time: &str, end_time: &str) -> Result<(), OciEmailError> {
    let start = parse_strict_utc_time(start_time, "start_time")?;
    let end = parse_strict_utc_time(end_time, "end_time")?;
    if start < end {
        Ok(())
    } else {
        Err(OciEmailError::InvalidInput(
            "start_time must be before end_time".to_string(),
        ))
    }
}

fn parse_strict_utc_time(value: &str, label: &str) -> Result<ParsedUtcTime, OciEmailError> {
    validate_time(value, label)?;
    let Some(without_z) = value.strip_suffix('Z') else {
        return Err(OciEmailError::InvalidInput(format!(
            "{label} must use a UTC Z offset"
        )));
    };
    let Some((date, time)) = without_z.split_once('T') else {
        return Err(OciEmailError::InvalidInput(format!(
            "{label} must contain a T separator"
        )));
    };
    let date_parts = date.split('-').collect::<Vec<_>>();
    if date_parts.len() != 3
        || date_parts[0].len() != 4
        || date_parts[1].len() != 2
        || date_parts[2].len() != 2
    {
        return Err(OciEmailError::InvalidInput(format!(
            "{label} must use YYYY-MM-DDTHH:MM:SSZ"
        )));
    }
    let time_parts = time.split(':').collect::<Vec<_>>();
    if time_parts.len() != 3 || time_parts[0].len() != 2 || time_parts[1].len() != 2 {
        return Err(OciEmailError::InvalidInput(format!(
            "{label} must use YYYY-MM-DDTHH:MM:SSZ"
        )));
    }
    let (seconds, nanos) = parse_seconds_fraction(time_parts[2], label)?;
    let year = parse_fixed_u32(date_parts[0], label)?;
    let month = parse_fixed_u32(date_parts[1], label)?;
    let day = parse_fixed_u32(date_parts[2], label)?;
    let hour = parse_fixed_u32(time_parts[0], label)?;
    let minute = parse_fixed_u32(time_parts[1], label)?;
    if month == 0
        || month > 12
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || seconds > 59
    {
        return Err(OciEmailError::InvalidInput(format!(
            "{label} must be a valid UTC timestamp"
        )));
    }
    Ok(ParsedUtcTime {
        year,
        month,
        day,
        hour,
        minute,
        second: seconds,
        nanos,
    })
}

fn parse_seconds_fraction(value: &str, label: &str) -> Result<(u32, u32), OciEmailError> {
    let Some((seconds, fraction)) = value.split_once('.') else {
        if value.len() != 2 {
            return Err(OciEmailError::InvalidInput(format!(
                "{label} must use YYYY-MM-DDTHH:MM:SSZ"
            )));
        }
        return Ok((parse_fixed_u32(value, label)?, 0));
    };
    if seconds.len() != 2
        || fraction.is_empty()
        || fraction.len() > 9
        || !fraction.chars().all(|ch| ch.is_ascii_digit())
    {
        return Err(OciEmailError::InvalidInput(format!(
            "{label} must use a valid fractional second"
        )));
    }
    let seconds = parse_fixed_u32(seconds, label)?;
    let mut nanos = parse_fixed_u32(fraction, label)?;
    for _ in fraction.len()..9 {
        nanos *= 10;
    }
    Ok((seconds, nanos))
}

fn parse_fixed_u32(value: &str, label: &str) -> Result<u32, OciEmailError> {
    if value.is_empty() || !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(OciEmailError::InvalidInput(format!(
            "{label} must contain numeric date and time fields"
        )));
    }
    value.parse::<u32>().map_err(|_| {
        OciEmailError::InvalidInput(format!("{label} must contain valid date and time fields"))
    })
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

#[allow(clippy::manual_is_multiple_of)]
fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn safe_query_value(value: &str) -> Result<String, OciEmailError> {
    let valid = !value.is_empty()
        && value.len() <= 256
        && value.chars().all(|ch| {
            ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '@' | ':' | '/')
        });
    if valid {
        Ok(value.to_string())
    } else {
        Err(OciEmailError::InvalidInput(
            "query values may contain only conservative identifier characters".to_string(),
        ))
    }
}

fn cap_limit(value: u32, hard_limit: u32) -> u32 {
    value.clamp(1, hard_limit)
}

fn rows_may_be_capped(returned: usize, limit: u32) -> bool {
    returned >= limit as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_query_filters_dimensions() {
        assert_eq!(
            metric_query("EmailsAccepted", "1h", Some("example.com"), None),
            "EmailsAccepted[1h]{resourceDomain = \"example.com\"}.sum()"
        );
    }

    #[test]
    fn metric_query_for_output_redacts_resource_id_filter() {
        let query = metric_query_for_output(
            "EmailsAccepted",
            "1h",
            Some("example.com"),
            Some("ocid1.emaildomain.oc1.ap-melbourne-1.example"),
        );

        assert!(query.contains("resourceDomain = \"example.com\""));
        assert!(query.contains("resourceId = \"[redacted-ocid:emaildomain:"));
        assert!(!query.contains("ocid1."));
    }

    #[test]
    fn normalizes_canonical_and_iso_metric_intervals() {
        for (input, expected) in [
            (None, "1h"),
            (Some("1m"), "1m"),
            (Some("PT1M"), "1m"),
            (Some("pt1m"), "1m"),
            (Some("1M"), "1m"),
            (Some("5m"), "5m"),
            (Some("PT5M"), "5m"),
            (Some("15m"), "15m"),
            (Some("PT15M"), "15m"),
            (Some("30m"), "30m"),
            (Some("PT30M"), "30m"),
            (Some("1h"), "1h"),
            (Some("PT1H"), "1h"),
            (Some("pt1h"), "1h"),
            (Some("1H"), "1h"),
            (Some("1d"), "1d"),
            (Some("P1D"), "1d"),
            (Some("p1d"), "1d"),
        ] {
            assert_eq!(normalize_interval(input).unwrap(), expected);
        }

        let err = normalize_interval(Some("PT2M")).unwrap_err();
        assert!(matches!(err, OciEmailError::InvalidInput(_)));
    }

    #[test]
    fn rejects_unsafe_log_query_value() {
        assert!(safe_query_value("abc| count").is_err());
        assert!(safe_query_value("abc@example.com").is_ok());
    }

    #[test]
    fn caps_limits() {
        assert_eq!(cap_limit(200, 100), 100);
        assert_eq!(cap_limit(0, 100), 1);
    }

    #[test]
    fn exact_limit_return_means_rows_may_be_capped() {
        assert!(rows_may_be_capped(20, 20));
        assert!(rows_may_be_capped(100, 100));
        assert!(!rows_may_be_capped(19, 20));
        assert!(!rows_may_be_capped(0, 20));
    }

    #[test]
    fn suppression_totals_are_redacted_and_reason_normalized() {
        let suppressions = vec![
            SuppressionSummary {
                time_created: Some("2026-06-30T00:00:00Z".to_string()),
                reason: Some("HARDBOUNCE".to_string()),
                recipient_redacted: Some("[redacted]@example.com".to_string()),
                recipient_domain: Some("example.com".to_string()),
                recipient_hash: Some("one".to_string()),
                raw_payload_returned: false,
            },
            SuppressionSummary {
                time_created: Some("2026-06-30T00:01:00Z".to_string()),
                reason: Some("hard bounce".to_string()),
                recipient_redacted: Some("[redacted]@example.com".to_string()),
                recipient_domain: Some("example.com".to_string()),
                recipient_hash: Some("two".to_string()),
                raw_payload_returned: false,
            },
            SuppressionSummary {
                time_created: Some("2026-06-30T00:02:00Z".to_string()),
                reason: Some("COMPLAINT".to_string()),
                recipient_redacted: Some("[redacted]@example.net".to_string()),
                recipient_domain: Some("example.net".to_string()),
                recipient_hash: Some("three".to_string()),
                raw_payload_returned: false,
            },
        ];

        let totals = suppression_totals(&suppressions);

        assert_eq!(totals.hard_bounce, 2);
        assert!(totals
            .by_reason
            .iter()
            .any(|item| item.key == "hardbounce" && item.count == 2));
        assert!(totals
            .by_reason
            .iter()
            .any(|item| item.key == "complaint" && item.count == 1));
        assert!(totals
            .by_recipient_domain
            .iter()
            .any(|item| item.key == "example.com" && item.count == 2));
        assert!(totals
            .by_recipient_domain
            .iter()
            .any(|item| item.key == "example.net" && item.count == 1));
        assert_eq!(totals.by_recipient_domain_omitted, 0);
    }

    #[test]
    fn suppressions_fetch_all_pages_and_return_bounded_sample() {
        let backend =
            LiveOciEmailBackend::with_runner(test_config(), Arc::new(FixtureSuppressionRunner));
        let report = backend
            .suppressions(&SuppressionsRequest {
                time_created_greater_than_or_equal_to: None,
                time_created_less_than: None,
                limit: Some(2),
                compartment_id: None,
            })
            .expect("suppression report");

        assert_eq!(report.status, "ok");
        assert_eq!(report.limit, 2);
        assert_eq!(report.returned, 2);
        assert_eq!(report.total_matched, 3);
        assert!(report.rows_capped);
        assert_eq!(report.count_state, "complete");
        assert_eq!(report.totals.hard_bounce, 2);
        assert_eq!(
            report.newest_time_created,
            Some("2026-06-30T00:02:00Z".to_string())
        );
        assert_eq!(report.suppressions.len(), 2);
        assert!(report.evidence.iter().any(|item| item.rows_capped));
    }

    #[test]
    fn suppression_domain_buckets_are_bounded_even_when_counts_are_complete() {
        let backend = LiveOciEmailBackend::with_runner(
            test_config(),
            Arc::new(HighCardinalitySuppressionRunner),
        );
        let report = backend
            .suppressions(&SuppressionsRequest {
                time_created_greater_than_or_equal_to: None,
                time_created_less_than: None,
                limit: Some(5),
                compartment_id: None,
            })
            .expect("suppression report");

        assert_eq!(report.total_matched, 55);
        assert_eq!(report.returned, 5);
        assert_eq!(report.count_state, "complete");
        assert_eq!(report.totals.by_recipient_domain.len(), 50);
        assert_eq!(report.totals.by_recipient_domain_omitted, 5);
        assert!(report
            .totals
            .by_recipient_domain
            .iter()
            .any(|item| item.key == "domain00.example" && item.count == 1));
        assert!(!report
            .totals
            .by_recipient_domain
            .iter()
            .any(|item| item.key == "domain50.example"));
    }

    #[test]
    fn parses_logging_search_wrapped_email_events_without_raw_payload() {
        let value = serde_json::json!({
            "datetime": "2026-06-30T00:10:00.000Z",
            "data": {
                "logContent": {
                    "type": "com.oraclecloud.emaildelivery.emaildomain.outboundrelayed",
                    "source": "example.com",
                    "time": "2026-06-30T00:10:00.000Z",
                    "data": {
                        "action": "unsubscribe",
                        "messageId": "message@example.com",
                        "recipient": "person@example.net",
                        "recipientIp": "203.0.113.4",
                        "receivingDomain": "example.net",
                        "userAgent": "Example Mail Client"
                    }
                }
            }
        });

        let summary = email_event_summary(&value);
        let payload = serde_json::to_string(&summary).expect("serialize summary");

        assert_eq!(summary.action.as_deref(), Some("unsubscribe"));
        assert_eq!(summary.source_domain.as_deref(), Some("example.com"));
        assert_eq!(summary.receiving_domain.as_deref(), Some("example.net"));
        assert_eq!(summary.recipient_domain.as_deref(), Some("example.net"));
        assert!(summary.recipient_hash.is_some());
        assert!(summary.message_id_hash.is_some());
        assert!(!summary.raw_payload_returned);
        assert!(!payload.contains("person@example.net"));
        assert!(!payload.contains("message@example.com"));
        assert!(!payload.contains("203.0.113.4"));
        assert!(!payload.contains("Example Mail Client"));
    }

    #[test]
    fn event_source_domain_falls_back_after_invalid_sender() {
        let value = serde_json::json!({
            "data": {
                "logContent": {
                    "type": "com.oraclecloud.emaildelivery.emaildomain.outboundaccepted",
                    "source": "oci.emaildelivery",
                    "data": {
                        "action": "accept",
                        "sender": "not-an-email",
                        "envelopeSender": "bounce@envelope.example",
                        "recipient": "person@recipient.example"
                    }
                }
            }
        });

        let summary = email_event_summary(&value);

        assert_eq!(summary.source_domain.as_deref(), Some("envelope.example"));
    }

    #[test]
    fn event_source_domain_falls_back_after_invalid_source_domain() {
        let value = serde_json::json!({
            "data": {
                "logContent": {
                    "type": "com.oraclecloud.emaildelivery.emaildomain.outboundaccepted",
                    "source": "oci.emaildelivery",
                    "data": {
                        "action": "accept",
                        "sourceDomain": "bad domain token",
                        "source-domain": "source.example",
                        "recipient": "person@recipient.example"
                    }
                }
            }
        });

        let summary = email_event_summary(&value);

        assert_eq!(summary.source_domain.as_deref(), Some("source.example"));
    }

    #[test]
    fn event_summary_caps_smtp_diagnostic_blobs() {
        let value = serde_json::json!({
            "data": {
                "logContent": {
                    "type": "com.oraclecloud.emaildelivery.emaildomain.outboundrelayed",
                    "data": {
                        "action": "bounce",
                        "recipient": "person@example.com",
                        "smtpStatus": format!(
                            "554 5.2.2 mailbox full; [BeginDiagnosticData]{}[EndDiagnosticData]",
                            "X".repeat(800)
                        )
                    }
                }
            }
        });

        let summary = email_event_summary(&value);
        let smtp_status = summary.smtp_status.expect("smtp status");

        assert!(smtp_status.starts_with("554 5.2.2 mailbox full;"));
        assert!(smtp_status.contains("[diagnostic-data-redacted]"));
        assert!(!smtp_status.contains("[BeginDiagnosticData]"));
        assert!(!smtp_status.contains("[EndDiagnosticData]"));
        assert!(smtp_status.chars().count() <= SMTP_STATUS_MAX_CHARS);
    }

    #[test]
    fn event_summary_caps_lowercase_smtp_diagnostic_marker() {
        let status = summarize_smtp_status(
            "554 mailbox full; [begindiagnosticdata]lowercase diagnostic[enddiagnosticdata]",
        );

        assert_eq!(
            status,
            "554 mailbox full; [diagnostic-data-redacted]".to_string()
        );
    }

    #[test]
    fn event_search_keeps_source_domain_out_of_provider_query() {
        let query = build_search_query(
            "ocid1.tenancy.oc1.example",
            &EventsRequest {
                start_time: "2026-06-30T00:00:00Z".to_string(),
                end_time: "2026-06-30T01:00:00Z".to_string(),
                action: Some("relay".to_string()),
                message_id: None,
                header_name: None,
                header_value: None,
                receiving_domain: Some("recipient.example".to_string()),
                source_domain: Some("sender.example".to_string()),
                limit: Some(20),
                compartment_id: None,
            },
        )
        .expect("query");

        assert!(query.contains("type='com.oraclecloud.emaildelivery.emaildomain.outbound*'"));
        assert!(query.contains("data.receivingDomain='recipient.example'"));
        assert!(!query.contains("source='sender.example'"));
    }

    #[test]
    fn event_search_filters_source_domain_after_redacted_summary() {
        let backend =
            LiveOciEmailBackend::with_runner(test_config(), Arc::new(FixtureEventSearchRunner));

        let report = backend
            .events(&EventsRequest {
                start_time: "2026-06-30T00:00:00Z".to_string(),
                end_time: "2026-06-30T01:00:00Z".to_string(),
                action: None,
                message_id: None,
                header_name: None,
                header_value: None,
                receiving_domain: None,
                source_domain: Some("sender.example".to_string()),
                limit: Some(20),
                compartment_id: None,
            })
            .expect("events");
        let payload = serde_json::to_string(&report).expect("serialize events");

        assert_eq!(report.status, "ok");
        assert_eq!(report.provider_returned, 2);
        assert_eq!(report.source_domain_matched, 1);
        assert_eq!(report.returned, 1);
        assert_eq!(report.counts.events_with_recipient_hash, 1);
        assert_eq!(report.counts.distinct_recipient_hashes, 1);
        assert_eq!(report.counts.events_with_message_id_hash, 1);
        assert_eq!(report.counts.distinct_message_id_hashes, 1);
        assert_eq!(report.counts.events_with_action_recipient_message_key, 1);
        assert_eq!(report.counts.distinct_action_recipient_message_keys, 1);
        assert_eq!(
            report.events[0].source_domain.as_deref(),
            Some("sender.example")
        );
        assert_eq!(
            report.events[0].recipient_domain.as_deref(),
            Some("recipient.example")
        );
        assert!(!payload.contains("person@recipient.example"));
        assert!(!payload.contains("sender@sender.example"));
        assert!(!payload.contains("other@other.example"));
    }

    #[test]
    fn event_search_reports_distinct_and_duplicate_redacted_event_keys() {
        let backend = LiveOciEmailBackend::with_runner(
            test_config(),
            Arc::new(FixtureDuplicateComplaintEventSearchRunner),
        );

        let report = backend
            .events(&EventsRequest {
                start_time: "2026-06-30T00:00:00Z".to_string(),
                end_time: "2026-06-30T01:00:00Z".to_string(),
                action: Some("complaint".to_string()),
                message_id: None,
                header_name: None,
                header_value: None,
                receiving_domain: None,
                source_domain: Some("sender.example".to_string()),
                limit: Some(20),
                compartment_id: None,
            })
            .expect("events");
        let payload = serde_json::to_string(&report).expect("serialize events");

        assert_eq!(report.status, "ok");
        assert_eq!(report.provider_returned, 3);
        assert_eq!(report.source_domain_matched, 3);
        assert_eq!(report.returned, 3);
        assert_eq!(report.counts.by_action.len(), 1);
        assert_eq!(report.counts.by_action[0].key, "complaint");
        assert_eq!(report.counts.by_action[0].count, 3);
        assert_eq!(report.counts.events_with_recipient_hash, 3);
        assert_eq!(report.counts.distinct_recipient_hashes, 2);
        assert_eq!(report.counts.duplicate_recipient_hash_events, 1);
        assert_eq!(report.counts.events_with_message_id_hash, 3);
        assert_eq!(report.counts.distinct_message_id_hashes, 2);
        assert_eq!(report.counts.duplicate_message_id_hash_events, 1);
        assert_eq!(report.counts.events_with_recipient_message_pair, 3);
        assert_eq!(report.counts.distinct_recipient_message_pairs, 2);
        assert_eq!(report.counts.duplicate_recipient_message_pair_events, 1);
        assert_eq!(report.counts.events_with_action_recipient_message_key, 3);
        assert_eq!(report.counts.distinct_action_recipient_message_keys, 2);
        assert_eq!(
            report.counts.duplicate_action_recipient_message_key_events,
            1
        );
        assert!(!payload.contains("first@recipient.example"));
        assert!(!payload.contains("second@recipient.example"));
        assert!(!payload.contains("message-one"));
        assert!(!payload.contains("message-two"));
    }

    #[test]
    fn event_counts_keep_mixed_actions_separate_for_same_recipient_message() {
        let base_event = EmailEventSummary {
            datetime: None,
            log_type: None,
            action: Some("accept".to_string()),
            source_domain: None,
            receiving_domain: None,
            recipient_domain: Some("recipient.example".to_string()),
            recipient_hash: Some("recipient-hash".to_string()),
            message_id_hash: Some("message-hash".to_string()),
            error_type: None,
            bounce_category: None,
            smtp_status: None,
            raw_payload_returned: false,
        };
        let mut relay_event = base_event.clone();
        relay_event.action = Some("relay".to_string());

        let counts = event_counts(&[base_event, relay_event.clone(), relay_event]);

        assert_eq!(counts.by_action.len(), 2);
        assert_eq!(counts.by_action[0].key, "accept");
        assert_eq!(counts.by_action[0].count, 1);
        assert_eq!(counts.by_action[1].key, "relay");
        assert_eq!(counts.by_action[1].count, 2);
        assert_eq!(counts.events_with_recipient_message_pair, 3);
        assert_eq!(counts.distinct_recipient_message_pairs, 1);
        assert_eq!(counts.duplicate_recipient_message_pair_events, 2);
        assert_eq!(counts.events_with_action_recipient_message_key, 3);
        assert_eq!(counts.distinct_action_recipient_message_keys, 2);
        assert_eq!(counts.duplicate_action_recipient_message_key_events, 1);
    }

    #[test]
    fn logging_status_lists_service_logs_without_raw_identifiers() {
        let backend = LiveOciEmailBackend::with_runner(
            test_config(),
            Arc::new(FixtureLoggingRunner { logs_visible: true }),
        );

        let report = backend
            .logging_status(&LoggingStatusRequest {
                compartment_id: None,
                resource_domain: None,
                resource_id: Some("ocid1.emaildomain.oc1.example".to_string()),
                limit: Some(20),
            })
            .unwrap_or_else(|err| panic!("logging status: {err}"));
        let payload = serde_json::to_string(&report).expect("serialize logging status");

        assert_eq!(report.status, "ok");
        assert_eq!(report.log_group_count, 1);
        assert_eq!(report.email_delivery_log_count, 1);
        assert_eq!(report.active_email_delivery_log_count, 1);
        assert_eq!(report.matching_requested_resource_log_count, 1);
        assert_eq!(report.active_matching_requested_resource_log_count, 1);
        assert!(!report.raw_payload_returned);
        assert!(payload.contains("[redacted-ocid:emaildomain:"));
        assert!(!payload.contains("ocid1."));
        assert!(!payload.contains("Email Delivery Log"));
    }

    #[test]
    fn logging_status_resolves_resource_domain_to_matching_log() {
        let backend = LiveOciEmailBackend::with_runner(
            test_config(),
            Arc::new(FixtureLoggingRunner { logs_visible: true }),
        );

        let report = backend
            .logging_status(&LoggingStatusRequest {
                compartment_id: None,
                resource_domain: Some("example.com".to_string()),
                resource_id: None,
                limit: Some(20),
            })
            .unwrap_or_else(|err| panic!("logging status: {err}"));
        let payload = serde_json::to_string(&report).expect("serialize logging status");

        assert_eq!(report.status, "ok");
        assert_eq!(report.resource_domain, Some("example.com".to_string()));
        assert!(report.requested_resource_id.present);
        assert_eq!(report.matching_requested_resource_log_count, 1);
        assert_eq!(report.active_matching_requested_resource_log_count, 1);
        assert!(report
            .evidence
            .iter()
            .any(|evidence| evidence.command == "email domain list"));
        assert!(!payload.contains("ocid1."));
        assert!(!payload.contains("Email Delivery Log"));
    }

    #[test]
    fn logging_status_blocks_when_resource_domain_is_not_visible() {
        let backend = LiveOciEmailBackend::with_runner(
            test_config(),
            Arc::new(FixtureLoggingRunner { logs_visible: true }),
        );

        let report = backend
            .logging_status(&LoggingStatusRequest {
                compartment_id: None,
                resource_domain: Some("missing.example".to_string()),
                resource_id: None,
                limit: Some(20),
            })
            .unwrap_or_else(|err| panic!("logging status: {err}"));

        assert_eq!(report.status, "blocked");
        assert!(!report.requested_resource_id.present);
        assert_eq!(report.matching_requested_resource_log_count, 0);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "logging_requested_resource_domain_not_visible"));
    }

    #[test]
    fn logging_status_blocks_when_resource_domain_and_id_disagree() {
        let backend = LiveOciEmailBackend::with_runner(
            test_config(),
            Arc::new(FixtureLoggingRunner { logs_visible: true }),
        );

        let report = backend
            .logging_status(&LoggingStatusRequest {
                compartment_id: None,
                resource_domain: Some("example.com".to_string()),
                resource_id: Some("ocid1.emaildomain.oc1.other".to_string()),
                limit: Some(20),
            })
            .unwrap_or_else(|err| panic!("logging status: {err}"));
        let payload = serde_json::to_string(&report).expect("serialize logging status");

        assert_eq!(report.status, "blocked");
        assert_eq!(report.resource_domain, Some("example.com".to_string()));
        assert!(report.requested_resource_id.present);
        assert_eq!(report.matching_requested_resource_log_count, 0);
        assert_eq!(report.active_matching_requested_resource_log_count, 0);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "logging_requested_resource_scope_mismatch"));
        assert!(!payload.contains("ocid1."));
    }

    #[test]
    fn logging_status_blocks_when_requested_resource_log_is_not_active() {
        let backend = LiveOciEmailBackend::with_runner(
            test_config(),
            Arc::new(FixtureInactiveRequestedResourceRunner),
        );

        let report = backend
            .logging_status(&LoggingStatusRequest {
                compartment_id: None,
                resource_domain: None,
                resource_id: Some("ocid1.emaildomain.oc1.requested".to_string()),
                limit: Some(20),
            })
            .unwrap_or_else(|err| panic!("logging status: {err}"));

        assert_eq!(report.status, "blocked");
        assert_eq!(report.email_delivery_log_count, 2);
        assert_eq!(report.active_email_delivery_log_count, 1);
        assert_eq!(report.matching_requested_resource_log_count, 1);
        assert_eq!(report.active_matching_requested_resource_log_count, 0);
        assert!(report
            .findings
            .iter()
            .any(|finding| { finding.code == "logging_requested_resource_not_active" }));
    }

    #[test]
    fn logging_status_blocks_when_no_email_delivery_logs_visible() {
        let backend = LiveOciEmailBackend::with_runner(
            test_config(),
            Arc::new(FixtureLoggingRunner {
                logs_visible: false,
            }),
        );

        let report = backend
            .logging_status(&LoggingStatusRequest {
                compartment_id: None,
                resource_domain: None,
                resource_id: None,
                limit: Some(20),
            })
            .unwrap_or_else(|err| panic!("logging status: {err}"));

        assert_eq!(report.status, "blocked");
        assert!(report
            .findings
            .iter()
            .any(|finding| { finding.code == "logging_no_email_delivery_service_logs" }));
    }

    #[test]
    fn logging_status_only_reports_attempted_logging_commands() {
        let backend =
            LiveOciEmailBackend::with_runner(test_config(), Arc::new(FixtureNoLogGroupsRunner));

        let report = backend
            .logging_status(&LoggingStatusRequest {
                compartment_id: None,
                resource_domain: None,
                resource_id: None,
                limit: Some(20),
            })
            .unwrap_or_else(|err| panic!("logging status: {err}"));

        assert_eq!(report.status, "blocked");
        assert!(report
            .evidence
            .iter()
            .any(|evidence| evidence.command == "logging log-group list"));
        assert!(!report
            .evidence
            .iter()
            .any(|evidence| evidence.command == "logging log list"));
    }

    #[test]
    fn logging_enablement_plan_blocks_without_authorizing_provider_mutation() {
        let backend = LiveOciEmailBackend::with_runner(
            test_config(),
            Arc::new(FixtureLoggingRunner {
                logs_visible: false,
            }),
        );

        let report = backend
            .logging_enablement_plan(&LoggingEnablementPlanRequest {
                compartment_id: None,
                resource_domain: None,
                resource_id: Some("ocid1.emaildomain.oc1.example".to_string()),
                limit: Some(20),
            })
            .unwrap_or_else(|err| panic!("logging enablement plan: {err}"));
        let payload = serde_json::to_string(&report).expect("serialize logging enablement plan");

        assert_eq!(report.status, "approval_required");
        assert_eq!(report.decision, "approval_required");
        assert!(!report.send_authorized);
        assert!(report.provider_mutation_required);
        assert!(!report.provider_mutation_authorized);
        assert_eq!(
            report.required_log_categories,
            vec![
                "emaildelivery.emaildomain.outboundaccepted".to_string(),
                "emaildelivery.emaildomain.outboundrelayed".to_string()
            ]
        );
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "logging_enablement_approval_required"));
        assert_eq!(report.current_logging.status, "blocked");
        assert!(!report.raw_payload_returned);
        assert!(!payload.contains("ocid1."));
    }

    #[test]
    fn logging_enablement_plan_reports_visible_logs_without_apply_need() {
        let backend = LiveOciEmailBackend::with_runner(
            test_config(),
            Arc::new(FixtureLoggingRunner { logs_visible: true }),
        );

        let report = backend
            .logging_enablement_plan(&LoggingEnablementPlanRequest {
                compartment_id: None,
                resource_domain: None,
                resource_id: Some("ocid1.emaildomain.oc1.example".to_string()),
                limit: Some(20),
            })
            .unwrap_or_else(|err| panic!("logging enablement plan: {err}"));

        assert_eq!(report.status, "already_visible_no_apply_needed");
        assert!(!report.send_authorized);
        assert!(!report.provider_mutation_required);
        assert!(!report.provider_mutation_authorized);
        assert_eq!(report.current_logging.status, "ok");
        assert!(report
            .post_enable_gates
            .iter()
            .any(|gate| gate.contains("oci_email_traceability_audit")));
    }

    #[test]
    fn logging_enablement_plan_accepts_resource_domain_for_no_apply_decision() {
        let backend = LiveOciEmailBackend::with_runner(
            test_config(),
            Arc::new(FixtureLoggingRunner { logs_visible: true }),
        );

        let report = backend
            .logging_enablement_plan(&LoggingEnablementPlanRequest {
                compartment_id: None,
                resource_domain: Some("example.com".to_string()),
                resource_id: None,
                limit: Some(20),
            })
            .unwrap_or_else(|err| panic!("logging enablement plan: {err}"));

        assert_eq!(report.status, "already_visible_no_apply_needed");
        assert_eq!(report.resource_domain, Some("example.com".to_string()));
        assert!(report.requested_resource_id.present);
        assert_eq!(report.current_logging.status, "ok");
        assert_eq!(
            report
                .current_logging
                .report
                .as_ref()
                .map(|current| current.active_matching_requested_resource_log_count),
            Some(1)
        );
    }

    #[test]
    fn logging_enablement_plan_blocks_scope_mismatch_without_provider_mutation() {
        let backend = LiveOciEmailBackend::with_runner(
            test_config(),
            Arc::new(FixtureLoggingRunner { logs_visible: true }),
        );

        let report = backend
            .logging_enablement_plan(&LoggingEnablementPlanRequest {
                compartment_id: None,
                resource_domain: Some("example.com".to_string()),
                resource_id: Some("ocid1.emaildomain.oc1.other".to_string()),
                limit: Some(20),
            })
            .unwrap_or_else(|err| panic!("logging enablement plan: {err}"));

        assert_eq!(report.status, "blocked");
        assert!(!report.provider_mutation_required);
        assert!(!report.provider_mutation_authorized);
        assert_eq!(report.current_logging.status, "blocked");
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "logging_enablement_target_scope_unresolved"));
    }

    #[test]
    fn logging_enablement_plan_requires_resource_scope_for_no_apply_decision() {
        let backend = LiveOciEmailBackend::with_runner(
            test_config(),
            Arc::new(FixtureLoggingRunner { logs_visible: true }),
        );

        let report = backend
            .logging_enablement_plan(&LoggingEnablementPlanRequest {
                compartment_id: None,
                resource_domain: None,
                resource_id: None,
                limit: Some(20),
            })
            .unwrap_or_else(|err| panic!("logging enablement plan: {err}"));

        assert_eq!(report.status, "review_required");
        assert!(!report.provider_mutation_required);
        assert!(!report.provider_mutation_authorized);
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.code == "logging_plan_resource_id_missing"));
    }

    struct FixtureSuppressionRunner;

    impl OciCliRunner for FixtureSuppressionRunner {
        fn run_json(&self, args: &[String]) -> Result<Value, OciEmailError> {
            match command_label(args).as_str() {
                "email suppression list" => {
                    assert!(args.iter().any(|arg| arg == "--all"));
                    assert!(!args.iter().any(|arg| arg == "--limit"));
                    assert!(args.windows(2).any(|window| {
                        window == ["--page-size".to_string(), "1000".to_string()]
                    }));
                    Ok(serde_json::json!({
                        "data": [
                            {
                                "time-created": "2026-06-30T00:00:00Z",
                                "reason": "HARDBOUNCE",
                                "email-address": "one@example.com"
                            },
                            {
                                "time-created": "2026-06-30T00:01:00Z",
                                "reason": "COMPLAINT",
                                "email-address": "two@example.net"
                            },
                            {
                                "time-created": "2026-06-30T00:02:00Z",
                                "reason": "hard bounce",
                                "email-address": "three@example.org"
                            }
                        ]
                    }))
                }
                other => panic!("unexpected OCI command: {other}"),
            }
        }
    }

    struct HighCardinalitySuppressionRunner;

    impl OciCliRunner for HighCardinalitySuppressionRunner {
        fn run_json(&self, args: &[String]) -> Result<Value, OciEmailError> {
            match command_label(args).as_str() {
                "email suppression list" => {
                    assert!(args.iter().any(|arg| arg == "--all"));
                    let data = (0..55)
                        .map(|index| {
                            serde_json::json!({
                                "time-created": "2026-06-30T00:00:00Z",
                                "reason": "HARDBOUNCE",
                                "email-address": format!("user{index}@domain{index:02}.example")
                            })
                        })
                        .collect::<Vec<_>>();
                    Ok(serde_json::json!({ "data": data }))
                }
                other => panic!("unexpected OCI command: {other}"),
            }
        }
    }

    struct FixtureLoggingRunner {
        logs_visible: bool,
    }

    impl OciCliRunner for FixtureLoggingRunner {
        fn run_json(&self, args: &[String]) -> Result<Value, OciEmailError> {
            match command_label(args).as_str() {
                "email domain list" => Ok(serde_json::json!({
                    "data": [{
                        "id": "ocid1.emaildomain.oc1.example",
                        "domain-name": "example.com",
                        "lifecycle-state": "ACTIVE"
                    }]
                })),
                "logging log-group list" => Ok(serde_json::json!({
                    "data": [{
                        "id": "ocid1.loggroup.oc1.example",
                        "display-name": "Private Log Group",
                        "lifecycle-state": "ACTIVE"
                    }]
                })),
                "logging log list" => {
                    assert!(args.windows(2).any(|window| {
                        window == ["--log-type".to_string(), "SERVICE".to_string()]
                    }));
                    assert!(args.windows(2).any(|window| {
                        window == ["--source-service".to_string(), "emaildelivery".to_string()]
                    }));
                    if self.logs_visible {
                        Ok(serde_json::json!({
                            "data": [{
                                "id": "ocid1.log.oc1.example",
                                "log-group-id": "ocid1.loggroup.oc1.example",
                                "display-name": "Email Delivery Log",
                                "lifecycle-state": "ACTIVE",
                                "log-type": "SERVICE",
                                "configuration": {
                                    "source": {
                                        "service": "emaildelivery",
                                        "resource": "ocid1.emaildomain.oc1.example",
                                        "category": "emaildomain",
                                        "kind": "service"
                                    }
                                }
                            }]
                        }))
                    } else {
                        Ok(serde_json::json!({ "data": [] }))
                    }
                }
                other => panic!("unexpected OCI command: {other}"),
            }
        }
    }

    struct FixtureInactiveRequestedResourceRunner;

    impl OciCliRunner for FixtureInactiveRequestedResourceRunner {
        fn run_json(&self, args: &[String]) -> Result<Value, OciEmailError> {
            match command_label(args).as_str() {
                "logging log-group list" => Ok(serde_json::json!({
                    "data": [{
                        "id": "ocid1.loggroup.oc1.example",
                        "display-name": "Private Log Group",
                        "lifecycle-state": "ACTIVE"
                    }]
                })),
                "logging log list" => Ok(serde_json::json!({
                    "data": [
                        {
                            "id": "ocid1.log.oc1.requested",
                            "log-group-id": "ocid1.loggroup.oc1.example",
                            "display-name": "Inactive Requested Resource Log",
                            "lifecycle-state": "INACTIVE",
                            "log-type": "SERVICE",
                            "configuration": {
                                "source": {
                                    "service": "emaildelivery",
                                    "resource": "ocid1.emaildomain.oc1.requested",
                                    "category": "emaildomain",
                                    "kind": "service"
                                }
                            }
                        },
                        {
                            "id": "ocid1.log.oc1.other",
                            "log-group-id": "ocid1.loggroup.oc1.example",
                            "display-name": "Active Other Resource Log",
                            "lifecycle-state": "ACTIVE",
                            "log-type": "SERVICE",
                            "configuration": {
                                "source": {
                                    "service": "emaildelivery",
                                    "resource": "ocid1.emaildomain.oc1.other",
                                    "category": "emaildomain",
                                    "kind": "service"
                                }
                            }
                        }
                    ]
                })),
                other => panic!("unexpected OCI command: {other}"),
            }
        }
    }

    struct FixtureNoLogGroupsRunner;

    impl OciCliRunner for FixtureNoLogGroupsRunner {
        fn run_json(&self, args: &[String]) -> Result<Value, OciEmailError> {
            match command_label(args).as_str() {
                "logging log-group list" => Ok(serde_json::json!({ "data": [] })),
                other => panic!("unexpected OCI command: {other}"),
            }
        }
    }

    struct FixtureEventSearchRunner;

    impl OciCliRunner for FixtureEventSearchRunner {
        fn run_json(&self, args: &[String]) -> Result<Value, OciEmailError> {
            let label = command_label(args);
            if label.starts_with("logging-search search-logs") {
                let query = args
                    .windows(2)
                    .find_map(|window| (window[0] == "--search-query").then(|| window[1].as_str()))
                    .expect("search query argument");
                assert!(!query.contains("source='sender.example'"));
                return Ok(serde_json::json!({
                    "data": {
                        "results": [
                            {
                                "datetime": "2026-06-30T00:10:00Z",
                                "data": {
                                    "logContent": {
                                        "type": "com.oraclecloud.emaildelivery.emaildomain.outboundaccepted",
                                        "source": "oci.emaildelivery",
                                        "time": "2026-06-30T00:10:00Z",
                                        "data": {
                                            "action": "accept",
                                            "sender": "sender@sender.example",
                                            "recipient": "person@recipient.example",
                                            "messageId": "message-one"
                                        }
                                    }
                                }
                            },
                            {
                                "datetime": "2026-06-30T00:11:00Z",
                                "data": {
                                    "logContent": {
                                        "type": "com.oraclecloud.emaildelivery.emaildomain.outboundaccepted",
                                        "source": "oci.emaildelivery",
                                        "time": "2026-06-30T00:11:00Z",
                                        "data": {
                                            "action": "accept",
                                            "sender": "other@other.example",
                                            "recipient": "other-person@recipient.example",
                                            "messageId": "message-two"
                                        }
                                    }
                                }
                            }
                        ]
                    }
                }));
            }
            panic!("unexpected OCI command: {label}")
        }
    }

    struct FixtureDuplicateComplaintEventSearchRunner;

    impl OciCliRunner for FixtureDuplicateComplaintEventSearchRunner {
        fn run_json(&self, args: &[String]) -> Result<Value, OciEmailError> {
            let label = command_label(args);
            if label.starts_with("logging-search search-logs") {
                return Ok(serde_json::json!({
                    "data": {
                        "results": [
                            {
                                "datetime": "2026-06-30T00:10:00Z",
                                "data": {
                                    "logContent": {
                                        "type": "com.oraclecloud.emaildelivery.emaildomain.outboundaccepted",
                                        "source": "oci.emaildelivery",
                                        "time": "2026-06-30T00:10:00Z",
                                        "data": {
                                            "action": "complaint",
                                            "sender": "sender@sender.example",
                                            "recipient": "first@recipient.example",
                                            "messageId": "message-one"
                                        }
                                    }
                                }
                            },
                            {
                                "datetime": "2026-06-30T00:11:00Z",
                                "data": {
                                    "logContent": {
                                        "type": "com.oraclecloud.emaildelivery.emaildomain.outboundaccepted",
                                        "source": "oci.emaildelivery",
                                        "time": "2026-06-30T00:11:00Z",
                                        "data": {
                                            "action": "complaint",
                                            "sender": "sender@sender.example",
                                            "recipient": "first@recipient.example",
                                            "messageId": "message-one"
                                        }
                                    }
                                }
                            },
                            {
                                "datetime": "2026-06-30T00:12:00Z",
                                "data": {
                                    "logContent": {
                                        "type": "com.oraclecloud.emaildelivery.emaildomain.outboundaccepted",
                                        "source": "oci.emaildelivery",
                                        "time": "2026-06-30T00:12:00Z",
                                        "data": {
                                            "action": "complaint",
                                            "sender": "sender@sender.example",
                                            "recipient": "second@recipient.example",
                                            "messageId": "message-two"
                                        }
                                    }
                                }
                            }
                        ]
                    }
                }));
            }
            panic!("unexpected OCI command: {label}")
        }
    }

    fn test_config() -> OciEmailConfig {
        OciEmailConfig {
            cli_bin: "oci".to_string(),
            profile: "TEST".to_string(),
            compartment_id: Some("ocid1.tenancy.oc1.example".to_string()),
            region: Some("example-region-1".to_string()),
            config_file: None,
            ledger_path: None,
            snapshot_root: None,
            warn_hard_bounce_percent: 0.5,
            pause_hard_bounce_percent: 0.55,
            throttle_hard_bounce_percent: 0.75,
            hard_stop_hard_bounce_percent: 1.0,
        }
    }
}
