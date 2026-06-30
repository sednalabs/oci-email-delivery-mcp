use crate::{
    config::OciEmailConfig,
    error::OciEmailError,
    redact::{email_domain, is_host_token, redact_email, redact_sensitive_text, short_hash},
    response::{
        EmailEventSummary, EventFilters, EventsReport, EventsRequest, Evidence, MetricRates,
        MetricResult, MetricTotals, MetricsFilters, MetricsReport, MetricsRequest,
        OciEmailStatusReport, QueryProbe, ReadinessFinding, RedactedIdentifier, StopThresholds,
        SuppressionSummary, SuppressionsReport, SuppressionsRequest, TraceCriteria,
        TraceMessageReport, TraceMessageRequest, DEFAULT_EVENT_LIMIT, DEFAULT_SUPPRESSION_LIMIT,
        HARD_EVENT_LIMIT, HARD_SUPPRESSION_LIMIT,
    },
};
use serde_json::Value;
use std::{collections::BTreeSet, process::Command, sync::Arc};

const NAMESPACE: &str = "oci_emaildelivery";

const STANDARD_METRICS: &[(&str, &str)] = &[
    ("accepted", "EmailsAccepted"),
    ("relayed", "EmailsRelayed"),
    ("hard_bounced", "EmailsHardBounced"),
    ("soft_bounced", "EmailsSoftBounced"),
    ("suppressed", "EmailsSuppressed"),
    ("complaints", "EmailComplaints"),
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
    fn trace_message(
        &self,
        request: &TraceMessageRequest,
    ) -> Result<TraceMessageReport, OciEmailError>;
    fn suppressions(
        &self,
        request: &SuppressionsRequest,
    ) -> Result<SuppressionsReport, OciEmailError>;
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
        validate_interval(request.interval.as_deref().unwrap_or("1h"))?;
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
        let interval = request.interval.clone().unwrap_or_else(|| "1h".to_string());
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
                if matches!(
                    *key,
                    "hard_bounced" | "soft_bounced" | "suppressed" | "complaints"
                ) {
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
            source_domain: None,
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
            "--limit".to_string(),
            limit.to_string(),
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
        let suppressions = json_items(&value)
            .into_iter()
            .map(suppression_summary)
            .collect::<Vec<_>>();
        let mut findings = Vec::new();
        if value.is_null() {
            findings.push(finding(
                "warning",
                "empty_suppression_stdout",
                "OCI CLI returned empty stdout for suppression list; treat as no sample, not as a full absence proof.",
            ));
        }
        Ok(SuppressionsReport {
            status: if findings.is_empty() {
                "ok".to_string()
            } else {
                "degraded".to_string()
            },
            limit,
            returned: suppressions.len(),
            suppressions,
            findings,
            evidence: vec![Evidence::new(
                "oci_cli",
                "email suppression list",
                request.limit.unwrap_or(DEFAULT_SUPPRESSION_LIMIT) > HARD_SUPPRESSION_LIMIT,
            )],
        })
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
        let events = log_results(&value)
            .into_iter()
            .map(email_event_summary)
            .collect::<Vec<_>>();
        let mut findings = Vec::new();
        if events.is_empty() {
            findings.push(finding(
                "warning",
                "no_log_events_returned",
                "No Email Delivery log events matched this window/filter; this does not prove logging is enabled.",
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
            returned: events.len(),
            events,
            findings,
            evidence: vec![Evidence::new(
                "oci_cli",
                "logging-search search-logs",
                request.limit.unwrap_or(DEFAULT_EVENT_LIMIT) > HARD_EVENT_LIMIT,
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
            totals.relayed,
            available_keys,
            "complaints",
            "relayed",
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
        source_domain: string_field(record, "source")
            .filter(|value| is_host_token(value))
            .map(|value| value.to_ascii_lowercase()),
        receiving_domain: string_field(data, "receivingDomain")
            .filter(|value| is_host_token(value))
            .map(|value| value.to_ascii_lowercase()),
        recipient_domain: email.and_then(email_domain),
        recipient_hash: email.map(short_hash),
        message_id_hash: message_id.map(short_hash),
        error_type: nested_string(data, &["errorType"]).map(redact_sensitive_text),
        bounce_category: nested_string(data, &["bounceCategory"]).map(redact_sensitive_text),
        smtp_status: nested_string(data, &["smtpStatus"]).map(redact_sensitive_text),
        raw_payload_returned: false,
    }
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
    if let Some(domain) = request.source_domain.as_deref() {
        validate_domain(domain, "source_domain")?;
        filters.push(format!("source='{}'", safe_query_value(domain)?));
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

fn validate_interval(value: &str) -> Result<(), OciEmailError> {
    let valid = matches!(value, "1m" | "5m" | "15m" | "30m" | "1h" | "1d");
    if valid {
        Ok(())
    } else {
        Err(OciEmailError::InvalidInput(
            "interval must be one of 1m, 5m, 15m, 30m, 1h, or 1d".to_string(),
        ))
    }
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
        assert!(query.contains("resourceId = \"ocid1.emaildomain:"));
        assert!(!query.contains("ocid1.emaildomain.oc1"));
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
}
