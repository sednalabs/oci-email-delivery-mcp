use crate::error::{OciEmailError, ToolErrorReport};
use crate::redact::redact_ocid;
use mcp_toolkit::rmcp::schemars;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_EVENT_LIMIT: u32 = 20;
pub const HARD_EVENT_LIMIT: u32 = 100;
pub const DEFAULT_SUPPRESSION_LIMIT: u32 = 20;
pub const HARD_SUPPRESSION_LIMIT: u32 = 100;
pub const DEFAULT_LEDGER_LIMIT: u32 = 100;
pub const HARD_LEDGER_LIMIT: u32 = 1000;

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct StatusRequest {
    pub compartment_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct MetricsRequest {
    pub start_time: String,
    pub end_time: String,
    pub interval: Option<String>,
    pub resource_domain: Option<String>,
    pub resource_id: Option<String>,
    pub compartment_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct EventsRequest {
    pub start_time: String,
    pub end_time: String,
    pub action: Option<String>,
    pub message_id: Option<String>,
    pub header_name: Option<String>,
    pub header_value: Option<String>,
    pub receiving_domain: Option<String>,
    pub source_domain: Option<String>,
    pub limit: Option<u32>,
    pub compartment_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct TraceMessageRequest {
    pub start_time: String,
    pub end_time: String,
    pub message_id: Option<String>,
    pub header_name: Option<String>,
    pub header_value: Option<String>,
    pub source_domain: Option<String>,
    pub limit: Option<u32>,
    pub compartment_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct SuppressionsRequest {
    pub time_created_greater_than_or_equal_to: Option<String>,
    pub time_created_less_than: Option<String>,
    pub limit: Option<u32>,
    pub compartment_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct WatchWindowRequest {
    pub start_time: String,
    pub end_time: String,
    pub interval: Option<String>,
    pub resource_domain: Option<String>,
    pub source_domain: Option<String>,
    pub resource_id: Option<String>,
    pub message_id: Option<String>,
    pub header_name: Option<String>,
    pub header_value: Option<String>,
    pub limit: Option<u32>,
    pub compartment_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct SendReadinessRequest {
    pub start_time: String,
    pub end_time: String,
    pub interval: Option<String>,
    pub resource_domain: Option<String>,
    pub source_domain: Option<String>,
    pub resource_id: Option<String>,
    pub sender_domain: Option<String>,
    pub campaign_id: String,
    pub batch_id: String,
    pub expected_ledger_rows: u64,
    pub message_id: Option<String>,
    pub header_name: Option<String>,
    pub header_value: Option<String>,
    pub limit: Option<u32>,
    pub compartment_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct LedgerWindowRequest {
    pub start_time: String,
    pub end_time: String,
    pub sender_domain: Option<String>,
    pub campaign_id: Option<String>,
    pub batch_id: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Evidence {
    pub source: String,
    pub command: String,
    pub checked_at_unix: u64,
    pub raw_payload_returned: bool,
    pub rows_capped: bool,
}

impl Evidence {
    pub fn new(source: impl Into<String>, command: impl Into<String>, rows_capped: bool) -> Self {
        Self {
            source: source.into(),
            command: command.into(),
            checked_at_unix: now_unix(),
            raw_payload_returned: false,
            rows_capped,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RedactedIdentifier {
    pub present: bool,
    pub redacted: Option<String>,
}

impl RedactedIdentifier {
    pub fn from_optional(value: Option<&str>) -> Self {
        Self {
            present: value.is_some(),
            redacted: value.map(redact_ocid),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReadinessFinding {
    pub severity: String,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OciEmailStatusReport {
    pub status: String,
    pub send_authorized: bool,
    pub profile: String,
    pub region: Option<String>,
    pub compartment: RedactedIdentifier,
    pub approved_sender_count: usize,
    pub active_sender_count: usize,
    pub sender_domains: Vec<String>,
    pub email_domain_count: usize,
    pub active_email_domain_count: usize,
    pub suppression_query: QueryProbe,
    pub findings: Vec<ReadinessFinding>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct QueryProbe {
    pub status: String,
    pub item_count: usize,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MetricsReport {
    pub status: String,
    pub namespace: String,
    pub start_time: String,
    pub end_time: String,
    pub interval: String,
    pub filters: MetricsFilters,
    pub metric_definitions_seen: Vec<String>,
    pub metrics: Vec<MetricResult>,
    pub totals: MetricTotals,
    pub rates: MetricRates,
    pub thresholds: StopThresholds,
    pub findings: Vec<ReadinessFinding>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MetricsFilters {
    pub resource_domain: Option<String>,
    pub resource_id: RedactedIdentifier,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MetricResult {
    pub key: String,
    pub oci_name: String,
    pub status: String,
    pub query: String,
    pub total: f64,
    pub point_count: usize,
    pub series_count: usize,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct MetricTotals {
    pub accepted: f64,
    pub relayed: f64,
    pub hard_bounced: f64,
    pub soft_bounced: f64,
    pub suppressed: f64,
    pub complaints: f64,
    pub blocklisted: f64,
    pub list_unsubscribed: f64,
    pub opened: f64,
    pub clicked: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct MetricRates {
    pub relay_rate: Option<f64>,
    pub hard_bounce_rate: Option<f64>,
    pub soft_bounce_rate: Option<f64>,
    pub complaint_rate: Option<f64>,
    pub blocklist_rate: Option<f64>,
    pub unsubscribe_rate: Option<f64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StopThresholds {
    pub hard_bounce_warn_percent: f64,
    pub hard_bounce_pause_percent: f64,
    pub hard_bounce_throttle_or_pause_percent: f64,
    pub hard_bounce_hard_stop_percent: f64,
}

impl Default for StopThresholds {
    fn default() -> Self {
        Self {
            hard_bounce_warn_percent: 0.5,
            hard_bounce_pause_percent: 0.55,
            hard_bounce_throttle_or_pause_percent: 0.75,
            hard_bounce_hard_stop_percent: 1.0,
        }
    }
}

impl StopThresholds {
    pub fn from_config(config: &crate::config::OciEmailConfig) -> Self {
        Self {
            hard_bounce_warn_percent: config.warn_hard_bounce_percent,
            hard_bounce_pause_percent: config.pause_hard_bounce_percent,
            hard_bounce_throttle_or_pause_percent: config.throttle_hard_bounce_percent,
            hard_bounce_hard_stop_percent: config.hard_stop_hard_bounce_percent,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EventsReport {
    pub status: String,
    pub start_time: String,
    pub end_time: String,
    pub filters: EventFilters,
    pub limit: u32,
    pub returned: usize,
    pub events: Vec<EmailEventSummary>,
    pub findings: Vec<ReadinessFinding>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EventFilters {
    pub action: Option<String>,
    pub message_id_hash: Option<String>,
    pub header_name: Option<String>,
    pub header_value_hash: Option<String>,
    pub receiving_domain: Option<String>,
    pub source_domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EmailEventSummary {
    pub datetime: Option<String>,
    pub log_type: Option<String>,
    pub action: Option<String>,
    pub source_domain: Option<String>,
    pub receiving_domain: Option<String>,
    pub recipient_domain: Option<String>,
    pub recipient_hash: Option<String>,
    pub message_id_hash: Option<String>,
    pub error_type: Option<String>,
    pub bounce_category: Option<String>,
    pub smtp_status: Option<String>,
    pub raw_payload_returned: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TraceMessageReport {
    pub status: String,
    pub criteria: TraceCriteria,
    pub events: EventsReport,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TraceCriteria {
    pub message_id_hash: Option<String>,
    pub header_name: Option<String>,
    pub header_value_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SuppressionsReport {
    pub status: String,
    pub limit: u32,
    pub returned: usize,
    pub suppressions: Vec<SuppressionSummary>,
    pub findings: Vec<ReadinessFinding>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SuppressionSummary {
    pub time_created: Option<String>,
    pub reason: Option<String>,
    pub recipient_redacted: Option<String>,
    pub recipient_domain: Option<String>,
    pub recipient_hash: Option<String>,
    pub raw_payload_returned: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ToolCallOutcome<T> {
    pub status: String,
    pub report: Option<T>,
    pub error: Option<ToolErrorReport>,
}

impl<T> ToolCallOutcome<T> {
    pub fn ok(status: impl Into<String>, report: T) -> Self {
        Self {
            status: status.into(),
            report: Some(report),
            error: None,
        }
    }

    pub fn blocked(error: OciEmailError) -> Self {
        Self {
            status: "blocked".to_string(),
            report: None,
            error: Some(ToolErrorReport::from(error)),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct WatchWindowComponents {
    pub status: ToolCallOutcome<OciEmailStatusReport>,
    pub metrics: ToolCallOutcome<MetricsReport>,
    pub events: ToolCallOutcome<EventsReport>,
    pub trace: Option<ToolCallOutcome<TraceMessageReport>>,
    pub suppressions: ToolCallOutcome<SuppressionsReport>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct WatchWindowReport {
    pub status: String,
    pub decision: String,
    pub send_authorized: bool,
    pub start_time: String,
    pub end_time: String,
    pub interval: String,
    pub resource_domain: Option<String>,
    pub source_domain: Option<String>,
    pub trace_requested: bool,
    pub components: WatchWindowComponents,
    pub findings: Vec<ReadinessFinding>,
    pub evidence: Vec<Evidence>,
    pub raw_payload_returned: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SendReadinessComponents {
    pub watch_window: ToolCallOutcome<WatchWindowReport>,
    pub ledger: ToolCallOutcome<LedgerWindowReport>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SendReadinessReport {
    pub status: String,
    pub decision: String,
    pub send_authorized: bool,
    pub start_time: String,
    pub end_time: String,
    pub interval: String,
    pub resource_domain: Option<String>,
    pub source_domain: Option<String>,
    pub sender_domain: Option<String>,
    pub campaign_hash: Option<String>,
    pub batch_hash: Option<String>,
    pub expected_ledger_rows: u64,
    pub trace_requested: bool,
    pub components: SendReadinessComponents,
    pub findings: Vec<ReadinessFinding>,
    pub evidence: Vec<Evidence>,
    pub raw_payload_returned: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LedgerWindowFilters {
    pub sender_domain: Option<String>,
    pub campaign_hash: Option<String>,
    pub batch_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LedgerRowSummary {
    pub submitted_at: Option<String>,
    pub provider_hash: Option<String>,
    pub campaign_hash: Option<String>,
    pub batch_hash: Option<String>,
    pub sender_domain: Option<String>,
    pub recipient_domain: Option<String>,
    pub recipient_address_hash: Option<String>,
    pub recipient_id_hash: Option<String>,
    pub message_id_hash: Option<String>,
    pub correlation_id_hash: Option<String>,
    pub template_version_hash: Option<String>,
    pub subject_hash: Option<String>,
    pub raw_recipient_returned: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LedgerWindowTotals {
    pub scanned_rows: usize,
    pub matched_rows: usize,
    pub returned_rows: usize,
    pub invalid_rows: usize,
    pub rows_capped: bool,
    pub missing_trace_key_count: usize,
    pub missing_recipient_key_count: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LedgerWindowReport {
    pub status: String,
    pub start_time: String,
    pub end_time: String,
    pub filters: LedgerWindowFilters,
    pub limit: u32,
    pub totals: LedgerWindowTotals,
    pub sender_domains: Vec<String>,
    pub campaigns: Vec<String>,
    pub batches: Vec<String>,
    pub rows: Vec<LedgerRowSummary>,
    pub findings: Vec<ReadinessFinding>,
    pub evidence: Vec<Evidence>,
    pub raw_payload_returned: bool,
}

pub fn tool_json<T: Serialize>(result: Result<T, OciEmailError>) -> String {
    match result {
        Ok(report) => serialize_tool_value(&report),
        Err(error) => serialize_tool_value(&ToolErrorReport::from(error)),
    }
}

fn serialize_tool_value<T: Serialize>(value: &T) -> String {
    match serde_json::to_string(value) {
        Ok(serialized) => serialized,
        Err(err) => {
            let fallback = ToolErrorReport {
                status: "blocked",
                error: "serialization_failed",
                message: err.to_string(),
                raw_payload_returned: false,
            };
            match serde_json::to_string(&fallback) {
                Ok(serialized) => serialized,
                Err(_) => {
                    "{\"status\":\"blocked\",\"error\":\"serialization_failed\",\"raw_payload_returned\":false}".to_string()
                }
            }
        }
    }
}

fn now_unix() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}
