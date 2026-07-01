//! # OCI Email Delivery MCP
//!
//! Curated stdio MCP server for OCI Email Delivery monitoring and no-send
//! readiness evidence.
//!
//! ## Rationale
//!
//! Agents need programmatic, redacted evidence from OCI Monitoring, Logging,
//! approved sender/domain state, and suppression list visibility before
//! production or cohort sends can safely expand. This crate keeps the
//! OCI/provider surface narrow and read-only, with optional local private
//! artifact writes for redacted monitoring snapshots.
//!
//! ## Security Boundaries
//!
//! * Uses the local OCI CLI credential chain.
//! * Exposes only read-only OCI/provider intent tools and redacted local
//!   snapshot artifact writes.
//! * Blocks send, DNS, suppression mutation, log-enable, Connector Hub apply,
//!   contact import, and production campaign actions.
//! * Redacts recipient local parts, message ids, header values, OCIDs, raw CLI
//!   errors, and raw provider JSON from tool output.
//! * Treats `EmailsRelayed` as recipient-domain acceptance, not inbox
//!   placement proof.
//!
//! ## References
//!
//! * `AGENTS.md`
//! * `docs/capability-matrix.md`
//! * `docs/live-proof-matrix.md`

mod config;
mod error;
mod ledger;
mod live;
mod redact;
mod response;
mod snapshot;

use std::sync::Arc;

pub use config::OciEmailConfig;
pub use error::{OciEmailError, ToolErrorReport};
pub use live::{LiveOciEmailBackend, OciCliRunner, OciEmailBackend, ProcessOciCliRunner};
use mcp_toolkit::rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo, Tool},
    tool, tool_handler, tool_router, ServerHandler,
};
use mcp_toolkit_core::{
    guarded_action::GuardedActionPosture,
    tool_inventory::{ToolCapability, ToolDiscoveryMetadata, ToolInventory, ToolInventoryError},
};
pub use response::{
    EmailDeliveryLogSummary, EmailEventSummary, EventFilters, EventsReport, EventsRequest,
    Evidence, LedgerRowSummary, LedgerWindowFilters, LedgerWindowReport, LedgerWindowRequest,
    LedgerWindowTotals, LogGroupSummary, LoggingEnablementPlanReport, LoggingEnablementPlanRequest,
    LoggingStatusReport, LoggingStatusRequest, MetricRates, MetricResult, MetricTotals,
    MetricsFilters, MetricsReport, MetricsRequest, OciEmailStatusReport, QueryProbe,
    ReadinessFinding, RedactedIdentifier, SendReadinessComponents, SendReadinessReport,
    SendReadinessRequest, SnapshotArtifactReport, SnapshotArtifactRequest, SnapshotArtifactSummary,
    StatusRequest, StopThresholds, SuppressionCount, SuppressionSummary, SuppressionTotals,
    SuppressionsReport, SuppressionsRequest, ToolCallOutcome, TraceCriteria, TraceMessageReport,
    TraceMessageRequest, TraceabilityAuditComponents, TraceabilityAuditReport,
    TraceabilityAuditRequest, TraceabilitySummary, WatchWindowComponents, WatchWindowReport,
    WatchWindowRequest,
};

#[derive(Clone)]
pub struct OciEmailMcpServer {
    backend: Arc<dyn OciEmailBackend>,
    tool_router: ToolRouter<Self>,
    inventory: ToolInventory,
}

impl OciEmailMcpServer {
    pub fn new(config: OciEmailConfig) -> Result<Self, ToolInventoryError> {
        Self::with_backend(Arc::new(LiveOciEmailBackend::new(config)))
    }

    pub fn with_backend(backend: Arc<dyn OciEmailBackend>) -> Result<Self, ToolInventoryError> {
        Ok(Self {
            backend,
            tool_router: Self::tool_router(),
            inventory: ToolInventory::from_capabilities([
                read_capability(
                    "oci_email_status",
                    "Check OCI Email Delivery profile readiness and sender/domain visibility.",
                    ["oci", "email", "status", "readiness"],
                ),
                read_capability(
                    "oci_email_metrics",
                    "Query fixed OCI Email Delivery Monitoring metrics for a UTC window.",
                    ["oci", "email", "metrics", "monitoring"],
                ),
                read_capability(
                    "oci_email_ledger_window",
                    "Summarize configured local send-ledger rows for a UTC window with redacted identifiers.",
                    ["oci", "email", "ledger", "local"],
                ),
                read_capability(
                    "oci_email_events",
                    "Search OCI Email Delivery logs with redacted event summaries.",
                    ["oci", "email", "logs", "events"],
                ),
                read_capability(
                    "oci_email_logging_status",
                    "Check whether OCI Email Delivery service logs are configured and visible without enabling or changing logs.",
                    ["oci", "email", "logs", "logging", "status"],
                ),
                read_capability(
                    "oci_email_logging_enablement_plan",
                    "Build a read-only operator plan for enabling OCI Email Delivery service-log visibility and post-enable proof.",
                    ["oci", "email", "logs", "logging", "enablement", "plan"],
                ),
                read_capability(
                    "oci_email_trace_message",
                    "Trace one message id or correlation header through OCI Email Delivery logs.",
                    ["oci", "email", "trace", "message"],
                ),
                read_capability(
                    "oci_email_suppressions",
                    "Summarize OCI Email Delivery suppressions without raw recipients.",
                    ["oci", "email", "suppressions", "audience"],
                ),
                read_capability(
                    "oci_email_watch_window",
                    "Build one read-only send-window monitoring receipt from status, metrics, logs, trace, and suppressions.",
                    ["oci", "email", "watch", "receipt"],
                ),
                read_capability(
                    "oci_email_send_readiness",
                    "Build one read-only send-window readiness receipt from monitoring evidence plus local send-ledger proof.",
                    ["oci", "email", "readiness", "ledger"],
                ),
                read_capability(
                    "oci_email_traceability_audit",
                    "Audit whether one UTC window proves exact OCI log and local send-ledger traceability or only aggregate delivery pressure.",
                    ["oci", "email", "traceability", "ledger", "logs"],
                ),
                ToolCapability::new("oci_email_monitoring_snapshot_artifact")
                    .with_group("read")
                    .with_risk_posture(GuardedActionPosture::no_mutation_proof())
                    .with_discovery(ToolDiscoveryMetadata::new(
                        "Write one redacted private OCI Email Delivery monitoring receipt artifact under a configured local root.",
                        ["oci", "email", "monitoring", "snapshot", "artifact"],
                    )),
            ])?,
        })
    }

    pub fn tool_schema_snapshot(&self) -> Vec<Tool> {
        self.tool_router.list_all()
    }

    pub fn inventory(&self) -> &ToolInventory {
        &self.inventory
    }
}

fn read_capability(
    name: &str,
    description: &str,
    keywords: impl IntoIterator<Item = &'static str>,
) -> ToolCapability {
    ToolCapability::new(name)
        .with_group("read")
        .with_read_only(true)
        .with_risk_posture(GuardedActionPosture::read_only())
        .with_discovery(ToolDiscoveryMetadata::new(description, keywords))
}

#[tool_router]
impl OciEmailMcpServer {
    #[tool(
        description = "Check OCI Email Delivery profile readiness and sender/domain visibility."
    )]
    fn oci_email_status(&self, Parameters(request): Parameters<StatusRequest>) -> String {
        response::tool_json(self.backend.status(&request))
    }

    #[tool(description = "Query fixed OCI Email Delivery Monitoring metrics for a UTC window.")]
    fn oci_email_metrics(&self, Parameters(request): Parameters<MetricsRequest>) -> String {
        response::tool_json(self.backend.metrics(&request))
    }

    #[tool(
        description = "Summarize configured local OCI send-ledger rows for a UTC window without raw recipients."
    )]
    fn oci_email_ledger_window(
        &self,
        Parameters(request): Parameters<LedgerWindowRequest>,
    ) -> String {
        response::tool_json(self.backend.ledger_window(&request))
    }

    #[tool(description = "Search OCI Email Delivery logs with redacted event summaries.")]
    fn oci_email_events(&self, Parameters(request): Parameters<EventsRequest>) -> String {
        response::tool_json(self.backend.events(&request))
    }

    #[tool(
        description = "Check whether OCI Email Delivery service logs are configured and visible without enabling or changing logs."
    )]
    fn oci_email_logging_status(
        &self,
        Parameters(request): Parameters<LoggingStatusRequest>,
    ) -> String {
        response::tool_json(self.backend.logging_status(&request))
    }

    #[tool(
        description = "Build a read-only OCI Email Delivery service-log enablement plan without enabling or changing logs."
    )]
    fn oci_email_logging_enablement_plan(
        &self,
        Parameters(request): Parameters<LoggingEnablementPlanRequest>,
    ) -> String {
        response::tool_json(self.backend.logging_enablement_plan(&request))
    }

    #[tool(
        description = "Trace one message id or correlation header through OCI Email Delivery logs."
    )]
    fn oci_email_trace_message(
        &self,
        Parameters(request): Parameters<TraceMessageRequest>,
    ) -> String {
        response::tool_json(self.backend.trace_message(&request))
    }

    #[tool(description = "Summarize OCI Email Delivery suppressions without raw recipients.")]
    fn oci_email_suppressions(
        &self,
        Parameters(request): Parameters<SuppressionsRequest>,
    ) -> String {
        response::tool_json(self.backend.suppressions(&request))
    }

    #[tool(
        description = "Build one read-only OCI Email Delivery monitoring receipt for an explicit UTC window."
    )]
    fn oci_email_watch_window(
        &self,
        Parameters(request): Parameters<WatchWindowRequest>,
    ) -> String {
        response::tool_json(self.backend.watch_window(&request))
    }

    #[tool(
        description = "Build one read-only OCI Email Delivery send-readiness receipt from monitoring and local send-ledger proof."
    )]
    fn oci_email_send_readiness(
        &self,
        Parameters(request): Parameters<SendReadinessRequest>,
    ) -> String {
        response::tool_json(self.backend.send_readiness(&request))
    }

    #[tool(
        description = "Audit whether one UTC window proves exact OCI Email Delivery traceability across logs and the local send ledger without authorizing a send."
    )]
    fn oci_email_traceability_audit(
        &self,
        Parameters(request): Parameters<TraceabilityAuditRequest>,
    ) -> String {
        response::tool_json(self.backend.traceability_audit(&request))
    }

    #[tool(
        description = "Write one redacted private OCI Email Delivery monitoring or send-readiness receipt artifact under a configured local root."
    )]
    fn oci_email_monitoring_snapshot_artifact(
        &self,
        Parameters(request): Parameters<SnapshotArtifactRequest>,
    ) -> String {
        response::tool_json(self.backend.snapshot_artifact(&request))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for OciEmailMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("OCI Email Delivery monitoring tools with a read-only OCI/provider surface and optional redacted local private snapshot artifacts. No send, DNS, suppression mutation, log-enable, Connector Hub apply, contact import, or campaign action tools are exposed.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcp_toolkit_core::tool_inventory::{ToolInventoryPolicy, ToolOperation};

    #[test]
    fn inventory_matches_exported_tool_names() {
        let server =
            OciEmailMcpServer::with_backend(Arc::new(crate::tests_support::FixtureBackend))
                .unwrap_or_else(|err| panic!("server inventory: {err}"));
        let names = server
            .tool_schema_snapshot()
            .iter()
            .map(|tool| tool.name.as_ref().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "oci_email_events",
                "oci_email_ledger_window",
                "oci_email_logging_enablement_plan",
                "oci_email_logging_status",
                "oci_email_metrics",
                "oci_email_monitoring_snapshot_artifact",
                "oci_email_send_readiness",
                "oci_email_status",
                "oci_email_suppressions",
                "oci_email_trace_message",
                "oci_email_traceability_audit",
                "oci_email_watch_window"
            ]
        );

        let policy = ToolInventoryPolicy::default();
        for name in names {
            assert!(server
                .inventory()
                .is_allowed(&name, ToolOperation::Call, &policy));
        }
    }
}

#[doc(hidden)]
pub mod tests_support {
    use super::*;

    #[derive(Debug)]
    pub struct FixtureBackend;

    impl OciEmailBackend for FixtureBackend {
        fn status(&self, _request: &StatusRequest) -> Result<OciEmailStatusReport, OciEmailError> {
            Ok(OciEmailStatusReport {
                status: "degraded".to_string(),
                send_authorized: false,
                profile: "TEST".to_string(),
                region: Some("example-region-1".to_string()),
                compartment: RedactedIdentifier {
                    present: true,
                    redacted: Some("ocid1.tenancy:fixture".to_string()),
                },
                approved_sender_count: 1,
                active_sender_count: 1,
                sender_domains: vec!["example.com".to_string()],
                email_domain_count: 1,
                active_email_domain_count: 0,
                suppression_query: QueryProbe {
                    status: "ok".to_string(),
                    item_count: 0,
                    note: None,
                },
                findings: vec![ReadinessFinding {
                    severity: "warning".to_string(),
                    code: "no_active_email_domain".to_string(),
                    message: "No ACTIVE Email Domain was visible.".to_string(),
                }],
                evidence: vec![Evidence::new("fixture", "status", false)],
            })
        }

        fn metrics(&self, _request: &MetricsRequest) -> Result<MetricsReport, OciEmailError> {
            Ok(MetricsReport {
                status: "degraded".to_string(),
                namespace: "oci_emaildelivery".to_string(),
                start_time: "2026-06-30T00:00:00Z".to_string(),
                end_time: "2026-06-30T01:00:00Z".to_string(),
                interval: "1h".to_string(),
                filters: MetricsFilters {
                    resource_domain: Some("example.com".to_string()),
                    resource_id: RedactedIdentifier {
                        present: false,
                        redacted: None,
                    },
                },
                metric_definitions_seen: vec![
                    "EmailsAccepted".to_string(),
                    "EmailsRelayed".to_string(),
                ],
                metrics: vec![MetricResult {
                    key: "accepted".to_string(),
                    oci_name: "EmailsAccepted".to_string(),
                    status: "ok".to_string(),
                    query: "EmailsAccepted[1h].sum()".to_string(),
                    total: 10.0,
                    point_count: 1,
                    series_count: 1,
                    note: None,
                }],
                totals: MetricTotals {
                    accepted: 10.0,
                    relayed: 9.0,
                    hard_bounced: 0.0,
                    soft_bounced: 0.0,
                    suppressed: 0.0,
                    complaints: 0.0,
                    blocklisted: 0.0,
                    list_unsubscribed: 0.0,
                    opened: 0.0,
                    clicked: 0.0,
                },
                rates: MetricRates {
                    relay_rate: Some(0.9),
                    hard_bounce_rate: Some(0.0),
                    soft_bounce_rate: Some(0.0),
                    complaint_rate: Some(0.0),
                    blocklist_rate: Some(0.0),
                    unsubscribe_rate: Some(0.0),
                },
                thresholds: StopThresholds::default(),
                findings: vec![ReadinessFinding {
                    severity: "warning".to_string(),
                    code: "metric_unavailable_hard_bounced".to_string(),
                    message: "A stop-gate metric is not currently visible.".to_string(),
                }],
                evidence: vec![Evidence::new("fixture", "metrics", false)],
            })
        }

        fn events(&self, _request: &EventsRequest) -> Result<EventsReport, OciEmailError> {
            Ok(fixture_events())
        }

        fn logging_status(
            &self,
            request: &LoggingStatusRequest,
        ) -> Result<LoggingStatusReport, OciEmailError> {
            let source_resource = request
                .resource_id
                .as_deref()
                .unwrap_or("ocid1.emaildomain.oc1.fixture");
            let source_resource = RedactedIdentifier::from_optional(Some(source_resource));
            let matching_requested_resource_log_count = usize::from(request.resource_id.is_some());
            Ok(LoggingStatusReport {
                status: "ok".to_string(),
                send_authorized: false,
                compartment: RedactedIdentifier {
                    present: true,
                    redacted: Some("ocid1.tenancy:fixture".to_string()),
                },
                requested_resource_id: RedactedIdentifier::from_optional(
                    request.resource_id.as_deref(),
                ),
                limit: 20,
                log_group_count: 1,
                service_log_count: 1,
                email_delivery_log_count: 1,
                active_email_delivery_log_count: 1,
                matching_requested_resource_log_count,
                log_groups: vec![LogGroupSummary {
                    log_group_id: RedactedIdentifier {
                        present: true,
                        redacted: Some("ocid1.loggroup:fixture".to_string()),
                    },
                    display_name_hash: Some("fixture".to_string()),
                    lifecycle_state: Some("ACTIVE".to_string()),
                    raw_payload_returned: false,
                }],
                email_delivery_logs: vec![EmailDeliveryLogSummary {
                    log_id: RedactedIdentifier {
                        present: true,
                        redacted: Some("ocid1.log:fixture".to_string()),
                    },
                    log_group_id: RedactedIdentifier {
                        present: true,
                        redacted: Some("ocid1.loggroup:fixture".to_string()),
                    },
                    display_name_hash: Some("fixture".to_string()),
                    lifecycle_state: Some("ACTIVE".to_string()),
                    source_service: Some("emaildelivery".to_string()),
                    source_resource,
                    source_category: Some("emaildomain".to_string()),
                    source_kind: Some("service".to_string()),
                    raw_payload_returned: false,
                }],
                findings: Vec::new(),
                evidence: vec![Evidence::new("fixture", "logging status", false)],
                raw_payload_returned: false,
            })
        }

        fn trace_message(
            &self,
            request: &TraceMessageRequest,
        ) -> Result<TraceMessageReport, OciEmailError> {
            let mut events = fixture_events();
            events.filters.header_name = request.header_name.clone();
            events.filters.header_value_hash = request
                .header_value
                .as_deref()
                .map(|_| "fixture".to_string());
            Ok(TraceMessageReport {
                status: "ok".to_string(),
                criteria: TraceCriteria {
                    message_id_hash: Some("fixture".to_string()),
                    header_name: request.header_name.clone(),
                    header_value_hash: request
                        .header_value
                        .as_deref()
                        .map(|_| "fixture".to_string()),
                },
                events,
            })
        }

        fn suppressions(
            &self,
            _request: &SuppressionsRequest,
        ) -> Result<SuppressionsReport, OciEmailError> {
            Ok(SuppressionsReport {
                status: "ok".to_string(),
                limit: 20,
                returned: 2,
                totals: SuppressionTotals {
                    hard_bounce: 1,
                    by_reason: vec![
                        SuppressionCount {
                            key: "complaint".to_string(),
                            count: 1,
                        },
                        SuppressionCount {
                            key: "hardbounce".to_string(),
                            count: 1,
                        },
                    ],
                    by_recipient_domain: vec![
                        SuppressionCount {
                            key: "example.com".to_string(),
                            count: 1,
                        },
                        SuppressionCount {
                            key: "example.net".to_string(),
                            count: 1,
                        },
                    ],
                },
                suppressions: vec![
                    SuppressionSummary {
                        time_created: Some("2026-06-30T00:00:00Z".to_string()),
                        reason: Some("HARDBOUNCE".to_string()),
                        recipient_redacted: Some("[redacted]@example.com".to_string()),
                        recipient_domain: Some("example.com".to_string()),
                        recipient_hash: Some("fixture".to_string()),
                        raw_payload_returned: false,
                    },
                    SuppressionSummary {
                        time_created: Some("2026-06-30T00:05:00Z".to_string()),
                        reason: Some("COMPLAINT".to_string()),
                        recipient_redacted: Some("[redacted]@example.net".to_string()),
                        recipient_domain: Some("example.net".to_string()),
                        recipient_hash: Some("fixture-2".to_string()),
                        raw_payload_returned: false,
                    },
                ],
                findings: Vec::new(),
                evidence: vec![Evidence::new("fixture", "suppressions", false)],
            })
        }

        fn ledger_window(
            &self,
            _request: &LedgerWindowRequest,
        ) -> Result<LedgerWindowReport, OciEmailError> {
            Ok(LedgerWindowReport {
                status: "ok".to_string(),
                start_time: "2026-06-30T00:00:00Z".to_string(),
                end_time: "2026-06-30T01:00:00Z".to_string(),
                filters: LedgerWindowFilters {
                    sender_domain: Some("example.com".to_string()),
                    campaign_hash: Some("fixture".to_string()),
                    batch_hash: Some("fixture".to_string()),
                },
                limit: 20,
                totals: LedgerWindowTotals {
                    scanned_rows: 1,
                    matched_rows: 1,
                    returned_rows: 1,
                    invalid_rows: 0,
                    rows_capped: false,
                    missing_trace_key_count: 0,
                    missing_recipient_key_count: 0,
                },
                sender_domains: vec!["example.com".to_string()],
                campaigns: vec!["fixture".to_string()],
                batches: vec!["fixture".to_string()],
                rows: vec![LedgerRowSummary {
                    submitted_at: Some("2026-06-30T00:10:00Z".to_string()),
                    provider_hash: Some("fixture".to_string()),
                    campaign_hash: Some("fixture".to_string()),
                    batch_hash: Some("fixture".to_string()),
                    sender_domain: Some("example.com".to_string()),
                    recipient_domain: Some("example.net".to_string()),
                    recipient_address_hash: Some("fixture".to_string()),
                    recipient_id_hash: None,
                    message_id_hash: Some("fixture".to_string()),
                    correlation_id_hash: Some("fixture".to_string()),
                    template_version_hash: Some("fixture".to_string()),
                    subject_hash: Some("fixture".to_string()),
                    raw_recipient_returned: false,
                }],
                findings: Vec::new(),
                evidence: vec![Evidence::new("fixture", "ledger", false)],
                raw_payload_returned: false,
            })
        }
    }

    fn fixture_events() -> EventsReport {
        EventsReport {
            status: "ok".to_string(),
            start_time: "2026-06-30T00:00:00Z".to_string(),
            end_time: "2026-06-30T01:00:00Z".to_string(),
            filters: EventFilters {
                action: Some("relay".to_string()),
                message_id_hash: Some("fixture".to_string()),
                header_name: None,
                header_value_hash: None,
                receiving_domain: Some("example.net".to_string()),
                source_domain: Some("example.com".to_string()),
            },
            limit: 20,
            provider_returned: 1,
            source_domain_matched: 1,
            returned: 1,
            events: vec![EmailEventSummary {
                datetime: Some("2026-06-30T00:10:00Z".to_string()),
                log_type: Some(
                    "com.oraclecloud.emaildelivery.emaildomain.outboundrelayed".to_string(),
                ),
                action: Some("relay".to_string()),
                source_domain: Some("example.com".to_string()),
                receiving_domain: Some("example.net".to_string()),
                recipient_domain: Some("example.net".to_string()),
                recipient_hash: Some("fixture".to_string()),
                message_id_hash: Some("fixture".to_string()),
                error_type: None,
                bounce_category: None,
                smtp_status: None,
                raw_payload_returned: false,
            }],
            findings: Vec::new(),
            evidence: vec![Evidence::new("fixture", "events", false)],
        }
    }
}
