//! # OCI Email Delivery MCP
//!
//! Curated stdio MCP server for read-only OCI Email Delivery monitoring and
//! no-send readiness evidence.
//!
//! ## Rationale
//!
//! Agents need programmatic, redacted evidence from OCI Monitoring, Logging,
//! approved sender/domain state, and suppression list visibility before
//! production or cohort sends can safely expand. This crate keeps that surface
//! narrow and read-only.
//!
//! ## Security Boundaries
//!
//! * Uses the local OCI CLI credential chain.
//! * Exposes only read-only intent tools.
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
mod live;
mod redact;
mod response;

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
    EmailEventSummary, EventFilters, EventsReport, EventsRequest, Evidence, MetricRates,
    MetricResult, MetricTotals, MetricsFilters, MetricsReport, MetricsRequest,
    OciEmailStatusReport, QueryProbe, ReadinessFinding, RedactedIdentifier, StatusRequest,
    StopThresholds, SuppressionSummary, SuppressionsReport, SuppressionsRequest, ToolCallOutcome,
    TraceCriteria, TraceMessageReport, TraceMessageRequest, WatchWindowComponents,
    WatchWindowReport, WatchWindowRequest,
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
                    "oci_email_events",
                    "Search OCI Email Delivery logs with redacted event summaries.",
                    ["oci", "email", "logs", "events"],
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

    #[tool(description = "Search OCI Email Delivery logs with redacted event summaries.")]
    fn oci_email_events(&self, Parameters(request): Parameters<EventsRequest>) -> String {
        response::tool_json(self.backend.events(&request))
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
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for OciEmailMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions("Read-only OCI Email Delivery monitoring tools. No send, DNS, suppression mutation, log-enable, Connector Hub apply, contact import, or campaign action tools are exposed.")
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
                "oci_email_metrics",
                "oci_email_status",
                "oci_email_suppressions",
                "oci_email_trace_message",
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

        fn trace_message(
            &self,
            _request: &TraceMessageRequest,
        ) -> Result<TraceMessageReport, OciEmailError> {
            Ok(TraceMessageReport {
                status: "ok".to_string(),
                criteria: TraceCriteria {
                    message_id_hash: Some("fixture".to_string()),
                    header_name: None,
                    header_value_hash: None,
                },
                events: fixture_events(),
            })
        }

        fn suppressions(
            &self,
            _request: &SuppressionsRequest,
        ) -> Result<SuppressionsReport, OciEmailError> {
            Ok(SuppressionsReport {
                status: "ok".to_string(),
                limit: 20,
                returned: 1,
                suppressions: vec![SuppressionSummary {
                    time_created: Some("2026-06-30T00:00:00Z".to_string()),
                    reason: Some("bounce".to_string()),
                    recipient_redacted: Some("[redacted]@example.com".to_string()),
                    recipient_domain: Some("example.com".to_string()),
                    recipient_hash: Some("fixture".to_string()),
                    raw_payload_returned: false,
                }],
                findings: Vec::new(),
                evidence: vec![Evidence::new("fixture", "suppressions", false)],
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
