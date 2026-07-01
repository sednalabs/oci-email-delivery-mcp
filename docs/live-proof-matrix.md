# OCI Email Delivery MCP Live Proof Matrix

This matrix records the no-send proof required before using the adapter for
pilot monitoring.

| evidence line | required proof | current status |
| --- | --- | --- |
| Server shape | Standalone curated stdio intent server built with `mcp-toolkit-rs`. | implemented locally |
| Toolkit template | `templates/curated-stdio-intent-server`. | implemented locally |
| Intent tools | `oci_email_status`, `oci_email_metrics`, `oci_email_ledger_window`, `oci_email_events`, `oci_email_logging_status`, `oci_email_trace_message`, `oci_email_suppressions`, `oci_email_watch_window`, `oci_email_send_readiness`, `oci_email_traceability_audit`, `oci_email_monitoring_snapshot_artifact`. | implemented locally |
| Toolkit contract tests | Schema snapshot and real stdio `tools/list` smoke. | implemented locally |
| Domain output contract tests | Fixture-backed output, redaction, missing-auth, invalid-filter, and missing-metric tests. | implemented locally |
| Live no-send proof | OCI profile read-only status, metric discovery/summarize, log search, and suppression query without `submit-email` or mutation commands. | passed as no-send/blocked on 2026-06-30; see `docs/no-send-live-proof-2026-06-30.md` |
| Logging configuration visibility | `oci_email_logging_status` inventories visible OCI service-log configuration and blocks when no active Email Delivery service log is visible, without enabling or mutating logs. | implemented with fixture tests; pending live configured-alias proof after hosted artifact install |
| Suppression aggregate proof | `oci_email_suppressions` returns redacted sample rows plus `totals.hard_bounce`, `totals.by_reason`, and `totals.by_recipient_domain` so clean-audience and stop-gate reconciliation does not depend on raw recipients. | implemented with fixture tests; pending hosted artifact install |
| Local send ledger proof | Configured private JSONL ledger can be summarized by UTC window with hashes/domains only and no raw recipients. | implemented with fixture tests; pending live configured ledger path |
| Composed send readiness proof | `oci_email_send_readiness` combines watch-window proof with local ledger row-count, trace-key, and recipient-key gates while still returning `send_authorized=false`. | implemented with fixture tests; pending live seed/cohort ledger rows and log traceability |
| Exact traceability proof | `oci_email_traceability_audit` reports `exact_message_traceable=true` only when a requested trace returns OCI log events and one uncapped local ledger row overlaps both the requested trace key and OCI event recipient hash; otherwise it reports `aggregate_only=true`. | implemented with fixture tests; pending live configured ledger path and matching OCI log events |
| Durable private snapshots | `oci_email_monitoring_snapshot_artifact` writes redacted watch, readiness, or traceability receipts to a configured private root and returns filename, bytes, SHA-256, and root hash without exposing the private path. | implemented with fixture tests; pending live configured snapshot root and hosted artifact install |
| GitHub Actions run | Hosted validation on reviewed commit, including Rust baseline, CodeQL, custom query tests, GitHub Code Quality coverage, DevSkim, OSV, and release-artifact where applicable. | public repo exists; Rust baseline, DevSkim, OSV, and custom query tests have run; Code Quality coverage upload still needs repository Code Quality enablement |
| Reviewer signoff | Sidecar review for architecture/contract, safety/redaction, release readiness, and monitoring runbook coverage. | local sidecar loop clean on 2026-06-30; hosted release review remains pending |
| Promotion source | Hosted artifact or tagged commit only; no local binary promotion. | release-artifact workflow present; pending hosted run and checksum install |
| Rollback | Remove MCP alias or restore previous hosted artifact. | deferred until install |

Operational posture: no-send-only and not production-ready until hosted
validation, reviewer findings, the hard-bounce blocker, degraded live log
evidence gaps, private ledger configuration, and GitHub Code Quality coverage
upload readiness are resolved. Accepting those gaps can only mean remaining
paused or seed-only; it is not production monitoring readiness.
