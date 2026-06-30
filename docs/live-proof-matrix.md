# OCI Email Delivery MCP Live Proof Matrix

This matrix records the no-send proof required before using the adapter for
pilot monitoring.

| evidence line | required proof | current status |
| --- | --- | --- |
| Server shape | Standalone curated stdio intent server built with `mcp-toolkit-rs`. | implemented locally |
| Toolkit template | `templates/curated-stdio-intent-server`. | implemented locally |
| Intent tools | `oci_email_status`, `oci_email_metrics`, `oci_email_ledger_window`, `oci_email_events`, `oci_email_trace_message`, `oci_email_suppressions`, `oci_email_watch_window`. | implemented locally |
| Toolkit contract tests | Schema snapshot and real stdio `tools/list` smoke. | implemented locally |
| Domain output contract tests | Fixture-backed output, redaction, missing-auth, invalid-filter, and missing-metric tests. | implemented locally |
| Live no-send proof | OCI profile read-only status, metric discovery/summarize, log search, and suppression query without `submit-email` or mutation commands. | passed as no-send/blocked on 2026-06-30; see `docs/no-send-live-proof-2026-06-30.md` |
| Local send ledger proof | Configured private JSONL ledger can be summarized by UTC window with hashes/domains only and no raw recipients. | implemented with fixture tests; pending live configured ledger path |
| GitHub Actions run | Hosted validation on reviewed commit, including Rust baseline, CodeQL, custom query tests, GitHub Code Quality coverage, DevSkim, OSV, and release-artifact where applicable. | public repo exists; Rust baseline, DevSkim, OSV, and custom query tests have run; Code Quality coverage upload still needs repository Code Quality enablement |
| Reviewer signoff | Sidecar review for architecture/contract, safety/redaction, release readiness, and monitoring runbook coverage. | local sidecar loop clean on 2026-06-30; hosted release review remains pending |
| Promotion source | Hosted artifact or tagged commit only; no local binary promotion. | release-artifact workflow present; pending hosted run and checksum install |
| Rollback | Remove MCP alias or restore previous hosted artifact. | deferred until install |

Operational posture: no-send-only and not production-ready until hosted
validation, reviewer findings, the hard-bounce blocker, degraded live log
evidence gaps, private ledger configuration, and GitHub Code Quality coverage
upload readiness are resolved. Accepting those gaps can only mean remaining
paused or seed-only; it is not production monitoring readiness.
