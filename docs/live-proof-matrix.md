# OCI Email Delivery MCP Live Proof Matrix

This matrix records the no-send proof required before using the adapter for
pilot monitoring.

| evidence line | required proof | current status |
| --- | --- | --- |
| Server shape | Standalone curated stdio intent server built with `mcp-toolkit-rs`. | implemented locally |
| Toolkit template | `templates/curated-stdio-intent-server`. | implemented locally |
| Intent tools | `oci_email_status`, `oci_email_metrics`, `oci_email_events`, `oci_email_trace_message`, `oci_email_suppressions`. | implemented locally |
| Toolkit contract tests | Schema snapshot and real stdio `tools/list` smoke. | implemented locally |
| Domain output contract tests | Fixture-backed output, redaction, missing-auth, invalid-filter, and missing-metric tests. | implemented locally |
| Live no-send proof | OCI profile read-only status, metric discovery/summarize, log search, and suppression query without `submit-email` or mutation commands. | passed as no-send/degraded on 2026-06-30; see `docs/no-send-live-proof-2026-06-30.md` |
| GitHub Actions run | Hosted validation on reviewed commit. | pending remote repo/PR |
| Reviewer signoff | Sidecar review for architecture/contract and safety/redaction. | pending post-implementation loop |
| Promotion source | Hosted artifact or tagged commit only; no local binary promotion. | deferred |
| Rollback | Remove MCP alias or restore previous hosted artifact. | deferred until install |

Operational posture: no-send-only and not production-ready until hosted
validation, reviewer findings, and degraded live evidence gaps are resolved or
explicitly accepted.
