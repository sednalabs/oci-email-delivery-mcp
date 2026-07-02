# OCI Email Delivery MCP

Stdio MCP server for OCI Email Delivery monitoring. The OCI/provider surface is
read-only; the only local write surface is a configured private artifact tool
for redacted monitoring snapshots. The first operator goal is to let agents
query OCI programmatically before production or cohort sends go live.

The server exposes thirteen curated intent tools:

| Tool | Purpose |
| --- | --- |
| `oci_email_status` | Check CLI/profile readiness, approved senders, email domains, and suppression-query visibility. |
| `oci_email_metrics` | Query fixed `oci_emaildelivery` Monitoring metrics for an explicit UTC window. |
| `oci_email_ledger_window` | Summarize configured local send-ledger rows for a UTC window without raw recipients. |
| `oci_email_events` | Search Email Delivery logs with whitelisted filters and redacted event summaries. |
| `oci_email_logging_status` | Check whether Email Delivery service logs are configured and visible without enabling or changing logs. |
| `oci_email_logging_enablement_plan` | Build a read-only operator plan for enabling Email Delivery service-log visibility and post-enable proof. |
| `oci_email_trace_message` | Trace one message id or correlation header through Email Delivery logs, optionally scoped by source domain. |
| `oci_email_suppressions` | Summarize OCI suppressions with reason/domain totals and no raw recipient addresses. |
| `oci_email_suppression_delta` | Compare full active suppressions with a bounded window and classify clean, incomplete, or blocked evidence. |
| `oci_email_watch_window` | Build one read-only monitoring receipt from status, logging configuration, metrics, logs, optional trace, and suppressions. |
| `oci_email_send_readiness` | Build one read-only send-window receipt that combines watch-window evidence with local send-ledger proof and expected row-count gates. |
| `oci_email_traceability_audit` | Audit whether one UTC window proves exact message/recipient traceability across OCI logs and the local send ledger, or only aggregate delivery pressure. |
| `oci_email_monitoring_snapshot_artifact` | Write one redacted private monitoring, send-readiness, or traceability receipt artifact under the configured local snapshot root. |

No tools send email, mutate OCI resources, enable logs, change DNS, import
contacts, or alter suppressions.

## Configuration

The server uses the standard OCI CLI credential chain through the local `oci`
binary. Configure a profile with normal OCI tooling, then set:

```bash
export OCI_MCP_PROFILE=DEFAULT
export OCI_MCP_COMPARTMENT_ID=ocid1.tenancy.oc1..example
```

`OCI_MCP_COMPARTMENT_ID` is optional when the selected profile in
`~/.oci/config` has a `tenancy` value. Additional optional settings:

```bash
export OCI_MCP_CLI_BIN=oci
export OCI_MCP_REGION=ap-melbourne-1
export OCI_MCP_WARN_HARD_BOUNCE_PERCENT=0.5
export OCI_MCP_PAUSE_HARD_BOUNCE_PERCENT=0.55
export OCI_MCP_THROTTLE_HARD_BOUNCE_PERCENT=0.75
export OCI_MCP_HARD_STOP_HARD_BOUNCE_PERCENT=1.0
export OCI_MCP_LEDGER_PATH=/path/to/private/send-ledger.jsonl
export OCI_MCP_SNAPSHOT_ROOT=/path/to/private/monitoring-snapshots
```

The hard-bounce threshold defaults above are operational guardrails only. Set
them explicitly for the sender policy you are proving.

Restart MCP clients after changing environment variables or replacing the
binary.

## Local Checks

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

For a live no-send smoke, run the binary through an MCP client or use the stdio
contract tests with an OCI profile configured. The live smoke must not use
`email-data-plane submit-email` or any OCI mutation command.

## Safety Notes

- Raw OCI JSON is not returned by tools.
- Recipient addresses are reduced to domain plus a short stable hash.
- Suppression reports include aggregate `totals` by reason and recipient
  domain, `total_matched`, count confidence, timestamp bounds, plus a
  canonical hard-bounce count, so stop-gate reviews do not need raw rows.
  High-cardinality recipient-domain totals are capped and report an omitted
  bucket count.
- OCIDs are reduced to kind plus a short stable hash.
- `EmailsRelayed` means recipient-domain acceptance only. It is not inbox
  placement proof.
- Missing metrics or log rows are reported as missing evidence, not as proof
  that bounce, complaint, open, or click counts are safe.
- Metric intervals accept OCI shorthand values `1m`, `5m`, `15m`, `30m`,
  `1h`, and `1d`; common ISO-8601 forms `PT1M`, `PT5M`, `PT15M`, `PT30M`,
  `PT1H`, and `P1D` are accepted case-insensitively and normalized to those
  canonical values before queries are built.
- `oci_email_logging_status` inventories visible service-log configuration
  without enabling logs. It returns counts, lifecycle state, and redacted
  identifiers only; when `resource_domain` or `resource_id` is supplied it
  reports both matching and active matching resource-log counts. A
  `resource_domain` request is resolved through the read-only OCI Email Domain
  list before log matching, so operators do not need to handle raw OCIDs for
  the common domain-scoped proof. If both `resource_domain` and `resource_id`
  are supplied, they must resolve to the same Email Domain. It blocks when
  active Email Delivery service logs are not visible, when the requested domain
  is not visible, when the supplied scope conflicts, or when the requested
  resource has no active matching log.
- `oci_email_logging_enablement_plan` turns that read-only status into an
  operator checklist for the required Email Domain service-log categories,
  permissions, approval boundary, and post-enable proof gates. It never
  authorizes or applies the OCI change. Target-scope problems such as an
  unresolved `resource_domain` or a domain/id mismatch block the plan without
  marking an OCI logging mutation as required.
- `oci_email_events` keeps the provider query scoped to Email Delivery event
  types plus exact action/message/header/recipient-domain filters, then applies
  `source_domain` after redacted event summaries are parsed. This avoids hiding
  valid events if OCI varies the top-level log `source` field; an empty result
  with `source_domain` is still missing event evidence, not proof of no sends.
  `provider_returned` and `source_domain_matched` distinguish no provider
  events from post-summary source-domain mismatch without returning raw events.
  When no `source_domain` is requested, `source_domain_matched` equals the
  returned event count.
- `oci_email_suppressions` fetches all pages for totals and timestamp bounds
  while returning only a bounded redacted sample in `suppressions`. Use
  `total_matched` and `count_state` for counts; use `returned` for sample rows.
  Use `totals.by_recipient_domain_omitted` to detect omitted domain buckets.
- `oci_email_suppression_delta` compares a full active suppression read with a
  bounded UTC window. It reports a clean decision only when both reads have
  complete count state and the window has no new active suppressions. New
  hard-bounce or complaint suppressions block; other new suppression reasons or
  no-sample/lower-bound reads degrade the receipt for operator review.
- Local send-ledger reads are disabled unless `OCI_MCP_LEDGER_PATH` is set.
  The ledger tool summarizes JSONL rows with hashes and domains only.
- Private monitoring snapshot artifacts are disabled unless
  `OCI_MCP_SNAPSHOT_ROOT` is set to an absolute existing private directory.
  On Unix, the directory must not grant group or other permissions. The
  snapshot tool writes generated direct-child JSON files only, returns a
  filename plus hashes rather than the private root path, and stores redacted
  watch, readiness, or traceability receipts. Redacted provider identifiers use
  non-provider-shaped markers such as `[redacted-ocid:<type>:<hash>]`, so any
  `ocid1.` string in a returned receipt or snapshot artifact is a leakage
  defect.
- `oci_email_watch_window` includes logging-status proof and blocks unscoped
  lane receipts when neither a metrics/logging resource domain/resource id nor
  an event source domain is available.
- `oci_email_send_readiness` also requires an expected local ledger row count
  and blocks when ledger rows are missing, capped, invalid, or lack trace or
  recipient reconciliation keys.
- `oci_email_traceability_audit` is the exact-trace boundary. It returns
  `aggregate_only=true` until a requested message/header trace returns OCI log
  events and one uncapped local ledger row overlaps both the requested trace
  key and the OCI event recipient hash. Aggregate metrics alone are never
  reported as per-recipient proof.

## Release And Operations

- Capability matrix: `docs/capability-matrix.md`
- Monitoring runbook: `docs/monitoring-runbook.md`
- Live proof matrix: `docs/live-proof-matrix.md`
- Hosted release checklist: `docs/hosted-release-checklist.md`
- Public release readiness: `docs/public-release-readiness.md`

Operational installs should use hosted release artifacts with checksum
verification. Restart MCP clients after replacing the binary or changing the
configured environment.
