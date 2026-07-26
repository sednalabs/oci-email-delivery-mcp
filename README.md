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
| `oci_email_traceability_audit` | Produce a v2 no-send traceability audit that distinguishes complete, partial, unavailable, and not-requested evidence from observed provider evidence. |
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
  valid events if OCI varies the top-level log `source` field; a successful
  JSON empty result with `source_domain` is still missing event evidence, not
  proof of no sends. Blank or JSON-null Logging Search output is unavailable
  evidence and blocks the component rather than being reshaped as an empty
  result. Every returned row must contain a recognized OutboundAccepted or
  OutboundRelayed record with an object payload, non-empty action, and valid
  UTC timestamp inside the requested half-open window; an unrecognized or
  out-of-window row makes the event read unavailable instead of contributing
  synthetic evidence. Forward-compatible unknown actions are summarized as
  `unknown` rather than copied from the provider payload, and make the event
  evidence partial so they cannot authorize exact traceability.
  `provider_returned` and `source_domain_matched` distinguish no provider
  events from post-summary source-domain mismatch without returning raw events.
  When no `source_domain` is requested, `source_domain_matched` equals the
  returned event count. SMTP diagnostic blobs are summarized and capped so
  receipts keep bounce context without returning verbose provider diagnostics.
  The `counts` object summarizes returned events by action and reports
  distinct versus duplicate redacted recipient, message, recipient/message, and
  action/recipient/message keys. Use those counts to avoid treating repeated
  log records for the same recipient/message as distinct recipient outcomes.
- `oci_email_suppressions` fetches all pages for totals and timestamp bounds
  with a provider-friendly page size while returning only a bounded redacted
  sample in `suppressions`. Use `total_matched` and `count_state` for counts;
  use `returned` for sample rows. Use
  `totals.by_recipient_domain_omitted` to detect omitted domain buckets. If OCI
  rate-limits the read, treat the receipt as blocked evidence and retry later
  instead of treating the suppression state as clean.
- `oci_email_suppression_delta` compares a full active suppression read with a
  bounded UTC window. It reports a clean decision only when both reads have
  complete count state and the window has no new active suppressions. New
  hard-bounce or complaint suppressions block; other new suppression reasons or
  no-sample/lower-bound reads degrade the receipt for operator review.
- Local send-ledger reads are disabled unless `OCI_MCP_LEDGER_PATH` is set.
  The ledger tool summarizes JSONL rows with hashes and domains only. It can
  narrow a large window by message id or approved non-PII correlation value
  before applying the returned-row cap, so exact traceability audits do not
  have to expose or scan a whole campaign in the transcript. Raw message and
  correlation values use the case-preserving opaque trace-key hash contract.
  Prehashed trace fields must contain a valid 20-hex digest from that same
  contract. When raw and prehashed forms coexist they must agree; malformed or
  contradictory pairs fail closed as missing trace evidence. Recipient address
  and recipient-id raw/prehashed pairs follow the same custody rule. A
  contradictory pair invalidates all recipient proof from that ledger row, and
  a present address hash is authoritative over an alternate recipient-id hash
  for provider-event overlap.
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
- `oci_email_traceability_audit` is the exact-trace boundary. Its v2 output has
  `schema="oci-email-delivery.traceability-audit.v2"`; consumers must branch
  on that schema and the evidence-state fields, rather than treat summary
  scalars as complete proof. `log_evidence_state` and `ledger_evidence_state`
  are `complete`, `partial`, or `unavailable`; `trace_evidence_state` also
  permits `not_requested`. `log_events_returned` is populated only after the
  general-event read and, when requested, the trace read both complete; a
  successful complete empty read is `0`, while partial or unavailable combined
  log evidence is `null`. A successful uncapped empty provider response remains
  complete even though its nested report carries the expected no-events
  warning; blank, malformed, capped, or missing responses do not. Trace scalars
  are `null` when trace evidence is `not_requested`, unavailable, or
  incomplete. Ledger scalars are `null` when the ledger is unavailable and
  otherwise preserve the observed `0`, `false`, or `true` value. In v1 the
  event, ledger-count, cap, and overlap scalars were non-null and did not carry
  explicit completeness state. V2 consumers must branch on the schema and state
  fields before interpreting nullable values.
  `provider_evidence_available=true` only means a provider metric datapoint or
  log event was observed; it is not a completeness, acceptance, relay, or exact
  traceability claim. `aggregate_only=true` means observed provider evidence
  lacks an exact message-to-recipient overlap, and
  `exact_message_traceable=true` additionally requires complete requested log
  evidence, equality with a supplied positive `expected_ledger_rows`, and one
  uncapped local ledger row overlapping both the trace identity and recipient
  hash on the same returned event. A message-id trace uses the returned event's
  message-id hash. A correlation-header trace uses only the requested header
  name's returned value hash; the request criterion by itself is not event
  identity. These opaque trace-key hashes preserve case and exact bytes; they
  deliberately do not use the case-folded address/domain hash contract.
  Omitting the optional expected count skips only that count
  comparison. Because this flag is scoped to one message trace, it may be true
  while the overall receipt remains blocked by an orthogonal profile, metric,
  logging-status, or suppression finding; neither state authorizes a send. The
  audit passes the requested trace key
  into the local ledger read before the row cap, which keeps high-volume windows
  measurable without weakening exact-proof requirements.

## Release And Operations

- Capability matrix: `docs/capability-matrix.md`
- Monitoring runbook: `docs/monitoring-runbook.md`
- Live proof matrix: `docs/live-proof-matrix.md`
- Hosted release checklist: `docs/hosted-release-checklist.md`
- Public release readiness: `docs/public-release-readiness.md`

Operational installs should use hosted release artifacts with checksum
verification. Restart MCP clients after replacing the binary or changing the
configured environment.
