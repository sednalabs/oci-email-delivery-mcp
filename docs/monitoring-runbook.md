# OCI Email Delivery Monitoring Runbook

This runbook is for no-send monitoring and send-window observation. The adapter
does not authorize sends. A send is eligible for expansion only when the
operator has separately approved the send path and this monitoring evidence is
green.

## Required Posture

- The MCP alias starts from a hosted release artifact whose checksum was
  verified.
- `oci_email_status` returns `send_authorized=false` and no blocker findings.
- `oci_email_metrics` sees the stop-gate metric definitions needed for the
  sender policy.
- `oci_email_logging_status` sees at least one ACTIVE Email Delivery service
  log in the selected compartment, and when an Email Domain/resource OCID is
  supplied it matches at least one visible service log.
- `oci_email_logging_enablement_plan` is the no-mutation fallback when logging
  status is blocked. It can prepare the operator checklist and post-enable
  gates, but it does not authorize or apply the OCI change.
- `oci_email_events` returns real Email Delivery log events for a seed/proof
  window before cohort expansion.
- `oci_email_suppressions` is callable and returns either a normal empty list
  or redacted suppression summaries with aggregate reason/domain totals.
- `oci_email_ledger_window` is configured with the private local send-ledger
  JSONL path before any seed/proof send. It returns only hashes, domains, and
  aggregate counts.
- `oci_email_send_readiness` is the preferred send-window receipt once a
  seed/cohort send has an expected ledger row count. It combines monitoring and
  local ledger proof and still returns `send_authorized=false`.
- `oci_email_traceability_audit` is the preferred exact-proof receipt when an
  operator needs to answer whether a specific message/header trace reached OCI
  logs and overlaps the configured local send ledger. It returns
  `aggregate_only=true` until exact message and recipient overlap is proven.
- `oci_email_monitoring_snapshot_artifact` writes redacted watch-window,
  send-readiness, or traceability-audit receipts to the configured private
  snapshot root for later replay. It returns a generated filename, root hash,
  bytes, and SHA-256, not the private root path.
- Every send lane is queried with the approved sender/source/resource domain
  for that lane. Do not mix separate publication or brand lanes in one
  unfiltered compartment-wide read.

## Stop Conditions

Pause the pilot or keep it paused when any of these are true:

- hard-bounce rate reaches the configured pause, throttle, or hard-stop
  threshold;
- complaint metric or complaint log evidence appears above the sender policy;
- soft-bounce, hard-bounce, suppression, or complaint metrics are missing and
  log evidence does not cover the gap;
- `oci_email_logging_status` returns no active Email Delivery service logs or
  cannot match the requested resource id for the sender lane;
- log search returns no events for a send window that should have accepted or
  relayed mail;
- suppression readback is blocked;
- local send-ledger readback is blocked, capped, or missing message/correlation
  keys for rows that should be traceable;
- `oci_email_send_readiness` returns `ledger_expected_rows_mismatch`,
  `expected_ledger_rows_zero`, `campaign_id_missing`, or `batch_id_missing`;
- provider warning, authentication failure, blocklist evidence, or
  reputation-style deferral appears;
- event ingestion fails or cannot be reconciled to the local send ledger;
- `oci_email_traceability_audit` returns `traceability_no_log_events`,
  `traceability_no_trace_events`, `traceability_no_ledger_rows`,
  `traceability_expected_ledger_rows_mismatch`,
  `traceability_no_ledger_trace_key_overlap`,
  `traceability_no_recipient_hash_overlap`,
  `traceability_no_single_ledger_row_overlap`, or `aggregate_only=true` for
  a send window that is expected to be traceable;
- any event or suppression response returns exactly the requested limit; narrow
  the window or filters and rerun before treating the result set as complete.

## Pre-Send Watch

Run these read-only tool calls for the planned UTC window or the immediately
preceding smoke window.

First prove that service-log configuration is visible. This is read-only and
does not enable logs:

```json
{
  "resource_id": null,
  "limit": 50
}
```

Expected: `send_authorized=false`; at least one active Email Delivery service
log is visible. When the operator has the Email Domain/resource OCID for the
lane, pass it as `resource_id` and require
`matching_requested_resource_log_count > 0`. A clean logging-status receipt
does not prove a particular send emitted events; it only proves the logging
configuration is visible enough for later event reads to be meaningful.

If logging status is blocked or degraded, call
`oci_email_logging_enablement_plan` with the same `resource_id` and `limit`.
Use its output as a planning receipt only. It should keep
`provider_mutation_authorized=false` and list the required categories,
permissions, approval boundary, and post-enable proof gates. After explicit
operator approval and external OCI apply, rerun `oci_email_logging_status`
before sending anything.

`oci_email_send_readiness` is the preferred first receipt once the planned
seed/cohort has a known expected local ledger row count. It composes the same
read-only monitoring checks as `oci_email_watch_window` and adds the configured
private send-ledger proof:

```json
{
  "start_time": "YYYY-MM-DDTHH:00:00Z",
  "end_time": "YYYY-MM-DDTHH:00:00Z",
  "interval": "1h",
  "resource_domain": "mail.example.com",
  "source_domain": "mail.example.com",
  "sender_domain": "mail.example.com",
  "campaign_id": "campaign-id-placeholder",
  "batch_id": "batch-id-placeholder",
  "expected_ledger_rows": 1,
  "message_id": null,
  "header_name": null,
  "header_value": null,
  "limit": 50
}
```

Expected: `send_authorized=false`; watch-window component status, metrics,
events, optional trace, suppressions, and ledger component are present.
`decision` is `remain_paused`, `hold_or_seed_only_with_operator_review`, or
`monitoring_and_ledger_ready_no_send_authorization`. The final state never
authorizes a send by itself. A missing or blank campaign/batch identifier,
zero expected rows, a row-count mismatch, missing ledger trace keys, missing
recipient keys, capped ledger rows, or invalid ledger rows keeps the lane
paused.

`oci_email_watch_window` remains useful before a specific send batch exists or
for diagnosis when ledger proof is not expected yet:

```json
{
  "start_time": "YYYY-MM-DDTHH:00:00Z",
  "end_time": "YYYY-MM-DDTHH:00:00Z",
  "interval": "1h",
  "resource_domain": "mail.example.com",
  "source_domain": "mail.example.com",
  "message_id": null,
  "header_name": null,
  "header_value": null,
  "limit": 50
}
```

Expected: `send_authorized=false`; a watch receipt without a metrics resource
domain/resource id or without an event source domain is `blocked` because a
compartment-wide receipt is not lane readiness proof.

Use `oci_email_traceability_audit` when the question is whether one exact
application, CRM, or SMTP test message can be tied to one local ledger row and
one OCI log trail. Campaign and batch filters are optional
narrowing inputs; exact proof is based on same-row trace-key and
recipient-hash overlap, not row counts alone:

```json
{
  "start_time": "YYYY-MM-DDTHH:00:00Z",
  "end_time": "YYYY-MM-DDTHH:00:00Z",
  "interval": "1h",
  "resource_domain": "mail.example.com",
  "source_domain": "mail.example.com",
  "sender_domain": "mail.example.com",
  "campaign_id": "campaign-id-placeholder",
  "batch_id": "batch-id-placeholder",
  "expected_ledger_rows": 1,
  "message_id": "provider-message-id",
  "header_name": null,
  "header_value": null,
  "limit": 50
}
```

Expected: `send_authorized=false`. `exact_message_traceable=true` only when a
message/header trace returned OCI log events, the configured local ledger has
matching rows for the window, the ledger is uncapped and valid, and one ledger
row overlaps both the requested trace key and OCI event recipient hash. The
summary field `single_ledger_row_overlap` is the same-row gate. Otherwise the
response is blocked or degraded with `aggregate_only=true`; aggregate accepted,
relayed, suppressed, or bounce totals are useful pressure signals, not
per-recipient proof.

Use `oci_email_monitoring_snapshot_artifact` whenever the receipt needs to be
replayable outside the MCP transcript. The tool writes only under
`OCI_MCP_SNAPSHOT_ROOT`, which must be an absolute existing private directory.
On Unix, create it with `chmod 700`; roots with group or other permissions are
rejected. It does not accept an arbitrary output path.

For a watch-window snapshot:

```json
{
  "start_time": "YYYY-MM-DDTHH:00:00Z",
  "end_time": "YYYY-MM-DDTHH:00:00Z",
  "interval": "1h",
  "resource_domain": "mail.example.com",
  "source_domain": "mail.example.com",
  "receipt_kind": "watch_window",
  "artifact_prefix": "seed-window",
  "limit": 50
}
```

For a send-readiness snapshot after the local send ledger has expected rows:

```json
{
  "start_time": "YYYY-MM-DDTHH:00:00Z",
  "end_time": "YYYY-MM-DDTHH:00:00Z",
  "interval": "1h",
  "resource_domain": "mail.example.com",
  "source_domain": "mail.example.com",
  "sender_domain": "mail.example.com",
  "campaign_id": "campaign-id-placeholder",
  "batch_id": "batch-id-placeholder",
  "expected_ledger_rows": 1,
  "receipt_kind": "send_readiness",
  "artifact_prefix": "seed-window",
  "limit": 50
}
```

For an exact traceability audit snapshot:

```json
{
  "start_time": "YYYY-MM-DDTHH:00:00Z",
  "end_time": "YYYY-MM-DDTHH:00:00Z",
  "interval": "1h",
  "resource_domain": "mail.example.com",
  "source_domain": "mail.example.com",
  "sender_domain": "mail.example.com",
  "campaign_id": "campaign-id-placeholder",
  "batch_id": "batch-id-placeholder",
  "expected_ledger_rows": 1,
  "message_id": "provider-message-id",
  "receipt_kind": "traceability_audit",
  "artifact_prefix": "seed-window",
  "limit": 50
}
```

Expected: the returned `artifact.filename`, `artifact.sha256`, and
`artifact.bytes` identify the private JSON receipt. Public notes may cite the
receipt status, decision, checksum, and root hash, but not the private root path
or raw campaign, batch, recipient, message, or provider payload values.

`oci_email_ledger_window` for the private local send ledger:

```json
{
  "start_time": "YYYY-MM-DDTHH:00:00Z",
  "end_time": "YYYY-MM-DDTHH:00:00Z",
  "sender_domain": "mail.example.com",
  "campaign_id": null,
  "batch_id": null,
  "limit": 100
}
```

Expected: the tool is configured through `OCI_MCP_LEDGER_PATH`, matching rows
have message or correlation hashes, recipient address or recipient-id hashes,
and no raw recipient, message id, subject, campaign id, batch id, or private
path is returned. `ledger_no_rows_matched`, `ledger_results_capped`,
`ledger_missing_trace_keys`, or `ledger_missing_recipient_keys` keeps the lane
paused for proof sends that should have ledger rows.

`oci_email_status`:

```json
{
  "compartment_id": null
}
```

Expected: profile and read-only OCI APIs work, active sender/domain reads are
visible, suppression query is `ok`, and `send_authorized` is `false`.

`oci_email_suppressions`:

```json
{
  "limit": 20
}
```

Expected: `status` is `ok` or explicitly `degraded` with a documented reason;
no raw recipient address is returned. Use `totals.hard_bounce`,
`totals.by_reason`, and `totals.by_recipient_domain` for stop-gate and
clean-audience reconciliation before inspecting redacted sample rows.

`oci_email_metrics` for the approved sender/resource domain:

```json
{
  "start_time": "YYYY-MM-DDTHH:00:00Z",
  "end_time": "YYYY-MM-DDTHH:00:00Z",
  "interval": "1h",
  "resource_domain": "mail.example.com"
}
```

Expected: accepted, relayed, hard-bounced, soft-bounced, suppressed,
complaint, and blocklist evidence is either visible as metrics or explicitly
covered by log proof. Missing stop-gate metrics are not treated as zero.

## During-Send Watch

Use short UTC windows, usually 5 to 15 minutes, and keep each observation
bounded. Compare every window against the previous one.

Start each observation with `oci_email_send_readiness` using the same
lane/domain and expected ledger-row filters once the send path has created
ledger rows. When an exact message/header trace is available, follow with
`oci_email_traceability_audit` for the same UTC window. If either receipt is
`blocked`, keep the lane paused. If either is `degraded`, continue only as
seed-only or hold for operator review, depending on the approved sender
policy.

For a real seed/cohort send, run `oci_email_ledger_window` for the same UTC
window and lane when diagnosing a failed readiness receipt. OCI events without
a local ledger row, or local ledger rows without a provider event after the
expected delay, are reconciliation gaps.

`oci_email_metrics`:

```json
{
  "start_time": "YYYY-MM-DDTHH:MM:00Z",
  "end_time": "YYYY-MM-DDTHH:MM:00Z",
  "interval": "1m",
  "resource_domain": "example.com"
}
```

Intervals should normally use OCI shorthand: `1m`, `5m`, `15m`, `30m`, `1h`,
or `1d`. The MCP also accepts common ISO-8601 inputs `PT1M`, `PT5M`,
`PT15M`, `PT30M`, `PT1H`, and `P1D` case-insensitively and normalizes them
before building OCI Monitoring queries.

Check:

- accepted total moved when a send occurred;
- relayed total is plausible but not treated as inbox placement;
- hard-bounce, soft-bounce, suppression, and complaint findings are clear;
- blocklist findings are clear;
- `status` is not `blocked`.

`oci_email_events` for the approved sender/source domain:

```json
{
  "start_time": "YYYY-MM-DDTHH:MM:00Z",
  "end_time": "YYYY-MM-DDTHH:MM:00Z",
  "action": null,
  "source_domain": "mail.example.com",
  "limit": 50
}
```

Check:

- expected accepted/relayed/bounce/suppression event types appear;
- recipient values are domains and hashes only;
- raw provider payload is not returned;
- zero rows in an active send window pauses expansion until logging is proven.
- `returned == limit` or `rows_capped=true` means the evidence is incomplete
  until the window is narrowed or filtered and rerun.

For separate publication lanes, run separate queries. Each publication or brand
window must have its own source/resource-domain filter and private receipt.

## Trace A Seed Or Probe Message

Prefer a provider message id if available. If using a custom header, use a
non-PII value generated for the seed/proof send.

```json
{
  "start_time": "YYYY-MM-DDTHH:MM:00Z",
  "end_time": "YYYY-MM-DDTHH:MM:00Z",
  "message_id": "provider-message-id",
  "header_name": null,
  "header_value": null,
  "source_domain": "mail.example.com",
  "limit": 20
}
```

Expected: trace criteria are hashed in the response and events connect the
local send ledger row to OCI accepted, relayed, bounced, complained, or
suppressed evidence.

## Post-Window Receipt

Record a private receipt containing:

- UTC window;
- campaign/batch identifier or private evidence pointer;
- tool versions or artifact checksum;
- status, metrics, events, trace, and suppression summaries;
- stop-threshold evaluation;
- unresolved proof gaps;
- explicit decision: remain paused, continue seed-only, expand cohort, or stop.
- suppression baseline and post-window delta, reconciled back to the local send
  ledger without exposing raw recipients in public docs or tickets.

Prefer `oci_email_monitoring_snapshot_artifact` for that private receipt so the
same redacted JSON can be hashed, retained, and re-opened later without
scraping a chat transcript.

For a first seed or cohort window, use a tight cadence:

- take a status, metrics, events, trace, and suppression snapshot immediately
  before send;
- monitor 1 to 5 minute windows for the first 30 minutes after send start;
- check again at 60 minutes, 4 hours, and 24 hours for delayed bounces,
  complaints, suppressions, and deferrals;
- keep the lane paused if any stop condition or unproven event-ingestion gap
  remains.

Public docs and tickets should only carry aggregate posture and decision state,
not raw recipients, message ids, provider payloads, private paths, or detailed
campaign identifiers.
