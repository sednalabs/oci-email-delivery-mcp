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
- `oci_email_events` returns real Email Delivery log events for a seed/proof
  window before cohort expansion.
- `oci_email_suppressions` is callable and returns either a normal empty list
  or redacted suppression summaries.
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
- log search returns no events for a send window that should have accepted or
  relayed mail;
- suppression readback is blocked;
- provider warning, authentication failure, blocklist evidence, or
  reputation-style deferral appears;
- event ingestion fails or cannot be reconciled to the local send ledger.
- any event or suppression response returns exactly the requested limit; narrow
  the window or filters and rerun before treating the result set as complete.

## Pre-Send Watch

Run these read-only tool calls for the planned UTC window or the immediately
preceding smoke window.

`oci_email_watch_window` is the preferred first receipt because it composes the
same read-only checks into one stop/go view:

```json
{
  "start_time": "YYYY-MM-DDTHH:00:00Z",
  "end_time": "YYYY-MM-DDTHH:00:00Z",
  "interval": "1h",
  "resource_domain": "update.example.com",
  "source_domain": "update.example.com",
  "message_id": null,
  "header_name": null,
  "header_value": null,
  "limit": 50
}
```

Expected: `send_authorized=false`; component status, metrics, events, optional
trace, and suppressions are present; `decision` is `remain_paused`,
`hold_or_seed_only_with_operator_review`, or
`monitoring_window_clean_no_send_authorization`. The final state never
authorizes a send by itself. A watch receipt without a metrics resource
domain/resource id or without an event source domain is `blocked` because a
compartment-wide receipt is not lane readiness proof.

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
no raw recipient address is returned.

`oci_email_metrics` for the approved sender/resource domain:

```json
{
  "start_time": "YYYY-MM-DDTHH:00:00Z",
  "end_time": "YYYY-MM-DDTHH:00:00Z",
  "interval": "1h",
  "resource_domain": "update.example.com"
}
```

Expected: accepted, relayed, hard-bounced, soft-bounced, suppressed,
complaint, and blocklist evidence is either visible as metrics or explicitly
covered by log proof. Missing stop-gate metrics are not treated as zero.

## During-Send Watch

Use short UTC windows, usually 5 to 15 minutes, and keep each observation
bounded. Compare every window against the previous one.

Start each observation with `oci_email_watch_window` using the same lane/domain
filters. If the receipt is `blocked`, keep the lane paused. If it is
`degraded`, continue only as seed-only or hold for operator review, depending
on the approved sender policy.

`oci_email_metrics`:

```json
{
  "start_time": "YYYY-MM-DDTHH:MM:00Z",
  "end_time": "YYYY-MM-DDTHH:MM:00Z",
  "interval": "1m",
  "resource_domain": "example.com"
}
```

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
  "source_domain": "update.example.com",
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
  "source_domain": "update.example.com",
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
