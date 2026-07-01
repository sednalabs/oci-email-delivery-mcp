# No-Send Live Proof - 2026-06-30

Scope: read-only MCP proof for OCI Email Delivery monitoring readiness. No
email send, DNS change, suppression mutation, log-enable action, Connector Hub
apply, contact import, or campaign action was run.

## Local Validation

Command:

```bash
MCP_TOOLKIT_UPDATE_TOOL_SNAPSHOTS=1 cargo test --test tool_schema_snapshot
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
public_release_scan.py . --include-untracked
```

Result: passed locally on 2026-06-30 after changing metric aggregation from
`count()` to `sum()` so message totals are not confused with datapoint counts.
The public release scan returned `HIGH=0 MEDIUM=0 LOW=0`.

Covered before the private snapshot artifact tool was added:

- schema snapshot contract for the direct monitoring/readiness tools present at
  the time;
- stdio `tools/list` smoke;
- fixture-backed domain output contracts;
- redaction contracts for recipient, message-id, OCID, IP address,
  private-path, and raw-payload output;
- invalid log-query filter coverage.

## MCP Stdio Proof

Transport: stdio.

Catalog proof:

- required direct read tools matched: `oci_email_status`, `oci_email_metrics`,
  `oci_email_ledger_window`, `oci_email_events`, `oci_email_trace_message`,
  `oci_email_suppressions`, `oci_email_watch_window`;
- expected tool count matched: 7;
- schema compatibility passed;

Tool-call proof:

- `oci_email_status`: callable through the MCP `tools/call` boundary; returned
  no-send `send_authorized=false`. Approved sender, Email Domain, and
  suppression query reads succeeded without a send-capable command.
- `oci_email_metrics`: callable for a bounded UTC window. OCI exposed accepted,
  relayed, hard-bounced, and suppressed metric definitions. The hard-bounce
  stop gate is currently blocking pilot readiness; soft-bounce, complaint, and
  blocklist definitions were not visible, so they return warnings rather than
  false zeroes.
- `oci_email_ledger_window`: callable with a synthetic private JSONL ledger
  configured through `OCI_MCP_LEDGER_PATH`. It returned one matched row, no
  capped rows, `raw_payload_returned=false`, and no raw recipient, message id,
  campaign id, or batch id in the MCP output.
- `oci_email_events`: callable against OCI Logging Search for the same UTC
  window. The query returned zero events and status `degraded`, explicitly not
  proof that logging is enabled.
- `oci_email_suppressions`: callable. It returned a normal redacted suppression
  sample with no raw recipient output.
- `oci_email_trace_message`: callable with a synthetic correlation header. It
  returned a hashed criterion and zero events, with no raw header value in
  output.
- `oci_email_watch_window`: callable for the same bounded UTC window. It
  returned `blocked` with `decision=remain_paused`, `send_authorized=false`,
  status read `ready`, metrics `blocked`, events `degraded`, suppressions
  `ok`, no capped rows, and no raw provider payload.
- Transcript scan across those tool calls found no raw email-shaped values.

Operator-specific counts and live readback details are retained outside this
public-release candidate repository.

Addendum: the later `oci_email_send_readiness` tool extends this proof set by
combining the watch-window receipt with configured local send-ledger proof and
expected row-count gates. Its fixture/schema proof is current, but live
send-window proof remains pending until a real seed/cohort window has expected
ledger rows and OCI log traceability.

Second addendum: the later `oci_email_monitoring_snapshot_artifact` tool
persists redacted watch/readiness/traceability receipts under
`OCI_MCP_SNAPSHOT_ROOT` and returns filename/checksum/root-hash evidence
without returning the private root path. Its fixture/schema proof is current,
but live installed artifact proof remains pending until the hosted binary is
released and the production host configures a private snapshot root.

Third addendum: the later `oci_email_traceability_audit` tool makes the
aggregate-versus-exact boundary explicit. It returns `exact_message_traceable`
only when a requested message/header trace has OCI log events and those events
overlap the same uncapped local ledger row by trace key and recipient hash.
Otherwise it returns `aggregate_only=true` with blocker findings such as no log
events, no trace events, no ledger rows, no trace-key overlap, no
recipient-hash overlap, or split-row overlap.
Fixture/schema proof is current; live exact traceability remains pending until
a real seed/proof window has matching OCI log events and configured local
ledger rows.

## Evidence Gaps Before Production Monitoring Readiness

- The hard-bounce stop gate must be understood and cleared before pilot
  expansion. Operator acceptance of the current gap can only mean remaining
  paused or seed-only.
- Soft-bounce, complaint, and blocklist metrics must become visible or be
  proven through logs before pilot expansion.
- Email Delivery logs must show real OutboundAccepted/OutboundRelayed events
  for a seed/proof send before the trace path is considered operational.
- The production host must configure the real private send-ledger JSONL path
  before ledger/event reconciliation can be treated as operational.
- `oci_email_traceability_audit` must return exact traceability, not
  aggregate-only pressure, for the relevant seed/proof message before the MCP
  is treated as a full monitor.
- The production host must configure the real private snapshot root before
  monitoring receipts can be treated as durable operational evidence.
- Hosted validation and reviewer signoff are still pending.
