# OCI Email Delivery MCP

Stdio MCP server for OCI Email Delivery monitoring. The OCI/provider surface is
read-only; the only local write surface is a configured private artifact tool
for redacted monitoring snapshots. The first operator goal is to let agents
query OCI programmatically before production or cohort sends go live.

The server exposes ten curated intent tools:

| Tool | Purpose |
| --- | --- |
| `oci_email_status` | Check CLI/profile readiness, approved senders, email domains, and suppression-query visibility. |
| `oci_email_metrics` | Query fixed `oci_emaildelivery` Monitoring metrics for an explicit UTC window. |
| `oci_email_ledger_window` | Summarize configured local send-ledger rows for a UTC window without raw recipients. |
| `oci_email_events` | Search Email Delivery logs with whitelisted filters and redacted event summaries. |
| `oci_email_trace_message` | Trace one message id or correlation header through Email Delivery logs, optionally scoped by source domain. |
| `oci_email_suppressions` | Summarize OCI suppressions with reason/domain totals and no raw recipient addresses. |
| `oci_email_watch_window` | Build one read-only monitoring receipt from status, metrics, logs, optional trace, and suppressions. |
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
  domain, plus a canonical hard-bounce count, so stop-gate reviews do not need
  raw rows.
- OCIDs are reduced to kind plus a short stable hash.
- `EmailsRelayed` means recipient-domain acceptance only. It is not inbox
  placement proof.
- Missing metrics or log rows are reported as missing evidence, not as proof
  that bounce, complaint, open, or click counts are safe.
- Local send-ledger reads are disabled unless `OCI_MCP_LEDGER_PATH` is set.
  The ledger tool summarizes JSONL rows with hashes and domains only.
- Private monitoring snapshot artifacts are disabled unless
  `OCI_MCP_SNAPSHOT_ROOT` is set to an absolute existing private directory.
  On Unix, the directory must not grant group or other permissions. The
  snapshot tool writes generated direct-child JSON files only, returns a
  filename plus hashes rather than the private root path, and stores redacted
  watch, readiness, or traceability receipts.
- `oci_email_watch_window` blocks unscoped lane receipts when neither a metrics
  resource domain/resource id nor an event source domain is available.
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
