# OCI Email Delivery MCP

Read-only stdio MCP server for OCI Email Delivery monitoring. The first
operator goal is to let agents query OCI programmatically before production
or cohort sends go live.

The server exposes six curated intent tools:

| Tool | Purpose |
| --- | --- |
| `oci_email_status` | Check CLI/profile readiness, approved senders, email domains, and suppression-query visibility. |
| `oci_email_metrics` | Query fixed `oci_emaildelivery` Monitoring metrics for an explicit UTC window. |
| `oci_email_events` | Search Email Delivery logs with whitelisted filters and redacted event summaries. |
| `oci_email_trace_message` | Trace one message id or correlation header through Email Delivery logs, optionally scoped by source domain. |
| `oci_email_suppressions` | Summarize OCI suppressions without returning raw recipient addresses. |
| `oci_email_watch_window` | Build one read-only monitoring receipt from status, metrics, logs, optional trace, and suppressions. |

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
- OCIDs are reduced to kind plus a short stable hash.
- `EmailsRelayed` means recipient-domain acceptance only. It is not inbox
  placement proof.
- Missing metrics or log rows are reported as missing evidence, not as proof
  that bounce, complaint, open, or click counts are safe.
- `oci_email_watch_window` blocks unscoped lane receipts when neither a metrics
  resource domain/resource id nor an event source domain is available.

## Release And Operations

- Capability matrix: `docs/capability-matrix.md`
- Monitoring runbook: `docs/monitoring-runbook.md`
- Live proof matrix: `docs/live-proof-matrix.md`
- Hosted release checklist: `docs/hosted-release-checklist.md`
- Public release readiness: `docs/public-release-readiness.md`

Operational installs should use hosted release artifacts with checksum
verification. Restart MCP clients after replacing the binary or changing the
configured environment.
