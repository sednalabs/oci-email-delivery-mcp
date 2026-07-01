# Public Release Readiness

Status: public repository published at `sednalabs/oci-email-delivery-mcp`;
hosted validation and Code Quality enablement are the current gates.

## Classification

Release Track candidate. The adapter is a generic OCI Email Delivery MCP with
a read-only OCI/provider surface plus a configured local private snapshot
artifact surface. It does not need operator-specific state to build, test, or
explain its core value.

## Current Public-Safety Posture

- No send, mutation, import, queue, cron, DNS, log-enable, or Connector Hub
  apply tool exists.
- Provider credentials are not stored in the repository; runtime auth is via
  the operator's OCI CLI profile.
- Examples use placeholder values.
- Tool output redacts email-shaped values, OCIDs, IP addresses, and private
  local paths before it returns through MCP.
- Local send-ledger support is default-deny unless `OCI_MCP_LEDGER_PATH` is
  configured at runtime. The repository contains no ledger data, and the tool
  returns hashes/domains/counts rather than raw recipients or campaign text.
- Local monitoring snapshot artifacts are default-deny unless
  `OCI_MCP_SNAPSHOT_ROOT` is configured at runtime. The tool writes only
  generated direct-child files under that private root and returns filename,
  root hash, byte count, and SHA-256 rather than the private path.
- Operator-specific live telemetry is kept out of the repository; public docs
  describe proof categories and blocker state only.
- GitHub Actions workflows use read-only top-level permissions, narrow
  job-scoped upload permissions where reporting requires them, SHA-pinned
  action references, and explicit `ubuntu-24.04` hosted runners.
- GitHub hosted quality coverage includes Rust baseline, CodeQL Advanced for
  Rust and Actions, a repository custom Actions CodeQL policy pack plus compile
  gate, GitHub Code Quality coverage upload, DevSkim SARIF upload, OSV
  scanning, and Dependabot update configuration. The coverage upload is
  intentionally fail-closed until GitHub Code Quality is enabled for the
  repository or organization.
- A workflow-dispatch release artifact lane exists for a Linux x86_64 binary
  tarball plus SHA-256 sidecar. Operational installs must use that hosted
  artifact after checksum verification, not a local EC2 build.
- The adapter includes composed `oci_email_watch_window` and
  `oci_email_send_readiness` receipts so operators can inspect one UTC window
  and, when a seed/cohort has expected ledger rows, tie monitoring evidence to
  local ledger proof. Both remain read-only and always return
  `send_authorized=false`.
- The adapter includes `oci_email_logging_status` so operators can distinguish
  active Email Delivery service-log configuration visibility from a bounded
  event search that simply returned no events. It is read-only and does not
  enable, update, or delete logs.
- The adapter includes `oci_email_traceability_audit` so operators can ask the
  narrower question: does this window prove exact message and recipient
  overlap across OCI logs and the same configured local ledger row, or only
  aggregate delivery pressure? The audit is read-only, redacted, and returns
  `aggregate_only=true` whenever exact overlap is missing.
- The adapter includes `oci_email_monitoring_snapshot_artifact` so those
  redacted watch, readiness, or traceability receipts can be persisted
  privately for later replay without scraping MCP transcripts or exposing raw
  recipient/provider data.

## Publication Gates

- License file and Cargo metadata are Apache-2.0. This release does not change
  license terms.
- Public target: `sednalabs/oci-email-delivery-mcp`.
- The `mcp-toolkit-rs` dependency is pinned to landed upstream `main` commit
  `211c5687645b08e1beb81ad78891dd3214746fea`.
- Final hosted validation must run on the commit that is published.
- GitHub security settings must be verified on the published repository.
- GitHub Code Quality must be enabled in repository or organization settings
  before the `code-coverage` workflow can upload Cobertura coverage
  successfully.
- Before production monitoring use, the current hard-bounce blocker and
  degraded log-event proof must be resolved, `oci_email_logging_status` must
  prove active service-log visibility for the sender lane, host-local ledger
  and snapshot paths must be configured, `oci_email_send_readiness` must match
  the expected ledger row count for the seed/cohort window, and
  `oci_email_traceability_audit` must move from aggregate-only to exact
  traceability for the relevant seed/proof message. Operator acceptance of the
  current gap can only mean remaining paused or seed-only. This is an
  operational-readiness blocker, not a public-release source-code blocker.

## Useful Hosted Gates

- `rust-baseline`: `cargo fmt --all --check`, `cargo clippy --all-targets
  --all-features -- -D warnings`, and `cargo test --all-targets
  --all-features`.
- `CodeQL Advanced`: Rust plus Actions analysis with the repository custom
  Actions workflow security query pack.
- `codeql-query-tests`: compiles the custom Actions query pack so branch
  protection can require query-pack health independently of analysis.
- `code-coverage`: uploads Cobertura coverage to GitHub Code Quality and keeps
  the XML report as a hosted artifact. A failure with "Code quality is not
  enabled for this repository" means the repository setting is still blocking
  the otherwise generated coverage report.
- `DevSkim` and `OSV-Scanner`: upload SARIF/dependency vulnerability evidence
  to GitHub code scanning.
- `release-artifact`: `cargo build --release --locked`, packaged Linux x86_64
  binary, and SHA-256 sidecar artifact.
