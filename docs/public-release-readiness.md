# Public Release Readiness

Status: public repository published at `sednalabs/oci-email-delivery-mcp`;
the current PR-head candidate requires its own hosted validation receipts.
GitHub Code Quality remains an optional reporting sink rather than a source,
merge, release, install, or live-proof gate.

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
  gate, mandatory Cobertura generation and hosted artifact retention, optional
  GitHub Code Quality reporting, DevSkim SARIF upload, OSV scanning, and
  Dependabot update configuration. The optional reporting job is isolated
  behind `CODE_QUALITY_UPLOAD_ENABLED=true`; the required coverage job does not
  depend on that external feature and retains no Code Quality write permission.
- A release artifact lane produces a Linux x86_64 binary tarball, archive
  SHA-256 sidecar, and target-specific CycloneDX 1.5 Cargo dependency SBOM.
  The workflow fails closed unless the SBOM contains components and a
  connected root dependency graph. Manual dispatches from `main` also produce
  provenance and SBOM attestations for the tarball; tag builds intentionally
  remain unattested. Operational installs must use the hosted artifact after
  checksum and applicable attestation verification, not a local EC2 build.
- The adapter includes composed `oci_email_watch_window` and
  `oci_email_send_readiness` receipts so operators can inspect one UTC window
  with resource-scoped logging-status proof and, when a seed/cohort has
  expected ledger rows, tie monitoring evidence to local ledger proof. Both
  remain read-only and always return
  `send_authorized=false`.
- The adapter includes `oci_email_logging_status` so operators can distinguish
  active Email Delivery service-log configuration visibility from a bounded
  event search that simply returned no events. It accepts either a generic
  Email Domain `resource_domain` or a private resource id for resource-scoped
  proof. It is read-only and does not enable, update, or delete logs.
- The adapter includes `oci_email_logging_enablement_plan` so a blocked or
  degraded logging-status receipt turns into a generic, redacted operator plan
  for service-log categories, approval boundaries, and post-enable proof
  without authorizing the OCI mutation.
- The adapter includes `oci_email_suppression_delta` so operators can compare
  full active suppressions with a bounded UTC window and distinguish clean,
  lower-bound, no-sample, and stop-gate suppression evidence without exposing
  raw recipients.
- The adapter includes v2 `oci_email_traceability_audit` so operators can ask the
  narrower question: does this window prove exact message and recipient
  overlap across provider logs and the same configured local ledger row, only
  aggregate provider evidence, or no provider evidence? The audit is read-only
  and redacted. It returns `aggregate_only=true` only when provider metric
  datapoints or log events exist without exact overlap. Its schema discriminator
  and evidence-state fields distinguish complete, partial, unavailable, and
  not-requested reads; observed provider evidence is never acceptance, relay,
  or exact proof. Exact proof additionally requires the selected local ledger
  row to carry unambiguous OCI Email Delivery provider authority; missing,
  non-OCI, malformed, or contradictory provider identity remains fail-closed.
- `oci_email_send_readiness` applies the same service-specific provider
  authority to every matched ledger row, so a missing, non-OCI, or mixed
  provider cohort cannot be described as OCI-ready even when counts match.
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
- The `code-coverage` workflow must generate and retain its Cobertura artifact
  on every candidate. If GitHub Code Quality is intentionally enabled, set
  `CODE_QUALITY_UPLOAD_ENABLED=true` and require the separate optional upload
  job to succeed; leaving the variable unset or false must not bypass
  generation or artifact retention.
- Before production monitoring use, the current hard-bounce blocker and
  degraded log-event proof must be resolved, `oci_email_logging_status` must
  prove active service-log visibility for the sender lane using a
  `resource_domain` or private resource id, host-local ledger and snapshot
  paths must be configured, `oci_email_send_readiness` must match the expected
  ledger row count for the seed/cohort window, and
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
- `code-coverage`: always generates Cobertura coverage and keeps the XML report
  as a hosted artifact. A separate job uploads that artifact to GitHub Code
  Quality only when `CODE_QUALITY_UPLOAD_ENABLED=true`; the required coverage
  job remains authoritative when the optional feature is unavailable.
- `DevSkim` and `OSV-Scanner`: upload SARIF/dependency vulnerability evidence
  to GitHub code scanning.
- `release-artifact`: `cargo build --release --locked`, packaged Linux x86_64
  binary, archive SHA-256 sidecar, and target-specific CycloneDX 1.5 Cargo
  dependency SBOM with a non-empty graph gate. A separate job attests
  provenance and the SBOM only for manual dispatches from `main`.
