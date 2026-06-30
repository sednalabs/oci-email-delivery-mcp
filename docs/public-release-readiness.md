# Public Release Readiness

Status: draft, not yet published.

## Classification

Release Track candidate. The adapter is a generic read-only OCI Email Delivery
MCP and does not need operator-specific state to build, test, or explain its
core value.

## Current Public-Safety Posture

- No send, mutation, import, queue, cron, DNS, log-enable, or Connector Hub
  apply tool exists.
- Provider credentials are not stored in the repository; runtime auth is via
  the operator's OCI CLI profile.
- Examples use placeholder values.
- Tool output redacts email-shaped values, OCIDs, IP addresses, and private
  local paths before it returns through MCP.
- Operator-specific live telemetry is kept out of the repository; public docs
  describe proof categories and blocker state only.
- GitHub Actions workflows use read-only permissions, SHA-pinned action
  references, and explicit `ubuntu-24.04` hosted runners.
- GitHub hosted quality coverage includes Rust baseline, CodeQL Advanced for
  Rust and Actions, a repository custom Actions CodeQL policy pack plus compile
  gate, GitHub Code Quality coverage upload, DevSkim SARIF upload, OSV
  scanning, and Dependabot update configuration.
- A workflow-dispatch release artifact lane exists for a Linux x86_64 binary
  tarball plus SHA-256 sidecar. Operational installs must use that hosted
  artifact after checksum verification, not a local EC2 build.

## Publication Blockers

- License choice needs explicit owner approval before public push. The current
  Cargo metadata follows the toolkit template's Apache-2.0 convention, but no
  public repository should be launched until that is confirmed.
- Target public repository name and owner are not yet selected.
- The `mcp-toolkit-rs` dependency is pinned to landed upstream `main` commit
  `211c5687645b08e1beb81ad78891dd3214746fea`.
- Final hosted validation must run on the commit that will be published.
- GitHub security settings must be verified after the repository exists.
- Before production monitoring use, the current hard-bounce blocker and
  degraded log-event proof must be resolved or explicitly accepted by the
  operator. This is an operational-readiness blocker, not a public-release
  source-code blocker.

## Useful Hosted Gates

- `rust-baseline`: `cargo fmt --all --check`, `cargo clippy --all-targets
  --all-features -- -D warnings`, and `cargo test --all-targets
  --all-features`.
- `CodeQL Advanced`: Rust plus Actions analysis with the repository custom
  Actions workflow security query pack.
- `codeql-query-tests`: compiles the custom Actions query pack so branch
  protection can require query-pack health independently of analysis.
- `code-coverage`: uploads Cobertura coverage to GitHub Code Quality and keeps
  the XML report as a hosted artifact.
- `DevSkim` and `OSV-Scanner`: upload SARIF/dependency vulnerability evidence
  to GitHub code scanning.
- `release-artifact`: `cargo build --release --locked`, packaged Linux x86_64
  binary, and SHA-256 sidecar artifact.
