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
- Tool output redacts email-shaped values, OCIDs, and IP addresses before it
  returns through MCP.
- GitHub Actions workflow uses read-only permissions and SHA-pinned action
  references. The hosted runner image is still the standard `ubuntu-latest`
  label and should be reviewed before public release if immutable runner
  pinning is required.

## Publication Blockers

- License choice needs explicit owner approval before public push. The current
  Cargo metadata follows the toolkit template's Apache-2.0 convention, but no
  public repository should be launched until that is confirmed.
- Target public repository name and owner are not yet selected.
- The `mcp-toolkit-rs` dependency is temporarily pinned to a non-main branch
  revision for no-mutation proof posture support. Public release should repin
  to the landed upstream commit before publishing, unless the owner explicitly
  approves the branch pin.
- Final hosted validation must run on the commit that will be published.
- GitHub security settings must be verified after the repository exists.

## Useful Hosted Gates

- `rust-baseline`: `cargo fmt --all --check`, `cargo clippy --all-targets
  --all-features -- -D warnings`, and `cargo test --all-targets
  --all-features`.
