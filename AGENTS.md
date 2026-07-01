# AGENTS.md - OCI Email Delivery MCP

This repository contains a Rust MCP server for OCI Email Delivery monitoring
and no-send readiness evidence. Its OCI/provider surface is read-only; local
private artifact writes are limited to redacted monitoring snapshots under a
configured private root. It follows the curated stdio intent-server pattern
from `sednalabs/mcp-toolkit-rs`.

## Engineering Rules

- Keep the MCP surface small and operator-shaped. Prefer OCI Email Delivery
  intent tools over generic OCI CLI, raw API, log-query, or dashboard scraping
  escape hatches.
- Read-only OCI/provider tools are the only current external scope. Local
  private artifact writes are allowed only for redacted monitoring snapshots
  under a configured private root. Do not add email send, DNS, suppression
  mutation, log-enable, Connector Hub apply, contact import, or production
  campaign actions without a new preview/apply safety design and explicit
  approval.
- Tool output must be redacted before it leaves the MCP. Never return raw
  recipient email addresses, raw OCIDs, credential paths, private key material,
  tokens, raw provider payloads, or full log events.
- Treat OCI `EmailsRelayed` and relayed log events as recipient-domain
  acceptance, not inbox placement.
- Preserve the no-send posture: this adapter may prove visibility and query
  readiness, but it does not authorize a seed, cohort, or full-list send.
- Fixtures must be synthetic or redacted. Do not commit live OCI JSON payloads,
  raw recipient addresses, private local paths, config files, keys, tokens, or
  customer campaign artifacts.
- Keep dependencies shallow and consistent with `mcp-toolkit-rs`.
- Build installable binaries only from a hosted, reviewed artifact. Local
  builds are for focused validation only, not operational promotion.

## Required Checks

Run focused checks before committing behavior changes:

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```

If OCI credentials are available, also run a no-send live smoke of
`oci_email_status` and a bounded `oci_email_metrics` query before treating the
adapter as operationally ready.
