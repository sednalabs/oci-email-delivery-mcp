# Hosted Release Checklist

This repository is a public-release candidate for a read-only OCI Email
Delivery MCP. Do not install a local debug binary as the operational artifact
when publishing or updating the adapter.

## Before Public Push

- Confirm repository owner and name.
- Confirm Apache-2.0 is the approved license for this adapter.
- Run the public release scan and keep `HIGH=0 MEDIUM=0 LOW=0`.
- Confirm public docs contain no operator-specific live counts, recipient
  addresses, private paths, tokens, host secrets, raw OCI payloads, or campaign
  identifiers.
- Confirm the capability matrix lists every exposed tool and every deferred
  mutation or send-adjacent workflow.

## Hosted Validation

After the repository exists, require hosted checks on the exact published
commit:

- `rust-baseline`
- `CodeQL Advanced`
- `codeql-query-tests`
- `code-coverage`
- `DevSkim`
- `OSV-Scanner`

The custom Actions CodeQL query pack must compile in `codeql-query-tests`
before its CodeQL analysis results are treated as meaningful.

`release-artifact` is not a normal pull-request branch-protection check because
it runs only on `workflow_dispatch` and `v*` tags. Treat it as the artifact
promotion gate after the reviewed commit is selected.

## Artifact Promotion

1. Dispatch or tag-trigger `release-artifact` for the reviewed commit.
2. Wait for the run to finish successfully.
3. Download `oci-email-delivery-mcp-linux-x86_64`.
4. Verify the SHA-256 sidecar against the downloaded binary.
5. Install the binary to the intended local MCP binary path.
6. Configure the MCP alias with the intended OCI profile, region, compartment,
   hard-bounce thresholds, and private ledger path if send-ledger
   reconciliation is required on that host.
7. Restart the MCP client process after changing the binary or environment.
8. Verify the configured alias initializes and lists exactly:
   `oci_email_status`, `oci_email_metrics`, `oci_email_ledger_window`,
   `oci_email_events`, `oci_email_trace_message`, `oci_email_suppressions`,
   and `oci_email_watch_window`.

Do not call the adapter released until the hosted artifact checksum and
configured alias startup proof are both recorded.

## GitHub Repository Settings

After public repository creation, verify:

- code scanning is enabled and accepting CodeQL, DevSkim, and OSV SARIF;
- Dependabot security updates are enabled;
- secret scanning and push protection are enabled where available;
- default branch protection requires the pull-request hosted validation gates
  above, excluding the manual/tag-only `release-artifact` promotion gate;
- the default branch does not require an outside reviewer when maintainer-only
  approval is the chosen policy;
- pushes to the default branch remain limited to approved maintainers.
