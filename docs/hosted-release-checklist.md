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

The required `Rust Cobertura coverage` job always generates the XML report and
uploads the `rust-cobertura-coverage` artifact with
`if-no-files-found: error`. GitHub Code Quality is an optional reporting sink,
not the coverage authority. Its separate upload job runs only when the
repository variable `CODE_QUALITY_UPLOAD_ENABLED` is exactly `true`; leaving
the variable unset or false keeps that unavailable feature skipped without
weakening coverage generation or artifact retention. The reporting job also
skips fork pull requests because their token cannot retain Code Quality write
authority; the required coverage artifact remains the review evidence for
those candidates. Do not add `continue-on-error` to either contract.

`release-artifact` is not a normal pull-request branch-protection check because
it runs only on `workflow_dispatch` and `v*` tags. Treat it as the artifact
promotion gate after the reviewed commit is selected.

## Artifact Promotion

1. Dispatch or tag-trigger `release-artifact` for the reviewed commit.
2. Wait for the run to finish successfully.
3. Download `oci-email-delivery-mcp-linux-x86_64`.
4. Confirm the artifact contains the Linux archive, archive SHA-256 sidecar,
   and `oci-email-delivery-mcp-linux-x86_64.cdx.json` CycloneDX 1.5 Cargo
   dependency SBOM for the Linux binary target. The release workflow rejects
   empty component lists and disconnected root dependency graphs before
   upload or attestation.
5. Verify the SHA-256 sidecar against the downloaded archive before extracting
   the binary.
6. For a manual dispatch from `main`, verify both the provenance and SBOM
   attestations for the Linux archive. Tag builds intentionally remain
   unattested:

   ```bash
   gh attestation verify \
     oci-email-delivery-mcp-linux-x86_64.tar.gz \
     --repo sednalabs/oci-email-delivery-mcp
   gh attestation verify \
     oci-email-delivery-mcp-linux-x86_64.tar.gz \
     --repo sednalabs/oci-email-delivery-mcp \
     --predicate-type https://cyclonedx.org/bom
   ```
7. Install the binary to the intended local MCP binary path.
8. Configure the MCP alias with the intended OCI profile, region, compartment,
   hard-bounce thresholds, private snapshot root, and private ledger path if
   send-ledger reconciliation is required on that host.
9. Restart the MCP client process after changing the binary or environment.
10. Verify the configured alias initializes and lists exactly:
   `oci_email_status`, `oci_email_metrics`, `oci_email_ledger_window`,
   `oci_email_events`, `oci_email_message_engagement`, `oci_email_logging_status`,
   `oci_email_return_paths`, `oci_email_logging_enablement_plan`,
   `oci_email_trace_message`, `oci_email_bulk_trace_messages`,
   `oci_email_suppressions`, `oci_email_suppression_delta`,
   `oci_email_watch_window`,
   `oci_email_send_readiness`, `oci_email_traceability_audit`, and
   `oci_email_monitoring_snapshot_artifact`.

Do not call the adapter released until the hosted artifact checksum, applicable
main-dispatch attestations, and configured alias startup proof are recorded.

## GitHub Repository Settings

After public repository creation, verify:

- code scanning is enabled and accepting CodeQL, DevSkim, and OSV SARIF;
- when GitHub Code Quality is intentionally enabled,
  `CODE_QUALITY_UPLOAD_ENABLED=true` and the optional upload job is accepting
  the generated Cobertura report on eligible same-repository events;
- Dependabot security updates are enabled;
- secret scanning and push protection are enabled where available;
- default branch protection requires the pull-request hosted validation gates
  above, including mandatory Cobertura generation/artifact retention but
  excluding the optional Code Quality upload and manual/tag-only
  `release-artifact` promotion gate;
- the default branch does not require an outside reviewer when maintainer-only
  approval is the chosen policy;
- pushes to the default branch remain limited to approved maintainers.
