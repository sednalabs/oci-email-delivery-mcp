# Security Policy

## Reporting A Vulnerability

Please report suspected vulnerabilities through GitHub private vulnerability
reporting or a GitHub Security Advisory when available for this repository.
Avoid opening public issues or pull requests that include sensitive
reproduction details before maintainers have had a chance to assess and
remediate the issue.

If private GitHub reporting is unavailable, open a public GitHub issue titled
`Security contact request` and do not include vulnerability details in that
issue. Maintainers will use that issue to establish a private coordination
channel.

When reporting privately, include:

- affected tool, workflow, or release artifact;
- impact and required preconditions;
- minimal reproduction details;
- suggested fix or mitigation, if known.

## Safety Posture

This adapter is intentionally read-only. Vulnerability reports should treat any
email send, OCI mutation, DNS change, suppression mutation, log-enable action,
Connector Hub apply, contact import, or campaign action path exposed by this
repository as security-sensitive until reviewed.

Security fixes should land through pull requests with the repository's hosted
checks. Operational installs should use hosted release artifacts with checksum
verification, not local debug builds.
