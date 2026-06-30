/**
 * @name High-risk write token permission in workflow
 * @description Public adapter workflows should avoid high-risk write permissions unless a release path explicitly needs them.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id oci-email-delivery-mcp/actions/high-risk-write-token-grant
 * @tags actions
 *       security
 *       maintainability
 */

import actions

private predicate highRiskWritePermission(string permission) {
  permission = "actions"
  or permission = "attestations"
  or permission = "checks"
  or permission = "contents"
  or permission = "deployments"
  or permission = "discussions"
  or permission = "id-token"
  or permission = "issues"
  or permission = "packages"
  or permission = "pages"
  or permission = "pull-requests"
  or permission = "repository-projects"
  or permission = "statuses"
}

from Permissions permissions, string permission
where
  highRiskWritePermission(permission) and
  permissions.getPermission(permission) = "write"
select permissions,
  "Workflow token grants high-risk permission '" + permission +
    ": write'. Keep public adapter workflows read-only unless a reviewed release path needs this grant."
