/**
 * @name pull_request_target trigger in public adapter workflow
 * @description Public adapter repositories should not run pull_request_target workflows without a dedicated threat model.
 * @kind problem
 * @problem.severity warning
 * @precision high
 * @id oci-email-delivery-mcp/actions/pull-request-target-trigger
 * @tags actions
 *       security
 */

import actions

from Workflow workflow, Event event
where
  event = workflow.getOn().getAnEvent() and
  event.getName() = "pull_request_target"
select event,
  "This workflow uses pull_request_target. Public adapter workflows should use pull_request or a separately reviewed maintainer-only release path."
