# smell-052-neg-flow-outside-handlers — the batch-script negative

There is untrusted input reaching a query sink in this project, and it is in
`scripts/reindex-orders.ts`: a maintenance script that reads `process.argv` and
interpolates it into SQL. That is a real defect and it belongs to a different
rule — the value arrives from an operator's shell, not from the request path, and
no route-level middleware would ever have stood in front of it.

VG-SMELL-052's remediation is "add it to the argument list of a registration".
For a flow with no registration anywhere near it, that instruction is not
actionable, and a finding whose evidence does not fit its subject is a finding
that should not be made.

`GET /status` is registered with no guard and `requireOrderAccess` is exported
and referenced by nothing, so the other two conditions are live. The restriction
of flows to REGISTERED handlers is the only thing keeping this quiet.
