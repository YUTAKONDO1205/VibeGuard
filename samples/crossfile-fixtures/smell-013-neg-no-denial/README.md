# smell-013-neg-no-denial

The largest population of correct code this rule has to stay away from:
branching on privilege to SHAPE a response.

`listInvoices` reads `req.user.role` on a subject receiver, with the
`requireInvoiceScope` convention established elsewhere in the project — and it
refuses nothing. A route-level guard could not replace it, because a guard's
whole vocabulary is "continue" or "refuse" and this handler wants neither.

`DENIAL_WINDOW` is what keeps the rule quiet here.
