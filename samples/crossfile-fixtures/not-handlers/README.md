# not-handlers/ — falsifies condition (d)

Four role comparisons across four files — `models/user.ts`,
`models/workspace.ts`, `lib/seat-pricing.ts`, `lib/audit-labels.ts` — which
satisfies (a) multiple files, (b) written inline, and (c) ≥3 occurrences. What
fails is condition **(d)**, "concentrated in API route / controller / handler
code": none of these functions is registered as a route handler, this directory
imports no web framework, and there is no route table anywhere in it. Two of the
sites are not even access decisions — `seatCostCents` prices a seat and
`roleLabel` renders a string — which is the ordinary reason a codebase mentions
roles in many files without having scattered its authorization. Condition (d) is
what keeps VG-SMELL-010 from degenerating into "this project has the word `role`
in it more than twice". A rule that scans for role comparisons project-wide
without first establishing that the enclosing symbol is on a request path fires
here, and must not.
