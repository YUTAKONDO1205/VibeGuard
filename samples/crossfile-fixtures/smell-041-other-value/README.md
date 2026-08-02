# smell-041-other-value — VG-SMELL-041 NEGATIVE

The sanitizer in this handler was written for a **different value**:
`escapeHtml(req.query.label)` runs before the query, its result is not what the
query uses, and the value that reaches the sink is `term`. Every ingredient of
the BYPASSED shape is present except the one that matters.

Expected: **no `VG-SMELL-041`**, with **two taint flows**.

Falsifies the premise — "a security operation written FOR THIS VALUE" — in two
places:

| function | shape | which condition keeps it quiet |
| --- | --- | --- |
| `searchCatalog` | the sanitizer names another value read off the same request | the guard's argument must name a chain name |
| `countTags` | a DIRECT flow whose source token is dotted and has no hop | `chainNames` refuses a dotted source token, so the chain has no names at all |

`countTags` passes the query object whole (`db.query(req.query)`), which is how a
query builder is called and the one shape where the source token would otherwise
be usable as a chain name. Admitting it back makes `escapeHtml(req.query)`
establish a premise about every value on that object at once.

## ★ Written after a mutation survived, and it changed the rule

Removing the premise filter entirely left all 39 tests green, so nothing was
pinning it. Writing this directory then showed why the first implementation could
not have been pinned: it admitted the flow's SOURCE TOKEN as a chain name, and
`\breq\.query\b` matches inside `escapeHtml(req.query.label)` — the `.` after
`query` satisfies the word boundary. Both values here are read off the same
request object on purpose, so the source name cannot tell them apart and only the
hop names can. `chainNames` now excludes dotted source tokens; the cost (a direct
flow from a dotted source can no longer establish the premise) is recorded there.
