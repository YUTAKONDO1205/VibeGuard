# smell-052-neg-on-taint-path/ — the sanitizer is called on the flow itself

The route is registered with **no** guard argument, so the "unguarded
registration" evidence the positive leans on is present here too. What is
different is where the sanitizer went: `searchProducts` calls
`sanitizeSearchTerm(raw)` between reading `req.query.q` and reaching
`db.query`, which is the correct place for it and is not a route registration at
all.

This is the fixture that stops the rule from being "the symbol does not appear in
any route's middleware list". A validator applied as a plain function call inside
the handler is wired; a rule that only recognises Express middleware mounting
accuses the handler that did the work by hand.

Note what `taint/` says about this file and what it does not: taint-lite does not
model sanitizers, so `term` is still tracked as tainted and the flow
`req.query → db.query` is still reported. The flow existing is exactly why this
directory is a real negative rather than a vacuous one — every precondition
VG-SMELL-052 needs is satisfied except the one this directory is named for.

**Expected: no `VG-SMELL-052` finding.**
