# smell-011-neg-guard-in-same-file/ — a single-file observation

Condition (c). The convention, the omission and the guard's definition are all in
`routes/report-routes.ts`, so nothing here needs more than one file to see.

The whole justification for this package is the sentence single-file analysis
cannot form — `MIN_FILES` in `scattered-authorization.ts` makes the same refusal
for the same reason. A finding a single-file rule could have produced does not
get to borrow the cross-file argument.

**Expected: no `VG-SMELL-011` finding.**
