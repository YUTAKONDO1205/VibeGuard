# smell-041-helper-guard — VG-SMELL-041 NEGATIVE

The same correct wiring as `smell-041-sanitize-first/`, with the sanitizer
reached through an imported namespace object: `sanitizers.escapeSql(status)`.
That is how a real project collects these functions, and the rule reads the LAST
dotted segment of a callee so that a helper accessed this way is recognised
exactly as a bare `escapeSql(...)` would be.

Expected: **no `VG-SMELL-041`**, with **two taint flows** — the query, and the
`res.send(JSON.stringify(rows))` that consumes a value derived from it. Both pass
through the same sanitised hop, so both must be silent; the second exists so the
directory does not prove its point on a single flow.

Falsifies: the dotted-callee handling in `classifyGuard`, and the on-path test.
