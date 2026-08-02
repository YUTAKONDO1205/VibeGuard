# smell-052-neg-no-untrusted-input/ — nothing untrusted is being handled

`validateInput` is exported, security-named, referenced by nothing, and the two
routes are registered with no guard argument. Structurally this directory is the
positive. What is missing is the only thing that makes the absence matter:
neither handler reads anything a client controls. `listStatus` and `listRegions`
take `_req`, answer from constants, and their sinks — a `db.query` with a literal
statement and a `res.send` with a literal body — receive no tainted value.

This is the fixture behind the taint requirement. Without it the rule would be
"an exported function whose name looks security-ish is never called", which is a
dead-code report wearing a CWE. The design plan is explicit that 041 and 052 must
have taint evidence rather than a structural heuristic (§5.4, and the risk table
that says *041/052 は taint 根拠必須*), and "evidence" here means: a real,
printable path by which attacker-controlled data reaches a sink inside a route
handler that the generated protection does not stand on.

Note that the sinks are present and the sources are not. A fixture with no
`db.query` at all would go quiet for a second reason and would not isolate this
one.

**Expected: no `VG-SMELL-052` finding.**
