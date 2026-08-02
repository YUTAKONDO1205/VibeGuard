# smell-041-sanitize-bypassed — VG-SMELL-041 POSITIVE (BYPASSED, transformer)

`sanitizeFilename(requested)` runs **before** the file is opened, and its result
is not the value that reaches `fs.createReadStream`. The page order is right; the
data order is not.

Expected: exactly one `VG-SMELL-041`, `severity: medium`, `confidence: medium`,
primary location `reports.ts:22`.

## ★ This is the severity/confidence sentinel

It is the only directory in the group where **both** graded fields sit at the
floor, and it exists to fail the day either becomes constant — the other two
positives are `high` on both, so a rule that emitted `high`/`high`
unconditionally would satisfy every other assertion in the suite.

- `medium` severity: a `file` sink is context-dependent (this one reads under a
  fixed base directory), unlike the `query`/`exec`/`eval` sinks that hand a value
  to an interpreter.
- `medium` confidence: BYPASSED claims "the transformed copy is not the value
  that arrived", and an **incomplete** taint chain looks exactly the same — H1
  follows no property writes and no compound assignment. `high` would be the rule
  claiming past a gap its input has documented.

If you are editing this directory: moving the sanitizer below the
`createReadStream` call turns it into an INVERTED finding and changes both
fields, and the test that pins them will say so.
