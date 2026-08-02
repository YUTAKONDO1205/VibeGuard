# smell-041-validate-after — VG-SMELL-041 POSITIVE (INVERTED, validator)

`isValidHostname(host)` runs after `childProcess.execSync` has already executed
the command built from `host`. A validator returns a verdict rather than a safe
copy, so running first is the *only* thing that can make it effective — this is
the purest form of the smell.

Expected: exactly one `VG-SMELL-041`, `severity: high` (an `exec` sink),
`confidence: high` (INVERTED, two hops), primary location `diagnostics.ts:18`.

## ★ The second sink is the point of the fixture

`res.send(output)` on the last line is a second taint sink fed by the same
source, and H1 reports both flows — the test asserts `flows.length === 2` so this
cannot decay. By the time that line runs, the hostname **has** been validated and
the failing branch has returned, so the rule must say nothing about it.

One finding, not two, is what separates "reports a mis-ordered check" from
"reports every sink in a function that validates anything".
