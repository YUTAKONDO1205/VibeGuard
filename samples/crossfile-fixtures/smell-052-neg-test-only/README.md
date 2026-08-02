# smell-052-neg-test-only/ — referenced only from the test tree

The false positive this rule is most likely to produce, isolated.

`validateInput` is exported, security-named, and never applied at a route. The
routes are registered with no guard argument, and `req.query.slug` reaches
`db.query`. Every condition the positive satisfies is satisfied here — except
that `__tests__/validate-input-cases.ts` imports the function and exercises it.

The temptation is to exclude the test tree from the mention scan, because that is
what `VG-SMELL-010` does with `TEST_PATH` and it is correct there: a duplicated
authorization check written in a test is not a duplicated authorization check in
the product. **The same exclusion is a bug here, and the reason is that the two
rules fail in opposite directions.** VG-SMELL-010 fires on the PRESENCE of code
and excluding a file can only lose a finding; VG-SMELL-052 fires on the ABSENCE
of a reference, so excluding a file can only invent one. Every file the mention
scan is not allowed to read is a file that could be holding the reference which
would have made the finding wrong.

So: candidates are never taken from the test tree, and references are always
counted from it. The asymmetry is deliberate and this directory is what pins it.

**Expected: no `VG-SMELL-052` finding.**

The test file is named `validate-input-cases.ts`, not `*.test.ts` or `*.spec.ts`,
because Vitest would otherwise collect it as a real suite — see the note in the
parent `README.md`. The `__tests__/` directory is what makes it test code as far
as `TEST_PATH` is concerned.
