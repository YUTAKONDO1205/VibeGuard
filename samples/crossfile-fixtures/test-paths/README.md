# test-paths/ — falsifies the population, not a condition

Three inlined role checks in three route handlers across three files: read
literally, conditions (a) through (d) of §7.2 all hold. The reason VG-SMELL-010
must stay silent is that none of these files is part of the population the rule
is defined over. Two live under `__tests__/` and one under `spec/`, and test code
is excluded before the count is taken — the same `TEST_PATH_RE` / `isTestPath`
exclusion the single-file design smells already apply. Test fixtures inline
checks *on purpose*: a harness that duplicates a guard so it can assert the 403
branch in isolation is doing the correct thing, and telling its author to
centralise the policy would be telling them to make the test depend on the code
under test. Two different path segments are used rather than one, because a rule
that hardcodes `__tests__` and does not go through the shared predicate passes
half of this directory.

## Why the filenames are not `*.test.ts` / `*.spec.ts`

They cannot be, and this is a constraint of the repository rather than a
weakening of the fixture. `TEST_PATH_RE` recognises test paths two ways — a
`tests`/`__tests__`/`__mocks__`/`fixtures`/`spec`/`specs` **path segment**, or a
`.test.<ext>` / `.spec.<ext>` **filename suffix** — and Vitest's default
`include` (`**/*.{test,spec}.?(c|m)[jt]s?(x)`) claims every filename that would
exercise the second branch. A root-level `npx vitest run` walks `samples/`, so a
file here named `report-controller.spec.ts` is collected as a real suite, fails
to resolve its `express` import, and turns a green repo-wide run red. Verified:
with the suffix names in place, `npx vitest run samples/crossfile-fixtures`
reported `Test Files 3 failed (3)`.

So this directory covers the path-segment branch on two segments, and the
filename-suffix branch is **not covered by any fixture**. If VG-SMELL-010's
exclusion is implemented by calling `isTestPath` on the file path, both branches
come along for free and the gap is cosmetic. If it is implemented with a
hand-written path check, the suffix branch is untested here and should be covered
by a unit test inside the rule's own package, where a `.spec.ts` fixture can live
as a string rather than as a file on disk.
