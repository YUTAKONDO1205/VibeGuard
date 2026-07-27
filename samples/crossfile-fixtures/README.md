# samples/crossfile-fixtures — the VG-SMELL-010 falsification corpus

Five directories, each one condition away from `samples/crossfile-vulnerable/`.
**None of them may produce a `VG-SMELL-010` finding.** Each isolates a single
negative so that when the rule regresses, the directory that starts firing names
the cause:

| directory | what it holds | what it falsifies |
| --- | --- | --- |
| `delegated/` | 4 handlers, 3 files, each calling `requireAdmin(req)` | condition (b) — the check is not inlined |
| `two-sites/` | 2 inlined checks, 2 files | condition (c) — below the ≥3 threshold |
| `single-file/` | 3 inlined checks, 1 file | the "multiple files" half of condition (a) |
| `not-handlers/` | 4 role comparisons in models and utilities | condition (d) — not route/handler code |
| `test-paths/` | 3 inlined checks under `__tests__/` and `spec/` | the population — test code is excluded |

These are written from the §7.2 spec text, not from any implementation, and they
are deliberately *near misses*: each one satisfies every condition but the one it
names. A corpus of obviously-unrelated code would prove nothing, because a rule
can be wrong in ways that only show up one step from the boundary.

`single-file/` is the one directory expected to produce a finding at all — the
single-file rule `VG-SMELL-012` owns that case, and its README explains why that
is the intended outcome rather than a leak. Every other directory here is
expected to be quiet under the existing rule set as well as under VG-SMELL-010.

## No file here may be named `*.test.ts` or `*.spec.ts`

Vitest's default `include` is `**/*.{test,spec}.?(c|m)[jt]s?(x)` and the root
`vitest.config.ts` does not exclude `samples/`, so any file under this tree with
one of those suffixes is collected as a real suite by a root-level
`npx vitest run` and fails — these are corpus files with `express` imports, not
tests. `test-paths/` therefore expresses "this is test code" with `__tests__/`
and `spec/` **directories**, which `TEST_PATH_RE` recognises just as well and
Vitest ignores. See that directory's README for what this leaves uncovered.

## Observed baseline

Scanned with the 0.2.x rule set (VG-SMELL-010 not yet implemented), via
`node apps/cli/dist/index.js <dir> --format json --fail-on never`:

| directory | `summary.total` |
| --- | --- |
| `delegated/` | 0 |
| `two-sites/` | 0 |
| `single-file/` | 3 (all `VG-SMELL-012`, high) |
| `not-handlers/` | 0 |
| `test-paths/` | 0 |
