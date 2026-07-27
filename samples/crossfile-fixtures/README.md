# samples/crossfile-fixtures — the cross-file falsification corpus

**This directory started as five VG-SMELL-010 negatives and is no longer only
that.** It now also holds the severity fixtures for the Security Context Boost
(#22d) and the falsification corpus for `VG-RTOS-003` (#20d). Read the group
headings below before assuming what a directory is for — in particular, the old
blanket claim "none of them may produce a `VG-SMELL-010` finding" is **false**
now, and three directories are positives on purpose.

## Group 1 — VG-SMELL-010 negatives (the original five)

Each is one condition away from `samples/crossfile-vulnerable/`. **None of these
five may produce a `VG-SMELL-010` finding.** Each isolates a single negative so
that when the rule regresses, the directory that starts firing names the cause:

| directory | what it holds | what it falsifies |
| --- | --- | --- |
| `delegated/` | 4 handlers, 3 files, each calling `requireAdmin(req)` | condition (b) — the check is not inlined |
| `two-sites/` | 2 inlined checks, 2 files | condition (c) — below the ≥3 threshold |
| `single-file/` | 3 inlined checks, 1 file | the "multiple files" half of condition (a) |
| `not-handlers/` | 4 role comparisons in models and utilities | condition (d) — not route/handler code |
| `test-paths/` | 3 inlined checks under `__tests__/` and `spec/` | the population — test code is excluded |

Two later additions belong to this group and are also expected to be quiet or to
fire for reasons their own READMEs explain: `chat-roles/` (the LLM
`message.role === 'assistant'` collision found by real-corpus evaluation) and
`generic-receivers/`.

## Group 2 — VG-SMELL-010 severity fixtures (#22d)

These three **do** produce a finding; what they pin is its `severity`. See
`boost-none/README.md` — it is the sentinel that fails the day every finding
becomes `high`.

| directory | boost condition present | expected |
| --- | --- | --- |
| `boost-none/` | none | `VG-SMELL-010` **medium** |
| `boost-db/` | ③ data mutation (`updateOne`/`deleteOne` and a real SQL statement) | `VG-SMELL-010` **high** |
| `boost-authpath/` | ① security word in the path | `VG-SMELL-010` **high** |

## Group 3 — the C/C++ cross-file rules

`embedded-hallucinated/`, `embedded-real-api/`, `embedded-partial-sdk/`,
`embedded-unintegrated/` and `embedded-wired/` belong to VG-AISC-002/003 (#20b).

The six `embedded-volatile-*/` directories are the `VG-RTOS-003` corpus (#20d):
`embedded-volatile-missing/` is the **positive** and must produce exactly one
finding; `declared`, `static`, `two-decls`, `typedef` and `angled` are negatives
and must be silent.

These are written from the §7.2 spec text, not from any implementation, and they
are deliberately *near misses*: each one satisfies every condition but the one it
names. A corpus of obviously-unrelated code would prove nothing, because a rule
can be wrong in ways that only show up one step from the boundary.

Within group 1, `single-file/` is the one directory expected to produce a finding
at all — the single-file rule `VG-SMELL-012` owns that case, and its README
explains why that is the intended outcome rather than a leak. Every other
directory in group 1 is expected to be quiet under the existing rule set as well
as under VG-SMELL-010.

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

The cross-file rules need `--include-design-smells`; without it none of the
group 2 or group 3 directories reports anything, which is why the sample gates
in `security-scan.yml` do not cover them and the tests in
`packages/analysis-graph` do.
