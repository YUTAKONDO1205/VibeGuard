# @vibeguard/analysis-graph

The cross-file pass. Runs only when the CLI is given `--include-design-smells`
(or the Action's `include-design-smells: true`), over the whole target tree
rather than one file at a time.

Status is `0.3.0-alpha.1`, reported separately from the core engine as
`engineVersions['analysis-graph']`. The `-alpha` is not decoration: the analysis
indexes **lexically**, not by parsing, and the confidence caps below follow from
that.

## The constraint this package exists to satisfy

Cross-file analysis, taint tracking, and any future AST dependency stay **here**,
behind an opt-in flag, reachable only from the CLI and the GitHub Action. The
Chrome and VS Code extensions bundle `analyzer-core` + `rules` and nothing else.

That is not a packaging preference. It is what keeps three product properties
true at once — zero dependencies, light enough to run on every save in a
browser, and four channels that provably agree — and a single import of this
package from `analyzer-core` would put a project-wide graph builder inside a
service worker and take all three with it.

The boundary is **not** maintained by discipline.
[`scripts/check-packaging-invariants.mjs`](../../scripts/check-packaging-invariants.mjs)
asserts it three ways (source imports, declared dependencies, and this package's
path appearing in no shipped bundle), and that check runs as part of the test
suite. See `AG_BUNDLE_SENTINEL` in `src/index.ts` for the measured limits of each
needle — including a first version of the check that was convincing and wrong.

## Rules

| Rule | What it reports | Confidence |
|---|---|---|
| `VG-SMELL-010` | **Scattered authorization** — the same privilege decision re-derived inline in ≥3 route handlers across ≥2 files, instead of in one guard. Severity rises to `high` on a privilege word, a security-worded path, or a data-store write in the handler. | `medium`, or `high` at ≥5 sites over ≥3 files |
| `VG-AISC-002` | A call into a **known SDK namespace whose member no member header declares** — the hallucinated-API shape. Reported only when the project's own quoted includes all resolve. | capped at `medium` |
| `VG-AISC-003` | A **security initialiser that is defined and never named anywhere else** in the project. | capped at `medium` |
| `VG-RTOS-003` | An **ISR-written shared variable missing `volatile`, where the reader is in another file** — the cross-file half of `VG-RTOS-002`. | capped at `medium` |
| `VG-SMELL-020` | A **security-relevant module inside an import cycle**, where every edge is a runtime import. Initialisation order in a cycle is decided by which member is imported first, so a key can be read before it is set. | capped at `medium` |
| `VG-SMELL-021` | A **security module that depends on an unusually large number of others** — attack surface and initialisation complexity concentrated in the one file that can least afford it. Uses `fanMetrics`. | capped at `medium` |
| `VG-SMELL-041` | **Temporal security coupling** — a taint flow whose protecting call cannot have protected it, because it runs after the sink in the same block. Backed by `taint/`, so the report carries the source → hops → sink chain. | capped at `medium` |
| `VG-SMELL-052` | **Generated boilerplate never wired in** — an exported security helper that no route mounts and no taint path crosses, in a project that has unguarded routes reached by tainted input. Backed by `taint/`. | capped at `medium` |

### What the β four cost to admit, measured

The bar was not "the tests pass". `VG-SMELL-041` and `VG-SMELL-052` both had
green tests and full negative-fixture sets on their first submission and were
**rejected**: swept across the 1000 repositories in `paper_data/corpus1k`, 041
produced three findings and none were true — one of them a guard in the sibling
arm of an `if`/`else`, the exact failure its own header claimed to be designed
against — and 052 fired on a correctly-mounted guard reached through an
`export *` barrel. Both were reworked until that sweep came back clean.

| Rule | Real-corpus sweep (630 repos with source) |
|---|---|
| `VG-SMELL-020` | 6 findings, all adjudicated: 5 true, 1 false (a `from . import x` resolver artifact) |
| `VG-SMELL-021` | 2 findings, all adjudicated: 2 true. Was 3 — the third counted imports TypeScript erases, fixed in `type-erasure.ts` |
| `VG-SMELL-041` | 0 findings — was 3, all false, before the rework |
| `VG-SMELL-052` | 0 findings — was firing on barrels, before the rework |

The two zeroes are honest about their limits. They show the reworked rules no
longer fire on a large body of real code, which is what `samples/safe == 0`
generalises to. They show **nothing about recall**: neither produced a true
positive on that corpus either, so their only evidence of usefulness is their own
fixtures. That is a weaker claim than 020 and 021 can make, and it is written
down here rather than averaged away.

Six of the eight never reach `high` confidence, and it is the same reason each
time: the evidence is that a **lexical** scan did not find something. "No header
declares this member", "this token never appears elsewhere", "this declaration
has no `volatile`" — a generated header, a linker-supplied symbol, a declaration
behind a preprocessor conditional this analysis does not evaluate, or a naming
convention it does not know would all produce the same shape with nothing wrong.
`VG-SMELL-010` is the exception only where the pattern is emphatic enough that
the lexical uncertainty stops mattering.

Rule IDs are unique across this package and `@vibeguard/rules`; the number does
not tell you which package a rule is in. The split is by analysis *scope*, so
`VG-SMELL-003/004/012`, `VG-AISC-001` and `VG-RTOS-001/002/004` are single-file
rules that live in `rules/`.

## Layout

```
src/
├── structure-indexer/       what is in a file      (symbols, routes, imports)
├── dependency-graph/        what points at what    (import edges, #include edges)
├── symbol-table/            what identifiers mean  (role / guard / token inference)
├── metrics/                 what the numbers are   (DesignMetrics)
├── design-smells-crossfile/ the eight rules that need all of the above
├── taint/                   intra-procedural source → sink (H1; read by 041/052)
├── budget.ts                the cost ceiling for a whole-tree pass
├── project.ts               analyzeProject / buildProjectIndex / runCrossFileRules
└── version.ts               ANALYSIS_GRAPH_VERSION
```

## Public surface

- `analyzeProject(options)` — collect files, build the index, run the cross-file
  rules, and return `CrossFileResult`.
- `buildProjectIndex(...)` / `runCrossFileRules(...)` — the two halves, separately,
  for tests and for callers that already hold an index.
- `mergeCrossFileFindings(...)` / `applyConfigSuppression(...)` — fold the result
  into a per-file scan's findings under the same suppression policy as the
  single-file path.
- `ANALYSIS_GRAPH_VERSION` — what the CLI reports as
  `engineVersions['analysis-graph']`.

## Corpora

The gates for these rules are **not** in the `samples` CI job, because that job
scans without `--include-design-smells` and would see nothing. They live in this
package's vitest suites, over:

- [`samples/crossfile-vulnerable`](../../samples/crossfile-vulnerable) — exactly one
  `VG-SMELL-010`, at `high`.
- [`samples/crossfile-safe`](../../samples/crossfile-safe) — the same service
  refactored behind one middleware. Zero findings, from any rule.
- [`samples/crossfile-fixtures`](../../samples/crossfile-fixtures) — one directory per
  falsifiable condition, each a near miss that satisfies everything but the
  condition it names.
