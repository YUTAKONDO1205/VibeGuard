# Reproducing the paper evaluation (SES2026)

This document maps every number reported in the SES2026 paper
"AI生成コードに対するマルチコンテキスト型セキュリティ診断基盤 VibeGuard の設計と実装"
to the exact command that produces it, so a third party can reproduce the
evaluation from a clean clone.

## Artifact

- Repository: <https://github.com/YUTAKONDO1205/VibeGuard>
- Paper version: **v0.1.3** (`ENGINE_VERSION 0.1.0`), 47 rules, 8 languages.
- Reference environment used in the paper: Windows 11, Intel Core i5-12400,
  32 GB RAM, Node.js v24. Functional results (finding counts, consistency,
  diff reduction) are deterministic and environment-independent; only the E5
  timings are machine-dependent.

## Setup

```bash
git clone https://github.com/YUTAKONDO1205/VibeGuard
cd VibeGuard
npm install
npm run build            # builds all 8 workspaces
npm test                 # 261 unit/integration tests, all green
```

Note: run the test suite via `npm test` (per-workspace). Invoking `vitest`
directly at the repo root may pick up local, untracked experiment files and
report a different count.

## E1 — cross-channel judgment consistency

```bash
node scripts/e1-consistency-eval.mjs
```

Expected: 70/70 findings identical (`samples/vulnerable` 50 + `test_problem` 20)
between the Node bundle (CLI / GitHub Actions / VS Code path) and the browser
bundle (Chrome path), compared as
(filePath, ruleId, severity, startLine, startColumn, confidence, category)
tuples; exit code 0. The same check gates CI (`consistency-e2e` job).

## E2 / E3 — curated samples

```bash
node apps/cli/dist/index.js samples/vulnerable --format json --fail-on never
node apps/cli/dist/index.js samples/safe       --format json --fail-on never
```

Expected: `samples/vulnerable` (13 files, 6 languages) → **50 findings**
(severity 5 critical / 15 high / 27 medium / 3 low; confidence 6 high /
26 medium / 18 low; 15 of category `ai-quality`). `samples/safe` → **0 findings**.

## E4 — PR-diff scan reduction

```bash
node scripts/e4-prdiff-eval.mjs
```

Builds a temporary git corpus (9 files copied from `samples/vulnerable` plus
one safe file; baseline full scan = **38 findings**) and applies three PR
scenarios. Expected (R = 1 − |F_diff| / |F_all|):

| scenario | full | diff | R |
|---|---|---|---|
| A new vulnerable file (`eval`) | 39 | 1 (VG-INJ-004, critical) | ≈0.974 |
| B safe lines appended to a vulnerable file | 38 | 0 | 1.0 |
| C vulnerable line appended to a safe file | 39 | 1 (VG-INJ-003, high) | ≈0.974 |

## E5 — performance

```bash
node scripts/perf-bench.mjs
```

Three workloads, three runs each, median of child-process wall time (includes
Node.js startup). Paper values on the reference machine: single-file fast scan
73 ms, `samples/vulnerable` standard scan 90 ms, repo-wide scan 225 ms.
Timings vary with hardware/load; the design targets (3 s / 1 s / 5 min) are the
contract. When timing the repo-wide scan locally, add `--ignore paper_data` if
you have regenerated the (gitignored) experiment outputs, since large local
JSON artifacts inflate the scan.

## E6 — context-window confidence correction

Mechanism fixtures (control vs treatment pairs in `samples/context-window`):

```bash
node scripts/e6-confidence-eval.mjs
```

Expected: 9 findings, **5 down-ranked** (docstring / block-comment / test-path
occurrences), executable control occurrences unchanged, **0 collateral
down-ranks** over `samples/vulnerable` (confidence distribution stays
6/26/18), `samples/safe` stays 0.

Extended evaluation on 11 public OSS repositories (8 languages):

```bash
node scripts/e6-extended-eval.mjs
```

Expected aggregate (paper Table 9): 11 repos, ≈430.6 KLOC, **2533 findings**,
66 critical+high, test/doc ratio **T = 0.73** (range 0.10–0.99), context-window
correction down-ranks **139 (5.5%)**, demoting **105** below the
medium-confidence action threshold.

The script clones each repository's default branch at `--depth 1` and records
the exact commit in `paper_data/e6_extended.json`. The paper numbers were
obtained at the following upstream commits (re-verified 2026-06-10 with an
identical aggregate):

| repo | commit |
|---|---|
| pallets/flask | `36e4a824` |
| psf/requests | `6f66281a` |
| pallets/click | `8a1b1a33` |
| expressjs/express | `dae209ae` |
| axios/axios | `fe964f96` |
| colinhacks/zod | `bbc68f99` |
| gin-gonic/gin | `d75fcd4c` |
| google/gson | `004e7a49` |
| sinatra/sinatra | `5236d345` |
| guzzle/guzzle | `5af96f37` |
| JamesNK/Newtonsoft.Json | `4f73e743` |

Scanning later upstream commits may shift per-repo counts as those projects
evolve; pin the commits above to reproduce the paper numbers exactly.

## SAST baseline comparison (complementarity, not a precision race)

VibeGuard side of the corpus:

```bash
node apps/cli/dist/index.js samples/vulnerable --format json --fail-on never > vg.json
```

**Bandit** (paper Table 6; Python-scoped — Bandit 1.9.4):

```bash
pip install bandit
python -m bandit -r samples/vulnerable -f json -o bandit.json
node scripts/sast-baseline-eval.mjs "samples/vulnerable (.py)" vg.json bandit.json
```

Expected (`.py` files): VibeGuard 15 (12 general + 3 ai-quality), Bandit 13,
co-located 12, VibeGuard-only 3 (all ai-quality/SATD — Bandit has no such
rules), Bandit-only 2 (B404, B105).

**Semgrep** (multi-language; Semgrep 1.165.0 runs natively on Windows):

```bash
pip install semgrep
semgrep --config=p/default --json --metrics=off --output semgrep.json samples/vulnerable
node scripts/sast-baseline-eval.mjs "samples/vulnerable (multi-lang)" vg.json semgrep.json
```

Result at 2026-06-10 (`p/default`, 665 rules ran): Semgrep 20 findings vs
VibeGuard 50; co-located 12, Semgrep-only 2 (CSRF middleware check,
`math/rand` weak PRNG), VibeGuard-only 38 — including **all 15 ai-quality
findings (0/15 co-located)**. Python-scoped: Semgrep 7, overlap 6,
Semgrep-only 0. Caveat: `p/default` is a curated registry pack that evolves
over time; record the rule count and date when re-running. Findings are
matched by location (same file, ±2 lines), not by rule semantics.

These comparisons measure *coverage complementarity*. Totals must not be read
as precision/recall — the corpora are small and author-written, and the tools
target different rule families.
