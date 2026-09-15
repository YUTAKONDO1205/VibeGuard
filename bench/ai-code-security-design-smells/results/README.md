# results/

Result files written by `scripts/bench-score.mjs --out`. One JSON per scored
run, schema `bench/result@1`, and `scripts/bench-leaderboard.mjs` reads this
directory to build the leaderboard.

This directory is **empty on purpose**, and the emptiness is the honest state:
no tool has been run over the real corpus from this repository. Scoring one
requires fetching ~1700 third-party repositories at their pinned commits, and
the licence status of every entry is `unresolved` (see the benchmark README).

There is no `LEADERBOARD.md` beside this directory for the same reason. The
generator refuses to write a table with no rows -- an empty leaderboard reads as
"nobody has entered yet" and is indistinguishable from "the generator was
pointed at the wrong directory". A worked, end-to-end leaderboard does exist,
over the positive control, at `../fixtures/positive-control/LEADERBOARD.md`;
its rows are about the scorer, not about any tool.

This file itself is listed as `SKIPPED  README.md` on every generator run, and
that is deliberate: a file here that is not `*.json` is named rather than
filtered out in silence, so a submitter who mistypes `yourtool-1.2.3.jsonn` sees
their file named instead of watching it vanish.

Two things a result file written here must carry, or the generator rejects the
row by name rather than rendering it:

- `counts.labelsCovered` / `counts.labelsTPCovered` — the denominator is the
  labels the run COVERED. A row from a scorer that scored every label whether or
  not the run touched it reports repositories that were never scanned as misses.
- buckets that add up: `matched + UNSCORED + UNMAPPED + unattributed` must equal
  `findingsTotal`, and the label-side splits must partition too.
