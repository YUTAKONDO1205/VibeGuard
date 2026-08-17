# compiler/eval/comparison — lane CMP, the nine systems of §23.2

Runs the nine comparison systems named in the design plan section 23.2 over one fixture
set and records, for each, **what it reported** and **what it cannot report by
design**.

The second half is the reason this directory exists. Five of the nine arms
answer a question that is not "did this security property survive the build",
and a table that only recorded their verdicts would rank them badly at a
question nobody built them for. Every arm therefore carries a `cannotReport`
list in `arms.mjs`, and those lists are statements of scope, not of quality.

**Nothing here is scored against anything else.** No arm record carries a
`score` or `rank` field, in the registry or in any emitted cell, and there is no
total and no "best". (The words appear in `arms.mjs` prose only, saying that
ranking is not done.)

## Running it

```sh
node compiler/eval/comparison/run-comparison.mjs          # 4 opt levels, 48 cells
node compiler/eval/comparison/run-comparison.mjs --quick  # -O0 and -O2 only
```

Defaults, all overridable (`--fixtures`, `--out`, `--repo`, `--observer`,
`--work`, `--cc`, `--opt`):

| | |
|---|---|
| fixtures | `$LAB/fixtures` |
| results | `$LAB/_results-wave2/comparison/comparison.json` |
| observer plugin | `/root/vg-build/observer-mainverify/libPropertyObserver.so` |
| scratch | `$LAB/_work/cmp-run` (wiped each run) |

Linux only: it drives `clang-18`, `scan-build-18`, `checksec`, `strings` and
the LLVM pass plugin.

## The one rule about input

**Every arm in a cell sees the same bytes, the same `-O` level and the same
mitigation flags.** A cell is `(fixture, compiler, opt, mitigation)`; the arms
are run inside it, not alongside it. An arm that was handed an easier input and
came out looking better has not been compared with anything.

The mitigation axis needs one piece of care that is easy to get silently wrong:
`-s` is a link-time strip, and passing it to `-c` makes clang warn about an
unused argument and change nothing. `flagPhase()` routes it to the link step
only. Without that, the `notappear` mitigation axis would be a no-op while the
cell was still labelled `mit-on` — a fabricated comparison with a plausible
label.

## The nine arms

| # | arm | here | layer |
|---|---|---|---|
| ① | current VibeGuard | runs | source |
| ② | Clang Static Analyzer | runs | source/AST |
| ③ | Clang warnings | runs | source/AST |
| ④ | binary strings scan | runs | artifact |
| ⑤ | hardening checker (checksec) | runs | artifact |
| ⑥ | Alive2 | **`UNSUPPORTED` / `TOOL_ABSENT`** | IR |
| ⑦ | compiler-side pre/post IR only | runs | IR, two endpoints |
| ⑧ | compiler-side pass-level tracking | runs | IR, every boundary |
| ⑨ | Beyond integrated | **`UNSUPPORTED` / `SUBJECT_ABSENT`** | — |

### ⑥ and ⑨ are absent for different reasons, and the codes stay apart

`TOOL_ABSENT` — `alive-tv` is not installed on this host, and building it needs
z3 plus an LLVM build that was not done in this session. **This is a fact about
our machine.** Alive2 is real, works, and would run if installed.

`SUBJECT_ABSENT` — there is no `beyond/` directory in this repository and
nothing imports such a component. There is no installation that would fix it;
**the comparison subject does not exist yet.** Verified by search: the only two
occurrences of `beyond/` in the tree are this lane and the ablation lane, each
recording that it does not exist.

Collapsing both into one "unavailable" would destroy the only information the
distinction carries — that one is a gap in our setup and the other is a gap in
the world.

### ⑥ Alive2 is complementary, not a competitor

The plan states the relationship explicitly and this lane holds to it. Alive2
asks *was this transformation a refinement of its input* — functional
translation validation. This work asks *which pass removed this defence*.

Those are different questions, and the interesting fact is that they can both
answer "fine" about the same event: **deleting a dead store to a secret buffer
is a correct optimisation.** Alive2 would be right to pass it. The property is
gone anyway. That is the gap the pass-level arm exists to name, and it is not a
deficiency of Alive2 — "security property" is not a term in its specification.

No verdict in this lane ranks ⑥ against anything, and its absence must not be
read as one.

## Vocabulary

Two vocabularies, kept apart. The first is
`compiler/schema/interfaces.md` §3 and **is not extended here**:

`PRESENT` · `ABSENT` · `LOST` · `REINTRODUCED` · `NOT_APPLICABLE` ·
`NOT_OBSERVED`

`ABSENT` (observed missing where the property had not yet been established) is
not `LOST` (observed missing where it had previously been present), and neither
is `NOT_OBSERVED` (no observation was made). The preprocessor fixtures are the
case that makes this matter: the defence is genuinely gone, and no pass did it.

The second says what happened to the *arm*, and never occupies a slot in the
first: `OUT_OF_SCOPE`, `UNSUPPORTED`, `VERIFICATION_INCOMPLETE`,
`NO_MARKERS_DECLARED`, `NO_PROPERTY_DECLARED`.

Attribution is a third axis, because "reports no loss" and "cannot report
where" are different: `ATTRIBUTED`, `NO_LOSS_TO_ATTRIBUTE`,
`NO_ATTRIBUTION_BY_DESIGN`, `LOSS_PRECEDES_WINDOW`, `NOT_OBSERVED`,
`UNSUPPORTED`.

## Controls

Every run writes a `controls` block, and no arm's output should be read without
it. All seven pass in the recorded run.

**Positive.** `observer-fully-configured` — the fully configured observer on a
cell where the loss is known, expected to write a log, resolve both names,
report the subject `LOST` with a named pass and the control `PRESENT`.
`prepost-effect-visible-at-O0` — the endpoint comparator at `-O0`, where
nothing should be removed; an endpoint comparator that reported `LOST`
everywhere would look impressive and be worthless.

**Negative.** `checksec-discriminates` — the same sources linked hardened and
unhardened must produce different checksec output. If nothing in the harness
can change those bytes, then "they did not change" is not information.

**Red.** Four demonstrations of the harness lying if a fence were removed:

- `red-missing-env-var` — `OBS_CONTROL_FN` unset. The compiler exits **0**, the
  plugin prints `refusing to install`, and **no log is written**. An harness
  that checked only `rc` would call this a clean measurement. The fence is
  "was the log produced", never the exit code.
- `red-subject-name-resolves-to-nothing` — `OBS_TARGET_FN=handle_requestX`.
  rc 0, a non-empty log **is** written, the control **is** `PRESENT`, `STATS`
  counts 650 passes — and none of it is about the subject. Only `SUBJECTRES`
  plus `tools/check-subject-resolution.mjs` (exit 2) separates this from a
  subject erased before the first boundary. Read as `NOT_OBSERVED`, never
  `LOST`.
- `red-prepost-subject-name-resolves-to-nothing` — the same trap in arm ⑦. A
  comparator that found no function and said `LOST` would fabricate a finding
  out of a typo. The weaker arm is fenced against the same lie as the stronger
  one; what separates them is attribution, not honesty.
- `red-strings-absence-needs-a-positive-control` — the oracle-control marker
  must be found in the same scan that reports other markers absent. A strings
  scan that finds nothing has two explanations, and only a found positive
  control removes one of them.

`rc = 0` is not evidence anywhere in this harness. Every step that should
produce a file is asked whether the file exists and is non-empty
(`produced()`), because a step that exits clean and produces nothing is a
failure with a good exit code.

One bug this discipline caught during development: `run()` originally used
`execFileSync`, which only returns stderr on the throwing path. The observer's
`refusing to install` goes to stderr *with rc 0*, so the red control silently
recorded an empty message and reported `passed=false`. It is `spawnSync` now.

## What the recorded run establishes, and what it does not

48 cells: 6 fixtures × 4 opt levels × 2 mitigation settings, `clang-18` only.
Full data in `comparison.json`; the summary is in the parent report.

Does establish, on this fixture set:

- arms ①–③ and ⑤ returned `OUT_OF_SCOPE` in all 48 cells — none of them emits a
  property state at all, in any configuration;
- arm ① is config-invariant, **measured** rather than assumed: one distinct
  report across all 8 cells of every fixture;
- arms ⑦ and ⑧ agreed on the property state in 48/48 cells, and arm ⑧ named a
  pass in the 8 cells where one was responsible while arm ⑦ named none in any
  cell. The agreement is on *state*; the whole difference is *attribution*, so
  agreement here is not cross-validation of either arm.

Does **not** establish:

- anything about `gcc-13`. The manifests list it on the compiler axis; this
  lane fixed the compiler at `clang-18` so that every arm saw one toolchain,
  and arms ⑦/⑧ are clang-specific in any case.
- anything about Alive2's behaviour. It was never run here.
- anything at all about arm ⑨.
- generalisation beyond six small hand-written fixtures. These were built to
  make specific losses happen; they are not a sample of anything.
- that arm ⑦ is safe to use in place of arm ⑧. Two endpoints cannot see a loss
  that was later undone and will report `PRESENT` for a property that spent
  most of the pipeline deleted. No fixture here exercises that, so it is a
  known blind spot that this run did **not** measure.

## Files

| | |
|---|---|
| `arms.mjs` | the nine arms, their scopes, and the two vocabularies |
| `lib/observer-log.mjs` | reader for the `PropertyObserver` TSV (field lists transcribed from `History.h`, not guessed from a sample) |
| `lib/ir-effect.mjs` | arm ⑦'s endpoint comparator |
| `run-comparison.mjs` | the runner |
