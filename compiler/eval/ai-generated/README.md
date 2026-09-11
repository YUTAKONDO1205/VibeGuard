# ai-generated

Asks the question the rest of `compiler/eval/` cannot: the other lanes measure
whether a security property survives compilation on fixtures **we** wrote. This
one measures it on fixtures a language model wrote, because that is who writes
the C the product is aimed at.

It exists to connect two halves of this repository that had no measured link.
`compiler/` measures where a defence is lost between source and artifact.
`packages/rules/` scans AI-generated code for defences that are wrong at the
source. Nothing until now measured whether the defences a model actually emits
reach the artifact — and the product's own README claims the AI-generated-code
audience while its C rules had never been tested against AI-generated C.

## What was measured

Two rounds. The first is a pilot whose only job was to fix the protocol before
the numbers existed; the second is the measurement.

| | round 1 | round 2 |
|---|---|---|
| generations | 120 | **720** |
| design | 4 models x 3 framings x 5 scenarios x 2 reps | 4 models x 3 framings x **20 scenarios** x 3 reps |
| families | erasure | erasure 10, authz 5, configguard 5 |
| optimisation levels | `-O0 -O2` | `-O0 -O1 -O2 -O3 -Os` |
| build verdicts | 244 | **4,660** |

The three families are the three of the five properties in the paper's state
matrix that a lexical generator can be asked for. Same properties, different
authors: hand-written fixtures there, model output here.

Prompts came in three framings, and the framing is the independent variable that
matters most:

- **N** — the task, with no security word in it at all.
- **S** — the same task, "written securely".
- **E** — the same task, with the property asked for by name ("do not leave the
  secret in memory").

Agents were not told they were being measured. Telling them would have produced
the code we hoped for instead of the code they write.

## The instrument

Survival is decided by **differential compilation**, never by searching the
assembly for a symbol name. The paper's own oracle experiment shows name search
mislabels 6 of 8 configurations, and this corpus reproduces the reason: at `-O1`
and above the wipe survives as inlined stores with no `memset` symbol anywhere.

For each file the wipe statement is deleted and both versions are compiled with
identical flags. If the target function's body is byte-identical, the wipe
contributed nothing to the emitted code and was eliminated. If it differs, it
survived. This needs no binding analysis, which is what makes it usable here:
the zeroing-instruction oracle cannot tell an inlined wipe from an array
initialiser, and that is the defect section 9 of the paper already declares.

`lib/asm-oracle.mjs` is **not** duplicated. This lane imports
`../../second-vendor/lib/asm-oracle.mjs`, so the vendor-neutral reading of a
function body is the same code the second-vendor lane uses.

A positive control travels in every translation unit: the same wipe followed by
an opaque read, which cannot be a dead store. A configuration whose control does
not show its effect is `VERIFICATION_INCOMPLETE`, never `WIPE_ELIMINATED`.
Calling a blind configuration a loss is the shortest path to a manufactured
result.

## Results

Instrument health first, because the numbers are worthless without it: the
positive control was PRESENT in **3,190 / 3,190** scored erasure configurations,
the erasure family had **zero** compile errors, and ablation failed to compile
for 2 of 720 files (unscored, by design). 62 configurations in the authz and
configguard families did not compile — 16 files, mostly a `struct session` the
scenario text left incomplete — and they are dropped from those families'
denominators rather than counted as "no change".

**erasure — the model's choice of idiom (360 generations)**

| framing | `memset` | non-removable | both | no wipe | chose removable |
|---|---|---|---|---|---|
| N neutral | 69 | 18 | 0 | **33** | 57.5% |
| S "securely" | 40 | 64 | 15 | 1 | 45.8% |
| E property named | 24 | 80 | 11 | 5 | 29.2% |

**20 of 720 generations** call `explicit_bzero`, `memset_s` or
`SecureZeroMemory`, and 18 of those 20 do it inside a portability ladder
(`#if defined(__STDC_LIB_EXT1__)` and friends) with a hand-rolled fallback for
the branch that actually compiles here. Only **2** call one unconditionally.
Every other non-removable wipe was hand-rolled — a `volatile` pointer loop, a
`volatile` function pointer to `memset`, or a helper taking a
`volatile`-qualified parameter.

**erasure — survival to the artifact**

| idiom | `-O0` | `-O1` | `-O2` | `-O3` | `-Os` |
|---|---|---|---|---|---|
| `memset` | 0/266 | 170/266 | **221/266** | 221/266 | 221/266 |
| non-removable | 0/324 | 0/324 | 0/324 | 0/324 | 0/324 |
| both | 0/52 | 0/52 | 0/52 | 0/52 | 0/52 |

The `both` row is 26 generations that wrote a removable wipe *and* a
non-removable one. Ablation deletes every wipe in the target function at once,
so a surviving `volatile` write keeps the body different and the cell reads
SURVIVED — correctly, since the secret does get erased, but it says nothing
about the `memset` those files also contain. Do not fold that row into either
of the two above.

Elimination begins at `-O1`, saturates at `-O2`, and `-Os` is no safer. clang-18
and gcc-13 agree closely (71.1% vs 67.9% at `-O2`).

End to end at `-O2`, over **720 opportunities — 360 erasure files each measured
on two compilers**, which is a different 720 from the 720 generations above and
is counted per (file, vendor): 10.8% never wrote a wipe, 57.9% wrote one that
survived, **30.7% wrote one the compiler removed**. Confirmed absent from the
artifact: **41.5%**. Under the neutral framing that rises to **78.3%**.

A caveat on those intervals, and the per-file numbers to read instead. The two
vendors read the same source file, so a (file, clang) and a (file, gcc) verdict
are not independent draws — for the memset idiom they agree in all but a handful
of cells. Every interval quoted in this file and in `data/r2-results.txt` is
computed on the doubled n and is therefore narrower than the true uncertainty.

The honest denominators are per file, and they are half of what the tables say:
360 erasure generations, of which 133 wrote a removable wipe, 162 a
non-removable one, 26 both, and 39 none. Treat the percentages as descriptive
statistics over those 360 files and the intervals as decoration; nothing here is
a hypothesis test.

**authz — 0 / 180 generations used `assert`**, and `-DNDEBUG` changed the emitted
code in 0 of 712 compiling configurations. Models write `if (...) return -1;`. This is a
negative result worth keeping: the paper's `assert`-based authz fixture, whose
defence vanishes in preprocessing in every cell, is **not** representative of
AI-written authorization code.

**configguard — 179 / 180 put the defence behind `#if`/`#ifdef`**, and the
default build differs from the all-macros-defined build in 326 of 666 compiling
configurations. Of the 100 files whose guard could be read through a named
helper, 14 leave the defence **off in the default build** (17 including files
that are mixed across configurations). That is the paper's configguard finding, reproduced on code a
model wrote.

## Per-span supplement

A post-hoc addition, recorded as such in `PROTOCOL-r2.md`'s change history. It
changes **no verdict and no number above**: the erasure tables stay cell-level,
because that is the criterion the protocol fixed and the one the poster quotes.
What it adds is a second measurement beside them, in a second data file,
`data/r2-span-rows.json`.

**Why.** Ablation deletes every wipe span of the target function at once. When
the target body holds two zero-fills, deleting both can change the code for a
reason that has nothing to do with the wipe a reader cares about — an
initialiser that matters, or a loop laid out differently once an error-path wipe
is gone — so the cell reads `WIPE_SURVIVED` although a wipe the model wrote,
deleted on its own, changes nothing: it was already gone. The repair loop
(`../repair-loop/README.md`, *The per-span view*) found 63 such `clang-18` cells
in 19 files. `gcc-13` was never looked at, and the `both` row above says nothing
about the `memset` those 26 files contain for exactly this reason.

**What is measured.** `lib/build-spans.mjs`, stock compilers only, no plugin.
For every erasure file whose tracked rows show two or more wipe spans (155 of
360), for each vendor and level:

```
w      the file as written                 (+ the positive control)
wo     every span ablated                  -> cell   = verdictOf(w, wo)
wo_i   only removable span i ablated       -> span_i = verdictOf(w, wo_i)
```

`FLAGS`, `compile`, `pool`, `wipeSpans`, `ablateSpans`, `verdictOf` and the
positive control are imported from `lib/ablation-cell.mjs`, as is `spanPlan`
(which spans get an ablation of their own), which moved there from the repair
loop so that both lanes plan their per-span compiles with one function. A
nonremovable span is listed and not ablated alone (a volatile-pointer
declaration deleted without its loop does not compile). Of the 155 files, 77
have a removable span (51 `removable`, 26 `both`); the other 78 have only
nonremovable spans and get rows with no compile, since there is nothing to
ablate alone. Rows carry verdict words, ids and booleans only.

A **hidden elimination** is a cell the tracked rows score `WIPE_SURVIVED` in
which some removable span, ablated alone, is `WIPE_ELIMINATED` — the repair
loop's `hiddenElimination`, read against the tracked verdict. It is not counted
as the cell being eliminated: the other span still survives. It says that at
least one wipe statement the model wrote contributed nothing to the emitted
body.

**Checks, every run.** The span count and idiom of every file must equal its
tracked rows', and the re-derived cell verdict must equal the tracked one. For
`clang-18`, each span verdict must equal the repair loop's plugin-off verdict
for the same (id, level, span index) wherever that loop measured the span alone
(`../repair-loop/data/r2-repair-rows.json`, `spans[].off` with `source: "span"`),
and the two `hiddenElimination` flags must agree; the repair rows are read as
data. Any disagreement, or a `clang-18` run in which no span could be compared,
exits 2 and lists the ids. The check was shown to fail on a lab copy of the
repair rows with every span index shifted by one.

**Results.** The full run (`--write-data`, both vendors, all five levels,
`data/r2-span-rows.json`, 1550 rows): 155 multi-span files, 770 measured cells
(77 files with a removable span × 2 vendors × 5 levels), 1670 per-span verdicts.
"Hidden" counts cells of those 77 files.

| vendor | level | cell-level eliminated (tracked, whole family) | hidden eliminations (removable / both) | cell-level + hidden | hidden whose eliminated span is initialiser-like |
|---|---|---|---|---|---|
| `clang-18` | `-O0` | 0 | 0 | 0 | 0 |
| `clang-18` | `-O1` | 62 | 7 (7 / 0) | 69 | 0 |
| `clang-18` | `-O2` | 113 | 19 (17 / 2) | 132 | 1 |
| `clang-18` | `-O3` | 113 | 18 (17 / 1) | 131 | 0 |
| `clang-18` | `-Os` | 113 | 19 (17 / 2) | 132 | 1 |
| `gcc-13` | `-O0` | 0 | 0 | 0 | 0 |
| `gcc-13` | `-O1` | 108 | 23 (22 / 1) | 131 | 0 |
| `gcc-13` | `-O2` | 108 | 23 (22 / 1) | 131 | 0 |
| `gcc-13` | `-O3` | 108 | 23 (22 / 1) | 131 | 0 |
| `gcc-13` | `-Os` | 108 | 23 (22 / 1) | 131 | 0 |

Read against the headline table above, and without changing it: in the
`memset` row, the files in which some removable wipe is gone when judged one
span at a time are **199/266** at `-O1` (tracked 170) and **260/266** at `-O2`,
`-O3` and `-Os` (tracked 221). The `both` row's 0/52 hides 2 (`clang-18 -O2`,
`-Os`), 1 (`clang-18 -O3`) and 1 (`gcc-13 -O1`..`-Os`) cells in which the
removable span is gone on its own; in `fable_E_dbpass_r3` (`clang-18 -O2`,
`-Os`) that span is initialiser-like (a `memset` before `strncpy`), so it is
not a lost wipe. The tracked cell-level numbers stay the find step's criterion;
these are the same `verdictOf` at a finer grain, beside them.

Re-derived cell verdicts agreeing with the tracked rows: 770/770. Cross-check
against the repair rows: 835 span verdicts compared, 835 agree, 385
`hiddenElimination` flags compared, 0 disagree. The ids of every hidden
elimination are printed in the run's results text, per vendor and level. gcc-13
had no per-span view before this run; every one of its 22 removable multi-span
cells scored `WIPE_SURVIVED` at `-O1`..`-Os` holds a span that is eliminated on
its own.

### initialiserLike

A lexical label per span, printed beside its verdict and never folded into it
(`lib/span-label.mjs` holds the exact definition and its limits). A span is
initialiser-like when the object it zeroes is read or written, by the same
name, in text that can run after it in the same function body: from the span
to the first unconditional `return` of an enclosing block (not taken as the end
when a `goto`, `break` or `continue` comes first), plus the back edge of any
enclosing loop that return does not leave. `sizeof`, a release call (`free`,
`munlock`, ...), `p = NULL`, a sibling struct member and an inline-asm barrier
operand are not uses. It cannot see a use through another name, it reads the
text before preprocessing, and it does not model `switch`, `goto` targets or
calls that do not return. It exists because `wipeSpans` labels an initialising
`memset` a wipe span (see `../repair-loop/README.md`, *Limits of the find
step's labelling*): `opus_N_pinpad_r2` and `sonnet_S_privkey_r3`, whose only span
is a `memset` before the buffer is filled, come out initialiser-like, so their
cell verdicts are verdicts about an initialiser (`test/span-label.test.mjs` pins
both).

Cross-checked against the repair plugin's own `followedByUse` at `-O0`, where
the plugin has no cleanup code to over-approximate through (`lib/label-check.mjs`:
`clang-18 -O0`, module scope, dry run, `-gline-tables-only` so that each recorded
site carries a line to match a span on, and a second compile without it to show
the line tables change no recorded site). Only a span that is an `llvm.memset` in
the target function has a site to compare; helper calls and volatile loops have
none. Over 321 files and 575 spans, the 249 removable spans: 244 agree, 1
disagrees, 4 have `followedByUse: null` (the destination is not a stack
object: `haiku_E_aeskey_r1`/`r3` write through a pointer, `opus_S_privkey_r1`
spans 0 and 2 write a parameter); the 326 nonremovable spans have no site. By
design they differ on
an asm barrier: in `opus_N_token_r3` the trailing `memset` is followed only by
`__asm__ __volatile__("" : : "r"(token) : "memory")`, which the plugin counts
as a later instruction touching the buffer and the label does not count as a
use, because it is the idiom that keeps the wipe, not a fill.

## What this changed in the product

Two independent defects in `VG-MEM-006`, both found by running the shipped rule
over this corpus and comparing against the ablation ground truth:

1. **Vocabulary.** The secret-word list had 14 entries. The models named secrets
   `sk`, `pin`, `seed`, `seed_phrase` and `premaster` — none of them in it.
2. **Casts.** The pattern admitted `&secret` but not `(void *)secret`, so
   `memset((void *)password, 0, sizeof password)` was silently unreported even
   though `password` was already in the vocabulary.

Recall on this corpus went from **57.2% to 95.6%**, with **zero** findings on the
162 files that wipe non-removably, zero on the 39 that wipe not at all, zero
regressions, and zero findings against this repository's own tracked sources.

**That 95.6% is in-sample and is not a generalisation.** The second-tier
vocabulary was mined from the misses in this corpus and the false-positive
repairs were fitted to an adversarial pass over the same rule; measuring the
result on the corpus it was derived from reports goodness of fit, not recall on
C the rule has not seen. There is no held-out split, because 720 generations is
not enough to spend half of on one. Quote it as "recovers 95.6% of the wipes
this corpus contains", never as "catches 95.6% of secret wipes".
The 7 remaining misses are `buf`, `buffer`, `hash`, `entered` and `vkey` — all of
them on purpose: a scratch buffer called `buf` is the rule's standing negative
control, and `vkey` is discussed below.

**What the widening had to give back.** An adversarial pass over the new rule —
four attackers, each finding refuted from three independent angles — produced
twelve false positives that this corpus could never have shown, because every
file in it handles a secret. They are now regression tests:

- `vkey` was dropped from the vocabulary entirely. It is the Win32 name for the
  256-byte virtual-key state array `GetKeyboardState()` fills, it has no sibling
  word to veto it, and it was worth two detections in 720 generations.
- `sk` is gated on the file looking like it handles secrets at all, because the
  kernel writes a bare `sk` for a socket and control code writes `Sk` for the
  Kalman innovation covariance, and neither offers a sibling to veto. Applying
  that gate to `pin` and `seed` as well was measured and rejected: it took recall
  to 66.0%, because a keypad file that wipes a `pin` contains no cryptographic
  vocabulary and is exactly the file the rule is for.
- The `pin` and `seed` veto lists grew the words embedded and PRNG code actually
  uses — `relay_pin`, `row_pin`, `scan_pin_history`, `xorshift_seed`,
  `world_seed` — and the veto now matches plurals, since `pin_state` was silent
  while `pin_states` fired.

## Why the corpus is tracked but exempt from the self-scan

`generated-corpus/` holds 840 C files that handle secrets badly on purpose. That
is the same situation as `samples/` and `scripts/fixtures/`, and it gets the same
treatment: a directory-level `--ignore generated-corpus` in
`.github/workflows/security-scan.yml`. Without it the PR gate would fail on
`high` findings that are the entire point of the corpus — the gate would be
reporting that our measured vulnerabilities are vulnerable.

The corpus is tracked rather than regenerated because it cannot be regenerated.
Sampling is not deterministic and the model identifiers are internal and moving;
a protocol plus a seed does not reproduce these 840 files, so discarding them
would discard the evidence for every number above.

## Re-running

```bash
# needs clang-18 and gcc-13 on the path (this lane is developed under WSL)
cd compiler/eval/ai-generated/lib
node build-analyze.mjs            # 4,698 rows -> ../data/r2-build-rows.json
node configguard-direction.mjs    #           -> ../data/r2-configguard-direction.json
python3 analyze.py                # tables    -> ../data/r2-results.txt

# the per-span supplement (stock compilers; rows, results and scratch in the lab dir)
node build-spans.mjs --out <lab dir> [--cc clang-18,gcc-13] [--opts -O2] [--files <globs>]
node build-spans.mjs --out <lab dir> --write-data    # the full run only -> ../data/r2-span-rows.json
# initialiserLike against the repair plugin's followedByUse (clang-18 -O0)
node label-check.mjs --plugin <libWipePin.so> --out <lab dir>
```

`build-spans.mjs` refuses `--write-data` for a subset or a non-default input
before compiling anything, and after the run when a check failed. Exit codes: 0
every check held; 2 a check failed (the ids are listed); 3 nothing selected; 4
bad arguments; 5 a compiler or an input could not be used.

`_build/` is scratch and is ignored. Generation itself is not scripted here: it
was 720 subagent calls, and the protocol records the prompts verbatim so the
design is auditable even though the sampling is not repeatable.

## What this does not claim

- **The generator is an agent, not a bare API.** Every generation carries a
  coding-agent system prompt. It is constant across all cells, so differences
  between models and framings hold; absolute rates may not transfer to a raw API
  call. That is the largest single caveat and it is not resolved here.
- Temperature was not controlled. Repetitions capture whatever nondeterminism
  the system has, not a temperature sweep.
- Scenarios are synthetic and do not represent the distribution of real tasks.
- One-shot generation. Real agent use iterates and reviews; this does not.
- The four models are `haiku`, `sonnet`, `opus` and `fable`, named in every
  filename under `generated-corpus/` and in `data/r2-results.txt`. They are the
  identifiers the runner was invoked with at the time of measurement, and they
  are **one vendor's family** — this is a within-family comparison, and nothing
  here supports a claim about language models in general.
- Per model x framing cells are n=60 in round 2 and n=10 in round 1. Round 1
  intervals are wide and it is a pilot, not evidence.
- The 62 `COMPILE_ERROR` configurations are all in the authz and configguard
  families (16 files, mostly a `struct session` left incomplete by the scenario
  text). They are excluded from those families' denominators. The erasure family,
  which carries the headline result, has none.

## Files

| path | what |
|---|---|
| `PROTOCOL-r1.md` | pilot protocol, fixed before round 1 ran |
| `PROTOCOL-r2.md` | measurement protocol, with round 1's four detector defects and their fixes recorded as amendments |
| `scenarios.json` | 20 scenarios: family and target function per key |
| `generated-corpus/r1`, `r2` | the 840 generations, named `<model>_<framing>_<scenario>_r<rep>.c` |
| `lib/build-analyze.mjs` | ablation across 5 levels x 2 vendors, plus the authz and configguard differentials |
| `lib/ablation-cell.mjs` | one ablation cell as an importable module with no side effects — wipe finding, ablation, compile, `verdictOf`, and `spanPlan` for the per-span view — so another lane reaches its verdict through the same code; `test/ablation-cell.test.mjs` covers it without a compiler |
| `lib/build-spans.mjs` | the per-span supplement: each removable span of a multi-span file ablated alone, both vendors, five levels, with the repair-rows cross-check |
| `lib/span-summary.mjs` | the supplement's rows, integrity checks, cross-check, hidden-elimination counts; pure, `test/span-summary.test.mjs` |
| `lib/span-label.mjs` | the lexical `initialiserLike` label; pure, `test/span-label.test.mjs` |
| `lib/label-check.mjs` | `initialiserLike` against the repair plugin's `followedByUse` at `-O0`; lab output only |
| `lib/compare-rows.mjs` | `<a.json> <b.json>`: compares two build-row files as multisets of rows (runs are in pool completion order), exit 0 iff equal |
| `lib/configguard-direction.mjs` | which side of the `#ifdef` the default build lands on |
| `lib/classify-lexical.py` | round 1's independent lexical classifier |
| `lib/analyze.py`, `lib/analyze-r1.py` | the tables |
| `data/` | every verdict row and the rendered results |
