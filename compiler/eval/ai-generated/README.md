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
| build verdicts | 244 | **4,650** |

Corrected 2026-09-12: the round-2 build-verdict count said **4,660** from the day
it was written, and no measurement ever produced that number. `data/r2-build-rows.json`
holds 4,689 rows, of which exactly 4,650 carry a `(cc, opt)` cell -- the other 39 are
`NO_WIPE_WRITTEN` rows for files in which no wipe was written at all, so there was
nothing to build a cell for. The lane's own generated results file says the right
number and always did: `data/r2-results.txt` line 3 reads
`生成 720 / ビルド判定 4650 構成`. The rows file has had 4,689 rows since its only
commit, so this was a transcription error in this table rather than drift between the
prose and a moving dataset. It is recorded rather than silently patched because a
denominator is the one number a rate table cannot be wrong about, and
`eval/actuarial/` now derives rates from these rows. 

A **second** transcription of the same count was found on 2026-09-12 and corrected
with it: the Re-running section below said `build-analyze.mjs` writes **4,698**
rows. The file has 4,689. Two independent mistypings of one number, in one README,
neither of which any test could see -- which is why `eval/actuarial/` recomputes the
denominator from the rows rather than reading it from prose, and why its tests
assert the recomputed value rather than a literal.

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

The table is `wipeSpans`' labelling, which counts every zero-fill `memset` in
the target function as a wipe, including one that initialises a buffer before
it is filled. Read with `initialiserLike` (below) over every removable span, 26
of these files wrote no removable wipe: in 24 of the 26 `both` files and in 2
`memset` files (`opus_N_pinpad_r2`, `sonnet_S_privkey_r3`) every removable span
zero-fills a buffer that is used afterwards. Each of those spans was also read
by hand in the source, and each is followed by the buffer's fill (`read_keypad`,
`fgets`, `load_seed_phrase`, `strncpy`, `get_premaster`, ...); WipePin's
`followedByUse` at `-O0`, which can err the same way as the label, says the
same of all 31 of their removable spans. The 24 `both` files
zero-fill the buffer, fill it, and wipe it with a non-removable idiom. With the
26 moved out of the removable columns, *chose removable* would read **56.7% /
33.3% / 20.8%** (N / S / E): the gap between the neutral framing and the other
two is wider than the table shows, 23.4 points to S instead of 11.7 and 35.9 to
E instead of 28.3. A post-hoc reading beside the table, which stays as
measured; `test/initialiser-reading.test.mjs` recomputes it from the corpus and
the tracked rows.

The labelling also misses wipes, the other way round. `wipeSpans` does not see a
non-removable wipe of three shapes: a pointer declared `volatile` without an
initialiser and pointed at the buffer later (`volatile unsigned char *vp; … vp =
secret;` and then `vp[i] = 0` in a loop), a buffer that is itself `volatile`
zeroed by a plain loop, and a volatile loop inside a macro (`SECURE_MEMZERO(sk,
64)`). Read by hand, seven files wipe that way and are counted as something
else: the six the table counts as *no wipe* under S and E, which is every entry
of that column outside N (`haiku_E_otpsecret_r3`, `haiku_E_premaster_r1`,
`haiku_E_premaster_r2`, `haiku_S_premaster_r3`: the first shape;
`haiku_E_pinpad_r1`: the second; `haiku_E_privkey_r1`: the third), and
`haiku_S_seedphrase_r3`, a `memset` file with one span, whose error path wipes
with a `memset` before `return -1` and whose normal path with a loop of the
first shape. `sonnet_S_privkey_r3`'s real wipes are the first shape too. None of
the 33 N files in the *no wipe* column holds a `volatile` or a zeroing loop.
With both readings, the *no wipe* column would be **34 / 0 / 0** (N / S / E;
`opus_N_pinpad_r2`, which wipes nothing afterwards, joins N), and *chose
removable* stays at the figures above, since the seven move only between the
non-removable, `both` and *no wipe* columns. `lib/missed-wipes.mjs` is the
reading: it answers, for one function body, which of the three shapes it holds,
and nothing else. `haiku_S_seedphrase_r3`'s seven
`WIPE_ELIMINATED` cells (`clang-18` `-O2`..`-Os`, `gcc-13` `-O1`..`-Os`) are its
error-path `memset` gone, the only wipe on that path, while the normal path
stays wiped; labelled `both`, it would be judged with every wipe deleted at
once, the volatile loop included. The tables and every verdict stay as
measured; `test/missed-wipes.test.mjs` pins the seven to the corpus and the
tracked rows.

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

Judged one wipe span at a time as well, with the same `verdictOf`, the
`memset` row has a removable wipe gone in **199/266** cells at `-O1` and
**260/266** at `-O2`, `-O3` and `-Os`: the eliminated cells above plus the
cells scored `WIPE_SURVIVED` in which a removable span, ablated on its own, is
`WIPE_ELIMINATED`. That is a second count beside the table, which stays the
protocol's cell-level criterion; see *Per-span supplement* below and
`data/r2-span-results.txt`. Moving the two `memset` files that wrote no
removable wipe (above) out of the row leaves every numerator as it is — both
read `WIPE_SURVIVED` at every level on both vendors — and the denominator at
262: 221/262 at `-O2`. Moving `haiku_S_seedphrase_r3` to the `both` row as well
(above) takes its two `-O2` cells from both sides: 219/260.

The `both` row is 26 generations that `wipeSpans` labels as writing a removable
wipe *and* a non-removable one; in 24 of them the removable one is an
initialising `memset`, and one `memset` file, `haiku_S_seedphrase_r3`, belongs
in the row (both above). Ablation deletes every wipe in the target function at once,
so a surviving `volatile` write keeps the body different and the cell reads
SURVIVED — correctly, since the secret does get erased, but it says nothing
about the `memset` those files also contain. Do not fold that row into either
of the two above.

Elimination begins at `-O1`, saturates at `-O2`, and `-Os` is no safer. clang-18
and gcc-13 agree closely (71.1% vs 67.9% at `-O2`).

The two vendors are not built with the same headers, and `FLAGS` does not make
them so: Ubuntu's gcc-13 defines `_FORTIFY_SOURCE=3` whenever it optimises, and
clang-18 defines nothing (`-dM -E` with `FLAGS`: `#define _FORTIFY_SOURCE 3` at
each of gcc-13's `-O1`..`-Os`, nothing at clang-18's `-O2`). So every gcc-13
cell above at `-O1` and beyond was built with glibc's fortifying wrappers.
Measured afterwards by `lib/fortify-check.mjs`, with this lane's own
`wipeSpans`/`ablateSpans`/`verdictOf` and `-U_FORTIFY_SOURCE
-D_FORTIFY_SOURCE=0` added to both compiles of every erasure file with a wipe
span: at gcc-13 `-O1`, `-O2`, `-O3` and `-Os`, 0 of 321 verdicts change at
each level, and the default build re-derives the tracked verdict in 321/321.
The flags do reach the code: the file-as-written listing differs between the
two builds in 313 of 321 cells at each level, and in 28/12/12/14 of them
(`-O1`/`-O2`/`-O3`/`-Os`) by more than gcc's unit-wide `.L` label numbering.
clang-18 at `-O2`, run as a control, also gives 0 changes, and that says
nothing: clang predefines no `_FORTIFY_SOURCE`, and its listing differs in 0 of
321 cells. The asymmetry does not move these numbers; it does matter to a repair
that pins memset calls (see `../gcc-repair/README.md`).

```bash
cd compiler/eval/ai-generated/lib
node fortify-check.mjs --cc gcc-13 --opts -O1,-O2,-O3,-Os --out <lab dir>
node fortify-check.mjs --cc clang-18 --opts -O2 --out <lab dir>    # the control
```

It writes to the lab directory only (an `--out` inside the repository is
refused) and exits 2 when a default verdict does not re-derive the tracked one.

End to end at `-O2`, over **720 opportunities — 360 erasure files each measured
on two compilers**, which is a different 720 from the 720 generations above and
is counted per (file, vendor): 10.8% never wrote a wipe, 57.9% wrote one that
survived, **30.7% wrote one the compiler removed**. Confirmed absent from the
artifact: **41.5%**. Under the neutral framing that rises to **78.3%**. Read
with the two corrections under the idiom table, *never wrote a wipe* would be
68/720 (9.4%): the twelve cells of the six files with a wipe `wipeSpans` does
not see leave it, and `opus_N_pinpad_r2`'s two join it. The other shares are
not recomputed here.

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
What it adds is a second measurement beside them, in its own data: the rows,
`data/r2-span-rows.json`, and the results text the run printed from them,
`data/r2-span-results.txt`.

**Why.** Ablation deletes every wipe span of the target function at once. When
the target body holds two zero-fills, deleting both can change the code for a
reason that has nothing to do with the wipe a reader cares about — an
initialiser that matters, or a loop laid out differently once an error-path wipe
is gone — so the cell reads `WIPE_SURVIVED` although a wipe the model wrote,
deleted on its own, changes nothing: it was already gone. The repair loop
(`../repair-loop/README.md`, *The per-span view*) found 63 such `clang-18` cells
in 19 files; `gcc-13` had not been looked at before this supplement, and the
`both` row above says nothing about the `memset` those 26 files contain for
exactly this reason.

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
every vendor whose repair-loop rows file exists — `clang-18`:
`../repair-loop/data/r2-repair-rows.json`, `gcc-13`:
`../repair-loop/data/r2-repair-rows-gcc-13.json` (named in
`lib/span-summary.mjs` `REPAIR_ROWS_FILES`, spelled as the repair loop's
`dataFileNames` spells them; this lane imports none of its code) — each span
verdict must equal the repair loop's plugin-off verdict for the same (vendor,
id, level, span index) wherever that loop measured the span alone (`spans[].off`
with `source: "span"`), and the two `hiddenElimination` flags must agree; the
repair rows are read as data. Any disagreement, or a vendor in which no span
could be compared although spans were measured, exits 2 and lists the ids. A
vendor with no repair rows file is printed `not cross-checked (no repair rows)`
and never counted as held; that alone does not fail the run, but it refuses
`--write-data`. `--repair-rows <cc>=<path>` names another file for one vendor.
The check was shown to fail on a lab copy of the repair rows with every span
index shifted by one (`clang-18`), and on a lab copy of the `gcc-13` rows whose
span verdicts were rotated by one position (71 mismatches at `-O2`, exit 2).

**Results.** The full run (`--write-data`, both vendors, all five levels, stock
`clang-18` 18.1.3 and `gcc-13` 13.3.0; `data/r2-span-rows.json`, 1550 rows, and
`data/r2-span-results.txt`): 155 multi-span files, 770 measured cells (77 files
with a removable span × 2 vendors × 5 levels), 1670 per-span verdicts. A second
full run into another lab directory wrote both files byte for byte the same.
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
`memset` row, the cells in which a removable wipe is gone — scored
`WIPE_ELIMINATED`, or a hidden elimination — are **199/266** at `-O1` (tracked
170) and **260/266** at `-O2`, `-O3` and `-Os` (tracked 221). Counted strictly
span by span instead (a one-span cell by its verdict, a multi-span cell only by
its spans ablated alone), `-O1` gives 181, not 199: 18 `clang-18 -O1` cells, in
18 files, score `WIPE_ELIMINATED` while every removable span, ablated alone,
reads `WIPE_SURVIVED`. In the lab listings of the run, each of those 37
single-span ablations adds zero stores (an `xorps` and `movaps`) to the body:
with every `memset` in the source, `clang-18 -O1` emits none of them; with any
one deleted, stores for the others come back. A per-span `WIPE_SURVIVED` can
therefore be another wipe reappearing rather than this one surviving; `-O2`,
`-O3` and `-Os` have no such cell. The `both` row's 0/52 hides 2
(`clang-18 -O2`, `-Os`), 1 (`clang-18 -O3`) and 1 (`gcc-13 -O1`..`-Os`) cells
in which the removable span is gone on its own; in `fable_E_dbpass_r3`
(`clang-18 -O2`, `-Os`) that span is initialiser-like (a `memset` before
`strncpy`), so it is not a lost wipe. The tracked cell-level numbers stay the
find step's criterion; these are the same `verdictOf` at a finer grain, beside
them.

Re-derived cell verdicts agreeing with the tracked rows: 770/770. Cross-check
against the repair rows, per vendor: `clang-18` 835 span verdicts compared, 835
agree, 385 `hiddenElimination` flags compared, 0 disagree; `gcc-13` the same,
835/835 and 385 with 0 disagreeing. Each vendor's check is printed in
`data/r2-span-results.txt` beside the sha256 of the repair rows it was checked
against (`--write-data` writes nothing unless both held); a repair rows file
re-recorded after that has not been checked against until `--write-data` runs
again. The ids of every hidden elimination are in the same file, per vendor and
level. gcc-13 had no per-span view before this run; every one of its 22
removable multi-span cells scored `WIPE_SURVIVED` at `-O1`..`-Os` holds a span
that is eliminated on its own.

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
the line tables change no recorded site). The numbers below are from a
`label-check.mjs` run, whose output goes to the lab only and is not tracked,
with WipePin `wipe-pin-v2` sha256 `e89e07fd…cbad6` (the build before the
link-time line). `followedByUse` at `-O0` is the same in every v2 build: a
re-run with `db3298cf…73a4c8`, the build the repair loop's results quote, gave
the same counts and the same disagreement. Only a span that is an `llvm.memset` in
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

Over every span of every wipe file, not only the two named above, the label
finds 26 files whose every removable span is initialiser-like: those two, which
`wipeSpans` labels `removable`, and 24 of the 26 it labels `both`
(`test/initialiser-reading.test.mjs` recomputes the list from the corpus;
`label-check.mjs` prints it). The plugin agrees on every one of their 31
removable spans: `followedByUse` true for 31, false for 0, null for 0 (a
`label-check.mjs` run with `db3298cf…73a4c8`, lab only). What that does to the
idiom table is under *Results*, beside it; no verdict and no tracked number
moves.

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
node build-analyze.mjs            # 4,689 rows -> ../data/r2-build-rows.json
node configguard-direction.mjs    #           -> ../data/r2-configguard-direction.json
python3 analyze.py                # tables    -> ../data/r2-results.txt

# the per-span supplement (stock compilers; rows, results and scratch in the lab dir)
node build-spans.mjs --out <lab dir> [--cc clang-18,gcc-13] [--opts -O2] [--files <globs>]
node build-spans.mjs --out <lab dir> --write-data    # the full run only -> ../data/r2-span-rows.json, ../data/r2-span-results.txt
# initialiserLike against the repair plugin's followedByUse (clang-18 -O0)
node label-check.mjs --plugin <libWipePin.so> --out <lab dir>
# does gcc-13's predefined _FORTIFY_SOURCE move a verdict? (lab output only)
node fortify-check.mjs --cc gcc-13 --opts -O1,-O2,-O3,-Os --out <lab dir>
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
- The 20 `ABLATION_DID_NOT_COMPILE` configurations are **two erasure files at
  five levels in both arms**, and the two have different causes. Measured
  2026-09-12 by running `wipeSpans`/`ablateSpans` over the corpus rather than by
  reading them.
  - `fable_E_seedphrase_r3` (`export_wallet`): the wipe is a `volatile` pointer
    declaration plus a loop, and the file ends the block with
    `__asm__ __volatile__("" : : "r"(p) : "memory")`. Deleting the declaration
    leaves that barrier naming an undeclared `p`. The ablated form is
    supposed to be the same program without the wipe; here it is not a program.
  - `haiku_S_privkey_r1` (`sign_with_private_key`): `wipeSpans` returns the span
    `[323,382]` **twice**, and `ablateSpans` splices from the end of the list
    without sorting or de-duplicating, so the same region is replaced twice and
    the second splice cuts a neighbouring token in half
    (`/* ablated */;ey_file(keyfile, sk);`). This is a defect in the shared
    instrument, not in the model's code.
  Both are `nonremovable` in every span, so neither is in the removable-idiom
  table that carries the headline. **The blast radius was measured rather than
  assumed**: over all 720 files, span lists are out of order in 0 and overlap or
  repeat in exactly 1 — `haiku_S_privkey_r1`. So no other cell in this corpus can
  have been ablated into corrupted-but-compilable source, which is the failure
  that would have been silent. This one is loud: it does not compile, it scores
  nothing, and it is excluded from the denominator. It is recorded and **not
  repaired**, because de-duplicating the span list would move rows inside a
  dataset that is already quoted; repairing it is a re-measurement, not an edit.

## Files

| path | what |
|---|---|
| `PROTOCOL-r1.md` | pilot protocol, fixed before round 1 ran |
| `PROTOCOL-r2.md` | measurement protocol, with round 1's four detector defects and their fixes recorded as amendments |
| `scenarios.json` | 20 scenarios: family and target function per key |
| `generated-corpus/r1`, `r2` | the 840 generations, named `<model>_<framing>_<scenario>_r<rep>.c` |
| `lib/build-analyze.mjs` | ablation across 5 levels x 2 vendors, plus the authz and configguard differentials |
| `lib/ablation-cell.mjs` | one ablation cell as an importable module with no side effects — wipe finding, ablation, compile, `verdictOf`, and `spanPlan` for the per-span view — so another lane reaches its verdict through the same code; `test/ablation-cell.test.mjs` covers it without a compiler |
| `lib/build-spans.mjs` | the per-span supplement: each removable span of a multi-span file ablated alone, both vendors, five levels, with the repair-rows cross-check for every vendor that has repair rows |
| `lib/span-summary.mjs` | the supplement's rows, integrity checks, cross-check, hidden-elimination counts; pure, `test/span-summary.test.mjs` |
| `lib/span-label.mjs` | the lexical `initialiserLike` label and `initialiserOnly`; pure, `test/span-label.test.mjs`, `test/initialiser-reading.test.mjs` |
| `lib/missed-wipes.mjs` | the three non-removable shapes `wipeSpans` does not see, read from a function body; pure, `test/missed-wipes.test.mjs`. A report beside the find step: no verdict uses it |
| `lib/label-check.mjs` | `initialiserLike` against the repair plugin's `followedByUse` at `-O0`; lab output only |
| `lib/fortify-check.mjs` | every erasure verdict with the default flags and with `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0`, against the tracked rows; lab output only; pure parts in `test/fortify-check.test.mjs` |
| `lib/compare-rows.mjs` | `<a.json> <b.json>`: compares two build-row files as multisets of rows (runs are in pool completion order), exit 0 iff equal |
| `lib/configguard-direction.mjs` | which side of the `#ifdef` the default build lands on |
| `lib/classify-lexical.py` | round 1's independent lexical classifier |
| `lib/analyze.py`, `lib/analyze-r1.py` | the tables |
| `data/` | every verdict row and the rendered results |
| `data/r2-span-results.txt` | the per-span supplement's results text, written with `data/r2-span-rows.json` by the same full `build-spans.mjs --write-data` run; `test/span-readme.test.mjs` pins the per-span numbers this README quotes from tracked data to both files and to `data/r2-build-rows.json` (not those from lab-only runs, such as `label-check.mjs`'s) |
