# repair-loop

Asks the question that comes after `../ai-generated`: when the compiler removed
a wipe a model wrote, can a repair loaded into **the same compiler** bring it back
— and does the **same observation** that found the removal say so?

The loop has three legs, and this directory is the third:

| leg | what | where |
|---|---|---|
| find | differential compilation over model-written C, stock toolchain | `../ai-generated` |
| repair | an out-of-tree LLVM pass plugin that marks zero-fill `llvm.memset` intrinsics volatile in the selected functions | `compiler/llvm-repair/` |
| confirm | the find step's verdict code, re-run with the plugin loaded | here |

The find step's tracked result is what there is to repair. For `clang-18` and
the removable idiom (a plain `memset` a compiler may delete), the tracked rows
say **113 of 133** wipes are `WIPE_ELIMINATED` at `-O2`, `-O3` and `-Os`, 62 at
`-O1`, and none at `-O0`. Those are the find step's numbers, read from
`../ai-generated/data/r2-build-rows.json`; this lane re-derives them as its
baseline and says whether it agrees.

## The four-compile cell

For every erasure-family file and every requested optimisation level, four
compiles with identical flags (`FLAGS` from `../ai-generated/lib/ablation-cell.mjs`,
plus the level):

| | plugin off | plugin on |
|---|---|---|
| **wipe kept** (`w`) | `w/off` | `w/on` |
| **wipe deleted** (`wo`) | `wo/off` | `wo/on` |

```
baseline = verdictOf(w/off, wo/off, fn)
repaired = verdictOf(w/on,  wo/on,  fn)
```

"On" adds `-fpass-plugin=<so>` and nothing else to the command line. The plugin
is steered by environment only: `WPIN_OUT` (a record path unique to that
compile), and `WPIN_TARGET_FNS=<fn>,<helpers...>` in functions scope or
`WPIN_SCOPE=module` in module scope, plus `WPIN_DRY_RUN=1` for the dry-run red
control. Every inherited `WPIN_*` variable is removed before the first compile,
and each record path is deleted before the compile that should write it, so a
record left over from an earlier run can never be read as this one's.

`verdictOf`, `wipeSpans`, `ablateSpans`, `bodyOf`, `controlPresent`, the
positive control and its `CONTROL_EFFECT` are **imported** from the find step,
and `observeEffect` from `../second-vendor/lib/asm-oracle.mjs`, not copied. A
repair judged by a private copy of the oracle would be judging itself, and the
two copies would drift. If either module is missing the runner stops with exit 5;
it has nothing to fall back on, by design.

The helpers named in `WPIN_TARGET_FNS` are the ones `wipeSpans` finds — the same
list the find step uses to decide which statements to delete. A wipe routed
through a function that list does not name is not selected in functions scope;
module scope exists for that.

## The per-span view

The four-compile cell deletes **every** wipe span of the target function at once,
because that is the find step's criterion, and the cell outcome below keeps it
unchanged. But a cell-level verdict can hide a removed wipe. When the target
body holds two zero-fills, deleting both can change the code for a reason that
has nothing to do with the wipe the reader cares about:

- a memset on an error path plus a trailing memset (`fable_N_token_r3`): deleting
  both changes the loop layout, so the cell reads `WIPE_SURVIVED`, while the
  trailing memset deleted on its own changes nothing — at `-O2` it was already
  gone;
- an initialising memset before the buffer is filled plus a trailing wipe
  (`sonnet_S_pinpad_r1`): the initialiser matters, so deleting both reads
  `WIPE_SURVIVED`, while the trailing wipe alone reads `WIPE_ELIMINATED`.

So for every cell whose `wipeSpans` result has two or more spans, each span of
kind `removable` is ablated **alone** (through the imported `ablateSpans`) into
its own unit, `wo_i`, and compiled plugin off and plugin on with the same flags,
the same plugin environment as the cell's `wo` compiles and its own record path.
The same `verdictOf` then judges it against the cell's own `w` listings:

```
spanOff_i = verdictOf(w/off, wo_i/off, fn)
spanOn_i  = verdictOf(w/on,  wo_i/on,  fn)
```

A cell with exactly one span is not recompiled: ablating its only span *is* the
cell's ablation, so its span verdict is the cell verdict, and the span entry says
so (`source: "cell"`; the row's `spanSource` is `"cell"`). A nonremovable span in
a multi-span cell is listed with `source: "not-measured"` and no verdicts: it is
a store or call the compiler may not delete, and a volatile-pointer declaration
deleted without its loop does not compile. Rows carry
`spans: [{index, kind, off, on, source, recordOk}]` — verdict words only, no
source text.

Two row booleans come from it:

| field | when |
|---|---|
| `hiddenElimination` | the cell baseline is `WIPE_SURVIVED` **and** some removable span, ablated alone, is `WIPE_ELIMINATED` without the plugin |
| `hiddenRetained` | `hiddenElimination`, and **every** such span is `WIPE_SURVIVED` with the plugin |

Neither changes the cell outcome. The cell outcome is the find step's own
criterion and the headline "same observation"; the per-span layer is the same
`verdictOf` at a finer grain, reported beside it.

## Outcomes

`lib/outcome.mjs` is a pure function of the two verdicts, the two plugin
records and whether the control was present in the plugin-on compiles. **First
match wins**, and the order is tested:

| # | outcome | when |
|---|---|---|
| 1 | `NOT_SCORED` | the baseline is not `WIPE_ELIMINATED` or `WIPE_SURVIVED`. A file that does not compile without the plugin is not a broken repair. |
| 2 | `BROKEN_REPAIR` | a record is missing or refused by `lib/pin-record.mjs`; a requested function did not resolve; the two records disagree about being a dry run; or the positive control is not `PRESENT` in either plugin-on compile. Ahead of 3 on purpose: a plugin that breaks the build or blinds the oracle must not read as "not scored". |
| 3 | `NOT_SCORED` | the repaired verdict is not a `WIPE_` verdict although the repair itself is intact. Both verdicts are carried. |
| 4 | `ALREADY_SURVIVED` | survived without the plugin and with it |
| 4 | `REGRESSED` | survived without the plugin, eliminated with it |
| 4 | `RETAINED` | eliminated without the plugin, survived with it, and the wipe-kept record pinned at least one site |
| 4 | `SURVIVED_WITHOUT_PIN` | eliminated without, survived with, but nothing was pinned. **Never counted as `RETAINED`.** Something other than the pin changed the code, and that has to be found before any number is quoted. |
| 4 | `PIN_INEFFECTIVE` | eliminated both ways although something was pinned (or, in a dry run, would have been) |
| 4 | `PIN_NOT_APPLIED` | eliminated both ways, nothing to pin, every requested name resolved |

Lane-level words that are not cell outcomes: `NO_WIPE_WRITTEN` (the model wrote
no wipe; two compiles only), `OUT_OF_REACH_PREPROCESS`, `NO_LOSS_OBSERVED`,
`UNSUPPORTED_VENDOR`, `NOT_ATTEMPTED` — see *Where the repair cannot reach*.

### What the plugin's record is for, and what it is not

The record never decides survival. Survival is decided by comparing assembly,
exactly as in the find step. The record is read for two things only: that the
repair **ran**, on the functions it was asked about, in the configuration it was
loaded into; and whether it **changed** anything (`pinnedCount`), which is what
separates `RETAINED` from a survival the plugin did not cause.

The plugin seals the record as the other native components do (`interfaces.md`
§5: `evidenceDigest` over everything but `context`, written by the same
`Record.cpp` the IR observer uses). The reader re-derives that digest with
`compiler/evidence/canon.mjs`, which shares no code with the C++ writer, so a
record edited after its compile is refused (`digest-mismatch`) rather than
believed.

`lib/pin-record.mjs` reads it strictly, and reads **`wipe-pin-v1` only**: v0 plus
`pinned[].followedByUse` (`true`/`false`/`null`), `resolution[].exact`
(`true`/`false`/`null`), `resolution[].linkage` (a string or `null`) and a
top-level `toolchain` object with exactly `digest` (a string, possibly empty),
`clang` (a string) and `packages` (an array of objects). `toolchain` is inside
the digest. Unknown or missing fields, a count that is not a non-negative
integer, a `module` that is a path rather than a basename, any other
`schemaVersion`, a dry run with mutations, and a record whose optimisation pair,
scope, module or request list does not match the compile that was supposed to
write it — each is a refusal, and a refusal is `BROKEN_REPAIR`.

The counts are tied to the list exactly. `pinned` lists every eligible site (in a
dry run too); a site that was already volatile is listed and in neither count.
Outside a dry run `pinnedCount === wouldPinCount ===` the number of listed sites
not already volatile; in a dry run `pinnedCount` is 0 and `wouldPinCount` is that
number. Anything else is refused. If the plugin grows a field, the reader grows it
in the same change.

One exception to "every requested name resolves", and only one. Ablation deletes
the wipe statement; when that statement was the only call to a `static` helper,
the compiler stops emitting the helper in the wipe-deleted unit, and the plugin
correctly reports it `not-in-module` there. That is ablation working, not a
repair that missed its target. It was first seen in the smoke on a nonremovable
file whose `static secure_wipe` has exactly one caller. The exception applies
only to a name resolved in the `w` record and `not-in-module` in the `wo`
record; the names are kept in the row as `absentAfterAblation` and counted in
the results, so the tolerance is visible.

## Controls

- **The positive control travels in every translation unit**, as in the find
  step: a wipe followed by an opaque read, which no conforming compiler may
  remove. In a plugin-on compile it must be `PRESENT` in both `w/on` and `wo/on`,
  or the cell is `BROKEN_REPAIR`.
- **The baseline is re-derived, not trusted.** Every plugin-off verdict is
  compared with the tracked row for the same `(id, cc, opt)`, and the row
  carries `baselineMatchesTracked` true or false. Neither side is preferred
  silently: a disagreement is listed by id and makes the run exit 2.
- **Preflight, fail-closed**, before any cell: the plugin must load (exit 5
  otherwise); a module-scope compile must produce a record the reader accepts
  (exit 5 otherwise, before any cell: every cell would be `BROKEN_REPAIR`, so
  there is nothing to measure); a compile with `WPIN_OUT` but no target must
  produce no record; and a compile without `WPIN_OUT` must print a refusal and
  still compile. The last is recorded only as whether stderr was empty, because
  its text may carry a path. A record written without a target, an empty stderr,
  or a failed compile there is an integrity failure (`lib/preflight.mjs`): the
  run exits 2, and `--write-data` is refused before any cell.
- **Nothing written carries a path.** The manifest names the plugin as
  `{basename, sha256}` and the baseline rows as `(default)`, a
  repository-relative path, or `(outside the repository)` with the file's
  sha256. Before anything is written, the rows, the manifest, the results text
  and the pin plan are scanned for `/home/`, `/root/`, `/mnt/`, `/Users/` and a
  drive letter (`lib/provenance.mjs`); a hit fails the run with exit 5 and
  nothing goes to `data/` (the lab copies are still written, so the run can be
  debugged).

## Surgicality

Reported beside the outcome, never folded into it. A `RETAINED` cell that fails
one is still `RETAINED` — and is listed. `true` held, `false` violated, `null`
not applicable or not decidable; `null` is never counted as a pass.

| check | what must hold |
|---|---|
| `ablatedUnchanged` | where the wipe-deleted compile pinned nothing, its target body is the same with and without the plugin. The plugin cannot fabricate a wipe. |
| `controlUntouched` | functions scope only: the body of `vgctl_control` is the same with and without the plugin, in both units. It is not a selected function. |
| `noPinNoChange` | for every plugin-on compile whose record pinned nothing, the **full** listing equals the plugin-off one — so an analysis invalidation or pass-order side effect anywhere in the unit would show, not only in the target. Checked for `w`, `wo` and the no-wipe files. |

Any violated check makes the run exit 2.

`pinDelta` (the wipe-kept compile's pin count minus the wipe-deleted one's) is
still carried in every row, but it is **not attribution** and the results no
longer present it as such. Where the wipe-deleted compile pins nothing — which
the full run showed for every scored cell — it is simply the wipe-kept pin
count, which `RETAINED` already requires to be positive, so "`pinDelta > 0` in
every `RETAINED` cell" restates the outcome rule. Nor can it tell an initialising
memset from a wipe when the find step labelled both as spans and the ablation
deleted both. What looks at each span on its own is the per-span view above.

## Beside the outcome

None of these changes an outcome. Each is computed in `lib/summaries.mjs` from the
rows and printed in the results.

- **Per-span counts**, per level: in `RETAINED` cells, how many removable spans
  survive individually with the plugin (`X/Y`; a one-span cell contributes its
  cell verdict), and how many cells the find step scored `WIPE_SURVIVED` hold a
  span that is individually eliminated without the plugin (`hiddenElimination`),
  with how many of those are retained with it (`hiddenRetained`) and their ids.
- **Corroboration.** The effect oracle the find step's `controlPresent` is built
  on (`observeEffect` from `../second-vendor/lib/asm-oracle.mjs`, imported, with
  `CONTROL_EFFECT` imported from `../ai-generated/lib/ablation-cell.mjs`) reads the
  target body of `w/off` and `w/on`; rows carry `effectW: {off, on}`. The results
  count `RETAINED` cells with the effect `PRESENT` in `w/on`, and in `w/off`. The
  `w/off` count is unreliable by construction: the oracle counts any memset call
  or zero store to memory in the body, so an array initialiser (`= {0}`) or an
  initialising memset can read `PRESENT` although the wipe is gone. It is printed
  so that blind spot stays visible, not as evidence.
- **Listing provenance.** Rows carry `listings: {wOff, woOff, wOn, woOn}` (the
  no-wipe rows `{wOff, wOn}`): the sha256 of each full `-S` listing exactly as
  read, `null` where the compile failed. The results print how many were hashed.
- **A pin that changed a listing where the find step reported no loss:**
  `ALREADY_SURVIVED` cells whose wipe-kept compile pinned something and whose
  `w/off` and `w/on` digests differ, per level, split by `hiddenElimination`.
  Where it is true, the change is the repair of a wipe the cell verdict could
  not see; where it is false, the plugin moved code nobody asked it to (for
  example an initialising memset, or the `-O0` memset call that a pinned memset
  replaces with inline stores).
- **Cross-vendor coverage**, one line, computed from the tracked find-step rows
  over the selected files and levels: `eliminations reversed / found: clang-18
  R/F, gcc-13 0/G (no plugin can load), total R/(F+G)`. `F` and `G` are the
  tracked `WIPE_ELIMINATED` erasure cells per vendor; `R` is the `RETAINED` cells
  whose tracked verdict is `WIPE_ELIMINATED`.

### The pin plan: find → fix

Every run writes `<out>/pin-plan.json`. It is the artifact that turns the find
step's observation into a repair request: one entry per file, with `{id, fn,
helpers, opts, reason}`, where `opts` are the levels at which the cell baseline is
`WIPE_ELIMINATED` (`reason: "cell"`) or `hiddenElimination` is true (`reason:
"span"`). At those levels the repair to load is `WPIN_TARGET_FNS = [fn,
...helpers]`. Files with no such level are left out. The plan is built from
plugin-off observations only, so it is the same in a red-control run.

## Limits of the find step's labelling

This lane re-uses the find step's `wipeSpans` and does not fix it. One limit
matters for reading its numbers: **an initialising memset in the target body is
counted as a wipe span.** In `opus_N_pinpad_r2` the only zero-fill is a memset
before the buffer is filled, and nothing is wiped afterwards; in
`sonnet_S_privkey_r3` the real wipes are loops through a pointer declared
`volatile` without an initialiser, which `wipeSpans` does not pair with the
loops, so the initialising memset is the only span. Both are labelled `removable`
with one span, both read `WIPE_SURVIVED` at every level, and in both that verdict
is about the initialiser. Being one-span cells, the per-span view cannot separate
them; they show up, if anywhere, among the cells where a pin changed a listing
without a reported loss.

## Red controls

Each is a run whose correct answer is known in advance, and the answer is
**graded**, not narrated: `gradeRedControl` in `lib/outcome.mjs` prints
`HELD` or `FAILED` with every violating cell, and a failed red control exits 2.
A red control in which no cell had a scorable baseline is `FAILED` as vacuous,
because a control that never ran looks exactly like one that held. None of them
may be written to `data/`; `--write-data` refuses them.

- `--dry-run` — the plugin loads, decides, and mutates nothing. Expected: **no
  `RETAINED` anywhere** (a dry-run record has `pinnedCount` 0, so the most a
  survival can read is `SURVIVED_WITHOUT_PIN`, which would itself be a finding);
  **no `hiddenRetained` anywhere** (a plugin that mutates nothing cannot retain a
  span either); every `noPinNoChange` held, because a plugin that mutates nothing
  must change no byte of any listing; baseline-eliminated cells read
  `PIN_INEFFECTIVE` where something would have been pinned and `PIN_NOT_APPLIED`
  otherwise.
- `--target-suffix <s>` — every requested name gets `<s>` appended, so nothing
  resolves. Expected: `BROKEN_REPAIR` in every cell whose baseline is scorable,
  and `noPinNoChange` held.
- **A plugin that writes no record.** Expected: `BROKEN_REPAIR` everywhere, with
  `record-missing` as the reason. Shown in the smoke with a probe plugin that
  pins but does not report.

`--scope module` is not a red control. It widens the repair to every function,
including the positive control, which is why `controlUntouched` is not
applicable there. It also means the control's own memset is pinned in every
unit, so no record has `pinnedCount` 0 and `ablatedUnchanged` and
`noPinNoChange` are not applicable either: a module-scope run carries no
surgicality evidence at all. Surgicality is measured in functions scope.

## Where the repair cannot reach

The plugin runs at the start of the LLVM optimisation pipeline, on IR. That fixes
what it can and cannot see, and each family gets a line in the results rather
than an absence.

- **authz** — `NO_LOSS_OBSERVED`. The tracked rows show `-DNDEBUG` changing the
  target body in 0 of 712 compiling configurations: models write
  `if (...) return -1;`, not `assert`. There is no loss to repair, which is a
  different statement from "out of reach". Had there been one, it would be out
  of reach: an `assert` the preprocessor removed never becomes IR.
  `test/stage-gate.test.mjs` pins this sentence to the tracked data.
- **configguard** — `OUT_OF_REACH_PREPROCESS`. Every tracked `DEFAULT_DIFFERS`
  file for `clang-18 -O2` is compiled three times: default macros with the
  plugin off, default macros with the plugin on in module scope, and every macro
  the file mentions defined. The row carries the measured booleans:
  `pluginLeftDefaultBodyUnchanged` (the observable half of "cannot bring back a
  defence the preprocessor removed"), `pluginDefaultEqualsEnabled` (the direct
  form of the claim), and `defaultDiffersReproduced` (the tracked verdict,
  re-observed). A plugin that pins a real memset in the target function will
  change the default body; that is reported as measured, and it is still not a
  restored defence.
- **gcc** — `UNSUPPORTED_VENDOR`, one line with the tracked cell count. An LLVM
  pass plugin cannot load into gcc; `--cc gcc-*` is refused.
- **nullcheck, signedovf** — `NOT_ATTEMPTED`. Neither family is in this corpus,
  and the loss there is a folded comparison, not a removed store.

Within the erasure family, what the plugin does not pin, by construction:

- a wipe that reaches IR as anything other than a zero-fill `llvm.memset`
  intrinsic in a selected function. The record counts the memset-shaped ones it
  saw and left alone (`unhandled.libcallMemset`, `memsetChk`, `nonZeroFill`,
  `atomicMemset`, `inlineWrapperMemset`), and the results print their totals.
  The last is the `_FORTIFY_SOURCE` shape: the target calls clang's
  `memset.inline` wrapper, whose body holds the `__memset_chk`, so nothing in the
  target is an intrinsic and the wipe can still be removed. The corpus is built
  without `_FORTIFY_SOURCE`, so all five totals are 0 here;
- a zeroing loop that a later pass would turn into a memset: at the pipeline
  start it is still a loop;
- anything after the translation unit. The observation is the `-S` listing of one
  unit. Linking and link-time optimisation are not in the loop.

## Re-running

Needs `clang-18` on the path and the plugin built; this lane is developed under
WSL. Records, the manifest, the rows and `pin-plan.json` go to the directory given
by `--out`, which belongs outside the repository. Build scratch goes to `_build/`
here, which is ignored. The per-span layer adds two compiles for every removable
span of every multi-span cell; the run prints how many pairs before it starts.

```bash
# the measurement
node compiler/eval/repair-loop/run-repair-loop.mjs --plugin <path/to/libWipePin.so> --out <lab dir>

# the red controls, each into its own lab directory
node compiler/eval/repair-loop/run-repair-loop.mjs --plugin <so> --out <dir> --dry-run
node compiler/eval/repair-loop/run-repair-loop.mjs --plugin <so> --out <dir> --target-suffix __absent

# the tracked data: only a full functions-scope run over all five levels is accepted
node compiler/eval/repair-loop/run-repair-loop.mjs --plugin <so> --out <dir> --write-data
```

Options: `--cc` (default `clang-18`), `--scope functions|module`, `--opts`
(comma list, default all five), `--files` (comma list of basenames or globs),
`--rows` (default the find step's tracked rows), `--conc` (default 8).

Do not run two instances at once: they share `_build/`.

Exit codes: `0` run complete and every integrity check held · `2` run complete,
but a baseline disagreed with the tracked rows, a surgicality check was
violated, a red control did not give its designed answer, or the preflight's
refusal checks failed (with `--write-data`, that last one is refused before any
cell) · `3` nothing was selected · `4` bad arguments · `5` the compiler, the
plugin, the shared verdict module or the effect oracle could not be used, the
module-scope preflight record was refused (before any cell), or a text about to
be written carried an absolute path. Outside the red controls the exit code says
nothing about outcomes: a measurement run in which every cell is `BROKEN_REPAIR`
exits 0, and the results say why.

Unit tests need no compiler:

```bash
node --test compiler/eval/repair-loop/test/*.test.mjs
```

## Results

`clang-18` 18.1.3 (Ubuntu), x86-64, the plugin built from `compiler/llvm-repair/`
(`wipe-pin-v1`, `libWipePin.so` sha256 `aa7329c3…f0a66`, the same bytes from two
independent builds). Full functions-scope run over all five levels; the rows and
the rendered table are `data/r2-repair-rows.json` and `data/r2-repair-results.txt`.
Only the module-scope line below comes from an earlier run with the `wipe-pin-v0`
plugin; v1 changes what the record says, not what the plugin emits (identical
`-S` output on the files and levels compared when v1 was written).

**The find step reproduces.** Plugin off, every wipe cell agrees with the tracked
find-step row: 1605/1605, and the 195 no-wipe cells are `NO_WIPE_WRITTEN` there
too.

**Every elimination the find step reported is reversed** — at the find step's
own, cell-level granularity. The per-span view below finds eliminations that
granularity hides, and the plugin retains those too.

| removable idiom (133 files) | `-O0` | `-O1` | `-O2` | `-O3` | `-Os` |
|---|---|---|---|---|---|
| eliminated without the plugin | 0 | 62 | 113 | 113 | 113 |
| `RETAINED` | 0 | **62** | **113** | **113** | **113** |
| `ALREADY_SURVIVED` | 133 | 71 | 20 | 20 | 20 |
| `PIN_INEFFECTIVE` / `PIN_NOT_APPLIED` / `BROKEN_REPAIR` / `REGRESSED` / `SURVIVED_WITHOUT_PIN` | 0 | 0 | 0 | 0 | 0 |

The nonremovable (162 files) and `both` (26) idioms are `ALREADY_SURVIVED` in
every cell, apart from the 2 nonremovable files whose ablated form does not
compile (`NOT_SCORED`, as in the find step). `-O1` matters: there the loss is
not `DSEPass` (the `-O1` pipeline has none) but later, and the volatile flag
holds it too.

- **Per span** (the same `verdictOf`, one span ablated at a time; cell outcomes
  above unchanged): in `RETAINED` cells, every removable span also survives on
  its own with the plugin — 81/81 at `-O1`, 156/156 at each of `-O2`/`-O3`/`-Os`
  (549/549). Cells the find step scored `WIPE_SURVIVED` in which a span is
  individually eliminated without the plugin: **0/7/19/18/19** at
  `-O0`..`-Os` (63 cells in 19 files), and the plugin retains **all 63**. The
  error-path shape (`fable_N_token_r3`: no zero store left in the target body,
  but deleting both wipes also rotates the loop, so the cell reads "survived")
  and the initialiser-plus-wipe shape (`sonnet_S_pinpad_r1`) are the two this
  layer was added for; the ids are listed in the results file. Per-span
  plugin-on records valid 835/835.
- **`pinDelta` is not attribution** (see *Surgicality*): the wipe-deleted compile
  pinned nothing in any scored cell, so `pinDelta > 0` in the 401 `RETAINED`
  cells only restates that each pinned something.
- **Corroboration** by the effect oracle: `RETAINED` cells with the effect
  `PRESENT` in `w/on`: 401/401; in `w/off`: 101 of 401 (5/32/32/32 at
  `-O1`..`-Os`) — unreliable by construction, see *Beside the outcome*.
- **Listings hashed:** 6790.
- **A pin changed a listing where the find step reported no loss**
  (`ALREADY_SURVIVED`, w pinned > 0, w/off and w/on digests differ):
  158/32/26/25/26 at `-O0`..`-Os`. With a hidden elimination: 0/7/19/18/19;
  without: 158/25/7/7/7. At `-O0` that is the pin turning a `memset` call into
  inline stores (see `compiler/llvm-repair/README.md`). The 7 at `-O2` were read
  record by record: every site pinned in them is one the plugin marks
  `followedByUse` (initialiser-like; that hint can over-approximate, see the
  plugin README), `opus_N_pinpad_r2` among them. The `-O1` 25 were not read one
  by one. None of these is a repair, and none is counted as one.
- **Pin plan:** 132 files — the 113 whose cell is eliminated at some level plus
  the files with only a hidden elimination.
- **Cross-vendor coverage:** eliminations reversed / found: clang-18 401/401,
  gcc-13 0/432 (no plugin can load), total 401/833.
- **Positive control** `PRESENT` in every plugin-on compile that compiled:
  `w/on` 321/321 and no-wipe 39/39 at each level; `wo/on` 319/321 (the 2 files
  whose ablation does not compile).
- **Surgicality, 0 violations:** `ablatedUnchanged` 1595 held, `controlUntouched`
  1595 held, `noPinNoChange` held for `w` 810, `wo` 1595, no-wipe 195.
- **Records:** 3395/3405 valid; the 10 missing are the wipe-deleted compiles of
  the 2 files whose ablation does not compile. `unhandled.*` totals are all 0.
  The static-helper exception above was applied in 770 cells.
- **Red controls, both `HELD`** (`-O2`, functions scope): `--dry-run` gives
  `RETAINED` 0 and `PIN_INEFFECTIVE` 113 with every `noPinNoChange` held;
  `--target-suffix X` gives `BROKEN_REPAIR` in every scorable cell. In the dry
  run the 19 `-O2` hidden eliminations are all still eliminated
  (`hiddenRetained` 0 of 19).
- **Module scope** (`wipe-pin-v0`, all five levels, not tracked): `RETAINED` 62/113/113/113 at
  `-O1`..`-Os`, 0 eliminated cells left unrepaired. It carries no surgicality
  evidence, as explained above.
- **configguard, `-O2`:** the tracked `DEFAULT_DIFFERS` result re-observed in
  81/81 files; with the plugin loaded in module scope the default build equals
  the all-macros build in **0/81** — the plugin does not bring back a defence the
  preprocessor removed. It left the default target body unchanged in 80/81; in
  the exception (`opus_E_debugdump_r3`) the module-scope record pins 4 memsets
  and the target body changes, still without becoming the enabled build's.

A second, independent instrument agrees on the lane's hand-written fixture: see
`compiler/llvm-repair/README.md` (the IR observer reads the erasure subject
`LOST` at `DSEPass` without the plugin and `PRESENT` with it, at `-O2` and `-O3`).

## What this does not claim

- **Not that the code is now secure.** A volatile memset guarantees that the
  store is emitted. It does not remove other copies of the secret — registers,
  spilled stack slots, a caller's buffer, a copy the program made itself — and
  it says nothing about what happens to the memory afterwards.
- **`RETAINED` is the find step's criterion, nothing stronger.** It says the
  target body differs with and without the wipe statement once the plugin is
  loaded. The oracle is differential, not semantic: it does not check that the
  surviving stores write zeros over the secret's bytes.
- **The per-span view is the same criterion at a finer grain, nothing more.**
  `hiddenRetained` says each individually eliminated removable span makes the
  body differ once the plugin is loaded; it inherits every limit of `verdictOf`
  and of `wipeSpans` (see *Limits of the find step's labelling*).
- **The record is not evidence of survival**, and is never used as such.
- **Not a statement about any other compiler.** One vendor, one version
  (`clang-18`), one target (x86-64), the flags in `FLAGS`, no link-time
  optimisation. gcc is not measured at all.
- **Not a statement about code in general.** The corpus is the find step's: one
  model family, synthetic scenarios, one-shot generation. Every caveat in
  `../ai-generated/README.md` carries over unchanged.
- **Not an argument that a compile-time pin is the right fix.** Writing
  `explicit_bzero` or a volatile loop in the source is the repair a reviewer can
  see. This measures whether a toolchain-side mitigation holds when the source
  was not fixed.

## Files

| path | what |
|---|---|
| `run-repair-loop.mjs` | the runner: preflight, the four-compile cell, the per-span compiles, no-wipe files, configguard, results, manifest, pin plan |
| `lib/outcome.mjs` | the outcome table and its precedence, and the red-control grading; pure |
| `lib/pin-record.mjs` | strict reader for the plugin's `wipe-pin-v1` record |
| `lib/spans.mjs` | the per-span plan, span entries, `hiddenElimination` / `hiddenRetained`; pure, verdicts injected |
| `lib/summaries.mjs` | per-span counts, corroboration, listing-changed-without-loss, cross-vendor coverage, the pin plan; pure |
| `lib/provenance.mjs` | listing digests, the rows-file label, the absolute-path scan |
| `lib/preflight.mjs` | the preflight's refusal checks; pure |
| `lib/surgicality.mjs` | the surgicality checks; pure, `bodyOf` injected |
| `lib/stage-gate.mjs` | the out-of-reach families; pure |
| `test/*.test.mjs` | unit tests, no compiler |
| `data/` | written only by `--write-data` after a full run |

## Licence

Apache-2.0 WITH LLVM-exception, like the rest of `compiler/`. See
`compiler/LICENSE`.
