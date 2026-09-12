# repair-loop

Asks the question that comes after `../ai-generated`: when the compiler removed
a wipe a model wrote, can a repair loaded into **the same compiler** bring it back
— and does the **same observation** that found the removal say so?

The loop has three legs, and this directory is the third:

| leg | what | where |
|---|---|---|
| find | differential compilation over model-written C, stock toolchain, `clang-18` and `gcc-13` | `../ai-generated` |
| repair, clang | WipePin, an out-of-tree LLVM pass plugin that marks zero-fill `llvm.memset` intrinsics volatile in the selected functions | `compiler/llvm-repair/` |
| repair, gcc | WipePinGcc, a GCC plugin that puts a volatile `asm` barrier naming the buffer after every zero-fill `__builtin_memset` in the selected functions | `compiler/gcc-repair/` |
| confirm | the find step's verdict code, re-run with the plugin loaded | here |

One run drives one compiler. The vendor is read from the basename of `--cc`
(`lib/vendor.mjs`): a `clang`, `clang-N` or `…-clang-N` spelling loads the
plugin with `-fpass-plugin=<so>` and holds its record to `component: "WipePin"`;
a `gcc`, `gcc-N`, `g++-N` or `…-gcc-N` spelling loads it with `-fplugin=<so>` and
holds the record to `component: "WipePinGcc"`. Any other basename is refused
(exit 4) rather than guessed at. The tracked find-step rows are keyed by
compiler name (`clang-18`, `gcc-13`), and the baseline is looked up by the
`--cc` basename exactly as typed: a basename the rows hold no erasure row for
(`gcc`, even where it is a symlink to gcc-13) would leave every baseline without
a tracked verdict, so it is refused before any cell (exit 5, naming the
compilers the rows do hold; `--write-data` included). No spelling is mapped to
another. Everything below — the cell, the per-span
layer, the controls, surgicality, the plan, configguard — is the same code for
both; where gcc behaves differently it is said in the section it affects.

The find step's tracked result is what there is to repair. For the removable
idiom (a plain `memset` a compiler may delete), the tracked rows say:

| `WIPE_ELIMINATED`, removable idiom (133 files) | `-O0` | `-O1` | `-O2` | `-O3` | `-Os` |
|---|---|---|---|---|---|
| `clang-18` | 0 | 62 | 113 | 113 | 113 |
| `gcc-13` | 0 | 108 | 108 | 108 | 108 |

and no elimination in any other idiom, for either compiler (401 clang-18 cells,
432 gcc-13 cells). Those are the find step's numbers, read from
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

"On" adds the plugin argument — `-fpass-plugin=<so>` for clang, `-fplugin=<so>`
for gcc — and nothing else to the command line. Both plugins read the same
four variables and are steered by environment only: `WPIN_OUT` (a record path unique to that
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

**The gcc cells are built with glibc's fortifying headers, and the clang cells
are not.** Ubuntu's gcc-13 predefines `_FORTIFY_SOURCE=3` whenever it optimises;
clang-18 does not predefine it at all; `FLAGS` does not set it, so it does not
equalise it. The find step's gcc rows were built the same way, so the baseline
is like for like; the two vendors are not. Every run measures it instead of
assuming it — `-dM -E` with the cells' own `FLAGS` at each level — and prints it
in the results header and the manifest (`preflight.fortify`); in the subset run
below it read `-O0 (not defined), -O1 3, -O2 3, -O3 3, -Os 3` for gcc-13 and
`(not defined)` at every level for clang-18. What it changes for the repair:
under the fortifying headers a `memset` in the source is a call to the header's
`gnu_inline` wrapper when WipePinGcc runs. GCC keeps that call a
`BUILT_IN_MEMSET`, so it is pinned like any other (the barrier follows the call
and survives its inlining); a `bzero` is a call to the header's `bzero` wrapper,
which is not a memset and is not pinned (see *Where the repair cannot reach*).

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
`SEPARATE_RUN`, `UNSUPPORTED_VENDOR`, `NOT_ATTEMPTED` — see *Where the repair
cannot reach*.

### What the plugin's record is for, and what it is not

The record never decides survival. Survival is decided by comparing assembly,
exactly as in the find step. The record is read for two things only: that the
repair **ran**, on the functions it was asked about, in the configuration it was
loaded into; and whether it **changed** anything (`pinnedCount`), which is what
separates `RETAINED` from a survival the plugin did not cause.

Each plugin seals the record as the other native components do
(`interfaces.md` §5: `evidenceDigest` over everything but `context`): WipePin
with the same `Record.cpp` the IR observer uses, WipePinGcc with its own
`src/Canon.cpp` (a GCC plugin cannot link libLLVM), calibrated against the
shared digest vectors. The reader re-derives that digest with
`compiler/evidence/canon.mjs`, which shares no code with either C++ writer, so a
record edited after its compile is refused (`digest-mismatch`) rather than
believed.

`lib/pin-record.mjs` reads it strictly, and reads **`wipe-pin-v2` only** (a `v1`
or `v0` record is refused like any other wrong shape). One reader serves both
repair plugins: `component` is `WipePin` (the LLVM plugin) or `WipePinGcc` (the
GCC plugin), and the caller says which one it loaded (`expect.component`; this
runner passes the component of the vendor its `--cc` names) — a record from the
other one is `wrong-compile`. The fields v1 added stay: `pinned[].followedByUse`
(`true`/`false`/`null`), `resolution[].exact` (`true`/`false`/`null`),
`resolution[].linkage` (a string or `null`). The top-level `toolchain` object
is now read exactly: `digest`, `packages` and exactly one compiler key — `clang`
for `WipePin`, `gcc` for `WipePinGcc` — whose value is the version the plugin
was built against; `packages` is exactly `[{name: "llvm" | "gcc", version: <the
same version>}]`; `digest` is the SHA-256 of the canonical serialisation of
`{<compiler key>, packages}` and is re-derived (`toolchain-digest-mismatch`
otherwise). `toolchain` is inside the record's own digest too. The optimisation
pair is compared with the flag through the component's own table
(`OPT_LEVELS[component]`; the `WipePinGcc` column is gcc-13's measured
`optimize`/`optimize_size` from `compiler/gcc-repair/README.md`, which for `-O0`
… `-Oz` are the same pairs as LLVM's; gcc's `-Ofast` and `-Og` are in neither
table, and this runner never passes them). Unknown or missing fields, a count
that is not a non-negative integer, a `module` that is a path rather than a
basename, any other `schemaVersion`, a dry run with mutations, and a record whose
component, optimisation pair, scope, module or request list does not match the
compile that was supposed to write it — each is a refusal, and a refusal is
`BROKEN_REPAIR`.

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

On gcc the same exception applies at `-O1` and above, and is not needed at
`-O0`: gcc-13 at `-O0` still hands an unreferenced `static` function to the
pass, so the helper stays `resolved` (linkage `internal`) in the wipe-deleted
unit. Measured in the subset run below, on `fable_E_aeskey_r1` (`secure_wipe`)
and `opus_E_dbpass_r2` (`secure_bzero`): WipePinGcc's `wo` record reads
`resolved` at `-O0` and `not-in-module` at `-O1`, `-O2`, `-O3`, `-Os` (8 cells),
where clang reads `not-in-module` at all five levels (10 cells). The rule is not
special-cased per vendor: it tolerates exactly the shape it always did, and on
gcc at `-O0` that shape does not occur.

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
  otherwise — which is also what a plugin of the other vendor does: measured,
  WipePin's `.so` given to `--cc gcc-13` exits 5 with `cc1: error: cannot load
  plugin …libWipePin.so: … undefined symbol:
  _ZN4llvm17PreservedAnalyses14AllAnalysesKeyE`, and WipePinGcc's `.so` given
  to `--cc clang-18` exits 5 with `error: unable to load plugin
  '…libWipePinGcc.so': 'Could not load library …: undefined symbol:
  _ZN8opt_pass5cloneEv'`); a module-scope compile must produce a record the reader accepts
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
| `controlUntouched` | functions scope only: the body of `vgctl_control` is the same with and without the plugin, in both units, once gcc's `.L<n>` label names are canonicalised (below). It is not a selected function. |
| `noPinNoChange` | for every plugin-on compile whose record pinned nothing, the **full** listing equals the plugin-off one — so an analysis invalidation or pass-order side effect anywhere in the unit would show, not only in the target. Checked for `w`, `wo` and the no-wipe files. |

Any violated check makes the run exit 2.

**Label names on gcc.** gcc numbers its local code labels, `.L<n>`, with one
counter for the whole translation unit, in emission order. A pin that gives the
target one label more or fewer therefore renumbers every `.L<n>` in the
functions emitted after it — the control among them — with not one instruction
changed there. Measured on `fable_N_token_r3` at `-O1`, `-O2`, `-O3`: the
control's body with the plugin differed from the one without it in exactly two
lines, `jne .L12` / `.L12:` against `jne .L13` / `.L13:` (at `-O2`, `.L15`
against `.L14`); the unit-wide diff shows the extra labels in the target. Compared
as raw text that read as a `controlUntouched` violation, which it is not. So the
control's bodies are compared after `canonicalLocalLabels` (`lib/surgicality.mjs`),
which renames each `.L<digits>` in order of first appearance and touches nothing
else — a branch that now goes elsewhere, or a label that moved, still differs.
clang names its labels per function (`.LBB<f>_<n>`, `.Ltmp<n>`, `.LCPI…`), which
the pattern does not match, so on clang the check is the one it always was.
Where the renaming was needed for the check to hold, the row says so
(`controlUntouchedRenumberedOnly`) and the results count it: 3 wipe cells in the
gcc subset run, 0 in the clang one.

The same counter means the find step's own `verdictOf`, which compares target
bodies as text, can read two bodies that differ only in label names as
`WIPE_SURVIVED`. This lane does not change the verdict; it reports where that
happened (`labelsOnly: {baseline, repaired}` in the rows, and a per-level count
in the results): for the baseline, a find-step `WIPE_SURVIVED` that is a
renumbering; for a `RETAINED` cell, a repair that is only a renumbering, listed
by id. Both were 0 in the subset runs. The per-span verdicts are not checked
this way.

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
  The oracle also does not know `rep stos`, which is how gcc-13 writes a zero
  fill at `-Os`: in the gcc subset run all 4 `-Os` `RETAINED` cells read not
  `PRESENT` in `w/on` through the oracle. So rows carry a second, separately
  labelled reading, `effectWRepStos: {off, on}` — a zeroed `%eax`, then `rep
  stos`, in the target body — made by `repStosZeroFill` from
  `compiler/gcc-repair/scripts/lib/asm-presence.mjs` (imported; it is the find
  step's `controlPresent` fallback applied to any function). The results print,
  per level, how many of the oracle's `w/on` misses the rep-stos reading finds (4
  of 4 at gcc `-Os` in the subset), and never add it to the oracle's count. The
  positive control's own `-Os` reading goes through the find step's fallback
  already; the results say how many control readings did (23 at gcc `-Os`, 0 on
  clang, in the subset runs).
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
- **Cross-vendor coverage**, one line (`crossVendorCoverage` in
  `lib/summaries.mjs`). "Found" is, per compiler, the tracked find-step
  `WIPE_ELIMINATED` erasure cells over the selected files and levels; "reversed"
  is a found cell whose repair row is `RETAINED`. A run measures one compiler, so
  its own count comes from its own rows, and each other compiler's from that
  compiler's **tracked** repair rows file (`data/r2-repair-rows.json` for
  clang-18, `data/r2-repair-rows-gcc-13.json` for gcc-13), read when present,
  with its sha256 and whether it passes `fullRunCheck` (`lib/vendor.mjs`: one
  compiler, functions scope, no dry run, no target suffix, a row for every
  erasure file of the corpus at every level — what `--write-data` writes). An
  example, from a gcc-13 subset run; the counts are that run's and the sha256
  is whatever the tracked clang-18 file's is when a run reads it (here
  `d87e7f6a…`, the v1 rows at `main` `c7971ce`, not the file tracked now):

  ```
  eliminations reversed / found: gcc-13 16/16 (this run), clang-18 12/12 (tracked repair rows
  compiler/eval/repair-loop/data/r2-repair-rows.json, sha256 d87e7f6a…, a full --write-data run), total 28/28
  ```

  With no file the other compiler reads `-/G (not measured: no tracked repair
  rows for gcc-13)` and the total says how many found cells nobody measured —
  "not measured" is never printed as `0`. A file that is not a full run is
  counted where it has rows, and the line says `NOT a full --write-data run:
  <why>`; a file that cannot be read counts nothing and says why. The line
  therefore reflects the other compiler's tracked file as it was when this run
  read it; its sha256 pins which one.

### The pin plan: find → fix

Every run writes `<out>/pin-plan.json`. It is the artifact that turns the find
step's observation into a repair request: one entry per file, with `{id, fn,
helpers, opts, reason}`, where `opts` are the levels at which the cell baseline is
`WIPE_ELIMINATED` (`reason: "cell"`) or `hiddenElimination` is true (`reason:
"span"`). At those levels the repair to load is `WPIN_TARGET_FNS = [fn,
...helpers]`. Files with no such level are left out. The plan is built from
plugin-off observations only, so it is the same in a red-control run. It names
the compiler it was observed with (`cc`), and `--plan` refuses a plan written
for another one (exit 5): gcc-13 and clang-18 lose different wipes at different
levels.

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
without a reported loss. The same labelling puts 24 of the 26 `both` files in
that idiom for an initialising `memset` beside a non-removable wipe
(`../ai-generated/README.md`, *initialiserLike*); their cells read
`ALREADY_SURVIVED` in this lane either way.

It misses wipes the other way round too (`../ai-generated/README.md`, under the
idiom table): a volatile pointer declared without an initialiser, a volatile
array zeroed by a loop, a volatile loop in a macro. One such file has cells in
this lane's counts: `haiku_S_seedphrase_r3`, labelled `removable` with one span,
its error-path `memset`, while its normal path is wiped by a volatile loop
`wipeSpans` does not see. Its seven eliminated cells (`clang-18` `-O2`..`-Os`,
`gcc-13` `-O1`..`-Os`, among the 401 and 432) are that `memset` gone on the error
path, the only wipe there, and each is `RETAINED` with one site pinned; the loop
needed no repair. The six files the find step reads as writing no wipe, for the
same reason, are no-wipe cells here as well.

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

Each plugin runs early in its compiler's middle end: WipePin at the start of the
LLVM optimisation pipeline, on IR; WipePinGcc on GIMPLE directly after `cfg`,
before `ssa`, `einline` and `dse1`. That fixes what they can and cannot see, and
each family gets a line in the results rather than an absence.

- **authz** — `NO_LOSS_OBSERVED`. The tracked rows show `-DNDEBUG` changing the
  target body in 0 of 712 compiling configurations: models write
  `if (...) return -1;`, not `assert`. There is no loss to repair, which is a
  different statement from "out of reach". Had there been one, it would be out
  of reach: an `assert` the preprocessor removed never becomes IR.
  `test/stage-gate.test.mjs` pins this sentence to the tracked data.
- **configguard** — `OUT_OF_REACH_PREPROCESS`. Every tracked `DEFAULT_DIFFERS`
  file for the run's own compiler at `-O2` (81 for `clang-18`, 83 for `gcc-13`)
  is compiled three times, with that compiler and its plugin: default macros with the
  plugin off, default macros with the plugin on in module scope, and every macro
  the file mentions defined. The row carries the measured booleans:
  `pluginLeftDefaultBodyUnchanged` (the observable half of "cannot bring back a
  defence the preprocessor removed"), `pluginDefaultEqualsEnabled` (the direct
  form of the claim), and `defaultDiffersReproduced` (the tracked verdict,
  re-observed). A plugin that pins a real memset in the target function will
  change the default body; that is reported as measured, and it is still not a
  restored defence. Nothing is planned here, and that is a decision rather than
  an unfinished item: bringing such a defence back means defining the macro,
  which is a choice of build configuration made before the compiler sees the
  file, not a repair made inside it. Which way each file's default build falls is
  already the find step's `configguard` direction table.
- **the other compiler** — `SEPARATE_RUN`, one line with its tracked cell
  count: a clang run says gcc-13's cells are measured by a run with `--cc
  gcc-13` (WipePinGcc, `-fplugin=`), and a gcc run says the same of clang-18.
  `UNSUPPORTED_VENDOR` is still the word for a compiler in the tracked rows
  that no repair plugin loads into; for the r2 rows, which know only clang-18
  and gcc-13, it no longer occurs.
- **nullcheck, signedovf** — `NOT_ATTEMPTED`. Neither family is in this corpus,
  and the loss there is a folded comparison, not a removed store.

Within the erasure family, what WipePin (clang) does not pin, by construction:

- a wipe that reaches IR as anything other than a zero-fill `llvm.memset`
  intrinsic in a selected function. The record counts the memset-shaped ones it
  saw and left alone (`unhandled.libcallMemset`, `memsetChk`, `nonZeroFill`,
  `atomicMemset`, `inlineWrapperMemset`), and the results print their totals.
  The last is the `_FORTIFY_SOURCE` shape: the target calls clang's
  `memset.inline` wrapper, whose body holds the `__memset_chk`, so nothing in the
  target is an intrinsic and the wipe can still be removed. clang-18 does not
  predefine `_FORTIFY_SOURCE` and `FLAGS` does not set it, so the clang cells
  are built without it and all five totals are 0 there;
- a zeroing loop that a later pass would turn into a memset: at the pipeline
  start it is still a loop;
- anything after the translation unit. The observation is the `-S` listing of one
  unit; linking is not in the loop. Link-time optimisation is measured beside it,
  by `tools/lto-probe.mjs` (`tools/LTO.md`): the pin made at compile time holds
  through a full and a thin LTO link of one object, and WipePin loaded only on
  the link line never runs its pass there. A wipe helper in another unit, which
  only an LTO link can inline, is measured on a generated fixture rather than on
  this corpus, by the `xtu` cells of the fixture loop
  (`compiler/llvm-repair/README.md`).

What WipePinGcc (gcc) does not pin — `compiler/gcc-repair/README.md`, *What it
does not handle*, measured on its fixture loop; what matters here:

- anything that is not a zero-fill `__builtin_memset` call in a selected
  function once `cfg` has run. Counted, as on clang: a call to a `memset` that is
  not the builtin (`-fno-builtin`; `libcallMemset`), a `__builtin___memset_chk`
  whose object size is not a constant (`memsetChk`), a non-zero or non-constant
  fill (`nonZeroFill`); `atomicMemset` and `inlineWrapperMemset` name LLVM shapes
  and are always 0 on gcc. Under the fortifying headers every gcc cell at `-O1`
  and above is built with, a source `memset` is the header's `gnu_inline`
  wrapper, which GCC keeps a `BUILT_IN_MEMSET` and which is pinned;
- **`bzero`**: under those headers, at `-O1` and above, the target calls the
  header's `bzero` wrapper, which is not a memset and has no counter. The record
  says nothing to pin and the wipe is gone. In the r2 corpus no file wipes with a
  plain `bzero(` call (0 calls; the 18 files that mention `bzero` spell
  `explicit_bzero`, which `wipeSpans` labels nonremovable and which needs no pin,
  or name a helper `secure_bzero`), so no cell here is of that shape;
- `= {0}`: clang lowers it to a zero-fill memset, which WipePin pins as an
  initialiser; GCC lowers it to an aggregate assignment, which is not a site;
- a wipe written as stores, a memset a later pass creates, a wipe in a helper
  the request does not name, and a call through a function pointer — as on clang;
- anything after the translation unit. WipePinGcc refuses to install when loaded
  into the LTO back end (`-fplugin` on an `-flto` link line). Link-time
  optimisation is measured beside the loop by `tools/lto-probe-gcc.mjs`
  (`tools/LTO.md`, *gcc-13*), for one object per `-flto -shared` link: the pin
  made at compile time holds through the link in all 108 cells the tracked rows
  score eliminated at each of `-O1`, `-O2`, `-O3` and `-Os`, and WipePinGcc on the
  link line is refused twice per link and changes neither the assembly nor the
  shared object. In each of those cells the stock wipe is already gone from the
  object cc1 writes (read back with `lto-dump-13`), and the 25 removable-idiom
  wipes that do reach the link at `-O2` still survive it, so the pin was carried
  through gcc's LTO link but never met an elimination the link itself performs.

## Re-running

Needs the compiler on the path and its plugin built — `clang-18` with WipePin,
`gcc-13` with WipePinGcc (a GCC plugin loads only into the GCC it was built
against, so build it with `g++-13`); this lane is developed under WSL
(Ubuntu 24.04). Records, the manifest, the rows and `pin-plan.json` go to the
directory given by `--out`, which belongs outside the repository. Build scratch
goes to `_build/` here, which is ignored. The per-span layer adds two compiles
for every removable span of every multi-span cell; the run prints how many
pairs before it starts.

```bash
# the two plugins
cmake -S compiler/llvm-repair -B <build>/llvm-repair -G Ninja -DLLVM_DIR=$(llvm-config-18 --cmakedir)
ninja -C <build>/llvm-repair                                  # -> libWipePin.so
cmake -S compiler/gcc-repair -B <build>/gcc-repair -G Ninja -DCMAKE_CXX_COMPILER=g++-13
ninja -C <build>/gcc-repair                                   # -> libWipePinGcc.so

# the measurement, one compiler per run
node compiler/eval/repair-loop/run-repair-loop.mjs --plugin <build>/llvm-repair/libWipePin.so --out <lab dir>
node compiler/eval/repair-loop/run-repair-loop.mjs --cc gcc-13 --plugin <build>/gcc-repair/libWipePinGcc.so --out <lab dir>

# the red controls, each into its own lab directory (add --cc gcc-13 and the gcc plugin for gcc)
node compiler/eval/repair-loop/run-repair-loop.mjs --plugin <so> --out <dir> --dry-run
node compiler/eval/repair-loop/run-repair-loop.mjs --plugin <so> --out <dir> --target-suffix __absent

# the tracked data: only a full functions-scope run over all five levels is accepted
node compiler/eval/repair-loop/run-repair-loop.mjs --plugin <so> --out <dir> --write-data
node compiler/eval/repair-loop/run-repair-loop.mjs --cc gcc-13 --plugin <gcc so> --out <dir> --write-data

# find -> fix as a user runs it: pin only what the previous run's pin plan names
node compiler/eval/repair-loop/run-repair-loop.mjs --plugin <so> --out <dir2> --plan <dir>/pin-plan.json
node compiler/eval/repair-loop/run-repair-loop.mjs --plugin <so> --out <dir3> --plan <dir>/pin-plan.json --dry-run

# followedByUse site by site across the levels, module scope, dry run (lab only, never data/)
node compiler/eval/repair-loop/tools/fbu-levels.mjs --plugin <build>/llvm-repair/libWipePin.so --out <dir4>
node compiler/eval/repair-loop/tools/fbu-levels.mjs --cc gcc-13 --plugin <build>/gcc-repair/libWipePinGcc.so --out <dir5>
```

`tools/fbu-levels.mjs` compiles every erasure-family file at every level with
the plugin in module scope as a dry run, joins each site to its `-O0` reading
on (file, function, index) with the line as a second key, and lists every
site whose `followedByUse` differs, by direction, and every site that does not
join; it runs its own controls (`-O0` twice; every level again without the
line flag). A plugin of an older schema is read with `--reader` naming the
`lib/pin-record.mjs` of its own commit. The measurements are in
`compiler/llvm-repair/README.md` and `compiler/gcc-repair/README.md`.

`--write-data` writes `data/r2-repair-rows.json` and `data/r2-repair-results.txt`
for `clang-18` — the names the tracked clang data has always had — and
`data/r2-repair-rows-<cc>.json` and `data/r2-repair-results-<cc>.txt` for any
other `--cc` (`r2-repair-rows-gcc-13.json` for gcc-13; `dataFileNames` in
`lib/vendor.mjs`). One name
per compiler, so a run with one compiler can never overwrite another's file, and
a second clang (say `clang-19`) does not write over clang-18's.

`--plan` compiles only the (file, level) cells the plan names, each with exactly
the names it lists, and refuses a plan whose names no longer match this tree's
find step, or that was written for another compiler (exit 5). A planned cell
whose loss does not reproduce plugin-off (`STALE`) or does not come back with the
plugin (`NOT REPAIRED`) makes the run exit 2. It is refused with `--write-data`
and in module scope.

Options: `--cc` (default `clang-18`; the vendor is read from the basename),
`--scope functions|module`, `--opts` (comma list, default all five), `--files`
(comma list of basenames or globs), `--rows` (default the find step's tracked
rows), `--conc` (default 8).

Do not run two instances at once, whatever the compiler: they share `_build/`.

Exit codes: `0` run complete and every integrity check held · `2` run complete,
but a baseline disagreed with the tracked rows, a surgicality check was
violated, a red control did not give its designed answer, or the preflight's
refusal checks failed (with `--write-data`, that last one is refused before any
cell) · `3` nothing was selected · `4` bad arguments, including a `--cc` whose
basename names neither clang nor gcc · `5` the compiler, the plugin (a plugin of
the other vendor fails to load, see *Controls*), the shared verdict module, the
effect oracle or the rep-stos reading could not be used, the tracked rows hold
no erasure row for the `--cc` basename (before any cell), the module-scope
preflight record was refused (before any cell), a `--plan` was refused, or a
text about to be written carried an absolute path. Outside the red controls the
exit code says nothing about outcomes: a measurement run in which every cell is
`BROKEN_REPAIR` exits 0, and the results say why.

Unit tests need no compiler:

```bash
node --test compiler/eval/repair-loop/test/*.test.mjs
```

## Results

`clang-18` 18.1.3 (Ubuntu), x86-64, the plugin built from `compiler/llvm-repair/`
(`wipe-pin-v2`, `libWipePin.so` sha256 `db3298cf…73a4c8`, the same bytes from two
independent builds). Full functions-scope run over all five levels; the rows and
the rendered table are `data/r2-repair-rows.json` and `data/r2-repair-results.txt`.
The plan-driven run and the red controls are not tracked; their numbers below
are from runs made with the same plugin bytes on the same tree, and were run
again on 2026-09-12 with those bytes, giving the same numbers.

These rows were first recorded with the `wipe-pin-v1` plugin (`aa7329c3…f0a66`)
and re-recorded with v2. Against the v1 rows (the file as it was at `main`
`c7971ce`), all 1881 rows have the same outcome, baseline and repaired verdict,
the listings are the same (the rows hold 6810 listing slots: 6790 digests, all
equal between v1 and v2 because v2 emits the same code, and 20 `null` slots, the
`wo/off` and `wo/on` compiles of the 2 files whose ablation does not compile, at
each of the five levels), and the span verdicts are the same. What moved is `recordW.followedByUseCount` in 12 rows —
`fable_N_token_r3`, `sonnet_N_token_r1` and `sonnet_S_pwverify_r1` at `-O1`
to `-Os` — where v1 read the cleanup dispatch's infeasible edge as a later use
(`compiler/llvm-repair/README.md`): per level 58/62/62/62/62 in v1, 58 at every
level in v2.

**The find step reproduces.** Plugin off, every wipe cell agrees with the tracked
find-step row: 1605/1605, and the 195 no-wipe cells are `NO_WIPE_WRITTEN` there
too.

**Every clang-18 elimination the find step reported is reversed** — at the find
step's own, cell-level granularity (gcc-13's 432 are reversed by WipePinGcc; see
*Results, gcc-13*). The per-span view below finds eliminations that granularity
hides, and the plugin retains those too.

**find -> fix -> confirm, driven by the plan.** Replaying the full run's
`pin-plan.json` with `--plan` — 132 files, 464 planned cells, the plugin loaded
nowhere else: the 401 cells planned because the cell is eliminated are all
`RETAINED`; the 63 planned because a span is eliminated on its own all have that
span retained; 0 planned cells failed to reproduce their loss plugin-off, 0 failed
to come back. The same plan with `--dry-run`: 0 of 401 and 0 of 63 (red control
`HELD`). A plan with one function name changed is refused (exit 5).

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
  record by record: 11 of the 12 sites pinned in them are ones the plugin marks
  `followedByUse` (initialiser-like; that hint can over-approximate, see the
  plugin README), `opus_N_pinpad_r2` among them; the 12th (`opus_E_pwverify_r2`,
  in the helper `secure_wipe`) writes through a pointer argument, so the plugin
  cannot say (`null`). The `-O1` 25 were not read one by
  one. None of these is a repair, and none is counted as one. Across the run the
  plugin flags `followedByUse` on 295 listed sites (`pinned[]`, which also lists
  sites already volatile in the source; 311 with v1, the 16 being the four
  error-path sites above at four levels), and 290 of them were actually pinned:
  the other 5 are the one already-volatile site of the no-wipe file
  `haiku_E_pinpad_r1`, at each of the five levels. The results print both
  counts (`listed sites …` and `of them actually pinned …`; the rows carry
  `followedByUseCount` and `pinnedFollowedByUseCount`). No record names a
  non-exact target definition.
- **Pin plan:** 132 files — the 113 whose cell is eliminated at some level plus
  the files with only a hidden elimination.
- **Cross-vendor coverage:** eliminations reversed / found: clang-18 401/401
  (this run), gcc-13 432/432 (read from the tracked gcc-13 rows), total
  **833/833**.
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
- **configguard, `-O2`:** the tracked `DEFAULT_DIFFERS` result re-observed in
  81/81 files; with the plugin loaded in module scope the default build equals
  the all-macros build in **0/81** — the plugin does not bring back a defence the
  preprocessor removed. It left the default target body unchanged in 80/81; in
  the exception (`opus_E_debugdump_r3`) the module-scope record pins 4 memsets
  and the target body changes, still without becoming the enabled build's.

A second, independent instrument agrees on the lane's hand-written fixture: see
`compiler/llvm-repair/README.md` (the IR observer reads the erasure subject
`LOST` at `DSEPass` without the plugin and `PRESENT` with it, at `-O2` and `-O3`).

### Results, gcc-13

`gcc-13` 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), x86-64, the plugin built from
`compiler/gcc-repair/` with g++-13 (`wipe-pin-v2`, component `WipePinGcc`,
`libWipePinGcc.so` sha256 `a023b047…47ba1b`, the same bytes from two
independent builds). Full functions-scope run over all five levels; the rows and
the rendered table are `data/r2-repair-rows-gcc-13.json` and
`data/r2-repair-results-gcc-13.txt`. `_FORTIFY_SOURCE` as the run measured it:
not defined at `-O0`, `3` at `-O1`..`-Os`. The plan-driven run and the red
controls are not tracked; their numbers below are from runs made with the same
plugin bytes on the same tree, and were run again on 2026-09-12 with those
bytes, giving the same numbers. The subset numbers quoted in the sections above
come from a 16-file development run and are not this section.

**The find step reproduces.** Plugin off, every wipe cell agrees with the tracked
gcc-13 find-step row: 1605/1605, and the 195 no-wipe cells are
`NO_WIPE_WRITTEN` there too.

**Every gcc-13 elimination the find step reported is reversed**, at the find
step's cell-level granularity:

| removable idiom (133 files) | `-O0` | `-O1` | `-O2` | `-O3` | `-Os` |
|---|---|---|---|---|---|
| eliminated without the plugin | 0 | 108 | 108 | 108 | 108 |
| `RETAINED` | 0 | **108** | **108** | **108** | **108** |
| `ALREADY_SURVIVED` | 133 | 25 | 25 | 25 | 25 |
| `PIN_INEFFECTIVE` / `PIN_NOT_APPLIED` / `BROKEN_REPAIR` / `REGRESSED` / `SURVIVED_WITHOUT_PIN` | 0 | 0 | 0 | 0 | 0 |

The nonremovable (162 files) and `both` (26) idioms are `ALREADY_SURVIVED` in
every cell, apart from the 2 nonremovable files whose ablated form does not
compile (`NOT_SCORED`).

- **find -> fix -> confirm, driven by the plan.** The full run's `pin-plan.json`
  (131 files, 524 planned cells) replayed with `--plan`: the 432 cells planned
  because the cell is eliminated are all `RETAINED`; the 92 planned because a
  span is eliminated on its own all have that span retained; 0 failed to come
  back. The same plan with `--dry-run`: 0 of 432 and 0 of 92 (red control
  `HELD`).
- **Per span:** in `RETAINED` cells every removable span also survives on its own
  with the plugin, 146/146 at each of `-O1`..`-Os`. Cells scored
  `WIPE_SURVIVED` in which a span is individually eliminated without the plugin:
  0/23/23/23/23 at `-O0`..`-Os` (the same 23 files at every level, listed in the
  results file), and the plugin retains all 92. Per-span plugin-on records valid
  835/835.
- **Corroboration** by the effect oracle, `RETAINED` cells with the effect
  `PRESENT` in `w/on`: 96/108 at each of `-O1`..`-O3` and 25/108 at `-Os`. Every
  miss has `rep stos` in the target body, which the oracle does not know: the 12
  at `-O1`..`-O3` are the 256-byte seed buffers, the 83 at `-Os` are gcc's
  `-Os` zero fill. That reading is printed beside the oracle's and never added to
  it; the outcome does not depend on either (it is `verdictOf`'s differential
  comparison).
- **Labels.** gcc numbers its `.L<n>` labels across the whole unit, so a pin in
  the target renumbers the positive control's labels: `controlUntouched` held in
  1595 cells, 93 of them only after the labels were renamed in order of first
  appearance (`lib/surgicality.mjs`). Target bodies that differ only in label
  names: 0 at every level, baseline and `RETAINED` alike.
- **Surgicality, 0 violations:** `ablatedUnchanged` 1595 held, `controlUntouched`
  1595 held, `noPinNoChange` held for `w` 815, `wo` 1595, no-wipe 195.
- **Records:** 3395/3405 valid; the 10 missing are the wipe-deleted compiles of
  the 2 files whose ablation does not compile. 1240 sites pinned, `unhandled.*`
  all 0, no no-wipe file pinned, 290 listed sites flagged `followedByUse` and
  285 of them actually pinned (the other 5: the one site of `opus_N_token_r3`,
  which WipePinGcc records as already pinned, at each of the five levels), no
  non-exact target. The static-helper exception was applied in 616 cells (at
  `-O1`..`-Os` only: at `-O0` gcc still emits the uncalled `static` helper, and
  the plugin resolves it).
- **A pin changed a listing where the find step reported no loss:**
  156/28/50/50/49 at `-O0`..`-Os`; with a hidden elimination 0/23/23/23/23.
  None is counted as a repair.
- **Red controls, both `HELD`** (`-O2`, functions scope): `--dry-run` gives
  `RETAINED` 0 and `PIN_INEFFECTIVE` 108 with every `noPinNoChange` held and
  `hiddenRetained` 0 of 23; `--target-suffix __absent` gives `BROKEN_REPAIR` in
  every scorable cell.
- **configguard, `-O2`:** the tracked `DEFAULT_DIFFERS` result re-observed in
  83/83 files; with the plugin in module scope the default build equals the
  all-macros build in **0/83**. It left the default target body unchanged in
  81/83; in `opus_E_debugdump_r1` (2 pinned) and `opus_E_debugdump_r3` (4 pinned)
  the body changes, still without becoming the enabled build's.
- **Cross-vendor coverage:** gcc-13 432/432 (this run), clang-18 401/401 (read
  from the tracked clang-18 rows, sha256 `05d1240e…912ce96`), total **833/833**.
  Each results file names the other vendor's tracked rows by sha256; the rows are
  deterministic (a second `--write-data` run of each vendor wrote the same bytes),
  so the two files' references agree.

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
- **Not a statement about any other compiler.** Two compilers, one version
  each (`clang-18` 18.1.3, `gcc-13` 13.3.0, both from the Ubuntu 24.04
  archive), one target (x86-64), the flags in `FLAGS` — which do not equalise
  `_FORTIFY_SOURCE`, so the gcc cells are built with glibc's fortifying headers
  at `-O1` and above and the clang cells are not. The two repairs are different
  mechanisms (a volatile `llvm.memset` against a volatile `asm` barrier), and a
  number for one is not a number for the other. Link-time optimisation over this
  corpus only as far as `tools/LTO.md` measured it: one object per link,
  `-shared`, with lld 18 for clang and with GNU ld 2.42 through gcc's linker
  plugin, at gcc's default partitioning, for gcc-13; the helper-in-another-unit
  case, which only a link can create, on one generated fixture per vendor in the
  fixture loops' `xtu` cells.
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
| `run-repair-loop.mjs` | the runner: preflight, the four-compile cell, the per-span compiles, no-wipe files, configguard, results, manifest, pin plan; one compiler per run, clang or gcc |
| `lib/vendor.mjs` | the vendor from the `--cc` basename, its plugin flag and record component, the per-compiler data file names, the `_FORTIFY_SOURCE` reading, the full-run check of a tracked rows file, the refusal of a `--cc` the tracked rows do not name; pure |
| `lib/outcome.mjs` | the outcome table and its precedence, and the red-control grading; pure |
| `lib/pin-record.mjs` | strict reader for the `wipe-pin-v2` record, from either repair plugin (`WipePin` or `WipePinGcc`); `followedByUseCounts` (listed vs actually pinned) |
| `lib/spans.mjs` | span entries, `hiddenElimination` / `hiddenRetained`; pure, verdicts injected. The per-span plan (`spanPlan`) is the find step's, re-exported from `../ai-generated/lib/ablation-cell.mjs` |
| `lib/summaries.mjs` | per-span counts, corroboration (oracle and rep-stos readings), listing-changed-without-loss, label renumbering, cross-vendor coverage, the pin plan; pure |
| `lib/provenance.mjs` | listing digests, the rows-file label, the absolute-path scan |
| `lib/preflight.mjs` | the preflight's refusal checks; pure |
| `lib/plan.mjs` | `--plan`: reading a pin plan, matching it to this tree and compiler, the plan-driven summary; pure |
| `lib/surgicality.mjs` | the surgicality checks, and the `.L<n>` label canonicalisation they use; pure, `bodyOf` injected |
| `lib/stage-gate.mjs` | the out-of-reach families; pure |
| `lib/corpus.mjs` | the selection: the corpus files, what each one is, the erasure family; imported by the runner and by `tools/fbu-levels.mjs`; pure |
| `pin-families.json`, `lib/pin-families.mjs`, `PIN-FAMILIES.md` | the per-property pin-family table: one row per (property, disappearance shape, repair candidate), its claim definitions and its validator; pure |
| `tools/intervene.mjs` | the second repair candidate: delete the attributed pass from the pipeline clang printed and replay under opt and llc, reading the IR and the asm channel; lab output only, never `data/` |
| `test/pin-families.test.mjs` | recomputes every measured number in `pin-families.json` from the tracked rows, and re-runs the intervention gate over every claim that uses it |
| `tools/lto-probe.mjs`, `tools/lib/lto.mjs`, `tools/LTO.md` | the LTO probe: the same cell judged on the assembly a full or thin LTO link writes; lab output only, never `data/` |
| `tools/lto-probe-gcc.mjs`, `tools/lib/lto-gcc.mjs` | its gcc-13 twin: the same cell judged on the assembly lto1 writes for an `-flto -shared` link, WipePinGcc records read through `lib/pin-record.mjs`, the compile-stage GIMPLE read back with `lto-dump-13`; lab output only (`tools/LTO.md`, *gcc-13*) |
| `tools/fbu-levels.mjs`, `tools/lib/fbu.mjs` | `followedByUse` at `-O1`..`-Os` against `-O0`, site by site, both vendors; lab output only, never `data/` |
| `test/*.test.mjs` | unit tests, no compiler |
| `data/` | written only by `--write-data` after a full run: `r2-repair-rows.json` / `r2-repair-results.txt` for clang-18, `r2-repair-rows-gcc-13.json` / `r2-repair-results-gcc-13.txt` for gcc-13 |

## Licence

Apache-2.0 WITH LLVM-exception, like the rest of `compiler/`. See
`compiler/LICENSE`.
