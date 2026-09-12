# Pin families

`WipePin` is a trick for one shape. This file generalises it into a per-property
catalogue and says, for every other shape the two repair plugins enumerate,
whether anything is measured to bring the property back.

The shape of the argument is borrowed rather than invented: hold many candidate
repairs, put each one against the shape it claims to fix, **measure** which ones
actually make the property come back, keep those, and classify the rest. The
part that does the work is the discarding. A catalogue that lists candidates
without measuring them is a list of hopes, and this repository has a word for
that already — `unmeasured`.

- `pin-families.json` is the table.
- `lib/pin-families.mjs` holds the claim definitions, the table's validator and
  the gate that is allowed to say "never comes back".
- `test/pin-families.test.mjs` **recomputes every measured number in the table
  from the tracked rows in `data/`** and fails on drift — and recomputes the
  counts this document makes about the table itself (how many rows, how many a
  human typed, how many route to a rule that does not cover the shape), which
  were the numbers nothing checked until an adversarial read found two wrong.
- `tools/intervene.mjs` is the second instrument: it deletes a pass from the
  pipeline the compiler actually printed and replays.

## The four words

A row is one repair **candidate** against one disappearance **shape** of one
**property**, and its `status` is exactly one of:

| status | what it means here |
|---|---|
| `measured-retained` | the candidate was run over tracked cells and the property came back. The row cites a claim; the test recomputes it from `data/`. |
| `measured-not-retained` | the candidate was run over tracked cells and the property did **not** come back. Same evidence discipline. |
| `unmeasured` | nothing was run. Often because the corpus contains **no instance of the shape** — which is a statement about this corpus, never about the world. |
| `not-repairable-in-compiler` | the shape does not come back, and the row says on what basis: `measured-here`, `one-lab-run`, or `by-construction` with the stage named. |

Three things are kept apart, because merging them is how a table like this
starts lying (`../../schema/interfaces.md` §3):

- **measured here** — a ratio the drift test recomputes from `data/`.
- **one lab run** — an intervention or a fixture-loop reading that exists but is
  not tracked. It rides along as `labObservation` or `intervention` and **never**
  carries a `measured-*` status. The validator refuses that combination.
- **not looked at** — `unmeasured`, with the reason in the row.

Every ratio is `{num, den}` integers, never a float, as everything else recorded
in this directory is.

## Which rows are recomputed, and which a human typed

The status word says what was found. It does not say **who found it** — and a
table where the reader cannot tell a recomputed number from a typed one is the
defect this repository exists to prevent. So every row carries exactly one
**provenance**, decided by `rowProvenance()` in `lib/pin-families.mjs` and
counted by `tableCensus()` beside it:

| provenance | rows | where the number comes from |
|---|---|---|
| `recomputed` | 22 | tracked evidence with a cite: `test/pin-families.test.mjs` recomputes the ratio from the rows in `data/` (or from the corpus text) on every run, and fails on drift |
| `lab-run` | 3 | one real run, typed in by hand and recomputed by nothing. The gate is re-run over it and its quote is checked against the file it names; the numbers inside its prose are not evidence in this lane's sense |
| `no-number` | 2 | there is no reading to check: `[SPEC]`, or an argument about where in the pipeline the repair sits |

That is 27 rows in total, over 7 properties and 18 (property, shape) groups.

The five rows that are **not** recomputed are the ones a reader must not take for
measurements, so they are named here rather than only counted:

- `lab-run` — `dead-store-memset-intrinsic` / `pass-delete/attributed-position`
  (the `-O2` intervention below), `backend-drop-after-ir-pipeline` /
  `pass-delete/attributed-position` (the `-O1` run), and
  `wipe-in-a-helper-in-another-translation-unit` /
  `wipe-pin/pin-the-helper-by-name` (measured on another lane's fixture loop,
  not here).
- `no-number` — `dead-store-builtin-memset-gimple` / `gcc/fdisable-tree-pass`
  (**[SPEC]**) and `wipe-written-as-stores` / `none` (`by-construction`).

6 of the 22 `recomputed` rows also carry a hand-typed `labObservation` beside
their recomputed count: the six zero-instance shapes, whose counts are recomputed
(`0/3200` from the tracked records in `data/`, `0/720` from the corpus text) and
whose sentence about what the plugin does with the shape is quoted from another
README. The count is recomputed; the sentence is checked only for still being in
the file it is attributed to.

Every ratio in the two tables below, and the `0/712` in the
`survive.authorization-check` section, is `recomputed`. Three numbers in this
document belong to neither kind, and say so where they appear: the recall
**91/174** and the **95.6%** beside it are quotes from files this lane does not
own, checked for still being there rather than recomputed; and the *0 of the
erasure files* in *Limits* is a one-off reading of the corpus text taken while
this lane was written, tracked nowhere.

`tableCensus()` derives every count in this section from `pin-families.json`,
and the drift test reads them back out of this prose — including the two counts
further down that an adversarial read caught wrong (rows carrying
`appliesToThisShape: "no"`, and `unmeasured` wipe rows). Until that test existed,
those were the only numbers in the deliverable that nothing could fail on, and
both were wrong.

## What the table says

### `survive.secure-wipe`

| shape | candidate | status | measured |
|---|---|---|---|
| dead-store memset intrinsic (clang) | `wipe-pin/volatile-memset` | `measured-retained` | **401/401** cell eliminations reversed |
| dead-store memset intrinsic (clang) | `pass-delete/attributed-position` | `not-repairable-in-compiler` (one lab run) | the property never came back; see below |
| dead-store `__builtin_memset` on GIMPLE (gcc) | `wipe-pin-gcc/volatile-asm-barrier` | `measured-retained` | **432/432** |
| dead-store `__builtin_memset` on GIMPLE (gcc) | `gcc/fdisable-tree-pass` | `unmeasured` | **[SPEC]** — nothing in this tree drives it |
| hidden span elimination (clang) | `wipe-pin/volatile-memset` | `measured-retained` | **63/63** |
| hidden span elimination (gcc) | `wipe-pin-gcc/volatile-asm-barrier` | `measured-retained` | **92/92** |
| dropped by the backend, after the IR pipeline | `wipe-pin/volatile-memset` | `measured-retained` | **62/62** at `-O1` |
| dropped by the backend, after the IR pipeline | `pass-delete/attributed-position` | `unmeasured` | there is no middle-end position to delete |
| wipe in a helper in another translation unit | `wipe-pin/pin-the-helper-by-name` | `unmeasured` | no cell here; measured on another instrument |
| `libcall-memset` (`-fno-builtin`) | `wipe-pin/volatile-memset` | `unmeasured` | 0 occurrences in 3200 records |
| `memset-chk` | `wipe-pin/volatile-memset` | `unmeasured` | 0 occurrences in 3200 records |
| `inline-wrapper-memset` (`_FORTIFY_SOURCE`) | `wipe-pin/volatile-memset` | `unmeasured` | 0 occurrences in 3200 records |
| `non-zero-fill` | `wipe-pin/volatile-memset` | `unmeasured` | 0 occurrences in 3200 records |
| `atomic-memset` | `wipe-pin/volatile-memset` | `unmeasured` | 0 occurrences in 3200 records |
| `bzero` through the fortifying header (gcc) | `wipe-pin-gcc/volatile-asm-barrier` | `unmeasured` | 0 plain `bzero(` calls in 720 corpus files |
| wipe written as stores (a zeroing loop) | none | `not-repairable-in-compiler` (by construction) | the loop is still a loop where both plugins run |

Six of the rows above carry a count of 0, and that count is the honest part
(the seventh shape with nothing measured, the zeroing loop, has no count to
carry: nothing was run for it at all). `0` occurrences is a reason for
`unmeasured`, and the table refuses to let it become `measured-not-retained`:
nobody put that shape in front of the repair, so nothing is known about what the
repair would have done with it.

### `survive.authorization-check`

One row. An authorisation decision written as `assert(...)` is deleted by the
preprocessor under `-DNDEBUG`, before anything this project can load into ever
runs — `not-repairable-in-compiler`, basis `by-construction`, stage
`preprocess`. Its tracked number is **0/712**: over the find step's compiling
`authz` configurations, `-DNDEBUG` changed the target body zero times. The two
halves of the row are deliberately separate sentences: *nothing was lost here*
(measured), and *if something had been, it would have been out of reach*
(by construction). It routes to `VG-AUTH-008`, whose recall is **unverified** —
no measured recall for that rule exists anywhere in this tree, and the corpus
that would produce one contains none of the shape.

### The `configguard` properties

Five properties, one shape — *a defence present only when a build macro is
defined* — and two candidates each, both `measured-not-retained`:

| property | clang | gcc |
|---|---|---|
| `survive.audit-record` | 0/14 | 0/14 |
| `survive.bounds-check` | 0/19 | 0/19 |
| `notappear.debug-endpoint` | 0/21 | 0/23 |
| `survive.input-validation` | 0/14 | 0/14 |
| `survive.fail-closed-branch` | 0/13 | 0/13 |

The numerator counts files whose default build, with the plugin loaded in
module scope, produced the same target body as the build with every macro
defined. It is zero everywhere, on both vendors. Four of the five route to
**no rule at all** (`rule: "none"`, with the reason in the row): this lane did
not identify a VibeGuard rule for a defence behind a build macro, and naming a
plausible one would have been a guess. The fifth names `VG-AUTH-001` as the
place to look and marks it `unverified`, because the rule was not run over
these files.

### Routing, and the recall that goes with it

A shape that no candidate retains has to say where it goes instead; the
validator enforces that per (property, shape) group, and only there — a rule id
printed beside a shape the compiler already repairs reads as "and the rule
catches it too" when nobody checked.

`VG-MEM-006` is the routing target for the wipe shapes, and the number quoted
with it is **91/174**, from `packages/rules/src/rules/lang-c-secret-wipe.test.ts`:

> of 174 generated files that wiped a secret with a removable `memset`, the rule
> reported 91

That is the recall **before** the widening that file is the regression test for.
After it, `../ai-generated/README.md` reports *"Recall on this corpus went from
57.2% to 95.6%"* and says in the same paragraph that the figure **is in-sample
and is not a generalisation**. The tree carries no numerator and denominator for
the 95.6%, so the table keeps the integers it can check and quotes the later
percentage as text; the test asserts both sentences are still in the files they
are attributed to.

Four rows route to `VG-MEM-006` with `appliesToThisShape: "no"`, and those are
the ones worth reading twice:

- **a plain `bzero(` wipe** (`bzero-through-the-fortifying-header`) — the rule's
  scope is `memset` only, and `explicit_bzero` is what it recommends as the
  *fix*. The gcc plugin cannot see the shape either (the fortifying header's
  `bzero` wrapper is not a memset and has no counter). Neither side covers it.
  The corpus contains 0 such calls, so nothing here is measured about it at all.
- **a wipe written as a zeroing loop** (`wipe-written-as-stores`) — no memset for
  the rule to match and no site for either plugin to pin.
- **a non-zero fill** (`non-zero-fill`) — out of scope on both sides, and
  deliberately: overwriting a secret with `0xAA` is a different act from
  clearing it.
- **the element-wise unordered atomic memset** (`atomic-memset`) — C source
  cannot spell that intrinsic, so there is no source text for a lexical rule to
  match, and the pin is written for the ordinary `llvm.memset`. The corpus holds
  0 of them, so nothing is measured about this one either.

This list is four bullets and not three because `atomic-memset` belongs in it:
the prose said *three* until `tableCensus()` started recomputing the count. It
is the same kind of error the table's `measured-*` rows are built to make
impossible, in the one place no test was looking.

## The intervention tool, and what it found

`tools/intervene.mjs` asks the other question: instead of changing the code so
the pass cannot remove the wipe, **remove the pass**. It is lab-only and writes
nothing under `data/`.

It replays the compilation rather than describing it:

1. the pre-optimisation IR, `clang -O<n> -Xclang -disable-llvm-passes -emit-llvm -S`;
2. **the pipeline string that compiler actually built**, `-mllvm
   -print-pipeline-passes` — not `default<O2>`, which is a different string
   (established in `../../pass-instrumentation/observer/rq2/rq2.mjs`, check
   RQ2-01);
3. the unmodified replay, which **must** reproduce the loss;
4. attribution: the pipeline truncated after each pass in turn, with the whole
   state sequence kept rather than the first `PRESENT → LOST` transition;
5. the interventions: the attributed pass deleted **by position**, and
   separately the pass after it.

Every reading is taken on **both channels**, the IR after `opt` and the assembly
after `llc`, and both are graded by the find step's own `verdictOf` on a
differential — the file as written against the file with its wipe statement
deleted. Nothing decides survival by searching a listing for a symbol name. The
positive control travels in the same translation unit (the find step's own
`CONTROL`, imported, not respelled) and the fixture's own read-after-wipe
control is read beside it.

### The smoke run, verbatim

`clang-18 -O2`, the hand-written erasure fixture from
`compiler/llvm-pass/tools/make-fixtures.sh`, 2026-09-12:

```
span 0  removable     kept     handle_request(void) { unsigned char secret[32];
span 1  removable     DELETED  memset(secret, 0, sizeof secret);
stock  clang-18 -O2 -S            subject WIPE_ELIMINATED, control PRESENT
pipeline  106 passes, 3868 chars, printed by clang-18 itself (not default<O2>), parser round-trips it
replay  unmodified                    asm WIPE_ELIMINATED, ir WIPE_ELIMINATED, control PRESENT, wipe_kept PRESENT
sweep   full, 107 prefixes read on the IR channel; state changes: WIPE_SURVIVED->WIPE_ELIMINATED at 60 (dse)
attrib  dse at position 59 [cgscc > devirt<4> > function<eager-inv;no-rerun>]
cut  59  dse                      the attributed pass                ir WIPE_SURVIVED, asm WIPE_ELIMINATED, control PRESENT/PRESENT
cut  60  move-auto-init           the pass after the attributed one  ir WIPE_ELIMINATED, asm WIPE_ELIMINATED, control PRESENT/PRESENT
RESULT  NEVER_CAME_BACK -- 2 positions tried, both channels read, the property came back at none of them
```

**Read the `cut 59` line twice.** Deleting the pass the loss is attributed to
puts the `llvm.memset` back in the IR — and changes nothing whatsoever in the
assembly. Checked by hand afterwards: `cut-w-59.ll` line 12 is
`call void @llvm.memset.p0.i64(... i8 0, i64 32, i1 false)`, and the
`handle_request` body of `cut-w-59.s` is byte-identical to the ablated form's.
The same IR read through `llc-18` at each of its levels, differentially, with
the control `PRESENT` throughout:

```
llc-18 -O0  subject WIPE_SURVIVED, control PRESENT
llc-18 -O1  subject WIPE_ELIMINATED, control PRESENT
llc-18 -O2  subject WIPE_ELIMINATED, control PRESENT
llc-18 -O3  subject WIPE_ELIMINATED, control PRESENT
```

The elimination has a **second site**, in the backend, from `-O1` upward.
Suppressing the first one is not a repair, and an IR-only reading would have
recorded this candidate as `measured-retained`. That is the whole reason the
gate refuses "never comes back" unless the asm channel was read.

### The second run, `-O1`

```
pipeline  90 passes, 3546 chars, printed by clang-18 itself (not default<O1>), parser round-trips it
replay  unmodified                    asm WIPE_ELIMINATED, ir WIPE_SURVIVED, control PRESENT, wipe_kept PRESENT
sweep   full, 91 prefixes read on the IR channel; state changes: none
attrib  none -- the IR channel holds the property to the end of the pipeline and the asm channel does not: the loss is in the backend, where deleting a middle-end pass cannot reach it
RESULT  NOT_ENOUGH_EVIDENCE -- no intervention position was tried, so nothing here says anything about whether the property would come back
```

This reproduces, on a second instrument, what `../calibration/README.md` records:
*"The wipe survives the entire IR optimiser and is dropped after it."* There is
no middle-end position to intervene at, the gate refuses to conclude anything
from zero positions, and the row in the table is `unmeasured` — not
`not-repairable`, because nothing was tried.

### The gate

`interventionVerdict()` in `lib/pin-families.mjs` is the only place allowed to
write "never comes back", and it refuses unless:

- the unmodified replay reproduced the loss (otherwise the interventions were
  made against a pipeline the loss did not come from) — `BROKEN_MEASUREMENT`;
- both positive controls read `PRESENT` in every replay — `BROKEN_MEASUREMENT`;
- **at least two** intervention positions were tried — one position proves
  nothing, because deleting a pass can simply hand the same elimination to the
  next pass entitled to make it;
- **the asm channel was read** — for the reason the `cut 59` line above shows.

Anything short of that is `NOT_ENOUGH_EVIDENCE`, which is a result and not an
error. The table's validator re-runs the gate over every `intervention` block it
holds, so a row cannot assert a verdict the gate would not give.

### gcc

`-fdisable-tree-<pass>` is the same idea on the other vendor and is **[SPEC]**:
the candidate is in the table, nothing in this tree drives it, and no reading of
any kind exists. The clang result does not transfer — it is a statement about
clang's pipeline and clang's backend.

## Running it

```
# the fixtures, if they are not in the lab yet
bash compiler/llvm-pass/tools/make-fixtures.sh

# the pipeline surgery and the gate, with no compiler at all
node compiler/eval/repair-loop/tools/intervene.mjs --selftest

# the measurement (lab output only; --out must be outside the repository)
node compiler/eval/repair-loop/tools/intervene.mjs --out ~/vg-lab/pin-families \
     --cc clang-18 --opt -O2 --span 1

# the table and its drift test
node --test compiler/eval/repair-loop/test/pin-families.test.mjs
```

Exit codes: 0 the run completed and its verdict is in the report (`CAME_BACK`,
`NEVER_CAME_BACK` and `NOT_ENOUGH_EVIDENCE` are all results); 2 the replay did
not reproduce the loss, or a control went missing, so there is no reading; 3 a
tool or the fixture is missing; 4 bad arguments.

## Limits, including the ones that bit during this work

- **`--span` exists because of a real defect, not for convenience.** The find
  step's `wipeSpans` is derived from the generated corpus, where no erasure
  target is declared `void` (checked: 0 of the erasure files). The hand-written
  fixture's `handle_request` **is** `void` and zeroes a buffer, so `wipeHelpers`
  puts the target's own name in its call-name list, the function's header is
  matched as a wipe call, and deleting it produces a translation unit that does
  not compile. The tool prints every span with `DELETED` or `kept` beside it,
  and refuses with `ABLATION_DID_NOT_COMPILE` rather than reporting a verdict.
  The tracked rows are unaffected; nothing in `wipeSpans` was changed.
- **One fixture, one subject, two levels.** The smoke is `handle_request` in the
  erasure fixture at `-O2` and `-O1`. It is not a corpus measurement and the
  table does not treat it as one: its result lives in an `intervention` block
  and cannot carry a `measured-*` status.
- **The asm channel is `llc`, not `clang -S`.** The replay's assembly comes from
  `opt` then `llc` at the same numeric level. The stock compilation is read
  through `clang -S` as the rest of the lane does, and the unmodified replay is
  required to agree with it about the loss before anything else is believed.
  `-Os` and `-Oz` are refused: `llc` has no such level and quietly mapping them
  to `-O2` would misdescribe the measurement.
- **`ir` and `asm` are lane-local channel names.** They are not checkpoint words
  from `../../schema/observation.schema.json`, whose enum is
  `invocation | ast | pre-opt-ir | after-pass | object | linked | artifact`.
  This tool emits a lane-local report and no `observation.schema.json` document,
  so it does not need one; `../metamorphic/lib/asm-read.mjs` uses the word `asm`
  the same way. If a pin-family reading is ever emitted as an observation, the
  checkpoint word is a question for `interfaces.md` first.
- **The `unmeasured` rows are the honest majority.** Nine of the sixteen
  `survive.secure-wipe` rows are `unmeasured`, six of them because the corpus
  contains zero instances of the shape. The table is mostly a map of what has
  not been measured, and that is what it is for.

## Edits requested in files this lane does not own

Both are one-line additions; neither changes any measurement.

**1. `compiler/eval/repair-loop/README.md`, in the *Files* table** — add these
three rows after the `lib/corpus.mjs` row so the new files are findable from the
lane's own index:

```
| `pin-families.json`, `lib/pin-families.mjs`, `PIN-FAMILIES.md` | the per-property pin-family table: one row per (property, disappearance shape, repair candidate), its claim definitions and its validator; pure |
| `tools/intervene.mjs` | the second repair candidate: delete the attributed pass from the pipeline clang printed and replay under opt and llc, reading the IR and the asm channel; lab output only, never `data/` |
| `test/pin-families.test.mjs` | recomputes every measured number in `pin-families.json` from the tracked rows, and re-runs the intervention gate over every claim that uses it |
```

**2. Nothing is requested in `compiler/schema/`.** It is worth recording why,
since the question came up twice. The five `configguard` scenarios map onto
existing property ids (`survive.audit-record`, `survive.bounds-check`,
`notappear.debug-endpoint`, `survive.input-validation`,
`survive.fail-closed-branch`), so no new property was needed; the shape they
share — *a defence present only when a build macro is defined* — is a shape and
not a property, and it lives in this table's `shape` column where it belongs.
No new checkpoint word is needed either, for the reason in *Limits* above.
