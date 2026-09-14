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
| `no-number` | 2 | there is no reading to check: an instrument nobody has run yet, or an argument about where in the pipeline the repair sits |

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
  (**driven, not yet run**) and `wipe-written-as-stores` / `none`
  (`by-construction`).

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
| dead-store `__builtin_memset` on GIMPLE (gcc) | `gcc/fdisable-tree-pass` | `unmeasured` | **driven, not yet run** — `tools/intervene.mjs --cc gcc-13` |
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

### gcc — driven, not yet run

`-fdisable-tree-<pass>` is the same idea on the other vendor, and
`tools/intervene.mjs --cc gcc-13` now drives it. gcc prints no pass pipeline and
has no `opt`/`llc` to replay one under, so the clang steps have no gcc form; what
gcc does offer is its own numbered dump sequence and a flag that takes one
GIMPLE pass out:

1. compile both units with `-fdump-tree-all -fdump-rtl-all` and read every dump
   **differentially** — the target function's region as written against the same
   region with the wipe ablated — to find the first dump at which the wipe stops
   making a difference. That reading is `firstIndifferentDump`;
2. rebuild with `-fdisable-tree-<that pass>`, then at a second position — where
   the walk says the loss moved to once the first pass was gone — and finally
   with both disabled at once. The gate decides the verdict, as on clang.

#### Three words, three oracles, and why this channel does not borrow one

`firstIndifferentDump` is this channel's own word, and it is deliberately none of
the two that already exist:

| where | how the reading is taken | its word |
|---|---|---|
| the pass-plugin observer (clang) | an instrument we inject and drive, cross-checked against the source and object gates | `firstLossPass` |
| `../../second-vendor/run-gcc-dump-probe.mjs` | gcc's own dumps, **one unit**, searched for a `memset`-family token in the function's region | `firstAbsentDump` — "absent" means the token was not found |
| this channel | gcc's own dumps, **both units**, the written region compared against the ablated region | `firstIndifferentDump` — "indifferent" means the wipe made no difference by that dump |

The middle and the bottom row read the same files and answer different questions,
so they do not share a name: a dump can hold no `memset` token and still differ
between the two units (gcc lowers the fill to stores), and it can hold one in
both units and be identical in both. This section used to call this channel's
reading `firstAbsentDump` "the word the neighbour established", which read as one
result taken twice. It is not; it is two results, and only the words keep them
apart. What they do share is their weakness, and `../metamorphic/catalogue.json`
excludes both for it: gcc describing its own behaviour to itself, with nothing
instrumented and no independent confirmation that the dump boundary is where the
transformation happened. Neither may enter an agreement evidence base.

#### The controls, none of them optional

A flag gcc ignored and a flag gcc honoured produce the same exit code, and a walk
that read nothing answers in the same shape as a walk that read something:

| control | what must hold | if it does not |
|---|---|---|
| (a) the disable is announced | `cc1: note: disable pass tree-<pass> for functions in the range of …` naming the pass that was asked for, in **both** compiles of a reading | the reading is `no-note`, and the run stops with `INTERVENTION_NOT_ANNOUNCED`, exit 2. A build that succeeded is never read as an intervention that happened |
| (b) the channel is checked | a deliberately misspelled pass name (`…xx`, extended until it collides with no pass the walk saw) must **fail** the build: `cc1: error: unknown pass tree-…xx specified in '-fdisable'` | `CHANNEL_NOT_CHECKED`, exit 2, before any reading is taken: if gcc ignores an unknown name, a missing note in (a) proves nothing |
| (c) the controls travel | the co-resident `vgctl_control` and the fixture's own `wipe_kept` read `PRESENT` in every replay, the second through the oracle or the labelled `rep stos` fallback | `CONTROL_NOT_PRESENT`, exit 2 |
| (d) the walk read the function | at least one dump holds the target function **in both units**, so that at least one entry of the walk is a comparison rather than a blind reading | `FUNCTION_IN_NO_DUMP`, exit 2 |

Control (d) is the one this channel shipped without, and it is the reason the
vocabulary above is four words rather than three. A dump that does not hold the
function is `NOT_OBSERVED`; a walk made **entirely** of those compared nothing at
all, and it used to answer `absent-from-first-dump` — documented as the finding
*"the wipe made no difference in any dump gcc emits"* — at exit 0. An apparatus
that found nothing to read was reporting a result about the wipe. On this machine
`gcc-13 -O2 -fdump-tree-all` emits ~122 dumps for a small file, so zero readable
ones is a broken walk and not a fact about any pass. The four outcomes are now:

| walk outcome | what it says |
|---|---|
| `first-indifferent-dump-located` | some dump read `WIPE_SURVIVED` and a later one `WIPE_ELIMINATED`; that later one is named |
| `indifferent-from-first-dump` | the function **was** read, and no dump ever showed a difference |
| `no-indifference-observed` | the wipe still made a difference in the last dump that held the function |
| `function-in-no-dump` | not one dump held the function in both units: nothing was compared, and this is fatal |

Two more readings that used to be silent are named the same way: a pass gcc
refuses is read in **both** units (a one-sided refusal is not a refusal — the
refusing unit exits non-zero, so the reading is `compile-failed`), and dumps
present in one unit but not the other are counted, printed with their share, and
refused as `DUMP_SETS_DISAGREE` above 10% of the union. A loss located in an RTL
or IPA dump is still reported as out of this channel's reach — `-fdisable-rtl-`
and `-fdisable-ipa-` are real flags and this tool does not drive them — rather
than disabled with the wrong prefix.

#### Every way this channel refuses to produce a reading

Each one is a key in `GCC_EXIT_REASONS` (`lib/gcc-disable-tree.mjs`), it is what
`report.verdict.reason` holds, and `report.verdict.why` is its sentence. They are
all exit 2, and `test/gcc-disable-tree.test.mjs` fails if one of them is missing
from this list:

| reason | when |
|---|---|
| `DUMP_BUILD_FAILED` | the stock compilation compiled and the same compilation with the dumps turned on did not |
| `NO_DUMPS` | gcc produced no dump file the walk could read |
| `FUNCTION_IN_NO_DUMP` | control (d): no dump held the function in both units |
| `DUMP_SETS_DISAGREE` | the two units wrote dump sets that do not match, above the threshold |
| `REPLAY_DID_NOT_REPRODUCE` | the dump build does not lose the property the stock compilation loses |
| `CONTROL_NOT_PRESENT` | control (c): a positive control was not `PRESENT` in a compile a reading was taken from |
| `CHANNEL_NOT_CHECKED` | control (b): gcc accepted a pass name it cannot know |
| `NO_GIMPLE_DUMP` | the walk holds no GIMPLE dump, so there is no pass name to ask gcc about |
| `INTERVENTION_NOT_ANNOUNCED` | control (a): gcc built the intervention at exit 0 and announced no disable |
| `INTERVENTION_BUILD_FAILED` | the intervention build failed for a reason that is not gcc refusing the name in both units |

`NO_GIMPLE_DUMP` is in that list because it existed in the code and in no
document: a run could stop for a reason this file did not name. `report.verdict`
used to be assembled on the fatal paths by asking the gate for a sentence about
evidence the run never gathered — a `no-note` fatality was reported as *"the
positive control was not PRESENT in every replay"*, which was false, and it is
that sentence a reader would have transcribed into this file. The reason is
looked up now, and an unnamed one throws rather than becoming prose.

#### What a reader takes from a run

`report.verdict` — `{verdict, reason, why}` — and `report.gateEvidence`, which is
what the gate was given (`positionsTried`, `asmChannelRead`, `irChannelRead`,
`cameBackAt`, `replayReproducedLoss`, `controlHeld`) plus `fatality` when the run
stopped early. `gateEvidence` is written on **every** exit from this channel, not
only on the path that reaches the gate, so the runs that most need explaining are
no longer the ones with nothing to copy. `asmChannelRead` is false unless an
intervention reading was actually taken: it used to be passed as `true` on four
paths where zero interventions had been made, which is a control that cannot fail
asserted as one that passed. `positionsTried` counts single-position readings;
the both-passes-at-once reading is a third reading of two positions already
counted, so it does not raise the count — but it is under the same fatality rules
as the others and its controls are in the same evidence, which they were not
until 2026-09-14.

**What is still missing is the reading.** No run of this channel exists, here or
beside this tree, so the row stays `unmeasured` and carries no ratio: writing the
instrument is not measuring with it, and neither is unit-testing it. The guards
above are pinned by `test/intervene-gcc-driver.test.mjs`, which drives the driver
over scripted readings with no compiler present; that is evidence about the
apparatus and none at all about gcc. Promoting the row means running it in WSL
(`--out` a lab directory outside the checkout, one run at a time — this lane's
tools share their scratch) and moving the row, this section and
`test/pin-families.test.mjs` in the same change. The clang result does not
transfer and never will: it is a statement about clang's pipeline and clang's
backend.

## Running it

```
# the fixtures, if they are not in the lab yet
bash compiler/llvm-pass/tools/make-fixtures.sh

# the pipeline surgery and the gate, with no compiler at all
node compiler/eval/repair-loop/tools/intervene.mjs --selftest

# the measurement, clang (lab output only; --out must be outside the repository)
node compiler/eval/repair-loop/tools/intervene.mjs --out ~/vg-lab/pin-families --cc clang-18 --opt -O2 --span 1

# the same question on gcc, through -fdisable-tree-<pass>. Its own lab
# directory: this lane's tools share their scratch, so two of them must not be
# run at once, whatever the compiler.
node compiler/eval/repair-loop/tools/intervene.mjs --out ~/vg-lab/pin-families-gcc --cc gcc-13 --opt -O2 --span 1

# the table and its drift test, and the gcc channel's own unit tests (no compiler)
node --test compiler/eval/repair-loop/test/pin-families.test.mjs
node --test compiler/eval/repair-loop/test/gcc-disable-tree.test.mjs
```

Exit codes: 0 the run completed and its verdict is in the report (`CAME_BACK`,
`NEVER_CAME_BACK` and `NOT_ENOUGH_EVIDENCE` are all results); 2 the replay did
not reproduce the loss, a control went missing, or (on gcc) the channel could
not be shown to have been exercised, so there is no reading — on gcc the reason
is one of the ten `GCC_EXIT_REASONS` above and is in `report.verdict.reason`; 3 a
tool or the fixture is missing; 4 bad arguments; 5 the report carried an absolute
path and was not written.

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
  checkpoint word is a question for `interfaces.md` first. The gcc channel adds
  no channel word: what it records is `firstAbsentDump` and gcc's own dump-file
  suffixes (`042t.dse1`), which are gcc's names for gcc's own files and are not
  checkpoint words either — and, deliberately, not clang's `firstLossPass` or
  this tool's `attribution.pass`, which name a different kind of reading
  altogether (`../../second-vendor/run-gcc-dump-probe.mjs`).
- **The `unmeasured` rows are the honest majority.** Nine of the sixteen
  `survive.secure-wipe` rows are `unmeasured`, six of them because the corpus
  contains zero instances of the shape. The table is mostly a map of what has
  not been measured, and that is what it is for.

## Edits requested in files this lane does not own

Both are one-line additions; neither changes any measurement.

**1. `compiler/eval/repair-loop/README.md`, in the *Files* table** — the rows for
this table, its tool and their tests, so the files are findable from the lane's
own index. They are in the README now, and the `tools/intervene.mjs` and
`test/pin-families.test.mjs` rows were widened when the gcc channel landed:

```
| `pin-families.json`, `lib/pin-families.mjs`, `PIN-FAMILIES.md` | the per-property pin-family table: one row per (property, disappearance shape, repair candidate), its claim definitions and its validator; pure |
| `tools/intervene.mjs` | the second repair candidate, on either vendor: on clang, delete the attributed pass from the pipeline clang printed and replay under opt and llc, reading the IR and the asm channel; on gcc, take the GIMPLE pass gcc's own dump sequence names out with `-fdisable-tree-<pass>` and rebuild. Lab output only, never `data/` |
| `lib/gcc-disable-tree.mjs` | the gcc channel's pure half: gcc's dump-file ordering, the differential reading of one dump, `firstIndifferentDump` and the whole walk beside it, the walk's own positive control (at least one dump must have held the function in both units), the dump-set comparison, the stderr controls (the disable must be announced in both units, a misspelled pass must fail the build, a refusal counts only when both units refused) and the named reasons this channel refuses to produce a reading; pure |
| `test/pin-families.test.mjs` | recomputes every measured number in `pin-families.json` from the tracked rows, re-runs the intervention gate over every claim that uses it, and reads the gcc channel's state back out of the prose |
| `test/gcc-disable-tree.test.mjs` | the gcc channel's decisions, without a compiler: the walk and its positive control, the two gcc messages quoted verbatim, the rule that a build which succeeded without the disable note is `no-note` and fatal, and that `PIN-FAMILIES.md` names every refusal reason the code can give |
| `test/intervene-gcc-driver.test.mjs` | the gcc DRIVER's fail-closed guards, over scripted readings and no compiler: each guard has a case that goes red when the guard is deleted (`PIN-FAMILIES.md`, *gcc — driven, not yet run*) |
```

**2. Nothing is requested in `compiler/schema/`.** It is worth recording why,
since the question came up twice. The five `configguard` scenarios map onto
existing property ids (`survive.audit-record`, `survive.bounds-check`,
`notappear.debug-endpoint`, `survive.input-validation`,
`survive.fail-closed-branch`), so no new property was needed; the shape they
share — *a defence present only when a build macro is defined* — is a shape and
not a property, and it lives in this table's `shape` column where it belongs.
No new checkpoint word is needed either, for the reason in *Limits* above.

## Reading this table during a run (A5, automated)

Until 2026-09-12 this table was read by a person. A run printed its cells and
outcomes; someone then opened `pin-families.json`, found the shape, and carried
the sentence *"this one is not repairable in the compiler, send it to the
source"* across by eye. `../lib/routing.mjs` does that step now, and every run
of `../run-repair-loop.mjs` prints a **routing** section and writes
`<out>/routing.json`, with the summary repeated in `pin-plan.json` so the
find → fix hand-off carries it.

**The mapping is derived from this table, not written in the code.** A second
copy of *"`libcallMemset` means the `libcall-memset` shape"* in a module would
be exactly the hand-transcription this table exists to remove: it would go
stale the first time a row was renamed, and nothing would fail. So the routing
reads the rows' own `evidence.cite`. Two claims name something a run row
carries, and they are the entire vocabulary:

| claim | field | what a run row carries |
|---|---|---|
| `unhandled-shape-occurrences` | `counter` | a counter in a plugin record's `unhandled` block |
| `configguard-default-equals-enabled` | `scen` | a `configguard` row's scenario id |

Every other claim counts outcomes of a repair, not occurrences of a shape, and
cannot key a decision. A (property, shape) group reached by neither claim has
**no shape signal**, and the section prints that with a count instead of
omitting the group.

Two refusals carry the weight:

- A counter, or a `scen`, that no row of this table names is an **exception**,
  and the run exits 2. Dropping it silently is the substitution this whole
  document is written against: *nobody looked at that shape* becoming *that
  shape did not occur*.
- A signal that fired **zero** times routes nothing, and the reason is counted
  separately — `zero-occurrences`, `not-measured` (a `--plan` run measures no
  `configguard` cell, so 0 rows there is an absent measurement and not an
  absent shape) or `no-signal-defined`.

`shapeVerdicts()`' `routed-to-source` is split one step further, because this
table's own `appliesToThisShape` makes the distinction and throwing it away at
the last step would undo it: `route-to-source` needs a rule whose scope was
checked to cover the shape, `route-to-source-unverified` is a rule that names
where to look, and `no-source-rule-covers-it` is a rule that explicitly does
not cover it. The last one is printed with `unrouted` and `open` as **not held
by either side**.

### What this is measured on, and what it is not

The honest split, because the automation is new and the corpus is old:

- **Measured, on the tracked rows.** The five `defence-behind-a-build-macro`
  groups. `data/r2-repair-rows.json` holds `configguard` rows for all five
  scenarios, the plugin turned none of them into the enabled build, and the
  routing over those rows reads four `unrouted` and one
  `route-to-source-unverified` (`VG-AUTH-001`, `survive.input-validation`).
  `../test/routing.test.mjs` asserts exactly that against the tracked file.
- **Not measured. Synthetic rows only.** Every `survive.secure-wipe` group the
  routing could reach. All five `unhandled` counters read 0 in both tracked
  runs — the pin two sections above — so over the r2 corpus no erasure-side
  signal has ever fired, and the routing reports those five groups as
  `zero-occurrences`. That the routing sends them to `VG-MEM-006` when a
  counter *does* fire is shown by synthetic rows in `../test/routing.test.mjs`
  and by nothing else. It has not been observed on a compiler.
- **~~Not exercised end to end.~~ Run on 2026-09-12**, three times with
  `libWipePin.so` and once with `libWipePinGcc.so`: a two-file subset and the
  two full runs that produced `data/r2-regate.json`. Each printed the routing
  section, wrote `routing.json` and carried the `routing` block in
  `pin-plan.json`, with `absolutePathHits` empty and the tracked rows and
  results text untouched. What those runs could **not** exercise is the erasure
  side of the table: every shape counter read 0 over the r2 corpus, which is
  the same zero `test/pin-families.test.mjs` pins, so the routed rows in them
  are the configguard ones and the erasure routing remains demonstrated only by
  the synthetic rows in `test/routing.test.mjs`.
