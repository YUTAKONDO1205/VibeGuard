# metamorphic — lane H

Metamorphic relations over property-shaped specimens, plus cross-compiler
agreement on the difference each relation makes.

A metamorphic relation is a statement about **two programs and one instrument**:
apply this source transformation and the reading must stay put, or apply that one
and the reading must move along this named edge. Nothing here needs a ground-truth
oracle for a single program, which is the point — the property a single reading
would have to be checked against is exactly the thing nobody has independently.

Every specimen is **generated** by `tools/make-mutants.py` into a lab outside the
repository (interfaces.md §1). Nothing in this directory is a measurement input and
nothing here says anything whatever about a real subject.

## The division of labour, and the drift this README exists to prevent

**Lane H breaks the PROPERTY. The calibration battery measures the INSTRUMENT'S
LIMITS.** Those are different findings and they must not share a table.

After an R2 mutation here the program genuinely no longer does what the property
says, or genuinely no longer offers the same referent to ask about. A mutation that
leaves the property intact and merely defeats the extractor's recognition —
`memset(b, 0, n)` → `memset(b, 0, 0xAA)`, a guard rewritten as a `select`, a guard
written as arithmetic, a wipe reached through a function pointer — is an
**instrument-limit probe** and belongs to the other lane. Put one here and it would
"pass" by having the extractor go blind, which is the most flattering possible way
to manufacture a result.

`catalogue.json`'s `notInThisLane` names the four such mutations that were
considered and rejected, so that the exclusion is reviewable rather than tacit.

## R1 is the half that can catch the other half lying

An R2 operator that moves proves that **something** moved. Only an R1 operator that
stayed put shows it was the property, rather than the spelling, the position, the
buffer size, or a function added elsewhere in the module. `check-meta.py` therefore
refuses a `MEASURED` lane that carries no graded R1 operator: a lane without one
reports movement it cannot attribute.

## There is no total order on the six property states, and none is invented

interfaces.md §3 gives six states. Only two of them are comparable as more-or-less
of the property surviving, and this lane defines exactly that two-point axis:

```
PRESENT  >  LOST                 the survival axis, for must-survive polarity
ABSENT, NOT_APPLICABLE, NOT_OBSERVED, REINTRODUCED      OFF the axis
```

`ABSENT` means the property was never established at the first checkpoint.
`NOT_APPLICABLE` means the question stopped having the same referent.
`NOT_OBSERVED` means nothing was read. None of the three is a smaller amount of
survival, and ranking them would let a **lost referent be reported as a lost
property**.

So `survivalAxisGraded` is true for R2b cells and false for everything else, and
`check-meta.py` re-derives that from the catalogue's `class` field rather than
reading the document's copy of it.

### The classes

| class | what the mutation does | declared direction | legible at |
|---|---|---|---|
| `R1` | property-preserving | `INVARIANT` — any change is exit 2 | both checkpoints |
| `R1-spelling` | property-preserving, and changes which half of the extractor carries the effect | `INVARIANT` | both checkpoints |
| `R2a` | source-removing: the effect is deleted from the source | `PRESENT->ABSENT` | `pre-opt-ir` |
| `R2b` | survivability-breaking: the effect is still in the pre-opt IR and the optimiser now removes it | `PRESENT->LOST` | `after-pass` |
| `R2c` | referent-removing: the object leaves memory, or the unit is inlined away | `PRESENT->NOT_APPLICABLE` | `after-pass` |
| `R2-spelling` | introduction that arrives under a different symbol list than the source names | `ABSENT->PRESENT` | see the two `F-R2S-*` entries |

**R2b is the class the lane exists for.** It is the only one whose movement is a
movement down the survival axis, and it is the only one an optimiser has to
participate in.

**R2c is the named class that must NOT be read as monotonicity.** Its edge ends off
the axis. For `W-R2C-UNPIN` the buffer was promoted out of memory; for
`G-R2C-INLINE` the guard is still enforced at run time and moved into the caller.
Grading either as a loss would report a rescoped or referent-less question as a
removed defence — in the direction that looks like a result.

The **forbidden** polarity has no survival axis at all. There, R2 is
**introduction**: `ABSENT->PRESENT`, clean → hit. The same six words carry the
opposite valence for `ir.forbidden-callee`, and one operator (`F-R2S-PRINTF`) shows
why that matters. Its mutant holds one forbidden `printf` at `pre-opt-ir` and none
after the pass, because clang rewrote the call to `puts`; §3 spells that pair `LOST`,
a must-survive word answering a must-not-appear question, and grading it would report
a forbidden call *disappearing* as a finding against the instrument.

It was first landed as `graded: false` for that reason, and that was the wrong
repair: an operator with `graded: false` is an off switch with no condition on it, so
nothing about the cell could ever be falsified again. It is now graded on the
**count** at the checkpoint the catalogue names, via an explicit
`gradeOn: "count-at-pre-opt-ir"` — where the base holds 0 and the mutant holds 1, so
the declared `ABSENT->PRESENT` edge holds at both `-O0` and `-O2`.

`gradeOn` is an opt-in and is never inferred. Inferring it from `checkpointRead`
was tried and is wrong: the R2b and R2c operators also name a single checkpoint
there, to document where their loss becomes visible, and treating that as a grading
instruction collapsed their `PRESENT->LOST` and `PRESENT->NOT_APPLICABLE` edges into
`PRESENT`/`ABSENT` and sent five correct cells off-axis. `check-meta.py` now refuses
`gradeOn` on any R2b or R2c operator outright (exit 2), because one checkpoint can
say only `PRESENT` or `ABSENT` while those classes' edges are claims about a change
between two — and it recomputes the graded pair from the counts rather than trusting
the assembler's copy, since that field is what a verdict now turns on.

### Grading words

| word | meaning | exit |
|---|---|---|
| `pass` | moved along its declared edge | 0 |
| `not-expressed` | did not move: the compiler did not take the bait at this configuration | 0 — **counted and reported by name, never dropped** |
| `off-axis-landing` | moved somewhere other than its declared edge | **2** |
| `origin-mismatch` | the base was not at the declared origin, so the landing cannot be attributed to the mutation | 3 |
| `vacuous-invariance` | an `INVARIANT` cell whose base never established the property | 3 |

`not-expressed` is not a failure and not a miss. R2b and R2c ask the optimiser to do
something, and at `-O0` it declines. A denominator whose removals are not described
is not a denominator anyone can check, so the word is in the table and in the tally.

## Cross-compiler agreement — a DIFFERENT and COARSER instrument

The IR extractors are clang-only by construction, so this channel does not use
them. It compiles each specimen to assembly with `clang-18` and `gcc-13` and reads
it with `compiler/eval/second-vendor/lib/asm-oracle.mjs`, **imported and not
copied** — that file has no per-vendor branch anywhere in it, and a per-vendor
branch is how a comparison quietly stops being a comparison.

What the channel compares is **the TRANSITION (base→mutant) per vendor**, never the
raw states. Two compilers may legitimately render one surviving effect differently —
a call on one, inlined zeroing on the other — so equal states are not the claim. A
metamorphic relation is about the **difference** the mutation makes, and that is the
object both vendors can be asked about symmetrically.

| word | meaning |
|---|---|
| `vendors-agree` | both sides readable, transitions match |
| `vendors-split` | both sides readable, transitions differ. **The discovery channel.** Not an invariant violation, so **never exit 2** — two compilers may legitimately differ, and the split is enumerated as data |
| `vendor-unreadable` | either side was `VERIFICATION_INCOMPLETE`, `UNSUPPORTED`, `NOT_OBSERVED`, or failed its own positive-witness control. `unreadableSide` records which. **Never folded into `vendors-split`** |

The last row is the one that matters most. `frontier-match.mjs` never folds
`incomparable` into `mismatch` for the identical reason: *"the two differ"* and *"I
could not look"* send a reader to two different places and only one of them is a
finding.

These three words are deliberately **not** `frontier-match.mjs`'s
`exposure-consistent` / `exposure-mismatch` / `exposure-incomparable`. That triple
asks whether one build's optimiser treats the ladder the way another build's did,
from IR readings of one vendor. This triple asks whether two vendors made the same
difference to one specimen, from assembly readings. Same shape, different question,
different evidence base — and a vocabulary shared between two evidence bases is one
either can widen alone.

### What this instrument cannot do, stated wherever its output appears

- **No pass attribution**, on either vendor. There is no `firstLossPass` in this
  channel and no field from which one could be inferred.
- **It cannot distinguish `LOST` from `NOT_APPLICABLE`.** It reads one listing rather
  than a checkpoint pair and has no alloca census, so §3's `ABSENT`, `LOST` and
  `NOT_APPLICABLE` all present here as the single word `LOST`.
- Pass attribution under gcc is **`UNSUPPORTED` by construction**, not merely
  not-observed: gcc cannot load an LLVM `-fpass-plugin` at all.
- The clang-defined reference configuration is **not** automatically a witness
  configuration under gcc (`second-vendor` records `referenceConfigIsWitness:
  false`), so a cell whose own control did not show its effect carries no
  information about the subject and is never counted as agreeing.

### What a split may and may not claim

**May:** *these two compilers, at these versions and these flags, transformed this
specimen under this mutation differently at the asm checkpoint.*

**May not:** that either vendor is wrong; anything about a user's real subject;
anything about an IR-level cause on the gcc side; support for any `status` value in
`compiler/schema/properties.json`. And nothing in this channel reads gcc's
`-fdump-tree-all` self-report: `second-vendor/README.md` records `firstAbsentDump`
as having **no independent confirmation**, so it must not enter an agreement
evidence base.

### The witness beside the blind cell

`G-R2C-INLINE` is in this channel **because** the asm oracle must go blind on it:
once the unit has internal linkage and has been inlined away there is no
`meta_g_inline:` label and no closing `.size` directive, so `extractFunctionBody`
returns `null` rather than guessing a boundary — a wrong boundary would silently
import the caller's calls.

`G-R1-INVERT` is in the channel as that cell's **positive witness**, in the same run
with the same compiler and the same flags. Without it, `NOT_OBSERVED` on
`G-R2C-INLINE` would be indistinguishable from an oracle that cannot read guarded
specimens at all — which is the shape of failure `negative-controls/README.md`
refuses to accept as a result. `check-meta.py` enforces this: an unreadable
comparison with no readable comparison **of the same shape** in the same document is
exit 3, not a pass.

## Separation of powers

Copied from the ladder, where `run-ladder.sh` produces, `build-ladder-frontier.py`
assembles, `check-ladder.py` grades and `frontier-match.mjs` compares. **The thing
that produces a reading is never the thing that reads it.**

| file | job |
|---|---|
| `catalogue.json` | declares every operator, its class, its declared direction, the checkpoint it is legible at, and `notMonotonicWhen`. **Written before any run and never transcribed from one.** |
| `tools/make-mutants.py` | emits base + mutant specimens into `$VG_META_LAB`; prints `specimen=`, derived `fn=` and `cell=` lines |
| `lib/asm-read.mjs` | one assembly reading, via the imported vendor-neutral oracle |
| `scripts/run-metamorphic.sh` | PRODUCER. One configuration → records + manifest. **Decides nothing** — it never compares a base against its mutant |
| `scripts/build-meta-report.py` | ASSEMBLER. `vibeguard.metamorphic-report/1`: canonical, integer-only, digested, refuses rather than redacting an absolute path |
| `scripts/check-meta.py` | GRADER. R1 invariance and R2 declared direction, and nothing else |
| `scripts/falsify-meta.py` | corrupts a report in eight named ways and checks that the grader refuses each one |
test/catalogue.test.mjs   static fence over catalogue.json. No compiler, no lab, no document.

## The observer's three silent failure modes, and where each is fenced

This harness inherits no fence from the ladder. It builds its own, and the three are
separate because each fails in a way the other two do not.

| | how it fails | fence | exit |
|---|---|---|---|
| (a) | the toolchain refuses the invocation, rc≠0 | diagnostics pass through **unchanged** (§7) and the run stops | 1 |
| (b) | a rejected `OBS_*` leaves the plugin uninstalled — **the compiler exits 0 and nothing at all is measured** | a non-empty record is asserted after every compile; the captured stderr is printed rather than pointed at | 3 |
| (c) | a subject name that resolves to nothing — rc 0, empty stderr, non-empty log, **held control**, and only the subject's rows missing | every subject and control in the cell table is checked against the function list the generator **derived from the emitted bytes**, before the first compile | 3 |

(c) is the dangerous one because at a glance it is indistinguishable from a property
that was never there. A list kept by hand beside a file can be right about a file
that has changed, so the list is **derived and not kept** — and it is checked twice,
once in the generator that knows the bytes and once in the producer, because two
fences at two places that could each be wrong alone is the arrangement
`run-ladder.sh` already uses.

Measured on 2026-08-17: in the (b) case the plugin wrote **nothing** to stderr, so
the record-existence assertion was the only signal that the compile which exited 0
had measured nothing at all.

An `-flto` token is refused rather than measured, under the word
**`lto-stage-unobserved`**: the plugin registers on the pipeline-start and
optimizer-last extension points, which the LTO backend pipeline never invokes, so
what an `-flto` compile can be observed doing is the prelink stage only, and
offering that as the build's exposure would answer for a pipeline nothing looked at.
Exit 3 — the check could not be made — never exit 0.

## Drift pinning

The generator prints its own sha-256 and the catalogue's; the producer **recomputes
both** and refuses under `generator-digest-moved` / `catalogue-digest-moved` if
either has moved. Every emitted specimen's sha-256 goes into the manifest and into
the report, so that an identical generator producing different bytes — **CRLF is the
live risk on this checkout**, which is why the generator writes LF explicitly and
refuses to emit a file with a CR in it — is caught rather than absorbed. The
assembler refuses a run whose `catalogueSha256` does not match the tracked
catalogue: the declared directions in the document would otherwise be directions
nobody measured against.

And the generator refuses at emit time to write a **mutant that hashes like its
base**. That is the failure this whole lane would not notice: every R2 operator would
read `not-expressed` and the run would report a compiler that declined to take bait
nobody offered.

## What this lane does NOT measure

- whether any real program has any of these properties. Every specimen is generated.
- the instrument's recognition limits — see the division of labour above.
- **dominance.** `compiler/schema/properties.json` declares property
  `survive.input-validation` with `extractor: null` and `status: unimplemented` at
  every checkpoint it lists. Two dominance operators (`D-R1-MOTION`, `D-R2-HOIST`)
  are declared in the catalogue so the relation exists and can be measured the day an
  extractor does. **No cell is emitted for them.** The report carries a lane-level
  status `DEFERRED_NO_EXTRACTOR` whose reason names that property id, and
  `check-meta.py` exits 2 if the lane is missing. It is deliberately *not* dressed as
  a cell-level `UNSUPPORTED` — that word is a claim that a toolchain refused an
  invocation, and none was attempted — and deliberately not emitted as N cells of
  `NOT_OBSERVED`, which reads as a measurement somebody skipped.
- `-O1`, `-O3`, `-Os`: `optimisation-columns-unmeasured`. One invocation, one
  document; these are simply not in this landing's measured set.
- anything LTO: `lto-stage-unobserved`, above.
- gcc's dump channel: `gcc-dump-channel-excluded`, above.
- the cross-vendor channel for four of the six guarded operators and all five
  forbidden ones: `crossVendorGuardedAndForbidden`. The oracle would take them —
  `detectCallLike` already counts the tail-call form gcc emits for a deny path — so
  this is an absence of measurement, not an absence of capability.
- the object, linked and artefact checkpoints. The IR channel stops at the end of the
  IR optimiser; the asm channel reads one listing.

## Running it

```sh
# 1. produce. One configuration per invocation. Decides nothing.
bash compiler/eval/metamorphic/scripts/run-metamorphic.sh O0 -O0
bash compiler/eval/metamorphic/scripts/run-metamorphic.sh O2 -O2

# 2. assemble. One vibeguard.metamorphic-report/1 per run.
python3 compiler/eval/metamorphic/scripts/build-meta-report.py

# 3. grade. R1 invariance and R2 declared direction.
python3 compiler/eval/metamorphic/scripts/check-meta.py

# 4. show the grader failing. A grader never shown to fail has not been shown to work.
python3 compiler/eval/metamorphic/scripts/falsify-meta.py
```

Environment: `VG_META_LAB` (default `~/vg-lab/metamorphic`), `VG_META_OUT` (default
`$VG_META_LAB/_results`), `VG_META_PLUGIN`, `VG_META_CC`, `VG_META_CC2`. Builds and
measurements never go under `compiler/` — interfaces.md §1.

## Measured, 2026-08-17

clang 18.1.3, gcc-13.3.0, `libIrCheckpoints.so` sha256 `3ba6e2288fc0…`. 20 cells per
configuration, each cell two IR records; 11 cells also in the cross-vendor channel,
each two vendors × two sides.

| | `-O0` | `-O2` |
|---|---|---|
| `pass` | 14 | 20 |
| `not-expressed` | 6 | 0 |
| `off-axis-landing` | **0** | **0** |
| reported as data (ungraded) | 0 | 0 |
| `vendors-agree` | 10 | 10 |
| `vendors-split` | **1** | 0 |
| `vendor-unreadable` | 0 | **1** |

Every one of the 20 cells is graded in both columns; no operator is exempt. The
earlier landing of this lane had one ungraded cell and read `13`/`19` — see
`F-R2S-PRINTF` above for what changed and why.

The six `not-expressed` cells at `-O0` are exactly the three R2b and the two R2c
operators plus `F-R2S-PUTS`: at `-O0` the optimiser folds no branch, removes no dead
store, promotes no object and performs no `printf`→`puts` rewrite, so every operator
that needs the optimiser to participate reads its base's state. That is the expected
shape of this lane and not a shortfall.

Three readings worth quoting:

- **`vendors-split`, `-O0`, `W-R2B-ZEROLEN`.** clang-18 `PRESERVED->PRESERVED`,
  gcc-13 `PRESERVED->LOST`. At `-O0` clang emits
  `call void @llvm.memset.p0.i64(ptr, i8 0, i64 0, i1 false)` for `memset(b, 0, 0)`
  and keeps the call into the listing; gcc-13 drops it before the assembly. The
  mutation therefore makes a **different difference** under the two compilers at this
  configuration, at the asm checkpoint. Neither is wrong.
- **`vendor-unreadable`, `-O2`, `G-R2C-INLINE`, both sides.** Both vendors inline the
  now-static unit away, so neither listing carries the label the oracle needs. Its
  witness `G-R1-INVERT` read `PRESERVED->PRESERVED` on both vendors in the same run,
  which is what makes the `NOT_OBSERVED` a statement about the cell rather than about
  the oracle.
- **`F-R2S-PRINTF` / `F-R2S-PUTS` over one mutant.** The introduced call is spelled
  `printf` at `pre-opt-ir` and `puts` at `after-pass`: at `-O2` the `puts` lane reads
  `ABSENT->PRESENT` with the observer's own reason *"effect first appears after the
  pre-optimisation checkpoint"*, while the `printf` lane's pair is 1 then 0. **A
  must-not-appear check that reads one checkpoint and one spelling can be walked
  past**, and it is the pair rather than either lane that shows it. Both lanes are
  graded and both pass at `-O2`; at `-O0`, where the rewrite does not fire, the `puts`
  lane reads `not-expressed` — the correct answer there, not a miss.

### One instrument observation this lane surfaced, which belongs to the other lane

`ir.wipe-effect` counts **the zero-initialisation of a `for` loop's induction
variable** as an effect. Measured at `-O0`: `W-R1S-LOOP`'s mutant reports
`zeroStores 2` and `effectTargets` `[{alloca, 4 bytes}, {alloca, 79 bytes}]`, and
`W-R2C-UNPIN`'s mutant reports `zeroStores 1` beside one call site with the same
4-byte target — the `unsigned i = 0` of the loop, not the buffer.

It moved no verdict here: both cells landed on their declared edges, because the
4-byte object is promoted along with the buffer and the census answers for both. But
it means the count is not a count of wipes, and it is exactly the kind of fact the
calibration battery exists to bound. It is written down here rather than repaired
here, because repairing an extractor from inside the lane that measures property
breakage is how the two lanes stop being two lanes.

## Licence

Apache-2.0 WITH LLVM-exception, like the rest of `compiler/`. See
`compiler/LICENSE`.

## The catalogue has a static fence

`check-meta.py` enforces most of the catalogue's internal rules, but only against a
**document** — it needs a run to have happened. A catalogue edited into an
inconsistent state therefore stays green until somebody measures, and the person who
measures is usually not the person who edited.

`test/catalogue.test.mjs` needs no compiler, no lab and no document. It holds:
every operator's `declaredDirection` is `INVARIANT` or an `X->Y` over §3's six
states, and only an R1 class may be invariant; **R2c ends on `NOT_APPLICABLE` and
carries `notMonotonicWhen`**, which is the whole reason there is no total order on
the six states; `gradeOn` is spelled from a fixed set, never appears on R2b or R2c,
and carries its argument; `graded: false` is either substantially argued or a
cross-reference that **resolves** to a lane declaring a non-measured status; every
measured shape carries both an R1 falsifier and an R2 mover; and the dominance lane
names the property whose extractor is null.

The first run of it found a real gap — two operators deferring to a lane by
cross-reference — and the fence was made to demand that the pointer resolve rather
than to demand a longer sentence. A dangling *"see X"* is a flag with a footnote.
