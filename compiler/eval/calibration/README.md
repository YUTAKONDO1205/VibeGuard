# calibration — a probe is qualified by reading a set whose answers were fixed before it arrived

The IQI ladder next door answers "what does *this build's* optimiser do to
property-shaped code". It does that by compiling a graded specimen under the
build's own command line and reading which rungs survive — the radiographic
penetrameter, applied to a compiler.

A ladder tells you nothing about whether the **probe** reading it works. That is
this directory. It is the metrology half: a set of reference specimens with **known
true values**, established before any probe is pointed at them, so that an
extractor can be qualified by being made to read them.

> The error model is **measured**, not derived. Nothing here argues from an
> extractor's source about how it ought to degrade. It builds specimens whose
> answers are already known and reads what the extractor says.

## The two questions, and why they are two files

| Question | Grader | Failure means |
|---|---|---|
| Does the extractor read a known true value correctly? | `scripts/check-battery.py` | a defect in the extractor |
| Does the catalogue's English description of the extractor's weaknesses match what it does? | `scripts/check-claims.py` | a defect in the prose, or in the code the prose describes |

One grader doing both jobs would let either go green behind the other.

## Separation of powers

Copied from the ladder (`run-ladder.sh` produces, `build-ladder-frontier.py`
assembles, `check-ladder.py` grades), with one addition: **the thing that produces
a reading does not hold the answers.**

```
tools/make-battery.sh          the STANDARD. Emits 19 specimens into the lab. Pinned by sha-256.
battery.json                   the cell table: what is measured. No answers in it.
claims/expected.json           the answers. Opened by check-battery.py and by nothing else.
claims/degradation-claims.json Experiment 1's ledger: every degradationRisk sentence, verbatim.
scripts/run-battery.sh         PRODUCER. One configuration -> records + listings + manifest. Decides nothing.
scripts/witness-asm.mjs        the independent leg, at the `asm` checkpoint. Decides nothing.
scripts/build-battery-report.py ASSEMBLER. Applies interfaces.md §3.1's pairing rule. Grades nothing.
scripts/check-battery.py       GRADER: readings against known true values.
scripts/check-claims.py        GRADER: the catalogue's prose against the measurement. Runs no compiler.
```

## How a "known true value" avoids being circular

`known-PRESENT` decided by the extractor under test is not a calibration, it is a
regression test wearing metrology vocabulary. Every cell therefore stands on at
least one channel that is **not** `ir.wipe-effect`, `ir.guarded-call` or
`ir.forbidden-callee`, and `claims/expected.json` names the channels per cell in
`truthArgument`:

- **construction** — the C language forbids the other readings. A wipe whose zeros
  are afterwards read by an opaque consumer cannot be removed by a conforming
  compiler. This channel consults no instrument at all.
- **asm-witness** — `second-vendor/lib/asm-oracle.mjs`, imported not copied, on a
  listing from the *same* invocation compiled *without* the pass plugin. A
  different instrument at a different checkpoint. It is **coarser**: no pass
  attribution, and **it cannot tell `LOST` from `NOT_APPLICABLE`** — so it is never
  the channel that decides that discrimination.
- **asm-witness-structural** — three readings of the same listing that are not
  effect counts, and they decide what the counts cannot:
  - the **stack frame** the body reserves. `cal-wipe-napp`'s object is **199
    bytes**, chosen above the 128-byte x86-64 red zone precisely so that an object
    still in memory *requires* a visible `sub $N,%rsp`. Measured at `-O2`: frame 0
    → the object is not in memory → `NOT_APPLICABLE`, without ever consulting the
    alloca census being calibrated.

    **This witness was unsound as first written**, and the repair is worth reading
    before trusting it. Its own header called the number *"a lower bound on what the
    function reserves"* and then concluded *"a frame this small cannot hold an object
    of size S"* — an inference that needs an **upper** bound. The comment stated the
    premise that broke its own conclusion. It is an upper bound exactly when every
    write to `%rsp` in the body is one of four accounted-for forms; any other —
    `subq %rax,%rsp`, `andq $-32,%rsp`, a `leaq`/`mov` into `%rsp` — now yields
    `undecidable` instead of a verdict. And the reading is now **declared and graded**
    (`expectFrameRulesOutObject`, both directions), because an adversarial pass found
    it computed and held against nothing.
  - the **subject's own label**. `cal-guard-napp` at `-O2` has none; at `-O0` it
    does. That pair separates "the unit is genuinely gone" from "the observer
    failed to resolve a name", which look identical in a record.
  - whether a call is **indirect**, so the two indirect probes can be shown to
    still be probing what they claim.
- **defined-fns** — names read back out of the emitted bytes.

### What a `known-broken` cell is

A cell whose **control is designed to fall**. interfaces.md §4: a measurement whose
control's count also reached zero is a *broken measurement, not a finding*. Its
expectation lives in the apparatus column, not the state column:
`expectedMeasurement: BROKEN_MEASUREMENT` with `trueState: NOT_OBSERVED`, per
§3.1's pairing rule.

Each of the three is expected to be broken at `-O2` **and OK at `-O0`**. Both
directions, because a cell that reported a broken apparatus at every configuration
would be indistinguishable from a harness that always says so.

These cells also test the *harness* rather than the extractor, and that is worth
stating plainly: **the raw observer records do not obey the pairing rule.** Measured
2026-08-17, `cal-wipe-broken` at `-O2` carries `verdict.state = LOST` beside
`control.held = false`. `build-battery-report.py` is the only thing standing between
that word and a reader; it keeps it as `rawRecordState` and never as `state`, and
the known-broken cells are how anyone finds out whether it still does.

### An open question this lane inherited, not one it settled

§3.1 says a cell whose `measurement` is not `OK` carries `controlHeld` **null** —
*"not `false`, which would claim a control was run and failed"*. On a **fallen**
control that claim is factually true, so the rule and the fact pull apart, and the
tree currently answers it two ways:

| | fallen control is recorded as |
|---|---|
| `llvm-pass/scripts/build-ladder-frontier.py:479` | `controlHeld = bool(control["held"])` → **`false`**, with a separate `broken` flag |
| this lane, and `eval/metamorphic` | **`null`**, per §3.1's literal text, with the fact kept in `rawRecordControlHeld` (here) and `brokenReason` + the raw control counts (there) |

Both preserve the fact; they disagree about which field carries it. This directory
took the §3.1-literal reading because a consumer reads `controlHeld` as *"this
cell's apparatus is sound"*, and a fallen control must not be able to present as a
sound apparatus with a bad answer. **That is a choice, not a resolution.** Settling
it needs a sentence in §3.1 saying where a fallen control's fact belongs, and
interfaces.md opens by saying nobody edits it while implementing against it — so it
is recorded here as a request rather than taken.

## The dominance lane has no probe, and says so

`compiler/schema/properties.json`, property `survive.input-validation`:
`extractor: null`, with the note that *a control for a dominance property is not the
same shape as a control for a count*. So the fourth shape ships **two specimens and
no probe**, and the lane appears in every report as:

```
lane dominance: no-probe -- ... survive.input-validation, extractor: null ...
```

Deliberately **not** `UNSUPPORTED`: §3.1 fixes that word as a claim about the
*compiler* refusing an invocation, and nothing was refused here. Deliberately not a
row of `NOT_OBSERVED` cells either, which would read as a measurement somebody
skipped. `check-battery.py` exits 3 if the lane is missing from a document, because
a lane that is absent reads as a shape nobody thought about.

Shipping the standard before the probe is the correct metrological order: whoever
writes the dominance extractor has to make it read a set it did not choose. A
battery assembled afterwards by the same hand that wrote the probe would be that
probe's own homework.

## Experiment 1 — the catalogue's prose against the measurement

`compiler/schema/properties.json` carries, per extractor, a `degradationRisk` list
of English sentences describing how it degrades and in which direction it errs.
Other documents quote them as fact. Nothing had ever held one against a measurement.

`claims/degradation-claims.json` is one entry per sentence, the sentence copied
**verbatim**, and — where the sentence predicts a reading — a fixture and the
reading it predicts. `check-claims.py` recomputes the sentence list from the
catalogue and diffs it against the ledger: a sentence with no entry, or an entry
whose copy has drifted, is exit 3 under `claims-coverage-broken`. **That fence is
the honesty mechanism.** An untested sentence still has to be entered with a
reason, and editing the catalogue forces the ledger to move in the same commit.

Fenced scope: the `degradationRisk` arrays of the three implemented extractor
entries — 14 sentences. The per-*property* arrays elsewhere in the catalogue are
**not** fenced by this revision.

### Result, standard revision 5, clang 18.1.3, 2026-08-17

```
claim-agrees            7     the documented degradation is real and correctly described
doctrine-held           2     the prescribed apparatus arrangement holds
claim-deferred          6     testable in principle, no specimen yet
claim-not-a-prediction  3     the sentence predicts nothing measurable here
```

`check-claims.py` **exits 0** at this revision. It did not at revision 3 or 4, and
the two findings that held it at exit 2 are what this experiment was for. Both are
now described in the catalogue:

**★ Finding 1 — `degradationRisk[1]` named the wrong trigger.** It said two
same-size allocas in a unit make the verdict *"fall back to LOST"*. They do not:
`IrCheckpoints.cpp:195-201` compares the **count** of objects of that size
(`return After >= Before;`), so the count falls with the promoted object and
`NOT_APPLICABLE` is correct — measured on `cal-wipe-samesize`.

The first write-up called that the catalogue *overstating* a weakness. An
adversarial pass falsified **that** reading in turn: the degradation is real and its
trigger is **broader**. `cal-wipe-inlinesize` now pins it — one 192-byte buffer
promoted away, a static helper's own 192-byte local inlined in:

```
pre  sizes [4, 192]   effect 2      control HELD
post sizes [192]      effect 0      verdict LOST      (truth: NOT_APPLICABLE)
```

The count held because a pass **created** an object of that size. So inlining
reintroduces same-size collisions regardless of source-level prime hygiene, and this
battery's own size-discipline rationale was demoted with the sentence. The sentence
was rewritten to name the real trigger; `cal-wipe-samesize` became a **reference**
cell, since what it measures is the census working.

**★ Finding 2 — the zero-store over-count was in no sentence at all.** That half
counts **any** null-constant store whose underlying object is an alloca or pointer
parameter (`Extractors.cpp:237-246`) — no relation to the property's object, no size
floor. So `int flag = 0;` is counted as the wipe. `cal-wipe-zeroinit` at `-O2`: the
real 181-byte wipe is removed (`effectCallSites = 0`) while `flag` keeps
`zeroStores = 1`, so the cell reads **`PRESENT` with its control HELD while the
property is `LOST`**.

This errs **towards `PRESENT`** — the report says the defence is there. Every other
risk in that list errs towards a visible `ABSENT` or `LOST`. A sentence was appended
as `degradationRisk[7]`.

The asm oracle shares this flaw (`detectInlineZeroStore` counts `movl $0, 12(%rsp)`
too), so cross-checking the two instruments would **not** have found it. Only the
construction argument did.

**Why the amendment is a separate change from the measurement.** A battery that
repairs its own subject in the act of measuring it has stopped being an independent
measurement. Revisions 3 and 4 measured and exited 2; revision 5 amends the
catalogue, moves this ledger in the same commit because the coverage fence forces
it, and only then reaches exit 0. Closing the loop also ran the exit-0 path for the
first time and found a `KeyError` and a `TypeError` sitting on it — both repaired.

## What a battery pass licenses

**A shape qualification, and nothing more.** Every cell is a
`(synthetic-specimen, configuration)` measurement. `implemented` in
`properties.json` requires a fixture in this repository to have measured a named
**property** in a named configuration, and no cell here does that for any property
in that catalogue.

This is the same trap `envelope/frontier-match.mjs` guards against with its
★ GUARD-ONLY rule: a ladder rung may *refuse* a cell and may never *fill* one. A
battery pass is **necessary for promotion and never sufficient**. Promotion is a
double gate: pass the battery, and measure the property.

## Running it

Everything below runs on the Linux side. Builds and measurements never go under
`compiler/` — interfaces.md §1.

```sh
bash compiler/eval/calibration/scripts/run-battery.sh O0 -O0
bash compiler/eval/calibration/scripts/run-battery.sh O2 -O2
node   compiler/eval/calibration/scripts/witness-asm.mjs O0
node   compiler/eval/calibration/scripts/witness-asm.mjs O2
python3 compiler/eval/calibration/scripts/build-battery-report.py O0
python3 compiler/eval/calibration/scripts/build-battery-report.py O2
python3 compiler/eval/calibration/scripts/check-battery.py     # 0 on revision 5
python3 compiler/eval/calibration/scripts/check-claims.py      # 2 on revision 5, by design
```

Lab: `$VG_CAL_LAB`, default `~/vg-lab/calibration`. Plugin: `$IRCK_PLUGIN`.
Compiler: `$IRCK_CC`, default `clang-18`.

### Pinning the standard

`battery.json` carries `generatorSha256` and an integer `standardRevision`.
`run-battery.sh` recomputes the generator's digest and refuses to measure on a
mismatch, under `calibration-standard-drifted`. A generator that changed is a
different standard, and a report assembled across two of them is comparable with
nothing while looking comparable with everything. Change the generator and
`battery.json` in the same commit.

CRLF is not a live risk here: `.gitattributes` already pins `compiler/** text
eol=lf`, so the generator's bytes are the same on both sides of the mount.

## How to read a failure

Three failures, three meanings, and the graders do not conflate them:

- **a REFERENCE cell misread its true value** — a defect in the extractor. Fix the
  extractor. **Do not edit `claims/expected.json`**: that makes the cell green and
  leaves the instrument exactly as it was, behind a tick. It is the failure
  `compiler/eval/negative-controls/README.md` names.
- **an expectation's construction turned out to be wrong** — fix the *generator*,
  not the expectation. Two specimens were changed that way on 2026-08-17 and both
  carry the reason at the specimen in `tools/make-battery.sh`:
  `cf_forbidden_entry` needed `noinline` because its control's direct call was
  being inlined away, and `cal-wipe-zeroinit`'s statement order was wrong — an
  opaque call standing *after* a wipe may observe the zeros, so the wipe was not
  dead and the cell measured nothing.
- **a cell could not be graded** — exit 3 territory, never counted as clean. An
  `expectDefinedInAsm` declaration disagreeing with the listing in *either*
  direction lands here: in neither direction is that cell's state evidence of
  anything.

`check-battery.py` prints **NOT ESTABLISHED** rather than a pass when no cell in
the whole set read a `BROKEN_MEASUREMENT`: a battery whose apparatus column was
never seen to fire is indistinguishable from a grader that always reports OK.

## What this directory does not measure

- `-O1`, `-O3`, `-Os` — **not-measured**. The ladder's finding that `-O2`/`-O3`/`-Os`
  are indistinguishable belongs to *its* rung set and is not transferable here.
- anything LTO — **`lto-stage-unobserved`**, refused at measurement time.
- the `object`, `linked` and `artifact` checkpoints — no extractor to qualify.
- a second compiler vendor. `gcc` cannot load an LLVM `-fpass-plugin`; the
  cross-vendor question belongs to `../second-vendor` and `../metamorphic`.
- the dominance shape — **`no-probe`**.
- machine-to-machine variation. One host.

## Licence

Apache-2.0 WITH LLVM-exception, like the rest of `compiler/`. See
`compiler/LICENSE`.
