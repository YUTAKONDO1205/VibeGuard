# eval/spike — the spike/recovery self-test gate

An analytical laboratory does not ask an assay whether it is working. It adds a
known quantity of the analyte to the sample, reports how much of it came back
beside the result, and **invalidates the batch** when recovery is short — not
because the spike matters, but because the instrument has just been shown, on
*this* run, not to see what it is for.

This lane is that move, for the erasure instrument. Every run mixes in two known
translation units — one whose wipe the optimiser is permitted to delete, one
whose it is not — and judges them with the **same** `verdictOf` the corpus lane
and the repair loop judge their cells with. Recovery short of 2/2 in any
configuration makes the whole run INVALID and no measurement in it may be
written as data — and so does a run in which *no* configuration ever required
the two spikes to read differently.

It exists because of a sentence in
`compiler/pass-instrumentation/observer/README.md`:

> **No harness in this repository invokes `check-subject-resolution.mjs`.** As of
> 2026-08-17 its only caller is `test/subject-resolution.test.mjs`;
> `scripts/run-all.sh` does not run it, and it is not wired into CI.

The third silent failure — a subject name that resolves to nothing — was made
*audible* and *recorded*, and then nothing was made to listen. A checker nobody
calls is a checker that has been written, not a check that is performed. This
lane is the automatic caller, on both channels, with the gate re-earning its
claim to be a gate on every run.

## The mechanism

| | |
|---|---|
| **spike** | a translation unit whose behaviour under the instrument is registered in advance |
| **recovery** | how many of the two spikes read what was registered, as `k/2` |
| **discriminating** | a configuration whose two spikes are registered to read **different words** |
| **injection** | a third measurement, deliberately broken, that the gate **must** refuse |
| **established** | recovery 2/2 in every configuration, **at least one** discriminating configuration, **and** the injected run went red |

A run that is not `established` is reported NOT ESTABLISHED, and **no
measurement taken in it may be written as data**. The run's own report,
`spike-gate.json`, is still written to the lab — for a red run too, which is the
copy a reader needs — unless `--no-write` is passed; nothing in the repository
consumes it. Four things are deliberately *not* treated as passes:

* **A spike that did not compile is FAILED, never "held".** `COMPILE_ERROR`,
  `ABLATION_DID_NOT_COMPILE`, `NOT_OBSERVED`, `NO_WIPE_WRITTEN`,
  `VERIFICATION_INCOMPLETE`, `UNSUPPORTED` and `BROKEN_MEASUREMENT` are readings
  about the instrument, not about the code. A gate that counted an unreadable
  spike as an absent violation would be green exactly when the instrument is
  most broken. This is the vacuous pass, and refusing it is most of the point.
* **An unregistered configuration recovers nothing.** A spike graded against no
  expectation always passes. `clang-19 -O2` reads exactly what `clang-18 -O2`
  reads on this host (measured below) and is still refused, because nothing was
  registered for it.
* **A run of only non-discriminating configurations is NOT ESTABLISHED.** At
  `-O0` both spikes are registered `WIPE_SURVIVED`, so 2/2 there is also what an
  instrument that can only ever say `WIPE_SURVIVED` would score. See below: this
  was a hole in the gate until 2026-09-12 and it was demonstrated, not imagined.
* **A run that did not perform the injection is NOT ESTABLISHED**, and neither is
  one whose injection was measured where nothing is registered. A gate that has
  never been watched refuse has not been shown to be a gate — and a check that
  *could not have failed* is not a watching.

## What is here

```
run-spike.mjs                  the CLI; measures, grades, prints, exits 0/2/3/4
lib/measure.mjs                produces readings. Cannot see the answers.
lib/claims.mjs                 the only module that opens the registered answers
lib/spike.mjs                  gradeSpike / gradeInjected / gateVerdict. PURE.
lib/gate.mjs                   runSpikeGate(): the function other harnesses call
lib/observer.mjs               the second channel, under libPropertyObserver.so
claims/spike-expected.json     the answers, registered per (vendor, level)
subjects/spike-disappearing.c  the wipe the optimiser may delete
subjects/spike-surviving.c     the wipe it may not
tools/make-spike-lab.sh        materialise both spikes for reproduction by hand
test/spike.test.mjs            the grader, in both directions
test/lane.test.mjs             separation, subject shape, claims
```

Nothing is written under `compiler/`. Sources, listings and the report go to a
lab directory outside the repository, and a lab inside it is refused
(`interfaces.md` §1; `scripts/check-packaging-invariants.mjs` line 1274 refuses a
tracked path with a `fixtures` or `_results` segment, and this lane has neither).

## The two spikes

`subjects/spike-disappearing.c` is the erasure fixture's `handle_request` shape:
a buffer that escapes into two functions the translation unit cannot see,
filled, read, then wiped. The wipe is the last use, so it is a dead store and
the optimiser is *permitted* to delete it. Its disappearance is the recovery
reading.

`subjects/spike-surviving.c` is the fixture's `wipe_kept` shape: the same
buffer, wiped, and then **read**. The read makes the zeroes observable, so no
level of either vendor may remove the wipe.

The surviving half is the one that catches a different failure. A pair with only
the disappearing member would pass for an instrument that reports
`WIPE_ELIMINATED` for everything — an ablation whose two compiles were
accidentally the same file, a body reader returning the same empty string twice.
Survival here is *structural* (the wipe is read afterwards) rather than a
property of a spelling the optimiser is told to leave alone, so the pair keeps
working on a libc without `explicit_bzero` and under a different effect-symbol
list. **No wipe-symbol list is written anywhere in this lane**: the positive
control is the `CONTROL` imported from `../ai-generated/lib/ablation-cell.mjs`
and appended at compile time, and the observer channel reads its symbol list out
of `compiler/schema/effect-symbol-lists.json` (group `wipe-5-observer`) rather
than spelling one — `compiler/schema/effect-symbol-lists.test.mjs` fails on a
literal the registry does not declare, and rightly.

## Both subjects report VG-MEM-006, and one of them is the interesting one

The shipped analyser scans this repository, `compiler/` included, and it reports
`VG-MEM-006 Secret buffer cleared with a removable memset` on **both** subjects:
`spike-disappearing.c:56` and `spike-surviving.c:35`. Neither is suppressed, and
neither should be.

`spike-disappearing.c` is the easy half: the rule is right, the wipe is a dead
store, and the compiler removes it at every level above `-O0`. The source rule
and this lane's differential verdict agree, and a subject that did NOT report
would be the wrong subject.

`spike-surviving.c` is the half worth reading. The rule reports it, and this
lane's instrument measures `WIPE_SURVIVED` at every registered level on both
vendors. **They disagree, and the disagreement is not a defect in either of
them**: the rule reads the source lexically, where a `memset` on a secret buffer
looks removable whatever follows it; the instrument compiles both forms and
compares the emitted body, where the read that follows the wipe makes its zeroes
observable and no optimiser may delete them. A lexical reader cannot see that
and is not pretending to.

So the pair is also a small, standing example of the thing the closed loop
exists to measure: **where the source-side rule and the artefact-side
measurement part company, and which of them the reader should act on.** Here the
rule's finding is a true statement about the source shape and a false alarm
about the artefact, and it is the artefact that ships. That is recorded here
rather than silenced in `.vibeguardrc.json`, because a suppression would delete
the example along with the noise.

## Pre-registration, and why the runner cannot see the answers

`claims/spike-expected.json` holds what each spike must read per
(vendor, level). `lib/measure.mjs` — the half that produces a reading — does not
import it, does not name it, and does not spell a verdict it could compare
against; `test/lane.test.mjs` pins that by grepping `measure.mjs`'s own source,
so the guarantee survives an edit that only meant to improve a comment. This is
the separation `compiler/eval/calibration` keeps between the script that measures
a configuration and the file that says what it should read, for the same reason:
an instrument that can see the expected answer can be adjusted until it agrees,
and afterwards nobody can tell whether it was adjusted or measured.

The expectations are **grounded in tracked data, not in a first run**:

* `-O0` — of the 321 erasure files in
  `compiler/eval/ai-generated/data/r2-build-rows.json`, **zero** read
  `WIPE_ELIMINATED` at `-O0` on clang-18 and zero on gcc-13 (319 `WIPE_SURVIVED`
  and 2 `ABLATION_DID_NOT_COMPILE` in each). So `-O0` registers `WIPE_SURVIVED`
  for **both** spikes: an elimination at `-O0` would be a reading about the
  instrument, not about the code. `test/lane.test.mjs` re-derives that count from
  the tracked rows, so if a future re-measurement ever puts an elimination at
  `-O0` the ground under the expectation has moved and the test fails rather than
  the gate quietly staying green. Registering one word twice is right here and
  costs something: read the next section before treating a `-O0` run as a check.
* `-O1`..`-Os` — eliminations start at `-O1` in the same rows and do not change
  with level above it (clang-18 62/113/113/113, gcc-13 108/108/108/108 at
  `-O1`/`-O2`/`-O3`/`-Os`), and the disappearing spike is the shape those
  eliminations are of.

The expectations were written **before** the first measurement and were not
edited afterwards. All ten registered configurations recovered 2/2 on the first
run that could compile the subjects. An expectation edited to fit its
measurement has stopped being an expectation.

## Discriminating configurations — the hole this gate had

Read the `-O0` row again. Both spikes are registered `WIPE_SURVIVED`, on both
vendors, and correctly so: the tracked rows have never put an elimination there.
But a configuration whose two registered answers are the **same word** cannot
separate an instrument that is reading from one that is not. Recovery 2/2 at
`-O0` is exactly what an instrument that reports `WIPE_SURVIVED` for everything
would score.

That was not a hypothetical. Until 2026-09-12 the gate required only 2/2
everywhere plus a red injection, so:

```
# verdictOf made structurally unable to ever report an elimination, in a COPY of
# the lane (ablation-cell.mjs: `cell.verdict = 'WIPE_SURVIVED';` unconditionally)
$ node run-spike.mjs --cc clang-18,gcc-13 --opt -O0 --no-write --out ~/vg-lab/blind
spike gate: ESTABLISHED -- clang-18-O0 2/2 | gcc-13-O0 2/2 -- injection RED (as required)
EXIT=0
```

A blind instrument, 2/2 on both vendors, injection red, exit 0. The same break at
`--opt -O0,-O2` was caught (`recovery 1/2 -- WRONG_VERDICT(disappearing)`), which
is the whole difference: `-O2` registers two different answers and `-O0` does
not.

So `gateVerdict` now also requires **at least one discriminating configuration**
— one whose two registered answers differ — and a run without one is
`NO_DISCRIMINATING_CONFIGURATION`, red, exit 2, naming every configuration it
had and the one word each registered. On the pristine lane today:

```
$ node run-spike.mjs --cc clang-18,gcc-13 --opt -O0 --no-write --out ~/vg-lab/a2-o0
spike gate: NOT ESTABLISHED -- clang-18-O0 2/2 | gcc-13-O0 2/2 -- injection RED (as required) -- 0/2 discriminating
  ... both configurations 2/2, both spikes WIPE_SURVIVED, control PRESENT ...

NOT ESTABLISHED. No measurement taken in this run may be written as data.
  - NO_DISCRIMINATING_CONFIGURATION: no configuration in this run registers two different
    answers, so recovering 2/2 in every one of them is also what an instrument that can only
    ever report one word would score. Non-discriminating: clang-18 -O0 (both spikes registered
    WIPE_SURVIVED); gcc-13 -O0 (both spikes registered WIPE_SURVIVED). Add a configuration
    whose two registered answers differ -- any level above -O0 on either registered vendor is one
EXIT=2
```

Two things this rule is **not**:

* **It does not drop `-O0` from the matrix.** `-O0` is a legitimate rung and the
  place where an elimination would itself be a finding *about the instrument*.
  The full matrix below still gates at `-O0` on both vendors and is
  `ESTABLISHED`, because the same run also carries nine configurations that
  discriminate. What is refused is a run made **only** of rungs that cannot tell
  the two spikes apart.
* **The injection does not substitute for it, and it does not substitute for the
  injection.** They fail different ways. The injection misspells the subject's
  *name*: it proves the gate can refuse a run in which nothing observed the
  subject. An instrument stuck on one verdict observes the subject perfectly
  well and passes the injection exactly as a working one does — which is why the
  blind run above printed `injection RED (as required)` on its way to exit 0.
  Both checks are required and each is reported separately: the summary line
  carries `k/n discriminating` beside the injection's word.

The counts are in the record as well as on the line: `verdict.discriminating`
`{num, den}`, and each configuration carries `discriminating` and, when it is
false, the `sharedAnswer` both spikes were registered to read.

## The injection — and the red

Every run also measures with the subject's name deliberately misspelt
(`vgspike_disappearing` → `vgspike_disappearingX`). That is the observer's own
third silent failure transplanted onto this channel: a valid configuration of a
subject that does not exist. `bodyOf()` finds nothing, the reading becomes
`NOT_OBSERVED`, and the gate must refuse it. If the gate stays green under
injection, the entire run is reported NOT ESTABLISHED.

The misspelt spans still resolve — `wipeSpans()` falls back to a name gate when
it cannot find the target's body, and the buffer is called `secret` so the
fallback reaches the same span. That is deliberate: the injected reading has to
fail for the reason being injected (no body to read) rather than for a second,
accidental one (nothing to ablate). `test/lane.test.mjs` pins it.

**The injection must be measured where something is registered.** `--inject-at`
takes any level, independently of `--opt`. At a level the claims file does not
register, every reading is refused as `NO_EXPECTATION` before it is compared, so
the injected grade is red *whatever came back* — including when nothing was
actually broken. It was red by construction, and the line `injection RED (as
required)` was then a statement about the claims file rather than about the
gate's sensitivity. Measured on the pristine lane: with `MISSPELT_SUFFIX`
emptied to `''`, so that the "broken" run was the good run under the correct
name, `--opt -O2 --inject-at -Ofast` printed `injection RED (as required)` and
exited **0**, while the same neutering at the registered default was caught
(`injection stayed GREEN`, exit 2). An injection at an unregistered
configuration is now `INJECTION_NOT_GRADEABLE` and the run is red:

```
$ node run-spike.mjs --cc clang-18 --opt -O2 --inject-at -Ofast --no-write --out ~/vg-lab/a2-ofast
spike gate: NOT ESTABLISHED -- clang-18-O2 2/2 -- injection NOT GRADEABLE (unregistered configuration) -- 1/1 discriminating
  clang-18 -O2 [differential]  recovery 2/2
    disappearing  verdict=WIPE_ELIMINATED control=PRESENT spans=1
    surviving     verdict=WIPE_SURVIVED control=PRESENT spans=1
  injected (subject name + "X") -- the gate must refuse these
    clang-18 -Ofast [differential]  recovery 0/2  NOT GRADEABLE -- nothing is registered for this configuration, so the gate is red either way
      disappearing  verdict=NOT_OBSERVED fn=vgspike_disappearingX
      surviving     verdict=NOT_OBSERVED fn=vgspike_survivingX

NOT ESTABLISHED. No measurement taken in this run may be written as data.
  - the injection was measured at a configuration nothing is registered for, where the gate is
    red whatever the readings say -- so it shows nothing about the gate's sensitivity. Inject at
    a level the claims file registers; this run is NOT ESTABLISHED
EXIT=2
```

A graded injection also records **why** it went red: `redBecause` is the set of
violation codes the refusal rested on, `["NOT_A_READING"]` for the misspelling
this lane injects. "Red" and "red for the reason being injected" are not the same
claim, and the record keeps them apart.

## Two channels

| | decides by | vocabulary |
|---|---|---|
| `differential` | compiling the file and its ablated form and comparing the target function's body | `verdictOf`'s: `WIPE_SURVIVED` / `WIPE_ELIMINATED` |
| `observer` | watching the pass pipeline under `libPropertyObserver.so` and reading the state the property ended in | `interfaces.md` §3: `PRESENT` / `LOST` |

They are different instruments answering the same question about the same two
translation units, which is the only reason running both is worth anything. The
observer channel additionally runs
`compiler/pass-instrumentation/observer/tools/check-subject-resolution.mjs` on
every log it produces, and a non-zero exit turns the reading into `NOT_OBSERVED`
with the exit code beside it — `interfaces.md` §3.1's pairing rule, not a
property state invented for an observation that did not happen.

The observer channel is **opt-in** (`--observer <libPropertyObserver.so>`). A run
without it prints `observer channel: NOT OBSERVED` and says why. An absent
channel that left no trace would be indistinguishable from one that passed.

## What was measured

Measured 2026-09-12 on Ubuntu-24.04 under WSL2, clang-18 18.1.3 / gcc-13 13.3.0,
with `libPropertyObserver.so` as built at `~/vg-build/pass-observer`.

```
$ node compiler/eval/spike/run-spike.mjs --out ~/vg-lab/spike-final \
    --cc clang-18,gcc-13 --opt -O0,-O1,-O2,-O3,-Os --inject-at -O0,-O2 \
    --observer ~/vg-build/pass-observer/libPropertyObserver.so
spike gate: ESTABLISHED -- clang-18-O0 2/2 | clang-18-O1 2/2 | clang-18-O2 2/2 | clang-18-O3 2/2 | clang-18-Os 2/2 | gcc-13-O0 2/2 | gcc-13-O1 2/2 | gcc-13-O2 2/2 | gcc-13-O3 2/2 | gcc-13-Os 2/2 | clang-18-O2[obs] 2/2 -- injection RED (as required) -- 9/11 discriminating
  clang-18 -O0 [differential]  recovery 2/2
    disappearing  verdict=WIPE_SURVIVED control=PRESENT spans=1
    surviving     verdict=WIPE_SURVIVED control=PRESENT spans=1
  clang-18 -O1 [differential]  recovery 2/2
    disappearing  verdict=WIPE_ELIMINATED control=PRESENT spans=1
    surviving     verdict=WIPE_SURVIVED control=PRESENT spans=1
  ... -O2, -O3, -Os on clang-18 and -O0..-Os on gcc-13 all 2/2, with
      disappearing=WIPE_ELIMINATED at every level above -O0 and
      surviving=WIPE_SURVIVED everywhere; control PRESENT in all twenty ...
  clang-18 -O2 [observer]  recovery 2/2
    disappearing  verdict=LOST control=PRESENT subjectResolutionExit=0 firstLoss=DSEPass
    surviving     verdict=PRESENT control=PRESENT subjectResolutionExit=0 firstLoss=-
  injected (subject name + "X") -- the gate must refuse these
    clang-18 -O0 [differential]  recovery 0/2  the gate went RED
      disappearing  verdict=NOT_OBSERVED fn=vgspike_disappearingX
      surviving     verdict=NOT_OBSERVED fn=vgspike_survivingX
    clang-18 -O2 [differential]  recovery 0/2  the gate went RED
    gcc-13 -O0 [differential]  recovery 0/2  the gate went RED
    gcc-13 -O2 [differential]  recovery 0/2  the gate went RED
    clang-18 -O2 [observer]  recovery 0/2  the gate went RED
      disappearing  verdict=NOT_OBSERVED fn=vgspike_disappearingX subjectResolutionExit=2
      surviving     verdict=NOT_OBSERVED fn=vgspike_survivingX subjectResolutionExit=2
EXIT=0
```

Nine of the eleven configurations discriminate; the two that do not are `-O0` on
each vendor, which is what `-- 9/11 discriminating` on the summary line says.
Both are 2/2 and both stay in the matrix.

The written report carries no absolute path, no float and no digest of the
measuring machine: 11 configurations graded, `verdict.configurations`
`{num: 11, den: 11}`, `verdict.discriminating` `{num: 9, den: 11}`, and a scan
for `/home/ /root/ /mnt/ /Users/` and a drive letter finds nothing — checked, not
assumed, and `run-spike.mjs` refuses to write a report that carries one.

### The reds, run rather than described

```
$ node run-spike.mjs --cc clang-19 --opt -O2 --no-write --out ~/vg-lab/spike-red1
spike gate: NOT ESTABLISHED -- clang-19-O2 0/2 -- injection NOT GRADEABLE (unregistered configuration) -- 0/1 discriminating
  clang-19 -O2 [differential]  recovery 0/2
    disappearing  verdict=WIPE_ELIMINATED control=PRESENT spans=1
    surviving     verdict=WIPE_SURVIVED control=PRESENT spans=1
    VIOLATION NO_EXPECTATION (disappearing): nothing was registered for this spike in this configuration
    VIOLATION NO_EXPECTATION (surviving): nothing was registered for this spike in this configuration
  injected (subject name + "X") -- the gate must refuse these
    clang-19 -O2 [differential]  recovery 0/2  NOT GRADEABLE -- nothing is registered for this configuration, so the gate is red either way

NOT ESTABLISHED. No measurement taken in this run may be written as data.
  - clang-19 -O2: recovery 0/2 -- NO_EXPECTATION(disappearing), NO_EXPECTATION(surviving)
  - NO_DISCRIMINATING_CONFIGURATION: ... Non-discriminating: clang-19 -O2 (no pair of registered answers to compare) ...
  - the injection was measured at a configuration nothing is registered for ...
EXIT=2

$ node run-spike.mjs --cc clang-99 --opt -O2 --no-write --out ~/vg-lab/spike-red2
spike gate: NOT ESTABLISHED --  -- no injection -- 0/0 discriminating

NOT ESTABLISHED. No measurement taken in this run may be written as data.
  - not installed on this host: clang-99
EXIT=3

$ node run-spike.mjs --cc clang-18 --opt -O2 --out compiler/eval/spike/_scratch
run-spike.mjs: measureSpikes: the lab directory is inside the repository; measurement
inputs and outputs live on the side that produces them (interfaces.md section 1)
EXIT=4
```

The first is the one worth looking at twice: `clang-19` read *exactly the right
pair of verdicts* and was still refused, because nothing had been registered for
it. That is the anti-vacuous-pass rule doing the only job it has. It now fails
three ways at once, and all three are true of that run: nothing was registered,
so nothing discriminated, so the injection could not be graded either.

Two more reds are shown where they are explained: a run of `-O0` alone
(`NO_DISCRIMINATING_CONFIGURATION`, exit 2) under *Discriminating
configurations*, and `--inject-at` at an unregistered level
(`INJECTION_NOT_GRADEABLE`, exit 2) under *The injection*. Both exited **0**
before 2026-09-12.

### The unit tests

```
$ node --test compiler/eval/spike/test/*.test.mjs
# tests 48
# pass 48
# fail 0
# skipped 0
# todo 0
```

Both directions: the grader is tested on the readings that must hold and on
every reading that must not — each `NOT_A_READING` word, a missing reading, a
duplicated one, an unknown spike, a control that is not `PRESENT`, a wrong
verdict, an unregistered configuration, a failure word smuggled in as the
registered answer, an injected run the gate let through, an injection measured
where nothing is registered, a run of non-discriminating configurations only,
and a run verdict with no configuration at all.

Five of them are about what this lane SAYS rather than what it does: a claims
file that cannot be read must name itself relative to the repository and never by
machine path, the README's account of what a red run writes must match
`run-spike.mjs`, the README must quote `interfaces.md`'s definition of
`UNSUPPORTED` rather than characterise it, and each of the four wiring patches
below must carry the discrimination rule to the file it asks to change, and
`gradeSpike`'s `requireControl` JSDoc must describe a call `gate.mjs` makes. A README
that claims more than the code does is the defect this repository exists to
prevent, so those claims are pinned by tests like any other.

## ⚠ What is gated, and what is not

**Nothing in this repository calls this gate yet.** As of 2026-09-12 its only
callers are `run-spike.mjs` and `test/`. This lane owns `compiler/eval/spike/**`
and nothing else; the wiring into the harnesses that produce data is written out
below as patches for whoever owns those files to apply, and until those are
applied the honest description is:

* **closed** — a spike/recovery gate exists, it is importable as one function, it
  refuses a vacuous pass, it refuses an unregistered configuration, it refuses a
  run in which no configuration ever required the two spikes to read differently,
  it re-earns its own credibility on every run through an injection it can only
  count where the injection could have failed, and it has been run end to end on
  both vendors at five levels and on both channels.
* **not closed** — no harness's data depends on it. A run of the corpus lane, the
  repair loop or either LTO probe today still writes rows whether or not the
  instrument was reading anything.

These harnesses are **not** gated, by name:

| harness | gated? |
|---|---|
| `compiler/eval/ai-generated/lib/build-analyze.mjs` | no — patch below |
| `compiler/eval/repair-loop/run-repair-loop.mjs` | no — patch below |
| `compiler/eval/repair-loop/tools/lto-probe.mjs` | no — patch below |
| `compiler/eval/repair-loop/tools/lto-probe-gcc.mjs` | no — patch below |
| `compiler/eval/calibration/run-all.sh` | **no, and no patch is offered** |
| `compiler/pass-instrumentation/observer/scripts/run-all.sh` | **no, and no patch is offered** |
| `compiler/eval/second-vendor` | **no, and no patch is offered** |
| `compiler/eval/metamorphic` | **no, and no patch is offered** |

The last four are not oversights and are not one-line changes. `calibration`
drives its configurations out of `battery.json` through four separate programs in
a fixed order, and its graders read reports rather than readings; the observer's
`run-all.sh` writes logs for five harnesses and several configurations into one
tree, which is exactly the case the observer's own README says a naive glob
reports as `inconsistent-name`. Wiring either from outside, without owning them,
would produce a green tick over a change nobody measured. **Do not write "the
third silent-failure mode is closed" about any row in that table.**

## Edits requested in files this lane does not own

Five patches. Each is given with five lines of surrounding context. None of them
changes a measurement: the gate runs before the first cell and either lets the
run proceed unchanged or stops it.

### 1. `compiler/eval/ai-generated/lib/build-analyze.mjs` — the corpus loop owner

**1a — import.** Context (the existing import of the cell module and the line
after it):

```js
import {
  CONTROL, maskNonCode, wipeSpans, ablateSpans, bodyOf, compile, pool, verdictOf,
} from './ablation-cell.mjs';
const HERE = dirname(fileURLToPath(import.meta.url));
```

becomes

```js
import {
  CONTROL, maskNonCode, wipeSpans, ablateSpans, bodyOf, compile, pool, verdictOf,
} from './ablation-cell.mjs';
import { runSpikeGate, summarise as summariseSpikeGate } from '../../spike/lib/gate.mjs';
import { homedir } from 'node:os';
const HERE = dirname(fileURLToPath(import.meta.url));
```

**1b — the gate, before the corpus.** Context:

```js
const VENDORS = ['clang-18', 'gcc-13'];
const OPTS = ['-O0', '-O1', '-O2', '-O3', '-Os'];

// ---------------------------------------------------------------- main -------
const files = readdirSync(GEN).filter((f) => f.endsWith('.c')).sort();
```

becomes

```js
const VENDORS = ['clang-18', 'gcc-13'];
const OPTS = ['-O0', '-O1', '-O2', '-O3', '-Os'];

// ---- spike/recovery gate, before the corpus ---------------------------------
//
// The corpus cannot check itself: a model file whose wipe survived and one the
// instrument failed to read are the same row, and 720 of them look like a
// measurement either way. So two known translation units go through the same
// verdictOf first -- one whose wipe the optimiser may delete, one whose it may
// not -- together with a run whose subject name is deliberately misspelt and
// which the gate must refuse. Nothing is rewritten when it does not hold.
//
// OPTS must keep at least one level above -O0: at -O0 both spikes are registered
// to read the same word, so a -O0-only gate is 2/2 for an instrument that can
// only ever report that word. The gate refuses such a run by itself
// (NO_DISCRIMINATING_CONFIGURATION), which is a red corpus run, not a silent one.
//
// The gate's scratch goes to the lab, not to _build: _build is inside the
// repository, and interfaces.md section 1 puts measurement inputs on the side
// that produces them.
const SPIKE_LAB = process.env.SPIKE_LAB || join(homedir(), 'vg-lab', 'spike');
const spike = await runSpikeGate({ ccs: VENDORS, opts: OPTS, lab: SPIKE_LAB });
process.stderr.write(`${summariseSpikeGate(spike)}\n`);
if (!spike.established) {
  for (const why of spike.verdict.reasons) process.stderr.write(`  spike gate: ${why}\n`);
  process.stderr.write('the spike/recovery gate did not hold; data/r2-build-rows.json was NOT rewritten\n');
  process.exit(3);
}

// ---------------------------------------------------------------- main -------
const files = readdirSync(GEN).filter((f) => f.endsWith('.c')).sort();
```

`join` is already imported from `node:path` in that file. Cost, measured: 40
compiles plus 8 for the injection, 1.8 s wall on this host, against a corpus run
of 4650 cells.

### 2. `compiler/eval/repair-loop/run-repair-loop.mjs` — before any cell

**2a — import.** Context:

```js
import { sha256Text, absolutePathHits, rowsFileLabel } from './lib/provenance.mjs';
import { preflightProblems } from './lib/preflight.mjs';
import { corpusFiles, erasureFamily } from './lib/corpus.mjs';

const run = promisify(execFile);
```

becomes

```js
import { sha256Text, absolutePathHits, rowsFileLabel } from './lib/provenance.mjs';
import { preflightProblems } from './lib/preflight.mjs';
import { corpusFiles, erasureFamily } from './lib/corpus.mjs';
import { runSpikeGate, summarise as summariseSpikeGate } from '../spike/lib/gate.mjs';

const run = promisify(execFile);
```

**2b — the gate, immediately before the plugin preflight block.** It must run
before any cell and must refuse `--write-data` on failure. Context:

```js
    if (args.dryRun) env.WPIN_DRY_RUN = '1';
    return env;
  };

  // ---- preflight: does the plugin load, and does it refuse when it should? ----
```

becomes

```js
    if (args.dryRun) env.WPIN_DRY_RUN = '1';
    return env;
  };

  // ---- spike/recovery gate: is the instrument reading anything, in this run? ----
  //
  // Before the plugin preflight, because the plugin preflight asks whether the
  // REPAIR works and this asks whether the thing that would judge it is working
  // at all. Two known translation units, judged by the same verdictOf this lane
  // judges its cells with, plus a run with the subject name deliberately
  // misspelt that the gate must refuse. Recovery short of 2/2, a green injected
  // run, or a level list in which no configuration registers two different
  // answers, makes every cell below meaningless.
  //
  // args.opts goes through unchanged, so `--opts -O0` alone gets a red gate
  // (NO_DISCRIMINATING_CONFIGURATION): at -O0 both spikes are registered the same
  // word and 2/2 there is also what an instrument stuck on that word would score.
  const spike = await runSpikeGate({ ccs: [args.cc], opts: args.opts, lab: join(args.out, 'spike') });
  process.stderr.write(`${summariseSpikeGate(spike)}\n`);
  if (!spike.established) {
    for (const why of spike.verdict.reasons) process.stderr.write(`  spike gate: ${why}\n`);
    if (args.writeData) {
      die(2, '--write-data refused: the spike/recovery gate did not hold, so no reading in this run '
        + 'is evidence about a repair');
    }
    die(3, 'the spike/recovery gate did not hold; no cell was run');
  }

  // ---- preflight: does the plugin load, and does it refuse when it should? ----
```

`join` and `die` are already in scope (`node:path` at line 54, `die` at line
116). `args.cc` may be a path; the gate files a reading under its basename — the
same reduction this file already makes with `ccName` — so `--cc /usr/bin/clang-18`
grades against the registered `clang-18`. A `--cc` or `--opts` this lane has not
registered is refused with `NO_EXPECTATION`; that is the intended behaviour, and
it means a new compiler version has to be grounded before it can validate a run.
A partial `--opts` of `-O0` alone is refused too, with
`NO_DISCRIMINATING_CONFIGURATION` — this file's own line 165 already refuses
`--write-data` with a partial `--opts`, and this is the same rule reached from
the other side: a run that never asked the instrument to tell the two spikes
apart has not shown that it can.

### 3. `compiler/eval/repair-loop/tools/lto-probe.mjs` — preflight

**3a — import.** Context:

```js
import { sha256Text, absolutePathHits } from '../lib/provenance.mjs';
```

becomes

```js
import { sha256Text, absolutePathHits } from '../lib/provenance.mjs';
import { runSpikeGate, summarise as summariseSpikeGate } from '../../spike/lib/gate.mjs';
```

**3b — the gate, at the top of the preflight.** Context:

```js
    if (l.rc !== 0) return { asm: null, problem: `llc rc ${l.rc}`, layout: null, stderrEmpty, stderrFlags, linkLine };
    return { asm: readFileSync(sOut, 'utf8'), problem: null, layout: null, stderrEmpty, stderrFlags, linkLine };
  }

  // ---- preflight: can post-LTO assembly be cut, and does the plugin run under -flto? ----
```

becomes

```js
    if (l.rc !== 0) return { asm: null, problem: `llc rc ${l.rc}`, layout: null, stderrEmpty, stderrFlags, linkLine };
    return { asm: readFileSync(sOut, 'utf8'), problem: null, layout: null, stderrEmpty, stderrFlags, linkLine };
  }

  // ---- spike/recovery gate, before the preflight ----------------------------
  //
  // The preflight below asks whether post-LTO assembly can be cut at all. This
  // asks the prior question: does verdictOf read a known elimination and a known
  // survival in this run. A NOT_LTO cell and a cell nobody could read are
  // different failures and only one of them is about LTO.
  //
  // "a known elimination AND a known survival" is the point: this probe's default
  // --opts is -O2, where the two spikes are registered to read different words.
  // `--opts -O0` alone has no such pair and the gate refuses the run with
  // NO_DISCRIMINATING_CONFIGURATION rather than passing it 2/2.
  const spike = await runSpikeGate({ ccs: [args.cc], opts: args.opts, lab: join(OUT, 'spike') });
  process.stderr.write(`${summariseSpikeGate(spike)}\n`);
  if (!spike.established) {
    for (const why of spike.verdict.reasons) process.stderr.write(`  spike gate: ${why}\n`);
    die(3, 'the spike/recovery gate did not hold; no LTO cell was run');
  }

  // ---- preflight: can post-LTO assembly be cut, and does the plugin run under -flto? ----
```

`OUT` is `args.out`, which this probe already refuses to place inside the
repository, so the gate's lab is outside it too.

### 4. `compiler/eval/repair-loop/tools/lto-probe-gcc.mjs` — preflight

**4a — import.** Add after the existing `./lib/lto.mjs` import:

```js
import { runSpikeGate, summarise as summariseSpikeGate } from '../../spike/lib/gate.mjs';
```

**4b — the gate.** Context:

```js
    if (bodies[names[0]] === null) return { ok: false, problem: `${names[0]}: not defined in the object` };
    const m = zeroMemsetsInGimple(bodies);
    return { ok: true, plain: m.plain, pinned: m.pinned, helperCalls: m.helperCalls, defined: m.defined };
  }

  // ---- preflight, per level, before any cell -------------------------------------
```

becomes

```js
    if (bodies[names[0]] === null) return { ok: false, problem: `${names[0]}: not defined in the object` };
    const m = zeroMemsetsInGimple(bodies);
    return { ok: true, plain: m.plain, pinned: m.pinned, helperCalls: m.helperCalls, defined: m.defined };
  }

  // ---- spike/recovery gate, before the preflight ----------------------------
  //
  // Same reason as the clang twin: the preflight asks whether lto1's assembly can
  // be cut, and this asks whether the judgement that would cut it is working in
  // this run at all. Same caveat, too: the default --opts is -O2, which registers
  // two different answers; a run of -O0 alone registers one word twice and is
  // refused with NO_DISCRIMINATING_CONFIGURATION, because 2/2 there would also be
  // what an instrument stuck on that word scores.
  const spike = await runSpikeGate({ ccs: [args.cc], opts: args.opts, lab: join(OUT, 'spike') });
  process.stderr.write(`${summariseSpikeGate(spike)}\n`);
  if (!spike.established) {
    for (const why of spike.verdict.reasons) process.stderr.write(`  spike gate: ${why}\n`);
    die(3, 'the spike/recovery gate did not hold; no LTO cell was run');
  }

  // ---- preflight, per level, before any cell -------------------------------------
```

### 5. `.github/workflows/ci.yml` — this lane's suite reaches no runner

The job named *"compiler/ suites that reach no other runner"* carries an explicit
list, and `compiler/eval/spike` is not in it — the same omission its own comment
block describes finding three times already ("they arrived with their
directories, nothing named them"). The two suites here read literals and tracked
source and invoke no compiler; the one exception is a single small file written
into the system temp directory and removed again, by the test that pins what an
unreadable claims file may say. They were seen green under node 18.19.1 on
Ubuntu-24.04 (48 tests, 48 pass, 0 fail, 0 skipped) before this was written.
Context:

```yaml
          run_suite observer              compiler/pass-instrumentation/observer/test/*.test.mjs
          run_suite calibration           compiler/eval/calibration/test/*.test.mjs
          run_suite metamorphic           compiler/eval/metamorphic/test/*.test.mjs
          run_suite ai-generated          compiler/eval/ai-generated/test/*.test.mjs
```

becomes

```yaml
          run_suite observer              compiler/pass-instrumentation/observer/test/*.test.mjs
          run_suite calibration           compiler/eval/calibration/test/*.test.mjs
          run_suite metamorphic           compiler/eval/metamorphic/test/*.test.mjs
          run_suite ai-generated          compiler/eval/ai-generated/test/*.test.mjs
          run_suite spike                 compiler/eval/spike/test/*.test.mjs
```

`run_suite` already asserts its own inputs exist, so a renamed or moved file
fails the step instead of passing an empty glob. This adds no compiler
invocation to CI: it does **not** run `run-spike.mjs`, only the unit tests.

**Applying any of these requires no change to this lane and no change to
`claims/spike-expected.json`.** A caller that asks for a compiler or a level the
claims file does not register gets a red gate naming the configuration, which is
the correct answer and not a bug in the patch. The same goes for a caller whose
levels are all non-discriminating (`-O0` alone): the gate is red with
`NO_DISCRIMINATING_CONFIGURATION`, and the fix is to gate at a level where the
two spikes are registered to read different words — not to relax the rule.

## What is NOT measured

* **No harness's data is gated.** See the table above. The four patches are
  written and were *not* applied by this lane, and the two runs they would guard
  (a corpus rebuild and a repair-loop run) were not performed with the gate in
  place. **Unmeasured, not "passing".**
* **The observer channel at levels other than `-O2`, and on gcc.** The plugin is
  an LLVM pass-instrumentation plugin; gcc has no such channel here, and only
  `-O2` is registered. The registered `-O2` cell was run and held.
* **The version ladder is not registered.** All eleven installed compilers were
  *observed* at `-O2` (1.8 s for the whole sweep): clang-15/16/17/18/19/20 and
  gcc-10/11/12/13/14 each read `disappearing = WIPE_ELIMINATED` and
  `surviving = WIPE_SURVIVED`, with the control `PRESENT` in all twenty-two
  readings. That is an observation, not a registration — it happened after the
  claims were written, and grounding a version means a person deciding the entry.
  Only clang-18 and gcc-13 recovered; the other nine were refused with
  `NO_EXPECTATION`, as they should be.
* **CI.** This lane did not wire itself into CI: the job "compiler/ suites that
  reach no other runner" has an explicit list, adding to it is section 5 below,
  and `.github/workflows/` is not this lane's to edit. As of 2026-09-12 the
  working tree does carry that line (`run_suite spike
  compiler/eval/spike/test/*.test.mjs`), added by whoever owns that file — **this
  lane has not seen it run on a runner**, and whether it is committed or green in
  CI is not something this lane can report. Until a CI run says otherwise, the
  48/48 below is local evidence: node 18.19.1 under WSL2 and node 24.14.1 on
  Windows, both green.
* **`spike-gate.json` is not tracked and nothing consumes it.** It is a lab
  artefact for a reader.

## Findings worth keeping

**A `void` subject is ablated out of existence.** `wipeHelpers()` treats every
`void` function whose body zeroes as a wipe helper, and the call pattern it then
looks for — name, `(`, anything up to the first `;` — matches the helper's *own
definition header* when the body opens with a declaration. Written
`void vgspike_disappearing(void)`, the ablated form lost
`vgspike_disappearing(void) {` and the declaration after it, and all four of
clang-18/gcc-13 × `-O0`/`-O2` read `ABLATION_DID_NOT_COMPILE` — which the gate
correctly refused as a vacuous pass on its very first run. The r2 corpus never
hits this because all twenty of its subjects return `int`. The spikes now return
`int` too, so that they are shaped like the population the instrument is given;
the interaction is recorded here and in `test/lane.test.mjs` rather than repaired
in a file this lane does not own.

**A whole-file `diff` is not the criterion, and gets it backwards.** At
clang-18 `-O2` the only line that differs between the disappearing spike's two
listings is `.file "disappearing.w.c"`. A reader who diffs the listings concludes
the wipe SURVIVED when it was eliminated. `bodyOf()` drops
`.file/.loc/.cfi_/.ident/.section/.p2align/.type/.size/.globl/.align` for exactly
this reason. `tools/make-spike-lab.sh` prints an `awk` re-implementation of that
filter, verified to agree with the harness on all eight of
(disappearing, surviving) × (clang-18, gcc-13) × (`-O0`, `-O2`).

**The observer's third silent failure, reproduced here.** With
`OBS_TARGET_FN=vgspike_disappearingX`: clang-18 exits 0, the log is non-empty,
`STATS` counts 454 passes, and the control reads `PRESENT` — only the subject's
`SUMMARY` row is missing. `check-subject-resolution.mjs` exits 2 on it. That is
the failure this lane exists to make automatic, and it is now automatic on the
observer channel of any run that passes `--observer`.

## Running it

```sh
node compiler/eval/spike/run-spike.mjs --out ~/vg-lab/spike
node compiler/eval/spike/run-spike.mjs --out ~/vg-lab/spike \
     --cc clang-18,gcc-13 --opt -O0,-O1,-O2,-O3,-Os --inject-at -O0,-O2
node compiler/eval/spike/run-spike.mjs --out ~/vg-lab/spike \
     --observer ~/vg-build/pass-observer/libPropertyObserver.so --observer-opt -O2
bash compiler/eval/spike/tools/make-spike-lab.sh ~/vg-lab/spike-hand
node --test compiler/eval/spike/test/*.test.mjs
```

Exit codes (`interfaces.md` §7):

| | |
|---|---|
| 0 | every requested configuration recovered 2/2, at least one of them registered two different answers, and the injected run went red |
| 2 | the gate is RED — a spike did not read what was registered, did not produce a reading at all, was never registered, no configuration in the run was discriminating, or the injected run stayed green (or could not be graded) |
| 3 | a check could not be completed: a requested compiler is not installed here |
| 4 | bad arguments, a lab inside the repository, malformed expectations, or a report that would carry an absolute path |

A spike that fails to *compile* lands at 2, not at 1. The gate's business is
whether this run may be believed, and a run whose own spike would not compile may
not be; calling that "the underlying tool failed" would say something true about
the compiler and nothing about the run.

A note on vocabulary: a compiler that is **not installed** is reported as exit 3
here, not as `UNSUPPORTED`. `interfaces.md` §3.1 defines that word in two
sentences:

> The toolchain refused the invocation, so there was nothing to read. The
> configuration was asked for and could not be built.

The first is about a toolchain that ran and refused; the second can be read to
cover a configuration that could not be built *because the toolchain is absent*.
That file does not settle which, so this lane does not report one reading of it
as settled — an earlier version of this section said §3.1 "reserves" the word for
a refusal, and that was a selective reading stated as fact. What this lane does
is its own choice and is the narrow one: "it refused" and "it is not here" are
different facts about different things, a reader who sees `UNSUPPORTED` cannot
tell them apart, so an absent compiler is reported as a check that could not be
completed (exit 3) with the compilers named, and no status word is written for
it. If the repository decides §3.1's second sentence does cover an absent
toolchain, that decision belongs in `interfaces.md` and this lane follows it;
this lane does not edit that file.

## Licence

Apache-2.0 WITH LLVM-exception, like the rest of `compiler/`. See
`compiler/LICENSE`.
