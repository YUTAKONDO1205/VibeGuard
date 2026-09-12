# eval/oracle-agreement — do the two oracles say the same thing?

Seven lanes in this directory report on the same phenomenon and mostly say the
same thing about it. That has been read, more than once, as seven independent
confirmations. **It is not.** Most of them reach their verdict by calling one
function — `verdictOf` in `../ai-generated/lib/ablation-cell.mjs` — so what those
lanes agree about is what one instrument says, measured seven times. **Seven
lanes agreeing is re-sampling one instrument, and that is not independent
corroboration.** A systematic error in `verdictOf` — a body reader that returns
the same empty string for both compiles, an ablation that silently did nothing,
a comparison made against the wrong function — would be reported by all seven of
them, in unison, with the same confidence.

This lane is the smallest thing that can say something about that: put a
**second instrument** on the **same cells** and tabulate where the two part
company.

It is not a gate, it does not go red when the instruments disagree, and it is
not trying to show that they agree. **The off-diagonal is the result.** Each
cell in it is a place where a differential text comparison and an IR call-site
count give different answers about the same build, and every one of those is
either a defect in one instrument or a boundary between two vocabularies that
nobody has drawn yet. Both are worth more than another point on the diagonal.

## The sentence this lane answers, and the half of it that is wrong

Section 2.20(g) of the implementation order says:

> **共有オラクルの独立性**: A1/A2/A3/A5/A7 と（rows 経由で）A6 は、いずれも
> `compiler/eval/ai-generated/lib/ablation-cell.mjs` の `verdictOf` を通る。
> […] **「7レーンが一致した」は独立な裏付けではない**。
> 紙に書くときは「同じ器の出力を再標本した」と明記すること。

The warning is right and it is the reason this directory exists. The
**inventory** is wrong in two places, and both corrections make the tree look
better than the sentence says, so they are worth getting right rather than
leaving as a modest overstatement of a weakness.

```
$ grep -rn "ablation-cell\|verdictOf" compiler/eval/lto-window
$ echo $?
1                       # grep found nothing, in any file of that lane

$ grep -rn "cell\.verdictOf(" compiler/eval/residue-tracer
compiler/eval/residue-tracer/run-residue-tracer.mjs:  confirm = { ...cell.verdictOf(aW, aWo, SUBJECT_FN), nSpans: spans.length };
```

**A7 does not use the shared oracle at all.** `../lto-window` reaches its verdict
from the PropertyObserver pass's own log on the clang side and from
`../lto-window/tools/read-wipe.py` reading a disassembly on the gcc side. It
never imports `ablation-cell.mjs` and never names `verdictOf`.

**A1 uses it for one column.** `../residue-tracer/run-residue-tracer.mjs` calls
`cell.verdictOf(...)` exactly once, to fill its `confirm` column. (No line number
is quoted: that file is under active edit, and a line number in prose is a fact
that rots in a week. `test/lane.test.mjs` counts the call sites instead.) The
residue measurement itself — the thing the lane is for — is a ptrace observer
written in C that stops a live process and scans registers and stack for known
bytes. That is not the shared oracle re-sampled; it is a different question asked
of a different artefact.

So the tree already contains **four** oracles, not one:

| | oracle | what it actually reads | artefact | who uses it |
|---|---|---|---|---|
| **O1** | `verdictOf` (`../ai-generated/lib/ablation-cell.mjs`) | the target function's body in two assembly listings, compared as **text**, with and without the wipe | assembly | A2, A3, A5, A6 (via rows), and A1's `confirm` column only |
| **O2** | PropertyObserver LLVM pass | an **IR call-site count**, read between passes: PRESENT / LOST / ABSENT / REINTRODUCED / NOT_APPLICABLE / NOT_OBSERVED | IR, mid-pipeline | A7 (clang side), `../spike --observer`, `../comparison`, **and this lane** |
| **O3** | `../lto-window/tools/read-wipe.py` | instructions in a **disassembly**, read directly | linked object | A7 (gcc side, where the pass plugin is refused) |
| **O4** | the ptrace residue observer | bytes in the **registers and stack of a live process** at a chosen return point | a running program | A1 |

`test/lane.test.mjs` re-runs both corrections as tests. If A7 ever starts
importing the shared oracle, or A1's single `verdictOf` call becomes several,
this README is wrong about a file and the suite says so rather than the paragraph
quietly ageing.

**None of that weakens the original warning.** Four oracles that have never been
compared are still four instruments nobody has cross-checked, and O1 remains the
one that most of the tree's numbers come out of. The point of the correction is
that a comparison is *possible* — O1 and O2 can both be pointed at the same
corpus cell — and until this lane there was nothing that did it.

## What is here

```
run-oracle-agreement.mjs   the CLI: selects cells, runs O2, tabulates, exits 0/2/3/4
lib/agreement.mjs          the 2x2 table and every rule about what enters it. PURE.
lib/rows.mjs               the O1 side: the tracked rows, read; and the selection
lib/observe.mjs            the O2 side: one corpus cell under libPropertyObserver.so
test/agreement.test.mjs    the arithmetic, over synthetic rows
test/rows.test.mjs         indexing and selection, plus facts re-derived from the rows
test/lane.test.mjs         hygiene, the plugin configuration, and the four-oracle map
```

Nothing is written under `compiler/`. The copied sources, the object files, the
plugin logs and the report all go to a lab directory outside the repository, and
a lab inside it is refused (`../../schema/interfaces.md` §1).

**The tracked rows are opened for reading and never for writing.**
`../ai-generated/data/r2-build-rows.json` is a frozen record: it is what the
corpus run produced, it is quoted in a write-up, and re-deriving it here would
substitute today's toolchain for the one the number was taken on without anyone
noticing. `lib/rows.mjs` imports exactly `readFileSync` from `node:fs` and
`test/lane.test.mjs` pins that by reading this file's own import list.

## The mechanism

For a chosen set of corpus cells — a cell is one `(generation id, vendor,
optimisation level)` — the lane obtains two verdicts:

* **O1** from the tracked rows. `WIPE_ELIMINATED` or `WIPE_SURVIVED`. Not
  re-measured.
* **O2** by compiling the same generation now, with `CONTROL` appended exactly as
  the corpus run appends it, under `-fpass-plugin=libPropertyObserver.so`, and
  reading the subject's `finalState` out of the plugin's SUMMARY record.

and files the pair in one of four cells:

```
                      O2 LOST      O2 PRESENT
   O1 ELIMINATED       agree        DISAGREE
   O1 SURVIVED        DISAGREE       agree
```

Every off-diagonal cell is printed **individually, by id**, with the vendor, the
level, the idiom the corpus run recorded, both verdicts, and the pass the
observer says the property was first lost at. A count of disagreements is not
useful; a list of them is, because each one has to be opened.

## The diagonal is a conjecture, not a definition

This is the assumption the whole table rests on and it should be read slowly.

O1 says `WIPE_ELIMINATED` when **the assembly is the same whether or not the wipe
is in the source**. O2 says `LOST` when **an effect-symbol call site that existed
at one observation point does not exist at a later one**. Those are different
sentences about different artefacts, and treating them as the same sentence is
the hypothesis, not the method.

Two shapes where they can legitimately differ, without either being broken:

* **A wipe written as a `volatile` loop.** There is no effect-symbol call site at
  all, so O2 has nothing to watch: it reads `NOT_APPLICABLE`, or the subject
  never appears. O1 has no such trouble — it removes the loop and compares the
  listings. The corpus's `idiom` column records that these exist; roughly a
  third of the erasure generations are `nonremovable`, which is largely this
  shape.
* **A wipe lowered away before the pipeline's first observation point.** O2 reads
  `ABSENT` — the site was never there to lose — where O1 would very plausibly
  read `WIPE_ELIMINATED`, because removing it from the source changes nothing.

`lib/agreement.mjs` **refuses to map either of those onto a cell.**
`NOT_APPLICABLE`, `ABSENT`, `REINTRODUCED` and `NO_WIPE_WRITTEN` are excluded as
`NOT_COMPARABLE`, counted, and listed. Folding `ABSENT` into `LOST` is a
defensible reading and it is exactly the reading this lane exists to test, so
building it into the tabulator would be assuming the conclusion inside the thing
that is supposed to measure it.

That decision has a cost and it is not hidden: it makes the denominator smaller
and it means the lane is silent about precisely the boundary cases that are most
interesting. The `NOT_COMPARABLE` list is where those live, and the intended use
of this lane is to read that list, not the rate.

## `-O0` is tabulated separately, always

Section 2.20(d) records what happened when the spike gate was run at `-O0` alone:

> A2 | -O0 では消失側・生存側の登録解が**ともに `WIPE_SURVIVED`**＝識別力ゼロ。
> 消失を原理的に報告できない器でも 2/2 回収して ESTABLISHED になる

At `-O0` the two spike subjects — one whose wipe the optimiser may delete, one
whose it may not — come back with the **same** verdict. The tracked rows say the
same thing about the corpus: of the erasure cells at `-O0`, **zero** read
`WIPE_ELIMINATED` on clang-18 and zero on gcc-13 (319 `WIPE_SURVIVED` and 2
`ABLATION_DID_NOT_COMPILE` in each). `test/rows.test.mjs` re-derives those counts
from the tracked file, so if a re-measurement ever puts an elimination at `-O0`
the ground under this section has moved and the suite fails rather than the
argument silently ageing.

So a `-O0` table that came out perfectly on the diagonal would mean **"neither
instrument can report the phenomenon here"**, not "the instruments agree". It
would be the same number a blind O2 that always says `PRESENT` would produce.
Pooling those rows in with the levels that can discriminate would let them
contribute agreement they cannot possibly have earned.

`-O0` is therefore its own stratum, printed with a note saying why, and
`laneVerdict` looks only at the stratum above it. The rule is enforced as
**arithmetic** rather than as a level name: `degeneracyOf` marks a stratum
non-discriminating whenever **either** instrument's marginal puts all of its mass
in one word, so a `-O2` selection that happened to come out uniform is caught by
the same rule that catches `-O0`.

## What leaves the denominator, and the three kinds

Never silently. Every excluded cell is counted **and listed by id**, and every
exclusion carries one of three kinds. A count without names is a quiet drop with
a receipt attached.

| kind | what it says | examples |
|---|---|---|
| **BROKEN_MEASUREMENT** | a statement about the **apparatus** — nothing about this cell's wipe can be read out of this run | O2's control came back anything but `PRESENT`; the subject name never resolved (`check-subject-resolution.mjs` exited non-zero); the compile failed; O1's row is `COMPILE_ERROR` or `ABLATION_DID_NOT_COMPILE` |
| **NO_READING** | the instrument **ran** and there was no reading of this property here | `NOT_OBSERVED` on either side |
| **NOT_COMPARABLE** | both instruments worked, both answered, and the two **vocabularies** do not meet in this table | `NOT_APPLICABLE`, `ABSENT`, `REINTRODUCED`, `NO_WIPE_WRITTEN`; a cell with no O1 row |

The middle one is not pedantry. `../../schema/interfaces.md` §3.1 is emphatic
that "the instrument worked and there was nothing here to read" is a third
situation and not a broken instrument, and `../lto-window/lib/cell.mjs` records
what happened in this tree when the two were merged: a module whose whole job was
to keep them apart **threw** on the legal pair, and the throw was reported as
evidence that the lane enforced the specification mechanically.

### The control rule, and why it is checked first

**A cell whose O2 control comes back anything but `PRESENT` is
BROKEN_MEASUREMENT and leaves the denominator.** The control is `vgctl_control`
— the same function `../ai-generated/lib/ablation-cell.mjs` exports and the
corpus run appends — and its wipe is read afterwards, so no pass may remove it.
If it is gone, the instrument has stopped seeing wipes, and the subject's own
"it is gone" cannot be told apart from that.

The order matters and is tested. `classifyPair` reads **both controls before
either subject**. A lane that read the subject first would have already decided
what it was about to exclude, and a cell with a fallen control and a beautiful
subject reading would have been counted as agreement on a run where the
instrument had been shown not to work. The excluded count is printed, broken out
by reason, with the word the control actually read in the detail.

## Agreement is not the success criterion

**The exit code is not "0 iff they agree."** A lane that went red on
disagreement would be a lane with an incentive, and the first thing anybody does
with a red run is make it green — here that would mean quietly widening the
mapping until `ABSENT` counts as `LOST`, which is the one thing this lane must
not do.

The exit code answers a different question: **was the comparison performed?**

| code | meaning |
|---|---|
| **0** | at least one stratum above `-O0` has a non-empty denominator **and** neither instrument's marginal is degenerate in it. The two instruments each said both of their words on the same cells, so the table is a comparison. **Perfect agreement exits 0. Perfect disagreement also exits 0.** |
| **2** | no such stratum: everything was excluded, or only `-O0` was run, or the selected cells were uniform on one side. **The run could not ask its question.** Not a claim about agreement. |
| **3** | a check could not be completed: the plugin is not built, a requested compiler is not installed, the tracked rows could not be read — **or the run was a `--dry-run`**, which measures nothing and must never be readable as a green lane |
| **4** | bad arguments, a lab inside the repository, or a report that would carry an absolute path and was refused |

Exit 3 for `--dry-run` is deliberate and slightly rude. A `--dry-run` that exited
0 is a flag somebody adds to a CI job to make it faster, and then the job is
green forever without compiling anything.

`test/agreement.test.mjs` contains a test named for this in capitals, because it
is the property most likely to be "fixed" by someone who has not read this
section.

## The rate printed is not the corpus's rate

`selectCells` takes `--per-bucket` cells from **each** `(vendor, level, O1
verdict)` bucket, so a run draws a balanced number of `WIPE_ELIMINATED` and
`WIPE_SURVIVED` cells. It has to: the corpus is not balanced — at `-O2`, clang-18
reads 113 eliminated against 206 survived, gcc-13 108 against 211 — and a run
that took the first N ids alphabetically could easily draw N cells that all read
the same word, in which case `laneVerdict` correctly reports that the table
cannot separate an agreeing second instrument from one stuck on a word, having
spent N compiles to find out.

The consequence is stated twice in the output, once at the top of the table and
once on the last line: **the marginals are an artefact of the selection, and the
number on the diagonal is not an estimate of anything about the corpus.** What
this lane measures is *where* the two instruments part company. That is a
question about cases. Turning it into a proportion would require a sample drawn
for that purpose, and this is not one.

## Running it

The plugin first, if it is not already built — the invocation is
`../../pass-instrumentation/observer/README.md`'s, not a copy of it:

```sh
cmake -S "$REPO"/compiler/pass-instrumentation/observer -B ~/vg-build/pass-observer \
      -G Ninja -DLLVM_DIR="$(llvm-config-18 --cmakedir)"
ninja -C ~/vg-build/pass-observer
```

Then, from the repository root:

```sh
# what would be observed, and out of what. Compiles nothing; exits 3.
node compiler/eval/oracle-agreement/run-oracle-agreement.mjs --dry-run \
     --cc clang-18 --opt -O2 --per-bucket 12

# the run. 2 x --per-bucket compiles; the lab MUST be outside the repository.
node compiler/eval/oracle-agreement/run-oracle-agreement.mjs \
     --observer ~/vg-build/pass-observer/libPropertyObserver.so \
     --cc clang-18 --opt -O2 --per-bucket 12 \
     --out ~/vg-lab/oracle-agreement

# -O0 as well, to see the stratum that cannot discriminate stated rather than
# assumed. The -O0 rows are tabulated separately and never pooled.
node compiler/eval/oracle-agreement/run-oracle-agreement.mjs \
     --observer ~/vg-build/pass-observer/libPropertyObserver.so \
     --cc clang-18 --opt -O0,-O2 --per-bucket 8 \
     --out ~/vg-lab/oracle-agreement

# one named cell, to diagnose an off-diagonal entry the table listed
node compiler/eval/oracle-agreement/run-oracle-agreement.mjs \
     --observer ~/vg-build/pass-observer/libPropertyObserver.so \
     --ids fable_E_aeskey_r1 --cc clang-18 --opt -O2 \
     --out ~/vg-lab/oracle-agreement --json
```

`gcc-13` is accepted by `--cc` and will not work: the plugin is an LLVM pass
plugin and `gcc` does not load it. `../lto-window` hit the same wall from the
other side and named the result `UNSUPPORTED`. Cross-vendor comparison here needs
O3 (`read-wipe.py`) as the second oracle instead, which this lane does not
implement — see below.

The suite needs no compiler and no plugin:

```sh
node --test compiler/eval/oracle-agreement/test/*.test.mjs
```

## Measured, 2026-09-12 — and the comparison was refused

Run on WSL2 Ubuntu-24.04, `clang-18` 18.1.3, observer
`~/vg-build/pass-observer/libPropertyObserver.so` (the 2026-08-17 build). The O1
half is read from the tracked rows and was measured on a different day, which is
why the two builds are both named here.

```
node compiler/eval/oracle-agreement/run-oracle-agreement.mjs      --observer ~/vg-build/pass-observer/libPropertyObserver.so      --cc clang-18 --opt -O0,-O2 --per-bucket 24      --out ~/vg-lab/oracle-agreement            # exit 2
```

| | value |
|---|---|
| cells selected, `clang-18`, `-O0` and `-O2` | 48 |
| denominator above `-O0` after exclusions | **25** |
| on the diagonal | **24 / 25 (96.0 %)** |
| off-diagonal entries, by id | `fable_E_dbpass_r3` `clang-18 -O2`, `idiom=both`, O1 `WIPE_SURVIVED` / O2 `LOST` (`firstLoss=DSEPass`) |
| excluded | `BROKEN_MEASUREMENT` 0, `NO_READING` 0, **`NOT_COMPARABLE` 23**, all `o2-not-a-reading(ABSENT)` |
| `-O0` stratum | every cell `NOT_COMPARABLE`; denominator 0 |
| **exit** | **2 — THE COMPARISON WAS NOT PERFORMED** |

**Read the 96 % as nothing.** The run refuses its own table: above `-O0`, all 25
graded cells read `LOST` on O2, so the O2 marginal is degenerate and an agreement
rate over it measures how often one instrument says its only word. The lane exits
2 and prints *"above -O0: all 25 graded cells read LOST on O2, the same objection
in the other direction"*. A number that cannot come out otherwise is not evidence
that two instruments agree, and this lane was built to say so rather than to
print 96 % and let a reader do the arithmetic later.

### The 23 exclusions are the boundary of what O2 can be ASKED, not a failure

Diagnosed rather than assumed, over all 48 selected cells, by counting
`@memset` / `@llvm.memset` / `@explicit_bzero` call sites in the `-O0` LLVM IR of
each corpus file:

| | IR wipe call sites `== 0` | `>= 1` |
|---|---|---|
| excluded, O2 `ABSENT` (23) | **23** | 0 |
| graded by both (25) | 0 | **25** |

**A perfect split, 48 of 48.** O2 is a *call-site* oracle: it watches an effect
symbol's call site through the pass pipeline. A wipe written as a `volatile`
pointer loop has no call site to watch, so O2 correctly reports `ABSENT` — it was
never asked a question it could answer. O1 is a differential over assembly text
and sees that wipe perfectly well, because deleting the loop changes the listing.

So the two oracles do not merely agree or disagree. **They have different
domains**, and the intersection on this corpus is 25 of 48 cells. Any sentence of
the form "an independent instrument agreed" has to carry that denominator.

A false trail worth recording, because it is the shape of mistake this lane
exists to catch: a first pass classified the corpus by grepping the SOURCE for
`memset(` and found 5 of the 23 exclusions apparently calling `memset` anyway.
They do not. The grep was matching the word inside the files' own comments
(*"memset() before a stack variable goes out of scope is routinely elided…"*).
Counting IR call sites instead of source text removed all five and left the split
exact. Attribution by pattern-match on text is how §2.20(c)3 of the
implementation order got twenty cells wrong.

### The two predictions, scored

They were written before the run so they could be wrong. One was, and one was
right for a stronger reason than it gave.

1. **"The `nonremovable` idiom will dominate the `NOT_COMPARABLE` exclusions."**
   **CONFIRMED, and not merely dominant — total.** Every excluded cell has zero
   IR wipe call sites and every graded cell has at least one. The prediction's
   escape clause (*"if O2 reports PRESENT/LOST for them, the plugin is matching
   something this README does not understand"*) was not taken.

2. **"`SURVIVED/LOST` will be rarer than `ELIMINATED/PRESENT`."**
   **CONTRADICTED.** `SURVIVED/LOST` = 1, `ELIMINATED/PRESENT` = 0. The single
   off-diagonal cell is the corner the prediction called the *less* likely one,
   and the corner it expected to see never appeared. The counts are 1 and 0, so
   this contradicts the ordering and establishes nothing about the rate; it is
   recorded because a prediction that is quietly dropped when it loses is worth
   less than no prediction.

   `fable_E_dbpass_r3` is the cell, and it is worth a look rather than a
   footnote: O1 says the two listings differ when the wipe is ablated
   (`WIPE_SURVIVED`), while O2 watched the call site disappear inside `DSEPass`.
   Both can be true — the call site can be replaced by inline stores that still
   differ from the ablated form — and that is precisely the disagreement the lane
   was built to surface. It is `idiom=both`, the one family that writes a
   removable and a non-removable wipe in the same file.

### What a next run should change

- **Select for a non-degenerate O2 marginal.** `--per-bucket` balances on O1's
  verdict, which is what made O2 read one word throughout. Stratifying on the
  expected O2 side, or simply taking more cells, is what makes the table mean
  anything.
- **Name the builds.** The O1 half came from the 2026-09-11 rows and the O2 half
  from the 2026-08-17 plugin; the lane records both, and a comparison across a
  toolchain change would need them re-measured together.

## What is NOT measured

* **Anything about O3 or O4.** This lane compares O1 against O2 only. The
  disassembly reader (`read-wipe.py`) and the ptrace residue observer are named
  in the four-oracle map above and are not run here. A three-way or four-way
  table is the obvious next lane and is not this one.
* **gcc.** The plugin is an LLVM pass plugin. Every O2 reading in this lane is
  clang, whatever `--cc` is passed, and a gcc run will exit 3 or produce
  `BROKEN_MEASUREMENT` for every cell. The corpus's gcc-13 half therefore has no
  second oracle at all in this lane.
* **Whether O1 is right.** Agreement does not make either instrument correct; two
  instruments can share a blind spot, and these two share the `CONTROL` function,
  the corpus, the effect-symbol registry and the definition of "the wipe". What a
  disagreement establishes is that at least one of them is wrong about that cell.
  What an agreement establishes is weaker than it looks.
* **Toolchain drift.** O1's half of every pair was measured on another day, on
  the machine that ran the corpus. A disagreement could be a compiler that has
  moved rather than a difference between the instruments, and nothing here can
  tell those apart. `../ai-generated/lib/compare-rows.mjs` is the tool for that
  question.
* **`-O1`, `-O3`, `-Os`, LTO, and any level not passed on the command line.**
* **The corpus's agreement rate.** See the section on the balanced selection: the
  marginals are chosen, so the proportion is not an estimate.
* **Whether the `ABSENT` refusal is the right call.** It is a judgement, it is
  argued above, and the `NOT_COMPARABLE` list is the evidence anybody would need
  to overturn it.

## Findings worth keeping

* The sentence in section 2.20(g) was **more pessimistic than the tree**, and the
  correction was two greps. It is worth noticing which direction the error went:
  a self-critical note about a weakness went unchecked for longer than a
  favourable claim would have, because nobody audits a confession.
  `scripts/check-doc-drift.mjs` has the same asymmetry by construction — it
  reports drift in documents that claim too much and is structurally blind to
  documents that claim too little.
* The four-oracle map is a **claim about files**, so it is a test. Prose that
  describes the shape of a codebase rots at exactly the speed of the codebase,
  and the only prose in this directory that has stayed true is prose something
  re-derives.
* `../spike/lib/observer.mjs` keeps the path to `check-subject-resolution.mjs` as
  a module-private constant, so this lane spells it again. That is a duplicated
  path, it is recorded below rather than fixed by reaching into another lane, and
  it is the kind of small duplication that becomes a silent divergence the first
  time the checker moves.

## Edits requested in files this lane does not own

Neither has been applied. Both change a file that produces readings somebody
quotes, and this lane does not get to make that edit on its own.

### 1. `../spike/lib/observer.mjs` — export the checker path and the env builder

`CHECKER` and the `OBS_*` environment are module-private there and are spelled
again in `lib/observe.mjs`. `test/lane.test.mjs` fences the divergence by
comparing the two files' `OBS_*` key sets, which catches a *new* variable and
does not catch the checker path moving. Exporting `CHECKER` — and, better, an
`observerEnv({fn, logPath, symbols})` — would make the fence unnecessary.

### 2. `../comparison/run-comparison.mjs:48` — the hard-coded plugin default

```js
// paraphrased: the literal cannot be quoted here, because this file is scanned
const OBSERVER_SO = arg('observer', '<the superuser home directory>/vg-build/observer-mainverify/libPropertyObserver.so');
```

That is one machine's account layout in a tracked file — the shape
`scripts/check-disclosure-shape.mjs` exists to refuse, surviving because that
path is not on the list of files the packaging check scans. Every other caller in
the tree spells the same location with a tilde. Changing it changes a default
that a recorded run may have relied on, so it is reported rather than edited.

### 3. `.github/workflows/ci.yml` — this lane's suite reaches no runner

Line 443 ends a block of `run_suite` lines that already carries the other six
A1–A7 lanes. One more is needed, or the 108 tests in `test/` run only on the
machine of whoever last edited the lane:

```yaml
          run_suite oracle-agreement     compiler/eval/oracle-agreement/test/*.test.mjs
```

It is cheap and needs no compiler: the whole suite is pure functions plus reads
of the tracked rows. Two of its tests read files in *other* lanes
(`../lto-window`, `../residue-tracer`) to re-derive the four-oracle map, so this
is also the thing that would notice if one of those lanes started using the
shared oracle.

### 4. `../../schema/interfaces.md` §3 — a word for "two instruments, one cell"

The vocabulary has words for what the property did and for whether the
instrument worked. It has none for *this cell was read by two instruments and
they said different things*, which is the only output this lane produces. The
lane uses `NOT_COMPARABLE` for the vocabulary boundary and plain table cells for
the disagreement; if a second cross-oracle lane is ever written, the word should
be in the schema first. `interfaces.md` is not edited during implementation (its
own first rule), so this is a request and not a change.

---

Licence: Apache-2.0 WITH LLVM-exception (see `compiler/LICENSE`).
