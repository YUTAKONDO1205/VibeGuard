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
run-oracle-agreement.mjs   the CLI: selects cells, runs the second oracle, tabulates, exits 0/2/3/4/5
lib/agreement.mjs          the 2x2 table, the two vocabularies, and what may enter. PURE.
lib/rows.mjs               the O1 side: the tracked rows, read; and the selection
lib/observe.mjs            the O2 side: one corpus cell under libPropertyObserver.so
lib/disasm.mjs             the O3 side: one corpus cell built, LINKED, and disassembled
lib/bufferbytes.mjs        how many bytes should the wipe have written? the compiler answers
lib/liveo1.mjs             O1 recomputed NOW, as a third column beside the frozen one
lib/fixtures.mjs           the synthetic sources the two apparatus checks put questions to
lib/callsites.mjs          were there any wipe call sites to watch? -O0 IR, counted
lib/record.mjs             the tracked record: what may go in it, and what may not
data/                      one record per compiler, written only by a full --write-data run
tools/check-bytes-readout.mjs   does the byte-count read-out work here, and refuse what it must?
tools/check-o3-apparatus.mjs    can O3 tell a wipe that cannot be removed from one that was?
test/agreement.test.mjs    the arithmetic, over synthetic rows
test/rows.test.mjs         indexing and selection, plus facts re-derived from the rows
test/second-oracle.test.mjs the two vocabularies, the O3 table, and the live O1 column
test/bufferbytes.test.mjs  there is no default byte count, and every refusal has a name
test/fixtures.test.mjs     the controls' fixtures are the things they claim to be
test/callsites.test.mjs    the counting rule, over IR text and no compiler
test/record.test.mjs       the three fences on the record, each tested by trying to pass it
test/data.test.mjs         the record against the numbers printed in THIS file
test/lane.test.mjs         hygiene, the plugin configuration, and the four-oracle map
```

The two `tools/` files are CHECKS and not tests, and the difference is the point.
They need a compiler, python and objdump; the suite needs none of those and must
keep needing none, so a compiler-dependent question cannot live in it. Put behind
a fence in a test file it would go GREEN on every host without a compiler --
which is what the first draft of `tools/check-bytes-readout.mjs` did: seventeen
milliseconds, four green ticks, no compiler present. These exit **3** when they
cannot run, and name what was missing.

The only thing written under `compiler/` is the record in `data/`. The copied
sources, the object files, the plugin logs, the emitted IR and the report all go
to a lab directory outside the repository, and a lab inside it is refused
(`../../schema/interfaces.md` §1).

**The record is integers, booleans and short strings — never a rate.** A ratio
is carried as `{num, den}`, `lib/record.mjs` refuses to write a record
containing a number that is not an integer, and it scans the text for a home
directory, a mount point or a drive letter before it opens the file (exit 5,
nothing written). The reason is the one this lane's own result section gives:
`24/25` with the refusal beside it is a measurement, and `0.96` in a JSON file
is that measurement with both of the things that make it readable removed.

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
  re-measured for the table. (`--live-o1` recomputes it beside the tracked
  reading; see below. The table still grades the tracked one.)
* **the second oracle**, measured now, on the same generation, with `CONTROL`
  appended exactly as the corpus run appends it. WHICH second oracle depends on
  the driver, because gcc does not load an LLVM pass plugin:

| driver | second oracle | what it reads | its two gradable words |
|---|---|---|---|
| `clang-18` | **O2** | the subject's `finalState` in the plugin's SUMMARY record, `-fpass-plugin=libPropertyObserver.so` | `LOST` / `PRESENT` |
| `gcc-13` | **O3** | the zero fill of the subject function in the **linked program**, through `../lto-window/tools/read-wipe.py` | `ABSENT` / `PRESENT` |

and files the pair in one of four cells — named in the second oracle's OWN words,
so a gcc record reads `ELIMINATED/ABSENT` and never `ELIMINATED/LOST`:

```
                      O2 LOST      O2 PRESENT          O3 ABSENT    O3 PRESENT
   O1 ELIMINATED       agree        DISAGREE            agree        DISAGREE
   O1 SURVIVED        DISAGREE       agree             DISAGREE       agree
```

**The two column headings are not the same heading.** O2's `LOST` is "an effect
call site that existed at one observation point does not exist at a later one".
O3's `ABSENT` is "the linked function contains no zero fill and no memset call".
And `ABSENT` is *also* one of O2's words, where it means a third thing — "the
site was never there to lose" — which this lane refuses to fold into `LOST`
because that fold is the hypothesis under test. Mapping O3's `ABSENT` onto O2's
`LOST` to keep one table would perform the same merge one level up, inside the
module whose job is to keep two sentences apart, so the vocabulary is a parameter
of the tabulator and the cell names are built from it.

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

# THE RUN THIS FILE'S RESULT SECTION IS OF, and the one that writes the record.
node compiler/eval/oracle-agreement/run-oracle-agreement.mjs \
     --observer ~/vg-build/pass-observer/libPropertyObserver.so \
     --cc clang-18 --opt -O0,-O2 --per-bucket 24 \
     --diagnose-callsites --write-data \
     --out ~/vg-lab/oracle-agreement
```

`--write-data` writes `data/oracle-agreement-clang-18.json` — one file per
compiler, named after it, so a second vendor's run can never overwrite the
first's. It is **refused for anything but the full run**: `--ids`, a missing
`-O0` or `-O2`, `--no-write`, more than one `--cc`, a missing `--observer` or a
missing `--diagnose-callsites` each exit 4 with the reason named, before a
single compile. A subset in the file whose name says it is the result is the
failure the refusal exists for, and `../repair-loop/run-repair-loop.mjs` refuses
its own `--write-data` the same way.

`--diagnose-callsites` counts the `-O0` IR wipe call sites of every selected
generation — the split the result section below is built on. It is required for
`--write-data` because without it that split would be recorded with its
provenance as prose rather than as a count.

### gcc, and the sentence this section used to carry

This section said, from the day the lane was written until 2026-09-14:

> `gcc-13` is accepted by `--cc` and will not work: the plugin is an LLVM pass
> plugin and `gcc` does not load it. […] Cross-vendor comparison here needs O3
> (`read-wipe.py`) as the second oracle instead, **which this lane does not
> implement**.

The first half was true and the behaviour was bad: a `--cc gcc-13` run compiled
every cell, failed to load the plugin, and produced a table of
`BROKEN_MEASUREMENT` — fifty compiles spent to discover an argument that could
have been refused before the first one. The second half is no longer true.

**The second oracle now follows the vendor.** `--second-oracle` defaults to `O2`
for a `clang` driver and `O3` for anything else, and an impossible pairing is
refused in `parseArgs`, before a compile, with the reason named. `--second-oracle
O2 --cc gcc-13` exits 4 rather than measuring a plugin that never ran.

##### One pairing is impossible; the other one was only preferred

| | | |
|---|---|---|
| `--second-oracle O2 --cc gcc-13` | **refused, exit 4** | The PropertyObserver is an LLVM pass plugin and this driver does not load it. Every cell would read `BROKEN_MEASUREMENT`. An **impossibility**. |
| `--second-oracle O3 --cc clang-18` | **allowed** | It was refused, and the reason given was that the pass observer *"says more than a reading of the finished program"*. That is a **preference between instruments**, not an obstacle. |

There is no obstacle. `read-wipe.py` and `objdump_fill.py` match x86-64
disassembly — a vector register zeroed against itself and stored, an immediate
zero stored, a call to `memset`/`__memset_chk` — and none of those is a spelling
only gcc emits; `lib/disasm.mjs` compiles and links with whatever `--cc` names
and stubs the symbols the **linker** reported, which is vendor-neutral; and
`lib/bufferbytes.mjs` establishes its count with `_Static_assert` under
`-fsyntax-only`, which clang has. `test/second-oracle.test.mjs` greps both
modules, comments stripped, for a vendor name and finds none.

And the preference foreclosed the cheapest validation this lane's newest
instrument has. O3 over **clang** cells is the one place where every cell can be
read **three ways** — O1's differential text comparison, O2's IR call-site count,
and O3's zero fill in the linked program — on one vendor, on one build, with no
second toolchain to attribute a disagreement to. A gcc-only O3 table has no
second opinion for its off-diagonal to disagree with; this one does.

**What it may still not do is `--write-data`,** and that refusal *is* an
impossibility: `lib/record.mjs` `dataFileName` names the record after the
compiler alone, so an O3 run on clang wants
`data/oracle-agreement-clang-18.json` — the O2 record that is this lane's
measured result — and would replace a table of `ELIMINATED/LOST` with a table of
`ELIMINATED/ABSENT` under a name that says neither. `writeDataRefusals` names it;
run it without `--write-data` and quote the report.

```sh
# the three-way reading: O3 over clang cells O2 has already answered.
node compiler/eval/oracle-agreement/run-oracle-agreement.mjs \
     --cc clang-18 --second-oracle O3 --opt -O0,-O2 --per-bucket 24 \
     --restrict-domain --live-o1 \
     --out ~/vg-lab/oracle-agreement          # no --write-data: see above
```

```sh
# the gcc side. No --observer: the disassembly reader loads no pass plugin, and
# naming one here is REFUSED, because a record that named it would be recording
# an instrument that did not run.
node compiler/eval/oracle-agreement/run-oracle-agreement.mjs \
     --cc gcc-13 --opt -O0,-O2 --per-bucket 24 \
     --restrict-domain --live-o1 \
     --out ~/vg-lab/oracle-agreement

# before believing anything the line above prints, on a host that has not run it:
node compiler/eval/oracle-agreement/tools/check-bytes-readout.mjs --cc gcc-13 --lab ~/vg-lab/oracle-agreement
node compiler/eval/oracle-agreement/tools/check-o3-apparatus.mjs  --cc gcc-13 --lab ~/vg-lab/oracle-agreement
```

#### How many bytes should the wipe have written?

This is the question O3 needs answered and the tracked rows cannot answer. A row
is `id, model, framing, scen, rep, fam, fn, kind, idiom, cc, opt, n_spans,
named_secret, scoped, control, control_via, verdict` — **there is no buffer size
anywhere in it**, because O1 never needed one: it compares two listings as text.
`../lto-window` takes its `bufferBytes` from the generator that wrote its
fixtures; this corpus has 720 files written by three models and no generator.

Three answers were rejected before the fourth was taken, and they are recorded
because each is the obvious one:

* **A default.** A fixed 32 turns every surviving wipe of another size into
  `PARTIAL` and every reading into a statement about the default. There is no
  default in `lib/bufferbytes.mjs` and no argument that supplies one;
  `test/bufferbytes.test.mjs` greps the lane for `bytes ?? <n>` and for a literal
  assignment, because that is a one-line edit that reads like a convenience.
* **A number read out of the source text.** This repository has been burned by
  exactly that twice: the first pass at the O2 exclusion split grepped the corpus
  for `memset(` and matched the word inside the files' own comments (see "A false
  trail worth recording" below), and §2.20(c)3 of the implementation order got
  twenty cells wrong the same way.
* **Reading the `-O0` zero fill back out of a disassembly**, which is the
  corroboration that first suggests itself and **does not work on this corpus**.
  At `-O0` a `memset` of 32 bytes is a CALL, so the byte count read back is 0;
  and a `volatile` pointer loop is a LOOP with one one-byte store in it, so the
  byte count read back is 1. Neither number is the buffer's size. A corroboration
  that returns 0 or 1 for the two commonest idioms in the corpus is not one.

**The number comes from the compiler**, by constant-expression evaluation, with
`_Static_assert` as the read-out. The text supplies only the LOCATION of the wipe
— from `wipeSpans`, the corpus run's own span finder, so O3 is pointed at the
wipe O1 ablated rather than at a second opinion about where the wipe is — and the
EXPRESSION in its length argument. Every digit is the compiler's:

1. **The apparatus control, first.** `_Static_assert(1, …)` at the probe point
   must compile and `_Static_assert(0, …)` must not. An assertion inserted
   somewhere that is not compiled succeeds for every question anybody asks it.
2. **Is the length constant at all?** `(LEN) <= 65536` and `(LEN) > 65536` are
   complementary: exactly one compiles for a constant. Neither means a runtime
   length, and the cell leaves by name.
3. **The value, by bisection** on `(LEN) <= mid`. Seventeen `-fsyntax-only`
   compiles at most.
4. **Confirmed** by the same complementary trick at the answer: `(LEN) == N`
   compiles, `(LEN) == N + 1` does not.
5. **It is the WIPED OBJECT's size**, not merely a constant in the last argument
   position: `(LEN) == sizeof(OBJ)` must compile, where `OBJ` is the identifier
   the wipe's first argument names.

**A cell that does not get a number leaves the denominator BY NAME**, under
`o3-buffer-bytes-unestablished` or `o3-no-single-wipe`, counted and listed with
its id like every other exclusion. It is never defaulted and never guessed.

#### What O3 can be ASKED, measured over the tracked rows

Counted by `locateWipe` over the 321 gcc-13 erasure generations at `-O2`, without
a compiler, and re-derived by `test/bufferbytes.test.mjs`:

| | generations |
|---|---|
| one wipe span, written as a call, resolvable | **162** |
| more than one wipe span — no single `(caller, helper, bytes)` triple | 155 |
| through a `volatile` function pointer — the call is indirect, so `objdump` resolves no target | 4 |

Of the 162, the O1 column reads 79 `WIPE_ELIMINATED` and 83 `WIPE_SURVIVED`, so a
balanced selection over that domain is possible. `--restrict-domain` selects from
it; without the flag roughly half of any gcc selection is spent on cells that
leave by name. **A restricted run's denominator is over that domain and is not a
statement about the gcc half of the corpus**, and the record says so in its
`domain` field.

#### The reader's own control, per cell — and the fabrication it stops

`objdump_fill.py` recognises exactly three things: a vector register zeroed
against itself and stored, an immediate zero stored, and a call to `memset` or
`__memset_chk`. **A wipe written any other way is invisible to it.** Two shapes
in this corpus are:

| written as | what the reader sees | the verdict it produces |
|---|---|---|
| `explicit_bzero(token, 32)` | a call to a symbol not on its list, and no zero store | **`ABSENT`** |
| a `volatile` byte loop | ONE one-byte store, against a buffer of 32 | **`PARTIAL`** |

`PARTIAL` is `NOT_COMPARABLE` and merely leaves the denominator. **`ABSENT` is
O3's gradable word**, so the first of those rows is an *elimination manufactured
out of the reader's symbol list* — a wipe that is plainly in the linked program,
graded as gone, on exactly the `nonremovable` cells where O1 says it survived. It
would enter the table as an off-diagonal entry and read as a finding.

So **every cell is read twice**: once at its own level, and once at `-O0`. `-O0`
is the right level for it because the corpus has never recorded an elimination
there — 319 gcc rows and 319 clang rows, re-derived from the frozen record by
`test/rows.test.mjs` and again by `test/second-oracle.test.mjs` — so a wipe the
reader cannot see at `-O0` is a wipe the reader cannot see.

| `-O0` subject reads | what the cell is |
|---|---|
| `PRESENT` | the reader recognised this wipe **as it is written at `-O0`**; whatever it says at the cell's level is a reading |
| anything else | `o3-reader-blind-to-this-wipe`, `BROKEN_MEASUREMENT`, out of the denominator, listed by id — **never an elimination** |

It doubles the builds and it is not optional; `test/second-oracle.test.mjs`
checks that there is no flag which turns it off, and that the control read comes
before the cell's own.

##### Exactly what that control qualifies, and what it does not

This file used to call the `-O0` reading a positive control **for the cell** —
flatly, for every cell. (The exact wording is not reproduced: it is grepped for
by `test/second-oracle.test.mjs`, which would then fail on a corrected file.) That is too strong in two places, and both are now recorded per
reading in `readerControl.qualification` by `lib/disasm.mjs` `qualificationOf`,
which is a pure function with tests rather than a paragraph:

| | what it means | field |
|---|---|---|
| **At `-O0` it is not a control at all** | The cell's level and the control's level are the same level: one build, one read, returned twice. And `observeCellO3` cannot return a `-O0` reading unless that read was `PRESENT` — anything else becomes `o3-reader-blind-to-this-wipe` before it — so **no `-O0` cell can be graded `ABSENT` and this control cannot fail on one**. A check that cannot fail is not a check. | `independent: false` |
| **Above `-O0` it may exercise a different recognizer** | `objdump_fill.py`'s three recognizers are three separate matchers. At `-O0` a `memset(...)` wipe is usually a **call**; at `-O2` the same wipe is usually **inlined into stores**. Recognising the call says nothing about whether the store matcher would have fired, and the store matcher is what an `-O2` `PRESENT` reading depends on. | `branchRelevant` |
| **On the cell that matters most it qualifies nothing about the branch** | A subject that read *no fill at all* — the `ABSENT` reading, the one that becomes an elimination — fired **no** recognizer branch. There is no branch for the control to have exercised, so the control cannot speak to the blindness that would have produced that `ABSENT`. | `branchRelevant: false`, with the sentence in `doesNotEstablish` |

**What it does establish, and this is the whole of it:** at the cell's own level,
that the reader recognised *this wipe, in its `-O0` form, in this program*. That
is enough to close the `explicit_bzero` fabrication — a call to a symbol not on
the reader's list is unrecognised at `-O0` too, so the cell leaves under
`o3-reader-blind-to-this-wipe` instead of being graded as an elimination — and it
is measurably not enough to close a reader that recognises calls and not stores.
Closing that one needs a control built at the cell's own level out of a wipe that
cannot be removed there; `tools/check-o3-apparatus.mjs`'s `kept` fixture is that
control **for the host**, at `-O2`, and there is no per-cell equivalent in this
lane. Neither the qualification nor its absence excludes a cell: it travels with
the reading so an off-diagonal `ABSENT` can be read with the control's reach
beside it. **The prediction that follows is that most of the
`nonremovable` idiom leaves under this word rather than appearing as a
disagreement**, which is a domain boundary of the same kind as the 23 `ABSENT`
exclusions on the O2 side. It is written down here so the first run can
contradict it.

#### The two halves, measured together

`--live-o1` recomputes O1 **now**, with this driver, through the same
`wipeSpans` / `ablateSpans` / `verdictOf` the corpus run used, and prints it
beside the tracked verdict. This closes the limitation `lib/rows.mjs` states in
its own header and the project ledger states as a refusal:

> O1 は 2026-09-11 の tracked rows、O2 は 2026-08-17 の plugin。別の日・別の条件で
> 測ったものを突き合わせているので、不一致をどちらの器に帰属させることもできない。

With the column, an off-diagonal cell can be read three ways instead of two:
tracked == live means the two **instruments** disagree about this build, and
tracked != live means the O1 reading itself has moved and the cell establishes
nothing about the second oracle either way. **The table still grades the TRACKED
verdict** — the frozen rows are read and never rewritten — and the live column is
lab output: it is in the report under `--out` and is never written into `data/`.

The suite needs no compiler and no plugin:

```sh
node --test compiler/eval/oracle-agreement/test/*.test.mjs
```

## NOT MEASURED, as of 2026-09-14: the gcc side has code and no run

The O3 channel, the byte-count read-out, the live O1 column and their two
apparatus checks are implemented and their suites are green, and **no gcc run has
been performed**. There is no `data/oracle-agreement-gcc-13.json`, this file
carries no gcc table, and `test/data.test.mjs` checks the gcc record only if one
appears — it will not invent one and it does not skip: the clang record is still
required and anything else in `data/` fails immediately.

So every gcc sentence in this file is **[SPEC]**: a description of what the code
will do, not a reading. The numbers that ARE measured on the gcc side are the two
counted over the tracked rows without a compiler — the 162/155/4 domain split and
the 79/83 verdict balance within it — and `test/bufferbytes.test.mjs` re-derives
them. The `PARTIAL` prediction is written down precisely so that the first run
can contradict it.

The order for that run, and what each exit means, is under "gcc, and the sentence
this section used to carry" above. **Run the two `tools/` checks first.** An O3
channel that is subtly broken produces a clean, quotable, entirely wrong table:
every cell reads `ABSENT` and the run reports that gcc eliminated every wipe in
the corpus. Nothing in the reading distinguishes that from the truth; the
`kept`/`removed` fixture pair does.

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
| `-O0` stratum | 23 of 24 cells `NOT_COMPARABLE`; **denominator 1**, agreeing (`SURVIVED`/`PRESENT`) — see the correction below |
| **exit** | **2 — THE COMPARISON WAS NOT PERFORMED** |

Every figure in that table is now also in
`data/oracle-agreement-clang-18.json`, and `test/data.test.mjs` reads both sides
— the record, and these numbers parsed back out of this file — and fails when
they part company. The test does not check that the run was right; it checks
that the prose and the artefact are about the same run.

**On the 48, which is two different counts in this table.** The selector draws
cells at both levels: 24 at `-O0` and 48 above it, 72 in all. The 48 is the
above-`-O0` stratum — the 23 excluded plus the 25 graded — and it is what the
exclusion row, the call-site table and the intersection sentence below are all
counts over. The `-O0` cells are selected and tabulated separately, and are the
row underneath. The record carries both numbers
under different names for that reason, and the test asserts the 48 against the
stratum rather than against the selection.

**Correction, 2026-09-12: the `-O0` stratum's denominator is 1, not 0.** This
table said "every cell `NOT_COMPARABLE`; denominator 0" from the day it was
written. `test/data.test.mjs` asserted it against the record on the first run
that produced one, and failed: 23 of the 24 `-O0` cells are `NOT_COMPARABLE`
and one is not. The comparable cell is `fable_E_dbpass_r3`, the same file that
is the off-diagonal above `-O0`, and for the same reason — it is the one
`idiom=both` file in the selection, so it has an IR call site for O2 to watch
at every level. At `-O0` the two oracles agree on it: O1 `WIPE_SURVIVED`, O2
`PRESENT`.

This is a correction to the prose, not a change in a reading. It was checked
both ways before being written down: the runner as it stands reads
`O2=PRESENT` for that cell, and so does the runner as it was before this
lane grew `--write-data` (run from `git show`, same plugin, same command,
same output). The plugin is the same bytes in both runs
(`94d6f956…`, and the 2026-08-17 build at `~/vg-build/pass-observer` has that
digest too), so nothing about the instrument moved. What moved is that a
sentence nothing could check became one something checks.

A denominator of 1 discriminates nothing, which is the point the stratum was
separated for in the first place: it is reported, and it is not pooled.

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

<!-- Counted by hand on 2026-09-12 and by `--diagnose-callsites` since. The
     symbol list the tool counts is the registry's (`wipe-5-observer`), which is
     the list the plugin itself is configured with and a superset of the three
     named here; the record carries the per-symbol counts, so the subtotal for
     those three stays derivable. -->


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

* **THREE ORACLES AT ONCE.** O3 was added on 2026-09-14 and it is a SECOND
  second oracle, not a third column: a run tabulates O1 against O2 *or* O1
  against O3, never both in one table. The two never meet on the same cell here,
  so nothing in this lane says whether the pass observer and the disassembly
  reader agree with each other — which is a real question and the obvious next
  lane. Two bullets above this one used to say "anything about O3" was not
  measured; that is now half wrong and the half that changed is stated rather
  than deleted.
* **O4.** The ptrace residue observer is named in the four-oracle map above and
  is not run here.
* **A gcc reading of anything O3 cannot be pointed at.** O3 reads ONE
  `(caller, helper, bytes)` triple out of a linked program. 155 of the 321 gcc-13
  erasure generations perform more than one wipe and 4 wipe through a `volatile`
  function pointer; all 159 leave the denominator by name. What a gcc run
  measures is the 162 that remain, and `--restrict-domain` says so in the record.
* **Anything about a wipe the disassembly reader cannot see.** `objdump_fill.py`
  reads static zero stores and calls to `memset` / `__memset_chk`, so an
  `explicit_bzero` or a `volatile` byte loop is invisible to it. Every such cell
  is caught by the reader's own `-O0` control and leaves as
  `o3-reader-blind-to-this-wipe`. **This lane does not say whether those wipes
  survived** — it says O3 cannot be asked, which is a different sentence and the
  only one it has earned.
* **Whether O1 is right.** Agreement does not make either instrument correct; two
  instruments can share a blind spot, and these two share the `CONTROL` function,
  the corpus, the effect-symbol registry and the definition of "the wipe". What a
  disagreement establishes is that at least one of them is wrong about that cell.
  What an agreement establishes is weaker than it looks.
* **Toolchain drift — in a run WITHOUT `--live-o1`.** O1's half of every pair was
  measured on another day, on the machine that ran the corpus, so a disagreement
  could be a compiler that has moved rather than a difference between the
  instruments. `--live-o1` recomputes O1 in the same run and prints it beside the
  tracked verdict, which is what lets a disagreement be attributed; a run without
  it still cannot tell the two apart, and the output says so in as many words.
  What the live column does NOT do is re-derive the tracked rows or replace them
  in the table — `../ai-generated/lib/compare-rows.mjs` is still the tool for the
  question a moved reading raises.
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

Four requests, of which **one has been applied** (#3, the CI line) and three have
not. Each changes a file that produces readings somebody quotes, or a schema this
lane reads and does not own, and this lane does not get to make those edits on
its own. The applied one is kept in place rather than deleted, with what is now
stale about the lines around it, because a request that disappears on the day it
is granted leaves nobody able to tell an applied request from one nobody read.

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

### 3. `.github/workflows/ci.yml` — APPLIED, and now one line behind

This section asked for a `run_suite` line because the suite reached no runner.
**It has been added** — `ci.yml` carries `run_suite oracle-agreement` in the same
block as the other A1–A7 lanes, and `scripts/ci-suite-coverage.test.mjs` asserts
that this directory is named there. The request is kept rather than deleted
because what it asked for is the line below, and because the count beside it has
moved: the comment above that line still says the suite "compares the shared
differential oracle against the IR observer", which is now the clang half only,
and `ci.yml` elsewhere says this lane "ship[ped] with 109 tests" where the suite
now has **204**. Both are comments, neither gates anything, and neither is edited
from here — workflow files are changed centrally.

The line itself, unchanged and still correct:

```yaml
          run_suite oracle-agreement     compiler/eval/oracle-agreement/test/*.test.mjs
```

It is cheap and needs no compiler: the whole suite is pure functions plus reads
of the tracked rows, and it stayed that way when the gcc-side oracle was added —
the two questions that need a compiler are in `tools/`, as checks that exit 3
when they cannot run, precisely so this line stays a line anybody can add. Two of
its tests read files in *other* lanes (`../lto-window`, `../residue-tracer`) to
re-derive the four-oracle map, so this is also the thing that would notice if one
of those lanes started using the shared oracle.

### 4. `../../schema/interfaces.md` §3 — `PARTIAL`, and a word for "two instruments, one cell"

Two things, and the first is older than this lane.

**`PARTIAL` is not in §3's table.** `../../gcc-repair/scripts/objdump_fill.py`
has returned it since long before this lane existed — "some zero fill, but not
the buffer's worth" — and §3 lists `PRESENT`, `ABSENT`, `LOST`, `REINTRODUCED`,
`NOT_APPLICABLE`, `NOT_OBSERVED` and nothing else. O3 now carries that word into
this lane, where it is handled as `NOT_COMPARABLE`, so the gap is no longer
confined to one script. §3's own rule is that "a component that needs a
[seventh] reports that and it is added here first"; this is the report. Nothing
here edits that file.

**And a word for the cross-oracle cell.** The vocabulary has words for what the
property did and for whether the instrument worked. It has none for *this cell
was read by two instruments and they said different things*, which is the only
output this lane produces. The lane uses `NOT_COMPARABLE` for the vocabulary
boundary and plain table cells for the disagreement; if a second cross-oracle
lane is ever written, the word should be in the schema first. `interfaces.md` is
not edited during implementation (its own first rule), so this is a request and
not a change.

---

Licence: Apache-2.0 WITH LLVM-exception (see `compiler/LICENSE`).
