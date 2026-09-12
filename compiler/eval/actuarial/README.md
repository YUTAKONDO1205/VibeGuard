# actuarial

An actuary does not predict your fire. They publish a rate table: so many claims
per so many policy-years, with the exposure base written next to the number, so
that anyone can recount it and disagree with the arithmetic rather than with the
author. This lane does that to the build verdicts in `../ai-generated/`.

It runs no compiler. The measurement already happened in that lane, by
differential compilation, and its verdicts are tracked. What was missing was the
denominator. Tallied flat, the rows say `WIPE_ELIMINATED` 833 — and a count with no
exposure base underneath it cannot be checked, cannot be compared between two
idioms, and cannot be carried anywhere without being re-derived by whoever quotes
it next. So this lane produces one artefact — a table keyed by
(idiom x vendor x optLevel) whose every cell is `num/den` over a stated base —
and one rule, written down, about how that artefact may be read. The rule is
stated in full below, including the part of it that no test in this lane can hold.

```
node compiler/eval/actuarial/build-rate-table.mjs            # print, write nothing
node compiler/eval/actuarial/build-rate-table.mjs --write    # rewrite data/
node compiler/eval/actuarial/build-rate-table.mjs --check    # exit 1 on drift
node --test compiler/eval/actuarial/test/*.test.mjs
```

## The table

```
idiom         vendor          -O0      -O1      -O2      -O3      -Os
removable     clang-18      0/133   62/133  113/133  113/133  113/133
removable     gcc-13        0/133  108/133  108/133  108/133  108/133
both          clang-18       0/26     0/26     0/26     0/26     0/26
both          gcc-13         0/26     0/26     0/26     0/26     0/26
nonremovable  clang-18      0/160    0/160    0/160    0/160    0/160
nonremovable  gcc-13        0/160    0/160    0/160    0/160    0/160
```

Each cell reads: **in the r2 corpus, N of D files with this idiom lost the wipe
under (vendor, optLevel).** Four things in the table are worth saying out loud
before anything else is said about it, and the last two are about the same 0s
having two different meanings.

**The two vendors do not agree, and they disagree about *where*, not about how
much.** gcc-13 reaches its full elimination at `-O1` and does not move again;
clang-18 removes 62 at `-O1` and then 113 from `-O2` on. A build that "is
optimised" says nothing until it says which compiler and which level, which is the
whole reason the key has three axes instead of one. Counted per file rather than
per cell — a reading the table does not carry, since its cells are counts: at `-O1`
the 62 files clang removes are a strict subset of the 108 gcc removes, 46 files
being removed by gcc alone and none by clang alone.

**`-O0` is 0 everywhere.** The instrument is not detecting a property of the
source; it is detecting what a pipeline did to it. The same 133 files, unmodified,
lose nothing at `-O0` and lose 113 at `-O2`.

**The `nonremovable` row is 0 across the board, and that row — only that row — is
the control column of this table.** `nonremovable` is what the source-side detector
classed as a wipe a compiler is not free to drop — a call to `explicit_bzero`,
`memset_s`, `SecureZeroMemory`, `sodium_memzero` or `OPENSSL_cleanse`, a call
through a `volatile` function pointer, a write through `volatile`, or a helper whose
body or header carries `volatile` (`../ai-generated/lib/ablation-cell.mjs`,
`wipeSpans` and `wipeHelpers`). Its 0s are two claims agreeing: a source
classification made before the build, and the 1,600 scored configurations of that
row after it. If an elimination appeared there, the finding would be about one of
the two, not about a compiler getting worse.

**The `both` row is 0 too, and it is not a second agreement — it is close to what
the ablation design forces.** A `both` file wrote one of each idiom, and the
measurement ablates a file's wipe spans *as a unit*: `ablateSpans(src, spans)` with
the whole list, once per file (`../ai-generated/lib/build-analyze.mjs`, the line
that writes the ablated form). So the ablated form of a `both` file has lost its
nonremovable span as well, and `WIPE_ELIMINATED` — which is decided by
`bodyOf(as written) === bodyOf(ablated)` — would require the listing to be unchanged
after removing a wipe the same classifier says cannot be removed. 0/26 is therefore
near-forced by the construction: two 0 rows are not two independent agreements, and
this one is mostly the ablation reporting that it changed the file.

What the `both` row is emphatically not is evidence that the removable span inside
those files survived. The per-span supplement — the same `verdictOf`, the same
flags, but one removable span ablated alone — finds a removable span eliminated in
**9 of the 260 configurations behind this row** (2 of its 26 files, in 7 of its 10 cells)
while the file-level verdict stays `WIPE_SURVIVED`:
`../ai-generated/data/r2-span-rows.json`, field `hiddenElimination`, computed
against this table's own source file (`r2-span-results.txt` carries its sha256, and
it is the one printed above). A cell-level table cannot see those and this one does
not claim to. Read the `both` row as *this ablation, applied as a unit, changed the
listing every time*, and go to the per-span rows for the question it looks like it
answers.

The idiom is a label on the *source*, and it is worth being clear that it is only
that: it decides which row of this table a file lands in and nothing else. The
verdict in the cell was decided by compiling twice and comparing, so a mislabelled
file moves between rows without changing any verdict — which is the property that
makes (idiom x vendor x optLevel) a legitimate key rather than a circularity.
`ablation-cell.mjs` makes the same point where it classifies helpers: "The ablation
VERDICT is unaffected either way: that is decided by compiling, not by this label."

`data/rate-table.json` is the record; `data/rate-table.txt` is the same numbers as
text. Neither prints a percentage anywhere, deliberately: `num/den` cannot be
quoted without its denominator, and a percentage can.

## Denominator

The exposure base was checked before it was used, because the count that a rate
table must not be wrong about is the one underneath the line. Four facts, all
first-hand:

1. `../ai-generated/data/r2-build-rows.json` holds **4,689 rows**, of which
   **exactly 4,650 carry a `(cc, opt)` cell**. The other 39 are `NO_WIPE_WRITTEN`
   rows for files in which no wipe was written at all, so there was no build
   configuration to record.
2. The lane's own machine-generated results file agrees: `../ai-generated/data/r2-results.txt`
   line 3 reads `生成 720 / ビルド判定 4650 構成` — 4,650, matching the rows exactly.
3. `../ai-generated/README.md` said **4,660** in its round-2 table. That was a
   transcription error, not a measurement: no run ever produced that number. It
   has since been corrected in place, with the correction left visible rather than
   patched silently.
4. `git log` on the rows file shows 4,689 rows since its only commit, so this was
   never drift between a moving dataset and stale prose. One of the two numbers
   was simply typed.

### What `den` counts, and why it is not the row count

**`eliminated.den` counts the rows of the cell whose positive control was still
visible in that build (`control === 'PRESENT'`), not every row of the cell.**

Every translation unit in that measurement carries a second wipe that the compiler
is not permitted to remove, compiled by the same command in the same file. When
that control is missing from the listing, the run cannot distinguish *the subject's
wipe was removed* from *this configuration stopped being readable*. Round 1 is why
this is spelled out rather than assumed: gcc-13 at `-Os` emits the control as
`rep stos`, the repository's oracle did not know that shape, and all 74 gcc `-Os`
configurations of round 1 reported the control absent. (That count is
`../ai-generated/PROTOCOL-r2.md`'s, not this lane's — round 1's rows are not in the
file this lane reads.) r2 added a local `rep stos` fallback and records, per row,
which path saw the control; counted here, that is 2,871 rows via the oracle and 319
via the fallback.

So the denominators differ from the ones in `r2-results.txt`, and only for
`nonremovable`: 160 rather than 162 per cell. Two files — `fable_E_seedphrase_r3`
and `haiku_S_privkey_r1` — do not compile once their wipe is ablated, so all 10 of
their cells reach no verdict at all. The other lane counts them in its
denominator; this one does not. The difference is 20 rows, it is in the table as
`notScored`, and the drift test asserts **both** denominators so that the gap is a
checked number rather than a remark here.

### The three counters

| field | what it counts |
|---|---|
| `eliminated` | `{num, den}` — num is verdict `WIPE_ELIMINATED`, den is the live-control rows |
| `verificationIncomplete` | rows where the control itself was not visible, so the reading is **withheld** |
| `notScored` | rows that reached no verdict: the build failed, the ablated form failed to build, or the target function's body was not found |

`verificationIncomplete` is **0 in every cell of this table**, and that is a
measured 0, not an absent column. The `rep stos` fallback is what made it 0, and
the counterfactual is exact rather than rhetorical: `controlPresent` returns
`via: 'rep-stos-fallback'` only after the oracle has failed to see the control, so
the 319 rows carrying that value are precisely the rows this column would hold had
r2 shipped round 1's oracle. It stays in the record so that a future run which
loses its control sees the count move instead of seeing its denominator quietly
shrink.

`notScored` is a roll-up of three different reasons, so it is never the last word:
every cell also carries `byVerdict`, which names them separately. Neither withheld
nor not-scored rows are ever added to either side of the ratio. *Did not look* and
*was not there* stay different words all the way to the printed table.

The record has to say this as well, because the record is what travels while this
README stays here. `denominatorRule` in `data/rate-table.json` names **both** ways
out of a denominator, and `denominatorExclusions` beside it counts which one this
record actually took: `{ rows: 20, withheldControlUnseen: 0, noVerdictReached: 20,
byVerdict: { ABLATION_DID_NOT_COMPILE: 20 } }`. The distinction is not decorative
and the earlier wording of that rule got it backwards: **every** row excluded from a
denominator in this record is of the second kind. `verdictOf` returns
`{ verdict: 'ABLATION_DID_NOT_COMPILE' }` before it ever calls `controlPresent`, so
those rows carry no `control` key at all — they are not rows whose control was
looked for and missed. A reader quoting a rule that mentioned only the missed
control, to explain why `den` is 160 where `rows` is 162, would have given the wrong
reason for all 20 of them. The printed table carries the same line
(`out of every den 20 (control unseen 0, no verdict 20: ABLATION_DID_NOT_COMPILE 20)`),
and the drift test fails if the rule stops naming a path the record's own counts
say was taken.

### What is out of the table, and why

- **1,440 rows (360 files)** are the `authz` and `configguard` families. They carry
  no idiom and no wipe verdict; they were scored against other questions entirely
  (does the check survive `-DNDEBUG`; does the default build differ from the
  all-macros build). Folding them in would need a second table, not a wider one.
- **39 rows (39 files)** wrote no wipe at all. In actuarial terms there is no
  policy: nothing could be eliminated because nothing was written. This is a real
  and large finding of the other lane — it is simply not a *rate*, and it is not
  hidden here either, it is a named line of the exposure base.

The axis values are read from the rows rather than declared: the idiom classes are
whatever `row.idiom` actually spells (`removable`, `nonremovable`, `both`), and a
class this lane's display order does not know is appended to the table rather than
dropped from it. The vendor keeps its version (`clang-18`, not `clang`), because
the version is the thing that was run; a table keyed on "clang" would be a claim
about a compiler family that nothing here measured.

## The wording rule

This lane may say:

> in the r2 corpus, N of D files with this idiom lost the wipe under
> (vendor, optLevel)

It may **never** say *probability*, and neither may anything downstream of it.

That rule is part mechanism and part standing instruction, and the two are worth
separating, because a rule presented as enforced when it is not is the same class of
error this lane exists to correct:

- **Mechanised.** The sentence is a constant in the code (`lib/rate-table.mjs`,
  `READING`), copied into `data/rate-table.json` and printed above the text table.
  The drift test spells the literal out again and pins every copy of it to that
  literal, character for character — the constant, the record's `reading`, the
  printed line, and both of this README's copies. Edit any one of them alone and
  the suite fails; edit all of them together and the test still fails, because the
  sentence it compares against is written out in the test file itself. That is a guard against drift between copies, which is a real failure mode
  here: this README is a second copy of the table as well, and it is checked for the
  same reason.
- **Mechanised, but narrowly.** The drift test also fails if the forbidden word
  appears anywhere in this lane outside this section. That is a substring test on
  one word, and it is worth exactly what a substring test on one word is worth. It
  also stops at the lane boundary: nothing here checks anything *downstream*, so the
  second half of the sentence above is a request to whoever writes the consumer, and
  the rendering rule in the [SPEC] section below is where it is written down for
  them.
- **Not mechanised at all.** Nothing here recognises a *paraphrase*. "N of every D
  builds of this idiom will lose the wipe" never says the forbidden word, passes
  every check in this lane, and is precisely the promotion the rule exists to
  prevent. No test in this lane can tell that sentence from the one above it; a
  reviewer can. The rule is written down so that the reviewer has something to hold
  it to — not because the repository can enforce it.

This is not fastidiousness about words. The product has an axis that looks like the
place such a number would go, and that axis has a contract which a rate would
break. From `packages/rules/src/confidence.ts`, read first-hand:

- **Lines 19-22.** "Policy decision (see paper): this is **downgrade-only**. We
  never raise confidence, because 'this match is on a real production path' cannot
  be decided reliably from a regex window and a wrong guess manufactures false
  `high`-confidence findings."
- **Lines 33-44.** "A false-positive filter is also an attack surface. Someone who
  controls the file can wrap a *real* vulnerability in a docstring ... **a context
  downgrade is a noise-reduction convenience and must never decide a security
  question.** `SEVERITY_CONFIDENCE_FLOOR` therefore bounds how far this module may
  lower a finding whose *impact* would be severe if real ... Severity is static per
  rule and attacker-controlled text cannot move it, which is exactly what makes it
  usable as the bound."
- **Line 413**, inside `explainContextConfidence`: "the floor may only ever hold a
  downgrade back, never push a finding above the confidence its rule declared" —
  the `min(RANK[base], …)` that makes `result <= base` true by construction, for
  every input.
- **Lines 96-97.** "**a rule that sets `m.confidence` takes on the gate's
  responsibility itself.** No rule sets it today."

The axis is downgrade-only *because the context it reads is attacker-controlled*.
A rate attached to it would be a raise — and a raise sourced from a corpus, which
is worse than a raise sourced from the file, because the file at least belongs to
the user being warned. So the transfer below carries a ratio under its own name and
does not touch that axis at all.

## Product side — [SPEC] only, nothing implemented

Nothing in `packages/` is changed by this lane and nothing here is wired to the
product. What follows is a specification for a field, to be implemented (or
rejected) in a separate PR on the product release train.

**Field name: `compileLossEvidence`.** Not `confidence`, and not a modifier of it.

```jsonc
// on a Finding, optional
"compileLossEvidence": {
  "num": 113,            // integer: files of this idiom that lost the wipe
  "den": 133,            // integer: files of this idiom with a live control
  "corpusId": "r2",      // which corpus the ratio was counted over
  "vendor": "clang-18",  // the toolchain the consumer builds with
  "optLevel": "-O2"      // the level the consumer builds at
}
```

**It is supplied by the consumer, never derived by the analyser.** The analyser
cannot know the two axes that decide the cell. `packages/rules/src/rule-types.ts`
lines 27-33: a `RuleContext` is `{ filePath?, language?, content, lines }` — text
and a path. Nothing in it names a compiler or an optimisation level, and nothing
should: the product scans source that has not been built yet, often on a machine
that will never build it. A build system, a CI job or an IDE extension knows its
own vendor and level; the analyser knows a string. So the field arrives from
outside, and a finding without it is the normal case rather than a degraded one.

Rendering rule, inherited from the wording rule above: a consumer may print
"113 of 133 files with this idiom lost the wipe under clang-18 -O2 in corpus r2"
and may not print a percentage, a score, or anything that reads as a forecast about
*this* file. The ratio is about a corpus; the finding is about a line.

**Why it is worth doing at all**: this is the fourth step of a loop whose first
three exist. Today `find → fix → confirm` closes entirely on the build side — the
compiler-side finder locates a wipe, the repair plugins pin it
(`compiler/llvm-repair`, `compiler/gcc-repair`), and differential compilation
confirms the repair on the same instrument that found the loss. The person who
wrote the `memset` never hears any of it. `compileLossEvidence` is the step where what the
build side confirmed travels back to the source-side finding that a human actually
reads, carrying its denominator with it. It is the difference between "this wipe
may be removed by the compiler" — true of every wipe, and therefore ignorable — and
"113 of 133 files that wrote this idiom lost it under the toolchain you are
building with".

## Adoption is not granted yet

The project's planning document (not tracked in this repository) fixes what a new
increment is allowed to supply, and admits exactly three axes:
**観測粒度** (finer observation), **観測範囲** (wider observation), **網羅**
(coverage). This lane supplies none of them. It observes nothing that was not
already observed: it re-presents one existing measurement with its denominator
attached, and then proposes a **transfer to the product**, which is a fourth kind
of thing the rule does not currently admit.

So this is flagged as pending a ruling, not assumed to have one. The lane is
written so that the ruling can cut it in half: the table and its drift test stand
alone, change nothing outside `compiler/eval/actuarial/`, and are useful to the
paper whatever is decided; the product-side section is a specification with no code
behind it. If the ruling is no, that section is deleted and nothing else moves.

## What this lane does not do

- **It measures nothing.** Every number is a recount of tracked rows. If the
  underlying measurement is wrong, this table is wrong in exactly the same way and
  will not notice.
- **It has no version ladder.** The vendor axis has two values because the
  measurement had two compilers. `clang-18` and `gcc-13` are not "clang" and "gcc",
  and this table says nothing about any other version.
- **It is not a sample of the world.** 321 files from four models on twenty
  synthetic scenarios, each a single-shot generation with none of the revision and
  review a real change goes through — the confounders are listed in
  `../ai-generated/PROTOCOL-r2.md`. The corpus id is carried in every record so
  that a reader can go and disbelieve the corpus rather than the arithmetic.
- **It emits no evidence finding.** The `VG-ART-*` ids are for records produced by
  observing a build; this lane observes a file that a build already produced. If
  the transfer above is adopted, an id will be needed for the record the product
  consumes — this lane does not claim one in advance.
- **It is not in CI yet.** See below; until that edit is applied, the drift test
  runs only when a person runs it. That is the condition the CI step's own comment
  describes finding elsewhere in this tree: "42 more assertions were running
  nowhere (observer 22, calibration 10, metamorphic 10)".

## Layout

```
build-rate-table.mjs       the only executable; reads tracked rows, writes data/
lib/rate-table.mjs         pure functions: buildTable(), renderText(), the counters
data/rate-table.json       the record
data/rate-table.txt        the same numbers as text
test/rate-table.test.mjs   the drift test; imports nothing from this lane
test/guard.test.mjs        the branches r2 does not exercise; imports the library
```

`build-rate-table.mjs` is not called `run-actuarial.mjs`, which is the layout the
other lanes follow. Every other `run-*` invokes a toolchain and produces a
measurement; this one invokes nothing, so the name says what it is. It carries no
shebang for the reason the repository's `.gitattributes` explains at length: a
shebang terminated by CRLF stops a module from loading under WSL, silently, and
`node <path>` cannot acquire that fault.

## The drift test

`test/rate-table.test.mjs` recomputes the whole table from the rows with its own
arithmetic and does **not** import `lib/rate-table.mjs`. A test that calls the
builder and compares the builder's output to the builder's output catches a
hand-edited record and nothing else; written out longhand, it also catches the
aggregator being wrong, which is the failure that would matter here because a rate
table is quoted and its inputs are not re-read. Four legs, failing for different
reasons:

1. this file's own counting vs the tracked JSON — a wrong aggregator;
2. the tracked text table parsed back vs the tracked JSON — a stale `.txt`;
3. `build-rate-table.mjs --check` as a subprocess — a builder that no longer
   reproduces its own record;
4. `../ai-generated/data/r2-results.txt` RQ2 block vs the tracked JSON — a
   numerator that drifted from the lane it came from.

Three more legs were added after a review found the lane asserting things no test
held. They fail on prose, which is unusual and deliberate: in a lane whose product
is a number and the sentence you may read it with, an unpinned sentence is an
unpinned deliverable.

5. the reading sentence against a literal spelled out in the test file — the
   constant in `lib/rate-table.mjs`, the record's `reading`, the line printed above
   the table, and both of this README's copies, character for character;
6. the `both` row against `../ai-generated/data/r2-span-rows.json`: the 9 hidden
   eliminations, the 2 files and 7 cells they fall in, the sha256 saying both layers
   read the same corpus, and the README sentences that report them;
7. `denominatorRule` against `denominatorExclusions` — a record whose rule names
   only a path its own counts say was not taken fails here.

Plus the shape rules: every number an integer (and no float *spelled* anywhere —
`Number.isInteger(1.0)` is true, so the raw text is checked as well as the parsed
values), each cell's verdict classes summing to its row count, the exposure base
summing to 4,689, and the vocabulary rule. The needle for the forbidden word is
assembled from fragments at runtime, following `scripts/check-disclosure-shape.mjs`,
so that the test does not match itself and report a clean lane as dirty.

`test/guard.test.mjs` is the second file and the only one that imports the
library. It asks what happens to row shapes the r2 corpus does not contain but the
ai-generated lane can produce: a `NOT_OBSERVED` row whose control is alive (the
table refuses to print rather than absorb it into a denominator), a
`VERIFICATION_INCOMPLETE` row (counted by name, on neither side of the ratio), an
idiom or optimisation level this lane's display order has never seen (appended to
the table, not dropped from it), and a cell that loses rows by *both* exclusion
paths at once, which r2 never does — that one is what keeps `denominatorExclusions`
from being a column shaped by the only corpus it has seen. Those branches decide
where a row lands in a ratio and nothing in the tracked data reaches them.

**The needles were fired.** A green test that cannot fail is decoration, so each
leg was made to fail on purpose: the first four by planting the fault in the tracked
files and restoring them afterwards (the three files were compared by digest, byte-
identical), the last five in a throwaway copy of the lane outside this tree, which
is where a needle belongs once a lane has a record to keep:

| planted | what failed |
|---|---|
| one numerator changed `113` → `114` in `data/rate-table.json` | legs 1, 2, 3 *and* 4 — four independent failures from one digit |
| the forbidden word appended to `data/rate-table.txt` | the vocabulary rule, and leg 3 |
| one digit changed in the README's copy of the table | the README-verbatim check only |
| `"den": 133` rewritten as `133.0` | the float check (`a float is spelled in the record: 133.0`) |
| the `READING` constant rewritten as a forecast about your build, and the record regenerated so it agrees | leg 5 only, printing both sentences against each other (leg 3 as well, if the record is *not* regenerated) |
| the README's copy of the rule rewritten, code and record left alone | leg 5 (`README.md carries the reading sentence verbatim 1 time(s)`) |
| the `both` paragraph put back to "the 0s are two claims agreeing" | leg 6 (`the README does not say that the wipe spans of a file are ablated as a unit`) |
| `denominatorRule` put back to the one-path sentence, record regenerated | leg 7 (`denominatorRule does not name notScored`) and the guard that pins both paths (leg 3 instead, if the record is not regenerated) |
| the whole exclusion accounting removed from the record | leg 7, and both guards — 3 failures |

The last five rows carry a second measurement, and it is the one worth reading: with
the three added legs and the two added guards removed, **every one of those five
breaks leaves the suite at 17 pass, 0 fail.** The wording rule and the record's
account of its own denominator could each be rewritten into something untrue — in
the code and in the record at once — and nothing in the lane said a word. That is
what those five legs bought, and it is why they are here rather than a sentence
promising the same thing.

## Edits requested in files this lane does not own

**1. `.github/workflows/ci.yml`** — the lane's suite reaches no runner. Insert one
line after line 420 (`run_suite ai-generated`), in the step "compiler/ suites that
reach no other runner":

```
          run_suite actuarial             compiler/eval/actuarial/test/*.test.mjs
```

That step's own comment says it is for suites that are "pure JS over catalogues,
schemas and recorded text" and "invoke no compiler at all". This one qualifies: it
reads two tracked JSON files and two tracked text files, and the only process it
spawns is `node` running `build-rate-table.mjs --check`.

**2. `compiler/eval/ai-generated/README.md`** — *already applied by the owning
agent; recorded here only so the reconciliation above has a visible outcome.* The
round-2 build-verdict count now reads 4,650 with the correction stated in place.
No further edit is requested.
