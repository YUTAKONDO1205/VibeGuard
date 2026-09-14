# version-ladder — at which compiler version does the wipe first disappear?

Every erasure number this project has is a number about `clang-18` and `gcc-13`.
That pin is a scope limit, and scope limits read like results: "the wipe is
eliminated at `-O2`" is a sentence about two compiler builds, and a reader is
entitled to ask whether the previous release did it too, or whether the next one
will. This lane puts the installed versions side by side and, for each
(file, level, vendor), records the version at which `WIPE_ELIMINATED` **first
appears** — or states, with the gap named, that it cannot.

**The shape is not new and this lane does not claim it is.** Simon, Chisnall and
Anderson (*What You Get is What You C: Controlling Side Effects in Mainstream C
Compilers*, EuroS&P 2018) compiled constant-time selection with three clang
versions and reported that as

> "compiler version increases (Clang 3.0, 3.3 and 3.9), more [implementations
> become insecure]"

Three versions, hand-inspected, one property. What this lane adds is the
**oracle**, not the idea: each rung's verdict comes from differential
compilation of the file against an ablated copy of itself, with a positive
control co-resident in the same translation unit, so at every rung "the wipe was
removed" stays separable from "the extractor stopped recognising wipes in this
version's output". Hand inspection cannot separate those at scale, and a search
of the assembly for a symbol name cannot separate them at all.

## The instrument is the find step's, not a copy of it

```
../ai-generated/lib/ablation-cell.mjs   FLAGS, CONTROL, CONTROL_EFFECT, wipeSpans,
                                        ablateSpans, compile, pool, verdictOf, bodyOf
../repair-loop/lib/vendor.mjs           vendorOf, fortifyFromDefines, trackedCcProblem
../repair-loop/lib/surgicality.mjs      differsOnlyInLabels
../repair-loop/lib/provenance.mjs       absolutePathHits, sha256Text, rowsFileLabel
```

Nothing here re-implements a span finder, an ablation, a control check or a
verdict. That is not tidiness — it is what makes the anchor below mean anything.
This lane does **not** drive `run-repair-loop.mjs`, which refuses a `--cc` absent
from the tracked rows (exit 5); nine of this lane's eleven rungs are exactly that
case.

## The anchor — the false-positive killer

The lane's claim is comparative, and a comparative claim survives almost any
systematic error in the measurement, because the error lands on every rung
equally. A dropped flag, a control that was never appended, the wrong target
function: every rung would shift together and the ladder would still look like a
clean story.

Two rungs are rungs the project has already measured. `clang-18` and `gcc-13`
*are* the compilers behind `../ai-generated/data/r2-build-rows.json`. So the run
joins its own `clang-18` and `gcc-13` rows to the tracked rows on
`(id, cc, opt)` and **exits 2 on any disagreement**, before printing a ladder. A
row whose compiler is an anchor compiler and which finds no tracked cell is also
a disagreement, not a pass: `0/0 agree` must never read as clean.

**And a run that compares no anchor cell at all exits 2 as well.** That sentence
is here because the lane first shipped without it, and the hole was not exotic:
`anchorDisagreements` returns `{checked: 0, agreed: 0, disagreements: []}` when
no row of the run is an anchor row, `main()` exited on
`disagreements.length` alone, and so

```
node run-version-ladder.mjs --out <lab> --ccs clang-15,clang-16 --opts -O2 \
    --ids haiku_E_aeskey_r1 --no-subjects
```

printed a full ladder, `0/0 cells reproduce the tracked verdict`, and **exit 0**.
On a machine without the pinned pair that was the *default* invocation. A
comparative claim survives any systematic error that lands on every rung, so a
ladder with no fixed point is not a weaker result — it is an unchecked
instrument. Three ways in, and a backstop for a fourth nobody has thought of —
all refused now:

| the run has | refused |
|---|---|
| no obtained rung among `clang-18`, `gcc-13` | exit 2, **before the compiles** (`vacuousAnchorProblem`) |
| no selected subject the tracked rows hold cells for | exit 2, before the compiles — this lane's own `subjects/*.c` are not r2 files |
| `--rows` holding no erasure row for an obtained anchor rung | exit 2 (`trackedCcProblem`, reused from `../repair-loop/lib/vendor.mjs`, whose refusal already reads *"0/0 agree" would pass vacuously*) |
| `anchor.checked === 0` at the join, by any other route | exit 2 (`anchorProblem`, the backstop: it is the one place the exit code is read from) |

`manifest.anchor.problem` in the JSON is the machine-readable half — `null`
exactly when the run exits 0 — because a consumer reading `checked`/`agreed`
can compute `0/0` and call it clean, which is how this shipped.

Measured, in the run recorded in `data/`:

```
anchor against the find-step rows in (default) (clang-18, gcc-13)
  60/60 cells reproduce the tracked verdict
```

The exit-2 paths are exercised end to end by `test/exit-codes.test.mjs`, which
spawns the runner and asserts the code (see "Running it"), and the disagreement
path was exercised by hand as well: a **lab copy** of the tracked rows with one
verdict flipped (the tracked file itself untouched, confirmed with `git status`)
produced

```
anchor against the find-step rows in (outside the repository) (clang-18, gcc-13)
  0/1 cells reproduce the tracked verdict
  NOT ANCHORED: 1 of 1 anchor cell(s) do not reproduce the tracked verdict.
  Nothing below is anchored: a comparative ladder with no fixed point cannot tell a real
  version effect from a systematic error that lands on every rung. This run exits 2.
  DISAGREEMENTS -- every other rung is unexplained until these are:
  haiku_E_aeskey_r1 clang-18 -O2: this lane WIPE_ELIMINATED, tracked WIPE_SURVIVED
```

and exit code 2.

## The identity guard

A rung that is secretly another rung does not fail anywhere. It compiles, it
produces a verdict, and the verdict is filed under the wrong version — and the
lane would then report a first appearance one or more rungs away from the truth
with nothing in the output to see it by. `clang` on a `PATH` can be a symlink to
anything, and so can a versioned name.

So every rung is probed for `--version`, `-dumpversion`, and the sha256 of the
binary `readlink -f` actually reaches, and:

- an **unversioned** spelling (`clang`, `gcc`, `cc`) is refused outright — it
  names no rung, and the whole output is indexed by rung;
- a versioned spelling whose banner major or `-dumpversion` major differs from
  the `N` in `clang-N` / `gcc-N` is refused;
- a version that is not on the declared ladder is refused.

Refusal is **exit 6**, distinct from bad arguments. Demonstrated rather than
asserted — a symlink named `clang-17` pointing at clang-20, first on `PATH`:

```
version-ladder: identity guard: --cc clang-17: the binary reports version 20.1.2,
whose major is 20, not 17. A name that is a link to another version would file
every one of its verdicts under the wrong rung
EXIT=6
```

Only the resolved binary's **basename and digest** are recorded, never the
directory it sits in: that is this machine's layout, and the records are scanned
for it (`absolutePathHits`) before anything is written.

## `_FORTIFY_SOURCE`, read per version rather than assumed

The memset spelling a source `memset` becomes depends on `_FORTIFY_SOURCE`, and
the project's existing note about it is a note about `gcc-13`. Read per rung,
with the lane's own `FLAGS` and `-dM -E`, it is **not** constant across the gcc
ladder:

| rung | `-O0` | `-O1` | `-O2` | `-O3` | `-Os` |
|---|---|---|---|---|---|
| clang-15 … clang-20 | not-defined | not-defined | not-defined | not-defined | not-defined |
| gcc-10, gcc-11 | not-defined | **2** | **2** | **2** | **2** |
| gcc-12, gcc-13, gcc-14 | not-defined | **3** | **3** | **3** | **3** |

That is a real per-version difference in the build, sitting underneath a table of
per-version verdicts, and it is why this was measured instead of assumed. It did
not move any verdict in this run — but "it did not move a verdict here" is a
different sentence from "it is the same everywhere", and only the first one is
measured.

`spellingSeen` in the rows records which of the declared effect symbols the
file-as-written listing calls. It is **metadata and is read by nothing**: the
verdict is a differential compilation, and `interfaces.md` §4 forbids deciding an
effect's presence by searching for a symbol name. The list comes from
`CONTROL_EFFECT.symbols`, never a literal of this lane's own
(`compiler/schema/effect-symbol-lists.test.mjs` exists to stop a tenth copy of
that list appearing).

Across all 495 cells the observed spellings were `memset` (40 cells) and `none`
(455) — `__memset_chk` never appeared, on any gcc rung, at any fortify level.

A negative observation is worth reading only if the instrument could have seen
the thing, so that is a **command, not a sentence**:

```bash
node compiler/eval/version-ladder/tools/fortify-spelling-probe.mjs \
    --ccs gcc-10,gcc-11,gcc-12,gcc-13,gcc-14,clang-15,clang-18,clang-20 --opts -O0,-O1,-O2
```

It builds two probes with the lane's own `FLAGS` and reads them with the runner's
own `spellingIn`: one wiping `sizeof buf` of a 32-byte buffer (the shape every
subject here has), one wiping the same buffer for a length the compiler cannot
fold. Measured:

```
  rung      level const size     runtime length
  gcc-11    -O0   memset         memset
  gcc-11    -O1   none           __memset_chk
  gcc-11    -O2   none           __memset_chk
  gcc-13    -O1   none           __memset_chk
  gcc-13    -O2   none           __memset_chk
  clang-18  -O1   none           none
```

— and the same on gcc-10, gcc-12, gcc-14, and `none` on every clang rung, which
is the `_FORTIFY_SOURCE` table above showing up in the listings. So the detector
does see `__memset_chk` wherever fortify has something to check; the reason no
cell here shows it is that both sizes are known and the wrapper folds away.

(The line this replaces quoted a `cc -S file.c | grep` loop, which cannot have
produced the output printed beside it: `-S` writes the listing to a **file** and
pipes an empty stream. The fact held — it is re-measured above — but the record
of it did not, and a record a reader cannot re-run is not a record.)

## The first-appearance rule

This is the one thing in the lane that would make it **wrong** rather than
incomplete, so it is written down here and tested on tables in
`test/ladder.test.mjs` without a compiler.

For each (fileId, optLevel, vendor), against the **declared** ladder:

| status | when |
|---|---|
| `FIRST_AT v` | `v` is the lowest rung showing `WIPE_ELIMINATED`, **and every rung below `v` in the declared ladder was obtained and scorable** |
| `NEVER_ELIMINATED` | every declared rung was obtained and scorable, and none eliminated |
| `UNDETERMINED` | otherwise, with `gaps` naming each rung that stopped the question being answerable, and why |

`FIRST_AT` carries a second word, because on its own it is two different
observations under one name and a program reading `data/version-ladder.json`
cannot tell them apart:

| `transition` | what was observed |
|---|---|
| `observed` | at least one declared rung **below** `v` was obtained, was scorable and kept the wipe. The elimination appears between two measured rungs — the only shape that says a version introduced it |
| `none-below` | `v` is the **lowest** rung of the declared ladder. The set below it is empty, so "every lower rung was obtained and kept the wipe" is true of nothing observed: the wipe was already gone at the bottom of the ladder and **no transition was seen anywhere**. Not evidence that `v` introduced the elimination |

The counting line prints the split, and a `FIRST_AT` carrying neither word breaks
the accounting rather than being filed under the kinder one. This matters here
and not in the abstract: **all 38** first appearances in the run below are
`none-below`.

Scorable means `WIPE_SURVIVED` or `WIPE_ELIMINATED`. A `COMPILE_ERROR`, an
`ABLATION_DID_NOT_COMPILE`, a `NOT_OBSERVED` or a `VERIFICATION_INCOMPLETE` below
the first elimination is a gap, named by its own verdict — a rung with no reading
cannot be stepped over on the way to a "first". A rung *above* the first
elimination that was not obtained does not disturb the answer.

The ladder is **declared, not discovered**. The difference between "version 15
kept the wipe" and "version 15 was never installed here" is the whole of the
rule, and it can only be drawn against a list written down in advance. A vendor
with no declared ladder **throws** rather than being given an empty one: with no
rungs, every set below is empty, and `firstAppearance` would return a clean
`NEVER_ELIMINATED` over a ladder that does not exist — the one answer the table
above forbids for a valid vendor. No caller in the lane can reach that today
(`appearancesFrom` iterates the declared vendors); the next caller of an exported
pure function should not be able to either.

### Words this lane is careful about

A rung that was not obtained **produces no cell rows at all**. It appears in
`versions[]` as `{obtained: false, reason: 'not-installed' | 'not-requested'}`,
is counted as `skipped` in the counting line, and prints as `-(not obtained)`.

It is **never `NOT_OBSERVED`** and **never `UNSUPPORTED`.**
`compiler/schema/interfaces.md` §3.1 gives `UNSUPPORTED` a specific meaning — the
toolchain refused an invocation it was given — and §3 gives `NOT_OBSERVED` the
meaning "no observation was made here" for a reading that was attempted. Neither
is true of a compiler that is not installed on the machine. Rather than invent a
word, this lane uses `not-obtained` in its own `gaps` field and says so here. See
"Edits requested in files this lane does not own" below for the vocabulary
request that follows from this.

`skipped` is split by reason because the two are different facts and only one is
about the machine: `not-installed` (asked for, absent) versus `not-requested`
(this invocation did not ask). Both are `not-obtained` to the rule.

`transition` is a lane-local word too, and deliberately not a request to
`interfaces.md` §3.1: that section fixes what a **cell's instrument** may report
(`OK` / `UNSUPPORTED` / `BROKEN_MEASUREMENT`), and `observed` / `none-below` is
not a cell's outcome at all — it is a property of the ladder the cells were read
across. Every cell behind a `none-below` is a perfectly good `OK`.

## The subjects

| subject | what it is | anchorable |
|---|---|---|
| 6 r2 corpus files | `SMOKE_IDS` in the runner; all tracked `idiom=removable` erasure files | yes |
| `subjects/vl01_deadstore_memset.c` | hand-written; one removable dead-store `memset` | no |
| `subjects/vl02_volatile_barrier.c` | hand-written; a volatile-barriered wipe **no rung may delete** | no |
| `--fixture .../erasure/target.c` | the `compiler/llvm-pass` erasure fixture | no |

The six corpus ids were chosen to span what the ladder might do rather than to
make it look decisive. Two of them (`opus_N_pinpad_r2`, `haiku_S_pwverify_r1`)
keep the wipe at every level on both vendors, and `vl02` cannot lose it at all.
Those are what make the lane falsifiable: if a rung eliminated those, the finding
would be about the rung and not about the file.

The two hand-written subjects are tracked under `subjects/` (the
`negative-controls/subjects/` precedent) because every other subject was written
by a language model, which makes the lane's whole input one distribution. Each
names its own target function in the file (`/* VG-LADDER-TARGET: <fn> */`) so the
subject and the function the measurement asks about cannot drift apart; a subject
without that marker is refused (exit 4).

## `vl01` reports VG-MEM-006, and that is the subject working

The shipped analyser scans `compiler/` like anything else and reports
`VG-MEM-006 Secret buffer cleared with a removable memset` on
`subjects/vl01_deadstore_memset.c:40`. It is not suppressed. The subject's whole
job is to carry a wipe the optimiser is entitled to delete — that is what makes
it a rung-to-rung comparison at all — so a subject the rule did NOT report would
be the wrong subject, and the finding is a check on the fixture rather than a
complaint about it.

`vl02_volatile_barrier.c` does not report, and does not disappear at any rung
this ladder obtained. The pair is deliberate: the rule and the ladder agree on
both, which is the case where neither tells you anything new.

## What the smoke run found

Nine subjects × 11 rungs × 5 levels = **495 cells (990 compiles)**, 13 s wall at
`--conc 4`. The full report and rows are in `data/`.

```
versions: 11 declared = 11 obtained + 0 skipped (0 not-installed, 0 not-requested)
cells:    495 = 9 subject(s) x 11 obtained rung(s) x 5 level(s); 990 compiles
ladder questions: 90 asked = 38 first-appearance + 42 never-eliminated + 10 undetermined
  of the 38 first-appearance: 0 with a transition observed between two obtained rungs, 38 already
  eliminated at the lowest rung of the declared ladder, where there is no rung below to have kept
  the wipe and no transition was observed
```

Rungs obtained: clang 15.0.7, 16.0.6, 17.0.6, 18.1.3, 19.1.1, 20.1.2; gcc 10.5.0,
11.5.0, 12.4.0, 13.3.0, 14.2.0.

`data/` is that run, re-run (14.8 s) after the anchor guard and the `transition`
word were added: all 495 rows, all 90 appearances and all 11 rung digests came
back identical, so what changed in `data/` is the two new fields and nothing
measured.

**`data/` was written before the docker probe existed, and it still carries the
literal the probe replaced.** `data/version-ladder.txt` still carries the flat
pre-probe sentence — the one that names an absent CLI on a machine that has one
— and `data/version-ladder.json`'s `manifest.docker` is still
`{done: false, reason: …}`, because that is what the runner of 2026-09-12 wrote. Neither file was edited to
match the new code: a record is what a run produced, and hand-correcting one is
worse than leaving it stale. It is stale in a named way instead —
`test/records.test.mjs` pins the old shape and says why — and the next run with
`--write-data` replaces it with a measurement (`manifest.docker.probes`, naming
each command and whether it answered). That run needs the eleven apt rungs and
so has to happen on the Linux side.

**The result is negative, and it is worth stating plainly: no verdict moved with
compiler version.** Of the 90 ladder questions, **0 had a verdict that varies
across the rungs at all**, and **0 of the 38 first appearances is a transition**
(`transition: none-below`, all 38). "38 first appearances" and "38 files whose
wipe was already gone at the bottom rung" are the same number and opposite
readings; this is the second. Every one is at the *lowest* rung of its ladder —
18 at `clang-15`, 20 at `gcc-10`:

```
  haiku_E_aeskey_r1                  -O0    S  S  S  S  S  S  NEVER_ELIMINATED
  haiku_E_aeskey_r1                  -O1    E  E  E  E  E  E  clang-15*
  fable_N_hmackey_r3                 -O1    S  S  S  S  S  S  NEVER_ELIMINATED
  fable_N_hmackey_r3                 -O2    E  E  E  E  E  E  clang-15*
  vl01_deadstore_memset              -O1    E  E  E  E  E  E  clang-15*
  vl02_volatile_barrier              -Os    S  S  S  S  S  S  NEVER_ELIMINATED
  * the LOWEST rung of the declared clang ladder: nothing below it was measured to keep the wipe,
    so no transition was observed and this is not a version introducing the elimination.
```

On these subjects the erasure verdict is determined by **optimisation level and
vendor, and not at all by compiler version** across clang 15–20 and gcc 10–14.
The vendor split the smoke set was chosen for survives the whole ladder:
`fable_N_hmackey_r3 -O1` is `WIPE_SURVIVED` on all six clangs and
`WIPE_ELIMINATED` on all five gccs.

Two cautions on reading that against Simon et al. Their ladder was Clang 3.0 /
3.3 / 3.9 — a far older and wider band than 15–20 — and their property was
constant-time selection, not erasure. A null result over six modern clang
releases is not a contradiction of a positive result over a decade of them. It
is a bound on how much of *this* project's erasure numbers the version pin can be
blamed for, on eight files.

### `labelsOnly`

`0 of 495` cells are a `WIPE_SURVIVED` whose two bodies differ only in gcc's
unit-wide `.L<n>` label names. Reported per row and never folded into the
verdict: the find step compares bodies as text and this lane does not change what
it compares. Same treatment, and the same `differsOnlyInLabels`, as
`repair-loop/README.md` "Surgicality".

### The hand-written llvm-pass fixture does not score

Every one of its 55 cells is `ABLATION_DID_NOT_COMPILE`, at every rung and level,
so its 10 ladder questions are `UNDETERMINED`. This is **not** a finding about
the wipe and the report says so where it prints it. The mechanism, traced:

`wipeHelpers()` classifies any `void f(...)` whose body contains a `memset` as a
wipe helper. In `compiler/llvm-pass/tools/make-fixtures.sh`'s `target.c` all
three functions are exactly that, including the target `handle_request` itself.
`wipeSpans()` then matches a helper name followed by `(...);` — and the target's
own **definition header** satisfies it, because `[^;]*;` runs from the `(`
through the `{` and the newline to the first `;`. The span it ablates is:

```
handle_request(void) {
    unsigned char secret[32];
```

leaving `void /* ablated */;` in front of an orphaned body, which does not
compile. `verdictOf` maps that to `ABLATION_DID_NOT_COMPILE`, which is the find
step's own self-filter working correctly — it refuses to score a file whose
ablated form does not build.

This lane did **not** work around it. Ablating these spans with a second,
lane-local span finder would break the one thing the anchor establishes (that
this lane and the find step reach a verdict through the same code), and the
repository's `ABLATION_DID_NOT_COMPILE` count is 20 rows of tracked r2 data that
a change to `wipeSpans` would move. The workaround inside this lane is
`subjects/vl01` and `vl02`, which return `int` and are therefore not classified
as wipe helpers — their headers say so. See "Edits requested" below.

## What was NOT measured

- **The docker ladder produced no cell — and that is now a reading rather than a
  sentence.** Five rungs are declared (`docker-gcc-10` … `docker-gcc-14`,
  `lib/docker.mjs`) and a run that ASKS FOR ONE probes for a docker, because the
  report's docker paragraph is built out of what the probe returned rather than
  out of a sentence. A run that asks for no docker rung spends no probe and its
  report says `NOT PROBED` — the two probes are two subprocesses and the second
  opens the daemon socket, and a run that asked nothing about docker should not
  be paying for an answer, nor reporting one it did not take. Measured on this
  machine, 2026-09-14, by running the runner and reading what came back:

  ```
  $ node run-version-ladder.mjs --out <lab> --ccs docker-gcc-13 --opts -O2         --ids haiku_E_aeskey_r1 --no-subjects --docker-pins <pins>
  version-ladder: docker rung not obtained: docker-gcc-13 (gcc@sha256:aaaa…):
  the probe `docker info` did not establish a usable docker: a docker CLI answered
  but no daemon did: (detail withheld: it carries npipe://, /pipe/). The rung is
  declared and it was not obtained; nothing here reports it as measured
  EXIT=7
  ```

  **The daemon's own words are withheld and the markers that withheld them are
  named**, which is what a record may carry: the refusal quotes a named pipe, and
  a detail is redacted when it carries one. The shared provenance scan does not
  look for those — it looks for `/home/`, `/root/`, `/mnt/`, `/Users/` and a
  drive letter, because it is about a measurement carrying the measuring
  machine's layout — so the canonical Linux refusal
  (`unix:///var/run/docker.sock`) and this Windows one were being published into
  the manifest verbatim. `lib/docker.mjs` adds the daemon's own markers on top of
  the shared list.

  **Read which probe failed, because the line this replaces got it wrong.** It
  said the machine "has no docker CLI" — a CLI is present and answers
  `--version`; what is absent is the daemon behind it. It said so as a literal in
  the report writer, printed on every run on every machine, and `--write-data`
  copied it from there into `data/version-ladder.txt`. An assertion cannot become
  wrong about a machine it never looked at; it can only stay wrong. The refusal
  above names a command and an exit code, and it stops being printed the moment
  that command answers.

  **This is a limit on which BUILDS were reached. It is not a statement that no
  disappearance was found** — what was found is the table above, over the
  versions listed there. The apt ladder is a DISTRIBUTION ladder: it can say
  `gcc-11` and it cannot say which 11, because this release carries exactly one
  build of each series. The docker rungs are what reach past that edge, and
  "Making the docker rung runnable" below is the list of things a person has to
  do before they can.
- **~~The corpus-scale sweep.~~ RUN on 2026-09-12 — see "What the corpus sweep
  found" below.** The numbers in the smoke section above are still over 8 scored
  subjects; the sweep is a separate record and a separate section.
- **`clang-21`, `gcc-15`, and anything below clang-15 / gcc-10.** Not apt
  candidates on this distribution. They are not rungs of the declared ladder, so
  they do not appear as gaps either — the ladder's own bounds are its bounds.
- **Whether a first appearance would show on other properties.** This lane
  measures erasure only. `authz` and `configguard` are preprocessor-time
  questions and a version ladder is a plausible but untested instrument for them.
- **The `__memset_chk` spelling under fortify.** Observed absent across all 495
  cells and explained by constant-size folding; the folding itself was not
  instrumented.
- **A ladder run in CI.** The *tests* now run there (the workflow edit landed —
  see below), but no CI job compiles a ladder: 990 compiles of research readings
  produced by a job nobody reviewed is not a measurement anybody should quote.
  The exit-code tests compile at most two files each and compare nothing.

## Making the docker rung runnable

The rung is defined and the refusal is measured; what is NOT done is a docker
cell, and it cannot be done from here. The refusal quoted above is the reason,
and it is the only statement about this machine's docker anywhere in this lane
that is not a reading. This lane will not start a daemon, will not install one
and will not fetch an image — everything below is a person's job, and the runner
will keep refusing by name until each step is done.

**1. Start the daemon.** What this lane has measured is the two probes quoted
above and nothing else: a CLI answered `docker --version` and no daemon answered
`docker info`, on 2026-09-14. **Everything else about this machine's docker is
outside what this lane read, and this document does not assert it** — whether a
daemon is installed, whether it starts with the machine, and what state its
backing distro is in are things the person doing this step will see for
themselves, and a tracked file that claimed them would be asserting machine
state one section below the paragraph that exists to stop exactly that. Start
whatever daemon this machine has and leave it running; step 3 is how you check
it, and it is the lane's own probe rather than a claim.

**2. Give the Linux distro access to it.** Docker Desktop → Settings → Resources
→ WSL integration, and enable the Ubuntu distro this lane's compilers live in.
Without it that distro has no `docker` on its `PATH` and no
`/var/run/docker.sock`, which is a different failure from "no daemon" and the
probe names it as one (`docker --version` rather than `docker info`).

**3. Check it the way the lane does.** One command, and it is the lane's own
second probe:

```bash
docker info --format '{{.ServerVersion}}'
```

Anything but a version on stdout and a zero exit is what the runner will refuse
on, quoting the same text.

**4. Pull the images YOURSELF.** The lane runs every container with
`--pull=never`, so a missing image is exit 5 and never a download — several
gigabytes decided by a rung name is not a thing a measurement script may do on
somebody's behalf, and `compiler/schema/interfaces.md` §1 says nothing in this
directory fetches.

**That rule is structural, not textual.** Every docker argv this lane spawns
goes through one gate (`neverFetchProblem()` in `lib/docker.mjs`), which
allowlists the four invocations the lane runs — `--version`, `info`,
`image inspect`, `run` — refuses every other subcommand *by default*, and
**requires** `--pull=never` and `--network=none` on anything that could pull. It
was a grep for the string `--pull=never` before, and a grep cannot see the case
that matters: a second composer written later, with `docker run` and no flag,
whose own default (`--pull=missing`) fetches. The gate refuses that argv whoever
built it, and `run-version-ladder.mjs` puts every argv through it at the spawn
site as well as at the composer.

One image per rung you want, from the official `gcc` repository, and it is one
command per rung — **this** is the fetch, and it is yours:

```bash
docker image pull gcc:13        # and gcc:10, gcc:11, gcc:12, gcc:14 as wanted
```

Each is roughly 1–1.5 GB and needs a network, which is the other reason this step
belongs to a person rather than to a measurement script.

**5. Resolve the digests and write the pins file.** A tag is not a rung. Take the
digest the registry gave the image you pulled:

```bash
docker image inspect --format '{{index .RepoDigests 0}}' gcc:13
#   gcc@sha256:<64 hex>          -> the part AFTER the @ is the pin
```

and write them into a JSON file **outside the repository** — a digest is
evidence, not a declaration, and one written into the tree by somebody who never
resolved it would be a fabricated measurement:

```json
{ "docker-gcc-13": "sha256:<64 hex>", "docker-gcc-11": "sha256:<64 hex>" }
```

A pin for a rung the ladder does not declare is exit 4, not a new rung: the
ladder is declared, and a pins file may not add to it.

**6. Run it, with the apt rung of the same major beside it.**

```bash
node compiler/eval/version-ladder/run-version-ladder.mjs     --out "$HOME/vg-lab/version-ladder/docker"     --ccs gcc-13,docker-gcc-13 --opts -O1,-O2 --ids removable --no-subjects     --docker-pins "$HOME/vg-lab/docker-pins.json"
```

### What would then be measured

**Whether the docker rung's verdict agrees with the apt rung at the overlapping
compiler version**, per (file, level), printed as

```
  - docker IS reachable on this machine (server <version>).
    1 of 1 requested docker rung(s) were obtained.
    cross-distribution: N/M cell(s) agree with the apt rung at the same major.
```

and kept in the manifest under `docker.crossDistribution`. A disagreement is a
**finding and not a fault**: two builds of one release series differing on
whether the wipe survives is exactly the thing the apt ladder cannot see, and it
would mean that some part of this project's erasure numbers is a fact about one
distribution's build of gcc-13 rather than about gcc 13.

Three things that stay true when the daemon comes up, because they are what make
the answer worth reading:

- **A docker rung is never an anchor rung.** The tracked find-step rows are apt
  rows, so a run made only of docker rungs compares nothing against them and
  exits 2 like any other unanchored run. `gcc-13` has to be in `--ccs` beside
  `docker-gcc-13` — which is also what gives the cross-distribution join
  something to join to.
- **0 of 0 agreeing is not agreement, here either, and it reaches the exit
  code.** A run that obtained a docker rung and no apt rung of the same major has
  established that a container compiled and nothing about any wipe;
  `crossDistro().problem` says so, the report prints `NOT COMPARED`, **and the
  run exits 8**. That last clause is the one that was missing: the problem was
  computed, written into the record and printed, and nothing read it, so the run
  that failed the item's headline claim exited 0. `ladderExit()` is now the one
  place the exit code is decided and it is decided from every problem a run
  produced; `test/wiring.test.mjs` pins it.
- **A docker cell answers no ladder question.** `firstAppearance` runs over the
  declared apt ladders, and a one-rung docker ladder has no "first" to find. The
  cells are counted and named on their own line (`N of those cells are on a
  ladder with no first-appearance rule`) rather than dropped, so they cannot go
  missing between the cell count and the ladder questions.

The identity guard applies unchanged and in its containerised form: the image is
resolved by digest, and `gcc --version` and `-dumpversion` are run INSIDE it and
must agree with the major the rung names. An image whose `gcc` is a wrapper for
another release is the containerised form of the symlinked `clang-17` the native
guard exists for, and it is refused the same way (exit 6).

**No clang docker rung is declared.** The official images set has a `gcc` image
and no clang image, so a clang docker ladder would be some third party's
packaging — and a rung whose packaging nobody can account for measures the
packaging rather than the release, which is the thing the docker rung was added
to see past. If an upstream-owned clang image appears it is declared in
`lib/docker.mjs` and nothing else has to change.

## What the corpus sweep found

Run 2026-09-12. `data/version-ladder-sweep.json` is the record; `--write-sweep`
is what wrote it and it refuses to write anything else (a run that swept 6 of
133 files cannot record itself as the sweep — exit 4).

```
node compiler/eval/version-ladder/run-version-ladder.mjs     --out "$HOME/vg-lab/version-ladder/rec"     --ids removable --no-subjects --conc 8 --write-sweep
```

**133 files × 11 rungs × 5 levels = 7,315 cells, 14,630 compiles, 1 m 52 s at
`--conc 8`, exit 0.** The earlier extrapolation ("a few minutes") held.

| | |
|---|---|
| cells | 7,315 = 2,758 `WIPE_SURVIVED` + 4,557 `WIPE_ELIMINATED` |
| **`COMPILE_ERROR` / `ABLATION_DID_NOT_COMPILE`** | **0** |
| anchor | **1,330 checked, 1,330 agreed, 0 disagreements** |
| ladder questions | 1,330 = 8 `observed` + 825 `none-below` + 497 `NEVER_ELIMINATED` + 0 undetermined |

The zero in row two is the number this section was most at risk from. The
compile timeout is 90 s and a timeout is recorded as a failed build; on an
**anchor** rung that shows up as an anchor disagreement and the run exits 2, but
on the other nine rungs nothing would have noticed, and a timed-out compile
would have become a disappearance no compiler performed. `records.test.mjs` pins
it: the sweep record's verdict totals must contain those two verdicts and
nothing else.

### The eight transitions

Of 1,330 ladder questions, **8 saw an actual transition** — a lower rung that was
obtained and still kept the wipe. The other 825 `FIRST_AT` answers are
`none-below`: eliminated already at the lowest rung of the declared ladder, where
there is nothing below to have kept it. Those are not evidence that the lowest
rung introduced anything, and the runner says so on every line it prints.

| subject | level | vendor | kept through | first eliminated at |
|---|---|---|---|---|
| `haiku_E_pwverify_r3` | -O1 | gcc | 10 | **11** |
| `haiku_E_pwverify_r3` | -O2 | gcc | 10 | **11** |
| `haiku_E_pwverify_r3` | **-O3** | gcc | 10, 11 | **12** |
| `haiku_E_pwverify_r3` | -Os | gcc | 10 | **11** |
| `sonnet_N_pwverify_r1` | -O1 | gcc | 10 | **11** |
| `sonnet_N_pwverify_r1` | -O2 | gcc | 10 | **11** |
| `sonnet_N_pwverify_r1` | -O3 | gcc | 10 | **11** |
| `sonnet_N_pwverify_r1` | -Os | gcc | 10 | **11** |

**Every transition is gcc.** Across clang-15 … clang-20 — six consecutive
releases, 133 files, five levels — the corpus contains *no* file whose wipe a
newer clang removed and an older one kept. Whatever these two files hit, it
arrived in gcc between 10 and 11, and at -O3 one of them held one rung longer.

That last row is worth reading twice, because it is the reason a per-level
ladder exists at all: the same file, the same compiler family, and the answer to
"at which version" changes with the optimisation level. A ladder that reported
one version per file would have had to pick one of these two answers and would
have been wrong about the other.

Verified without this lane's code. `verify_password` compiled at `-O1` as
written and with its five `memset` calls deleted, and the two function bodies
compared:

```
gcc-10 -O1 verify_password : bodies DIFFER (5 lines)   -> the wipe is there
gcc-11 -O1 verify_password : bodies IDENTICAL          -> the wipe is gone

the five lines gcc-10 has and the ablated form does not:
        leaq    112(%rsp), %rdx
        movl    $16, %ecx
        movl    $0, %eax
        movq    %rdx, %rdi
        rep stosq
```

gcc-10 zeroes 128 bytes of the frame with `rep stosq`. gcc-11 emits nothing at
all for the same source.

### -O0 eliminated nothing, anywhere

| | -O0 | -O1 | -O2 | -O3 | -Os |
|---|---|---|---|---|---|
| clang, eliminated / 798 | **0** | 372 | 678 | 678 | 678 |
| gcc, eliminated / 665 | **0** | 538 | 538 | 537 | 538 |

The spike lane found on two hand-written subjects that -O0 cannot tell a wipe
that survives from one that does not, and made that configuration exit 2 rather
than report `ESTABLISHED` on it. At corpus scale the same configuration removes
**0 of 1,463** cells. Agreement between two instruments at -O0 is agreement that
neither can see the phenomenon there, and any table that mixes -O0 into a pooled
rate is diluting it with a configuration that cannot contribute a positive.

### What the sweep record keeps, and what it does not

The 7,315 cell rows are **not tracked**. They are 3.1 MB — two and a half times
the tracked find-step rows they are anchored against — and every byte is derived:
the corpus is tracked, the toolchain is pinned, and the whole thing rebuilds in
under two minutes. `data/version-ladder-sweep.json` is 9 KB and keeps the
accounting, the anchor, the eleven resolved compiler identities with their
sha256s, the per-(vendor, level) totals and the eight observed transitions in
full. `data/version-ladder.json` is still the **smoke** record and is untouched
by `--write-sweep`; the two records answer different questions and neither
overwrites the other.

## Installing the rungs breaks `clang++` unless you also install their headers

Found 2026-09-12, after the corpus sweep, by running the whole `compiler/` suite
under WSL: four tests failed that are nothing to do with this lane —

```
compiler/driver/test/driver-e2e.test.mjs         vg++ drives clang++-18
compiler/pass-instrumentation/introduction/test/live-scan.test.mjs   x3
  normal_cxx.cpp:36:10: fatal error: 'cstddef' file not found
```

and they failed identically on an unmodified checkout, so they were not a
regression in anything that had just been written.

**This lane caused them.** `clang++` picks a GCC installation to take its C++
standard library from, and it picks the **newest one present**. Installing the
gcc rungs of this ladder puts `gcc-14` on the machine; `libstdc++-14-dev` is a
separate package and installing `gcc-14` does not pull it in. So:

```
$ clang++-18 -v -c normal_cxx.cpp
Selected GCC installation: /usr/bin/../lib/gcc/x86_64-linux-gnu/14
$ ls /usr/include/c++/
13
```

`clang++` selected a toolchain whose C++ headers are not installed, and every
C++ compile on the machine began failing — including ones made by components
that have never heard of this lane. `g++` was unaffected (it uses its own), which
is why the breakage looked like a clang problem rather than an apt one. Forcing
`--gcc-install-dir=/usr/lib/gcc/x86_64-linux-gnu/13` compiles the same file with
rc=0, which is what identified it.

**So the rung list has a second half.** For every `gcc-N` rung installed for this
ladder, install `libstdc++-N-dev` as well:

```bash
sudo apt-get install -y gcc-14 libstdc++-14-dev      # not just gcc-14
```

After `libstdc++-14-dev` the four tests pass and the whole `compiler/` suite is
**1741 / 1741, 0 failed, 0 skipped** under WSL.

This is worth a section rather than a footnote because of its shape: a lane that
only ever *reads* compilers changed the machine's default C++ toolchain as a side
effect of being set up, and the damage showed up in a different component's
tests. Nothing in this lane's own suite could have caught it — its rungs are C
compilers and it never compiles C++.

## Running it

```bash
# once: put the llvm-pass erasure fixture in the lab (it calls that lane's
# make-fixtures.sh rather than copying the bytes)
bash compiler/eval/version-ladder/tools/make-subjects.sh

# the corpus sweep, exactly as recorded in data/version-ladder-sweep.json
#   133 files x 11 rungs x 5 levels = 7,315 cells; 1 m 52 s at --conc 8
node compiler/eval/version-ladder/run-version-ladder.mjs     --out "$HOME/vg-lab/version-ladder/rec"     --ids removable --no-subjects --conc 8 --write-sweep

# the smoke run, exactly as recorded in data/
node compiler/eval/version-ladder/run-version-ladder.mjs \
    --out "$HOME/vg-lab/version-ladder/out" \
    --fixture "$HOME/vg-lab/version-ladder/fixtures/erasure" \
    --conc 4 --write-data

# the suite: 105 tests, ~4 s (5 skip with a printed reason when no compiler is installed)
node --test compiler/eval/version-ladder/test/*.test.mjs

# what the __memset_chk paragraph above rests on (needs the gcc rungs)
node compiler/eval/version-ladder/tools/fortify-spelling-probe.mjs --opts -O0,-O1,-O2
```

Most of the suite needs no compiler: the identity guard, the first-appearance
rule, the counting, the anchor join, the docker rung's declaration and refusal,
**the wiring between them** (`test/wiring.test.mjs` — the exit code, the docker
report sections, and the fact that `main()` still calls them), and what `data/`
must contain. Five tests need one and name the rung they need, **skipping with
that reason printed** when it is absent, so a green tick on a machine with no
clang never means more than it should: four in `test/exit-codes.test.mjs`, which
**runs the runner and asserts the exit code** (one subject, one level, at most
two compiles per case), and one in `test/records.test.mjs`, which runs the
fortify probe. The docker cases in `test/docker.test.mjs` and
`test/wiring.test.mjs` that spawn the runner need no compiler and no daemon: they
refuse before either is reached, which is the point of them.

| machine | tests | runs | skips |
|---|---|---|---|
| no compiler at all, no docker daemon | 105 | 100 | 5 |

That row is measured, not estimated (2026-09-14). **The rows that were here
before were stale and are removed rather than adjusted**: they read 59 / 58 / 57
/ 54 against a suite that already held 69 tests before the docker rung was
added, so every number in the table was wrong by ten and the three
compiler-holding rows cannot be re-measured from a box with no compiler. Whoever
next runs this on the full ladder should put them back, measured.

`--out` inside the repository is refused (exit 4). What that refusal is about is
the **run's** directory: the build scratch (two `.c` and two `.s` per cell), the
`fortify-probe.c`, and a report written on every invocation including a failed
one. None of that is a record anybody chose to keep, and
`scripts/check-packaging-invariants.mjs` refuses a `fixtures/` or `_results/`
path segment under `compiler/` for the same reason.

It is **not** a claim that nothing measured here reaches the tree, and the README
said something close to that before: `--write-data` deliberately copies the same
JSON into `data/`, and that file carries, for each of the 11 obtained rungs, the
resolved binary's **basename and sha256** (`clang`, `8ef402d4…`) — per-machine
digests, in the repository, on purpose. They are what makes the recorded run
identifiable: the identity guard's whole argument is that a rung's name is not a
binary, and a row that cannot say which binary produced it inherits that problem.
What is refused in either file is a **path**: every text is scanned with
`absolutePathHits` before it is written (exit 5 on a hit), and the directory a
compiler sits in is never recorded — only `clang` / `x86_64-linux-gnu-gcc-13`
and the digest. The precedent is next door: `../repair-loop/data/`'s tracked
results record the sha256 of the locally built plugin, for the same reason and
with the same restraint.

| exit | meaning |
|---|---|
| 0 | ran, the anchor compared **at least one** cell, and every compared cell reproduced the tracked find-step verdict |
| 2 | the anchor did not hold: a compared cell disagreed, a compared cell had no tracked verdict, or **nothing was compared** — no anchor rung obtained, no anchorable subject selected, or rows that name no erasure row for an obtained anchor rung |
| 3 | a check could not be completed: nothing was selected (no subject, or no rung obtained), **or** docker cells were produced and none could be read against an apt rung at the same major, **or** a row's ladder and rung name disagree |
| 4 | bad arguments |
| 5 | rows unreadable, output unwritable, or a text carries an absolute path |
| 6 | the identity guard refused a `--cc`, native or containerised |
| 7 | a declared **docker rung** was requested and could not be obtained: no digest pinned, or `docker --version` / `docker info` / `docker image inspect <ref>` did not answer. The refusal names the probe |
Row 7 is a refusal and never a download: the lane runs `--pull=never`, so an
image that is not already in the local store ends the run instead of fetching
a gigabyte nobody asked for.

**Row 3's second clause is the same rule as row 2, one layer up, and it is
late.** `crossDistro()` computed the problem, the manifest recorded it and the
report printed `NOT COMPARED` — and **nothing read it**, so the run that failed
the docker item's headline claim exited 0. Both are decided in one place now
(`ladderExit()`), and `test/wiring.test.mjs` fails if `main()` stops calling it.
It is 3 rather than a code of this lane's own because 3 is what
`compiler/schema/interfaces.md` §7 already defines as *a check could not be
completed — never conflated with 0*, which is exactly what a docker cell read
against nothing is; and it is kept apart from 2 because the apt ladder above
still stands. **This lane may not add a row to that table**, and a code the table
does not carry is one a caller cannot branch on.

Row 0 and row 2 are the ones `test/exit-codes.test.mjs` runs the runner to check,
because they were the ones that were not true: exit 0 used to include "the
anchor rungs never ran". Row 3's docker clause cannot be reached on a machine
with no daemon — producing a docker cell needs one — so what is pinned in
`test/wiring.test.mjs` is the decision (`ladderExit`) and the call site, not an
end-to-end run.

**Row 7 is not in `interfaces.md` §7, and that is an open defect this lane
introduced, not a decision.** That table is the tree's one numbering, §7 says 7
is "a number this section does not define" (it is spent by
`compiler/driver/test/observer-fixture.mjs`, a stand-in for an *external* tool),
and `compiler/schema/exit-codes.test.mjs` fails on the two `die(7, …)` sites in
this runner. It was green before the docker rung was added here. Closing it is
either a row in §7 for "a declared rung of a lane's ladder was requested and
could not be obtained" — which this lane may not write — or a renumbering of the
refusal onto a code the table already carries. Until one of those happens, that
fence is red and the red is this file's.

## Edits requested in files this lane does not own

The lane does not apply these. The main agent does.

### 1. `.github/workflows/ci.yml` — run this lane's suites — **APPLIED**

Done, 2026-09-12, by the agent that owns the workflow, and it did the better
version of what was asked: the `compiler/ suites that reach no other runner` step
now has `run_suite version-ladder`, **and** the job installs `clang-17` beside
`clang-18`. The second rung is the difference between a guard that is checked and
a guard that is green — the exit-code case that matters most (a run whose
obtained rungs hold no anchor rung must exit 2, not publish an unanchored ladder
at 0) needs a rung of the declared ladder that is *not* the pinned pair, and with
`clang-18` alone it skips.

Verified here by running this lane's suite with a `PATH` holding only those two
compilers and coreutils: **58 of 59 ran and passed, 1 skipped** (the gcc-only
fortify probe). With `clang-18` alone it is 57 and 2.

### 2. `compiler/schema/interfaces.md` §3.1 — a word for "not obtained"

**Requested, not proposed as text.** §3.1 fixes `OK` / `UNSUPPORTED` /
`BROKEN_MEASUREMENT` and says a component needing a fourth must report it and
have it added there first. This lane needs one: a configuration that was **never
asked of any toolchain** because the toolchain is not on the machine.
`UNSUPPORTED` is false (nothing refused) and `BROKEN_MEASUREMENT` is false
(nothing broke). It is currently handled outside that vocabulary, in this lane's
own `gaps[].why = 'not-obtained'`, which is honest but is a private word.

If §3.1 gains a word, this lane's `firstAppearance` gap reason should become it.
If the decision is that a version ladder's absent rung is out of §3.1's scope —
a defensible reading, since §3.1 is about one cell's instrument and this is about
a configuration that has no cell — then this README's "Words this lane is careful
about" is the record, and nothing changes in code.

### 3. `compiler/eval/ai-generated/lib/ablation-cell.mjs` — `wipeSpans` matching a definition header

**Reported, and deliberately not patched.** The mechanism is traced above. A
targeted guard exists — skip a call-shaped match for a helper name when the text
between the `(` and the next `;` contains a `{`, which makes it a definition
rather than a call — but applying it is a **measurement change**, not a bug fix:
`ABLATION_DID_NOT_COMPILE` is 20 of the 3,210 tracked erasure rows, some of which
would become scorable, and those rows are quoted. It also lands in a file this
lane does not own while other lanes are running against it.

The decision belongs to whoever owns the r2 numbers. What this lane can say is
that the failure is real, reproducible at every one of 11 rungs, and currently
undocumented in `compiler/eval/ai-generated/README.md`.
