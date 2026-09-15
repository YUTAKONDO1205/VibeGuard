# pass-instrumentation/observer — `PropertyObserver`

An LLVM pass-instrumentation plugin that answers *which pass, on which IR unit,
removed the effect of a declared security property*.

It registers callbacks and nothing else: no pass is added, no analysis result is
returned, and no IR is written to. That is what makes the measurement usable as
evidence about a real build rather than about a modified one, and it is checked
rather than asserted — see [Non-invasiveness](#non-invasiveness).

## Building

Out of band, never by `npm run build`. See `compiler/README.md` for why.

```sh
REPO=$(cd "$(git rev-parse --show-toplevel)" && pwd)

cmake -S "$REPO"/compiler/pass-instrumentation/observer \
      -B ~/vg-build/pass-observer -G Ninja \
      -DLLVM_DIR=$(llvm-config-18 --cmakedir)
ninja -C ~/vg-build/pass-observer
```

Produces `~/vg-build/pass-observer/libPropertyObserver.so`. Measured against
LLVM 18.1.3 with GCC 13.3.0 as the host compiler.

## Using it

```sh
OBS_TARGET_FN=handle_request \
OBS_CONTROL_FN=wipe_kept \
OBS_EFFECT_SYMBOLS=llvm.memset,memset,explicit_bzero,bzero,__memset_chk \
OBS_OUT=$HOME/vg-lab/pass-observer/out/erasure-O2.tsv \
OBS_MODE=trace \
clang-18 -O2 -c target.c -o target.o \
         -fpass-plugin=$HOME/vg-build/pass-observer/libPropertyObserver.so
```

`opt` works the same way with `-load-pass-plugin=`.

| Variable | Meaning |
|---|---|
| `OBS_TARGET_FN` | the subject function |
| `OBS_CONTROL_FN` | the control function, whose effect cannot be removed |
| `OBS_EFFECT_SYMBOLS` | comma-separated callees that count as the effect |
| `OBS_OUT` | the log **stem**, not a filename — see [What the plugin writes](#what-the-plugin-writes). **One translation unit per file** — a clang invocation with three sources runs three frontends, and the last one to open this path is the one whose log survives |
| `OBS_MODE` | `standard`, `trace` or `forensic` |
| `OBS_SNAPSHOT_DIR` | where `forensic` writes IR; required in that mode |
| `OBS_REQUIRE_LIVE_BRANCH` | `1` to count the effect only while a conditional branch still depends on a value |

Configuration is validated up front and a missing field is refused loudly, with
the field named. That matters more than it looks: the failure mode of an
observer is an empty log, and an empty log read as "nothing was lost" is worse
than no measurement at all.

That validation only asks whether the variables were *set*. Whether
`OBS_TARGET_FN` names anything is a different question, and it is answered
somewhere else — see [Did the run observe the subject at
all?](#did-the-run-observe-the-subject-at-all).

### Modes

| Mode | Records |
|---|---|
| `standard` | boundaries only: state changes, count changes, unit births and deaths, the summary |
| `trace` | every pass and every observation of a tracked unit, changed or not |
| `forensic` | trace, plus the subject's IR at every boundary where its count changed, with the control function in the same file so a driver can re-apply its own predicate to exactly the IR that was counted |

All three run the same state machine, so `standard` and `trace` give the same
attribution for the same compilation; only the volume of record differs.

## What it records, and why it is shaped that way

### Attribution is a pair, not a pass

LLVM's pipeline nests module inside call graph inside function inside loop, and
a function pass's callback fires once per function. "The seventh pass" is not a
position anyone can point at. Every record therefore names `(pass, unit)`.

The unit arrives inside `llvm::Any` as a *pointer*, and all four kinds are
decoded: `Module`, `LazyCallGraph::SCC`, `Function`, `Loop`. The probe has to be
`any_cast<const Function *>(&IR)`, which returns null on a mismatch; the value
form aborts instead, so it cannot be used to ask "is it one of these".

Nothing keeps a `Function *` between callbacks. A pass may delete the function
it was handed; the tracker stores names and looks them up again.

### The history runs to the end of the pipeline

A property can be removed in one form and rebuilt in another. A checker that
stops at the first `PRESENT → LOST` transition reports a loss that a later pass
undid — a false positive with a plausible story attached, which is the expensive
kind. So the whole state sequence is kept, and the first loss and the final
state are recorded as two separate facts.

States are the ones fixed by `compiler/schema/interfaces.md` §3.
`NOT_APPLICABLE` is deliberately never emitted: deciding that a question lost
its referent is a judgement about the property, and an observer that made it
would be deciding the answer it is supposed to be measuring. A driver that can
make that judgement makes it from the `forensic` snapshots.

### A vanished unit is not a lost property

When a function is deleted its callbacks simply stop arriving. Nothing announces
it, so an observer that only listens reports its last sighting for ever — a
false negative. This plugin keeps its own census of the tracked units: a full
walk at module boundaries, where a clone that did not exist before can be
discovered, and a symbol-table lookup per tracked unit at every other boundary.

Disappearance is recorded on its own channel (`UNIT … ERASED`, `fate` in the
summary), never as a loss of the property. Those are different claims and
merging them is how a checker starts lying.

### A name is not an identity

The inliner, function specialisation and internal-name uniquing produce clones
whose names are the original plus a suffix — `handle_request.llvm.10412843`,
`handle_request.specialized.1`, `handle_request.__uniq.99`. Keying a state
history by name splits one logical function into two histories: the original
goes `LOST` when it is deleted, the clone starts fresh at `PRESENT`, and a
reader who merges them by name sees a reintroduction that never happened.

So each concrete unit keeps its own history — which is what makes that false
positive impossible — and the units are *grouped* into a lineage by
`Oracle.cpp`'s `lineageRoot`. Births and deaths are explicit events, so the
grouping is visible without being load-bearing.

### Did the run observe the subject at all?

There is a third way for this plugin to fail silently, and it is the one the
other two fences do not touch.

`OBS_TARGET_FN=handle_requestX` is a valid configuration of a subject that does
not exist. Measured on `clang-18 -O2` against the erasure fixture: **rc 0, zero
bytes on stderr, a six-line non-empty log, `STATS` counting 650 passes, and the
control `PRESENT`.** Only the subject's rows are missing — and "no rows for the
subject" is also what a subject erased before the first boundary looks like. The
co-resident control cannot separate them, because the control is fine. Every
invariant the harness had was satisfied.

It cannot be caught at load time. `llvmGetPassPluginInfo` registers callbacks;
there is no module yet, so there is nothing for a name to resolve against. The
earliest moment the question has an answer is the first module boundary, and
that is where the plugin writes it:

```
SUBJECTRES  seq  moduleId  role  name  resolution
```

with `resolution` one of `resolved`, `declaration-only`, `not-in-module`,
`not-scanned` (the last meaning no module boundary was ever reached, so nobody
asked). Four new words on purpose: none of them is a property state or a unit
fate, because they answer a different question and a word shared between two
questions can no longer answer either. Both roles are recorded — a control that
resolves nowhere breaks the measurement exactly as completely, and "the control
held" is the invariant that cannot notice it.

Anything but `resolved` also goes to stderr, loudly, in the same family as
`refusing to install`. The build is **not** failed: rc stays 0.

**The plugin records the fact and refuses to draw the conclusion**, and that is
the load-bearing part of the design. In a whole-project build the plugin is
loaded once per translation unit, so a subject defined in one file is
legitimately `not-in-module` in every other; module-level evidence cannot tell
that apart from a typo. The question with an answer is about the *run*:

```sh
node tools/check-subject-resolution.mjs out/*.tsv
# exit 0 some module resolved the names
#      2 no module did — the run is broken
#      3 it could not be judged (no logs, no SUBJECTRES record, or not-scanned)
```

`lib/subject-resolution.mjs` is the same logic as a module. Measured on a
two-translation-unit build: the unit holding the subject records `resolved`, the
other records `not-in-module`, and the aggregate passes; misspell the name and
both record `not-in-module` and the aggregate exits 2.

### ⚠ What this calls automatically, and what it still does not

**Until 2026-09-12 no harness in this repository invoked
`check-subject-resolution.mjs`** — its only caller was
`test/subject-resolution.test.mjs`, `scripts/run-all.sh` did not run it, and it
was not wired into CI. That was still true when this section was first written
on 2026-08-17 and stayed true for most of a month; `compiler/eval/spike` was
built out of it, and 2026-09-12 is the day it stopped being true, in one narrow
place. State the change narrowly or not at all:

* **closed** — a misspelt `OBS_TARGET_FN` is *audible* (a line on stderr) and
  *recorded* (`SUBJECTRES … not-in-module`), and a whole run can be judged by a
  checker that distinguishes "wrong name" from "the plugin never saw that unit".
* **closed** — `scripts/run-all.sh` now runs the checker automatically, on **two
  translation units of its own**, immediately after it builds the plugin and
  before the first of the five harnesses. It runs `compiler/eval/spike`'s gate at
  `-O2` with `--observer` pointed at the `libPropertyObserver.so` this run just
  built: one spike whose wipe the optimiser may delete, one whose it may not, the
  checker run on each log, and then the whole thing again with the subject name
  deliberately misspelt, which the gate must refuse. A red gate stops `run-all.sh`
  before anything is measured, with `run-spike.mjs`'s own exit code
  (`interfaces.md` §7: 2 red, 3 a compiler is absent, 4 malformed expectations).
* **not closed** — that is a check on **the instrument**, not on the five
  harnesses' own logs. A `run-all.sh` run in which the plugin and the checker are
  demonstrably working can still contain a harness whose own `OBS_TARGET_FN` is
  wrong, and nothing reads those logs for it.

The reason the second bullet is not the naive wiring this paragraph used to rule
out: the checker's aggregate is per *run*, and the five harnesses write logs for
several different configurations into one tree, so a glob over `$OBS_LAB` reports
`inconsistent-name` (**correctly**) and would turn a green harness red for
something that is not a defect. The gate does not glob that tree. It compiles into
`$OBS_LAB/spike`, reads only what it wrote there, and answers a different and
prior question: *is this plugin, with this checker, able to read a known
elimination, a known survival, and to go red at all, in this build.*

**Do not write "the third silent-failure mode is closed" without the third bullet
above.** What is automatic is the check on the instrument. The per-run call on a
harness's own logs still belongs with whoever drives that observation; the corpus
lane does it that way.

The record is written to the main `OBS_OUT` log only, not to
`<OBS_OUT>.summary.tsv` — it is written at the first module boundary, long
before anything could truncate a run, and keeping the side file unchanged means
every existing reader of it is untouched.

```sh
node --test compiler/pass-instrumentation/observer/test/*.test.mjs   # 22 cases
```

### Counting

`compiler/schema/interfaces.md` §4, unchanged: walk `CallBase` instructions and
compare the resolved callee, inside one IR unit, never a symbol-name search. A
deleted call leaves its `declare` behind, and a name search then blames whichever
pass eventually sweeps the declaration away instead of the pass that removed the
call.

## What the plugin writes

`OBS_OUT` is a stem. One process can hold more than one tracker — the
registration callback runs once per `PassBuilder`, and under `-flto=thin` lld
builds one per backend module, on its own thread — so a single filename cannot
be right. What lands on disk:

| File | Written by |
|---|---|
| `<OBS_OUT>` | the first tracker in the process to reach a module boundary |
| `<OBS_OUT>.summary.tsv` | that same tracker's side file |
| `<OBS_OUT>.<sanitised module id>.tsv` | every later tracker |
| `<OBS_OUT>.<sanitised module id>.tsv.summary.tsv` | each of those trackers' side files |
| `<OBS_OUT>.modules` | all of them: one line each, `<raw module id>\t<the log path that tracker opened>` |

A plain compile and a full-LTO link create exactly one tracker, so both write
`<OBS_OUT>` and `<OBS_OUT>.summary.tsv` under the names they always used, and
the only new file on those paths is `<OBS_OUT>.modules`, one line long.

**Byte-for-byte sameness holds for the compile path only**, and this paragraph
claimed it for both until 2026-09-15. On a compile, the object, the main log,
the side file and stderr are identical to the previous plugin's — measured. On
a full-LTO link the names are the same and the main log is not: see the two
consequences below, the first of which is that `finish()` now runs there.

The manifest is the part worth explaining. **Read it, do not re-derive the
names.** Which backend ends up with the unsuffixed file is a race and is not
worth resolving; the manifest records the path each tracker actually opened, so
a reader never has to know the naming convention and never has to guess. It also
covers the case the convention cannot express: a module id too long for a
filename falls back to `module-<index>`. A tracker writes its line *before* it
opens its log, so **N lines and fewer than N logs means a backend's history was
lost** — which is exactly the fact that used to be silent. The file is truncated
by the tracker that takes the unsuffixed name, so it describes one run and not
every run that reused the stem.

The log is opened at the first module boundary rather than in the tracker's
constructor, because that is the first moment the module id — and therefore the
name — exists. Records produced before that boundary are buffered and written
ahead of the `HANDSHAKE`, so nothing is dropped by the delay. A tracker that
never reaches a boundary still opens its log from `finish()`: an empty log says
"this process ran the plugin and observed nothing", and a missing one says
nothing at all.

Two consequences of the tracker no longer being a process-global, both measured:

- **Under full LTO the main log now carries `SUMMARY`, `HIST` and `STATS`.** The
  tracker belongs to the `PassInstrumentationCallbacks`, which lld destroys when
  the backend finishes, so `Tracker::finish()` runs where it previously never
  did. The attribution rows are identical to the ones the side file already
  carried; the `STATS` counters differ, because the side file's were written at
  the last state change and the main log's are written at the end. A reader that
  prefers the main log's summary when there is one will now take it from there.
- **Under ThinLTO the attribution exists at all.** Each backend gets its own
  intact log, so `DSEPass on handle` can be read from the link rather than from a
  file three backends were overwriting.

## Log format

Line-oriented TSV; field one is the record type. `History.h` carries the full
field lists. `SUMMARY`, `HIST` and `STATS` are also written on their own to
`<OBS_OUT>.summary.tsv` after every change, so a run whose process does not
unwind still leaves a current attribution behind. `SUBJECTRES` is the one record
that stays out of the side file; the reason is in the section above.

A reader of this log should ignore record types it does not know rather than
reject them. The types here have been added to before and will be again, and a
reader that fails on an unfamiliar one turns every addition into a broken tool.

The log is raw observation output, not an evidence record: it carries the module
identifier as the compiler saw it. A component that turns it into a record under
`interfaces.md` §5 is responsible for making the paths relative.

## Non-invasiveness

Two halves, both recorded on every measurement run:

1. the compiler is not modified — the toolchain binaries are digested before and
   after, and the plugin links no LLVM library of its own (it resolves against
   the process that loads it);
2. with the plugin and without it, the object file and the linked executable are
   byte-identical.

Byte-identity is only ever reported **together with** evidence that the observer
actually observed. A plugin that silently declined to install produces identical
bytes trivially, so a run whose log has no `EV` records fails rather than passing
quietly. And there is a negative control: `-opt-bisect-limit` is applied to the
same compilation and the object file is *required* to differ, because if nothing
in the harness can change those bytes then "they did not change" is not
information.

★ 2026-09-15: both halves now cover **ThinLTO** as well as the compile-time
path. Until that date `scripts/noninvasive.mjs` linked no LTO of any form, and
the byte-identity claim was a claim about one process holding one tracker — the
shape the plugin stopped having on 2026-09-14. Under `-flto=thin` lld builds one
`PassBuilder` per backend module on its own thread, and the plugin's allocation
and I/O follow. NI-09..NI-11 in the table below are that coverage, and NI-11 is
its own negative control: NI-04 perturbs a `cc1` process and says nothing about
whether anything in this harness can move the bytes lld emits.

### In CI

`scripts/noninvasive.mjs` runs in the `native-plugins` job of
`.github/workflows/ci.yml` (ubuntu-24.04, `clang-18` from the 24.04 archive).
Before that job it had only been run by hand. The job builds this directory
with the cmake line under [Building](#building), into `$RUNNER_TEMP` rather
than `~/vg-build`, and then runs, from the repository root:

```sh
OBS_LAB="$RUNNER_TEMP/lab/pass-observer" \
  bash compiler/pass-instrumentation/observer/tools/make-fixtures.sh
OBS_LAB="$RUNNER_TEMP/lab/pass-observer" \
OBS_PLUGIN="$RUNNER_TEMP/build/pass-observer/libPropertyObserver.so" \
  node compiler/pass-instrumentation/observer/scripts/noninvasive.mjs
```

`OBS_LAB` defaults to `~/vg-lab/pass-observer` and `OBS_PLUGIN` to
`~/vg-build/pass-observer/libPropertyObserver.so`, so a run by hand with
neither set measures what it measured before `OBS_PLUGIN` existed.

The step fails unless the harness exits 0 **and** its report,
`<lab>/rq2/results/noninvasive.json`, holds exactly these 24 checks, every one
passing, with a `pluginSha256` equal to the sha256 of the `.so` the job built:

| Check | At | Passes when |
|---|---|---|
| NI-01 | each of -O0..-O3 | two plugin-free compiles of every unit give the same object |
| NI-02 | each of -O0..-O3 | every object is byte-identical with and without the plugin, and `target.c` has `EV` records |
| NI-03 | each of -O0..-O3 | the linked executable is byte-identical, and `target.c` has `EV` records |
| NI-03b | each of -O0..-O3 | at least one unit's identity is backed by `EV` records |
| NI-04 | -O2 | `-opt-bisect-limit=40` changes the `target.c` object (the negative control) |
| NI-05 | -O2 | under that limit the object is still byte-identical, and still observed |
| NI-06 | -O2 | the skipped-pass callback fired under that limit: at least one skipped-pass record |
| NI-07 | — | `clang-18`, `opt` and `libLLVM.so.1` under `/usr/lib/llvm-18` have the same sha256 after the run as before it |
| NI-08 | — | `ldd` exits 0 and lists the plugin's libraries, and none is libLLVM or libclang (an empty listing fails) |
| NI-09 | -O2 `-flto=thin` | two plugin-free ThinLTO links of the same bitcode objects give the same executable |
| NI-10 | -O2 `-flto=thin` | the executable is byte-identical with and without `-Wl,--load-pass-plugin`, and the observer left `EV` records in a `.modules` manifest naming at least two backends |
| NI-11 | -O2 `-flto=thin` | `-Wl,-mllvm,-opt-bisect-limit=40` changes the linked executable (the ThinLTO negative control) |

The count, the ids and the digest are read from the report and not only from
the exit code, so a harness that exits 0 and writes no report, a report
measured on another plugin, and a check that stopped running each fail the
step. So does the harness pointed at a plugin that does change the object:
with `OBS_PLUGIN` set to `libWipePin.so`, `WPIN_SCOPE=module` and `WPIN_OUT`
set, the `target.c` object differed at all four levels and the run ended
9/24 on 2026-09-15 (measured locally, not in CI; it was 7/21 before NI-09..NI-11
existed).

**That run does not exercise NI-10's byte comparison, and saying so is the
point of recording it.** WipePin registers on the pipeline-start extension
point, and an LTO link builds a pipeline without one — it prints exactly that
and pins nothing — so the ThinLTO executable came back byte-identical and NI-10
failed on its *observation* half (`ev=0`, an empty manifest) rather than on its
bytes. What shows the byte half is live is NI-11, which moves those same bytes
in the same run (`5d34e026ceaae346` stock, `cd753dcbbc3201e1` under the bisect
limit), and a deliberate one-line mutation of the harness on 2026-09-15 that
gave the observed link the bisect limit too: NI-10 then failed with `ev=4` and
three backends and two different digests, 23/24. If a plugin that mutates
inside an LTO backend ever exists here, that is the better demonstration and
this paragraph should be replaced by it.

What the CI run does **not** cover:

* one toolchain: `clang-18` as the Ubuntu 24.04 archive ships it (the job
  prints the version it got) on an x86-64 runner;
* one fixture: the erasure fixture's three translation units at `-O0`..`-O3`,
  plus `target.c` at `-O2` under `-opt-bisect-limit=40`, plus the same three
  units linked with `-flto=thin` at `-O2` (NI-09..NI-11); no `-Os` or `-Oz`,
  and **no full LTO** — a full-LTO link creates one tracker, so it is the
  compile-time shape under another name, and it is the ThinLTO shape that is
  not covered anywhere else;
* NI-07 digests three files, in the same job, before and after the run. On a
  runner that exists for one job, that says this run did not change them, and
  nothing about any other file of the toolchain;
* the job builds with no `CMAKE_BUILD_TYPE`, as the cmake line under
  [Building](#building) does; `scripts/run-all.sh` builds `Release`. Those are
  two different `.so` files with two different sha256s. Built from the same
  sources against LLVM 18.1.3 with g++ 13.3.0, both ran 24/24 locally on
  2026-09-15, and they really are two different files: `d644978e2b80cf57…`
  for the default build, `3449b8e1deceb3a4…` for `Release`. A CI report and a
  `run-all.sh` report of the same sources therefore carry different
  `pluginSha256` values;
* the other four harnesses `scripts/run-all.sh` runs (`rq2/rq2.mjs`,
  `rq2/modes.mjs`, `rq2/broken-controls.mjs`, `scripts/crosscheck.mjs`) are not
  in CI. `tools/check-subject-resolution.mjs` **is** called automatically since
  2026-09-12 — by `scripts/run-all.sh:83`, through `compiler/eval/spike`'s
  observer channel, on two translation units of its own (see the section above)
  — and **not** on those four harnesses' logs, which is the distinction that
  section draws and this bullet used to blur by saying "nothing automatic".

## Measurement harness

Sources here are tracked; builds and measurements are not, and live on the Linux
filesystem (`interfaces.md` §1):

```
~/vg-build/pass-observer/          the plugin
~/vg-lab/pass-observer/            logs, fixtures, run-log.txt
~/vg-lab/pass-observer/rq2/results/ the reports; scripts/noninvasive.mjs writes noninvasive.json
~/vg-lab/pass-observer/rq2/        the ground-truth harness
```

`lib/` and `test/` are the exception: they read a recorded log and need no
compiler, so they run anywhere and are tested with `node --test` like the rest
of the repository. `test-link/` is the exception to the exception — it links,
with `clang-18` and an `ld.lld`, and it is the only suite here that loads the
`.so` at all. It takes the plugin from `OBS_PLUGIN` (same default as
`scripts/noninvasive.mjs`) rather than building one, and without the toolchain
it FAILS; `VG_OBS_LINK_ALLOW_SKIP=1` authorises the skip and names each case.
Its subject is the per-module change of 2026-09-14: one log per backend module,
one `HANDSHAKE` per log, a manifest whose column 2 is the path that was
actually opened, and no NUL byte or torn line in any of them. ci.yml runs it in
`native-plugins`, beside `compiler/fingerprint`, because `native-toolchain`
installs no linker.

The ground-truth harness exists because "how often is the first-loss pass right"
has no answer until *right* is defined, and no real `-O2` compilation supplies
one — which pass removed the effect is exactly what is in dispute, so agreement
between tools is agreement, not truth. It manufactures the answer instead:

1. take the pre-optimisation IR from `clang -Xclang -disable-llvm-passes`;
2. take the pipeline string from the **same** clang invocation
   (`-mllvm -print-pipeline-passes`) — `opt -passes='default<O2>'` is a
   different string, so a harness that assumes they are the same injects at a
   position that does not exist in the compilation it claims to describe;
3. replay that string under `opt` with a synthetic pass that removes the effect,
   placed at an index the harness chose.

The correct attribution is then known because the harness wrote it down before
the observer ran. The synthetic passes mutate IR on purpose and are the exact
opposite of this plugin, so they live with the harness, in a CMake project of
their own (`rq2/`, `libSyntheticGroundTruth.so`), and are never loaded by a
real build. CI's native-plugins job builds that project to show it still
compiles against LLVM 18, and loads it nowhere.
