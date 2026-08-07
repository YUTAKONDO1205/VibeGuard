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
cmake -S /mnt/c/Users/PC_User/VibeGuard/compiler/pass-instrumentation/observer \
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
| `OBS_OUT` | the log. **One translation unit per file** — a clang invocation with three sources runs three frontends, and the last one to open this path is the one whose log survives |
| `OBS_MODE` | `standard`, `trace` or `forensic` |
| `OBS_SNAPSHOT_DIR` | where `forensic` writes IR; required in that mode |
| `OBS_REQUIRE_LIVE_BRANCH` | `1` to count the effect only while a conditional branch still depends on a value |

Configuration is validated up front and a missing field is refused loudly, with
the field named. That matters more than it looks: the failure mode of an
observer is an empty log, and an empty log read as "nothing was lost" is worse
than no measurement at all.

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

### Counting

`compiler/schema/interfaces.md` §4, unchanged: walk `CallBase` instructions and
compare the resolved callee, inside one IR unit, never a symbol-name search. A
deleted call leaves its `declare` behind, and a name search then blames whichever
pass eventually sweeps the declaration away instead of the pass that removed the
call.

## Log format

Line-oriented TSV; field one is the record type. `History.h` carries the full
field lists. `SUMMARY`, `HIST` and `STATS` are also written on their own to
`<OBS_OUT>.summary.tsv` after every change, so a run whose process does not
unwind still leaves a current attribution behind.

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

## Measurement harness

Sources here are tracked; builds and measurements are not, and live on the Linux
filesystem (`interfaces.md` §1):

```
~/vg-build/pass-observer/          the plugin
~/vg-lab/pass-observer/            logs, fixtures, run-log.txt
~/vg-lab/pass-observer/noninvasive.mjs   the byte-identity measurement
~/vg-lab/pass-observer/rq2/        the ground-truth harness
```

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
opposite of this plugin, so they live with the harness and outside this
repository; they are never loaded by a real build.
