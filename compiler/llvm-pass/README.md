# IrCheckpoints — the pre-optimisation and post-optimisation observers

An out-of-tree LLVM pass plugin that reads one IR unit at two checkpoints and
says which of six states a declared security property is in there. It is written
against `compiler/schema/interfaces.md`; that file is the contract and is not
edited from here.

The component exists for one distinction:

| | |
|---|---|
| `LOST` | The effect is gone and the thing it acted on is still there. |
| `NOT_APPLICABLE` | The representation changed, so the question no longer has the same referent — the buffer was promoted out of memory, or the unit was inlined away and deleted. |

Collapsing those two is how a checker of this kind becomes a false-positive
generator. At `-O2` a great many buffers stop being buffers, and reporting each
one as a removed wipe buries the one case where a wipe really was deleted.

`NOT_APPLICABLE` is also not a pass. The record carries
`verdict.completesTheCheck: false` for it, so a caller maps it to exit 3 rather
than to a clean build.

## Building

```sh
cmake -S compiler/llvm-pass -B ~/vg-build/llvm-pass -G Ninja \
      -DLLVM_DIR=$(llvm-config-18 --cmakedir)
ninja -C ~/vg-build/llvm-pass          # -> ~/vg-build/llvm-pass/libIrCheckpoints.so
```

Nothing is built or measured under `compiler/`. Measurement output goes to
`~/vg-lab/llvm-pass/`.

## Running the measurement

```sh
bash    compiler/llvm-pass/scripts/run-matrix.sh      # produces records
python3 compiler/llvm-pass/scripts/check-matrix.py    # grades them; 0 / 2 / 3
```

`run-matrix.sh` decides nothing and `check-matrix.py` compiles nothing, so the
code that produces a number is never the code that grades it. The expectations
in `check-matrix.py` were written from what each fixture is for; a cell that
disagrees is printed as a disagreement rather than edited into agreement.

## The extractors

There is no generic graph normaliser here, deliberately. A normaliser has to
decide what "the same thing" means for every property at once, and the decision
it makes for a wipe is not the one a fail-closed branch needs. Each extractor
carries its own notion of the effect and of the object the effect acts on, and
puts both in the record.

| extractor | counts | `NOT_APPLICABLE` when |
|---|---|---|
| `ir.wipe-effect` | call sites to a wipe symbol **plus** inline stores of a zero constant into a stack object or a pointer parameter | the wiped stack object was promoted out of memory, or the unit is gone |
| `ir.guarded-call` | call sites to a deny symbol, but only while some conditional branch in the unit still tests a value | the unit is gone |
| `ir.forbidden-callee` | call sites to a forbidden symbol; opposite polarity, a non-zero count is the finding | the unit is gone |

The zero-store half of `ir.wipe-effect` is not a convenience. Above `-O0` the
compiler is entitled to render a wipe either as a call or as inline zeroing, and
an extractor that knows only the call form reports the *control* as lost, which
makes the whole measurement worthless.

## The oracle rules, and how they are obeyed

`interfaces.md` §4 gives three rules. Each is obeyed structurally and then
measured, so the obedience is a number in the record rather than a claim in a
comment.

**Walk call sites, never the symbol table.** Effects are counted by walking
`CallBase` and resolving `getCalledFunction()`. The naive alternative is kept
and recorded next to it so the two can be seen disagreeing in the same run. In
the `residue` fixture at `-O2`:

```
oracleDivergence.callSiteOracle.pass                          DSEPass          (observation 68)
oracleDivergence.nameLookupOracle.sweptByPass                 GlobalOptPass    (observation 131)
oracleDivergence.observationsBetween                          63
oracleDivergence.declaredButUncalledWhenTheCallLeftTheUnit    ["llvm.memset.p0.i64"]
```

That is the failure the rule prevents, measured: the call went at `DSEPass`, the
leftover `declare` stayed for 63 more pass observations, and a name lookup would
have named the global-cleanup pass as the cause.

Note that the declaration is swept *before* the post-optimisation checkpoint, so
the residue is only visible mid-pipeline — which is why the after-pass probe
exists and why looking only at the two endpoints would have missed it.

**Count inside one IR unit.** The `inlined` fixture at `-O2`: the subject's
per-unit count is 0 while `naiveOracle.moduleWideCallSitesPostOpt` is 2. The
effect is still in the program — it moved into the caller — so the per-unit
reading has to be `NOT_APPLICABLE`, and a module-wide count would have reported
it present in a function that no longer exists.

**Carry a control that cannot be removed.** Every cell names a co-resident
control unit and every record carries `control.held` and
`control.minEffectObserved`. A run in which the control also fell to zero sets
`held: false`, emits `VG-PROP-003`, and sets `completesTheCheck: false`.

## The fixtures

| fixture | subject | shows |
|---|---|---|
| `erasure` | `handle_request` | a wipe that is a dead store; `LOST` at `-O2`/`-O3`, attributed to `DSEPass` |
| `promotion` | `use_token` | the same source compiled twice, one `-D` apart: `NOT_APPLICABLE` without the escape, `LOST` with it |
| `inlined` | `scrub_and_report` | `NOT_APPLICABLE` because the unit was inlined and deleted, while the effect is still in the module |
| `residue` | `handle_request` | the two oracles disagreeing about the same module in the same run |
| `authz` | `serve`, `serve_folded` | a guard that survives and a guard that folds |

`promotion` is the load-bearing one. Both of its cells compile the same file and
both show the effect count going `1 → 0`; a checker that decides from the count
alone must give them the same verdict. It does not, and the record says which
fact separated them:

```
                              effect 1→0   allocasEscapingToOpaqueCall   post allocaSizes   verdict
promotion-escape-off -O2      yes          0                             []                 NOT_APPLICABLE
promotion-escape-on  -O2      yes          1                             [16]               LOST
```

## Positive controls

A check that cannot fail is not checking anything. Four cells exist to fail, and
`check-matrix.py` fails the run if they stop failing.

| cell | breaks | must produce |
|---|---|---|
| `pc1-no-discriminator-O2` | `OBS_DISABLE_MEMOBJ_DISCRIMINATOR=1` — the `LOST`/`NOT_APPLICABLE` discriminator itself | `LOST` where the same cell otherwise reads `NOT_APPLICABLE` |
| `pc2-broken-control-O2` | names a control whose wipe *is* removable | `control.held: false`, `VG-PROP-003`, `completesTheCheck: false` |
| `pc3-missing-subject-O2` | names a subject that is not in the unit | `NOT_OBSERVED` — never `ABSENT`, never a pass |
| `pc4-wrong-symbol-O2` | configures the oracle against a symbol nothing calls | `ABSENT` subject **and** `control.held: false` |

`pc4` is the one that matters most in practice: an oracle pointed at the wrong
symbol reads every unit as clean, and the only thing that catches it is the
control failing at the same time.

`check-matrix.py` also re-derives every record's `evidenceDigest` from
`interfaces.md` §5 in Python, independently of the C++ that wrote it, checks
that no absolute path appears anywhere in any record, and then alters a record
to confirm the digest check can fail.

## Configuration

Six names are fixed by `interfaces.md` §0:

| | |
|---|---|
| `OBS_TARGET_FN` | subject IR unit |
| `OBS_CONTROL_FN` | control IR unit |
| `OBS_EFFECT_SYMBOLS` | comma separated |
| `OBS_OUT` | record path |
| `OBS_SNAPSHOT_DIR` | where IR is dropped at each count change |
| `OBS_REQUIRE_LIVE_BRANCH` | `1` to demand a live conditional branch |

Five more were needed and are **not** added to `interfaces.md` from here —
that file says a component needing an unlisted shape reports it instead. They
are `OBS_EXTRACTOR`, `OBS_FORBIDDEN_SYMBOLS`, `OBS_PROPERTY_ID`,
`OBS_FIXTURE_REL` and `OBS_DISABLE_MEMOBJ_DISCRIMINATOR`, and they are also
listed under `interfaceExtensionsRequested` in `compiler/schema/properties.json`.

## What this component does not do

- It stops at the end of the IR optimiser. At `-O1` this fixture's wipe survives
  every checkpoint here and is dropped later; that is a scope limit, and
  `erasure-O1` records `PRESENT` for exactly that reason.
- It reads no object file, no link, and no command line. Every `must-not-appear`
  property is therefore at most partial, and the `must-originate-from`,
  `must-be-configured` and `must-remain-unobservable` kinds have no
  implementation at all. `compiler/schema/properties.json` says so per property
  rather than leaving it to be inferred.
- It counts no indirect call. `getCalledFunction()` returns null for one, so a
  wipe or a deny path reached through a function pointer reads as absent — a
  visible false positive rather than silence, which is the direction chosen
  everywhere an unknown had to be resolved.
