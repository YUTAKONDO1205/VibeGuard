# WipePin — the deliberately invasive repair plugin

**This plugin changes the object file on purpose.** Every other plugin under
`compiler/` that loads into clang is an observer, and those observers are
claimed — and measured — to leave the object byte-identical. None of that
applies here: WipePin exists to make the object different. The
non-invasiveness claims belong to the observers and are measured **without**
this plugin loaded; a run that loads it is a repair run, not an observation.

It is the *repair* in find → repair → confirm, and never the *confirm*. The
record it writes says what it did to the IR. Whether the wipe then reaches the
assembly is decided by the same stock observation that found it missing, re-run
with this plugin loaded. A repair tool that grades its own repair has measured
its own intentions.

## What it does

One module pass, `WipePinPass`, registered on the **pipeline-start** extension
point with `isRequired() = true`:

- For every `MemSetInst` in scope whose value operand is a `ConstantInt` equal
  to zero, it sets the intrinsic's volatile operand to `true`. A volatile
  `llvm.memset` is a volatile memory operation, which the optimiser is not
  allowed to delete as a dead store. That it actually survives — to the
  post-optimisation IR and to the assembly — is measured below, not assumed.
- An `llvm.memset` that is already volatile is recorded (`alreadyVolatile:
  true`) and left alone.
- It returns `PreservedAnalyses::none()` if it changed anything, `all()`
  otherwise.

Pipeline start is the only place this can work. It runs before SROA,
InstCombine and DSE ever see the memset; a pass placed after them would find
nothing left to pin in exactly the cases it exists for. `isRequired()` keeps it
running on `optnone` functions, which is every function at `-O0` — a pin that
silently did not happen at `-O0` would be a record saying one thing and an
object saying another.

## Configuration

| variable | |
|---|---|
| `WPIN_OUT` | record path. **Required.** |
| `WPIN_TARGET_FNS` | comma-separated function names |
| `WPIN_SCOPE` | `module`: every defined function in the module |
| `WPIN_DRY_RUN` | `1`: write the record exactly as if pinning, change nothing (the red control) |

One of `WPIN_TARGET_FNS` / `WPIN_SCOPE=module` is required. If both are set,
`WPIN_TARGET_FNS` wins, the record says `scope: "functions"`, and stderr says so.

## The record

One clang invocation, one source file, one record, written at the end of the
pass's single run and overwriting whatever was at `WPIN_OUT`:

```json
{ "schemaVersion": "wipe-pin-v0", "component": "WipePin", "module": "<basename>",
  "optLevel": {"speedup": 2, "size": 0}, "scope": "functions",
  "requested": ["encrypt_blob"],
  "resolution": [{"name": "encrypt_blob", "resolution": "resolved"}],
  "dryRun": false,
  "pinned": [{"function": "encrypt_blob", "index": 0, "lengthBytes": 32,
              "destKind": "alloca", "alreadyVolatile": false, "line": null}],
  "pinnedCount": 1, "wouldPinCount": 1,
  "seen": {"zeroFillMemsetInScope": 1, "zeroFillMemsetInModule": 1},
  "unhandled": {"libcallMemset": 0, "memsetChk": 0, "nonZeroFill": 0,
                "atomicMemset": 0, "inlineWrapperMemset": 0},
  "evidenceDigest": "...", "context": {"generatedAt": ..., "timeSource": ..., "sourceDateEpoch": ...} }
```

- `module` is the basename only. Every number is an integer.
- `pinnedCount` counts `setVolatile` calls actually made; it is `0` in a dry
  run, where `wouldPinCount` still counts the eligible sites.
- `index` is the 0-based ordinal of the site among the zero-fill memsets of its
  function, in instruction order.
- `lengthBytes` is `null` when the length is not a constant; `line` is `null`
  without `-g`.
- `destKind` uses the words `classifyTarget` in `../llvm-pass/src/Extractors.cpp`
  uses. It is read from pre-SROA IR, where a pointer parameter is reloaded from
  the stack slot the front end spilled it to, so that one shape is seen through
  and reported as `argument`.
- `evidenceDigest` and `context` follow `../schema/interfaces.md` §5, written
  with the same `Record.cpp` the observer uses (compiled in, not copied).
- `resolution` uses the observer's `SUBJECTRES` words: `resolved`,
  `declaration-only`, `not-in-module`.

## What it does not handle — counted, not ignored

Everything below leaves the program exactly as it was. Where the plugin can see
the shape, it is **counted** in `unhandled` (in scope only), so "nothing was
pinned" is never confused with "there was nothing to pin".

| counter | what it is | measured example |
|---|---|---|
| `libcallMemset` | a call to a function named `memset` that is not the intrinsic | `-fno-builtin`: 1, and the call survives `-O2` on its own |
| `memsetChk` | a call to `__memset_chk` in the target function | — |
| `inlineWrapperMemset` | a call to `memset.<suffix>` that is not the intrinsic | `-D_FORTIFY_SOURCE=2`: 1 — see below |
| `nonZeroFill` | a `MemSetInst` whose fill is non-zero or not a constant | a probe with `memset(k, 0xAA, …)` and `memset(p, c, n)`: 2 |
| `atomicMemset` | `llvm.memset.element.unordered.atomic` | — |

`inlineWrapperMemset` was not in the original contract; it was added after a
measurement. Under `-D_FORTIFY_SOURCE=2` with glibc's headers, clang renames the
header's `gnu_inline` memset wrapper to `memset.inline`, and at pipeline start
the target function calls *that*. The `__memset_chk` is inside the wrapper, out
of scope. On `fable_N_aeskey_r3.c` at `-O2` the wipe is then eliminated and,
before the counter existed, the record said zero of everything.

**Not counted, because the plugin cannot see them as wipes:**

- Wipes written as stores — an explicit zeroing loop, `= {0}` initialisation,
  a store through a volatile pointer (that last one needs no pin).
- A memset that a later pass creates, such as loop-idiom recognition turning a
  zeroing loop into `llvm.memset` after pipeline start.
- A wipe inside a helper the target calls. Pin the helper by name instead;
  the target then reads "nothing to pin", which is said on stderr.
- Calls through a function pointer, including the `volatile` function-pointer
  idiom (which needs no pin either).

It also does not make anything reachable. Code the optimiser proves unreachable
is deleted along with any volatile memset in it. And a volatile memset only
guarantees the stores to that buffer; copies of the secret in registers or
spill slots are outside what this pass, or any memset, can clear.

## The silent failures, and how each is made loud

Every failure a repair plugin can have ends in the same place: a build that
succeeded and looks repaired. Each one is turned into something audible.

| failure | what makes it loud |
|---|---|
| not installed: `WPIN_OUT` unset, no target, or `WPIN_DRY_RUN` neither `0` nor `1` | stderr `WipePin: refusing to install: <reason>`; no record, so `pin.sh` exits **3**. clang's rc is unaffected. |
| installed, but the pass never ran (`-Xclang -disable-llvm-passes` — measured here: rc 0, no record; a plugin on an LTO link line, where pipeline start does not fire, per `../docs/toolchain-probes.md` §2, was not re-measured) | no record → `pin.sh` exits **3** |
| a misspelt name | `resolution: not-in-module` in the record **and** `WipePin: target <name> not-in-module` on stderr |
| the right name, nothing eligible in it | stderr `WipePin: nothing to pin in scope …` with the `unhandled` counts |
| the dry run | `dryRun: true` in the record and a stderr line; the fixture loop's `dry-O2` cell shows the loss coming back and the object byte-identical to the no-plugin build |
| the record cannot be written | stderr `WipePin: cannot write the record …` saying whether the IR was changed; `pin.sh` exits **3** |
| two source files on one clang line | measured: rc 0, no plugin warning, one record naming the last file. `pin.sh` counts source operands, warns, and writes `sourceOperands=` to its manifest. (If one process ever hands the pass a second module, the plugin itself warns.) |
| the pin is in the IR and the wipe still is not in the object | **not detectable here, by design.** That is the confirm step's job, done by the stock observation. The record is never the verdict. |

## Building and running

```sh
cmake -S compiler/llvm-repair -B ~/vg-build/llvm-repair -G Ninja \
      -DLLVM_DIR=$(llvm-config-18 --cmakedir)
ninja -C ~/vg-build/llvm-repair                  # -> libWipePin.so

# one cell: exit 0 record written / 1 clang failed / 3 no record
WPIN_TARGET_FNS=encrypt_blob \
  bash compiler/llvm-repair/scripts/pin.sh ~/vg-build/llvm-repair/libWipePin.so \
       <lab>/cell.json -O2 -c file.c -o <lab>/cell.o
```

`pin.sh` writes `<lab>/cell.manifest.kv` (plugin sha256, compiler version, rc,
what the plugin was asked) and `<lab>/cell.stderr.txt` next to the record.

### The second instrument: the fixture loop

The IR observer from `../llvm-pass` watches the erasure fixture from
`../llvm-pass/tools/make-fixtures.sh` with and without WipePin, in the same
clang invocation (observer's `-fpass-plugin` first, so its pre-optimisation
checkpoint reads the IR before the pin). The effect-symbol list is the
registered `wipe-6` list, read by id from `../schema/effect-symbol-lists.json`,
which is what `run-matrix.sh` configures its erasure cells with.

```sh
cmake -S compiler/llvm-pass -B ~/vg-build/llvm-pass -G Ninja \
      -DLLVM_DIR=$(llvm-config-18 --cmakedir) && ninja -C ~/vg-build/llvm-pass
bash compiler/llvm-repair/scripts/run-fixture-loop.sh --lab <lab> \
     --observer ~/vg-build/llvm-pass/libIrCheckpoints.so \
     --wipepin  ~/vg-build/llvm-repair/libWipePin.so
python3 compiler/llvm-repair/scripts/check-fixture-loop.py --lab <lab>   # 0 / 2 / 3
```

The runner decides nothing and the checker compiles nothing. The fixtures are
generated into the lab on every run, never into this tree. There are no default
lab or build paths in either script.

## Measured

clang 18.1.3, Ubuntu 24.04 (WSL), plugin built with g++ 13.3.0, 2026-09-11.
Every number below was copied from a run, not from reasoning.

**Build.** `-Wall -Wextra`: 0 warnings.

**Smoke, `fable_N_aeskey_r3.c` (`encrypt_blob`), from
`compiler/eval/ai-generated/generated-corpus/r2/`.**

- `-O2 -S`, `WPIN_TARGET_FNS=encrypt_blob`: `pinnedCount` 1, one site,
  `destKind` `alloca`, `lengthBytes` 32; 0 bytes on stderr.
- no `WPIN_OUT`: `WipePin: refusing to install: WPIN_OUT not set`, no record.
- `WPIN_TARGET_FNS=encrypt_blobX`: `not-in-module` in the record and on stderr,
  `pinnedCount` 0.
- `-O2 -S -emit-llvm`: with the plugin, `encrypt_blob` holds
  `call void @llvm.memset.p0.i64(ptr nonnull align 16 %4, i8 0, i64 32, i1 true)`;
  without it, 0 `llvm.memset` anywhere in the module.
- record written at `-O0`, `-O1`, `-O2`, `-O3`, `-Os`, with `optLevel`
  `{0,0} {1,0} {2,0} {3,0} {2,1}`; one volatile `llvm.memset` in `encrypt_blob`
  post-optimisation at all five. Without the plugin the memset is still there at
  `-O0`/`-O1` and gone at `-O2`/`-O3`/`-Os`.
- `-O2 -Xclang -fdebug-pass-manager`: `WipePinPass` is line 4, first `SROAPass`
  line 19, first `InstCombinePass` line 30, first `DSEPass` line 103; it runs
  once. At `-O0` it is line 1.

**Artifact level, by hand.** The first three ids, sorted, among the
clang-18 / `-O2` / `removable` / `WIPE_ELIMINATED` rows of
`compiler/eval/ai-generated/data/r2-build-rows.json`, re-run through that
lane's own ablation and `bodyOf` code with the plugin added to both compiles:

| id | stock verdict (reproduced) | with WipePin on both sides | what differs in the target body |
|---|---|---|---|
| `fable_N_aeskey_r1` | `WIPE_ELIMINATED` | `WIPE_SURVIVED` | `xorps` + 2 × `movaps` to the stack |
| `fable_N_aeskey_r3` | `WIPE_ELIMINATED` | `WIPE_SURVIVED` | `xorps` + 2 × `movaps` to the stack |
| `fable_N_dbpass_r3` | `WIPE_ELIMINATED` | `WIPE_SURVIVED` | `xorps` + 4 × `movaps` to the stack |

In all three the ablated file's target body was identical with and without the
plugin (there was nothing to pin, and the record said `wouldPinCount` 0).
`fable_N_aeskey_r3` at the other levels: `-O3`/`-Os` also go
`WIPE_ELIMINATED` → `WIPE_SURVIVED`; `-O0`/`-O1` are `WIPE_SURVIVED` either way.
At `-O0` the plugin still changes the kept body — the stock wipe is
`callq memset@PLT`, the pinned one is expanded inline (`xorps` + 2 × `movaps`) —
so the `-O0` object is not the stock one even though the wipe survived in both.
At `-O1` the kept body was unchanged by the plugin. This is three files, by
hand; the lane that runs the whole corpus is separate.

**Fixture loop** (`run-fixture-loop.sh` + `check-fixture-loop.py`, exit 0):

```
cell          opt  WipePin  verdict  effect pre->post  firstZero  ctl held  volatile@post  pinned/would/mode/res   obj!=base
base-O0       -O0  no       PRESENT  1->1              -          yes       0              -                       -          ok
base-O1       -O1  no       PRESENT  1->1              -          yes       0              -                       -          ok
base-O2       -O2  no       LOST     1->0              DSEPass    yes       0              -                       -          ok
base-O3       -O3  no       LOST     1->0              DSEPass    yes       0              -                       -          ok
pin-O0        -O0  yes      PRESENT  1->1              -          yes       1              1/1/live/resolved       yes        ok
pin-O1        -O1  yes      PRESENT  1->1              -          yes       1              1/1/live/resolved       yes        ok
pin-O2        -O2  yes      PRESENT  1->1              -          yes       1              1/1/live/resolved       yes        ok
pin-O3        -O3  yes      PRESENT  1->1              -          yes       1              1/1/live/resolved       yes        ok
dry-O2        -O2  yes      LOST     1->0              DSEPass    yes       0              0/1/dry/resolved        no         ok
wrongname-O2  -O2  yes      LOST     1->0              DSEPass    yes       0              0/0/live/not-in-module  no         ok
```

`dry-O2` and `wrongname-O2` produce objects byte-identical to `base-O2`: loaded
and changing nothing, the plugin changes nothing. The checker was shown to fail:
a deleted WipePin record exits 3; a record edited to claim two pins exits 2 and
its digest no longer re-derives; `base-O2`'s reading swapped for `pin-O2`'s
exits 2 on verdict, first-zero pass and volatile count.

**Other forms.** `-flto` and `-flto=thin` compiles: a record is written and the
bitcode carries the volatile memset (what the LTO backend then does was not
measured). `-g`: `line` 19, the memset's source line.
