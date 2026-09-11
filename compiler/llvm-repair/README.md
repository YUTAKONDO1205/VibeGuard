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
- Before it changes anything, it reads every site and records whether the
  buffer is used again after it (`followedByUse`, below). A zero-fill memset is
  also what `= {0}` lowers to and what clear-before-fill code looks like, and
  pinning one of those does nothing for the wipe.
- It returns `PreservedAnalyses::none()` if it changed anything, `all()`
  otherwise.

When clang loads the plugin — before any configuration is read, before any
refusal, and whether or not the pass later runs — whatever is at `WPIN_OUT` is
removed. "No record" after a compile therefore always means "no record from
this compile".

Pipeline start is the only place this can work. It runs before SROA,
InstCombine and DSE ever see the memset; a pass placed after them would find
nothing left to pin in exactly the cases it exists for. `isRequired()` keeps it
running on `optnone` functions, which is every function at `-O0` — a pin that
silently did not happen at `-O0` would be a record saying one thing and an
object saying another.

## Configuration

| variable | |
|---|---|
| `WPIN_OUT` | record path. **Required.** Removed when the plugin loads; a directory or non-regular file there is a refusal |
| `WPIN_TARGET_FNS` | comma-separated function names |
| `WPIN_SCOPE` | `module`: every defined function in the module |
| `WPIN_DRY_RUN` | `1`: write the record exactly as if pinning, change nothing (the red control) |

One of `WPIN_TARGET_FNS` / `WPIN_SCOPE=module` is required. If both are set,
`WPIN_TARGET_FNS` wins, the record says `scope: "functions"`, and stderr says so.

## The record

One clang invocation, one source file, one record, written at the end of the
pass's single run and overwriting whatever was at `WPIN_OUT`:

```json
{ "schemaVersion": "wipe-pin-v1", "component": "WipePin", "module": "<basename>",
  "toolchain": {"clang": "18.1.3", "packages": [{"name": "llvm", "version": "18.1.3"}],
                "digest": "<sha256>"},
  "optLevel": {"speedup": 2, "size": 0}, "scope": "functions",
  "requested": ["encrypt_blob"],
  "resolution": [{"name": "encrypt_blob", "resolution": "resolved",
                  "exact": true, "linkage": "external"}],
  "dryRun": false,
  "pinned": [{"function": "encrypt_blob", "index": 0, "lengthBytes": 32,
              "destKind": "alloca", "alreadyVolatile": false,
              "followedByUse": false, "line": null}],
  "pinnedCount": 1, "wouldPinCount": 1,
  "seen": {"zeroFillMemsetInScope": 1, "zeroFillMemsetInModule": 1},
  "unhandled": {"libcallMemset": 0, "memsetChk": 0, "nonZeroFill": 0,
                "atomicMemset": 0, "inlineWrapperMemset": 0},
  "evidenceDigest": "...", "context": {"generatedAt": ..., "timeSource": ..., "sourceDateEpoch": ...} }
```

What `wipe-pin-v1` added to `v0`; apart from `schemaVersion`, nothing else
changed:

- **`pinned[].followedByUse`** — `true`, `false` or `null`. `true` when the
  memset's destination has an underlying object that is an `AllocaInst`, and
  some *other* instruction using that object is potentially reachable after the
  memset (`llvm::isPotentiallyReachable`, instruction to instruction, with a
  dominator tree and loop info built on the unmodified function). Uses are
  followed through GEP, bitcast and addrspacecast chains, through phi and
  select, and through stores of the address into a stack slot (loads from that
  slot count as the address again); `llvm.lifetime.*`, debug intrinsics and
  the memset itself are not uses. Another memset into the same buffer is.
  `false` when there is no such use: the memset is the buffer's last word, the
  shape of a wipe before the buffer dies. `null` when the underlying object is not an alloca (a parameter,
  a global, a pointer reloaded from memory) — the question has no answer inside
  this function. Computed at pipeline start for every recorded site, in a dry
  run as well, before anything is changed.
- **`resolution[].exact`** — for a resolved name, `Function::isDefinitionExact()`:
  `false` for `linkonce_odr` (C++ inline and template functions), `weak`,
  `available_externally` (a C99 inline definition, which clang emits only when
  optimising) and the other linkages whose body may be replaced by another
  unit's. `null` for a name that did not resolve.
- **`resolution[].linkage`** — for a resolved name, LLVM's textual-IR spelling of
  its linkage (`external`, `internal`, `linkonce_odr`, `available_externally`,
  `weak`, `weak_odr`, `linkonce`, `private`, `common`, `extern_weak`,
  `appending`); `null` otherwise.
- **`toolchain`** — outside `context`, as `../schema/interfaces.md` §5 requires
  of every record. Exactly the keys `clang`, `packages` and `digest`, built the
  way `IrCheckpoints::toolchainJson` in `../llvm-pass/src/IrCheckpoints.cpp`
  builds them: `clang` is `LLVM_VERSION_STRING` of the LLVM headers the plugin
  was compiled against; `packages` is `[{"name": "llvm", "version":
  LLVM_VERSION_STRING}]`; `digest` is the SHA-256 of the canonical
  serialisation of `{clang, packages}`. Nothing comes from the environment, so
  there is no unavailable case (IrCheckpoints has none either). The fixture
  loop checks that the block equals the IR observer's in the same compile and
  re-derives the digest.

- `module` is the basename only. Every number is an integer.
- `pinnedCount` counts `setVolatile` calls actually made; it is `0` in a dry
  run, where `wouldPinCount` still counts the eligible sites.
- `index` is the 0-based ordinal of the site among the zero-fill memsets of its
  function, in instruction order.
- `pinned[]` lists every zero-fill site in scope, including `alreadyVolatile`
  ones and, in a dry run, the ones that would have been pinned. The name is
  kept from `v0`.
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

- Wipes written as stores — an explicit zeroing loop, or a store through a
  volatile pointer (that one needs no pin). `= {0}` is **not** in this list:
  clang lowers it to a zero-fill `llvm.memset`, which *is* pinned, and which is
  an initialiser, not a wipe — see `followedByUse` and the partial line below.
- A memset that a later pass creates, such as loop-idiom recognition turning a
  zeroing loop into `llvm.memset` after pipeline start.
- A wipe inside a helper the target calls. Pin the helper by name instead.
  The target reads "nothing to pin" on stderr **only if it has no zero-fill
  memset of its own**. If it also has a pinnable one — typically the buffer's
  `= {0}` initialiser — that one is pinned, `pinnedCount` is positive, and the
  wipe in the helper is still removable; what says so is the site's
  `followedByUse: true` and the partial line (measured: the `inithelper` shape
  in the fixture loop).
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
| a record from an earlier compile at `WPIN_OUT` | removed when the plugin loads, before any refusal — so a refused compile and a compile whose pass never ran leave **no** record, not the old one (measured: `stale-refused`, `stale-nopasses` below). If it cannot be removed (a directory, a non-regular file, an unlink error other than "not there"): `WipePin: refusing to install: <reason>`, and the IR is not touched. |
| installed, but the pass never ran (`-Xclang -disable-llvm-passes` — measured here: rc 0, no record; a plugin on an LTO link line, where pipeline start does not fire, per `../docs/toolchain-probes.md` §2, was not re-measured) | no record → `pin.sh` exits **3** |
| a misspelt name | `resolution: not-in-module` in the record **and** `WipePin: target <name> not-in-module` on stderr; `pin.sh` exits **4** |
| the right name, nothing eligible in it | stderr `WipePin: nothing to pin in scope …` with the `unhandled` counts; `pin.sh` exits **4** |
| **something was pinned, but not the wipe** — an `= {0}` initialiser or a clear-before-fill memset pinned while the wipe is a zeroing loop or sits in a helper | the site's `followedByUse: true`, and one stderr line, `WipePin: partial: pinned <P> site(s) in <module>; <K> followed by a later use of the same buffer (initialiser-like, not a wipe); unhandled in scope: libcallMemset=.. memsetChk=.. nonZeroFill=.. atomicMemset=.. inlineWrapperMemset=..`. `pin.sh` still exits **0** (something was pinned) and writes `followedByUseCount` to its manifest. |
| something was pinned while a memset-shaped call in scope was left alone (`unhandled` > 0) | the same partial line (not exercised by the fixture loop, whose shapes all have `unhandled` 0) |
| the target is not an exact definition (C99 `inline`, C++ `inline`/template, `weak`) | `exact: false` and `linkage` in the record, and `WipePin: target <name> is not an exact definition (<linkage>); the copy that runs may come from another translation unit`. `pin.sh` writes `exactAll=false`. |
| the dry run | `dryRun: true` in the record and a stderr line; `pin.sh` exits **4**; the fixture loop's `dry-O2` cell shows the loss coming back and the object byte-identical to the no-plugin build |
| the record cannot be written | stderr `WipePin: cannot write the record …` saying whether the IR was changed; `pin.sh` exits **3** |
| two source files on one clang line | measured: rc 0, no plugin warning, one record naming the last file. `pin.sh` counts source operands, warns, and writes `sourceOperands=` to its manifest. (If one process ever hands the pass a second module, the plugin itself warns.) |
| the pin is in the IR and the wipe still is not in the object | **not detectable here, by design.** That is the confirm step's job, done by the stock observation. The record is never the verdict. |

### What `followedByUse` can and cannot say

It is a hint that points one way. `true` means "some use of this buffer is
reachable in the CFG after this site"; `false` means "none is". Neither says the
wipe survives — that is still the confirm step's question.

- **It over-approximates, and that is measured.** Reachability is asked of the
  IR as the front end wrote it, which at `-O1` and above contains clang's
  cleanup dispatch: a `return` from inside a loop body that declares a local
  goes through a shared cleanup block whose `switch` has an edge back to the
  loop. On `fable_N_token_r3.c` (`send_session_token`), the error-path wipe
  `memset(token, …); return -1;` inside the `while` loop (line 17) is
  `followedByUse: false` at `-O0` and `true` at `-O1` and `-O2`, because the CFG
  path 17 → cleanup → loop header → `write(fd, token + total, …)` exists even
  though no execution takes it. The partial line is printed for that file at
  `-O1`/`-O2`. An over-approximation of this kind can add a partial line; it can
  never remove one. `isPotentiallyReachable` also answers `true` when it gives
  up on a large CFG.
- **It follows the address through stack slots, and nowhere else in memory.**
  When the buffer's address is stored into a stack slot (`unsigned char *p =
  key;`), loads from that slot count as the address again, and so on for any
  slot those are stored into; `memset(key, …); derive(p);` reads `true`
  (measured: the `aliasinit` shape). An address stored anywhere else — a
  global, a heap object, a struct field or array element reached through a GEP
  of a slot, or inside a callee — and used from there after the memset is not
  seen, and that site reads `false`. That direction *can* hide a partial line.
- **It is about the pinned site, not about the wipe.** A `true` site says that
  site is not the wipe. It does not find the wipe, which may be a loop of
  stores, a helper call, or absent.

## Building and running

```sh
cmake -S compiler/llvm-repair -B ~/vg-build/llvm-repair -G Ninja \
      -DLLVM_DIR=$(llvm-config-18 --cmakedir)
ninja -C ~/vg-build/llvm-repair                  # -> libWipePin.so

# one cell
WPIN_TARGET_FNS=encrypt_blob \
  bash compiler/llvm-repair/scripts/pin.sh ~/vg-build/llvm-repair/libWipePin.so \
       <lab>/cell.json -O2 -c file.c -o <lab>/cell.o
```

`pin.sh` exit codes:

| exit | meaning |
|---|---|
| `0` | clang succeeded; a `wipe-pin-v1` record was written; it pinned at least one site; every requested name resolved. **Not** "the wipe survived", and not even "the wipe was pinned": a pinned initialiser counts. `followedByUseCount` and the partial line are where that shows. |
| `1` | clang failed |
| `3` | clang succeeded and there is no usable record: the plugin refused to install, its pass never ran, the record could not be written, or what was written is not a `wipe-pin-v1` record `python3` can read |
| `4` | clang succeeded and a record was written, but nothing was repaired: `pinnedCount` is 0 (a dry run, a misspelt name, nothing eligible in scope) or a requested name did not resolve |

`pin.sh` reads the record with `python3` (no `jq`), and writes
`<lab>/cell.manifest.kv` and `<lab>/cell.stderr.txt` next to it. The manifest
has plugin sha256, compiler version, clang's `rc`, `status` (the exit code),
what the plugin was asked, and what the record says: `pinnedCount`,
`wouldPinCount`, `followedByUseCount` (sites with `followedByUse: true`),
`unresolved` (comma list of names that did not resolve, empty if none),
`exactAll` (`true` when every resolved name is an exact definition; `true` when
there are none, as in module scope) and `recordError` (why a written record was
not usable, empty otherwise). Those fields are empty when there is no usable
record.

### Everything WipePin prints on stderr

| line | when |
|---|---|
| `WipePin: refusing to install: <reason>` | not installed; followed by explanatory lines for "no target" |
| `WipePin: target <name> not-in-module` / `declaration-only` | a requested name did not resolve |
| `WipePin: target <name> is not an exact definition (<linkage>); the copy that runs may come from another translation unit` | a resolved name with `exact: false` |
| `WipePin: dry run: <n> zero-fill llvm.memset site(s) would be pinned; none was changed` | dry run with eligible sites |
| `WipePin: nothing to pin in scope in <module> (zero-fill llvm.memset in scope: 0; unhandled in scope: …)` | no zero-fill memset in scope |
| `WipePin: partial: pinned <P> site(s) in <module>; <K> followed by a later use of the same buffer (initialiser-like, not a wipe); unhandled in scope: libcallMemset=.. memsetChk=.. nonZeroFill=.. atomicMemset=.. inlineWrapperMemset=..` | some site in `pinned[]` has `followedByUse: true` (K > 0), or `pinnedCount` > 0 while an in-scope `unhandled` counter is > 0. One line. In a dry run P is 0. |
| `WipePin: cannot write the record to WPIN_OUT (…); the IR was changed/not changed and nothing records it` | the record could not be opened |
| `WipePin: a second module (…) reached this pass in one process; …` | a host handed the pass two modules |
| notes about `WPIN_TARGET_FNS` / `WPIN_SCOPE` / duplicates | configuration notes, printed at load |

A compile whose record has only exact targets, a `followedByUse: false` site
for everything pinned, and no unhandled shapes prints nothing.

### The second instrument: the fixture loop

The IR observer from `../llvm-pass` watches the erasure fixture from
`../llvm-pass/tools/make-fixtures.sh` with and without WipePin, in the same
clang invocation (observer's `-fpass-plugin` first, so its pre-optimisation
checkpoint reads the IR before the pin). The effect-symbol list is the
registered `wipe-6` list, read by id from `../schema/effect-symbol-lists.json`,
which is what `run-matrix.sh` configures its erasure cells with.

Every observer+WipePin cell is also compiled through `pin.sh` with the same
`WPIN_*` settings and WipePin alone, so the exit code a `pin.sh` caller would
see is graded per cell, and the two WipePin records (with and without the
observer loaded first) must have the same `evidenceDigest`. Two more cells run
`pin.sh` alone where it must exit 3. Then two groups that do not involve the
observer, generated into the lab:

- **shapes**: small sources, each compiled `-O2 -g` through `pin.sh`, whose
  record and stderr have a known right answer — an `= {0}` initialiser followed
  by a zeroing loop (`initloop`), the same initialiser with the wipe in a
  helper (`inithelper`), a clear-before-fill memset and a trailing wipe memset
  on one buffer (`initwipe`), a clear-before-fill memset whose later uses all
  go through a copied pointer (`aliasinit`), a trailing memset only
  (`trailing`), a C99 inline target (`c99inline`) and a C++ inline target
  (`cxxinline`);
- **stale records**: clang run directly (not `pin.sh`, which deletes the path
  itself) with a file that is not this compile's record already at `WPIN_OUT`:
  a refused compile, a `-Xclang -disable-llvm-passes` compile, a normal compile,
  and a directory at `WPIN_OUT`.

```sh
cmake -S compiler/llvm-pass -B ~/vg-build/llvm-pass -G Ninja \
      -DLLVM_DIR=$(llvm-config-18 --cmakedir) && ninja -C ~/vg-build/llvm-pass
bash compiler/llvm-repair/scripts/run-fixture-loop.sh --lab <lab> \
     --observer ~/vg-build/llvm-pass/libIrCheckpoints.so \
     --wipepin  ~/vg-build/llvm-repair/libWipePin.so
python3 compiler/llvm-repair/scripts/check-fixture-loop.py --lab <lab>   # 0 / 2 / 3
```

The runner decides nothing and the checker compiles nothing. The fixtures and
the shape sources are generated into the lab on every run, never into this
tree. There are no default lab or build paths in either script.

## Measured

clang 18.1.3, Ubuntu 24.04 (WSL), plugin built with g++ 13.3.0, 2026-09-11.
Every number below was copied from a run, not from reasoning.

### `wipe-pin-v1`

**Build.** `-Wall -Wextra`: 0 warnings. `libWipePin.so` sha256
`aa7329c3d9ba002915f885624c17d6da1418aa39a2b762d1655e83786e6f0a66`, the same
bytes from two builds into separate directories.

**Same code as `v0`.** v1 adds a read-only analysis and moves the
`setVolatile` calls after it; it emits the same code. Measured against the
`v0` plugin built from the previous commit (sha256 prefix `0436d66b`, the one
the repair-loop results quote): identical `-S` output for
`sonnet_S_pinpad_r1`, `fable_N_token_r3` and `fable_N_aeskey_r3` at `-O0`,
`-O1`, `-O2`, `-O3` and `-Os` (15/15), and identical disassembly for the six
WipePin cells of the fixture loop.

**Fixture loop** (`run-fixture-loop.sh` + `check-fixture-loop.py`, exit 0,
"all 23 cells as expected"):

```
cell          opt  WipePin  verdict  effect pre->post  firstZero  ctl held  volatile@post  pinned/would/mode/res   followedByUse  obj!=base  pin.sh
base-O0       -O0  no       PRESENT  1->1              -          yes       0              -                       -              -          -       ok
base-O1       -O1  no       PRESENT  1->1              -          yes       0              -                       -              -          -       ok
base-O2       -O2  no       LOST     1->0              DSEPass    yes       0              -                       -              -          -       ok
base-O3       -O3  no       LOST     1->0              DSEPass    yes       0              -                       -              -          -       ok
pin-O0        -O0  yes      PRESENT  1->1              -          yes       1              1/1/live/resolved       false          yes        0       ok
pin-O1        -O1  yes      PRESENT  1->1              -          yes       1              1/1/live/resolved       false          yes        0       ok
pin-O2        -O2  yes      PRESENT  1->1              -          yes       1              1/1/live/resolved       false          yes        0       ok
pin-O3        -O3  yes      PRESENT  1->1              -          yes       1              1/1/live/resolved       false          yes        0       ok
dry-O2        -O2  yes      LOST     1->0              DSEPass    yes       0              0/1/dry/resolved        false          no         4       ok
wrongname-O2  -O2  yes      LOST     1->0              DSEPass    yes       0              0/0/live/not-in-module  -              no         4       ok

pin.sh alone     rc  clang rc  record
notarget-O2      3   0         -       ok
nollvmpasses-O2  3   0         -       ok

shape (-O2 -g)  pin.sh  pinned  followedByUse  exact/linkage               partial line  non-exact line
initloop        0       1       true           True/external               yes           no              ok
inithelper      0       1       true           True/external               yes           no              ok
initwipe        0       2       true,false     True/external               yes           no              ok
aliasinit       0       1       true           True/external               yes           no              ok
trailing        0       1       false          True/external               no            no              ok
c99inline       0       1       false          False/available_externally  no            yes             ok
cxxinline       0       1       false          False/linkonce_odr          no            yes             ok

stale record    before  clang rc  after   WipePin stderr
stale-refused   file    0         absent  WipePin: refusing to install: no target                ok
stale-nopasses  file    0         absent  -                                                      ok
stale-live      file    0         file    -                                                      ok
stale-dir       dir     0         dir     WipePin: refusing to install: WPIN_OUT is a directory  ok
```

What the shapes show, beyond the table:

- `initloop` is the silent case the `v0` record could not show: the pinned
  site is the `= {0}` initialiser (`line` 4, `followedByUse: true`), stderr is
  the one partial line, and in the `-O2` IR `handle` holds one volatile
  `llvm.memset` (the initialiser) and 0 `store i8 0` — the zeroing loop is gone
  with the plugin loaded. `pin.sh` exits 0, with `followedByUseCount=1`.
- `inithelper`: the `-O2` IR of `handle` holds only the volatile initialiser;
  the static helper was inlined and its memset is gone, and the helper is no
  longer defined. Stderr is the partial line, not "nothing to pin".
- `aliasinit` reads `followedByUse: true` because loads from the slot holding
  the copied pointer count as uses; a build of v1 without that one step through
  memory read `false` there and printed nothing.
- `trailing`: 0 bytes on stderr.
- The toolchain block in every WipePin record of the loop equals the IR
  observer's in the same compile, and its digest re-derives.

**The checker was shown to fail.** On a copy of the lab: the partial line
deleted from `initloop`'s stderr → exit 2; a stale file put back at
`stale-refused`'s `WPIN_OUT` → exit 2; `dry-O2`'s `pin.sh` exit code edited to
0 → exit 2; `c99inline`'s record deleted → exit 3; `initwipe`'s first site
flipped to `false` with the digest re-sealed → exit 2; `pin-O2`'s
`toolchain.digest` zeroed with the record re-sealed → exit 2 (three
disagreements, one of them the digest re-derivation). The `v0` plugin run
through the same loop → exit 2: `schemaVersion`, no `toolchain`, no
`followedByUse`/`exact`/`linkage`, `pin.sh` 3 on every record, no partial or
non-exact line on any shape; in `stale-refused` and `stale-nopasses` the old
file (`stale: not a record from this compile`) was still at `WPIN_OUT`
afterwards, where a reader would have taken it for this compile's; and in
`stale-dir` it printed `WipePin: cannot write the record to WPIN_OUT (Is a
directory); the IR was changed and nothing records it`, where v1 refuses before
touching the IR.

**Corpus files** named in the review (`-O2 -g`, the find step's `FLAGS`,
through `pin.sh`):

| file (target) | sites: line / followedByUse | stderr | `pin.sh` |
|---|---|---|---|
| `sonnet_S_pinpad_r1` (`check_pin`) | 12 / `true`, 18 / `false` | partial: pinned 2, 1 followed | 0 |
| `fable_N_token_r3` (`send_session_token`) | 17 / `true`, 23 / `false` | partial: pinned 2, 1 followed | 0 |
| `fable_N_aeskey_r3` (`encrypt_blob`) | 19 / `false` | nothing | 0 |
| `fable_N_aeskey_r3` (`encrypt_blobX`) | none | `not-in-module`, nothing to pin | 4 |
| `fable_N_aeskey_r3` (`encrypt_blob`, dry run) | 19 / `false` | dry run | 4 |

`sonnet_S_pinpad_r1` line 12 is a clear-before-fill memset: correctly `true`.
`fable_N_token_r3` line 17 is not: it is the error-path wipe inside the loop,
and reads `true` only through the cleanup-dispatch edge described in *What
`followedByUse` can and cannot say* (it is `false` at `-O0`, `true` at `-O1`
and `-O2`).

### Carried over from `wipe-pin-v0`

Measured with the `v0` plugin. The pinning itself is unchanged in v1 (see
*Same code as `v0`* above); these were not re-run with v1 except where the
v1 corpus table repeats them.

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
hand; the lane that runs the whole corpus is separate. Those verdicts are
cell-level: every wipe span of a file is deleted at once, so a file with two
spans can read `WIPE_SURVIVED` although one of its wipes is gone. That is the
find step's criterion and is not decided here.

`dry-O2` and `wrongname-O2` produce objects byte-identical to `base-O2`: loaded
and changing nothing, the plugin changes nothing (re-measured with v1: the
loop's `obj!=base` column).

**Other forms.** `-flto` and `-flto=thin` compiles: a record is written and the
bitcode carries the volatile memset (what the LTO backend then does was not
measured). `-g`: `line` 19, the memset's source line.
