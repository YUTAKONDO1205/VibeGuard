# WipePinGcc — the GCC twin of WipePin, deliberately invasive in the same way

**This plugin changes the object file on purpose.** Every plugin under
`compiler/` that loads into a compiler as an observer is claimed — and measured
— to leave the object byte-identical. None of that applies here: WipePinGcc
exists to make the object different. The non-invasiveness claims belong to the
observers and are measured **without** this plugin loaded; a compile that loads
it is a repair, not an observation.

It is the GCC half of the *repair* in find → repair → confirm, beside
`../llvm-repair/` (WipePin, for clang), and never the *confirm*. The record it
writes says what it did to GIMPLE. Whether the wipe then reaches the assembly is
decided by the same stock observation that found it missing, re-run with this
plugin loaded. A repair tool that grades its own repair has measured its own
intentions.

Both plugins write the same record, `wipe-pin-v2`; this one with `component:
"WipePinGcc"`. What the record means, field by field, is WipePin's README plus
the GCC readings under *What is different on GCC* below.

## What it does

One GIMPLE pass, `wipe_pin`, registered with `PLUGIN_PASS_MANAGER_SETUP`
directly after `cfg`:

- Directly after every `__builtin_memset` call in scope whose value argument is
  the constant zero (`gimple_call_builtin_p(call, BUILT_IN_MEMSET)` and
  `integer_zerop`), it inserts

  ```c
  __asm__ __volatile__("" : : "g"(dest) : "memory");
  ```

  built with `gimple_build_asm_vec` and `gimple_asm_set_volatile`, where `dest`
  is the memset's own first argument. A volatile asm is never deleted; it takes
  the buffer's address as an input and may read any memory, so the bytes the
  memset wrote are not dead and no later pass may delete the memset. GIMPLE has
  no volatile memset to mark, which is what WipePin does on LLVM IR; the barrier
  is the pin here. That the wipe actually survives to the assembly is measured
  below, not assumed.
- A memset that is already directly followed by a volatile asm with a `memory`
  clobber (a previous pin, or a barrier the source wrote) is recorded
  (`alreadyVolatile: true`) and left alone.
- Before it changes a function it reads every site in it and records whether
  the buffer is used again afterwards (`followedByUse`), for the reason WipePin
  does: a zero-fill memset is also what clear-before-fill code looks like, and
  pinning one of those does nothing for the wipe.
- The record is written once, at `PLUGIN_FINISH_UNIT`, after every function of
  the unit has been through the pass.

When cc1 loads the plugin — first thing in `plugin_init`, before the version
check, before any configuration is read, before any refusal — whatever is at
`WPIN_OUT` is removed. "No record" after a compile therefore always means "no
record from this compile".

### Where the pass runs

Right after `cfg` is the only kind of place this can work: it is inside the
lowering passes, which run for every function at every level, and it is before
`ssa`, before `einline` and before `dse1`. A pass placed after the early
optimisations would find nothing left to pin in exactly the cases it exists
for. Being before `ssa` also means the barrier needs no SSA update: the into-SSA
pass that follows gives it virtual operands like any other statement.

Measured with `-fdump-passes` on the erasure fixture with the plugin loaded
(line numbers in that listing; `gcc-13` 13.3.0):

| level | `tree-cfg` | `tree-wipe_pin` | `tree-ssa` | `tree-einline` | `tree-dse1` |
|---|---|---|---|---|---|
| `-O0` | 11 ON | **12 ON** | 21 ON | 34 ON | 47 OFF |
| `-O1` | 11 ON | **12 ON** | 21 ON | 34 ON | 47 ON |
| `-O2` | 11 ON | **12 ON** | 21 ON | 34 ON | 47 ON |
| `-O3` | 11 ON | **12 ON** | 21 ON | 34 ON | 47 ON |
| `-Os` | 11 ON | **12 ON** | 21 ON | 34 ON | 47 ON |

`-fdump-tree-all` writes the pass's dump as `*.wipe_pin` (numbered after GCC's
own passes, as plugin dumps are). On the fixture at `-O2` it shows
`memset (&secret, 0, 32);` followed by `__asm__ __volatile__("" :  : "g"
&secret : "memory");` and then the scope's clobber, and the `optimized` dump
still holds both. The empty template emits no instruction; it is the operand
and the clobber that keep the memset.

## Configuration

The same four variables as WipePin, with the same meanings and refusals
(`src/Config.cpp` is `../llvm-repair/src/PinSelector.cpp`'s logic and wording,
with POSIX calls where that one uses LLVM's support library):

| variable | |
|---|---|
| `WPIN_OUT` | record path. **Required.** Removed when the plugin loads; a directory or non-regular file there is a refusal |
| `WPIN_TARGET_FNS` | comma-separated function names (assembler names: for C the declared name, for C++ the mangled one) |
| `WPIN_SCOPE` | `module`: every function body in the unit |
| `WPIN_DRY_RUN` | `1`: write the record exactly as if pinning, change nothing (the red control) |

`-fplugin-arg-<plugin>-...` arguments are not read; if any are given, stderr
says so.

## The record

A measured record (`-O2`, the erasure fixture, `WPIN_TARGET_FNS=handle_request`),
re-keyed for reading; on disk it is one line in canonical key order:

```json
{ "schemaVersion": "wipe-pin-v2", "component": "WipePinGcc", "module": "target.c",
  "toolchain": {"gcc": "13.3.0", "packages": [{"name": "gcc", "version": "13.3.0"}],
                "digest": "59918b2e94592419773ed8982734ac2d9ed571a328feec4d8430d158995291e0"},
  "optLevel": {"speedup": 2, "size": 0}, "scope": "functions",
  "requested": ["handle_request"],
  "resolution": [{"name": "handle_request", "resolution": "resolved",
                  "exact": true, "linkage": "external"}],
  "dryRun": false,
  "pinned": [{"function": "handle_request", "index": 0, "lengthBytes": 32,
              "destKind": "alloca", "alreadyVolatile": false,
              "followedByUse": false, "line": 22}],
  "pinnedCount": 1, "wouldPinCount": 1,
  "seen": {"zeroFillMemsetInScope": 1, "zeroFillMemsetInModule": 3},
  "unhandled": {"libcallMemset": 0, "memsetChk": 0, "nonZeroFill": 0,
                "atomicMemset": 0, "inlineWrapperMemset": 0},
  "evidenceDigest": "...", "context": {"generatedAt": ..., "timeSource": ..., "sourceDateEpoch": ...} }
```

The counting rules are WipePin's: `pinnedCount` counts barriers actually
inserted (0 in a dry run, where `wouldPinCount` still counts the eligible
sites); `pinned[]` lists every zero-fill site in scope, `alreadyVolatile` ones
included; `index` is the site's ordinal among the zero-fill memsets of its
function; `lengthBytes` is `null` for a length that is not a constant; every
number is an integer; `module` is the basename only.

`evidenceDigest` and `context` follow `../schema/interfaces.md` §5. WipePin
writes them with `../llvm-pass/src/Record.cpp`, whose SHA-256 is
`llvm::SHA256`; a GCC plugin cannot link libLLVM, so `src/Canon.cpp` is a
second writer of the same canonical text with its own SHA-256. Two writers of
one canonical form agree only if something checks that they do: `canon-vectors`
runs every vector of `../evidence/testdata/digest-vectors.json` through it, and
the Python reader that `pin-gcc.sh` uses (`scripts/wpin_gcc_record.py`, which
shares no code with either) is calibrated against the same vectors by its
tests.

### What is different on GCC

- **`toolchain`** has exactly `gcc`, `packages` and `digest` (the contract's
  §3). `gcc` is `basever` from the `plugin-version.h` the plugin was compiled
  against; `packages` is `[{"name": "gcc", "version": <same>}]`; `digest` is
  the SHA-256 of the canonical serialisation of `{gcc, packages}`. For 13.3.0
  that is `59918b2e…`, the value `../evidence/canon.mjs` derives for the same
  object. Nothing comes from the environment.
- **`optLevel`** is `{speedup: optimize, size: optimize_size}` from the global
  options when the plugin loads (the driver's `-O` flags are decoded by then).
  Measured, from the plugin's own record:

  | flag | `-O0` | `-O1` | `-O2` | `-O3` | `-Os` | `-Oz` | `-Ofast` | `-Og` |
  |---|---|---|---|---|---|---|---|---|
  | `{speedup, size}` | `{0,0}` | `{1,0}` | `{2,0}` | `{3,0}` | `{2,1}` | `{2,2}` | `{3,0}` | `{1,0}` |

  For `-O0` … `-Oz` these are the pairs the repair loop's reader already
  expects of clang (`OPT_LEVELS` in `../eval/repair-loop/lib/pin-record.mjs`),
  so no per-component table is needed for those six; `-Ofast` and `-Og` are not
  in that table at all. That reader belongs to the repair-loop lane; this
  component only reports what gcc-13 says.
- **`destKind`** uses the observer's words (the contract's §5): a local
  automatic `VAR_DECL` is `alloca`; a `PARM_DECL`, or a pointer that is one, is
  `argument`; a static or global `VAR_DECL` is `global`; anything else is
  `other`. The destination is followed back through `&obj`, `&MEM[p + off]` (to
  `p`) and SSA temporaries that copy, convert or offset a pointer. A local
  pointer *variable* holding an address (`unsigned char *p = key;
  memset(p, …)`) is not followed — before `ssa` it is a variable, not a value —
  and reads `other`, as the same shape reads on the LLVM side (a pointer
  reloaded from a stack slot). A VLA or `__builtin_alloca` buffer is reached
  through such a pointer and reads `other` too (LLVM would say `alloca`).
- **`resolution[].linkage`** uses LLVM's spelling (the contract's §6): not
  `TREE_PUBLIC` → `internal`; `DECL_COMDAT` → `linkonce_odr`; `DECL_WEAK` →
  `weak`; `DECL_EXTERNAL` with a body (gnu_inline / C99 `inline`) →
  `available_externally`; otherwise `external`. `exact` is `true` exactly for
  `external` and `internal`. **`DECL_COMDAT` is tested before `DECL_WEAK`**,
  where the contract lists weak first: measured with a probe plugin at the same
  position, a C++ `inline` function has `TREE_PUBLIC=1 DECL_WEAK=1
  DECL_COMDAT=1` (ELF's `MAKE_DECL_ONE_ONLY` marks every one-only decl weak), so
  weak-first would call every C++ inline function `weak` where clang says
  `linkonce_odr`. A plain `__attribute__((weak))` function has `DECL_WEAK=1
  DECL_COMDAT=0` and reads `weak` in the record (measured, with a `static`
  function beside it reading `internal` and a plain one `external`). Both
  words have `exact: false`.
- **`resolution[].resolution`**: `resolved` when a body of that name reached
  the pass; `declaration-only` when no body did but some body in the unit
  references the function (calls it or takes its address) — clang's module
  holds a declaration for exactly the functions a unit references; otherwise
  `not-in-module`. A function referenced only from a static initialiser reads
  `not-in-module` here (not measured on the LLVM side). A C99 `inline`
  definition is lowered only when it may be inlined: at `-O2` it resolves
  (`available_externally`), at `-O0` it reads `declaration-only` and
  `pin-gcc.sh` exits 4 (measured; clang does not emit it at `-O0` either).
- **`line`** is read from the statement's location, which GCC keeps with or
  without `-g`. WipePin reads it from debug info and writes `null` without
  `-g`.
- **`followedByUse`** is computed on GIMPLE, as the contract's §4 says: for an
  `alloca` site, breadth-first over basic blocks from the memset — the rest of
  its block, then every block reachable along any successor edge — any
  statement that mentions the buffer's `VAR_DECL` (taking its address included)
  is a use; the memset itself, clobbers (`key ={v} {CLOBBER}`) and debug
  statements are not. Beyond the decl itself it follows, to a fixed point,
  every SSA name or local pointer variable assigned from something that
  mentions the buffer or such a carrier, which is the GCC reading of WipePin's
  step through stack slots (the `aliasinit` shape needs it). `null` when the
  destination is not a local. There is no path feasibility at all: that can add
  a partial line, never remove one.
- **`seen` / `unhandled`** keep their keys (the contract's §8).
  `atomicMemset` and `inlineWrapperMemset` name LLVM shapes GCC does not have
  and are always 0. Under glibc's fortifying headers — which Ubuntu's gcc-13
  turns on by default whenever it optimises (`_FORTIFY_SOURCE` is `3` at `-O2`,
  undefined at `-O0`, measured with `-dM -E`) — the target calls the header's
  `gnu_inline` `memset` wrapper, and GCC keeps that call a `BUILT_IN_MEMSET`:
  it is pinned like any other (every fixture cell at `-O1` and above is that
  case). clang renames the same wrapper `memset.inline`, which is why WipePin
  needed `inlineWrapperMemset`.
- **`alreadyVolatile`**: the statement after the memset in its block is a
  volatile asm with a `memory` clobber. Such a barrier usually names the buffer,
  and the contract counts any later statement that names it as a use, so the
  site also reads `followedByUse: true` and prints the partial line (measured:
  the `srcbarrier` shape). That is the direction that adds a line, not the one
  that hides one.
- **`= {0}` is not a site.** clang lowers it to a zero-fill `llvm.memset`, which
  WipePin pins as an initialiser. GCC lowers it to the aggregate assignment
  `key = {}`, which is not a call. The `initloop` shape — initialiser, then a
  zeroing loop as the wipe — therefore reads "nothing to pin" on GCC (exit 4)
  where WipePin pins the initialiser and prints the partial line.

## What it does not handle — counted, not ignored

Everything below leaves the program exactly as it was. Where the plugin can see
the shape, it is **counted** in `unhandled` (in scope only), so "nothing was
pinned" is never confused with "there was nothing to pin".

| counter | what it is | measured example (fixture-loop shapes, `-O2`) |
|---|---|---|
| `libcallMemset` | a call to a function named `memset` that is not the builtin | `nobuiltin`: `-fno-builtin` → 1, nothing to pin, exit 4 |
| `memsetChk` | `BUILT_IN_MEMSET_CHK`, or a call named `__memset_chk` | `chk`: `__builtin___memset_chk(p, 0, n, __builtin_dynamic_object_size(p, 0))` → 1, nothing to pin, exit 4 |
| `nonZeroFill` | `__builtin_memset` with a non-zero or non-constant value | `nonzero`: `memset(pad, 0xAA, …)` and `memset(key, c, …)` → 2, beside one pinned trailing wipe: the partial line |
| `atomicMemset`, `inlineWrapperMemset` | shapes GCC does not have | always 0 |

`chkconst`: the same `__builtin___memset_chk` on a local array, where the
object size is a constant, has already been folded into `__builtin_memset` when
the pass runs, so it is an ordinary site and is pinned (`memsetChk` 0). The
first version of the `chk` shape was this source, and expected `memsetChk` 1;
it is kept under its own name with the measured reading.

**Not counted, because the pass cannot see them as wipes:**

- Wipes written as stores — an explicit zeroing loop, or a store through a
  volatile pointer (which needs no pin).
- **`bzero`**, measured on a trailing `bzero(key, sizeof key)`: at `-O0` GCC
  has turned it into `__builtin_memset` by the time `cfg` has run, and it is
  pinned (`pin-gcc.sh` 0). At `-O2`, with the fortifying headers on by default,
  the target calls the header's `bzero` wrapper instead — not a memset, and no
  counter exists for it — so the record says nothing to pin, stderr says so,
  `pin-gcc.sh` exits 4, and the wipe is gone from the listing. If the same
  function also had a pinnable memset, only that one would be pinned and the
  `bzero` wipe would go unmentioned unless the pinned site reads
  `followedByUse: true`. 18 files of the r2 corpus mention `bzero`; how many of
  their wipes are cells like this was not measured here.
- A memset that a later pass creates (loop distribution turning a zeroing loop
  into a memset).
- A wipe inside a helper the target calls. Pin the helper by name. The target
  reads "nothing to pin" only if it has no zero-fill memset of its own
  (`inithelper`: it has none on GCC, because its initialiser is `key = {}`).
- Calls through a function pointer, including the `volatile` function-pointer
  idiom (which needs no pin either).

It also does not make anything reachable. Code the optimiser proves unreachable
is deleted along with any pinned memset in it. And the barrier only keeps the
stores to that buffer; copies of the secret in registers or spill slots are
outside what this pass, or any memset, can clear.

## The silent failures, and how each is made loud

| failure | what makes it loud |
|---|---|
| not installed: `WPIN_OUT` unset, no target, or `WPIN_DRY_RUN` neither `0` nor `1` | stderr `WipePinGcc: refusing to install: <reason>` (plus the explanatory note for "no target"); no record, so `pin-gcc.sh` exits **3** (measured: `notarget-O2`, `baddry-O2`). The compile's rc is unaffected. |
| built for another GCC | `plugin_default_version_check` fails: `WipePinGcc: refusing to install: built against GCC <x>, loaded into GCC <y> …`, no record (not exercised: there is one gcc-13 here) |
| loaded into the LTO back end (`-fplugin` on an `-flto` link line) | `WipePinGcc: refusing to install: loaded into the LTO back end, where this pass does not run; load it into the compile step instead` — measured: printed twice on one link, rc 0, and a stale file at `WPIN_OUT` was gone afterwards |
| a record from an earlier compile at `WPIN_OUT` | removed at load, before any refusal — a refused compile and one that never reached the end of the unit leave **no** record (measured: `stale-refused`, `stale-syntaxonly`). If it cannot be removed (a directory, a non-regular file, an unlink error other than "not there"): `WipePinGcc: refusing to install: <reason>`, nothing touched (`stale-dir`). |
| installed, but the unit never reaches the end (`-fsyntax-only`) | no record → `pin-gcc.sh` exits **3** (`syntaxonly-O2`) |
| a misspelt name | `resolution: not-in-module` in the record **and** `WipePinGcc: target <name> not-in-module`; `pin-gcc.sh` exits **4** (`wrongname-*`) |
| the right name, nothing eligible in it | `WipePinGcc: nothing to pin in scope …` with the `unhandled` counts; exit **4** |
| **something was pinned, but not the wipe** — a clear-before-fill memset pinned while the wipe is a loop of stores or sits in a helper | the site's `followedByUse: true`, and the partial line, `WipePinGcc: partial: pinned <P> site(s) in <module>; <K> followed by a later use …`. `pin-gcc.sh` still exits **0** and writes `followedByUseCount` (`initwipe`, `aliasinit`) |
| something was pinned while a memset-shaped call in scope was left alone (`unhandled` > 0) | the same partial line (`nonzero`) |
| the target is not an exact definition | `exact: false` and `linkage`, and `WipePinGcc: target <name> is not an exact definition (<linkage>); …`; `pin-gcc.sh` writes `exactAll=false` (`c99inline`, `cxxinline`) |
| the dry run | `dryRun: true`, a stderr line, exit **4**; the `dry-*` cells show the loss coming back with listing and object byte-identical to the stock build |
| the record cannot be written | `WipePinGcc: cannot write the record to WPIN_OUT (…); the IR was changed/not changed …`; exit **3** |
| a site where no barrier can go (a memset that ends its block with no fallthrough edge — it cannot, being nothrow) | `WipePinGcc: could not place a pin …`, and `pinnedCount` < `wouldPinCount`, which the strict readers refuse (never observed) |
| two source files on one line | measured: the driver runs one cc1 per file, each deletes `WPIN_OUT` at load and writes at the end, so the last file's record is the one left — `-c target.c opaque.c` leaves `opaque.c`'s record, which says `handle_request` is `not-in-module` (exit 4) although `target.c` was pinned. `pin-gcc.sh` counts source operands, warns, and writes `sourceOperands=`. One process never sees two units; the plugin still warns if it ever does. |
| `-fplugin` given twice | measured: GCC loads it once — one `tree-wipe_pin` in `-fdump-passes`, one pin in the record |
| the pin is in GIMPLE and the wipe still is not in the object | **not detectable here, by design.** That is the confirm step's job. The record is never the verdict. |

### Everything WipePinGcc prints on stderr

WipePin's lines with the prefix `WipePinGcc:`, the same wording, and
"zero-fill memset" where WipePin says "zero-fill llvm.memset":

| line | when |
|---|---|
| `WipePinGcc: refusing to install: <reason>` | not installed; followed by explanatory lines for "no target" |
| `WipePinGcc: target <name> not-in-module` / `declaration-only` | a requested name did not resolve |
| `WipePinGcc: target <name> is not an exact definition (<linkage>); the copy that runs may come from another translation unit` | a resolved name with `exact: false` |
| `WipePinGcc: dry run: <n> zero-fill memset site(s) would be pinned; none was changed` | dry run with eligible sites |
| `WipePinGcc: nothing to pin in scope in <module> (zero-fill memset in scope: 0; unhandled in scope: …)` | no zero-fill memset in scope |
| `WipePinGcc: partial: pinned <P> site(s) in <module>; <K> followed by a later use of the same buffer (initialiser-like, not a wipe); unhandled in scope: libcallMemset=.. memsetChk=.. nonZeroFill=.. atomicMemset=0 inlineWrapperMemset=0` | some site has `followedByUse: true` (K > 0), or `pinnedCount` > 0 while an in-scope `unhandled` counter is > 0 |
| `WipePinGcc: cannot write the record to WPIN_OUT (…); the IR was changed/not changed and nothing records it` | the record could not be written |
| `WipePinGcc: could not place a pin after a zero-fill memset in <fn> …` | see the table above |
| `WipePinGcc: a second module (…) reached this pass in one process; …` | one process finished two units |
| notes about `WPIN_TARGET_FNS` / `WPIN_SCOPE` / duplicates / `-fplugin-arg-` | configuration notes, printed at load |

A compile whose record has only exact targets, a `followedByUse: false` site
for everything pinned, and no unhandled shapes prints nothing.

## Building and running

```sh
cmake -S compiler/gcc-repair -B ~/vg-build/gcc-repair -G Ninja \
      -DCMAKE_CXX_COMPILER=g++-13
ninja -C ~/vg-build/gcc-repair            # -> libWipePinGcc.so, canon-vectors
~/vg-build/gcc-repair/canon-vectors compiler/evidence/testdata/digest-vectors.json

# one cell
WPIN_TARGET_FNS=encrypt_blob \
  bash compiler/gcc-repair/scripts/pin-gcc.sh ~/vg-build/gcc-repair/libWipePinGcc.so \
       <lab>/cell.json -O2 -c file.c -o <lab>/cell.o
```

The plugin is compiled by `g++-13` against `$(g++-13 -print-file-name=plugin)/include`
(asked of the compiler, not spelled out), C++17, `-fno-rtti`, `-Wall -Wextra`,
GCC's headers as system headers. `-ffile-prefix-map` keeps the source directory
out of the binary.

`pin-gcc.sh` exit codes, the same as `pin.sh`'s:

| exit | meaning |
|---|---|
| `0` | the compiler succeeded; a `wipe-pin-v2` record from WipePinGcc was written; it pinned at least one site; every requested name resolved. **Not** "the wipe survived", and not even "the wipe was pinned": a pinned clear-before-fill counts. `followedByUseCount` and the partial line are where that shows. |
| `1` | the compiler failed |
| `3` | the compiler succeeded and there is no usable record: the plugin refused to install, the unit never reached its end, the record could not be written, or what was written is not a `wipe-pin-v2` WipePinGcc record — read strictly by `scripts/wpin_gcc_record.py`, which re-derives both digests and refuses an unknown field, a wrong type, a count that contradicts its list, `atomicMemset`/`inlineWrapperMemset` ≠ 0, a `clang` toolchain, or a v1 record |
| `4` | the compiler succeeded and a record was written, but nothing was repaired: `pinnedCount` 0 (a dry run, a misspelt name, nothing eligible, a site the source had already pinned) or a requested name did not resolve |

The manifest (`<lab>/cell.manifest.kv`) has the same fields as `pin.sh`'s:
plugin sha256, compiler and version, `rc`, `status`, `sourceOperands`,
`record`, `recordError`, `pinnedCount`, `wouldPinCount`, `followedByUseCount`,
`unresolved`, `exactAll`, the `WPIN_*` settings, and the argv and stderr in
base64 with the home directory replaced by `~`. The reader needs `python3` and
nothing else.

### The fixture loop

```sh
bash compiler/gcc-repair/scripts/run-gcc-fixture-loop.sh --lab <lab> \
     --plugin ~/vg-build/gcc-repair/libWipePinGcc.so
python3 compiler/gcc-repair/scripts/check-gcc-fixture-loop.py --lab <lab>   # 0 / 2 / 3
```

The runner decides nothing and the checker compiles nothing. The erasure
fixture is the one `../llvm-pass/tools/make-fixtures.sh` writes — the runner
calls that script with the lab as `IRCK_LAB` — and the shape sources are
written into the lab on every run; nothing is generated into this tree. There
are no default lab or build paths.

Whether the wipe is in a listing is decided by `observeEffect` from
`../eval/second-vendor/lib/asm-oracle.mjs`, imported (not copied) by
`scripts/lib/asm-presence.mjs`, with ablation-cell's `CONTROL_EFFECT` (memset
and `__memset_chk` calls, inline zero stores). The oracle does not know
`rep stos`, the form gcc-13 uses at `-Os`; without help it reads the fixture's
control as ABSENT at `-Os` with or without the plugin. `asm-presence.mjs` adds
the same two-line fallback `ablation-cell.mjs`'s `controlPresent` uses (a
zeroed `%eax`, then `rep stos`), and a reading that came from it says
`rep-stos-fallback` in the table rather than being folded in. Objects are
compared byte for byte.

Tests: `node --test compiler/gcc-repair/test/asm-presence.test.mjs
compiler/gcc-repair/test/corpus-smoke.test.mjs`, and, as files (the directory
name is not a Python package name), `python3
compiler/gcc-repair/test/test_wpin_gcc_record.py` and `python3
compiler/gcc-repair/test/test_check_gcc_fixture_loop.py`.

## Measured

gcc-13 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), Ubuntu 24.04 under WSL, plugin
built with g++-13 13.3.0, 2026-09-11. Every number below was copied from a run,
not from reasoning.

**Build.** `-Wall -Wextra`: 0 warnings. `libWipePinGcc.so` sha256
`954b5b58d3e14028798fc48d6f7420fd77051d8d91233d048886959c3425f025`, the same
bytes from two builds into separate directories; no absolute path in the
binary. `canon-vectors` on the shared calibration: `canon-vectors: 22 vectors,
8 mustFail, 66 checks held, 0 disagreed` (the 66 include an extra UTF-16 key
order case, the 13.3.0 toolchain digest, SHA-256 at the padding boundaries and
the escaping of control characters, with expected values from `canon.mjs` and
`node:crypto`).

**Fixture loop** (`run-gcc-fixture-loop.sh` rc 0, `check-gcc-fixture-loop.py`
exit 0, "all 50 cells as expected"; plugin sha256 `954b5b58…`):

```
cell          opt  kind       subject  via                control                      obj=base  asm=base  pinned/would/mode/res   followedByUse  pin-gcc.sh
base-O0       -O0  base       PRESENT  oracle             PRESENT                      -         -         -                       -              -           ok
base-O1       -O1  base       ABSENT   oracle             PRESENT                      -         -         -                       -              -           ok
base-O2       -O2  base       ABSENT   oracle             PRESENT                      -         -         -                       -              -           ok
base-O3       -O3  base       ABSENT   oracle             PRESENT                      -         -         -                       -              -           ok
base-Os       -Os  base       ABSENT   oracle             PRESENT (rep-stos-fallback)  -         -         -                       -              -           ok
pin-O0        -O0  pin        PRESENT  oracle             PRESENT                      no        no        1/1/live/resolved       false          0           ok
pin-O1        -O1  pin        PRESENT  oracle             PRESENT                      no        no        1/1/live/resolved       false          0           ok
pin-O2        -O2  pin        PRESENT  oracle             PRESENT                      no        no        1/1/live/resolved       false          0           ok
pin-O3        -O3  pin        PRESENT  oracle             PRESENT                      no        no        1/1/live/resolved       false          0           ok
pin-Os        -Os  pin        PRESENT  rep-stos-fallback  PRESENT (rep-stos-fallback)  no        no        1/1/live/resolved       false          0           ok
dry-O0        -O0  dry        PRESENT  oracle             PRESENT                      yes       yes       0/1/dry/resolved        false          4           ok
dry-O1        -O1  dry        ABSENT   oracle             PRESENT                      yes       yes       0/1/dry/resolved        false          4           ok
dry-O2        -O2  dry        ABSENT   oracle             PRESENT                      yes       yes       0/1/dry/resolved        false          4           ok
dry-O3        -O3  dry        ABSENT   oracle             PRESENT                      yes       yes       0/1/dry/resolved        false          4           ok
dry-Os        -Os  dry        ABSENT   oracle             PRESENT (rep-stos-fallback)  yes       yes       0/1/dry/resolved        false          4           ok
wrongname-O0  -O0  wrongname  PRESENT  oracle             PRESENT                      yes       yes       0/0/live/not-in-module  -              4           ok
wrongname-O1  -O1  wrongname  ABSENT   oracle             PRESENT                      yes       yes       0/0/live/not-in-module  -              4           ok
wrongname-O2  -O2  wrongname  ABSENT   oracle             PRESENT                      yes       yes       0/0/live/not-in-module  -              4           ok
wrongname-O3  -O3  wrongname  ABSENT   oracle             PRESENT                      yes       yes       0/0/live/not-in-module  -              4           ok
wrongname-Os  -Os  wrongname  ABSENT   oracle             PRESENT (rep-stos-fallback)  yes       yes       0/0/live/not-in-module  -              4           ok
nothing-O0    -O0  nothing    -        -                  -                            yes       yes       0/0/live/module         -              4           ok
nothing-O1    -O1  nothing    -        -                  -                            yes       yes       0/0/live/module         -              4           ok
nothing-O2    -O2  nothing    -        -                  -                            yes       yes       0/0/live/module         -              4           ok
nothing-O3    -O3  nothing    -        -                  -                            yes       yes       0/0/live/module         -              4           ok
nothing-Os    -Os  nothing    -        -                  -                            yes       yes       0/0/live/module         -              4           ok

pin-gcc.sh alone  rc  cc rc  record              module
notarget-O2       3   0      -                   -         ok
syntaxonly-O2     3   0      -                   -         ok
baddry-O2         3   0      -                   -         ok
twosources-O2     4   0      twosources-O2.json  opaque.c  ok

shape (-g)     pin-gcc.sh  pinned  followedByUse  lines  exact/linkage               partial line  nothing line
initloop       4           0       -              -      True/external               no            yes           ok
inithelper     4           0       -              -      True/external               no            yes           ok
initwipe       0           2       true,false     6,9    True/external               yes           no            ok
aliasinit      0           1       true           7      True/external               yes           no            ok
trailing       0           1       false          8      True/external               no            no            ok
loopreturn-O0  0           2       false,false    11,16  True/external               no            no            ok
loopreturn-O1  0           2       false,false    11,16  True/external               no            no            ok
loopreturn-O2  0           2       false,false    11,16  True/external               no            no            ok
loopreturn-O3  0           2       false,false    11,16  True/external               no            no            ok
loopreturn-Os  0           2       false,false    11,16  True/external               no            no            ok
srcbarrier     4           0       true           8      True/external               yes           no            ok
c99inline      0           1       false          8      False/available_externally  no            no            ok
cxxinline      0           1       false          8      False/linkonce_odr          no            no            ok
nobuiltin      4           0       -              -      True/external               no            yes           ok
nonzero        0           1       false          12     True/external               yes           no            ok
chk            4           0       -              -      True/external               no            yes           ok
chkconst       0           1       false          7      True/external               no            no            ok

stale record      before  cc rc  after   WipePinGcc stderr
stale-refused     file    0      absent  WipePinGcc: refusing to install: no target                ok
stale-syntaxonly  file    0      absent  -                                                         ok
stale-live        file    0      file    -                                                         ok
stale-dir         dir     0      dir     WipePinGcc: refusing to install: WPIN_OUT is a directory  ok
```

What the table shows, beyond itself:

- gcc-13 deletes the fixture's subject wipe at every level above `-O0` (the
  base rows); with the plugin it is in the listing at every level. At `-O1` …
  `-O3` the pinned wipe is `pxor` + 2 × `movaps` to the stack; at `-Os` it is
  `xorl %eax, %eax; rep stosl` (read through the fallback); at `-O0` it is the
  `call memset@PLT` that was there anyway, and the object still differs from
  the stock one by one instruction, `leaq -48(%rbp), %rax`, which materialises
  the barrier's operand.
- **Loaded, nothing to pin, nothing changed** — measured at all five levels,
  not assumed: `nothing-*` (a unit with no memset at all, module scope),
  `dry-*` and `wrongname-*` give a listing and an object byte-identical to the
  compile without the plugin. The plugin is installed in all of them: each
  wrote its record, which happens only at the end of the unit.
- In every plugin cell the record from the `-S` compile and the one from the
  `pin-gcc.sh -c` compile have the same `evidenceDigest`.
- `loopreturn` is the shape of `fable_N_token_r3`'s line 17, where clang's
  cleanup dispatch gives a `return` inside the loop a CFG edge back to the
  header and WipePin reads `true` at `-O1`/`-O2`. GCC copies a clobber-only
  cleanup onto each exit instead (the `cfg` dump at `-O0` and `-O2` shows
  `n = {CLOBBER(eol)}` on the return path, then a jump to the block that
  clobbers `token` and returns), so there is no such edge and the error-path
  wipe reads `false` at every level. The corpus file itself, through `pin-gcc.sh` (`-g`, the find step's
  flags): sites at lines 17 and 23, both `false`, at `-O0`, `-O1` and `-O2`.
- The toolchain block in every record re-derives, and so does every
  `evidenceDigest` (`scripts/wpin_gcc_record.py`, calibrated against the shared
  vectors).

**The checker was shown to fail.** On a copy of the lab, one corruption at a
time: the partial line deleted from `initwipe`'s stderr → exit 2; `dry-O2`'s
object replaced by the pinned one → exit 2 ("object DIFFERENT"); the zero
stores deleted from `pin-O2`'s listing → exit 2 (subject ABSENT); `c99inline`'s
record deleted → exit 3; `trailing`'s site flipped to `followedByUse: true` with
the digest re-sealed → exit 2; a stale file put back at `stale-refused`'s
`WPIN_OUT` → exit 2; `pin-O2`'s toolchain version edited with `evidenceDigest`
re-sealed and the toolchain digest not → exit 2 (three disagreements: the
toolchain digest, the two records differing, and the self-check that uses that
record); `dry-O2`'s `pin-gcc.sh` exit code edited to 0 → exit 2.

**Corpus smoke** (`scripts/run-gcc-corpus-smoke.mjs`, exit 0). The first three
ids, sorted, among the gcc-13 / `-O2` / `removable` / `WIPE_ELIMINATED` rows of
`../eval/ai-generated/data/r2-build-rows.json`, re-run through that lane's own
`wipeSpans`, `ablateSpans`, `bodyOf`, `FLAGS`, `CONTROL` and `verdictOf` in the
four-compile cell of `../eval/repair-loop/run-repair-loop.mjs`, with
`-fplugin=` on both sides:

| id | stock verdict (reproduced) | with WipePinGcc on both sides | what differs in the target body |
|---|---|---|---|
| `fable_N_aeskey_r1` | `WIPE_ELIMINATED` | `WIPE_SURVIVED` | `pxor` + 2 × `movaps` to the stack (+3 lines, −0) |
| `fable_N_aeskey_r3` | `WIPE_ELIMINATED` | `WIPE_SURVIVED` | `pxor` + 2 × `movaps` to the stack (+3, −0) |
| `fable_N_dbpass_r3` | `WIPE_ELIMINATED` | `WIPE_SURVIVED` | `pxor` + 4 × `movaps`, and a different frame: the barrier keeps the buffer's address live, in `%r12` (+22, −14) |

In all three the record pinned one site with `followedByUse: false`, the control
was PRESENT on both sides, and the ablated file's target body was identical
with and without the plugin (its record: 0 pinned, 0 would pin). These are the
same three ids WipePin's smoke picked on clang. Three files at one level, by
hand; the repair loop that runs the corpus is a separate lane.

**Other forms.**

- `-flto -O2 -c` with the plugin writes a record and pins; linking that object
  with the fixture's other two units under `-flto -O2`, without the plugin,
  gives an executable whose `main` (everything is inlined into it) holds two
  zero fills where the stock link holds one — the pin survived whole-program
  inlining. The plugin on the link line refuses, as above.
- C++: `WPIN_TARGET_FNS=_Z5wipe2i` resolves a non-`extern "C"` function and
  pins it (exit 0); `WPIN_TARGET_FNS=wipe2` reads `not-in-module` (exit 4).

## What it does not claim

- That a pin is a repair. The record says what was inserted; whether the wipe
  reached the object is the confirm step's question, answered by the stock
  observation.
- Anything about the wipe that is not a zero-fill `__builtin_memset` at the
  time `cfg` has run (see *Not counted*), or about copies of the secret outside
  the buffer.
- Anything about a GCC other than 13.3.0; the plugin loads only into the GCC it
  was built against, and every number above is from that one.
- Byte-identity when it pins. The `nothing`, `dry` and `wrongname` cells are the
  claim that it changes nothing when it pins nothing; a pinned compile is
  different on purpose.

## Licence

`compiler/` is Apache-2.0 WITH LLVM-exception (`../LICENSE`), and so is this
component. GCC loads a plugin only if the plugin defines
`plugin_is_GPL_compatible`, the plugin's declaration that its licence is
compatible with the GPL under which GCC and the headers it is compiled against
are distributed. Apache-2.0 is compatible with GPLv3, and the declaration was
approved for this component; `src/WipePinGcc.cpp` makes it with a comment
saying so. The plugin links against nothing but the host GCC it is loaded
into.
