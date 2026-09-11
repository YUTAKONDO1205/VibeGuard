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
"WipePinGcc"`. What the record means, field by field and per vendor, is
`../schema/wipe-pin.md`; the GCC readings are summarised under *What is
different on GCC* below.

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
- A memset that is already directly followed by a pin — a volatile asm with a
  `memory` clobber that also takes the memset's destination as an input
  operand (a previous pin, or a barrier the source wrote in that form) — is
  recorded (`alreadyVolatile: true`) and left alone. A barrier without that
  operand is not a pin, and the site is pinned (the `clobonly` and `otherbar`
  shapes).
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

- **`toolchain`** has exactly `gcc`, `packages` and `digest`
  (`../schema/wipe-pin.md` §3.1). `gcc` is `basever` from the
  `plugin-version.h` the plugin was compiled against; `packages` is `[{"name": "gcc", "version": <same>}]`; `digest` is
  the SHA-256 of the canonical serialisation of `{gcc, packages}`. For 13.3.0
  that is `59918b2e…`, the value `../evidence/canon.mjs` derives for the same
  object. Nothing comes from the environment.
- **`optLevel`** is `{speedup: optimize, size: optimize_size}` from the global
  options when the plugin loads (the driver's `-O` flags are decoded by then).
  Measured, from the plugin's own record:

  | flag | `-O0` | `-O1` | `-O2` | `-O3` | `-Os` | `-Oz` | `-Ofast` | `-Og` |
  |---|---|---|---|---|---|---|---|---|
  | `{speedup, size}` | `{0,0}` | `{1,0}` | `{2,0}` | `{3,0}` | `{2,1}` | `{2,2}` | `{3,0}` | `{1,0}` |

  For `-O0` … `-Oz` these are the pairs the repair loop's reader holds for
  WipePinGcc (`OPT_LEVELS` in `../eval/repair-loop/lib/pin-record.mjs`, the
  same pairs as its clang column); `-Ofast` and `-Og` are not in that table at
  all (`../schema/wipe-pin.md` §4). This component only reports what gcc-13
  says.
- **`destKind`** uses the observer's words (`../schema/wipe-pin.md` §7): a
  local automatic `VAR_DECL` is `alloca`; a `PARM_DECL`, or a pointer that is one, is
  `argument`; a static or global `VAR_DECL` is `global`; anything else is
  `other`. The destination is followed back through `&obj`, `&MEM[p + off]` (to
  `p`) and SSA temporaries that copy, convert or offset a pointer. A local
  pointer *variable* holding an address (`unsigned char *p = key;
  memset(p, …)`) is not followed — before `ssa` it is a variable, not a value —
  and reads `other`, as the same shape reads on the LLVM side (a pointer
  reloaded from a stack slot). A VLA or `__builtin_alloca` buffer is reached
  through such a pointer and reads `other` too (LLVM would say `alloca`).
- **`resolution[].linkage`** uses LLVM's spelling (`../schema/wipe-pin.md`
  §5): not `TREE_PUBLIC` → `internal`; `DECL_COMDAT` → `linkonce_odr`;
  `DECL_WEAK` → `weak`; `DECL_EXTERNAL` with a body (gnu_inline / C99
  `inline`) → `available_externally`; otherwise `external`. `exact` is `true`
  exactly for `external` and `internal`. **`DECL_COMDAT` is tested before
  `DECL_WEAK`**: measured with a probe plugin at the same
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
- **`followedByUse`** is computed on GIMPLE (`../schema/wipe-pin.md` §8): for
  an `alloca` site, breadth-first over basic blocks from the memset — the rest of
  its block, then every block reachable along any successor edge — any
  statement that mentions the buffer's `VAR_DECL` (taking its address included)
  is a use; the memset itself, clobbers (`key ={v} {CLOBBER}`) and debug
  statements are not. Beyond the decl itself it follows, to a fixed point,
  every SSA name or local pointer variable assigned from something that
  mentions the buffer or such a carrier, which is the GCC reading of WipePin's
  step through stack slots (the `aliasinit` shape needs it). `null` when the
  destination is not a local. There is no path feasibility at all: that can add
  a partial line, never remove one. No erasure-family site of the r2 corpus
  reads a different `followedByUse` at `-O1`..`-Os` than at `-O0`
  (*Measured*).
- **`seen` / `unhandled`** keep their keys (`../schema/wipe-pin.md` §10).
  `atomicMemset` and `inlineWrapperMemset` name LLVM shapes GCC does not have
  and are always 0. Under glibc's fortifying headers — which Ubuntu's gcc-13
  turns on by default whenever it optimises (`_FORTIFY_SOURCE` is `3` at `-O2`,
  undefined at `-O0`, measured with `-dM -E`) — the target calls the header's
  `gnu_inline` `memset` wrapper, and GCC keeps that call a `BUILT_IN_MEMSET`:
  it is pinned like any other (every fixture cell at `-O1` and above is that
  case). clang renames the same wrapper `memset.inline`, which is why WipePin
  needed `inlineWrapperMemset`.
- **`alreadyVolatile`** (`../schema/wipe-pin.md` §9): the next non-debug
  statement after the memset in its block is a volatile asm with a `memory`
  clobber **and** an input operand that is the memset's destination — the same
  pointer value, or the address of the same base declaration. Such a barrier
  names the buffer, and any later statement that names it is a use, so the site
  also reads `followedByUse: true` and prints the partial line (measured: the
  `srcbarrier` shape). That is the direction that adds a line, not the one that
  hides one.

  The clobber alone is not a pin. Measured at `-O2`: a `uint64_t k` zeroed by
  `memset` and followed by `__asm__ __volatile__("" ::: "memory")` loses its
  zero store in the stock listing (the local's address never leaves the
  function), and so does one followed by a barrier whose only operand is
  another local. The first version of this rule treated any volatile asm with a
  `memory` clobber as a pin, recorded both sites `alreadyVolatile: true`, pinned
  nothing, and the stores stayed deleted; now both are pinned and the store is
  in the listing (`clobonly`, `otherbar`, graded from the listings). An operand
  the gimplifier first copies into a temporary (`"r"(key + 16)`: the `cfg` dump
  shows `_1 = &key + 16;` between the memset and the asm) means the asm is not
  the next statement, and the site is pinned — a second barrier, harmless.
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
  `followedByUse: true`. The r2 corpus has no such cell: 18 of its files contain
  the letters `bzero`, but the only such spellings followed by `(` are
  `explicit_bzero(` (8 occurrences) and `secure_bzero(` (5, a helper a model
  wrote and defined); a plain `bzero(` occurs 0 times.
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
| loaded into the LTO back end (`-fplugin` on an `-flto` link line) | `WipePinGcc: refusing to install: loaded into the LTO back end, where this pass does not run; load it into the compile step instead` — graded by the fixture loop's `lto-linkline` cell: printed exactly twice on a one-object `-flto -shared` link (lto1 runs twice, `-fwpa` then `-fltrans`, and each loads the plugin), link rc 0, the compile's record at the same `WPIN_OUT` gone afterwards, and the linked object byte-identical to a stock link of the same object |
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
| the memset is followed by a barrier that does not name the buffer (a `memory` clobber and no operand, or an operand that is another local) | not treated as a pin: the site reads `alreadyVolatile: false` and is pinned (`clobonly`, `otherbar`). Before the rule required the operand, such a site read `alreadyVolatile: true`, `pinnedCount` 0, `pin-gcc.sh` 4, and the store was gone from the listing. |
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
`rep-stos-fallback` in the table rather than being folded in. The same oracle
reads the barrier shapes' listings (`shapes/<id>.s` with the plugin,
`shapes/<id>-stock.s` without, subject `handle`). Objects are compared byte
for byte.

The `lto` group's output is a linked shared object, not a listing. Its zero
fill is read from `objdump -d --no-show-raw-insn` of `handle` by
`objdump_zero_stores` in the checker: the oracle's two inline idioms in
objdump's spelling (a vector register zeroed against itself and then stored to
memory, 16 bytes per `%xmm` store; an immediate `$0x0` stored to memory, by
suffix), plus calls to `memset` / `__memset_chk`, with a vector register that
anything else writes no longer counting as zeroed.

Tests: `node --test compiler/gcc-repair/test/asm-presence.test.mjs
compiler/gcc-repair/test/corpus-smoke.test.mjs`, and, as files (the directory
name is not a Python package name), `python3
compiler/gcc-repair/test/test_wpin_gcc_record.py` and `python3
compiler/gcc-repair/test/test_check_gcc_fixture_loop.py`.

## Measured

gcc-13 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), Ubuntu 24.04 under WSL, plugin
built with g++-13 13.3.0, 2026-09-11, and again 2026-09-12 for the barrier rule
and the `lto` cells. Every number below was copied from a run, not from
reasoning.

**Build.** `-Wall -Wextra`: 0 warnings. `libWipePinGcc.so` sha256
`a023b047abcafdbb824f627d227861e0ae0556072c9e4ba87e102b2c9747ba1b`, the same
bytes from two builds into separate directories; no absolute path in the
binary. The build before the barrier rule, `954b5b58…425f025` (rebuilt from
its commit to the same sha256), is "the previous plugin" below. `canon-vectors` on the shared calibration: `canon-vectors: 22 vectors,
8 mustFail, 66 checks held, 0 disagreed` (the 66 include an extra UTF-16 key
order case, the 13.3.0 toolchain digest, SHA-256 at the padding boundaries and
the escaping of control characters, with expected values from `canon.mjs` and
`node:crypto`).

**Fixture loop** (`run-gcc-fixture-loop.sh` rc 0, `check-gcc-fixture-loop.py`
exit 0, "all 55 cells as expected"; plugin sha256 `a023b047…`; the 50 cells
the loop had before read exactly as they did with the previous plugin, and the
five new ones are `clobonly`, `otherbar` and the three `lto` cells):

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

shape (-g)     pin-gcc.sh  pinned  followedByUse  alreadyVolatile  lines  exact/linkage               partial line  nothing line  zero store plugin/stock
initloop       4           0       -              -                -      True/external               no            yes           -                        ok
inithelper     4           0       -              -                -      True/external               no            yes           -                        ok
initwipe       0           2       true,false     false,false      6,9    True/external               yes           no            -                        ok
aliasinit      0           1       true           false            7      True/external               yes           no            -                        ok
trailing       0           1       false          false            8      True/external               no            no            -                        ok
loopreturn-O0  0           2       false,false    false,false      11,16  True/external               no            no            -                        ok
loopreturn-O1  0           2       false,false    false,false      11,16  True/external               no            no            -                        ok
loopreturn-O2  0           2       false,false    false,false      11,16  True/external               no            no            -                        ok
loopreturn-O3  0           2       false,false    false,false      11,16  True/external               no            no            -                        ok
loopreturn-Os  0           2       false,false    false,false      11,16  True/external               no            no            -                        ok
srcbarrier     4           0       true           true             8      True/external               yes           no            PRESENT/PRESENT          ok
clobonly       0           1       false          false            8      True/external               no            no            PRESENT/ABSENT           ok
otherbar       0           1       false          false            10     True/external               no            no            PRESENT/ABSENT           ok
c99inline      0           1       false          false            8      False/available_externally  no            no            -                        ok
cxxinline      0           1       false          false            8      False/linkonce_odr          no            no            -                        ok
nobuiltin      4           0       -              -                -      True/external               no            yes           -                        ok
nonzero        0           1       false          false            12     True/external               yes           no            -                        ok
chk            4           0       -              -                -      True/external               no            yes           -                        ok
chkconst       0           1       false          false            7      True/external               no            no            -                        ok

stale record      before  cc rc  after   WipePinGcc stderr
stale-refused     file    0      absent  WipePinGcc: refusing to install: no target                ok
stale-syntaxonly  file    0      absent  -                                                         ok
stale-live        file    0      file    -                                                         ok
stale-dir         dir     0      dir     WipePinGcc: refusing to install: WPIN_OUT is a directory  ok

lto (-O2)     rc   refusals  compile record  WPIN_OUT before  WPIN_OUT after  output==stock  zero fill in handle (objdump -d)
lto-compile   0    -         wipe-pin-v2/1   -                file            -              -                                                                  ok
lto-linkline  0    2         -               file             absent          yes            -                                                                  ok
lto-stock     0/0  -         -               -                -               -              pinned 2 store(s)/32B/0 call(s); unpinned 0 store(s)/0B/0 call(s)  ok
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
  header. WipePin's `wipe-pin-v1` read that site `true` at `-O1`/`-O2`
  through that edge; `wipe-pin-v2` no longer counts an edge the path cannot
  take and reads it `false` (`../llvm-repair/README.md`, *What
  `followedByUse` can and cannot say*). GCC copies a clobber-only cleanup onto
  each exit instead (the `cfg` dump at `-O0` and `-O2` shows
  `n = {CLOBBER(eol)}` on the return path, then a jump to the block that
  clobbers `token` and returns), so there is no such edge and the error-path
  wipe reads `false` at every level. The corpus file itself, through
  `pin-gcc.sh` (`-g`, the find step's flags): sites at lines 17 and 23, both
  `false`, at `-O0`, `-O1` and `-O2` (measured with the previous plugin).
- `clobonly` and `otherbar` are graded from the listings, not from the record:
  in the stock listing the zero store is gone (`ABSENT`), with the plugin it is
  back (`PRESENT`, `movq $0, (%rsp)` in `clobonly`). `srcbarrier`'s own
  barrier keeps its store in both listings, which is why leaving that site
  alone is right.
- `lto-compile`: `-O2 -flto -c` with the plugin writes a valid record (one
  site pinned, `followedByUse: false`) and prints nothing. `lto-linkline`:
  linking that object `-O2 -flto -shared` with `-fplugin` and the same
  `WPIN_OUT` exits 0, prints the LTO refusal exactly twice (lto1 runs twice for
  this link, once with `-fwpa` and once with `-fltrans`, and each loads the
  plugin), and leaves nothing at `WPIN_OUT`: the compile's record is removed at
  load, before the refusal. The linked object is byte-identical to a stock link
  of the same object. `lto-stock`: in a stock `-flto -shared` link of the
  pinned object, `handle` holds `pxor %xmm0,%xmm0` and two `movaps` of `%xmm0`
  to the stack, 32 bytes, the whole buffer; the same link of an object compiled
  `-flto` without the plugin holds no zero store at all. The pin travels in the
  object's GIMPLE and survives link-time optimisation; the plugin is needed at
  compile time only.
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
record); `dry-O2`'s `pin-gcc.sh` exit code edited to 0 → exit 2. For the new
cells, 2026-09-12, again one corruption at a time on a copy of the lab:
`lto/stock-pinned.objdump.txt` replaced by the unpinned link's → exit 2
(`0 zero bytes stored in handle, expected 32`); a file put back at the link's
`WPIN_OUT` → exit 2; one of the two refusal lines deleted → exit 2 (`printed 1
time(s), expected 2`); the compile's record deleted → exit 2; `clobonly`'s
listing replaced by its stock listing → exit 2 (zero store `ABSENT`);
`otherbar`'s stock listing replaced by the pinned one → exit 2 (stock
`PRESENT`).

**The previous plugin through the same loop** (`954b5b58…`, rebuilt from its
commit): `run-gcc-fixture-loop.sh` rc 0, `check-gcc-fixture-loop.py` exit 2,
and the only cells that disagree are the two new shapes — every other cell,
the `lto` ones included, reads `ok`:

```
clobonly: pinnedCount = 0, expected 1
clobonly: alreadyVolatile per site = [True], expected [False]
clobonly: pin-gcc.sh rc = '4', expected '0'
clobonly: manifest status = '4', expected '0'
clobonly: zero store in the listing with the plugin = 'ABSENT', expected 'PRESENT'
otherbar: pinnedCount = 0, expected 1
otherbar: alreadyVolatile per site = [True], expected [False]
otherbar: pin-gcc.sh rc = '4', expected '0'
otherbar: manifest status = '4', expected '0'
otherbar: zero store in the listing with the plugin = 'ABSENT', expected 'PRESENT'
```

**The barrier rule changes nothing in the r2 corpus.** Every file of
`../eval/ai-generated/generated-corpus/r2/` (720), with the find step's `FLAGS`
(`ablation-cell.mjs`: `-S -std=gnu11 -w -Wno-error=implicit-function-declaration
-fcf-protection=none`), at `-O0`, `-O1`, `-O2`, `-O3` and `-Os`, module scope,
live, with the previous plugin and this one (a build of this source whose
sha256 is the `a023b047…` above): 3585 (file, level) pairs compiled,
and in all 3585 the `-S` output and stderr are byte-identical and the records
are equal once `context` is dropped. The other 15 pairs are three files that do
not compile, with or without a plugin (`haiku_S_debugdump_r1`: an incomplete
`struct session`; `haiku_S_filedel_r2` and `opus_E_apicall_r2`: `NULL`
undeclared). The corpus's sites with `alreadyVolatile: true` are the same 10
under both plugins — `opus_E_pwverify_r2` line 13 (`secure_wipe`, followed by
`__asm__ __volatile__("" : : "r"(p), "r"(n) : "memory")`) and
`opus_N_token_r3` line 31 (followed by `"r"(token)`), each at five levels —
and both barriers name the buffer. The one barrier in the corpus with a
`memory` clobber and no operand, `fable_S_premaster_r3.c:29`, follows a loop
of stores through a `volatile unsigned char *`, not a memset, so no site is
followed by it.

**`followedByUse` reads the same at every level, site by site.** Measured
2026-09-12 with `../eval/repair-loop/tools/fbu-levels.mjs`, plugin
`a023b047…`: the 360 erasure-family files the repair loop measures, the find
step's `FLAGS` plus `-g1`, module scope, dry run, `-O0`..`-Os`; 3960 compiles,
every record accepted by `../eval/repair-loop/lib/pin-record.mjs`. `-g1` is
GCC's line-tables level, passed so that both vendors run the same kind of
compile and the same control; the line needs no flag here, and gcc-13
refuses `-gline-tables-only` (`unrecognized debug output level`, rc 1). 250
sites at each level; WipePin's 251 include one more, `haiku_E_pinpad_r1`'s
`volatile char pin[7] = {0};`, a volatile `llvm.memset` on clang and an
aggregate assignment here. At each of `-O1`..`-Os` all 250 join their `-O0`
site on (file, function, index) with the same line — 0 unmatched, 0
duplicate keys, 0 files not compared — and 0 of the 1000 joined (site, level)
pairs read a different `followedByUse`, in any direction; the same 58 sites
read `true` at every level. One other field does move with the level:
`lengthBytes` of the three sites of `haiku_S_token_r3` (lines 18, 22 and 28)
is `null` at `-O0` and 32 at `-O1`..`-Os`. Their length is `token_size`, a
`const ssize_t` local initialised to 32; the `cfg` dump shows `memset (&token,
0, token_size.1_5)` at `-O0` and `memset (&token, 0, 32)` at `-O1`: by the
time the pass runs, the call carries the constant only when optimising.
Those three read `followedByUse: false` at all five levels. Controls in the
same run: `-O0` compiled twice, 0 differences and the same `evidenceDigest`
in 360/360 files; every level compiled again without `-g1`, records equal on
every field but `line` in 1800/1800, with a line on all 1250 (site, level)
pairs either way. There is no older WipePinGcc to rerun as a positive
control; the same tool finds WipePin v1's 16 known level-dependent sites
(`../llvm-repair/README.md`), and the `lengthBytes` rows above are it finding
a level-dependent field in WipePinGcc's own records. Not covered: `-O0` is
the reference, not the truth, and a site read wrongly at every level alike
does not show; one corpus, one gcc.

**Corpus smoke** (`scripts/run-gcc-corpus-smoke.mjs`, exit 0). The first three
ids, sorted, among the gcc-13 / `-O2` / `removable` / `WIPE_ELIMINATED` rows of
`../eval/ai-generated/data/r2-build-rows.json`, re-run through the find step's own
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
hand, with the previous plugin; the whole corpus is run by
`../eval/repair-loop/`.

**Other forms.**

- LTO is graded by the fixture loop's `lto` cells (above): `-O2 -flto -c` with
  the plugin writes a record and pins (`lto-compile`); the plugin on the
  `-flto` link line refuses twice, exits 0 and removes the compile's record at
  `WPIN_OUT` (`lto-linkline`); a stock `-flto -shared` link keeps the pinned
  object's 32-byte zero fill in `handle` and loses the unpinned object's
  (`lto-stock`). Load the plugin at compile time; if a build exports `WPIN_*`
  to every step, keep `-fplugin` off the link line or give the link a
  different `WPIN_OUT`. By hand, with the previous plugin: linking the erasure
  fixture's pinned `target.c` with its other two units under `-flto -O2`,
  without the plugin, gave an executable whose `main` (everything is inlined
  into it) holds two zero fills where the stock link holds one.
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
component. It is compiled against GCC's plugin headers (the installed
`gcc-13-plugin-dev`), which carry GCC's own terms: the GNU General Public
License, version 3 or (at your option) any later version. GCC loads a plugin
only if the plugin defines `plugin_is_GPL_compatible`, the plugin's
declaration that its licence is compatible with the GPL; `src/WipePinGcc.cpp`
defines it. The FSF's licence list names the Apache License 2.0 as compatible
with version 3 of the GPL. No GCC source is copied here; the headers stay where
the package manager put them. Besides the symbols of the GCC process that loads
it, the plugin needs only the C and C++ runtimes (`readelf -d`: `NEEDED`
`libstdc++.so.6`, `libgcc_s.so.1`, `libc.so.6`). `../../NOTICE` and
`../README.md` state the terms for the whole directory. This is a description
of the terms, not legal advice.
