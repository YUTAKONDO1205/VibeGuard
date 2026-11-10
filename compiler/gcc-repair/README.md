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

Both plugins write the same record, `wipe-pin-v3`; this one with `component:
"WipePinGcc"`. What the record means, field by field and per vendor, is
`../schema/wipe-pin.md` (§14 for what v3 adds to v2); the GCC readings are
summarised under *What is different on GCC* below.

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
- Two switches, both **off by default**, put the same barrier after shapes
  that are otherwise only counted (*Configuration*): `WPIN_BARRIER_CALLS=1`
  after a zero-fill `__builtin___memset_chk` and after `bzero`;
  `WPIN_ZERO_COPY=1` after a copy from an all-zero read-only static
  (`memcpy(key, zeros, n)` with `static const unsigned char zeros[N];`), which
  GCC has made either an aggregate assignment or a `memcpy` call by the time the
  pass runs — except a copy of 1, 2, 4, 8 or 16 bytes without the fortifying
  headers, which the gimplifier has already folded into a plain store of zero
  and which no switch counts or repairs (*Not counted*). The call or copy
  itself is left as it is; the barrier takes its destination. With both off
  the pass changes GIMPLE exactly as the `wipe-pin-v2` plugin did, as far as
  measured: the same `-S` output, byte for byte, in the 44 pairs of the fixture
  loop's `previous` group with the current build, and, with the build before the
  buffer barrier landed, on the 3,585 compiles of the r2 corpus at five levels
  and on 1,092 compiles of other files and rewrites (*Measured, 2026-11-09*).
- A third switch, also **off by default**, `WPIN_BUFFER_BARRIER=1`, puts the
  same barrier at the other end of a buffer's life: directly before each
  `buf ={v} {CLOBBER}` of a local buffer in scope that some zero fill writes
  (a zero-fill memset, `__builtin___memset_chk` or `bzero`, a store of zero
  inside a loop into an aggregate, a zero copy), with `&buf` as its input —
  unless every zero fill of the buffer is followed by a later use, in which
  case the buffer is read as holding an initialiser and gets none. Of the
  repairs here it is the only one that can reach a loop of zero stores into a
  local buffer of a function in scope — a loop that indexes the buffer, or
  writes through a pointer every assignment of which is the buffer's address;
  not a loop that walks a pointer through it (*What it does not do*, below).
  Measured on the fixture loop and on E3 v2's 52 machine-made rewrites at
  `-O2` only, all 52 of one loop template, an index loop with a constant bound
  (*The buffer barrier*, below).
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

The seven variables of `../schema/wipe-pin.md` §12 and §14.2, with WipePin's
meanings and refusals (`src/Config.cpp` is
`../llvm-repair/src/PinSelector.cpp`'s logic and wording, with POSIX calls where
that one uses LLVM's support library):

| variable | |
|---|---|
| `WPIN_OUT` | record path. **Required.** Removed when the plugin loads; a directory or non-regular file there is a refusal |
| `WPIN_TARGET_FNS` | comma-separated function names (assembler names: for C the declared name, for C++ the mangled one) |
| `WPIN_SCOPE` | `module`: every function body in the unit |
| `WPIN_DRY_RUN` | `1`: write the record exactly as if pinning, change nothing (the red control) |
| `WPIN_BARRIER_CALLS` | `1`: also put the barrier directly after a `BUILT_IN_MEMSET_CHK` whose fill is the constant zero (whatever its length), and after a `BUILT_IN_BZERO` or a call of a function named `bzero` with at least two arguments. Recorded in `barrierCalls` |
| `WPIN_ZERO_COPY` | `1`: also put the barrier after a copy from an all-zero read-only static — the aggregate assignment the gimplifier makes of a constant-length `memcpy` (form `aggregate`), a `BUILT_IN_MEMCPY` call (`builtin`), or a `BUILT_IN_MEMCPY_CHK` / non-builtin `memcpy` / `__memcpy_chk` call (`call`). Recorded in `zeroCopy`. **Not reached:** without the fortifying headers a copy of 1, 2, 4, 8 or 16 bytes is a plain store of zero by the time the pass runs, and is neither counted nor repaired (measured on gcc-10 … gcc-14, *Not counted*). A copy that is an initialiser, not a wipe, is repaired and counted like a wipe (*Building and running*, exit 0) |
| `WPIN_BUFFER_BARRIER` | `1`: also put the barrier directly before the end of the lifetime of each local buffer in scope that a zero fill writes, unless every zero fill of the buffer is followed by a later use (*The buffer barrier*; `../schema/wipe-pin.md` §14.6). Recorded in `bufferBarriers` |

The last three are read after `WPIN_DRY_RUN`, in that order, and the first one
that fails is the refusal. Unset, empty or `0` is off; `1` is on; any other
value is `refusing to install: WPIN_<NAME>='<value>' is neither 0 nor 1` — no
record, and the compile's exit status is left alone. A value read as "off" by mistake would change what the
compile does without saying so, which is why `2` is not quietly `0`. The record
echoes each switch as its block's `enabled`, `true` exactly when the variable is
`1`; `pin-gcc.sh` hands the reader what it set, and a record that disagrees is
refused (`wrong-compile`, `../schema/wipe-pin.md` §14.9 W1).

`-fplugin-arg-<plugin>-...` arguments are not read; if any are given, stderr
says so.

## The record

A measured record (`-O2`, the erasure fixture, `WPIN_TARGET_FNS=handle_request`,
every switch off; the fixture loop's `records/pin-O2.s.json`, 2026-11-09),
re-keyed for reading; on disk it is one line in canonical key order:

```json
{ "schemaVersion": "wipe-pin-v3", "component": "WipePinGcc", "module": "target.c",
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
                "atomicMemset": 0, "inlineWrapperMemset": 0, "bzeroCall": 0,
                "inlineWrapperBzero": 0, "zeroGlobalCopy": 0, "zeroGlobalCopyCall": 0},
  "barrierCalls": {"enabled": false, "sites": [], "barrierCount": 0, "wouldBarrierCount": 0},
  "zeroCopy": {"enabled": false, "sites": [], "repairedCount": 0, "wouldRepairCount": 0},
  "bufferBarriers": {"enabled": false, "count": 0, "sites": []},
  "host": {"ident": "13.3.0", "identMajor": 13, "builtMajor": 13, "checked": true,
           "intrinsicsCompared": null},
  "evidenceDigest": "...", "context": {"generatedAt": ..., "timeSource": ..., "sourceDateEpoch": ...} }
```

With `WPIN_ZERO_COPY=1` on the fixture loop's `zcopyagg` cell (`-O2
-U_FORTIFY_SOURCE`), the block reads `"zeroCopy": {"enabled": true, "sites":
[{"function": "handle", "form": "aggregate", "callee": null, "source":
"vg_zeros", "destKind": "alloca", "lengthBytes": 32, "line": 9}],
"repairedCount": 1, "wouldRepairCount": 1}`, with `pinnedCount` 0; with
`WPIN_BARRIER_CALLS=1` on `chkvar`, `"barrierCalls": {"enabled": true, "sites":
[{"function": "handle", "callee": "__builtin___memset_chk", "lengthBytes":
null, "line": 7}], "barrierCount": 1, "wouldBarrierCount": 1}` (measured).

The counting rules are WipePin's: `pinnedCount` counts barriers actually
inserted after a zero-fill `__builtin_memset` (0 in a dry run, where
`wouldPinCount` still counts the eligible sites); `pinned[]` lists every
zero-fill site in scope, `alreadyVolatile` ones included; `index` is the site's
ordinal among the zero-fill memsets of its function; `lengthBytes` is `null`
for a length that is not a constant; every number is an integer; `module` is
the basename only. A barrier placed by a switch is counted in its own block
(`barrierCount`, `repairedCount`), never in `pinnedCount`; each block's
would-count is the length of its `sites`, in the order of `pinned[]`
(functions in `../schema/wipe-pin.md` §5's order, statements in order). The
sites are kept as plain data per function: no GCC `tree` is held from the pass
to the end of the unit, across which the garbage collector runs.
`bufferBarriers` is the line above with the switch off; with it on, see *The
buffer barrier*.

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
- **`host`** (`../schema/wipe-pin.md` §14.7): `ident` is the `basever` cc1
  hands `plugin_init` — the running compiler's — and `builtMajor` the major of
  the `basever` the plugin was compiled against. `checked` is always `true` and
  `intrinsicsCompared` always `null`: `plugin_default_version_check` has
  already compared the two compilers (`basever`, `datestamp`, `devphase`,
  `revision`, configuration arguments) and refused on a difference, so a record
  is only ever written by a plugin in the GCC it was built for. Measured
  2026-11-09: each of gcc-10 … gcc-14 with its own build writes `ident` equal to
  its `-dumpfullversion` (10.5.0, 11.5.0, 12.4.0, 13.3.0, 14.2.0).
- **`seen` / `unhandled`** (`../schema/wipe-pin.md` §10 and §14.3): nine
  counters, the same keys as WipePin's. `atomicMemset`, `inlineWrapperMemset`
  and `inlineWrapperBzero` name LLVM shapes GCC does not have and are always 0.
  Under glibc's fortifying headers — which Ubuntu's gcc-13
  turns on by default whenever it optimises (`_FORTIFY_SOURCE` is `3` at `-O2`,
  undefined at `-O0`, measured with `-dM -E`) — the target calls the header's
  `gnu_inline` `memset` wrapper, and GCC keeps that call a `BUILT_IN_MEMSET`:
  it is pinned like any other (every fixture cell at `-O1` and above is that
  case). clang renames the same wrapper `memset.inline`, which is why WipePin
  needed `inlineWrapperMemset`.
- **`bzero`, the checked memset, and copies from a zero constant** reach the
  pass in GCC's own forms, so the same source line lands on different counters
  on the two vendors (as `memset` already does). Measured on the fixture loop's
  `switch` cells, gcc-13 `-O2`:
  - a trailing `bzero(key, sizeof key)` under the default `_FORTIFY_SOURCE` is a
    call of the header's `gnu_inline` wrapper, which GCC keeps under the name
    `bzero` — `bzeroCall` 1, never `inlineWrapperBzero` (clang's rename of such
    a wrapper would be `bzero.<suffix>`). Without the fortifying headers, and at
    `-O0`, GCC has already turned it into `__builtin_memset` and it is an
    ordinary pinned site;
  - `__builtin___memset_chk(key, 0, n, __builtin_object_size(key, 0))` with `n`
    a parameter stays a `BUILT_IN_MEMSET_CHK` (`memsetChk` 1; `callee`
    `__builtin___memset_chk`, `lengthBytes` `null` when the switch is on). With a
    constant length it has been folded into `__builtin_memset` already (the
    `chkconst` shape);
  - `memcpy(key, vg_zeros, 32)` from `static const unsigned char vg_zeros[64];`
    is the aggregate assignment `MEM <unsigned char[32]> [&key] = MEM <unsigned
    char[32]> [&vg_zeros]` under `-U_FORTIFY_SOURCE` (form `aggregate`), and a
    `BUILT_IN_MEMCPY` call — the fortifying wrapper's `__builtin___memcpy_chk`
    folded to plain `memcpy` — under the default `_FORTIFY_SOURCE` (form
    `builtin`, `callee` `memcpy`). Both count in `zeroGlobalCopy`; only a
    checked or library call counts in `zeroGlobalCopyCall`. The form `builtin`
    was predicted before the run by the analogy with memset's wrapper, and held.
    A copy of 1, 2, 4, 8 or 16 bytes under `-U_FORTIFY_SOURCE` is neither: the
    gimplifier has already made it `D.n = 0; MEM <unsigned long> [&key] = D.n;`
    (the 8-byte case, from the `cfg` dump), a store of a temporary that holds
    zero, which no counter and no switch reads (*Not counted*).

  The repair keeps the copy: what reaches the listing is a load of `vg_zeros`
  and a store of that register (`movdqa vg_zeros(%rip), %xmm0; movaps %xmm0,
  (%rsp)`, twice), not a zero store. The shared oracle counts zero stores and
  reads it ABSENT; the fixture loop's checker therefore also reads these cells
  with `zcopy_reading` (loads of the constant, their stores, `memcpy` calls),
  and the measurements below count a copy that reached the listing as kept.
  The census reads `destKind` and `lengthBytes` of an aggregate copy without
  marking anything addressable; the declaration is marked only when its barrier
  is placed, never in a dry run, which is why a dry run still compiles to the
  stock bytes.
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
- **Module scope takes in the fortifying headers' wrappers.** Under the default
  `_FORTIFY_SOURCE`, a unit that calls `memset` or `bzero` from `<string.h>` /
  `<strings.h>` has the header's `gnu_inline` wrapper as a function body of
  its own (the `cfg` dump lists `handle` and `memset`, or `handle` and
  `bzero`), and `WPIN_SCOPE=module` puts that body in scope too. Measured on
  gcc-13 `-O2` with this build: the memset wrapper's
  `__builtin___memset_chk(__dest, __ch, …)` fills with a parameter, not a
  constant, so it counts `memsetChk` 1 (a unit whose one call is a trailing
  `memset`), and the pinned `memset` in the caller then prints the partial
  line; with `WPIN_BARRIER_CALLS=1` the bzero
  wrapper's zero-fill `__builtin___memset_chk` gets a barrier, listed in
  `barrierCalls.sites` under `function` `bzero` beside the caller's own site.
  With `WPIN_TARGET_FNS`, or with `-U_FORTIFY_SOURCE`, neither happens
  (`memsetChk` 0, no `bzero` site).

## The buffer barrier (`WPIN_BUFFER_BARRIER`)

The GCC twin of WipePin's (`../llvm-repair/README.md`, *The buffer barrier*).
Every other repair sits right after a wipe it can see; a wipe written as a loop
of stores is not a call, and none of them sees it. The buffer barrier sits at
the other end: directly before each `buf ={v} {CLOBBER}` the gimplifier wrote
where the buffer's scope ends, or before every `return` when the buffer has
none (a `volatile` local gets none), it places the asm of the pin with `&buf`
as its input. Every store into the buffer before it may then be read, so none
is dead. It was prototyped and measured outside this tree first (lab notes
kept outside this repository) and then landed here; the numbers under
*Measured* are the landed builds' own.

**Which buffers.** In the functions in scope only: a `VAR_DECL` local to the
function (`auto_var_in_fn_p`) that is the destination of a zero-fill
`__builtin_memset` or `__builtin___memset_chk` or a call named `memset` /
`__memset_chk`, of a `BUILT_IN_BZERO` or a call named `bzero` (whether or not
`WPIN_BARRIER_CALLS` repairs it), of a copy from an all-zero read-only static
(the aggregate assignment, or a `memcpy` / `__memcpy_chk` call), or of a
non-volatile store of zero into an aggregate inside a loop — "inside a loop"
being a basic block on a cycle of the CFG, since the pass runs before loop
discovery. The destination is followed through `&obj`, `&MEM[p + off]`, SSA
temporaries, and a pointer-typed local whose every assignment is the address
of the same buffer (`unsigned char *p = key; … p[i] = 0;`). `T b = {0};` is the
empty-constructor assignment `b = {}`, not a zero write here (measured:
`initbar-on`, no barrier). A zero fill of anything else (an argument, a
global, the heap, a pointer not followed) gets no barrier and is counted on
stderr; for a store of zero inside a loop that count takes only a store into
an array element — an index on the way (`out[i]`, `g[i]`, `p->buf[i]`) or
pointer arithmetic (`*p++`, `*(b + i)`) — and not a store into one scalar
(`g = 0`, `*count = 0`, `p->next = 0`, `gs.n = 0`), as a store into a local
scalar is no buffer either (measured, one function per form).

**Initialisers get none.** A buffer whose every zero fill is followed by a
later use of it — a zeroed buffer that is then filled and read, and never
wiped — gets no barrier and no `sites` entry; stderr counts it
(`… N buffer(s) not barriered: every zero fill is followed by a later use
(read as an initialiser; a wipe that later code still touches, even code the
optimiser removes, is counted here too)`; until 2026-11-10 the line ended
`(initialiser-like, not a wipe)`). There is no wipe to keep, and the barrier
would make the buffer live in memory until its scope ends, holding the
secret's last value. Measured on gcc-13 `-O2` with a lab probe kept outside
this repository (a 16-byte buffer zeroed by `memset`, then given a copy of a
secret, then read, never wiped; the caller counts copies of the secret-derived
bytes below its stack pointer right after the return): 0 copies without the
plugin, 1 with the build before this rule (`ce1f515a…`), 0 with the build of
2026-11-10 that followed it (`10fc7a00…`; the current source differs from it
only in a stderr line); the return value is the same in all three.

The later use is looked for with the walk of `reason` below, run twice: once
as it is, and once stopping each path at a clobber of the buffer itself
(`buf ={v} {CLOBBER}`, the end of its lifetime), and a fill has a later use
only if both walks find one.
The second walk is what makes a buffer declared in a loop body and wiped at
the end of every iteration read as wiped: the next iteration's fill and uses
come after the clobber, in another lifetime (measured: `inloop-on` gets its
barrier and prints nothing; `initzero-on`, a loop of zero stores as an
initialiser, gets none and prints the not-barriered line). Both walks
over-approximate (no path feasibility), so the rule still errs towards "a
later use", that is, towards leaving a buffer out: a buffer whose only zero
fill is a wipe that, along some path the program never takes, appears to be
followed by a use gets no barrier. So does a wipe followed, on the path that
always runs, by code that touches the buffer and that the optimiser later
removes — a read of a wiped byte folded to the zero already known, a call
that inlines to nothing, a dump guarded by a flag nothing sets: the walks read
the GIMPLE this pass sees, not what survives it. Measured on gcc-13 `-O2`, one
probe of each of those three shapes (lab notes): the wipe deleted as stock
deletes it, where the build before this rule (`ce1f515a…`) kept it; a control
with nothing after the wipe kept it on every build. The walks over-approximate
the paths, not the uses: an address of the buffer stored into a field of
another local (`struct ctx c = {key, 16};`) is not followed, so an initialiser
used afterwards only through `c` reads as a wipe and gets a barrier (one
reviewer's probe, gcc-13 `-O2`: one site, anchor `clobber`).

**When.** The census reads the body before any barrier of it is placed and
marks nothing addressable; `mark_addressable` on the buffer is part of placing
the barrier, never of a dry run, so a dry run compiles to the stock listing
(measured: `loopbar-dry`).

**The record** (`../schema/wipe-pin.md` §14.6): `count` is the barriers placed
(0 in a dry run); `sites` one entry per barrier placed or, in a dry run, that
would have been, in the order of functions as in `pinned[]`, buffers by their
first zero fill, then each buffer's clobbers in block order. `buffer` is the
`DECL_NAME` (or `null`), `bytes` the type's size when it is a constant,
`reason` the kind of the first zero fill no later use follows (§8's walk,
except that a statement that only computes an address of the buffer into a
pointer is not a use — each loop iteration does that), and `anchor` `clobber`
or `ret`.

**What it does not do.** It covers local buffers of functions in scope and
nothing else: not the heap, not a caller's or a callee's buffer, not a
function out of scope. A wipe that walks a pointer through a local buffer
(`unsigned char *p = key; while (n--) *p++ = 0;`) is not followed back to the
buffer — `p`'s assignments include `p = p + 1`, not only the buffer's address
— so it gets no barrier and is counted as a zero fill that is not a local
buffer (measured). The barrier makes the buffer addressable and keeps it in
memory, so code around it can change, and so can a function out of scope:
measured outside this tree on the prototype, gcc-13 `-Os` folded an
out-of-scope fixture function into the target by identical-code folding
without the barrier and could not with it (its own wipe was deleted both
ways). It keeps the stores to the buffer, not copies in registers; that every
store of the secret into the buffer before the barrier is now a store to
memory is part of what it does, not a side effect that can be ruled out. Its
cost in run time or code size is not measured.

## What it does not handle — counted, not ignored

Everything below leaves the program exactly as it was. Where the plugin can see
the shape, it is **counted** in `unhandled` (in scope only), so "nothing was
pinned" is never confused with "there was nothing to pin".

With a switch on, the shapes it covers get a barrier and are no longer
counted; with every switch off (the default) they are counted here and left
alone.

| counter | what it is | measured example (fixture-loop shapes, `-O2`) |
|---|---|---|
| `libcallMemset` | a call to a function named `memset` that is not the builtin. No switch covers it | `nobuiltin`: `-fno-builtin` → 1, nothing to pin, exit 4 |
| `memsetChk` | `BUILT_IN_MEMSET_CHK`, or a call named `__memset_chk`. With `WPIN_BARRIER_CALLS=1` a zero-fill `BUILT_IN_MEMSET_CHK` gets a barrier instead; a non-builtin `__memset_chk` is still counted | `chk`: `__builtin___memset_chk(p, 0, n, __builtin_dynamic_object_size(p, 0))` → 1, nothing to pin, exit 4; `chkvar` (switches off) → 1, exit 4, listing byte-identical to stock |
| `nonZeroFill` | `__builtin_memset` with a non-zero or non-constant value | `nonzero`: `memset(pad, 0xAA, …)` and `memset(key, c, …)` → 2, beside one pinned trailing wipe: the partial line |
| `bzeroCall` | `BUILT_IN_BZERO`, or a call of a function named `bzero`. With `WPIN_BARRIER_CALLS=1` one with two arguments gets a barrier instead | `bzero` (switches off) → 1, nothing to pin, exit 4, the wipe gone from the listing |
| `zeroGlobalCopy` | a copy from an all-zero read-only static as the compiler's own operation: the aggregate assignment, or a `BUILT_IN_MEMCPY` call. With `WPIN_ZERO_COPY=1` it gets a barrier instead | `zcopyagg`, `zcopyhdr` (switches off) → 1 each, nothing to pin, exit 4 |
| `zeroGlobalCopyCall` | the same copy as a `BUILT_IN_MEMCPY_CHK` call or a call of a non-builtin `memcpy` / `__memcpy_chk`. With `WPIN_ZERO_COPY=1` it gets a barrier instead | not measured: no fixture cell or measured file had this form |
| `atomicMemset`, `inlineWrapperMemset`, `inlineWrapperBzero` | shapes GCC does not have | always 0 |

`chkconst`: the same `__builtin___memset_chk` on a local array, where the
object size is a constant, has already been folded into `__builtin_memset` when
the pass runs, so it is an ordinary site and is pinned (`memsetChk` 0). The
first version of the `chk` shape was this source, and expected `memsetChk` 1;
it is kept under its own name with the measured reading.

Before `wipe-pin-v3` a `bzero` under the fortifying headers was not counted at
all: if the same function also had a pinnable memset, only that one was pinned
and the `bzero` wipe went unmentioned. It is `bzeroCall` now, so that function
prints the partial line. The r2 corpus has no such cell: 18 of its files contain
the letters `bzero`, but the only such spellings followed by `(` are
`explicit_bzero(` (8 occurrences) and `secure_bzero(` (5, a helper a model
wrote and defined); a plain `bzero(` occurs 0 times.

**Not counted, because the pass cannot see them as wipes:**

- Wipes written as stores — an explicit zeroing loop, or a store through a
  volatile pointer (which needs no pin). With `WPIN_BUFFER_BARRIER=1` a zeroing
  loop into a local aggregate of a function in scope gets a barrier before the
  buffer's clobber, unless the buffer only ever holds an initialiser (*The
  buffer barrier*); it is still not a `pinned[]` site and not counted in
  `unhandled`.
- A memset that a later pass creates (loop distribution turning a zeroing loop
  into a memset).
- A wipe inside a helper the target calls. Pin the helper by name. The target
  reads "nothing to pin" only if it has no zero-fill memset of its own
  (`inithelper`: it has none on GCC, because its initialiser is `key = {}`).
- Calls through a function pointer, including the `volatile` function-pointer
  idiom (which needs no pin either).
- A copy from an all-zero read-only static of 1, 2, 4, 8 or 16 bytes when the
  fortifying headers are off (`-U_FORTIFY_SOURCE`, and every `-O0` compile,
  where Ubuntu's gcc leaves `_FORTIFY_SOURCE` undefined). The gimplifier has
  folded it before the pass runs into a store of a temporary that holds zero
  (`D.2968 = 0; MEM <unsigned long> [(char * {ref-all})&key] = D.2968;` for 8
  bytes, `MEM <uint128_t> …` for 16, in gcc-13's `cfg` dump at `-O2`): not
  `zeroGlobalCopy`, not seen by `WPIN_ZERO_COPY=1`, and not by the buffer
  barrier either, since it is not inside a loop. Measured with these builds on
  `memcpy(key, vg_zeros, N)` as a 1- to 32-byte buffer's last use: for N = 1,
  2, 4, 8 and 16 with the headers off — gcc-13 at `-O0` … `-Os`, gcc-10, 11,
  12 and 14 at `-O2`, 50 compiles, each with `WPIN_ZERO_COPY=1` and with that
  and `WPIN_BUFFER_BARRIER=1` — every record has `zeroCopy` 0, every
  `unhandled` counter 0 and `bufferBarriers` 0, stderr says "nothing to pin",
  `pin-gcc.sh` exits 4 (run at gcc-13 `-O2`), and the `-S` output is the stock
  output byte for byte. The stock listing has no zero store left for these at
  `-O1` and above (read by hand at gcc-13 `-O2` for 8 and 16 bytes; at the
  other levels and versions by the oracle and the copy reading only); at `-O0`
  the store stays (`movl $0, %eax; movq %rax, -16(%rbp)`, read by hand). A
  16-byte key — AES-128's — is one of these sizes. With the headers off, 24
  and 32 bytes are form `aggregate` and are repaired (20 of 20 compiles); with
  the default `_FORTIFY_SOURCE` at `-O1` and above every N is form `builtin`
  and repaired (56 of 56). Of those 56, the repaired copy of 2 bytes at `-O2`
  (all five versions) and `-O3`, and of 4 and 8 bytes at `-Os`, reaches the
  listing as a store of a register zeroed by `xor` (`xorl %eax, %eax; movw %ax,
  6(%rsp)`, read by hand on gcc-13 at `-O2` and `-Os`), which neither the
  oracle nor the copy reading counts: 8 compiles where the readings say ABSENT
  and the listing holds the store.

It also does not make anything reachable. Code the optimiser proves unreachable
is deleted along with any pinned memset in it. And the barrier only keeps the
stores to that buffer; copies of the secret in registers or spill slots are
outside what this pass, or any memset, can clear.

## The silent failures, and how each is made loud

| failure | what makes it loud |
|---|---|
| not installed: `WPIN_OUT` unset, no target, `WPIN_DRY_RUN`, `WPIN_BARRIER_CALLS`, `WPIN_ZERO_COPY` or `WPIN_BUFFER_BARRIER` neither `0` nor `1` | stderr `WipePinGcc: refusing to install: <reason>` (plus the explanatory note for "no target"); no record, so `pin-gcc.sh` exits **3** (measured: `notarget-O2`, `baddry-O2`, `badbarrier-O2`, `badzerocopy-O2`, `badbuffer-O2`). The compile's rc is unaffected. |
| built for another GCC | `plugin_default_version_check` fails: `WipePinGcc: refusing to install: built against GCC <x>, loaded into GCC <y> (or a differently configured build of it)`, no record, rc 0 (measured 2026-11-09: the gcc-13 build in gcc-12 and in gcc-14). **Not always reached:** the gcc-12 build loaded into gcc-13 never gets that far — cc1 cannot load it (`undefined symbol: tree_code_type`) and the compile fails, rc 1 (measured). Either way there is no record |
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
| the same for a switch's site (a call that ends its block with no fallthrough edge, or an aggregate copy whose destination has no address to give the barrier) | `WipePinGcc: could not place a barrier after a zero-fill call …` / `… after a copy from an all-zero constant …`, and the block's done-count below its would-count, which the strict readers refuse (never observed) |
| a switch set, and a record that says otherwise | `pin-gcc.sh` passes what it set to the reader (`--expect`), which refuses the record as `wrong-compile` → exit **3** (`../schema/wipe-pin.md` §14.9 W1; tested in `test/test_wpin_gcc_record.py`) |
| a repair made only by a switch, with `pinnedCount` 0 | `pin-gcc.sh` tests the sum of `pinnedCount`, `barrierCalls.barrierCount`, `zeroCopy.repairedCount` and `bufferBarriers.count` (`../schema/wipe-pin.md` §14.8), so a barrier-only repair exits **0**, not 4 (measured: the `switch` cells' `on` rows) |
| `WPIN_BUFFER_BARRIER=1` and a buffer that only holds an initialiser (every zero fill followed by a later use) | no barrier and no `sites` entry, and `WipePinGcc: buffer barrier: <n> buffer(s) not barriered: every zero fill is followed by a later use (read as an initialiser; a wipe that later code still touches, even code the optimiser removes, is counted here too)`. If nothing else in scope was repaired, `pin-gcc.sh` exits **4** (measured: `initzero-on`). Before this rule the buffer got a barrier, counted on stderr as initialiser-like, and `pin-gcc.sh` exited 0 |
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
| `WipePinGcc: dry run: <n> zero-fill call(s) would get a barrier; none was changed` | dry run with `WPIN_BARRIER_CALLS=1` and sites for it |
| `WipePinGcc: dry run: <n> copy(ies) from an all-zero constant would get a barrier; none was changed` | dry run with `WPIN_ZERO_COPY=1` and sites for it |
| `WipePinGcc: dry run: <n> buffer barrier(s) would be placed; none was changed` | dry run with `WPIN_BUFFER_BARRIER=1` and barriers it would place |
| `WipePinGcc: buffer barrier: <n> zero fill(s) in scope write memory that is not a local buffer of the function (an argument, a global, the heap, or a pointer this pass does not follow); no barrier covers them` | `WPIN_BUFFER_BARRIER=1` and such zero fills in scope; a store of zero inside a loop counts only when it writes an array element (*The buffer barrier*, "Which buffers") |
| `WipePinGcc: buffer barrier: <n> buffer(s) not barriered: every zero fill is followed by a later use (read as an initialiser; a wipe that later code still touches, even code the optimiser removes, is counted here too)` | `WPIN_BUFFER_BARRIER=1` and local buffers left without a barrier because every zero fill a later use follows — an initialiser, or a wipe the source touches again; `<n>` counts buffers. Until 2026-11-10 the line ended `(initialiser-like, not a wipe)`. It replaces `… <n> of <m> barrier site(s) are on buffers whose every zero fill is followed by a later use …`, which the build before this rule printed for barriers it did place on such buffers |
| `WipePinGcc: nothing to pin in scope in <module> (zero-fill memset in scope: 0; unhandled in scope: …)` | no zero-fill memset in scope, and no site for a switch that is on |
| `WipePinGcc: partial: pinned <P> site(s) in <module>; <K> followed by a later use of the same buffer (initialiser-like, not a wipe); unhandled in scope: libcallMemset=.. memsetChk=.. nonZeroFill=.. atomicMemset=0 inlineWrapperMemset=0 bzeroCall=.. inlineWrapperBzero=0 zeroGlobalCopy=.. zeroGlobalCopyCall=..` | some site has `followedByUse: true` (K > 0), or something was repaired while an in-scope `unhandled` counter is > 0. `<P>` counts every barrier this compile inserted, a switch's included |
| `WipePinGcc: cannot write the record to WPIN_OUT (…); the IR was changed/not changed and nothing records it` | the record could not be written |
| `WipePinGcc: could not place a pin after a zero-fill memset in <fn> …` / `could not place a barrier after …` | see the table above |
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

A GCC plugin loads only into the GCC whose headers it was compiled against, so
each GCC needs its own build, made by its own `g++-N`. `scripts/build-matrix.sh`
makes them all and says what each gave:

```sh
bash compiler/gcc-repair/scripts/build-matrix.sh --out <build-root> [--versions "10 11 12 13 14"] [--jobs 2]
```

It builds `<build-root>/gcc-repair-N` with `-DCMAKE_CXX_COMPILER=g++-N` for
each version, runs that build's `canon-vectors`, and prints one row per version
(also `<build-root>/build-matrix.tsv`): the `g++-N --version` line, the header
directory, `ok` / `skipped` / `cmake_failed` / `build_failed` /
`canon_failed`, the number of `warning:` lines, the sha256 and the
`canon-vectors` line. There is no default output directory. `--out` is resolved
to an absolute path before anything is created (the part that exists, with
symbolic links resolved, then the rest; a part that does not exist yet may not
contain `.` or `..`), and a directory anywhere inside this repository is
refused with nothing made — matched by name and by being the same directory as
the repository's root or one inside it, so a symbolic link or another spelling
on a case-folding file system is refused too (measured: 15 cases, including
`compiler/gcc-repair/x`, `compiler/x`, the root itself, a relative path, a
`..` into the tree, a link to the tree and the lower-case spelling of the
`/mnt/c` path). Exit 0 when every requested version built with 0 warnings and
its vectors held; 2 otherwise; 3 usage or a refused `--out`. Run it under
`taskset -c …` to keep it on some CPUs.

`pin-gcc.sh` exit codes, the same as `pin.sh`'s:

| exit | meaning |
|---|---|
| `0` | the compiler succeeded; a `wipe-pin-v3` record from WipePinGcc was written; it repaired at least one site — `pinnedCount + barrierCalls.barrierCount + zeroCopy.repairedCount + bufferBarriers.count > 0` (`../schema/wipe-pin.md` §14.8); every requested name resolved. **Not** "the wipe survived", and not even "the wipe was pinned": a pinned clear-before-fill counts. For pinned memsets, `followedByUseCount` and the partial line are where that shows. A `zeroCopy` site has no such mark: a copy from a zero constant that is an initialiser counts as repaired exactly as a wipe does. Measured with the gcc-13 build `10fc7a00…`: a unit whose only functions are `struct S16 ret16(void) { return z16; }` and the same for a 64-byte struct, no wipe anywhere, compiled with `WPIN_ZERO_COPY=1`, has `zeroCopy.repairedCount` 2 (both form `aggregate`) and exits 0, with nothing on stderr. |
| `1` | the compiler failed |
| `3` | the compiler succeeded and there is no usable record: the plugin refused to install, the unit never reached its end, the record could not be written, or what was written is not a `wipe-pin-v3` WipePinGcc record for the switches this compile set — read strictly by `scripts/wpin_gcc_record.py`, which re-derives both digests and refuses an unknown field, a wrong type, a count that contradicts its list, `atomicMemset`/`inlineWrapperMemset`/`inlineWrapperBzero` ≠ 0, a block whose `enabled` disagrees with the switch, a `host` whose major is not `toolchain.gcc`'s, a `clang` toolchain, or a v1 or v2 record (`../schema/wipe-pin.md` §14.10: a v2 record is read with the reader of its own commit) |
| `4` | the compiler succeeded and a record was written, but nothing was repaired: that sum is 0 (a dry run, a misspelt name, nothing eligible, a site the source had already pinned) or a requested name did not resolve |

The manifest (`<lab>/cell.manifest.kv`) has the same fields as `pin.sh`'s:
plugin sha256, compiler and version, `rc`, `status`, `sourceOperands`,
`record`, `recordError`, `pinnedCount`, `wouldPinCount`, `followedByUseCount`,
`unresolved`, `exactAll`, `barrierCount`, `wouldBarrierCount`,
`zeroCopyRepairedCount`, `wouldZeroCopyCount`, `bufferBarrierCount`,
`repairCount` (the sum above), the `WPIN_*` settings, and the argv and stderr
in base64 with the home directory replaced by `~`. The reader needs `python3`
and nothing else.

### The fixture loop

```sh
bash compiler/gcc-repair/scripts/run-gcc-fixture-loop.sh --lab <lab> \
     --plugin ~/vg-build/gcc-repair/libWipePinGcc.so \
     [--previous-plugin <an earlier libWipePinGcc.so>]
python3 compiler/gcc-repair/scripts/check-gcc-fixture-loop.py --lab <lab>   # 0 / 2 / 3
```

Every cell runs with the three switches unset, except the `alone` cells that
set one to a value the plugin must refuse, and the `switch` group: the four
shapes the switches exist for (`bzero` and `chkvar` for `WPIN_BARRIER_CALLS`,
`zcopyagg` and `zcopyhdr` for `WPIN_ZERO_COPY`), each compiled `-O2` four ways —
stock, the plugin with no switch (`off`), with its switch (`on`) and with its
switch and `WPIN_DRY_RUN=1` (`dry`). `off` and `dry` must give the stock
listing byte for byte, `on` must not, and the wipe must read PRESENT only in
`on`. The `buffer` group does the same for `WPIN_BUFFER_BARRIER`: `loopbar`, a
wipe written as `for (unsigned i = 0; i < sizeof key; i++) key[i] = 0;` as
`handle`'s last statement beside a control `wipe_kept` that zeroes its buffer
the same way and then reads it, stock, off, on and dry, where the control must
read PRESENT everywhere and its body in the `on` listing must be the stock
listing's once `.L` labels are renumbered in order of appearance (GCC numbers
them across the file); `initbar`, `= {0}` followed by uses and no wipe,
stock and on, where nothing is placed; `inloop`, a buffer declared in a loop
body, filled, read and wiped by a loop of zero stores in every iteration,
beside the same control, stock and on, where the barrier is placed and no
initialiser-like line may appear; and `initzero`, a loop of zero stores used as
an initialiser and then uses and no wipe, stock and on, where nothing is placed
and the not-barriered line must appear. With `--previous-plugin`, the
`previous` group compiles every plugin cell of the loop, the shapes, the
`switch` group's `off` cells and `loopbar-off` again, `-S`, with this plugin
and with the given one, each first copied to the same staged path so that the
`-fplugin=` string cannot differ; every pair must be the same bytes, and the
given plugin must not be this one (the same sha256 in both is a disagreement:
the group would compare the plugin with itself). Without the option the group
is not run and the checker says so (CI runs it that way).

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
`objdump_zero_stores` in `scripts/objdump_fill.py`: the oracle's two inline
idioms in objdump's spelling (a vector register zeroed against itself and then
stored to memory, 16 bytes per `%xmm` store; an immediate `$0x0` stored to
memory, by suffix), plus calls to `memset` / `__memset_chk`, with a vector
register that anything else writes no longer counting as zeroed.

The `xtu` group is a wipe helper in another translation unit, the loss only a
link can create. `secure_wipe(void *p, size_t n) { memset(p, 0, n); }` in
`wipe.c`; `handle()` in `use.c`, the helper's one caller, fills a 32-byte local
(`derive`), reads it (`use`) and calls `secure_wipe(key, sizeof key)` as its
last use; `main.c` calls it; `io.c` holds `derive` and `use` and is never
compiled `-flto`, so no link sees into them; `wipe_kept()` is the control, a
memset of its own on a buffer `use` reads afterwards, which no build may
remove. The same four sources as the WipePin loop's xtu cells, linked into an
executable at `-O2`: stock without LTO (`xtu-nolto`), and with `-flto` a stock
build (`xtu-lto-stock`), a build with the plugin at the compile of `wipe.c`
only, `WPIN_TARGET_FNS=secure_wipe` (`xtu-lto-pin`), and the same as a dry run
(`xtu-lto-dry`). The checker disassembles each executable itself, with the same
`objdump_fill.py` (which the WipePin loop's checker imports too), and reads
whether a call to `secure_wipe`, or to a renamed copy of it such as an IPA-CP
clone, is left in `handle` — a cell whose helper was not inlined, where
inlining is the point, disagrees rather than passes — and where the 32-byte
fill is: in `handle` when the helper was inlined, in the function `handle`
calls when it was not (a call or tail call to `memset` there counts).

Tests: `node --test compiler/gcc-repair/test/asm-presence.test.mjs
compiler/gcc-repair/test/corpus-smoke.test.mjs`, and, as files (the directory
name is not a Python package name), `python3
compiler/gcc-repair/test/test_wpin_gcc_record.py` and `python3
compiler/gcc-repair/test/test_check_gcc_fixture_loop.py` (which also tests
`objdump_fill.py`, holds both loops' xtu tables to the same design, and tests
how the WipePin loop's checker reads what its xtu cells were built as: the LTO
form, the linker and the link).

## Measured

Every number in this section was copied from a run, not from reasoning.

### 2026-11-10, later: the not-barriered line reworded

Measured 2026-11-10 with the source as it stands in this tree
(`src/WipePinGcc.cpp` sha256 `2ef0ad10…`). The only change against the builds
of *2026-11-10* below (`2b6be2a6…`) is the wording of one stderr line: a
buffer whose every zero fill is followed by a later use is now reported as
`… every zero fill is followed by a later use (read as an initialiser; a wipe
that later code still touches, even code the optimiser removes, is counted
here too)`, not `… (initialiser-like, not a wipe)`, because such a buffer can
hold a real wipe (*The buffer barrier*, "Initialisers get none"). The scripts,
the expectations written before each run and the data are lab notes kept
outside this repository.

**Builds** (`scripts/build-matrix.sh --versions "10 11 12 13 14" --jobs 6`,
exit 0): 0 warnings and `canon-vectors` 66 held, 0 disagreed, for each; the
gcc-13 build, made again into another directory, has the same sha256.

| GCC | `libWipePinGcc.so` sha256 |
|---|---|
| 10 | `b8c1dc28dbc78a1790b9893a2a0ab63314b062a98fedb241ddfaed59ba1f09a7` |
| 11 | `1a60958f77aba3bd688b3a7dd5175062651ba052a2fd7b1eb4cc192740846d4e` |
| 12 | `9fedd7ae398db724fd08948cbfa5ffff82ce5d543884ee541825cac129f505b9` |
| 13 | `ea3e8c7e8e58d6a2278b9c76420cf9d2b215d6371df3bfaf7a37bda2efeaedf9` |
| 14 | `d18fc093515f365fab30931832f4575f64e8999acb7ba12eb76126c0e3a0bc81` |

**Fixture loop:** "all 88 cells as expected" as CI runs it, and 132 with each
`--previous-plugin` (the `22e7222` build, and the gcc-13 build of the next
subsection, `10fc7a00…`), 44/44 previous pairs byte-identical in each.

**The corpora again, with these builds.** Every run of the next subsection was
repeated with these builds and the builds of the clang twin (its *2026-11-10,
later*), by the same scripts with only the build paths changed (twice: with
the clang twin's afternoon builds and again with its evening ones; the GCC rows
came out the same both times): r4 L, E3 and
E5 on LLVM 15 to 20 and GCC 10 to 14 (108,108 rows over both vendors), the
run-time readout, the files with no wipe, the compiler wrapper and the
handshake matrix. The expectation written before the run was that nothing but
the wording of the not-barriered lines would differ. Row by row against the
next subsection's run, every field: 107,712 rows the same, 396 the same once
the new wording is put back to the old, none different otherwise, no verdict
changed. The 396 are E5 v5, v8 and v10 of `sonnet_S_dbpass_r3` and
`sonnet_S_pinpad_r2` with the buffer barrier or its dry run (3 settings × 11
versions × 2 files × 2 arms): the rows keep the stderr of the compile with the
wipe only, and these are the files where that compile prints the line. Every
table, count and file set of the next subsection's summary came out the same:
the run-time readout's verdicts in every row (only the length of the longest
matching run, which no verdict uses, varied, in stock arms as well), the
no-wipe summaries, the wrapper's table, and in the handshake matrix `pin.sh`'s
exit and the record in all 108 compiles, where only the way clang crashed
varied in five cross-version pairs. The numbers of the next subsection
therefore hold for these builds too.

`scripts/wpin_gcc_record.py`, which `pin-gcc.sh` uses, accepted `1` and `0` for a
pinned site's `followedByUse` (Python's `in` compares with `==`), since `22e7222`;
it now requires a boolean or `null`, and `test/test_wpin_gcc_record.py` has a test
that fails on the old line.

### 2026-11-10: the builds of the 2026-11-09 fixes, GCC 10 to 14, on r4 L and its E3 and E5 rewrites (`-O2`)

Measured 2026-11-10 with the source as it stood before *2026-11-10, later*
above (`src/WipePinGcc.cpp` sha256 `2b6be2a6…`), built again from scratch for
GCC 10 to 14 into a separate directory: 0 warnings and `canon-vectors` 66 held,
0 disagreed, for each, and each build byte-identical to the one in the table
of the next section (gcc-13: `10fc7a00…`, which recorded the tracked
repair-loop rows that morning; the build of the current source recorded the
same rows again that afternoon, `../eval/repair-loop/data/r2-v3-rerecord.json`). The
scripts (copies of those of the runs below, with only the plugin paths
changed), the expectations written before the run, the one comparison rule
added after it with its time and reason, and the data are lab notes kept
outside this repository. Every corpus row is `-O2`, the target and its
helpers named (functions scope), `-U_FORTIFY_SOURCE`, `=2` and the version's
default (which is `=3` on gcc-12 to 14 and `=2` on gcc-10 and 11, where `=3`
does not exist, so their three settings are unset, 2 and 2); "kept" =
`verdictOf`, the zero-store count and the count difference all say so; the
denominator is the files stock deleted (below the table). E3 v2's 52 files all
use one loop template, an index loop over the buffer with a constant bound.

| GCC | r4 L: `ext` kept | E3 v2 (loop): `ext` kept | E3 v2: **`+ WPIN_BUFFER_BARRIER=1` kept** |
|---|---|---|---|
| 10 | 50/50 | 0 of 50 | **50/50** |
| 11 | 51/51 | 0 of 50 | **50/50** |
| 12 | 51/51 | 0 of 51 | **51/51** |
| 13 | 51/51 | 0 of 51 | **51/51** |
| 14 | 51/51 | 0 of 50 | **50/50** |

Each cell is the same in all three settings, and the three readings agreed on
every file the buffer barrier kept. On E3 v1 (each wipe rewritten as `bzero`)
and v3 (as `__builtin___memset_chk`), and on E5 v4, v5 and v7 (v7: as a copy
from a `static const` zero array), `ext` (`WPIN_BARRIER_CALLS=1
WPIN_ZERO_COPY=1`) kept every file stock deleted, in every setting, on every
version, and adding `WPIN_BUFFER_BARRIER=1` kept no fewer. How `ext` kept
them is the same on every version: on E3 v3 a barrier after the call in 3 of
the 52 files and a pin in 50, in each setting; on E3 v1 a barrier after the
`bzero` call in 52/52 with the fortifying headers and a pinned memset site in
52/52 without them; on E5 v7 a zero-copy repair in 52/52. On E5 v8
(`explicit_bzero`) and v10 (a `volatile` function pointer) stock deleted no
wipe. In every row the dry run compiled to the stock listing, with and without
the buffer barrier, and with every switch off this build compiled to the
listing of the `22e7222` source built for the same GCC, for the file with and
without its wipe. Apart from r4 L, these sets are machine-made rewrites of its
52 generated files, and all of it is `-O2` only: no loop a model wrote was
measured. The denominator is the files the verdict reads as deleted by stock. The files
outside it are not counted: on E3 v2, two per version on clang (three on
clang-15) and one or two on GCC, among them files of which stock deleted only
part of the wipe; on every one of them, in every setting, the buffer barrier
left more zero stores than stock (63 file × setting rows, lab notes).

**Against a run of the same scripts on the builds before initialisers were
left out** (gcc-13 `ce1f515a…`, the build of the section after next, and builds
of the same source for gcc-10, 11, 12 and 14; that run is in the lab notes, not
in this README). Row by row over the 49,140 gcc rows (nine sets ×
52 files × 3 settings × 5 versions × 7 arms), every field, stderr included:
48,600 the same, 540 different, no verdict changed. Every difference is in an
arm with the buffer barrier (or its dry run) and in one of two files,
`sonnet_S_dbpass_r3` and `sonnet_S_pinpad_r2`, whose `memset` initialiser the
earlier build barriered where it was the buffer's only zero fill (without the
wipe; in E5 v5, v8 and v10 with it too) and this build does not: on each of
E5 v5, v8 and v10, a barrier in 6 file × setting rows per version before, in
none now. In some of those rows only the record differs; in the rest the
listing does too, by the barrier and the register allocation and labels
around it (read by hand on representative cells built with both builds). The
`pinned N` of the partial line falls by the barriers removed, which the
comparison rule written before the run did not anticipate; it was widened for
that after the run (lab notes).

**Read at run time** (the harness of the runs below), gcc-13 with
`-U_FORTIFY_SOURCE` and with the default `=3`, on the 20 files of five tasks of
each set: in r4 L and in E5 v7 the secret was readable in 20 of the 20 files
stock deleted and in 0 with `ext`; in E3 v2 in 20 of 20 with stock, 20 with
`ext`, and 0 with the buffer barrier added. The same counts and files as on
the earlier build. "Not readable" is about the window the harness reads.

**Files with no wipe.** The 39 files of the r2 corpus that the find step
labels as having no wipe written (one of them, `haiku_E_pinpad_r1`, clears a
`volatile` buffer in a loop, which the find step does not count as a wipe), at
`-O0` to `-Os` (195 compiles per arm), gcc-13, functions scope, with the
corpus's control function appended: with every switch off, with
`WPIN_BUFFER_BARRIER=1`, and with all three switches on, the listing equalled
stock's in 195/195 and no barrier was placed; `pin-gcc.sh` at `-O2` exited 4
for all 39 with the switch off and on. The files as written, in module scope:
195/195 in every arm.

**A build loaded into another GCC** (one wipe file, `-O2`): the gcc-13 build in
gcc-12 and in gcc-14 refused to install (`WipePinGcc: refusing to install:
built against GCC 13.3.0, loaded into GCC 12.4.0 …`; gcc rc 0, no record,
`pin-gcc.sh` 3); the gcc-12 build in gcc-13 could not be loaded at all (`cc1:
error: cannot load plugin …: undefined symbol: tree_code_type`; gcc rc 1, no
record, `pin-gcc.sh` 1, and no line from the plugin, which never ran). Each
build in its own GCC (12, 13, 14): a record, `pin-gcc.sh` 0.

**Fixture loop:** "all 88 cells as expected" as CI runs it, and 132 with each
`--previous-plugin` (the `22e7222` build and the build of the section after
next), 44/44 previous pairs byte-identical in each.

Not measured with these builds: levels other than `-O2` on the corpora (only
the no-wipe files at five levels); the run-time readout and the no-wipe files
on versions other than gcc-13; C++; LTO; the cost in time or size; and any
loop a model wrote.

### 2026-11-09, later: initialisers get no buffer barrier; GCC 10 to 14 rebuilt

Measured with the source as it was then (`2b6be2a6…`; *2026-11-10, later*
changed one stderr line). The scripts, the expectations written before
each run, the changes made to them afterwards, and the data are lab notes kept
outside this repository. What changed against the build of the next section
(`ce1f515a…`): a local buffer whose every zero fill is followed by a later use
gets no buffer barrier, with that use looked for both as before and with each
path stopped at the buffer's own clobber (*The buffer barrier*, "Initialisers
get none"); the not-a-local-buffer count on stderr no longer takes a store of
zero into one scalar inside a loop; the checker's `previous` group refuses a
previous plugin that is this plugin; `build-matrix.sh` resolves `--out` before
creating it and refuses the whole repository.

**Builds** (`scripts/build-matrix.sh --versions "10 11 12 13 14" --jobs 2`,
exit 0). Each row is a build of that source by that version's `g++`,
against that version's plugin headers; the sha256 are this machine's. The
gcc-13 build, made again into another directory, has the same sha256; the
source's sha256 was the same before and after the builds.

| GCC | `g++` | warnings | `libWipePinGcc.so` sha256 | `canon-vectors` |
|---|---|---|---|---|
| 10 | 10.5.0 | 0 | `968c683db975d34de1cf9fe6f8b9385d72957f232ee451d71ee199d39a055f4d` | 66 held, 0 disagreed |
| 11 | 11.5.0 | 0 | `d11291650d190e68a6164a96c2a7fb1621fbfe2c5e9d7b11818177746232c4c9` | 66 held, 0 disagreed |
| 12 | 12.4.0 | 0 | `5de6e151c40e35260002114ad3b038ec200f17fa0682d80b5d01d0a3833a790a` | 66 held, 0 disagreed |
| 13 | 13.3.0 | 0 | `10fc7a0012df20a2f126b0ac78e729afc06fa6e071c80206da4124687f72377e` | 66 held, 0 disagreed |
| 14 | 14.2.0 | 0 | `61b12cdf6f870bf858dc4ae9d47bb13481769aa31ee822426577d87fc3ac238f` | 66 held, 0 disagreed |

**Fixture loop** (gcc-13 build `10fc7a00…`). As CI runs it:
`run-gcc-fixture-loop.sh` rc 0, `check-gcc-fixture-loop.py` exit 0, "all 88
cells as expected" (loop 25, alone 7, shapes 19, stale 4, lto 3, xtu 4, switch
16, buffer 10). With `--previous-plugin` the `wipe-pin-v2` build `a023b047…`:
"all 132 cells as expected", the 44 pairs of the `previous` group
byte-identical; with `--previous-plugin` the build of the next section
(`ce1f515a…`): "all 132 cells as expected", its 44 pairs byte-identical too.
With `--previous-plugin` set to this build itself: exit 2, and the one
disagreement is `previous: the previous plugin is this plugin (both sha256
10fc7a00…); the group compares the plugin with itself`. The build of the next
section run as `--plugin`, CI form: exit 2, and its disagreements are the two
new cells only — `inloop-on` prints `… 1 of 1 barrier site(s) are on buffers
whose every zero fill is followed by a later use …`, and `initzero-on` places a
barrier (count 1), exits 0 and lacks the not-barriered line — so the new cells
tell the two builds apart. The `buffer` group with this build:

```
buffer (-O2)    pin-gcc.sh  switch  count/sites  reason/anchor/buffer    wipe in handle  control           asm=stock
loopbar-stock   -           -       -            -                       ABSENT          PRESENT           -          ok
loopbar-off     4           off     0/0          -/-/-                   ABSENT          PRESENT same=-    yes        ok
loopbar-on      0           on      1/1          loop-store/clobber/key  PRESENT         PRESENT same=yes  no         ok
loopbar-dry     4           on/dry  0/1          loop-store/clobber/key  ABSENT          PRESENT same=-    yes        ok
initbar-stock   -           -       -            -                       -               -                 -          ok
initbar-on      4           on      0/0          -/-/-                   -               - same=-          yes        ok
inloop-stock    -           -       -            -                       ABSENT          PRESENT           -          ok
inloop-on       0           on      1/1          loop-store/clobber/key  PRESENT         PRESENT same=yes  no         ok
initzero-stock  -           -       -            -                       -               -                 -          ok
initzero-on     4           on      0/0          -/-/-                   -               - same=-          yes        ok
```

**Corpora** (gcc-13 `-O2`; `-U_FORTIFY_SOURCE`, `=2` and the default `=3`; the
evaluation script of the next section, copied with only the plugin paths and
the arms changed; "kept" = `verdictOf`, the zero-store count and the count
difference all say so; the denominator is the files stock deleted):

| | stock deleted | `ext` kept (`WPIN_BARRIER_CALLS=1 WPIN_ZERO_COPY=1`) | **`+ WPIN_BUFFER_BARRIER=1` kept** | disagreeing readings |
|---|---|---|---|---|
| E3 v2 (wipe written as a loop), each of the 3 settings | 51 of 52 | 0 | **51/51** | 0 |

E3 v2 is 52 machine-made rewrites of generated files, each file's wipe
rewritten as a loop of zero stores; it is not code a model wrote in that form.
With all three switches and `WPIN_DRY_RUN=1` the `-S` was the stock `-S`, for
the file with and without its wipe, in 156/156 file × setting rows. The same
three switches on E3 v1 and v3, E5 v7 and r4 L kept 51/51 in each setting too.
Against the build of the next section with the same switches, the record's
`bufferBarriers` for the file with its wipe was the same in all 156 rows of
each of E3 v1, v2 and v3, E5 v7 and r4 L (180 sites in each set). It differs in
two places, both initialisers:

- E5 v8 (`explicit_bzero`) and v10 (a `volatile` function pointer), where the
  only zero fill a buffer barrier can read is a `memset` initialiser: the
  earlier build placed 12 barriers in 12 file × setting rows (2 files, both
  variants, 3 settings), every one counted on its stderr as initialiser-like;
  this build places 0 and prints the not-barriered line in the same 12 rows.
  No arm deleted a wipe of v8 or v10 (156/156 `WIPE_SURVIVED` in each arm).
- Two files, `sonnet_S_dbpass_r3` and `sonnet_S_pinpad_r2`, in every set:
  compiled without the wipe (the comparison side of the verdict), each keeps
  only a `memset` initialiser in the buffer; the earlier build barriered it and
  this build does not (3 barriers per file per set before, one per setting, 0
  now). Only `sonnet_S_dbpass_r3`'s `-S` differs; for `sonnet_S_pinpad_r2` only
  the record does. With the wipe both files compile to the same bytes on both
  builds, and the verdicts are the same. (This bullet said "one file … 6
  barriers per set" until 2026-11-10; a refuter recounted the rows.)

The small zero copies (*Not counted*), the fortifying headers' wrappers in
module scope (*What is different on GCC*), the residue probe (*The buffer
barrier*, "Initialisers get none") and the `--out` cases of `build-matrix.sh`
(*Building and running*) were measured with these builds, as those sections
say.

Not measured in this run: the corpora on gcc-10, 11, 12 and 14; levels
other than `-O2` on the corpora; the run-time readout on the corpora; C++;
LTO; the cost in time or size; and any loop wipe a model actually wrote. The
corpora on gcc-10, 11, 12 and 14 and the run-time readout on gcc-13 were
measured with the same builds on 2026-11-10 (the section above).

### 2026-11-09: the buffer barrier (`WPIN_BUFFER_BARRIER`), gcc-13

Measured with the build after the buffer barrier landed (`ce1f515a…`), before
initialisers were left out (the section above), gcc-13 only. The scripts, the
expectations written before each run, and the data are lab notes kept outside
this repository. The next section is the run with the build before the buffer
barrier landed (`58276997…`), in which `WPIN_BUFFER_BARRIER=1` was still a
refusal (the `bufferon-O2` cell, now gone).

**Build** (`scripts/build-matrix.sh --versions 13 --jobs 2`, exit 0): 0
warnings, sha256
`ce1f515adb80d1e2b52ef7a5c8f3ec36508c1ff74574edb4497170425be16274`, the same
bytes from a second build into another directory; `canon-vectors: 22 vectors,
8 mustFail, 66 checks held, 0 disagreed`.

**Fixture loop.** As CI runs it: `run-gcc-fixture-loop.sh` rc 0,
`check-gcc-fixture-loop.py` exit 0, "all 84 cells as expected" (loop 25, alone
7, shapes 19, stale 4, lto 3, xtu 4, switch 16, buffer 6). With
`--previous-plugin` the `wipe-pin-v2` build `a023b047…`: "all 128 cells as
expected", the 44 pairs of the `previous` group byte-identical. With
`--previous-plugin` the build `58276997…` (the build before this change):
"all 128 cells as expected", its 44 pairs byte-identical too — with every
switch off this build compiles the loop, the shapes, the switch-off cells and
`loopbar-off` to the bytes the build before it did. The `buffer` group:

```
buffer (-O2)   pin-gcc.sh  switch  count/sites  reason/anchor/buffer    wipe in handle  control           asm=stock
loopbar-stock  -           -       -            -                       ABSENT          PRESENT           -          ok
loopbar-off    4           off     0/0          -/-/-                   ABSENT          PRESENT same=-    yes        ok
loopbar-on     0           on      1/1          loop-store/clobber/key  PRESENT         PRESENT same=yes  no         ok
loopbar-dry    4           on/dry  0/1          loop-store/clobber/key  ABSENT          PRESENT same=-    yes        ok
initbar-stock  -           -       -            -                       -               -                 -          ok
initbar-on     4           on      0/0          -/-/-                   -               - same=-          yes        ok
```

The new checks were shown to fail: 8 copies of the CI-form lab, each with one
thing broken (the `on` record's count, anchor or reason, each resealed; the
`on` listing replaced by stock's; an instruction added to the control in the
`on` listing; a line appended to the dry listing; an extra initialiser-like
line in `initbar-on`'s stderr; the `off` record deleted), gave exit 2, and 3
for the deletion, as written down before the run; the unbroken copy gave 0.

**Corpora** (the prototype's evaluation script, kept with the lab notes,
copied with only the plugin paths and the arms changed; the earlier lab run's
reading and files, `-O2`, `-U_FORTIFY_SOURCE`, `=2` and the default `=3`;
"kept" = `verdictOf`, the zero-store count and the count difference all say
so; the denominator is the files stock deleted):

| | stock deleted | `ext` kept (`WPIN_BARRIER_CALLS=1 WPIN_ZERO_COPY=1`) | **`+ WPIN_BUFFER_BARRIER=1` kept** | disagreeing readings |
|---|---|---|---|---|
| E3 v2 (wipe written as a loop), each of the 3 settings | 51 of 52 | 0 | **51/51** | 0 |

E3 v2 is 52 machine-made rewrites of generated files, each file's wipe
rewritten as a loop of zero stores; it is not code a model wrote in that form.
On E3 v1 and v3, E5 v7 and r4 L (each 52 files, 3 settings), adding the switch
kept every file `ext` kept. The dry run with the switch on compiled to the
stock `-S`, the file with and without its wipe, in 780/780 file × setting
rows. On E5 v8 (`explicit_bzero`) and v10 (a `volatile` function pointer) no
arm deleted any wipe (156/156 each). With the same switches (none, or
`WPIN_BARRIER_CALLS=1 WPIN_ZERO_COPY=1`) this build and the build before it
(`58276997…`) gave the same `-S` and the same record apart from `context`, for
the file with and without its wipe, in all 1,092 file × setting rows of each
(7 sets × 52 files × 3 settings). Every row matched the prototype's run
outside this tree (`72ff8ae6…`): the same `-S` for stock, ext, the switch and
its dry run, and the same `bufferBarriers` block. (This build still placed
barriers on initialiser-only buffers: 12 on E5 v8/v10, counted on stderr as
initialiser-like; the section above measures the rule that removed them.)

Not measured with this build: gcc-10, 11, 12 and 14, levels other than `-O2`
on the corpora, the run-time readout, C++, LTO, the cost in time or size, and
any code a model wrote with a loop wipe.

### 2026-11-09: `wipe-pin-v3`, the two switches, GCC 10 to 14

Ubuntu 24.04 under WSL, x86-64, the Ubuntu packages of gcc-10 … gcc-14 with
their own `g++-N` and `gcc-N-plugin-dev`.

**Builds** (`scripts/build-matrix.sh --versions "10 11 12 13 14" --jobs 2`,
exit 0). Each row is a build of the source as it was then — before the buffer
barrier landed; the current source's builds are in the first section — by
that version's `g++`, against that version's plugin headers; the sha256 are
this machine's (another machine's compiler packages may give other bytes).
"Loads" is one compile of a three-line wipe at `-O2` with the build loaded
into its own GCC: a `wipe-pin-v3` record that `scripts/wpin_gcc_record.py`
accepts with every switch stated off, one site pinned, and `host.ident` equal
to that GCC's `-dumpfullversion`; `WPIN_ZERO_COPY=2` and, in that build,
`WPIN_BUFFER_BARRIER=1` each refused, no record.

| GCC | `g++` | warnings | `libWipePinGcc.so` sha256 | `canon-vectors` | loads | r4 L (below) |
|---|---|---|---|---|---|---|
| 10 | 10.5.0 | 0 | `831978b9c2da2853f6117cd8298513d1b95296f17511a1f7a8cbd2117e9e1c70` | 66 held, 0 disagreed | yes, `10.5.0` | not measured with this build |
| 11 | 11.5.0 | 0 | `ef7ad8ce0a09bd26fa0ae54354b4109cbd52dc5913915b437f3273a2f6d627af` | 66 held, 0 disagreed | yes, `11.5.0` | not measured with this build |
| 12 | 12.4.0 | 0 | `bfd0c0a4743daa27c85d279fb7e8b11b51d7dc736f77fbafed56cfaa286f48c1` | 66 held, 0 disagreed | yes, `12.4.0` | not measured with this build |
| 13 | 13.3.0 | 0 | `58276997c4630e3d212f633e4dbc095863241c66f50dcb283c862ec8f58e855f` | 66 held, 0 disagreed | yes, `13.3.0` | 51/51 kept in each `_FORTIFY_SOURCE` setting |
| 14 | 14.2.0 | 0 | `939156b34b3e66c67a4a2e61a7365e9b524c43ab2fdbb9100f251fb2ce2d2bf5` | 66 held, 0 disagreed | yes, `14.2.0` | not measured with this build |

The `canon-vectors` line is `canon-vectors: 22 vectors, 8 mustFail, 66 checks
held, 0 disagreed` for all five; `../evidence/testdata/digest-vectors.json` is
unchanged. The gcc-13 build, made again into another directory, has the same
sha256. Apart from the sections dated 2026-11-10 above and the builds and the
small-copy probe of *2026-11-09, later*, every other section of this README is
about gcc-13; nothing in this section says that the switches repair anything
on gcc-10, 11, 12 or 14 — the shapes they exist for were not measured there
with these builds.

**Fixture loop** (gcc-13 build `58276997…`). As CI runs it, without
`--previous-plugin`: `run-gcc-fixture-loop.sh` rc 0, `check-gcc-fixture-loop.py`
exit 0, "all 79 cells as expected" (loop 25, alone 8, shapes 19, stale 4, lto
3, xtu 4, switch 16). The 59 cells the loop had before read as expected with
every switch off; their expectations changed only in the stderr's list of
`unhandled` counters (nine) and the record's version. With `--previous-plugin`
set to the `wipe-pin-v2` build `a023b047…` (below): exit 0, "all 122 cells as
expected", and in all 43 pairs of the `previous` group (the loop's 20 plugin
cells, the 19 shapes, the four `off` cells) this plugin's `-S` listing is the
previous plugin's, byte for byte. The `switch` group:

```
switch (-O2)    pin-gcc.sh  switch  done/would  unhandled         site                    wipe in handle                    asm=stock
bzero-stock     -           -       -           -                 -                       ABSENT (oracle)                   -          ok
bzero-off       4           off     0/0         bzeroCall=1       -                       ABSENT (oracle)                   yes        ok
bzero-on        0           on      1/1         -                 bzero                   PRESENT (oracle)                  no         ok
bzero-dry       4           on/dry  0/1         -                 bzero                   ABSENT (oracle)                   yes        ok
chkvar-stock    -           -       -           -                 -                       ABSENT (oracle)                   -          ok
chkvar-off      4           off     0/0         memsetChk=1       -                       ABSENT (oracle)                   yes        ok
chkvar-on       0           on      1/1         -                 __builtin___memset_chk  PRESENT (oracle)                  no         ok
chkvar-dry      4           on/dry  0/1         -                 __builtin___memset_chk  ABSENT (oracle)                   yes        ok
zcopyagg-stock  -           -       -           -                 -                       ABSENT (oracle) [zcopy 0L/0S/0C]  -          ok
zcopyagg-off    4           off     0/0         zeroGlobalCopy=1  -                       ABSENT (oracle) [zcopy 0L/0S/0C]  yes        ok
zcopyagg-on     0           on      1/1         -                 aggregate               PRESENT (zcopy) [zcopy 2L/2S/0C]  no         ok
zcopyagg-dry    4           on/dry  0/1         -                 aggregate               ABSENT (oracle) [zcopy 0L/0S/0C]  yes        ok
zcopyhdr-stock  -           -       -           -                 -                       ABSENT (oracle) [zcopy 0L/0S/0C]  -          ok
zcopyhdr-off    4           off     0/0         zeroGlobalCopy=1  -                       ABSENT (oracle) [zcopy 0L/0S/0C]  yes        ok
zcopyhdr-on     0           on      1/1         -                 builtin                 PRESENT (zcopy) [zcopy 2L/2S/0C]  no         ok
zcopyhdr-dry    4           on/dry  0/1         -                 builtin                 ABSENT (oracle) [zcopy 0L/0S/0C]  yes        ok
```

- Read by hand, `handle` in the `on` listings against stock: `bzero-on` adds
  `pxor %xmm0, %xmm0` and two `movaps %xmm0` to the stack (32 bytes);
  `chkvar-on` keeps the call, `call __memset_chk@PLT` with the length in
  `%rdx`, and the frame grows by 8 bytes to hold it; `zcopyagg-on` and
  `zcopyhdr-on` add `movdqa vg_zeros(%rip), %xmm0`, `movdqa
  16+vg_zeros(%rip), %xmm1` and the two `movaps` of those registers to the
  stack. Every expectation of the group was written before its first run,
  including the two least certain ones: that stock gcc-13 `-O2` deletes a
  `__memset_chk` whose length is not a constant, and that `zcopyhdr` is form
  `builtin`.
- **The checker was shown to fail** on the new cells, one corruption at a time
  on a copy of the lab (16 corruptions, each exit 2 except a deleted record,
  exit 3): an `on` listing replaced by stock; a `dry` listing replaced by `on`;
  a record count edited without re-sealing (`digest-mismatch`); a record
  re-sealed with the switch off where it was set (`wrong-compile`); a site's
  form changed to `call`; the "nothing to pin" line deleted; an `off` exit code
  edited to 0; an `off` record deleted (exit 3); a stock listing replaced by
  one holding the copy (stock `PRESENT via zcopy`); one previous-plugin listing
  edited; one previous-group cell removed from the runner's list; the staged
  plugin's sha256 edited; a refusal line deleted; a record put where
  `WPIN_BUFFER_BARRIER=1` must leave none; a loop record re-sealed with a
  switch on; a loop record's `host.ident` re-sealed as `13.2.0`.

**Corpus files and rewrites** — a lab run outside this tree, gcc-13 `-O2`,
three `_FORTIFY_SOURCE` settings (`-U`; `-U -D…=2`; the default, which `-dM -E`
reads as 3), the find step's `FLAGS`, five arms: stock, the `wipe-pin-v2`
build `a023b047…` (orig), this build with no switch (off), with
`WPIN_BARRIER_CALLS=1 WPIN_ZERO_COPY=1` (ext) and the same with
`WPIN_DRY_RUN=1` (dry). "Kept" is the find step's `verdictOf` reading
`WIPE_SURVIVED` with the wipe span ablated as the comparison, over the files
whose wipe stock deletes; the denominators are those files.

| files | stock deletes | orig kept | off kept | **ext kept** | dry kept |
|---|---|---|---|---|---|
| 52 files of another corpus (r4 L) | 51 / 51 / 51 | 51 / 51 / 51 | 51 / 51 / 51 | **51 / 51 / 51** | 0 / 0 / 0 |
| the same 52, each wipe rewritten as `bzero` | 51 / 51 / 51 | 51 / 0 / 0 | 51 / 0 / 0 | **51 / 51 / 51** | 0 / 0 / 0 |
| … as a zeroing loop | 51 / 51 / 51 | 0 / 0 / 0 | 0 / 0 / 0 | **0 / 0 / 0** | 0 / 0 / 0 |
| … as `__builtin___memset_chk` | 51 / 51 / 51 | 49 / 49 / 49 | 49 / 49 / 49 | **51 / 51 / 51** | 0 / 0 / 0 |
| … as `memcpy` from a `static const` zero array | 51 / 51 / 51 | 0 / 0 / 0 | 0 / 0 / 0 | **51 / 51 / 51** | 0 / 0 / 0 |
| … as `explicit_bzero` (control) | 0 / 0 / 0 | – | – | – | – |
| … through a `volatile` function pointer (control) | 0 / 0 / 0 | – | – | – | – |

- In every row and setting the dry listing is the stock listing in 52/52
  files and the off listing is the orig listing in 52/52 — 1,092 (file,
  setting) pairs where this plugin with every switch off compiled to the bytes
  of the `wipe-pin-v2` plugin. On r4 L the ext listing is the orig listing too
  (52/52 in each setting) and no ext record has a barrier or a copy site: the
  shapes the switches exist for are not in those files' target functions, so
  r4 L cannot show the switches working. The rewrites can; they were made
  after each gap had been seen, so they show the gap closed, not strength on
  forms nobody wrote down.
- What the ext records say: `bzero` with the fortifying headers, a barrier in
  52 files (77 `bzero` sites; without them `bzero` is already a memset and is
  pinned); `__builtin___memset_chk`, a barrier in 3 files in each setting (the
  2 that orig loses, and 1 that also has a pinned memset); in the other 49 the
  pass found only a zero-fill `__builtin_memset` and pinned it (the `chkconst`
  reading: a constant object size lets GCC fold the checked call first); the
  `memcpy` rewrite, a copy site in 52 files, form `aggregate` under `-U`
  (74 sites, and 3 of form `builtin`) and `builtin` under the fortifying
  headers (77). The zeroing loop is not a shape the pass can see, with or
  without a switch (*Not counted*).
- 44 of the 51 `memcpy` rewrites kept by ext are kept only in the copy
  reading — the listing holds a load of the zero array and its store, and no
  zero store — in each setting; the other 7 have a zero store as well.
- Second and third readings: the zero-store reading (`asm_read2`, plus the
  copy reading) agrees with `verdictOf` in all 780 r4 L rows, all 2,340 rows
  of the `bzero`, loop and `__builtin___memset_chk` rewrites, and all 780 rows
  of the `memcpy` rewrite. In the two controls it disagrees in 1,175 of 1,560
  rows, always the same way: `verdictOf` reads the wipe as present (it is: the
  call is in the listing) and the zero-store reading counts nothing, because a
  call of `explicit_bzero` or a call through a pointer is not a zero store. The
  count of zero-writing instructions with and without the wipe (w − wo) agrees
  with `verdictOf` everywhere outside the same two controls.
- Every listing (with and without the wipe) and every verdict equals the row
  of an earlier lab run of the patches this code lands from (plugin
  `6f7db9a3…`, which wrote its new keys under `wipe-pin-v2`), in all 4,524
  rows compared: the move to v3 changed the record, not what the pass does.
- All 6,552 records of the off, ext and dry arms (with and without the wipe)
  are accepted by `scripts/wpin_gcc_record.py` with the switches each compile
  set as `expect`; 0 compiles left no record. Control function present in
  every compile; 0 build failures.

**With every switch off, the r2 corpus compiles as it did under
`wipe-pin-v2`.** Every file of `../eval/ai-generated/generated-corpus/r2/`
(720), the find step's `FLAGS`, `-O0` … `-Os`, module scope, live, with the
`wipe-pin-v2` build `a023b047…` and with this one (each copied in turn to the
same path): 3,585 (file, level) pairs compiled, and in all 3,585 the `-S`
output is byte-identical, the records are equal once the v3 additions,
`schemaVersion`, `evidenceDigest` and `context` are dropped, and stderr is
equal once the four new counters are dropped from its lines. The other 15
pairs are the same three files that do not compile with or without a plugin
(*2026-09-12* below). In all 3,585 v3 records the four new counters are 0 and
no block is enabled.

Not measured with this build: the repair on gcc-10, 11, 12 or 14 (the r4 L
column above); `zeroGlobalCopyCall`'s form; `-O` levels other than `-O2`
outside the fixture loop; whether the secret can be read back at run time; the
compile-time or run-time cost of the barriers; C++, LTO and real projects with
the switches on.

### 2026-09-11 and 2026-09-12: the `wipe-pin-v2` plugin

gcc-13 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), Ubuntu 24.04 under WSL, plugin
built with g++-13 13.3.0, 2026-09-11, and again 2026-09-12 for the barrier rule,
the `lto` cells and the `xtu` cells. These measurements are of the
`wipe-pin-v2` build `a023b047…`; the fixture-loop cells they describe read the
same with the 2026-11-09 build and every switch off (above).

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

**The xtu cells** (2026-09-12, the same plugin, `a023b047…`; GNU ld and
objdump 2.42). `run-gcc-fixture-loop.sh` rc 0, `check-gcc-fixture-loop.py`
exit 0, "all 59 cells as expected". For the 55 cells above, the checker's
output is byte-identical to that of a run of the loop as it was before these
cells, in another lab; only the new table and the total differ:

```
xtu (-O2, executable)  form  mode   rc  objects             wipe.c record         inlined  subject: handle                                          control: wipe_kept                     ==stock
xtu-nolto              none  stock  0   elf (io.o elf)      -                     no       PRESENT in secure_wipe (0 store(s)/0B/1 memset call(s))  PRESENT in wipe_kept (2 store(s)/32B)  -        ok
xtu-lto-stock          lto   stock  0   gcc-lto (io.o elf)  -                     yes      ABSENT in handle (0 store(s)/0B)                         PRESENT in wipe_kept (2 store(s)/32B)  -        ok
xtu-lto-pin            lto   pin    0   gcc-lto (io.o elf)  wipe-pin-v2/1/1/live  yes      PRESENT in handle (2 store(s)/32B)                       PRESENT in wipe_kept (2 store(s)/32B)  no       ok
xtu-lto-dry            lto   dry    0   gcc-lto (io.o elf)  wipe-pin-v2/0/1/dry   yes      ABSENT in handle (0 store(s)/0B)                         PRESENT in wipe_kept (2 store(s)/32B)  yes      ok
```

- `xtu-nolto`: `handle` calls `secure_wipe`, which is `endbr64; mov %rsi,%rdx;
  xor %esi,%esi; jmp <memset@plt>`: a length nothing in `wipe.c` can know, and
  a tail call.
- `xtu-lto-stock`: `handle` is `call derive`, `call use` and the stack-protector
  epilogue; the link inlined the helper and deleted the fill. `xtu-lto-dry` is
  that executable byte for byte (sha256 `0613216b…`), and its compile printed
  the dry-run line.
- `xtu-lto-pin`: the same `handle` with three more instructions after `call
  use`, `pxor %xmm0,%xmm0` and two `movaps %xmm0` to the stack. The barrier
  travelled in `wipe.o`'s GIMPLE and came with the inlined body; it emits no
  instruction. The record: one site, in `secure_wipe`, `destKind` `argument`,
  `lengthBytes` null, `followedByUse` null, `line` 3, `pinnedCount` 1; the
  compile printed nothing.
- The pinned and dry-run `wipe.o` record `-fplugin=<the plugin's path>` in their
  `.gnu.lto_.opts` section (the stock one does not); the stock link loaded
  nothing from it, and printed no WipePinGcc line (the checker requires none).
  GCC's `-flto` objects are not byte-comparable between compiles: `main.o`,
  compiled the same way in all three LTO cells, has three different sha256. The
  byte comparison is therefore of the executables.
- The control's 32-byte fill (two 16-byte stores of a zeroed register) is in
  `wipe_kept` in all four.
- A second run into another lab gave the same checker output and the same
  four executables, byte for byte.

**The first xtu fixture, and why it was replaced.** The expectations were
written before the first run, for a fixture whose control called `secure_wipe`
too (`wipe_kept` called it on a buffer `use` read afterwards), so the helper
had two callers. That run: `xtu-nolto`, `xtu-lto-stock` and `xtu-lto-dry` as
expected (in the two LTO builds the control's call inlined along with the
subject's), and:

```
xtu-lto-pin: secure_wipe was not inlined into handle (['call   1170 <secure_wipe.constprop.0>'] left): this cell cannot show a loss that inlining creates, nor a pin that survives one
xtu-lto-pin: control: secure_wipe not inlined into wipe_kept, where the subject's call is expected inlined
```

What happened, from the link's own reports on copies of those objects
(`-fopt-info-inline-all`, `-fdump-ipa-inline-details`): IPA-CP made a clone,
`secure_wipe.constprop.0`, with the length 32 propagated. In the stock build the
WPA inliner put the clone into both callers because that was estimated to grow
nothing (`overall growth 0`; `Inlining secure_wipe.constprop/29 size 12.` twice;
`Inlined 2 calls, eliminated 1 functions`), and in `handle` the inlined fill was
then deleted. With the barrier the clone's estimated size is one more (`self
size` 12 → 13, `estimated growth:1`), inlining it everywhere was no longer
free, and the small-function heuristic refused both calls (`call is unlikely and
code size would grow`; `Inlined 0 calls, eliminated 0 functions`). `handle` and
`wipe_kept` called the clone, which held the 32-byte fill (`pxor` and two
`movups` through `%rdi`). The wipe survived, out of line, and the cell, which is
about a pin surviving an inlining, could not show one: the plugin had changed
an inlining decision, not only a store. The fixture was changed, for both
loops, to the shape these cells are for: `secure_wipe`'s one caller is
`handle`, and the control is a memset of its own in `wipe_kept`. With one
caller the pinned helper is inlined (the table above). The subject's
expectations are the ones written before the first run; only the control's
changed, with its design.

**The checker was shown to fail** on the xtu cells, one corruption at a time on
a copy of the lab: `xtu-lto-pin`'s executable replaced by `xtu-lto-stock`'s →
exit 2 (`subject ABSENT in handle (0 store(s)/0B), expected PRESENT`; `pinned,
yet the executable is byte-identical to xtu-lto-stock's`); `xtu-nolto`'s
replaced by `xtu-lto-stock`'s → exit 2 (`secure_wipe was inlined into handle:
the helper was not opaque to its caller here, …`); `xtu-lto-dry`'s replaced by
`xtu-lto-pin`'s → exit 2 (`subject PRESENT …, expected ABSENT`; `told to change
nothing, yet the executable differs from xtu-lto-stock's`); `xtu-lto-pin`'s
`wipe.o` replaced by the non-LTO one → exit 2 (`wipe.o is elf, expected
gcc-lto`); the dry run's compile stderr emptied → exit 2 (`stderr lacks
'WipePinGcc: dry run: …'`); `xtu-lto-dry`'s record deleted → exit 3. Both
records are accepted by `../eval/repair-loop/lib/pin-record.mjs` with
everything the compile asked for as `expect` (`component: "WipePinGcc"`,
functions scope, `requested: ["secure_wipe"]`, the dry run, `-O2`, `module:
"wipe.c"`), 2/2; the same `xtu-lto-pin` record is refused when read as
WipePin's or as a dry run.

What the xtu cells do not cover: one fixture (one `external` helper, one call
site passing a constant length, `-O2`, an executable, x86-64), gcc-13's own LTO
through GNU ld's linker plugin, and nothing else — not `-shared`, not a helper
with several callers as a cell (the first fixture had two, above), not a
`static inline` helper in a header, not the corpus. The executables are
disassembled and never run.

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

**On the r2 corpus, `followedByUse` reads the same at every level, site by
site.** Measured
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
read `true` at every level. One other field of the joined sites does move with
the level:
`lengthBytes` of the three sites of `haiku_S_token_r3` (lines 18, 22 and 28)
is `null` at `-O0` and 32 at `-O1`..`-Os`. Their length is `token_size`, a
`const ssize_t` local initialised to 32; the `cfg` dump shows `memset (&token,
0, token_size.1_5)` at `-O0` and `memset (&token, 0, 32)` at `-O1`: by the
time the pass runs, the call carries the constant only when optimising.
Those three read `followedByUse: false` at all five levels. The join compares
sites; record-level counters move as well, and one does here: `unhandled.memsetChk`
is 0 at `-O0` and non-zero at `-O2` in 209 of the 360 files (measured 2026-09-12
with the same compiles), because the fortifying headers make a source `memset` a
`__builtin___memset_chk` whenever gcc optimises — so the `partial` line this
plugin prints reads differently at `-O0` and above for a reason that has nothing
to do with `followedByUse`. No other `seen` or `unhandled` counter differs in any
file. Controls in the
same run: `-O0` compiled twice, 0 differences and the same `evidenceDigest`
in 360/360 files; every level compiled again without `-g1`, records equal on
every field but `pinned[].line` in 1800/1800 — `context` and `evidenceDigest`
dropped before the comparison — with a line on all 1250 (site, level)
pairs either way. The older WipePinGcc build (`954b5b58…`, before the barrier
rule of *What counts as already pinned*) is no positive control here: what
changed in it is which sites count as already pinned, not how `followedByUse`
is answered. The same tool finds WipePin v1's 16 known level-dependent sites
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
  into it) holds two zero fills where the stock link holds one. A wipe helper
  in another unit, which only the link can inline, is graded by the `xtu`
  cells (above): the stock `-flto` link loses its fill, and the plugin at the
  compile of the helper's unit alone keeps it.
- C++: `WPIN_TARGET_FNS=_Z5wipe2i` resolves a non-`extern "C"` function and
  pins it (exit 0); `WPIN_TARGET_FNS=wipe2` reads `not-in-module` (exit 4).

## What it does not claim

- That a pin is a repair. The record says what was inserted; whether the wipe
  reached the object is the confirm step's question, answered by the stock
  observation.
- Anything about a wipe that is not a zero-fill `__builtin_memset` at the
  time `cfg` has run, with every switch off (see *Not counted*). With a switch
  on, the `bzero`, `__builtin___memset_chk`, zero-constant copy and loop-store
  shapes it covers are claimed only as far as *Measured* goes: the fixture
  loop's cells, and `-O2` on 52 files and machine-made rewrites of them (E3 v1
  to v3, E5 v4, v5 and v7) in three `_FORTIFY_SOURCE` settings, on gcc-13 and,
  with the builds of the current source, on gcc-10, 11, 12 and 14. A copy of 1, 2, 4,
  8 or 16 bytes without the fortifying headers is not reached at all, and a
  wipe that walks a pointer through a buffer gets no buffer barrier.
- Anything about copies of the secret outside the buffer, in registers or
  spill slots; or that the buffer barrier adds no store of the secret to
  memory — it makes the buffer live in memory, which is why a buffer that
  holds only an initialiser gets none.
- Anything about a GCC other than 13.3.0 beyond what *Measured, 2026-11-09*
  and *2026-11-10* say: that this source builds with gcc-10 … gcc-14 with 0
  warnings, that each build loads into its own GCC and writes an accepted
  record, for one probe file at `-O2` (*Not counted*) which zero-constant
  copies `WPIN_ZERO_COPY=1` records and which it does not reach, and the
  `-O2` corpus runs of 2026-11-10 (r4 L and its machine-made rewrites, in
  three `_FORTIFY_SOURCE` settings). A plugin loads only into the GCC it was
  built against. Nothing here says that the switches repair anything on
  gcc-10, 11, 12 or 14 at another level, in code other than those 52 files and
  their rewrites, or at run time (the run-time readout is gcc-13 only).
- That the switches repair anything beyond the shapes and files measured, or
  that they are free: their cost was not measured.
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
