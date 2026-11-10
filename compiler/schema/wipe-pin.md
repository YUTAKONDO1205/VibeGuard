# The `wipe-pin-v2` and `wipe-pin-v3` records

§1–§13 describe `wipe-pin-v2`, the record every writer and reader in this
directory produced and accepted until 2026-11-09. §14 fixes `wipe-pin-v3`,
which both writers write, and every reader listed in §14.10 accepts, since
then — and only it. v3 is v2 with the differences §14 lists, so §1–§13 stay
the description of every v2 record and of everything v3 does not change.

The record the two repair plugins write: `WipePin` (`../llvm-repair/`, a pass
plugin for clang/LLVM) and `WipePinGcc` (`../gcc-repair/`, a GCC plugin). One
compile of one translation unit, one record, at the path in `WPIN_OUT`. The
record is each plugin's own account of what it did to the intermediate
representation; it is never the verdict on whether a wipe reached the object
file. That is decided by re-running the stock observation with the plugin
loaded.

Everything below is taken from the two plugins' sources
(`../llvm-repair/src/WipePin.cpp`, `../llvm-repair/src/PinSelector.cpp`,
`../gcc-repair/src/WipePinGcc.cpp`, `../gcc-repair/src/Config.cpp`), their
READMEs, and the reader `../eval/repair-loop/lib/pin-record.mjs`. Where those
sources do not say the same thing, §13 lists it; nothing here settles such a
case silently. Measured values are the READMEs', with the toolchain they name
(clang 18.1.3 and gcc-13 13.3.0, unless a README names another version).

## 1. Writers and readers

| | component | compiler | source |
|---|---|---|---|
| writer | `WipePin` | clang 15 to 20 (a build per LLVM version, loaded into that clang only), a new-pass-manager module pass on the pipeline-start extension point | `../llvm-repair/src/WipePin.cpp` |
| writer | `WipePinGcc` | gcc-10 to 14 (a build per GCC version, likewise), a GIMPLE pass registered directly after `cfg` | `../gcc-repair/src/WipePinGcc.cpp` |
| reader | both | — | `../eval/repair-loop/lib/pin-record.mjs` (`validatePinRecord`, `readPinRecord`) |
| reader | `WipePinGcc` only | — | `../gcc-repair/scripts/wpin_gcc_record.py`, used by `pin-gcc.sh` |
| reader | `WipePin` (`wipe-pin-v3` only; any `wipe-pin-v2` until 2026-11-09) | — | the inline reader in `../llvm-repair/scripts/pin.sh`, which checks `schemaVersion` and the fields its exit code needs, and nothing else |
| reader | both (`wipe-pin-v3` only) | — | the compiler wrapper `../pin-wrapper/vgpin-cc` (§14.10) |

The table is as of `wipe-pin-v3`. Until 2026-11-09 the writers were built for
clang 18 and gcc-13 only and wrote `wipe-pin-v2`.

`pin-record.mjs` is the enforcement: the repair loop reads every record through
it, and a record it refuses turns the cell into a broken repair. It is strict
on purpose — an unknown field, a missing field, a wrong type, a digest that does
not re-derive, a count that contradicts the list it counts, or a record that
describes a different compile is a refusal. The rules in §11 are the ones it
applies. `wpin_gcc_record.py` applies the same rules to WipePinGcc records and
some further ones (§11, §13), so that `pin-gcc.sh` needs no node.

Until 2026-11-09 only `"wipe-pin-v2"` was accepted, and a `wipe-pin-v1` or
`v0` record was refused like any other record of the wrong shape. Each reader
accepts one version: the readers of this table have since moved to v3 and
accept v3 only, the compiler wrapper `../pin-wrapper/vgpin-cc` is one more
reader of the same kind, and the writers build against LLVM 15 to 20 and GCC
10 to 14 (§14.10, and the writers' READMEs).

## 2. The file, `evidenceDigest` and `context`

One JSON object on one line, followed by a newline, written once at the end of
the unit (WipePin: at the end of its pass's single run over the module;
WipePinGcc: at `PLUGIN_FINISH_UNIT`, after every function of the unit has been
through the pass), replacing whatever the path held. Every number is an integer.

`evidenceDigest` and `context` follow `interfaces.md` §5: `evidenceDigest` is
the lowercase-hex SHA-256 of the canonical serialisation of the record with the
top-level `context` and `evidenceDigest` removed; `context` is recorded and not
digested. WipePin computes it with `../llvm-pass/src/Record.cpp`; WipePinGcc,
which cannot link libLLVM, with `../gcc-repair/src/Canon.cpp`, whose output is
checked against every vector of `../evidence/testdata/digest-vectors.json` by
`canon-vectors`. Both readers re-derive it with code that shares nothing with
either writer (`../evidence/canon.mjs`; the serialiser in
`wpin_gcc_record.py`).

`context` holds exactly three keys in both writers:

| key | type | value |
|---|---|---|
| `timeSource` | string | `"SOURCE_DATE_EPOCH"` when that variable is set, `"wall-clock"` otherwise |
| `sourceDateEpoch` | integer or `null` | the variable's value read with `strtoll`, or `null` when it is not set |
| `generatedAt` | integer | the same value when the variable is set, `time(nullptr)` otherwise |

## 3. Top-level fields

| field | type | meaning |
|---|---|---|
| `schemaVersion` | string | `"wipe-pin-v2"` |
| `component` | string | `"WipePin"` or `"WipePinGcc"` |
| `module` | string | the translation unit's basename (WipePin: the filename of the module identifier, e.g. `t.c`, or `t.bc` under `-save-temps`; WipePinGcc: `lbasename(main_input_filename)`). Never a path. |
| `toolchain` | object | §3.1 |
| `optLevel` | object | `{speedup, size}`, §4 |
| `scope` | string | `"functions"` or `"module"`, §5 |
| `requested` | array of strings | §5 |
| `resolution` | array of objects | §5 |
| `dryRun` | boolean | `true` when `WPIN_DRY_RUN=1`: the record is written exactly as if pinning, and nothing is changed |
| `pinned` | array of objects | every zero-fill memset site in scope, §6 |
| `pinnedCount` | integer | pins actually made (WipePin: `setVolatile` calls; WipePinGcc: barriers inserted); `0` in a dry run |
| `wouldPinCount` | integer | listed sites that are not `alreadyVolatile`, counted in a dry run too |
| `seen` | object | §10 |
| `unhandled` | object | §10 |
| `evidenceDigest` | string | §2 |
| `context` | object | §2 |

### 3.1 `toolchain`

Exactly three keys: `digest`, `packages`, and one compiler key that names the
vendor. Nothing in it comes from the environment.

| component | compiler key and value | `packages` |
|---|---|---|
| `WipePin` | `clang`: `LLVM_VERSION_STRING` of the LLVM headers the plugin was compiled against (`"18.1.3"`) | `[{"name": "llvm", "version": <the same string>}]` |
| `WipePinGcc` | `gcc`: `gcc_version.basever` from the `plugin-version.h` the plugin was compiled against (`"13.3.0"`) | `[{"name": "gcc", "version": <the same string>}]` |

`digest` is the lowercase-hex SHA-256 of the canonical serialisation of
`{<compiler key>, packages}`. For gcc 13.3.0 that is
`59918b2e94592419773ed8982734ac2d9ed571a328feec4d8430d158995291e0`.
`pin-record.mjs` requires the compiler key the record's `component` names and
refuses the other (`toolchain-vendor`), requires exactly one package whose
`name` matches the vendor and whose `version` repeats the compiler key's value,
and re-derives `digest`.

## 4. `optLevel`

`{speedup, size}`, both integers. WipePin copies the `OptimizationLevel` its
pipeline-start callback is handed (`getSpeedupLevel()`, `getSizeLevel()`);
WipePinGcc copies the global options `optimize` and `optimize_size` as they
stand when the plugin loads, after the driver has decoded `-O`.

| flag | `WipePin` (clang 18.1.3) | `WipePinGcc` (gcc-13 13.3.0) | in `pin-record.mjs`'s table |
|---|---|---|---|
| `-O0` | `{0,0}` | `{0,0}` | yes, both |
| `-O1` | `{1,0}` | `{1,0}` | yes, both |
| `-O2` | `{2,0}` | `{2,0}` | yes, both |
| `-O3` | `{3,0}` | `{3,0}` | yes, both |
| `-Os` | `{2,1}` | `{2,1}` | yes, both |
| `-Oz` | `{2,2}` | `{2,2}` | yes, both |
| `-Ofast` | — | `{3,0}` | no |
| `-Og` | — | `{1,0}` | no |

Every value in the table was measured from the plugin's own record (WipePin's
`-Oz` later than the rest, §13). The reader compares `optLevel` with the flag the caller passed,
through the column of the component the caller says it loaded; a flag with no
row there (`-Ofast`, `-Og`) is refused as "no known optimisation pair" rather
than matched to a level whose pair it shares.

## 5. `scope`, `requested`, `resolution`

`scope` is `"functions"` when `WPIN_TARGET_FNS` names at least one function
(it wins over `WPIN_SCOPE`, and stderr says so when both are set), `"module"`
when only `WPIN_SCOPE=module` is set. §12 has the rest of the configuration.

`requested` is the names from `WPIN_TARGET_FNS` in the order given, each
trimmed of surrounding whitespace, empty items dropped, a repeated name kept
once (with a note on stderr); `[]` in module scope. The names are the ones the
object file uses: for WipePin the IR name `Module::getFunction` looks up, for
WipePinGcc the assembler name with GCC's leading `*` stripped. For C both are
the declared name; for C++ both are the mangled name.

`resolution` has one entry per requested name, in the same order, and is `[]`
in module scope:

| key | type | meaning |
|---|---|---|
| `name` | string | the requested name |
| `resolution` | string | `resolved`, `declaration-only` or `not-in-module` (the observer's `SUBJECTRES` words) |
| `exact` | boolean or `null` | `null` exactly when the name did not resolve |
| `linkage` | string or `null` | `null` exactly when the name did not resolve |

**`resolution` per vendor.**

- WipePin: `Module::getFunction(name)`; absent → `not-in-module`, a
  declaration → `declaration-only`, a definition → `resolved`.
- WipePinGcc: `resolved` when a function body of that name reached the pass;
  otherwise `declaration-only` when some body in the unit references the
  function (calls it or takes its address), which is the set of functions
  clang's module holds a declaration for; otherwise `not-in-module`. A
  function referenced only from a static initialiser reads `not-in-module` on
  GCC. A C99 `inline` definition reaches the pass only when it may be inlined:
  measured, it resolves at `-O2` and reads `declaration-only` at `-O0`.

**`exact` per vendor.**

- WipePin: `Function::isDefinitionExact()`. `false` for `linkonce_odr` (C++
  inline and template functions), `weak`, `available_externally` (a C99 inline
  definition, emitted only when optimising) and the other linkages whose body
  another unit's copy may replace.
- WipePinGcc: `true` exactly for the linkage words `external` and `internal`.

**`linkage` per vendor.**

- WipePin: LLVM's textual-IR spelling of the function's linkage: `external`,
  `internal`, `linkonce_odr`, `available_externally`, `weak`, `weak_odr`,
  `linkonce`, `private`, `common`, `extern_weak`, `appending`.
- WipePinGcc: the same vocabulary, restricted to the five words its mapping
  can produce, tested in this order:

  | test on the `FUNCTION_DECL` | word |
  |---|---|
  | not `TREE_PUBLIC` | `internal` |
  | `DECL_COMDAT` | `linkonce_odr` |
  | `DECL_WEAK` | `weak` |
  | `DECL_EXTERNAL` (the body reached the pass, so a gnu_inline / C99 inline definition this unit never emits) | `available_externally` |
  | otherwise | `external` |

  `DECL_COMDAT` is tested before `DECL_WEAK` because a C++ inline function is
  both: measured with a probe plugin at the same pass position, it has
  `TREE_PUBLIC=1 DECL_WEAK=1 DECL_COMDAT=1` (on ELF every one-only declaration
  is also marked weak). Weak first would call every C++ inline function `weak`
  where clang says `linkonce_odr`. A plain `__attribute__((weak))` function has
  `DECL_WEAK=1 DECL_COMDAT=0` and reads `weak`.

In module scope the functions in scope are, for WipePin, every function in the
module that has a body, in module order; for WipePinGcc, every function body
that reached the pass, ordered by `DECL_UID` (the order the declarations were
created, for C the order of first declaration).

## 6. `pinned[]`

Every zero-fill memset site in the functions in scope, including those that are
`alreadyVolatile` and, in a dry run, those that were not changed. Functions in
the order of §5 (in functions scope, the order of the requested names that
resolved); within a function, statement order (basic blocks in the function's
block order, statements in block order).

A zero-fill memset site is:

- WipePin: a `MemSetInst` (`llvm.memset`) whose value operand is a
  `ConstantInt` equal to zero. The element-wise atomic memset is not one (§10).
- WipePinGcc: a call for which `gimple_call_builtin_p(call, BUILT_IN_MEMSET)`
  holds and whose value argument is the constant zero (`integer_zerop`), as the
  body stands directly after `cfg`. A `memset` through glibc's fortifying
  `gnu_inline` wrapper is still `BUILT_IN_MEMSET` there. `= {0}` is not a site
  on GCC (it is the aggregate assignment `key = {}`), where clang lowers it to a
  zero-fill `llvm.memset`, which is.

| key | type | meaning |
|---|---|---|
| `function` | string | the function's name, as in `requested` |
| `index` | integer ≥ 0 | the site's ordinal among the zero-fill memsets of its function |
| `lengthBytes` | integer ≥ 0 or `null` | the length when it is a constant (WipePin: a `ConstantInt` with at most 63 active bits; WipePinGcc: an `INTEGER_CST` that fits a signed host integer, is ≥ 0 and ≤ 2^53 − 1); `null` otherwise |
| `destKind` | string | §7 |
| `alreadyVolatile` | boolean | §9 |
| `followedByUse` | boolean or `null` | §8 |
| `line` | integer ≥ 0 or `null` | the site's source line. WipePin reads it from debug info and writes `null` without `-g`. WipePinGcc reads the statement's location, which GCC keeps with or without `-g`, and writes `null` only when the location is unknown. |

## 7. `destKind`

The words of the observer's `classifyTarget` (`../llvm-pass/src/Extractors.cpp`):
`alloca`, `argument`, `global`, `other`.

| | WipePin (pre-SROA IR) | WipePinGcc (GIMPLE after `cfg`) |
|---|---|---|
| `alloca` | `getUnderlyingObject(dest)` is an `AllocaInst` | the destination is the address of an automatic `VAR_DECL` of this function |
| `argument` | the underlying object is an `Argument`, or a load from the stack slot the front end spilled one pointer parameter into and uses for nothing else | a `PARM_DECL`, a pointer that is one, or the address of an aggregate passed by value |
| `global` | the underlying object is a `GlobalValue` | a static or global `VAR_DECL` |
| `other` | anything else | anything else |

WipePinGcc follows the destination back through `&obj`, `&MEM[p + off]` (to
`p`), and SSA temporaries that copy, convert or offset a pointer. A local
pointer *variable* holding an address (`unsigned char *p = key; memset(p, …)`)
is not followed and reads `other` on both sides. A VLA or `__builtin_alloca`
buffer is reached through such a pointer and reads `other` on GCC; the LLVM
README says LLVM would read `alloca`.

## 8. `followedByUse`

Whether some other use of the buffer the memset writes can run after the site.
A zero-fill memset is also what clear-before-fill code looks like (and, on
clang, what `= {0}` lowers to); pinning one of those does nothing for the wipe.
A pinned site with `followedByUse: true` makes the plugin print its "partial"
line, and `pin.sh` / `pin-gcc.sh` count such sites as `followedByUseCount`.

| value | meaning |
|---|---|
| `true` | some use of the buffer is reachable after the site, as the component computes reachability below |
| `false` | none is: the site is the buffer's last word, the shape of a wipe |
| `null` | the destination is not a local stack object, so the question has no answer inside the function. In both writers this is exactly the case `destKind` is not `alloca`. |

Neither value says the wipe survives. Both computations run on the body as the
front end wrote it, for every recorded site, in a dry run too, before the
plugin changes anything. Both treat another memset into the same buffer as a
use, and neither treats the site itself as one.

**WipePin.** Uses are collected from the `AllocaInst` through GEP, bitcast,
addrspacecast, phi and select; when the address is stored into a stack slot,
every load from that slot counts as the address again (and so on through
further slots). `llvm.lifetime.*` and debug intrinsics are not uses. The
reachability question is asked twice:

1. `llvm::isPotentiallyReachable`, instruction to instruction, with a
   dominator tree and loop info built on the unmodified function (the
   `wipe-pin-v1` answer). A `false` here is final.
2. Only where (1) said `true`: a search over (block, the constant last stored
   into each *modelled slot* on this path) that follows every CFG edge except,
   at a `switch` whose condition is a load of a modelled slot read on the
   current walk of that block, the edges the stored constant does not select.
   A modelled slot is an integer `alloca` in the entry block every one of whose
   users is a non-volatile store into it of a `ConstantInt` of its own type or
   a non-volatile load from it of its type — the shape of clang's cleanup
   dispatch slot at `-O1` and above. At the memset every slot is unknown, and
   an unknown slot keeps all of its switch's edges. Past 65 536 explored
   states the search answers `true`.

**The soundness rule:** step 2 turns `true` into `false` only when every CFG
path from the memset to every use goes through a modelled switch edge that is
infeasible on that path; it never turns `false` into `true`. Whatever the model
does not describe stays plain reachability, which can add a partial line and
never remove one. (Measured over the erasure corpus, the refinement changed 16
sites, all `true` → `false`, all at `-O1`..`-Os`; the LLVM README has the list
and what the refinement still over-approximates.)

**WipePinGcc.** Computed during lowering, on GIMPLE before `ssa`. The buffer's
carriers are its `VAR_DECL` and, to a fixed point, every SSA name or
pointer-typed local variable assigned (or returned from a call) by a statement
that mentions a carrier. A use is any statement other than the site that
mentions a carrier at any operand depth (taking the address included), except
clobbers (`key ={v} {CLOBBER}`) and debug statements; a barrier asm that names
the buffer is a use. The search is breadth-first over basic blocks from the
site: the rest of its block, then every block reachable along any successor
edge (EH and abnormal edges included), each scanned whole, so a loop back into
the site's own block scans the statements before it too. There is no path
feasibility at all. GCC copies a clobber-only cleanup onto each exit rather
than dispatching through a shared block, so the dispatch edge WipePin's step 2
exists for does not arise (measured: the `loopreturn` shape reads `false,false`
at every level).

On both sides an address stored anywhere other than a stack slot (WipePin) or a
pointer-typed local (WipePinGcc) — a global, the heap, a struct field or array
element, a callee's memory — is not followed, and a use made through it is
missed. That direction can hide a partial line.

On the r2 corpus's erasure-family files, the 360 the repair loop measures,
neither writer's answer depends on the level: joined site by site to its `-O0`
reading, each of WipePin's 251 and WipePinGcc's 250 sites there reads the same
`followedByUse` at `-O1`..`-Os`
(`../eval/repair-loop/tools/fbu-levels.mjs`; the numbers and controls are in
both READMEs).

## 9. `alreadyVolatile`

`true` when the site was already pinned before this plugin looked at it. Such a
site is listed in `pinned[]`, left alone, and not counted in `pinnedCount` or
`wouldPinCount`.

- WipePin: `MemSetInst::isVolatile()` — the `llvm.memset`'s volatile operand is
  already `true`.
- WipePinGcc: the next non-debug statement in the site's basic block is an asm
  that is volatile, has a `"memory"` clobber, **and** has an input operand that
  is the memset's destination — the same pointer value (`operand_equal_p`), or
  the address of the same base declaration (`get_base_address` of an
  `ADDR_EXPR`, through conversions). That is the form of the plugin's own pin,
  `__asm__ __volatile__("" : : "g"(dest) : "memory")`, and of a barrier the
  source wrote in the same form. Measured forms that read `true`: `"r"(key)`
  for a local array (the `srcbarrier` shape), `"g"(&k)` for a local scalar, and
  `"r"(p)` for a pointer parameter passed to the memset unchanged. An operand
  the gimplifier first computes into a temporary (measured: `"r"(key + 16)`)
  puts that assignment between the memset and the asm, so the asm is not the
  next statement and the site is pinned.

  A barrier without that operand is not a pin, and a site followed by one is
  pinned like any other. A `"memory"` clobber alone does not make a store to a
  local observable when the local's address never leaves the function: gcc-13
  `-O2` deletes the zero fill of `uint64_t k` followed by
  `__asm__ __volatile__("" ::: "memory")`, and of one followed by a barrier
  whose only operand is another local (the `clobonly` and `otherbar` shapes).
  A barrier that names the buffer is also a later use of it (§8), so such a
  site reads `followedByUse: true`.

## 10. `seen` and `unhandled`

`seen` has exactly two integer keys:

| key | WipePin | WipePinGcc |
|---|---|---|
| `zeroFillMemsetInScope` | zero-fill memset sites in the functions in scope | the same |
| `zeroFillMemsetInModule` | zero-fill memset sites in every function of the module that has a body | zero-fill memset sites in every function body that reached the pass |

In both writers `zeroFillMemsetInScope` equals the length of `pinned[]`.

`unhandled` has exactly five integer keys, counted in the functions in scope
only. Each counts a memset-shaped operation the plugin leaves alone, so that
"nothing was pinned" is never read as "there was nothing to pin".

| key | WipePin | WipePinGcc |
|---|---|---|
| `libcallMemset` | a direct call to a non-intrinsic function named `memset` (e.g. under `-fno-builtin`) | a call to a function whose `DECL_NAME` is `memset` that is not `BUILT_IN_MEMSET` |
| `memsetChk` | a direct call to `__memset_chk` | `BUILT_IN_MEMSET_CHK`, or a call to a function named `__memset_chk` |
| `nonZeroFill` | a `MemSetInst` whose value is not a zero `ConstantInt` | a `BUILT_IN_MEMSET` whose value is not the constant zero |
| `atomicMemset` | `llvm.memset.element.unordered.atomic` | always `0`: GCC has no such operation |
| `inlineWrapperMemset` | a direct call to a non-intrinsic `memset.<suffix>`, the name clang gives glibc's fortifying `gnu_inline` wrapper | always `0`: GCC keeps the wrapper's call a `BUILT_IN_MEMSET`, which is a site |

## 11. Counts that must agree

`pin-record.mjs` refuses a record that breaks any of these:

1. Outside a dry run: `pinnedCount` = `wouldPinCount` = the number of `pinned[]`
   entries with `alreadyVolatile: false`.
2. In a dry run: `pinnedCount` = 0, and `wouldPinCount` = the number of
   `pinned[]` entries with `alreadyVolatile: false`.
3. `seen.zeroFillMemsetInScope` ≤ `seen.zeroFillMemsetInModule`.
4. `pinnedCount` ≤ `seen.zeroFillMemsetInScope`, and `wouldPinCount` ≤
   `seen.zeroFillMemsetInScope`.
5. In functions scope: every requested name has exactly one `resolution` entry,
   no entry names a function that was not requested, and every `pinned[]` entry
   is in a requested function.

A WipePinGcc site where no barrier could be placed (a memset that ends its
basic block with no fallthrough edge, which a nothrow `__builtin_memset` cannot)
would leave `pinnedCount` < `wouldPinCount`, breaking rule 1; the plugin says
so on stderr. It has never been observed.

`wpin_gcc_record.py` also refuses a WipePinGcc record in which:
`seen.zeroFillMemsetInScope` differs from the length of `pinned[]`;
`resolution` does not name exactly `requested`, in order, or a requested name
repeats; module scope has a non-empty `requested` or `resolution`;
`followedByUse` is `null` when `destKind` is `alloca` or not `null` when it is
not; `destKind` is not one of the four words; a resolved entry's `linkage` is
not one of the five GCC words or its `exact` does not follow from it; an
unresolved entry has a non-null `exact` or `linkage`; `atomicMemset` or
`inlineWrapperMemset` is not 0; `context` has any key but its three.

Beyond the record's own consistency, `pin-record.mjs` takes what the caller
asked of this compile — `component`, `scope`, `requested`, `dryRun`, `opt`,
`module` — and refuses a record that describes a different one
(`wrong-compile`).

## 12. Configuration: the environment, refusals, and when there is no record

Configured only by environment variables, the same four for both plugins, read
by the same logic (`../llvm-repair/src/PinSelector.cpp`; `../gcc-repair/src/Config.cpp`
is that file's logic and wording with POSIX calls). An unset variable and an
empty one are the same.

| variable | |
|---|---|
| `WPIN_OUT` | the record's path. Required. |
| `WPIN_TARGET_FNS` | comma-separated function names (§5) |
| `WPIN_SCOPE` | `module`: every function with a body in the unit. Any other value, with no `WPIN_TARGET_FNS`, is a refusal. |
| `WPIN_DRY_RUN` | empty or `0`: pin; `1`: record as if pinning and change nothing; anything else is a refusal |

When the plugin is loaded, before any configuration is read and before any
refusal, whatever is at `WPIN_OUT` is removed (a symlink as a link). So after a
compile, "there is a record" means this compile wrote it, and "no record" means
this compile wrote none. If something is there that cannot be removed, the
plugin refuses and touches nothing: `WPIN_OUT is a directory`, `WPIN_OUT is not
a regular file`, `cannot inspect WPIN_OUT (…)`, `cannot remove the previous
record at WPIN_OUT (…)`.

A refusal prints `<component>: refusing to install: <reason>` on stderr, writes
no record, and leaves the compile's exit status alone. The reasons from the
configuration are `WPIN_OUT not set`, `no target` (followed by a line saying
why), and `WPIN_DRY_RUN='<value>' is neither 0 nor 1`. WipePinGcc also refuses
when it was built against a different GCC (`plugin_default_version_check`) —
provided cc1 can load it at all: measured on 2026-11-10, the gcc-13 build
loaded into gcc-12 and into gcc-14 refused (no record, gcc rc 0), while the
gcc-12 build could not be loaded by gcc-13's cc1 (`undefined symbol:
tree_code_type`; gcc rc 1, no record, and no refusal line, since the plugin
never ran) — and it refuses when it is loaded into the LTO back end (`lto1`),
where its pass never runs; it ignores `-fplugin-arg-…` arguments and says so.

No record is written, besides a refusal, when the unit never reaches the point
where the record is written: WipePin in a compile under
`-Xclang -disable-llvm-passes` or on an LTO link line (it prints its
link-time line there, `../llvm-repair/README.md`); WipePinGcc under
`-fsyntax-only` or in `lto1`. When the record cannot be written, the plugin
says so and whether the code was changed. `pin.sh` and `pin-gcc.sh` turn "no
usable record" into exit 3. The complete list of stderr lines is in each
component's README.

## 13. Where the sources disagree

Reported here rather than resolved, apart from the first, which is resolved and
kept so the history is readable:

1. **Resolved: the reader was weaker than the writers.** `pin-record.mjs` now
   holds both components to what both writers do: `seen.zeroFillMemsetInScope`
   equal to the length of `pinned[]`; `destKind` one of the four words;
   `followedByUse` `null` exactly when `destKind` is not `alloca`; `exact` and
   `linkage` `null` for an unresolved name, and for a resolved one a `linkage`
   from LLVM's vocabulary with `exact` true exactly for `external`, `internal`
   and `private`; `unhandled.atomicMemset` and `inlineWrapperMemset` 0 on a
   WipePinGcc record; `resolution` in the order of `requested`, both empty in
   module scope. No real record breaks them: every `wipe-pin-v2` record in the
   lab directories of this work, 78,855 files (39,185 WipePin, 39,670
   WipePinGcc; 22,360 distinct evidence digests) from full repair-loop runs of
   both vendors, their red controls and plan replays, fixture loops and
   module-scope corpus sweeps, passes the reader with none of these rules
   broken. The keys of `context` are still not checked by it; see the next
   item.
2. **`context` is narrower in the Python reader than in `interfaces.md`.**
   `interfaces.md` §5 allows `context` to hold `host` and repository provenance
   as well; both writers write only the three keys of §2, and
   `wpin_gcc_record.py` refuses any other, while `pin-record.mjs` accepts any
   object.
3. **Resolved: WipePin at `-Oz`.** `pin-record.mjs` held `{2,2}` for WipePin at
   `-Oz` without a measurement; measured since with the plugin (clang-18,
   module scope): `-O0`..`-Oz` give `{0,0} {1,0} {2,0} {3,0} {2,1} {2,2}`.
4. **Resolved: `pin-record.mjs` pointed at a document that is not in the
   repository.** Its header now points here, and says what v2 changed about
   `followedByUse` (how WipePin computes it, §8) as well as what it may hold.
5. **What "already pinned" means differs by vendor by construction** (§9): a
   volatile flag on LLVM, a barrier of a specific form on GCC. A GCC site
   followed by a barrier of another form is pinned a second time, which is
   harmless; the rule exists because the earlier reading (any volatile asm with
   a `"memory"` clobber) left `clobonly` unpinned and its zero fill deleted.

## 14. `wipe-pin-v3`

Fixed on 2026-11-05 as a contract, before any writer or reader implemented
it. Since 2026-11-09 both writers (`../llvm-repair/`, `../gcc-repair/`) write
it, and every reader listed in §14.10 accepts it and refuses v2. v3 is v2 with
the differences below; whatever this section does not mention is exactly as
§1–§13 say.

The new fields come from six patches written and measured outside this tree:
WipePin and WipePinGcc putting a barrier after zero-fill calls they used to
only count (`WPIN_BARRIER_CALLS`), the same for copies from an all-zero
constant (`WPIN_ZERO_COPY`), and a source change that lets WipePin build
against LLVM 15 to 17. Those patches wrote their new keys under
`"wipe-pin-v2"`, which every v2 reader refuses (`unknown-field`); v3 is the
version those keys belong to. Where the two vendors' patches wrote different
shapes — `barrierCalls` and `zeroCopy` were lists of sites on WipePin and bare
counts on WipePinGcc, and WipePinGcc's `zeroGlobalCopy` counted calls that
WipePin counts separately — this section picks one shape and says which writer
changes.

This section is the contract, and it was written before any v3 writer
existed. What the writers do has been measured since, and those measurements
are in the writers' READMEs (*Measured* in `../llvm-repair/README.md` and
`../gcc-repair/README.md`); where a statement below was first written as a
requirement or an expectation and has been measured since, it says so and
names the README. The `llvm.ident` strings in §14.7 were read from the
compilers installed for this work (clang-15 to clang-20 and gcc-10 to gcc-14,
Ubuntu 24.04 packages); the example records in §14.11 are constructed, not
captured, and their digests were computed with `../evidence/canon.mjs` and
re-derived with `wpin_gcc_record.py`'s serialiser, which agree.

### 14.1 What changes

| | v2 | v3 |
|---|---|---|
| `schemaVersion` | `"wipe-pin-v2"` | `"wipe-pin-v3"` |
| top-level keys | the 16 of §3 | 20: the 16, plus `barrierCalls` (§14.4), `zeroCopy` (§14.5), `bufferBarriers` (§14.6) and `host` (§14.7). All four are written on every record, whatever the configuration |
| `unhandled` | 5 keys | 9 keys, the same set for both writers: the 5, plus `bzeroCall`, `inlineWrapperBzero`, `zeroGlobalCopy`, `zeroGlobalCopyCall` (§14.3) |
| configuration | 4 variables (§12) | 7: plus `WPIN_BARRIER_CALLS`, `WPIN_ZERO_COPY`, `WPIN_BUFFER_BARRIER`, each off by default (§14.2) |
| refusals | §12 | §12, plus a new variable that is neither `0` nor `1`, `WPIN_BUFFER_BARRIER=1` in a build that does not implement it, and on WipePin the version handshake: a module whose producer's major version is not the one the plugin was built against, a module whose intrinsic numbering differs from the build's, or a host whose own intrinsic table differs from the build's (§14.7) |
| `pinnedCount`, `wouldPinCount` | the `pinned[]` sites | unchanged. A barrier after a call or a copy is counted in its own block, never here |
| "something was repaired" | `pinnedCount > 0` | the sum of `pinnedCount`, `barrierCalls.barrierCount`, `zeroCopy.repairedCount` and `bufferBarriers.count` is positive (§14.8) |
| `evidenceDigest` | §2 | §2, unchanged; it covers the four new blocks (§14.8) |
| unchanged | | `component`, `module`, `toolchain`, `optLevel`, `scope`, `requested`, `resolution`, `dryRun`, `pinned[]`, `seen`, `context` |

With the three new variables unset, a v3 writer must change the code exactly
as the v2 writer did: the new blocks say `enabled: false` and list nothing, and
the four new `unhandled` keys only count. That is a requirement. It was
measured with the variables unset against the source of `22e7222` built for
the same compiler (on clang with the two build changes LLVM 15 to 17 need):
on WipePin's fixture loop, the `-S` of every four-arm v3 case equalled the
`22e7222` build's (`db3298cf…`; 11/11 with the current build); on
WipePinGcc's, the 44 pairs of the `previous` group were byte-identical with
the `22e7222` build (`a023b047…`); on the corpora of the writers' READMEs
(r4 L, and the E3 and E5 rewrites, 52 files each, `-O2`, three
`_FORTIFY_SOURCE` settings, clang-15 to 20 and gcc-10 to 14) every
switches-off `-S` equalled that build's, with and without the wipe; and the
tracked repair-loop rows, re-recorded on 2026-11-10, equal the v2 rows once
the four new keys are removed (§14.10). It is not measured on C++, on LTO, or
at levels other than `-O2` beyond the r2 rows.

### 14.2 Configuration

Three more variables, read by the same logic as `WPIN_DRY_RUN` (§12), after it
and in this order. The first one that fails is the refusal.

| variable | unset, empty or `0` | `1` | anything else: the refusal reason |
|---|---|---|---|
| `WPIN_BARRIER_CALLS` | off | zero-fill calls get a barrier (§14.4) | `WPIN_BARRIER_CALLS='<value>' is neither 0 nor 1` |
| `WPIN_ZERO_COPY` | off | copies from an all-zero constant are repaired (§14.5) | `WPIN_ZERO_COPY='<value>' is neither 0 nor 1` |
| `WPIN_BUFFER_BARRIER` | off | a barrier at the end of the lifetime of each stack buffer a zero fill writes and that is not only initialised (§14.6). Both writers in this tree implement it; a build that does not refuses with `WPIN_BUFFER_BARRIER=1 is not implemented by this build` | `WPIN_BUFFER_BARRIER='<value>' is neither 0 nor 1` |

The refusal is §12's: `<component>: refusing to install: <reason>` on stderr,
no record, and the compile's exit status left alone.

The record says which were on in the way v2 says `WPIN_DRY_RUN` was: one
boolean, `true` exactly when the variable is `1`. v2 has no configuration
block — `dryRun` is a top-level boolean — and v3 does not add one; each boolean
is the `enabled` of the block its variable switches (`barrierCalls.enabled`,
`zeroCopy.enabled`, `bufferBarriers.enabled`). A reader told what the caller
set compares it with `enabled` as it compares `dryRun` (`wrong-compile`).

### 14.3 `unhandled`

Exactly nine integer keys on both writers, counted in the functions in scope
only. The first five mean what §10 says, except that a call or copy a switch
repairs is no longer left alone and is not counted. A key whose shape a vendor
cannot produce is written as `0` on every record of that vendor, and the
readers refuse anything else, as v2 does for `atomicMemset` and
`inlineWrapperMemset`. One key set for both vendors rather than one per vendor,
so that a reader, a tracked row and a table of counters need one list.

| key | WipePin | WipePinGcc |
|---|---|---|
| `libcallMemset` | §10. With `WPIN_BARRIER_CALLS=1`, a plain call (not an `invoke`) with at least three arguments whose fill argument is a zero `ConstantInt` gets a barrier and is not counted | §10. `WPIN_BARRIER_CALLS` does not cover it: still counted |
| `memsetChk` | §10, with the exception `libcallMemset` has | §10. With `WPIN_BARRIER_CALLS=1`, a `BUILT_IN_MEMSET_CHK` whose fill argument is the constant zero (`integer_zerop`) gets a barrier and is not counted; a call to a non-builtin function named `__memset_chk` is still counted |
| `nonZeroFill` | §10 | §10 |
| `atomicMemset` | §10 | always `0` (§10) |
| `inlineWrapperMemset` | §10, with the exception `libcallMemset` has | always `0` (§10) |
| `bzeroCall` | a direct call or invoke of a non-intrinsic function named `bzero`. With `WPIN_BARRIER_CALLS=1`, a plain call with at least two arguments gets a barrier and is not counted | a call for which `gimple_call_builtin_p(call, BUILT_IN_BZERO)` holds, or of a function whose `DECL_NAME` is `bzero`. With `WPIN_BARRIER_CALLS=1`, one with at least two arguments gets a barrier and is not counted |
| `inlineWrapperBzero` | a direct call or invoke of a non-intrinsic function named `bzero.<suffix>`, the name clang would give a `gnu_inline` `bzero` wrapper as it gives `memset.inline` to memset's. With `WPIN_BARRIER_CALLS=1`, as `bzeroCall`. The spelling `bzero.inline` is what clang 18.1.3 with glibc 2.39 produced under `-D_FORTIFY_SOURCE=2` and `=3`, read as the barrier site's `callee` on the clang fixture loop's cells `v3-bzero-fort2` and `v3-bzero-fort3` (`../llvm-repair/README.md`); other clang versions and other C libraries were not read | always `0`: a `gnu_inline` `bzero` wrapper keeps the name `bzero` on GCC and is counted in `bzeroCall` |
| `zeroGlobalCopy` | a non-volatile `llvm.memcpy` whose source is a *zero constant* (below). With `WPIN_ZERO_COPY=1` it is repaired and not counted. A volatile one is already kept, and is neither counted nor listed | the copy as the compiler's own operation: an assignment that is not a clobber, whose left-hand side is not a register and whose right-hand side's base address is a zero constant (what the gimplifier makes of a constant-length `memcpy`); or a call for which `gimple_call_builtin_p(call, BUILT_IN_MEMCPY)` holds, with at least three arguments and a zero constant source. With `WPIN_ZERO_COPY=1` each gets a barrier and is not counted |
| `zeroGlobalCopyCall` | a direct call or invoke of a non-intrinsic function named `memcpy`, `__memcpy_chk` or `memcpy.<suffix>`, with at least three arguments and a zero constant source. With `WPIN_ZERO_COPY=1` a plain call gets a barrier and is not counted; an invoke stays counted | a call for which `gimple_call_builtin_p(call, BUILT_IN_MEMCPY_CHK)` holds, or of a function named `memcpy` or `__memcpy_chk` that is not the matching builtin, with at least three arguments and a zero constant source. With `WPIN_ZERO_COPY=1` it gets a barrier and is not counted |

A *zero constant* source:

- WipePin: `getUnderlyingObject(source)` is a `GlobalVariable` that is
  constant (`isConstant()`), has a definitive initializer
  (`hasDefinitiveInitializer()`), and whose initializer is the null value.
- WipePinGcc: a `VAR_DECL` that is `TREE_STATIC` and `TREE_READONLY`, not
  `DECL_EXTERNAL`, not `DECL_COMMON`, not `TREE_THIS_VOLATILE`, and whose
  `DECL_INITIAL` is absent or `initializer_zerop`. For a call, the declaration
  whose address the source argument is.

The vendor split follows §10's for memset: the compiler's own operation (LLVM's
intrinsic; GCC's builtin and its aggregate copy) on one side, the checked,
wrapper and library calls on the other. The same source line can land on
different keys on the two vendors, as it already can for memset
(`inlineWrapperMemset` on clang is a `pinned[]` site on GCC): a `memcpy` under
`-D_FORTIFY_SOURCE` is a `memcpy.inline` call on clang, and on GCC it stays
`BUILT_IN_MEMCPY` (form `builtin`; predicted by the analogy with §6 and
measured on gcc-13 13.3.0 with the fixture cell `zcopyhdr`,
`../gcc-repair/README.md`).

What the writers change from the patches: WipePinGcc splits its one
`zeroGlobalCopy` counter into the two keys above and writes
`inlineWrapperBzero` as `0`; WipePin counts an `invoke` of a zero-constant
copy, which its patch neither repaired nor counted.

### 14.4 `barrierCalls`

```json
"barrierCalls": {"enabled": true, "sites": [ … ], "barrierCount": 1, "wouldBarrierCount": 1}
```

| key | type | meaning |
|---|---|---|
| `enabled` | boolean | `WPIN_BARRIER_CALLS=1` |
| `sites` | array of objects | every zero-fill call in scope that gets a barrier (or would, in a dry run); `[]` when not enabled |
| `barrierCount` | integer ≥ 0 | barriers inserted; `0` in a dry run and when not enabled |
| `wouldBarrierCount` | integer ≥ 0 | the length of `sites` |

The calls (when not enabled, the same calls are counted in `unhandled`,
§14.3):

| | WipePin | WipePinGcc |
|---|---|---|
| memset family | a plain call of `memset`, `__memset_chk` or `memset.<suffix>` with at least three arguments and a zero `ConstantInt` fill | a `BUILT_IN_MEMSET_CHK` with a zero fill |
| bzero family | a plain call of `bzero` or `bzero.<suffix>` with at least two arguments | a `BUILT_IN_BZERO`, or a call of a function named `bzero`, with at least two arguments |

The barrier goes directly after the call and takes the destination (argument
0); the call itself is left as it is, so the check inside a fortify wrapper
stays. WipePin: `call void asm sideeffect "", "r,~{memory}"(ptr <dest>)` with
the call's debug location. WipePinGcc: the pin of §9,
`__asm__ __volatile__("" : : "g"(dest) : "memory")`.

`sites[]`, in the order of `pinned[]` (§6: functions in the order of §5,
statement order within a function):

| key | type | meaning |
|---|---|---|
| `function` | string | as in `requested` |
| `callee` | string | WipePin: the called function's name, one of `memset`, `__memset_chk`, `bzero`, or a name beginning `memset.` or `bzero.`. WipePinGcc: the `DECL_NAME` of the called function (spellings not enumerated: not measured) |
| `lengthBytes` | integer ≥ 0 or `null` | the length argument (argument 2 of the memset family, argument 1 of the bzero family) under §6's rule for a constant length |
| `line` | integer ≥ 0 or `null` | as `pinned[].line` (§6) |

A GCC barrier that cannot be placed (a call that ends its basic block with no
fallthrough edge) leaves `barrierCount` below `wouldBarrierCount`, which the
readers refuse, as §11 rule 1 does for a pin.

### 14.5 `zeroCopy`

```json
"zeroCopy": {"enabled": true, "sites": [ … ], "repairedCount": 1, "wouldRepairCount": 1}
```

| key | type | meaning |
|---|---|---|
| `enabled` | boolean | `WPIN_ZERO_COPY=1` |
| `sites` | array of objects | every copy from a zero constant in scope that is repaired (or would be, in a dry run); `[]` when not enabled |
| `repairedCount` | integer ≥ 0 | repairs made; `0` in a dry run and when not enabled |
| `wouldRepairCount` | integer ≥ 0 | the length of `sites` |

The repair, by `form`:

| `form` | writer | the copy | the repair |
|---|---|---|---|
| `intrinsic` | WipePin | `llvm.memcpy` or `llvm.memcpy.inline` | replaced by a volatile `llvm.memset` of the same destination, length and destination alignment, with the copy's debug location; an `llvm.memcpy.inline` (`__builtin_memcpy_inline`) by a volatile `llvm.memset.inline` of the same operands, which, like the copy it replaces, is never lowered to a library call (measured: the clang fixture cell `v3-zcopy-inline`, `-ffreestanding`). `callee` is `"llvm.memcpy"` for both (§14.9 C7) |
| `call` | WipePin | a plain call of `memcpy`, `__memcpy_chk`, `memcpy.<suffix>` | the barrier of §14.4 after it |
| `aggregate` | WipePinGcc | the aggregate assignment of §14.3 | the barrier of §9 after it, taking the address of the left-hand side |
| `builtin` | WipePinGcc | a `BUILT_IN_MEMCPY` call | the barrier of §9 after it (argument 0) |
| `call` | WipePinGcc | a `BUILT_IN_MEMCPY_CHK` call, or a call of a non-builtin `memcpy` / `__memcpy_chk` | the barrier of §9 after it (argument 0) |

When not enabled, a site of form `call` is counted in
`unhandled.zeroGlobalCopyCall` and one of any other form in
`unhandled.zeroGlobalCopy`, on both vendors. The volatile `llvm.memset` that
replaces a copy is made after the census: it is not in `pinned[]`, `seen`,
`pinnedCount` or `wouldPinCount`.

`sites[]`, in the order of `pinned[]`:

| key | type | meaning |
|---|---|---|
| `function` | string | as in `requested` |
| `form` | string | WipePin: `intrinsic` or `call`. WipePinGcc: `aggregate`, `builtin` or `call` |
| `callee` | string or `null` | WipePin: `"llvm.memcpy"` exactly when `form` is `intrinsic`, otherwise the called function's name (`memcpy`, `__memcpy_chk`, or a name beginning `memcpy.`). WipePinGcc: `null` exactly when `form` is `aggregate`, otherwise the `DECL_NAME` of the called function |
| `source` | string | the zero constant: WipePin the `GlobalVariable`'s IR name, WipePinGcc the `VAR_DECL`'s `DECL_NAME`; `""` when it has none |
| `destKind` | string | one of the four words of §7, for the destination: WipePin as §7 reads a memset's; WipePinGcc §7 applied to argument 0 of a call, or to the left-hand side of an aggregate assignment |
| `lengthBytes` | integer ≥ 0 or `null` | WipePin and a WipePinGcc call: the length argument under §6's rule. WipePinGcc `aggregate`: the size in bytes of the left-hand side's type when it is a constant within that rule |
| `line` | integer ≥ 0 or `null` | as `pinned[].line` (§6) |

On GCC the census must not change the body: `destKind` and `lengthBytes` are
read without marking any declaration addressable (marking the left-hand side's
base addressable belongs to placing the barrier, after the census and never in
a dry run), or a dry run would no longer compile to the stock output.

### 14.6 `bufferBarriers`

```json
"bufferBarriers": {"enabled": true, "count": 1, "sites": [{"function": "handle", "buffer": "key", "bytes": 32, "reason": "loop-store", "anchor": "clobber"}]}
```

A barrier at the end of a buffer's lifetime. Every other repair acts at the
wipe (it marks a memset, or puts a barrier right after a call or a copy); a
wipe written as a loop of zero stores has neither when the writers run, so
none of them reaches it. With `WPIN_BUFFER_BARRIER=1`, each stack buffer of a
function in scope that a zero fill writes gets an empty asm that reads the
buffer, directly before each end of the buffer's lifetime: WipePin puts
`call void asm sideeffect "", "r,~{memory}"(ptr %buf)` at each point where a
wipe's path leaves the buffer's lifetime: directly before each
`llvm.lifetime.end` of the `alloca` in a block reachable from the entry that a
wipe of the buffer reaches, and before each `ret` in a reachable block that a
wipe reaches before the lifetime ends or starts again — every such `ret` when the buffer has no
lifetime markers (every buffer at `-O0`, a variable-length array at every
level), and, at every level, a `ret` after a musttail call, where clang puts
the scope's lifetime end after the call and its `ret` in a block no path
reaches. Before a `ret` that follows a musttail call the barrier goes before
the call, since nothing may stand between the two. A lifetime end only
wipe-less paths reach is not a place. If a `ret` a wipe reaches is one the
`alloca` does not dominate, or a wipe reaches a block that ends in
`unreachable` (after a call that does not return, such as `exit`), the buffer
gets no barrier at all (*Buffers that get none*). Until 2026-11-10 a lifetime
end in a dead block was a place too, and a buffer with any lifetime end got
barriers there only: after a musttail call the barrier was deleted with the
dead block at `-O1` and above while the record counted it; and until that
evening every reachable lifetime end was a place, so a wipe only before `exit`
left its path uncovered while the record counted the other path's barrier
(the writer's README). WipePinGcc puts §9's
`__asm__ __volatile__("" : : "g"(&buf) : "memory")` directly before each
`buf ={v} {CLOBBER}`, or before every `return` when the buffer has none. The
asm writes nothing, but it is not claimed to leave what the program computes
untouched: the stores before it may now be read, so they are not dead, the
buffer must stay in memory, and code around it can change (the writers'
READMEs, *The buffer barrier*). With the switch off, both writers write
exactly `{"enabled":false,"count":0,"sites":[]}` on every record, and the code is
what it is without the switch (§14.1).

**Which buffers.** In the functions in scope only: a stack object (WipePin: an
`alloca`, also when the destination is a pointer reloaded from a stack slot
every store into which points into that same `alloca`, the store of the
slot's own value advanced included, so `while (n--) *p++ = 0;` and
`for (p = key; p < key + n; p++) *p = 0;` are followed;
WipePinGcc: a
`VAR_DECL` local to the function, also through a pointer-typed local every
assignment to which is the address of that same local) that is the
destination of

- a zero-fill memset or memset-family call: the zero-fill `llvm.memset` /
  `__builtin_memset`, and the calls of §14.4 (`memset`, `__memset_chk`,
  `memset.<suffix>`, `bzero`, `bzero.<suffix>`; on GCC `BUILT_IN_MEMSET_CHK`
  and a function named `bzero`), whether or not a switch repairs them;
- a store of the constant zero inside a loop, into an aggregate object (an
  array or a struct; on WipePin also a variable-length `alloca`). "Inside a
  loop" is LoopInfo on WipePin and a basic block on a cycle of the CFG on
  WipePinGcc. A volatile store is not counted;
- a copy from a zero constant (§14.3);

and that is not only initialised: some zero fill of it is not followed by a
later use of it (`reason`, below). A buffer whose every zero fill is followed
by one gets no barrier (*Buffers that get none*, below).

On GCC, `T b = {0};` is an empty-constructor assignment and is not a zero
write here. A zero fill whose destination is not such a buffer (an argument, a
global, the heap, a pointer the writer does not follow) gets no barrier, and
the writer counts those on stderr: `<component>: buffer barrier: N zero
fill(s) in scope write memory that is not a stack buffer of the function (an
argument, a global, the heap, or a pointer this pass does not follow); no
barrier covers them` (WipePinGcc says "local buffer", and of the stores of
zero inside a loop it counts there only those into an array element — an
index or pointer arithmetic on the way — not a store into one scalar such as
`g = 0` or `p->n = 0`).

The census reads each body before any repair of it is placed and changes
nothing; on GCC, marking the buffer addressable belongs to placing the
barrier, after the census and never in a dry run, so a dry run compiles to
the stock output.

| key | type | meaning |
|---|---|---|
| `enabled` | boolean | `WPIN_BUFFER_BARRIER=1` |
| `count` | integer ≥ 0 | barriers inserted; `0` in a dry run and when not enabled |
| `sites` | array of objects | one entry per barrier inserted (or, in a dry run, that would be): a buffer with two lifetime ends has two entries. `[]` when not enabled |

`sites[]`: functions in the order of §5; within a function, buffers in the
order of their first zero write; within a buffer, its anchors in statement
order.

| key | type | meaning |
|---|---|---|
| `function` | string | as in `requested` |
| `buffer` | string or `null` | the buffer's source name when the writer can tell it (WipePin: the variable a debug declaration names for the `alloca` — `dbg.declare`, the debug-record declare from LLVM 19, or the `dbg.assign` markers linked to the `alloca` under assignment tracking — else the `alloca`'s IR name if it has one; WipePinGcc: the `VAR_DECL`'s `DECL_NAME`), `null` otherwise. A release clang discards IR value names, so on WipePin it is `null` without `-g` |
| `bytes` | integer ≥ 0 or `null` | the buffer's size when it is a constant, under §6's rule; `null` otherwise |
| `reason` | string | the kind of the zero write the barrier is for: the first zero write into the buffer, in statement order, that no later use of the buffer follows (the wipe). `memset` (a zero-fill memset or memset-family call, as listed above), `loop-store` (a store of the constant zero inside a loop), `zero-copy` (a copy from a zero constant, §14.5). A write has a later use only when two walks from it both find one: §8's walk (WipePin: `laterUseOf`'s, through clang's cleanup dispatch; WipePinGcc: §8's, except that a statement that only computes an address of the buffer into a pointer, as each loop iteration does, is not a use), and a walk that stops each path where the buffer's lifetime ends or starts again (WipePin: its `llvm.lifetime.end` or `llvm.lifetime.start`, or the re-execution of a variable-length array's `alloca`, and neither a store that only advances a pointer kept in a stack slot nor a comparison of the buffer's address is a use there; WipePinGcc: its `{CLOBBER}`). Both walks over-approximate the paths, so on the paths the rule errs towards "a later use", that is, towards leaving a buffer out; not on the uses: an address stored anywhere but a pointer slot (a field of a local struct) is not followed, so an initialiser used afterwards only through such a copy reads as a wipe and gets a barrier (measured on one probe, both writers). Both walks read the IR (GIMPLE) the writer runs on, so a use the optimiser removes later still counts |
| `anchor` | string | where the barrier goes. WipePin: `lifetime-end` (directly before a reachable `llvm.lifetime.end` of the buffer that a wipe reaches) or `ret` (before a reachable `ret` a wipe of the buffer reaches before its lifetime ends, or before the musttail call that `ret` follows). WipePinGcc: `clobber` (directly before the buffer's `{CLOBBER}`) or `ret` |

**Buffers that get none.** Two kinds of buffer that a zero fill writes get no
barrier and no `sites` entry; the keys above are fixed, so the writer counts
each kind in one stderr line:

- an initialiser-only buffer, whose every zero fill is followed by a later use
  (`reason`, above): `<component>: buffer barrier: N buffer(s) not barriered:
  every zero fill is followed by a later use (read as an initialiser; a wipe
  that later code still touches, even code the optimiser removes, is counted
  here too)`. The line does not say the buffer held no wipe: a wipe followed by
  code that touches the buffer and that the optimiser later removes is counted
  here too, and stock's deletion of it stands (measured on one probe of each of
  three such shapes, clang-18 and gcc-13, `-O2`; the writers' READMEs). For an
  initialiser there is no wipe to keep, and a barrier would keep the buffer's last stores,
  typically the secret itself, in memory until its lifetime ends (measured
  with probes on clang 18.1.3 and gcc-13 13.3.0 at `-O2`: a buffer cleared,
  then given a copy of a secret and read, never wiped, left copies of the
  secret below the caller's stack pointer after the return with the builds
  that barriered it — 2 per probe on clang, 1 on gcc — and none with stock or
  with the current builds; the writers' READMEs). clang emits no lifetime
  markers at `-O0`, so there a buffer declared in a loop body and wiped in
  each iteration reads as an initialiser and gets none;
- on WipePin, a buffer where a reachable `ret` a wipe reaches is not
  dominated by the `alloca`, or where a wipe reaches a block that ends in
  `unreachable`, or that has no place at all: `WipePin: buffer barrier: N buffer(s)
  not barriered: the buffer does not dominate a return its wipe reaches, or
  there is no place (an alloca or variable-length array inside a branch or
  loop, or a function that does not return)`.

Until 2026-11-10 the two lines read `… later use (initialiser-like, not a
wipe)` and `… the buffer does not dominate a return (an alloca …)`. Builds
made before these rules (2026-11-09) placed a barrier on initialiser-only
buffers and printed `<component>: buffer barrier: N of M barrier site(s) are
on buffers whose every zero fill is followed by a later use
(initialiser-like, not a wipe)`; no build of the current source prints that
line. A pinned memset with `followedByUse: true` (§8) is unchanged: the
pin is placed, and only the buffer barrier is withheld.

What was measured with these writers, and what was not, is in
`../llvm-repair/README.md` and `../gcc-repair/README.md` (*The buffer
barrier* and *Measured*). In short, with the builds of the current source: on
the fixture loops (clang-18, gcc-13) a loop wipe that stock deletes at `-O2`
is kept with the switch on, a dry run compiles to the stock bytes, and on
clang the IR left in each placement cell passes LLVM's verifier, and in the
four cells that check it (musttail at `-O2` and `-Os`, two exits, a loop bounded
by an address comparison) the barriers the record counts are still in the
optimised IR — which is not true in general: the optimiser may hoist two
barriers on two paths into one block; on E3
v2 — 52 machine-made rewrites of generated code with the wipe written as a
loop, all of one template (an index loop with a constant bound), not code a
model wrote in that form — every file stock deleted at `-O2` was kept, in three
`_FORTIFY_SOURCE` settings (unset, 2, and 3 on clang or the compiler's default
on GCC, which is 3 on gcc-12 to 14 and 2 on gcc-10 and 11, where 3 does not
exist), on clang-15 (49/49), clang-16 to 20 (50/50 each), gcc-10, 11 and 14
(50/50 each) and gcc-12 and 13 (51/51 each). The denominator is the files
the verdict reads as deleted by stock; the files outside it (two or three per
version on clang, one or two on GCC, among them files of which stock deleted
only part of the wipe) are not counted, and on every one of them, in every
setting, the barrier left more zero stores than stock (63 file × setting
rows). On the 39 files of the r2 corpus
that the find step labels as having no wipe written, with the switch on,
clang-18 and gcc-13 compiled every file at `-O0` to `-Os` to the stock `-S`
and placed no barrier. Not measured: the cost in run time or code size, any
loop a model wrote, levels other than `-O2` on the rewrites, C++ and LTO.

### 14.7 `host`

The version handshake: which compiler the plugin is running in, read from that
compiler, against the version the plugin was built for. A WipePin built
against another major version of LLVM can load into clang, run, find nothing
to pin and write a record (measured outside this tree: the clang-18 build
loaded into clang-19 printed its `nothing to pin` line and exited 0). A
WipePinGcc built against another GCC is refused by cc1's own version check
when cc1 can load it, and otherwise fails to load (§12); either way there is
no record.

```json
"host": {"ident": "Ubuntu clang version 18.1.3", "identMajor": 18, "builtMajor": 18, "checked": true, "intrinsicsCompared": null}
```

| key | type | WipePin | WipePinGcc |
|---|---|---|---|
| `ident` | string or `null` | the first operand of the module's `!llvm.ident`, with every parenthesised group (nested ones included) and the whitespace directly before it removed, an unmatched `)` removed, and surrounding whitespace trimmed. `null` when the module has no `!llvm.ident` or its first operand is not a string | the `basever` of the `plugin_gcc_version` cc1 hands `plugin_init` — the running compiler's, e.g. `"13.3.0"` |
| `identMajor` | integer ≥ 1 or `null` | the decimal integer directly after the first `clang version ` in `ident`; `null` when `ident` is `null` or has no such text | the decimal integer before the first `.` of `ident` |
| `builtMajor` | integer ≥ 1 | `LLVM_VERSION_MAJOR` of the headers the plugin was compiled against: the integer before the first `.` of `toolchain.clang` | the integer before the first `.` of `gcc_version.basever` from `plugin-version.h`: that of `toolchain.gcc` |
| `checked` | boolean | `true` exactly when `identMajor` is not `null` | always `true`: `plugin_default_version_check` passed before the plugin installed, comparing `basever`, `datestamp`, `devphase`, `revision` and `configuration_arguments` |
| `intrinsicsCompared` | integer ≥ 0 or `null` | `null` when the build does not check its intrinsic numbering against the module's; otherwise how many `llvm.`-prefixed declarations of the module it checked (check 2 below; the component's README says which). Check 3, which asks the host about every name of the build's table whatever the module declares, is not counted here. A disagreement is a refusal, so a record never shows one | always `null` |

The parenthesised groups are removed because they hold build identifiers,
repository URLs and, for a clang built from a local checkout, the checkout's
absolute path, which interfaces.md §5 keeps out of every record; the version
the handshake needs is outside them. Read from the installed compilers:

| compiler | `!llvm.ident` / version | `ident` | `identMajor` |
|---|---|---|---|
| clang-15 | `Ubuntu clang version 15.0.7` | `Ubuntu clang version 15.0.7` | 15 |
| clang-16 | `Ubuntu clang version 16.0.6 (23ubuntu4)` | `Ubuntu clang version 16.0.6` | 16 |
| clang-17 | `Ubuntu clang version 17.0.6 (9ubuntu1)` | `Ubuntu clang version 17.0.6` | 17 |
| clang-18 | `Ubuntu clang version 18.1.3 (1ubuntu1)` | `Ubuntu clang version 18.1.3` | 18 |
| clang-19 | `Ubuntu clang version 19.1.1 (1ubuntu1~24.04.2)` | `Ubuntu clang version 19.1.1` | 19 |
| clang-20 | `Ubuntu clang version 20.1.2 (0ubuntu1~24.04.3)` | `Ubuntu clang version 20.1.2` | 20 |
| gcc-10 … gcc-14 | `-dumpfullversion` 10.5.0, 11.5.0, 12.4.0, 13.3.0, 14.2.0 | the same strings | 10 … 14 |

(The clang column is the first `!{!"…clang…"}` metadata line of `-S -emit-llvm`
for a one-line C file. For GCC the column is `-dumpfullversion`; that the
`basever` a plugin receives is the same string is measured for gcc-13 only,
where the plugin's own `basever` is the `13.3.0` of §3.1 and the version check
makes the host's equal to it.)

**When the versions disagree there is no record.** WipePin compares
`identMajor` with `builtMajor` when its pass runs, before it reads or changes
anything; on a difference it prints

```
WipePin: refusing to install: the module was produced by clang <identMajor> (llvm.ident "<ident>") and this plugin was built against LLVM <builtMajor>
```

writes no record, and changes nothing. The check runs when the pass does,
because the module does not exist when the plugin loads; it is reported with
the refusal prefix of §12 so that one search finds every refusal. A module
compiled from one source file carries one `!llvm.ident` operand; one linked
from several can carry more, and then every operand is compared (any
difference refuses) while `ident` and `identMajor` record the first. If the
build checks its intrinsic numbering (`intrinsicsCompared` not `null`), it
checks twice more, and a disagreement in either refuses with a reason that
begins `intrinsic table mismatch: `: (2) for each `llvm.`-prefixed declaration
of the module that the build's table knows, the number the host gave that
declaration against the number the build's own headers give the name; (3) for
each name in the build's table, whatever the module declares, the number the
host's own `lookupIntrinsicID("llvm.<name>")` gives (`Function::` up to LLVM
19, `Intrinsic::` in 20; libLLVM's, so the host answers) against the build's.
Check 3 does not depend on the module, so it also refuses, in the wrong host,
IR that declares none of the table's intrinsics, which checks 1 and 2 pass
when the IR's `!llvm.ident` names the build's version or is absent (measured
2026-11-10 with the current builds: front-end IR whose only `llvm.*`
declaration is `llvm.objectsize`, with and without `!llvm.ident`, read by
clang-19 with the LLVM 18 build, clang-17 with the LLVM 18 build and clang-18
with the LLVM 19 build, with and without `WPIN_BARRIER_CALLS=1`: 12/12
refused, no record, the `-S` equal to that clang's stock `-S`; the build
before check 3 accepted such IR in clang-19 and wrote a record with
`intrinsicsCompared: 0`; `../llvm-repair/README.md`).

**When there is nothing to compare there is a record.** A module with no
`!llvm.ident`, or whose `ident` names no clang version, is not refused: the
record says `checked: false`, and WipePin says so in one stderr line,

```
WipePin: the module's llvm.ident names no clang version (<"ident" or absent>); the host compiler was not checked against LLVM <builtMajor>
```

So a written record has `identMajor` equal to `builtMajor` or `null`, never
another number, and readers refuse a record that says otherwise.

The handshake is a check that runs only when the plugin loads and its pass
runs. A plugin that fails to load, or a host that never runs the pass, is not
covered by it (a wrapper that compares versions before starting the compiler
is the place for those). In the matrix of the LLVM 15 to 20 builds and
clang-15 to 20 (each clang with each build, on three inputs; measured
2026-11-09 and again 2026-11-10 with the current builds), 18 of the 90
cross-version compiles reached the pass and were refused by it, and 72 failed
in clang before the pass ran — a symbol lookup error (clang rc 127, 28 of
them), clang-15 failing to parse the IR a newer clang wrote for that build (rc
1, 5), or a crash (rc 1 or 139, the rest; which of the two a given pair gave
varied between runs). Those 72 are clang's own failures, not the handshake. None of the 90
left a record or made `pin.sh` exit 0.

`host` is not interfaces.md §5's `context.host`, which names the machine and
which neither writer writes; this block is about the compiler, is reproduced
by a re-run with the same compiler and plugin, and is therefore digested.

### 14.8 `evidenceDigest`, and what counts as a repair

The digest rule is §2's, unchanged: SHA-256 of the canonical serialisation
(interfaces.md §5) of the record without the top-level `context` and
`evidenceDigest`. The four new blocks are inside it. `context` keeps exactly
its three keys.

v3 adds no kind of value (strings, integers ≥ 0, booleans, `null`, arrays,
objects), so the GCC writer's canonicaliser `../gcc-repair/src/Canon.cpp`
needs no change, and nothing in `canon-vectors` or
`../evidence/testdata/digest-vectors.json` changes (its 22 vectors already
cover key order inside arrays of objects, `null`, string escaping and
non-ASCII text). `toolchain` and its digest are unchanged.

A compile *made a repair* when `pinnedCount + barrierCalls.barrierCount +
zeroCopy.repairedCount + bufferBarriers.count` is positive. That sum, not
`pinnedCount` alone, is what `pin.sh` and `pin-gcc.sh` test for their exit
status 4 ("a record was written and nothing was repaired"): with
`WPIN_BARRIER_CALLS=1`, a fortified wipe is repaired by a barrier while
`pinnedCount` is 0. Like `pinnedCount`, the sum says what the plugin did to the
intermediate representation, never whether a wipe reached the object file.

### 14.9 Rules the readers apply to v3

Every rule of §11 still applies. In addition, a v3 reader refuses a record in
which any of these fails. Structure first (refused as `missing-field`,
`unknown-field` or a type problem, before any consistency rule is checked):

- **S1** the top-level keys are exactly the 20 of §14.1, and `schemaVersion`
  is `"wipe-pin-v3"`;
- **S2** `unhandled` has exactly the nine keys of §14.3, each an integer ≥ 0;
- **S3** `barrierCalls` has exactly `enabled` (boolean), `sites` (array),
  `barrierCount`, `wouldBarrierCount` (integers ≥ 0); each site exactly
  `function`, `callee` (non-empty strings), `lengthBytes`, `line` (integer ≥ 0
  or `null`);
- **S4** `zeroCopy` has exactly `enabled`, `sites`, `repairedCount`,
  `wouldRepairCount`; each site exactly `function` (non-empty string), `form`
  (string), `callee` (non-empty string or `null`), `source` (string),
  `destKind` (one of the four words of §7), `lengthBytes`, `line` (integer ≥ 0
  or `null`);
- **S5** `bufferBarriers` has exactly `enabled`, `count`, `sites`; each site
  exactly `function` (non-empty string), `buffer` (non-empty string or
  `null`), `bytes` (integer ≥ 0 or `null`), `reason` (`memset`, `loop-store`,
  `zero-copy`), `anchor` (`lifetime-end`, `ret`, `clobber`);
- **S6** `host` has exactly `ident` (string or `null`), `identMajor` (integer
  ≥ 1 or `null`), `builtMajor` (integer ≥ 1), `checked` (boolean),
  `intrinsicsCompared` (integer ≥ 0 or `null`).

Then consistency (refused as `inconsistent`, or the problem named):

- **C1** a block whose `enabled` is `false` has `sites: []` and every count 0;
- **C2** `barrierCalls` enabled: `wouldBarrierCount` is the length of `sites`;
  in a dry run `barrierCount` is 0, otherwise it equals `wouldBarrierCount`;
- **C3** `zeroCopy` enabled: the same with `repairedCount` and
  `wouldRepairCount`;
- **C4** `bufferBarriers` enabled: in a dry run `count` is 0, otherwise it is
  the length of `sites`;
- **C5** in functions scope, every site of the three blocks is in a requested
  function;
- **C6** `host`: `checked` is `true` exactly when `identMajor` is not `null`;
  a non-null `identMajor` equals `builtMajor`; `identMajor` re-derives from
  `ident` (WipePin: the digits after the first `clang version `; WipePinGcc:
  the digits before the first `.`); `ident` contains neither `(` nor `)`;
  `builtMajor` is the integer before the first `.` of the record's
  `toolchain.clang` or `toolchain.gcc`;
- **C7** per vendor. WipePin: every `zeroCopy` site's `form` is `intrinsic` or
  `call`, its `callee` is `"llvm.memcpy"` exactly when the form is
  `intrinsic` and otherwise `memcpy`, `__memcpy_chk` or a name beginning
  `memcpy.`; every `barrierCalls` site's `callee` is `memset`, `__memset_chk`,
  `bzero` or a name beginning `memset.` or `bzero.`; every `bufferBarriers`
  anchor is `lifetime-end` or `ret`. WipePinGcc: `unhandled.atomicMemset`,
  `inlineWrapperMemset` and `inlineWrapperBzero` are 0; every `zeroCopy`
  site's `form` is `aggregate`, `builtin` or `call`, with `callee` `null`
  exactly when the form is `aggregate`; every `bufferBarriers` anchor is
  `clobber` or `ret`; `host.checked` is `true`, `host.ident` is not `null`,
  and `host.intrinsicsCompared` is `null`.

And the compile (refused as `wrong-compile`):

- **W1** when the caller says whether it set `WPIN_BARRIER_CALLS`,
  `WPIN_ZERO_COPY` or `WPIN_BUFFER_BARRIER`, the matching `enabled` agrees.
  The repair loop says `false` for each variable it did not set.

`pin.sh`'s inline reader keeps checking only what its exit status needs (§1),
now the four counts of §14.8 as well.

### 14.10 Readers, and the v2 records already written

Each reader accepts one version. Since the writers moved to v3,
`pin-record.mjs`, `wpin_gcc_record.py` (and `pin-gcc.sh` through it), the
inline reader in `pin.sh`, the two fixture-loop checkers and the compiler
wrapper `../pin-wrapper/vgpin-cc` accept `"wipe-pin-v3"` only; a v2 record is
refused like any other record of the wrong shape (by the wrapper with exit 3:
`the record is 'wipe-pin-v2', not one of wipe-pin-v3`; measured with the
`22e7222` builds on clang-18 and gcc-13, `../pin-wrapper/README.md`). A v2 record is read
with the reader of the commit that wrote it — `22e7222` for the last v2
writers — which is how `../eval/repair-loop/tools/fbu-levels.mjs --reader`
already measures a v1 plugin. No writer writes v2 after its change, and no
switch makes one.

No tracked file needs a v2 reader. Counted in the two tracked row files of the
repair loop: `data/r2-repair-rows.json` holds 1,881 rows with 3,405 record
summaries (3,395 of an accepted record, 10 of a refused one), and
`data/r2-repair-rows-gcc-13.json` 1,883 rows with 3,405 (3,395 and 10). None
of the 6,810 carries a `schemaVersion` or an `evidenceDigest`: they are what
the runner kept of each record (counts, `seen`, `unhandled`, unresolved and
non-exact names), not records. Every accepted summary's `unhandled` has
exactly the nine keys of §14.3: the rows were re-recorded on 2026-11-10 with
the v3 plugins built from this tree (clang-18 `7c9d11f2…`, gcc-13
`ea3e8c7e…`), every switch off, and every row equals the v2 row it replaced
once the four new keys are removed
(`../eval/repair-loop/data/r2-v3-rerecord.json`).

Those summaries are still read: the repair loop's routing and its table of pin
families count the `unhandled` counters over the tracked rows. Since the
re-record each of the four new counters is counted, and it reads 0 in each of
the 3,395 accepted summaries of each vendor. A counter a row did not carry
would be **not measured** for that row — never 0 — and even a counted zero is
`unmeasured` in `../eval/repair-loop/PIN-FAMILIES.md`'s vocabulary: a count of
none says the corpus never put the shape in front of the repair, not that the
repair works on it.

### 14.11 Examples

Constructed to show the shape, not captured from a compile. Both satisfy §11
and §14.9; their `evidenceDigest` and `toolchain.digest` were computed with
`../evidence/canon.mjs` and re-derived, equal, with `wpin_gcc_record.py`'s
serialiser. The WipePinGcc `toolchain.digest` is the one §3.1 gives for gcc
13.3.0.

WipePin, clang-18 `-O2 -D_FORTIFY_SOURCE=2`, functions scope,
`WPIN_BARRIER_CALLS=1 WPIN_ZERO_COPY=1`, not a dry run. The one `pinned[]` site
is an initialiser (`followedByUse: true`); the wipe at the end is a
`memset.inline` call, repaired by a barrier, and a copy from an all-zero
constant through `memcpy.inline`, repaired the same way:

```json
{"schemaVersion":"wipe-pin-v3","component":"WipePin","module":"session.c","toolchain":{"clang":"18.1.3","packages":[{"name":"llvm","version":"18.1.3"}],"digest":"a532c6b0418aba5c30e069c3b9b2b9657b3d8f256ec342d27b2fb9df625a35cd"},"optLevel":{"speedup":2,"size":0},"scope":"functions","requested":["close_session"],"resolution":[{"name":"close_session","resolution":"resolved","exact":true,"linkage":"external"}],"dryRun":false,"pinned":[{"function":"close_session","index":0,"lengthBytes":32,"destKind":"alloca","alreadyVolatile":false,"followedByUse":true,"line":41}],"pinnedCount":1,"wouldPinCount":1,"seen":{"zeroFillMemsetInScope":1,"zeroFillMemsetInModule":2},"unhandled":{"libcallMemset":0,"memsetChk":0,"nonZeroFill":1,"atomicMemset":0,"inlineWrapperMemset":0,"bzeroCall":0,"inlineWrapperBzero":0,"zeroGlobalCopy":0,"zeroGlobalCopyCall":0},"barrierCalls":{"enabled":true,"sites":[{"function":"close_session","callee":"memset.inline","lengthBytes":32,"line":57}],"barrierCount":1,"wouldBarrierCount":1},"zeroCopy":{"enabled":true,"sites":[{"function":"close_session","form":"call","callee":"memcpy.inline","source":"zero_block","destKind":"alloca","lengthBytes":64,"line":58}],"repairedCount":1,"wouldRepairCount":1},"bufferBarriers":{"enabled":false,"count":0,"sites":[]},"host":{"ident":"Ubuntu clang version 18.1.3","identMajor":18,"builtMajor":18,"checked":true,"intrinsicsCompared":null},"evidenceDigest":"4eca66759c0a3475a9aedb15f35bc9b8690310db743e85d23c9a6fccb542f9b3","context":{"timeSource":"SOURCE_DATE_EPOCH","sourceDateEpoch":1762300800,"generatedAt":1762300800}}
```

WipePinGcc, gcc-13 `-O2`, module scope, `WPIN_DRY_RUN=1` with
`WPIN_BARRIER_CALLS=1 WPIN_ZERO_COPY=1`: everything is listed, nothing is
changed, so every done-count is 0 and every would-count is the list's length:

```json
{"schemaVersion":"wipe-pin-v3","component":"WipePinGcc","module":"session.c","toolchain":{"gcc":"13.3.0","packages":[{"name":"gcc","version":"13.3.0"}],"digest":"59918b2e94592419773ed8982734ac2d9ed571a328feec4d8430d158995291e0"},"optLevel":{"speedup":2,"size":0},"scope":"module","requested":[],"resolution":[],"dryRun":true,"pinned":[{"function":"close_session","index":0,"lengthBytes":32,"destKind":"alloca","alreadyVolatile":false,"followedByUse":false,"line":55}],"pinnedCount":0,"wouldPinCount":1,"seen":{"zeroFillMemsetInScope":1,"zeroFillMemsetInModule":1},"unhandled":{"libcallMemset":1,"memsetChk":0,"nonZeroFill":0,"atomicMemset":0,"inlineWrapperMemset":0,"bzeroCall":0,"inlineWrapperBzero":0,"zeroGlobalCopy":0,"zeroGlobalCopyCall":0},"barrierCalls":{"enabled":true,"sites":[{"function":"close_session","callee":"bzero","lengthBytes":16,"line":56}],"barrierCount":0,"wouldBarrierCount":1},"zeroCopy":{"enabled":true,"sites":[{"function":"close_session","form":"aggregate","callee":null,"source":"zero_block","destKind":"alloca","lengthBytes":64,"line":58}],"repairedCount":0,"wouldRepairCount":1},"bufferBarriers":{"enabled":false,"count":0,"sites":[]},"host":{"ident":"13.3.0","identMajor":13,"builtMajor":13,"checked":true,"intrinsicsCompared":null},"evidenceDigest":"3904af95abe913d30dc707fa10a9e7f51737f6d56bc95a21c15b2f4fe145c77e","context":{"timeSource":"SOURCE_DATE_EPOCH","sourceDateEpoch":1762300800,"generatedAt":1762300800}}
```
