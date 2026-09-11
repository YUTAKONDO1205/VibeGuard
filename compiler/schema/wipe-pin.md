# The `wipe-pin-v2` record

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
(clang 18.1.3; gcc-13 13.3.0).

## 1. Writers and readers

| | component | compiler | source |
|---|---|---|---|
| writer | `WipePin` | clang 18, a new-pass-manager module pass on the pipeline-start extension point | `../llvm-repair/src/WipePin.cpp` |
| writer | `WipePinGcc` | gcc-13, a GIMPLE pass registered directly after `cfg` | `../gcc-repair/src/WipePinGcc.cpp` |
| reader | both | — | `../eval/repair-loop/lib/pin-record.mjs` (`validatePinRecord`, `readPinRecord`) |
| reader | `WipePinGcc` only | — | `../gcc-repair/scripts/wpin_gcc_record.py`, used by `pin-gcc.sh` |
| reader | any `wipe-pin-v2` | — | the inline reader in `../llvm-repair/scripts/pin.sh`, which checks `schemaVersion` and the fields its exit code needs, and nothing else |

`pin-record.mjs` is the enforcement: the repair loop reads every record through
it, and a record it refuses turns the cell into a broken repair. It is strict
on purpose — an unknown field, a missing field, a wrong type, a digest that does
not re-derive, a count that contradicts the list it counts, or a record that
describes a different compile is a refusal. The rules in §11 are the ones it
applies. `wpin_gcc_record.py` applies the same rules to WipePinGcc records and
some further ones (§11, §13), so that `pin-gcc.sh` needs no node.

Only `"wipe-pin-v2"` is accepted. A `wipe-pin-v1` or `v0` record is refused like
any other record of the wrong shape.

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
| `-Oz` | not measured (§13) | `{2,2}` | yes, both, as `{2,2}` |
| `-Ofast` | — | `{3,0}` | no |
| `-Og` | — | `{1,0}` | no |

Every value in the table was measured from the plugin's own record except the
one marked. The reader compares `optLevel` with the flag the caller passed,
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
when it was built against a different GCC (`plugin_default_version_check`) and
when it is loaded into the LTO back end (`lto1`), where its pass never runs; it
ignores `-fplugin-arg-…` arguments and says so.

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
