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

`wipe-pin-v3` (`../schema/wipe-pin.md` §14) adds three repairs, all off by
default, and one check that is always on:

- `WPIN_BARRIER_CALLS=1`: a zero-fill memset or bzero that reaches pipeline
  start as a **call** rather than the intrinsic — the `-D_FORTIFY_SOURCE`
  wrappers `memset.inline` and `bzero.inline`, `__memset_chk`, a library
  `memset` (`-fno-builtin`), `bzero` — gets `call void asm sideeffect "",
  "r,~{memory}"(ptr <dest>)` directly after it, with the call's debug location.
  The optimiser must assume the asm reads the buffer, so the stores before it
  are not dead. The call itself is left alone, so the check inside a fortify
  wrapper stays.
- `WPIN_ZERO_COPY=1`: a wipe written as a copy from an all-zero constant global
  (`memcpy(p, zeros, n)` with `static const unsigned char zeros[N];`). An
  `llvm.memcpy` is replaced by a volatile `llvm.memset` of the same destination,
  length and destination alignment, and an `llvm.memcpy.inline`
  (`__builtin_memcpy_inline`) by a volatile `llvm.memset.inline`, which, like
  the copy it replaces, is never lowered to a library call; a call of
  `memcpy`, `__memcpy_chk` or `memcpy.<suffix>` gets the barrier above.
- `WPIN_BUFFER_BARRIER=1`: the barrier at the other end of the buffer's life.
  Every stack buffer (`alloca`) of a function in scope that some zero fill
  writes — a zero-fill memset or memset-family call, a store of the constant
  zero inside a loop into an aggregate, a copy from an all-zero constant
  global — and that is not only initialised gets `call void asm sideeffect
  "", "r,~{memory}"(ptr %buf)` at each point where its wipe's path leaves the
  buffer's lifetime: directly before each reachable `llvm.lifetime.end` the
  wipe reaches, and before each reachable `ret` it reaches first — every such
  `ret` when the buffer has no lifetime markers (every buffer at `-O0`, a
  variable-length array at every level), and a `ret` after a musttail call at
  every level, where clang puts the lifetime end after the call and its `ret`,
  in a block no path reaches. The barrier goes before the musttail call when
  the `ret` follows one. A buffer whose wipe reaches a call that does not
  return (`exit`, `abort`) gets none, and stderr counts it.
  Of this plugin's repairs it is the only one that can reach a loop of zero
  stores into a stack buffer of a function in scope, which is neither a
  memset nor a call at pipeline start; measured on E3 v2's 52 machine-made
  rewrites at `-O2` (all of one loop template) and on the fixture loop's
  cells only (*The buffer barrier*, below).
- The version handshake. Before the pass reads anything else it compares the
  module's producer (`!llvm.ident`), the module's intrinsic numbering and the
  host's own intrinsic table with the LLVM its headers came from, and refuses
  on a difference (*The silent failures*).

With the three new variables unset, the code it emits is the v2 plugin's
(measured, *`wipe-pin-v3`* under *Measured*).

When clang loads the plugin — before any configuration is read, before any
refusal, and whether or not the pass later runs — whatever is at `WPIN_OUT` is
removed. "No record" after a compile therefore always means "no record from
this compile".

An LTO link that loads the plugin (`-Wl,--load-pass-plugin=`) removes it too,
and there the file may be the record the compile step wrote. The link's
pipeline never runs pipeline start, so the pass never runs there; the plugin
says so on stderr, once, and says whether its load removed a file (see *The
silent failures* and *The link-time line* under *Measured*).

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
| `WPIN_BARRIER_CALLS` | `1`: a barrier after each zero-fill memset-family or bzero-family call in scope (above). Unset, empty or `0`: off, and those calls are only counted |
| `WPIN_ZERO_COPY` | `1`: copies from an all-zero constant global in scope are repaired (above). Unset, empty or `0`: off, and they are only counted |
| `WPIN_BUFFER_BARRIER` | `1`: a barrier at the end of the lifetime of each stack buffer in scope that a zero fill writes and that is not only initialised (above; `../schema/wipe-pin.md` §14.6). Unset, empty or `0`: off |

One of `WPIN_TARGET_FNS` / `WPIN_SCOPE=module` is required. If both are set,
`WPIN_TARGET_FNS` wins, the record says `scope: "functions"`, and stderr says so.

`WPIN_DRY_RUN` and the three switches are read in that order, and each accepts
unset, empty, `0` or `1` only. Anything else is a refusal —
`WipePin: refusing to install: WPIN_<NAME>='<value>' is neither 0 nor 1` —
with no record and clang's exit status left alone: a misspelt "on" read
as off would leave the fortified wipe as removable as before, silently. The
record says which were on as `barrierCalls.enabled`, `zeroCopy.enabled` and
`bufferBarriers.enabled`, the way `dryRun` says `WPIN_DRY_RUN` was.

## The record

The record, field by field for both plugins, is specified in `../schema/wipe-pin.md`.

One clang invocation, one source file, one record, written at the end of the
pass's single run and overwriting whatever was at `WPIN_OUT`:

```json
{ "schemaVersion": "wipe-pin-v3", "component": "WipePin", "module": "<basename>",
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
                "atomicMemset": 0, "inlineWrapperMemset": 0, "bzeroCall": 0,
                "inlineWrapperBzero": 0, "zeroGlobalCopy": 0, "zeroGlobalCopyCall": 0},
  "barrierCalls": {"enabled": false, "sites": [], "barrierCount": 0, "wouldBarrierCount": 0},
  "zeroCopy": {"enabled": false, "sites": [], "repairedCount": 0, "wouldRepairCount": 0},
  "bufferBarriers": {"enabled": false, "count": 0, "sites": []},
  "host": {"ident": "Ubuntu clang version 18.1.3", "identMajor": 18, "builtMajor": 18,
           "checked": true, "intrinsicsCompared": 3},
  "evidenceDigest": "...", "context": {"generatedAt": ..., "timeSource": ..., "sourceDateEpoch": ...} }
```

What `wipe-pin-v3` changed from `v2`, for this plugin (`../schema/wipe-pin.md`
§14 is the contract):

- `schemaVersion`, and four blocks written on every record whatever the
  configuration. `barrierCalls` lists each call that got a barrier (or would
  have, in a dry run) as `{function, callee, lengthBytes, line}`; `zeroCopy`
  each repaired copy as `{function, form, callee, source, destKind,
  lengthBytes, line}`, `form` being `intrinsic` (callee `llvm.memcpy`) or
  `call`. `bufferBarriers` lists each barrier placed before a lifetime end or
  a `ret` (or that would have been, in a dry run) as `{function, buffer, bytes, reason,
  anchor}` and counts the ones placed in `count` (*The buffer barrier*). A
  switch that is off reads `enabled: false`, no sites, every count 0.
- `host`, the version handshake's account. `ident` is the first operand of
  `!llvm.ident` with every parenthesised group removed; `identMajor` the digits
  after its first `clang version `; `builtMajor` is `LLVM_VERSION_MAJOR` of the
  headers this plugin was compiled against; `checked` is true exactly when
  `identMajor` is not null. A record never shows a mismatch: a mismatch is a
  refusal with no record. `intrinsicsCompared` is never null from this build:
  it is how many `llvm.*` declarations of the module have a name in the
  plugin's intrinsic table (`memset`, `memset.inline`,
  `memset.element.unordered.atomic`, `memcpy`, `memcpy.inline`,
  `memcpy.element.unordered.atomic`, `lifetime.start`, `lifetime.end`,
  `dbg.declare`, `dbg.value`, `dbg.label`, each with its type suffixes), every
  one of which had the same number in the host as in the plugin's headers.
  The third check, which asks the host's table for every name in that list
  whatever the module declares, is not counted there: a record exists only
  when it found no difference.
- Four more `unhandled` counters, `bzeroCall`, `inlineWrapperBzero`,
  `zeroGlobalCopy`, `zeroGlobalCopyCall` (*What it does not handle*). A call or
  copy that a switch repairs is not counted.
- `pinned[]`, `pinnedCount`, `wouldPinCount` and `seen` are computed exactly as
  in v2. A barrier or a copy repair is counted in its own block, never there,
  and the volatile memset that replaces a copy is not a `pinned[]` site.

What `wipe-pin-v2` changed from `v1`, for this plugin: `schemaVersion`, and how
`followedByUse` is computed. Its three values and its meaning are the same; what
no longer counts as a path to a later use is an edge of clang's cleanup dispatch
that the path being followed cannot take (see *What `followedByUse` can and
cannot say*). Every other field is computed exactly as in v1, and the code the
plugin emits is the same (measured below). The v2 contract also admits a second
writer, the GCC plugin `WipePinGcc` (`../gcc-repair/`), whose `toolchain` block
carries `gcc` where this one carries `clang`; one reader,
`../eval/repair-loop/lib/pin-record.mjs`, reads both, and takes the component
the caller loaded (`WipePin` here) as part of what the record must match.

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
  run as well, before anything is changed. (v2 asks the reachability question a
  second time where the first answer is `true`; see below.)
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
  run, where `wouldPinCount` still counts the eligible sites. The same holds for
  `barrierCalls.barrierCount` / `wouldBarrierCount` and
  `zeroCopy.repairedCount` / `wouldRepairCount`.
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

## The buffer barrier (`WPIN_BUFFER_BARRIER`)

Every other repair acts at the wipe: it marks the memset, or puts a barrier
right after a call or a copy. A wipe written as a loop of stores
(`for (i = 0; i < n; i++) key[i] = 0;`) has neither at pipeline start — loop
idiom recognition makes it an `llvm.memset` only later, and DSE then deletes
that — so no other repair reaches it
(`../eval/repair-loop/pin-families.json`, `wipe-written-as-stores`). The
buffer barrier acts at the other end, the end of the buffer's lifetime. It
was prototyped and measured outside this tree first (lab notes kept outside
this repository, on the patch series this tree's v3 came from) and then
landed here; the numbers below are the landed build's own.

**Which buffers.** In the functions in scope only (`WPIN_TARGET_FNS`, or every
function with `WPIN_SCOPE=module`): an `alloca` that is the destination of a
zero-fill `llvm.memset`, of a zero-fill call of `memset`, `__memset_chk`,
`memset.<suffix>`, `bzero` or `bzero.<suffix>` (whether or not
`WPIN_BARRIER_CALLS` repairs it), of a copy from an all-zero constant global
(`llvm.memcpy` or a call of `memcpy`, `__memcpy_chk`, `memcpy.<suffix>`), or
of a non-volatile store of the constant zero inside a loop (LoopInfo), the
last only when the `alloca` is an array, a struct or variable-length: a
scalar zeroed in a loop is a counter or a flag far more often than a secret.
A destination is followed through `getUnderlyingObject`, and through the
pre-SROA shape `unsigned char *p = key; … p[i] = 0;` when every store into
`p`'s stack slot points into the same `alloca` — including the store of the
slot's own value advanced, so `while (n--) *p++ = 0;` is followed too
(measured: `v3-loop-ptr`). Anything else — an argument, a global, the heap, a
pointer the pass does not follow — gets no barrier and is counted on stderr
(below).

**Only a wipe.** A buffer gets a barrier only when some zero fill of it is not
followed by a later use of the buffer in the same lifetime. The question is
asked twice, and the answer is "a later use" only when both say so: the walk
`followedByUse` uses (from the fill, through clang's cleanup dispatch; *What
`followedByUse` can and cannot say*), and a walk over every CFG path that stops
where the buffer's lifetime ends or starts again (its `llvm.lifetime.end` or
`llvm.lifetime.start`, or the re-execution of a variable-length array's
`alloca`). The second walk is what lets a buffer declared in a loop body and
wiped at the end of each iteration read as wiped: the next iteration's use is
a use of another lifetime of the same `alloca` (measured: `v3-buffer-inloop`).
A store that only advances a pointer kept in a stack slot (`p++`) is not a use
there, and neither is a comparison of the buffer's address, the bound of
`for (p = key; p < key + n; p++) *p = 0;` (measured: `v3-loop-ptrcmp-O2`;
until 2026-11-10 that loop read as an initialiser and got no barrier). A
buffer whose every zero fill is followed by a use is an initialiser
— the `= {0}` of a buffer that is never wiped, say — and gets **no** barrier:
its last stores are the secret itself, and a barrier would keep them in
memory to the end of the lifetime with no wipe to protect. Measured on five
probes that each take a 16-byte secret, compiled `-O2` with clang 18.1.3 and
the three switches on, then run, counting the copies of a secret-derived byte
pattern in the 4096 bytes below the caller's stack pointer after the call: with
the build before this rule, the three whose buffer is only initialised and
otherwise kept in registers (an 8-byte and a 16-byte buffer cleared by
`memset` first, and one cleared by `= {0}`) left 2 copies each where stock left
0; with this build they get no barrier and leave 0, as stock does. The return
values were the same in every build. stderr counts each such buffer (below). clang
emits no lifetime markers at `-O0`, so there a buffer declared in a loop body
reads as an initialiser and gets no barrier; clang's `-O0` pipeline runs no
dead-store elimination, and a stock `-O0` build of that shape kept the loop's
zero store (one probe, not a corpus).

Both walks read the IR as the front end wrote it, before any optimisation, so
"a later use" is a use the source writes, not one that survives. A real wipe
followed by code that touches the buffer and that the optimiser then removes
— a read of a wiped byte that it folds to the zero it already knows, a call
that inlines to nothing, a dump guarded by a flag nothing sets — reads as an
initialiser and gets no barrier, and stock's deletion of the wipe stands; the
build before this rule barriered such a buffer. Measured on clang-18 `-O2`,
one probe of each of those three shapes (lab notes): the wipe's zero stores
missing from the `-S` as from stock's, where the build before this rule
(`b509c308…`) kept them; a control with nothing after the wipe kept them on
both builds. The
direction is chosen (towards leaving the program as stock compiles it), and
stderr counts each such buffer, but its line does not say whether the fill
was a wipe.

The walks over-approximate the paths, not the uses. An address the uses are
followed through is the buffer's own, or one loaded back from a stack slot it
was stored into; an address stored anywhere else — a field of a local struct,
`struct ctx c = {key, 16};` — is not followed, so an initialiser used
afterwards only through such a copy reads as a wipe and gets a barrier (a
reviewer's probe, clang-18 `-O0` and `-O2`: one site, `pin.sh` 0, where the
buffer held no wipe; GCC's twin does the same). It is the same limit as the
`followedByUse` walk's (*What `followedByUse` can and cannot say*).

**Where.** One barrier per buffer per place, and the places are, in
instruction order, the points where one of the buffer's wipes leaves the
buffer's lifetime: each `llvm.lifetime.end` of the buffer, in a block reachable
from the entry, that a wipe reaches, and each `ret` in a reachable block that a
wipe reaches before the lifetime ends or starts again. A lifetime end that only
paths without a wipe reach is not a place: a barrier there protects no wipe
and keeps the buffer's last stores — the secret — in memory. clang emits no
lifetime markers at `-O0`, and none for a variable-length array at any level
(measured, `-O2`: `v3-vla-musttail-O2`), so there every `ret` the wipe reaches
is a place. At `-O1` and above clang ends a buffer's lifetime before an
ordinary `ret`, so the `ret` is not reached first and only the lifetime end is
a place; but for a scope that ends in a musttail call it puts the lifetime end
after the call and its `ret`, in a block no path reaches, so there the place
is the `ret` (measured: `v3-musttail-O2`, `v3-musttail-Os`, and
`v3-musttail-exits-O2` for a buffer with a lifetime end on one path and a
musttail call on the other). A `ret` that follows a musttail call gets the
barrier before the call, since nothing may stand between the two. When a
`ret` a wipe reaches is one the buffer's `alloca` does not dominate — an
`alloca` or a variable-length array declared inside a branch or a loop — the
read there would be invalid IR, and the buffer gets no barrier at any place:
a barrier on some paths only would make the record and `pin.sh` say
"repaired" for a wipe that another path still loses. The same holds when a
wipe reaches a block that ends in `unreachable` — the block after a call that
does not return, such as `exit` or `abort` — where the buffer's lifetime ends
at no lifetime end and no `ret`: the buffer gets no barrier at all (measured:
`v3-exit-O2`). A buffer left with no place gets no barrier and is counted on
stderr (measured: `v3-vla-branch-O0`, `-O2`).

Until 2026-11-10 a lifetime end in a block no path reaches was a place too,
and a buffer with any lifetime end got barriers at its lifetime ends only. A
loop wipe before a musttail call therefore got its barrier in the dead block
at `-O1` and above: the optimiser deleted it with the block, the record still
counted it, and `pin.sh` exited 0 for a `-S` byte-identical to stock's
(measured on that build for `-O1`, `-O2`, `-O3` and `-Os`, clang 18; found by
a refuter). The fixture loop's musttail cells at `-O2` and `-Os` now ask that
the barriers the record counts are still in the optimised IR. Until the
evening of 2026-11-10 every reachable lifetime end was a place, whether a wipe
reached it or not: a wipe only on a path that ends in `exit` left that path
uncovered while the other path's lifetime end got the barrier, and the record
said 1 and `pin.sh` 0. Measured on that build, clang 18, a key computed in the
function and wiped only before `exit`: at `-O2` and `-Os` the wipe was gone,
and at `-O2` the barrier on the other path made the key be written to the
stack, where stock kept it in registers (found by a reviewer; *2026-11-10,
later*). The asm is the one
`WPIN_BARRIER_CALLS` uses, taking the buffer, with the anchor's debug
location. The census runs on the unmodified IR, before any repair of any
function in scope is placed, and a dry run places nothing.

The asm writes nothing, but placing it is not free of effects, and it is not
claimed to leave what the program computes untouched in every program: the
buffer's last stores may now be read, so they are not dead; the buffer must
stay in memory, so SROA cannot split it and inlining, register allocation and
the frame can change around it. Two shapes made the build before these
placement rules produce IR that LLVM's verifier rejects, with clang exiting 0
(a release clang does not verify): a barrier between a musttail call and its
`ret` at `-O0` turned the guaranteed tail call into a call and a return, and a
program that recursed 10⁷ deep through it then crashed (rc 139, where stock
returned); and a barrier on a variable-length array in a branch read a value
that did not dominate it. Both are now placed as above, and the fixture
loop's cells run the IR verifier on what the plugin leaves.

**The record** (`../schema/wipe-pin.md` §14.6). `bufferBarriers.count` is the
number of barriers placed (0 in a dry run); `sites` has one entry per barrier
placed (or, in a dry run, that would have been), in the order: functions as
in `pinned[]`, buffers by their first zero fill, then each buffer's places
(lifetime ends and returns) in instruction order.

- `buffer`: the variable a debug declaration names for the `alloca`
  (`dbg.declare`, the debug-record declare from LLVM 19, or the `dbg.assign`
  markers of assignment tracking, clang's default at `-O1` and above from 17),
  else the `alloca`'s IR name, else `null`. A release clang discards IR value
  names, so without `-g` it is `null` (measured: `v3-loop` below; with `-g`,
  `key`, `v3-loop-g`).
- `bytes`: the `alloca`'s size when it is a constant.
- `reason`: the kind of the first zero fill of the buffer that no later use
  follows in the same lifetime (*Only a wipe*, above): `memset`, `loop-store`
  or `zero-copy`.
- `anchor`: `lifetime-end` or `ret`.

A buffer that gets no barrier is not in `sites` and adds nothing to `count`;
§14.6 fixes the record's keys, so stderr says it, one line per reason:
`WipePin: buffer barrier: <N> buffer(s) not barriered: every zero fill is
followed by a later use (read as an initialiser; a wipe that later code still
touches, even code the optimiser removes, is counted here too)` (measured:
`v3-buffer-init`, `v3-buffer-initloop`) and `WipePin: buffer barrier: <N>
buffer(s) not barriered: the buffer does not dominate a return its wipe
reaches, or there is no place (an alloca or variable-length array inside a
branch or loop, or a function that does not return)` (measured:
`v3-vla-branch-O0`, `-O2`). Until 2026-11-10 the two lines read `… later use
(initialiser-like, not a wipe)` and `… does not dominate a return (an alloca
…)`. The build before these rules placed a barrier on the first kind, with the
line `… <N> of <M> barrier site(s) are on buffers whose every zero fill is
followed by a later use …`, which this build no longer prints.

**What it does not do.** It covers stack buffers of functions in scope and
nothing else: not a heap buffer (`malloc` … `free`), not a buffer of a caller
or a callee, not a function out of scope — so not a wipe written as a loop
inside a helper, whose stores go through an argument, even with the helper in
scope. It keeps the stores into
the buffer, not copies of the secret in registers or spill slots, and it
cannot tell a secret from any other buffer that is wiped. Its cost in run
time or code size is not measured.

## What it does not handle — counted, not ignored

As of `wipe-pin-v3` (2026-11-09). The table as it stood at `22e7222`
(`wipe-pin-v2`, before the two switches existed) is kept below, under its date.

Everything counted below leaves the program exactly as it was. Where the plugin
can see the shape, it is **counted** in `unhandled` (in scope only), so "nothing
was pinned" is never confused with "there was nothing to pin". A call or copy
that a switch repairs is not counted; with the switch off it is counted and left
alone. The measured examples are the fixture loop's `v3-*` cells (clang 18.1.3,
glibc 2.39, target `handle`, `-O2`; *Measured*).

| counter | what it is | repaired by | measured example |
|---|---|---|---|
| `libcallMemset` | a call to a function named `memset` that is not the intrinsic | `WPIN_BARRIER_CALLS=1`: a plain call with ≥ 3 arguments and a zero `ConstantInt` fill | `-fno-builtin` (`v3-libcall`): 1 with the switch off, 0 and one barrier with it on. The call survives `-O2` stock as well: the wipe is in all four executables |
| `memsetChk` | a call to `__memset_chk` | the same | `__builtin___memset_chk` through a local pointer (`v3-chk`): stock deletes the wipe, the barrier keeps it |
| `inlineWrapperMemset` | a call to `memset.<suffix>` that is not the intrinsic | the same | `-D_FORTIFY_SOURCE=2` and `=3` (`v3-fort2`, `v3-fort3`): callee `memset.inline` — see below |
| `bzeroCall` | a call or invoke of a function named `bzero` that is not an intrinsic | `WPIN_BARRIER_CALLS=1`: a plain call with ≥ 2 arguments | not reached by any measured case: without FORTIFY, clang 18's front end already lowers `bzero(k, 32)` to `llvm.memset`, which is pinned like any other (measured in the lab before the cells were written) |
| `inlineWrapperBzero` | a call or invoke of `bzero.<suffix>` | the same | `-D_FORTIFY_SOURCE=2` and `=3` (`v3-bzero-fort2`, `v3-bzero-fort3`): callee `bzero.inline` (the wrapper's name is measured, clang 18.1.3, glibc 2.39) |
| `zeroGlobalCopy` | a non-volatile `llvm.memcpy` (or `llvm.memcpy.inline`) whose source is an all-zero constant global (below) | `WPIN_ZERO_COPY=1`: replaced by a volatile `llvm.memset` (`llvm.memcpy.inline` by a volatile `llvm.memset.inline`, so no call of `memset` appears; the site's `callee` is still `llvm.memcpy`) | `memcpy(key, vg_zeros, 32)` without FORTIFY (`v3-zcopy`); `__builtin_memcpy_inline` under `-ffreestanding` (`v3-zcopy-inline`) |
| `zeroGlobalCopyCall` | a call or invoke of `memcpy`, `__memcpy_chk` or `memcpy.<suffix>` with ≥ 3 arguments, from an all-zero constant global | `WPIN_ZERO_COPY=1`: a barrier after a plain call | the same under `-D_FORTIFY_SOURCE=2` (`v3-zcopy-fort2`): callee `memcpy.inline` |
| `nonZeroFill` | a `MemSetInst` whose fill is non-zero or not a constant | nothing | a probe with `memset(k, 0xAA, …)` and `memset(p, c, n)`: 2 (2026-09-11) |
| `atomicMemset` | `llvm.memset.element.unordered.atomic` | nothing | — |

An **invoke** (a call that can unwind, in C++ with exceptions) of any of these
is counted and never repaired, switch or not: the barrier is placed only after
a plain call. No fixture has one. A one-unit C++ probe (2026-11-11,
`../eval/repair-reach/README.md`) produced one only with a declaration that is
not `noexcept`, `-fno-builtin` and a cleanup together, and the record counted it
as `libcallMemset` with nothing placed.

The *all-zero constant global* is read from the IR: `getUnderlyingObject` of
the source is a `GlobalVariable` that is constant, has a definitive initializer
(not replaceable at link time), and whose initializer is the null value. A
writable global that happens to hold zeros, a constant that is not all zero, a
local array of zeros, `memmove` and `mempcpy` are not this shape: neither
repaired nor counted (not measured).

`inlineWrapperMemset` was not in the original contract; it was added after a
measurement. Under `-D_FORTIFY_SOURCE=2` with glibc's headers, clang renames the
header's `gnu_inline` memset wrapper to `memset.inline`, and at pipeline start
the target function calls *that*. The `__memset_chk` is inside the wrapper, out
of scope. On `fable_N_aeskey_r3.c` at `-O2` the wipe is then eliminated and,
before the counter existed, the record said zero of everything. With
`WPIN_BARRIER_CALLS=1` the call gets the barrier, and the wipe survived in each
of the 51 r4 L files at `=2` and at `=3` (*Measured*, *`wipe-pin-v3`*).

**Not counted, because the plugin cannot see them as wipes** (neither
`WPIN_BARRIER_CALLS` nor `WPIN_ZERO_COPY` reaches them):

- Wipes written as stores — an explicit zeroing loop, or a store through a
  volatile pointer (that one needs no pin). With `WPIN_BUFFER_BARRIER=1` a
  zeroing loop into a stack buffer of a function in scope gets a barrier
  before the buffer's lifetime ends (*The buffer barrier*); it is still not a
  `pinned[]` site and not counted in `unhandled`. Zero stores outside a loop,
  and stores into memory that is not such a buffer, get nothing; nor does a
  buffer the barrier does not cover (an initialiser only, or no place it can
  stand), which stderr counts instead. `= {0}` is
  **not** in this list: clang lowers it to a zero-fill `llvm.memset`, which
  *is* pinned, and which is an initialiser, not a wipe — see `followedByUse`
  and the partial line below.
- A memset that a later pass creates, such as loop-idiom recognition turning a
  zeroing loop into `llvm.memset` after pipeline start.
- A wipe inside a helper the target calls. When the helper's wipe is a
  zero-fill memset, pin the helper by name instead; when it is a loop of zero
  stores, naming the helper does not help either — its stores go through an
  argument, which no buffer barrier covers (counted on stderr as a zero fill
  that does not write a stack buffer of the function), and `pin.sh` exits 4
  unless something else in scope was repaired. The target reads "nothing to pin" on stderr **only if it has no zero-fill
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
spill slots are outside what this pass, or any memset, can clear. The barrier
of v3 makes the same promise about the buffer its asm takes, and no other.

### As it stood at `22e7222` (`wipe-pin-v2`, 2026-09-12)

Kept as it was written then. Calls of `bzero` and copies from a zero constant
were neither counted nor repaired, and nothing repaired a memset-shaped call.

| counter | what it is | measured example |
|---|---|---|
| `libcallMemset` | a call to a function named `memset` that is not the intrinsic | `-fno-builtin`: 1, and the call survives `-O2` on its own |
| `memsetChk` | a call to `__memset_chk` in the target function | — |
| `inlineWrapperMemset` | a call to `memset.<suffix>` that is not the intrinsic | `-D_FORTIFY_SOURCE=2`: 1 — see below |
| `nonZeroFill` | a `MemSetInst` whose fill is non-zero or not a constant | a probe with `memset(k, 0xAA, …)` and `memset(p, c, n)`: 2 |
| `atomicMemset` | `llvm.memset.element.unordered.atomic` | — |

## The silent failures, and how each is made loud

Every failure a repair plugin can have ends in the same place: a build that
succeeded and looks repaired. Each one is turned into something audible.

| failure | what makes it loud |
|---|---|
| not installed: `WPIN_OUT` unset, no target, `WPIN_DRY_RUN`, `WPIN_BARRIER_CALLS`, `WPIN_ZERO_COPY` or `WPIN_BUFFER_BARRIER` neither `0` nor `1` | stderr `WipePin: refusing to install: <reason>`; no record, so `pin.sh` exits **3**. clang's rc is unaffected. (Measured for `WPIN_BARRIER_CALLS=2`, `WPIN_ZERO_COPY=true` and `WPIN_BUFFER_BARRIER=2`: the `v3-refuse-*` cells.) |
| **WipePin built against one major version of LLVM, loaded into a clang of another** | Before v3, measured outside this tree with builds that wrote v2 records: built against LLVM 18 and loaded into clang-19, the plugin ran, found no `MemSetInst` (a probe plugin read the host numbering `llvm.memset` 236 where LLVM 18's headers say 222), wrote a record saying `nothing to pin`, and clang exited 0 — the `22e7222` build does the same (measured again here, *Measured*). In clang-17 the LLVM-18 build hit an assertion (rc 74); the LLVM-17 build in clang-18 had not finished after 15 minutes when it was stopped. Now the pass checks first, before it reads or changes anything: (1) the major version after `clang version ` in every operand of the module's `!llvm.ident` against `LLVM_VERSION_MAJOR` of its own headers; (2) for every `llvm.*` declaration its intrinsic table knows, the number the host gave it against the number its own headers give that name; (3) for every name in that table, whatever the module declares, the number the host's `lookupIntrinsicID` gives `llvm.<name>` (`Function::lookupIntrinsicID` up to LLVM 19, `Intrinsic::lookupIntrinsicID` in 20; libLLVM's, so the host answers) against its own. Not `Intrinsic::getBaseName()` for (2), which lives in libLLVM and so answers from the host's table (measured with a probe plugin: in clang-19, the LLVM-18 probe got `llvm.memset` back for 236). A difference prints `WipePin: refusing to install: the module was produced by clang <N> (llvm.ident "<ident>") and this plugin was built against LLVM <M>`, or `WipePin: refusing to install: intrinsic table mismatch: the host numbers <name> <n> and this plugin, built against LLVM <M>, numbers <base> <m>`; no record, nothing changed, clang's exit status left at 0, `pin.sh` exits **3**. Measured over all 30 cross pairs of the LLVM 15–20 builds and clang-15–20: the 6 pairs among 17, 18 and 19 refuse this way (on C source by the first check, on IR without `!llvm.ident` by the second, on the build's own clang's front-end IR that declares none of the table's intrinsics by the third); the other 24 fail the compile before the pass runs (a crash, clang rc 1 or 139, with no WipePin line and no `Optimizer` frame in the crash report; `symbol lookup error`, rc 127; or, for clang-15 reading the IR a newer clang wrote for that build, an IR parse error, rc 1), which `pin.sh` reports as **1**. No cross compile gave `pin.sh` 0 or left a record (*Measured*). **The check cannot speak when the plugin fails to load or crashes before its pass runs**, and it relies on the host running the pass; comparing versions before starting the compiler is a wrapper's job (`../pin-wrapper/`). |
| the module names no clang version: IR without `!llvm.ident` (`-x ir`), or an ident without `clang version` | not refused: the record says `host.checked: false`, and stderr `WipePin: the module's llvm.ident names no clang version (<"ident" or absent>); the host compiler was not checked against LLVM <M>`. Checks (2) and (3) still run, and they are what refused in the cross-version cases above on IR with no ident (measured: `-Qn` front-end IR of a fortified `memset`, which declares only `llvm.objectsize`, refused by (3) in clang-19 with the LLVM-18 build). `pin.sh` writes `hostChecked=false` to its manifest. |
| IR written by one clang, compiled by another with `-x ir` | `llvm.ident` names the compiler that **produced** the module, not the host. clang-18 with the LLVM-18 build, reading clang-19's front-end IR, refuses although the numbering agrees (measured): the loud direction. clang-19 with the LLVM-18 build, reading clang-18's front-end IR, passes the first check; it is refused by the second when the IR declares one of the table's intrinsics (measured: `llvm.lifetime.start`), and by the third when it declares none (measured: `-O2 -D_FORTIFY_SOURCE=2 -Xclang -disable-llvm-passes` front-end IR of a `memset` wipe, whose only `llvm.*` declaration is `llvm.objectsize`: `intrinsic table mismatch: the host numbers llvm.memset 236 and this plugin, built against LLVM 18, numbers llvm.memset 222`, no record, clang rc 0, `pin.sh` 3, with and without `WPIN_BARRIER_CALLS=1`, and the `-S` the same as clang-19's stock `-S`). Before the third check that IR was accepted: measured with the build before the fix (`b509c308…`), clang-19 wrote a record with `checked: true`, `intrinsicsCompared: 0` and every counter 0 — the `memset.inline` call neither repaired nor counted — and with `WPIN_BARRIER_CALLS=1` placed no barrier; `pin.sh` 4. |
| a record from an earlier compile at `WPIN_OUT` | removed when the plugin loads, before any refusal — so a refused compile and a compile whose pass never ran leave **no** record, not the old one (measured: `stale-refused`, `stale-nopasses` below). If it cannot be removed (a directory, a non-regular file, an unlink error other than "not there"): `WipePin: refusing to install: <reason>`, and the IR is not touched. |
| installed, but the pass never ran: a compile under `-Xclang -disable-llvm-passes` | no record → `pin.sh` exits **3**. On stderr it depends on the output: with `-c` or `-S` nothing (rc 0, 0 bytes — clang runs no pass-manager pass at all, so nothing the plugin hooks fires; a direct clang user sees nothing); with `-emit-llvm` the link-time line below, because the bitcode writer or IR printer still runs as a pass (measured). The bitcode step of `-save-temps` is this case: clang runs it with `-disable-llvm-passes` and the line appears (`there was no file …`), and the next step builds the whole pipeline from the `.bc`, where WipePin runs and writes the record (`module` `t.bc`, measured). |
| installed, but the pass never ran: **WipePin on an LTO link line** (`-Wl,--load-pass-plugin=<so>`, full or thin LTO) with `WPIN_OUT` / `WPIN_TARGET_FNS` in the link's environment — a build that exports them to every step | An LTO link's pipeline never runs pipeline start, so the pass is never added. The load-time callback still removes the file at `WPIN_OUT`, which here is the record the compile step wrote. Until this change that link exited 0 with 0 bytes on stderr and the record gone (measured again below, full and thin, `-O0`..`-Os`). Now the first pass the link runs makes the plugin print, once per process, `WipePin: loaded into a pipeline built without the pipeline-start extension point (an LTO link, or a compile under -disable-llvm-passes), where this pass does not run; nothing was pinned in this process, and the file at WPIN_OUT was removed when the plugin loaded` (or `… and there was no file at WPIN_OUT when the plugin loaded`). The removal is kept (why: *The link-time line*). `pin.sh` does not link and is not involved; the fixture loop's `lto-*-linkline` cells and the LTO probe's configuration (ii) grade the line. |
| a misspelt name | `resolution: not-in-module` in the record **and** `WipePin: target <name> not-in-module` on stderr; `pin.sh` exits **4** |
| the right name, nothing eligible in it | stderr `WipePin: nothing to pin in scope …` with the `unhandled` counts; `pin.sh` exits **4** |
| **something was pinned, but not the wipe** — an `= {0}` initialiser or a clear-before-fill memset pinned while the wipe is a zeroing loop or sits in a helper | the site's `followedByUse: true`, and one stderr line, `WipePin: partial: pinned <P> site(s) in <module>; <K> followed by a later use of the same buffer (initialiser-like, not a wipe); unhandled in scope: libcallMemset=.. memsetChk=.. nonZeroFill=.. atomicMemset=.. inlineWrapperMemset=.. bzeroCall=.. inlineWrapperBzero=.. zeroGlobalCopy=.. zeroGlobalCopyCall=..`. `pin.sh` still exits **0** (something was pinned) and writes `followedByUseCount` to its manifest. |
| something was repaired — a pin, a barrier, a copy repair or a buffer barrier — while a memset-shaped call or a zero copy in scope was left alone (`unhandled` > 0) | the same partial line; `<P>` counts pins only (not exercised by the fixture loop, whose shapes all have `unhandled` 0 where something is repaired) |
| `WPIN_BUFFER_BARRIER=1` and a buffer it leaves without a barrier: every zero fill of the buffer is followed by a use in the same lifetime (read as an initialiser), or a wipe reaches a return the buffer's `alloca` does not dominate or a call that does not return, or there is no place at all | `WipePin: buffer barrier: <N> buffer(s) not barriered: every zero fill is followed by a later use (read as an initialiser; …)`, or `… <N> buffer(s) not barriered: the buffer does not dominate a return its wipe reaches, or there is no place (…)`; the record cannot say it (§14.6 fixes the keys). `pin.sh` exits **4** when nothing else was repaired (measured: `v3-buffer-initloop`, `v3-vla-branch-O0`, `-O2`, `v3-exit-O2`), **0** when something was (`v3-buffer-init`: the initialiser's memset is pinned) |
| a zero fill the buffer barrier cannot cover (its destination is an argument, a global, the heap, or a pointer the pass does not follow) | `WipePin: buffer barrier: <N> zero fill(s) in scope write memory that is not a stack buffer of the function (…); no barrier covers them`. Not reached by the fixture loop's cells |
| a call-shaped wipe with its switch off | counted in `unhandled`, and when nothing else in scope is pinned, `WipePin: nothing to pin in scope …` names the counter; `pin.sh` exits **4** (measured: every `v3-*-off` arm) |
| the target is not an exact definition (C99 `inline`, C++ `inline`/template, `weak`) | `exact: false` and `linkage` in the record, and `WipePin: target <name> is not an exact definition (<linkage>); the copy that runs may come from another translation unit`. `pin.sh` writes `exactAll=false`. |
| the dry run | `dryRun: true` in the record and a stderr line per kind of repair it held back; `pin.sh` exits **4**; the fixture loop's `dry-O2` cell shows the loss coming back and the object byte-identical to the no-plugin build, and each `v3-*-dry` arm the `-S` output byte-identical to stock's with the switch on |
| the record cannot be written | stderr `WipePin: cannot write the record …` saying whether the IR was changed; `pin.sh` exits **3** |
| two source files on one clang line | measured: rc 0, no plugin warning, one record naming the last file. `pin.sh` counts source operands, warns, and writes `sourceOperands=` to its manifest. (If one process ever hands the pass a second module, the plugin itself warns.) |
| the pin is in the IR and the wipe still is not in the object | **not detectable here, by design.** That is the confirm step's job, done by the stock observation. The record is never the verdict. |

### What `followedByUse` can and cannot say

It is a hint that points one way. `true` means "some use of this buffer is
reachable in the CFG after this site, not counting a cleanup-dispatch edge the
path cannot take"; `false` means "none is". Neither says the wipe survives —
that is still the confirm step's question.

- **v2 no longer counts the cleanup-dispatch edge a path cannot take.**
  Reachability is asked of the IR as the front end wrote it, which at `-O1` and
  above contains clang's cleanup dispatch: a scope that declares a local has a
  cleanup (its lifetime markers), and every jump out of it — a `return` inside a
  loop body, a `break`, falling off the end of the body — goes through one shared
  cleanup block. Which way the jump was going is kept in an `i32` stack slot
  (`cleanup.dest.slot` in a build that keeps value names): each jump stores its
  own constant there, the shared block loads it, and a `switch` on the load
  sends control on. On `fable_N_token_r3.c` (`send_session_token`, front-end IR
  at `-O1`) the `return -1` path stores `1`, the fall-through path stores `0`,
  and the switch sends `0` back to the loop header and everything else to the
  exit. So the CFG has a path from the error-path wipe `memset(token, …);
  return -1;` (line 17) back to `write(fd, token + total, …)`, which no
  execution takes. v1 answered reachability with `isPotentiallyReachable` alone
  and read that site `true` at `-O1` and above (`false` at `-O0`, where that
  scope has no dispatch), and printed the partial line for it.

  v2 asks twice. First `isPotentiallyReachable`, exactly as v1; a `false` there
  is final. Only where it says `true`, a second search follows the CFG from the
  memset, carrying for each **modelled slot** the constant last stored into it
  on the current path, and at a `switch` whose condition is a load from such a
  slot, read on the current walk of that block, it follows only the edge that
  constant selects (the default when no case matches). Every other edge, and
  every edge of any other terminator, is followed. A slot is modelled only when
  every one of its users is a non-volatile store *into* it of a `ConstantInt` of
  its own type, or a non-volatile load *from* it of its type — nothing else can
  write it and its address goes nowhere, so its value on a path is the constant
  last stored on that path. At the memset every slot is "unknown" (the search
  does not look backwards), and an unknown slot keeps all of its switch's edges.
  The model goes by that shape, not by clang's slot name: a source variable of
  the same shape switched on directly is pruned the same way, and for the same
  reason just as soundly (in the corpus sweep below no site changed for that
  reason).

  **The soundness rule:** v2 turns `true` into `false` only when every CFG path
  from the memset to every use goes through a modelled switch edge that is
  infeasible on that path. It never turns `false` into `true` (the first
  question is v1's, unchanged). Past 65 536 explored (block, slot values) pairs
  the search gives up and answers `true` — the direction `isPotentiallyReachable`
  gives up in. The fixture loop has a guard for exactly the wrong answer this
  could give: `loopbreakuse`, where the memset is followed by `break` and the
  buffer is read after the loop; the break reaches the read *through* the
  dispatch switch, on the edge its own constant selects, and must stay `true`. A
  deliberately unsound build that took the switch's default edge instead reads
  it `false` and the checker exits 2 (measured below).

  Measured over the whole erasure corpus (below): the refinement changed 16
  sites, all `true` → `false`, all at `-O1`..`-Os`, in exactly
  `fable_N_token_r3`, `sonnet_N_token_r1` and `sonnet_S_pwverify_r1` (the
  `return` inside the loop, and in the last file the two `return 0` inside the
  nested hex-decoding loop), and each now reads what it reads at `-O0`.
- **What it still over-approximates.** Everything the dispatch model does not
  describe is plain reachability, as in v1:
  - any other correlation between a stored value and a later branch — a flag
    (`ok = 0; … if (ok) use(buf);`), a loop counter, the return-value slot
    compared in an `if`, a condition on an ordinary variable. Only a `switch`
    on a load is ever pruned, and only on a slot of the shape above;
  - a slot whose constant was stored *before* the memset (the search starts
    with every slot unknown), and a switch whose load sits in another block;
  - a dispatch slot with any other user (a lifetime marker, a GEP, a call, its
    address stored somewhere) — clang's own slot has none, measured on the
    three files above; a different front end or a later clang might;
  - `isPotentiallyReachable` giving up on a large CFG, and the second search
    giving up past its bound: both answer `true` (how close any search in the
    corpus came to the bound was not measured).

  Each of these can add a partial line; none can remove one. The repair loop's
  results still call `followedByUse` "a hint that can over-approximate", and
  after the measurement below that is still true in the sense that needs no
  change of level: a flag tested before a use, a constant stored before the
  memset into a slot the source itself switches on, and the search bounds can
  make a site read `true` at `-O0` as well as above it. The items that concern
  clang's own dispatch — its slot holding a constant stored before the memset,
  another user of that slot, a switch whose load sits in another block — exist
  only where the dispatch does: where lifetime markers give a scope its
  cleanup, which is at `-O1` and above (and at `-O0` under a sanitizer that
  writes the markers there, `-fsanitize=address` with its default
  use-after-scope among them), and where a scope has a cleanup of another kind, at
  every level (two items down). In this corpus none of them made any site read
  differently from `-O0`, which says nothing about a front end, or a later
  clang, that emits those shapes.
- **On the r2 corpus, site by site, v2 reads at `-O1`..`-Os` what it reads at
  `-O0`.** The v1
  against v2 table below shows the per-level counts agreeing; this is the claim
  for each site. Measured 2026-09-12 with
  `../eval/repair-loop/tools/fbu-levels.mjs`, plugin `db3298cf…73a4c8`, clang
  18.1.3: the 360 erasure-family files the repair loop measures (its own
  selection, `../eval/repair-loop/lib/corpus.mjs`), the find step's `FLAGS` plus
  `-gline-tables-only` so that every site carries a line, module scope, dry
  run, `-O0`..`-Os`; 3960 compiles, every record accepted by
  `../eval/repair-loop/lib/pin-record.mjs`. 251 sites at each level. At each of
  `-O1`, `-O2`, `-O3` and `-Os`, all 251 join their `-O0` site on (file,
  function, index) with the same line: 0 sites on one side only, 0 lines
  differing, 0 duplicate keys, 0 files not compared. Of the 1004 joined
  (site, level) pairs, 0 read a different `followedByUse` — 0 `false` → `true`,
  0 `true` → `false`, 0 into or out of `null` — and `lengthBytes`, `destKind`
  and `alreadyVolatile` agree in all of them. Two controls in the same run:
  `-O0` compiled twice gives 0 differences and the same `evidenceDigest` in
  360/360 files; every level compiled again without `-gline-tables-only`
  gives records equal on every field but `pinned[].line` in 1800/1800 — with
  `context` (a clock) and `evidenceDigest` (which covers the line) dropped
  before the comparison — and a line on 1255 of 1255 (site, level) pairs with
  the flag, on none without. The v1 plugin
  through the same tool — `aa7329c3…f0a66` again, rebuilt from
  `git archive 1ae6438~1` of this directory and of `../llvm-pass/src`, which
  its build compiles in, its records read by that commit's `pin-record.mjs`
  because this tree's refuses `wipe-pin-v1` — gives exactly the 16 sites
  listed below, the four error-path sites `false` at `-O0` and `true` at each
  of `-O1`..`-Os`, and no other difference: the join finds the level
  dependence it is there to find. What this does not cover: `-O0` is the
  reference, not the truth, so a site the list above makes wrong at every
  level alike does not show, nor would a reading through a dispatch that `-O0`
  has as well (next item; this corpus has none); one corpus, one clang, x86-64.
- **Where `-O0` has the dispatch too.** clang 18.1.3 writes no lifetime markers
  at `-O0` in these compiles (it does under `-fsanitize=address`, below), so a
  scope whose only cleanup would be its markers has no dispatch there; the
  three files of v1's 16 sites are that case. A scope with a cleanup of another
  kind has the dispatch at `-O0` as well, and a reading through it can then be
  the same at every level, which a comparison with `-O0` cannot show. Measured
  2026-09-12 with v1 `aa7329c3…` and v2 `db3298cf…` on three probes generated
  into the lab, each an error-path wipe (`memset`, then `return -1`) inside a
  loop whose body declares the buffer: front-end IR from the find step's
  `FLAGS`, the level and `-emit-llvm -Xclang -disable-llvm-passes
  -fno-discard-value-names`; records from the same `FLAGS` plus
  `-gline-tables-only`, module scope, dry run, each read by the
  `pin-record.mjs` of its own schema. With a VLA in that body, or a local
  carrying `__attribute__((cleanup))`, the `-O0` IR already has a
  `cleanup.dest.slot` and a switch on it, and v1 reads the wipe `true` at all
  five levels; the same body with neither has no slot at `-O0`, and v1 reads it
  `false` there and `true` at `-O1`..`-Os`. v2 reads all three `false` at all
  five levels. With `-fsanitize=address` the plain probe has lifetime markers,
  the slot and the switch at `-O0` too, and reads `true` on v1 there, `false`
  on v2. The site-by-site measurement above does not meet this case: the `-O0`
  IR of the 360 erasure-family files has no `cleanup.dest.slot`, no switch on
  one, no `llvm.stacksave` and no lifetime marker in any file, while at each of
  `-O1`..`-Os` 248 files have the slot, 39 a switch on it (the three files of
  v1's 16 sites among them) and all 360 lifetime markers.
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
# the same source builds against LLVM 15 to 20: -DLLVM_DIR=$(llvm-config-<N> --cmakedir)
# (measured, *2026-11-09: where the buffer barrier goes…* under *Measured*);
# load each build only into clang-<N>

# one cell
WPIN_TARGET_FNS=encrypt_blob \
  bash compiler/llvm-repair/scripts/pin.sh ~/vg-build/llvm-repair/libWipePin.so \
       <lab>/cell.json -O2 -c file.c -o <lab>/cell.o
```

`pin.sh` exit codes:

| exit | meaning |
|---|---|
| `0` | clang succeeded; a `wipe-pin-v3` record was written; it made at least one repair — `pinnedCount + barrierCalls.barrierCount + zeroCopy.repairedCount + bufferBarriers.count > 0` (`../schema/wipe-pin.md` §14.8); every requested name resolved. **Not** "the wipe survived", and not even "the wipe was repaired": a pinned initialiser counts. `followedByUseCount` and the partial line are where that shows. |
| `1` | clang failed (this includes a plugin built for another LLVM that crashes clang, or cannot be loaded, before its pass runs) |
| `3` | clang succeeded and there is no usable record: the plugin refused to install (a configuration it refuses, or the version handshake), its pass never ran, the record could not be written, or what was written is not a `wipe-pin-v3` record `python3` can read (a v2 record from an older build is one) |
| `4` | clang succeeded and a record was written, but nothing was repaired: the sum above is 0 (a dry run, a misspelt name, nothing eligible in scope, a call-shaped wipe with its switch off) or a requested name did not resolve |

`pin.sh` reads the record with `python3` (no `jq`), and writes
`<lab>/cell.manifest.kv` and `<lab>/cell.stderr.txt` next to it. The manifest
has plugin sha256, compiler version, clang's `rc`, `status` (the exit code),
what the plugin was asked (the seven `WPIN_*` settings), and what the record
says: `pinnedCount`, `wouldPinCount`, `barrierCount`, `zeroCopyRepairedCount`,
`bufferBarrierCount`, `repairCount` (their sum with `pinnedCount`),
`hostChecked`, `followedByUseCount` (sites with `followedByUse: true`),
`unresolved` (comma list of names that did not resolve, empty if none),
`exactAll` (`true` when every resolved name is an exact definition; `true` when
there are none, as in module scope) and `recordError` (why a written record was
not usable, empty otherwise). Those fields are empty when there is no usable
record.

### Everything WipePin prints on stderr

| line | when |
|---|---|
| `WipePin: refusing to install: <reason>` | not installed; followed by explanatory lines for "no target". Also the version handshake's two refusals (`the module was produced by clang <N> …`, `intrinsic table mismatch: …`), printed when the pass runs |
| `WipePin: the module's llvm.ident names no clang version (<"ident" or absent>); the host compiler was not checked against LLVM <M>` | the handshake had no producer version to compare (`host.checked: false`); the record is written |
| `WipePin: target <name> not-in-module` / `declaration-only` | a requested name did not resolve |
| `WipePin: target <name> is not an exact definition (<linkage>); the copy that runs may come from another translation unit` | a resolved name with `exact: false` |
| `WipePin: dry run: <n> zero-fill llvm.memset site(s) would be pinned; none was changed` | dry run with eligible sites |
| `WipePin: dry run: <n> zero-fill memset or bzero call(s) would get a barrier; none was changed` | dry run with `WPIN_BARRIER_CALLS=1` and calls it would repair |
| `WipePin: dry run: <n> copy(ies) from an all-zero constant would be repaired; none was changed` | dry run with `WPIN_ZERO_COPY=1` and copies it would repair |
| `WipePin: dry run: <n> buffer barrier(s) would be placed; none was changed` | dry run with `WPIN_BUFFER_BARRIER=1` and barriers it would place |
| `WipePin: buffer barrier: <n> zero fill(s) in scope write memory that is not a stack buffer of the function (an argument, a global, the heap, or a pointer this pass does not follow); no barrier covers them` | `WPIN_BUFFER_BARRIER=1` and such zero fills in scope |
| `WipePin: buffer barrier: <n> buffer(s) not barriered: every zero fill is followed by a later use (read as an initialiser; a wipe that later code still touches, even code the optimiser removes, is counted here too)` | `WPIN_BUFFER_BARRIER=1` and buffers in scope whose every zero fill a later use follows in the IR before optimisation — an initialiser, or a wipe the source touches again (in a dry run as well) |
| `WipePin: buffer barrier: <n> buffer(s) not barriered: the buffer does not dominate a return its wipe reaches, or there is no place (an alloca or variable-length array inside a branch or loop, or a function that does not return)` | `WPIN_BUFFER_BARRIER=1` and buffers in scope where a reachable return a wipe reaches is not dominated by the `alloca`, or that have neither a reachable lifetime end nor such a return (in a dry run as well) |
| `WipePin: nothing to pin in scope in <module> (zero-fill llvm.memset in scope: 0; unhandled in scope: …)` | no zero-fill memset in scope, and nothing a switch that is on would repair; the tail lists the nine counters |
| `WipePin: partial: pinned <P> site(s) in <module>; <K> followed by a later use of the same buffer (initialiser-like, not a wipe); unhandled in scope: libcallMemset=.. memsetChk=.. nonZeroFill=.. atomicMemset=.. inlineWrapperMemset=.. bzeroCall=.. inlineWrapperBzero=.. zeroGlobalCopy=.. zeroGlobalCopyCall=..` | some site in `pinned[]` has `followedByUse: true` (K > 0), or a pin, barrier or copy repair was made while an in-scope `unhandled` counter is > 0. One line. P counts pins only; in a dry run it is 0. |
| `WipePin: cannot write the record to WPIN_OUT (…); the IR was changed/not changed and nothing records it` | the record could not be opened |
| `WipePin: a second module (…) reached this pass in one process; …` | a host handed the pass two modules |
| `WipePin: loaded into a pipeline built without the pipeline-start extension point (an LTO link, or a compile under -disable-llvm-passes), where this pass does not run; nothing was pinned in this process, and the file at WPIN_OUT was removed when the plugin loaded` | the plugin installed, and a pass ran in this process through a pipeline that was built without the pipeline-start extension point: an LTO link (full or thin, any level), or a `-disable-llvm-passes` compile that writes IR. Once per process. The ending is `… and there was no file at WPIN_OUT when the plugin loaded` when the load-time callback found nothing to remove. |
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
`pin.sh` alone where it must exit 3. Then five groups that do not involve the
observer, generated into the lab. Every record in the first four, and in the
observer cells, is read as `wipe-pin-v3` with the three switches off (each
block `enabled: false`) and `host.checked: true`:

- **shapes**: small sources, each compiled `-g` through `pin.sh` at `-O2`,
  whose record and stderr have a known right answer — an `= {0}` initialiser
  followed by a zeroing loop (`initloop`), the same initialiser with the wipe in
  a helper (`inithelper`), a clear-before-fill memset and a trailing wipe memset
  on one buffer (`initwipe`), a clear-before-fill memset whose later uses all
  go through a copied pointer (`aliasinit`), a trailing memset only
  (`trailing`), a C99 inline target (`c99inline`), a C++ inline target
  (`cxxinline`), and, each also at `-O0` and `-O1`, the error-path wipe inside
  a loop (`loopreturn`: `memset; return -1;` in the body, which also reads the
  buffer, plus a trailing memset — `false`, `false`, no partial line) and its
  soundness guard (`loopbreakuse`: `memset; break;` with the buffer read after
  the loop — `true` and the partial line);
- **stale records**: clang run directly (not `pin.sh`, which deletes the path
  itself) with a file that is not this compile's record already at `WPIN_OUT`:
  a refused compile, a `-Xclang -disable-llvm-passes` compile, a normal compile,
  and a directory at `WPIN_OUT`;
- **lto**: the `trailing` shape at `-O2` compiled `-flto` with WipePin
  (`lto-full-compile`: a valid record, a bitcode object, no WipePin line), and
  the same compile followed by a link with WipePin on the link line and the
  same `WPIN_OUT`, full and thin (`lto-full-linkline`, `lto-thin-linkline`:
  link rc 0, the link-time line exactly once in its "removed" form, nothing at
  `WPIN_OUT` afterwards, and the linked shared object byte-identical to a stock
  link of the same bitcode);
- **xtu**: a wipe helper in another translation unit, the loss only a link can
  create. `secure_wipe(void *p, size_t n) { memset(p, 0, n); }` in `wipe.c`;
  `handle()` in `use.c`, the helper's one caller, fills a 32-byte local
  (`derive`), reads it (`use`) and calls `secure_wipe(key, sizeof key)` as its
  last use; `main.c` calls it; `io.c` holds `derive` and `use` and is never
  compiled `-flto`, so no link sees into them. `wipe_kept()` beside `handle` is
  the control: a memset of its own on a buffer `use` reads afterwards, which no
  build may remove. Linked into an executable at `-O2` (`-fuse-ld=lld`):
  stock without LTO (`xtu-nolto`: the call stays and the helper's memset with
  it), and for full and thin LTO a stock build (`xtu-*-stock`: the link inlines
  the helper, and the fill is a dead store), a build with WipePin at the
  compile of `wipe.c` only, `WPIN_TARGET_FNS=secure_wipe` (`xtu-*-pin`: the
  volatile memset is inlined and kept), and the same as a dry run (`xtu-*-dry`:
  as stock, byte for byte). The checker disassembles each executable itself
  (`objdump -d`) with `../gcc-repair/scripts/objdump_fill.py` — imported, not
  copied; the WipePinGcc loop reads its own xtu cells with it — and reads
  whether a call to `secure_wipe` is left in `handle` (a cell whose helper was
  not inlined, where inlining is the point, disagrees rather than passes), and
  where the 32-byte fill is. What a cell was built as is read from what the
  build left, not from the runner's word: the LTO form from the block each
  `-flto` object's module summary is in (`llvm-bcanalyzer-18 -dump`:
  `GLOBALVAL_SUMMARY_BLOCK` for thin, `FULL_LTO_GLOBALVAL_SUMMARY_BLOCK` for
  full), the linker from the executable's `.comment`, where lld writes
  `Linker: <version>`, and the link from whether the executable still defines
  `secure_wipe` (measured: a ThinLTO link of this fixture keeps it, a full-LTO
  link does not).
- **v3**: what `wipe-pin-v3` adds, target `handle`, `-O2`, no `-g` unless
  said. Eight cases, one per call-shaped wipe a switch repairs: `memset` under
  `-D_FORTIFY_SOURCE=2` and `=3` (`v3-fort2`, `v3-fort3`: `memset.inline`),
  `bzero` under both (`v3-bzero-fort2`, `v3-bzero-fort3`: `bzero.inline`),
  `__builtin___memset_chk` through a local pointer (`v3-chk`), `memset` under
  `-fno-builtin` (`v3-libcall`), and `memcpy(key, vg_zeros, 32)` from a
  `static const` all-zero array without FORTIFY and under `=2` (`v3-zcopy`:
  `llvm.memcpy`; `v3-zcopy-fort2`: `memcpy.inline`). Each source also holds the
  control `wipe_kept()`, whose fill `use()` reads afterwards. Each case is
  compiled `-S` four times — stock, through `pin.sh` with the switches unset
  (`off`), with its switch `=1` (`ext`), and with its switch and
  `WPIN_DRY_RUN=1` (`dry`) — and each `-S` is assembled and linked with the same
  stock `io.c` and `main.c` into an executable the checker disassembles, as in
  the xtu cells. The checker expects: the subject's 32-byte fill absent in
  stock, off and dry and present in ext (present in all four under
  `-fno-builtin`, where the call is opaque); the control present everywhere;
  off and dry `-S` byte-identical to stock's, ext's not; the off record
  counting the call in its one `unhandled` counter with `pin.sh` 4, the ext
  record holding exactly one site with every counter 0 and `pin.sh` 0, the dry
  record the same site with the repair count 0 and `pin.sh` 4. With
  `--baseline <a 22e7222 build>` on the runner a fifth compile, `orig`, runs
  that v2 build with the same target, and off's `-S` must equal it byte for
  byte (`check-fixture-loop.py --require-baseline` makes a run without it
  disagree; without either flag the column reads `not run`). The same four
  arms for the buffer barrier on a wipe written as a loop of zero stores,
  `for (unsigned i = 0; i < sizeof key; i++) key[i] = 0;` as `handle`'s last
  statement, beside a control that zeroes its buffer the same way and then
  reads it (`v3-loop`, and `v3-loop-g` compiled `-g`): off has nothing to pin
  or count (`nothing to pin`, every counter 0, `pin.sh` 4), ext one site
  `{handle, null, 32, loop-store, lifetime-end}` (`buffer` `key` with `-g`)
  and `count` 1, dry the same site with `count` 0 and the dry-run line; and in
  `v3-loop` the control's `-S` text, from its label to `.Lfunc_end`, is the
  same in ext as in stock. The same four arms for the loop written through an
  advancing pointer, `while (n--) *p++ = 0;` (`v3-loop-ptr`). Then
  `v3-buffer-init`: `= {0}`, `derive`, `use`, no wipe, through `pin.sh` with
  `WPIN_BUFFER_BARRIER=1`: the initialiser's memset pinned as without the
  switch (`followedByUse: true`, the partial line), **no** buffer barrier
  (`count` 0, no `#APP` in `handle`), and the line counting one buffer not
  barriered as initialiser-like. Then twelve cells through `pin.sh` alone, each
  compiled `-S` and `-S -emit-llvm` with the same settings (the two records
  must be the same), beside a stock `-S`, with the `.ll` read by `opt-<N>
  -passes=verify` (exit 0 required; a release clang does not verify the IR a
  plugin leaves): a variable-length array inside a branch, wiped by a loop, at
  `-O0` and `-O2` (`v3-vla-branch-O0`, `-O2`: no barrier, the no-place line,
  nothing to pin, `pin.sh` 4, the `-S` byte-identical to stock's); a loop wipe
  followed by `__attribute__((musttail)) return next(x);` at `-O0`
  (`v3-musttail-O0`: one site with anchor `ret` — the unreachable `ret` clang
  also emits is not counted — one barrier call in the `.ll`, and the musttail
  call directly followed by its `ret`); a variable-length array in a block,
  wiped by a loop, then a musttail call, at `-O2` (`v3-vla-musttail-O2`: the
  backend compiles it, one site with anchor `ret` and `bytes` null, the
  musttail call directly followed by its `ret`); the loop wipe and musttail
  call at `-O2` and `-Os` (`v3-musttail-O2`, `-Os`: one site with anchor
  `ret`, one barrier left in the optimised `.ll`, the `-S` not stock's); a
  return on one path and a musttail call on the other (`v3-musttail-exits-O2`:
  two sites, `ret` then `lifetime-end`, two barriers left); a wipe loop bounded
  by a pointer comparison (`v3-loop-ptrcmp-O2`: one site at the lifetime end,
  one barrier left); a wipe only on a path that ends in `exit` (`v3-exit-O2`:
  no barrier, the no-place line, nothing to pin, `pin.sh` 4, the `-S`
  byte-identical to stock's); an initialiser written as a
  loop of zero stores (`v3-buffer-initloop`: no barrier, the initialiser-like
  line, nothing to pin, `pin.sh` 4, the `-S` byte-identical to stock's); a
  buffer declared in a loop body and wiped at the end of each iteration
  (`v3-buffer-inloop`: one site with anchor `lifetime-end`, no WipePin line);
  and `__builtin_memcpy_inline(key, vg_zeros, 32)` under `-ffreestanding` with
  `WPIN_ZERO_COPY=1` (`v3-zcopy-inline`: one zero-copy site, `form`
  `intrinsic`, `callee` `llvm.memcpy`, and no call of `memset` in the plugin's
  `-S` or in stock's). Then three `pin.sh` runs whose configuration must be refused
  (`WPIN_BARRIER_CALLS=2`, `WPIN_ZERO_COPY=true`, `WPIN_BUFFER_BARRIER=2`:
  exit 3, no record, exactly the refusal line), and the version handshake: the `trailing` shape's
  front-end IR (`-O2 -Xclang -disable-llvm-passes -S -emit-llvm`) compiled back
  with `-x ir -S`, through `pin.sh` and stock, as clang wrote it
  (`v3-ident-same`: a record, `host` as clang's ident says, `intrinsicsCompared`
  equal to the count of table intrinsics the checker finds declared in the
  `.ll`), with its `!llvm.ident` rewritten to the next major version
  (`v3-ident-other`: refused, no record, `pin.sh` 3, and the `-S` output
  byte-identical to stock's), and with no `!llvm.ident` (`v3-ident-none`: a
  record with `checked: false` and the no-version line).

```sh
cmake -S compiler/llvm-pass -B ~/vg-build/llvm-pass -G Ninja \
      -DLLVM_DIR=$(llvm-config-18 --cmakedir) && ninja -C ~/vg-build/llvm-pass
bash compiler/llvm-repair/scripts/run-fixture-loop.sh --lab <lab> \
     --observer ~/vg-build/llvm-pass/libIrCheckpoints.so \
     --wipepin  ~/vg-build/llvm-repair/libWipePin.so \
     [--baseline <a WipePin built from 22e7222>]
python3 compiler/llvm-repair/scripts/check-fixture-loop.py --lab <lab> \
     [--require-baseline]                                              # 0 / 2 / 3
```

The runner decides nothing and the checker compiles nothing (it runs `objdump`
on the xtu executables and `llvm-bcanalyzer-18` on their objects, so binutils
and llvm-18 are needed besides `python3`; `--bcanalyzer` names another
llvm-bcanalyzer). The fixtures and the shape sources are generated into the lab
on every run, never into this tree. There are no default lab or build paths in
either script.

## Measured

**Since this section (2026-11-11):** `-O1`, `-O3` and `-Os`, C++, LTO with the
v3 switches, the run-time readout on clang 16, 17 and 19, loops a model was
asked to write, and a QuickJS build through `../pin-wrapper/vgpin-cc` were
measured with the builds of *2026-11-10, later*, without changing this
plugin's source: `../eval/repair-reach/README.md`. Not everything there is
repaired: four libstdc++ `fill` shapes are not, a template's repaired copy can be
dropped at link time, and one of 44 deleted model-written loops is not kept. What is left of the repairs
at the end of the pipeline is read by a separate plugin, `../wipe-witness/`.

clang 18.1.3, Ubuntu 24.04 (WSL), plugin built with g++ 13.3.0, 2026-09-11.
Every number below was copied from a run, not from reasoning.

### 2026-11-10, later: no place in a dead block or on a path without the wipe, loops bounded by an address comparison, and the not-barriered lines

Measured 2026-11-10 with the source as it stands in this tree
(`src/WipePin.cpp` sha256 `675c1a9e…`; the afternoon's state before the last
item below was `a5036cdc…`). The scripts, the expectations written
before each run, the changes made afterwards with their times and reasons, and
the data are lab notes kept outside this repository. What changed against the
builds of *2026-11-10* below (`a927762a…`), all of it in the buffer barrier
(*The buffer barrier*, "Where" and "Only a wipe"):

- A lifetime end in a block no path reaches is no longer a place, and a `ret`
  that a wipe reaches before the buffer's lifetime ends is one at every level.
  A refuter found that a loop wipe before a musttail call got its barrier in
  such a block at `-O1` and above: on the build of the next subsection, with
  `WPIN_BUFFER_BARRIER=1` and the target named, `-O1`, `-O2`, `-O3` and `-Os`
  each gave a record with `count` 1 and anchor `lifetime-end`, `pin.sh` 0, no
  barrier left in the optimised IR, and a `-S` byte-identical to stock's (this
  build: anchor `ret`, one barrier left, the `-S` differs). The probe table of
  *2026-11-09* below gave that cell at `-O2` as placed; whether the barrier
  survived was not read there. A buffer whose wipe reaches a `ret` its `alloca` does
  not dominate now gets no barrier at all, rather than barriers on the paths it
  dominates.
- A lifetime end that only paths without a wipe reach is no longer a place,
  and a buffer whose wipe reaches a block that ends in `unreachable` (after
  `exit` or `abort`) gets no barrier at all. A reviewer of the afternoon's
  build found the case: a wipe only on the path that ends in `exit` got no
  barrier, the other path's lifetime end got one, and the record said 1 and
  `pin.sh` 0. With a key computed in the function and wiped only before
  `exit`, that build lost the wipe at `-O2` and `-Os` as stock does, and at
  `-O2` the useless barrier made the key be written to the stack, where stock
  kept it in registers; this build places none, prints the no-place line, and
  `pin.sh` exits 4. A reviewer's second finding is left in the code and
  written down instead (*The buffer barrier*, "Only a wipe"): an initialiser
  used afterwards only through an address stored in a struct gets a barrier.
- A comparison of the buffer's address is not a later use, so
  `for (p = key; p < key + n; p++) *p = 0;` reads as a wipe (on the build
  before, it read as an initialiser at every level and got no barrier).
- The two not-barriered lines are reworded (*Everything WipePin prints on
  stderr*): the initialiser line no longer says "not a wipe".

**Builds** (`cmake -G Ninja -DLLVM_DIR=$(llvm-config-<N> --cmakedir)`, Ubuntu
24.04 under WSL, the Ubuntu packages of LLVM 15 to 20): 0 warnings each; the
LLVM 18 build, made again into another directory, has the same sha256; the
source's sha256 was the same before and after the builds.

| LLVM | `libWipePin.so` sha256 |
|---|---|
| 15.0.7 | `541f52b3365e5c874992a2546bf6f5aec206797e9a3e4f497ae1dc9a709d3c67` |
| 16.0.6 | `3a273d1905f166ae192ebdbce7e375e731b3be7b31220bd0df2a0afd68320eb2` |
| 17.0.6 | `85749599138b1db42bb2c548be6eeb5a366729273b874e19061c8f560d0e9f84` |
| 18.1.3 | `7c9d11f2053182eb66497f14a6ea07115de43ae09f333a51e1facdd9c9609b99` |
| 19.1.1 | `461689aee864af0bb4ca9a665db9971e35cb73fd5f289fe73ec0c117c0174e74` |
| 20.1.2 | `535e85897683e6002e2b27d241346211090ecfdc290d2d510d53f3666102b1cc` |

The afternoon's builds of the state before the last change (LLVM 18:
`239e8230…`) are the ones the fixture loop and the corpora were first run with
below; the runs that matter were repeated with the builds above, as each
paragraph says.

**Fixture loop:** "all 72 cells as expected" with the builds above, in the CI
form and with each of two baselines (the `22e7222` build, and the afternoon's
LLVM 18 build, `239e8230…`), `off==v2` `yes` in 11/11 in each baseline form;
with the afternoon's builds, 71 cells, and the same against `22e7222` and
`8f2bd520…`. The five new cells are `v3-musttail-O2`, `v3-musttail-Os`,
`v3-musttail-exits-O2`, `v3-loop-ptrcmp-O2` and `v3-exit-O2` (*The second
instrument: the fixture loop*); where the `.ll` is optimised IR they ask that
the barriers the record counts are still there. The first run of the new cells disagreed in one place, the checker's:
it expected `pin.sh`'s `repairCount` to be 1 wherever something was repaired,
and `v3-musttail-exits-O2` repairs two; the checker now expects the number
placed, and was run again on the same lab.

**The corpora again, with these builds.** Every run of the next subsection was
repeated with the afternoon's builds (LLVM 18 `239e8230…`) and the builds of
the GCC twin (its *2026-11-10, later*), by the same scripts with only the build
paths changed, and then once more with the builds above: r4 L, E3 and
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
varied in five cross-version pairs. The second repetition, with the builds
above, gave rows equal to the first's in every field (108,108 of 108,108; the
change it carries does not occur in these corpora), the same summaries, the
same no-wipe summaries and wrapper table, and the same `pin.sh` exits and
records in the handshake matrix. The numbers of the next subsection therefore
hold for these builds too.

**The checker's own tests.** `test/test_check_fixture_loop.py` has 118 tests
(`python3`, no compiler): every record check, and every cell group graded on
synthetic labs — the single cells including the four new ones, the four-arm
cells, the refusals, the version handshake, a loop cell and a shape cell. A
refuter weakened the checker one check at a time (43 versions) and 39 of them
still passed the 55 tests of *2026-11-09*; all 43, and 14 more aimed at the new
cells, now make the file fail (lab notes). That work also found the record
check of `followedByUse` accepting `1` and `0` for `true` and `false` (Python's
`in` compares with `==`), in this checker and in
`../gcc-repair/scripts/wpin_gcc_record.py`, which `pin-gcc.sh` uses, both
since `22e7222`; both now require a boolean or `null`, and a test of each
fails on the old line.

Not measured with these builds beyond what this subsection and the next say:
the shapes this subsection fixes do not occur in the three corpora (no musttail
call, no loop bounded by an address comparison), so on them the fixture loop's
cells and the probes are the only reading; levels other than `-O2` on the
corpora; C++; LTO; the cost in time or size; and any loop a model wrote.

### 2026-11-10: the builds of the 2026-11-09 fixes, LLVM 15 to 20, on r4 L and its E3 and E5 rewrites (`-O2`)

Measured 2026-11-10 with the source as it stood before *2026-11-10, later*
above (`src/WipePin.cpp` sha256 `a927762a…`), built again from scratch for
LLVM 15 to 20 into a separate directory: 0 warnings each, and each build
byte-identical to the one listed in the next subsection (LLVM 18:
`8f2bd520…`, which recorded the tracked repair-loop rows that morning; the
build of the current source recorded the same rows again that afternoon,
`../eval/repair-loop/data/r2-v3-rerecord.json`). The scripts (copies of those
of the runs below, with only the plugin paths changed), the expectations
written before the run, the one comparison rule added after it with its time
and reason, and the data are lab notes kept outside this repository. Same
toolchain as *`wipe-pin-v3`* below. Every corpus row is `-O2`, the target and
its helpers named (functions scope), with `_FORTIFY_SOURCE` undefined, 2 and
3; "kept" = `verdictOf`, the zero-store count and the count difference all say
so; the denominator is the files stock deleted (below the tables). E3 v2's 52
files all use one loop template, an index loop over the buffer with a constant
bound; other forms of loop wipe are measured only by fixture cells.

**The loop rewrites, clang-18** (E3 v2, read as under *The buffer barrier*
below):

| | stock deleted | `ext` kept (`WPIN_BARRIER_CALLS=1 WPIN_ZERO_COPY=1`) | **`+ WPIN_BUFFER_BARRIER=1` kept** | disagreeing readings |
|---|---|---|---|---|
| E3 v2 (wipe written as a loop), each of the 3 settings | 50 of 52 | 0 | **50/50** | 0 |

**Every LLVM**, each cell the same in all three settings:

| clang | r4 L: `ext` kept | E3 v2: `ext` kept | E3 v2: **`+ WPIN_BUFFER_BARRIER=1` kept** |
|---|---|---|---|
| 15 | 50/50 | 0 of 49 | **49/49** |
| 16, 17, 18, 19, 20 | 51/51 each | 0 of 50 each | **50/50 each** |

On E3 v1 (each wipe rewritten as `bzero`) and v3 (as
`__builtin___memset_chk`), and on E5 v4, v5 and v7 (v7: as a copy from a
`static const` zero array), `ext` kept every file stock deleted, in every
setting and on every LLVM (50/50 on clang-15, 51/51 on clang-16 to 20), and
adding `WPIN_BUFFER_BARRIER=1` kept no fewer (cells where it kept fewer: 0).
On E5 v8 (`explicit_bzero`) and v10 (a `volatile` function pointer) stock
deleted no wipe. In every row of these nine sets (52 files × 3 settings × 6
LLVMs each) the dry run compiled to the stock `-S`, with and without the
buffer barrier, and with every switch off this build compiled to the `-S` of
the `22e7222` source built for the same LLVM (with the two build changes LLVM
15 to 17 need), for the file with and without its wipe. Apart from r4 L,
these sets are machine-made rewrites of its 52 generated files, and all of it
is `-O2` only: no loop a model wrote was measured. The denominator is the files the verdict reads as deleted by stock. The files
outside it are not counted: on E3 v2, two per version on clang (three on
clang-15) and one or two on GCC, among them files of which stock deleted only
part of the wipe; on every one of them, in every setting, the buffer barrier
left more zero stores than stock (63 file × setting rows, lab notes).

**Against a run of the same scripts on the builds before the fixes** (LLVM 18
`b509c308…`, the build of *The buffer barrier* below, and builds of the same
source for LLVM 15 to 17, 19 and 20; that run is in the lab notes, not in this
README). Row by row over the 58,968 clang rows (the nine sets × 52 files × 3
settings × 6 LLVMs × 7 arms), every field, stderr included: 58,320 the same,
648 different, no verdict changed. Every difference is in an arm with the
buffer barrier (or its dry run) and in one of two files, `sonnet_S_dbpass_r3`
and `sonnet_S_pinpad_r2` (each set's version of them). Both hold a `memset`
initialiser whose buffer is used afterwards; where that initialiser was the
buffer's only zero fill — in the file built without its wipe, and in E5 v5,
v8 and v10 in the file with it too, since the wipe there is not a memset of
that buffer — the build before placed a barrier and this one does not. 17
representative cells were compiled again with both builds and read: the
differences are the barrier and the registers, frame and labels around it.
Over both vendors the comparison rule written before the run put 288 of the
differing rows outside its prediction, every one for stderr alone: the dry
run's `would be placed` line is not printed when the count is 0, and on gcc
the `pinned N` of the partial line falls by the barriers removed. The rule was
widened for exactly those two after the run, which is recorded in the lab
notes; under it nothing differed that was not predicted.

**Read at run time** (the harness of the runs below: the stack window and
registers read after the call returns), clang-15, 18 and 20,
`_FORTIFY_SOURCE` undefined and 2, on the 20 files of five tasks of each set:
in r4 L and in E5 v7 the secret was readable in 19 of the 19 files stock
deleted and in 0 with `ext`; in E3 v2 it was readable in 19 of 19 with stock,
in 19 with `ext`, and in 0 with the buffer barrier added. The same counts and
the same files as on the build before. "Not readable" is about the window the
harness reads, not a proof of absence.

**Files with no wipe.** The 39 files of the r2 corpus that the find step
labels as having no wipe written (one of them, `haiku_E_pinpad_r1`, clears a
`volatile` buffer in a loop, which the find step does not count as a wipe), at
`-O0`, `-O1`, `-O2`, `-O3` and `-Os` (195 compiles per arm), clang-18,
functions scope, with the corpus's control function appended: with every
switch off, with `WPIN_BUFFER_BARRIER=1`, and with all three switches on, the
`-S` equalled stock's in 195/195 and no barrier was placed; `pin.sh` at `-O2`
exited 4 for all 39, with the switch off and on. The files as written, without
the control function, in module scope: 195/195 in every arm. (With the control
function in module scope, the control's `memset` is pinned, so 39 of the 195
differ from stock, and its buffer gets no barrier: its `memset` is followed by
a use.) The build before changed one of these files, `haiku_E_pinpad_r1`, at
all five levels with the switch on; this build changes none.

**The version handshake**, the 6×6 matrix of the next subsection re-run with
these builds (108 compiles through `pin.sh`): the same refusals and records as
there — 18 cross-version compiles refused (clang rc 0, `pin.sh` 3, no record),
the 18 same-version compiles not refused, and 0 of the 90 cross-version
compiles with `pin.sh` 0 or a record. Of the 72 clang failures, rc 1 in 43,
127 in 28 and 139 in 1, where the run of the next subsection had 40, 28 and 4:
five pairs crashed with rc 1 in one run and 139 in the other. Five of the rc 1
are not crashes: clang-15 could not parse the IR a newer clang wrote for that
build (`unterminated attribute group`), the same five in both runs. How clang crashes
with a plugin built for another LLVM did not repeat between runs; that it
crashes before the pass, with no record, did. The front-end IR whose only
`llvm.*` declaration is `llvm.objectsize`, and its twin without
`!llvm.ident`, were refused by the third check in clang-19 with the LLVM 18
build, clang-17 with the LLVM 18 build and clang-18 with the LLVM 19 build,
with and without `WPIN_BARRIER_CALLS=1` (12/12, each refused `-S` equal to
stock's); clang-18 and clang-19 with their own builds accepted them (with
`WPIN_BARRIER_CALLS=1`: one barrier, `pin.sh` 0).

**Fixture loop:** "all 67 cells as expected" in the CI form and with each of
the two baselines, `off==v2` `yes` in 11/11 in each baseline form.

Not measured with these builds: levels other than `-O2` on the corpora (only
the no-wipe files were compiled at five levels); the run-time readout on
clang-16, 17 and 19; the no-wipe files on versions other than clang-18; C++;
LTO; the cost in time or size; and any loop a model wrote. No file of these
corpora has the shapes the placement and pointer fixes of the next subsection
are for (a musttail call, a variable-length array or `alloca`,
`__builtin_memcpy_inline`, `*p++ = 0`): for those, the fixture loop's cells
are the only reading.

### 2026-11-09: where the buffer barrier goes, initialisers, and the third handshake check

Measured 2026-11-09 evening with the source as it was then (`a927762a…`;
changed again in *2026-11-10, later*), after a
review found the build before it (`b509c308…`, *The buffer barrier* below)
placing barriers that make invalid IR, placing them on buffers that are only
initialised, and accepting IR from the wrong host. The same toolchain as
*`wipe-pin-v3`* below. The scripts, the expectations written before each run
(and the two changed after it, with the reason), and the data are lab notes
kept outside this repository. What changed: the barrier's `ret` places
(reachable, dominated, before a musttail call), no barrier on a buffer that is
only initialised (with a second, lifetime-bounded reading of "a later use"),
the pointer slot advanced by `p++` followed, `llvm.memcpy.inline` repaired as
`llvm.memset.inline`, and the handshake's third check. With the three switches
unset nothing of this runs but the third check, which changes no IR.

**Builds.** The same source against each LLVM, `-Wall -Wextra` on all three
compile commands of each build, 0 warnings each; the LLVM 18 build gave the
same bytes from a second build into a separate directory:

| LLVM | `libWipePin.so` sha256 |
|---|---|
| 15.0.7 | `1afa16d105442ddb5783c708c93aac237004d25ea0e59a1a3e342772acd8dc6f` |
| 16.0.6 | `040dbe5b458bec8c731c0f99c682f03c8307ce5e4af1854e72f5443fcc4d996f` |
| 17.0.6 | `092f7902309ec5d971306bfdab1bb627adfa07993b6a0bdc5b1487b83cbe5f4a` |
| 18.1.3 | `8f2bd520f03a6becef9e5ea9d28b91b8f06b9b45beb326f8f707693511f06b30` |
| 19.1.1 | `ab0bdfb8845904a98f94afa9a2eee1b6a87c04b14b80a25fdadbec69616d2988` |
| 20.1.2 | `6e6ed70537edcdf8b58d99fc70f68f1004cc55c066a01e4fbfd32dfcc4719fdf` |

Each loaded into its own clang on the one-function `memset` file below: a
record, `pin.sh` 0, `host` `{identMajor: N, builtMajor: N, checked: true,
intrinsicsCompared: 3}` for every N. Everything else in this subsection is the
LLVM 18 build unless it says otherwise.

**Fixture loop.** `run-fixture-loop.sh` rc 0 and `check-fixture-loop.py` exit
0, "all 67 cells as expected", three times: without `--baseline` (as `ci.yml`
runs it); with `--baseline` the `22e7222` build (`db3298cf…`) and
`--require-baseline`; and with `--baseline` the build before this change
(`b509c308…`) and `--require-baseline`, so that the switches-off `-S` of every
four-arm v3 case was compared byte for byte with both (`off==v2` `yes` in
11/11 each). The 59 cells of that build's run less one changed expectation,
plus eight new cells (*The second instrument*, above, describes each):

```
v3 (-O2, target handle)  cflags               switch / setting                        ext callee / host                 pin.sh off/ext/dry  subject stock/off/ext/dry        dry==stock  off==stock  off==v2
v3-loop-ptr              -                    WPIN_BUFFER_BARRIER                     loop-store                        4/0/4               ABSENT/ABSENT/PRESENT/ABSENT     yes         yes         yes      ok
v3-buffer-init           -                    WPIN_BUFFER_BARRIER=1                   memset (initialiser), no barrier  0                   -                                -           -           -        ok
v3-vla-branch-O0         -O0                  WPIN_BUFFER_BARRIER=1                   count=0                           4                   IR verify rc 0                   -           -S=stock    -        ok
v3-vla-branch-O2         -O2                  WPIN_BUFFER_BARRIER=1                   count=0                           4                   IR verify rc 0                   -           -S=stock    -        ok
v3-musttail-O0           -O0                  WPIN_BUFFER_BARRIER=1                   count=1 ret                       0                   IR verify rc 0                   -           -S!=stock   -        ok
v3-vla-musttail-O2       -O2                  WPIN_BUFFER_BARRIER=1                   count=1 ret                       0                   IR verify rc 0                   -           -S!=stock   -        ok
v3-buffer-initloop       -O2                  WPIN_BUFFER_BARRIER=1                   count=0                           4                   IR verify rc 0                   -           -S=stock    -        ok
v3-buffer-inloop         -O2                  WPIN_BUFFER_BARRIER=1                   count=1 lifetime-end              0                   IR verify rc 0                   -           -S!=stock   -        ok
v3-zcopy-inline          -O2 -ffreestanding   WPIN_ZERO_COPY=1                        zeroCopy 1                        0                   IR verify rc 0                   -           -S!=stock   -        ok
```

(The `off==v2` column of `v3-loop-ptr` is from the run against `b509c308…`;
against `db3298cf…` it read `yes` too.) The changed expectation is
`v3-buffer-init`'s: it expected a barrier with `reason` `memset` and the line
`1 of 1 barrier site(s) are on buffers whose every zero fill is followed by a
later use`, and now expects no barrier and the not-barriered line, for the
reason in *Only a wipe*. The checker's v3 record checks and the new cells'
grading have unit tests on synthetic records, `test/test_check_fixture_loop.py`
(55 tests, `python3`); each of seven deliberate breaks of the checker — the C6
major check, the C4 count check, the musttail check, the initialiser
expectation reverted to a barrier, the verifier's exit status ignored, the
evidence digest not re-derived, the two records of a cell not compared — made
that file fail, and the unbroken checker passed it. (Those tests graded two of
the new cells, `v3-musttail-O0` and `v3-buffer-init`; 39 of 43 one-check
weakenings of the checker passed them. See *2026-11-10, later*.)

**Probes** (`WPIN_BUFFER_BARRIER=1`, `WPIN_SCOPE=module`, `-S -emit-llvm`, then
`opt-18 -passes=verify`; every clang rc 0 and every verifier rc 0. The build
before, on the same sources: clang rc 0 every time, and verifier rc 1 on the
first row at `-O0` — `musttail call must precede a ret`, with `count` 2 — and
on the second row at both levels — `Instruction does not dominate all uses!`):

| source | `-O0` | `-O2` |
|---|---|---|
| a loop wipe, then `musttail return g(r)` | 1 barrier, anchor `ret`, before the musttail call (the unreachable `ret` not counted) | 1, anchor `lifetime-end` — **wrong**: that lifetime end was in a block no path reaches, the barrier went with it, and the `-S` was stock's (found 2026-11-10; *2026-11-10, later*) |
| `if (c) { char v[n]; … loop wipe }` | no barrier, the no-place line | no barrier, the no-place line |
| `unsigned char key[16] = {0}; derive(key); return use(key);` | no barrier, the initialiser line (the memset pinned as before) | the same |
| the buffer declared in a loop body, wiped each iteration | no barrier, the initialiser line (no lifetime markers at `-O0`) | 1, anchor `lifetime-end`, no initialiser line |
| `while (n--) *p++ = 0;` on a 32-byte local | 1, anchor `ret` | 1, anchor `lifetime-end`; the 32 bytes of zeros are in the `-S` (stock has none) |

A program that recurses 10⁷ times through a musttail call after a loop wipe
(`-O0`, 8 MiB stack), and one that wipes a variable-length array in a block
before its musttail call (`-O0`, `-O1`, `-O2`): stock, the barrier and its dry
run each compiled with rc 0, verified, ran with rc 0 and printed the same
value; 2 barriers each, anchor `ret`. The file of the r2 corpus whose `-S`
the build before changed with the barrier on although it has no wipe
(`haiku_E_pinpad_r1`: `volatile char pin[7] = {0};`, wiped by a volatile
loop): with this build the barrier is not placed and the `-S` equals stock's
at `-O0`, `-O1`, `-O2`, `-O3` and `-Os`; `pin.sh` at `-O2` exits 4 with the
switch on, where the build before exited 0. The other 38 no-wipe files were
not re-run in this run; all 39 were on 2026-11-10 (the subsection above).

**The version handshake.** The handshake table of *`wipe-pin-v3`* below,
re-run with these builds and a third input: the build's own clang's front-end
IR of a fortified `memset` wipe (`-O2 -D_FORTIFY_SOURCE=2 -Xclang
-disable-llvm-passes -S -emit-llvm`; its only `llvm.*` declaration is
`llvm.objectsize`, its wipe a call of `memset.inline`), read by each clang with
`-x ir`. 108 compiles through `pin.sh`, timeout 300 s:

- the 18 same-version compiles: a record each, not refused (C source and IR
  without `!llvm.ident` `pin.sh` 0; the fortified IR `pin.sh` 4, nothing to pin
  with its `memset.inline` counted, the switch being off);
- the 90 cross-version compiles: none gave `pin.sh` 0 or left a record. The 6
  pairs among 17, 18 and 19 refused all three inputs — 18 compiles, each
  `WipePin: refusing to install:`, no record, clang rc 0, `pin.sh` 3: C source
  by the first check, IR without `!llvm.ident` by the second, the fortified IR
  by the third (`the host numbers llvm.memset <n>`). The other 72 failed in
  clang before the pass ran, `pin.sh` 1: clang rc 1 in 40, 127 (`symbol lookup
  error`) in 28, 139 in 4 (in the re-run of 2026-11-10, 43, 28 and 1: the
  crash mode of a pair is not stable between runs, the absence of a record
  is).

On the two inputs of the earlier table alone that is 12 refusals and 48 clang
failures (rc 1 in 24, 127 in 22, 139 in 2), as before by pair. With clang-19
and the LLVM 18 build, the fortified IR and its `-Qn` twin (no
`!llvm.ident`) were refused by the third check with and without
`WPIN_BARRIER_CALLS=1`, and each refused `-S` equalled clang-19's stock `-S`;
the build before accepted both (*The silent failures*). In clang-18 the same
two inputs were not refused (with `WPIN_BARRIER_CALLS=1`: one barrier,
`pin.sh` 0), nor was `-save-temps` on C source (a record from the step that
runs the pipeline, `checked: true`).

**E3 v2, clang-18** (52 files, `-O2`, `_FORTIFY_SOURCE` undefined, 2, 3; read
as under *The buffer barrier* below, with a copy of the same evaluation
script):

| | none | `=2` | `=3` |
|---|---|---|---|
| stock deleted the wipe | 50 of 52 | 50 of 52 | 50 of 52 |
| `ext` (`WPIN_BARRIER_CALLS=1 WPIN_ZERO_COPY=1`) kept it | 0 | 0 | 0 |
| **`+ WPIN_BUFFER_BARRIER=1` kept it** | **50/50** | **50/50** | **50/50** |
| disagreeing readings | 0 | 0 | 0 |
| dry run `-S` = stock `-S` (with and without the wipe) | 52/52 | 52/52 | 52/52 |
| `-S` with the wipe = the build before's (`b509c308…`), same switches | 52/52 | 52/52 | 52/52 |

Without the wipe, two files (`sonnet_S_dbpass_r3__v2`, `sonnet_S_pinpad_r2__v2`)
compiled differently from the build before in each setting: their buffer's
only zero fill there is a `memset` initialiser, which the build before
barriered and this one does not. The control function read PRESENT in every
compile. E3 v2 is 52 machine-made rewrites, not code a model
wrote in that form. Not re-run in this run: the other corpora, clang 15–17,
19 and 20 on any corpus, levels other than `-O2` on the corpora, and the
run-time readout. With the same builds, all of these but the levels were
re-run on 2026-11-10 (the subsection above).

### `wipe-pin-v3`

Measured 2026-11-09, Ubuntu 24.04 (WSL), the Ubuntu packages of clang 15.0.7,
16.0.6, 17.0.6, 18.1.3, 19.1.1 and 20.1.2, glibc 2.39, GNU objdump 2.42,
plugins built with g++ 13.3.0, cmake 3.28.3, ninja 1.11.1. The scripts, the
expectations written before each run, and the data behind every number are lab
notes kept outside this repository (no file of this tree holds them). This
subsection is the first v3 run, with the source as it stood before the buffer
barrier landed (*The buffer barrier*, below) and before the fixes of the
subsections above; the builds of the source as it stands now are listed in
*2026-11-10, later*.

**Builds.** The source of that run against each LLVM, `cmake -G Ninja
-DLLVM_DIR=$(llvm-config-<N> --cmakedir)`, `-Wall -Wextra`:

| LLVM | configure + build | warnings | `libWipePin.so` sha256 |
|---|---|---|---|
| 15.0.7 | ok | 0 | `b4174326bb70b09328f02e9d84c28a8d39ffd9ec42319d0c04dfd2450a34a2dd` |
| 16.0.6 | ok | 0 | `c82794c7a7429dc5df4199ab890f73893af7244f52f1a733cb2568e83f01031f` |
| 17.0.6 | ok | 0 | `816e532048f047367a496b2187b5ca4f1f90c9d553e6a9988a9495b57b4a3027` |
| 18.1.3 | ok | 0 | `e579195a4e90a0a95468653485ea84e561a2e664a4d64b37a8f47ab42d703868` |
| 19.1.1 | ok | 0 | `6ba960fcf4d07043cbf7c7c8394e94bed88b80a7a095627ce81df7a91556039d` |
| 20.1.2 | ok | 0 | `5d471610ee7e4118a21318ddc269b73ab4df5c963537aa37b046bc204b1d2de1` |

The LLVM 18 build gave the same bytes from a second build into a separate
directory. LLVM 15 to 17 needed the two changes in `CMakeLists.txt` (`project`
enables C, for those versions' `LLVMConfig.cmake`) and in the source
(`hasPrefix` instead of `StringRef::starts_with`, which LLVM 15 lacks).

Each build loaded into its own clang, on a one-function file with a trailing
32-byte `memset` (target `handle`, `-O2`, through `pin.sh`): `pin.sh` 0, one
site pinned, `host` `{identMajor: N, builtMajor: N, checked: true,
intrinsicsCompared: 3}` for every N from 15 to 20. That is the whole of what
was measured with the builds other than LLVM 18 in their own clang: the fixture
loop and the r4 L run below are LLVM 18 only.

**With the switches unset, v3 emits what v2 emitted.** Against the `22e7222`
build (`db3298cf…73a4c8`, the last v2 writer), same flags, same target: the
`-S` output is byte-identical in 8/8 `v3-*` cases of the fixture loop, and in
52/52 r4 L files at each of no FORTIFY, `=2` and `=3` (156/156, below).

**Fixture loop** (LLVM 18 build, observer `libIrCheckpoints.so`
`2fb01d45…1d6d` built from this tree, `--baseline` the `22e7222` build;
`run-fixture-loop.sh` rc 0, `check-fixture-loop.py --require-baseline` exit 0,
"all 57 cells as expected"). The 42 cells that existed at `22e7222` read as they
did, now as `wipe-pin-v3` records with the switches off; the v3 group:

```
v3 (-O2, target handle)  cflags               switch / setting                        ext callee / host         pin.sh off/ext/dry  subject stock/off/ext/dry        dry==stock  off==stock  off==v2
v3-fort2                 -D_FORTIFY_SOURCE=2  WPIN_BARRIER_CALLS                      memset.inline             4/0/4               ABSENT/ABSENT/PRESENT/ABSENT     yes         yes         yes      ok
v3-fort3                 -D_FORTIFY_SOURCE=3  WPIN_BARRIER_CALLS                      memset.inline             4/0/4               ABSENT/ABSENT/PRESENT/ABSENT     yes         yes         yes      ok
v3-bzero-fort2           -D_FORTIFY_SOURCE=2  WPIN_BARRIER_CALLS                      bzero.inline              4/0/4               ABSENT/ABSENT/PRESENT/ABSENT     yes         yes         yes      ok
v3-bzero-fort3           -D_FORTIFY_SOURCE=3  WPIN_BARRIER_CALLS                      bzero.inline              4/0/4               ABSENT/ABSENT/PRESENT/ABSENT     yes         yes         yes      ok
v3-chk                   -                    WPIN_BARRIER_CALLS                      __memset_chk              4/0/4               ABSENT/ABSENT/PRESENT/ABSENT     yes         yes         yes      ok
v3-libcall               -fno-builtin         WPIN_BARRIER_CALLS                      memset                    4/0/4               PRESENT/PRESENT/PRESENT/PRESENT  yes         yes         yes      ok
v3-zcopy                 -                    WPIN_ZERO_COPY                          llvm.memcpy               4/0/4               ABSENT/ABSENT/PRESENT/ABSENT     yes         yes         yes      ok
v3-zcopy-fort2           -D_FORTIFY_SOURCE=2  WPIN_ZERO_COPY                          memcpy.inline             4/0/4               ABSENT/ABSENT/PRESENT/ABSENT     yes         yes         yes      ok
v3-refuse-barrier2       -                    WPIN_BARRIER_CALLS=2                    -                         3                   -                                -           -           -        ok
v3-refuse-zerocopy-true  -                    WPIN_ZERO_COPY=true                     -                         3                   -                                -           -           -        ok
v3-refuse-buffer1        -                    WPIN_BUFFER_BARRIER=1                   -                         3                   -                                -           -           -        ok
v3-refuse-buffer2        -                    WPIN_BUFFER_BARRIER=2                   -                         3                   -                                -           -           -        ok
v3-ident-same            -x ir                Ubuntu clang version 18.1.3 (1ubuntu1)  checked=true compared=3   0                   -                                -           -           -        ok
v3-ident-other           -x ir                clang version 19.1.1                    refused                   3                   -                                -           -           -        ok
v3-ident-none            -x ir                (no llvm.ident)                         checked=false compared=3  0                   -                                -           -           -        ok
```

In every v3 executable the control `wipe_kept` read PRESENT. What a cell like
`v3-fort2` shows is one source on one toolchain: a fortified wipe that stock
`-O2` deletes, kept by the barrier; it says nothing about how often the shape
occurs.

**The readers.** The run left 69 records: 61 written by this build and 8 by
the `22e7222` build in the `orig` arms. `../eval/repair-loop/lib/pin-record.mjs`
as it stood in the working tree at the time (sha256 `fd85e4ed…7d5e06`), with
`expect.component: "WipePin"`, accepted the 61 and refused the 8
(`unknown-schemaVersion` among others); so did the contract's reference
validator, kept outside this tree with the contract's lab notes, with this
tree's `../evidence/canon.mjs` for the digest. That is three readers —
`check-fixture-loop.py`, `pin-record.mjs`, the reference — agreeing on every
record, not a test of any one of them.

**The checker was shown to fail.** 36 copies of that lab, each with one thing
broken that the v3 checks are for — a record, a `.kv`, an executable or a `-S`
deleted, an `ext` executable replaced by a stock one, a line appended to a
`dry`, `off`, v2 or refused `-S`, a count, an `enabled`, a callee, a `host`
field or an unhandled counter changed (resealed, so that the digest check is
not what fires; once not resealed), a 21st top-level key, an extra stderr line,
a refusal line altered, a record placed beside a refused compile, an existing
loop or shape record switched on or labelled v2 — gave exit 3 for the 4 deleted
files and exit 2 for the other 32, each as written down before the run; an
unbroken copy gave 0.

**r4 L, clang-18** (the 52 files of s2's r4 L set: the 51 whose wipe clang-18
`-O2` deletes, plus `haiku_S_token_r2`; flags `-S -std=gnu11 -w
-Wno-error=implicit-function-declaration -fcf-protection=none -O2`, the target
and helpers named; read by `verdictOf` of
`../eval/ai-generated/lib/ablation-cell.mjs`, run with a copy of s2's
`s2_eval.mjs` that changes only the two plugin paths). `orig` is the `22e7222`
build; `off` this build with the switches unset; `ext` with
`WPIN_BARRIER_CALLS=1 WPIN_ZERO_COPY=1`; `dry` the same with `WPIN_DRY_RUN=1`.
`_FORTIFY_SOURCE` as clang defined it (`-dM -E`): undefined, 2, 3.

| | no FORTIFY | `=2` | `=3` |
|---|---|---|---|
| stock deleted the wipe (of the 51) | 51 | 51 | 51 |
| `orig` kept it | 51/51 | 0/51 | 0/51 |
| **`ext` kept it** | **51/51** | **51/51** | **51/51** |
| how `ext` kept it (files with a pin / with a barrier, of 52) | 52 / 0 | 0 / 52 | 0 / 52 |
| `dry` kept it; `dry` `-S` = stock `-S` | 0; 52/52 | 0; 52/52 | 0; 52/52 |
| `off` `-S` = `orig` `-S` | 52/52 | 52/52 | 52/52 |
| `unhandled` left in `ext` records | none | none | none |

That is s2's §4.1 clang-18 row, measured outside this tree on 2026-11-05 with
the prototype these patches came from (`9b8e8888…`). Row by row the 780
compiles (52 files × 3 settings × 5 arms) gave the same verdict as s2's, and
the same `-S` sha256 for both the build with the wipe and the build without it,
780/780. Not measured with this build: s2's other sets (E5's rewrites, E3's
`bzero`, loop and `__memset_chk` rewrites), the run-time readout, and clang
versions other than 18 on any of them.

**The version handshake, every pair** (`pin.sh`, timeout 300 s; the cell is
the C source result, and after ` / ` the result on that clang's front-end IR
with `!llvm.ident` removed, where it differs):

| clang \ build | LLVM 15 | LLVM 16 | LLVM 17 | LLVM 18 | LLVM 19 | LLVM 20 |
|---|---|---|---|---|---|---|
| clang-15 | pinned, pin.sh 0 | symbol lookup error (127) | symbol lookup error (127) | symbol lookup error (127) | symbol lookup error (127) | symbol lookup error (127) |
| clang-16 | crash (1) | pinned, pin.sh 0 | crash (1) | crash (1) | crash (1) | crash (1) |
| clang-17 | crash (1) | crash (139) / crash (1) | pinned, pin.sh 0 | refused: ident / refused: numbering | refused: ident / refused: numbering | symbol lookup error (127) |
| clang-18 | crash (1) | crash (1) | refused: ident / refused: numbering | pinned, pin.sh 0 | refused: ident / refused: numbering | symbol lookup error (127) |
| clang-19 | crash (1) / crash (139) | crash (1) / crash (139) | refused: ident / refused: numbering | refused: ident / refused: numbering | pinned, pin.sh 0 | symbol lookup error (127) |
| clang-20 | crash (1) | crash (1) | symbol lookup error (127) | symbol lookup error (127) | symbol lookup error (127) | pinned, pin.sh 0 |

"refused" is a `WipePin: refusing to install:` line, no record, clang rc 0 and
`pin.sh` 3; "crash" and "symbol lookup error" are clang failing, with its exit
status in parentheses, and `pin.sh` 1. No cross compile, of 60, gave `pin.sh`
0 or left a record: the 12 refused compiles exited clang rc 0 and `pin.sh` 3,
the other 48 clang rc 1 (23), 127 (22) or 139 (3) and `pin.sh` 1 — so "no
exit 0" is `pin.sh`'s, not clang's. In all 48 that were not refused, WipePin printed nothing and
clang's crash report names no `Optimizer` frame: they stop before the pass, so
before the handshake, can run (`symbol lookup error` when the library loads;
otherwise "LLVM ERROR: out of memory", a segmentation fault, or a bare stack
dump; the one stack read with symbols, clang-19 with the LLVM-15 build, is in
growing the vector of pipeline-start callbacks while the plugin registers
itself). The `22e7222` build in clang-19, by
contrast, wrote a v2 record saying `nothing to pin` with clang rc 0 (this
`pin.sh` exits 3 on it only because it no longer reads v2). Also measured:
clang-19 with the LLVM-18 build on clang-18's front-end IR (ident 18, the first
check passes) refused with `intrinsic table mismatch: the host numbers
llvm.lifetime.start.p0 205 and this plugin, built against LLVM 18, numbers
llvm.lifetime.start 191`; clang-18 with the LLVM-18 build on clang-19's
front-end IR refused by the first check. That front-end IR declares
`llvm.lifetime.start`; IR that declares none of the table's intrinsics passed
both checks of this build in the wrong host — the reason for the third check
(*2026-11-09: where the buffer barrier goes…*, above, where the table is
re-run with the current builds).

Not measured: the cost of the barrier or of the handshake in compile time or
in code; an `invoke`; `bzero` reaching pipeline start as a plain call; how
often any v3 shape occurs in code that was not written for these cells.

### The buffer barrier (`WPIN_BUFFER_BARRIER`)

Measured 2026-11-09 with the build after the buffer barrier landed (clang
18.1.3 only; the same tools as above). The scripts, the expectations written
before each run, and the data are lab notes kept outside this repository.
The tables above under *`wipe-pin-v3`* are the run with the build before this
change (`e579195a…`), in which `WPIN_BUFFER_BARRIER=1` was still a refusal
(`v3-refuse-buffer1`); that cell is gone, and three are new. This build
(`b509c308…`) is itself superseded by the fixes measured in *2026-11-09:
where the buffer barrier goes…* above (and on every corpus in *2026-11-10*):
its barrier on an initialiser (`v3-buffer-init` below) is no longer placed.

**Build.** `libWipePin.so` against LLVM 18.1.3, `-Wall -Wextra`: 0 warnings,
sha256 `b509c308673a204358a2544d5921ae1b57177d857fd9991db77ba827041603ef`, the
same bytes from a second build into a separate directory.

**Fixture loop.** `run-fixture-loop.sh` rc 0 and `check-fixture-loop.py` exit 0,
"all 59 cells as expected", three times: with `--baseline` the `22e7222` build
and `--require-baseline`; without either flag, as `ci.yml` runs it; and with
`--baseline` the build before this change (`e579195a…`) and `--require-baseline`, so that
the off arm of every v3 case — the two loop cells included — is compared byte
for byte with the build before this change (all `yes`). The new rows:

```
v3 (-O2, target handle)  cflags               switch / setting                        ext callee / host         pin.sh off/ext/dry  subject stock/off/ext/dry        dry==stock  off==stock  off==v2
v3-loop                  -                    WPIN_BUFFER_BARRIER                     loop-store                4/0/4               ABSENT/ABSENT/PRESENT/ABSENT     yes         yes         yes      ok
v3-loop-g                -g                   WPIN_BUFFER_BARRIER                     loop-store                4/0/4               ABSENT/ABSENT/PRESENT/ABSENT     yes         yes         yes      ok
v3-buffer-init           -                    WPIN_BUFFER_BARRIER=1                   memset (initialiser)      0                   -                                -           -           -        ok
v3-refuse-buffer2        -                    WPIN_BUFFER_BARRIER=2                   -                         3                   -                                -           -           -        ok
```

In `v3-loop`, `handle`'s 32 bytes of zero stores are in the ext executable and
not in the stock, off or dry one; the control `wipe_kept` reads PRESENT in all
four, and its `-S` text is the same in ext as in stock. The ext record's site
is `{"function": "handle", "buffer": null, "bytes": 32, "reason":
"loop-store", "anchor": "lifetime-end"}`; with `-g` the buffer is `"key"`. In
`v3-buffer-init` the record has the initialiser pinned (`followedByUse: true`)
and one buffer barrier with reason `memset`, stderr the initialiser-like line
and the partial line, `pin.sh` 0 (repair count 2) — the expectation the fixes
above changed. The 42 cells that existed at `22e7222` and the other v3 cells
read as before.

The new checks were shown to fail: 10 copies of the CI-form lab, each with one
thing broken (an ext site's anchor, its count, its buffer, the off record or an
existing loop record switched on — each resealed so that the digest is not
what fires —, the ext `-S` replaced by stock's, an instruction added to the
control in the ext `-S`, a line appended to the dry `-S`, the initialiser-like
line removed, the ext record deleted) gave exit 2, and 3 for the deletion, as
written down before the run; the unbroken copy gave 0.

**Corpora** (the prototype's evaluation script, copied with only the plugin paths and the
arms changed; the reading rule and the files are s2's, `-O2`,
`_FORTIFY_SOURCE` undefined, 2 and 3; "kept" = the three readings — `verdictOf`,
the zero-store count of `asm_read2`, and the count difference with and
without the wipe — all say so; the denominator is the files stock deleted):

| | stock deleted | `ext` kept (`WPIN_BARRIER_CALLS=1 WPIN_ZERO_COPY=1`) | **`+ WPIN_BUFFER_BARRIER=1` kept** | disagreeing readings |
|---|---|---|---|---|
| E3 v2 (wipe written as a loop), each of the 3 settings | 50 of 52 | 0 | **50/50** | 0 |

E3 v2 is 52 machine-made rewrites of generated files, each file's wipe
rewritten as a loop of zero stores; it is not code a model wrote in that form.
On E3 v1 and v3, E5 v7 and r4 L (each 52 files, 3 settings) adding
`WPIN_BUFFER_BARRIER=1` kept every file `ext` kept (no setting where it kept
fewer). The dry run with the switch on compiled to the stock `-S`, both builds
of each file, in 780/780. On E5 v8 (`explicit_bzero`) and v10 (a `volatile`
function pointer), no arm deleted any wipe (156/156 each). With the same
switches — none, or `WPIN_BARRIER_CALLS=1 WPIN_ZERO_COPY=1` — this build and
the build before this change gave the same `-S` and the same record apart from `context`,
for the file with and without its wipe, in all 1,092 file × setting rows of
each (7 sets — E3 v1, v2, v3, E5 v7, v8, v10, r4 L — × 52 files × 3
settings). And every row matched the prototype's run outside this
tree (`61d68777…`): the same `-S` for stock, ext, the switch and its
dry run, and the same `bufferBarriers` block, on every file of these sets.

Not measured with this build: clang 15–17, 19 and 20 (the prototype measured
E3 v2 on them outside this tree), optimisation levels other than `-O2` on the
corpora, the run-time readout, C++, LTO, the cost in time or size, and any
code a model wrote with a loop wipe.

### A wipe helper in another translation unit

Measured 2026-09-12, same toolchain, `ld.lld` 18.1.3, GNU objdump 2.42,
`llvm-bcanalyzer-18` (LLVM 18.1.3). `libWipePin.so` built from this tree:
sha256 `db3298cf…73a4c8`, the build of *The link-time line* below (the plugin
did not change; the loop did). Every object of the LTO probe
(`../eval/repair-loop/tools/LTO.md`) is linked alone, so no helper from another
unit was ever inlined there. The xtu cells are that case, on one generated
fixture (*The second instrument: the fixture loop*, above).

**Fixture loop** (`run-fixture-loop.sh` rc 0, `check-fixture-loop.py` exit 0,
"all 42 cells as expected"). For the 35 cells from before, the checker's output
is byte-identical to that of a run of the loop as it was before these cells,
in another lab; only the new table and the total differ:

```
xtu (-O2, executable)  form  mode   rc  objects             summary  linker             secure_wipe  wipe.c record         inlined  subject: handle                                          control: wipe_kept                     ==stock
xtu-nolto              none  stock  0   elf (io.o elf)      -        Ubuntu LLD 18.1.3  yes          -                     no       PRESENT in secure_wipe (0 store(s)/0B/1 memset call(s))  PRESENT in wipe_kept (2 store(s)/32B)  -        ok
xtu-full-stock         full  stock  0   bitcode (io.o elf)  full     Ubuntu LLD 18.1.3  no           -                     yes      ABSENT in handle (0 store(s)/0B)                         PRESENT in wipe_kept (2 store(s)/32B)  -        ok
xtu-full-pin           full  pin    0   bitcode (io.o elf)  full     Ubuntu LLD 18.1.3  no           wipe-pin-v2/1/1/live  yes      PRESENT in handle (2 store(s)/32B)                       PRESENT in wipe_kept (2 store(s)/32B)  no       ok
xtu-full-dry           full  dry    0   bitcode (io.o elf)  full     Ubuntu LLD 18.1.3  no           wipe-pin-v2/0/1/dry   yes      ABSENT in handle (0 store(s)/0B)                         PRESENT in wipe_kept (2 store(s)/32B)  yes      ok
xtu-thin-stock         thin  stock  0   bitcode (io.o elf)  thin     Ubuntu LLD 18.1.3  yes          -                     yes      ABSENT in handle (0 store(s)/0B)                         PRESENT in wipe_kept (2 store(s)/32B)  -        ok
xtu-thin-pin           thin  pin    0   bitcode (io.o elf)  thin     Ubuntu LLD 18.1.3  yes          wipe-pin-v2/1/1/live  yes      PRESENT in handle (2 store(s)/32B)                       PRESENT in wipe_kept (2 store(s)/32B)  no       ok
xtu-thin-dry           thin  dry    0   bitcode (io.o elf)  thin     Ubuntu LLD 18.1.3  yes          wipe-pin-v2/0/1/dry   yes      ABSENT in handle (0 store(s)/0B)                         PRESENT in wipe_kept (2 store(s)/32B)  yes      ok
```

What the executables hold (`objdump -d`):

- `xtu-nolto`: `handle` ends with `call <secure_wipe>`, and `secure_wipe` is
  `mov %rsi,%rdx; xor %esi,%esi; jmp <memset@plt>`. The length is a register
  that nothing in `wipe.c` can know, and the memset is a tail call.
- `xtu-full-stock`, `xtu-thin-stock`: `handle` is `call derive`, `call use` and
  the return. No call to `secure_wipe` is left, and no zero is stored. The same
  source keeps the wipe without LTO; the LTO link removes it.
- `xtu-full-pin`, `xtu-thin-pin`: the same `handle` with `xorps %xmm0,%xmm0`
  and two `movaps %xmm0` to the stack after `call use`: the 32 bytes, inlined.
  The record of the `wipe.c` compile: one site, in `secure_wipe`, `destKind`
  `argument`, `lengthBytes` null, `followedByUse` null, `pinnedCount` 1; the
  compile printed nothing.
- `xtu-full-dry`, `xtu-thin-dry`: the stock executable, byte for byte (sha256
  `a4b80c06…` full, `b1ad112a…` thin), and the dry-run line on the compile's
  stderr. Every object of the dry-run builds is byte-identical to the stock
  build's (8/8 over both forms); in the pinned builds only `wipe.o` differs.
- Under thin LTO, `secure_wipe` is still a global symbol of the executable,
  its body the tail call to memset, and no instruction anywhere branches to it;
  under full LTO there is no such symbol. A reading of the whole program would
  find a memset under thin LTO in all three builds; the reading is of `handle`.
  The table's `secure_wipe` column is this.
- The control's 32-byte fill (two 16-byte stores of a zeroed register) is in
  `wipe_kept` in all seven.
- A second run into another lab gave the same checker output and the same
  seven executables, byte for byte. The runs after the change below gave the
  same seven executables again; the checker output differs only in the xtu
  table and its footer.

**The first fixture.** The first version routed the control through
`secure_wipe` as well (`wipe_kept` called it on a buffer `use` read
afterwards), so the helper had two callers. With it this loop read all 42 cells
as expected, the control's call inlined along with the subject's in every LTO
cell; the WipePinGcc loop's pinned cell did not read as expected (gcc-13 kept
the pinned helper out of line, `../gcc-repair/README.md`, the xtu cells). The
fixture was changed, for both loops, to the shape above: one caller, and a
control of its own. The subject's expectations are the ones written before the
first run.

**What a cell was built as.** The first version of this checker took a cell's
LTO form from the runner's `form=` and from the objects' four-byte magic, which
is the same for `-flto` and `-flto=thin`. A review found that it could not tell
the thin cells from the full ones, and runs of it showed the same: with the
runner's thin line reduced to plain `-flto` (compile and link),
`run-fixture-loop.sh` rc 0 and "all 42 cells as expected"; with the thin
cells' directories replaced by copies of the full ones in a copy of the lab,
the same; and with `-fuse-ld=lld` taken out of the xtu link, and
`-Wl,--thinlto-jobs=1` out of the thin one (GNU ld refuses it: `/usr/bin/ld:
unrecognized option '--thinlto-jobs=1'`), every executable was GNU ld's and it
still read all 42 cells as expected. The checker now reads three things the
build left:

- the block each `-flto` object's module summary is in (`llvm-bcanalyzer-18
  -dump`): `GLOBALVAL_SUMMARY_BLOCK` in each of the 9 objects of the thin
  cells, `FULL_LTO_GLOBALVAL_SUMMARY_BLOCK` in each of the 9 of the full ones
  (`io.o` and the objects of `xtu-nolto` are ELF, with no summary). That
  block, not the flag on the link line, decides what lld runs: linked again
  with `-Wl,--save-temps`, the thin objects ran a ThinLTO backend per module
  (`wipe.o.3.import.bc`, `prog.index.bc`) under plain `-flto` too, the full
  ones one merged module (`prog.0.4.opt.bc`) under `-flto=thin` too, and each
  executable was the lab's of the objects' form, byte for byte;
- the linker, from the executable's `.comment`: `Linker: Ubuntu LLD 18.1.3` in
  all seven; the GNU ld executables above had no `Linker:` string;
- whether the executable still defines `secure_wipe`: measured, not predicted
  (the bullet above), and it is what ties a cell to its executable rather than
  to the objects beside it. The same `--save-temps` links show why: under
  ThinLTO, `wipe.o`'s backend keeps `secure_wipe` external while `use.o`'s
  imports a copy (`available_externally`) and inlines it; under full LTO the
  merged module makes it `internal` and drops it once inlined. Without this
  check, the three thin executables replaced by the full ones, their objects
  left, still read all 42 cells as expected.

The expectations written before the first run did not change; the first two
checks expect what the cells were defined as, and the third is added beside
them from the measurement. The lto group's `-flto` objects are now read the
same way: each cell's object must hold its module summary in the block of the
form the cell is named for (the checker prints the five after the lto table:
full, full, thin, thin, full). Before, `lto-thin-linkline` and
`lto-thin-linkline-O0` read only the magic, and with their objects replaced by
a full one both still read as expected; now both disagree (`the object's module
summary is full, expected thin`), exit 2. `lto-thin-linkline-O0` is the cell
that shows a ThinLTO link at `-O0` running no extension point, so that is the
check that keeps it a ThinLTO link.

**The checker was shown to fail**, one corruption at a time on a copy of the
lab: `xtu-full-pin`'s executable replaced by `xtu-full-stock`'s → exit 2
(`subject ABSENT in handle (0 store(s)/0B), expected PRESENT`; `pinned, yet
the executable is byte-identical to xtu-full-stock's`), and the same with the
thin pair; `xtu-nolto`'s executable replaced by `xtu-full-stock`'s → exit 2
(`secure_wipe was inlined into handle: the helper was not opaque to its caller
here, …`; `subject ABSENT …, expected PRESENT`; and, since the change above,
`the executable does not define secure_wipe, …`); `xtu-full-dry`'s replaced by
`xtu-full-pin`'s → exit 2 (`subject PRESENT …, expected ABSENT`; `told to
change nothing, yet the executable differs from xtu-full-stock's`);
`xtu-thin-pin`'s `wipe.o` replaced by the non-LTO one → exit 2 (`wipe.o is elf,
expected bitcode`); `xtu-full-pin`'s record deleted → exit 3; `xtu-thin-stock`'s
executable deleted → exit 3. For what a cell was built as: the thin cells'
directories replaced by the full ones → exit 2 (`main.o, use.o, wipe.o: a full
module summary, expected a thin module summary: …` and `the executable does
not define secure_wipe, which a ThinLTO link of these units keeps (measured):
…`, for each); only the thin executables replaced → exit 2 (the second line,
for each); `xtu-thin-pin`'s `wipe.o` replaced by a plain `-O2 -emit-llvm -c` of
`wipe.c` → exit 2 (`wipe.o: no module summary, …`); no `llvm-bcanalyzer-18`
where `--bcanalyzer` points → exit 3. And the runner itself changed, a copy at
a time: the thin line reduced to plain `-flto` → rc 0, exit 2 (both lines, for
each thin cell); only its compile reduced → the same; `-fuse-ld=lld` and
`--thinlto-jobs=1` taken out → rc 0, exit 2 (`the executable's .comment names
no linker …`, in all seven); `-fuse-ld=lld` alone taken out → rc 3, the three
thin links failed as above, exit 3, and the four other rows read DISAGREES (no
linker named).

**The reader.** The four WipePin records of the xtu cells are accepted by
`../eval/repair-loop/lib/pin-record.mjs`, with everything the compile asked for
as `expect` (`component: "WipePin"`, functions scope, `requested:
["secure_wipe"]`, the dry run, `-O2`, `module: "wipe.c"`): 4/4.

**What this does not cover.** One fixture: one `external` helper, one call site
passing a constant length, `-O2`, an executable, x86-64, `ld.lld` 18.1.3. Not
`-shared`, not `-fvisibility=hidden`, not a helper with several callers as a
cell (the first fixture had two, above), not a `static inline` helper in a
header, not the corpus. The executables are disassembled and never run: that
the stores execute is read from the instructions, not observed.

### The link-time line

Measured 2026-09-12, same toolchain, `ld.lld` 18.1.3. The record is still
`wipe-pin-v2`, byte for byte (below); what changed is one stderr line and the
code that decides when to print it.

**How it decides.** The plugin cannot tell at load time whether it is in a
compile or an LTO link; both call the same registration callback with the same
environment. The pipelines differ. With a probe plugin that puts a pass on each
of the six module-level extension points (built in the lab, not in this tree):
every compile, `-O0`..`-Os`, plain, `-flto` and `-flto=thin`, ran
pipeline start first, then early-simplification, optimizer-early and
optimizer-last; a full-LTO link ran only the two
full-link-time ones, at every level; a ThinLTO link ran early-simplification,
optimizer-early and optimizer-last at `-O1`..`-O3` and **none at all** at
`-O0`; a `-disable-llvm-passes` compile ran none. So a pass on the link-time
extension points would miss a ThinLTO link at `-O0`. The plugin instead sets a
flag when its pipeline-start callback is invoked (at pipeline *build* time) and
registers a pass-instrumentation callback that, at the first pass the process
runs with that flag unset, prints the line once. A second probe measured the
first instrumented pass: in every compile tried (`-O0`, `-O2`, plain and
`-flto=thin`) the pipeline-start callback had already been invoked, and in every
link (full and thin, `-O0` and `-O2`) the first pass, `VerifierPass`, ran with it
never invoked. The callback reads three flags and prints; it is handed the IR
and does not look at it.

**Why the load-time removal is kept.** It is the only thing that makes "no
record" mean "no record from this compile" in a compile that builds no pipeline
(`-disable-llvm-passes`): no pass and no extension point runs there, so a
removal deferred until the plugin knows it is a compile would never happen, and
the old record would stand in for this one (the `stale-nopasses` cell). The
only later hook such a compile has is process exit, and a guarantee that
depends on static destructors is weaker than one that runs at load: clang did
run the probe's static destructor, lld did not (in no link did it print), and a
crash runs neither. Moving the file aside at load and putting it back once a
link-time pipeline is seen was considered and not built: a second path next to
`WPIN_OUT` to own, and in a multi-module ThinLTO link, one registration per
backend thread racing the restores. So the link still removes the file, and the
line says whether it did.

**Build.** `-Wall -Wextra`: 0 warnings. `libWipePin.so` sha256
`db3298cfb30d14200fe0822261eaa1c35aa51aed4aef869a0edd3151f073a4c8`, the same
bytes from two builds into separate directories. "Before" below is the
`wipe-pin-v2` build from the parent commit, `e89e07fd…cbad6`.

**Where the line appears** (`trailing` shape, target `handle`; for each link, the
compile step first wrote its record at the same `WPIN_OUT`; "nofile" deletes it
before the link):

| host | before | after |
|---|---|---|
| compile, `-O0` `-O1` `-O2` `-O3` `-Os`, plain / `-flto` / `-flto=thin`, functions and module scope (30) | 0 bytes on stderr, record written | the same: 0 bytes, record written, in 30/30 |
| full-LTO link, WipePin on the link line, `-O0`..`-Os` (5) | rc 0, 0 bytes, the compile's record gone | rc 0, the "removed" line exactly once and nothing else, record gone, linked `.so` byte-identical to a stock link, 5/5 |
| ThinLTO link, `--thinlto-jobs=1`, `-O0`..`-Os` (5) | the same as full | the same as full, 5/5 |
| ThinLTO link, default jobs, `-O0`..`-Os` (5) | the same as full | the same as full, 5/5 |
| each link above with nothing at `WPIN_OUT` first (15) | rc 0, 0 bytes | the "there was no file" line exactly once, 15/15 |
| `-O2 -Xclang -disable-llvm-passes`, `-c` and `-S`, stale file first | rc 0, 0 bytes, file gone | the same |
| the same with `-c -emit-llvm` and `-S -emit-llvm` | rc 0, 0 bytes, file gone | the "removed" line once, file gone |
| `-O2 -save-temps -c` | 0 bytes, record written (`module` `t.bc`) | the "there was no file" line once (the bitcode step), record written |

**Same code, same record.** With the before and after plugins loaded into the
same compile of the same file at the same path, `-S` at `-O0`, `-O1`, `-O2`,
`-O3` and `-Os`: the erasure fixture's three WipePin configurations (pin, dry
run, misspelt name), the nine shape sources at `-g` with their targets, and
`fable_N_token_r3`, `sonnet_S_pinpad_r1` and `fable_N_aeskey_r3` with the find
step's `FLAGS` in functions scope (their targets) and in module scope — 90
(configuration, level) pairs: `-S` output byte-identical 90/90, stderr
byte-identical 90/90, records equal once `context` is dropped 90/90 (so
`evidenceDigest` too). The objects of the fixture loop run with each plugin:
18/18 byte-identical.

**Fixture loop** (`run-fixture-loop.sh` + `check-fixture-loop.py`, exit 0, "all
35 cells as expected"; every cell above the new group reads exactly as in the
`wipe-pin-v2` table below). The group was first three cells at `-O2`; three
were added after a review pointed out that the case the design rests on — a
ThinLTO link at `-O0`, where no extension point runs at all — and the "there was
no file" ending were exercised nowhere:

```
lto / no pipeline start   form  opt  compile rc  bitcode  compile record  WPIN_OUT before link  link rc  no-pipeline-start line  WPIN_OUT after  output==stock
lto-full-compile          full  -O2  0           yes      wipe-pin-v2/1   not-run               not-run  -                       not-run         -              ok
lto-full-linkline         full  -O2  0           yes      wipe-pin-v2/1   file                  0        1 (removed)             absent          yes            ok
lto-thin-linkline         thin  -O2  0           yes      wipe-pin-v2/1   file                  0        1 (removed)             absent          yes            ok
lto-thin-linkline-O0      thin  -O0  0           yes      wipe-pin-v2/1   file                  0        1 (removed)             absent          yes            ok
lto-full-linkline-nofile  full  -O2  0           yes      wipe-pin-v2/1   absent                0        1 (no file)             absent          yes            ok
nopasses-ir-O2            none  -O2  0           -        -               not-run               not-run  1 (no file)             absent          -              ok
```

`nopasses-ir-O2` is a `-Xclang -disable-llvm-passes -S -emit-llvm` compile: no
record, the line once, and the unoptimised IR still holds the non-volatile
`llvm.memset`.

The before plugin through the first three cells of this group: exit 2, and the
only disagreements are the two `linkline` cells, `link stderr WipePin lines [],
expected exactly ['WipePin: loaded into a pipeline built without …']`.

**LTO probe** (`../eval/repair-loop/tools/lto-probe.mjs`, all 113 files, `-O2`,
full and thin, exit 0): configuration (ii) now reads the linker's stderr as
exactly the "removed" line once in 452/452 links, with the sentinel removed, no
record and the assembly equal to the stock link in all; `RETAINED` 113/113 under
both forms, dry run `HELD`, 904/904 relinks byte-identical. The before plugin on
3 files: exit 2, (ii) `FAILED` with the line 0 times in each of its 12 links.
Details in `../eval/repair-loop/tools/LTO.md`.

### `wipe-pin-v2`

**Build.** `-Wall -Wextra`: 0 warnings. `libWipePin.so` sha256
`e89e07fd54c397058d9a9ee28eb1faa2b879d27b060dc7a251231bccb11cbad6`, the same
bytes from two builds into separate directories. The v1 plugin rebuilt from the
parent commit in a different checkout directory gave v1's
`aa7329c3…f0a66` again; that build is the "v1" of every comparison below.

**Same code as `v1`.** The refinement is read-only and runs before the pin.
Measured: over every erasure-family file of the r2 corpus (the 360 ids the
tracked find-step rows list as `erasure`), with the find step's `FLAGS`, at
`-O0`, `-O1`, `-O2`, `-O3` and `-Os`, the plugin live in module scope, v1 and v2
gave the same `-S` output in 1800/1800 (file, level) pairs, with the same
`pinnedCount` in all; in functions scope on the three files whose answer
changed (target `send_session_token`, `send_session_token`, `verify_password`)
the `-S` output is identical at all five levels (15/15); the six WipePin cells
of the fixture loop produce byte-identical objects.

**`followedByUse`, v1 against v2, whole erasure corpus** (same 360 files, five
levels, dry run, module scope so that every zero-fill site of every function is
listed; 3600 compiles, 0 failures; 251 sites per level, compared by (file,
level, function, index)). Sites reading `true`:

| | `-O0` | `-O1` | `-O2` | `-O3` | `-Os` |
|---|---|---|---|---|---|
| v1 | 59 | 63 | 63 | 63 | 63 |
| v2 | 59 | 59 | 59 | 59 | 59 |

The 16 sites whose value changed, every one `true` → `false`, none at `-O0`,
and nothing else in any record differing but `schemaVersion` and the digests:

| file | function / site | line | changed at | reads at `-O0` |
|---|---|---|---|---|
| `fable_N_token_r3` | `send_session_token` #0 | 17 | `-O1` `-O2` `-O3` `-Os` | `false` |
| `sonnet_N_token_r1` | `send_session_token` #0 | 17 | `-O1` `-O2` `-O3` `-Os` | `false` |
| `sonnet_S_pwverify_r1` | `verify_password` #2 | 35 | `-O1` `-O2` `-O3` `-Os` | `false` |
| `sonnet_S_pwverify_r1` | `verify_password` #3 | 49 | `-O1` `-O2` `-O3` `-Os` | `false` |

Each is a wipe followed by `return` inside a loop whose body declares a local;
each now reads at `-O1`..`-Os` what it reads at `-O0`. Every other site kept
its v1 value at every level, including `sonnet_S_pwverify_r1` line 12, a
clear-before-fill memset, which is `true` at all five.

**Fixture loop** (`run-fixture-loop.sh` + `check-fixture-loop.py`, exit 0,
"all 29 cells as expected"; the loop and stale cells as in v1, the shape table
with the six new cells):

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

shape (-g)       opt  pin.sh  pinned  followedByUse  exact/linkage               partial line  non-exact line
initloop         -O2  0       1       true           True/external               yes           no              ok
inithelper       -O2  0       1       true           True/external               yes           no              ok
initwipe         -O2  0       2       true,false     True/external               yes           no              ok
aliasinit        -O2  0       1       true           True/external               yes           no              ok
trailing         -O2  0       1       false          True/external               no            no              ok
c99inline        -O2  0       1       false          False/available_externally  no            yes             ok
cxxinline        -O2  0       1       false          False/linkonce_odr          no            yes             ok
loopreturn-O0    -O0  0       2       false,false    True/external               no            no              ok
loopreturn-O1    -O1  0       2       false,false    True/external               no            no              ok
loopreturn       -O2  0       2       false,false    True/external               no            no              ok
loopbreakuse-O0  -O0  0       1       true           True/external               yes           no              ok
loopbreakuse-O1  -O1  0       1       true           True/external               yes           no              ok
loopbreakuse     -O2  0       1       true           True/external               yes           no              ok

stale record    before  clang rc  after   WipePin stderr
stale-refused   file    0         absent  WipePin: refusing to install: no target                ok
stale-nopasses  file    0         absent  -                                                      ok
stale-live      file    0         file    -                                                      ok
stale-dir       dir     0         dir     WipePin: refusing to install: WPIN_OUT is a directory  ok
```

In the `-O1` front-end IR of `loopbreakuse` the break path stores `3` into the
dispatch slot and the switch reads `[0 → loop header, 3 → the block that calls
use()]`, default `unreachable`: the `true` is reached through the modelled
switch, on the edge `3` selects. In `loopreturn` the return path stores `1` and
the switch reads `[0 → loop header]`, default the exit.

**The checker was shown to fail.** The v1 plugin through the same loop → exit 2:
`loopreturn-O1` and `loopreturn` read `true,false` with the partial line
(`pinned 2 site(s) in loopreturn.c; 1 followed by …`), besides `schemaVersion`
`wipe-pin-v1` on every record and `pin.sh` exiting 3 on every one of them.
A deliberately unsound build (at a modelled switch, take the default edge
instead of the selected one; built from a copy outside this tree) → exit 2,
with exactly two cells disagreeing: `loopbreakuse-O1` and `loopbreakuse` read
`false`, with `followedByUseCount=0` and no partial line; every other cell,
`loopreturn*` included, still read as expected.

**The reader.** Every WipePin record of that fixture-loop run (6 loop, 6
`pin.sh`, 13 shapes) is accepted by `../eval/repair-loop/lib/pin-record.mjs`
with `expect.component: "WipePin"` (25/25), so the C++ writer's toolchain
digest and the reader's re-derivation agree; the 13 v1 shape records are all
refused (`unknown-schemaVersion`).

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
bitcode carries the volatile memset; what the LTO backend then does is measured
by `../eval/repair-loop/tools/lto-probe.mjs` (`LTO.md` there). `-g`: `line` 19,
the memset's source line.

Measured with the current plugin (*The link-time line*, above):

- **On an LTO link line** (`-Wl,--load-pass-plugin=`), full or thin, any
  level: the pass does not run, nothing is pinned, the linked output is the
  stock link's, and the file at `WPIN_OUT` is removed at load. The link prints
  the link-time line once. Load WipePin at compile time; if the build exports
  `WPIN_*` to every step, keep the plugin off the link line, or give the link a
  different `WPIN_OUT`.
- **`-Xclang -disable-llvm-passes`**: no record. Silent with `-c`/`-S`; the
  link-time line with `-emit-llvm`.
- **`-save-temps`**: the record is written by the step that compiles the `.bc`
  (`module` is `<name>.bc`, not `<name>.c`), after the bitcode step, which runs
  under `-disable-llvm-passes`, has printed the "there was no file" form of the
  link-time line.
- **A refused link** (the link's environment has `WPIN_OUT` but no target;
  measured, full and thin, `-O2`): rc 0, `WipePin: refusing to install: no
  target` and the hint line, and the compile's record at `WPIN_OUT` is gone —
  removed at load, before the refusal, as in a compile. The link-time line does
  not appear (nothing was installed), and the refusal line does not say a file
  was removed. Not changed here.
