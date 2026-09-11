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

One of `WPIN_TARGET_FNS` / `WPIN_SCOPE=module` is required. If both are set,
`WPIN_TARGET_FNS` wins, the record says `scope: "functions"`, and stderr says so.

## The record

One clang invocation, one source file, one record, written at the end of the
pass's single run and overwriting whatever was at `WPIN_OUT`:

```json
{ "schemaVersion": "wipe-pin-v2", "component": "WipePin", "module": "<basename>",
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
| installed, but the pass never ran: a compile under `-Xclang -disable-llvm-passes` | no record → `pin.sh` exits **3**. On stderr it depends on the output: with `-c` or `-S` nothing (rc 0, 0 bytes — clang runs no pass-manager pass at all, so nothing the plugin hooks fires; a direct clang user sees nothing); with `-emit-llvm` the link-time line below, because the bitcode writer or IR printer still runs as a pass (measured). The bitcode step of `-save-temps` is this case: clang runs it with `-disable-llvm-passes` and the line appears (`there was no file …`), and the next step builds the whole pipeline from the `.bc`, where WipePin runs and writes the record (`module` `t.bc`, measured). |
| installed, but the pass never ran: **WipePin on an LTO link line** (`-Wl,--load-pass-plugin=<so>`, full or thin LTO) with `WPIN_OUT` / `WPIN_TARGET_FNS` in the link's environment — a build that exports them to every step | An LTO link's pipeline never runs pipeline start, so the pass is never added. The load-time callback still removes the file at `WPIN_OUT`, which here is the record the compile step wrote. Until this change that link exited 0 with 0 bytes on stderr and the record gone (measured again below, full and thin, `-O0`..`-Os`). Now the first pass the link runs makes the plugin print, once per process, `WipePin: loaded into a pipeline built without the pipeline-start extension point (an LTO link, or a compile under -disable-llvm-passes), where this pass does not run; nothing was pinned in this process, and the file at WPIN_OUT was removed when the plugin loaded` (or `… and there was no file at WPIN_OUT when the plugin loaded`). The removal is kept (why: *The link-time line*). `pin.sh` does not link and is not involved; the fixture loop's `lto-*-linkline` cells and the LTO probe's configuration (ii) grade the line. |
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
  and read that site `true` at `-O1` and above (`false` at `-O0`, which has no
  dispatch), and printed the partial line for it.

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

  Each of these can add a partial line; none can remove one.
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
| `0` | clang succeeded; a `wipe-pin-v2` record was written; it pinned at least one site; every requested name resolved. **Not** "the wipe survived", and not even "the wipe was pinned": a pinned initialiser counts. `followedByUseCount` and the partial line are where that shows. |
| `1` | clang failed |
| `3` | clang succeeded and there is no usable record: the plugin refused to install, its pass never ran, the record could not be written, or what was written is not a `wipe-pin-v2` record `python3` can read (a v1 record from an older build is one) |
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
`pin.sh` alone where it must exit 3. Then three groups that do not involve the
observer, generated into the lab:

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
  link of the same bitcode).

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
32 cells as expected"; every cell above the new group reads exactly as in the
`wipe-pin-v2` table below):

```
lto (-O2)          form  compile rc  bitcode  compile record  link rc  link-time line  WPIN_OUT after link  output==stock
lto-full-compile   full  0           yes      wipe-pin-v2/1   not-run  -               not-run              -              ok
lto-full-linkline  full  0           yes      wipe-pin-v2/1   0        1               absent               yes            ok
lto-thin-linkline  thin  0           yes      wipe-pin-v2/1   0        1               absent               yes            ok
```

The before plugin through the same loop: exit 2, and the only disagreements are
the two `linkline` cells, `link stderr WipePin lines [], expected exactly
['WipePin: loaded into a pipeline built without …']`.

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
