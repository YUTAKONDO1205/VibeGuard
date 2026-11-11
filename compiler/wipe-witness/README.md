# WipeWitness — what is left of WipePin's repairs at the end of the pipeline

**This plugin changes nothing.** It is a second reading of WipePin's work, taken
by code that shares nothing with WipePin (`../llvm-repair/`): it counts the
shapes of WipePin's repairs in each function directly after WipePin has run,
and again at the last extension point before code generation, and writes both
counts to a record of its own. `scripts/witness_check.py` compares that record
with WipePin's.

Why it exists: WipePin runs once, at the pipeline-start extension point, and
writes its record there. Whatever the optimiser does to a repair afterwards,
the record does not change. One of WipePin's placement errors (fixed in the
tree since; `../llvm-repair/README.md`, *2026-11-10, later*) put a buffer
barrier before a lifetime end in a block no path reaches; the optimiser deleted
the block, and the record still said `count` 1, `pin.sh` still exited 0, and
the `-S` was byte-identical with stock's. This plugin reports that shape
(measured below on the build that had the error).

What it reports is narrow: **a function WipePin's record says it placed a
repair in, which is still a definition at the end of the optimisation pipeline,
and in which no WipePin barrier and no volatile zero memset is left.** It is
not a verdict on whether a wipe reached the object file — that is still the
stock observation re-run with the plugins loaded — and it does not see the
cases listed under *What it cannot see*.

## Building

```sh
cmake -S compiler/wipe-witness -B ~/vg-build/wipe-witness -G Ninja \
      -DLLVM_DIR=$(llvm-config-18 --cmakedir)
ninja -C ~/vg-build/wipe-witness      # -> libWipeWitness.so
```

The same source builds against LLVM 15 to 20 (`#if LLVM_VERSION_MAJOR >= 20`
for the third argument LLVM 20 adds to the optimizer-last callback). Load each
build only into the clang of the same major version; a module whose
`llvm.ident` names another clang major version is not counted (one line on
stderr, no record). A directory of its own rather than a second target in
`../llvm-repair/CMakeLists.txt`, so that building it cannot change how
`libWipePin.so` is built.

## Running

```sh
WPIN_OUT=pin.json WPIN_TARGET_FNS=handle WPIN_BUFFER_BARRIER=1 WWIT_OUT=witness.json \
  clang-18 -O2 -fpass-plugin=libWipePin.so -fpass-plugin=libWipeWitness.so -c t.c
python3 compiler/wipe-witness/scripts/witness_check.py --pin pin.json --witness witness.json
```

- `WWIT_OUT`: where the record goes. Unset or empty, the plugin prints one line
  and registers nothing. The file at that path is removed when the plugin
  loads, so a record left by an earlier compile cannot stand in for this one.
- **Order.** WipePin must come first on the command line: clang runs
  pipeline-start callbacks in the order the plugins were loaded, and the start
  count is meant to be of WipePin's output. The plugin watches the pass
  instrumentation for a pass named `WipePinPass` and writes the order it saw
  into the record; the checker refuses any order but `wipepin-first`.
- One source file per compile, as for WipePin.

`witness_check.py` exit codes:

| code | meaning |
|---|---|
| 0 | every function WipePin placed a repair in still has at least one WipePin barrier or volatile zero memset at the end, or is no longer a definition there (inlined or removed: reported as *not judged*) |
| 2 | at least one function is **SILENT**: placed, still defined, nothing left |
| 3 | cannot judge: a record missing, unreadable or of the wrong shape; the two records describe different modules, builds or producers; the order is not `wipepin-first`; the end of the pipeline was not reached; or the start count is below what WipePin says it placed |
| 4 | WipePin placed nothing (a dry run, or nothing in scope): nothing to judge |

## What is counted

Per function, at the start (directly after WipePin's pass, pipeline-start
extension point) and at the end (optimizer-last extension point):

| key | what |
|---|---|
| `barriers` | a call of `asm sideeffect "", "r,~{memory}"` with one pointer argument and no result: the exact shape both of WipePin's barrier writers build (`InlineAsm::get(FT, "", "r,~{memory}", true)` with `FT` = `void(ptr)`) |
| `otherMemoryAsm` | any other side-effecting inline asm whose constraint string clobbers memory |
| `volatileZeroMemsets` | a call of `llvm.memset.*` or `llvm.memset.inline.*` whose fill is the constant zero and whose volatile flag is the constant true: the shape of WipePin's pin and of its repair of a copy from an all-zero constant. Recognised by the callee's name, not its intrinsic id. `llvm.memset.element.unordered.atomic` is not counted |
| `volatileZeroStores` | a volatile store of a null constant. Not a shape WipePin makes; counted so a reader can see a wipe the source already kept |

## The GCC twin (`gcc/`, `libWipeWitnessGcc.so`)

The same reading of WipePinGcc's work (`../gcc-repair/`), written as a GCC
plugin; `witness_check.py` pairs a `WipePinGcc` record with a `WipeWitnessGcc`
record by the same rule.

```sh
cmake -S compiler/wipe-witness/gcc -B ~/vg-build/wipe-witness-gcc -G Ninja \
      -DCMAKE_CXX_COMPILER=g++-13
ninja -C ~/vg-build/wipe-witness-gcc       # -> libWipeWitnessGcc.so
WPIN_OUT=pin.json WPIN_TARGET_FNS=handle WWIT_OUT=witness.json \
  gcc-13 -O2 -fplugin=libWipePinGcc.so -fplugin=libWipeWitnessGcc.so -c t.c
```

What differs from the clang plugin:

- **Where it counts.** Two GIMPLE passes: the start pass after
  `*warn_function_return` (instance 1), the end pass after `optimized`
  (instance 1). In GCC 10 to 14 `*warn_function_return` follows `cfg`, and
  WipePinGcc's pass is inserted directly after `cfg`, so the start count is of
  WipePinGcc's output whichever plugin comes first on the command line
  (measured, below); nothing here depends on the order in which GCC
  initialises plugins. The record's `order` is read from the pass list:
  `wipepin-first` when a pass named `wipe_pin` precedes the start pass,
  `no-wipepin` when there is none.
- **What a barrier is.** WipePinGcc's pin and barriers are all
  `__asm__ __volatile__("" : : "g"(dest) : "memory")`: a volatile asm with an
  empty string, one input whose constraint is `"g"`, no outputs, no labels and
  the one clobber `"memory"`. GCC adds no clobbers to a GNU `asm` statement in
  GIMPLE, so **the same statement written in the source is the same GIMPLE and
  is counted as a barrier** (measured below); one written with `"r"` is
  `otherMemoryAsm`. `volatileZeroMemsets` is always 0: GCC has no volatile
  memset, and WipePinGcc's pin is the barrier.
- **Absent functions.** A function inlined everywhere never reaches the end
  pass and is `absent`; GCC never reports a function as `declaration`.
- **The record** is written once, at the end of the unit, with the keys of
  the clang record except `component` (`"WipeWitnessGcc"`) and `gccMajor` /
  `gccVersion` (the plugin headers' basever) in place of `llvmMajor` /
  `llvmVersion`; `ident` is the running compiler's basever, as in WipePinGcc's
  `host.ident`.

## The record (`wipe-witness-v1`)

One JSON object on one line. No timestamp: two runs of the same compile write
the same bytes.

| key | type | meaning |
|---|---|---|
| `schemaVersion` | string | `"wipe-witness-v1"` |
| `component` | string | `"WipeWitness"` |
| `module` | string | the module identifier's file name, as in WipePin's record |
| `ident` | string or null | the first `llvm.ident` operand with every parenthesised group removed (the rule of `../schema/wipe-pin.md` §14.7) |
| `identMajor` | integer or null | the integer after the first `clang version ` in `ident` |
| `llvmMajor` | integer | `LLVM_VERSION_MAJOR` of the headers the plugin was built against |
| `llvmVersion` | string | `LLVM_VERSION_STRING` of the same |
| `optLevel` | object | `{speedup, size}` of the pipeline the start pass was added to |
| `order` | string | `wipepin-first` (WipePinPass ran before the start pass), `witness-first` (it ran after), `no-wipepin` (it did not run), `unknown` (the host gave no pass instrumentation) |
| `endReached` | boolean | `false` in the record written by the start pass; the end pass overwrites it with `true` |
| `functions` | array | every function defined at the start, in module order, then every function defined at the end that was not (a clone the optimiser made) |

Each `functions[]` entry: `name` (the IR name, byte for byte), `start` (the four
counts, or `null` for a clone), `end` (the four counts when the function is
still a definition at the end, otherwise `null`), `endState` (`defined`,
`declaration` or `absent`; `null` while `endReached` is `false`).

## The rule

`witness_check.py` reads from WipePin's record the functions it placed
something in: the `pinned[]` sites that were not `alreadyVolatile` (when
`pinnedCount` is positive), and the sites of `barrierCalls`, `zeroCopy` and
`bufferBarriers` when their count of repairs is positive. A dry run places
nothing. For each such function `f`:

- the witness's start count of `f` (barriers + volatile zero memsets) must be
  at least the number placed, or the pair is refused: the start count is taken
  directly after WipePin, so everything WipePin placed is there;
- `f` not a definition at the end: *not judged*;
- `f` a definition with barriers + volatile zero memsets = 0 at the end:
  **SILENT**.

The counts are never compared for equality. The optimiser can hoist two
barriers into one block (`../llvm-repair/README.md` has a case where the record
said 2 and the optimised IR had 1, with both paths covered), and inlining copies
a callee's barriers into its caller (measured below: the `inline` source).

## What it cannot see

- **Code generation.** The end count is of the IR handed to the backend. A store
  the instruction selector drops after that is not seen.
- **Whether a barrier protects the wipe.** A barrier on a path the wipe does
  not take survives and is counted. Another of WipePin's placement errors
  (fixed since: a wipe only on the path that ends in `exit()`, and a barrier on
  the other path's lifetime end) is not reported: measured below, exit code 0.
- **Why a repair is gone.** A repair in code the optimiser proves dead is
  deleted with it, and is reported SILENT exactly like a misplaced one
  (measured below: a memset behind a static flag nothing sets).
- **Who placed a barrier.** A barrier of WipePin's exact shape that the source
  or another tool put there is counted the same way, and can mask a WipePin
  barrier that is gone. On x86-64, clang appends `~{dirflag},~{fpsr},~{flags}`
  to the constraints of every GNU `asm` statement, so a barrier written in C as
  `__asm__ __volatile__("" : : "r"(p) : "memory")` has another constraint
  string and is counted as `otherMemoryAsm`, not as a barrier (measured on
  clang 15 to 20, below). That is a property of the target and of clang's C
  front end, not something this plugin checks; other targets, and IR from
  other producers, are not measured.
- **Clones.** The rule is per function name. A function the optimiser replaced
  by a clone under another name (`.cold`, `.constprop.N`, …) is *not judged*
  if the original is gone, and a barrier in the clone does not count for the
  original.
- **LTO.** A link that runs the end extension point without pipeline start
  writes no record (one line on stderr); and, as with WipePin, the file at
  `WWIT_OUT` is removed when the plugin loads into the link. The link is not
  measured; the compile step is, once (below).

## Measured

2026-11-11, x86-64, Ubuntu 24.04 under WSL, the Ubuntu packages of clang 15.0.7,
16.0.6, 17.0.6, 18.1.3, 19.1.1 and 20.1.2, with the WipePin builds of
`../llvm-repair/README.md` (*2026-11-10, later*: LLVM 18 `7c9d11f2…`, and the
five others in its table). The scripts, the expectations written before each
run and the data are lab notes kept outside this repository.

**Builds.** 0 warnings against each of LLVM 15 to 20 (GNU 13.3.0); each
build, made again into another directory, has the same sha256. Building this
directory does not touch `../llvm-repair/`: the six WipePin builds above, made
again from this tree, have the sha256s of that README's table.

**The witness changes nothing.** 14 source configurations (13 generated
files, one of them also with `-D_FORTIFY_SOURCE=2`) × `-O0`, `-O1`, `-O2`,
`-O3`, `-Os` × clang 15 to 20, each compiled `-S` with and without the
witness: stock against the witness alone; WipePin (switches off) against
WipePin then the witness; WipePin with `WPIN_BARRIER_CALLS=1`,
`WPIN_ZERO_COPY=1` and `WPIN_BUFFER_BARRIER=1` against the same then the
witness, and against the witness then WipePin; and, on clang 18, the same for
two older WipePin builds. 1,820 comparisons, 0 differ. No compile exited
non-zero.

**`-O0`.** Both passes run and `endReached` is `true` in every record; the start
and end counts are equal for every function in every compile where WipePin ran
first or did not run (16 functions per version and arm, clang 15 to 20).

**The current WipePin builds.** Over the 70 compiles per version and arm, the
checker gave exit 0 or 4 everywhere with the switches on (0: 60, 4: 10 in each
version), and SILENT only for the dead-code source with the switches off
(below).

**Other paths through the plugin** (clang 15 to 20 for the first; clang 18 for
the rest). Front-end IR whose `llvm.ident` was rewritten to name the next major
version: `refusing to count` on stderr, no record (a file left at `WWIT_OUT`
before the compile was gone), `-S` identical with stock's. `WWIT_OUT` unset:
one line, `-S` identical with stock's. `WWIT_OUT` in a directory that does not
exist: one line, compile exit 0. `-Xclang -disable-llvm-passes`: no record.
The same compile twice: byte-identical records. The compile step of
`-flto=thin -c` and of `-flto -c` (one source, the `musttail` one): both passes
ran, `endReached` `true`, checker exit 0.

**The older builds (clang 18 only).**

| source, level | build | record (placed) | end: barriers | checker | `-S` against stock |
|---|---|---|---|---|---|
| loop wipe before `musttail`, `-O1` `-O2` `-O3` `-Os` | of the 2026-11-09 fixes (`8f2bd520…`), anchor `lifetime-end` | 1 | 0 | **2 (SILENT)** | identical, at all four levels |
| the same, `-O0` | of the 2026-11-09 fixes | 1 | 1 | 0 | differs |
| the same, every level | current (`7c9d11f2…`), anchor `ret` | 1 | 1 | 0 | differs: two 16-byte zero stores before the tail jump at `-O2` |
| wipe only before `exit()`, `-O1` to `-Os` | 2026-11-10 afternoon (`239e8230…`) | 1 | 1 | 0 (not reported) | differs: the barrier reads the buffer on the return path |
| the same | current | 0 | 0 | 4 | identical |

In that `exit()` source the key is passed to two external functions, and the
stock compile kept the wipe before `exit()` at `-O2` (read in the assembly);
nothing was lost there, but the witness could not have said so either way.

**Past placement shapes** (clang 18, `-O2`, `WPIN_BUFFER_BARRIER=1` with the
other two switches on, current build). Zero stores read by hand in the
function's assembly.

| source | record (placed) | end: barriers | checker | zero stores of the buffer (stock → with WipePin) |
|---|---|---|---|---|
| loop wipe before `musttail` | 1 | 1 | 0 | none → 32 bytes |
| VLA in a branch, loop wipe | 0 (no place) | 0 | 4 | none → none |
| wipe only before `exit()` | 0 (no place) | 0 | 4 | 32 bytes → the same |
| `goto` out of the block after the wipe | 1 | 1 | 0 | 32 bytes → the same |
| backward `goto` past the declaration (second function) | 0 | 0 | — | 32 bytes → the same |
| `setjmp` (wipe on both returns) | 1 | 1 | 0 | none → 32 bytes |
| declaration at the top of a `switch` body | 1 | 1 | 0 | none → 32 bytes |
| nested loops over `unsigned char[4][8]` | 1 | 1 | 0 | none → 32 bytes |
| the same buffer wiped twice | 1 | 1 | 0 | 32 bytes → 64 bytes |

**Dead code.** A pinned memset behind `if (wipe_enabled)`, where the static
`wipe_enabled` is never written: SILENT at `-O1`, `-O2`, `-O3` and `-Os` on
clang 15 to 20 with the switches off, and the `-S` equals stock's at each; not
SILENT at `-O0`. With `WPIN_BUFFER_BARRIER=1`, not SILENT: the buffer barrier
at the end of the lifetime survives the deleted branch.

**Inlining.** A static wipe helper with a memset: at `-O2` the helper is absent
at the end (not judged) and its caller, in which nothing was placed, has the
volatile zero memset at the end and none at the start.

**The source's own barrier.** `__asm__ __volatile__("" : : "r"(key) : "memory")`
after a memset: `call void asm sideeffect "", "r,~{memory},~{dirflag},~{fpsr},~{flags}"`
in the IR of clang 15 to 20, counted as `otherMemoryAsm` (1) and not as a
barrier (0) at all five levels and all six versions; WipePin's barrier in the
same versions is `"r,~{memory}"`.

**Reversed order.** The witness loaded before WipePin: `order` was
`witness-first` and the checker exited 3 in every such compile (70 per
version), and the `-S` was identical with WipePin's alone.

**A build loaded into another clang.** The LLVM 19 build of the witness given
to clang 18 (by `scripts/run-witness-check.sh`): it loaded, its start pass
refused the module by `llvm.ident`, no record was written, and the runner
exited 3.

**`scripts/run-witness-check.sh`** (clang 18 and gcc 13): all 18 cells as
expected, exit 0. Given the LLVM 18 build of the 2026-11-09 fixes (`8f2bd520…`) instead, it exits 2:
`musttail-O2` is SILENT, and `exit-O2` gives 0 where 4 is expected (that
build places a barrier there).

**The GCC twin** (gcc 10.5.0, 11.5.0, 12.4.0, 13.3.0 and 14.2.0, with the
WipePinGcc builds of `../gcc-repair/README.md`; gcc 13 `ea3e8c7e…`). Builds:
0 warnings each; each, made again into another directory, has the same
sha256. The same 14 source configurations plus two (a loop wipe, and
the source's own barrier written with `"g"`), minus the `musttail` one, which
gcc 10 to 14 do not parse: 15 × five levels × five versions, compared as for
clang (stock against the witness alone; WipePinGcc with the switches off, and
on, with and without the witness; the witness first on the command line):
1,500 comparisons, 0 differ, no compile exited non-zero. `order` was
`wipepin-first` in every compile with WipePinGcc, in either command-line order.
Checker: 0 or 4 everywhere with the switches on, in both orders (0: 60, 4: 15
per version); SILENT only for the dead-code source with the switches off, at
`-O1` to `-Os` (20 of 20). `-O0`: `endReached` `true` in all 225 records, start
equal to end for all 255 functions. The source's own barrier: with `"g"`,
counted as a barrier (1) at the start and the end in every version and level,
and WipePinGcc left that memset alone (`alreadyVolatile`), so nothing was
placed; with `"r"`, `otherMemoryAsm`.

**A corpus.** Every file of the r4 L corpus (1,295 generated C files; the
WipePin README's measurements use 51 of them), `-O2`, `WPIN_SCOPE=module` with
the three switches on, clang 18 with WipePin (`_FORTIFY_SOURCE` not defined)
and gcc 13 with WipePinGcc (its default at `-O2`, `_FORTIFY_SOURCE=3`). 66
files (clang) and 43 (gcc) do not compile, stock included, and are left out.
Of the rest, every `-S` with the witness equalled the `-S` without it (stock
against the witness alone, and the repair plugin against the repair plugin
then the witness: 1,229 and 1,252 files). No file was SILENT and none was
refused. clang: 184 files with a placement (exit 0), 1,045 with none (exit 4);
of the functions with a placement, 130 were judged `ok` and 62 were not
definitions at the end (inlined: *not judged*). gcc: 108 and 1,144 files; 105
functions `ok`, 3 not judged. So on clang about a third of the functions with
a placement were outside what the rule can judge.

**The checker's tests** (`test/test_witness_check.py`, 52 tests, no compiler):
each of 16 mutations of the rule in `witness_check.py` (for example comparing
for equality, counting volatile stores as kept, judging absent functions,
skipping the order or the start-count check) makes at least one test fail.

## Not measured

C++ (`invoke`, `linkonce_odr`), LTO links (full or thin) and LTO compile steps
beyond the one source above (none on GCC), targets other than x86-64, the
corpora beyond the one run above (the E3 and E5 rewrites, other levels,
`_FORTIFY_SOURCE` settings and versions), builds loaded into a
compiler of another major version beyond the one pair above (the GCC twin
relies on `plugin_default_version_check`, as WipePinGcc does), the GCC twin
against an older WipePinGcc build, and any claim about the object file beyond
the `-S` comparisons above.

## Files

| file | what |
|---|---|
| `src/WipeWitness.cpp` | the clang plugin |
| `gcc/src/WipeWitnessGcc.cpp`, `gcc/CMakeLists.txt` | the GCC plugin |
| `scripts/witness_check.py` | the checker (Python 3 standard library) |
| `scripts/run-witness-check.sh` | ten cells with a real clang and WipePin, and eight more with gcc and WipePinGcc when both GCC plugins are given, graded against fixed exit codes (`--lab <dir> --wipepin <so> --witness <so> [--cc clang-18] [--wipepin-gcc <so> --witness-gcc <so> [--gcc gcc-13]]`; exit 0 all held, 2 one did not, 3 a tool or record missing) |
| `test/test_witness_check.py` | the checker's unit tests; run as a file |
