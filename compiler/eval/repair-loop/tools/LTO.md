# The LTO probe

`compiler/llvm-repair/README.md` ("Other forms") left one question open: a
`-flto` or `-flto=thin` compile with WipePin loaded writes a record, and the
bitcode carries the volatile memset — but what the LTO backend then does with it
was never measured. `lto-probe.mjs` measures it, with the find step's own
verdict, on the assembly the LTO backend writes.

Its twin for gcc-13 and WipePinGcc, `lto-probe-gcc.mjs`, has its own section
below (*gcc-13*); everything before that section is about clang.

**Answer, for what was run** (`clang-18` / `lld` 18.1.3, x86-64, one object per
link, `-shared`): every wipe the stock LTO build loses comes back when WipePin is
loaded at compile time — 113/113 at `-O2` under full and under thin LTO, 62/62 at
`-O1` under both, 10/10 at `-O3` and at `-Os` under both on a sample of 10 files.
Over all 133 files of the `removable` idiom at `-O2` (run F), neither LTO form
removes a wipe the non-LTO find step saw survive. Loaded only on the link line, WipePin is loaded but its pass never runs: no
record, and the assembly is byte-identical to the stock link, in every link.
Since the plugin change described under *What changed in (ii)* below, it also
says so on the link's stderr, once. Before that change it was silent, and its
load had deleted whatever was at `WPIN_OUT`.

## What is measured

For each selected file, LTO form (`full`, `thin`) and level, the probe makes the
same two units the repair loop makes — the file as written plus the positive
control (`w`), and the same with every wipe span deleted by the imported
`ablateSpans` (`wo`) — and compiles each of them three times:

| config | compile | link |
|---|---|---|
| off | stock | stock |
| on | `-fpass-plugin=<so>`, `WPIN_TARGET_FNS=<fn>,<helpers>` | stock |
| dry | as *on*, plus `WPIN_DRY_RUN=1` | stock |

Every compile uses the find step's `FLAGS` (imported from
`../../ai-generated/lib/ablation-cell.mjs`) with `-S` replaced by `-c` and
`-flto` or `-flto=thin` appended; the probe refuses to run if `FLAGS` does not
carry `-S` exactly once or already carries an output-form flag. Each object is
then linked **alone**, and lld stops after the LTO backend and writes the
assembly it would have assembled. `verdictOf`, `bodyOf` and `controlPresent` —
imported, not copied — judge that assembly:

```
baseline = verdictOf(w/off, wo/off, fn)     # the find step, under LTO
repaired = verdictOf(w/on,  wo/on,  fn)     # (i)   the measurement
dry      = verdictOf(w/dry, wo/dry, fn)     # (iii) the red control
linkline = verdictOf(w/off + plugin on the link line, wo/off + same, fn)   # (ii)
```

- **(i) plugin at compile time, stock link.** Outcomes use the repair loop's
  words and precedence (`../lib/outcome.mjs`), restated over the three record
  fields this probe reads (see below), with one word in front: `NOT_LTO`.
  `PIN_INEFFECTIVE` — eliminated both ways although something was pinned — is the
  word that would say the LTO backend undid the pin.
- **(ii) plugin only on the link line** (`-Wl,--load-pass-plugin=<so>`, with
  `WPIN_OUT` and `WPIN_TARGET_FNS` in the link's environment). WipePin registers
  its pass on the pipeline-start extension point, and an LTO link does not run
  that point (`../../../docs/toolchain-probes.md` §2.2), so the expectation is
  that it never fires. That is measured, not assumed: before the link a sentinel
  file is put at `WPIN_OUT`; afterwards the probe records whether a record was
  written, whether the sentinel is gone (WipePin removes whatever is at
  `WPIN_OUT` in its load-time callback, before anything else, so "gone" means the
  plugin was loaded and its callback ran), how often the linker's stderr carries
  WipePin's link-time line (`LINK_LINE_REMOVED` in `lib/lto.mjs`) and whether it
  carries anything else, and whether the assembly is byte-identical to the stock
  link of the same object. Graded (`gradeLinkPlugin`): `HELD` when every such
  link removed the sentinel, wrote no record, printed exactly that line once and
  nothing else, and produced the stock link's assembly; otherwise `FAILED`, and
  the run exits 2.
- **(iii) dry run.** Every cell whose LTO baseline is `WIPE_ELIMINATED` must still
  read `WIPE_ELIMINATED`, and both dry-run records must say `dryRun: true`,
  `pinnedCount: 0`. Graded `HELD`/`FAILED`; a control with no eliminated baseline
  is `FAILED` as vacuous. Also reported: whether each dry-run object is
  byte-identical to the plugin-off object, and its post-LTO assembly to the
  plugin-off one.
- **Determinism.** The `off` and `on` objects of both units are each linked a
  second time; the two assemblies must be byte-identical.
- **Where the loss happens.** `llvm-dis-18` reads the compile-stage bitcode of
  `w/off` and `w/on`, and the probe counts zero-fill `llvm.memset` calls in the
  requested functions, split by the volatile operand. A wipe the compile stage
  already removed never reaches the linker.
- **Against the tracked rows.** Each LTO baseline is compared with the find
  step's tracked, non-LTO verdict for the same `(id, clang-18, level)`; every
  difference is listed by id. A difference is allowed — the LTO backend is a
  second optimisation of the same code — but it must be visible.

### Guards, so that a non-LTO measurement cannot pass as one

- **Bitcode magic.** Every object must start with `BC` `0xC0DE`. An ELF object,
  an empty file or anything else makes the cell `NOT_LTO`, ahead of every other
  outcome, and the run exits 2.
- **The one file each form writes.** Each object sits alone in its own directory
  and each link's `-o` is put beside it, so every file lld writes lands there.
  The link must write exactly the one file its form writes (below); anything
  else makes the cell `NOT_LTO`. The name also says which backend ran, so a thin
  object that lld linked as full LTO (or the reverse) is caught.
- **Preflight, per form and level, before any cell.** A small unit (a memset
  plus the positive control) is compiled `-flto`. A way of reading post-LTO code
  is accepted only if (a) what it yields is cut by `bodyOf` with the positive
  control `PRESENT`, and (b) its link demonstrably builds the LTO optimisation
  pipeline: with WipePin on that link line, the sentinel at `WPIN_OUT` must be
  gone, since WipePin's load-time callback runs when the LTO backend builds its
  pass pipeline. The first way is `--lto-emit-asm`; if it failed, the probe falls
  back to `--save-temps` (its `precodegen.bc`, the module after the LTO
  optimisation pipeline) plus `llc-18` and says so on stderr and in the results;
  with neither it exits 5. The plugin must load into an `-flto` compile and write
  a record that pinned something (exit 5 otherwise). And the sentinel of
  configuration (ii) must be able to say "kept": after a stock link, and after a
  link naming a plugin file that does not exist, it must still be there (exit 5
  otherwise).
- **Nothing inherited steers anything.** Every `WPIN_*` variable is removed from
  the environment before the first compile; record paths are deleted before the
  compile that should write them, and each cell's directory is deleted before
  the cell runs.
- **Lab only.** `--out` inside the repository is refused (exit 4), and so is
  `--write-data` (exit 4): nothing this probe writes is tracked data. The rows,
  results and manifest are scanned for absolute paths before the run ends
  (`../lib/provenance.mjs`, exit 5 on a hit).

### What the records are read for

Plugin records are read with `JSON.parse` and three fields only — `dryRun`,
`pinnedCount`, `module` — not through `../lib/pin-record.mjs`, so that the probe
does not depend on the record schema beyond them. A record is refused when it is
missing, is not a JSON object, has a field of the wrong type, names a path as its
`module`, names another unit, carries the wrong `dryRun`, or is a dry run that
pinned. The price: **a requested name that did not resolve is not seen here**,
and neither is the static-helper exception the repair loop tolerates. The record
never decides survival; the assembly does.

## lld 18.1.3 behaviour the probe relies on (measured)

| what | measured |
|---|---|
| `--lto-emit-asm`, full LTO | writes `<-o>.lto.s` next to `-o`; nothing at `-o` |
| `--lto-emit-asm`, ThinLTO | writes `<basename of -o>.lto.<object stem>.s` **next to the object**, not next to `-o`; nothing at `-o` |
| `--lto-emit-llvm` | does not exist: `ld.lld: error: unknown argument '--lto-emit-llvm'`, exit 1 |
| `--plugin-opt=emit-llvm` | writes bitcode to `-o` itself (both forms) — but **before** the LTO optimisation pipeline: with `--lto-debug-pass-manager` it prints 0 `Running pass` lines (15 for `--lto-emit-asm`, full LTO, `-O1`, on `haiku_E_hmackey_r2`), a plugin on its link line is never asked to register (the sentinel stayed in all 40 (ii) links of a 5-file run made with an earlier version of this probe, which used it as the fallback), and at full `-O1` its output still holds the memset in `sign_message` that the LTO link removes. Not usable as "post-LTO code"; the fallback was rebuilt on `--save-temps` and the preflight's check (b) added because of it |
| `--save-temps` with `--lto-emit-asm` | besides the assembly: full LTO `<-o>.0.0.preopt.bc`, `.0.2.internalize.bc`, `.0.4.opt.bc`, `.0.5.precodegen.bc`, `.resolution.txt`; ThinLTO `<-o>.0.0.preopt.bc`, `.0.2.internalize.bc`, `.index.bc`, `.index.dot`, `.resolution.txt` and, named after the object, `<obj>.0.preopt.bc` … `.5.precodegen.bc`. The fallback reads `precodegen.bc` with `llc-18` |
| the driver's link line (`-###`) | `-plugin-opt=mcpu=x86-64 -plugin-opt=O2 [-plugin-opt=thinlto] --lto-emit-asm [--thinlto-jobs=1]`; `-O1` gives `-plugin-opt=O1`, `-Os` gives `-plugin-opt=O2` (the size preference travels as function attributes in the bitcode) |
| the object's summary block (`llvm-bcanalyzer-18 -dump`, one pair) | `-flto=thin`: `GLOBALVAL_SUMMARY_BLOCK`; `-flto`: `FULL_LTO_GLOBALVAL_SUMMARY_BLOCK` |
| a plugin file that does not exist on an LTO link line | stderr carries `Failed to load passes` (the exit code, 0 in `../../../docs/toolchain-probes.md` §2.4, is not recorded by the probe); the sentinel at `WPIN_OUT` kept |

The same object linked twice gave byte-identical assembly in every pair the
probe made (below). The full-LTO assembly names its module `ld-temp.o` in its
`.file` line; the ThinLTO assembly names the source unit.

## Commands

Build the plugin from this tree, outside it:

```sh
cmake -S compiler/llvm-repair -B ~/vg-build/lane-e-wipepin -G Ninja \
      -DLLVM_DIR=$(llvm-config-18 --cmakedir)
ninja -C ~/vg-build/lane-e-wipepin      # libWipePin.so; runs A–D: sha256 aa7329c3…f0a66, run E: db3298cf…73a4c8
```

What one cell runs (`<d>` is the object's own directory under the lab):

```sh
# compile (off; on adds -fpass-plugin=<so> and WPIN_OUT=<d>/record.json
#          WPIN_TARGET_FNS=<fn>,<helpers>; dry adds WPIN_DRY_RUN=1)
clang-18 -c -std=gnu11 -w -Wno-error=implicit-function-declaration \
         -fcf-protection=none -flto <opt> -o <d>/u.o <id>.w.c

# stock link, full LTO: the assembly is <d>/stock1.s.lto.s
clang-18 <opt> -flto -fuse-ld=lld -shared -Wl,--lto-emit-asm -o <d>/stock1.s <d>/u.o

# stock link, ThinLTO: the assembly is <d>/stock1.s.lto.u.s
clang-18 <opt> -flto=thin -Wl,--thinlto-jobs=1 -fuse-ld=lld -shared \
         -Wl,--lto-emit-asm -o <d>/stock1.s <d>/u.o

# (ii): the stock link line of the off object plus
#   -Wl,--load-pass-plugin=<so>   with WPIN_OUT=<sentinel> WPIN_TARGET_FNS=... in the environment
```

The runs whose numbers are below (the lab directories are outside the
repository; the probe refuses anything else):

```sh
P=compiler/eval/repair-loop/tools/lto-probe.mjs
SO=~/vg-build/lane-e-wipepin/libWipePin.so
node $P --plugin $SO --out <lab>/A-O2   --conc 4                                   # all 113, -O2
node $P --plugin $SO --out <lab>/B-O1   --opts -O1 --conc 4                        # all 113, -O1
node $P --plugin $SO --out <lab>/C-O3Os --opts -O3,-Os --sample 10 --conc 4        # 10 of 113
node $P --plugin $SO --out <lab>/D-llc  --opts -O1,-O2 --sample 5 --force-fallback --conc 4
node $P --plugin $SO --out <lab>/F-rem  --all-removable --conc 2                   # all 133 removable, -O2
```

Options: `--modes full,thin` (default both), `--opts` (default `-O2`), `--files`
(basenames or globs within the selection), `--sample <n>` (n files spread evenly
over the sorted selection), `--conc` (default 4), `--force-fallback`,
`--all-removable`, `--cc`, `--llc`, `--llvm-dis`, `--rows`. The selection itself
is fixed: the `clang-18` erasure files the tracked rows
(`../../ai-generated/data/r2-build-rows.json`) score `WIPE_ELIMINATED` at `-O2` —
113 files, all of the `removable` idiom — or, with `--all-removable`, every
`clang-18` erasure file of the `removable` idiom there: 133 files, the 113 and 20
whose wipe survives without LTO (`selectErasureIds` in `lib/lto.mjs`).

Unit tests for the pure parts (`lib/lto.mjs`), no compiler needed:

```sh
node --test compiler/eval/repair-loop/test/lto-probe.test.mjs
```

Exit codes: `0` complete and every integrity check held · `2` complete, but a
cell was `NOT_LTO`, a relink was not byte-identical, the dry-run red control
did not hold or was vacuous (no cell with an eliminated baseline, so nothing to
control), or configuration (ii) was `FAILED` · `3` nothing selected · `4` bad arguments, `--out` inside the
repository, or `--write-data` · `5` a tool, the plugin or the shared verdict
module could not be used, the preflight failed, or a lab text carried an
absolute path. A cell's own `BROKEN_REPAIR` or `REGRESSED` is an outcome, not an
integrity failure: it is counted in the table and does not change the exit code,
as in the repair loop. What the run proves is read from the counts, not from the
exit code. The `--out` guard compares the resolved paths as strings, so a
symlink into the repository, or a path that differs only in case where the file
system does not, is not caught.

## Results

`clang-18` 18.1.3 (Ubuntu), `Ubuntu LLD 18.1.3`, WSL Ubuntu 24.04, x86-64;
`libWipePin.so` built from `compiler/llvm-repair/`. Runs A–D were made with the
`wipe-pin-v1` build, sha256
`aa7329c3d9ba002915f885624c17d6da1418aa39a2b762d1655e83786e6f0a66`, which emits
the same code as v2 (`compiler/llvm-repair/README.md`, *`wipe-pin-v2`*,
"Same code as `v1`");
run E, below, with `db3298cfb30d14200fe0822261eaa1c35aa51aed4aef869a0edd3151f073a4c8`,
the build the repair loop's tracked results now quote, and so do runs F and G.
Run G re-measures B and C with that build, and C over every file rather than a
sample. Post-LTO code read
through `--lto-emit-asm` in runs A–C: the preflight passed in every form and
level, so the fallback was not needed. All four runs exited 0.

| run | form | level | cells | eliminated without the plugin (LTO) | differs from the tracked non-LTO row | `RETAINED` | `ALREADY_SURVIVED` | `BROKEN_REPAIR` / `PIN_INEFFECTIVE` / other | dry run (iii) |
|---|---|---|---|---|---|---|---|---|---|
| A | full | `-O2` | 113 | 113 | 0 | **113** | 0 | 0 | `HELD` 113/113 |
| A | thin | `-O2` | 113 | 113 | 0 | **113** | 0 | 0 | `HELD` 113/113 |
| B | full | `-O1` | 113 | 62 | 0 | **62** | 51 | 0 | `HELD` 62/62 |
| B | thin | `-O1` | 113 | 62 | 0 | **62** | 51 | 0 | `HELD` 62/62 |
| C | full | `-O3` | 10 | 10 | 0 | **10** | 0 | 0 | `HELD` 10/10 |
| C | thin | `-O3` | 10 | 10 | 0 | **10** | 0 | 0 | `HELD` 10/10 |
| C | full | `-Os` | 10 | 10 | 0 | **10** | 0 | 0 | `HELD` 10/10 |
| C | thin | `-Os` | 10 | 10 | 0 | **10** | 0 | 0 | `HELD` 10/10 |

**Run G: B and C again with `wipe-pin-v2`, C over every file** (2026-09-12,
plugin `db3298cf…73a4c8`, `--opts -O1,-O3,-Os`, both forms, all 113 files, exit
0, about 5.5 minutes). Every count of B and C holds with the v2 build, and
`-O3`/`-Os` are no longer a sample of 10:

| run | form | level | cells | eliminated without the plugin (LTO) | differs from the tracked non-LTO row | `RETAINED` | `ALREADY_SURVIVED` | dry run (iii) | (ii) graded | relinks identical |
|---|---|---|---|---|---|---|---|---|---|---|
| G | full | `-O1` | 113 | 62 | 0 | **62** | 51 | `HELD` 62/62 | `HELD`, 226 links | 452/452 |
| G | thin | `-O1` | 113 | 62 | 0 | **62** | 51 | `HELD` 62/62 | `HELD`, 226 links | 452/452 |
| G | full | `-O3` | 113 | 113 | 0 | **113** | 0 | `HELD` 113/113 | `HELD`, 226 links | 452/452 |
| G | thin | `-O3` | 113 | 113 | 0 | **113** | 0 | `HELD` 113/113 | `HELD`, 226 links | 452/452 |
| G | full | `-Os` | 113 | 113 | 0 | **113** | 0 | `HELD` 113/113 | `HELD`, 226 links | 452/452 |
| G | thin | `-Os` | 113 | 113 | 0 | **113** | 0 | `HELD` 113/113 | `HELD`, 226 links | 452/452 |

The `-O1` reading below holds with v2 as well: in all 62 eliminated cells per
form the `w/off` compile-stage bitcode still holds the plain zero-fill memset
and the `w/on` bitcode a volatile one, and at `-O3` and `-Os` neither holds one
in any of the 113.

- **The find step's verdict does not move under LTO** in anything run here: in
  every cell the LTO baseline equals the tracked non-LTO verdict for the same
  file and level (0 differences; at `-O1` the same 62 of 113 are eliminated).
- **(i)** No `BROKEN_REPAIR`, `PIN_INEFFECTIVE`, `SURVIVED_WITHOUT_PIN`,
  `REGRESSED`, `NOT_SCORED` or `NOT_LTO` cell in any run. The positive control
  was `PRESENT` in every plugin-on link.
- **(ii) plugin on the link line only**: in all 452 links of run A (and 452 of B,
  80 of C) no record was written, the sentinel at `WPIN_OUT` was removed — the
  plugin was loaded and its load-time callback ran — the linker's stderr was
  empty, and the assembly was byte-identical to the stock link of the same
  object; the (ii) verdict equals the baseline in every cell. WipePin on an LTO
  link line was loaded, silent, and did nothing. That silence is what the change
  in *What changed in (ii)* removes; the probe as it is now grades a silent
  link `FAILED` (measured with the pre-change `wipe-pin-v2` plugin, below).
- **(iii) dry run**: `HELD` everywhere. Every dry-run object is byte-identical to
  the plugin-off object (452/452 in A), and so is its post-LTO assembly.
- **Determinism**: 904/904 relinks byte-identical in A, 904/904 in B, 160/160 in C.
- **Where the loss happens.** At `-O2`, `-O3` and `-Os`, in every eliminated
  cell, the compile-stage bitcode of `w/off` already holds **no** zero-fill memset
  in the requested functions, under both forms: the stock wipe is gone before the
  linker sees it (the full-LTO compile runs nearly the whole `-O2` pipeline,
  `../../../docs/toolchain-probes.md` §2.1, and the ThinLTO pre-link pipeline
  removes it too). The pinned one is in the `w/on` bitcode as a volatile memset
  in every cell, and it is still in the post-LTO assembly. At **`-O1`** the
  compile-stage bitcode of `w/off` still **holds** the plain memset in all 62
  eliminated cells: there the loss happens after the compile stage, in the LTO
  link (its optimisation or its code generation; this probe does not separate the
  two), and with the pin all 62 survive it. So `-O1` is the level at which the
  volatile flag was tested against an elimination the LTO link itself performs.
- **The fallback path** (run D, `--force-fallback`: `--save-temps`'
  `precodegen.bc` plus `llc-18`, 5 files, `-O1`/`-O2`, both forms): the same
  baseline, repaired, dry-run and outcome words as the assembly path for the
  same 20 (file, form, level) cells — `-O1` 3 `RETAINED` and 2
  `ALREADY_SURVIVED` per form, `-O2` 5 `RETAINED` per form — dry run `HELD`,
  80/80 relinks byte-identical, and in configuration (ii) the sentinel removed in
  40/40 links (the LTO pipeline was built). The fallback also passed the
  preflight in every form and level of runs A–D. Exercised so that it is not
  dead code; it was not needed.

Wall time on 4 parallel cells: about 1.5 minutes for each of runs A and B.

### A link-line load deletes the compile's record

One-off, by hand, both forms at `-O2` on `fable_N_aeskey_r1`: a compile with
WipePin at compile time wrote its record (`pinnedCount` 1) at `WPIN_OUT`; a link
of that object with `-Wl,--load-pass-plugin=<so>` and the **same** `WPIN_OUT` in
the environment then exited 0 with 0 bytes on stderr, and the record was gone. A
build that loads WipePin on both lines with one `WPIN_OUT` therefore ends with no
record although the object is pinned — a loud-looking "the repair never ran"
that is false. This is the load-time stale-record removal
(`compiler/llvm-repair/README.md`) doing what it was written to do, in a host it
was not written for.

### What changed in (ii)

The plugin now says it. `compiler/llvm-repair/src/WipePin.cpp` sets a flag when
its pipeline-start callback is invoked, which happens when a pipeline is built,
and registers a pass-instrumentation callback. The first pass a process runs
while that flag is unset makes it print, once per process:

```
WipePin: loaded into a pipeline built without the pipeline-start extension point (an LTO link, or a compile under -disable-llvm-passes), where this pass does not run; nothing was pinned in this process, and the file at WPIN_OUT was removed when the plugin loaded
```

(`… and there was no file at WPIN_OUT when the plugin loaded` when its load
found nothing to remove). The removal itself is kept, and the line says it
happened; the README gives the reason (*The link-time line*). The record schema
and the code the plugin emits in a compile are unchanged (measured there).

So the probe changed with it. Before, (ii) counted "linker stderr empty", and
an empty stderr was the right answer: it is also what hid the deletion. Now (ii)
expects that line, in its "removed" form (the probe always puts the sentinel at
`WPIN_OUT` first), exactly once and nothing else on the linker's stderr. An
empty stderr, the line twice, the line plus a linker diagnostic, or the
"there was no file" form are all violations. (ii) is graded `HELD`/`FAILED` as
the dry run is (`gradeLinkPlugin` in `lib/lto.mjs`), and a `FAILED` (ii) makes
the run exit 2; before, (ii) was reported and never graded. The line's text is
pinned in `lib/lto.mjs` as `LINK_LINE_REMOVED`, and a unit test rebuilds it from
the plugin's C++ string literals so that the two cannot drift apart silently.

**Run E** (plugin `db3298cfb30d14200fe0822261eaa1c35aa51aed4aef869a0edd3151f073a4c8`,
built from `compiler/llvm-repair/` at this change; all 113 files, `-O2`, full and
thin, `--conc 4`, exit 0, about 1.8 minutes):

| form | level | cells | eliminated without the plugin (LTO) | differs from the tracked non-LTO row | `RETAINED` | dry run (iii) | (ii) links | (ii) stderr exactly the line, once | (ii) sentinel removed / record written | (ii) assembly equal to the stock link | (ii) graded | relinks identical |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| full | `-O2` | 113 | 113 | 0 | **113** | `HELD` 113/113 | 226 | **226/226** | 226 / 0 | 226/226 | `HELD` | 452/452 |
| thin | `-O2` | 113 | 113 | 0 | **113** | `HELD` 113/113 | 226 | **226/226** | 226 / 0 | 226/226 | `HELD` | 452/452 |

Everything outside (ii) reads as in run A: dry-run objects byte-identical to
plugin-off 226/226 per form, and in every eliminated cell the compile-stage
bitcode of `w/off` holds no zero-fill memset while `w/on` holds a volatile one
(113/113 per form).

### Run F: every removable-idiom file at `-O2`

Runs A–E link only the files the find step scored eliminated, so they cannot
see an elimination the LTO link adds. `--all-removable` selects every `clang-18`
erasure file of the `removable` idiom at `-O2` instead: the 113 eliminated ones
and the 20 whose wipe survives without LTO. **Run F** (plugin
`db3298cfb30d14200fe0822261eaa1c35aa51aed4aef869a0edd3151f073a4c8`, built from
`compiler/llvm-repair/` again for this run; `-O2`, full and thin, `--conc 2`,
exit 0, 216 s):

| form | level | cells | eliminated without the plugin (LTO) | differs from the tracked non-LTO row | added eliminations | `RETAINED` | `ALREADY_SURVIVED` | dry run (iii) | (ii) graded | relinks identical |
|---|---|---|---|---|---|---|---|---|---|---|
| full | `-O2` | 133 | 113 | 0 | 0 | **113** | 20 | `HELD` 113/113 | `HELD`, 266 links | 532/532 |
| thin | `-O2` | 133 | 113 | 0 | 0 | **113** | 20 | `HELD` 113/113 | `HELD`, 266 links | 532/532 |

The 20 wipes that survive without LTO survive the full and the thin LTO link
too, and stay `ALREADY_SURVIVED` with the plugin; the 113 read as in runs A and
E. In (ii), each of the 266 links per form removed the sentinel, wrote no
record, printed the link-time line exactly once and nothing else, and gave the
stock link's assembly; dry-run objects and their post-LTO assembly were
byte-identical to plugin-off (266/266 per form); and in all 113 eliminated
cells per form the compile-stage bitcode of `w/off` holds no zero-fill memset
while `w/on` holds a volatile one.

### Shown to fail

Each through a compiler wrapper generated into the lab (not in this tree):

- a wrapper that drops `-flto*` from the compiles of the corpus units (not from
  the preflight unit), 2 files, full LTO, `-O2`: both cells `NOT_LTO`
  (`w.off object is elf; …` for all six objects), the dry-run control `FAILED` as
  vacuous, exit **2**;
- a wrapper that removes `WPIN_DRY_RUN` from the compile's environment, 2 files,
  thin LTO, `-O2`: the dry run reads `WIPE_SURVIVED` in both cells and both
  dry-run records are refused (`dryRun-false-expected-true`), red control
  `FAILED`, exit **2**;
- `--out` inside the repository: exit **4**, nothing created; `--write-data`:
  exit **4**;
- the `wipe-pin-v2` plugin from before the link-time line
  (`e89e07fd54c397058d9a9ee28eb1faa2b879d27b060dc7a251231bccb11cbad6`), 3 files
  (`--sample 3`), full and thin, `-O2`: (ii) `FAILED` under both forms, 12
  violations, every one `the linker's stderr carries the link-time line 0
  time(s), expected exactly once and nothing else`, with the sentinel removed,
  no record and the assembly equal to the stock link in all 12 links, and
  everything else as in run E (`RETAINED` 3/3, dry run `HELD`, 12/12 relinks
  identical, per form); exit **2**.

## What this does not claim

- **One translation unit per link.** Each object is linked alone, so there is no
  cross-unit inlining here: a wipe helper defined in another unit and inlined at
  link time, or a target inlined into a caller from another unit, is not measured
  by this probe. The wipe and its target are always in the same module here. The
  first of those cases is measured on a generated fixture instead, by the `xtu`
  cells of both fixture loops (`../../llvm-repair/README.md`, *A wipe helper in
  another translation unit*; `../../gcc-repair/README.md`, the xtu cells): the
  LTO link inlines the helper and the fill is a dead store, and the pin made at
  the helper's compile keeps it.
- **`-shared`, and nothing after the LTO backend.** Exported symbols stay
  exported, so the target function is never internalized or deleted as unused.
  An executable link (which internalizes everything but what is exported) or
  `-fvisibility=hidden` could inline or drop the target entirely; not measured.
  `--lto-emit-asm` stops before anything is assembled or linked: no shared object
  was produced, and nothing a real link would do afterwards (relocation checks,
  `--gc-sections`, `--icf`) is in the measurement.
- **One vendor, one version, one linker.** `clang-18` and `lld` 18.1.3 on
  x86-64. Not the gold plugin, not `ld.bfd`, not another LLVM version, not gcc's
  LTO (no LLVM plugin loads there at all; gcc-13's is measured with WipePinGcc
  by `lto-probe-gcc.mjs`, *gcc-13* below).
- **The same level on both lines.** Compile and link always used the same `-O`.
  A mismatch (an `-O0` object in an `-O2` LTO link, say) is not measured.
- **The cell verdict only.** The per-span view of `../README.md` was not run
  under LTO; a cell that reads `WIPE_SURVIVED` can hide an eliminated span there
  as it can without LTO.
- **Three record fields.** A requested name that did not resolve would not be
  seen by this probe (the repair loop's reader sees it).
- **Only erasure files of the `removable` idiom.** Runs A–E link the 113 the
  find step scored eliminated at `-O2`; at `-O1`, `-O3` and `-Os` the selection
  is the same 113 files (all of them at `-O1`, 10 at `-O3`/`-Os`). Run F adds the
  20 removable-idiom files whose wipe survives without LTO, at `-O2` only: the
  LTO link removed none of those wipes. Whether it would at another level, or
  in a file of the nonremovable or `both` idiom, was not measured.
- **Not that the code is secure**, and not that a link-time pin is the right fix:
  every caveat in `../README.md` ("What this does not claim") carries over.

## gcc-13: `lto-probe-gcc.mjs`

`compiler/gcc-repair/README.md` ("Other forms") showed on one fixture, the
trailing shape at `-O2`, that the barrier WipePinGcc puts in at compile time
travels in the object's GIMPLE through an `-flto -shared` link, and that
WipePinGcc on the link line refuses inside lto1. `lto-probe-gcc.mjs` asks the
same of the r2 corpus, with the find step's own verdict, on the assembly lto1
writes.

**Answer, for what was run** (`gcc-13` 13.3.0, GNU ld 2.42 through gcc's LTO
linker plugin, x86-64, one object per link, `-shared`, gcc's default
partitioning): every wipe the stock LTO build loses comes back when WipePinGcc
is loaded at compile time — 108/108 at each of `-O1`, `-O2`, `-O3` and `-Os`,
the same 108 files the tracked non-LTO rows score eliminated at every one of
those levels, and in every cell the LTO baseline equals the tracked non-LTO
verdict. The build loses those wipes before the link, not in it: in all 108
cells at every level, the object cc1 writes (its GIMPLE, read back with
`lto-dump-13`) holds no zero-fill memset in the target function, so lto1 never
sees the wipe, while the plugin-on object holds the memset and its barrier.
Over every removable-idiom file at `-O2` (133), the 25 wipes that do reach the
link, a memset in the object, still survive it. So in no cell here does the
LTO link eliminate a wipe: the runs show a pin made at compile time carried
through gcc's LTO link, not the pin holding against an elimination the link
itself performs (clang's `-O1` cells, above, are that test; no gcc cell here
is). Loaded only on the link line, WipePinGcc is refused by lto1 twice per
link, leaves nothing at `WPIN_OUT`, and the link's assembly and shared object
are byte-identical to the stock link's, in all 1,130 such links.

### What is measured, gcc

The cell is the clang probe's, built with gcc's tools. For each selected file
and level, the two units — `w`, the file as written plus the positive control,
and `wo`, the same with every wipe span deleted by the imported `ablateSpans` —
are compiled three times each:

| config | compile | link |
|---|---|---|
| off | stock | stock |
| on | `-fplugin=<so>`, `WPIN_OUT=<d>/record.json`, `WPIN_TARGET_FNS=<fn>,<helpers>` | stock |
| dry | as *on*, plus `WPIN_DRY_RUN=1` | stock |

- **Selection, per level**, from the tracked gcc-13 repair rows
  (`../data/r2-repair-rows-gcc-13.json`): the erasure files whose baseline is
  `WIPE_ELIMINATED` at that level — 108 at each of `-O1` to `-Os`, the same 108
  files at every level — or, with `--all-removable`, every file of the
  `removable` idiom there (133 at `-O2`). Each selected row's `requested` must be
  the `[fn, ...helpers]` this tree's `wipeSpans` gives (exit 5 otherwise).
- **Compile**: the find step's `FLAGS` with `-S` replaced by `-c` and `-flto`
  appended (`gccCompileFlags`, which is `lib/lto.mjs`'s rewrite, refusals
  included). Nothing else, and in particular not `-fPIC`, although every link
  is `-shared`: this gcc-13 defaults to `-fPIE` (`--enable-default-pie`), the
  object's `.gnu.lto_.opts` section lists `-fPIC` for such a compile, and
  lto-wrapper passes that to both lto1 runs (table below). Every link of a
  corpus unit in the runs below exited 0.
- **Link**: each object alone, in its own directory, and the link runs there:
  `gcc-13 <opt> -flto -shared -save-temps -o <d>/<tag>.so <d>/u.o`. The link
  runs to the end; `-save-temps` keeps what lto1 wrote, and the probe reads the
  one partition's assembly, `<tag>.so.ltrans0.ltrans.s`. `verdictOf`, `bodyOf`
  and `controlPresent`, imported, judge it, as in the clang probe.
- **(i) plugin at compile time, stock link.** The outcome is the repair loop's
  own `outcomeOf` (`../lib/outcome.mjs`), unchanged, with `NOT_LTO` in front
  (`gccLtoOutcome`). Every record is read through `../lib/pin-record.mjs`, told
  the component is `WipePinGcc` and given the compile's scope, dry-run flag,
  level, module and requested names; a record that fails any of it is refused,
  and a refused record makes the cell `BROKEN_REPAIR`, as in the repair loop.
  Here the gcc probe differs from the clang probe, which reads three fields on
  its own (*What the records are read for*, above).
- **(ii) plugin only on the link line** (`-fplugin=<so>` on the link line,
  `WPIN_OUT` and `WPIN_TARGET_FNS` in the link's environment, a sentinel file at
  `WPIN_OUT`). WipePinGcc refuses to install in lto1 (`plugin_init` in
  `compiler/gcc-repair/src/WipePinGcc.cpp`), after its stale-record rule has
  removed whatever was at `WPIN_OUT`. Graded (`gradeLinkPluginGcc`): `HELD` when
  every such link exited 0; printed the refusal exactly twice — lto1 runs twice
  for one object, the whole-program analysis and then the one partition — and
  otherwise exactly what the stock link of the same object printed; removed the
  sentinel and wrote no record; wrote the eleven files below; and produced an
  assembly and a shared object byte-identical to the stock link's. Otherwise
  `FAILED`, and the run exits 2.
- **(iii) dry run.** Graded as in the clang probe (`gradeDryRun`, imported), with
  both dry-run records read through `pin-record.mjs`: component `WipePinGcc`,
  `dryRun: true`, `pinnedCount: 0`. Also reported: the dry-run link's assembly
  and shared object against the plugin-off link's. The objects themselves are
  never compared: gcc names its LTO sections with a suffix that changes per
  compile (table below).
- **Determinism.** All six objects of a cell are linked a second time, and the
  assembly and the shared object must both be byte-identical.
- **The compile's plugin stays in the compile.** A plugin-on object's
  `.gnu.lto_.opts` section names the plugin; lto-wrapper does not pass it on.
  Every stock link's stderr is read for a `WipePinGcc:` line, and one is a
  violation (exit 2).
- **Against the tracked rows.** Each LTO baseline is compared with the tracked
  gcc-13 row's baseline for the same `(id, level)`, and every difference is
  listed by id; with `--all-removable`, a wipe the tracked row saw survive and
  the LTO build removes is listed again as an added elimination (whether in the
  compile or in the link, the GIMPLE reading below says). A difference is
  allowed; it must be visible.
- **Where the loss happens.** Where the clang probe reads the compile-stage
  bitcode with `llvm-dis-18`, this one reads the compile-stage GIMPLE — what
  cc1 streamed into the object's `.gnu.lto_` sections, the code lto1 starts
  from — with `lto-dump-13 -dump-body=<fn>`, for the `w/off`, `wo/off` and
  `w/on` objects, after the cell's links. It counts the zero-fill memset calls
  in the requested functions, `pinned` when the next statement is WipePinGcc's
  barrier naming the same destination and `plain` otherwise, and calls to a
  named helper (`zeroMemsetsInGimple` in `lib/lto-gcc.mjs`). `w/off` still
  carries the wipe to the link when it holds more of these than `wo/off`; a wipe
  the compile stage already removed never reaches lto1. A reading counts only
  when the same object's positive control, `vgctl_control`, reads as exactly
  one plain zero-fill memset (`gimpleControlOk`); a cell whose objects do not is
  listed as unread. Reported, not graded, as in the clang probe; left out when
  the tool cannot be started (`--lto-dump`, default `lto-dump-13`).

### Guards, gcc

- **A gcc LTO object.** Every object must be an ELF file with at least one
  section named `.gnu.lto_…`, read from its section table (`elfSections`,
  `gccObjectKind` in `lib/lto-gcc.mjs`). A plain ELF object, LLVM bitcode, an
  ELF file whose section table cannot be read, or an empty file makes the cell
  `NOT_LTO`, ahead of every other outcome, and the run exits 2.
- **The eleven files.** Each object sits alone in its directory with every
  link's `-o` beside it, and every stock link must write exactly the eleven files
  a one-partition link writes, nothing more and nothing missing; anything else
  makes the cell `NOT_LTO`. The names also say how lto1 ran: an object without
  `.gnu.lto_` sections leaves the shared object alone, `-flto-partition=none`
  writes seven other names, a second partition an `ltrans1` set.
- **Preflight, per level, before any cell.** A small unit (a memset plus the
  positive control) is compiled `-flto`. It must be a gcc LTO object; its stock
  link must write the eleven files and give an assembly cut by `bodyOf` with the
  positive control `PRESENT`; and the plugin on its link line must read as (ii)
  requires. The plugin must load into an `-flto` compile and write a record that
  `pin-record.mjs` accepts and that pinned something; a stock link of that
  object must not load the plugin (no `WipePinGcc` line, and a sentinel at
  `WPIN_OUT` kept); and the sentinel must also survive a stock link and a link
  naming a plugin file that does not exist. When `lto-dump-13` can be started,
  it must read the unit's memset, which writes through a parameter and so
  reaches the object, as one plain zero-fill memset in the plugin-off object and
  one pinned in the plugin-on object, with both controls read. Any failure exits
  5: a reader that reads nothing would report every wipe gone before the link.
- **Records through `pin-record.mjs` only**, with component `WipePinGcc`.
- **Nothing inherited, lab only.** As in the clang probe: every `WPIN_*`
  variable is removed before the first compile, record paths and cell
  directories are deleted before they are used, `--out` inside the repository
  and `--write-data` exit 4, and the rows, results and manifest are scanned for
  absolute paths (the count is the results' last line; a hit exits 5). A `--cc`
  whose basename does not name gcc exits 4, and one the tracked rows do not hold
  exits 5 (`../lib/vendor.mjs`).

### gcc-13 13.3.0 behaviour the probe relies on (measured)

`<o>` is the basename of the link's `-o`; `<s>` a section-name suffix.

| what | measured |
|---|---|
| `-flto -c` | an ELF object whose section table, after the null entry, holds `.text`, `.data` and `.bss`, all of size 0 (a slim object: no machine code); the `.gnu.lto_` sections `.profile.<s>`, `.icf.<s>` and `.ipa_sra.<s>` (these two not at `-O1`), `.inline.<s>`, `.jmpfuncs.<s>`, `.pureconst.<s>`, `.ipa_modref.<s>`, `.lto.<s>`, one `.gnu.lto_<function>.<n>.<s>` per function, `.symbol_nodes.<s>`, `.refs.<s>`, `.decls.<s>`, `.symtab.<s>`, `.ext_symtab.<s>` and `.opts`; then `.comment`, `.note.GNU-stack`, `.symtab`, `.strtab`, `.shstrtab`. For the preflight unit: 25 entries at `-O2`, `-O3` and `-Os`, 23 at `-O1`, read with `readelf -SW` and, entry for entry the same, with the probe's `elfSections` |
| the suffix `<s>` | up to 16 hex digits, a 64-bit id printed without leading zeros (over the 11,330 suffixed objects of two runs of this probe, A and B: 16 digits in 10,632, 15 in 654, 14 in 42, 13 in 2), one per object, carried by every suffixed name (15 of them for the preflight unit at `-O2`, 13 at `-O1`), and new in every compile: three `-O2` compiles of the preflight unit gave three suffixes of the same length and three objects of one size that are byte-identical once the suffix is replaced by a fixed string |
| `.gnu.lto_.opts` | for a compile at the default: `'-fno-openmp' '-fno-openacc' '-fPIC' '-mtune=generic' '-march=x86-64' '-O2' '-Wno-error=implicit-function-declaration' '-w' '-fcf-protection=none' '-flto' '-fasynchronous-unwind-tables' '-fstack-protector-strong' '-fstack-clash-protection'` — `-fPIC`, although no `-fPIC` was given and the default is `-fPIE` (`gcc-13 -v`: `--enable-default-pie`). With the plugin loaded, also `-fplugin=<path>` and, twice, `-iplugindir=<gcc's plugin directory>` |
| `-flto -shared -save-temps`, one object | eleven files, all next to `-o`: `<o>` (the shared object), `<o>.lto_wrapper_args`, `<o>.ltrans.out`, `<o>.ltrans0.ltrans.args.0`, `<o>.ltrans0.ltrans.o`, `<o>.ltrans0.ltrans.s` (the assembly the probe reads), `<o>.ltrans0.ltrans_args`, `<o>.ltrans0.o`, `<o>.ltrans_args`, `<o>.res`, `<o>.wpa.args.0`; the same at `-O1`, `-O2`, `-O3` and `-Os` |
| the working directory | with plain `-save-temps`, a link run in another directory wrote the same eleven next to `-o` and nothing in the working directory. `-save-temps=obj` run from another directory kept nine of them (no `.lto_wrapper_args`, no `.ltrans0.ltrans.o`). The probe uses plain `-save-temps` and runs each link in its object's directory |
| lto1's two runs | `<o>.ltrans_args` holds the whole-program run's arguments (`-fwpa`, `-fresolution=<o>.res`, `-flinker-output=dyn`), `<o>.ltrans0.ltrans_args` the partition's (`-fltrans`); both carry the object's `-fPIC`, and neither `-fPIE` |
| `-flto-partition=none` | seven files: `<o>`, `<o>.lto.o`, `<o>.lto.o.args.0`, `<o>.lto.o.s`, `<o>.lto_wrapper_args`, `<o>.ltrans_args`, `<o>.res`. lto1 runs once, and WipePinGcc on that link line is refused once |
| WipePinGcc on the link line | exit 0; `WipePinGcc: refusing to install: loaded into the LTO back end, where this pass does not run; load it into the compile step instead` twice; the file at `WPIN_OUT` removed; assembly and shared object byte-identical to the stock link's |
| the compile's `-fplugin` | named in the object's `.gnu.lto_.opts`, and not passed to lto1: a stock link of a plugin-on object prints nothing and leaves a sentinel at `WPIN_OUT` |
| a plugin file that does not exist, on the link line | exit 1; stderr `lto1: error: cannot load plugin <path>: <path>: cannot open shared object file: No such file or directory`, then `lto-wrapper: fatal error: gcc-13 returned 1 exit status`, `compilation terminated.`, `/usr/bin/ld: error: lto-wrapper failed`, `collect2: error: ld returned 1 exit status`; the sentinel at `WPIN_OUT` kept |
| an object without `.gnu.lto_` sections, the same link line | exit 0, and the shared object is the only file written: lto1 never runs |
| the assembly | begins `.file "<artificial>"` and names no path; the same object linked twice gave byte-identical assembly and shared objects, under a different `-o` name too |
| `lto-dump-13 -dump-body=<fn> <obj>` | the function's GIMPLE, as cc1 streamed it, on **stderr**, and `GIMPLE body of function: <fn>` on stdout; exit 0. A name the object does not define (a declaration such as `kdf`) prints `lto-dump-13: error: Function not found.` and exits 0, and so does every name in an object without `.gnu.lto_` sections; a file it cannot open exits 1. Without `-o` it also writes an empty `<object stem>.s` beside the object; with `-o /dev/null`, as the probe runs it, it writes nothing |
| a pinned site in that GIMPLE | `__builtin_memset (&key, 0, 32);` followed by `__asm__ __volatile__("" :  : "g" &key : "memory");` (`encrypt_blob`, `fable_N_aeskey_r1`, `-O2`, the `w/on` object); the positive control `vgctl_control` reads as its one `__builtin_memset (&vgctl_secret, 0, 32);`, not pinned, plugin on or off |

### Commands, gcc

Build the plugin from this tree, outside it:

```sh
CXX=g++-13 cmake -S compiler/gcc-repair -B <build>/gcc-repair -G Ninja
ninja -C <build>/gcc-repair      # libWipePinGcc.so, sha256 a023b047…7ba1b
```

What one cell runs (`<d>` is the object's own directory under the lab, and
every link runs in it):

```sh
# compile (off; on adds -fplugin=<so> and WPIN_OUT=<d>/record.json
#          WPIN_TARGET_FNS=<fn>,<helpers>; dry adds WPIN_DRY_RUN=1)
gcc-13 -c -std=gnu11 -w -Wno-error=implicit-function-declaration \
       -fcf-protection=none -flto <opt> -o <d>/u.o <id>.w.c

# stock link: the assembly is <d>/stock1.so.ltrans0.ltrans.s
gcc-13 <opt> -flto -shared -save-temps -o <d>/stock1.so <d>/u.o

# (ii): the stock link line of the off object plus
#   -fplugin=<so>   with WPIN_OUT=<sentinel> WPIN_TARGET_FNS=... in the environment

# where the loss happens, after the links, for w/off, wo/off and w/on: the
# requested functions and the positive control, one name per run
lto-dump-13 -dump-body=<fn> <d>/u.o -o /dev/null
lto-dump-13 -dump-body=vgctl_control <d>/u.o -o /dev/null
```

The runs whose numbers are below (the lab directories are outside the
repository; the probe refuses anything else):

```sh
P=compiler/eval/repair-loop/tools/lto-probe-gcc.mjs
SO=<build>/gcc-repair/libWipePinGcc.so
node $P --plugin $SO --out <lab>/A --opts -O1,-O2,-O3,-Os --conc 2   # the 108 eliminated files, four levels
node $P --plugin $SO --out <lab>/B --opts -O2 --all-removable --conc 2   # the 133 removable-idiom files
```

Options: `--opts` (default `-O2`), `--all-removable`, `--files` (basenames or
globs within the selection), `--sample <n>` (n files spread evenly over each
level's selection), `--conc` (default 2), `--cc` (default `gcc-13`), `--rows`
(default the tracked gcc-13 repair rows), `--lto-dump` (default `lto-dump-13`).
Unit tests for the pure parts (`lib/lto-gcc.mjs`), no compiler needed:

```sh
node --test compiler/eval/repair-loop/test/lto-probe-gcc.test.mjs
```

Exit codes: `0` complete and every integrity check held · `2` complete, but a
cell was `NOT_LTO`, a relink was not byte-identical, the dry-run red control
did not hold or was vacuous, configuration (ii) was `FAILED`, or WipePinGcc
printed on a stock
link · `3` nothing selected · `4` bad arguments, a `--cc` that is not gcc,
`--out` inside the repository, or `--write-data` · `5` a tool, the plugin, the
tracked rows or the shared verdict module could not be used (a tracked row
whose requested names differ from this tree's find step included), the
preflight failed, or a lab text carried an absolute path.

### Results, gcc

`gcc-13` 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1), GNU ld (GNU Binutils for
Ubuntu) 2.42, WSL Ubuntu 24.04, x86-64, Node 18.19.1; `libWipePinGcc.so` built
from `compiler/gcc-repair/` with g++-13, sha256
`a023b047abcafdbb824f627d227861e0ae0556072c9e4ba87e102b2c9747ba1b`, the build
the tracked gcc-13 results quote; the GIMPLE read with `lto-dump-13`, which
Ubuntu ships with gcc-13. The preflight passed at every level, and both runs
exited 0: run A in 521 s, run B in 154 s, on 2 parallel cells while other work
shared the machine. An earlier pair of the same runs, with code identical but
for the wording of one results line, wrote byte-identical rows files.

| run | level | cells | eliminated without the plugin (LTO) | differs from the tracked non-LTO row | `RETAINED` | `ALREADY_SURVIVED` | other outcomes | dry run (iii) | (ii) links | (ii) refusals, each link | (ii) sentinel removed / record written | (ii) assembly / shared object equal to the stock link | (ii) graded | relink comparisons identical |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A | `-O1` | 108 | 108 | 0 | **108** | 0 | 0 | `HELD` 108/108 | 216 | 2 | 216 / 0 | 216 / 216 | `HELD` | 1296/1296 |
| A | `-O2` | 108 | 108 | 0 | **108** | 0 | 0 | `HELD` 108/108 | 216 | 2 | 216 / 0 | 216 / 216 | `HELD` | 1296/1296 |
| A | `-O3` | 108 | 108 | 0 | **108** | 0 | 0 | `HELD` 108/108 | 216 | 2 | 216 / 0 | 216 / 216 | `HELD` | 1296/1296 |
| A | `-Os` | 108 | 108 | 0 | **108** | 0 | 0 | `HELD` 108/108 | 216 | 2 | 216 / 0 | 216 / 216 | `HELD` | 1296/1296 |
| B | `-O2`, `--all-removable` | 133 | 108 | 0 | **108** | 25 | 0 | `HELD` 108/108 | 266 | 2 | 266 / 0 | 266 / 266 | `HELD` | 1596/1596 |

- **The find step's verdict does not move under gcc's LTO** in anything run
  here: 0 differences at every level. In run B the 25 removable-idiom files
  whose wipe survives without LTO at `-O2` survive the LTO link as well (0
  added eliminations), and stay `ALREADY_SURVIVED` with the plugin.
- **Where the loss happens: in the compile, not the link.** In every cell the
  request names the target function alone (no helper), so the reading is of
  the target. In all 108 eliminated cells at every level, the `w/off` object
  holds no zero-fill memset there, as `wo/off` holds none, so it carries
  nothing to the link that the ablated unit does not; and the `w/on` object
  holds a pinned memset in all 108 — in every cell exactly as many as the `w`
  record's `pinnedCount` (146 per level). In run B the `w/off` object of each
  of the 25 survived cells carries the wipe, one to three zero-fill memsets
  that `wo/off` lacks, and the cell still reads `WIPE_SURVIVED` after the link.
  No cell was unread. Which compile pass removes it, from a one-off outside the
  probe: the plugin-off `w` and `wo` units of run A's cells, compiled as the
  probe compiles them plus `-fdump-tree-dse1-details`, give a dump that reports
  `Deleted dead call: … memset (…, 0, …)` in the target for all 108 `w` units
  and none of the `wo` units, at each of the four levels — cc1's first
  dead-store elimination, `dse1`, in the compile itself.
- **(i)** No `NOT_LTO`, `BROKEN_REPAIR`, `PIN_INEFFECTIVE`, `PIN_NOT_APPLIED`,
  `SURVIVED_WITHOUT_PIN`, `REGRESSED` or `NOT_SCORED` cell. `pin-record.mjs`
  accepted every record (`w`, `wo` and both dry-run records, in every cell); the
  positive control was `PRESENT` in every plugin-on link; and the `w` records of
  the 108 cells of each level pinned 146 sites in all, the total the tracked
  non-LTO rows give for the same cells.
- **(ii)** In each of the 1,130 links (864 in A, 266 in B): exit 0, the refusal
  exactly twice, the sentinel at `WPIN_OUT` removed and no record written, no
  other stderr (the stock links printed none either), the eleven files, and an
  assembly and a shared object byte-identical to the stock link of the same
  object. The verdict of (ii) equals the baseline in every cell.
- **(iii)** `HELD` at every level. Every dry-run link gave the plugin-off link's
  assembly and shared object byte for byte (216/216 per level in A, 266/266 in
  B).
- **Determinism**: every object was linked twice — 648 relinks per level in A,
  798 in B — and each relink's assembly and shared object were byte-identical to
  the first link's (the table counts the two comparisons of every relink).
- **Stock links**: none of the 5,184 in A or the 1,596 in B printed anything,
  so no `WipePinGcc` line: the compile's `-fplugin`, named in every plugin-on
  object's options section, never reached lto1.
- No target body differed from its counterpart only in `.L<n>` label names,
  in either the baseline or the repaired pair.

### Shown to fail, gcc

Each through a `gcc-13` or `lto-dump-13` wrapper generated into the lab (not in
this tree), 2 files (`--sample 2`), `-O2`:

- a wrapper that drops `-flto` from the compiles of the corpus units (not from
  the preflight unit): both cells `NOT_LTO` (`w.off object is elf; w.on object is
  elf; …` for all six objects), the dry-run control and (ii) `FAILED` as vacuous,
  exit **2**;
- a wrapper that adds `-flto-partition=none` to every link carrying `-fplugin`,
  except the preflight's: (ii) `FAILED`, with three violations in each of the
  four links — `the LTO refusal printed 1 time(s), expected 2`, the
  `partition-none` layout, and no assembly to compare (the shared objects were
  byte-identical to the stock links') — and everything else as in run A
  (`RETAINED` 2/2, dry run `HELD`, 24/24 relink comparisons), exit **2**. The same
  wrapper without the preflight's exception stops the run in the preflight,
  exit **5** (`refusals 1, … layout partition-none`);
- a wrapper that, after each plugin-on compile of a corpus unit, replaces the
  record at `WPIN_OUT` with the one WipePin writes for the same unit and the
  same `WPIN_*` environment under `clang-18` — a genuine, sealed `wipe-pin-v2`
  record whose component is `WipePin`: both cells `BROKEN_REPAIR`
  (`record-w: wrong-compile: component WipePin, this compile loaded WipePinGcc`),
  the dry-run control `FAILED` on the same refusal, exit **2**. `lib/lto.mjs`'s
  three-field reader accepts all 8 of those records; `pin-record.mjs` refuses
  all 8, each for that one reason;
- a wrapper that removes `WPIN_DRY_RUN` from the compile's environment: the dry
  run reads `WIPE_SURVIVED` in both cells and all four dry-run records are
  refused (`wrong-compile: dryRun false, this compile asked for true`), exit **2**;
- an `lto-dump-13` that reads nothing — every `-dump-body` answers `Function
  not found.` and exits 0, which is what lto-dump-13 itself answers for any
  name in an object without `.gnu.lto_` sections: the preflight stops the run,
  exit **5** (`the positive control read not-defined`). Without that check it
  would have read every cell as "holds no zero-fill memset". The same reader
  switched on only after the preflight: both cells are listed `UNREAD` and are
  counted neither as holding nor as carrying anything; the column is reported,
  not graded, so that run exits **0**;
- `--out` inside the repository: exit **4**, nothing created; `--write-data`:
  exit **4**; `--cc clang-18`: exit **4**; `--cc gcc`, a spelling the tracked
  rows (which say `gcc-13`) do not hold: exit **5**, nothing created.

### What this does not claim, gcc

- **One translation unit per link, `-shared`.** As for clang: no cross-unit
  inlining in this probe, and exported symbols stay exported; an executable link,
  `-fvisibility=hidden` or `-fwhole-program` could inline or drop the target and
  is not measured. Unlike the clang probe, the link runs to the end and the
  shared object is compared too; nothing about loading or running it is. The
  helper-in-another-unit case is measured on a generated fixture by the gcc
  fixture loop's `xtu` cells (`../../gcc-repair/README.md`), in an executable
  link.
- **One compiler, one version, one linker.** `gcc-13` 13.3.0 (Ubuntu) with GNU
  ld 2.42 through gcc's linker plugin, on x86-64. Not gold, not lld or mold under
  gcc, not another gcc, not `-ffat-lto-objects`, not `-flto=<n>` or
  `-flto=auto` (every link here says plain `-flto`), and not a partitioning
  other than gcc's default, which gave one partition in every link here.
- **The same level on both lines**, as for clang.
- **The cell verdict only.** The per-span view of `../README.md` was not run
  under LTO: in a cell that still reads `WIPE_SURVIVED` after the link, a
  memset the link removed beside one it kept would not show (3 of run B's 25
  survived cells carry two or three memsets into the link).
- **Not the pin against an elimination the LTO link performs, over this corpus.**
  Every stock wipe the LTO build loses here is gone before the link, and every
  wipe that reaches the link still reads `WIPE_SURVIVED` after it, so no corpus
  cell tests the barrier against an elimination lto1 makes; clang's `-O1` cells
  are that test for the volatile memset. For gcc that test is the fixture loop's
  `xtu` cells (`../../gcc-repair/README.md`) rather than a corpus cell: there the
  link inlines a helper from another unit, the stock build loses the fill, and
  the barrier made at the helper's compile keeps it. Over this corpus, whether
  gcc's link would remove a wipe it receives is not measured.
- **Only files of the `removable` idiom.** The eliminated files are all of that
  idiom; the nonremovable and `both` idioms were not linked, at any level.
- **Not that the code is secure**, and not that a link-time pin is the right fix:
  every caveat in `../README.md` ("What this does not claim") carries over.

## Files

| path | what |
|---|---|
| `lto-probe.mjs` | the runner: preflight, the cells, configurations (i)–(iii), determinism, results; lab output only |
| `lib/lto.mjs` | the pure parts: flags, link lines, object kind, lld's output names, the three-field record reader, the outcome, the dry-run grade, the sentinel reading, the link-time line and the (ii) grade, the IR memset count, the selection (both probes'), the summary |
| `../test/lto-probe.test.mjs` | unit tests for `lib/lto.mjs`, no compiler |
| `lto-probe-gcc.mjs` | the gcc-13 runner: preflight, the cells, configurations (i)–(iii), determinism, results; lab output only |
| `lib/lto-gcc.mjs` | its pure parts: the compile and link lines, the ELF section reader and the object kind, gcc's output names and layouts, the lto1 refusal and the (ii) grade, the outcome (the repair loop's `outcomeOf` behind `NOT_LTO`), the GIMPLE reading (lto-dump's output, the zero-fill memsets in it, the positive control), the selection, the summary |
| `../test/lto-probe-gcc.test.mjs` | unit tests for `lib/lto-gcc.mjs`, no compiler |
| `LTO.md` | this file |
