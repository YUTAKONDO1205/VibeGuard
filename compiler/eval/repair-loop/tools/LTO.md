# The LTO probe

`compiler/llvm-repair/README.md` ("Other forms") left one question open: a
`-flto` or `-flto=thin` compile with WipePin loaded writes a record, and the
bitcode carries the volatile memset — but what the LTO backend then does with it
was never measured. `lto-probe.mjs` measures it, with the find step's own
verdict, on the assembly the LTO backend writes.

**Answer, for what was run** (`clang-18` / `lld` 18.1.3, x86-64, one object per
link, `-shared`): every wipe the stock LTO build loses comes back when WipePin is
loaded at compile time — 113/113 at `-O2` under full and under thin LTO, 62/62 at
`-O1` under both, 10/10 at `-O3` and at `-Os` under both on a sample of 10 files.
Loaded only on the link line, WipePin is loaded but its pass never runs: no
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
```

Options: `--modes full,thin` (default both), `--opts` (default `-O2`), `--files`
(basenames or globs within the selection), `--sample <n>` (n files spread evenly
over the sorted selection), `--conc` (default 4), `--force-fallback`, `--cc`,
`--llc`, `--llvm-dis`, `--rows`. The selection itself is fixed: the `clang-18`
erasure files the tracked rows (`../../ai-generated/data/r2-build-rows.json`)
score `WIPE_ELIMINATED` at `-O2` — 113 files, all of the `removable` idiom.

Unit tests for the pure parts (`lib/lto.mjs`), no compiler needed:

```sh
node --test compiler/eval/repair-loop/test/lto-probe.test.mjs
```

Exit codes: `0` complete and every integrity check held · `2` complete, but a
cell was `NOT_LTO`, a relink was not byte-identical, the dry-run red control
did not hold, or configuration (ii) was `FAILED` · `3` nothing selected · `4` bad arguments, `--out` inside the
repository, or `--write-data` · `5` a tool, the plugin or the shared verdict
module could not be used, the preflight failed, or a lab text carried an
absolute path.

## Results

`clang-18` 18.1.3 (Ubuntu), `Ubuntu LLD 18.1.3`, WSL Ubuntu 24.04, x86-64;
`libWipePin.so` built from `compiler/llvm-repair/`. Runs A–D were made with the
`wipe-pin-v1` build, sha256
`aa7329c3d9ba002915f885624c17d6da1418aa39a2b762d1655e83786e6f0a66`, which emits
the same code as v2 (`compiler/llvm-repair/README.md`, *`wipe-pin-v2`*,
"Same code as `v1`");
run E, below, with `db3298cfb30d14200fe0822261eaa1c35aa51aed4aef869a0edd3151f073a4c8`,
the build the repair loop's tracked results now quote. Post-LTO code read
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
  cross-unit inlining: a wipe helper defined in another unit and inlined at link
  time, or a target inlined into a caller from another unit, is not measured. The
  wipe and its target are always in the same module here.
- **`-shared`, and nothing after the LTO backend.** Exported symbols stay
  exported, so the target function is never internalized or deleted as unused.
  An executable link (which internalizes everything but what is exported) or
  `-fvisibility=hidden` could inline or drop the target entirely; not measured.
  `--lto-emit-asm` stops before anything is assembled or linked: no shared object
  was produced, and nothing a real link would do afterwards (relocation checks,
  `--gc-sections`, `--icf`) is in the measurement.
- **One vendor, one version, one linker.** `clang-18` and `lld` 18.1.3 on
  x86-64. Not the gold plugin, not `ld.bfd`, not another LLVM version, not gcc's
  LTO (no LLVM plugin loads there at all).
- **The same level on both lines.** Compile and link always used the same `-O`.
  A mismatch (an `-O0` object in an `-O2` LTO link, say) is not measured.
- **The cell verdict only.** The per-span view of `../README.md` was not run
  under LTO; a cell that reads `WIPE_SURVIVED` can hide an eliminated span there
  as it can without LTO.
- **Three record fields.** A requested name that did not resolve would not be
  seen by this probe (the repair loop's reader sees it).
- **Only erasure files the find step scored eliminated at `-O2`.** Files whose
  wipe survives without LTO at `-O2` were not compiled under LTO; whether the LTO
  backend removes any of *those* wipes (an elimination LTO adds) is not answered
  here. At `-O1`, `-O3` and `-Os` the selection is the same 113 files (all of
  them at `-O1`, 10 at `-O3`/`-Os`).
- **Not that the code is secure**, and not that a link-time pin is the right fix:
  every caveat in `../README.md` ("What this does not claim") carries over.

## Files

| path | what |
|---|---|
| `lto-probe.mjs` | the runner: preflight, the cells, configurations (i)–(iii), determinism, results; lab output only |
| `lib/lto.mjs` | the pure parts: flags, link lines, object kind, lld's output names, the three-field record reader, the outcome, the dry-run grade, the sentinel reading, the link-time line and the (ii) grade, the IR memset count, the summary |
| `../test/lto-probe.test.mjs` | unit tests for `lib/lto.mjs`, no compiler |
| `LTO.md` | this file |
