# What this toolchain will and will not tell you

Measured on clang/lld 18.1.3 under Ubuntu 24.04, before the components that
depend on the answers were written. Four of the guesses a reasonable implementer
would make about these flags are false on this toolchain, and each one produces
a checker that reports success while checking nothing -- so the measurements are
kept rather than the conclusions alone.

Paths have been replaced with placeholders: what is being recorded is a property
of the compiler version, not of the machine it was run on. Raw captures stay on
the measurement side, per the rule in this directory README.


All numbers below were produced by running the commands shown, on this box, on 2026-08-07.
Nothing here is inferred from documentation unless explicitly labelled **INFERENCE**.

## Environment (measured)

```
$ clang-18 --version        -> Ubuntu clang version 18.1.3 (1ubuntu1), x86_64-pc-linux-gnu
$ ld.lld-18 --version       -> Ubuntu LLD 18.1.3 (compatible with GNU linkers)
$ readelf --version         -> GNU readelf (GNU Binutils for Ubuntu) 2.42
$ llvm-readelf-18 --version -> Ubuntu LLVM version 18.1.3, Optimized build
$ llvm-config-18 --version  -> 18.1.3
$ cmake --version           -> 3.28.3 ; ninja --version -> 1.11.1 ; nproc -> 12
WSL Ubuntu-24.04, HOME=<home>
```

Layout used:
- fixtures + scripts + report: `~/vg-lab/probes/`
- raw tool output: `~/vg-lab/probes/raw/` (61 files)
- all commands + exit codes: `~/vg-lab/probes/run-log.txt`
- build scratch (not a deliverable): `~/vg-build/probes/{q1,q2,q4,plugin}`

Reusable artifacts written:
- `~/vg-lab/probes/hardening.py` — structural ELF hardening extractor (pure `struct` reads)
- `~/vg-lab/probes/crosscheck.py` — validates the above against `llvm-readobj-18` JSON
- `~/vg-lab/probes/initarray_join.sh` — resolves `.init_array` slot -> object -> ctor symbol
- `~/vg-lab/probes/Observer.cpp` — minimal observer pass plugin (builds without cmake)

---

# 問い1: リンカからどこまで取れるか

## 1.1 `-Wl,-Map=<file>` の内容

Command:

```bash
cd ~/vg-build/probes/q1
clang-18 -fuse-ld=lld -o app a.o -L. -larch -lmine -Wl,-rpath,. -Wl,-Map=map_clang_lld.txt
```

Raw: `~/vg-lab/probes/raw/q1_map_clang_lld.txt` (8418 B). Format is a 7-column table:

```
             VMA              LMA     Size Align Out     In      Symbol
             2a8              2a8       1c     1 .interp
             2a8              2a8       1c     1         <internal>:(.interp)
            17a0             17a0      1d0    16 .text
            17a0             17a0       26    16         /lib/x86_64-linux-gnu/Scrt1.o:(.text)
            17a0             17a0       26     1                 _start
            1890             1890       b0    16         a.o:(.text)
            1890             1890       12     1                 ctor_a
            18b0             18b0       23     1                 copy_it
            18e0             18e0       60     1                 main
            1940             1940       30    16         ./libarch.a(b_arch.o):(.text)
            1940             1940       12     1                 ctor_b
            1960             1960       10     1                 helper
```

Verdict per requested item:

| item | from Map? | evidence |
|---|---|---|
| object | **YES** | `a.o:(.text)`, `/lib/x86_64-linux-gnu/Scrt1.o:(.text)` |
| archive member | **YES**, `archive(member)` form | `./libarch.a(b_arch.o):(.text)` |
| shared library | **NO** | `grep "\.so\|libmine" map_clang_lld.txt` -> no match, although `libmine.so` was linked and `libfn` resolved to it |
| section | **YES** | out-sections (`.text`) and in-sections (`obj:(.text)`), with VMA/LMA/Size/Align |
| symbol resolution | **PARTIAL** | Map lists *defined* symbols with addresses. It does **not** say which file a *reference* was resolved against. Use `-Wl,--cref` for that (§1.4). |
| entry point | **NO** | see below |

**Entry point is provably NOT in the Map.** Positive control:

```bash
clang-18 -fuse-ld=lld -o app_e a.o -L. -larch -lmine -Wl,-e,main -Wl,-Map=map_entry.txt
diff map_clang_lld.txt map_entry.txt      # -> byte-identical, exit 0
readelf -h app   | grep Entry             # -> 0x17a0
readelf -h app_e | grep Entry             # -> 0x18e0
```

The entry point really changed (0x17a0 -> 0x18e0) yet the Map did not change by a single byte.
`grep -i entry` on the Map matches only `__frame_dummy_init_array_entry` /
`__do_global_dtors_aux_fini_array_entry`, i.e. symbol names, not the ELF entry.
**Entry point must be read from `e_entry` in the ELF header, not the Map.**

Only members actually extracted appear: `libarch.a` contained `archsrc.o` and `b_arch.o`;
only `b_arch.o` is in the Map, because only `helper` was referenced.

## 1.2 `-Wl,-Map=` option forms, and a silent-loss trap

```bash
ld.lld-18 -o /dev/null free.o -Map=m1.txt     # exit 0, m1.txt written (817 B)
ld.lld-18 -o /dev/null free.o --Map=m2.txt    # exit 0, m2.txt written (817 B)
ld.lld-18 -o /dev/null free.o -Map m3.txt     # exit 0, m3.txt written (817 B)
```

All three forms work. **But `--print-map` silently voids `-Map=<file>`:**

```bash
ld.lld-18 -o /dev/null free.o -Map=g1.txt --print-map   # exit 0, stdout 817B, g1.txt MISSING
ld.lld-18 -o /dev/null free.o --print-map -Map=g2.txt   # exit 0, stdout 817B, g2.txt MISSING
```

Exit 0, no warning, no file, in either order. If a build system passes both, the map file
silently never appears. `--print-map` alone writes to **stdout** (8418 B, stderr 0 B) and its
content is byte-identical to the `-Map=` file (`diff` -> IDENTICAL).

Direct `ld.lld-18` (not via clang) produces the same format — raw:
`~/vg-lab/probes/raw/q1_map_direct_ldlld.txt`.

## 1.3 `-Wl,-t` — stdout or stderr?

```bash
clang-18 -fuse-ld=lld -o app_t a.o -L. -larch -lmine -Wl,-rpath,. -Wl,-t
```

**stdout** (361 B on stdout, **0 B on stderr** — raw: `raw/q1_link_t.stdout` / `.stderr`).

```
/lib/x86_64-linux-gnu/Scrt1.o
/lib/x86_64-linux-gnu/crti.o
/usr/bin/../lib/gcc/x86_64-linux-gnu/13/crtbeginS.o
a.o
./libarch.a(b_arch.o)
./libmine.so
/lib/x86_64-linux-gnu/libgcc_s.so.1
/lib/x86_64-linux-gnu/libc.so.6
/lib64/ld-linux-x86-64.so.2
/lib/x86_64-linux-gnu/libgcc_s.so.1
/usr/bin/../lib/gcc/x86_64-linux-gnu/13/crtendS.o
/lib/x86_64-linux-gnu/crtn.o
```

`-t` **does** list shared libraries, which the Map does not. It is the complement of the Map:
Map = layout without DSOs; `-t` = input inventory including DSOs, but no addresses/sections.

By contrast `-Wl,--verbose` goes to **stderr**, is prefixed `ld.lld: `, and shows *more* —
the archive itself (`./libarch.a`, not the member), plus files pulled in via nested linker
scripts (raw: `raw/q1_lld_verbose.stderr`):

```
ld.lld: ./libarch.a
ld.lld: ./libmine.so
ld.lld: /usr/bin/../lib/gcc/x86_64-linux-gnu/13/libgcc.a
ld.lld: /lib/x86_64-linux-gnu/libc.so
ld.lld: /lib/x86_64-linux-gnu/libc.so.6
ld.lld: /usr/lib/x86_64-linux-gnu/libc_nonshared.a
```

## 1.4 Symbol resolution: `--cref` and `--why-extract`

`-Wl,--cref` -> **stdout**, 1656 B (raw: `raw/q1_cref.stdout`). Definition first, then referrers:

```
Symbol                                            File
libfn                                             ./libmine.so
                                                  a.o
strcpy                                            /lib/x86_64-linux-gnu/libc.so.6
                                                  a.o
helper                                            ./libarch.a(b_arch.o)
                                                  a.o
```

This is the real symbol-resolution answer, and it *does* cover shared libraries.

`-Wl,--why-extract=<file>` -> TSV explaining archive extraction (raw: `raw/q1_why_extract.txt`):

```
reference	extracted	symbol
a.o	./libarch.a(b_arch.o)	helper
```

## 1.5 `.init_array` entries and their origin — **fully recoverable**

The Map gives slot -> object directly:

```
2a08  18  8 .init_array
2a08   8  8    /usr/bin/../lib/gcc/x86_64-linux-gnu/13/crtbeginS.o:(.init_array)
2a10   8  8    a.o:(.init_array)
2a18   8  8    ./libarch.a(b_arch.o):(.init_array)
```

but **not** the constructor symbol. The section content is useless on its own — it is all
zeros in a PIE, the pointers live in relocation addends:

```bash
$ objdump -s -j .init_array app
 2a08 00000000 00000000 00000000 00000000
 2a18 00000000 00000000
$ readelf -rW app | grep RELATIVE
0000000000002a08  R_X86_64_RELATIVE   1880
0000000000002a10  R_X86_64_RELATIVE   1890
0000000000002a18  R_X86_64_RELATIVE   1940
```

Joining Map(slot->object) + reloc addend(slot->target) + Map .text(address->symbol) resolves
it completely. `~/vg-lab/probes/initarray_join.sh` does this:

```bash
cd ~/vg-build/probes/q1 && ~/vg-lab/probes/initarray_join.sh app map_clang_lld.txt
```

```
SLOT       ORIGIN_OBJECT                        TARGET     CTOR_SYMBOL
0x2a08     .../13/crtbeginS.o                   0x1880     frame_dummy
0x2a10     a.o                                  0x1890     ctor_a
0x2a18     ./libarch.a(b_arch.o)                0x1940     ctor_b
```

**Positive control** — add a constructor in a new object, and remove it again:

```bash
clang-18 -c -o c.o ~/vg-lab/probes/src/c.c      # contains ctor_c_NEW
clang-18 -fuse-ld=lld -o app_pc a.o c.o -L. -larch -lmine -Wl,-Map=map_pc.txt
~/vg-lab/probes/initarray_join.sh app_pc map_pc.txt
```

```
0x2aa8     .../13/crtbeginS.o    0x18f0   frame_dummy
0x2ab0     a.o                   0x1900   ctor_a
0x2ab8     c.o                   0x19b0   ctor_c_NEW      <-- appears
0x2ac0     ./libarch.a(b_arch.o) 0x19e0   ctor_b
```

Re-linking without `c.o` makes the row disappear (raw:
`raw/q1_initarray_join_baseline.txt` vs `raw/q1_initarray_join_poscontrol.txt`).
Runtime agrees with the table order: `LD_LIBRARY_PATH=. ./app_pc` prints
`ctor_a / ctor_c / ctor_b`.

## 1.6 Linker script detection

Script used (`~/vg-lab/probes/src/extra2.ld`):

```
SECTIONS { .myprobe : { LONG(0xdeadbeef); __probe_marker = .; } } INSERT AFTER .text;
```

```bash
clang-18 -fuse-ld=lld -o app_ld3 a.o -L. -larch -lmine -Wl,-T,extra2.ld -Wl,-Map=map_script2.txt
```

Script *effects* are visible in the Map, and script-origin lines are structurally distinct —
they carry no `object:(section)` field:

```
            29e0             29e0        4     1 .myprobe
            29e0             29e0        4     1         LONG ( 0xdeadbeef )
            29e4             29e4        0     1         __probe_marker = .
```

**But the filename is not recorded**: `grep "extra2" map_script2.txt` -> no match, and
`-Wl,-t` output is byte-identical with and without `-T` (`raw/q1_link_t.stdout` vs
`raw/q1_t_with_script.stdout`).

**Negative result worth keeping:** an INSERT script whose output section ends up empty is
discarded, and then the Map is byte-identical to the no-script build (`diff` clean). So
"Map unchanged" does **not** prove "no linker script was used".

Related: `/lib/x86_64-linux-gnu/libc.so` is itself a GNU ld script
(`/* GNU ld script ... GROUP ( ... ) */`), so on any normal glibc link a linker script is
always in play — visible only through `--verbose`, never through the Map or `-t`.

## 1.7 取れなかったもの (問い1)

- **entry point** — not in the Map; byte-identical Map under `-e main`. Read `e_entry`.
- **shared libraries** — absent from the Map entirely. Use `-t`, `--verbose`, or `--cref`.
- **which file a reference resolved to** — not in the Map. Use `--cref`.
- **linker script filename / "was `-T` used"** — not in the Map, not in `-t`, not in `--verbose`.
- **constructor symbol on the `.init_array` line** — not in the Map; recoverable only by
  joining with relocations (§1.5).
- I did **not** test: `-Map` under `--gc-sections`, `--icf`, ThinLTO-with-Map, or non-x86_64
  targets. Unknown.

---

# 問い2: LTO で観測は成立するか  ← 分水嶺

Observer plugin: `~/vg-lab/probes/Observer.cpp`. Built without cmake:

```bash
clang++-18 -shared -fPIC -o ~/vg-build/probes/plugin/libObserver.so \
  ~/vg-build/probes/plugin/Observer.cpp $(llvm-config-18 --cxxflags)   # exit 0
```

It logs to `$VG_OBS_LOG`: `PLUGIN_LOADED`, `EP <name> module=... defined_funcs=N`, and one
`PASSRUN <PassID>` per pass via `registerBeforeNonSkippedPassCallback`.

Two API notes for LLVM 18 (both were compile errors first):
`registerOptimizerLastEPCallback` takes `(ModulePassManager&, OptimizationLevel)` — **no**
`ThinOrFullLTOPhase` third parameter; and `<unistd.h>` is needed for `getpid`.

## 2.1 Does `-fpass-plugin=` fire under `-flto`?

| configuration | PLUGIN_LOADED | EP firings | PASSRUN | distinct |
|---|---|---|---|---|
| `-O2` no LTO, compile (a.c) | 1 | PipelineStart, OptimizerLast | 327 | 78 |
| `-O2 -flto` compile (a.c) | 1 | PipelineStart, OptimizerLast | 326 | 77 |
| `-O2 -flto=thin` compile (a.c) | 1 | PipelineStart, OptimizerLast | 225 | 60 |
| `-O2 -flto -fpass-plugin=` **on the link line** | **0** | **0** | **0** | 0 |

Reproduce:

```bash
SO=~/vg-build/probes/plugin/libObserver.so
export VG_OBS_LOG=$HOME/vg-lab/probes/x.log; rm -f $VG_OBS_LOG
clang-18 -O2 -flto -fpass-plugin=$SO -c -o /dev/null ~/vg-lab/probes/src/a.c
grep -c '^PASSRUN' $VG_OBS_LOG
```

**The premise in the task is only half right.** Under **ThinLTO** the compile-stage pipeline
really is thinner (225 vs 327 pass runs, 60 vs 78 distinct). Under **full LTO** it is
essentially the *whole* `-O2` pipeline (326 vs 327). The only passes present without LTO and
missing from the `-flto` compile stage are four late/codegen ones:

```
AssignmentTrackingPass  CGProfilePass  EliminateAvailableExternallyPass  RelLookupTableConverterPass
```

`-fpass-plugin=` on the **link** command line is a complete no-op (0 firings) — clang forwards
it to `-cc1` only, never to the linker.

## 2.2 Loading a pass plugin at link time — **`-Wl,--load-pass-plugin=` works**

`ld.lld-18 --help` lists `--load-pass-plugin=<value>`. It works, but only under LTO:

```bash
cd ~/vg-build/probes/q2
export VG_OBS_LOG=$PWD/A.log; rm -f $VG_OBS_LOG
clang-18 -O2 -flto -fuse-ld=lld -o appA a_lto.o b_lto.o -L. -lmine \
  -Wl,-rpath,'$ORIGIN' -Wl,--load-pass-plugin=$SO      # exit 0, ./appA runs, exit 0
```

| configuration | PLUGIN_LOADED | EP firings | PASSRUN | distinct |
|---|---|---|---|---|
| **Full LTO** link | 1 | `FullLTO_Early`(module `ld-temp.o`, 4 defined fns), `FullLTO_Last`(3 fns) | 226 | 59 |
| **ThinLTO** link | 2 | `OptimizerLast` x2, once per module (`a_thin.o`, `b_thin.o`) | 495 | 76 |
| **non-LTO** link | **0** | **0** | **0** | 0 |

Raw: `raw/q2_A_fullLTO_link_loadpassplugin.log`, `raw/q2_C_thinLTO_link_loadpassplugin.log`.

Full LTO and ThinLTO differ in **which extension points exist**, not just in counts:

- Full LTO link fires only `registerFullLinkTimeOptimizationEarly/LastEPCallback`, on a single
  merged module named `ld-temp.o`. `PipelineStart` and `OptimizerLast` do **not** fire.
- ThinLTO link fires `registerOptimizerLastEPCallback` **once per input module**, and
  `llvmGetPassPluginInfo()` is called twice (one PassBuilder per backend). `PipelineStart` does
  not fire; the FullLTO EPs do not fire.

An observer that only hooks `PipelineStart`/`OptimizerLast` sees **nothing** at full-LTO link
time, and an observer that only hooks the FullLTO EPs sees nothing under ThinLTO.

## 2.3 Passes that exist ONLY at full-LTO link time

```
ArgumentPromotionPass  CallSiteSplittingPass  CrossDSOCFIPass  GlobalSplitPass
LowerTypeTestsPass     PGOIndirectCallPromotion  VerifierPass  WholeProgramDevirtPass
```

Computed by set-differencing the PASSRUN logs (reproduce):

```bash
cd ~/vg-build/probes/q2
comm -13 <(cat <(grep '^PASSRUN' tu.log) <(grep '^PASSRUN' tuflto.log) | sed 's/PASSRUN //' | sort -u) \
         <(grep '^PASSRUN' A.log | sed 's/PASSRUN //' | sort -u)
```

`LowerTypeTestsPass`, `WholeProgramDevirtPass` and `CrossDSOCFIPass` are exactly the CFI
lowering machinery. **A compile-stage-only observer cannot see CFI being applied.**

## 2.4 Two silent-failure modes (positive controls)

```bash
# (4) LTO + broken plugin
clang-18 -O2 -flto -fuse-ld=lld -o appH a_lto.o b_lto.o -L. -lmine \
  -Wl,--load-pass-plugin=/nonexistent.so
#  -> exit 0 ; stderr: "Failed to load passes from '/nonexistent.so'. Request ignored."

# (5) non-LTO + broken plugin
clang-18 -O2 -fuse-ld=lld -o appI a_n.o b_n.o -L. -lmine \
  -Wl,--load-pass-plugin=/nonexistent.so
#  -> exit 0 ; stderr COMPLETELY EMPTY
```

1. A broken observer **does not fail the build** — exit 0, warning on stderr only.
2. Without LTO, `--load-pass-plugin` is not even examined: no message at all. Any pipeline
   that relies on it must verify LTO is actually on, or it will report "observed, no findings"
   while having observed nothing.

## 2.5 `-Wl,-mllvm,...` and `--lto-debug-pass-manager`

`-Wl,-mllvm,X` is a real channel and is **fail-loud** on unknown options:

```bash
clang-18 -O2 -flto -fuse-ld=lld ... -Wl,-mllvm,-debug-pass-manager
# exit 1: ld.lld: error: -mllvm: ld.lld: Unknown command line argument '-debug-pass-manager'.
```

(`-debug-pass-manager` is a PassBuilder constructor argument, not a `cl::opt` inside lld, so it
is unavailable this way — use `--lto-debug-pass-manager` instead.)

`-print-pipeline-passes` **is** recognized by lld (misspelling it yields
`Did you mean '--print-pipeline-passes'?`) but is **inert at LTO link time**: exit 0,
0 B stdout, 0 B stderr (raw: `raw/q2_wl_mllvm_print_pipeline.*`).

`-Wl,--lto-debug-pass-manager` works: **stderr**, 23996 B, 0 B stdout.

```
Running pass: VerifierPass on [module]
Running analysis: VerifierAnalysis on [module]
Running pass: CrossDSOCFIPass on [module]
Running pass: OpenMPOptPass on [module]
Running analysis: TargetLibraryAnalysis on puts
```

`-Wl,--plugin-opt=debug-pass-manager` is an exact alias — byte-identical size (23996 B).
This needs no plugin at all and is the cheapest way to enumerate the link-time pipeline.

## 2.6 取れなかったもの (問い2)

- Did **not** measure whether the observer can *modify* IR at link time (only that it runs).
- Did **not** test `--load-pass-plugin` with `-plugin-opt=` argument passing to the plugin.
- Did **not** test the gold plugin (`LLVMgold.so`) path, or `-fno-fat-lto-objects` /
  `--fat-lto-objects`.
- ThinLTO `PLUGIN_LOADED=2` matches the 2 input modules here; I did not vary module count or
  `--thinlto-jobs` to confirm it scales with modules rather than threads.

---

# 問い3: pipeline の印字

## 3.1 `-fdebug-pass-manager` is a **cc1** option, not a driver option

```bash
clang-18 -O2 -fdebug-pass-manager -c a.c b.c
# exit 1: clang-18: error: unknown argument '-fdebug-pass-manager';
#         did you mean '-Xclang -fdebug-pass-manager'?
```

Correct invocation, and `-mllvm -debug-pass-manager` is **not** an alternative:

```bash
clang-18 -O2 -mllvm -debug-pass-manager -c -o /dev/null a.c
# exit 1: clang (LLVM option parsing): Unknown command line argument '-debug-pass-manager'.
```

Working form:

```bash
clang-18 -O2 -Xclang -fdebug-pass-manager -c ~/vg-lab/probes/src/a.c ~/vg-lab/probes/src/b.c
# exit 0, stdout 0 B, stderr 43713 B, 786 lines
```

Output goes to **stderr**. Format:

```
Running pass: Annotation2MetadataPass on [module]
Running analysis: TargetLibraryAnalysis on puts
Running pass: AnnotationRemarksPass on helper (3 instructions)
```

i.e. `Running pass: <PassID> on [module]` for module passes, and
`Running pass: <PassID> on <function> (<N> instructions)` for function passes.

**TU boundaries are not marked.** `grep -c 'a\.c\|b\.c'` over the 786 lines returns **0** — no
source filename is ever printed. The only boundary signal is that the pipeline-opening pass
repeats:

```
1:Running pass: Annotation2MetadataPass on [module]
476:Running pass: Annotation2MetadataPass on [module]
```

So splitting a multi-TU log requires cutting on `Annotation2MetadataPass on [module]` and
relying on argument order to name the pieces. Raw: `raw/q3_fdebug_pm_2TU_xclang.stderr`.

## 3.2 `-mllvm -print-pipeline-passes` via clang — **yes, it really works**

```bash
clang-18 -O2 -mllvm -print-pipeline-passes -c -o /dev/null ~/vg-lab/probes/src/a.c
# exit 0, stdout 3869 B, stderr 0 B
```

**stdout**, one single-line pipeline string:

```
annotation2metadata,forceattrs,declare-to-assign,inferattrs,coro-early,function<eager-inv>(lower-expect,
simplifycfg<bonus-inst-threshold=1;no-forward-switch-cond;...>,sroa<modify-cfg>,early-cse<>),openmp-opt,
ipsccp,called-value-propagation,globalopt,function<eager-inv>(mem2reg,instcombine<...>,...
```

With two TUs it emits **one line per TU** (7738 B, `wc -l` = 2), newline-separated, in argument
order — unlike `-fdebug-pass-manager` this is cleanly machine-splittable. Raw:
`raw/q3_print_pipeline.stdout`, `raw/q3_print_pipeline_2TU.stdout`.

Summary of destinations: `-fdebug-pass-manager` -> stderr; `-print-pipeline-passes` -> stdout;
`--lto-debug-pass-manager` -> stderr.

---

# 問い4: hardening 判定に使えるフィールド

`~/vg-lab/probes/hardening.py` reads the ELF **binary structure** with `struct.unpack_from` —
ELF header, program headers, section headers, `.dynamic` tag/value pairs, and `.dynsym`/`.symtab`
entries. It never parses tool text.

Field definitions used:

| property | structural rule |
|---|---|
| PIE | `e_type == ET_DYN (3)` **AND** `DT_FLAGS_1 & DF_1_PIE (0x08000000)` |
| NX | `PT_GNU_STACK (0x6474e551)` exists AND `p_flags & PF_X (1) == 0` |
| RELRO | `PT_GNU_RELRO (0x6474e552)` present |
| BIND_NOW | `DT_FLAGS & DF_BIND_NOW (0x8)` OR `DT_FLAGS_1 & DF_1_NOW (0x1)` OR `DT_BIND_NOW (24)` present |
| Full RELRO | RELRO AND BIND_NOW |
| stack protector | `__stack_chk_fail` in `.dynsym`/`.symtab` (version suffix stripped at `@`) |
| FORTIFY | any symbol whose name ends in `_chk` other than `__stack_chk_fail` |
| build ID | `.note.gnu.build-id` walked as a note: `n_type == NT_GNU_BUILD_ID (3)` and owner `GNU` |
| W+X | section: `SHF_ALLOC|SHF_WRITE|SHF_EXECINSTR`; segment: `PT_LOAD` with `PF_W|PF_X` |

## 4.1 The matrix — every field is shown to move

```bash
cd ~/vg-build/probes/q4
python3 ~/vg-lab/probes/hardening.py base sp_all sp_none pie nopie relro_now norelro \
  relro_lazy fortify2 fortify0 nobuildid buildid_sha1 execstack
```

Raw: `raw/q4_hardening_matrix.json`.

| binary | e_type | DT_FLAGS_1 | PIE | GNU_STACK | NX | RELRO | BINDNOW | SSP | FORTIFY | build_id |
|---|---|---|---|---|---|---|---|---|---|---|
| base | ET_DYN | 0x8000000 | True | 0x6 | True | True | False | False | False | 5a216023 |
| sp_all | ET_DYN | 0x8000000 | True | 0x6 | True | True | False | **True** | False | f286465f |
| sp_none | ET_DYN | 0x8000000 | True | 0x6 | True | True | False | False | False | 5a216023 |
| pie | ET_DYN | 0x8000000 | True | 0x6 | True | True | False | False | False | 5a216023 |
| **nopie** | **ET_EXEC** | **0x0** | **False** | 0x6 | True | True | False | False | False | 3464a2e9 |
| **relro_now** | ET_DYN | **0x8000001** | True | 0x6 | True | True | **True** | False | False | efe1e034 |
| **norelro** | ET_DYN | 0x8000000 | True | 0x6 | True | **False** | False | False | False | b672aa1f |
| relro_lazy | ET_DYN | 0x8000000 | True | 0x6 | True | True | False | False | False | 5a216023 |
| **fortify2** | ET_DYN | 0x8000000 | True | 0x6 | True | True | False | False | **True** | 9ca6ec9a |
| fortify0 | ET_DYN | 0x8000000 | True | 0x6 | True | True | False | False | False | 5a216023 |
| **nobuildid** | ET_DYN | 0x8000000 | True | 0x6 | True | True | False | False | False | **NONE** |
| buildid_sha1 | ET_DYN | 0x8000000 | True | 0x6 | True | True | False | False | False | d0b3e968 |
| **execstack** | ET_DYN | 0x8000000 | True | **0x7** | **False** | True | False | False | False | 02624f5c |

`fortify2` `_chk` symbols: `['__printf_chk', '__sprintf_chk', '__strcpy_chk']`.

Each flag moves exactly the intended field and nothing else:
`-no-pie` -> `ET_EXEC` + `DT_FLAGS_1` 0x8000000 -> 0x0;
`-Wl,-z,execstack` -> `PT_GNU_STACK` 0x6 -> 0x7;
`-Wl,-z,norelro` -> `PT_GNU_RELRO` disappears;
`-Wl,-z,relro,-z,now` -> `DT_FLAGS_1` 0x8000000 -> 0x8000001 (DF_1_NOW);
`-fstack-protector-all` -> `__stack_chk_fail` appears;
`-D_FORTIFY_SOURCE=2` -> three `_chk` symbols appear;
`-Wl,--build-id=none` -> note gone.

**Free negative control:** `base`, `sp_none`, `pie`, `relro_lazy` and `fortify0` all share
build-id `5a216023` — byte-identical binaries. Those five flags are this toolchain's defaults,
so the *absence* of a change there is confirmed rather than assumed.

Consequently, measured Ubuntu clang-18 defaults are: **PIE on, NX on, partial RELRO
(no BIND_NOW), stack protector OFF, FORTIFY OFF.** (Ubuntu's gcc enables SSP/FORTIFY by
default; this clang does not.)

## 4.2 W+X positive control

The whole matrix above reports `wx_sections: []` — which proves nothing until the check is
shown to fire. `-Wl,-N` (omagic) does not work here (`ld.lld: error: unable to find library
-lgcc_s`). Forcing it with explicit assembler section flags does:

```asm
    .section .wxsec,"awx",@progbits      # ~/vg-lab/probes/src/wx.s
```

```bash
clang-18 -fuse-ld=lld -O2 -o wx_asm ~/vg-lab/probes/src/hard.c ~/vg-lab/probes/src/wx.s   # exit 0
python3 ~/vg-lab/probes/hardening.py wx_asm
#   wx_sections = ['.wxsec']
#   wx_segments = ['0x2860']
```

Ground truth agrees exactly:

```
readelf -SW wx_asm ->  [18] .wxsec  PROGBITS  0000000000002860 ... WAX
readelf -lW wx_asm ->  LOAD  0x000860 0x0000000000002860 ... RWE 0x1000
```

Note NX stays `True` for `wx_asm` (`PT_GNU_STACK` = 0x6): W+X and NX are independent checks and
must both be reported.

## 4.3 Cross-validation against llvm-readobj — and a real LLVM 18 limitation

```bash
cd ~/vg-build/probes/q4
python3 ~/vg-lab/probes/crosscheck.py base nopie sp_all relro_now norelro execstack \
  nobuildid buildid_sha1 fortify2 wx_asm
# ALL_AGREE: True   (exit 0, 70 checks, 0 mismatches)
```

Raw: `raw/q4_crosscheck.txt`. Compared numerically against
`llvm-readobj-18 --elf-output-style=JSON`: `e_type`, `PT_GNU_STACK.p_flags`,
`PT_GNU_RELRO` presence, build ID, `__stack_chk_fail` presence.

**LLVM 18 limitation found:** `--elf-output-style=JSON` does not support `--dynamic-table`. It
silently emits GNU text into the middle of the JSON stream and still exits 0:

```bash
for opt in --file-headers --program-headers --section-headers --dynamic-table \
           --dyn-symbols --notes --relocations; do
  llvm-readobj-18 --elf-output-style=JSON $opt base > t.json 2>/dev/null
  python3 -c 'import json;json.load(open("t.json"))' 2>/dev/null && echo "$opt VALID_JSON" || echo "$opt NOT_JSON"
done
```

-> everything `VALID_JSON` **except `--dynamic-table` -> NOT_JSON**, exit 0 in all cases.

So `DT_FLAGS` / `DT_FLAGS_1` (i.e. PIE confirmation, BIND_NOW, full RELRO) have **no structured
llvm-readobj source in LLVM 18**. Either walk `PT_DYNAMIC` yourself (what `hardening.py` does)
or fall back to parsing `readelf -d` text. In the cross-check those two rows are labelled
`TEXT-XCHECK`, not `STRUCT`.

## 4.4 Controls proving the checks are real

**Tamper control** — flip `e_type` in a copy of `base` from ET_DYN(3) to ET_EXEC(2):

```bash
cp base tampered && printf '\x02' | dd of=tampered bs=1 seek=16 count=1 conv=notrunc status=none
python3 ~/vg-lab/probes/hardening.py tampered   # -> e_type_name=ET_EXEC, PIE=False
```

`base` reported ET_DYN/True, so the parser is genuinely reading the file. Note the tampered
file still has `DF_1_PIE=True` while `e_type=ET_EXEC` — which is precisely why PIE must be
`ET_DYN AND DF_1_PIE` and not either alone.

**Fault injection** — break `hardening.py`'s `PT_GNU_STACK` constant and confirm the
cross-check fails:

```bash
sed -i 's/PT_GNU_STACK=0x6474e551/PT_GNU_STACK=0x6474e553/' ~/vg-lab/probes/hardening.py
rm -rf ~/vg-lab/probes/__pycache__
python3 ~/vg-lab/probes/crosscheck.py base execstack     # exit 1
#   base       PT_GNU_STACK.p_flags  None  6  MISMATCH
#   execstack  PT_GNU_STACK.p_flags  None  7  MISMATCH
#   ALL_AGREE: False
```

Raw: `raw/q4_crosscheck_FAULTINJECTED.txt`. Restoring the constant returns exit 0.

**Gotcha:** `crosscheck.py` imports `hardening.py` as a module, so `__pycache__` must be cleared
after editing it — a stale `.pyc` made a restored file still report exit 1 during this session.

## 4.5 取れなかったもの (問い4)

- **CFI / SafeStack / shadow-call-stack / `-z ibt`,`-z shstk` (CET)** — not measured at all.
- **RELRO "partial vs full"** is inferred from `PT_GNU_RELRO` + BIND_NOW; I did not verify the
  RELRO segment actually covers `.got.plt`.
- FORTIFY detection is presence-of-`_chk`-symbol only. It cannot distinguish
  `_FORTIFY_SOURCE=1/2/3`, and a binary where no fortifiable call survives optimization will
  report FORTIFY=False even if compiled with it. Not a compile-flag oracle.
- Static (non-dynamic) executables: `.dynsym` is absent so SSP/FORTIFY fall back to `.symtab`,
  which a stripped static binary will not have. **Untested.**
- Only x86_64 ELF was tested.

---

# 問い5: 比較対象の実現可能性

## 5.1 clang-tidy / scan-build

All **MISSING**: `clang-tidy`, `clang-tidy-18`, `scan-build`, `scan-build-18`, `analyze-build`,
`cppcheck`, `checksec`.

Installable — archive metadata is reachable and the simulation resolves cleanly:

```bash
apt-get -s install clang-tidy-18     # exit 0
#  -> Inst clang-tools-18 (1:18.1.3-1ubuntu1)   [provides scan-build / analyze-build]
#  -> Inst clang-tidy-18  (1:18.1.3-1ubuntu1)
#  0 upgraded, 2 newly installed, 0 to remove
```

So: `apt-get install clang-tidy-18 clang-tools-18`. **I did not install them** (not asked to
change the box).

**The Clang Static Analyzer itself needs no install** — it is already reachable through the
driver, and it fires on real bugs:

```bash
clang-18 --analyze -Xanalyzer -analyzer-output=text ~/vg-lab/probes/src/bug.c -o /dev/null
```

```
bug.c:3:51: warning: Use of memory after it is freed [unix.Malloc]
bug.c:3:24: note: Memory is allocated
bug.c:3:35: note: Memory is released
bug.c:4:36: warning: Dereference of null pointer (loaded from variable 'q') [core.NullDereference]
2 warnings generated.
```

Raw: `raw/q5_analyze_bug.txt`. Caveat measured: **exit code is 0 even with findings** — the exit
status is not a pass/fail signal; count the diagnostics.
Note it did *not* flag the `strcpy(b, s)` overflow in `h()`; `scan-build` adds driver
integration and HTML reports but not that checker.

## 5.2 checksec replacement

`checksec` is not installed. `~/vg-lab/probes/hardening.py` covers the standard checksec
columns (PIE / NX / RELRO / BIND_NOW / stack protector / FORTIFY / build ID) plus W+X, from
structural fields, validated against `llvm-readobj` (§4.3) with a fault-injection control
(§4.4). `pwntools`' `checksec` and the `checksec.sh` script are the off-the-shelf alternatives
but neither is present and neither reports W+X segments.

## 5.3 Alive2 — verdict: custom LLVM build required, hours-scale. Did not start a build.

Measured prerequisites:

| requirement (from Alive2 `CMakeLists.txt`, fetched) | this box | met? |
|---|---|---|
| `cmake_minimum_required(VERSION 3.10)` | 3.28.3 | yes |
| `CMAKE_CXX_STANDARD 20` | clang-18 / g++-13 | yes |
| `find_package(Z3 4.8.5 REQUIRED)` | libz3-dev **4.8.12** installed | yes |
| `find_program(RE2C re2c)` — `SEND_ERROR` if absent | **MISSING** | no (apt-installable) |
| `if (NOT LLVM_ENABLE_RTTI) FATAL_ERROR` | `llvm-config-18 --has-rtti` -> **YES** | yes |

```bash
llvm-config-18 --has-rtti        # YES
llvm-config-18 --build-mode      # RelWithDebInfo
llvm-config-18 --assertion-mode  # OFF
grep Z3_.*VERSION /usr/include/z3_version.h   # 4 . 8 . 12
```

Raw: `raw/q5_alive2_CMakeLists.txt`, `raw/q5_alive2_README.md`, `raw/q5_alive2_tags.json`.

The RTTI axis is **not** the blocker — Ubuntu's llvm-18-dev has RTTI on. The blockers are:

1. **Exceptions.** Alive2's README: *"Alive2's `opt` and `clang` translation validation requires
   a build of LLVM with RTTI and exceptions turned on."* `llvm-config-18 --cxxflags` emits
   `-fno-exceptions`, which indicates this LLVM was built with `LLVM_ENABLE_EH=OFF`.
   **INFERENCE** — llvm-config has no `--has-eh`; I did not compile an EH-using consumer to
   confirm.
2. **Version coupling.** Alive2 publishes tags per LLVM major, and the tag list is
   `['v21.0', 'v20.0', 'v19.0']` — **there is no v18 tag**. LLVM 18 is below the supported
   floor. README: *"The latest version of Alive2 is always intended to be built against the
   latest version of LLVM, using the main branch."*
3. `re2c` missing (trivial: `apt-get install re2c`).

So making Alive2 usable here means building LLVM (main or >=19) with
`-DLLVM_ENABLE_RTTI=ON -DLLVM_ENABLE_EH=ON`, then Alive2 against it. That is a **hours-scale**
task (LLVM from source on 12 cores), not a 30-minute one. **Not started, per instructions.**

Not determined: whether standalone `alive-tv` alone (without the opt/clang plugins) would
configure against stock llvm-18-dev. Given no v18 tag exists, I did not pursue it.

---

# Cross-cutting traps found (all measured)

1. `--print-map` silently discards `-Map=<file>`; exit 0, no file, no warning.
2. `-Wl,--load-pass-plugin=` in a **non-LTO** link is silently ignored — even a nonexistent
   `.so` produces no message and exit 0.
3. A **broken** pass plugin under LTO does not fail the build: exit 0, stderr warning only.
4. `-fpass-plugin=` on a link line is a no-op; the link-time route is `-Wl,--load-pass-plugin=`.
5. `-fdebug-pass-manager` is cc1-only; the driver rejects it and `-mllvm -debug-pass-manager`
   does not exist. Use `-Xclang -fdebug-pass-manager`.
6. `llvm-readobj-18 --elf-output-style=JSON --dynamic-table` emits invalid JSON, exit 0.
7. `-fdebug-pass-manager` never prints a source filename, so multi-TU logs have no labelled
   boundary.
8. A linker script whose section ends up empty leaves the Map byte-identical — "Map unchanged"
   does not mean "no script".
9. `.init_array` bytes are all zero in a PIE; the payload is in `R_X86_64_RELATIVE` addends.
10. Editing `hardening.py` requires clearing `~/vg-lab/probes/__pycache__` before re-running
    `crosscheck.py`, or a stale `.pyc` is imported.

# Method caveats

- `-flto` fixtures were 2 small C TUs. Pass counts will differ on real code; the
  **relative** statements (full-LTO compile ~ full pipeline, ThinLTO compile thinner, 8
  link-only passes) are what I would carry forward, not the absolute numbers.
- Pass counts come from `registerBeforeNonSkippedPassCallback`, so skipped passes are excluded
  by construction.
- Everything is x86_64 ELF, lld 18.1.3, glibc. No cross-target, no static-only, no Windows/Mach-O.

---

# Run-log coverage (honest scope)

`~/vg-lab/probes/run-log.txt` (199 lines) contains:

1. every command wrapped by the `run()` / `runs()` helpers in `runlog.sh` (the Q1/Q2 build and
   link steps), with exit code and raw byte counts; and
2. a **FINAL VERIFICATION PASS** block appended by `~/vg-lab/probes/verify.sh`, which re-runs
   every headline claim in this report with an explicit exit code.

It does **not** contain literally every interactive command issued during the session — several
exploratory greps and `--help` invocations were run outside the helpers. Re-run
`~/vg-lab/probes/verify.sh` to regenerate the verification block from scratch; it is
self-contained apart from the build trees under `~/vg-build/probes/`.

Verification pass result (all as expected):

```
Q1 map identical under -e main             exit=0    (entry point NOT in Map)
Q1 no .so in Map (grep must FAIL=1)        exit=1    (no shared lib in Map)
Q1 init_array join                         exit=0
Q1 --print-map voids -Map=                 expected_missing=yes
Q2 link with -fpass-plugin (LTO)           exit=0    log lines=0   (no-op)
Q2 link with --load-pass-plugin (fullLTO)  exit=0    PLUGIN_LOADED=1 EP=2 PASSRUN=226
Q2 link with --load-pass-plugin (NON-LTO)  exit=0    log lines=0   (silent no-op)
Q3 -fdebug-pass-manager (driver, must FAIL) exit=1
Q3 -Xclang -fdebug-pass-manager (must PASS) exit=0
Q3 -mllvm -print-pipeline-passes           exit=0
Q4 crosscheck (must be exit 0)             exit=0    70 checks, 0 mismatches
Q4 hardening.py on wx_asm                  exit=0
```

# Repository hygiene

Nothing was written into the repository. All output went to the measurement
directory and the build scratch directory, both on the Linux filesystem. The
earlier out-of-repo measurement workspace was never read or written. No git
command other than `git status` and `git log` was run.

Note for the main agent: during this session the repo HEAD moved from `b9b56b4` to `aa7a736`
and several `compiler/*` directories appeared as untracked, plus a modified `.gitignore`.
**That was not me** — a grep for my artifact names (`vg-lab/probes`, `VG_OBS_LOG`,
`initarray_join`, `hardening.py`) across `compiler/` returns no matches. Another agent is
working in the repo concurrently.
