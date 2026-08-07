# Clean-rebuild byte comparison — what actually happened

Produced by `node tools/rebuild-compare.mjs --work <scratch dir>`. Every number
below came out of that run; nothing is inferred.

**Environment.** Linux (WSL, Ubuntu 24.04), node 18.19.1, `clang version 18.1.3
(1ubuntu1)`, GNU `readelf`. Builds went to a scratch directory on the Linux
filesystem — never under `compiler/`, per `../../schema/interfaces.md` §1. The
concrete paths are elided below as `<scratch>` because a build instruction
carrying one machine's directory layout is both a disclosure and wrong for
everyone else.

**Result line.**

```
inputs=11 checked=11 skipped=0
cases=11 reproduced=7 differed=4 broken=0
```

Exit 0. Seven cases reproduce byte for byte; four differ, and each difference
has an identified cause.

---

## Before anything was compared: is the fixture real?

An artefact with nothing in it reproduces perfectly. So the runner emits IR at
`-O0` and `-O2` first and counts memset **call sites per function**
(`../../schema/interfaces.md` §4), and refuses to report a comparison from a
build in which the control's count reached zero.

Identical in all eleven cases:

| | `-O0` | `-O2` |
|---|---|---|
| `wipe_secret` (target) call sites | 1 | **0** |
| `control_wipe` (control) call sites | 1 | **1** |
| `declare …@llvm.memset…` lines | 1 | 1 |
| module total call sites | 2 | 1 |

The target's zeroing disappears under optimisation; the control's does not; the
declaration survives in both. A name search over the `-O2` IR finds the string
twice and would report the effect as still present. That gap — 2 by name, 1 by
call site — is the reason the oracle is written the way it is.

---

## The matrix

`same` = both builds use the identical directory, which is removed between them.
`differ` = the two builds use different directories, which is what a second
build on a second machine looks like.

| Case | What varies | `wipe.o` | `main.o` | `app` |
|---|---|---|---|---|
| `same-path-clean` | nothing | same | same | same |
| `same-path-debug` | nothing, with `-g` | same | same | same |
| `builddir-differs-nodebug` | output directory | same | same | same |
| `builddir-differs-debug` | output directory, `-g` | **differs** | **differs** | **differs** |
| `srcdir-differs-nodebug` | source directory | same | same | same |
| `srcdir-differs-debug` | source directory, `-g` | **differs** | **differs** | **differs** |
| `srcdir-differs-debug-mapped` | source directory, `-g`, with `-ffile-prefix-map` + `-fdebug-compilation-dir=.` | same | same | same |
| `file-macro` | source directory, `__FILE__` compiled in | same | **differs** | **differs** |
| `time-macros-unpinned` | the clock only (`__DATE__`/`__TIME__`, builds >1 s apart) | same | **differs** | **differs** |
| `time-macros-pinned` | the same, with `SOURCE_DATE_EPOCH` set | same | same | same |
| `buildid-link` | nothing, linked `-Wl,--build-id=sha1` | same | same | same |

---

## The four differences, and why

### 1 & 2. Recorded paths, and only with `-g`

`builddir-differs-debug` and `srcdir-differs-debug` differ in exactly two
sections of every object and of the linked binary:

```
.debug_line_str   bytes-differ
.debug_str        bytes-differ
```

and, for `app` only, `.note.gnu.build-id`.

Reading the DWARF out of `wipe.o` separates the two causes cleanly.

`builddir-differs-debug` — the **working directory** moved, the source did not:

```
run 1  DW_AT_name      <scratch>/builddir-differs-debug/src/wipe.c
       DW_AT_comp_dir  <scratch>/builddir-differs-debug/build-a
run 2  DW_AT_name      <scratch>/builddir-differs-debug/src/wipe.c
       DW_AT_comp_dir  <scratch>/builddir-differs-debug/build-b
```

`srcdir-differs-debug` — the **source path** moved, the working directory did
not:

```
run 1  DW_AT_name      <scratch>/srcdir-differs-debug/src-a/wipe.c
       DW_AT_comp_dir  <scratch>/srcdir-differs-debug/build
run 2  DW_AT_name      <scratch>/srcdir-differs-debug/src-b/wipe.c
       DW_AT_comp_dir  <scratch>/srcdir-differs-debug/build
```

Two separate path inputs, two separate attributes, one shared symptom. Note also
what did **not** differ: `.debug_line`, `.text`, `.rodata`, `.symtab`. The
compiler's output is a function of its inputs; the path is one of the inputs,
and with `-g` it is recorded verbatim.

**Without `-g`, neither move is visible at all.** `builddir-differs-nodebug` and
`srcdir-differs-nodebug` are byte-identical, and identical to `same-path-clean`
— the same three digests appear in all three rows of the report. Compiling the
same source from a different directory is reproducible unless you ask the
compiler to write the directory down.

### 3. Proving the path is the cause rather than assuming it

`srcdir-differs-debug-mapped` is the same move, with the reproducible-builds
mitigation applied:

```
-ffile-prefix-map=<the source dir>=/fixture   -fdebug-compilation-dir=.
```

Result: byte-identical, all three artefacts. The DWARF now reads

```
DW_AT_name      /fixture/wipe.c
DW_AT_comp_dir  .
```

Removing the varying input removes the difference. That is what turns "the path
is probably the cause" into a measurement.

### 4. `__FILE__` — a path that no debug-info switch reaches

`file-macro` compiles the source path into the program itself. `wipe.o` is
unaffected (it contains no such macro); `main.o` differs in `.rodata.str1.1` and
`app` in `.rodata`:

```
run 1   <scratch>/file-macro/src-a/main.c
run 2   <scratch>/file-macro/src-b/main.c
```

This one is worth separating from the DWARF cases because the usual remedy does
not apply to it: `-g` is not involved, so turning debug info off changes
nothing. `-ffile-prefix-map` does cover `__FILE__` in clang, but the difference
lives in the program's data, not in its debug information, and a build that
strips symbols still carries it.

### 5. The clock, and `SOURCE_DATE_EPOCH`

`time-macros-unpinned` varies nothing but the wall clock. The two builds are
more than a second apart, and `.rodata.str1.1` in `main.o` differs:

```
run 1   Aug  7 2026 21:09:22
run 2   Aug  7 2026 21:09:24
```

`time-macros-pinned` is the same source and the same delay with
`SOURCE_DATE_EPOCH=1700000000` exported. Byte-identical, and the string
compiled in is

```
Nov 14 2023 22:13:20
```

which is that epoch. So clang 18.1.3 honours `SOURCE_DATE_EPOCH` for `__DATE__`
and `__TIME__`, measured rather than assumed, and the clock stops being a source
of divergence when it is pinned.

---

## `.note.gnu.build-id` is a consequence, never a cause

It appears in the differing-section list for `app` in every case where `app`
differs, and in none where it does not. That is expected: the build id is a hash
of the linked output, so it moves when anything else moves and never on its own.
The runner labels it as a consequence rather than letting it be read as an
explanation — a report that lists it alongside `.debug_str` without comment
invites the conclusion that the linker is nondeterministic, which is the wrong
conclusion here.

**A null result worth recording:** `buildid-link` links with
`-Wl,--build-id=sha1` and produces a binary byte-identical to `same-path-clean`,
which does not pass the flag — same sha256 for `app`, and the same 20-byte note
(`fbbddcbd63…`). On this toolchain the driver's default already produces that
note, so the flag is a no-op and the case does **not** independently exercise
build-id generation. It is kept because it establishes the null result; it is
not evidence that the flag does anything.

---

## What was not observed

Stated because the absence of a result is not a result:

- **A second machine.** Every build here ran on one machine, one filesystem, one
  clang install, one user. Cross-machine reproducibility — different kernel,
  different locale, different `/usr` — was not measured.
- **A second toolchain.** Nothing was rebuilt with a different compiler; see the
  diverse-double-compiling non-goal in `../README.md`.
- **Parallelism.** Every build here is serial. Link-order and job-scheduling
  nondeterminism, which is a common real cause, cannot appear in this matrix.
- **Archives and packaging.** No `ar` archive, no tarball, no `.deb` was
  produced, so the classic timestamp-and-uid sources of irreproducibility in
  those formats were not exercised.
- **Long-running drift.** The two builds in each case are seconds apart. Nothing
  here says anything about a rebuild a year later against an updated `/usr`.
- **Locale and environment.** `LC_ALL`, `TZ` and `PATH` were whatever the shell
  had; they were not varied deliberately, so a dependency on them would not have
  been detected except by accident.

## Reproducing this

```sh
node tools/rebuild-compare.mjs --work <scratch dir on the linux filesystem>
node tools/rebuild-compare.mjs --list        # the cases and why each exists
node tools/rebuild-compare.mjs --work <dir> --case srcdir-differs-debug
```

The runner writes a JSON report (`rebuild-report.json` in the work directory by
default) carrying, per case, the oracle counts, both digests of every artefact,
the differing section list and the first differing hexdump line in each. Those
lines contain absolute paths from the machine that produced them, which is why
the report goes to the scratch directory and not into the repository.
