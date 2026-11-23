# How far the repair reaches — measured 2026-11-11

The repair plugins' READMEs measure them at `-O2`, in C, without LTO, on the
files the corpora already held, and list what they did not measure. This file
records a day of measurement aimed at that list. It changes no plugin:
`../../llvm-repair/src/WipePin.cpp` and `../../gcc-repair/src/WipePinGcc.cpp`
are the sources of `7c9d11f2…` (clang 18) and `ea3e8c7e…` (gcc 13), the builds
named in `../../llvm-repair/README.md` and `../../gcc-repair/README.md`
(*2026-11-10, later*), and every number below was taken with those builds or
with the other versions' builds listed there.

Setting, unless a section says otherwise: x86-64, Ubuntu 24.04 under WSL,
clang 18.1.3 and gcc 13.3.0, `_FORTIFY_SOURCE` undefined (`-U_FORTIFY_SOURCE`,
which matters on gcc 13: it defines 3 by default when optimising). The scripts, the
expectations written before each run, the listings and the generated sources
are lab notes kept outside this repository, like every other measurement under
`compiler/`.

**How a row is read.** The verdict is `verdictOf` from `../repair-loop/`, the
same differential reading the repair loop uses: a file *kept* its wipe when the
build with the wipe and the build without it differ, and the co-resident
control is PRESENT. The denominator is always the files **stock deleted at
that level and setting**, counted again for each level (a file stock does not
delete cannot be repaired). The arms:

| arm | what is loaded |
|---|---|
| stock | nothing |
| off | the repair plugin, every switch off |
| ext | the plugin with the switches the repair loop's `ext` arm sets |
| xb | ext, plus `WPIN_BUFFER_BARRIER=1` |
| dry | ext, plus `WPIN_DRY_RUN=1` (records, changes nothing); xbdry is xb with it |

## Optimisation levels

52 files of the r4 L corpus (its stack-wipe files; at `-O2` stock deletes 51
of them, the files the plugin READMEs measure), E3 v2 (52 machine-made rewrites of the same wipes as loops of
zero stores), and two controls that no level should delete: E5 v8
(`explicit_bzero`) and E5 v10 (`memset` through a volatile function pointer).

| level | compiler | r4 L: stock deleted | kept by off / ext / xb | E3 v2: stock deleted | kept by off / ext / xb |
|---|---|---|---|---|---|
| `-O0` | clang 18 | 0 | — | 0 | — |
| `-O0` | gcc 13 | 0 | — | 0 | — |
| `-O1` | clang 18 | 28 | 28 / 28 / 28 | 26 | 0 / 0 / 26 |
| `-O1` | gcc 13 | 52 | 52 / 52 / 52 | 7 | 0 / 0 / 7 |
| `-O2` | clang 18 | 51 | 51 / 51 / 51 | 50 | 0 / 0 / 50 |
| `-O2` | gcc 13 | 51 | 51 / 51 / 51 | 51 | 0 / 0 / 51 |
| `-O3` | clang 18 | 51 | 51 / 51 / 51 | 50 | 0 / 0 / 50 |
| `-O3` | gcc 13 | 51 | 51 / 51 / 51 | 51 | 0 / 0 / 51 |
| `-Os` | clang 18 | 51 | 51 / 51 / 51 | 51 | 0 / 0 / 51 |
| `-Os` | gcc 13 | 51 | 51 / 51 / 51 | 51 | 0 / 0 / 51 |

- At `-O2` the rows are those behind the plugin READMEs' `-O2` numbers: the
  19,656 rows of the clang 18 and gcc 13 runs were produced again and are
  identical in every field.
- The two controls: 0 deleted, at every level, by both compilers, in every arm.
  The `-S` of both dry arms (`WPIN_DRY_RUN=1` with and without the barrier
  switch) is byte-identical with stock's, with and without the wipe, in all
  5,616 comparisons of each level (every file, setting and dry arm).
- `-O0` has no denominator: nothing is deleted. clang emits no lifetime
  markers there, so a barrier count of 0 at `-O0` is not a failure.
- **Two places where the reading, not the repair, decides the number.** At
  `-O1`, clang 18 compiles six r4 L files (the `pinpad` task) so that the build
  with the wipe and the build without it differ only by a one-byte frame offset
  (`leaq 8(%rsp)` against `leaq 9(%rsp)`); `verdictOf` reads that difference as
  *kept*, so those six are outside the 28 even though stock deletes their wipe.
  At `-O1`, gcc 13 deletes the stores of most E3 v2 loops but leaves the empty
  count-down loop, which `verdictOf` also reads as *kept*; 7 is the number
  `verdictOf` reports, not the number of loops whose stores were deleted. Both
  are the differential reading's known blind spot (a difference that is not a
  wipe). A corrected classification in the lab notes counts 34 and 50 deleted,
  all kept by the same arms as in the table; it is not `verdictOf`, and it is not
  re-checked here.
- At `-O1` gcc also deletes the one r4 L wipe it keeps at `-O2`, hence 52.
- Within the table's denominators the ext arm keeps none of E3 v2: it pins
  `memset`, and a loop of stores has none. Only the buffer barrier keeps a
  loop.

Not measured: the other nine versions at `-O1`, `-O3` and `-Os` (started, not
finished); `-Og` and `-Oz`; the same table with `-D_FORTIFY_SOURCE=2` and `3`
(run, not summarised here); by `verdictOf`, the repair arms on the six clang
`-O1` files and on the gcc `-O1` loops it reads as kept under stock.

## Loops a model wrote

The plugin READMEs could not measure a loop a model wrote: the corpora had none
that stock deleted. So the models were asked for one. 120 requests: the ten
stack-wipe tasks of the r4 L files, the same four models, three times each,
with one paragraph added after the task, translated: *"for the wipe, do not use
a library function such as memset; write 0 one byte at a time in a loop."* The
launch differed from the earlier groups' only in that paragraph (checked on
all 120 command lines and inputs).

- 108 responses count. The other 12 were requests to one model that, after a
  safety stop, were answered by a different model; they are excluded, as in the
  earlier groups. All 108 compile with clang 18 and gcc 13.
- 64 of the 108 declared the loop's pointer `volatile` (by model: 30 of 30,
  18 of 18, 13 of 30, 3 of 30). 44 did not.
- Stock `-O2` deleted exactly those 44, with both compilers and with
  `_FORTIFY_SOURCE` undefined, 2 and 3. The 64 `volatile` loops were all kept.
- The buffer barrier kept **43 of the 44** (both compilers, all three settings);
  off and ext kept 0. The one it did not keep wipes through a `static` helper's
  pointer argument, which is not a stack buffer of the function: WipePin prints
  its *not a stack buffer* line and places nothing, the documented unhandled
  shape (`../../llvm-repair/README.md`, *What it does not handle*).
- The dry arm's `-S` is byte-identical with stock's for all 108.

This counts a shape the request asked for. It is not how often a model writes
a loop wipe unprompted.

## How often the shapes occur: a census of the model-written files

Measured 2026-11-11; summarised and checked 2026-11-23. The plugin READMEs show
what each v3 shape does on sources written for it, and say they did not measure
how often a shape occurs in code nobody wrote for it
(`../../llvm-repair/README.md`, *Not measured: … how often any v3 shape occurs*).
This counts them in every model-written C file at hand. What it counts are
**zero-fill sites**, not wipes: an initialiser (`= {0}`, a clear before a fill)
is a site too.

**Files.** 6,283, in eleven groups: the r4 corpus (1,476); r4 L (1,295); a
regeneration of r4 L that came back byte-identical (1,295, so measured as r4 L);
seven later generations that vary the prompt (1,377 together: r4 L's prompt
again; with an OpenSSF example; naming SEI CERT C and CWE; "you are an expert";
asking for `explicit_bzero`; for Linux and Windows; and the four conditions of
`../../claude-code/README.md`); and `../ai-generated/generated-corpus/` (840).
A file whose content and target function repeat another's is measured once:
**4,619 unique files**. clang 18 at `-O2` compiles 4,485 of them with
`_FORTIFY_SOURCE` undefined; 134 do not compile (mostly an undeclared `NULL`,
`SIZE_MAX`, `errno` or `PATH_MAX`, or a missing Windows header — the source's
fault) and are left out of everything below. gcc 13 compiles 4,488.

**Arms**, on every unique file, both compilers, `_FORTIFY_SOURCE` undefined and
2 (gcc with `-U_FORTIFY_SOURCE` first): stock; the plugin in module scope as a
dry run (`WPIN_SCOPE=module WPIN_DRY_RUN=1`), every switch off, and again with
the three switches on — the census is read from these two records; at 2, the
same dry run limited to the file's own functions (`WPIN_TARGET_FNS`), which
tells the inline wrappers' bodies (clang's `memset.inline`, glibc's `memset`)
apart; and, on clang, an independent count over the IR before any pass
(`-disable-llvm-passes`), written from this README's and the schema's words, not
from WipePin's source. Where the file has a wipe, the deletion reading:
`verdictOf` on the file with and without its wipe, and on every file stock
deleted, the xb arm read the same way.

**Checks.**

- The dry run changes nothing: the `-S` of every dry compile is byte-identical
  with stock's, 35,900 of 35,900 (the own-functions arm, 8,974 of 8,974).
- Every record is accepted: 35,900 of 35,900 by
  `../repair-loop/lib/pin-record.mjs`, and gcc's 24,095 of 24,095 by
  `../../gcc-repair/scripts/wpin_gcc_record.py`.
- Closure: nineteen comparisons between WipePin's record and the independent IR
  count — zero `llvm.memset` against `pinned`, each kind of call against its
  `unhandled` key, the barrier switches, the zero-filled stack buffers, the
  *not a stack buffer* lines. **Every comparison agrees in all 4,485 and 4,487
  clang cells.** gcc has no IR to count.
- The known values came out first: the 1,605 + 195 rows of
  `../repair-loop/data/r2-repair-rows.json` and its gcc twin, field for field
  (the `unhandled` sum is 0 in all 3,200 records of each compiler), the 251 and
  250 sites and the 209 of 360 of the plugin READMEs, and the earlier `-O2`
  deletion verdicts of ten of the eleven groups (4,734 of 4,748 the same; the
  other 14 are seven files both measurements could not read, under two names).

**Counts.** Unique files, `-O2`; "deleted" is the number of those files whose
wipe stock deleted (the six files of the next paragraph excluded).

| shape (record or IR count) | clang 18 | gcc 13 |
|---|---|---|
| a zero fill the plugin would pin, `_FORTIFY_SOURCE` undefined | 838 (deleted 412) | 705 (deleted 407) |
| the same at 2 (clang's fortified `memset` is a call, not the intrinsic) | 73 | 705 |
| a pinned site followed by a use of the buffer (initialiser-like), undefined | 334 | 259 |
| a fill whose destination is not a stack buffer of the function (heap) | 151 (deleted 31) | 147 (deleted 31) |
| a buffer the buffer barrier would cover, filled by `memset` / by a loop | 439 / 1 | 440 / 1 |
| at 2, `__memset_chk` (`memsetChk`) | 879 | 881 |
| at 2, a call to `memset.inline` (`inlineWrapperMemset`), switches off / on | 772 / 1 | 0 / 0 |
| a zeroing loop through a helper's pointer argument | 7 (deleted 0) | |
| a zeroing loop into the heap; an `invoke` | 0; 0 | |
| not counted by the plugin: zero stores outside a loop into a stack aggregate | 799 | |
| not counted: a zeroing loop over a scalar, through a volatile pointer | 998, 937 | |
| not counted: a copy from a writable zero global; a `memmove` or `mempcpy` from a zero global; a copy from a non-zero constant global | 1; 0; 132 | |

- `memsetChk` is the wrappers' bodies, all of it: 879 files in module scope, 0
  in the own-functions arm, and the IR holds no `__memset_chk` in any user
  function. `inlineWrapperMemset` is none of it (772 in both
  arms). On gcc, `memsetChk` is 881 in module scope and 0 in the
  own-functions arm.
- The 799 files with zero stores outside a loop are mostly string terminators
  (`pin[6] = '\0';`). Stock deleted the wipe of 106 of them on clang, and in
  each of five read the deleted wipe is a `memset`, not one of the stores.
- The one copy from a writable zero global is not a wipe (`auth = g_auth;`,
  a global holding an authorisation token).
- Of the four copies `../../llvm-repair/README.md` lists as not counted (from
  a writable zero global, from a local zero array, `memmove`, `mempcpy`), only
  the first occurs, once.

**The deletion reading, and the six files the repair "did not keep".** Of the
2,312 unique files with a wipe that clang 18 compiles, stock deleted the wipe
of 418 (gcc 13: 413 of 2,315); 2,173 files have no wipe. The xb arm read *kept*
in 412 of the 418 and 407 of the 413, with `_FORTIFY_SOURCE` undefined and at 2.
The other six are the same six files in all four cells, and in each the wipe
sits in a preprocessor branch this target does not compile: five inside
`#ifdef _WIN32` (four `SecureZeroMemory` calls and one `memset` that initialises
a `STARTUPINFO`), one inside `#if defined(VG_DEBUG_DUMP_SENSITIVE)`. Their text is
in the source once and in the `-E` output of either compiler zero times. With
and without it the program is the same, and `verdictOf` reads that as
*deleted*: a defect of finding the wipe in the text, not a deletion. **Without
those six, stock deleted 412 (clang) and 407 (gcc) of these files' compiled
wipes, and the xb arm kept every one.** The xb arm names the function and its
helpers (`WPIN_TARGET_FNS`); it is not the wrapper's module scope.

The reading is wrong the other way too. `verdictOf` and a count of zero writes
in the w-only lines disagree on 90 files on clang (95 on gcc) with
`_FORTIFY_SOURCE` undefined, and on 629 (608) at 2. Every one was classified by
rule and a stratified 30 per cell read by hand, the two agreeing; a second
classifier written apart from the first gave the same classes. Almost all are
wipes the count cannot see and `verdictOf` reads right — an indirect call through a volatile function pointer, to `memset` in
all but one file (86, 92), and at 2 the
`__explicit_bzero_chk` that glibc's fortified `explicit_bzero` calls (539, 513),
a name the zero-write count's call pattern misses. On clang, two files (one of
r4 L, one of `../ai-generated/`) read *kept* although their wipe is gone in the
build with it too, and gcc reads both *deleted*; so clang's 418 is short by at
least those two. It also holds at least one deletion that is not of a wipe: a
`memset` just before a `strncpy` into the same buffer, an initialisation, which
gcc reads as *kept*. Outside the disagreements neither kind was looked for.

The 39 files with a wipe whose build without it does not compile are, in 37
cases (classified by rule, 15 read by hand), the same kind of defect: the target function itself taken as a wipe
helper so that its header is cut out (26), a `(void)` cast left without its
operand (6), the same span replaced twice (4), nested spans (1).

**How often the wrapper stops a compile that needed no stopping.** Read from
the dry-run records with `vgpin-cc`'s own rule (an `unhandled` key above 0 and
not in `unhandledIgnore`, which defaults to `memsetChk` and `nonZeroFill`), over
the files whose wipe stock did not delete or that have none: **clang 18 at
`_FORTIFY_SOURCE=2` with the switches off stops 348 of 4,030** (8.6%; all on
`inlineWrapperMemset`), with the switches on 1. Undefined, and gcc 13 at either
setting: 0. The one with the switches on wipes nothing: a non-zero `memset`,
counted as `nonZeroFill` without FORTIFY and as `inlineWrapperMemset` under it,
because the fill reaches the plugin as a call to `memset.inline` — the same
shape as libsodium's below. 181 compiles of 41 distinct files were run through
the real `vgpin-cc` in strict mode and matched the reading, exit 3 or 0, in
all 181.

**`_FORTIFY_SOURCE=3` and `-g`.** At 3 every number above is the same as at 2
(418 and 413 deleted, the same six, closure 0 in all 4,487 clang cells). With
`-g`, the dry run's `-S` matches stock's on clang in every file, and on gcc in
none: gcc writes its command line into `DW_AT_producer`, and the dry run's
contains `-fplugin=`. In all 8,976 gcc pairs the code and data before the first
`.debug_` section are byte-identical, and with ` -fplugin=…` taken out of the
producer string the two listings hold the same lines. Comparing gcc `-g`
listings byte for byte needs `-gno-record-gcc-switches`.

Not measured: levels other than `-O2`; versions other than clang 18 and gcc 13;
the wrapper's module scope on the deletion reading (the xb arm names functions);
the run-time readout of these files; the deletion reading under `-g`; why two
files compile only with `_FORTIFY_SOURCE=2`.

## C++

Fifteen one-unit sources, compiled with clang++ 18 (WipePin) and g++ 13
(WipePinGcc), the plugin told the function's name, `_FORTIFY_SOURCE` undefined.
At `-O2` stock deleted 12 of the 15 wipes on clang and 11 on gcc; off and ext
kept 7 and 6, xb kept 8 and 7. `-O3` and `-Os` give the same counts. At `-O1`
stock deleted 10 on clang (off and ext kept 5, xb 6) and 8 on gcc (6, 6 and 6).

| shape | stock | kept by |
|---|---|---|
| `memset` in a destructor (the member array; `linkonce_odr`, record `exact: false`) | deleted | off, ext, xb |
| `std::memset`; `memset` after a call that may throw (with and without `-fno-exceptions`); in a lambda; in a function template | deleted | off, ext, xb |
| a loop of zero stores in a function template | deleted | xb |
| `memset` before the `std::vector<unsigned char>` is freed | deleted by clang, kept by gcc | off, ext, xb (clang) |
| `std::fill` (`int`), `std::fill` (`unsigned char`), `std::fill_n`, `std::array::fill` | deleted | **none** |
| `memset` through its own declaration with `-fno-builtin` and a cleanup (an `invoke`), and the same with `-fno-exceptions` (a `call`) | kept | — |
| `explicit_bzero` (control) | kept | — |

- The four `fill` shapes are not repaired by any arm. For `std::fill` on
  `unsigned char` and for `std::array::fill`, libstdc++ passes the fill byte
  through a variable, so the record counts a `nonZeroFill`; for the other two
  the record says there is nothing to pin.
- **`invoke`.** A wipe call becomes an `invoke` only when all three hold: a
  declaration of `memset` (or `bzero`, or `memcpy` from a zero constant) that
  is not `noexcept`, `-fno-builtin`, and a cleanup in the function. Remove any
  one and it is a `call`. WipePin counts the `invoke` and places nothing, as
  its README says; in that shape stock kept the call anyway.
- **A repaired unit can be undone at link time.** A function template's body
  is emitted in every unit that instantiates it, and the linker keeps one copy.
  With `work<32>` instantiated in two units, one compiled with WipePin (record:
  pinned 1, the unit's `work<32>` writes the zeros) and one without, linking
  `main a b` keeps the repaired copy and linking `main b a` keeps the other: the
  executable has no wipe, although the repaired unit's record and object both
  show one. Repair every unit that instantiates the template, or read the
  linked binary.

Not measured: more than one unit outside that link-order case; other C++
standard libraries; exceptions thrown at run time; compilers other than
clang++ 18 and g++ 13; the witness and the run-time readout on C++.

## LTO, with the v3 switches

`-O2`, `_FORTIFY_SOURCE` undefined, the plugin on the compile step only and the
link plain (a plugin on the link line removes the record). The verdict is
`verdictOf` on the link's output; an `objdump` reading of the linked executable
was taken beside it.

| set | compiler, form | stock deleted | kept by off | ext | xb | dry = stock |
|---|---|---|---|---|---|---|
| r4 L 52 | gcc 13, `-flto` | 51 | 51 | 51 | 51 | 52 / 52 |
| r4 L 52 | clang 18, `-flto=full` | 51 | 51 | 51 | 51 | 52 / 52 |
| r4 L 52 | clang 18, `-flto=thin` | 51 | 51 | 51 | 51 | 52 / 52 |
| E3 v2 52 | gcc 13, `-flto` | 51 | 0 | 0 | 51 | 52 / 52 |
| E3 v2 52 | clang 18, `-flto=full` | 50 | 0 | 0 | 50 | 52 / 52 |
| E3 v2 52 | clang 18, `-flto=thin` | 50 | 0 | 0 | 50 | 52 / 52 |

Every row agrees, file by file, with the same arm without LTO; the control was
PRESENT in all 52 files of every row. Each file is one unit, so no wipe helper
was inlined across units at link time.

Not measured: levels other than `-O2`; `_FORTIFY_SOURCE` 2 and 3; versions other
than clang 18 and gcc 13; a wipe helper in another unit; the plugin on the link
line; the run-time readout of LTO builds; C++ with LTO.

## Reading the secret back, on more versions

The run-time readout of `../../llvm-repair/README.md` (the secret's bytes read
from the dead stack frame after the function returns) had been taken on
clang 15, 18 and 20 and gcc 13. It was taken on clang 16, 17 and 19 and gcc 10,
11, 12 and 14, with `_FORTIFY_SOURCE` undefined and with a second setting (2 on
clang, gcc's own default on gcc), on 40 runs per version and setting (the 20
r4 L files and their 20 E5 v7 rewrites) and on 20 E3 v2 files:

| set | without repair | ext | xb |
|---|---|---|---|
| r4 L + E5 v7 (40) | read back in 40 | 0 | 0 |
| E3 v2 (20) | read back in 20 | 20 | 0 |

The same on every one of the seven versions. A 0 means the secret's bytes were
not found in that frame; registers and other copies were not examined. One of
the 20 r4 L files is the
one whose wipe `verdictOf` reads as kept on clang (`../repair-loop/README.md`);
its secret is read back nonetheless.

**`-g` changes the differential reading, not the bytes.** With `-g` added
(clang 18, and gcc 13 with its default `_FORTIFY_SOURCE=3`), the readout was the
same as without, 40 of 40 runs each. `verdictOf` was not: it changed from
*deleted* to *kept* on 26 of 40 rows on clang and 4 of 40 on gcc. Do not read
`-g` builds with `verdictOf`.

Not measured: the readout at levels other than `-O2`, on the loops a model
wrote, on C++ and on LTO builds.

## A real build through the wrapper

QuickJS 2020-11-08, built with `CC` set to `../../pin-wrapper/vgpin-cc` for
clang 18 and gcc 13, with the repair's switches off (`wrap`) and on (`all`), in
`warn` and `strict` mode: every build compiled and linked (14 wrapper
invocations per build, 0 refused), and the 11 scripts of `make test` exit 0 in
every build, as in the stock build. The `qjs` binary's `.text` is 96 bytes larger
than stock's with clang 18 and 96 bytes smaller with gcc 13, the same in all
four arms; why was not read, and neither was the number of repairs placed, so
this is not a measurement of the repair's cost. What it measures is that the
wrapper builds this project and its tests pass.

libsodium 1.0.22, measured 2026-11-23 the same way (`./configure
--disable-shared`, whose own flags are `-O3` and `-D_FORTIFY_SOURCE=3`, then
`make` and `make check`, which compiles 101 test programs as well). libsodium
wipes through its own `sodium_memzero`; it is not a repair target, so this
counts what the wrapper does to a project, not repairs.

| compiler | arm | builds | `make check` | `libsodium.a` `.text` | stopped |
|---|---|---|---|---|---|
| clang 18 | stock | yes | 101/101 | 478,108 | — |
| clang 18 | wrap, warn | yes | 101/101 | 478,188 | 0 |
| clang 18 | wrap, strict | no | — | — | 79 (40 library, 39 test) |
| clang 18 | all, warn | yes | 101/101 | 480,488 | 0 |
| clang 18 | all, strict | no | — | — | 33 (8 library, 25 test) |
| gcc 13 | stock | yes | 101/101 | 442,463 | — |
| gcc 13 | wrap, warn | yes | 101/101 | 442,654 | 0 |
| gcc 13 | wrap, strict | library yes | test build fails | 442,654 | 1 (test) |
| gcc 13 | all, warn / strict | yes | 101/101 | 442,654 | 0 |

- The four gcc wrapper arms produce the same `libsodium.a`, byte for byte.
  The clang stock and *wrap, warn* builds, and the stops of *wrap, strict*, are
  those of a first run on 2026-11-11 (stopped there after three arms), to the
  byte.
- **clang 18's strict stops are all `inlineWrapperMemset`**, and with every
  switch on most of them are not wipes. Of the 33 compiles still stopped, 28
  count exactly as many calls as the file has `memset` calls with a non-zero
  constant value (HMAC's pads, `memset(pad, 0x36, 64)` and `0x5c`, among them);
  four more call `memset` with a variable fill (`argon2-core.h`,
  `memset(b->v, in, …)`).
  Under clang's FORTIFY such a call reaches the plugin as a call to
  `memset.inline`, which the record counts in `inlineWrapperMemset`, not in
  `nonZeroFill`, so `unhandledIgnore` cannot pass it and strict stops a file
  that has nothing left to repair. The census above finds the same shape once.
  The 33rd (`aead_aes256gcm_aesni.c`, three zero `memset` calls, six barriers,
  `inlineWrapperMemset` 2 left) was not read.
- gcc 13's one stop is a test (`core_keccak1600.c`): a copy from a zero
  constant global, `zeroGlobalCopy`, which the switches off leave unhandled;
  with them on, strict builds the library and passes 101/101.

Not measured: why the clang wrapper arms are 80 and 2,380 bytes larger.

## The gcc pass-disable channel

`../repair-loop/tools/intervene.mjs --cc gcc-13` had never been run. It was run
once; the result is in `../repair-loop/PIN-FAMILIES.md` (*gcc — run once, the
wipe never came back*), and the row in `../repair-loop/pin-families.json` now
says so. It stays `unmeasured`.

## Two readers, and a witness

- `../repair-loop/tools/lib/asm-zero-writes.mjs` counts zero writes in an AT&T
  listing per function and per frame offset, including stores through a
  register zeroed in the same block, `rep stos` with a zero accumulator, and
  vector stores of a zeroed register. `../repair-loop/tools/lib/ir-pin-reading.mjs`
  counts, per function, WipePin's barriers and volatile zero memsets in
  optimised IR, and WipePinGcc's in gcc's `-fdump-tree-optimized` text. Neither
  is used by `verdictOf` or by any verdict; they are a second and third reading
  for the lab. Their tests are under `../repair-loop/test/`.
- `../../wipe-witness/` is a plugin that counts what is left of WipePin's
  repairs at the end of the pipeline and reports a function whose repair is
  gone. Its README has its rule, what it cannot see, and its measurements.
