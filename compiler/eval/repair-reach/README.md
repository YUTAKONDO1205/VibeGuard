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
clang 18.1.3 and gcc 13.3.0, `_FORTIFY_SOURCE` undefined. The scripts, the
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
| xb | the plugin with `WPIN_BUFFER_BARRIER=1` |
| dry | `WPIN_DRY_RUN=1` (records, changes nothing) |

## Optimisation levels

The r4 L files (52; at `-O2` stock deletes 51 of them, the files the plugin
READMEs measure), E3 v2 (52 machine-made rewrites of the same wipes as loops of
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
  wipe), read by hand in the lab notes.
- The ext arm keeps none of E3 v2 at any level: it pins `memset`, and a loop of
  stores has none. Only the buffer barrier keeps a loop.

Not measured: the other nine versions at `-O1`, `-O3` and `-Os` (started, not
finished); `-Og` and `-Oz`; the same table with `-D_FORTIFY_SOURCE=2` and `3`
(run, not summarised here).

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

## C++

Fifteen one-unit sources, compiled with clang++ 18 (WipePin) and g++ 13
(WipePinGcc), the plugin told the function's name. At `-O2` stock deleted 12 of
the 15 wipes on clang and 11 on gcc; off and ext kept 7 and 6, xb kept 8 and 7.
`-O1`, `-O3` and `-Os` give the same pattern.

| shape | stock | kept by |
|---|---|---|
| `memset` in a destructor (the member array; `linkonce_odr`, record `exact: false`) | deleted | off, ext, xb |
| `std::memset`; `memset` after a call that may throw (with and without `-fno-exceptions`); in a lambda; in a function template | deleted | off, ext, xb |
| a loop of zero stores in a function template | deleted | xb |
| `memset` before the `std::vector<unsigned char>` is freed | deleted by clang, kept by gcc | off, ext, xb (clang) |
| `std::fill` (`int`), `std::fill` (`unsigned char`), `std::fill_n`, `std::array::fill` | deleted | **none** |
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
standard libraries; exceptions thrown at run time.

## LTO, with the v3 switches

The plugin on the compile step only, the link plain (a plugin on the link line
removes the record), read in the linked executable with `objdump`.

| set | compiler, form | stock deleted | kept by off | ext | xb | dry = stock |
|---|---|---|---|---|---|---|
| r4 L 52 | gcc 13, `-flto` | 51 | 51 | 51 | 51 | 52 / 52 |
| r4 L 52 | clang 18, `-flto=full` | 51 | 51 | 51 | 51 | 52 / 52 |
| r4 L 52 | clang 18, `-flto=thin` | 51 | 51 | 51 | 51 | 52 / 52 |
| E3 v2 52 | gcc 13, `-flto` | 51 | 0 | 0 | 51 | 52 / 52 |
| E3 v2 52 | clang 18, `-flto=full` | 50 | 0 | 0 | 50 | 52 / 52 |
| E3 v2 52 | clang 18, `-flto=thin` | 50 | 0 | 0 | 50 | 52 / 52 |

Every row agrees, file by file, with the same arm without LTO; the control was
PRESENT in all 52 files of every row.

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

The same on every one of the seven versions. One of the 20 r4 L files is the
one whose wipe `verdictOf` reads as kept on clang (`../repair-loop/README.md`);
its secret is read back nonetheless.

**`-g` changes the differential reading, not the bytes.** With `-g` added
(clang 18, and gcc 13 with its default `_FORTIFY_SOURCE=3`), the readout was the
same as without, 40 of 40 runs each. `verdictOf` was not: it changed from
*deleted* to *kept* on 26 of 40 rows on clang and 4 of 40 on gcc. Do not read
`-g` builds with `verdictOf`.

Not measured: the readout at levels other than `-O2`, and on the loops a model
wrote.

## A real build through the wrapper

QuickJS 2020-11-08, built with `CC` set to `../../pin-wrapper/vgpin-cc` for
clang 18 and gcc 13, with the repair's switches off (`wrap`) and on (`all`), in
`warn` and `strict` mode: every build compiled and linked (14 wrapper
invocations, 0 refused), and the 11 scripts of `make test` exit 0 in every
build, as in the stock build. The `qjs` binary's `.text` is
96 bytes larger than stock's with clang 18 and 96 bytes smaller with gcc 13, the
same in all four arms. QuickJS has no secret wipe this repairs; what this
measures is that the wrapper builds a real project and refuses nothing it
should not.

Not measured: libsodium (started, not finished), build time, run time.

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
