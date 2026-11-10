# compiler/pin-wrapper — `vgpin-cc`

**This wrapper changes the compile on purpose.** It puts a repair plugin
(`WipePin`, `../llvm-repair/`, for clang; `WipePinGcc`, `../gcc-repair/`, for
gcc) into every compile it runs, and it is meant to sit where a build names its
compiler: `CC=vgpin-clang-18 make`. Nobody who calls it — a person, a code
generator, `make` — needs to know the plugin's name, its environment variables,
or which functions hold a wipe.

It is an interlock, not the confirm step. The plugins fail open: without
`WPIN_OUT` or a target they print `refusing to install`, exit 0 and leave the
stock code (`../llvm-repair/README.md`, *The silent failures*). The wrapper
makes that impossible to miss: it pins the plugin by sha256 and by the compiler
major version it was built for, configures it itself, reads the record the
plugin writes, and withholds the output when the record does not show the
repair installed. What the record says is still the plugin's account of what it
did to the IR — never whether the wipe reached the object file. That is decided
by comparing assembly, and the numbers under *Measured* were decided that way,
not by this wrapper.

Python 3 standard library only, one file, no network. Written from a
prototype, `vgpin_cc.py`, kept with lab notes outside this repository, with the
pin moved out of the code into a file and the command-line rules re-decided by
measurement (below).

## What it does, in order

1. **Classify the command line.** Response files (`@file`) are expanded for
   this step only, with the tokenizer rules of `../driver/lib/cmdline.mjs`; the
   compiler always gets the caller's arguments as written. A response file that
   cannot be read, includes itself, or nests deeper than 16 is exit 5.
2. **Pass through or refuse** the shapes in *Command lines* below, before
   anything else is read.
3. **The pin.** Read the pins file named by `VGPIN_PINS`. Run
   `<compiler> --version` and read the family and major version from it. Pick
   the pin with that family and major; if there is none, stop (exit 4). Hash
   the plugin and compare with the pin's sha256; a difference is exit 4. The
   compiler has not compiled anything at this point.
4. **Compile** with the plugin flag (`-fpass-plugin=` / `-fplugin=`) in front of
   the caller's arguments, `WPIN_OUT` pointing into a fresh temporary
   directory, `WPIN_SCOPE=module` (every function of the unit: no function
   names are passed), and the pin's own switches. Every `WPIN_*` variable from
   the caller's environment is removed first, on every path, passed-through
   ones included. stdout and stderr are inherited, so the compiler's and the
   plugin's lines arrive unchanged.
5. **Read the record** (*The record* below). If the compiler failed, its exit
   code is returned and nothing is read.
6. **Decide.** No problem: exit 0. A problem: print each one with a `vgpin:`
   prefix and, under `VG_PIN_MODE=strict` (the default), rename the output to
   `<output>.vgpin-rejected` and exit 3; under `warn`, keep the output and
   exit 0.

## Installing and calling

The tracked file's executable bit is not relied on (a checkout on some
machines does not keep it; `../driver/cli/` has the same property), so install
a copy:

```sh
install -m 755 compiler/pin-wrapper/vgpin-cc ~/bin/vgpin-cc
ln -s vgpin-cc ~/bin/vgpin-clang-18          # the name after vgpin- is the compiler
ln -s vgpin-cc ~/bin/vgpin-gcc-13
VGPIN_PINS=~/vgpin/pins.json CC=~/bin/vgpin-clang-18 make
```

The compiler is `VG_PIN_CC` if set, otherwise the part of the program name
after `vgpin-` (so `vgpin-cc` itself runs `cc`). A compiler that resolves to the
wrapper is exit 4.

| variable | |
|---|---|
| `VGPIN_PINS` | path of the pins file. Required for a compile; not read for a passed-through line |
| `VG_PIN_MODE` | `strict` (default) or `warn`. Anything else is exit 4 |
| `VG_PIN_CC` | the compiler to run, instead of the name after `vgpin-` |
| `VG_PIN_REQUIRE_REPAIR` | `1`: a unit in which nothing was repaired is a problem (default `0`, below) |
| `VG_PIN_RECORD_DIR` | copy each record there as `<basename of the output>.wipe-pin.json` |
| `VG_PIN_VERBOSE` | `1`: one line per compile saying what the record held |

The three switches are `0` or `1` and nothing else (exit 4 otherwise): a
misspelt value read as off would turn a check off without anyone deciding it,
the same rule the plugins apply to `WPIN_DRY_RUN`.

## The pins file

`pins.example.json` is the shape. As it stands it is refused (exit 4): its
sha256 values are placeholders.

| key | |
|---|---|
| `schemaVersion` | `"vgpin-pins-v1"` |
| `pins[]` | one entry per plugin: `family` (`clang` or `gcc`), `compilerMajor` (positive integer: the major version of the compiler the plugin was built for), `plugin` (path; a relative one is read against the pins file's directory), `sha256` (64 lowercase hex digits), optional `env`, optional `comment` |
| `pins[].env` | plugin switches to set, `WPIN_*` names only, values `"0"` or `"1"`. `WPIN_OUT`, `WPIN_SCOPE`, `WPIN_TARGET_FNS` and `WPIN_DRY_RUN` belong to the wrapper and are refused here |
| `unhandledIgnore` | `unhandled` counters that do not stop a compile. Default `["memsetChk", "nonZeroFill"]` |
| `comment` | free text |

Every key is checked and an unknown one is refused, as is a second pin for the
same family and major. Several majors of one family can be pinned side by side;
the one matching `--version` is used.

**Why `memsetChk` is ignored by default.** In module scope it also counts the
`__memset_chk` inside the fortifying wrapper's own body (clang's
`memset.inline`, gcc's `memset` wrapper), so it is non-zero in compiles whose
wipe survived: measured, gcc-13 at its default `_FORTIFY_SOURCE=3` and at `=2`,
`memsetChk` ≥ 1 in 51/51 records of files whose wipe survived (*Measured*). Had
it stopped the compile, every one of those would have been refused. The cost is
named under *What it does not do*. `nonZeroFill` is a fill that is not zero, so
not a wipe.

## Command lines

Measured on clang-18.1.3 and gcc-13.3.0 with both plugins loaded directly
(not through the wrapper), 2026-11-05:

| shape | decision | why |
|---|---|---|
| `--version`, `-dumpversion`, `-dumpmachine`, `-###`, `--help` | pass through | with a source and `-c -o` beside them, neither compiler wrote an object (5 flags × 2 compilers) |
| `-E`, `-M`, `-MM`, `-fsyntax-only` | pass through | no code generation; with either plugin loaded, none of the four wrote a record (nor did `-c` of a `.S`) |
| no C/C++ source: a link, an assembly (`.s`, `.S`), headers, nothing | pass through | nothing for the plugin; an LTO link gets neither the plugin nor `WPIN_OUT` — an LTO link that loads WipePin removes the file at `WPIN_OUT` (`../llvm-repair/README.md`, *The link-time line*) |
| `-v` with a source | compile with the plugin | it compiles: both compilers wrote the object. (The prototype passed `-v` through, which compiled without the plugin.) |
| one source (`.c`, `.i`, C++, Objective-C, `.ll`/`.bc`, or anything after `-x <lang>`), incl. `-MD`/`-MF` beside it | compile with the plugin | |
| standard input (`-x c -`) | one source | both compilers name the output `-.o` / `-.s`; the record's `module` is `-` (clang) or `<stdin>` (gcc) |
| `-flto -c` | compile with the plugin | both plugins write a valid record at the compile step (`../llvm-repair/README.md`, `../gcc-repair/README.md`) |
| `-flto` compile **and link** on one line, clang | compile with the plugin | clang 18.1.3 does not pass `-fpass-plugin=` to the link (`-###`), and the record survived with the default linker and lld, `-flto` and `-flto=thin` (4/4) |
| `-flto` compile **and link** on one line, gcc | **exit 5**, compiler not run | gcc loads the plugin into `lto1` too, which refuses twice and removes the record (`-flto`, `-flto=auto`: no record) |
| two or more inputs to compile (sources, or a source with an assembly or header input) | **exit 5**, compiler not run | each process deletes `WPIN_OUT` when it loads the plugin and writes at the end, so only the last unit's record is left (both repair READMEs, *The silent failures*). An assembly input counts: on gcc-13 the `.S` step removed a file at `WPIN_OUT`, and `-c t.c a.S` left no record; clang-18 kept `t.c`'s. One rule for both |
| `-o -` on a compile | **exit 5**, compiler not run | an output already on a pipe cannot be withheld |
| a response file it cannot read | **exit 5** | the line could not be classified |

`warn` does not change any exit 5 or exit 4: those are decided before the
compiler runs.

## The record

It accepts **`wipe-pin-v3` only** (`../schema/wipe-pin.md` §14), the rule
§14.10 gives every reader. Decided on 2026-11-09, when the v3 writers landed in
both plugins: until then the wrapper also took `wipe-pin-v2`, so that the
plugins built from `22e7222` could be pinned. A v2 record carries no `host`
block, so on it the version check would rest on `toolchain.<compiler>` alone,
and reading two versions is the tolerance §14.10 rules out. The cost: a plugin
built from `22e7222` or earlier is refused on every compile (exit 3, *the
record is 'wipe-pin-v2', not one of wipe-pin-v3*); build the plugins from this
tree. Within v3 it reads loosely on purpose and looks only at the fields its
decision needs. It is **not** a schema reader — it does not re-derive `evidenceDigest`
or apply §11/§14.9; `../eval/repair-loop/lib/pin-record.mjs` and
`../gcc-repair/scripts/wpin_gcc_record.py` do. A field it needs that is missing
or of the wrong type is a problem, never a pass. The problems:

- no record (the plugin refused to install — its line is printed above — or
  its pass never ran, or the record could not be written; schema §12: a refusal
  writes no record), or a record that is not JSON;
- a `schemaVersion` other than `wipe-pin-v3`, a `component` other than the
  family's, `scope` other than `module`, `dryRun` not `false`;
- `toolchain.<family>` (the version the plugin was built against) whose major
  is not the compiler's; no `host` object, or a `host.identMajor` or
  `host.builtMajor` that is not the compiler's major. `host.checked: false` (a
  module with no `llvm.ident`) is **not** a problem (schema §14.7);
- an eligible site left unrepaired: `wouldPinCount` > `pinnedCount`,
  `barrierCalls.wouldBarrierCount` > `barrierCount`,
  `zeroCopy.wouldRepairCount` > `repairedCount`;
- a pin that turns a switch on (`WPIN_BARRIER_CALLS`, `WPIN_ZERO_COPY`,
  `WPIN_BUFFER_BARRIER`) and a record without its block (`barrierCalls`,
  `zeroCopy`, `bufferBarriers`) — a writer that does not know the switch
  ignores the variable — or whose block says `enabled: false`;
- any `unhandled` counter above 0 that is not in `unhandledIgnore`, including
  one this wrapper has never heard of (v3's `bzeroCall`, `inlineWrapperBzero`,
  `zeroGlobalCopy`, `zeroGlobalCopyCall` among them);
- with `VG_PIN_REQUIRE_REPAIR=1`, nothing repaired: `pinnedCount` +
  `barrierCalls.barrierCount` + `zeroCopy.repairedCount` +
  `bufferBarriers.count` is 0 (schema §14.8).

**Nothing to pin is not a problem by default.** A unit with no zero-fill
memset and nothing counted in `unhandled` — most files of a real project —
passes: the plugin prints its `nothing to pin` line and the wrapper exit 0. The
wrapper cannot write a wipe the source does not have, and refusing every such
file would make it unusable as `CC`. For a unit known to hold a wipe,
`VG_PIN_REQUIRE_REPAIR=1` turns "nothing repaired" into exit 3.

**Why rename rather than delete.** Strict must never leave an unverified output
at the path the build expects: `make` treats an existing target as up to date
on the next run. Renaming to `<output>.vgpin-rejected` clears the path (the next
`make` rebuilds), keeps the bytes for inspection, and the suffix keeps the file
out of `*.o`-style globs. If the rename fails the output is removed, and if that
fails too the wrapper says so and still exits 3. Only a regular file or a
symlink (the link itself) is moved: `-o /dev/null` is a configure-script idiom,
and a wrapper running as root must not move a device node (measured below).
Intermediate files (`-save-temps`, a `.d` from `-MD`) are left alone.

## Exit codes

| exit | meaning | compiler run? | output |
|---|---|---|---|
| `0` | the record shows the repair installed and nothing left alone; or the line was passed through; or `warn` | yes | kept |
| the compiler's | it failed; a compiler killed by signal *n* is 128+*n*. The record is not read | yes | as the compiler left it |
| `3` | compiled, and the record does not show the repair (*The record*); strict | yes | renamed to `<output>.vgpin-rejected` |
| `4` | configuration: `VGPIN_PINS` unset or not a valid pins file, no pin for this family and major, a `--version` it cannot read, the plugin missing or with another sha256, a switch that is not `0`/`1`, the compiler not found | no (`--version` only) | none |
| `5` | a command line it does not verify (*Command lines*) | no | none |

A compiler can itself exit 3, 4 or 5 (gcc's internal compiler error is 4). The
wrapper's own refusals always print a `vgpin:` line; a compiler failure arrives
with the compiler's diagnostics and no `vgpin:` line.

## How it differs from the driver

`../driver/` (`vgcc`) is the opposite on purpose. Its shipping build gets the
caller's argv verbatim; anything it adds for itself runs as a separate
invocation; it never loads the repair plugin, and checks plugins only by
digest (`plugin-integrity`). It answers "is this build what the policy says".
`vgpin-cc` answers "was the repair plugin in this compile, and did it say it
repaired what it saw" — so it adds the plugin to the very compile whose output
the caller keeps. Neither is a substitute for the other, and neither runs the
other. They share one rule for one reason: the driver's `policy.fallback`
refuses an invocation with more than one source (`multi-source-invocation`)
because the translation unit is the granularity, and so does this wrapper.

## What it does not do

- **Decide whether a wipe survived.** That is the confirm step's question
  (compare assembly). The wrapper reads a record.
- **See what the plugin was not configured to see.** With a pin whose `env`
  leaves `WPIN_BUFFER_BARRIER` unset, a wipe written as stores (a zeroing loop)
  leaves "nothing to pin", which passes: on E3 v2 every loop wipe stock deleted
  passed silently (50 on clang-18, 51 on gcc-13; *Measured*, 2026-11-10). With
  `WPIN_BUFFER_BARRIER=1` in the pin's `env`, the plugin puts a barrier before
  the end of each such buffer's lifetime instead (`../schema/wipe-pin.md`
  §14.6), the record counts it in `bufferBarriers.count`, and the wrapper counts
  that as a repair: on the same files every one was kept (50/50, 51/51), in
  module scope, at `-O2`, on those machine-made rewrites only. Under clang's
  `_FORTIFY_SOURCE` that pin alone does not pass a unit that holds a fortified
  `memset` call: strict stops it on `inlineWrapperMemset` unless the pin also
  sets `WPIN_BARRIER_CALLS=1` (measured: r4 L 51/51 stopped, E3 v2 2). Either
  way, a wipe inside a helper in another unit, a call through a function
  pointer, and a loop into memory that is not a stack buffer of the function
  leave nothing for the plugin. It cannot add a wipe the source does not have.
- **Catch a `memsetChk` wipe by default.** Because `memsetChk` is ignored (see
  *The pins file*), a gcc `__builtin___memset_chk` whose size is not a constant
  — counted in `memsetChk` and not pinned by the plugins at `22e7222` — passes
  unrepaired unless the plugin is given `WPIN_BARRIER_CALLS=1` (v3, schema
  §14.4) or the pins file stops ignoring `memsetChk`. Not measured through the
  wrapper on that shape: the v3 run under *Measured* reads `memsetChk` ≥ 1 in
  every FORTIFY row with the switch on as well, and does not say which call
  each count is.
- **Work with the `22e7222` plugins.** They write `wipe-pin-v2`, which this
  wrapper refuses (*The record*).
- **Stop a hang or a crash from a mis-declared pin.** The `--version` check is
  only as good as `compilerMajor`. A pin that claims the wrong major is caught
  afterwards, when the plugin loads: with the v3 plugins built from this tree,
  WipePin's version handshake (schema §14.7) refused to install on clang-19 and
  on clang-17, wrote no record, and the wrapper withheld the output (exit 3;
  measured once each, below). With the `22e7222` plugin the same pins were
  caught by `toolchain.clang` on clang-19 and not at all on clang-17, where
  clang aborted in the plugin (exit 134, returned as is). A plugin that crashes
  before its pass runs is not caught, and there is no timeout.
- **Anything at link time**, C++ (treated as a source, not measured), targets
  other than x86-64 Linux, and builds that call the compiler without going
  through `CC`.
- **Cost.** `WPIN_SCOPE=module` also pins initialisers (`= {0}`); the buffer
  barrier, when the pin turns it on, is not placed on a buffer that is only
  initialised (`../schema/wipe-pin.md` §14.6). The effect on speed or size was
  not measured.

## Tests

```sh
python3 compiler/pin-wrapper/test/test_vgpin_parse.py   # 29 tests: tokenizer, classifier, version, pins, record, withhold
python3 compiler/pin-wrapper/test/test_vgpin_cc.py      # 69 tests: end to end against a fake compiler
```

Run as files (the directory name has a hyphen). No compiler or plugin is
needed: `test/vgpin_fakes.py` writes a fake `clang-18`/`gcc-13`/… into a
temporary directory, whose `--version` prints the real compilers' first lines,
and a "plugin" is a JSON file telling the fake compiler which record to write
(or to refuse). POSIX only; CI runs them on Linux. The record examples of
`../schema/wipe-pin.md` §14.11 are read as they are written there.

Before trusting them, each of 12 deliberate breakages of the wrapper (the major
ignored when picking a pin, `inlineWrapperMemset` ignored, two sources allowed,
the caller's `WPIN_*` kept, withholding disabled, `-v` passed through, sha256 not
compared, `toolchain` not compared, the gcc LTO line allowed, `warn` ignored, no
record accepted, the switch check off) made at least one test fail (measured
once, on copies outside this tree).

## Measured

### With the final `wipe-pin-v3` builds, 2026-11-10

WSL Ubuntu 24.04, the same compilers, python3 3.12.3, node v18.19.1. Plugins
built from this tree as it stood on the morning of 2026-11-10:
`libWipePin.so` (clang-18) `8f2bd520…`, `libWipePinGcc.so` (gcc-13)
`10fc7a00…`. The same runs with the builds of the current source (`7c9d11f2…`,
`ea3e8c7e…`, the builds that recorded the tracked repair-loop rows,
`../eval/repair-loop/data/r2-v3-rerecord.json`) gave the same table, the same
smoke result and the same refusal of a v2 record (lab notes).
The wrapper as it is now (v3 only), sha256 `6908066f…`. The scripts and data
are lab notes kept outside this repository. Four pins per compiler: *wrap*
(no `env`), *wrapBZ* (`WPIN_BARRIER_CALLS=1 WPIN_ZERO_COPY=1`), *wrapBB*
(`WPIN_BUFFER_BARRIER=1`) and *wrapAll* (all three). Two sets: the 51 r4 L
files of the runs below, and E3 v2 — the same corpus's 52 files with each wipe
rewritten by machine as a loop of zero stores, all 52 with one template (an
index loop over the buffer with a constant bound; no other form of loop wipe is in the
set) (50 of them deleted by stock
clang-18, 51 by stock gcc-13, in every setting). Readings, settings and
strict mode as below; where strict stopped a compile, the line was re-run
under `warn` to read the assembly, so a cell can be both kept and stopped.
Module scope throughout, as the wrapper always compiles.

r4 L (kept of the 51 stock deleted; stopped):

| compiler | `_FORTIFY_SOURCE` | stock | wrap | wrapBZ | wrapBB | wrapAll |
|---|---|---|---|---|---|---|
| clang-18 | none | 0/51 | 51/51 | 51/51 | 51/51 | 51/51 |
| clang-18 | `=2` | 0/51 | 0/51, stopped 51 | 51/51 | 51/51, stopped 51 | 51/51 |
| clang-18 | `=3` | 0/51 | 0/51, stopped 51 | 51/51 | 51/51, stopped 51 | 51/51 |
| gcc-13 | default (3), `-U`, `=2` | 0/51 | 51/51 | 51/51 | 51/51 | 51/51 |

E3 v2 (kept of those stock deleted; stopped; passed silently = exit 0 with
the wipe deleted):

| compiler | `_FORTIFY_SOURCE` | stock | wrap | wrapBZ | wrapBB | wrapAll |
|---|---|---|---|---|---|---|
| clang-18 | none | 0/50 | 0/50, silently 50 | 0/50, silently 50 | **50/50** | **50/50** |
| clang-18 | `=2` | 0/50 | 0/50, stopped 2, silently 48 | 0/50, silently 50 | **50/50**, stopped 2 | **50/50** |
| clang-18 | `=3` | 0/50 | 0/50, stopped 2, silently 48 | 0/50, silently 50 | **50/50**, stopped 2 | **50/50** |
| gcc-13 | default (3), `-U`, `=2` | 0/51 | 0/51, silently 51 | 0/51, silently 51 | **51/51** | **51/51** |

Every record the wrapper read was `wipe-pin-v3`, and no control was other than
`PRESENT`. The two readings disagreed only on 2 files of E3 v2 on clang-18, in
stock and in the arms without the buffer barrier; with it, in none. The r4 L
cells of *wrap* and *wrapBZ* are the same as the earlier runs' *wrap* and
*wrapB*, 18 of 18. A loop wipe passes silently unless the pin sets
`WPIN_BUFFER_BARRIER=1`, and with it every loop wipe stock deleted was kept.
Under clang's FORTIFY, a pin that sets only `WPIN_BUFFER_BARRIER=1` is still
stopped by strict wherever the unit holds a fortified `memset` call — every
r4 L file, and 2 of E3 v2 — because that call is counted in
`inlineWrapperMemset` until `WPIN_BARRIER_CALLS=1` repairs it; *wrapAll* was
stopped nowhere. `memsetChk` was ≥ 1 in 51/51 records of every FORTIFY row of
r4 L on both compilers, in every arm. The single cases below, repeated with
these builds: 36/36 as expected. A plugin built from `22e7222` (it writes
`wipe-pin-v2`), pinned and run: exit 3 on clang-18 and on gcc-13, the output
renamed, `the record is 'wipe-pin-v2', not one of wipe-pin-v3`.

All of it is `-O2`, module scope, two compilers and two sets of files, one of
them machine-made rewrites; no loop a model wrote was measured.

### With the first `wipe-pin-v3` builds, 2026-11-09

WSL Ubuntu 24.04, the same compilers, python3 3.12.3, node v18.19.1. Plugins
built from this tree before the fixes of 2026-11-09 evening (the barrier's
placement, initialisers left out, the third handshake check; superseded by the
builds above): `libWipePin.so` sha256 `b509c308…`, `libWipePinGcc.so`
`ce1f515a…`. The wrapper as it is now (v3 only), sha256 `6908066f…`. The run
below the next heading, repeated with these builds: the same 51 files, the same
two readings, the same three `_FORTIFY_SOURCE` settings per compiler, with the
arm *wrap* (a pin with no `env`) and the arm *wrapB* (a pin whose `env` sets
`WPIN_BARRIER_CALLS=1` and `WPIN_ZERO_COPY=1`).

| compiler | `_FORTIFY_SOURCE` | stock | wrap | stopped | wrapB | stopped | passed silently |
|---|---|---|---|---|---|---|---|
| clang-18 | none | 0/51 | **51/51** | 0 | **51/51** | 0 | 0 |
| clang-18 | `=2` | 0/51 | 0/51 | **51** | **51/51** | 0 | 0 |
| clang-18 | `=3` | 0/51 | 0/51 | **51** | **51/51** | 0 | 0 |
| gcc-13 | default (3) | 0/51 | **51/51** | 0 | **51/51** | 0 | 0 |
| gcc-13 | `-U` (none) | 0/51 | 51/51 | 0 | 51/51 | 0 | 0 |
| gcc-13 | `=2` | 0/51 | 51/51 | 0 | 51/51 | 0 | 0 |

Every record the wrapper read was `wipe-pin-v3` (306 per compiler), the two
readings disagreed in 0 rows, and no control was other than `PRESENT`. The
cells the earlier run has (the gcc-13 *wrapB* rows are new) are the same, 15 of
15. Under clang's FORTIFY, *wrap* stopped every compile and *wrapB* kept every
wipe: the v3 WipePin puts a barrier after the `memset.inline` call when the pin
turns `WPIN_BARRIER_CALLS` on. `memsetChk` was ≥ 1 in 51/51 records of every
FORTIFY row of both compilers, *wrapB* included, so in module scope the switch
does not clear that counter (the default `unhandledIgnore` is why those rows
pass; what the counter counts there is not established here). The single cases
(36/36 as expected) are the ones listed below, with one change: the clang-18
plugin pinned as `compilerMajor` 19 and as 17 was refused by WipePin's version
handshake in both (no record, exit 3), where the `22e7222` plugin ran on
clang-19 and aborted clang-17. Nothing here sets `WPIN_BUFFER_BARRIER`.

### With the `22e7222` plugins, 2026-11-05

2026-11-05, WSL Ubuntu 24.04, Ubuntu clang 18.1.3 (1ubuntu1), gcc-13 (Ubuntu
13.3.0-6ubuntu2~24.04.1) 13.3.0, python3 3.12.3, node v18.19.1. Plugins built
from `22e7222`: `libWipePin.so` sha256 `db3298cf…`, `libWipePinGcc.so`
`a023b047…`. Measured with the wrapper as it was then, which read
`wipe-pin-v2`; the wrapper as it is now refuses these plugins' records, so this
run cannot be repeated with it.

**The 51 files.** The r4 L files whose wipe `-O2` deleted (clang-18 51: 30 with
no extra instruction to the model; gcc-13 51: 29), the same set and the same
reading as the prototype's measurement: a wipe *survived* when the stock differential
verdict (`../eval/ai-generated/lib/ablation-cell.mjs`, `verdictOf`) says
`WIPE_SURVIVED` with its control `PRESENT`, **and** an independent read of the
assembly finds a zero-writing instruction only in the build with the wipe.
Through the wrapper under strict; where it stopped, the line was re-run under
`warn` to read the assembly. *Stopped* is exit 3; *passed silently* is exit 0
with the wipe not surviving.

| compiler | `_FORTIFY_SOURCE` as defined by the compiler | stock | wrapper | stopped | passed silently |
|---|---|---|---|---|---|
| clang-18 | none | 0/51 | **51/51** | 0 | 0 |
| clang-18 | `-D_FORTIFY_SOURCE=2` → 2 | 0/51 | 0/51 | **51** | **0** |
| clang-18 | `-D_FORTIFY_SOURCE=3` → 3 | 0/51 | 0/51 | **51** | **0** |
| gcc-13 | default → 3 | 0/51 | **51/51** | 0 | 0 |
| gcc-13 | `-U_FORTIFY_SOURCE` → none | 0/51 | 51/51 | 0 | 0 |
| gcc-13 | `-U… -D_FORTIFY_SOURCE=2` → 2 | 0/51 | 51/51 | 0 | 0 |

The two readings disagreed in 0 rows and no control was other than `PRESENT`.
Every cell equals the measurement of the prototype wrapper (15/15 cells,
including the arm below). Under clang's FORTIFY the stopped compiles were the
`inlineWrapperMemset` counter (the 22e7222 WipePin leaves a call to
`memset.inline` alone); `memsetChk` was ≥ 1 in 51/51 of them and in 51/51 of
gcc-13's default and `=2` rows, where the wipe survived.

With a pin whose `env` sets `WPIN_BARRIER_CALLS=1` on a prototype WipePin that
implements it (r5, sha256 `c865e64c…`, **not in this tree**), clang-18 kept
51/51 in all three configurations and stopped none. That is a reading of the
wrapper's `barrierCalls` handling on real records, not a measurement of the
plugin this tree will ship.

**Single cases** (one file of the same shape; 36/36 as expected):
`vgpin-clang-17` and `vgpin-clang-19` with only a clang-18 pin, and
`vgpin-gcc-12` with only a gcc-13 pin: exit 4, no output. A pins file that
declares the clang-18 plugin as `compilerMajor` 19, called as clang-19: the
plugin loaded, printed `nothing to pin`, clang exited 0, and the wrapper exited
3 on `toolchain.clang` 18.1.3. The same plugin declared as 17 and called as
clang-17: clang-17 aborted in the plugin (exit 134), returned as is. Two sources:
exit 5, no object. gcc `-flto` compile and link: exit 5; clang: exit 0 and a
linked program. `-v` with a source: the wipe kept. Standard input, a response
file, a link-only line, `--version` without `VGPIN_PINS`, `-fsyntax-only`: as
in the table above. A file with no wipe: exit 0, and exit 3 with
`VG_PIN_REQUIRE_REPAIR=1`. `-o /dev/null` under a FORTIFY refusal: exit 3 and
`/dev/null` still a character device.

**Not measured in this run:** a pin whose `env` sets `WPIN_BUFFER_BARRIER=1`
(what it does through the wrapper, in module scope, over the 51 files or the
loop rewrites; measured since, with the final builds, 2026-11-10 above);
the v3 plugins for compilers other than clang-18 and gcc-13 through the
wrapper; C++; any compiler other than those named; the cost of
`WPIN_SCOPE=module`; files whose wipe was not deleted (how often the wrapper
stops a compile that did not need stopping); a real project's build.
