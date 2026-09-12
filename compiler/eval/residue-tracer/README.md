# residue-tracer — did the SECRET survive, not did the WIPE INSTRUCTION survive

Every other lane in `compiler/eval/` ends at a verdict about an artefact.
Differential compilation deletes the wipe from the source, compiles both forms,
compares the target function's body, and `WIPE_SURVIVED` means the instruction is
still in the listing. That is the right question for a checker and the wrong
question for an attacker, who reads memory and does not care which instruction
produced the bytes.

This lane asks the second question on the **same build**: at a defined instant in
a running process, are the secret's bytes still readable? The find step's own
code decides the first question, the same assembly listing it judged is the one
that gets assembled and executed, and both answers land in one row.

`compiler/schema/properties.json` currently says of this whole property kind:
`"must-remain-unobservable": "none -- no extractor, no checkpoint, no
measurement"`. This is the first measurement of that kind in the directory. It
does not close the kind, and the section at the end of this file says exactly
which half it closes and asks for the catalogue to say `partial` rather than
`implemented`.

## What is measured, and what is not

**Measured.** Whether a per-run random 32-byte tracer is still readable in the
stack window `[rsp-below, rsp+64)`, in each general-purpose register, and in each
of `xmm0`–`xmm15`, at the instruction after the function that owned the buffer
returns, in a process running an **unmodified** binary. `below` is 4096 by default
and is a **floor**: each cell's window is grown to cover the frame depth `objdump`
reports for that cell's own binary, plus a 136-byte margin, so that a `NONE` is a
statement about a window that reached the bottom of the frame the secret lived in.
See *The window bound, from the binary*.

**Not measured, in every cell, and named in every row.** The heap. Other threads.
The stack on either side of that window — deeper than it, and the caller frames
above it, which every row now names separately. Kernel-saved state. The upper
halves of `ymm`/`zmm` registers — `PTRACE_GETFPREGS` returns the legacy FXSAVE
area, which
holds `xmm` only, so a fragment living in `ymm0[16:32]` is UNOBSERVED and not
absent. Anything the process copied somewhere before the stop.

**Therefore: a `NONE` reading is residency, not secrecy.** It says the tracer was
not in this window at this instant. It does not say the secret is gone. Nothing
in this lane, in its output, or in the row shape should be read as saying
otherwise, and if a summary you are writing would read that way, it is wrong.

## The instrument

An external observer written in C (`observer/residue-observer.c`), built with
`gcc-13`, run as a **separate process**. The subject binary is never modified on
disk — the row carries its sha256 before and after and `exe.unmodified` compares
them — and never links a line of the observer.

Three alternatives were rejected, each for a reason rather than a preference:

| Rejected | Why |
|---|---|
| `gdb` | Absent on this box, and reading a verdict out of a tool's human-readable output is exactly what `interfaces.md` §4 forbids. |
| An observer TU linked into the subject | It would run on the very stack it wants to read. Its own frame would sit where the residue is, and the reading would be of itself. |
| A core dump | `/proc/sys/kernel/core_pattern` here is a WSL pipe and `ulimit -c` is `0`, so there is nothing to read — and the kernel writes the signal frame onto the dead stack anyway (the x64 red zone; see Prior work), which destroys part of the answer. |

### The stop point, which is the subtle part

"Right after the wipe returns" is **unrealisable above `-O0`**: the wipe is
inlined and there is no wipe-function return to break on. What exists at every
level is the **return of the function that owns the buffer**, `handle_request`.

1. `PTRACE_TRACEME` + `exec`, so the first instruction is under control.
2. `int3` at the subject symbol's first byte. On the hit, `[rsp]` holds the
   return address — this is function entry, before any prologue push.
3. Restore the byte, rewind `rip`, plant `int3` at that return address, continue.
4. On the second hit, restore, rewind, and read. The owning frame is dead and
   nothing in the caller has executed.

The symbol address comes from `.symtab`, and the subject is linked `-no-pie` so
`st_value` **is** the runtime address. That is asserted rather than assumed: the
observer reads `/proc/<pid>/maps`, computes the load bias against the lowest
`PT_LOAD` page, and refuses a non-zero bias. After both breakpoints are removed
it reads the whole `.text` back out of the process and compares it byte for byte
against the file, so a restore that wrote the wrong word is caught rather than
confirmed (`textRestoredMatchesFile`).

Two things about the stop are checked, not assumed, and a failure of either is
`NOT_OBSERVED` and never a reading:

- `stop.matched` — `rip - 1` equals the return address that was actually read at
  step 2.
- `stop.rspMatched` — `rsp` equals the entry `rsp` plus eight. The `ret` popped
  one word and nothing else has run. A recursive call, a second call site
  reaching the same return address, or a `longjmp` would all land here with a
  different `rsp`, and each would point the window at a frame that is not the one
  under test.

## The controls

### The co-resident control, in the frame

Invariant: *a positive control must be co-resident in every measurement, so "the
detector stopped working" is distinguishable from "the defence was removed".*
Every `target-*.c` therefore holds **two** buffers in `handle_request`'s frame:
`secret[32]`, filled from the tracer file and wiped by the idiom under test, and
`keep[32]`, filled from the same descriptor and **never wiped**. The observer
searches for both needles. A cell whose control needle is not fully readable
measured nothing — `BROKEN_MEASUREMENT` with reason
`coresident-control-unreadable`, `controlHeld: false`, and no residue reading.

This is what separates "the wipe worked" from "the reader read nothing at all".
It is **not** enough on its own, and the next section is the part that was
missing.

### The window bound, from the binary

A readable control proves the window reached **the control**. It does not prove
the window reached the secret, and the two are not the same place: declare the
buffers `keep[32]; pad[8192]; secret[32];` and clang-18 `-O0` puts the control
near the top of the frame and the secret 8 KiB deeper. Measured on this box, over
one binary:

| `--below` | subject | control | what the old grader said |
|---|---|---|---|
| 4096 | 1/32 | 32/32 | `OK`, `controlHeld: true`, residue `NONE` |
| 8192 | 1/32 | 32/32 | the same |
| 8296 | 32/32 | 32/32 | — |
| 16384 | 32/32 | 32/32 | — |

The secret was in the process the whole time. The first two rows are a false
clean in the `(WIPE_SURVIVED, NONE)` square, produced by an instrument reporting
that it looked.

So every cell now carries a second, **external** bound. After the cell's binary is
linked it is disassembled with `objdump -d`, and `handle_request`'s own frame
depth is read out of it (`lib/frame.mjs`): every instruction in the function that
moves `rsp` down by a constant is summed and every instruction that moves it up is
ignored, so the number can only be too large. The forms are the ones compilers
actually emit — `push`, `sub $imm,%rsp`, an `add` of a *negative* immediate, `and
$-N,%rsp` realignment counted at its worst case — and anything that cannot be
bounded (`sub %rdx,%rsp` and `mov %rbx,%rsp`, which is what a VLA compiles to;
gcc's stack-clash probe emitted as a *loop* — measured here: unrolled at an
8 KiB frame, a loop at 128 KiB) makes the frame **unparsed**. The window is then grown to `frame + 136` bytes, and:

- a window shallower than that is `BROKEN_MEASUREMENT`, reason
  `window-shallower-than-subject-frame`, carrying the `--below` it needed;
- a frame that could not be parsed is `BROKEN_MEASUREMENT`, reason
  `subject-frame-unparsed`, with the instruction that defeated it;
- neither is ever a residue reading.

"We could not establish that we looked where the secret was" is the same case as
"we did not look", and this lane refuses to report either as "it was not there".
`objdump` is therefore a hard requirement: the runner exits 5 without it rather
than measuring cells it cannot qualify.

### The three run-level controls

Any one of them failing makes the whole run `INVALID_RUN`: exit 1, nothing
written to `data/`, and the rows kept in the lab so the failure can be looked at
— they are not measurements of anything.

| Control | Must read | What it catches |
|---|---|---|
| `control-retain` | `FULL` | No wipe at all, buffer escaped. If the reader and the window work, the whole tracer is there. This is what makes every `NONE` elsewhere something other than an instrument that reads nothing. |
| `control-nosecret` | `NONE` | The tracee is given a different tracer (`B ‖ K`) and the observer searches for one (`A`) that never entered its address space. Catches an observer that finds its own needle. |
| `control-o0-wiped` | `NONE` | A `memset` at `-O0` is a real call no optimiser removes, so the buffer **is** zero when the frame dies. |

**`control-o0-wiped` is the only one that catches a stop point placed BEFORE the
wipe, and that is why it is not optional.** `control-retain` and
`control-nosecret` both pass a too-early stop. This is not an argument; it was
measured on 2026-09-12 by re-running the same three binaries with the stop moved
to the return of the first `consume()` call, which is before the wipe:

```
--- the real stop point: the return of handle_request ---
control-retain     -O0   symbol=handle_request   subject=32  control=32  stop=true
control-nosecret   -O0   symbol=handle_request   subject=1   control=32  stop=true
control-o0-wiped   -O0   symbol=handle_request   subject=1   control=32  stop=true

--- a stop placed BEFORE the wipe (the return of the first consume) ---
control-retain     -O0   symbol=consume          subject=32  control=32  stop=true
control-nosecret   -O0   symbol=consume          subject=1   control=32  stop=true
control-o0-wiped   -O0   symbol=consume          subject=32  control=32  stop=true
```

Two of the three controls are identical in both worlds. The third goes from 1 to
32. In a lane without it, every subject cell would have read residue the wipe
would have removed, and nothing would have said so.

## What makes the pairing honest

For each cell:

1. `wipeSpans(src, 'handle_request')`, `ablateSpans`, `CONTROL`, `compile` and
   `verdictOf` come from `../ai-generated/lib/ablation-cell.mjs` — the find
   step's own code, imported, not copied. A copy is how two lanes quietly stop
   measuring the same thing.
2. `compile()` emits assembly (`-S`, which is in its `FLAGS`). **That listing is
   then assembled into the object that is linked and executed.** `asmSha256` and
   `objSha256` are both in the row.

So "confirm said `WIPE_SURVIVED` yet the secret was readable" cannot be waved
away as judging one build and running another. There is one build and its digests
are in the row.

The positive control from `ablation-cell.mjs` (`vgctl_control`) is appended to
every translation unit exactly as the corpus measurement appends it, so
`controlPresent()` inside `verdictOf` reads the same control here as there;
`opaque.c` defines `vgctl_fill` and `vgctl_use` so the link resolves.

## Fixtures

`tools/make-residue-fixtures.sh` writes them into `$HOME/vg-lab/residue-tracer/fixtures/`.
Generated rather than committed for the reason `llvm-pass/tools/make-fixtures.sh`
gives: `scripts/check-packaging-invariants.mjs` refuses any tracked path under
`compiler/` with a `fixtures` segment.

- **`main.c`** takes `argv[1]` = the path to the tracer file, opens it, and passes
  the **descriptor** to `handle_request` — never a caller-side buffer, which would
  live in `main`'s frame, above the window, and would make the reading depend on a
  frame the subject does not own. `handle_request`'s return value is used, so the
  call cannot become a tail jump and the return address stays inside `main`.
- **`opaque.c`** — `get_secret` reads straight into the caller's buffer (an
  intermediate buffer here would live in a frame *deeper* than the subject's,
  hence inside the window, and its residue would be read as the subject's);
  `consume` is a byte-at-a-time loop into a `volatile` sink. **Compiled at `-O0`
  always**, and that is a measurement decision: at `-O2` the loop vectorises,
  sixteen bytes of tracer land in an `xmm` register, and the observer reads
  register residue no wipe was ever responsible for. `main.c` is `-O0` for the
  same reason plus one more — its call site is where the second breakpoint lands.
- **`target-{retain,memset,volatile-loop,explicit-bzero}.c`** — identical but for
  the wipe. The `volatile-loop` variant puts `volatile` on a **declaration**
  preceding the loop, which is the dominant real-world shape and the one
  `wipeSpans` finds as a declaration/loop pair.

**The tracer never appears in a fixture.** It is 32 bytes drawn from
`/dev/urandom` by the runner at run time and written to a file whose path is
passed in `argv`. A literal would be constant-folded into `.rodata` and found in
a place no wipe was responsible for. Three independent draws per run: `A` (the
subject needle), `K` (the co-resident control needle), `B` (the decoy given to
`control-nosecret`'s tracee instead of `A`). A draw is rejected and redrawn if it
contains eight identical consecutive bytes or repeats an eight-byte block
(`needleSanity`) — that has never fired, and it is there because the alternative
is trusting a random source never to hand back a run.

## Grading

The observer reports a **length**, not a boolean, and `lib/grade.mjs` thresholds
it:

| Reading | Meaning |
|---|---|
| `FULL` | all 32 tracer bytes found contiguously |
| `PARTIAL` | a contiguous run of >= 8 bytes |
| `NONE` | the longest run is shorter than 8 bytes |
| `NOT_OBSERVED` | no reading was taken here. Never one of the three above. |

**Why `PARTIAL` matters.** Simon, Chisnall and Anderson measured what actually
survives an erasure on real code and found most of it is short — values around 64
bits, left by the ABI, by calling conventions and by register spills. A search
for all 32 bytes would report `CLEAN` over an eight-byte fragment of a key. The
floor is 8 because the tracer is uniform random: a chance run of 8 bytes over a
4 KiB window and a 32-byte needle has probability below 2^-47, while a 4-byte
coincidence in 4 KiB is ordinary.

**Register residue is reported beside the stack reading and excluded from the
headline.** A register holding secret bytes is the ABI's doing, not the wipe's.
`residue.gpr` and `residue.xmm` are in every row; neither enters the cross-tab.

`measurement` uses `interfaces.md` §3.1's three words and nothing else, and
§3.1's pairing rule is implemented rather than described: `gradeCell` never
returns a residue enum beside a non-`OK` measurement, and `assertPairing()` is run
over the whole row set before anything is written. `UNSUPPORTED` means the
toolchain refused; a cell that was never run because a plugin is not built is
`BROKEN_MEASUREMENT` with reason `plugin-absent`, because nothing was asked of the
toolchain.

Five things make a cell `NOT_OBSERVED`: `stop-mismatch`, `text-not-restored`,
`short-window`, `load-bias-not-zero`, `coresident-control-unreadable`. A sixth,
`second-scan-disagrees`, is described next.

### Two implementations, one answer

The C observer is the only component here that both chooses where to look and
decides what it saw, so a bug in its search would be invisible in its own record.
It therefore dumps the window bytes to disk, and the runner re-counts the same
runs in JavaScript (`lib/scan.mjs`) over that dump and over the register hex. A
disagreement makes the cell `NOT_OBSERVED` with reason `second-scan-disagrees`.
`scanAgrees` is in every row.

## The matrix

3 idioms × {`clang-18`, `gcc-13`} × {`-O0`,`-O1`,`-O2`,`-O3`,`-Os`} × {stock,
WipePin} = 60 subject cells, plus the controls. Without `--plugin`, every
`wipepin` cell is recorded `BROKEN_MEASUREMENT` / `plugin-absent` — **never
silently dropped and never reported as stock.**

## The headline

A cross-tab of `confirmVerdict` × `residue.stack`. Two of its cells are not
ordinary:

- **FINDING** — (`WIPE_SURVIVED`, `PARTIAL` or `FULL`). The confirm step said the
  wipe is still there and the secret was still readable. This is the claim the
  lane exists to be able to make.
- **ANOMALY** — (`WIPE_ELIMINATED`, `NONE`). This is **not good news** and is not
  reported as any. Either the buffer never reached the window, or something else
  overwrote it, or the confirm verdict is about a wipe that was not the one
  guarding this buffer. Each needs a look.

## What was actually run

Measured 2026-09-12 on WSL Ubuntu-24.04, `clang-18` 18.1.3 and `gcc-13` 13.3.0,
observer sha256 `e034acd417b4b8ecd5c91bbd69843a715e026a12a50dfe382d2cf3bc27afd21c`.
Verbatim, `clang-18`, `-O0` and `-O2`, both arms:

```
stock/clang-18/-O0/control-retain            confirm=NO_WIPE_WRITTEN    residue=FULL          run=32/32 ctl=32
stock/clang-18/-O2/control-retain            confirm=NO_WIPE_WRITTEN    residue=FULL          run=32/32 ctl=32
stock/clang-18/-O0/control-nosecret          confirm=NO_WIPE_WRITTEN    residue=NONE          run=1/32 ctl=32
stock/clang-18/-O2/control-nosecret          confirm=NO_WIPE_WRITTEN    residue=NONE          run=1/32 ctl=32
stock/clang-18/-O0/control-o0-wiped          confirm=WIPE_SURVIVED      residue=NONE          run=1/32 ctl=32
stock/clang-18/-O0/memset                    confirm=WIPE_SURVIVED      residue=NONE          run=1/32 ctl=32
stock/clang-18/-O0/volatile-loop             confirm=WIPE_SURVIVED      residue=NONE          run=1/32 ctl=32
stock/clang-18/-O0/explicit-bzero            confirm=WIPE_SURVIVED      residue=NONE          run=1/32 ctl=32
stock/clang-18/-O2/memset                    confirm=WIPE_ELIMINATED    residue=FULL          run=32/32 ctl=32
stock/clang-18/-O2/volatile-loop             confirm=WIPE_SURVIVED      residue=NONE          run=1/32 ctl=32
stock/clang-18/-O2/explicit-bzero            confirm=WIPE_SURVIVED      residue=NONE          run=1/32 ctl=32
wipepin/clang-18/-O0/memset                  confirm=NOT_RUN            residue=NOT_OBSERVED  run=-/32 ctl=- [plugin-absent]
wipepin/clang-18/-O0/volatile-loop           confirm=NOT_RUN            residue=NOT_OBSERVED  run=-/32 ctl=- [plugin-absent]
wipepin/clang-18/-O0/explicit-bzero          confirm=NOT_RUN            residue=NOT_OBSERVED  run=-/32 ctl=- [plugin-absent]
wipepin/clang-18/-O2/memset                  confirm=NOT_RUN            residue=NOT_OBSERVED  run=-/32 ctl=- [plugin-absent]
wipepin/clang-18/-O2/volatile-loop           confirm=NOT_RUN            residue=NOT_OBSERVED  run=-/32 ctl=- [plugin-absent]
wipepin/clang-18/-O2/explicit-bzero          confirm=NOT_RUN            residue=NOT_OBSERVED  run=-/32 ctl=- [plugin-absent]

controls
  HELD  control-retain     FULL  over 2 cell(s)
  HELD  control-nosecret   NONE  over 2 cell(s)
  HELD  control-o0-wiped   NONE  over 1 cell(s)

confirm verdict          residue NONE   PARTIAL      FULL
WIPE_SURVIVED                      5         0         0
WIPE_ELIMINATED                    0         0         1
graded cells: 6
excluded: 6 x plugin-absent

no (WIPE_SURVIVED, readable) cell and no (WIPE_ELIMINATED, NONE) cell in this run
```

`gcc-13` at the same two levels produced the **same eleven readings and the same
cross-tab** (5 / 0 / 0 and 0 / 0 / 1), with all three controls held.

Read plainly: at `-O2` both vendors removed the `memset` wipe and **all 32 tracer
bytes were still readable on the dead frame**, while `explicit_bzero` and the
`volatile` loop survived and left a longest run of one byte. At `-O0` every idiom
survived and left a longest run of one byte. Those short runs are the ordinary
coincidence rate for a 32-byte needle in a 4160-byte window and they vary between
runs because the tracer is redrawn each time -- a later controls-only run on the
same binaries read 2 bytes where this one read 1. Both are below the floor and
graded `NONE`, which is the floor doing its job.

This run contains **no FINDING**: nothing here shows a surviving wipe over a
readable secret. What it shows is that the instrument distinguishes the two
directions, that it agrees across vendors, and that the eliminated-wipe case is
readable in full.

### What is UNMEASURED, and why

- **`-O1`, `-O3`, `-Os`** — planned in the matrix, not run. The box is shared with
  other agents and `compile()` in `ablation-cell.mjs` returns `null` on its 90 s
  timeout, which `verdictOf` maps to `COMPILE_ERROR`; a loaded machine therefore
  manufactures rows saying the compiler failed when it did not.
- **The WipePin arm, entirely.** No plugin `.so` was passed. All 12 such cells in
  the runs above are `plugin-absent`. Nothing is known about whether the repair
  plugin changes residue.
- **No `data/` directory exists in this lane and no tracked data file was written.** `--write-data` was
  not passed and is refused on a controls-only run. Six graded cells per vendor
  is an instrument check, not a dataset.
- **A second machine.** Everything above is one WSL kernel, one libc.
- **Real cryptographic code.** Every number here is about this lane's own
  fixtures.
- **`ymm`/`zmm` upper halves, the heap, other threads, the rest of the stack.**
  See the top of this file. These are unobserved in every cell that was run.

### A measured fact about the recorded window bounds

The observer calls `personality(ADDR_NO_RANDOMIZE)` in the child. On this kernel
it does **not** take effect: two runs of the same binary recorded `window.lo` of
`140734159020752` and `140729091150416`. Nothing in the measurement depends on it
— the window is taken relative to `rsp` and no grading rule reads an absolute
address — but the recorded bounds are per-run facts and are not comparable
between runs. The comment in the observer says so rather than claiming otherwise.

## Prior work

Simon, Chisnall and Anderson, *"What you get is what you C: Controlling side
effects in mainstream C compilers"*, EuroS&P 2018.
<https://www.cl.cam.ac.uk/~rja14/Papers/whatyouc.pdf>

This is the paper this lane is downstream of, and the honest statement of what it
already established is longer than the statement of what is new here.

- **Residue after erasure, on real crypto libraries, is already established.**
  Lines 813–814: *"we implemented a runtime taint-tracking engine tool (available
  at [42]) on top of Valgrind to follow tainted (i.e. secret) data"* — [42] is
  Secretgrind. **This lane must not claim that as a finding, and does not.**
- **The shape of what survives** (lines 821–825): `*printf`, `*scanf` and friends
  are *"prone to leaving residual data"*, *"recursive functions tend to leave
  residual data"*, and residue arises *"due to the ABI, calling conventions, and
  register spills"*. This is the reason this lane grades a run length with an
  8-byte floor instead of asking whether the whole secret is present.
- **Their threat model** (line 1226) is access *"to the virtual address space of P
  at a time Tattacker > Tuse"* — the same instant this lane's stop point picks.
- **The red zone** (line 1323): on x64 the kernel writes the signal frame *"128
  bytes below"* `rsp`. That is one of the reasons core dumps are useless here and
  an external observer is used instead.
- **Their ladder result** (line 544): as *"compiler version increases (Clang 3.0,
  3.3 and 3.9), more"* implementations become insecure. That is the precedent for
  a version-ladder measurement; this lane does not run one.
- **Their solution needs a modified compiler.** Line 1219: their instrumentation
  is *"in the compiler backend after other backend optimizations"*. **That is the
  difference.** This lane measures **stock** binaries and modifies no compiler.

### The delta, stated narrowly

What is *not* in that paper, and is what this lane adds:

1. An **external native-process observer on an unmodified binary** at a **defined
   stop** — the return of the function owning the buffer, chosen because "after
   the wipe" does not exist above `-O0`.
2. **Per-cell coupling to a differential-compile verdict** derived by the find
   step's own code from the very listing that was assembled and run, with both
   digests recorded. The artefact question and the memory question answered on one
   build.
3. **Co-resident controls that qualify the residue reader** — one in the subject's
   own frame, plus three at run level, with the explicit demonstration above that
   only one of the three catches a mis-placed stop.
4. **Stage attribution** — the wipe's disappearance is attributed to `compile`
   here, because the listing judged is the listing assembled; link cannot be the
   explanation.

None of that makes residue-after-erasure a new phenomenon. It makes it something
a checker can be held to on a stock toolchain.

## Files

```
run-residue-tracer.mjs          the runner. Compiles, links, observes, grades, reports.
lib/scan.mjs                    longest-run search, the grading floor, needle sanity. Pure.
lib/grade.mjs                   what a reading means and when it means nothing. Pure.
lib/frame.mjs                   the subject frame, parsed out of objdump output. Pure.
lib/manifest.mjs                the matrix, the row, and the two record rules. Pure.
observer/residue-observer.c     the PTRACE observer. gcc-13, -Wall -Wextra clean.
tools/make-residue-fixtures.sh  writes the fixtures into the lab.
test/*.test.mjs                 61 cases. No compiler required.
```

The four `lib/` modules are pure and unit-tested without a compiler. The tests
were checked by mutation rather than by being observed to pass: breaking the
stop-mismatch guard, the control grader, the co-resident control check, the
grading floor, the frame bound and the frame parser's loop check each turns at
least one named test red. Two of those are worth naming, because they are the
mutants that produce plausible numbers rather than crashes: dropping the frame
gate turns a real shallow-window record into `OK` / `controlHeld: true` / `NONE`,
and reading only a prologue-shaped run of instructions counts gcc-13 `-O2`'s three
interleaved pushes as zero.

`test/frame.test.mjs` carries `objdump -d` output verbatim for seven real builds
(clang-18 and gcc-13, `-O0` and `-O2`, plus an over-aligned frame, a 128 KiB frame
and a VLA) rather than hand-written prologues, because the shapes that matter are
the ones compilers actually emit. `test/observer-record.test.mjs` reads the C
source as text and holds two constants duplicated on the JavaScript side equal to
it: the `unobserved` list and `WINDOW_MAX`.

## Running it

```sh
# the instrument, on its own — what a first run on a new box wants
node compiler/eval/residue-tracer/run-residue-tracer.mjs \
     --out "$HOME/vg-lab/residue-tracer" --cc clang-18 --controls-only

# a small measurement
node compiler/eval/residue-tracer/run-residue-tracer.mjs \
     --out "$HOME/vg-lab/residue-tracer" --cc clang-18 --opt -O0,-O2

node --test compiler/eval/residue-tracer/test/*.test.mjs
```

`objdump` must be on `PATH`: without it nothing bounds the subject's frame, and
the runner exits 5 rather than producing a matrix of cells it cannot qualify.
`--no-auto-window` keeps the window at exactly `--below` instead of growing it to
the frame; a cell whose frame is deeper than that then reports the `--below` it
needed and the run is `INVALID_RUN` if the cell was a control.

Exit codes: `0` measured; `1` `INVALID_RUN` — a control did not hold and nothing
was written to `data/`; `5` the lane could not be set up.

Do not run this concurrently with another compile-heavy lane. See the runner's
header.

## Failure modes this lane has

Named here rather than discovered later.

1. **The window covers the subject's own frame and nothing beyond it.** The
   `--below` figure is a floor: each cell's window is grown to cover the frame
   depth `objdump -d` reports for `handle_request` in that cell's own binary, plus
   a 136-byte margin (8 for the return word the `ret` popped, 128 for the red
   zone). A window that still does not reach it — because `--no-auto-window` was
   passed, or because the frame needs more than the observer's 1 MiB ceiling — is
   `BROKEN_MEASUREMENT` carrying the size it needed, and a frame that could not be
   parsed at all (a VLA, an `alloca`, or gcc's stack-clash probe emitted as a
   *loop* — measured here: unrolled at an 8 KiB frame, a loop at 128 KiB) is
   `BROKEN_MEASUREMENT` too. What is still outside the guarantee: residue left
   **below** the subject's frame by functions it called, and anything the process
   copied elsewhere. Both are unobserved, not absent.

   *This paragraph used to say something weaker and wrong.* It said the
   co-resident control catches a too-shallow window "only if `keep[]` is also
   outside the window — which it would be". It would not be, and that was
   measured, not argued: declare the buffers `keep[32]; pad[8192]; secret[32];`
   and clang-18 `-O0` puts the control near the top of the frame and the secret
   8 KiB deeper. At `--below 4096` the observer reads **control 32/32 and subject
   1 byte**; over the same binary at `--below 16384` it reads **subject 32/32**.
   The old grader called that `OK` / `controlHeld: true` / `NONE` — a silent false
   clean in the `(WIPE_SURVIVED, NONE)` square, which is the worst direction this
   lane can be wrong in. The frame bound above is what replaced the argument.
2. **One process, one instant.** Nothing here says what happens later, or in
   another thread, or on a machine with different libc internals.
3. **`-no-pie` is a requirement, not an observation.** A subject that must be
   position-independent cannot be measured by this observer at all.
4. **The idioms are three.** A wipe expressed as a memory barrier, as inline asm,
   or through a `volatile` function pointer is not in the fixture set even though
   `wipeSpans` knows those shapes.
5. **The confirm verdict is scoped to `handle_request`.** A cell where the
   compiler moved the wipe into a caller would be `WIPE_ELIMINATED` here and not
   eliminated in the program. No fixture exercises that.

---

# Edits requested in files this lane does not own

Nothing below has been applied. Each is a file another lane owns, or
`compiler/schema/`, whose own rule is that nobody edits it while implementing
against it.

**`properties.json` is not read by one test only.** An earlier draft of this file
said the coverage line in §3 was the only edit below with a test coupling. That
was wrong. Two checks bear on the edits below, and the second is the one that is
easy to miss:

| Check | What it checks | Which edit below it touches |
|---|---|---|
| `compiler/driver/test/properties.test.mjs` | `kindCoverage` for `must-remain-unobservable` reading `"none"`, and the verdicts that follow from it | §3 (the coverage line, and the test that reads it) |
| `scripts/check-doc-drift.mjs` check `[3]` | every `extractors[].path` **exists on disk** | §5 (the new `process.stack-residue` entry) |

The second is easy to miss because it is an `npm` script rather than a CI gate,
and because it passes in the tree this lane was written in — the directory is
there, untracked. Measured rather than assumed: in a shadow root holding only
tracked files, adding the §5 entry takes check `[3]` from 6 drifts to 7, the new
one being ``EXTRACTOR_PATH_MISSING | extractor `process.stack-residue` の path
`compiler/eval/residue-tracer` が存在しない``; against the real tree (`--root .`)
check `[3]` reports 0 drifts. **So §5 must not land before this directory is
committed.**

Other code reads this catalogue without being touched by anything below —
`compiler/driver/lib/properties.mjs` loads it at run time,
`compiler/eval/repair-loop/test/pin-families.test.mjs` asserts every pin-family
row names a property id this file defines, and
`compiler/eval/calibration/claims/degradation-claims.json` copies three
extractors' `degradationRisk` sentences verbatim (its own `doesNotCover` says the
per-property arrays, which is where §1's risks live, are outside it). Whoever
applies these edits should grep again rather than trust this list: it is the
result of one grep on 2026-09-12, not a guarantee.

## 1. `compiler/schema/properties.json` — the entry (required)

The catalogue's `unobservable.secret-buffer-residue` currently reads
`"status": "unimplemented"`. It should become **`"partial"`, not
`"implemented"`**, because its own oracle is `"strings, then residency"` and this
lane measures **only residency**, and only inside a window. Replace the entry at
line 895 onwards with:

```json
    {
      "id": "unobservable.secret-buffer-residue",
      "kind": "must-remain-unobservable",
      "title": "A secret does not survive in the artefact or in memory after use",
      "extractor": "process.stack-residue",
      "status": "partial",
      "statusDetail": "Half of this entry is measured and half is not, and the halves are the two clauses of the oracle below. RESIDENCY is measured: compiler/eval/residue-tracer reads the stack window [rsp-4096, rsp+64), the general-purpose registers and xmm0-15 of a live process at the return of the function that owned the buffer, on a binary it does not modify, and grades the longest contiguous run of a per-run random tracer. STRINGS are not measured here at all -- that half is the artefact scan, and it is the one _notAnExtractor.artifactByteScan says has no fixture carrying a control string without the forbidden one. The measured half is also narrower than the word 'memory': the heap, other threads, the stack outside the window, kernel-saved state and the upper halves of ymm/zmm are unobserved in every cell, so a NONE reading is residency at one instant and never secrecy. The observation point is a running process, which is NOT one of the seven checkpoints, so no observeAt row below can name it; that vocabulary gap is why both rows stay unimplemented while the entry is partial. Measured 2026-09-12 on clang-18 and gcc-13 at -O0 and -O2 only; -O1, -O3 and -Os are in the matrix and were not run.",
      "relatedTo": [
        "survive.secure-wipe"
      ],
      "observeAt": [
        {
          "checkpoint": "object",
          "extractor": null,
          "status": "unimplemented",
          "component": null
        },
        {
          "checkpoint": "linked",
          "extractor": null,
          "status": "unimplemented",
          "component": null
        }
      ],
      "oracle": {
        "counts": "strings, then residency",
        "detail": "Would look for the secret's bytes in the artefact, and separately for a wipe that reaches the storage at run time. A LOST on survive.secure-wipe is a sufficient reason to consider this property unmet; a PRESENT there is not sufficient to consider it met. The second half now has an implementation and the first does not. Measured 2026-09-12: clang-18 and gcc-13 at -O2 both report WIPE_ELIMINATED on a memset wipe and all 32 tracer bytes are readable on the dead frame, while the same source at -O0 and the volatile-loop and explicit_bzero idioms at -O2 report WIPE_SURVIVED with no run of 8 bytes or more anywhere in the window. That pair is what 'a PRESENT there is not sufficient' was written about, now with a number beside it.",
        "unitOfCount": "the object, then the linked image, then one process at one instruction",
        "requiresControl": true,
        "controlRule": "A byte sequence expected to be present, so an extractor that has stopped finding anything is visible. For the residency half the control is co-resident IN THE FRAME: the subject holds a second random tracer it never wipes, and a cell whose control tracer is not fully readable is BROKEN_MEASUREMENT rather than a clean wipe. That control is necessary and not sufficient -- it proves the window reached the CONTROL -- so each cell also carries an external bound: the subject function's frame depth read from its own binary with objdump, which the window must cover or the cell is BROKEN_MEASUREMENT. Three further controls qualify the run -- an unwiped subject that must read the whole tracer, a decoy tracer the observer must not find, and a memset at -O0 that must read nothing. Only the third catches a stop point placed before the wipe, measured 2026-09-12."
      },
      "degradationRisk": [
        "The window is [rsp-below, rsp+64) at one instruction, where below is 4096 by default and is grown per cell to cover the subject function's frame depth read from its own binary with objdump, plus a 136-byte margin. A window that still does not reach the frame, and a frame that cannot be parsed (a VLA, an alloca, or gcc's stack-clash probe emitted as a loop -- measured: unrolled at an 8 KiB frame, a loop at 128 KiB), are each BROKEN_MEASUREMENT carrying the size or the instruction that defeated them, never a residue reading. What is still not seen: residue left below the subject's frame by functions it called, and bytes the process copied to the heap or to another thread. Those err towards a clean reading, which is the dangerous direction, and are part of why this entry is partial rather than implemented. Until 2026-09-12 the window was fixed at 4096 and a subject buffer deeper than that read as NONE with the co-resident control still held -- a silent false clean, measured and then closed by the frame bound.",
        "PTRACE_GETFPREGS returns the legacy FXSAVE area, so only xmm0-15 are read. A tracer fragment in the upper half of a ymm or zmm register is unobserved rather than absent.",
        "The stop point is the return of the function that owns the buffer. A secret that outlives that function by design -- one in a caller's frame, or a static -- is out of scope rather than clean, and there is no fixture for it.",
        "The grading floor is an 8-byte contiguous run of a 32-byte uniform random tracer; a chance run that long has probability below 2^-47 over the window, but a SHORTER fragment of a real key reads NONE. Simon, Chisnall and Anderson found most field residue to be around 64 bits, which is exactly at the floor.",
        "The subject is linked -no-pie so that .symtab addresses are runtime addresses; the observer asserts a zero load bias from /proc/<pid>/maps rather than trusting the flag. A subject that must be position-independent cannot be measured at all.",
        "Nothing has been run against a real cryptographic library. The numbers describe the lane's own fixture shapes."
      ],
      "evidence": null
    }
```

## 2. `compiler/schema/properties.json` — `readMeFirst`, line 6 (coupled)

Two clauses in that sentence become false: `partial` is no longer used by exactly
one entry, and the distribution changes. Recounted from the file rather than
remembered — the current counts are `implemented 7, unimplemented 14, candidate
2, partial 1` over 24 entries, and `notappear.forbidden-external-call` is today
the only `partial`. Replace the two sentences beginning `'partial' means` with:

> `'partial' means an extractor measures part of what the title claims and the entry's statusDetail says which part -- it is used by two entries (notappear.forbidden-external-call, unobservable.secret-buffer-residue), and it went unlisted in this paragraph for months because a reader checking the vocabulary against the catalogue would have to count all 24 entries to notice. Current distribution, recomputed rather than remembered: implemented 7, unimplemented 13, candidate 2, partial 2.`

## 3. `compiler/schema/properties.json` — `kindCoverage.must-remain-unobservable`, line 124 (coupled)

Replace:

> `"must-remain-unobservable": "none -- no extractor, no checkpoint, no measurement"`

with:

> `"must-remain-unobservable": "partial -- one extractor, at a point the checkpoint vocabulary has no word for. compiler/eval/residue-tracer reads the stack window, the GPRs and xmm0-15 of a live process at the return of the function that owned the buffer, on an unmodified binary, with a control tracer co-resident in the same frame; measured 2026-09-12 on clang-18 and gcc-13 at -O0 and -O2. It answers the RESIDENCY half of unobservable.secret-buffer-residue and no part of the strings half, and it observes at run time, which is not one of the seven checkpoints -- so no observeAt row in this file names it. The other three entries in this kind remain unimplemented"`

### This edit breaks a test in a file I do not own — measured, not predicted

`compiler/driver/lib/properties.mjs:125` decides `kindHasAnyImplementation` by
testing whether the `kindCoverage` line **starts with the word `none`**. Changing
the line flips it. I loaded the patched catalogue through the real
`loadCatalogue`/`checkProperties` and measured:

```
BEFORE kindHasAnyImplementation(must-remain-unobservable) = false
BEFORE verdict for unobservable.secret-literal = kind-unimplemented finding VG-CFG-018
AFTER  kindHasAnyImplementation(must-remain-unobservable) = true
AFTER  verdict for unobservable.secret-literal = property-unimplemented finding VG-CFG-018
```

`compiler/driver/test/properties.test.mjs` is green today (29 pass) and has, at
lines 145–151:

```js
test('a kind whose coverage line is "none" has no implementation whatever an entry claims', () => {
  assert.equal(kindHasAnyImplementation(CATALOGUE, 'must-remain-unobservable'), false);
  assert.equal(kindHasAnyImplementation(CATALOGUE, 'must-survive'), true);
  const r = checkProperties([{ id: 'unobservable.secret-literal', kind: 'must-remain-unobservable' }], CATALOGUE);
  assert.equal(r.entries[0].verdict, 'kind-unimplemented');
  assert.equal(r.findings[0].id, 'VG-CFG-018');
});
```

Lines 146 and 149 go red. The test is asserting a real behaviour and should keep
doing so, on a kind that still reads `none`. Suggested replacement, which keeps
the behaviour under test and moves the example to a kind that has not changed:

```js
test('a kind whose coverage line is "none" has no implementation whatever an entry claims', () => {
  // must-remain-unobservable stopped reading "none" on 2026-09-12, when
  // compiler/eval/residue-tracer measured the residency half of
  // unobservable.secret-buffer-residue. There is no kind left whose line reads
  // "none", so the "none" branch is exercised against a constructed catalogue
  // rather than against a kind that happens to be unimplemented this month --
  // which is the more honest test anyway: it does not go quiet when coverage
  // grows.
  const noneKind = { ...CATALOGUE, kindCoverage: { ...CATALOGUE.kindCoverage, 'must-remain-unobservable': 'none -- no extractor, no checkpoint, no measurement' } };
  assert.equal(kindHasAnyImplementation(noneKind, 'must-remain-unobservable'), false);
  assert.equal(kindHasAnyImplementation(CATALOGUE, 'must-survive'), true);
  const r = checkProperties([{ id: 'unobservable.secret-literal', kind: 'must-remain-unobservable' }], noneKind);
  assert.equal(r.entries[0].verdict, 'kind-unimplemented');
  assert.equal(r.findings[0].id, 'VG-CFG-018');
  // And with the real catalogue the same property is now refused one step
  // later, by its own status rather than by its kind. Still not usable.
  const live = checkProperties([{ id: 'unobservable.secret-literal', kind: 'must-remain-unobservable' }], CATALOGUE);
  assert.equal(live.entries[0].verdict, 'property-unimplemented');
  assert.equal(live.findings[0].id, 'VG-CFG-018');
});
```

I did not write this into the file. `CATALOGUE` there is the object
`loadCatalogue()` returns, so the spread above needs whatever shape that object
has at the top of the test file — the main agent should check that line before
applying.

## 4. `compiler/schema/properties.json` — `checkpointOwners.linked`, line 115 (coupled)

Replace:

> `"linked": "compiler/elf-verifier, same scope and same limit as object."`

with:

> `"linked": "compiler/elf-verifier, same scope and same limit as object. Corrected 2026-09-12: the sentence in `object` that says a secret-residue extractor 'does not exist' is no longer true -- compiler/eval/residue-tracer is one -- but it does not observe HERE. It reads a running process, which the seven checkpoints have no word for, so this checkpoint is still not the place that answers must-remain-unobservable and the linked image is still unread for secret bytes."`

### And the sentence directly above it, `checkpointOwners.object` (line 114)

The task named three coupled sentences; this is a fourth, and leaving it is the
kind of half-correction this file keeps a record of elsewhere. It currently ends:

> `... which need a forbidden-string and secret-residue extractor that does not exist.`

That clause is now false in half. Suggested:

> `... which need a forbidden-string extractor that does not exist and a secret-residue extractor that now does, but not at this checkpoint: compiler/eval/residue-tracer reads a live process, not an object file.`

## 5. `compiler/schema/properties.json` — a new `extractors` entry (coupled)

`readMeFirst` says `'unimplemented' means there is no extractor at all`, so an
entry that says `partial` with `"extractor": null` contradicts the preamble. Add
to the `extractors` object:

```json
    "process.stack-residue": {
      "component": "ResidueTracer",
      "path": "compiler/eval/residue-tracer",
      "checkpoints": [],
      "counts": "The longest contiguous run of a per-run random 32-byte tracer found in the stack window [rsp-below, rsp+64) -- below being 4096 by default and grown per cell to cover the subject frame read from the binary with objdump -- in each general-purpose register and in each of xmm0-15, read out of a live process by an external PTRACE observer at the return of the function that owned the buffer. Bytes, not symbol names: nothing here reads an assembly listing or a tool's prose.",
      "whyCheckpointsIsEmpty": "The observation point is a running process. The seven checkpoints of observation.schema.json run from invocation to artifact and stop there, so there is no legal word for this point and none is invented. The lane writes plain rows rather than an observation record for exactly that reason, and the request for the word is in its README.",
      "discriminates": "Residency from the absence of a reading. A stop that is not the return of the subject function, a .text section that did not come back byte-identical after the breakpoints were removed, a short window read, a non-zero load bias, a co-resident control tracer that was not fully readable, a window shallower than the subject function's own frame, a frame that could not be parsed out of the binary at all, and a disagreement between the C search and the JavaScript re-count are each NOT_OBSERVED with a reason, never a clean wipe.",
      "degradationRisk": [
        "Every risk in unobservable.secret-buffer-residue's own list applies to this extractor and is recorded there rather than duplicated here.",
        "The grading floor is 8 bytes. Below it the reading is NONE, and the prior work says field residue is often about that long."
      ]
    }
```

`"checkpoints": []` is unusual and may not be what the catalogue wants. If an
empty array is unacceptable, the entry cannot be added until the vocabulary
request below is settled, and then `status` should stay `unimplemented` with the
`statusDetail` explaining why — which is worse but true.

**Order of operations.** `scripts/check-doc-drift.mjs` check `[3]` verifies that
`extractors[].path` exists on disk, so this entry names a path that has to be
present in any checkout the script is run against. Commit this directory first,
or the edit manufactures a drift finding in a tree where the lane is absent.

## 6. A vocabulary request — `compiler/schema/interfaces.md` / `observation.schema.json`

`observation.schema.json:184` fixes the checkpoint enum at
`["invocation","ast","pre-opt-ir","after-pass","object","linked","artifact"]`,
and `observation-schema.test.mjs` holds it identical to `policy.schema.json`.
There is no word for **an observation taken from a running process**, and this
lane needs one. It invented nothing: it emits plain rows like every other
`compiler/eval/` lane and writes no observation record at all, which is why the
gap costs nothing today and will cost something the moment this measurement wants
to be evidence.

Requested: a checkpoint named `process` (or `runtime`), added to both schemas in
the same change, positioned after `artifact`, with a description making clear
that it is the only checkpoint that is not a point in a compilation — it is a
point in an execution of the compilation's output, and a record at it therefore
names an instruction address rather than a pass.

I have not edited either file. `interfaces.md` line 5 says nobody edits it while
implementing against it.

## 7. Evidence finding ids — reserved, not registered

`VG-ART-064` and `VG-ART-065` are free. This lane **emits no evidence record
today** — it writes plain rows, as every other `compiler/eval/` lane does — so
nothing is registered and nothing should be. If a refusal-shaped check is ever
wanted for it, those are the two ids, and the rows they would be raised on are
`stop.matched === false` (the stop was not the one asked for) and
`controlHeld === false` (the co-resident control was not readable). Registering
them would mean editing `compiler/evidence/verify.mjs` and
`compiler/evidence/README.md`, neither of which this lane owns.

**Check availability again before registering.** `git status` at the time of
writing (2026-09-12) shows `compiler/evidence/verify.mjs`,
`compiler/evidence/README.md` and `compiler/evidence/ledger.mjs` modified or
added by work happening in parallel with this lane. "064 and 065 are free" is
true of the tree this lane was written against and may not be true of the tree it
is merged into.
