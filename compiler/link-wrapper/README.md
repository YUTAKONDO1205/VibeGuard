# link-wrapper — what actually went into the link

Everything upstream of this directory watches the compiler. The compiler is not
where a binary gets its final contents: the linker is. It pulls in start-up
objects nobody wrote, members of archives nobody named, shared libraries chosen
by a search path, and — if a linker script is in play — it can place, rename,
wrap or discard any section on the way. A build gate that stops at the object
files has checked the part of the process that is easiest to check.

This component records one link and compares it with `policy.link`. It owns the
`VG-LINK-0NN` namespace (compiler/schema/interfaces.md §2) and nothing else.

```
vg-link.mjs link  --policy <policy.json> [--root <dir>] [--record <out.json>]
                  [--work <dir>] [--allow-empty] -- <the whole link command>

vg-link.mjs recheck <record.json | directory> --root <dir> [--allow-empty]
```

## The one design decision everything else follows from

**The map is produced by the wrapper.** There is no flag that accepts a map
file, and a link command line that names the map — `-Wl,-Map=`, `-Wl,-M`,
`--print-map`, any spelling — is refused with exit 4 *before the linker runs*.

If the wrapper accepted a map handed to it, the caller would be supplying the
evidence. A verdict computed from a supplied map describes a link that never
happened and carries the authority of a check that never ran, which is strictly
worse than having no check: the second is visibly absent, the first is a green
tick. So the wrapper picks an unguessable path under its own working directory,
asserts the file does not already exist, runs the link, and then verifies the
file it reads is the one it named and that this run wrote it. The provenance
travels with the parsed map into `lib/verdict.mjs`, which refuses to produce a
verdict without it — deliberately awkward, so that no future caller can get a
verdict out of a map of unknown origin by taking a shorter path.

## Two captures, kept separate

The map and `-Wl,-t` see different things, and neither is sufficient.

| | in the map | in `-Wl,-t` |
|---|---|---|
| object files | yes | yes |
| archive members | yes, as `lib.a(member.o)` | yes |
| shared libraries | **no** — they contribute no input section | yes |
| the dynamic loader | no | yes |
| the linker script | no | no — read from the command line |
| symbol → defining input | yes | no |
| `.init_array` contributors | yes | no |

Two consequences that were measured rather than assumed:

- **`-Wl,-t` goes to the linker's STDOUT, not stderr.** A wrapper that captures
  the linker's output the way one captures diagnostics records an empty input
  list and then reports a link with nothing wrong in it. In the measured link,
  stdout held eleven lines and stderr held nothing.
- **A `.so` never appears in a map.** A check built on the map alone cannot see
  a library substitution at all.

The two are recorded as separate `sources` per input and merged nowhere. An
input the map has and the trace does not is `VG-LINK-008`: everything that
contributed bytes was opened, so the two accounts of the link disagree.

## The map's grammar is its indentation

```
             VMA              LMA     Size Align Out     In      Symbol
            1670             1670      174    16 .text
            1670             1670       26    16         /lib/x86_64-linux-gnu/Scrt1.o:(.text)
            1670             1670       26     1                 _start
            2840             2840        8     8         main.o:(.init_array)
```

Four fixed columns — VMA, LMA and Size in hex, Align in decimal — then one
space, then an indentation of 0, 8 or 16 further spaces which is the *only*
thing distinguishing an output section from an input section from a symbol. A
parser that splits on whitespace loses that, and then reports `_start` as a
linker input, which the policy fails to authorise. `test/map-parse.test.mjs`
asserts the distinction directly.

## Findings

| id | severity | meaning |
|---|---|---|
| `VG-LINK-001` | high | an object the policy does not authorise was linked in |
| `VG-LINK-002` | high | an archive member the policy does not authorise was pulled in |
| `VG-LINK-003` | high | a shared library the policy does not authorise |
| `VG-LINK-004` | high | a linker script was used and the policy forbids them |
| `VG-LINK-005` | high | the linker itself is not authorised |
| `VG-LINK-006` | critical | the artefact on disk is not the one this link produced |
| `VG-LINK-007` | critical | the map was not produced by this wrapper |
| `VG-LINK-008` | high | the map and the input trace describe different links |
| `VG-LINK-009` | high | `.init_array` carries a contribution from an unauthorised input |
| `VG-LINK-010` | high | the entry point is defined by an unauthorised input |
| `VG-LINK-011` | high | the link command line could not be fully observed |

Exit codes are the shared ones (interfaces.md §7): 0 clean · 1 the linker failed
· 2 findings at or above `failOn` · 3 a check could not be completed · 4 the
observation or the policy cannot be trusted.

## Absent is not empty, and neither is clean

`policy.link` is the interface, unchanged; the permitted key set is read out of
`compiler/schema/policy.schema.json` at run time rather than repeated here, so
this component cannot drift from the contract by being edited.

| policy state | what happens |
|---|---|
| `allowedObjects: [...]` | every object is compared with it |
| `allowedObjects: []` | an explicit decision: no object is authorised, every one is a finding |
| `allowedObjects` absent | object authorisation **was not checked** — exit 3, and every input it could not check is printed by name |
| `link` absent | nothing about the link can be checked — exit 3 |
| `forbidLinkerScripts` absent | the schema's default is `true`; absent does not read as permitted |

A policy entry matches an input by exact string, by glob (`*` within a path
segment, `**` across), or — only when the entry contains no `/` — by basename.
The record says which of the three matched, because a basename match is the
weakest and a reader should be able to see it was the one relied on.

## Paths in the record

interfaces.md §5 forbids absolute paths in a record: a digest over a
machine-specific string is reproducible on exactly one machine. Every input
therefore gets a portable **ref**:

```
main.o                                          under the link root
libarch.a(arch.o)                               under it, archive member
system:lib/x86_64-linux-gnu/Scrt1.o             a toolchain root
system:usr/lib/gcc/x86_64-linux-gnu/13/crtbeginS.o
withheld:rogue.o                                an account-named directory
```

The last form is the one that matters. A path through a per-user home directory
names an account, which no word list can contain and which is published the
moment it is committed. The path is withheld, the basename is kept, and the
withholding is recorded as a problem — reported rather than emitted, per §5.
`.` and `..` are collapsed first, so the two spellings of one crt object
(`/usr/bin/../lib/gcc/...` in the map, the same in the trace) become one ref
instead of a spurious `VG-LINK-008`.

## Counting

Both subcommands print

```
inputs=N checked=N skipped=S
```

and exit non-zero when `N` is 0 unless `--allow-empty` was passed. Every skipped
case is printed **by name**: a count of skipped cases without their names tells
a reader that something was not checked without telling them what.

## Running the tests

The parsing and verdict logic is pure — no filesystem, no child process, no
clock — and runs anywhere:

```sh
node --test compiler/link-wrapper/test/refs.test.mjs \
             compiler/link-wrapper/test/map-parse.test.mjs \
             compiler/link-wrapper/test/trace-parse.test.mjs \
             compiler/link-wrapper/test/cmdline.test.mjs \
             compiler/link-wrapper/test/verdict.test.mjs \
             compiler/link-wrapper/test/external-map.test.mjs \
             compiler/link-wrapper/test/counting.test.mjs \
             compiler/link-wrapper/test/artifact-recheck.test.mjs \
             compiler/link-wrapper/test/canonical.test.mjs \
             compiler/link-wrapper/test/exit.test.mjs
```

Pass the files, not the directory: `node --test <dir>` throws
`MODULE_NOT_FOUND` on current runtimes. Let the shell expand a glob.

The live suite needs a real toolchain and **fails rather than skipping** when
there is none, because a skipped live test and a passing one are the same green
tick in a summary:

```sh
node --test compiler/link-wrapper/test/live-link.test.mjs           # 7 cases
VG_LINK_ALLOW_SKIP=1 node --test compiler/link-wrapper/test/live-link.test.mjs
```

With the variable set, the six toolchain cases skip and are listed by name in
the output. `VG_LINK_SCRATCH=<dir>` moves the live build off the system
temporary directory.

## The proofs of concept

```sh
VG_LINK_LAB=<dir> bash compiler/link-wrapper/tools/poc.sh
```

Ten cases, each in both directions: an unapproved object linked in (negative:
the approved link is clean), a post-link modification (negative: the untouched
artefact is not reported), an externally supplied map (negative: the ordinary
link is not refused), and the empty-scan guard. It fails if `clang-18` is
missing rather than reporting an empty success.

Every fixture carries a **control** whose zeroing cannot be optimised away —
`control_fn`'s buffer escapes into another translation unit — and the control's
authorisation is asserted in the positive run as well as the negative one. A run
in which the control moves says nothing about the thing being detected;
`tools/make-fixtures.sh` fails outright if the control's call site count reaches
zero, counted per function on `call void @llvm.memset` rather than on the
surviving `declare` line (interfaces.md §4).

## testdata/

Real output from LLD 18.1.3, captured by `tools/make-fixtures.sh`; regenerate it
with that script rather than editing by hand. A hand-written map agrees with the
parser by construction and proves only that the author was consistent with
themselves.

| file | link |
|---|---|
| `neg.map.txt` / `neg.trace` | two approved objects |
| `pos.map.txt` / `pos.trace` | the same, plus an unapproved object with a constructor |
| `arc.map.txt` / `arc.trace` | an archive member pulled in to resolve a symbol |
| `scr.map.txt` / `scr.trace` | a linker script that adds a section |
| `neg.elfhdr.hex` / `pos.elfhdr.hex` | the first 64 bytes of a real artefact, hex-encoded |

Two naming decisions, both forced by something outside this directory. The maps
are `.map.txt` because `.gitignore` ignores `compiler/**/*.map` — build products,
correctly — and a fixture that is never committed is a suite that only ever runs
on the machine that generated it; the ignore file is not this component's to
edit. The ELF headers are hex text rather than binary because a binary file is
reported as *skipped* by the repository's own scanners, and a fixture that
silently opts out of them is a small hole in a check that exists to have none.

## What this does not check

Stated rather than implied, because a reader is entitled to know where the
boundary is:

- **Only lld's map format is parsed.** GNU `ld` writes a different one. A link
  through `bfd` or `gold` produces no readable map here, and the wrapper reports
  that as exit 3 rather than as a clean link.
- **The linker script's contents are not analysed.** Its use is a finding when
  the policy forbids scripts; when the policy permits them, nothing here reads
  what it does.
- **A response file makes the command line unobservable** (`VG-LINK-011`,
  exit 3). Expanding one is not implemented.
- **`recheck` proves the artefact has not changed since the link, not that it is
  the artefact anyone intended.** It compares with the digest the same run
  sealed; a record and an artefact replaced together would agree with each
  other. Binding the record to something outside this component is the evidence
  layer's job, not this one's.
