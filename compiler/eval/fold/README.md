# eval/fold — three functions that mean different things, and whether they become one

This lane exists because a sentence was on the public website with no evidence
in this repository behind it.

`site/src/pages/research/compiler.astro` said that three functions meaning
entirely different things to a reader came out as the same fourteen bytes of
machine code at `-O2` on x86-64. The number was real — it came from a working
note — but the note is under a path the ignore rules keep out of the tree, so no
reader could check it, no test could hold it, and the page's own editorial rule
("a number the project will not put in its own paper has no business being the
first thing a stranger reads") applied to it. This lane is the artefact that
sentence needed.

## What it measures

`subjects.c` holds three functions and one control:

| symbol | what a reader would call it |
|---|---|
| `is_authorized` | an authorization decision |
| `feature_enabled` | a feature-flag read |
| `meaningless_probe` | written to mean nothing |
| `reads_second_field` | **negative control** — same shape, reads the second field |

Each of the three takes a pointer to a different struct, reads the first `int`,
and returns whether it is non-zero. To a person they are three decisions. To a
compiler they are one function: the type names are gone by the time it decides
that.

`run-fold.mjs` compiles `subjects.c`, disassembles the object, collects each
function's encoded bytes keyed by symbol, and asks whether the three subjects are
byte-identical.

## Results, measured 2026-09-13

`clang-18` 18.1.3 (Ubuntu 1ubuntu1) and `gcc-13` 13.3.0 (Ubuntu
13.3.0-6ubuntu2~24.04.1), x86-64. `data/fold-rows.json` and
`data/fold-results.txt` are this run.

| compiler | level | verdict | bytes | encoding |
|---|---|---|---:|---|
| `clang-18` | `-O0` | identical | 25 | |
| `clang-18` | `-O2` | identical | **9** | `31 c0 83 3f 00 0f 95 c0 c3` |
| `gcc-13` | `-O0` | identical | 28 | |
| `gcc-13` | `-O2` | identical | **14** | `f3 0f 1e fa 8b 17 31 c0 85 d2 0f 95 c0 c3` |

The negative control differs from the three in every one of the four
configurations.

### Two things this changed about the claim

**The fourteen bytes are gcc's number, not the result's number.** clang gives
nine for the same source at the same level. The difference is the four-byte
`endbr64` that Ubuntu's gcc emits by default for branch protection and Ubuntu's
clang does not; the ten bytes of actual work are the same. Quoting "fourteen
bytes" without naming the compiler attaches a toolchain default to a finding
about code.

**Optimisation is not what folds them.** `-O0` was added to this lane expecting
the three to stay distinct there, which would have made the fold something the
optimiser does. They are identical at `-O0` too, on both compilers. The three
are the same computation as written; `-O2` only shortens the code they share.
The finding is that nothing in the toolchain tells you the distinction stopped
existing — not that `-O2` destroyed it.

## Why the negative control decides whether a run counts

The failure this lane has to rule out is a comparison of two empty strings
reporting agreement. `reads_second_field` has the same shape as the three and
differs only in which field it reads, so it cannot legitimately fold with them.
If it ever reads identical, or if any symbol's byte string comes back empty, the
runner exits non-zero and writes nothing rather than reporting a fold.

## Why bytes, and why padding is excluded

Comparing mnemonics would let a register-allocation difference read as
agreement. Comparing whole-file disassembly would let the symbol names decide it.
So the comparison is over encoded bytes, keyed by symbol.

Trailing alignment padding sits inside the address range `objdump` prints for a
function and is not part of the function. Including it added 7 bytes under clang
and 6 under gcc at `-O2` — half again the code itself, decided by the next
symbol's alignment rather than by anything in the source. `byteCount` excludes
it; `byteCountWithPadding` is what a naive read of `objdump` would give. Both are
in the rows because the gap between them is the mistake the field exists to
prevent.

## Running it

Needs the two compilers and `objdump` on PATH. There is no fallback: a missing
compiler exits 5 rather than reporting a narrower run as a complete one. Five and
not four, because `interfaces.md` section 7 gives 4 to a digest that does not
match its pin or a malformed policy, and gives 5 to a measuring harness that
could not be set up — which is what an absent compiler is.

```sh
node compiler/eval/fold/run-fold.mjs                  # print
node compiler/eval/fold/run-fold.mjs --write-data     # refresh data/
node compiler/eval/fold/run-fold.mjs --cc clang-18    # one compiler
```

Exit 0 when every configuration was measured, 3 when a control failed, 5 when a
tool could not be used.

`test/fold.test.mjs` needs neither compiler: it checks the tracked rows for the
shape and the properties the lane promises, and exercises the disassembly reader
against stored `objdump` output including the padding case.

## Limits

- **Four configurations, one source file, one architecture.** This says nothing
  about how often such a fold happens in real code, and it is not a rate.
- **Two compilers at one version each**, both as Ubuntu packages them. The
  branch-protection default that decides the byte count is the distribution's,
  not the compiler's.
- **The three subjects were written to fold.** That is the point — the lane
  measures that they do, and that the control does not — but it is a
  demonstration with a control, not a survey.
- **`-O1`, `-O3` and `-Os` are not measured.** `-O0` and `-O2` were chosen
  because they are what the claim needs: one level where the fold could have been
  absent, and the level the claim names.
