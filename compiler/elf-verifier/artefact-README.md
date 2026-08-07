# artefact verifier — the `VG-ART` block, from this side of the boundary

`README.md` next to this file documents the *introduction analysis*: something
appeared in the artefact, which permitted origin put it there. This is the other
artefact question: something was supposed to be in it — is it?

The verifier itself lives in `packages/artifact-integrity/`, because the shipped
product needs it too and `packages/**` cannot reference `compiler/**`. What is
here is the part that belongs to the compiler tree:

| File | What it is |
|---|---|
| `artefact-fixtures.sh` | Builds the hardening matrix: one fixture, each flag on and off. |
| `artefact-ground-truth.md` | What the matrix actually showed. The detector was written against this, not against expectation. |
| `artefact-controls.mjs` | Checks that table with **this tree's** reader (`./lib/elf.mjs`), independently of the package. |

## Why the check is run twice

The table is asserted by two pieces of code that share no line:

```
packages/artifact-integrity/tools/verify-real-fixtures.mjs   its own reader   235 comparisons
compiler/elf-verifier/artefact-controls.mjs                  ./lib/elf.mjs   323 comparisons
```

The duplication is not an oversight. `packages/**` and `compiler/**` do not
reference each other in either direction, so a shared implementation is not
available; and given that, two independently written readers agreeing on
twenty-three real binaries is better evidence than one reader agreeing with
itself. Three of the six decisions are not duplicated at all — `decidePie`,
`decideRelroFull` and `decideNx` already existed in `./lib/elf.mjs` and are
called from `artefact-controls.mjs` rather than rewritten.

## Running it

```sh
bash compiler/elf-verifier/artefact-fixtures.sh /somewhere/matrix
node compiler/elf-verifier/artefact-controls.mjs --dir /somewhere/matrix/bin --verbose
```

Exit codes are the shared set (`../driver/lib/exit.mjs`): `0` agreement, `2` a
row disagrees, `3` nothing was checked.

`artefact-fixtures.sh` **fails rather than skipping** when `gcc`, `readelf`,
`objcopy` or `python3` is missing, and fails if any row of the matrix failed to
build: a table with holes in it reads as agreement, which is the worst thing a
control run can produce.

`artefact-controls.mjs` treats a fixture the table names and the directory does
not hold as a **failure**. `VG_ART_ALLOW_MISSING_FIXTURES=1` downgrades that to
a skip, lists every skipped fixture by name, and still exits `3` when nothing
was read, because an authorised skip of everything is not a pass either.

## What the table is for

Four rows contradict the implementation anyone would write first, and one row is
the reason two properties abstain instead of answering. They are set out in
`artefact-ground-truth.md` sections 2 and 3; the short version:

- `-Wl,-z,norelro` **leaves `DT_FLAGS=BIND_NOW` set**, so an eager-binding check
  passes a binary with no `PT_GNU_RELRO`.
- `-Wl,-z,relro,-z,lazy` **keeps `PT_GNU_RELRO`**, so a segment check passes a
  binary with lazy binding.
- `DT_BIND_NOW` is **absent on all 23 fixtures**, including the hardened link.
- `ET_DYN` alone reports a shared library as a position-independent executable.
- In a `-static` image `__stack_chk_fail` is **defined either way**, and the
  canary-load count is 355 against 353. Whole-image granularity cannot decide
  it, so the answer is `NOT_OBSERVED` and the exit code is 3.

## Not touched

Nothing in this directory that existed before was edited. `baseline.mjs`,
`classify.mjs`, `controls.mjs`, `run-controls.mjs`, `test-units.mjs`,
`README.md` and everything under `lib/` are another block's, and
`artefact-controls.mjs` only *imports* from `lib/elf.mjs`.
