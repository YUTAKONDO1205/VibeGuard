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
| `artefact-require.mjs` | The consumer of `policy.artifact` — **one** image against one policy. |
| `run-artefact-policy.mjs` | One policy against a **set** of artefacts, by running `artefact-require.mjs` over each. |
| `lib/artefact-set.mjs` | Which files in a build directory are artefacts. Selection only; it decides no verdict. |
| `artefact-policy.matrix.json` | A policy written for the fixture matrix, so the command below runs on something. |

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

## Running one policy over a set of artefacts

`artefact-require.mjs` reads one image. A build writes many, so `policy.artifact`
had a reader and no caller until `run-artefact-policy.mjs` existed:

```sh
node compiler/elf-verifier/run-artefact-policy.mjs \
  --policy compiler/elf-verifier/artefact-policy.matrix.json \
  --dir    compiler/elf-verifier/_results/artefact-matrix/bin
```

Measured against the 23-row matrix: `artefacts=23 inspected=23 skipped=0
findings=34 incomplete=2`, exit `2`. The two incomplete entries are
`libshared.so` and `wx-on`, which are built from different sources and carry
neither the control string nor the marker, so their scans are `BROKEN` rather
than clean.

It decides nothing itself. It does not parse the policy — each artefact is
handed to `artefact-require.mjs`, which validates it, including the
`expectStrings`-must-be-an-array guard — and it does not compute a severity.
The aggregate exit code is a precedence over the codes the children returned:
findings outrank incompleteness (2 beats 3), `3` never collapses into `0`, and a
child that rejects the policy (`4`) stops the run where it stands. The only
judgement added is *which files are artefacts*, and that is `lib/artefact-set.mjs`.

Exit codes are the shared set (`../driver/lib/exit.mjs`), deliberately not
`run-controls.mjs`'s `0`/`1`: that file predates the shared set, and its `1`
means "a case disagreed", which the shared set spells `2`.

**A run with nothing to inspect is `3`, and there is no flag to make it `0`.**
The matrix is git-ignored and absent from a clean checkout, so this is the
common case rather than an edge one — measured: an absent `--dir` gives
`artefacts=0 inspected=0 ... incomplete=2` and exit `3`; a directory of ordinary
build files gives `artefacts=2 inspected=0 skipped=2` and exit `3`, with every
passed-over file named and the reason it was passed over. `artefact-controls.mjs`
has `--allow-empty` and this does not: there an authorised skip of a named row
is a meaningful record, and here "the build satisfied a policy nothing was read
from" is not an answer anyone wants.

### Who reads the output

Whoever ran the build — a human today. **Nothing schedules this.** The CI job
that covers this directory runs `node test-units.mjs` and nothing else under
`compiler/elf-verifier/`; `test/artefact-policy-run.test.mjs` and
`test/artifact-policy.test.mjs` reach no runner either. Wiring it needs one step
in `.github/workflows/ci.yml`, which this file cannot honestly claim exists:

```yaml
      - name: Artefact policy
        run: node compiler/elf-verifier/run-artefact-policy.mjs --policy <p> --dir <d>
```

Until then this is a command that works and is documented, not a gate that runs.

### One limit it inherits and does not fix

The byte scan under it reports a hit, and refuses to report anything when its
control string is missing. It has **never been shown to report `CLEAN` with a
live control and a forbidden string configured**, because every image in the
matrix that carries the control also carries the marker
(`compiler/schema/properties.json`, `_notAnExtractor.artifactByteScan`). Running
the scan over 23 images instead of 1 does not change that; only a fixture that
holds the control and not the marker would.

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
