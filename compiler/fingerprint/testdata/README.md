# Why these files are named `*.ll.txt`

They are LLVM textual IR. They are hand-written source, not build output, and
they are the only thing the normalisation tests have to compare against — if
they are not in the commit, twenty-odd tests fail with a missing file.

The repository ignores `compiler/**/*.ll` (`.gitignore`), which is the right
rule: generated IR is measurement input and belongs outside the tree. It does
not distinguish generated IR from a hand-written fixture, and it wins by
default, so these carry a second extension and stay committable.

Two consequences worth knowing:

- `llvm-as-18` reads by content, not by extension, so
  `tools/verify-testdata.sh` assembles every one of them exactly as if they
  were `.ll`. That is the check that keeps these from drifting into
  IR-shaped strings only this package's parser accepts.
- `cli/fp.mjs` accepts both extensions. A directory of real compiler output
  uses `.ll` and is not tracked; this directory uses `.ll.txt` and is.

The alternative was a negation in `.gitignore`
(`!compiler/fingerprint/testdata/*.ll`), which is a better fix and needs an
edit outside this package.

## What is in here

One pair per normalisation, plus a semantic control for each. `-a` and `-b` are
the two spellings of one program; `-sem` is a different program in the same
shape. `README.md` in the package directory has the table.
