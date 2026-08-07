# @vibeguard/evidence-bundle

Builds an **evidence-carrying artefact**: the bytes that were produced, the
record that describes how they were produced, and a manifest that binds the two
so that a third party can check the binding without trusting whoever handed it
over.

This is the generator half. The checker is `@vibeguard/evidence-verifier`, and
the two deliberately share no code — see "Why there is a third canonicaliser
here" below.

```
<bundle>/
  artifact/<name>     the bytes that were produced
  evidence.json       the sealed evidence-v0 record
  manifest.json       what is in this bundle, and its digest
```

```sh
node bin/seal-bundle.mjs --out out/ --records records/
node bin/calibrate.mjs                 # reproduce every digest vector
npm test -w @vibeguard/evidence-bundle
```

## Keeping the schema

The record is `evidence-v0` and the five canonicalisation rules are the ones
`schema/interfaces.md` section 5 fixes. Nothing here changes them:

1. `context` and `evidenceDigest` are removed from the **top level** before
   digesting, `context` as a whole subtree. Nothing else is removed, at any
   depth — a key called `context` below the top level is an ordinary key.
2. Object keys sort lexicographically at every level, inside arrays of objects
   too. Array order is significant and is never sorted.
3. No insignificant whitespace.
4. Every number is an integer. A ratio is a pair of integer counts,
   `{"num": 3, "den": 4}`, never a float. A non-integer is a malformed record
   and the canonicaliser fails rather than rounding.
5. SHA-256 over the UTF-8 bytes of the canonical text, lowercase hex.

The compatibility oracle is `testdata/digest-vectors.json`, vendored byte for
byte from the toolchain workspace. Both canonicalisers in this pair reproduce
every one of its 22 vectors and refuse all 8 of its must-fail inputs; that is
what `npm test` asserts first, and it is the only claim worth making about a
canonicaliser.

## Why there is a third canonicaliser here, rather than a vendored copy

The constraint that decides the design: nothing under `packages/` may import
from the toolchain workspace at the repository root. The boundary is zero in
both directions and a release-time invariant enforces it, because a user who
installs an editor extension has not agreed to install a compiler. So the
existing canonicaliser could not be imported, and the choice was:

**(a) Vendor the implementation, with a drift test.** Copy the code, and add a
test that fails when the two copies differ. Rejected, for two reasons:

- it proves only that two files are the same file. A bug in the shared
  implementation is in both copies, the drift test is green, and every digest is
  wrong in both places;
- the drift test has to READ the toolchain copy, and a quoted path reaching into
  that directory — in any source file under a workspace, tests included — is
  exactly what the boundary invariant refuses. The check could not live here.

**(b) Vendor the CONTRACT and write a third independent implementation.** Taken.
The digest vectors are copied byte for byte; the code is not. `src/canon.mjs` is
written from the five rules in a third shape — an iterative emitter driven by an
explicit work stack, with a hand-rolled string escaper and an explicit code-unit
key comparator — so it shares no line of reasoning with the two implementations
in the toolchain workspace, and the verifier next door is a fourth. Three
implementations that reproduce the same vectors are three pieces of evidence
about the rules. Two copies of one implementation are one.

The drift question does not disappear; it moves, and gets better. It becomes
"does every copy of the contract in this repository still say the same thing?",
which is a question about data files. `evidence-verifier`'s
`check-contract-copies` answers it by asking git for everything that would reach
a commit and comparing every file with the contract's name, wherever it lives —
so the toolchain copy is covered without this package naming a path to it, and a
fourth copy added next month is covered the day it appears.

The pin is over parsed **content**, not file bytes: this checkout converts line
endings for everything the root attributes file does not pin, so a byte pin
would fail for a reason that has nothing to do with the vectors. There is a
`.gitattributes` here fixing LF as well, so the raw bytes should also stay put;
that is a belt, and the content pin is the braces.

## What binds what

| Binding | Covers |
|---|---|
| `record.artifact.sha256` | the artefact bytes |
| `manifest.files[]` (digest **and** length) | every byte of every other file in the bundle |
| `manifest.bundleDigest` | the manifest's own canonical meaning |
| `manifest.contextDigest` | the `context` subtree that rule 1 excludes |
| `manifest.binds.evidenceDigest` | the record |

`manifest.evidenceDigest` is carried twice on purpose. Rule 1 excludes the
top-level key from every digest, so a top-level copy alone would be editable
without moving `bundleDigest`; the toolchain-side verifier reads that name, so
it has to stay. The same value therefore also sits at `binds.evidenceDigest`,
one level down where rule 1 does not reach, and the verifier compares the two.

`contextDigest` closes the matching hole for `context`: rule 1 removes the
subtree, so without it the whole volatile block could be rewritten and every
digest would still check out. The price is that a **manifest's** context must be
canonicalisable — integers only — which is stricter than a record's, where rule
1 makes a float harmless. `contextDigestOf` refuses rather than letting that
surprise anyone later.

## What is checked before a record is written

`sealRecord` gates before it digests, so a record that should not exist is never
digested and never referenced:

- **absolute paths** (`src/paths.mjs`). A record carrying a per-user home
  directory publishes an account name the moment it is committed, and a record
  that only resolves on one machine is not reproducible. Relative paths, URLs
  and ordinary strings are left alone — a gate that reddens on ordinary content
  is a gate someone turns off.
- **the state vocabulary and the oracle rule** (`src/states.mjs`).

## Property states and the oracle rule

The vocabulary is the six states of `schema/interfaces.md` section 3: `PRESENT`,
`ABSENT`, `LOST`, `REINTRODUCED`, `NOT_APPLICABLE`, `NOT_OBSERVED`. The last two
exist because "we did not see it" and "it is not there" are different claims.

`stateHistory` keeps the **whole sequence**. The tempting implementation stops
at the first loss, which reports the loss a later pass undid and drops the one
that reached the artefact; a `PRESENT, LOST, REINTRODUCED, LOST` history returns
two losses here, and there is a test that says so.

The oracle rule is about counting the zeroing **call site**, never the symbol
name: a deleted call leaves its declaration behind, so a name search reports the
effect as present until some later pass sweeps declarations away and the loss is
attributed to the sweeper. Two consequences are checkable from the record's own
numbers and both are enforced:

- a **control** count of zero is a broken measurement, not a finding. Every
  fixture carries a control whose effect cannot be optimised away;
- the verdict and the count must agree on zero-versus-nonzero.

## Counting contract

Every runner prints `inputs=N checked=N skipped=S`, on every path including the
failing ones, and exits non-zero when `N` is zero unless `--allow-empty` was
passed. An empty scan is not a clean scan. Skipped cases are listed by name; a
missing prerequisite fails rather than skipping.

Proved rather than described — `test/cli.test.mjs` points `seal-bundle` at an
empty directory and asserts `inputs=0 checked=0 skipped=0` with exit 3, and at
the same directory with `--allow-empty` and asserts exit 0.

## Boundaries

- **No dependencies at all** — not on the other half of the pair, not on the
  toolchain workspace, not on the registry. Plain `.mjs`, no build step, so
  nothing has to be compiled before the tests run.
- **Not for the browser or the editor.** This is a CLI/Action-side package. See
  the verifier's README for what does and does not fence it out of the shipped
  bundles today; the answer is not automatic and is worth reading.
