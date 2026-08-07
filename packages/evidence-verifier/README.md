# @vibeguard/evidence-verifier

Checks an evidence-carrying artefact bundle: do the files in this directory
agree with each other, and does the record agree with the artefact it names?

```sh
node bin/verify-bundle.mjs --bundle  out/wipe/     # one bundle
node bin/verify-bundle.mjs --bundles out/          # every bundle under a root
node bin/check-contract-copies.mjs                 # all copies of the contract agree
node bin/check-fence.mjs                           # are these packages fenced?
npm test -w @vibeguard/evidence-verifier
```

Exit codes are the shared ones: **0** clean, **2** findings at or above the
threshold, **3** the run could not be completed, **4** a record or manifest that
cannot be canonicalised at all. Three is never conflated with zero — that is the
code that keeps "we did not look" from being reported as "it is clean".

## What it cannot do — read this before the rest

**A bundle that was REGENERATED is not detected, and cannot be by any amount of
hashing.** Every digest in a bundle is computed from the bundle's own contents,
so a bundle rebuilt from different inputs is internally consistent and verifies
clean — correctly, given the question being asked. Anyone who can write the
bundle directory can write a bundle that passes.

There is a test called *"a REGENERATED bundle verifies CLEAN — this is the
limit, not a bug"*. It takes the real artefact bytes, writes a **new record
claiming the security property survived**, seals it properly, and asserts the
verifier reports `VERIFIED_CLEAN`. It does. A limit stated in a README is a
limit people skim; a limit with a passing test next to it is one they remember.

Closing it needs three things this package does not have: a detached signature
over the canonical text (the same bytes the digest is taken over, so "the
signature verifies" and "the digest matches" cannot come apart), a way to
distribute the public half, and a decision about who holds the private half.
Until then this is **modification** detection, not tamper detection.

Two smaller limits, also reported in every result and printed by the CLI on
every run:

- a change confined to **insignificant whitespace in `manifest.json`** is not
  detected. The manifest commits to its canonical *meaning*, and a file cannot
  commit to its own bytes. Every other file in the bundle is covered
  byte-for-byte. Measured: with a single-bit flip there is in fact no such
  change — JSON's only whitespace is space, tab, LF and CR, and flipping the low
  bit of any of them produces a character `JSON.parse` refuses — so the sweep in
  `test/reject-one-byte.test.mjs` rejects **every** byte of the manifest. The
  branch is still there so the claim is exact rather than lucky;
- the record's **internal semantics** — the confidence table, the stage table,
  coverage against `states[]` — are the toolchain-side verifier's job and are
  not re-checked here. This package checks the *binding*.

## What it does check

| Id | Condition |
|---|---|
| `VG-ART-050` | the record's `evidenceDigest` does not seal the record |
| `VG-ART-060` | the artefact the record names is not in the bundle |
| `VG-ART-061` | the artefact's bytes do not hash to what the record says |
| `VG-ART-062` | the manifest names a different `evidenceDigest` |
| `VG-ART-080` | `bundleDigest` does not match the manifest it seals |
| `VG-ART-081` | the manifest's two copies of `evidenceDigest` disagree |
| `VG-ART-082` | the manifest lists no files, so it commits to nothing |
| `VG-ART-083` | a file the manifest lists is missing from the bundle |
| `VG-ART-084` | a listed file's length differs — truncated or extended |
| `VG-ART-085` | a listed file's content differs |
| `VG-ART-086` | the bundle holds a file the manifest does not list |
| `VG-ART-087` | the manifest and the record name different artefacts |
| `VG-ART-088` | a measurement's control count is zero |
| `VG-ART-089` | a verdict and its effect count disagree on zero-versus-nonzero |
| `VG-ART-090` | a state name outside the six-state vocabulary |
| `VG-ART-091` | `REINTRODUCED` with no preceding loss in the same history |
| `VG-ART-092` | `contextDigest` does not match the context it commits to |

The first four name conditions the toolchain-side verifier already names, and
the ids are reused on purpose: one condition, one id. Two ids for one condition
produces a report that has to be read twice to notice it says one thing. The new
band starts at 080 because 050–069 is the toolchain's record-internal band and
070–079 was already in use elsewhere in this namespace.

A field nobody could check is **not** a field that passed: an unchecked field
puts the verdict at `VERIFICATION_INCOMPLETE`, not `VERIFIED_CLEAN`.

## Why this does not import the generator

One line would do it, and it would make every check here vacuous: two sides that
share an implementation agree by construction, so "the digest matches" would
mean "the same function was run twice", which is true of a correct record and of
a broken one alike. The toolchain workspace made the same decision for the same
reason.

`src/rederive.mjs` is therefore a **fourth** independent implementation of the
canonicalisation rules, in a fourth shape: two-phase — validate the whole tree
collecting every violation with its path, then emit — where the generator next
door is a single-pass iterative emitter. It uses `JSON.stringify` for string
literals where the generator hand-rolls the escaper, so the vectors covering
control characters, astral planes and combining marks compare two genuinely
different escapers.

The only thing the two sides share is the **contract**: `digest-vectors.json`,
vendored here as well, byte for byte. Both sides reproduce all 22 vectors and
refuse all 8 must-fail inputs, and `bin/verify-bundle.mjs` checks that before it
reads any bundle — an uncalibrated canonicaliser cannot tell a bad record from
its own bug, and it will report the second as the first with a critical severity
attached. A calibration failure exits 3, not 2: there are no findings, only a
broken tool.

### Keeping the copies honest

`bin/check-contract-copies.mjs` asks git for everything that would reach a
commit, keeps every file named `digest-vectors.json` wherever it lives, and
requires them all to agree. It names no directory, so it covers the toolchain
copy without pointing at it — which matters, because a quoted path into that
directory would itself be a boundary violation. Fewer than two copies is a
failure: "all copies agree" is trivially true of one copy and of none.

Measured 2026-08-07: `inputs=3 checked=3 skipped=0`, all three agreeing on
`c859dc00…`.

## Are these packages fenced out of the shipped bundles? — MEASURED: NO

`bin/check-fence.mjs` reads the packaging invariants script and reports whether
both packages appear in `CLI_ONLY_PACKAGES` and `CLI_ONLY_PATH_TOKENS`. It
parses those two array literals rather than grepping the file, because that file
is mostly commentary and several comments discuss which packages are CLI-only; a
substring match would report a fence that does not exist, which is worse than
reporting none.

Measured 2026-08-07, and this is the state as this package was written:

```
inputs=2 checked=2 skipped=0
NOT FENCED @vibeguard/evidence-bundle    — missing from CLI_ONLY_PACKAGES and CLI_ONLY_PATH_TOKENS
NOT FENCED @vibeguard/evidence-verifier  — missing from CLI_ONLY_PACKAGES and CLI_ONLY_PATH_TOKENS
exit 2
```

**A new package under `packages/` is not automatically fenced.** The toolchain
README says so in as many words, and the probe confirms it: the load-bearing
import-boundary invariant works from a list of names, and a package that is not
on the list is not looked for. The bundle-leak probe is name-based too. Nothing
else stands in the way — the workspace glob already includes these packages, so
they install and resolve like any other.

The remedy is two entries in one file, and that file is not this package's to
edit:

```
scripts/check-packaging-invariants.mjs
  CLI_ONLY_PACKAGES    += '@vibeguard/evidence-bundle', '@vibeguard/evidence-verifier'
  CLI_ONLY_PATH_TOKENS += 'evidence-bundle', 'evidence-verifier'
```

The test suite asserts that the **probe** works, in both directions, against
sources it writes itself — and asserts that it can still find its subject in the
real file. It deliberately does **not** assert today's answer: a test asserting
"fenced" would be red until somebody else changes that file, and one asserting
"not fenced" would go red the day they do. A test that breaks when the bug is
fixed is worse than no test. The live answer comes from `npm run check:fence`.

## Counting contract

Every runner prints `inputs=N checked=N skipped=S` on every path, including the
failing ones, and exits non-zero when `N` is zero unless `--allow-empty` was
passed. Skipped cases are listed by name. A missing prerequisite fails rather
than skipping — `check-contract-copies` without a git checkout exits 3 with the
reason, it does not report agreement.

An **empty bundle directory** gets the same treatment inside `verifyBundle`
itself: it is `VERIFICATION_INCOMPLETE` with the error *"contains no files … a
different answer from verified"*, never `VERIFIED_CLEAN`.

## Running time

The one-byte sweeps are exhaustive rather than sampled: every byte of the
artefact, of `evidence.json` and of `manifest.json` is flipped and re-verified.
That is about 2,900 full verifications, measured at roughly 36 s on the Windows
development machine and expected to be several times faster on Linux. It is the
strongest form of the claim and it is why the suite is not instant.
