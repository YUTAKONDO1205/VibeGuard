# second-vendor

Widens the `#V7 SCE` configuration envelope by **one axis only**: a second compiler
vendor (`gcc-13`) measured alongside `clang-18` with the same instrument.

It does not widen the machine axis, and it does not produce pass-level
attribution for gcc. Both are recorded in the output as `UNSUPPORTED` rather than
left for a reader to assume.

## What the instrument is

For each `(vendor x optimisation x mitigation)` cell, the fixture's `target.c` is
compiled to assembly. The oracle extracts the body of the **subject** function and
asks whether the security-relevant effect is still in it, then does the same for
the fixture's **control** function.

`lib/asm-oracle.mjs` is deliberately vendor-neutral — there is no per-vendor
branch anywhere in it. A per-vendor branch is how a comparison quietly stops being
a comparison.

Two details in that file exist because getting them wrong produced wrong answers
during development, and both are commented at the code:

- **Tail calls count.** gcc at `-O2` emits `jmp report_denied@PLT` for a
  tail-called reporter. A `call`-only detector reports that defence as removed
  when it is plainly present.
- **Inlined zeroing counts.** At `-O1`+ neither vendor necessarily keeps a
  `memset` call; clang emits `xorps`/`movaps`, gcc emits `pxor`/`movaps`. Counting
  only the call reports a surviving wipe as lost.

## Vocabulary

These are different words for different findings and are not interchangeable:

| term | meaning |
| --- | --- |
| `PRESERVED` | effect observed in the subject, control also observed |
| `LOST` | effect absent from the subject while the control **was** observed in the same listing |
| `VERIFICATION_INCOMPLETE` | the control did not show its effect, so the oracle is blind here and the subject reading carries no information |
| `NOT_OBSERVED` | the subject function could not be read at all |
| `UNSUPPORTED` | the measurement cannot be taken in this setup at all (no machine, no plugin) — not the same as "we did not take it" |

Calling a blind cell `LOST` is the single most attractive way to manufacture a
result here, which is why `classifyCell` checks the control first.

## Scripts

Run in this order. Nothing here writes to `_results/`; output goes to
`_results-wave2/second-vendor/`.

```sh
node run-controls.mjs        # must pass before the table means anything
node run-second-vendor.mjs   # the 80-cell envelope + correspondence table
node run-crosscheck.mjs      # replication check against the prior envelope (read-only)
node run-gcc-dump-probe.mjs  # EXPLORATORY, see the warning below
```

### `run-controls.mjs`

Four controls per property per vendor. Exits non-zero if any fails; a failure
invalidates the corresponding rows rather than being worked around.

- **C1 positive** — a *witness* configuration must exist in which the unmodified
  subject reads `PRESENT`. The search starts at the property's reference
  configuration, which is defined against clang and is **not** automatically a
  witness under gcc. When it isn't, that is recorded as
  `referenceConfigIsWitness: false`.
- **C2 negative (red demonstration)** — the defence is deleted at source and
  recompiled at the *witness* configuration; the subject must flip to `ABSENT`.
  It must run at the witness, not the reference: mutating a configuration that
  already read `ABSENT` would "pass" by observing `ABSENT -> ABSENT` and
  demonstrate nothing. The deletion is by **line number**, because
  `erasure/target.c` carries the identical `memset(...)` text on both the subject
  line and the control line.
- **C3 control survives mutation** — in the mutant, the control must still read
  `PRESENT`, separating "the defence went away" from "the listing went away".
- **C4 silent-failure guard** — asking for a function that does not exist must
  return `NOT_OBSERVED`, never `ABSENT` and never `LOST`.

### `run-second-vendor.mjs`

Emits `second-vendor-envelope.json`, including the **correspondence table**, whose
categories are the point of the lane:

- `both-preserved` / `both-lost`
- `clang-preserved-gcc-lost`, `clang-lost-gcc-preserved` — **vendor-dependent**
- `indeterminate` — at least one side was not in `{PRESERVED, LOST}`; excluded
  from vendor-dependence counts

Every cell records whether each artifact was actually produced and `stat`ed. In
this project a compiler driver has returned `rc=0` alongside an empty output
directory, so `rc` is recorded as data and never treated as proof.

### `run-gcc-dump-probe.mjs` — EXPLORATORY, read before quoting

gcc cannot load an LLVM `-fpass-plugin`, so the the compiler-side toolchain observer that produces
`firstLossPass` has **no gcc counterpart**. That limitation stands.

gcc does, however, describe its own behaviour through `-fdump-tree-all`. This
probe walks those dumps and reports `firstAbsentDump`. The field name is
deliberately different:

| | the compiler-side toolchain observer (clang only) | gcc dump channel (this probe) |
| --- | --- | --- |
| what it is | an instrument we inject and cross-check | the compiler's self-report |
| independent confirmation | yes | **none** |
| field | `firstLossPass` | `firstAbsentDump` |

"gcc's first-absent dump was `042t.dse1`" is supportable. "we identified the
first-loss pass under gcc" is **not**, and this script emits no field that would
let anyone write it by accident.

The probe carries its own controls (`P1`–`P4`), including a **P3 no-loss control**
run on a cell the main table scored `PRESERVED`, which must report no
disappearance — otherwise the probe could be a detector that always finds one.

## Limitations, stated as such

- **Multi-machine: `UNSUPPORTED`.** One host is available. Nothing in the output
  may be read as evidence about machine-to-machine variation.
- **gcc pass attribution: `UNSUPPORTED`.** No LLVM pass plugin under gcc.
- **clang pass attribution in this run: `NOT_OBSERVED`.** Pass names for clang
  exist elsewhere (`_results/envelope.json`) but are deliberately *not* imported
  here. This run uses the asm instrument for both vendors so the comparison is
  symmetric; importing one side's richer instrument would silently change the
  instrument mid-table.
