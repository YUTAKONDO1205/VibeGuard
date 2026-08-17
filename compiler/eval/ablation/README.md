# eval/ablation — the design plan section 24, run rather than estimated

Nine configurations, A–I, each switching on a subset of the six components, each
scored on whether it detected a security property that did not survive
compilation and whether it could say why.

```sh
node compiler/eval/ablation/run-ablation.mjs \
     --lab $LAB \
     --out $LAB/_results-wave2/ablation
```

`--lab` is the measurement workspace holding `fixtures/`, `scripts/lib/` and the
signed evidence bundles. Nothing is built or measured under `compiler/`; nothing
is written inside `--lab/_results`.

Options: `--fixtures a,b`, `--opts -O0,-O2`, `--compilers clang-18`,
`--skip-tamper`, `--observer <path.so>`, `--ast-plugin <path.so>`, `--cli <path>`,
`--pubkey <path>`.

---

## 1. What each letter is, in this repository

§24 names configurations by component. Which directory each component *is* is a
claim about this tree, and it is made in `lib/configs.mjs` so that it can be
disagreed with in one place.

| | Component | Driven here as |
|---|---|---|
| Source Gate | the shipped analyser | `apps/cli/dist/index.js <dir> --format json` |
| AST Gate | `compiler/clang-plugin` | `libIntentGate.so` + `tools/lexscan.mjs` + `rules/default-rules.json` |
| Pre/Post IR | `compiler/llvm-pass` | the `ir-pre` and `ir-post` checkpoints through the shared predicate |
| Pass-Level Tracking | `compiler/pass-instrumentation/observer` | `libPropertyObserver.so`, `OBS_*`, standard mode |
| Object/Link Integrity | `compiler/elf-verifier` + `compiler/link-wrapper` | **not these** — see §5 |
| Evidence Verifier | `scripts/evidence-verify.mjs` | the tamper matrix in `lib/tamper.mjs` |

Configurations, verbatim from §24: `A`=Source, `B`=AST, `C`=Pre/Post IR,
`D`=Pass tracking, `E`=Object/Link, `F`=Evidence Verifier, `G`=A+C, `H`=A+C+D,
`I`=A+C+D+E+F. **The AST Gate appears in no combination.** That is §24's shape,
not an omission here.

## 2. What counts as a loss

A configuration cannot be scored until something else says whether there was
anything to detect. Three candidates existed:

1. the manifest's `hypothesis.firstLossStage` — rejected, it is the experiment's
   expectation, and scoring detectors against an expectation measures agreement
   with the author;
2. the existing `_results/trace-*.json` — rejected, those come from the same
   checkpoint chain gates B and C are, so a gate would be scored against its own
   output;
3. **the assembly layer**, read through the shared predicate, with the fixture's
   co-resident control required to be visible in the same text.

(3) is used. `LOST` means the effect is absent from the subject *while the
control still shows it*, which is what separates "the compiler removed it" from
"the oracle cannot see this form of it". At `-O1` and above a wipe is frequently
rendered as inline zeroing rather than a call, and an oracle without the control
would report every such cell as a loss.

It is **not** independent of gates B and C in implementation: all three call
`predicates.evaluate`. They differ in the layer they read, not in the matcher.
See §6.

## 3. Measured — clang 18.1.3 / gcc 13.3.0, Ubuntu 24.04 (WSL2), 2026-08-17

88 cells: 5 measurement fixtures × 2 compilers × 4 optimisation levels ×
mitigation off/on = 80 scored, plus 8 artefact-only cells (`notappear`) that are
reported and never scored. 38 of the 80 are losses.

```
configuration  label                       recall  falseAlarm  tp fn fp tn excl  explained/losses
A              Source Gate only            0.447   0.357       17 21 15 27    0  0/38
B              AST Gate only               0.000   0.000        0  3  0  5   72  0/38
C              Pre-Post IR comparison only 0.471   0.000        8  9  0 23   40  0/38
D              Pass-Level Tracking only    0.471   0.000        8  9  0 23   40  8/38
E              Object-Link Integrity only  1.000   0.000       29  0  0 42    9  0/38
F              Evidence Verifier only      n/a     n/a          0  0  0  0   80  0/38
G              A + C                       0.605   0.357       23 15 15 27    0  0/38
H              A + C + D                   0.605   0.357       23 15 15 27    0  8/38
I              A + C + D + E + F           1.000   0.357       38  0 15 27    0  8/38
```

`excl` is not a miss. It is the count of cells where the component was never
asked: `UNSUPPORTED` (no rule in its table, or a compiler it cannot be loaded
into), `NOT_APPLICABLE` (it answers a different question), or
`VERIFICATION_INCOMPLETE` (it ran and its own validity check failed). Folding
those into `fn` would produce a recall that reads as "this component missed it"
for cells where it was never run.

### The four things §24 asks

**Which components contributed to recall.** Every increment is attributable to
exactly one component. A alone reaches 0.447 but with a 0.357 false-alarm rate;
adding C (`G`) takes recall to 0.605 and moves the false alarms not at all,
because C never produces one. Adding D (`H`) changes recall by **nothing** —
0.605 to 0.605. Adding E (`I`) closes the remaining 15 losses.

**Whether Pass-Level Tracking improved the explanation.** This is the clean
result. `C` and `D` detect the *identical* eight cells — verified by set
comparison, not by matching totals:

```
erasure/clang-18__O2__mit-off   erasure/clang-18__O3__mit-off
nullcheck/clang-18__O1__mit-off nullcheck/clang-18__O2__mit-off nullcheck/clang-18__O3__mit-off
signedovf/clang-18__O1__mit-off signedovf/clang-18__O2__mit-off signedovf/clang-18__O3__mit-off
```

C names no pass on any of them; D names one on all eight — `DSEPass` for
`erasure`, `EarlyCSEPass` for `nullcheck` and `signedovf`. **Pass-Level Tracking
added 0.000 recall and 8/8 explanations.** In the combinations: `G` explains
0/38 losses, `H` explains 8/38 with the same recall as `G`. That is what "does
this component improve cause attribution" looks like when the answer is yes and
the answer to "does it find more" is no.

**Source Gate + Compiler Gate.** A is configuration-blind — it reads source, so
it returns the same verdict for all sixteen cells of a fixture. Every one of its
15 false alarms is that blindness: eight are `authz` cells where the assert is
still in the binary because `-DNDEBUG` was not passed, and seven are `erasure`
cells where the wipe survived. The compiler-stage components have a
false-alarm rate of 0.000 and cannot see the two fixtures whose loss happens
before the optimiser runs. Neither is a substitute for the other, and the
measured shape of the combination is that A supplies coverage of the
preprocessor-stage losses and C/D supply the discrimination A does not have.

**What the Evidence Verifier detected.** Ten alterations, ten detected, with the
untouched copy coming back `VERIFIED_CLEAN`:

| alteration | class | verdict | finding |
|---|---|---|---|
| *(nothing)* | negative control | `VERIFIED_CLEAN` | — |
| one byte of the binary flipped | artefact content | `BAD_SIGNATURE` | `HASH_MISMATCH` |
| …and the manifest digest recomputed over it | artefact content, resealed digest | `BAD_SIGNATURE` | `BAD_SIGNATURE` |
| a value inside `evidence.json` rewritten | record content | `BAD_SIGNATURE` | `HASH_MISMATCH` |
| …and the manifest digest recomputed over it | record content, resealed digest | `BAD_SIGNATURE` | `BAD_SIGNATURE` |
| a file added that the manifest does not list | bundle membership | `BAD_SIGNATURE` | `EXTRA_FILE` |
| a listed file deleted | bundle membership | `BAD_SIGNATURE` | `MISSING_FILE` |
| the signature deleted | seal presence | `UNSIGNED` | `UNSIGNED` |
| another signed bundle's signature substituted | seal substitution | `BAD_SIGNATURE` | `BAD_SIGNATURE` |
| a member replaced by a symlink out of the bundle | path escape | `SYMLINK_ESCAPE` | `SYMLINK_ESCAPE`, `MISSING_FILE` |
| a duplicate `bundleId` key in the manifest | record parse ambiguity | `BAD_SIGNATURE` | `BAD_SIGNATURE` |

Nine classes, all detected. The *verdict* word is coarse — seven of ten come
back `BAD_SIGNATURE` — but the finding code separates them, and both are
recorded. What is **not** claimed: that the verifier named the alteration
correctly. "Detected" here means it refused to call the bundle clean.

### Two results that were not the point but are worth reading

**`erasure` at `-O1` is lost in the backend.** Present at `preprocess`, `ast`,
`ir-pre` *and* `ir-post`; absent at `asm`. The observer saw 536 pass invocations
and no state change. C and D both correctly report `NOT_DETECTED` with a reason,
and the loss is still real. This independently reproduces what
`compiler/llvm-pass/README.md` states about its own scope limit — the IR
components stop at the end of the IR optimiser.

**`configguard` is invisible to the Source Gate.** Its defence is inside
`#ifdef ENABLE_AUTH`; the shipped analyser reports nothing anywhere in the
fixture, so A scores 0/8 on it. `nullcheck` and `signedovf` are the same: 0
findings. A's whole 17 true positives come from two fixtures.

### The harness's own controls

Twelve, all held, run on two property families in the same invocation and
recorded in `harnessControls` in the output.

| polarity | control | must produce | observed |
|---|---|---|---|
| negative | observer loaded with no `OBS_*` | exit 0, no log, `refusing to install` | exactly that; the object file is still produced |
| red | observer pointed at a subject name that does not exist | exit 0, non-empty log, control `resolved`, subject **not** `resolved` | 650 passes seen, control `resolved`, subject `not-in-module` |
| red | ground-truth oracle given a control function not in the text | `INVALID_CONTROL` | `INVALID_CONTROL` |
| red | ground-truth oracle given a fictional effect symbol | family-dependent, see below | as predicted, on both families |
| positive | the same oracle, correctly configured | not `INVALID_CONTROL` | `ABSENT`, control count 2 |
| positive | the observer, correctly configured | handshake + subject resolved + a SUMMARY row | `DSEPass`, `LOST`, 650 passes |

The second row is the one that matters: **every invariant a co-resident control
can check is satisfied in that run.** The control resolves, the control is
`PRESENT`, hundreds of passes are counted, and only the subject's rows are
missing — which is also what a subject erased before the first boundary looks
like. `SUBJECTRES` is the only thing separating them, and column D reports
`VERIFICATION_INCOMPLETE` rather than a clean `NOT_DETECTED`.

The fourth row records a real limit rather than a pass. For `callSite` and
`guardedCheck` the symbol list *is* the oracle, so a fictional list blinds it and
the control catches that. For `erasure` it is not: the assembly extractor also
counts inline zeroing stores, which no symbol list turns off, so a wrong symbol
list is **not** caught. The co-resident control defends against the compiler
changing the *form* of the effect. It does not defend against the oracle being
pointed at the wrong effect.

## 4. Where B stands

The AST Gate ran on 8 of 80 cells and detected nothing.

It could not run on 72 for two stated reasons, both recorded per cell: 40 are
`gcc-13` cells, where a clang plugin cannot be loaded; 32 are cells whose
property has no entry in `rules/default-rules.json` — the table targets
`system`/`popen`, the exec family, `gets`, the `str*` family, `memset` and
`explicit_bzero`, and `assert`, `verify_user`, `on_null` and `on_overflow` are
none of those. **Nothing was added to the rule table for this run.** Extending
it would have meant inventing the standard the component is measured against.

On the 8 cells where it did run it returned `Confirmed / direct-call` at the
anchor in all of them, at `-O0` through `-O3`. That is correct and is not a
detection: the AST does not change when the optimiser runs. The gate's product
on those cells is a Derived Requirement (`must-survive`, scope
`function handle_request`, oracle `call-site memset`, expected count 1), which is
recorded in each cell's evidence. B detects a loss only when the loss happens at
or before the AST — a `-DNDEBUG` or an `#ifdef` — and the two fixtures with
exactly that shape are the two its rule table does not cover.

## 5. Column E is not elf-verifier

Both components were invoked and neither produced column E. The attempt is in
`attemptedNotUsed` in the output rather than left to be inferred from an absence.

- `compiler/elf-verifier/classify.mjs` answers "which permitted origin put this
  symbol in the artefact" and refuses without a baseline keyed by (toolchain
  digest, flag set, link form), with no nearest-match lookup by design. Forty
  such baselines were not built in this run.
- `compiler/link-wrapper/vg-link.mjs` compares one link against a `policy.link`
  document. No such policy exists for these fixtures, and writing one here would
  have meant inventing the standard.

What column E actually is: for the artefact-marker fixture, a byte search of the
linked executable for the `mustNotAppear` markers with the control marker
required present. For the must-survive fixtures, `objdump -d` of the subject
function in the linked executable, looking for a call to an effect symbol, with
the control function required to still make one. It is a **call-form-only**
oracle and it says so in every record it writes. That is why it refused nine
cells: all nine are `erasure`, where the surviving wipe is inline zeroing and
there is no call for it to see in either function.

## 6. What this does not measure

- **`I` is not the Beyond integrated system.** No `beyond/` directory exists in
  this repository. `I` is the union of the five components that do exist, and it
  is labelled that way in the output.
- **`E`'s recall is close to tautological.** E and the ground-truth oracle ask
  nearly the same question one layer apart — is the effect still in the subject
  at the end. 1.000 is not evidence that an artefact check is the best detector.
  Its informative columns are the nine cells it refused and the zero passes it
  named.
- **B and C share a matcher with the ground truth.** All three call
  `predicates.evaluate`. A false negative common to that matcher is invisible to
  this harness.
- **The rule tables were not extended.** A's coverage (2 of 5 fixtures) and B's
  (1 of 5) are properties of the shipped rule sets on this fixture set, not
  limits of the components' designs.
- **The tamper matrix measures refusal, not diagnosis.** Whether the verifier
  named each alteration correctly is recorded per row and is not aggregated.
- **One fixture per property kind, one machine, one toolchain pair.** Six
  fixtures is not a corpus. No OSS project was compiled here; the 11 pinned
  builds under `oss/` are not touched by this harness.
- **No timing, memory or build-slowdown figure is taken.**
- **The toolchain digest is absent.** `toolchainProvenance()` in the workspace
  returned `{ toolchainDigest: null, unresolved: "toolchain.json missing" }`, so
  the record names the compilers but does not pin their bytes. That is carried
  into the output rather than filled in.
- **`notappear`'s eight cells are reported and never scored.** It declares
  artefact markers, not a compiled property, so there is no assembly-layer oracle
  for it and it enters no denominator. E detected both markers in all eight.

## 7. Output

`ablation.json` (~500 KB) and `summary.txt` under `--out`. The JSON carries every
cell with its five checkpoint verdicts, its ground truth and reason, all six gate
results with their reasons and evidence, the nine configuration results, the
per-component and per-configuration tallies, the harness controls, the tamper
matrix and `notMeasured`.

Files under `--lab/_results` are not read for anything except the evidence
bundles, which are copied before being altered, and are never written to.
