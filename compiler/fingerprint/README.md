# General property fingerprint

A digest per IR function, computed from a canonical form of its instruction
graph, so that a security property's *shape* can be compared across
optimisation levels.

The thing that makes this different from everything else under `compiler/` is
what it does **not** know. The targeted extractors in `compiler/llvm-pass/`
each carry their own notion of "the effect" and "the thing the effect acts on";
one of them knows what a wipe is, another knows what a fail-closed branch is.
Nothing here knows either. The normaliser is property-class independent, and
that is the whole point of the block — it is also the reason it is allowed to
lose to the targeted version, which it does. **The measured result is at the
bottom of this file and it is negative.**

---

## The seven normalisations

| # | id | what it removes |
|---|---|---|
| 1 | `ssa-values` | Local value names. Every definition is renamed to its index in canonical order; parameters become `a0…`. |
| 2 | `block-names` | Basic-block labels. Blocks are numbered in reverse post-order from the entry, so the numbering follows the control-flow graph rather than the text. |
| 3 | `instruction-order` | *Part of* the instruction order. Within a maximal run of side-effect-free instructions, the run is put in a canonical dependency order. Anchors — `store`, `load`, `call`, `phi`, terminators — never move. |
| 4 | `inlined-calls` | The difference between a call and its expansion. Calls to callees the module defines are expanded, so the out-of-line form and the inlined form converge. |
| 5 | `commutative-operands` | Operand order where it does not matter. `add`/`mul`/`and`/`or`/`xor` operands are sorted; `icmp slt a, b` and `icmp sgt b, a` canonicalise to one form. |
| 6 | `debug-paths` | Debug information. `llvm.dbg.*` intrinsics, `!dbg` and `!DI*` attachments, and the source paths they carry. |
| 7 | `symbol-decoration` | Uniquing and clone suffixes on symbols (`.llvm.<digits>`, `.<digits>`, `.constprop.N`, `.isra.N`, `.cold`, …), plus linkage, visibility and attribute-group decoration. |

### Two steps that are NOT part of the seven

They are named here rather than folded in, because an eighth normalisation
smuggled in under one of the seven is how a stability number gets tuned.

- **`lexical`** — comments, whitespace, parameter attributes (`noundef`,
  `nocapture`, `dereferenceable(N)`, `align N`, …), poison and fast-math flags
  (`nsw`, `nuw`, `exact`, `inbounds`, `disjoint`, …) and the `tail` marker.
  **What this costs:** `nsw` and `inbounds` are semantic — they say a result is
  poison rather than wrapped. Two functions that differ only in those flags
  fingerprint the same here. They are dropped because optimisation adds and
  removes them freely, and keeping them would make every cross-level comparison
  fail for a reason that has nothing to do with the property.
- **`metadata-hints`** — non-debug metadata attachments: `!tbaa`, `!range`,
  `!prof`, `!llvm.loop`, `!noalias`, `!alias.scope` and friends. **What this
  costs:** a `!range` narrowing is real information about a value and it is
  discarded.

Both are always on. `--without <step>` can switch any of the nine off; the test
suite uses that to prove each of the seven is load-bearing.

---

## How each normalisation is proved

Every one of the seven has a tracked pair of `.ll` files and three assertions:

1. **PERTURBATION** — the pair differs only in the thing that step normalises,
   and the two fingerprints are equal.
2. **ISOLATION** — the same pair with *only that step disabled*, and the two
   fingerprints are now different.
3. **SEMANTIC** — a real difference in the same shape, and the fingerprints are
   different with the step enabled.

(1) alone is satisfied by `return 0`. (2) is what rules that out: it shows the
agreement in (1) was produced by that specific step. (3) rules out a normaliser
that has over-collapsed. The pairs:

| step | perturbation | semantic control |
|---|---|---|
| `ssa-values` | every local renamed | one use rewired (`add %x, %y` → `add %x, %x`) |
| `block-names` | labels renamed, including to the implicit numeric form with an unnamed entry block | the two arms of a conditional swapped |
| `instruction-order` | two independent pure instructions swapped | two stores to the same address swapped |
| `inlined-calls` | out-of-line vs already-inlined, single-block and multi-block callees | a caller written *character for character identically*, calling a callee whose body differs |
| `commutative-operands` | `add` operands flipped; `slt` written as `sgt` with operands flipped | `sub` operands swapped; the predicate changed without swapping operands |
| `debug-paths` | different source directory, different line numbers, value intrinsic dropped | identical debug information, one store operand changed |
| `symbol-decoration` | `@helper` vs `@helper.llvm.918273645` | `@helper` vs `@helper_other`, and `@helper` vs `@helper2` |

The last row's second control is the interesting one: an undecorator that ate
trailing digits without requiring the dot would merge `@helper2` into
`@helper`, and the fingerprint would stop being able to tell two callees apart.
There is a matching rule that `llvm.` names are never undecorated, because
`@llvm.memset.p0.i64` with a suffix stripped is an intrinsic that does not
exist.

All 28 testdata files assemble with `llvm-as-18` (`tools/verify-testdata.sh`),
so the pairs are real IR and not IR-shaped strings that only this parser
accepts.

They are named `*.ll.txt` rather than `*.ll`, because the repository ignores
`compiler/**/*.ll` and would otherwise drop every one of them at commit time.
`testdata/README.md` says so at the place where someone would notice the odd
extension, and names the cleaner fix that needs an edit outside this package.

---

## Running it

```sh
# fingerprint every function in a directory of .ll files
node cli/fp.mjs --dir <dir>
node cli/fp.mjs --dir <dir> --canonical @control_wipe   # show the canonical form
node cli/fp.mjs --dir <dir> --without instruction-order # disable one step

# build the real IR (writes outside the repository)
bash tools/make-fixtures.sh [scratch-dir]

# the measurement
node cli/stability.mjs [--ir <dir>] [--out <dir>]

# the testdata really is IR
bash tools/verify-testdata.sh

# the tests
node --test test/*.test.mjs
```

**Counting contract.** Every runner prints `inputs=N checked=N skipped=S` as
its last line and exits 3 (INCOMPLETE) when `N` is 0, unless `--allow-empty`
was passed. Measured: `cli/fp.mjs --dir <empty>` → exit 3;
`cli/stability.mjs --ir <empty>` → exit 3; `tools/verify-testdata.sh` against an
empty directory → exit 3.

**Skips.** A missing prerequisite fails. `test/realir.test.mjs` fails all nine
of its cases when there is no `clang-18`; setting
`VG_FP_ALLOW_MISSING_TOOLS=1` turns those into skips *and* makes the file print
every skipped case by name, and a final case asserts that the naming happened.

**Exit codes** are the shared ones from `compiler/driver/lib/exit.mjs`:
0 OK · 1 TOOL_FAILED · 2 FINDINGS · 3 INCOMPLETE · 4 INTEGRITY.

**Finding ids**, from the `VG-PROP-0NN` namespace reserved in
`compiler/schema/interfaces.md`:

| id | meaning |
|---|---|
| `VG-PROP-003` | the measurement's control did not hold (shared with the pass observer, deliberately) |
| `VG-PROP-010` | the general fingerprint of a control unit is not stable across optimisation levels |
| `VG-PROP-011` | a perturbation that must not change the fingerprint changed it |
| `VG-PROP-012` | a semantic difference did not change the fingerprint |

---

## The fixture and its control

`tools/make-fixtures.sh` writes a C fixture with, per
`compiler/schema/interfaces.md` section 4, a subject **and** a control whose
effect cannot be removed:

- `subject_wipe` — the wipe is dead; nothing reads the buffer afterwards.
- `control_wipe` — the wipe is followed by an escape to a function the compiler
  cannot see, so the call survives every level. **This is the control.**
- `control_pure`, `subject_branch`, `control_branch` — a straight-line unit and
  a fail-closed branch pair, so the measurement is not one property class.

Three variants are built from the same source at every level: without `-g`,
with every identifier renamed and the source in a different directory, and with
the control's wipe deleted. The first two must not move the fingerprint; the
third must. Without them a cross-level stability number describes the compiler,
not the fingerprint.

---

## The measurement

Measured with `clang-18` (Ubuntu 18.1.3), `-S -emit-llvm -g` at `-O0`, `-O1`,
`-O2`, `-O3`. Reproduce with `tools/make-fixtures.sh` then `cli/stability.mjs`.

**The oracle first.** Call sites, never symbol names:

| level | subject call sites | control call sites | naive name hits (module) |
|---|---|---|---|
| `-O0` | 1 | 1 | 3 |
| `-O1` | 1 | 1 | 3 |
| `-O2` | **0** | 1 | 2 |
| `-O3` | **0** | 1 | 2 |

The control holds at every level, so the measurement is valid, and the subject
goes 0-vs-non-zero at the `-O1` → `-O2` transition. The naive column is one
higher throughout: it is counting the surviving `declare` line.

**Both directions, on real output — this part works.** 60 of 60 checks as
expected (5 functions × 3 variants × 4 levels): the renamed build and the
no-debug build fingerprint identically to the original at every level, and
deleting the control's wipe moves the control's fingerprint and no other.

**Cross-level stability — this part does not.**

| unit | distinct fingerprints across `-O0…-O3` | across `-O1…-O3` |
|---|---|---|
| `subject_wipe` | 4 | 3 |
| `control_wipe` (**the control**) | **4** | **3** |
| `control_pure` | 2 | **1** |
| `subject_branch` | 2 | **1** |
| `control_branch` | 2 | **1** |

**General against targeted, transition by transition:**

| unit | transition | general | targeted |
|---|---|---|---|
| `subject_wipe` | O0→O1 | CHANGED | held |
| `control_wipe` | O0→O1 | CHANGED | held |
| `subject_wipe` | O1→O2 | CHANGED | **LOST** |
| `control_wipe` | O1→O2 | CHANGED | held |
| `subject_wipe` | O2→O3 | CHANGED | held |
| `control_wipe` | O2→O3 | CHANGED | held |

The general fingerprint raises 6 alarms out of 6 transitions. The targeted
oracle raises 1, at the transition where the effect actually disappeared.
**Three of the general fingerprint's six alarms are on the control** — a unit
that lost nothing and whose effect the targeted oracle counts as present at
every level. On this fixture the general version is not a weaker detector than
the targeted one; on the property the targeted one was built for, it is not a
detector at all, because it cannot separate "the property was lost" from "the
function was optimised".

### Where it breaks, specifically

1. **The `-O0` boundary is not crossed by anything.** Every unit has at least
   two distinct fingerprints across `-O0…-O3`, including the three that are
   perfectly stable across `-O1…-O3`. The cause is not among the seven: at
   `-O0` every local lives in an `alloca` and is reached by `load`/`store`,
   and at `-O1` it has been promoted into an SSA value. Making those agree
   needs a memory-to-register normalisation, which is an eighth item, and it
   was not added — adding it would be tuning the number the block exists to
   measure. Reported, not fixed.
2. **Loops defeat it above `-O1`.** `control_wipe` and `subject_wipe` both
   contain loops. Between `-O2` and `-O3` the control's canonical form goes
   from 31 instructions in 7 blocks to 676 instructions in 60 blocks:
   unrolling and vectorisation change how many times the shape appears, and no
   member of the seven addresses instruction count. The three units that are
   stable across `-O1…-O3` are exactly the three with no loop.
3. **`instruction-order` is partial by design and by name.** Only maximal runs
   of side-effect-free instructions are reordered. Code motion that crosses a
   `call` or a `store` — which is most of what a scheduler does — is not
   normalised. That is deliberate: sorting anchors would make the fingerprint
   unable to tell a wipe-then-read from a read-then-wipe, which is the one
   thing a security-property fingerprint must never lose.
4. **`inlined-calls` refuses more than it accepts, and says so.** A callee is
   expanded only if it is defined in the module, is not variadic, has exactly
   one `ret`, and contains no `invoke`/`landingpad`/`indirectbr`/`va_arg`.
   Recursion is refused, and expansion stops after 4 rounds or 6000
   instructions. Every refusal is counted in `refusedCallSites` and named in
   the record, because a fingerprint with four call sites left unexpanded is a
   different measurement from one with none.

### What was not observed

- No comparison against the **built** C++ targeted extractors. The baseline in
  `lib/oracle.mjs` is the call-site oracle of `interfaces.md` section 4
  reimplemented over the same parsed IR, so both sides see identical input; the
  LLVM pass in `compiler/llvm-pass/` was not built or run for this. Whether the
  built extractor and this reimplementation agree on this fixture is **not
  observed**.
- Only one compiler (`clang-18`), one target (`x86_64-pc-linux-gnu`), one
  source file, five functions. No `gcc`, no LTO, no cross-target, no second
  language, and no larger corpus. The stability figures above are a
  measurement on this fixture and are not a rate.
- Phi nodes are kept in textual order within a block rather than canonically
  sorted; a compiler that emitted the same phis in a different order would move
  the fingerprint. Not observed to happen on this fixture, and not ruled out.
- Two instructions in one movable run with identical canonical keys get an
  arbitrary-but-deterministic relative order. Not observed on this fixture.
- The fingerprint reads `.ll` **text**, not in-memory IR. It is a textual
  normaliser, and anything the parser does not understand is recorded in
  `notes` rather than hashed silently. `notes` was empty for all five functions
  at all four levels here.
