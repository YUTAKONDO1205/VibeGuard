# Interfaces — the contract every component in this directory is written against

This directory is built by several people (or several agents) at once. What
keeps that from turning into a merge argument is that the shapes below are
fixed *before* anyone writes code, and nobody edits this file while
implementing against it. If a component needs a shape that is not here, it
reports that and the shape is added here first.

Read this as the whole of the coupling. Two components that both obey this file
are expected to work together the first time they are run together; if they do
not, one of them is not obeying it, and that is a bug in the component rather
than a missing conversation.

## 0. Naming

Some words cannot appear in this repository, and the rule is not negotiable
here because the reason is not a style preference — an unannounced work name in
a public commit is a disclosure, and this repository does not rewrite pushed
history. The gate that enforces it runs before every push.

What that means for code in this directory:

| Do not write | Write instead |
|---|---|
| An uppercase three-letter work name beginning `VG` and ending `C`, or one beginning `BV` | nothing — there is no permitted spelling of these |
| The environment variables the out-of-repo prototype used — they are prefixed with the first of those work names | `OBS_TARGET_FN`, `OBS_CONTROL_FN`, `OBS_EFFECT_SYMBOLS`, `OBS_OUT`, `OBS_SNAPSHOT_DIR`, `OBS_REQUIRE_LIVE_BRANCH` |
| The prototype's CMake target, which carries the same prefix | `PropertyObserver` → `libPropertyObserver.so` |

Spelling a forbidden string in order to forbid it is the same disclosure as
using it, which is why the rows above describe rather than quote. The gate that
enforces this is written the same way, for the same reason.
| The name of the out-of-repo measurement workspace, in any file here | nothing — refer to it as "the prototype workspace" |

`vgcc`, `vg++` and the checker name are permitted **inside this directory and
nowhere else**. A file under `packages/` that names them is a leak even though
the same string here is fine.

C++ target names in use, so that two components do not claim one:
`PropertyObserver` (pass instrumentation), `MarkerPass` (the deliberately
invasive experiment plugin), `IntentGate` (Clang AST plugin), `IrCheckpoints`
(pre/post optimisation observer).

## 1. Where things live

Sources are tracked here, on the Windows side of the filesystem. Builds and
measurements are **not**: they go to the Linux filesystem, because a build
directory reached over the mount is slow, takes CRLF ambiguity into digests,
and bakes machine-specific paths into recorded output.

```
compiler/<component>/          sources, tracked, LF on disk everywhere
~/vg-build/<component>/        cmake -B target. Never under compiler/.
~/vg-lab/<component>/          measurement output, logs, fixtures. Never under compiler/.
```

The canonical invocation for a C++ component. `REPO` is wherever this checkout
is, as the Linux side sees it — under WSL that is a path beneath `/mnt`, and it
is written as a variable rather than spelled out because a build instruction
carrying one machine's account name is both a disclosure and wrong for everyone
else:

```sh
REPO=$(cd "$(git rev-parse --show-toplevel)" && pwd)

cmake -S "$REPO"/compiler/<component> \
      -B ~/vg-build/<component> -G Ninja \
      -DLLVM_DIR=$(llvm-config-18 --cmakedir)
ninja -C ~/vg-build/<component>
```

`find_package(LLVM REQUIRED CONFIG)` takes no version argument: LLVM 18's
config-version file rejects a bare `18` as incompatible with `18.1.3`. Point at
the tree with `-DLLVM_DIR` instead. A component that also needs Clang adds
`find_package(Clang REQUIRED CONFIG)` with `-DClang_DIR=/usr/lib/llvm-18/lib/cmake/clang`.

Nothing in this directory opens a socket, and nothing fetches a build
description. Both are checked by the boundary guard.

## 2. Findings

Every component that can complain produces findings of exactly this shape:

```json
{
  "id": "VG-PLG-002",
  "severity": "high",
  "title": "A pass plugin was loaded that the policy does not list",
  "detail": "libMarkerPass.so (sha256 3f2a…) is not in toolchain.allowedPlugins.",
  "where": { "kind": "invocation", "path": "src/wipe.c", "unit": null, "pass": null }
}
```

- `id` — from the namespaces below. These do not collide with the shipped
  analyser's rule IDs, which are checked against this list.
- `severity` — one of `low`, `medium`, `high`, `critical`.
- `where.kind` — one of `invocation`, `source`, `ir`, `object`, `link`,
  `artifact`. `unit` names an IR unit when the finding is attributable to one;
  `pass` names a pass when it is attributable to one. Both are `null` otherwise,
  and `null` means "not applicable", never "not looked at".

| Namespace | Owner | Meaning |
|---|---|---|
| `VG-CFG-0NN` | driver | The compilation was configured in a way the policy forbids, or a toolchain digest does not match the pin |
| `VG-PLG-0NN` | plugin integrity | A plugin, or a pass pipeline, that the policy does not authorise |
| `VG-PROP-0NN` | ir checkpoints, pass observer | A declared security property is absent where it should be present |
| `VG-INTRO-0NN` | introduction analysis | Something appeared that no permitted origin explains |
| `VG-LINK-0NN` | link wrapper | An input to the link that the policy does not authorise |
| `VG-ART-0NN` | artefact verifier | The final artefact fails a required property |

## 3. Property states

A property, at an observation point, is in exactly one of these states. The
last two exist because "we did not see it" and "it is not there" are different
claims and merging them is how a checker starts lying.

| State | Meaning |
|---|---|
| `PRESENT` | The property's effect was observed at this point. |
| `ABSENT` | Observed to be missing, at a point where the property had not yet been established. |
| `LOST` | Observed to be missing at a point where it was previously `PRESENT`. |
| `REINTRODUCED` | Observed `PRESENT` again after being `LOST` — the effect was reconstructed in another form. |
| `NOT_APPLICABLE` | The representation changed such that the question no longer has the same referent (a buffer promoted out of memory, a callee inlined away). Not a loss. |
| `NOT_OBSERVED` | No observation was made here. Never reported as any of the above. |

A component that records a state history **must keep the whole sequence** and
must not stop at the first `PRESENT → LOST` transition. Stopping there reports
a loss that a later pass undid, which is a false positive with a plausible
story attached, and those are the expensive kind.

## 3.1 Measurement status

Section 3 says what the property did. This column says whether the instrument
worked, and it is a separate question with a separate, equally fixed vocabulary.
A cell in a configuration matrix carries both.

| Status | Meaning |
|---|---|
| `OK` | The instrument ran and produced a reading. Whether the reading is good news is section 3's business, not this column's. |
| `UNSUPPORTED` | The toolchain refused the invocation, so there was nothing to read. The configuration was asked for and could not be built. |
| `BROKEN_MEASUREMENT` | The invocation was accepted and no usable reading came back: the observer never registered, or never reached its extension points, or left behind a record that no longer hashes to its own digest. |

These three are the whole vocabulary. A component that needs a fourth reports
that and it is added here first — the same rule this file opens with, and the
reason it applies here is that three separate components already read this
column, in two languages.

### Why this is not a seventh property state

Because neither of the failure words is a claim about the property. `UNSUPPORTED`
is a claim about the compiler; `BROKEN_MEASUREMENT` is a claim about the
observer. Section 3 opens by saying that "we did not see it" and "it is not
there" are different claims and that merging them is how a checker starts lying.
Adding either word to section 3's table performs that merge *inside the table
that exists to prevent it*: every consumer that switches on a property state
acquires two entries it must remember not to grade, and the first one that
forgets reports an unexamined build as a clean one.

Kept in its own column the pair composes instead. A cell that failed to measure
is `state = NOT_OBSERVED` — section 3's own word for "no observation was made
here" — with the reason in `measurement`. It is then excluded by every consumer
that already handles section 3 correctly, without any of them being taught a new
word, and the reason survives for a reader.

### The pairing rule

**A cell whose `measurement` is not `OK` must have `state` = `NOT_OBSERVED`.**
No reading came back, so there is no property state to report, and any other
state on such a cell is a verdict invented for a measurement that did not happen.
For the same reason such a cell's `controlHeld` is `null` — not `false`, which
would claim a control was run and failed — and its `completesTheCheck` is
`false`.

#### `controlHeld` on such a cell: `false` and `null` are different answers

The sentence above is about a control that was **never run**, and it has been read
as `null`-always. It is not. Two components read it that way, emitted `null` for a
control that demonstrably **fell**, and thereby described a control that was
measured and failed as one nobody measured.

| value | meaning | how a consumer excludes the cell |
|---|---|---|
| `false` | the control **was measured and failed** | `CONTROL_DID_NOT_HOLD` |
| `null` | **no control was measured at all** — legal only on a `NOT_OBSERVED` cell | `NOT_OBSERVED` |

`compiler/envelope/fragility.mjs` is the component that scores, and it has
separated these since before this subsection existed
(`:306-316` for what it accepts, `:366-386` for how it classifies). Its own comment
records the cost of merging them: doing so *"left `NOT_OBSERVED` unreachable for
exactly the cells it was written for … that list was misstating 16 of the 20
removals in the first real envelope this ran on."*

**The score is unaffected either way** — both values exclude the cell. What is
affected is the **list of removals**, and a denominator whose removals are
misdescribed is not one anyone can check. That is section 3's *"we did not see
it"* versus *"it is not there"*, one layer out from where section 3 guards it.

So: a fallen control is `false`, with the reason and the control's own counts
recorded beside it. `null` is reserved for the case the paragraph above was
written about, and demanding `null` there does not protect anything — it forces
the producer to invent a control verdict for a measurement that never happened,
which moves the fabrication one component upstream.

This subsection adds no vocabulary. It states a distinction the scorer already
implements, because the paragraph above it does not, and the two components that
misread it were reading in good faith.

**The converse does not hold. `state = NOT_OBSERVED` with `measurement = OK` is
legal**, and it is not a loophole; it is a third situation that a symmetric rule
would erase. The instrument ran, the record hashes, the control was measured —
and at this point there was no reading of *this* property, because the subject
was not in the translation unit, or the observation point was never reached. An
instrument that worked and found nothing to look at is a different fact from an
instrument that did not work, and this file's whole argument is that facts of
that shape are kept apart. Such a cell is ungradeable either way, so nothing
downstream changes; what changes is what the exclusion list says happened, and a
denominator whose removals are misdescribed is not a denominator anyone can
check.

A component that assembles a matrix writes this column on every cell. A consumer
that receives a cell without it reads `OK`. That default is permissive in
appearance only: on a cell that omits the column the apparatus claim is already
being made by `controlHeld` and `completesTheCheck`, and the pairing rule means
the cells this column would have excluded are exactly the ones those two exclude
already.

## 4. Counting an effect — the oracle rule

Never decide whether an effect is present by searching for a symbol name.

In IR, count **call sites**: walk `CallBase` instructions and compare the
resolved callee. A call that has been deleted still leaves
`declare void @llvm.memset.p0.i64(...)` behind, so a name search reports the
effect as present until some later pass sweeps unused declarations away — which
attributes the loss to the sweeper instead of to the pass that actually did it.
This was measured on the prototype: the naive oracle blamed the global-cleanup
pass, the call-site oracle named the store-elimination pass, and they disagreed
by nine pass-budget steps.

Two more rules with the same purpose:

- Count **within one IR unit**, not across the module. After inlining, the
  out-of-line original survives until dead-code elimination removes it, so a
  module-wide count keeps reporting the effect from a function nobody calls.
- Every fixture carries a **control** function whose effect cannot be removed.
  A measurement where the control's count also fell to zero is a broken
  measurement, not a finding.

## 5. Evidence

Records are JSON, and the canonicalisation rules are the ones the independent
verifier already implements. Any component that writes a record obeys them:

1. `context` and `evidenceDigest` are removed **as whole subtrees** from the
   top level before digesting. Nothing else is removed, at any depth.
2. Object keys sort lexicographically at every level, inside arrays of objects
   too. Array order itself is significant and is never sorted.
3. Serialise with no insignificant whitespace.
4. **Every number is an integer.** A ratio is a pair — `{"num": 3, "den": 4}` —
   never a float. A component that emits a non-integer number has produced a
   malformed record, and the canonicaliser fails rather than rounding.
5. SHA-256 over the UTF-8 bytes, lowercase hex.

`context` holds everything a re-run cannot reproduce and nothing else:
`generatedAt`, `timeSource` (`SOURCE_DATE_EPOCH` or `wall-clock`),
`sourceDateEpoch`, `host`, and repository provenance. It is recorded, never
digested. Volatile fields go *here* rather than onto an exclusion list, because
a list only covers what was known when it was written.

Every record additionally carries, outside `context`:

```json
"toolchain": { "digest": "<sha256 of the pinned set>", "clang": "18.1.3", "packages": [ … ] }
```

Absolute paths must not appear anywhere in a record. Write paths relative to
the fixture root. A component that cannot avoid one reports the problem instead
of emitting it.

## 6. Policy

One JSON file, `.vgpolicy.json`, found by searching upward from the working
directory, or named with `--policy <path>`. Its shape is `policy.schema.json`
in this directory. Components read it; none of them write it.

## 7. Exit codes

Shared by every executable here, so that a caller can branch without knowing
which component ran.

| Code | Meaning |
|---|---|
| 0 | Everything asked for was checked and nothing was found. |
| 1 | The underlying tool failed (compile error, link error). Its diagnostics pass through unchanged. |
| 2 | Findings at or above the policy's failure threshold. |
| 3 | A check could not be completed. **Never conflated with 0** — this is the code that keeps "we did not look" from being reported as "it is clean". |
| 4 | Toolchain or policy integrity failure: a digest does not match the pin, or the policy is malformed. Nothing else runs. |

Fail closed. An unreadable policy, an unresolvable plugin digest, or a missing
observation is 3 or 4 — never 0 with a warning.

One consequence worth stating because the repository's own scanner will catch
it otherwise: **do not put a security decision inside `assert`**. It disappears
under `NDEBUG`, which is precisely the class of disappearance this directory
exists to detect, and the shipped rules flag it at `high`.
