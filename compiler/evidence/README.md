# `compiler/evidence` — canonical records, and the check that they are canonical

Every component in this directory that records something writes it through here.
The contract is `../schema/interfaces.md` §5; this is its implementation, plus
the vectors and the verifier that keep two implementations of it from drifting
apart without anybody noticing.

| File | What it is |
|---|---|
| `canon.mjs` | Generation side. `canonicalJson`, `evidenceDigest`, and `sealRecord` — the chokepoint every writer goes through. |
| `clock.mjs` | The only place in this component allowed to read a clock, plus the audit that proves it is still the only one. |
| `paths.mjs` | The absolute-path gate. Runs **before** the digest, inside `sealRecord`. |
| `counting.mjs` | The counting contract: `inputs=N checked=N skipped=S`, and a run that checked nothing does not exit 0. |
| `fsguard.mjs` | Symlink refusal. A linked component anywhere on the path to an input is refused, not followed. |
| `machine.mjs` | Machine identity in a record, and the delegation to `scripts/check-disclosure-shape.mjs`. |
| `store.mjs` | Where measurement records live, and what makes one valid. |
| `validate-store.mjs` | The measurement-record validator. Written before the first record existed. |
| `record-run.mjs` | The writer: provenance, measured toolchain, seal, out-of-tree. |
| `verify.mjs` | Independent verifier. Re-derives the digest from the rules without importing `canon.mjs`. |
| `testdata/digest-vectors.json` | 22 input/output pairs and 8 inputs that must be refused. |
| `test/*.test.mjs` | 71 cases. `node --test compiler/evidence/test/*.test.mjs` — glob it; passing the directory throws `MODULE_NOT_FOUND` on newer runtimes. |

The measurement record store — where records live, what one must carry, and what
none of it can detect — is documented separately in [`STORE.md`](./STORE.md).

## The rules

1. `context` and `evidenceDigest` are removed from the **top level** before
   digesting, and `context` is removed as a **whole subtree**. Nothing else is
   removed, at any depth: a key called `context` below the top level is an
   ordinary key and is digested like any other.
2. Object keys sort lexicographically at every level, inside arrays of objects
   too. Array order itself is significant and is never sorted.
3. No insignificant whitespace.
4. Every number is an integer. A non-integer is a malformed record, not a
   rounding question — the canonicaliser fails rather than rounds. A ratio is a
   pair: `{"num": 3, "den": 4}`.
5. SHA-256 over the UTF-8 bytes of the canonical text, lowercase hex.

### Why rule 1 is a place and not a list of names

It used to be a list — drop `generatedAt` and `evidenceDigest`. A list only
covers what was known when it was written. Provenance for a *different*
repository was later added to the record, was not on the list, and so went into
the digest; the next uncommitted edit over there moved all forty digests without
a single measurement having changed. Nothing detected it, because there was
nothing to detect it with: the digest did exactly what it had been told to do.

With the exclusion expressed as a place, the schema itself says where volatile
fields live, and adding one more cannot move a digest. Anything a re-run cannot
reproduce — wall clock, host, durations, provenance of some other repository —
goes in `context`. That is the whole convention, and `C3d` in the controls below
replays the accident to show the rule now absorbs it.

## API

These signatures are depended on by other components. They do not change.

```js
import { canonicalJson, evidenceDigest, sealRecord, writeRecordSync } from './canon.mjs';

canonicalJson(obj) -> string      // rules 1–3; the text the digest is taken over
evidenceDigest(rec) -> string     // rule 5; exactly sha256(canonicalJson(rec))
```

`canonicalJson` applies the rule-1 exclusion, so `evidenceDigest(x)` is
`sha256(canonicalJson(x))` and the two can never drift. For a sub-object, where
a top-level `context` key would be ordinary data, use `canonicalJsonRaw`.
`canonicalText` is an alias of `canonicalJson`, under the name the out-of-repo
reference uses.

```js
sealRecord(record, { contextExtra, pathMode }) -> record   // the write path
writeRecordSync(file, record, opts) -> record
```

`sealRecord` is the generation-side chokepoint: it attaches `context` from
`clock.mjs`, **gates on absolute paths**, canonicalises (which is where a
non-integer number fails), and only then sets `evidenceDigest`. Nothing computes
a digest by hand.

```js
import { nowIso, timeSource, TIME_SOURCE, SOURCE_DATE_EPOCH, runContext } from './clock.mjs';
```

`nowIso()` is the only timestamp source. When `SOURCE_DATE_EPOCH` is set to
whole seconds, every timestamp derives from it and a re-run is byte-identical;
when it is not, `timeSource()` says `wall-clock` and `sourceDateEpoch` is
`null`, so a reader can tell the two situations apart. A malformed
`SOURCE_DATE_EPOCH` throws at import rather than quietly falling back to the
wall clock.

```js
import { relativise, assertNoAbsolutePaths, findAbsolutePaths } from './paths.mjs';
```

`relativise(p, root)` produces the form a record carries. It throws when there
is no relative path that means the same thing on another machine — a different
drive, or an escape from the root — because the contract says to report that
rather than emit it.

## Why the gate is on the generation side

A scan that runs after the fact finds a leak in a record that has already been
digested, indexed and sealed. The expensive part is not regenerating it; it is
that every digest computed in between was computed over a machine-specific
string and so is not reproducible anywhere else. `sealRecord` refuses first, and
`verify.mjs` repeats the scan only as a second opinion on records some other
generator produced.

## Strictness beyond the five rules

These refuse inputs that a laxer canonicaliser would silently mangle. None of
them changes the output for any input the rules already accept — checked
three-way against the reference implementation over 22 vectors and 40 real
records, all agreeing on both the canonical text and the digest.

- **A key that JavaScript treats as an array index** (`"0"`, `"10"`) is refused.
  This one was found by the vectors rather than reasoned out. Sorting the keys
  is not enough to fix the byte order, because an engine puts integer-index keys
  first, in ascending numeric order, ahead of every string key and regardless of
  insertion order. So the object rule 2 asks for serialises as
  `{"0":7,"9":9,"10":8,"-":6}` if you build an object and stringify it, and as
  `{"-":6,"0":7,"10":8,"9":9}` if you emit the sorted text directly. Both obey
  rule 2; the bytes differ; the digest differs. Rule 2 does not say which is
  right, so neither does this component: the key is unrepresentable and nothing
  has to guess. Prefix it (`"k10"`), or carry the map as an array of
  `{key, value}` pairs. Both spellings are recorded in the `mustFail` entry
  `an-array-index-key-is-refused`.
- **An integer outside the exact-integer range** is refused, because
  `JSON.stringify(1e21)` is `"1e+21"` and an implementation in another language
  writes the digits — same value, different bytes.
- **`undefined` as an object member** is refused rather than dropped. The
  contract defines `null` as "not applicable"; a member that simply vanishes
  says nothing at all.
- **`Date`, `Map`, `Set`, class instances** are refused rather than serialised
  as `{}`, and a cycle is reported as a cycle.

## Running it

```sh
node verify.mjs --self-test            # reproduce every vector, both directions
node verify.mjs --bundle <dir>         # one bundle directory
node verify.mjs --bundles <dir>        # every bundle directory beneath <dir>
node verify.mjs --record <evidence.json>
node verify.mjs --digest <file.json>   # re-derived digest, nothing else
node verify.mjs --clock-audit <dir>    # fail if anything but clock.mjs reads a clock
node verify.mjs --paths <file.json>    # absolute paths, as the gate would see them

node validate-store.mjs --self-test    # every store detector, both directions
node validate-store.mjs --store <dir>  # every measurement record in a store
node --test compiler/evidence/test/*.test.mjs
```

Exit codes are the shared ones (`../schema/interfaces.md` §7): `0` checked and
clean, `2` findings at or above the threshold, `3` a check could not be
completed, `4` the record is malformed and nothing downstream of it means
anything. `3` is never conflated with `0`: a bundle with no findings but a field
nothing could check reports `VERIFICATION_INCOMPLETE` and exits `3`, because a
field nobody checked is not a field that passed. `--record` now answers the same
way; it used to return `0` over the same unchecked list, so one record got two
different verdicts depending on which flag was used to look at it.

### The counting contract

Every mode prints `inputs=N checked=N skipped=S`, and a run that **checked
nothing** exits `3` unless `--allow-empty` was passed. `checked + skipped` must
equal `inputs`; a run where it does not also exits `3`. The rule lives in
`counting.mjs` and is imported, not repeated.

It is a module because this exact bug has appeared three times here. Most
recently `--self-test`, handed a vector file containing `{"vectors":[]}`,
reproduced every one of its nought vectors, agreed with `canon.mjs` about all
nought of them, and exited `0`. Nothing it printed was false; the exit code was.
The test that pins it is `test/selftest-empty.test.mjs`, and it asserts both
directions — the empty file exits `3`, the real one still exits `0`.

### Symlinked inputs are refused

A symbolic link on any component of the path to an input — including the
ancestors, since a linked *directory* redirects everything beneath it at once —
is refused rather than followed, and exits `2`. `--link-boundary <dir>` stops the
upward walk for a machine whose home directory is legitimately a link.

A report that names one path and reads another is wrong in every line, and the
substitution needs no privileges and leaves no trace in the record. What this
does **not** catch is a coherent regeneration of the evidence; that limit is
stated in full in [`STORE.md`](./STORE.md).

### Independence

Nothing on the verification path imports `canon.mjs`. `verify.mjs` re-derives
the canonical text from the written rules with a different shape of code — an
explicit serialiser rather than sort-then-stringify — because a verifier that
shares the generator's implementation agrees with it by construction and proves
nothing about any record. The one place `canon.mjs` is loaded is the cross-check
inside `--self-test`, which is reported as its own line.

The two sides are calibrated against `testdata/digest-vectors.json`, whose
expected values were produced by running the independent reference
canonicaliser that lives in the prototype workspace, never by hand. The eleven
vectors carried over from that workspace's own file were recomputed rather than
copied, and matched what was recorded there.

## Finding IDs

`verify.mjs` emits `VG-ART-05N`/`VG-ART-06N`. The namespace belongs to the
artefact verifier (`../schema/interfaces.md` §2); the 050–069 band is taken by
this component so nothing else in the namespace collides with it.

| ID | Meaning |
|---|---|
| `VG-ART-050` | `evidenceDigest` missing, or does not match a re-derivation |
| `VG-ART-051` | The record carries an absolute path |
| `VG-ART-052` | `command.argv` is empty |
| `VG-ART-053` | `confidence` disagrees with `agreement.level` |
| `VG-ART-054` | `firstLoss.stage` is not the stage the interval maps to |
| `VG-ART-055` | A pass is named for a stage that cannot attribute one |
| `VG-ART-056` | `PRESENT` after a loss with no `REINTRODUCED` marker |
| `VG-ART-057` | `fragility` violates `0 <= lost <= evaluated` |
| `VG-ART-058` | `coverage` disagrees with `states[]` |
| `VG-ART-059` | A coverage shortfall is not accounted for in `unresolved[]` |
| `VG-ART-060` | The referenced artefact is not in the bundle |
| `VG-ART-061` | The artefact's bytes do not match `artifact.sha256` |
| `VG-ART-062` | `manifest.json` names a different `evidenceDigest` |

A digest mismatch is a **disagreement inside the evidence**, not tamper
detection. Nothing binds a record to an authority, so a record regenerated
wholesale from a modified artefact verifies. The findings say that, and must
keep saying it.

## What has been measured

Every claim below was produced by running the code, not by reading it.

| Claim | How |
|---|---|
| All 22 vectors reproduce; all 8 must-fail inputs are refused; `canon.mjs` agrees | `node verify.mjs --self-test` → exit 0 |
| 40 real records verify clean — recomputed digest, artefact bytes, manifest digest, coverage, confidence, stage table | `node verify.mjs --bundles <bundle root>` → 40 clean, exit 0 |
| Reference implementation, `canon.mjs` and `verify.mjs` agree on canonical text *and* digest for 22 vectors + 40 real records | three-way comparison, 62/62 |
| A one-byte flip in a vector input is caught | tampered copy → exit 3, names the vector |
| A float outside `context` fails and is never rounded; a float inside `context` goes with the subtree | `--digest` → exit 4 / exit 0 |
| A flipped artefact byte, and a changed digested field, are caught | copied bundle → exit 2, `VG-ART-061` / `VG-ART-050` |
| Changing `context`, and adding a key nobody listed under `context`, do not move the digest; the same key one level up does | copied bundle → exit 0, exit 0, exit 2 |
| A manifest naming a different digest is caught | copied bundle, record re-sealed → exit 2, `VG-ART-062` |
| A field nothing could check reports `VERIFICATION_INCOMPLETE` and exit 3, with no findings | copied bundle with `coverage` removed → exit 3 |
| The path gate refuses a value, a sentence, an array element, an object key, a `~/` path, and one hidden inside `context` | `sealRecord` → six refusals, before any digest |
| `relativise` and the classifier behave, including on what they must *not* flag — a version string, `8/16`, `-O2`, a relative path — and every `relativise` result survives the gate | 30 cases, 30 passed |
| The clock audit is clean here and catches a stage that formats its own timestamp, without flagging prose about clocks | `--clock-audit` → exit 0 / exit 2 naming file, line and call |
| Two pinned runs are byte-identical; an unpinned run declares `wall-clock`; a malformed epoch is refused | probe under three environments |
