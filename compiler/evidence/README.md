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
| `ledger.mjs` | The double-entry ledger: at every planned checkpoint the four accounts must add up to what the declaration opened. `evidence-v1` only. |
| `testdata/digest-vectors.json` | 22 input/output pairs and 8 inputs that must be refused. |
| `testdata/bundles/`, `testdata/records/`, `testdata/declarations/` | Static record and bundle fixtures: three `evidence-v0`, eleven `evidence-v1` and one `evidence-v2` that exists only because this verifier must refuse it, plus three bundle manifests and two declaration documents — 23 files, which is what `find testdata -type f ! -name make-fixtures.mjs ! -name digest-vectors.json | wc -l` prints. Sealed through `canon.mjs` once and committed as bytes; `node testdata/make-fixtures.mjs` rebuilds the whole set byte-identically when a record body has to change, and `node verify.mjs --digest <file>` re-derives one digest on its own. The stand-in artefact is ASCII and is called `wipe-object.txt`, not `wipe.o`: `.gitignore` line 100 is `compiler/**/*.o`, so under the obvious name the file is never committed and every bundle test fails on a fresh clone with `VG-ART-060`; and `scripts/check-packaging-invariants.mjs` refuses a committable file under `compiler/` whose extension its egress tripwire cannot read, which ruled out inventing one. |
| `test/*.test.mjs` | 112 cases. `node --test compiler/evidence/test/*.test.mjs` — glob it; passing the directory throws `MODULE_NOT_FOUND` on newer runtimes. |

> That count read "71 cases" until the ledger was added, when the suite as it
> then stood ran 72. The line was one out and nothing was checking it; it is
> now the number `node --test` printed: 72 before the ledger, 102 with it, and
> 112 once the ten cases below — nine of them regressions found by taking this
> directory apart rather than by reading it — were added.

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
node verify.mjs --record <evidence.json> --declared <declaration.json>
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

## The double-entry ledger (`evidence-v1`)

`coverage` is two integers. `VG-ART-058` holds `observed` against `states[]`,
and `VG-ART-059` complains when `planned - observed` is positive and
`unresolved[]` is empty. Both are recomputed from the properties the record
carries, so a record that never mentions a property at all passes both of them:
the property is missing from the numerator and from the denominator at the same
time, and two numbers that moved together still agree.

An `evidence-v1` record carries a ledger, and the ledger is held to one identity
at **every planned checkpoint**:

```
present + absent + unobserved + unresolved  ==  declared(checkpoint)
```

One CELL per (declared property, planned checkpoint). Every cell posts to
exactly one of the four accounts. `unresolved[]` is the suspense account — "we
did not look here, and here is why" — and a cell that posts to none of the four
is `VG-ART-064`.

The three left-hand columns are the record's own verdict vocabulary, `PRESENT` /
`ABSENT` / `UNOBSERVED`. `../schema/interfaces.md` §3 keeps "we did not see it"
and "it is not there" apart with two words; this keeps them apart with two
columns that both have to be filled in, so the first cannot be lost by omission
rather than by a wrong word.

### Where `declared` comes from, and why that is the whole design

From the **declaration** — the list of accounts, opened before the run — and
never from `record.properties.length`. Taken from the record's own property
array the identity holds for every record that was ever written and the check is
theatre. `testdata/records/v1-observed-only.json` exists to prove this one is
not: it declares four properties, carries states for two, keeps its own totals
consistent with the two it carries, and must fail. The planned checkpoint list
comes from the same place for the same reason — derived from the checkpoints
that turn up in `states[]` it would say that every run planned exactly what it
managed to do.

Three sources, strongest first. The ordering is by how much of the document the
record's own producer wrote.

| Source | Where it is read from | What it can catch |
|---|---|---|
| `external` | `--declared <file>`, a `evidence-declaration-v1` document | Everything below, plus a record that shrank both of its own books. The only source the producer did not write. |
| `manifest` | a `declares` block in the bundle's `manifest.json` | A record that disagrees with the bundler about which properties were in scope. |
| `record` | `declaredProperties` and `ledger.plannedCheckpoints` | A record that dropped a property from `properties[]` while still declaring it. Not one that dropped it from both. |

The source in force is named in the report (`ledger: <source> declaration, …`)
and in `--json` output, because how much the check is worth depends on which one
answered. When the source is not the record, the two are compared and a
disagreement is `VG-ART-067`.

### Writing less must never buy a cleaner verdict

Four of this component's checks exist because it did. Each was found by taking a
fixture that verified clean and removing something from it, and in each case the
removal answered *better* than the honest version: a producer escaped
`VERIFICATION_INCOMPLETE` by writing less information, not more. The rule that
replaced each one is stated here because it is a rule producers have to know.

| Written out | What it used to answer | What it answers now |
|---|---|---|
| `ledger.entries` carrying the planned checkpoint names and no counts | `ledger.entries` **CHECKED**, exit 0 — nothing had been compared | every entry of a v1 ledger carries `declared` and all four accounts; a number the entry omits is a number nobody compared, so `ledger.entries` is **UNCHECKED** and the run exits 3, exactly as omitting the whole block does |
| a declared property with `"plannedCheckpoints": []` | the property matched no checkpoint, opened no account, posted to no column, and still counted in `declaredProperties` — exit 0 | a property planned nowhere is not a declared property: the declaration is refused, `ledger` is **UNCHECKED**, exit 3 |
| `ledger.plannedCheckpoints` narrowed while the record keeps its states at the dropped checkpoint | the column vanished from the ledger and the remaining cells balanced — exit 0 | `VG-ART-068`: a state at a checkpoint the declaration does not plan **for the property that carries it** is posted to no column and is named |
| `manifest.json` that is not a JSON object, or one that names no `evidenceDigest` | `VERIFIED_CLEAN`, exit 0 — the cross-check had not happened (for the literal `null`, only after the manifest read was moved; the full before/after is under [Compatibility](#compatibility-what-the-new-schema-version-cost)) | **UNCHECKED** (`manifest.json` / `manifest.evidenceDigest`), exit 3 |

The shape of all four is the same, and it is worth naming because it is easy to
reintroduce: a check written as "compare the fields that are there" reports
agreement over the empty set. The ledger's own rule — that an unchecked field is
not a field that passed — has to be applied one level down, to the *fields
inside* the block, or the block as a whole becomes the empty-input-set bug that
`counting.mjs` exists for.

### What this does not catch

- **A record that shrank both books.** With the declaration read out of the
  record, a producer that drops a property from `properties[]` *and* from
  `declaredProperties` emits a record that balances.
  `testdata/records/v1-shrunk-declaration.json` is that record and its test
  asserts **exit 0**, on purpose; the test after it names an outside declaration
  and the same record exits 2. Nothing inside a document can hold the document
  to a plan it also wrote, which is the same limit `STORE.md` states for the
  digests.
- **The same trick along the checkpoint axis.** A record that narrows
  `ledger.plannedCheckpoints` *and* drops the states at the dropped checkpoint
  balances over what is left, and `VG-ART-068` has nothing to notice because the
  record no longer carries the observation either. This is the previous limit
  with `plannedCheckpoints` in place of `declaredProperties`, it is closed by the
  same thing — an outside declaration, which reports
  `the record does not plan ["ir-post"]` as `VG-ART-067` — and the test named
  `a narrowed plan whose states went with it is the disclosed limit` asserts both
  halves.
- **A coherent regeneration.** As with `VG-ART-050`, a bundle rebuilt wholesale
  from different inputs is internally consistent and verifies. The ledger is a
  disagreement detector, not tamper detection.
- **A checkpoint vocabulary mismatch.** Checkpoint names are compared as
  strings. This component's records use `preprocess` / `ast` / `ir-pre` /
  `ir-post` / `asm` / `artifact` (the names `STAGE_TABLE` in `verify.mjs` maps),
  while `policy.schema.json`'s `observeAt` and `observation.schema.json` use
  `invocation` / `ast` / `pre-opt-ir` / `after-pass` / `object` / `linked` /
  `artifact`. A producer that copies `observeAt` straight into
  `plannedCheckpoints` gets an imbalance at every checkpoint naming every
  declared property. That is a true report — nothing was posted — but the cause
  is a vocabulary mismatch and the finding will not say so. The mapping is part
  of the producer-side request below, and this component does not guess at it.
- **A blanket `unresolved[]` entry** is refused rather than honoured: an entry
  settles a cell only when it names the property *and* the checkpoint
  (`checkpoint`, or `checkpoints` for several). An entry naming a property alone
  would let one line settle every cell a run skipped, which is the suspense
  account swallowing the ledger instead of exposing it.
- **A bundle with no `manifest.json` at all.** A manifest that is *there* and
  unreadable, or there and silent about the digest, is UNCHECKED; a bundle that
  carries no manifest is not reported at all, because the document is absent
  rather than the field. That is the same distinction the ledger draws between a
  v1 record with no `ledger` block (UNCHECKED) and a v0 record (nothing to look
  at), and it means a bundler that emits no manifest is cross-checked against
  nothing and still exits 0.
- **A `--fail-on` above the finding's severity.** `--fail-on` gates the exit
  code, not the check. Every ledger finding is `high` except `VG-ART-066` and
  `VG-ART-068`, which are `medium`, so `--fail-on critical` suppresses all of
  them and a record with unaccounted cells exits 0 with `VG-ART-064` printed. The
  default is `low`, where nothing is suppressed; a run that suppresses anything
  now says so on its last line (`note: N finding(s) are below --fail-on …`), and
  the test named `--fail-on is a gate on the exit code, not on the check`
  measures both ends rather than leaving it to be discovered.

### Why the ledger is a new schema version

Because `evidence-v0` has no ledger, and this README's own rule is that "a field
nobody checked is not a field that passed". Adding a mandatory check to v0 would
land every record ever written on `VERIFICATION_INCOMPLETE` and exit 3 — a true
statement about nothing, since the field the report would be complaining about
does not exist in that schema. So `evidence-v0` is verified exactly as it was,
`evidence-v1` is verified with the ledger, and anything else is `UNSUPPORTED`
and exit 3 — on **both** entry points.

That last clause is narrower than it sounds and was not true when it was first
written. `KNOWN_RECORD_VERSIONS` was consulted in `verifyBundle` alone, and the
ledger check is the first check here keyed on a schema version: it returns
nothing at all for anything that is not exactly `evidence-v1`. So a record
relabelled `evidence-v2` and resealed went through `--record` with the ledger
silently skipped — no finding, no `unchecked` entry, no `ledger:` line, exit 0 —
while the same bytes through `--bundle` were `UNSUPPORTED` and exit 3. A version
bump is not a way to buy a clean verdict, so the gate now lives in
`verifyRecord`, which both paths go through, and
`testdata/records/v2-relabelled.json` — `v1-unbalanced.json` relabelled and
resealed — is checked on both flags.

The distinction the code makes is narrow and worth stating: a v0 record is not
pushed onto `unchecked` for the ledger, because there is nothing to have looked
at; a **v1** record with no `ledger` block *is* pushed onto `unchecked`, because
there is. That is why `testdata/records/v1-no-ledger.json` exits 3 rather than
0, and `test/record-v0.test.mjs` asserts that no v0 run so much as mentions the
word.

### What the producer has to write — [SPEC], not implemented here

No component in this repository emits `evidence-v0` bundles today: the driver
emits `compiler-evidence-v0` and the schema emits observation records. So the
producer side of this is a specification and nothing more, and the exact field
spec is in **[Edits requested in files this lane does not own](#edits-requested-in-files-this-lane-does-not-own)**
below rather than applied, because `../schema/interfaces.md` is the one file
nobody edits while implementing against it.

## Finding IDs

`verify.mjs` emits `VG-ART-05N`/`VG-ART-06N`. The namespace belongs to the
artefact verifier (`../schema/interfaces.md` §2); the 050–069 band is taken by
this component so nothing else in the namespace collides with it. `063` was
already emitted by the symlink refusal and was missing from this table; `068` is
now taken by the checkpoint-axis complaint below, and `069` is the last one left
unused.

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
| `VG-ART-063` | A symbolic link on the path to the record or the artefact |
| `VG-ART-064` | The ledger does not balance at a planned checkpoint |
| `VG-ART-065` | The record's own ledger disagrees with the recomputed one |
| `VG-ART-066` | The record reports a property the declaration opened no account for |
| `VG-ART-067` | The declaration in force and the record's own declaration disagree |
| `VG-ART-068` | The record carries a state at a checkpoint the declaration does not plan for that property |

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
| The whole suite: 72 cases passed before the ledger was added, 102 after, 112 once the regressions below were closed; 0 failures at each count | `node --test compiler/evidence/test/*.test.mjs` → exit 0 all three times |
| The four `evidence-v0` probes answer identically before and after: bundle 0, record 0, missing `coverage` 3, `VG-ART-053` 2 | those four commands run against `verify.mjs` as it stood before `ledger.mjs` existed and against it now, outputs diffed, empty |
| A fifth probe did **not**: a v0 bundle whose `manifest.json` holds the four bytes `null` went 3 → 0 and is back to 3, and three more manifest shapes moved 0 → 3 with it | `--bundle` over five copied bundles, `null` / `[]` / `"x"` / `3` / `{}` → `VERIFICATION_INCOMPLETE`, exit 3 each |
| A balanced v1 record and a balanced v1 bundle exit 0, with `ledger` and `ledger.entries` on the checked list | `--record` / `--bundle` → exit 0 |
| A v1 record that leaves a planned cell in no account is `VG-ART-064` and exits 2, naming the property and the checkpoint | `--record testdata/records/v1-unbalanced.json` → exit 2, twice |
| That same record slips past `VG-ART-059`, which is the instrument that existed before: its `unresolved[]` is non-empty and settles nothing | same run, `VG-ART-059` absent from the findings |
| A v1 record that lists only the properties it observed fails, and its declared count (4) is not its `properties.length` (2) | `--record testdata/records/v1-observed-only.json` → exit 2 |
| A v1 record with no `ledger` block exits 3 with no findings and `ledger` on the unchecked list | `--record testdata/records/v1-no-ledger.json` → exit 3 |
| A ledger block carrying the planned checkpoint names and no counts is UNCHECKED for `ledger.entries`, not CHECKED: writing the shell costs exactly what omitting it costs | `--record testdata/records/v1-count-free-ledger.json` → exit 3, `unchecked: ledger.entries`, no findings |
| A declared property with `"plannedCheckpoints": []` is refused, so the ledger is UNCHECKED rather than balanced over the properties that are left | `--record testdata/records/v1-planned-nowhere.json` → exit 3, `ledger: NOT CHECKED - demo.fortify plans no checkpoints at all` |
| A narrowed `plannedCheckpoints` with the states still in the record is `VG-ART-068`, naming both cells | `--record testdata/records/v1-narrowed-plan.json` → exit 2 |
| A record relabelled to a version this verifier does not know is `UNSUPPORTED` and exit 3 through `--record`, not only through `--bundle` | `--record testdata/records/v2-relabelled.json` → exit 3; same file as a bundle → exit 3 |
| A record whose own ledger disagrees with the recomputation is `VG-ART-065`, separately from the balance | `--record testdata/records/v1-ledger-disagrees.json` → exit 2, balance still checked |
| A record that shrank both of its books exits 0 unaided and exits 2 against an outside declaration | `--record` with and without `--declared` → exit 0, then exit 2 with `VG-ART-064` and `VG-ART-067` |
| A declaration NARROWER than the record's own is compared too, and what the record has extra is named | `--record testdata/bundles/v1-balanced/evidence.json --declared testdata/declarations/two-properties.json` → exit 2, `VG-ART-067` naming `demo.fortify` and `demo.stackprot` |
| `--fail-on critical` suppresses every ledger finding and exits 0, and the run prints which findings it suppressed | `--record testdata/records/v1-unbalanced.json --fail-on critical` → exit 0 with `VG-ART-064` printed; `--fail-on high` → exit 2 |
| A `declares` block in the manifest becomes the declaration in force, and the report says so | `--bundle testdata/bundles/v1-manifest-declared` → exit 0, source `manifest` |
| The fixture builder rebuilds all 23 fixture files byte-identically — 15 records (3 of them a bundle's `evidence.json`), 3 artefacts, 3 manifests, 2 declarations | `node testdata/make-fixtures.mjs`, then `diff -rq` against a copy taken first → the 19 that existed before are unchanged, the 4 new ones are the only additions |
| The clock audit still passes over the enlarged directory, the fixture builder included | `--clock-audit` → 19 of 20 files, 0 reads, exit 0 |
| The vectors still reproduce and the store validator still self-tests clean | `--self-test` → 22/22 + 8/8, `canon.mjs` agrees on 30, exit 0; `validate-store.mjs --self-test` → 14/14 fired, 3/3 silent, exit 0 |
| The repository-wide packaging check passes over the new files, and the disclosure check is clean over this directory | `check-packaging-invariants.mjs` → exit 0; `check-disclosure-shape.mjs --paths <every file under compiler/evidence>` → 0 hits over 46 files. Run over the whole repository it now reports 3 hits and exit 1, all three in `compiler/eval/lto-window/test/record.test.mjs`, which is not this directory's file and was not touched here |

## Compatibility: what the new schema version cost

Almost nothing, and the "almost" is the part worth reading. `verifyRecord` and
`verifyBundle` had no test in this directory before the ledger was added — the
forty real records in the table above live outside the checkout — so the v0
fixtures under `testdata/` were written **first** and run against `verify.mjs` as
it stood before `ledger.mjs` existed. Those outputs are what
`test/record-v0.test.mjs` asserts, copied rather than predicted:

```
--bundle testdata/bundles/v0-complete                  VERIFIED_CLEAN  checked=7 unchecked=0  exit 0
--record testdata/bundles/v0-complete/evidence.json    checked 5, unchecked 0                exit 0
--record testdata/records/v0-unchecked.json            unchecked: coverage                   exit 3
--record testdata/records/v0-finding.json              VG-ART-053                            exit 2
```

Four probes, and all four are byte-identical after the change. This section used
to say "byte-for-byte unchanged" on the strength of exactly those four, and that
was a claim about `evidence-v0` asserted well past what had been measured. A
fifth probe, which nobody had run, was not unchanged:

```
--bundle <v0-complete, manifest.json = the four bytes `null`>
  before ledger.mjs   VERIFICATION_INCOMPLETE  checked=6 unchecked=1  exit 3
  with ledger.mjs     VERIFIED_CLEAN           checked=6 unchecked=0  exit 0   ← the regression
  now                 VERIFICATION_INCOMPLETE  checked=6 unchecked=1  exit 3
```

The cause was a refactor, not a decision: the manifest had to be read before the
record so that a `declares` block could become the ledger's declaration, and
reading it once moved the `man.evidenceDigest` access out of the `try` that had
been catching it. A manifest of literal `null` had thrown there and landed on
`unchecked`; guarded instead, it landed nowhere, and a cross-check that did not
happen was reported as one that passed. That is the single conflation these exit
codes exist to prevent, and it arrived in the change that added them.

The guard is now on the manifest's SHAPE rather than on which line happens to
throw, which means three more v0 answers moved — deliberately, and only in the
direction of "nobody checked this":

| `manifest.json` holds | before | now |
|---|---|---|
| a JSON object with a matching `evidenceDigest` | exit 0, `manifest.evidenceDigest` checked | unchanged |
| bytes that do not parse | exit 3, `manifest.json` unchecked | unchanged |
| `null` | exit 3, then exit 0 after the ledger landed | exit 3, `manifest.json` unchecked |
| `[]`, `"x"`, `3` | exit 0, silently | exit 3, `manifest.json` unchecked |
| a JSON object with no `evidenceDigest` | exit 0, silently | exit 3, `manifest.evidenceDigest` unchecked |
| nothing (no `manifest.json` at all) | exit 0 | unchanged — an absent document is not an unchecked field |

No v0 fixture, and none of the forty real records, is in any of the moved rows;
what moved is what a v0 bundle with a broken or silent manifest answers, and it
moved from 0 to 3. The same four probes above, plus all five manifest shapes,
are now in `test/record-v0.test.mjs`, so the next refactor of this path is held
to the whole table rather than to the four fixtures that happened to exist.

The one v1-visible difference in the original probe is the point of the whole
exercise: before the ledger, every `evidence-v1` fixture — unbalanced,
observed-only, no-ledger, ledger-disagrees, undeclared — exited **0** from
`--record`, and the bundle path called v1 `UNSUPPORTED`.

## Edits requested in files this lane does not own

Neither of these is applied here. `../schema/interfaces.md` is the file whose
own opening rule is that nobody edits it while implementing against it, and
`compiler/driver/lib/record.mjs` belongs to the driver.

### 1. `compiler/schema/interfaces.md` §5 — add the `evidence-v1` fields

Suggested text, to be appended to §5 after the `toolchain` paragraph:

> **`evidence-v1`** adds a declaration and a ledger. A record carrying
> `"schemaVersion": "evidence-v1"` additionally carries, outside `context`:
>
> ```json
> "declaredProperties": [
>   { "propertyId": "demo.erasure" },
>   { "propertyId": "demo.authz", "plannedCheckpoints": ["ir-pre"] }
> ],
> "ledger": {
>   "declarationSource": "policy",
>   "plannedCheckpoints": ["ir-pre", "ir-post"],
>   "entries": [
>     { "checkpoint": "ir-pre",  "declared": 2, "present": 2, "absent": 0, "unobserved": 0, "unresolved": 0 },
>     { "checkpoint": "ir-post", "declared": 2, "present": 1, "absent": 1, "unobserved": 0, "unresolved": 0 }
>   ]
> },
> "unresolved": [
>   { "propertyId": "demo.stackprot", "checkpoints": ["ir-pre", "ir-post"], "reason": "the observer never registered" }
> ]
> ```
>
> - `declaredProperties` is copied from the policy's `properties[]` — the
>   accounts, opened before the run. It is **not** derived from what was
>   measured; a producer that writes it from its own results has written one
>   book twice.
> - `ledger.plannedCheckpoints` is likewise the plan, not the outcome. The
>   policy states its checkpoints in `observeAt`, whose vocabulary
>   (`invocation`, `ast`, `pre-opt-ir`, `after-pass`, `object`, `linked`,
>   `artifact`) is **not** the vocabulary a record's `states[].checkpoint` uses
>   (`preprocess`, `ast`, `ir-pre`, `ir-post`, `asm`, `artifact`). The producer
>   maps between them and records which mapping it used; the verifier compares
>   the names literally and cannot tell a mismatch from a missing measurement.
>   A canonical mapping table belongs in this section.
> - A property may narrow `plannedCheckpoints` to a subset of the ledger's list.
>   It may not widen it.
> - `unresolved[]` entries name a `propertyId` and either a `checkpoint` or a
>   `checkpoints` array, plus a `reason`. An entry that names no checkpoint
>   settles no cell.
> - At every planned checkpoint,
>   `present + absent + unobserved + unresolved == declared`. The record's own
>   `entries` are for a reader; a verifier recomputes them and treats a
>   disagreement as its own finding.

### 2. A `declares` block in the bundle manifest (`packages/evidence-bundle`)

`buildManifest` should carry the same declaration one level away from the
record:

```json
"declares": { "plannedCheckpoints": ["ir-pre", "ir-post"], "properties": [{ "propertyId": "demo.erasure" }] }
```

`verify.mjs` already reads it and prefers it over the record's own copy. Put it
inside `binds` or leave it at the top level as a sibling of `files` — either
works for this verifier — but it has to be inside whatever `bundleDigest`
commits to, or it can be edited afterwards without moving a digest, which is
exactly the hole `binds.evidenceDigest` was added to close.

### 3. Neither is needed for this component to be useful today

`--declared <file>` takes a standalone `evidence-declaration-v1` document, so an
outside declaration can be supplied without either change landing. Two are in
`testdata/declarations/`, and both are read by tests: `four-properties.json` is
WIDER than the records it is pointed at, so it exercises "the record does not
declare X"; `two-properties.json` is NARROWER, so it exercises the other branch,
"the record declares X, which the declaration does not". It was committed with
nothing reading it, which left that second branch untested on the `--declared`
path.
