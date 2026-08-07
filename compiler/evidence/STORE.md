# The measurement record store

A measurement that nobody can re-run is a number somebody remembers. This is
where the numbers live, what has to be in one before it counts as evidence, and
— stated as plainly as the rest — what none of it can detect.

## Where the store is

**Not under `compiler/`.** That is a standing rule of this tree, and it is
enforced from outside this component: `scripts/check-packaging-invariants.mjs`
fails the build if a path with a `_results` or a `fixtures` segment becomes
committable beneath the directory, and `.gitignore` lists `compiler/**/_results/`
— listed before anything could write one, which was the point of the ordering.

The reason is not tidiness. A record embeds the sha256 of one machine's
toolchain binaries and the state of one checkout. Committed, it is
machine-specific noise at best; and because this repository does not rewrite
history — a force-push breaks every installed consumer of the published
channels — it is *permanent* machine-specific noise.

So the root is given, never assumed:

| Where it comes from | How |
|---|---|
| the flag | `--store <dir>` |
| the environment | `VG_EVIDENCE_STORE` |
| the default | `vg-lab/evidence-store` under the invoking user's home directory |

The default is computed at run time from `os.homedir()`; no absolute path is
written down anywhere in the tree. A root that resolves inside the checkout is
**refused** (`VG-ART-070`) rather than used, by both the writer and the
validator, so the rule survives an environment that is set wrongly.

Layout inside the store:

```
<store>/<pairId>/run-1.json
<store>/<pairId>/run-2.json
```

## The validator was written before the first record

At the time of writing, `git ls-files | grep _results` matched nothing: there
were no records at all, and every figure in the plan was unsourced. The
validator was built first on purpose. Under the no-rewrite rule the first record
that reaches a commit carrying an account name, a hostname or a
disclosure-shaped string cannot be taken back out, and a validator added
afterwards can only describe what is already permanent.

```sh
node validate-store.mjs --self-test          # fire every detector, both ways
node validate-store.mjs --store <dir>        # every record in a store
node validate-store.mjs --record <file>      # one record; no pair check
node record-run.mjs --observations o.json --store <dir> --pair-id p --run 1
```

## What a record must carry

`measurement-v0`. Every field below is checked, and a record missing one is a
finding, not a warning.

| Field | Why it is not optional |
|---|---|
| `provenance.gitSha` | forty lowercase hex. Without it the measurement names no inputs. |
| `provenance.dirty` | a boolean, and **absent is not false**. A record that does not say whether the tree was clean gives its sha no meaning. |
| `provenance.diffSha256` | required when `dirty` is true. The sha alone then describes inputs the run did not use. |
| `toolchain[].version` | names a package. |
| `toolchain[].sha256` | names what was executed. Two machines with the same version string routinely run different bytes, which is the entire reason both fields exist. |
| `oracle.kind` / `oracle.pattern` | must be a **call-site** oracle (`call …`). See below. |
| `observations[].control` | must be ≥ 1 in every configuration. |
| `reproduction.pairId` / `run` | which half of a re-run pair this is. |
| `evidenceDigest` | re-derived from the rules and compared. |

### The oracle rule, enforced rather than remembered

`interfaces.md` §4: **count the zeroing instruction, never the symbol name.** A
record whose `oracle.kind` is anything but `call-site`, or whose pattern is a
bare symbol, is `VG-ART-077`.

Measured on this machine, `clang-18` 18.1.3, on a fixture with one subject
function whose zeroing is dead and one control function whose zeroing escapes:

| | `-O0` | `-O2` |
|---|---|---|
| `call void @llvm.memset` call sites | 2 | 1 |
| `declare …@llvm.memset` | 1 | 1 |
| naive grep for `llvm.memset` | 3 | 2 |
| subject / control split | 1 / 1 | **0** / 1 |

The naive count never reaches zero, because the `declare` line survives the pass
that removed the store. A first-loss attribution built on it blames a
declaration cleanup for a dead-store elimination.

### The control, and 0-vs-nonzero

`control` must be non-zero in every observation. A subject count of zero beside
a control count of zero does not say the property was lost; it says the
apparatus produced nothing — a fixture that did not compile, a filter that
matched no function, an IR file that was never written. Those are the runs that
read as findings and are not.

## Byte-identity on re-run

Two runs of the same `pairId` must produce the same bytes **outside the
top-level `context` subtree and outside `reproduction`**.

`context` is where every volatile field lives by convention (rule 1 of the
canonicaliser removes it as a whole subtree), so excluding it *is* excluding the
timestamps — expressed as a place rather than as a list of field names that
would need keeping current. `reproduction` is excluded because run 1 and run 2
differ in it by definition.

Nothing else is excluded. A difference in a toolchain digest, an observation, the
git sha or the dirty digest is a real difference between two runs that claimed to
be the same run twice, and it is `VG-ART-078` (critical).

**A pair with only one half present is `VG-ART-078` at medium and lands the run
on exit 3**, not exit 0. Byte-identity is a property of two records; one record
can declare which pair it belongs to and nothing more. `--record <file>` on a
single file always reports `reproduction.byteIdentity` as unchecked for the same
reason.

Measured, twice, against a quiescent checkout with the compilation re-run from
scratch each time: the two files differ only in `generatedAt`, `reproduction.run`
and `evidenceDigest`; with `context`, `reproduction` and `evidenceDigest`
removed, both hash to `1eb37c2265c8576309b3635dbe06ea7be5fe0e73fa1d687d7a735208b13e0d0e`.
Run against *this* checkout while other work was in progress, the same pair came
back `VG-ART-078` — correctly: `provenance.diffSha256` really had moved between
the two runs, because the working tree really had changed.

### The dirty digest covers untracked files

`git diff HEAD` cannot see an untracked file. A digest built from it alone does
not move when the very file a measurement is about is added, edited or deleted,
while `git status --porcelain` calls the tree dirty the whole time — a `true`
flag beside a digest that cannot move. So the digest is taken over the porcelain
status, the diff, and the path *and content* sha256 of every untracked file that
the ignore rules do not exclude.

## What a record may not carry

Four kinds of string, caught four different ways.

| Kind | Caught by | Finding |
|---|---|---|
| an absolute path | `paths.mjs`, on the generation side, **before the digest** | `VG-ART-051` |
| an account name | the home-path segment shape, and the running machine's own account | `VG-ART-075` |
| a hostname | the running machine's own name, a `user@host` token, a UNC prefix | `VG-ART-075` |
| a disclosure-shaped string | **delegated** to `scripts/check-disclosure-shape.mjs` | `VG-ART-076` |

The delegation is the important one. That checker matches shapes rather than
words — it contains no proper noun at all, which is why it can be tracked and
run in CI — and it fires each of its needles against a positive control before
it will report a zero. Re-implementing it here would mean two lists to keep in
step, and the reason it exists is that lists cannot be kept in step. So it is
run as a process over the record files and its verdict is taken. **When it
cannot be run, the check is reported as NOT COMPLETED and the run exits 3** —
never as clean. `--no-delegate` does the same thing on purpose, so the
difference between "checked" and "not looked at" is visible in the exit code.

There is one deliberate overlap. The shape checker's home-directory needle
anchors on a leading slash, and the convention in this tree is to strip it
(`usr/bin/clang-18`); `home/<name>/x` therefore slips under both that needle and
the absolute-path gate. That gap is covered here, and only that gap.

The account allow-list here holds names that are a *role* rather than a person —
`root`, `runner`, `ubuntu`, `ci`. An allow-list is the opposite of a
forbidden-word list: it does not grow with the thing it is trying to catch, and
publishing it discloses nothing. Without it every record produced on a CI runner
would report the word `runner` as a leak.

## Symlinks are refused, not followed

Any component of the path to an input being a symbolic link is a refusal
(`VG-ART-071` in the store, `VG-ART-063` inside a bundle), on `verify.mjs` and
`validate-store.mjs` and `record-run.mjs` alike.

A verifier that opens whatever it is handed reports on the bytes at the far end
of a link while naming the near end: the file name, the digest and the counts are
then all true of a file the reader is not looking at. It needs no privileges and
leaves no trace in the record, and it survives by accident too — a store
restored as a link to an older copy verifies clean and dates from last month.

**Ancestors are checked, not just the final component.** `store -> elsewhere/`
redirects every file beneath it at once and is the cheaper substitution of the
two. The walk climbs to the filesystem root; `--link-boundary <dir>` stops it
short for a machine whose home directory is legitimately a link. That is a named
flag and not an inferred exemption, because someone has to say which
redirection is the expected one.

On Windows an unprivileged process cannot create a *file* symlink, but a
directory junction is reported by `lstat` as a symbolic link and performs the
same redirection; the tests build junctions there and real symlinks on Linux, and
both go through the same `isSymbolicLink()` test over the same component list.
Both forms were exercised: the file form on Linux, the directory form on both.

## What this does not detect

Stated here because a limit that is only implied gets read as a limit that does
not exist.

**A coherent regeneration of the evidence is outside the detection range.**
Nothing in this component binds a record to an authority. There is no signature,
no external timestamp, no witness. Someone who edits a fixture, re-runs the
measurement and re-seals the record produces a store that verifies clean and is
byte-identical across its pair — because it *is* consistent; it is simply
consistent with a different experiment. Every check here is an internal
agreement check:

* `evidenceDigest` catches a record edited **after** sealing, not a record
  sealed after editing.
* the pair comparison catches two runs that disagree, not two runs that agree
  about the wrong thing.
* the symlink refusal catches a report that names one file and reads another,
  not an author who replaces the file itself.
* `provenance.gitSha` and `diffSha256` are what the writer read from `git` on
  the machine that ran it, which is a claim about that machine.

What the store does provide is that a *disagreement* is visible, that a
measurement carries enough to be re-run by someone else, and that a check which
could not be completed says so rather than exiting 0. Detecting a coherent
regeneration would need something this component does not have and does not
pretend to: an authority outside the machine that produced the record.

Two smaller limits, for the same reason:

* the disclosure delegation needs the record to be expressible as a path
  relative to the checkout. A store on a different Windows drive cannot be
  handed to the shape checker, and the check is then reported NOT COMPLETED.
* `toolchain[].sha256` is the digest of the file at the path the writer was
  given. It does not establish that the binary is the one a distribution
  shipped; that is what a pin is for, and the pin lives in the driver.

## The counting contract

Every entry point here prints `inputs=N checked=N skipped=S`, and a run that
checked nothing exits 3 unless `--allow-empty` was passed. `checked + skipped`
must equal `inputs`, and a run where it does not also exits 3.

This is `counting.mjs`, imported rather than repeated, because it has been got
wrong three separate times in this repository — most recently by
`verify.mjs --self-test`, which reproduced every one of the nought vectors in
`{"vectors":[]}`, agreed with the generator about all nought of them, and exited
0. Nothing it printed was false. The exit code was.

The emptiness test keys on `checked` and not on `inputs`, so that "10 files, 0
findings, all 10 skipped" is refused by the same line as "0 files".

## Finding IDs

`VG-ART-0NN` is the artefact verifier's namespace (`../schema/interfaces.md`
§2). `verify.mjs` holds 050–062 for record-internal checks; 063 and 070–079 are
this component's.

| ID | Meaning |
|---|---|
| `VG-ART-050` | `evidenceDigest` missing, or does not match a re-derivation (shared with `verify.mjs`) |
| `VG-ART-051` | the record carries an absolute path (shared with `verify.mjs`) |
| `VG-ART-063` | a symbolic link on the path to a record or artefact inside a bundle |
| `VG-ART-070` | the store is inside the checkout |
| `VG-ART-071` | a symbolic link on the path to, or inside, the store |
| `VG-ART-072` | the record is not a measurement record, does not parse, or has no `gitSha` |
| `VG-ART-073` | the dirty-tree flag is missing, or a dirty tree pins no diff |
| `VG-ART-074` | a toolchain entry has no version or no binary digest |
| `VG-ART-075` | the record carries machine identity |
| `VG-ART-076` | the record carries a disclosure-shaped string (from the delegate) |
| `VG-ART-077` | the oracle counts something other than a call site |
| `VG-ART-078` | a re-run pair disagrees, or is missing a half |
| `VG-ART-079` | no observation, or an observation with no surviving control |

## What has been measured

Every line below was produced by running the code.

| Claim | How |
|---|---|
| every detector fires on a positive control and stays silent on a negative one | `validate-store.mjs --self-test` → 14 positive, 3 negative, exit 0 |
| the delegated shape checker still fires its own needles | the same run shells out to `check-disclosure-shape.mjs --self-test` |
| the delegate catches, in a record, a shape nothing here looks for | a `PLAN-LABEL` needle in a store record → `VG-ART-076`, exit 2 |
| two runs against a quiescent checkout are byte-identical outside `context` | both cores hash to `1eb37c22…`, `diff` exit 0 |
| two runs against a tree that changed between them are not | `VG-ART-078` critical, exit 2 — observed on this checkout, live |
| the oracle numbers | `clang-18` 18.1.3: `-O0` 2 call sites, `-O2` 1, `declare` 1 either way, naive grep 3 / 2 |
| an empty store exits 3, and 0 only with `--allow-empty` | run on both Windows and Linux |
| an empty vector file exits 3 | `verify.mjs --self-test --vectors <empty>` → 3 (was 0) |
| a symlinked record and a symlinked store are refused | file symlink on Linux, junction on Windows → exit 2 both |
| the store may not be inside the checkout | writer exit 2, validator `VG-ART-070` exit 2 |
| 71 tests | `node --test compiler/evidence/test/*.test.mjs` |
