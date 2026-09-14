# ai-code-security-design-smells — a public benchmark, v0

A labelled benchmark for one question: **can a tool tell that an authorization
decision has been scattered across request handlers instead of taken once by a
shared guard?**

This is v0. It is small, it is honest about being small, and most of what follows
is about the ways a benchmark like this usually lies.

---

## ⚠ THE LABELS ARE UNCONFIRMED. READ THIS BEFORE USING ANY NUMBER.

Every verdict in `labels.json` carries `groundTruth: "ai-draft-unconfirmed"` and
`humanConfirmed: false`. They were drafted by an AI agent against the rubric, and
**no human has read the implicated handlers.** `humanConfirmed` stands at
**0 of 5**.

This is not a disclaimer, it is what the artefact is. A count scored against an
unconfirmed draft and a count scored against ground truth are different readings
of the same table: where a tool disagrees with a row, the row may be what is
wrong. So —

- the scorer publishes **integer counts only** and refuses to divide
  (`rateWithheld` in `labels.json`, honoured in `bench-score.mjs`);
- every result file records the confirmation state of the labels it was scored
  over, in `labelProvenance`;
- the leaderboard carries a `labels confirmed` column and a banner saying the
  same thing, because a reader meets the numbers in the table, not in this file;
- a row whose `groundTruth` and `humanConfirmed` disagree is **refused** — by the
  builder and by the scorer — rather than published. It used to be the shipped
  state: all five rows said `human-review` beside `humanConfirmed: false`.

Confirm the verdicts at the source, rebuild, and every one of those withholdings
lifts by itself. Until then, the honest description of this artefact is
*a corpus, a rubric, and a draft label set*.

The positive control is the exception and says why in its own file: its ground
truth is `by-construction` — the code was written to be an instance — so its rows
are `humanConfirmed: true` and no rate is withheld. Those rows measure the
**scorer**. They say nothing about any tool's accuracy.

---

## What is here

| file | what it is |
| --- | --- |
| `manifest.json` | repository URL + pinned commit + licence status per entry. **Generated** by `scripts/bench-build-manifest.mjs`. |
| `labels.json` | the verdicts, with the rubric version they were made under and the provenance of each row. **Generated** by the same script. **Unconfirmed — see above.** |
| `rule-families.json` | which tool rule ids count as which family. Hand-written; read its `readThisFirst`. |
| `fixtures/positive-control/` | a corpus written for this repository, with by-construction ground truth. The scorer's control. |
| `fixtures/negative-control/` | an empty label set, which the scorer must refuse. |
| `results/` | result files written by `scripts/bench-score.mjs`. Empty until somebody scores a run. |

**No third-party source code is stored in this repository.** The corpus entries
are other people's repositories, their licences were never recorded by anything
this benchmark was built from, and vendoring them would be redistribution
without one. The published artefact is a manifest plus a fetch script; the
corpus is reconstructed on the machine that runs the benchmark, at the exact
commit the labels were written against.

## Running it

```
# 1. see what would be fetched, without fetching
node scripts/bench-fetch.mjs --plan

# 2. materialise the corpus OUTSIDE this repository
node scripts/bench-fetch.mjs --out ../bench-corpus --allow-unresolved-licence

# 3. run your tool over ../bench-corpus/<entry-id>, emitting SARIF

# 4. score it — naming EVERY labelled entry the run covered
node scripts/bench-score.mjs \
  --sarif your-run.sarif \
  --repository <entry-id> [--repository <entry-id> …] \
  --family-map your-family-map.json \
  --out bench/ai-code-security-design-smells/results/yourtool-1.2.3.json

# 5. regenerate the leaderboard
node scripts/bench-leaderboard.mjs --out bench/ai-code-security-design-smells/LEADERBOARD.md
```

Step 2 needs `--allow-unresolved-licence` and that is not a formality — see
**Licence status** below.

`--repository` is repeatable and it is a claim about **what the run covered**,
not a filter. Labels outside the covered set are reported as `NOT COVERED` and
never as misses. A run whose SARIF carries `versionControlProvenance` needs no
`--repository` at all: coverage is read from the log. When more than one
repository is declared and a finding carries no provenance of its own, that
finding is `unattributed` rather than assigned to the first declared id — the
declaration says which repositories were scanned, not which one a finding is in.

## Intake is SARIF, and only SARIF

The scorer reads SARIF 2.1.0. It does not accept this repository's own finding
format, deliberately: the moment a native path exists it becomes the tested one
and the SARIF path rots behind it, and a benchmark only its author's tool can
enter is not a benchmark. The intake is exercised against two differently shaped
fixtures — one carrying `versionControlProvenance` and `relatedLocations`, one
carrying neither and using `semanticVersion` instead of `version` — because
"tool-neutral" asserted once in a README is not a tested claim.

Only fields the specification requires are read: `tool.driver.name`,
`results[].ruleId`, and `locations[].physicalLocation` with an
`artifactLocation.uri` and a `region.startLine`. A result missing any of them is
**refused and counted** in the `refused` column, never dropped.

## How a finding is matched to a label

On four things, in this order:

1. **repository** — from the run's `versionControlProvenance`, or from a single
   `--repository`. There is no third arm that guesses; a finding that cannot be
   attributed is counted as `unattributed`.
2. **rule family** — via `rule-families.json` or a submitter's `--family-map`.
3. **file** — normalised to forward slashes, percent-decoded.
4. **line window** — within `--line-window` (default 3) lines of **any** site the
   label lists in that file, not only of its anchor. Two tools looking at the
   same duplication will not choose the same representative line, and requiring
   an exact match would score a real agreement as a miss.

**The window is bounded above, at 25.** A floor alone is not a bound: widen the
window far enough and every finding anywhere in a labelled file matches some site
in it, which lifts `recovered` and `reportedKnownFalsePositive` together. A
public benchmark must not ship a knob that improves your score, so a wider window
is a usage error rather than a tuning choice, and the value used is recorded in
the result file and printed in the leaderboard's `window` column.

## The denominator is the labels this run COVERED

The corpus is ~1700 repositories. The label set is five rows. Those two numbers
are the entire reason this section exists.

**On the finding side**, a finding on an unlabelled location is not a false
positive: nobody has decided what it is. So findings partition into four
disjoint, separately printed buckets, and every one of them is a column in the
leaderboard:

- `matched` — within the window of a labelled site.
- `UNSCORED` — the rule maps to a family, no label covers the location.
- `UNMAPPED` — the rule id maps to no family.
- `unattributed` — no repository could be determined.

`matched + UNSCORED + UNMAPPED + unattributed = findings`, in every row. The
scorer asserts it, the leaderboard asserts it again over the result FILE, and a
row that does not add up is rejected by name rather than rendered. Beside them
sits `refused`: SARIF results with no ruleId or no usable location, which never
became findings at all.

`UNSCORED` is the one that matters most. Folding it into zero would make a tool
that reports more score worse for reasons nobody measured, and it would do so
invisibly.

**On the label side**, a labelled repository the run never scanned is not a miss.
`--repository` names the repositories a run covered; `versionControlProvenance`
says the same thing from inside the log. Labels in repositories outside that set
are published as `NOT COVERED`, with their own TP/FP split, and are excluded from
`recovered` / `missed` / `known-FP reported`.

This was a real silent pass, not a hypothetical: scoring a run over ONE
repository against this five-row label set used to report the other four as
`missed` and exit 0, so a tool that scanned nothing at all produced a full set of
misses and a clean exit code. "The tool did not find it" and "the tool was never
pointed at it" are different sentences, and the scorer printed the first for
both.

## What the scorer refuses to do

All of these exit 3 — *nothing was scored* — rather than printing a zero. They
are separate branches with separate messages and the suite tests each one on its
own, because one passing arm standing in for the others is how this class of
defect survives a green test run.

- **An empty label set.** A score of 0 over an empty denominator is not a result,
  it is the shape of a result: every tool scores identically and the ranking is
  an artefact of the emptiness. `fixtures/negative-control/` exists to be refused.
- **A SARIF log with no results.** A scan that ran and found nothing is
  byte-identical, from the outside, to a scan that never ran.
- **A run in which every finding is UNMAPPED.** This one was found by running the
  Semgrep-shaped fixture against the benchmark's own family map: the report said
  `missed: 1`, which reads as "the tool failed to detect" when what happened is
  that no rule id in the run entered the comparison at all.
- **A run in which every mapped finding is UNATTRIBUTED.** No recognised
  `versionControlProvenance` and no single `--repository`: nothing could be tied
  to a manifest entry, so the label side would print a miss for every site — a
  statement about the attribution, read as a statement about the tool.
- **A `--repository` the manifest does not carry.** A typo in a submitted id used
  to score as a tool that detects nothing.
- **A run that covered no labelled repository.** There is no denominator, so
  there is no reading.

Two more are usage errors (exit 2) rather than vacuous runs, because the input
itself is wrong: a `--line-window` above the ceiling, and a label set carrying a
row whose `groundTruth` contradicts its `humanConfirmed`.

The fetcher refuses in the same spirit: a partial corpus is exit 3 with the
failed entries named, because a repository nobody managed to clone scores as a
repository the tool missed, and once the result file is written the two are
indistinguishable.

## The leaderboard

Generated from result files by `scripts/bench-leaderboard.mjs`, never edited. It
does not rank — rows sort by tool name, which is not a claim — and it publishes
every bucket, the coverage split, the confirmation state of the labels each row
was scored over, and the line window each row used.

Files in the results directory that are not `*.json` are listed as **SKIPPED**
with their names, and `*.json` files that are not usable results are listed as
**REJECTED** with the reason. Neither is filtered out in silence: a directory
README and a misnamed result file look identical to `readdir`, and only a reader
can tell them apart — only if the name is printed.

## Licence status — an open gap, stated rather than papered over

**Not one entry has a licence.** No input this manifest was built from carries
one: the upstream pin records hold `{sha, remote, committed, branch}` and the
corpus metadata holds `{full_name, clone_url, language, stars, kb, dir}`. There
was no licence field to transcribe.

Every entry therefore carries `licence.status: "unresolved"`, the manifest
carries `licenceResolved` as an integer pair, and `bench-fetch.mjs` refuses to
clone unresolved entries unless you pass `--allow-unresolved-licence`. Nothing
about that refusal claims the code is unlicensed — it says the licence was never
determined, which is a different and worse thing to act on silently. Closing the
gap means a network call to the forge for each entry, which the build step does
not make.

## Why only five entries, when the corpus has ~1700

An entry with no label contributes nothing to a score — every finding on it lands
in `UNSCORED` — so v0 publishes the part the scorer can actually decide.
Widening the manifest requires widening the labels, in that order. The manifest's
`provenance` block records both numbers so the ratio is visible rather than
implied.

## Regenerating

```
node scripts/bench-build-manifest.mjs          # rewrite manifest.json + labels.json
node scripts/bench-build-manifest.mjs --check  # verify they match a fresh build
```

The inputs are gitignored evaluation data and are absent from a clean clone, so
`--check` exits non-zero there naming the missing input. That is deliberate: a
run that built nothing must never be mistakable for a run that built the same
thing as last time.
