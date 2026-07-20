# Security

This document describes what VibeGuard defends, what it does not, and where the
limits are. It is written against **engine `0.2.0`** (`engineVersions.core` in
every scan result). See [README.md](README.md#versioning) for how the engine
version relates to the released tool version.

## Reporting a vulnerability

Open a [security advisory](https://github.com/YUTAKONDO1205/VibeGuard/security/advisories/new)
rather than a public issue. Reports about a rule missing a vulnerability, or
firing on safe code, are ordinary issues — those are accuracy, not security.

## Trust boundary

**Scanned code is never trusted, and never leaves the machine.**

Analysis is entirely local. There is no telemetry, no remote rule fetch, and no
account. Every code path in the shipped CLI, VS Code extension, Chrome extension
and their bundled dependencies is scanned on each push for network sinks, and CI
additionally runs the CLI inside a network namespace with no connectivity and
requires byte-identical findings to a normal run. Both checks are in
[`.github/workflows/no-network-assert.yml`](.github/workflows/no-network-assert.yml);
they are designed to fail loudly rather than to be reassuring, and the checks
themselves are tested against deliberately planted network calls on every run.

All four channels run the same analyzer, and CI asserts they agree.

## What can fail a build

**Only severity.** `--fail-on` compares severity, and nothing else.

Confidence is a triage aid — it orders a reviewer's attention. It is deliberately
**not** part of the gate decision. This matters because confidence is derived
from context (is this a test file, a comment, a docstring?) and context is
attacker-controlled: anyone who can write the file can make code look like a
test. If confidence gated CI, that would be a way to turn a real finding into a
passing build by moving it. It does not, so the worst such an attempt achieves is
a worse-ordered report.

The same principle applies to every mechanism that lowers or removes a finding:
**down-ranking and suppression are conveniences for humans, never security
verdicts.** Where a mechanism could be used to make a security-relevant finding
disappear, it is restricted or made visible, as below.

## Threat model

The attacker we model is **the author of the code being scanned** — a developer,
or a code-generating assistant acting on their behalf, who wants a finding not to
appear in review or CI. They control file contents and file placement, and they
know exactly how VibeGuard works: the rules, the context heuristics and the
suppression syntax are all public, and none of the defences below depend on them
being secret.

| What they try | What stops it | What remains |
| --- | --- | --- |
| Break up the dangerous expression so no pattern matches it (`"ev" + "al"`, comments inside a call) | Rules run over normalized text as well as the original, and the results are unioned, so a normalization can only add findings | Normalization is lexical. Semantic rewrites — moving the call behind an alias, restructuring control flow — are not covered by pattern matching in principle |
| Make the code look like a test or an example so its confidence is down-ranked | Findings that carry a security judgement (`critical`, `high`, `medium`) keep their declared confidence regardless of context | `low` and `info` are advisory bands and remain freely down-rankable, by design |
| Suppress it with a blanket `vibeguard:disable`, or a config entry that names no rules | A wildcard suppression cannot silence `critical`, `high` or `medium`, on either the comment or the config channel. The finding is reported with a marker saying a suppression was refused | Naming the rule explicitly still suppresses at any severity — see below |
| Feed the scanner input that makes a rule run forever, so the scan never completes | Rule patterns are bounded, with time and input-length backstops. A scan that stopped early reports that it stopped, rather than returning a short list that looks clean | A bounded scan is an incomplete scan; the report says so, but the unscanned remainder is genuinely unexamined |
| Bury the finding among thousands of matches so it falls past the per-file cap | Hitting the cap on a security-severity rule is reported as a degradation naming the rule and file | The number of findings beyond the cap is unknown and is not guessed |

### Named suppression is an escape hatch, and it is visible

`// vibeguard:disable-next-line VG-INJ-004` works at every severity. This is
deliberate: a team that has reviewed a specific finding and accepted it needs a
way to say so, and removing that would only push people to disable the tool.

What changed in `0.2.0` is that using it **leaves a record**. Findings removed by
a suppression are tallied in the scan result (`suppressions`), in the human and
JSON output, and as notes in the SARIF the GitHub Action uploads by default. The
tally names the rule, the channel, the scope and the file, and deliberately
carries no line number — reproducing the location would rebuild the finding the
author asked to remove.

**This is visibility, not prevention.** The suppression still applies and the
finding is still gone. The claim is narrow and worth stating precisely: a
suppression can remove a finding, but it cannot make the removal
indistinguishable from there having been nothing to find.

## Known limits

Stated plainly, because a checked box that hides a gap is worse than an open one.

- **The no-egress check is not a defence against a hostile commit.** It reads the
  shipped bytes for network sinks, and it identifies a remote reference by the
  literal URL scheme. Someone deliberately hiding a sink from the auditor — a
  scheme obscured by CSS escapes, a URL assembled at runtime from fragments — can
  get past it. It is sound against accidental egress and against a dependency
  quietly acquiring one, which is what it is for. Reviewing the diff is what
  covers the rest.
- **Suppression restrictions apply to the default gate.** They are keyed to the
  severities that carry a security judgement. A project that lowers its threshold
  to report `low` findings will find wildcard suppressions effective again in
  that band.
- **The suppression tally is visible in the CLI and in SARIF, not in the editors.**
  The VS Code and Chrome extensions receive it and do not yet display it.
- **Pattern matching has a ceiling.** VibeGuard reads syntax, not data flow. A
  vulnerability that only exists across function or file boundaries is outside
  what these rules can see, and no amount of rule-writing changes that.
- **Rules that are not shipped are not checked.** The bounds above are enforced
  on the rules in this repository. Supplying your own rule set through the
  library API bypasses that, and is not a supported deployment.

## Reproducibility

`engineVersions.core` identifies the detector. Two runs reporting the same engine
version produce the same verdicts on the same input; a change to detection
behaviour changes that number. Released tool versions move independently and do
not imply a detection change.

The `paper-css-v0.2.0` tag marks the commit at which engine `0.2.0` was settled,
for anyone reproducing published measurements. `paper-ses-v0.1.3` marks the
engine before this round of work.
