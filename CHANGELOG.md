<!-- vibeguard:disable-file VG-SEC-001 VG-QUAL-006 -->
<!-- This file quotes rule INPUTS to explain what changed — an AWS-shaped key
     for the redaction work, a placeholder email for the fast-vs-standard mode
     difference. Both rule IDs are named rather than blanket-suppressed. -->

# Changelog

All notable changes to VibeGuard across CLI / GitHub Action / VS Code extension /
Chrome extension are documented here. Per-extension changelogs live alongside
each extension (see `extensions/vscode/CHANGELOG.md`).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

Remediation-side hardening. **Engine is unchanged at `0.3.1`** — no rule changed what it
matches or at what severity. What changed is what `--fix` is willing to write, and what a
fix run reports back to CI.

The theme is one rule: **a fixer must be stricter than the detector that fed it.** Each item
below is a place where it was not, and where the result was worse than no fix at all — the
finding disappeared while the defect stayed.

### Changed

- **BREAKING — `--fail-on` now applies in fix mode.** `--fix` and `--dry-run` previously
  returned exit code 0 unconditionally, so adding either to a command turned a red gate
  green. This happened even for findings whose rule has no fixer, and even for `--dry-run`,
  which writes nothing: a scan that failed `--fail-on high` on its own passed the moment
  `--fix` was appended.

  Fix mode now evaluates `--fail-on` against the same finding set the non-fix path would
  have used, and returns the worse of the two exit codes. It is deliberately gated on the
  PRE-fix findings: that a fix was applied is not evidence that the finding is gone (the two
  items below are counterexamples), so the guarantee is only that **fix mode never weakens
  the gate**. Re-run the scan to get the post-fix verdict — an observation, rather than a
  claim by the process that did the writing.

  **If you run `--fix` in CI**, a job that was passing may now fail. That is the intended
  correction: it was passing because the gate was off, not because the code was clean. To keep
  a fix run advisory on purpose, pass `--fail-on never`, which is the supported way to say
  "report, do not gate" — rather than relying on fix mode to suppress the exit code.

- **`VG-EMB-020`'s remediation no longer prescribes `#define DEBUG 0` as a paste-ready fix.**
  Setting the flag to `0` disables it only where the code reads its VALUE (`#if DEBUG`).
  Where the code tests whether it is DEFINED (`#ifdef DEBUG`, `#if defined(DEBUG)`), a zero
  is still a definition and the debug path still compiles. The `how` text now names that
  condition and leads with the unconditional remedy (drop the define from release builds,
  select it from the build system); `exampleFix` is removed, because no single line is
  correct for both consumption styles and a paste-ready line is what gets pasted.

### Fixed

Three fixers could report a fix as applied while the finding's underlying defect survived —
in two of them the rule also stopped matching afterwards, so the file scanned clean. Each now
**declines** rather than edit under an assumption it cannot check from the bytes it reads, and
leaves the prose remediation, which can describe changes a token swap cannot perform.

- **`VG-EMB-010`** edited a URL the rule had deliberately passed over. The fixer's pattern
  lacked the loopback exclusion the rule's own pattern carries, and it searched forward from
  the reported column rather than requiring the token to start there. It now carries the same
  exclusion and only edits at the reported column. A payload the rule found through
  normalization no longer receives an automatic fix at all — the finding still reports, and
  the edit is left to a human.
- **`VG-INJ-020`** could guard a loop other than the one the finding was about. It now
  declines when the loop the finding refers to cannot be identified from the reported line
  alone.
- **`VG-EMB-020` / `VG-EMB-021`** assumed a preprocessor flag is consumed by value. Both
  fixers now decline when the file tests whether the macro is defined (see *Changed*, above).
  **This narrows what `--fix` will write; it does not change what the rules detect.**

> Each entry states what the fixer now refuses to do. Fuller technical write-ups follow once
> this release has reached all four channels, per the project's practice of not publishing a
> reproducible weakness against a version users are still running. The `--fail-on` change
> above is stated in full because operators need it to audit their pipelines today.

### Documentation

A sweep of every tracked `.md` against the code it describes. No behaviour changed; several
documents were describing a version of VibeGuard that no longer exists.

- **A setting named in the README does not exist.** The README told VS Code users to set
  `vibeguard.mode` to make the editor agree with CI. There is no such setting — the extension
  contributes `vibeguard.scanOnSave` and `vibeguard.scanOnSaveMode`, and anyone who followed
  the instruction got no error and no change, which is the worst shape this kind of mistake
  can take. Corrected to `vibeguard.scanOnSaveMode`.
- **`--fix` / `--dry-run` and `.vibeguardrc.json` were undocumented in the README** despite
  shipping. Both now have sections, including the pre-fix `--fail-on` semantics above.
- **Counts that had drifted.** `SECURITY.md` was written against engine `0.2.1` (now `0.3.1`)
  and said twelve rules declare `low` confidence (seventeen do). The README's version table
  still read `0.3.1` for the tool version (`0.3.3`). Two sample-corpus READMEs referred to
  "the 47 rules" (71).
- **Claims the code had outgrown.** `SECURITY.md` said cross-file vulnerabilities are outside
  what the rules can see, which stopped being unqualified when `--include-design-smells`
  landed; it now states what that pass does and does not raise. The README documented two CI
  workflows (there are five) and two sample gate pairs (there are four, plus the cross-file
  corpora that the `samples` job deliberately does not cover).
- **`packages/analysis-graph` had no README** — the only package without one, and the one with
  the packaging invariant most worth writing down. Added.
- The VS Code extension README listed its shipped Quick Fixes under "Roadmap", and
  `test_problem/README.md` named a rule prefix (`VG-SECRET-*`) that has never existed.

## [0.3.3] - 2026-07-29

Packaging fix for 0.3.2. **Engine is unchanged at `0.3.1`** — nothing about detection moved.

### Fixed

- **The Chrome extension shipped 0.3.2 with a manifest still saying `0.3.1`.**
  `extensions/chrome/manifest.json` is a hand-maintained static file that the build copies
  verbatim into `dist/`; the 0.3.2 bump moved every `package.json` and missed it. The Chrome
  Web Store reads the manifest and rejects an upload whose version is not greater than the
  published one, so the 0.3.2 zip could not be submitted.

  The failure arrived as late as it possibly could: the tag was pushed, the Release workflow
  went green, and the VSIX published to both marketplaces at 0.3.2 — the mismatch surfaced only
  when a human tried to upload the zip. `check-packaging-invariants.mjs` now asserts that the
  manifest matches its `package.json`, and that all four shipped surfaces match the root
  version — a source-only check, so it fails in seconds before anything is packaged. It was
  verified to reproduce this exact failure before being kept.

  0.3.2 stays published on the VS Code Marketplace and Open VSX; it is 0.3.3 minus this fix.
  Chrome goes straight from 0.3.1 to 0.3.3.

## [0.3.2] - 2026-07-29

**Engine moves to `0.3.1`, and this is the first bump that is not additive.**
Every release before it could say "no rule that already existed changed what it
matches". This one cannot: it follows a deep audit whose subject was existing
rules getting it wrong, and verdicts move in BOTH directions. Comparing a `0.3.0`
run against a `0.3.2` run is not meaningful — that is what the engine axis is
for.

Findings from a deep audit of `f274ef9`, verified against the code before being
acted on. Every item below was reproduced with a minimal PoC, fixed, and pinned
with a regression test; three audit claims did **not** reproduce and are recorded
at the end rather than "fixed".

`samples/safe` stays at 0 findings and `samples/vulnerable` at 51
(5 critical / 16 high / 27 medium / 3 low) — unchanged through every change
below, which is the evidence that the corrections are targeted rather than broad.
Test count 1,278 → 1,401.

### Upgrading

- **CI gates may move in either direction.** `VG-INJ-005` stops failing builds on
  `Loader=SafeLoader`; the canonical/raw merge and `VG-SMELL-012` start reporting
  findings that were being dropped. Re-baseline before assuming a regression.
- **A suppression that lived in a string literal has stopped working**, because
  it never should have. If a file went quiet after upgrading, look for prose that
  quotes a `vibeguard:disable-…` directive.
- **SARIF artifact URIs are now repository-root-relative** for a subdirectory
  scan. GitHub code scanning will retire the old alerts (which pointed at paths
  that did not exist) and open them at the correct locations.

### Fixed — suppression could be triggered by prose

- **A pragma quoted inside a string literal silenced the file.** `PRAGMA_RE`
  matches raw line text and knows nothing about where that text sits, so a
  string that merely QUOTED a suppression directive — a help message explaining
  the feature, an error message, a doc comment's example — disabled the rule it
  named for the whole file. The realistic trigger was not an attack but
  documentation; the same mechanism also let a directive be smuggled in as
  ordinary string data. `parseSuppressions` now rejects a directive that sits
  inside a quoted string.

  Quote state is tracked per line and stops at the first comment opener found
  outside a string, so `// don't` cannot swallow the rest of the file. A pragma
  inside a MULTI-line string (Python docstring, JS template literal, C++ raw
  string) is still honoured — the same residual class the canonicalizer
  documents. The error direction is the safe one either way: misjudging a real
  pragma reports a finding someone wanted hidden, while the reverse hides a
  finding nobody chose to hide.

  Not in the audit. Found by asking what the symmetric case of the VS Code
  comment-syntax bug was on the PARSING side.

### Fixed — secret disclosure

- **Secrets survived redaction whenever they were not written as quoted string
  literals.** `maskSecret` keyed off quote characters — a property of the source
  syntax, not of whether a value is a credential — so `aws_access_key_id: AKIA…`
  in a YAML file, `AWS_ACCESS_KEY_ID=AKIA…` in a `.env`, and a rule's bare
  `evidence` token all passed through verbatim. It now masks all three shapes.

  This is a disclosure bug and not a cosmetic one because `snippet` is the field
  the SARIF adapter emits, and `.github/workflows/security-scan.yml` and the
  README both document uploading that SARIF to GitHub code scanning: a scan
  published the key it had just found. It compounds with the scanner having no
  `.gitignore` awareness (`DEFAULT_IGNORE` is a fixed set of directory names), so
  a `.env` materialised during CI from repository secrets is scanned like any
  other file.

- **Length was the wrong discriminator, so every embedded credential leaked.**
  The first pass at the above kept a 12-character minimum and an alphanumeric
  character class, which walked straight past `WiFi.begin("HomeNet",
  "Tsu9any0!")` and `#define OTA_PASSWORD "Tsu9any0!"` — nine characters with
  punctuation, which is exactly what a password policy asks for. Embedded users
  were still having WiFi and OTA passwords copied into SARIF. What separates a
  credential from a placeholder is not length but whether the value is a known
  public default, so the character class now covers password punctuation, the
  minimum drops to six, and an explicit allowlist (`changeme`, `letmein`,
  `password`, …) keeps readable the values whose identity IS the finding —
  masking `changeme` to `chan***` deletes the entire message of `VG-AUTH-003`.

### Fixed — diff scans that reported clean because they read nothing

Both of these produced zero findings, exit 0, and no degradation, which is
indistinguishable from a genuinely clean diff.

- **A diff scan targeting a subdirectory found nothing, ever.** Diff headers are
  repo-root-relative whatever directory git ran in, and those paths were joined
  onto the scan TARGET — building `pkg/a/pkg/a/client.py` for a scan of `pkg/a`.
  Every read failed and every failure was swallowed as "file deleted in the new
  revision". Paths now resolve against `git rev-parse --show-toplevel`, and the
  target acts as a filter, so naming a subdirectory means "the part of this diff
  under here".

  Note what is deliberately NOT changed: the path a finding REPORTS stays
  relative to the target, matching a directory scan. Reading against the root
  and reporting against the root are different decisions, and conflating them
  breaks three consumers at once — `fix.ts` reads a finding back as
  `join(target, displayPath)`, config `suppress[].paths` globs are written
  against it, and the SARIF adapter emits it as the artifact URI. The first cut
  of this fix did conflate them and would have made `--fix` on a subdirectory
  diff look for `pkg/a/pkg/a/client.py`.

- **A user's gitconfig could silently disable diff scanning entirely.** The
  header parser recognises `+++ b/<path>` and nothing else, so `diff.noprefix`
  (headers arrive as `+++ path`), `diff.mnemonicPrefix` (`i/`, `w/`, `c/`, `o/`)
  and git's DEFAULT `core.quotepath=true` (non-ASCII names arrive octal-escaped
  and quoted, `+++ "b/src/\350\252\215…"`) each made it register no files at all.
  `gitDiff` now pins those knobs with `-c` for its own invocation and forces the
  prefixes, so there is one header shape to parse and it does not depend on
  ambient configuration.

  Unlike the subdirectory bug this one fires at the repo root, so it reaches the
  GitHub Action: a self-hosted runner or a Docker image with a baked-in gitconfig
  carries the setting into CI. Repositories with non-ASCII filenames were
  skipping exactly those files.

### Fixed — options and caps that applied on one scan path only

- **`--known-only` did nothing on a diff scan.** It reached `scanPath` and
  stopped there, so a workflow passing it with `--diff` scanned exactly the
  files it had asked to exclude — accepted, ignored, and silent about it. The
  diff path now honours it, and applies `MAX_FILE_BYTES` too, which it also
  lacked: a large generated file in a commit was read whole on the path where a
  directory scan would have skipped it.

- **`action.yml` dropped `path` whenever `diff` was set.** A workflow asking for
  `path: packages/api` plus a diff range scanned the whole repository instead —
  the opposite of what it wrote, in the widening direction. `path` now applies
  on both branches.

  This could only be fixed AFTER the diff path bug above. While a subdirectory
  target made every read fail, passing `path` here would have turned a scope
  error into a silent all-clear. The two changes ship together for that reason.

- **The cross-file pass and the core scan disagreed about which files exist.**
  `project.ts` declared `MAX_FILE_BYTES = 1024 * 1024` under a comment saying it
  mirrored the core's `1_000_000`, which it did not: every file in the
  48,576-byte gap was indexed by the cross-file pass and silently skipped by the
  per-file scan, so a cross-file finding could cite a file the report showed as
  clean. That is the exact failure the module header says its dependency on
  `analyzer-core` exists to prevent — the ignore set and language mapping are
  imported for that reason, and now the cap is too.

### Fixed — false positives that break correct code

- **`VG-INJ-005` reported `yaml.load(data, Loader=SafeLoader)` as critical.** The
  veto matched only the `yaml.SafeLoader` spelling, so the form PyYAML's own
  documentation uses — `from yaml import SafeLoader`, then a bare
  `Loader=SafeLoader` — failed the default `--fail-on high` gate on code that had
  already done the right thing. `CSafeLoader` and `BaseLoader` are now recognised
  too, bare or module-qualified. `FullLoader` and `UnsafeLoader` are still
  reported: both construct arbitrary Python objects.

  Worth calling out because there is no layer downstream that could have softened
  this: `SEVERITY_CONFIDENCE_FLOOR` pins critical/high findings to `high`
  confidence, so context downgrade cannot reach them.

- **`VG-SMELL-012` was disabled for a whole file by any mention of a
  mitigation.** The veto ran against raw text, so `const doc = 'see
  Object.freeze() docs';` — a doc string, a log line, an error message — silenced
  every role comparison in the file, silently. It now tests blanked code, so a
  real `Object.freeze({…})` still vetoes and a mention of one does not.

### Fixed — a decoy in a comment could take the real finding's place

- **The canonical/raw merge dropped a distinct payload as a duplicate.** The two
  passes are deduplicated by SOURCE OVERLAP, which is right for the case it was
  written for: normalisation MOVES a match, and the two faces are then
  describing one finding. But blanking a comment also lets a canonical match
  SPAN the blank run, and a raw match living inside that comment then overlaps
  it. Those are not duplicates — one is the assignment that runs, the other is
  text in a comment — and the merge kept the wrong one.

  The executed finding disappeared and the comment match stood in its place,
  wearing its position and its evidence. That inversion is what made it worth
  fixing: a reviewer seeing one finding on a comment line does the obvious thing
  and suppresses the false positive, which silenced the file completely.

  A raw match may now veto a canonical one only when it sits on text that
  SURVIVED normalisation. Both documented dedup cases still collapse to one
  finding, because in both the original match is on real code. `samples/safe`
  and `samples/vulnerable` are unchanged, and the canonicalizer soundness
  corpus — which fails the build if normalisation MANUFACTURES a finding —
  still passes: the extra finding appears only in the adversarial arrangement.

### Changed — F-002's remaining false negative is now a stated limitation

- Only the comment half of C's translation phase 2 is modelled. A splice inside
  an identifier still evades, and that is now written down rather than left
  implicit: a `KNOWN RESIDUAL` entry beside the code, an added note in the audit
  report, and `f002-splice-canary.test.ts` pinning the current answer so that
  implementing the splicing face breaks a test instead of passing quietly.

  The reason it stays open is the cost of closing it. Recognising a spliced
  identifier needs a transformed text whose offsets no longer match the source,
  and every position VibeGuard reports — findings, snippets, `disable-line`
  lookups, SARIF regions, the Quick Fix insertion point — is identity-mapped to
  the source by construction. Same shelf as the `R"(…)"` and Unicode-escape
  residuals: reachable only by someone writing the evasion.

### Fixed — evaluation harnesses measured different populations on each side

None of this ships in the tool; it changes what the research artifacts claim.

- **E6's density divided findings by a KLOC it did not measure.** The numerator
  came from a scan of everything on disk, the denominator from twelve source
  extensions under a different skip list with no size cap — a three-way
  mismatch. Both now come from ONE file manifest, built with the scanner's own
  ignore set, language mapping and size cap, and a finding landing outside it is
  counted and reported rather than silently included.
- **`sast-baseline-eval.mjs` had the same defect twice.** Locations were
  compared by BASENAME, so any two `utils.py` in different directories counted
  as the same file and inflated the overlap; and "VibeGuard-only" was filtered
  by extension, so a file the baseline never parsed counted as a miss by the
  baseline. Now matched on full relative paths — reconciled across the two
  tools' different bases, with ambiguous matches dropped and counted instead of
  guessed — and restricted to the files the baseline reports having analysed.
  The scope line naming what was excluded is part of the output.
- **The matched-pair tests reported a p-value their data cannot support.**
  McNemar assumes independent pairs; these pairs are repeated TRANSFORMS of the
  same original findings, so `n` counts transforms rather than evidence. Both
  harnesses now emit `inferentialValidity` beside the p-value, carrying the
  cluster structure (114 pairs are 19 original findings over 9 files; the 15
  discordant pairs are 7 originals over 4) and stating plainly that no general
  claim about tool classes rests on it. Aggregating to one vote per finding
  moves the value by an order of magnitude, and that sensitivity is the point.
- **E1 compared less than its own documentation claimed.** The header said the
  tuple included `category` and the end coordinates; the key did not, and the
  comparison went through a `Set`, so a difference in multiplicity was invisible
  too. Now a multiset comparison over the full tuple — still 0 divergences,
  which is the first time that result means what it says. The report also
  quantifies the mode gap it never mentioned: 40 findings on these corpora are
  visible at `standard` and not at `fast`, which is the default VS Code scans
  on save at.
- E6 can now pin each corpus repository to a commit (`paper_data/e6_pins.json`),
  so a published table can be regenerated rather than merely re-derived. Without
  the file the run floats on upstream HEAD, and says so.

### Fixed — the blankers decided the wrong things were code

`VG-INJ-020` Branch A matches on RAW text and consults the blanked copy only as
a veto (`if (blanked[m.index] !== content[m.index]) continue`). So blanking
something that IS code loses a finding, and failing to blank something that is
not keeps a bogus one. The comment claiming "fails to blank … is the same
fail-safe direction" was wrong for that consumer: there it is fail-OPEN.

- **`${…}` in a template literal was blanked wholesale.** A substitution is an
  evaluated expression, so `` `${obj.__proto__.polluted = userInput}` `` reported
  nothing while the identical assignment one line above reported `VG-INJ-020` at
  `high`. The blanker now re-enters the code state inside a substitution, with a
  brace stack so nested templates work. Ordinary template TEXT is still blanked.

- **`return /re/` was read as division.** The preceding significant character is
  `n`, an ordinary identifier char, so the regex state was never entered and the
  pattern BODY was classified as code — reporting the contents of a regex
  literal as a live prototype-pollution assignment. The division-vs-regex call
  now also looks at the preceding WORD, for the keywords that cannot end an
  expression (`return`, `typeof`, `case`, `throw`, …). Value positions —
  identifier, `)`, `]`, `.x`, a number — still divide.

- **A C line comment ending in a backslash did not continue.** C, C++ and
  Arduino delete backslash-newline in translation phase 2, BEFORE comments are
  recognised, so

  ```c
  // disabled call \
  gets(buf);
  ```

  is entirely comment — and was reported as `VG-MEM-001` **critical**. Both
  passes had to agree for the finding to go away, so the rule's blanker and the
  canonicalizer now read one shared predicate, the same arrangement this
  codebase already uses for comment SYNTAX. Splicing is off for every other
  language, where a trailing backslash means nothing and continuing would blank
  real code.

  **The matching false negative is NOT fixed.** `ge\` + newline + `ts(buf);` is
  `gets(buf)` to a compiler and still reports nothing. Recognising it needs a
  real splicing face with its own position mapping, which is the one change most
  likely to break the identity-mapped geometry every finding, snippet and
  suppression depends on. The FP half needed no such thing — blanking is
  length-preserving — so it ships now and the FN half is left open deliberately.

  The regression tests for this build their backslash from `String.fromCharCode(92)`
  rather than writing it as an escape. An escaping slip that loses it turns the
  fixture into one ordinary comment line, which every assertion would then pass
  for the wrong reason — as the first draft of those tests did. One test asserts
  the fixture's own shape before the others use it.

### Fixed — claims the tool could not support

- **`match-limit` asserted that further matches existed.** `runRegex` halts AT
  the cap without probing for a next match, so hitting the cap is not evidence
  that anything follows: a file with exactly 1000 matches raised a degradation
  reading "Further matches … exist and were NOT reported" while nothing had gone
  unreported. Reworded to "MAY exist … whether any do, and how many, is unknown",
  which is also what `REGEX_MATCH_LIMIT`'s own doc requires of consumers. The
  contradicting sentence in `findings-schema` is corrected to match.
- **`matchCount` was hardcoded to the global cap.** A rule passing its own
  smaller `limit` to `runRegex` reported `matchCount: 1000` beside three
  findings. It now carries the count the boundary event actually recorded.

### Fixed — SARIF

- `$schema` pointed at a sarif-spec branch path that 404s, and `informationUri`
  named `github.com/vibeguard/vibeguard`, which does not exist. Both now resolve
  (OASIS publication location, and this repository).
- Rule descriptors carry `security-severity` and `precision`. SARIF has four
  levels to VibeGuard's five severities, so `critical` and `high` both collapse
  to `error`; `security-severity` is where GitHub code scanning recovers the
  distinction, and without it every alert landed in one bucket.

### Fixed — Chrome extension reported clean for things it never looked at

Measured in a real browser against `rust-lang/rust#160102` (284 changed files),
using the extension's own selector chain.

- **A PR scan silently covered 43% of the PR.** GitHub collapses the diffs of a
  large PR behind "Load diff" and never puts those rows in the DOM: 121 files
  rendered, **163 not**. Scrolling to the bottom repeatedly does not change
  those numbers, so this is not lazy loading a reviewer can wait out. The panel
  reported "N file(s)" for whatever it got, with no hint that the rest existed.

  Every changed file has a `data-path` element whether or not its diff was
  drawn, so the page knows the full list even when it has only rendered part of
  it. The extension now reports the difference: the status line reads "121 of
  284 file(s)" and a banner names the files that went unread. Their NAMES, not
  just a count — a count invites the reader to assume the unread ones were the
  uninteresting ones.

- **Mixed-language pages lost one language's findings.** Every `<pre><code>`
  block was concatenated into a single snippet and scanned once, under a single
  language — with `// --- block N ---` separators, a JavaScript comment injected
  into text that might be Python, where `//` is floor division. Against the
  shipped browser core, a Python block calling `subprocess.call(…, shell=True)`
  next to a JavaScript block assigning to `innerHTML`:

  ```
  joined, scanned as python      -> 1 finding   (the JS sink is lost)
  joined, scanned as javascript  -> 1 finding   (the Python sink is lost)
  per block, per language        -> 2 findings
  ```

  Whichever language was picked, joining lost the other one's sinks — on AI chat
  transcripts, tutorials and API docs, which is most of what this feature is
  pointed at. Blocks are now their own unit of analysis, each with its own
  language, rendered per block.

- **"Could not scan" rendered as "✓ No issues".** A file whose scan threw was
  turned into an empty finding list, which the panel drew with the same green
  tick as a file that passed. There are three states, not two, and the tick is
  now reserved for a block that was actually read.

- **A crashed rule was invisible in BOTH extensions.** `analyzer.scan` catches a
  throwing rule, records it in `ruleErrors` and lets the rest finish — the right
  call, since a partial report beats none. But neither extension read that
  field, so a rule that died contributed no findings and the result rendered
  clean. Only the CLI surfaced it, which `analyzer.ts` itself notes.

  The side panel now shows a banner and marks an empty result OK only when
  nothing degraded AND nothing errored. The VS Code extension raises a line-1
  Warning per broken rule, through the same channel it already used for
  degradations and for the same stated reason: an incomplete scan must not look
  like a clean one. Both are deduped by rule id, so one broken rule is one
  warning however many times it threw.

- **Two unbounded allocations reachable from a hostile page.** The extension
  holds `<all_urls>`, so a page the user is merely steered to could return
  unbounded text. Block collection is now capped (500 blocks, 200k chars each,
  2M total; `innerText` forces layout per element, so the element count matters
  as much as the bytes). And the diff pseudo-file was sized by the highest
  `data-line-number` in the page — a page-supplied number, so a large enough one
  asked for an array big enough to take the side panel down before any rule ran.
  Now capped at 200,000 lines, and the cap is reported rather than applied
  silently.

### Fixed — VS Code

- **The suppression Quick Fix corrupted the file it was suppressing in.** Comment
  syntax was "`#` for nine languages, `//` for everything else", and the provider
  is registered on every file. Several rules are language-agnostic
  (`VG-CRYPTO-003` matches an `http://` URL in any text), so findings do appear
  in JSON, CSS, HTML and PowerShell — and accepting the fix in a `.json` file
  left a document `JSON.parse` rejects. Comment style is now per-language
  (`extensions/vscode/src/comment-syntax.ts`), falling back to a block comment
  where there is no line comment (CSS, HTML) and withholding the fix entirely for
  strict JSON, which has no comment syntax at all. The extension gained a test
  script; it had none.

### Documentation

- **`PRIVACY.md` contradicted the Chrome extension.** It described
  `chrome.storage.session` hand-off as the only storage, while the side panel
  persists up to 50 history entries in `chrome.storage.local` — including
  `codePreview`, the first 200 characters of the scanned text stored verbatim.
  The policy now describes what is stored, for how long, and how to clear it, and
  says that scan reports carry `snippet`/`evidence` and should be treated as
  sensitive as the code they describe. The README's history row said "summary +
  finding metadata only — never the full code", which omitted the preview.
- **"You'll get the same answer at every one of them" was not true by default.**
  VS Code's on-save scan defaults to `fast`, every other surface to `standard`,
  and they run different rule sets: `const email = "admin@example.com";` is clean
  on save and flags in CI. The README now states the qualifier (same engine, same
  input, same `mode`) and names both sources of divergence.
- Corrected: `findings-schema` advertised "Zod-style validation" with no schema
  library and no runtime validator, described a nested `location` the wire format
  does not have, and gave `targetType` as `file|diff` rather than
  `file|snippet|diff|repo`; `analyzer-core` documented a `detectLanguage` that
  does not exist (the exports are `detectLanguageFromPath` /
  `detectLanguageFromContent`); `remediation-engine` said `buildRemediation`
  returns `undefined` without a template when it returns a fallback; the VS Code
  README said **30 built-in rules** against an actual **71**.

### Audit claims that did not reproduce

Recorded rather than fixed, so they are not re-investigated from scratch later:

- **Object-literal division misread as a regex start.** The report's own example
  (`const n = {} / 2;` followed by a sink) detects normally, as do five variants
  including cross-line division. The two neighbouring claims in the same finding
  — template substitution `${…}` being blanked, and `return /re/` misread as
  division — do reproduce and are fixed above.
- **Chrome mixed-language extraction producing zero findings.** Joining blocks
  does lose findings — two separate blocks report 2, the joined text reports 1,
  in whichever language is chosen — but the "0 findings" figure was specific to
  an example whose other block was benign.
- **A subdirectory diff scan being the severe form of the path bug.** It is real
  (fixed above) but reaches only direct CLI use: `action.yml` never passes `path`
  when `diff` is set, so the Action always targets `.`. The severe form is the
  gitconfig one. Note the ordering dependency this creates — fixing `action.yml`
  to honour `path` would expose the subdirectory path bug to CI, so that fix must
  come after this one, not before.

## [0.3.1] - 2026-07-28

Chrome-only fix. **Engine stays at `0.3.0`** — nothing about detection changed,
which is what the two version axes are for.

### Fixed

- **The Chrome extension shipped a blank icon.** Every published build so far,
  `v0.3.0` included, carried four 68-byte **1×1 placeholder PNGs**: the build
  generates placeholders when `extensions/chrome/public/icons/` is empty, and
  that directory had never existed in the repository. The real set is now
  generated by `extensions/chrome/gen-icons.mjs` from the VS Code extension's
  icon, so all four channels carry one mark, and it is reproducible rather than
  pasted-in binaries. Two treatments, chosen by looking at magnified renders:
  128/48 use the artwork with its corners re-cut as **alpha** (the source is RGB
  with the corners flattened to black, which reads as a black-cornered box on a
  light toolbar), and 32/16 use a simplified shield silhouette — below ~48px the
  `< >` brackets and the pulse line turn into noise. Zero dependencies: PNG
  decode/encode over `node:zlib`, no image library.

## [0.3.0] - 2026-07-28

Two detection layers land at once, on two deliberately separate version axes:
single-file **security design smells** and **AI-supply-chain** rules move the
engine (`0.2.1` → `0.3.0`), and a new opt-in **cross-file analysis** package
reports its own axis (`engineVersions["analysis-graph"] = 0.3.0-alpha.1`) so a
scan that never asked for it is unaffected.

> **Note on 0.2.1.** The entry below it records the embedded layer as engine
> `0.2.1`, but no `v0.2.1` tag or published package was ever cut — the tool
> version stayed at `0.2.0`. `v0.3.0` is therefore the first *released artifact*
> that carries the C/C++/Arduino rules as well. Upgrading from `v0.2.0` gets both
> releases' worth of new findings.

### Added — cross-file analysis (`@vibeguard/analysis-graph`, phase 0.3.0-α)

- **New package `@vibeguard/analysis-graph`**, opt-in via `--include-design-smells`
  on the CLI and the `include-design-smells` input on the Action. Off by default:
  it reads every source file in the tree rather than one at a time, which is a
  different cost profile, and turning it on by default would change the findings
  of every existing workflow without anyone asking. Ignored with `--diff` (the
  CLI says so on stderr) — cross-file analysis needs whole files, not added lines.
  It indexes **lexically**, like the rest of VibeGuard: still no `tree-sitter`,
  still zero runtime dependencies.
- **Four cross-file rules.** `VG-SMELL-010` (scattered authorization — the
  flagship), `VG-AISC-002` (hallucinated API/symbol, C/C++), `VG-AISC-003`
  (generated security initializer that nothing ever calls, C/C++), and
  `VG-RTOS-003` (cross-file ISR `volatile`).
- **Package separation is enforced, not just intended.** `scripts/check-packaging-invariants.mjs`
  runs in CI both before and after the build and fails if cross-file analysis code
  reaches a browser or editor bundle. The Chrome and VS Code channels stay
  single-file by construction.
- **`VG-RTOS-003` — cross-file ISR `volatile`** (#20d). The half of the ISR
  shared-variable check that `VG-RTOS-002` could not reach: the ISR writes the
  variable in one file and the reader lives in another. Runs in
  `@vibeguard/analysis-graph` behind `--include-design-smells`, and fires only
  when the declaration is unique across the project's headers, carries a builtin
  scalar type, is not `static`, and reaches the reader through a resolved quoted
  include — every one of which is a way of refusing to guess when "the same name"
  might be two different variables. `confidence` is capped at `medium`.
- **Security Context Boost for `VG-SMELL-010`** (#22d): a finding is raised to
  `high` when a check sits on a security-worded path or its handler writes to a
  data store, in addition to the existing privilege-word condition. The
  routing-layer condition from the design addendum is **detected and reported but
  deliberately not wired to severity** — measured over 1,683 repositories it held
  for 95.4% of sites, and a severity that is `high` for almost everything is not
  a severity.
### Added — single-file design smells and AI supply chain (engine 0.2.1 → 0.3.0)

Additive with respect to engine `0.2.1`: no rule that existed then changed what
it matches or at what severity.

- **Three single-file security design smells**, category `security-design-smell`,
  computed lexically inside `match()` with no AST and no cross-file state:
  `VG-SMELL-003` (long, deeply nested security method), `VG-SMELL-004` (a generic
  Utils/Helper module mixing crypto/auth/validation with unrelated concerns), and
  `VG-SMELL-012` (authorization decided by comparing a role against hardcoded
  `"admin"`/`"root"` literals in three or more places). Each favours **precision
  over recall** — the repo ships a hard `samples/safe == 0 findings` gate, so a
  design smell that fires on well-factored code is a bug, not a near-miss.
- **`VG-AISC-001` — hallucinated dependency**: an import naming a package that
  near-misses a real one, the failure mode that makes slopsquatting possible.
- **`VG-INJ-020` — prototype-polluting merge**: a `for…in` copy loop with no
  `__proto__` / `constructor` / `prototype` key guard.
- **Per-match severity escalation** (`RuleMatch.severity`): a match may come out
  above its rule's static severity on its own content (a `VG-SMELL-012` hit on an
  `admin` literal, a `VG-SMELL-003` method that does authorization), and the
  suppression severity gate then applies at the escalated value rather than the
  declared one.
- **`--fix` / `--dry-run` on the CLI** (#18), plus `scripts/fix-pr.mjs` to open the
  result as a pull request. The fixers are the deterministic, LLM-free table in
  `@vibeguard/remediation-engine`; the CLI re-reads the exact bytes the scan saw
  so a fix lands on the token the finding pointed at, and `applyFixes` refuses a
  partial apply when two edits overlap (the file is left untouched and the fixes
  are counted unfixable). Fix code is CLI-only and never enters the browser or
  editor bundles. Zero-send is unchanged: nothing here reaches the network.
- **`VG-SMELL-012` now covers Java, Go and Kotlin** (#17z-e), with positive and
  negative corpora for each. Files carrying raw-string / text-block delimiters
  the blanker does not model are skipped rather than guessed at.
- **Two new deterministic fixers** (#17z-d): `VG-INJ-020` inserts the prototype-key
  guard at the top of a `for…in` merge loop, and `VG-AISC-001` renames an import
  to the package it near-misses. Both are `needs-review`; both are fixpoints (a
  second `--fix` is a no-op). `VG-SMELL-012` deliberately gets **no** fixer.
- **`declaredPackages` veto for `VG-AISC-001`** (#17z-b): the CLI reads the
  project's lockfile and suppresses findings for packages it actually declares.
  Lockfiles only — a `package.json` entry is not evidence a package exists, and
  the case this rule exists for is an LLM writing the manifest too.
- **`VG-AISC-001` data audit** (#17z-a/c): 38 real package names recovered by
  scanning 2,683 repositories' manifests for names the rule would have called
  near-misses, iterated to closure (`KNOWN_NPM` 283→298, `KNOWN_PYPI` 199→222);
  and separately 12 curated hallucinations added from the disclosure set of
  arXiv:2605.17062, each re-checked against the npm registry.

### Changed

- **`ENGINE_VERSION` moves to `0.3.0`.** The new single-file rules, per-match
  severity and the declared-package veto are detection-behaviour changes, so the
  engine axis moves with them. It is additive — the rules that existed at engine
  `0.2.1` are untouched — so `v0.2.0` / `paper-css-v0.2.0` remain sound baselines
  for the rules they already had. The cross-file pass does **not** move this
  number; it reports `engineVersions["analysis-graph"]` instead, deliberately
  still labelled `-alpha.1` because it is an α skeleton.
- **`VG-SMELL-010` condition ③ narrowed.** `MUTATING_METHOD` no longer contains
  the bare verbs `update`, `delete`, `insert`, `destroy`, and a SQL verb pair must
  now be accompanied by SQL syntax. Measured: `createHash(…).update(…)`,
  `req.session.destroy(…)`, `responseCache.delete(…)`, `progressBar.update(1)`
  and the English sentences "You cannot delete from an empty catalogue" /
  "Update your plan to set a higher listing limit" each raised the severity
  sentinel from `medium` to `high` on their own. All six are pinned as tests.

### Fixed

- **First measured firmware footprints** (#18b). `scripts/emb-fix-footprint.mjs`
  now drives the real pipeline (`match` → `buildFix` → `applyFixes`) and sizes the
  result with `arm-none-eabi-size`, so the "after" side is the fixer's own output
  rather than a hand-typed patch. The honest-null contract is unchanged: a row
  with no toolchain stays `null` and is never rendered as `0`.

  Measured 2026-07-28 on `arm-none-eabi-gcc 13.2.1 20231009` (Debian/Ubuntu
  `15:13.2.rel1-2`) with `GNU size 2.42`, one translation unit per specimen,
  `-mcpu=cortex-m4 -Os -Wall -c`. Reproduce with
  `node scripts/emb-fix-footprint.mjs` on a machine that has the toolchain; every
  row is `null` with reason `toolchain-absent` on a machine that does not.

  | rule | fix | flash Δ | ram Δ | source of the "after" |
  |---|---|---|---|---|
  | `VG-EMB-020` | Set the debug define to 0 | −33 B | +0 B | fixer output |
  | `VG-EMB-021` | Turn the bypass flag off | +10 B | +0 B | fixer output |
  | `VG-EMB-010` | Use https for the endpoint | +1 B | +0 B | fixer output |
  | `VG-EMB-011` | Require certificate verification | +0 B | +0 B | fixer output |
  | `VG-RTOS-004` | Add `O_SYNC` for durability | +0 B | +0 B | fixer output |
  | `VG-MEM-002` | `strcpy` → `snprintf` | +15 B | +0 B | **hand-written** (no fixer) |
  | `VG-MEM-001` | `gets` → `fgets` | +12 B | +0 B | **hand-written** (no fixer) |

  A `+0 B` here is a measured zero, not a missing measurement — `VG-EMB-011`
  swaps one integer constant for another and the two encode identically. The
  Arduino-API fixes (WiFi / Serial / HTTPClient) are absent rather than zero:
  they need a board core to compile, and sizing a stub of ours would be sizing
  the stub. This table, not a JSON artefact, is the record — the script writes
  JSON only when given `--json <path>`.

## [0.2.1] - 2026-07-21

### Added — C/C++/Arduino embedded layer (engine 0.2.0 → 0.2.1)

Purely additive: no web-language verdict changes (E2=51 / E3=0 hold), so
`v0.2.0` remains the immutable baseline for the pre-embedded engine.

- **Language layer:** `.ino`/`.hh`/`.cxx`/`.ipp` now scan as C++, and a new
  N_pp preprocessor-branch normalization face (a third union term,
  `D′ = D(x) ∪ D(N(x)) ∪ D(N_pp(x))`, C/C++ only) so a dangerous construct split
  across `#ifdef` branches can be matched. Still regex-and-lexical only — **no
  `tree-sitter` or other parser dependency**; `analyzer-core` and `rules` keep
  zero external runtime deps.
- **19 new rules:** `VG-MEM-001..005` (memory: `gets`/`strcpy`/`memcpy`-from-`strlen`/
  same-block double-free & use-after-free), `VG-EMB-001..003/010..012/020..023/031`
  (AI-generated embedded: hard-coded Wi-Fi & BLE creds, cleartext `http://`,
  `setInsecure()`, BLE Just Works, `#define DEBUG 1`, auth-bypass flag, credential
  to serial, "remove before production" comment, use-before-`begin()`), and
  `VG-RTOS-001/002/004` (forbidden call in an ISR body, shared ISR variable
  missing `volatile`, `O_DIRECT` without `O_SYNC`). A lexical `extractBlockAfter`
  helper extracts ISR/`setup()` bodies without a parser.
- **`samples/embedded/{vulnerable,safe}`** with its own CI gate (safe = 0,
  vulnerable ≥ 18) and a per-rule coverage pin — a separate count from the web
  samples.
- **Deterministic autofix** (`@vibeguard/remediation-engine`): a `fixers` table
  (`#define DEBUG 1`→`0`, TLS-verify constant, `http`→`https`, add `O_SYNC`),
  LLM-free, with overlap-rejecting `applyFixes`. Plus an honest-null firmware
  footprint measurement (`footprint.ts`) that reports "not measured" when the
  arm toolchain is absent rather than a fabricated zero.
- Rules intentionally **not** implemented (a lexical scanner cannot decide them)
  are listed in the README rule catalogue.

## [0.2.0] - 2026-07-20

> **Upgrading from 0.1.x:** one change can make a previously green CI start
> failing. A `vibeguard:disable` pragma with no rule IDs, or a `.vibeguardrc.json`
> `suppress` entry with no `rules`, no longer silences `critical`, `high` or
> `medium` findings — those findings come back, and a `--fail-on` gate at or above
> `medium` fails on them.
>
> The migration is mechanical and the tool prints it. Each returning finding now
> says which suppression was refused and the exact line to write instead:
>
> ```
> CRITICAL  Use of eval()  [VG-INJ-004] (confidence: high)
>   at app.js:2:11
>   note: a wildcard `vibeguard:disable-file` with no rule IDs does not apply to critical findings.
>         To accept this one, name it: `vibeguard:disable-next-line VG-INJ-004`.
> ```
>
> Naming the rule keeps working at every severity, so an accepted finding stays
> accepted — it just has to say which finding it accepted. `low` and `info` are
> unaffected: wildcards still apply to them. The VS Code quick-fix already emits
> the named form, so nothing changes for that path.

### Changed
- **`ENGINE_VERSION` moves to `0.2.0`**, releasing a deliberate hold. The engine
  version is a separate axis from the released tool version (`0.1.3`): it moves
  only when detection behaviour changes. Several such changes shipped without a
  bump, on purpose, so that one version would name one settled engine rather than
  a sequence of partial states — the accepted cost being that `0.1.0` did not
  satisfy the "same engine ⇒ identical verdicts" contract for that period. That
  debt is discharged here. `0.2.0` covers, in the order they landed:
  context-window confidence and its severity gate (`critical`/`high`/`medium`
  keep their declared confidence where they were previously down-ranked); the
  canonicalizer pre-pass (rules also run over normalized text, so lexically
  evaded payloads are detected — additive only); regex time and input-length
  bounds with the `degradations` channel (a scan that stopped early says so
  instead of looking clean); `confidenceAudit` on findings (values unchanged,
  schema changed); the suppression severity gate below; `match-limit` reporting;
  and the suppression tally. To compare against the engine from before this work,
  use the `paper-ses-v0.1.3` tag — the version field cannot distinguish states
  inside the hold. The tool version is unaffected and still moves per release.

### Changed (breaking)
- **A blanket suppression can no longer silence a `critical`, `high`, or
  `medium` finding.** A `vibeguard:disable-line` / `disable-next-line` /
  `disable-file` pragma that lists no rule IDs, and a `.vibeguardrc.json`
  `suppress` entry that omits `rules`, are both wildcards, and a wildcard is now
  a *utility* mechanism only: it keeps full authority over `low` and `info` and
  loses it over the severities that carry a security judgement. This closes a
  self-defence gap in which one comment anywhere in a file removed every finding
  in it — the same "utility must not overrule security" principle already
  enforced on the confidence axis, applied at the suppression enforcement point
  and derived from the same shared predicate.

  Naming the rule ID remains the escape hatch, at every severity, on both
  channels: `// vibeguard:disable-file VG-INJ-004` still works exactly as
  before, as does `"rules": ["VG-INJ-004"]` in the config. There is no flag or
  override to restore the blanket behaviour — a suppression that has to be
  written down as a specific rule is a reviewable statement, which is the point.
  `until=` and `expires` are unaffected: they decide whether an entry exists,
  not what it may cover, so an unexpired blanket entry is still a blanket entry.

  **Migration:** replace bare `disable-*` pragmas and `rules`-less config
  entries with explicit rule ID lists. Run a scan first — every finding whose
  suppression was refused is reported with a `suppressionOverridden` marker
  naming the channel and scope, so the scan output *is* the migration list.
  Every such pragma inside this repository has already been rewritten.

### Added
- **Refused suppressions are recorded rather than dropped silently.** `Finding`
  gains an optional `suppressionOverridden: { channel, scope, reason? }`. It is
  present only when a wildcard suppression matched a finding and the severity
  gate refused it — `channel` is `pragma` or `config`, `scope` is `file`,
  `line`, or `path`, and `reason` carries the refused entry's `reason=` text
  when it had one. Absence of the key is the contract for "nothing tried to
  suppress this", matching how `confidenceAudit` behaves.

- **Hitting the per-file match limit is reported for security findings.**
  `ScanDegradation` gains a third `kind`, `match-limit`. A rule stops after
  1000 matches in one file, and until now it stopped in complete silence: a file
  with 1500 `eval` calls returned exactly 1000 `critical` findings, an empty
  `degradations` array, and no way to tell that 500 more had been discarded — a
  truncated scan that read as a finished one. The cap is **not** raised or
  removed; it is what bounds an availability attack against the scanner. Only
  its effect is now visible, and only where it matters: `critical`, `high`, and
  `medium` rules report the truncation, while `low` and `info` keep the previous
  silence, since quality rules reach this cap routinely and reporting them would
  bury the signal. The split uses the same shared severity predicate as the
  suppression gate above.

  The report is aggregated to one entry per (file, rule) — never one per lost
  finding — so no crafted file can flood the channel. It states how many matches
  *were* reported and deliberately does not state how many were lost: matching
  stops at the cap, so the excess is never counted and any number would be
  invented. **Exit codes are unaffected**: `--fail-on` looks only at findings, so
  a `match-limit` degradation appears in the output without failing CI.

- **Decision: `ENGINE_VERSION` stays at `0.1.0` for this release.** Both changes
  above alter engine behaviour — a suppression that used to drop a finding may
  now keep it, and a new `degradations` kind can appear — so on their own each
  would justify a bump. It is deliberately not taken. `ENGINE_VERSION` is
  already behind by the confidence-layer severity gate, and the project's
  standing policy (recorded in `analyzer.ts` beside the constant and in
  `docs/EVALUATION.md`) is to hold the field until the engine is frozen and then
  bump once, so that a single version number denotes one settled engine rather
  than a sequence of partial states. Until then the field cannot be used to tell
  these engines apart; the `paper-ses-v0.1.3` tag is the sound baseline for any
  before/after comparison. Recording it here so the hold is a decision on the
  record and not an omission.

### Security
- **Rule patterns are bounded against catastrophic backtracking (ReDoS).** An
  audit of the shipped rule set found patterns whose match time grew
  super-linearly with input size, so a crafted file could push a single-file
  scan far past its performance budget. The affected patterns were rewritten to
  bound every variable-length whitespace and delimiter run. Detection is
  unchanged: the regression corpus reports the same findings before and after,
  and a new fixture suite pins the multi-line code shapes (Allman braces,
  wrapped argument lists, multi-line signatures) that the rewrite must keep
  matching. A CI check now scans adversarial inputs and fails if any rule
  becomes super-linear again.

### Added
- **Partial scans are reported instead of passing as clean.** `ScanResponse`
  gains `degradations`: when a ReDoS guard stops a rule early — because a file
  exceeded the regex input cap, or matching exceeded its time budget — the
  response says so, naming the file and what was skipped. This is a channel
  separate from `ruleErrors` (which means "the rule crashed and produced
  nothing"), because a degraded rule *did* run and *did* report findings, just
  not over the whole input. Surfaced in the CLI (human and markdown), in SARIF
  as a `warning`-level tool notification, in VS Code as a file-level warning
  diagnostic, and in the Chrome side panel as a banner. A scan that saw only
  part of a file no longer displays "No security issues found".
- **Confidence threshold**: the CLI takes `--min-confidence <high|medium|low>`
  and the Action takes a matching `min-confidence` input, hiding findings that
  rank below the given confidence. The threshold is applied once, before any
  format is rendered, so all four output formats agree — and because the
  exit-code check reads the same set, hidden findings no longer trip
  `--fail-on`. A build can therefore pass while lower-confidence findings
  exist; the hidden count goes to stderr, and the flag is best left unset in CI
  gates. Unset by default, so output is unchanged without it.
- **Confidence is visible in the VS Code extension**: each diagnostic ends with
  `(confidence: …)` in the Problems panel and on hover, and the findings tree
  shows it in a row's tooltip. The Chrome extension does not display it yet.
- **Context-window confidence correction**: a finding whose
  match sits inside a comment, docstring, or block comment, or on a
  test/fixture/mock path, has its `confidence` down-ranked (downgrade-only;
  `severity` is preserved). Rules now declare a *default* confidence that the
  analyzer corrects per occurrence
  (`packages/rules/src/confidence.ts`, applied at the analyzer-core chokepoint).
  The correction is **severity-gated**: `critical` and `high` findings keep their
  declared confidence in every one of those contexts (`SEVERITY_CONFIDENCE_FLOOR`).
  Down-ranking quiets triage noise; it is not a security verdict, and whoever
  writes a file also chooses where a pattern sits. The floor is clamped to the
  declared confidence, so it never *raises* one.
- **The severity gate now covers `medium`**: a `medium`-severity finding can
  still be down-ranked by context, but never below `medium` — the default
  actionable threshold. Previously `medium` was ungated, so wrapping a real
  finding in a docstring or parking it under `tests/` dropped it to `low` and out
  of a default-threshold triage view; measurement showed that path working
  essentially every time. `high → medium` still happens, so the noise reduction
  the context layer exists for survives. `low` and `info` stay ungated on
  purpose: there the false-positive reduction is worth most and the impact of
  abusing it least. As with `high`, the floor is clamped to the declared
  confidence, so the new rung cannot promote a `low`-confidence finding either.

### Changed
- **Language-aware comment detection**: `isCommentLine` now takes the language,
  so a leading `#` is only treated as a comment where `#` actually starts one.
  Previously an ES2022 private class field (`#token = "…"`), a C/C++ preprocessor
  directive, a Rust attribute or a Swift directive read as a comment line and the
  match was dropped before analysis — a silent false negative on rules up to
  `critical`. Comment detection is a per-language *allowlist*
  (`LINE_COMMENT_SPECS` in `packages/rules/src/matcher-utils.ts`): a leading
  `//`, `#`, or `--` opens a line comment only in the languages whose syntax
  uses it (`#[` is excluded for PHP8 attributes; an unknown language treats
  nothing as a comment, a fail-safe toward a false positive over a silent drop).
  It is the single source of truth for that question, consumed by both the
  comment-line predicate and the docstring/block-comment scanner.
- **Evaluation scripts**: new tracked scripts
  `scripts/e4-prdiff-eval.mjs` (PR-diff reduction scenarios) and
  `scripts/e6-extended-eval.mjs` (11 public OSS repositories, commits pinned in
  the output) join the existing `e1-consistency-eval` / `e6-confidence-eval` /
  `perf-bench` / `sast-baseline-eval` scripts. The context-window fixtures now
  live in tracked `samples/context-window/`.
- **Semgrep baseline on Windows**: `scripts/sast-baseline-eval.mjs` was run
  against Semgrep 1.165.0 (`p/default`), which now installs natively on
  Windows; `scripts/run-semgrep.sh` docs updated accordingly.

## [0.1.3] - 2026-05-28

### Fixed
- **VS Code**: `engines.vscode` raised from `^1.85.0` to `^1.120.0` to match
  the `@types/vscode@^1.120.0` dev-dependency that was bumped by Dependabot
  after `v0.1.1`. The `v0.1.2` release tag failed in CI at the VSIX
  packaging step (`vsce` refused to build the package because the type
  version exceeded the declared engine minimum); `v0.1.3` is the first
  successfully publishable release of the OK-state UX work.

## [0.1.2] - 2026-05-28

### Added
- **Unified OK-state UX**: every surface now shows an explicit "no findings"
  state (previously the VS Code panel and parts of the Chrome side panel were
  silently blank).
  - **VS Code**: empty Findings view shows a welcome message with
    `Scan Current File` / `Scan Selection` quick-actions; new status-bar item
    surfaces the active file's verdict (✓ no issues / N issues / not scanned);
    `VibeGuard: Scan File` now reports its result via a toast.
  - **Chrome**: side panel and PR-diff file groups show `✓ No security
    issues found.` instead of a muted "No findings." Same applies to history
    entries.
  - **CLI**: human-format output prints `✓ No findings.` in green when the
    scan is clean (markdown format already had `✅`).
- **Shared severity palette**: three custom color tokens (`vibeguard.ok` =
  `#2e7d32`, `vibeguard.issue` = `#856404`, `vibeguard.critical` = `#c62828`)
  align all surfaces with the project's reporting-quality color rules. The
  tokens are user-overridable via `workbench.colorCustomizations`.

## [0.1.1] - 2026-05-18

### Added
- **Rules**: framework-misconfig rules for Django, Flask, and Express
  (`VG-FW-001..003`).
- **Rules**: CRYPTO rules extended from JS/TS/Python to PHP, Ruby, Java, Go,
  and C# — same weak-algorithm / weak-RNG / weak-hash detections, more
  languages.
- **VS Code**: `VibeGuard: Export Findings (SARIF / JSON)` command — exports
  the workspace's accumulated findings to `.sarif` (v2.1.0) or `.json` via
  the standard save dialog.
- **Chrome**: `Scan PR diff` button on GitHub `/pull/<n>` Files-changed tabs.
  Walks the diff table, scans each touched file as a reconstructed
  pseudo-content, and filters to findings that overlap an added line.
- **Chrome**: scan history — the bottom **History** panel persists the most
  recent 50 scan results (summary + finding metadata only — never the full
  code) in `chrome.storage.local`.
- **CI**: tag-driven release workflow that packages the CLI tarball, VS Code
  VSIX, and Chrome zip and attaches them to the GitHub Release.
- **CI**: non-blocking performance benchmark job.

### Changed
- **VS Code**: extension renamed to `vibeguard-aicoding` (displayName
  `VibeGuard AICoding`) for the Marketplace listing. Marketplace icon added.

### Fixed
- **CLI**: `--ignore` is now honoured in diff scans; PR diff gate excludes
  `samples/` to mirror whole-repo self-scan.
- **Chrome**: side panel renderer no longer uses `innerHTML` (VG-INJ-006).
- **Rules**: rule definition files self-suppress (`vibeguard:disable-file`)
  so the analyzer doesn't flag its own pattern literals.

### Security
- Self-scan added a `vibeguard:disable-file` pragma to the Chrome
  diff-reconstruct test fixture (the AWS example key
  `AKIAIOSFODNN7EXAMPLE` was tripping VG-SEC-001 on main pushes).

## [0.1.0] - 2026-05-09

First public release.

- CLI: `@vibeguard/cli` published to npm.
- GitHub Action: `YUTAKONDO1205/VibeGuard@v0`.
- VS Code extension: `yutakondo.vibeguard-aicoding`.
- Chrome extension.
- 30 rules across injection / auth / secrets / crypto / AI-quality.
