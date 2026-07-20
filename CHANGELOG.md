<!-- vibeguard:disable-file VG-SEC-001 -->
# Changelog

All notable changes to VibeGuard across CLI / GitHub Action / VS Code extension /
Chrome extension are documented here. Per-extension changelogs live alongside
each extension (see `extensions/vscode/CHANGELOG.md`).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
