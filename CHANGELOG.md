# Changelog

All notable changes to VibeGuard across CLI / GitHub Action / VS Code extension /
Chrome extension are documented here. Per-extension changelogs live alongside
each extension (see `extensions/vscode/CHANGELOG.md`).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
