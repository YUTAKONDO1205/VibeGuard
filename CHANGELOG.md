# Changelog

All notable changes to VibeGuard across CLI / GitHub Action / VS Code extension /
Chrome extension are documented here. Per-extension changelogs live alongside
each extension (see `extensions/vscode/CHANGELOG.md`).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **Context-window confidence correction** in `analyzer-core`: a finding whose
  match sits inside a comment, docstring, or block comment, or on a
  test/fixture/mock path, has its `confidence` down-ranked (downgrade-only;
  `severity` is preserved). Rules now declare a *default* confidence that the
  analyzer corrects per occurrence
  (`packages/analyzer-core/src/confidence.ts`).
- **Paper-evaluation reproduction kit**: `docs/EVALUATION.md` maps every number
  in the SES2026 paper to a tracked command; new tracked scripts
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
