# Change Log

All notable changes to the VibeGuard VS Code extension are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.1.2] - 2026-05-28

### Added
- **Findings view welcome state** — when there are no findings, the
  `VibeGuard Findings` panel now shows `✓ No security findings.` plus
  one-click `Scan Current File` and `Scan Selection` actions, instead of a
  blank panel.
- **Status-bar item** — a new shield indicator in the right status bar
  reports the active file's verdict at a glance:
  - `VibeGuard: ✓ No issues` (green) when clean,
  - `VibeGuard: N issues` with warning/error background when findings exist,
  - `VibeGuard: –` when the file has not been scanned yet.
  Clicking it focuses the Findings view.
- **Scan-File result toast** — `VibeGuard: Scan File` now confirms its run
  with either `✓ no issues found.` or a finding count, matching the existing
  selection-scan behaviour.
- **Custom color tokens** — `vibeguard.ok` (#2e7d32), `vibeguard.issue`
  (#856404), `vibeguard.critical` (#c62828) drive the tree-view icons and
  status-bar foreground colours. Themes and
  `workbench.colorCustomizations` can override them.

## [0.1.1] - 2026-05-18

### Added
- Command `VibeGuard: Export Findings (SARIF / JSON)` — exports the workspace's
  accumulated findings to a `.sarif` (v2.1.0) or `.json` file via the standard
  save dialog. Format is chosen by file extension.

### Changed
- Bundled rule catalogue now includes the new framework-misconfig rules
  (Django/Flask/Express) and CRYPTO rules extended to PHP/Ruby/Java/Go/C#.

### Fixed
- `--ignore` is now honoured in CLI diff scans (shared bundled analyzer),
  matching whole-file scan behaviour.

## [0.1.0] - 2026-05-09

First public release on the Visual Studio Marketplace.

### Added
- On-save scan (`fast` mode by default; configurable via `vibeguard.scanOnSaveMode`).
- Manual scan command `VibeGuard: Scan File` (always `standard` mode).
- Manual scan command `VibeGuard: Scan Selection` (also wired into the editor
  right-click menu when text is selected).
- VS Code Diagnostics surface with severity → Error / Warning / Information
  mapping derived from the analyzer's `severity` field.
- Findings tree view in the Explorer side bar (`VibeGuard Findings`).
- Settings:
  - `vibeguard.scanOnSave` — toggle save-time scanning (default: on).
  - `vibeguard.scanOnSaveMode` — `fast` | `standard` (default: `fast`).
- Bundled rule catalogue (30 rules across injection / auth / secrets / crypto /
  AI-quality), shared with the VibeGuard CLI and GitHub Action so verdicts stay
  consistent across editor, browser, and CI.

### Notes
- All analysis runs locally. The extension makes no network requests.
- Workspace-wide diff scan is tracked for an upcoming release.
