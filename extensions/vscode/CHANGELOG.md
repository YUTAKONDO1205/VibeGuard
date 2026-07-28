# Change Log

All notable changes to the VibeGuard VS Code extension are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.3.1] - 2026-07-28

No change to this extension. The repository releases every channel under one
tool version, and `0.3.1` fixes the **Chrome** extension's icon; this build is
`0.3.0` with the version number moved. Analyzer engine is unchanged at `0.3.0`.

## [0.3.0] - 2026-07-28

> The extension version jumps `0.1.3` → `0.3.0` in this file because the `0.2.0`
> release was recorded only in the repository-level
> [CHANGELOG.md](../../CHANGELOG.md), not here. Everything in `0.2.0` is in this
> build too.

### Added
- Each finding's confidence is now visible: diagnostics end with
  `(confidence: …)` in the Problems panel and on hover, and the findings tree
  shows it in the row's tooltip. Confidence reflects how sure the analyzer is
  that a match is real — it does not change a finding's severity, and nothing
  is filtered out of the view.
- New rules from analyzer engine `0.3.0`, which the extension picks up without
  any UI change: the single-file security design smells (`VG-SMELL-003` /
  `VG-SMELL-004` / `VG-SMELL-012`), the hallucinated-dependency rule
  (`VG-AISC-001`), and prototype-polluting merges (`VG-INJ-020`). Plus the
  C/C++/Arduino embedded rules from engine `0.2.1` (`VG-MEM` / `VG-EMB` /
  `VG-RTOS`), which never reached a published build before now.
- A match can now escalate its own severity (e.g. a role check against a literal
  `"admin"`), so the same rule may show as a warning in one file and an error in
  another.

### Not included
- The cross-file analysis added in `0.3.0` (`--include-design-smells`,
  `VG-SMELL-010` and friends) is **CLI / GitHub Action only**. The extension scans
  the file in front of you and stays single-file by design; a CI packaging check
  fails the build if cross-file code ever reaches this bundle.

## [0.1.3] - 2026-05-28

### Changed
- `engines.vscode` raised from `^1.85.0` to `^1.120.0` to match the
  `@types/vscode@^1.120.0` dev-dependency. Users on older VS Code releases
  should stay on `v0.1.1` until they can update VS Code.

### Fixed
- Marketplace packaging — `v0.1.2` failed to publish because `vsce package`
  rejected the engines/types mismatch. `v0.1.3` is the first successfully
  shipped build of the v0.1.2 OK-state UX work (Findings welcome view,
  status-bar indicator, scan-file toast, severity colour tokens).

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
