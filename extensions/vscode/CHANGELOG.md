# Change Log

All notable changes to the VibeGuard VS Code extension are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.3.5] - 2026-08-06

No change to this extension's own code. The analyzer engine moves `0.3.1` → `0.3.2`, so a
**C or C++ file may report two findings it did not report before**: `VG-MEM-006` (a secret
buffer cleared with a `memset` the compiler is allowed to delete) and `VG-AUTH-008`
(authorization decided by an `assert`, which `NDEBUG` removes). Files in every other
language are unaffected — a file that was clean on save before is clean on save now.

Both rules are medium/high severity with medium confidence, so on the editor's default
`fast` mode they surface the same way any other C/C++ finding does.

## [0.3.4] - 2026-08-04

No change to this extension's own code, and none to what it reports on save. Analyzer engine is
unchanged at `0.3.1`, so a file that was clean on save before is clean on save now.

0.3.4 is mostly a remediation-side release: it narrows what the CLI's `--fix` will write and
makes `--fail-on` apply in fix mode. Neither is reachable from the editor — this extension's
Quick Fixes insert a `vibeguard:disable-line` comment or display a finding's remediation text,
and it never applies a deterministic fixer.

**One thing you will see**, because the extension shows remediation prose: `VG-EMB-020` no
longer suggests `#define DEBUG 0` as a paste-ready fix. Setting the flag to `0` only disables a
debug path that reads its VALUE; where the code tests whether it is DEFINED, a zero is still a
definition and the path still compiles. The remediation now says so and leads with dropping the
define from release builds instead.

The cross-file analysis that 0.3.4 promotes to beta (`0.3.0-alpha.1` → `0.3.0-beta.3`, four
rules → eleven) is **not** part of the on-save scan; it is opt-in behind the CLI's
`--include-design-smells`. If your editor and your CI disagree about a design smell, that flag
is why, and it is the intended difference rather than drift.

## [0.3.3] - 2026-07-29

No change to this extension. The repository releases every channel under one tool version, and
0.3.3 fixes the **Chrome** extension manifest version that blocked its 0.3.2 submission.
This build is 0.3.2 with the version number moved. Analyzer engine is unchanged at `0.3.1`.

## [0.3.2] - 2026-07-29

Analyzer engine moves to `0.3.1`, so **what this extension reports changes** —
see the root CHANGELOG for the full list. Two fixes are specific to the editor:

### Fixed

- **The suppression Quick Fix no longer corrupts the file it suppresses in.**
  Comment syntax was `#` for nine languages and `//` for everything else, and
  the provider is registered on every file type. Several rules are
  language-agnostic (`VG-CRYPTO-003` matches an `http://` URL in any text), so
  findings do appear in JSON, CSS, HTML and PowerShell — and accepting the fix in
  a `.json` file left a document `JSON.parse` rejects. Comment style is now
  per-language, falling back to a block comment where there is no line comment
  (CSS, HTML) and withholding the fix entirely for strict JSON, which has no
  comment syntax at all.
- **A rule that crashed used to leave the file green.** `ruleErrors` was never
  read, so a rule dying contributed no findings and looked exactly like a rule
  finding nothing. Each broken rule now raises a line-1 Warning, through the same
  channel already used for partial scans and for the same stated reason: an
  incomplete scan must not look like a clean one.

### Changed

- The README's rule count said **30**; there are **71**.

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
