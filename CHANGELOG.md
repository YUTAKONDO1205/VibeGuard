<!-- vibeguard:disable-file VG-SEC-001 -->
# Changelog

All notable changes to VibeGuard across CLI / GitHub Action / VS Code extension /
Chrome extension are documented here. Per-extension changelogs live alongside
each extension (see `extensions/vscode/CHANGELOG.md`).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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
