# VibeGuard

[![CI](https://github.com/YUTAKONDO1205/VibeGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/YUTAKONDO1205/VibeGuard/actions/workflows/ci.yml)
[![Security Scan](https://github.com/YUTAKONDO1205/VibeGuard/actions/workflows/security-scan.yml/badge.svg)](https://github.com/YUTAKONDO1205/VibeGuard/actions/workflows/security-scan.yml)
[![GitHub Marketplace](https://img.shields.io/badge/GitHub%20Action-Vibe--Guard--AICoding-blue?logo=github)](https://github.com/marketplace/actions/vibe-guard-aicoding)
[![VS Code Marketplace](https://img.shields.io/badge/VS%20Code-vibeguard--aicoding-007ACC?logo=visualstudiocode)](https://marketplace.visualstudio.com/items?itemName=yutakondo.vibeguard-aicoding)
[![Open VSX](https://img.shields.io/badge/Open%20VSX-vibeguard--aicoding-c160ef?logo=eclipseide)](https://open-vsx.org/extension/yutakondo/vibeguard-aicoding)
[![Chrome Web Store](https://img.shields.io/badge/Chrome%20Web%20Store-VibeGuard-4285F4?logo=googlechrome&logoColor=white)](https://chromewebstore.google.com/detail/ggdiodcjmdnkhncnpafcjokgonhmhbdf)

Author : Kondo Yuta（近藤 悠太）

VibeGuard is a security scanner for AI-generated code. It catches the bugs that "looks fine, ships fine" code tends to hide: missing input checks, hard-coded passwords, skipped login checks, exceptions silently caught, and so on.

You can run it at three places, and you'll get the same answer at every one of them:

- **While you write** — VS Code extension. Save the file, see findings inline.
- **While you read** — Chrome extension. Scan code snippets on any web page.
- **Before you merge** — CLI and GitHub Action. Block a PR when something risky lands.

The analysis engine is shared across all three, so a finding looks the same in your editor, in your browser, and in the PR comment.

For more detail: the design document is in [docs/DESIGN.ja.md](docs/DESIGN.ja.md) (Japanese). The privacy policy is in [PRIVACY.md](PRIVACY.md) — VibeGuard never sends your code anywhere.

## Install

VibeGuard is published on four channels. All of them run the same analysis engine, so the verdict on a given snippet is identical across editor, browser, and CI.

| Channel | Where to get it | Best for |
|---|---|---|
| **VS Code Marketplace** | [marketplace.visualstudio.com/items?itemName=yutakondo.vibeguard-aicoding](https://marketplace.visualstudio.com/items?itemName=yutakondo.vibeguard-aicoding) | Inline diagnostics on save while you write code in VS Code. Publisher `yutakondo`, extension `vibeguard-aicoding`. |
| **Open VSX Registry** | [open-vsx.org/extension/yutakondo/vibeguard-aicoding](https://open-vsx.org/extension/yutakondo/vibeguard-aicoding) | Same VS Code extension, mirrored for VSCodium / Cursor / Gitpod / code-server and other editors that pull from Open VSX instead of the Microsoft Marketplace. |
| **Chrome Web Store** | [chromewebstore.google.com/detail/ggdiodcjmdnkhncnpafcjokgonhmhbdf](https://chromewebstore.google.com/detail/ggdiodcjmdnkhncnpafcjokgonhmhbdf) | Scan code you see in the browser — GitHub PRs, Stack Overflow answers, blog posts, chat windows. Side Panel + right-click "Scan with VibeGuard". 100% local analysis. |
| **GitHub Marketplace (Action)** | [github.com/marketplace/actions/vibe-guard-aicoding](https://github.com/marketplace/actions/vibe-guard-aicoding) | Block risky PRs in CI. `uses: YUTAKONDO1205/VibeGuard@v0` — see the [Reusable Action](#reusable-action-github-marketplace) section for inputs / outputs. |

Source of truth for all four channels: this repository (MIT-licensed). The CLI under [`apps/cli`](apps/cli) is the same binary the Action wraps, and the analyzer-core under [`packages/analyzer-core`](packages/analyzer-core) is what powers both extensions.

## Monorepo layout

```text
VibeGuard/
├─ AGENTS.md                  # Project-wide rules for AI implementation agents
├─ docs/                     # Design docs (DESIGN.ja.md, EVALUATION.md, …)
├─ apps/
│  └─ cli/                    # CLI for local + CI use
├─ packages/
│  ├─ analyzer-core/          # Shared analysis engine
│  ├─ rules/                  # Rule definitions and execution logic
│  ├─ findings-schema/        # Canonical schema for findings
│  ├─ remediation-engine/     # Remediation generator
│  └─ sarif-adapter/          # SARIF v2.1.0 converter
├─ extensions/
│  ├─ vscode/                 # VS Code extension
│  └─ chrome/                 # Chrome extension (Manifest V3)
├─ samples/
│  ├─ vulnerable/             # Code that should be flagged (CI quality gate)
│  └─ safe/                   # Code that must NOT be flagged
└─ test_problem/              # Single-file demo that walks every rule family in one Python file
```

Future additions: `packages/scanner-semgrep` (deep mode), more language rule packs.

`samples/` and `test_problem/` look similar but serve different audiences. `samples/` is split per-rule and is consumed by the `samples` CI job as a regression / false-positive gate. [`test_problem/`](test_problem) is the opposite shape — one Python file that intentionally trips most rule families at once, intended for humans who want to see VibeGuard react without setting up a fixture tree. Editing `test_problem/` does **not** affect the CI gate. See [test_problem/README.md](test_problem/README.md) for the mapping of each section to its rule ID.

## Setup

Requires Node.js 18+.

```bash
npm install
npm run build
```

## CLI usage

> The CLI is not published to npm, and is not installable on its own. Use it
> either by cloning this repo (`npm install && npm run build`, then
> `node apps/cli/dist/index.js …` as below), or — for CI — via the
> [GitHub Action](#reusable-action-github-marketplace), which wraps the same CLI
> and is the supported path for automation.
>
> The `vibeguard-cli-<version>.tgz` attached to each release is a **source
> archive**, not a self-contained package: it declares `@vibeguard/*`
> dependencies that only exist inside this workspace, so `npm install` on it
> alone fails to resolve them. Making that tarball independently installable
> needs the CLI to be bundled the way the two extensions already are; until then,
> clone the repo.

```bash
# Scan a directory (human-readable output)
node apps/cli/dist/index.js ./samples/vulnerable

# Or try the bundled single-file demo: one Python file that trips every rule family
node apps/cli/dist/index.js ./test_problem/test_problem.py

# Emit SARIF so GitHub Code Scanning can ingest it
node apps/cli/dist/index.js ./src --format sarif --out report.sarif

# Exit non-zero only when something critical is found
node apps/cli/dist/index.js suspicious.py --fail-on critical

# Scan only the lines added in a PR (uses `git diff <range> --unified=0` internally)
node apps/cli/dist/index.js --diff origin/main...HEAD --format markdown
```

Main options:

| Option | Description |
|---|---|
| `--format <human\|json\|sarif\|markdown>` | Output format (default: `human`). `markdown` is meant for PR comments. |
| `--out <file>` | Write the report to a file instead of stdout. |
| `--mode <fast\|standard\|deep>` | Scan depth (default: `standard`). |
| `--fail-on <level>` | Exit non-zero when a finding of this severity (or higher) appears. |
| `--min-confidence <high\|medium\|low>` | Hide findings below this confidence (default: show all). Hidden findings are excluded from `--fail-on` too, so a build can pass even though lower-confidence findings exist — the hidden count is printed to stderr. Best left unset in CI gates; intended for local triage. |
| `--ignore <name>` | Extra directory name to skip (repeatable). |
| `--diff <range>` | Scan only lines added in `git diff <range> --unified=0`. |
| `--known-only` | Scan only files with known-language extensions. |
| `--no-remediation` | Skip remediation generation. |

## Tests

```bash
npm test
```

Runs every package's `*.test.ts` under vitest.

## Performance benchmark

```bash
npm run build
npm run bench           # human-readable table
npm run bench -- --json # machine-readable for CI artifacts
```

The benchmark exercises three representative workloads (single-file fast scan, samples directory, repo-wide scan) and prints a Markdown table comparing the median of 3 runs against the design targets in [docs/DESIGN.ja.md](docs/DESIGN.ja.md) §11.1. The benchmark exits non-zero when a workload exceeds 2× its target — the 2× headroom keeps the gate quiet on noisy CI VMs while still catching real regressions. A non-blocking `perf-bench` job uploads the JSON to a CI artifact on every push.

## GitHub Actions

The repository ships two workflows:

| Workflow | Role |
|---|---|
| [`.github/workflows/ci.yml`](.github/workflows/ci.yml) | The base gate: `npm ci` → `npm run build` → `npm test`. |
| [`.github/workflows/security-scan.yml`](.github/workflows/security-scan.yml) | Three jobs — self-scan, samples, pr-diff-scan. Self-scan uploads SARIF to Code Scanning and posts a sticky PR comment; samples is the rule-correctness gate; pr-diff-scan posts a separate comment for only the lines added in the PR. |

### self-scan job
Scans VibeGuard itself with `--fail-on never`, then surfaces the result as SARIF in the Security tab and as Markdown in a sticky PR comment. **It informs but never blocks the build**: rule definition files ([packages/rules/src/rules/](packages/rules/src/rules/)) legitimately contain literals like `eval()` and dummy credentials as regex examples, and test files include intentionally vulnerable code, so requiring 0 findings on the source tree is structurally impossible.

### samples job
The real quality gate for rule correctness.

- [`samples/safe`](samples/safe) → must produce 0 findings (false-positive guard).
- [`samples/vulnerable`](samples/vulnerable) → must produce ≥ 15 findings (regression guard).
- [`samples/embedded/safe`](samples/embedded/safe) → must produce 0 findings, and [`samples/embedded/vulnerable`](samples/embedded/vulnerable) → must produce ≥ 18 findings. This is a **separate count** from the web samples above (the embedded rules are language-gated to `c`/`cpp`, so the two corpora cannot perturb each other); exact per-rule coverage is pinned in `embedded-samples.test.ts`.

### pr-diff-scan job
Scans only the added lines in a PR and posts a dedicated sticky comment (header `vibeguard-diff`). Fails on `high` or above. The job runs `git diff --unified=0 origin/<base_ref>...HEAD`, reads each changed file from the working tree, runs a full scan, then keeps only the findings that overlap an added line.

### Note
PRs from forks don't get the comment posted (the `pull-requests: write` permission isn't granted to fork workflows). After the first push to `main`, results are aggregated in the GitHub Security tab.

## Reusable Action (GitHub Marketplace)

[`action.yml`](action.yml) at the repository root lets other repos call VibeGuard from a workflow with a single step.

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0      # required when using diff scan
- uses: YUTAKONDO1205/VibeGuard@v0
  with:
    path: .
    mode: standard
    format: sarif
    out: vibeguard.sarif
    fail-on: high
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: vibeguard.sarif
    category: vibeguard
```

PR diff-only scan example:

```yaml
- uses: YUTAKONDO1205/VibeGuard@v0
  with:
    diff: origin/${{ github.base_ref }}...HEAD
    format: markdown
    out: report.md
    fail-on: high
```

Main inputs:

| input | default | description |
|---|---|---|
| `path` | `.` | Scan target (relative to the consumer repo root). |
| `mode` | `standard` | `fast` / `standard` / `deep`. |
| `format` | `sarif` | `human` / `json` / `sarif` / `markdown`. |
| `fail-on` | `high` | `critical` / `high` / `medium` / `low` / `never`. |
| `min-confidence` | `''` | Hide findings below this confidence (`high` / `medium` / `low`). Hidden findings are excluded from `fail-on` too, so the job can pass even though lower-confidence findings exist. Best left unset in CI gates. |
| `out` | `''` | Report output file (stdout if empty). |
| `diff` | `''` | Scan only lines added in `git diff <range>`. |
| `ignore` | `''` | Comma-separated extra ignore directory names. |
| `known-only` | `false` | Scan only known-language extensions. |
| `no-remediation` | `false` | Skip remediation generation. |
| `node-version` | `20` | Node.js version used for the scan. |

outputs:

| output | description |
|---|---|
| `exit-code` | The CLI's exit code (non-zero when `fail-on` is tripped). |
| `output-file` | Absolute path of `out`, when set. |

Marketplace publishing is documented in [`docs/runbooks/publish-action-to-marketplace.md`](docs/runbooks/publish-action-to-marketplace.md). End-to-end verification runs in [`.github/workflows/action-smoke-test.yml`](.github/workflows/action-smoke-test.yml) using `uses: ./`.

## VS Code extension

`extensions/vscode/` hosts the extension. Press F5 to launch an Extension Host for development.

| Feature | How to invoke |
|---|---|
| Scan on save | On by default. Toggle with `vibeguard.scanOnSave`; pick `fast` / `standard` via `vibeguard.scanOnSaveMode`. |
| Manual scan | Command Palette → `VibeGuard: Scan File`. |
| Selection scan | Editor context menu → `VibeGuard: Scan Selection` (full-file scan, findings filtered to the selection). |
| Diagnostics | Severities map to Error / Warning / Information. |
| Code Action | Light bulb → `suppress <ruleId> on this line` (inserts a `vibeguard:disable-next-line` comment) / `show remediation`. |
| Findings sidebar | `VibeGuard Findings` view in the Explorer. File → finding hierarchy; click to jump to the line. |
| Export findings | Command Palette → `VibeGuard: Export Findings (SARIF / JSON)`. Format chosen by file extension in the save dialog. |

## Rule catalogue

66 rules at the moment, across 10 languages (including a C/C++/Arduino embedded layer). The ID prefix groups rules by source file; the `category` field is a separate, risk-oriented axis.

| Prefix | Coverage | Examples |
|---|---|---|
| `VG-INJ-NNN` | Injection | eval / SQL concatenation / innerHTML / pickle, etc. |
| `VG-AUTH-NNN` | Auth / TLS / placeholder auth | DEBUG bypass / `verify=False` / `dummy_token`. |
| `VG-SEC-NNN` | Hardcoded secrets | AWS keys / PEM / GitHub PAT / high-entropy strings. |
| `VG-CRYPTO-NNN` | Crypto | MD5/SHA1 / `Math.random` / `http://`. |
| `VG-QUAL-001..004` | General quality (CORS / swallowed exceptions / open redirect, etc.) | |
| `VG-QUAL-005..010` | **AI-trace heuristics** (`category: ai-quality`) | Stub implementations / placeholder emails / mock data / `debug=true` / "for now" comments / empty validators. |
| `VG-FW-NNN` | Framework misconfiguration | Django `DEBUG=True` / Flask `app.run(debug=True)` / CORS wildcard. |
| `VG-MEM-NNN` | **C/C++ memory** (`category: memory`) | `gets` / `strcpy`/`sprintf` / `memcpy` sized from `strlen` / same-block double-free & use-after-free. |
| `VG-EMB-NNN` | **AI-generated embedded** (secrets / crypto / ai-quality) | Hard-coded Wi-Fi & BLE creds / cleartext `http://` / `setInsecure()` / `#define DEBUG 1` / auth-bypass flag / credential to serial / "remove before production" / use-before-`begin()`. |
| `VG-RTOS-NNN` | **Interrupt / RTOS** (`category: concurrency`) | Forbidden call inside an ISR body / shared ISR variable missing `volatile` / `O_DIRECT` without `O_SYNC`. |

VG-QUAL-005..010 target the "compiles cleanly but shouldn't ship" patterns that AI-generated code produces. They run at `severity=medium` and `confidence=low~medium` because heuristics are inherently noisier than syntactic rules.

The C/C++/Arduino layer (`VG-MEM`/`VG-EMB`/`VG-RTOS`, plus the `.ino`/`.hh`/`.cxx`/`.ipp` extensions and a preprocessor-branch normalization face) is regex-and-lexical only — **no `tree-sitter` or other parser dependency** — so it ships to all four channels. `VG-EMB` is the intended focus: valid C that is a security problem because of *how AI writes firmware* (a hard-coded SSID is legal C, so existing embedded static analyzers stay silent). `VG-MEM` is a deliberate floor with no novelty (flawfinder/cppcheck territory).

**Deliberately NOT detected in the embedded layer** (kept out because a lexical scanner cannot decide them without a parser or dataflow, and forcing them would manufacture false positives):
- *Memory (17d):* destination-size-checked `memcpy`, use-after-free / double-free across any control flow, integer overflow before `malloc`, constant array-index out of bounds.
- *AI-embedded (17e):* CRC misused as an integrity/authenticity check (intent, not syntax), entropy/content-based "does this flash string look secret", cross-function/cross-file init order, power-management sequencing, hard-coded SD paths, and `digitalWrite` before `pinMode` (indistinguishable from the documented glitch-free-init idiom).
- *RTOS (17f):* `xTaskCreate` stack-size magic number (unit is words on vanilla FreeRTOS, bytes on ESP-IDF — any threshold is wrong somewhere), hard-coded task priorities, and mutex acquire-order / priority inversion (needs a cross-function lock graph).

Each rule declares a *default* confidence, and the analyzer then applies a **context-window confidence correction**: a match that sits inside a comment, docstring, or block comment, or on a test/fixture/mock path, has its confidence down-ranked (never up-ranked, and severity is untouched), so a pattern shown inside a docstring is reported at lower confidence than a live one.

The correction is **severity-gated**: a finding whose severity is `critical` or `high` keeps its declared confidence even in those contexts, and one whose severity is `medium` may be down-ranked but never below `medium` — the default actionable threshold — so a real finding cannot be buried by wrapping it in a docstring. `low` and `info` take the full down-rank, where the noise reduction is worth most and the abuse impact least. Down-ranking exists to quiet triage noise — it is a utility mechanism, not a security verdict — and anyone who can write the file can also choose where a pattern sits, so a context that lowers confidence must never lower it for a finding that matters. See `SEVERITY_CONFIDENCE_FLOOR` in `packages/rules/src/confidence.ts`, and run `node scripts/e6-confidence-eval.mjs` for a worked demonstration that reports both arms (un-gated and gated) side by side.

## Chrome extension

`extensions/chrome/` is a minimal Manifest V3 extension (Phase 3). It uses the analyzer-core `./browser` sub-path so the bundle contains no `node:fs` / `node:path`, and runs the analyzer from the Side Panel.

| Feature | How to invoke |
|---|---|
| Show Side Panel | Click the VibeGuard icon in the toolbar. |
| Paste-scan | Paste code into the Side Panel textarea and press **Scan**. |
| Extract from page | Side Panel → **Extract from page** collects `<pre><code>` blocks from the active tab and scans them. |
| Scan PR diff | On a GitHub `/pull/<n>` (Files-changed) tab, Side Panel → **Scan PR diff** walks the diff table, scans each touched file as a reconstructed pseudo-content, and reports findings grouped by file. Findings are filtered to those that overlap an *added* line. Re-running the button rescans the current page. |
| Selection scan | Select text on any page → context menu → `Scan with VibeGuard` (opens the Side Panel and scans immediately). |
| History | The bottom **History** section persists the most recent 50 scan results (summary + finding metadata only — never the full code) in `chrome.storage.local`. Click **Clear** to wipe it. |
| Language picker | `auto-detect` or js / ts / python / go / java / ruby / php / csharp. |

Build:

```bash
npm run build -w vibeguard-chrome
```

Point Chrome at `extensions/chrome/dist/` via `chrome://extensions` → **Load unpacked**. `npm run watch -w vibeguard-chrome` keeps esbuild rebuilding on save.

## Development phases

| Phase | Scope |
|---|---|
| 1 (MVP) | analyzer-core, 20–30 base rules, findings-schema, SARIF output, CLI, minimal VS Code extension. |
| 2 | GitHub Actions, PR comments, fail gates, CodeQL co-existence. |
| 3 | Chrome extension (code extraction / Side Panel / PR diff scan). |
| 4 | Smarter AI-driven remediation, org policies, more languages, dashboards. |

Currently around the Phase 1–3 footprint, with Phase 2 (Actions / PR comments) and parts of Phase 3 (Chrome extension scaffold) in place.

## Versioning

VibeGuard tracks **two independent version numbers**. Keeping them separate is intentional — reference the right one when reporting issues.

| Version | Where | Bumps when | Current |
| --- | --- | --- | --- |
| **Tool version** | `package.json` of each channel; CLI `--version`; SARIF `tool.version` | Any release of the published artifact — packaging, UX, docs, or detection changes. | `0.1.3` |
| **Engine version** | `ENGINE_VERSION` in [`analyzer-core`](packages/analyzer-core); every scan result and SARIF report as `engineVersions.core` | Only when **detection behavior** changes (rules, analysis, finding schema). | `0.2.1` |

The CLI prints both, e.g. `vibeguard 0.1.3 (engine 0.2.1)`. The tool version is read from `package.json` at runtime, so it always matches the published package. The engine stayed at `0.1.0` while the tool advanced to `0.1.3`, because those releases (vsce metadata fix, OK-state UX, license) did not change what VibeGuard detects, and it was then held there deliberately through a round of detection work so that one version would name one settled engine rather than several successive ones. `0.2.0` released that hold: context-window confidence and its severity gate, the canonicalizer pre-pass, regex time/length bounds with `degradations`, `confidenceAudit`, the suppression severity gate, `match-limit` reporting, and the suppression tally. `0.2.1` adds the C/C++/Arduino embedded layer (VG-MEM/VG-EMB/VG-RTOS, the `.ino`/`.hh`/`.cxx`/`.ipp` extensions, and the N_pp preprocessor face) — purely additive, so web-language verdicts are unchanged. See [CHANGELOG.md](CHANGELOG.md) for what each one changes. To compare against the engine from before that work, use the `paper-ses-v0.1.3` (pre-hold) or `v0.2.0` (pre-embedded) tags.

**Rule of thumb:** compare results across two runs by **engine version** (same engine ⇒ identical verdicts); report which build you installed by **tool version**.

## Implementation conventions (agent harness)

This repo is built on the assumption that AI implementation agents do the implementation in multi-agent runs. Responsibilities are split into three roles:

- **Planner** — Decomposes ambiguous requirements into implementable tasks.
- **Generator** — Implements exactly one task with the smallest viable change.
- **Evaluator** — Runs tests, static analysis, and (when needed) browser verification, and reports PASS / PASS WITH GAPS / FAIL.

Any non-trivial feature must go through Planner, and each generated task is gated by Evaluator. See [AGENTS.md](AGENTS.md) for the full protocol.

## License

[MIT](LICENSE) © 2026 KONDO YUTA
