# VibeGuard

[![CI](https://github.com/YUTAKONDO1205/VibeGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/YUTAKONDO1205/VibeGuard/actions/workflows/ci.yml)
[![Security Scan](https://github.com/YUTAKONDO1205/VibeGuard/actions/workflows/security-scan.yml/badge.svg)](https://github.com/YUTAKONDO1205/VibeGuard/actions/workflows/security-scan.yml)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-Vibe--Guard--AICoding-blue?logo=github)](https://github.com/marketplace/actions/vibe-guard-aicoding)

Author: Kondo Yuta

VibeGuard is a security scanner for AI-generated code. It catches the bugs that "looks fine, ships fine" code tends to hide: missing input checks, hard-coded passwords, skipped login checks, exceptions silently caught, and so on.

You can run it at three places, and you'll get the same answer at every one of them:

- **While you write** — VS Code extension. Save the file, see findings inline.
- **While you read** — Chrome extension. Scan code snippets on any web page.
- **Before you merge** — CLI and GitHub Action. Block a PR when something risky lands.

The analysis engine is shared across all three, so a finding looks the same in your editor, in your browser, and in the PR comment.

For more detail: the design document is in [DESIGN.ja.md](DESIGN.ja.md) (Japanese). The privacy policy is in [PRIVACY.md](PRIVACY.md) — VibeGuard never sends your code anywhere.

## Monorepo layout

```text
vibeguard-codex/
├─ AGENTS.md                  # Project-wide rules for Codex agents
├─ DESIGN.ja.md                # Detailed design doc v0.2 (Japanese)
├─ .codex/                    # Codex project config / agent definitions
│  ├─ config.toml
│  └─ agents/{planner,generator,evaluator}.toml
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
└─ samples/
   ├─ vulnerable/             # Code that should be flagged
   └─ safe/                   # Code that must NOT be flagged
```

Future additions: `packages/scanner-semgrep` (deep mode), more language rule packs.

## Setup

Requires Node.js 18+.

```bash
npm install
npm run build
```

## CLI usage

```bash
# Scan a directory (human-readable output)
node apps/cli/dist/index.js ./samples/vulnerable

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
| `--ignore <name>` | Extra directory name to skip (repeatable). |
| `--diff <range>` | Scan only lines added in `git diff <range> --unified=0`. |
| `--known-only` | Scan only files with known-language extensions. |
| `--no-remediation` | Skip remediation generation. |

## Tests

```bash
npm test
```

Runs every package's `*.test.ts` under vitest.

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

30 rules at the moment. The ID prefix groups rules by source file; the `category` field is a separate, risk-oriented axis.

| Prefix | Coverage | Examples |
|---|---|---|
| `VG-INJ-NNN` | Injection | eval / SQL concatenation / innerHTML / pickle, etc. |
| `VG-AUTH-NNN` | Auth / TLS / placeholder auth | DEBUG bypass / `verify=False` / `dummy_token`. |
| `VG-SEC-NNN` | Hardcoded secrets | AWS keys / PEM / GitHub PAT / high-entropy strings. |
| `VG-CRYPTO-NNN` | Crypto | MD5/SHA1 / `Math.random` / `http://`. |
| `VG-QUAL-001..004` | General quality (CORS / swallowed exceptions / open redirect, etc.) | |
| `VG-QUAL-005..010` | **AI-trace heuristics** (`category: ai-quality`) | Stub implementations / placeholder emails / mock data / `debug=true` / "for now" comments / empty validators. |
| `VG-FW-NNN` | Framework misconfiguration | Django `DEBUG=True` / Flask `app.run(debug=True)` / CORS wildcard. |

VG-QUAL-005..010 target the "compiles cleanly but shouldn't ship" patterns that AI-generated code produces. They run at `severity=medium` and `confidence=low~medium` because heuristics are inherently noisier than syntactic rules.

## Chrome extension

`extensions/chrome/` is a minimal Manifest V3 extension (Phase 3). It uses the analyzer-core `./browser` sub-path so the bundle contains no `node:fs` / `node:path`, and runs the analyzer from the Side Panel.

| Feature | How to invoke |
|---|---|
| Show Side Panel | Click the VibeGuard icon in the toolbar. |
| Paste-scan | Paste code into the Side Panel textarea and press **Scan**. |
| Extract from page | Side Panel → **Extract from page** collects `<pre><code>` blocks from the active tab and scans them. |
| Selection scan | Select text on any page → context menu → `Scan with VibeGuard` (opens the Side Panel and scans immediately). |
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

## Implementation conventions (Codex harness)

This repo is built on the assumption that Codex multi-agent runs do the implementation. Responsibilities are split into three roles:

- **Planner** — Decomposes ambiguous requirements into implementable tasks.
- **Generator** — Implements exactly one task with the smallest viable change.
- **Evaluator** — Runs tests, static analysis, and (when needed) browser verification, and reports PASS / PASS WITH GAPS / FAIL.

Any non-trivial feature must go through Planner, and each generated task is gated by Evaluator. See [AGENTS.md](AGENTS.md) for the full protocol.

## License

TBD (project is still in early stage).
