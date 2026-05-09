# VibeGuard for VS Code

Security diagnostics for AI-generated code, surfaced inline in the editor.

VibeGuard scans the file you're editing — on save and on demand — and reports
risky patterns straight to the **Problems** panel: SQL / command injection,
hardcoded secrets, weak crypto, missing auth checks, debug flags left on,
stub bodies, mock data on production paths, and other AI-coding artifacts.

The same analyzer powers the [VibeGuard CLI](https://github.com/YUTAKONDO1205/VibeGuard)
and the [GitHub Marketplace Action](https://github.com/marketplace/actions/vibe-guard-aicoding),
so a finding here will look identical in PR comments and SARIF uploads.

## Features

- **On-save scan** — every save runs a scan; results land in the Problems panel
  and as squigglies in the editor gutter. Default mode is `fast`; switch to
  `standard` if you want broader checks at save time.
- **Manual scan** — `VibeGuard: Scan File` (Command Palette) or right-click →
  `VibeGuard: Scan Selection` to scope a scan to a region of code.
- **Findings sidebar** — `VibeGuard Findings` view in the Explorer lists every
  finding in the active workspace with severity badges.
- **30 built-in rules** — injection / auth / secrets / crypto / AI-quality
  heuristics. AI-quality rules (stub bodies, placeholder emails, mock data,
  debug flags, "for now" comments, empty validators) are VibeGuard's specialty.

## Privacy

100% local. The extension makes no network requests, sends no telemetry, and
does not transmit your code anywhere. See [PRIVACY.md](https://github.com/YUTAKONDO1205/VibeGuard/blob/main/PRIVACY.md)
for the full statement.

## Settings

| Setting | Default | Description |
|---|---|---|
| `vibeguard.scanOnSave` | `true` | Run a VibeGuard scan when a file is saved. |
| `vibeguard.scanOnSaveMode` | `fast` | `fast` or `standard`. Manual scans always use `standard`. |

## Commands

| Command | When |
|---|---|
| `VibeGuard: Scan File` | Scan the active editor (`standard` mode). |
| `VibeGuard: Scan Selection` | Scan only the selected text (right-click menu). |

## Supported languages

JavaScript, TypeScript, Python, Go, Java, Ruby, PHP, C#, and a few more. The
analyzer falls back to a language-agnostic regex pass for everything else, so
you'll still get hardcoded-secret / TODO-style findings on unfamiliar files.

## Roadmap

Tracked in the project [README](https://github.com/YUTAKONDO1205/VibeGuard#readme).
Near-term: Code Action quick-fixes (apply remediation in one click), workspace
diff scan (only the lines you're about to commit), SARIF export from inside
VS Code.

## Development

If you cloned the monorepo and want to hack on the extension itself:

```bash
npm install
npm run build -w vibeguard-aicoding
# then open extensions/vscode/ in VS Code and press F5 to launch the
# Extension Development Host.
```

Verification:

1. Open `samples/vulnerable/xss.js` (or any file under `samples/vulnerable/`).
2. Save → Problems panel should populate.
3. Command Palette → `VibeGuard: Scan File` → results appear.
4. Toggle `vibeguard.scanOnSaveMode` between `fast` / `standard` and confirm
   the finding count differs.

## License

MIT — see the [repository](https://github.com/YUTAKONDO1205/VibeGuard).
