# test_problem/

A single-file demo for **running VibeGuard locally and seeing what it flags, at a glance**.

[test_problem.py](test_problem.py) packs the anti-patterns you should never ship into one Python file. The comment header above each block names the VibeGuard rule ID it is meant to trip (`VG-SECRET-*` / `VG-INJ-*` / `VG-CRYPTO-*` / `VG-AUTH-*` / `VG-FW-*` / `VG-QUAL-*`).

## Why this is separate from `samples/vulnerable/`

| | Purpose | Shape |
|---|---|---|
| [`samples/vulnerable/`](../samples/vulnerable) | **CI quality gate** — the `samples` job in `security-scan.yml` requires `>= 15 findings` | Many small files, one rule family each |
| `test_problem/` | **Manual demo** for humans poking at the scanner | One file that trips most rule families at once |

This folder is **not** wired into the CI gate, so editing it will not break the `samples` job. Use it for quick rule-behaviour checks, demos, or screenshots.

## Usage

The fastest path is the prebuilt CLI from the repo root:

```bash
npm run build
node apps/cli/dist/index.js test_problem/test_problem.py
```

For SARIF output:

```bash
node apps/cli/dist/index.js test_problem/test_problem.py --format sarif --out test_problem.sarif
```

If you launched the VS Code extension in an Extension Host, just open this file and save — inline diagnostics will appear.

## Warning

This file is **intentionally vulnerable**. Do not copy it into production code, and do not execute it directly with `python test_problem.py` — it starts Flask on `0.0.0.0:5000` with `debug=True`, which exposes the Werkzeug debugger. Read it with VibeGuard; do not run it.
