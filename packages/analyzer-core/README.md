# @vibeguard/analyzer-core

Core scanning engine. Owns the per-file analysis loop: language detection,
rule dispatch, snippet extraction, and suppression-comment handling.

## Public surface

- `analyzer.scan(request)` — analyze a single in-memory file. Returns
  `{ findings, summary }`. Used by `scanPath` (file walker), `scanDiff`
  (CLI `--diff`), and the VS Code / Chrome extensions.
- `scanPath(dir, options)` — walk a directory, scan each file, aggregate
  results. Honours `--ignore` globs and `--known-only`.
- `parseSuppressions(content)` / `isSuppressed(map, ruleId, line, severity)` /
  `evaluateSuppression(...)` — parses `vibeguard:disable-line`,
  `disable-next-line`, and `disable-file` pragmas emitted by source files.
  A pragma with no rule IDs is a wildcard and **cannot** suppress a
  `critical` / `high` / `medium` finding; such a finding is reported with a
  `suppressionOverridden` marker instead. `evaluateSuppression` returns that
  marker alongside the boolean; `isSuppressed` is the boolean alone.
- `suppressionsForPath(config, path)` / `isPathSuppressed(set, ruleId, severity)` /
  `evaluatePathSuppression(...)` — the same policy on the config
  (`.vibeguardrc.json` `suppress[].paths`) channel. An entry that omits `rules`
  is a wildcard and is gated identically.
- `detectLanguage(filePath, content)` — extension- and shebang-based
  language detection feeding `RuleDefinition.languages`.

## Where it sits

```
CLI / VS Code / Chrome
        │
        ▼
analyzer-core ──▶ rules (allRules, getRulesForLanguage)
        │
        ├──▶ findings-schema   (Finding, Severity, ScanRequest types)
        └──▶ remediation-engine (why / how / exampleFix)
```

## Adding behavior

- New rule? Edit `packages/rules/src/rules/` and register in `rules/index.ts`.
- New input shape (e.g. URL fetch)? Add a new dispatcher (see `apps/cli/src/diff.ts`)
  and call `analyzer.scan` with the appropriate `targetType`.
- New suppression syntax? Edit `src/suppress.ts` and extend the unit tests
  alongside `analyzer.test.ts`.
