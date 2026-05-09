# @vibeguard/findings-schema

Shared TypeScript types and Zod-style validation for the VibeGuard
finding format. Every other package depends on these types; this package
itself depends on nothing.

## Key types

- `Finding` — a single rule hit. `ruleId`, `severity`, `confidence`,
  `location` (file + start/end line/column), `snippet`, and an optional
  `remediation`.
- `Severity` — `'critical' | 'high' | 'medium' | 'low' | 'info'`.
- `Confidence` — `'high' | 'medium' | 'low'`.
- `ScanRequest` — input to `analyzer.scan`. Carries `content`,
  `filePath`, `language`, `mode` (`fast | standard | deep`), and a
  `targetType` discriminator (`'file' | 'diff'`).
- `ScanSummary` — aggregate counts by severity returned alongside
  findings.

## Why a separate package

Keeping the wire format in its own zero-dep package means:

- The Chrome extension can pull just this + analyzer-core without
  dragging in fs / path.
- The SARIF adapter can map `Finding → sarif.Result` without reaching
  back into rule internals.
- Schema changes are visible as a diff in this package and force a
  conscious update everywhere downstream.
