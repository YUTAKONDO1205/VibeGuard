# @vibeguard/findings-schema

Shared TypeScript types for the VibeGuard finding format. Every other
package depends on these types; this package itself depends on nothing —
including no schema-validation library. The types are compile-time only;
there is no runtime validator here.

## Key types

- `Finding` — a single rule hit. `ruleId`, `severity`, `confidence`,
  `category`, and an optional `remediation`. The location is **flat, not
  nested**: `filePath`, `startLine`, `endLine`, `startColumn`, `endColumn`.
  `snippet` is the matched line (secrets masked where the masker recognises
  the form); `evidence` is the raw matched text.
- `Severity` — `'critical' | 'high' | 'medium' | 'low' | 'info'`.
- `Confidence` — `'high' | 'medium' | 'low'`.
- `ScanRequest` — input to `analyzer.scan`. Carries `content`,
  `filePath`, `language`, `mode` (`fast | standard | deep`), and a
  `targetType` discriminator (`'file' | 'snippet' | 'diff' | 'repo'`).
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
