# @vibeguard/sarif-adapter

Converts VibeGuard `Finding[]` → SARIF v2.1.0. The output is consumed by
GitHub's Code Scanning UI (the `github/codeql-action/upload-sarif`
action) and by any other SARIF-aware tool (VS Code SARIF Explorer,
SonarQube, etc.).

## Public surface

- `toSarif(findings, { tool, runMetadata })` — returns a SARIF log object
  with one run, the rules deduplicated into `tool.driver.rules`, and one
  result per finding.

## Mapping notes

| VibeGuard      | SARIF            |
|----------------|------------------|
| `severity`     | `level` (`critical`/`high` → `error`, `medium` → `warning`, `low`/`info` → `note`) |
| `confidence`   | result property `confidence` (string) — not part of SARIF core |
| `location`     | `physicalLocation.artifactLocation.uri` + `region` |
| `remediation`  | `message.markdown` (rendered as why/how/exampleFix) |
| `ruleId`       | `result.ruleId` and key into `tool.driver.rules` |

## Why a separate package

SARIF is one of several output formats (human / json / sarif / markdown).
Each adapter lives in its own package so that the CLI can lazy-load
only what it needs and so that breaking changes to one format never
ripple into the others.
