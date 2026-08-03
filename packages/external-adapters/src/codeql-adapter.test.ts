// ★ EVERY ASSERTION IN THIS FILE IS ABOUT A FORMAT, NOT ABOUT A TOOL.
//
// The fixture is SCHEMA-DERIVED, not tool-recorded: no CodeQL run produced it,
// because CodeQL is not installed on the machine this was written on and no
// recorded CodeQL output exists anywhere in this repository. Its own
// `_fixtureProvenance` key says so as its first bytes. What these tests prove is
// that the adapter reads SARIF 2.1.0 the way the specification says to read it.
// What they do NOT prove — and no test here can — is that real CodeQL emits these
// rule ids, tag spellings or property names. Contrast semgrep-adapter.test.ts,
// which runs against bytes a real Semgrep produced.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parseCodeqlSarifReport } from './codeql-adapter.js';
import { ExternalReportError } from './types.js';

const FIXTURE_URL = new URL('./fixtures/codeql-schema-derived.sarif', import.meta.url);
const FIXTURE_TEXT = readFileSync(FIXTURE_URL, 'utf8');
const FIXTURE_PATH = fileURLToPath(FIXTURE_URL);
const OPTIONS = { reportPath: FIXTURE_PATH };

describe('the CodeQL fixture is honestly labelled', () => {
  it('declares itself schema-derived rather than tool-recorded, in its first key', () => {
    // This is not decoration. A future reader deciding how much the CodeQL
    // adapter is worth needs to find the answer before they find anything else,
    // and JSON has no comment syntax to put it in.
    const parsed = JSON.parse(FIXTURE_TEXT) as { _fixtureProvenance?: { kind?: string } };
    expect(Object.keys(parsed)[0]).toBe('_fixtureProvenance');
    expect(parsed._fixtureProvenance?.kind).toBe('SCHEMA-DERIVED, NOT TOOL-RECORDED');
  });

  it('is not confusable with the Semgrep fixture, which IS tool-recorded', () => {
    const semgrep = JSON.parse(
      readFileSync(new URL('./fixtures/semgrep-samples-vulnerable.json', import.meta.url), 'utf8'),
    ) as { _fixtureProvenance?: { kind?: string } };
    expect(semgrep._fixtureProvenance?.kind).toBe('TOOL-RECORDED — genuine bytes, not fabricated');
  });
});

describe('parseCodeqlSarifReport over the schema-derived SARIF log', () => {
  const report = parseCodeqlSarifReport(FIXTURE_TEXT, OPTIONS);

  it('reads the driver version from the report and never claims execution', () => {
    expect(report.provenance).toEqual({
      tool: 'codeql',
      versionFromReport: '2.20.3',
      reportPath: FIXTURE_PATH,
      obtainedBy: 'user-supplied-report',
    });
    for (const finding of report.findings) {
      expect(finding.provenance.obtainedBy).toBe('user-supplied-report');
    }
  });

  it('parses six results and refuses the seventh, which has no region', () => {
    expect(report.findings).toHaveLength(6);
    expect(report.refused).toHaveLength(1);
    expect(report.refused[0]?.index).toBe(6);
    expect(report.refused[0]?.toolRuleId).toBe('py/sql-injection');
    expect(report.refused[0]?.reason).toMatch(/region\.startLine/);
  });

  it('refuses a file-level result rather than parking it at line 1', () => {
    // ★ THE FAILURE THIS PREVENTS: a file-level advisory placed at line 1 becomes
    // a cluster peer of whatever really is on line 1, and the merge then reports
    // it as corroborating a finding it never located.
    expect(report.findings.some((f) => f.filePath === 'samples/vulnerable/generated_queries.py')).toBe(false);
    expect(report.findings.every((f) => (f.startLine ?? 0) >= 1)).toBe(true);
  });

  it('resolves rules living in tool.extensions, not just tool.driver.rules', () => {
    // ★ THE SILENT FAILURE THIS GUARDS. CodeQL puts query rules in
    // `tool.extensions[].rules`, one component per query pack; `driver.rules` is
    // empty in this fixture, as it is in real CodeQL output. A parser that only
    // looked at the driver would find no descriptor, fall through to the SARIF
    // default level, and render every finding `medium` — with nothing crashing
    // and every finding present.
    const sql = report.findings.find((f) => f.toolRuleId === 'py/sql-injection');
    expect(sql?.title).toBe('SQL query built from user-controlled sources');
    expect(sql?.confidence).toBe('high'); // properties.precision = high
    expect(sql?.cweIds).toEqual(['CWE-89']); // external/cwe/cwe-089, zeros stripped
    expect(sql?.evidence).toContain('codeql.security-severity=8.8');
  });

  it('resolves a rule by id when the result carries no rule reference object', () => {
    const shell = report.findings.find((f) => f.toolRuleId === 'py/command-line-injection');
    expect(shell?.title).toBe('Uncontrolled command line');
    expect(shell?.weaknessClass).toBe('injection-shell');
    expect(shell?.cweIds).toEqual(['CWE-78', 'CWE-88']);
  });

  it('walks the whole SARIF 3.27.10 level-defaulting chain', () => {
    // Level 1 — the result states it.
    const explicit = report.findings.find((f) => f.toolRuleId === 'py/sql-injection');
    expect(explicit?.rawSeverity).toBe('error');
    expect(explicit?.severity).toBe('high');
    expect(explicit?.evidence).toContain('sarif.level.effective=error');

    // Level 2 — the result states nothing; the rule's defaultConfiguration does.
    const fromRule = report.findings.find((f) => f.toolRuleId === 'py/request-without-cert-validation');
    expect(fromRule?.rawSeverity).toBeNull();
    expect(fromRule?.evidence).toContain('sarif.rule.defaultConfiguration.level=warning');
    expect(fromRule?.severity).toBe('medium');

    // Level 3 — neither states it; the specification's own default applies.
    const fromSpec = report.findings.find((f) => f.toolRuleId === 'js/insecure-randomness');
    expect(fromSpec?.rawSeverity).toBeNull();
    expect(fromSpec?.evidence).toContain('sarif.rule.defaultConfiguration.level=<absent>');
    expect(fromSpec?.evidence).toContain('sarif.level.effective=warning');
    expect(fromSpec?.severity).toBe('medium');
  });

  it('never promotes a SARIF error into critical', () => {
    expect(report.findings.map((f) => f.severity)).not.toContain('critical');
  });

  it('carries security-severity as evidence without converting it into a band', () => {
    // GitHub documents 9.0+ as critical; py/command-line-injection is 9.8 here.
    // Converting would stack a second unverified layer on an adapter no CodeQL
    // run has ever exercised, so the number is recorded and not acted on.
    const shell = report.findings.find((f) => f.toolRuleId === 'py/command-line-injection');
    expect(shell?.evidence).toContain('codeql.security-severity=9.8');
    expect(shell?.severity).toBe('high');
  });

  it('percent-decodes artifact URIs so paths with spaces can join', () => {
    // Without this, every finding in a path containing a space silently fails to
    // corroborate with VibeGuard's own findings in the same file.
    const decoded = report.findings.find((f) => f.toolRuleId === 'js/clear-text-storage-of-sensitive-data');
    expect(decoded?.filePath).toBe('samples/vulnerable/legacy client/session store.js');
  });

  it('leaves a malformed percent escape alone rather than dropping the finding', () => {
    const synthetic = {
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'CodeQL', rules: [] } },
          results: [
            {
              ruleId: 'py/sql-injection',
              level: 'error',
              message: { text: 'x' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: 'src/100%25/a%ZZ.py' },
                    region: { startLine: 3 },
                  },
                },
              ],
            },
          ],
        },
      ],
    };
    const parsed = parseCodeqlSarifReport(JSON.stringify(synthetic), OPTIONS);
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]?.filePath).toBe('src/100%25/a%ZZ.py');
  });

  it('classifies with the CodeQL half of the mapping and admits what it cannot name', () => {
    const byRule = Object.fromEntries(report.findings.map((f) => [f.toolRuleId, f.weaknessClass]));
    expect(byRule).toEqual({
      'py/sql-injection': 'injection-sql',
      'js/code-injection': 'eval-exec',
      'py/command-line-injection': 'injection-shell',
      'py/request-without-cert-validation': 'tls-verification-disabled',
      'js/clear-text-storage-of-sensitive-data': 'insecure-transport',
      // Not in any family. There is no CodeQL pattern for weak randomness in
      // sec-transfer-codeql.mjs, so inventing one here would be the first
      // unsourced entry in the table.
      'js/insecure-randomness': null,
    });
  });

  it('namespaces rule ids away from VibeGuard\'s id space', () => {
    for (const finding of report.findings) {
      expect(finding.ruleId.startsWith('codeql:')).toBe(true);
      expect(finding.sourceEngine).toBe('external');
      expect(finding.category).toBe('external-codeql');
    }
  });

  it('reports scannedPaths as EMPTY, meaning unknown coverage rather than nothing scanned', () => {
    expect(report.scannedPaths).toEqual([]);
  });

  it('is deterministic over the same bytes', () => {
    const again = parseCodeqlSarifReport(FIXTURE_TEXT, OPTIONS);
    expect(again.findings.map((f) => f.findingId)).toEqual(report.findings.map((f) => f.findingId));
    expect(new Set(report.findings.map((f) => f.findingId)).size).toBe(report.findings.length);
  });
});

describe('parseCodeqlSarifReport failures (synthetic inputs)', () => {
  it('throws rather than returning an empty report for non-JSON', () => {
    expect(() => parseCodeqlSarifReport('<xml/>', OPTIONS)).toThrow(ExternalReportError);
  });

  it('throws for JSON that is not a SARIF log, and says which adapter to use', () => {
    expect(() => parseCodeqlSarifReport(JSON.stringify({ version: '1.165.0', results: [] }), OPTIONS)).toThrow(
      /runs.*Semgrep|Semgrep/s,
    );
  });

  it('accepts an EMPTY runs array — a clean analysis is evidence, not an error', () => {
    const report = parseCodeqlSarifReport(JSON.stringify({ version: '2.1.0', runs: [] }), OPTIONS);
    expect(report.findings).toEqual([]);
    expect(report.provenance.versionFromReport).toBeNull();
  });

  it('surfaces a non-2.1.0 SARIF version as a warning instead of refusing outright', () => {
    const report = parseCodeqlSarifReport(JSON.stringify({ version: '2.2.0', runs: [] }), OPTIONS);
    expect(report.toolReportedErrors.some((e) => e.includes('2.2.0'))).toBe(true);
  });

  it('surfaces toolExecutionNotifications, because a partial analysis is not coverage', () => {
    const synthetic = {
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'CodeQL', rules: [] } },
          invocations: [
            {
              executionSuccessful: false,
              toolExecutionNotifications: [
                { level: 'error', message: { text: 'extractor failed for 3 files' } },
                { level: 'note', message: { text: 'this one is noise and is not surfaced' } },
              ],
            },
          ],
          results: [],
        },
      ],
    };
    const report = parseCodeqlSarifReport(JSON.stringify(synthetic), OPTIONS);
    expect(report.toolReportedErrors).toEqual(['error: extractor failed for 3 files']);
  });

  it('indexes refusals across every run of a multi-run log', () => {
    // CodeQL emits one run per database, so a repo analysed for three languages
    // is three runs in one file. Per-run indices would make refused[].index
    // useless for locating the offending result.
    const run = (uri: string) => ({
      tool: { driver: { name: 'CodeQL', rules: [] } },
      results: [
        { ruleId: 'py/sql-injection', message: { text: '' }, locations: [{ physicalLocation: { artifactLocation: { uri } } }] },
      ],
    });
    const report = parseCodeqlSarifReport(JSON.stringify({ version: '2.1.0', runs: [run('a.py'), run('b.py')] }), OPTIONS);
    expect(report.refused.map((r) => r.index)).toEqual([0, 1]);
  });
});
