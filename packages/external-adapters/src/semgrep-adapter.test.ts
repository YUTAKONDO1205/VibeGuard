// Semgrep adapter, tested against the RECORDED STRUCTURE of a real Semgrep
// 1.165.0 run over samples/vulnerable (src/fixtures/semgrep-samples-vulnerable.json,
// trimmed from paper_data/semgrep_vulnerable.json — provenance is the first key
// of the fixture itself).
//
// ⚠ "structure", not "bytes", since #44. The rule identifiers, the Windows
// backslash paths, the coordinates, the severities, the CWE ids and the
// confidences are what the tool emitted. The MESSAGES are not: every message,
// every autofix string and every metadata field made of Semgrep's own prose has
// been replaced with a placeholder, because the Semgrep Rules License permits
// use "only for your own internal business purposes" and this repository is
// public. Nothing below asserts on message text — that was checked before the
// redaction, not assumed — so the contract these tests state is unaffected. If
// you add an assertion that reads a message, you are asserting on a placeholder.
//
// The synthetic cases below exercise shapes the recording does not contain
// (missing lines, malformed severities, unparseable text). They are marked as
// synthetic where they appear, so nothing here reads as if a tool produced it.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parseSemgrepReport } from './semgrep-adapter.js';
import { ExternalReportError } from './types.js';

const FIXTURE_URL = new URL('./fixtures/semgrep-samples-vulnerable.json', import.meta.url);
const FIXTURE_TEXT = readFileSync(FIXTURE_URL, 'utf8');
const FIXTURE_PATH = fileURLToPath(FIXTURE_URL);
const OPTIONS = { reportPath: FIXTURE_PATH };

describe('parseSemgrepReport over recorded Semgrep 1.165.0 output', () => {
  const report = parseSemgrepReport(FIXTURE_TEXT, OPTIONS);

  it('reads the version from the report and never from anywhere else', () => {
    expect(report.provenance.versionFromReport).toBe('1.165.0');
    expect(report.provenance.tool).toBe('semgrep');
    expect(report.provenance.reportPath).toBe(FIXTURE_PATH);
    expect(report.provenance.obtainedBy).toBe('user-supplied-report');
  });

  it('never claims the tool was executed', () => {
    // The union has no such member, so this is a guard against someone widening
    // it later: every finding must carry the report provenance verbatim.
    for (const finding of report.findings) {
      expect(finding.provenance.obtainedBy).toBe('user-supplied-report');
      expect(finding.provenance.reportPath).toBe(FIXTURE_PATH);
    }
  });

  it('turns all 20 recorded results into findings and refuses none', () => {
    expect(report.findings).toHaveLength(20);
    expect(report.refused).toEqual([]);
    expect(report.toolReportedErrors).toEqual([]);
  });

  it('carries the scanned-file set, which is what makes "only tool X found it" a meaningful claim', () => {
    expect(report.scannedPaths).toHaveLength(13);
    expect(report.scannedPaths).toContain('samples/vulnerable/auth_bypass.py');
    // Normalised out of the Windows form the recording contains.
    expect(report.scannedPaths.every((p) => !p.includes('\\'))).toBe(true);
  });

  it('maps the first recorded result exactly', () => {
    const first = report.findings[0];
    expect(first?.toolRuleId).toBe('python.requests.security.disabled-cert-validation.disabled-cert-validation');
    expect(first?.ruleId).toBe('semgrep:python.requests.security.disabled-cert-validation.disabled-cert-validation');
    expect(first?.title).toBe('disabled-cert-validation');
    expect(first?.filePath).toBe('samples/vulnerable/auth_bypass.py');
    expect(first?.startLine).toBe(16);
    expect(first?.startColumn).toBe(12);
    expect(first?.endLine).toBe(16);
    expect(first?.endColumn).toBe(68);
    expect(first?.rawSeverity).toBe('ERROR');
    expect(first?.severity).toBe('high');
    // The recorded metadata says confidence LOW, and that is what is used —
    // an ERROR-severity finding whose rule author declared low confidence.
    expect(first?.confidence).toBe('low');
    expect(first?.cweIds).toEqual(['CWE-295']);
    expect(first?.weaknessClass).toBe('tls-verification-disabled');
    expect(first?.sourceEngine).toBe('semgrep');
    expect(first?.category).toBe('external-semgrep');
  });

  it('namespaces rule ids so a VibeGuard suppression pragma cannot reach them', () => {
    for (const finding of report.findings) {
      expect(finding.ruleId.startsWith('semgrep:')).toBe(true);
      expect(finding.ruleId.startsWith('VG-')).toBe(false);
    }
  });

  it('produces stable, unique finding ids over the same bytes', () => {
    const again = parseSemgrepReport(FIXTURE_TEXT, OPTIONS);
    expect(again.findings.map((f) => f.findingId)).toEqual(report.findings.map((f) => f.findingId));
    expect(new Set(report.findings.map((f) => f.findingId)).size).toBe(report.findings.length);
  });

  it('classifies exactly 11 of the 20 recorded results and leaves 9 unmapped', () => {
    // ★ THE MEASURED PARTIALNESS OF THE MAPPING, pinned as a number so it cannot
    // drift silently. 45% unmapped on a corpus the Semgrep half of the mapping
    // was DERIVED from is the honest starting point for the README's claim that
    // coverage on arbitrary code will be worse, not better.
    const classified = report.findings.filter((f) => f.weaknessClass !== null);
    expect(classified).toHaveLength(11);
    expect(report.findings.length - classified.length).toBe(9);

    const byClass = new Map<string, number>();
    for (const finding of classified) {
      byClass.set(finding.weaknessClass as string, (byClass.get(finding.weaknessClass as string) ?? 0) + 1);
    }
    expect(Object.fromEntries([...byClass].sort())).toEqual({
      'cookie-session-flags': 2,
      'debug-enabled': 1,
      'eval-exec': 1,
      'injection-shell': 1,
      'injection-sql': 2,
      'insecure-transport': 1,
      'tls-verification-disabled': 1,
      'weak-crypto': 2,
    });
  });

  it('does not classify the CWE-668 host-binding rule as debug mode', () => {
    // ★ THE REGRESSION GUARD FOR DEPARTURE 3 in weakness-class.ts. Both of these
    // fire on samples/vulnerable/flask_app.py:19 in the recording; only one of
    // them is CWE-489.
    const atFlask = report.findings.filter((f) => f.filePath === 'samples/vulnerable/flask_app.py');
    expect(atFlask).toHaveLength(2);
    const byRule = Object.fromEntries(atFlask.map((f) => [f.toolRuleId, f.weaknessClass]));
    expect(byRule['python.flask.security.audit.debug-enabled.debug-enabled']).toBe('debug-enabled');
    expect(byRule['python.flask.security.audit.app-run-param-config.avoid_app_run_with_bad_host']).toBeNull();
  });

  it('leaves the six co-located express_session.js:14 rules correctly split', () => {
    // ★ THE CASE THAT JUSTIFIES A HAND-BUILT MAPPING. Six Semgrep rules fire on
    // one line of the recording. Two of them are the missing-flag weakness
    // VG-AUTH-006 detects; four are different weaknesses that merely share a
    // line. A location-only merge would have called all six one finding.
    const atLine14 = report.findings.filter(
      (f) => f.filePath === 'samples/vulnerable/express_session.js' && f.startLine === 14,
    );
    expect(atLine14).toHaveLength(6);
    expect(atLine14.filter((f) => f.weaknessClass === 'cookie-session-flags').map((f) => f.title).sort()).toEqual([
      'express-cookie-session-no-httponly',
      'express-cookie-session-no-secure',
    ]);
    expect(atLine14.filter((f) => f.weaknessClass === null)).toHaveLength(4);
  });

  it('maps every observed severity band and keeps the raw string beside it', () => {
    const observed = new Map<string, string>();
    for (const finding of report.findings) {
      if (finding.rawSeverity !== null) observed.set(finding.rawSeverity, finding.severity);
    }
    // The value set measured across every recorded Semgrep artifact in the repo.
    expect(Object.fromEntries([...observed].sort())).toEqual({
      ERROR: 'high',
      INFO: 'low',
      WARNING: 'medium',
    });
    // ERROR is deliberately NOT critical — see the mapping's comment.
    expect([...observed.values()]).not.toContain('critical');
  });

  it('records the confidence provenance on every finding, absent or not', () => {
    for (const finding of report.findings) {
      expect(finding.evidence?.some((e) => e.startsWith('semgrep.metadata.confidence='))).toBe(true);
    }
  });

  it('does not surface Semgrep autofix text as VibeGuard remediation', () => {
    // ★ CORRECTED 2026-08-03. This comment used to claim the recording's
    // `extra.fix` values are "requires login" for redacted rules. They are not
    // — the redaction lands on `extra.lines`. The old comment survived because
    // `toContain('"fix"')` never checked the claim it was written to justify: a
    // comment asserting a fact that the assertion beside it does not test is a
    // fact nobody is maintaining. So the counts are asserted now.
    const results = JSON.parse(FIXTURE_TEXT).results as { extra?: { fix?: unknown; lines?: unknown } }[];
    expect(results.filter((r) => r.extra?.fix === 'requires login')).toHaveLength(0);
    expect(results.filter((r) => r.extra?.lines === 'requires login')).toHaveLength(results.length);
    // Real autofix text IS present (three of them), which is what makes the
    // refusal load-bearing rather than moot.
    expect(results.filter((r) => typeof r.extra?.fix === 'string').length).toBeGreaterThan(0);
    expect(report.findings.every((f) => f.remediation === undefined)).toBe(true);
  });
});

describe('parseSemgrepReport refusals and failures (synthetic inputs)', () => {
  it('throws rather than returning an empty report for non-JSON', () => {
    expect(() => parseSemgrepReport('not json at all', OPTIONS)).toThrow(ExternalReportError);
  });

  it('throws for JSON that is not a Semgrep report, and says which adapter to use', () => {
    // A user who ran `semgrep --sarif` and passed it to --semgrep-report must be
    // told, not silently given zero findings.
    expect(() => parseSemgrepReport(JSON.stringify({ version: '2.1.0', runs: [] }), OPTIONS)).toThrow(/results.*SARIF|SARIF/s);
  });

  it('accepts an EMPTY results array — a clean scan is evidence, not an error', () => {
    const report = parseSemgrepReport(JSON.stringify({ version: '1.165.0', results: [], errors: [] }), OPTIONS);
    expect(report.findings).toEqual([]);
    expect(report.provenance.versionFromReport).toBe('1.165.0');
  });

  it('reports a null version as null rather than inventing one', () => {
    const report = parseSemgrepReport(JSON.stringify({ results: [] }), OPTIONS);
    expect(report.provenance.versionFromReport).toBeNull();
  });

  it('refuses a result with no start line instead of placing it at line 1', () => {
    // ★ THE FAILURE THIS PREVENTS: a finding parked at line 1 becomes a cluster
    // peer of whatever really is on line 1, and the merge then reports two tools
    // agreeing about a line only one of them named.
    const synthetic = {
      version: '1.165.0',
      results: [
        { check_id: 'a.b.eval-detected', path: 'src/x.js', extra: { severity: 'ERROR' } },
        { check_id: 'a.b.eval-detected', path: 'src/x.js', start: { line: 4 }, extra: { severity: 'ERROR' } },
      ],
    };
    const report = parseSemgrepReport(JSON.stringify(synthetic), OPTIONS);
    expect(report.findings).toHaveLength(1);
    expect(report.findings[0]?.startLine).toBe(4);
    expect(report.refused).toHaveLength(1);
    expect(report.refused[0]?.index).toBe(0);
    expect(report.refused[0]?.reason).toMatch(/start\.line/);
  });

  it('refuses a result with no path', () => {
    const synthetic = { results: [{ check_id: 'a.b.eval-detected', start: { line: 3 } }] };
    const report = parseSemgrepReport(JSON.stringify(synthetic), OPTIONS);
    expect(report.findings).toEqual([]);
    expect(report.refused[0]?.reason).toMatch(/no path/);
  });

  it('maps an unknown severity to the neutral middle and preserves the raw string', () => {
    const synthetic = {
      results: [{ check_id: 'a.b.eval-detected', path: 'src/x.js', start: { line: 1 }, extra: { severity: 'EXPERIMENT' } }],
    };
    const report = parseSemgrepReport(JSON.stringify(synthetic), OPTIONS);
    expect(report.findings[0]?.severity).toBe('medium');
    expect(report.findings[0]?.rawSeverity).toBe('EXPERIMENT');
  });

  it('defaults an absent metadata confidence to medium, not to the bottom band', () => {
    const synthetic = {
      results: [{ check_id: 'a.b.eval-detected', path: 'src/x.js', start: { line: 1 }, extra: { severity: 'ERROR' } }],
    };
    const report = parseSemgrepReport(JSON.stringify(synthetic), OPTIONS);
    expect(report.findings[0]?.confidence).toBe('medium');
    expect(report.findings[0]?.evidence).toContain('semgrep.metadata.confidence=<absent>');
  });

  it('surfaces the tool\'s own errors[] rather than treating the scan as complete', () => {
    const synthetic = {
      results: [],
      errors: [{ type: 'SourceParseError', message: 'cannot parse src/broken.py' }],
    };
    const report = parseSemgrepReport(JSON.stringify(synthetic), OPTIONS);
    expect(report.toolReportedErrors).toEqual(['SourceParseError: cannot parse src/broken.py']);
  });

  it('disambiguates two identical results deterministically instead of colliding ids', () => {
    const one = { check_id: 'a.b.eval-detected', path: 'src/x.js', start: { line: 1 }, extra: { severity: 'ERROR' } };
    const report = parseSemgrepReport(JSON.stringify({ results: [one, one] }), OPTIONS);
    expect(report.findings).toHaveLength(2);
    expect(new Set(report.findings.map((f) => f.findingId)).size).toBe(2);
    expect(report.findings[1]?.findingId.endsWith('#2')).toBe(true);
  });

  it('normalises CWE ids and drops malformed ones rather than passing them through', () => {
    const synthetic = {
      results: [
        {
          check_id: 'a.b.eval-detected',
          path: 'src/x.js',
          start: { line: 1 },
          extra: { severity: 'ERROR', metadata: { cwe: ['CWE-95: Eval Injection', 'not a cwe', 'CWE-94: Code Injection'] } },
        },
      ],
    };
    const report = parseSemgrepReport(JSON.stringify(synthetic), OPTIONS);
    expect(report.findings[0]?.cweIds).toEqual(['CWE-94', 'CWE-95']);
  });
});
