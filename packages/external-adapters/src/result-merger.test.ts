// The merger, tested against the one recorded artifact this package has (real
// Semgrep 1.165.0 over samples/vulnerable) plus the schema-derived CodeQL log,
// plus synthetic VibeGuard findings.
//
// ★ WHAT THE VIBEGUARD SIDE IS AND IS NOT. The VibeGuard findings below are
// HAND-WRITTEN to sit at the locations the recorded Semgrep run flagged. They are
// not the output of a VibeGuard scan — this package must not depend on the engine
// to test a merger — so no assertion here says anything about what VibeGuard
// actually detects in samples/vulnerable. They exist to drive the agreement
// labels through every branch with realistic rule ids and realistic locations.
//
// The tests are grouped by the thing that could go wrong, and the group names say
// what the wrong output would have been.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { Finding } from '@vibeguard/findings-schema';
import { parseCodeqlSarifReport } from './codeql-adapter.js';
import { mergeEnsemble, mergedConfidence, mergedSeverity } from './result-merger.js';
import type { VibeguardSide } from './result-merger.js';
import { parseSemgrepReport } from './semgrep-adapter.js';
import type { ExternalReport, MergedFinding } from './types.js';
import { notSupplied, suppliedReport, unreadableReport } from './types.js';

const SEMGREP_URL = new URL('./fixtures/semgrep-samples-vulnerable.json', import.meta.url);
const CODEQL_URL = new URL('./fixtures/codeql-schema-derived.sarif', import.meta.url);
const semgrepReport = parseSemgrepReport(readFileSync(SEMGREP_URL, 'utf8'), {
  reportPath: fileURLToPath(SEMGREP_URL),
});
const codeqlReport = parseCodeqlSarifReport(readFileSync(CODEQL_URL, 'utf8'), {
  reportPath: fileURLToPath(CODEQL_URL),
});

function vgFinding(ruleId: string, filePath: string, startLine: number, extra: Partial<Finding> = {}): Finding {
  return {
    findingId: `${ruleId}@${filePath}:${startLine}`,
    ruleId,
    title: ruleId,
    description: '',
    severity: 'high',
    confidence: 'medium',
    category: 'security',
    filePath,
    startLine,
    sourceEngine: 'core-rule',
    ...extra,
  };
}

function vgSide(findings: Finding[]): VibeguardSide {
  return { findings, engineVersion: '0.3.3' };
}

function rowFor(rows: MergedFinding[], filePath: string, startLine: number, weaknessClass: string | null) {
  return rows.find((r) => r.filePath === filePath && r.startLine === startLine && r.weaknessClass === weaknessClass);
}

// ---------------------------------------------------------------------------
describe('degraded mode: the failure would be silently reporting an absent tool as agreeing', () => {
  it('says so, loudly and in the output, when no external report was supplied', () => {
    const result = mergeEnsemble({
      vibeguard: suppliedReport(vgSide([vgFinding('VG-INJ-001', 'src/db.ts', 10)])),
      semgrep: notSupplied(),
      codeql: notSupplied(),
    });

    expect(result.degraded).toBe(true);
    expect(result.degradedNotice).toContain('ENSEMBLE DEGRADED');
    expect(result.degradedNotice).toContain('Semgrep was NOT run (no report supplied)');
    expect(result.degradedNotice).toContain('CodeQL was NOT run (no report supplied)');
    // ★ The sentence that distinguishes the two facts must be present verbatim.
    expect(result.degradedNotice).toContain('this tool was never run');
  });

  it('refuses to compute agreement at all with one participant', () => {
    // ★ THE MOST DANGEROUS OUTPUT THIS PACKAGE COULD PRODUCE is a one-tool run
    // labelling everything "unique to VibeGuard", which is a restatement of the
    // input wearing the clothes of a three-tool comparison.
    const result = mergeEnsemble({
      vibeguard: suppliedReport(vgSide([vgFinding('VG-INJ-001', 'src/db.ts', 10)])),
      semgrep: notSupplied(),
      codeql: notSupplied(),
    });
    expect(result.agreementComputable).toBe(false);
    expect(result.agreementNotComputableReason).toContain('only VibeGuard participated');
    expect(result.merged.map((r) => r.agreement)).toEqual(['not-computable']);
    expect(result.byAgreement['unique-to-tool']).toBe(0);
    expect(result.byAgreement['unanimous']).toBe(0);
  });

  it('distinguishes a report that was not supplied from one that could not be read', () => {
    const result = mergeEnsemble({
      vibeguard: suppliedReport(vgSide([])),
      semgrep: unreadableReport('/tmp/semgrep.json', 'not valid JSON: Unexpected token <'),
      codeql: notSupplied(),
    });
    const semgrep = result.participation.find((p) => p.tool === 'semgrep');
    const codeql = result.participation.find((p) => p.tool === 'codeql');
    expect(semgrep?.status).toBe('report-unreadable');
    expect(semgrep?.detail).toContain('/tmp/semgrep.json');
    expect(semgrep?.detail).toContain('not valid JSON');
    expect(codeql?.status).toBe('not-supplied');
    expect(result.degradedNotice).toContain('NOT usable');
  });

  it('reports counts as null, never zero, for a tool that did not participate', () => {
    const result = mergeEnsemble({
      vibeguard: suppliedReport(vgSide([])),
      semgrep: notSupplied(),
      codeql: notSupplied(),
    });
    const semgrep = result.participation.find((p) => p.tool === 'semgrep');
    // ★ 0 would render identically to "participated and found nothing".
    expect(semgrep?.findingCount).toBeNull();
    expect(semgrep?.refusedCount).toBeNull();
    const vibeguard = result.participation.find((p) => p.tool === 'vibeguard');
    expect(vibeguard?.findingCount).toBe(0);
  });

  it('is NOT degraded only when all three participate', () => {
    const result = mergeEnsemble({
      vibeguard: suppliedReport(vgSide([])),
      semgrep: suppliedReport(semgrepReport),
      codeql: suppliedReport(codeqlReport),
    });
    expect(result.degraded).toBe(false);
    expect(result.degradedNotice).toBeNull();
    expect(result.participatingTools).toEqual(['vibeguard', 'semgrep', 'codeql']);
  });

  it('handles the all-absent case without pretending it succeeded', () => {
    const result = mergeEnsemble({ vibeguard: notSupplied(), semgrep: notSupplied(), codeql: notSupplied() });
    expect(result.merged).toEqual([]);
    expect(result.agreementComputable).toBe(false);
    expect(result.agreementNotComputableReason).toContain('no tool participated');
  });
});

// ---------------------------------------------------------------------------
describe('provenance: the failure would be claiming an external tool was executed', () => {
  const result = mergeEnsemble({
    vibeguard: suppliedReport(vgSide([vgFinding('VG-INJ-001', 'samples/vulnerable/sql_injection.py', 8)])),
    semgrep: suppliedReport(semgrepReport),
    codeql: suppliedReport(codeqlReport),
  });

  it('marks every external member as read from a user-supplied report', () => {
    const external = result.merged.flatMap((r) => r.members).filter((m) => m.tool !== 'vibeguard');
    expect(external.length).toBeGreaterThan(0);
    for (const member of external) {
      expect(member.provenance.obtainedBy).toBe('user-supplied-report');
      expect(member.provenance.reportPath).not.toBeNull();
    }
  });

  it('marks the VibeGuard side as in-process, with no report path', () => {
    const own = result.merged.flatMap((r) => r.members).filter((m) => m.tool === 'vibeguard');
    expect(own.length).toBeGreaterThan(0);
    for (const member of own) {
      expect(member.provenance.obtainedBy).toBe('vibeguard-in-process');
      expect(member.provenance.reportPath).toBeNull();
      expect(member.provenance.versionFromReport).toBe('0.3.3');
    }
  });

  it('says in the participation detail that VibeGuard did not run the external tools', () => {
    for (const tool of ['semgrep', 'codeql'] as const) {
      const entry = result.participation.find((p) => p.tool === tool);
      expect(entry?.detail).toContain('VibeGuard did NOT run');
      expect(entry?.detail).toContain('supplied by the user');
    }
  });

  it('reports the version the report stated and nothing else', () => {
    expect(result.participation.find((p) => p.tool === 'semgrep')?.provenance?.versionFromReport).toBe('1.165.0');
    expect(result.participation.find((p) => p.tool === 'codeql')?.provenance?.versionFromReport).toBe('2.20.3');
  });
});

// ---------------------------------------------------------------------------
describe('agreement labels: the failure would be overstating what the ensemble knows', () => {
  // Three VibeGuard findings placed on top of recorded Semgrep locations, plus
  // one where CodeQL is the only participant with a mapped detector.
  const result = mergeEnsemble({
    vibeguard: suppliedReport(
      vgSide([
        vgFinding('VG-INJ-001', 'samples/vulnerable/sql_injection.py', 8),
        vgFinding('VG-CRYPTO-001', 'samples/vulnerable/weak_crypto.rb', 7),
        vgFinding('VG-QUAL-001', 'samples/vulnerable/xss.js', 30),
      ]),
    ),
    semgrep: suppliedReport(semgrepReport),
    codeql: suppliedReport(codeqlReport),
  });

  it('calls a weakness every detector-bearing tool reported "unanimous"', () => {
    // injection-sql at sql_injection.py:8 — VibeGuard (hand-placed), Semgrep
    // (recorded sqlalchemy-execute-raw-query) and CodeQL (schema-derived
    // py/sql-injection) all have a mapped detector and all report it.
    const row = rowFor(result.merged, 'samples/vulnerable/sql_injection.py', 8, 'injection-sql');
    expect(row?.reportedBy).toEqual(['vibeguard', 'semgrep', 'codeql']);
    expect(row?.couldHaveBeenReportedBy).toEqual(['vibeguard', 'semgrep', 'codeql']);
    expect(row?.silentTools).toEqual([]);
    expect(row?.agreement).toBe('unanimous');
  });

  it('calls a weakness only one of several detector-bearing tools reported "unique-to-tool"', () => {
    // tls-verification-disabled at tls_client.py:42 — CodeQL only. VibeGuard and
    // Semgrep both have mapped detectors for this class and said nothing there,
    // so their silence carries information. THIS is the row the research claim
    // says needs investigation.
    const row = rowFor(result.merged, 'samples/vulnerable/tls_client.py', 42, 'tls-verification-disabled');
    expect(row?.reportedBy).toEqual(['codeql']);
    expect(row?.couldHaveBeenReportedBy).toEqual(['vibeguard', 'semgrep', 'codeql']);
    expect(row?.silentTools).toEqual(['vibeguard', 'semgrep']);
    expect(row?.agreement).toBe('unique-to-tool');
  });

  it('calls a weakness two of three reported "corroborated" and names the tool that stayed quiet', () => {
    // eval-exec at xss.js:9 — Semgrep (recorded eval-detected) and CodeQL
    // (js/code-injection). VibeGuard has VG-INJ-004 mapped for this class and
    // was not placed there, so it is the silent tool.
    const row = rowFor(result.merged, 'samples/vulnerable/xss.js', 9, 'eval-exec');
    expect(row?.reportedBy).toEqual(['semgrep', 'codeql']);
    expect(row?.silentTools).toEqual(['vibeguard']);
    expect(row?.agreement).toBe('corroborated');
  });

  it('does NOT call a weakness only one tool can see "unique-to-tool" — that is sole-detector', () => {
    // ★ TRAP 1 FROM THE Agreement DOC. cookie-session-flags at
    // express_session.js:14: Semgrep and VibeGuard have mapped detectors, CodeQL
    // does not. Here only Semgrep reported it and VibeGuard was silent, so it IS
    // unique-to-tool — but CodeQL must NOT appear in silentTools, because
    // nothing in the table teaches us to recognise a CodeQL cookie-flag finding.
    const row = rowFor(result.merged, 'samples/vulnerable/express_session.js', 14, 'cookie-session-flags');
    expect(row?.reportedBy).toEqual(['semgrep']);
    expect(row?.couldHaveBeenReportedBy).toEqual(['vibeguard', 'semgrep']);
    expect(row?.silentTools).toEqual(['vibeguard']);
    expect(row?.agreement).toBe('unique-to-tool');
  });

  it('labels sole-detector when no other participating tool has a mapped detector', () => {
    // Only Semgrep participates and only Semgrep has a debug-enabled detector in
    // the table, so nobody else's silence means anything.
    const soloish = mergeEnsemble({
      vibeguard: suppliedReport(vgSide([])),
      semgrep: suppliedReport(semgrepReport),
      codeql: suppliedReport(codeqlReport),
    });
    const row = rowFor(soloish.merged, 'samples/vulnerable/flask_app.py', 19, 'debug-enabled');
    expect(row?.reportedBy).toEqual(['semgrep']);
    // VibeGuard has VG-FW-002 mapped, so it IS in couldHave — the tool that is
    // absent from it is CodeQL, which has no mapped debug-mode pattern.
    expect(row?.couldHaveBeenReportedBy).toEqual(['vibeguard', 'semgrep']);
    expect(row?.agreement).toBe('unique-to-tool');

    // The genuinely sole-detector case: drop VibeGuard from the ensemble, so
    // Semgrep is the only participant with a mapped debug-enabled detector.
    const withoutVibeguard = mergeEnsemble({
      vibeguard: notSupplied(),
      semgrep: suppliedReport(semgrepReport),
      codeql: suppliedReport(codeqlReport),
    });
    const soleRow = rowFor(withoutVibeguard.merged, 'samples/vulnerable/flask_app.py', 19, 'debug-enabled');
    expect(soleRow?.couldHaveBeenReportedBy).toEqual(['semgrep']);
    expect(soleRow?.silentTools).toEqual([]);
    expect(soleRow?.agreement).toBe('sole-detector');
  });

  it('never labels an unmapped finding unique-to-tool', () => {
    // ★ TRAP 2 FROM THE Agreement DOC. "Only Semgrep found it" is a claim about
    // what the other tools did; an unmapped finding licenses no such claim.
    const unclassified = result.merged.filter((r) => r.weaknessClass === null);
    expect(unclassified.length).toBeGreaterThan(0);
    for (const row of unclassified) {
      expect(row.agreement).toBe('unclassified');
      expect(row.couldHaveBeenReportedBy).toEqual([]);
      expect(row.silentTools).toEqual([]);
    }
  });

  it('never puts a tool in reportedBy that is missing from couldHaveBeenReportedBy', () => {
    // The invariant classifyAgreement's arithmetic depends on.
    for (const row of result.merged) {
      if (row.weaknessClass === null) continue;
      for (const tool of row.reportedBy) {
        expect(row.couldHaveBeenReportedBy).toContain(tool);
      }
    }
  });

  it('accounts for every merged row in byAgreement', () => {
    const total = Object.values(result.byAgreement).reduce((a, b) => a + b, 0);
    expect(total).toBe(result.merged.length);
    // Every label present, including zeros — a missing key would read as "not
    // measured" rather than "measured, and it was zero".
    expect(Object.keys(result.byAgreement).sort()).toEqual([
      'corroborated',
      'not-computable',
      'sole-detector',
      'unanimous',
      'unclassified',
      'unique-to-tool',
    ]);
  });
});

// ---------------------------------------------------------------------------
describe('clustering: the failure would be folding unrelated findings into one row', () => {
  it('keeps the six co-located express_session.js:14 rules from becoming one finding', () => {
    // ★ THE CASE THE RECORDING PROVIDES. Six Semgrep rules fire on that one line:
    // two are the missing-flag weakness, four are different weaknesses. A
    // location-only merge would report all six as one corroborated finding.
    const result = mergeEnsemble({
      vibeguard: suppliedReport(vgSide([])),
      semgrep: suppliedReport(semgrepReport),
      codeql: notSupplied(),
    });
    const atLine14 = result.merged.filter(
      (r) => r.filePath === 'samples/vulnerable/express_session.js' && r.startLine === 14,
    );
    // One row for the mapped cookie-flags weakness (2 members), plus one row per
    // unmapped rule (4 of them) = 5 rows, not 1 and not 6.
    expect(atLine14).toHaveLength(5);
    const flags = atLine14.find((r) => r.weaknessClass === 'cookie-session-flags');
    expect(flags?.members).toHaveLength(2);
    expect(atLine14.filter((r) => r.weaknessClass === null)).toHaveLength(4);
  });

  it('does not chain: findings 2 lines apart in a run do not collapse into one span', () => {
    // ★ THE ANTI-CHAINING PROPERTY. With single-linkage clustering, lines
    // 4/6/8/10 all join (each within 2 of the next) into one 6-line row anchored
    // at 4. Anchor clustering produces two rows: {4,6} and {8,10}.
    const findings = [4, 6, 8, 10].map((line) => vgFinding('VG-INJ-001', 'src/db.ts', line));
    const result = mergeEnsemble({
      vibeguard: suppliedReport(vgSide(findings)),
      semgrep: suppliedReport(semgrepReport),
      codeql: notSupplied(),
    });
    const rows = result.merged.filter((r) => r.filePath === 'src/db.ts');
    expect(rows.map((r) => r.startLine)).toEqual([4, 8]);
    expect(rows.map((r) => r.members.length)).toEqual([2, 2]);
    // Every cluster spans at most the tolerance, by construction.
    for (const row of rows) {
      const lines = row.members.map((m) => m.startLine);
      expect(Math.max(...lines) - Math.min(...lines)).toBeLessThanOrEqual(result.lineTolerance);
    }
  });

  it('anchors a row at a line some tool really reported, never at an average', () => {
    const result = mergeEnsemble({
      vibeguard: suppliedReport(vgSide([vgFinding('VG-INJ-001', 'src/db.ts', 11)])),
      semgrep: suppliedReport(
        parseSemgrepReport(
          JSON.stringify({
            results: [
              {
                check_id: 'x.sqlalchemy-execute-raw-query',
                path: 'src/db.ts',
                start: { line: 13 },
                extra: { severity: 'ERROR' },
              },
            ],
          }),
          { reportPath: 'synthetic.json' },
        ),
      ),
      codeql: notSupplied(),
    });
    const row = rowFor(result.merged, 'src/db.ts', 11, 'injection-sql');
    expect(row?.members.map((m) => m.startLine).sort()).toEqual([11, 13]);
    expect(row?.startLine).toBe(11);
  });

  it('never clusters across files, even at the same line', () => {
    const result = mergeEnsemble({
      vibeguard: suppliedReport(
        vgSide([vgFinding('VG-INJ-001', 'src/a.ts', 5), vgFinding('VG-INJ-001', 'src/b.ts', 5)]),
      ),
      semgrep: suppliedReport(semgrepReport),
      codeql: notSupplied(),
    });
    expect(result.merged.filter((r) => r.weaknessClass === 'injection-sql' && r.filePath.startsWith('src/'))).toHaveLength(2);
  });

  it('never clusters across weakness classes at the same location', () => {
    const result = mergeEnsemble({
      vibeguard: suppliedReport(
        vgSide([vgFinding('VG-INJ-001', 'src/a.ts', 5), vgFinding('VG-CRYPTO-001', 'src/a.ts', 5)]),
      ),
      semgrep: suppliedReport(semgrepReport),
      codeql: notSupplied(),
    });
    const rows = result.merged.filter((r) => r.filePath === 'src/a.ts');
    expect(rows.map((r) => r.weaknessClass).sort()).toEqual(['injection-sql', 'weak-crypto']);
  });

  it('refuses a VibeGuard finding with no file or no line rather than parking it at line 1', () => {
    const snippet = vgFinding('VG-INJ-001', 'src/a.ts', 1);
    delete (snippet as { filePath?: string }).filePath;
    const noLine = vgFinding('VG-INJ-001', 'src/b.ts', 1);
    delete (noLine as { startLine?: number }).startLine;
    const result = mergeEnsemble({
      vibeguard: suppliedReport(vgSide([snippet, noLine, vgFinding('VG-INJ-001', 'src/c.ts', 4)])),
      semgrep: suppliedReport(semgrepReport),
      codeql: notSupplied(),
    });
    const vibeguard = result.participation.find((p) => p.tool === 'vibeguard');
    expect(vibeguard?.refusedCount).toBe(2);
    expect(vibeguard?.findingCount).toBe(1);
    expect(result.merged.some((r) => r.filePath === '')).toBe(false);
  });

  it('normalises VibeGuard paths so a Windows scan joins a POSIX report', () => {
    const result = mergeEnsemble({
      vibeguard: suppliedReport(vgSide([vgFinding('VG-INJ-001', 'samples\\vulnerable\\sql_injection.py', 8)])),
      semgrep: suppliedReport(semgrepReport),
      codeql: notSupplied(),
    });
    const row = rowFor(result.merged, 'samples/vulnerable/sql_injection.py', 8, 'injection-sql');
    expect(row?.reportedBy).toEqual(['vibeguard', 'semgrep']);
  });
});

// ---------------------------------------------------------------------------
describe('determinism: the failure would be a baseline diff that is never empty', () => {
  const input = () => ({
    vibeguard: suppliedReport(
      vgSide([
        vgFinding('VG-INJ-001', 'samples/vulnerable/sql_injection.py', 8),
        vgFinding('VG-INJ-004', 'samples/vulnerable/xss.js', 9),
      ]),
    ),
    semgrep: suppliedReport(semgrepReport),
    codeql: suppliedReport(codeqlReport),
  });

  it('produces byte-identical JSON over two merges of the same inputs', () => {
    expect(JSON.stringify(mergeEnsemble(input()))).toBe(JSON.stringify(mergeEnsemble(input())));
  });

  it('sorts rows by file, then line, and tools by the declared order', () => {
    const result = mergeEnsemble(input());
    const keys = result.merged.map((r) => `${r.filePath}:${String(r.startLine).padStart(6, '0')}`);
    expect(keys).toEqual([...keys].sort());
    for (const row of result.merged) {
      const positions = row.reportedBy.map((t) => ['vibeguard', 'semgrep', 'codeql'].indexOf(t));
      expect(positions).toEqual([...positions].sort((a, b) => a - b));
    }
  });
});

// ---------------------------------------------------------------------------
describe('mapping coverage: the failure would be hiding how partial the mapping is', () => {
  const result = mergeEnsemble({
    vibeguard: suppliedReport(
      vgSide([vgFinding('VG-INJ-001', 'samples/vulnerable/sql_injection.py', 8), vgFinding('VG-QUAL-001', 'src/x.ts', 3)]),
    ),
    semgrep: suppliedReport(semgrepReport),
    codeql: suppliedReport(codeqlReport),
  });

  it('reports the classified/unclassified split per tool', () => {
    expect(result.mappingCoverage.totalFindings).toBe(2 + 20 + 6);
    expect(result.mappingCoverage.byTool['semgrep']).toEqual({ classified: 11, unclassified: 9 });
    expect(result.mappingCoverage.byTool['codeql']).toEqual({ classified: 5, unclassified: 1 });
    expect(result.mappingCoverage.byTool['vibeguard']).toEqual({ classified: 1, unclassified: 1 });
    expect(result.mappingCoverage.classified + result.mappingCoverage.unclassified).toBe(
      result.mappingCoverage.totalFindings,
    );
  });

  it('lists the unmapped rule ids, which is the to-do list for extending the table', () => {
    expect(result.mappingCoverage.unmappedRuleIds).toContain('vibeguard:VG-QUAL-001');
    expect(result.mappingCoverage.unmappedRuleIds).toContain('codeql:js/insecure-randomness');
    expect(result.mappingCoverage.unmappedRuleIds).toContain(
      'semgrep:go.lang.security.audit.crypto.math_random.math-random-used',
    );
    expect(result.mappingCoverage.unmappedRuleIds).toEqual([...result.mappingCoverage.unmappedRuleIds].sort());
  });

  it('carries the unobservable caveat on every run', () => {
    expect(result.unobservable).toContain('unobservable from reports alone');
    expect(result.unobservable).toContain('is not evidence that there are none');
  });

  it('surfaces the tool\'s own reported errors on the participation record', () => {
    const broken: ExternalReport = {
      ...semgrepReport,
      toolReportedErrors: ['SourceParseError: cannot parse src/broken.py'],
    };
    const withErrors = mergeEnsemble({
      vibeguard: suppliedReport(vgSide([])),
      semgrep: suppliedReport(broken),
      codeql: notSupplied(),
    });
    expect(withErrors.participation.find((p) => p.tool === 'semgrep')?.toolReportedErrors).toEqual([
      'SourceParseError: cannot parse src/broken.py',
    ]);
  });
});

// ---------------------------------------------------------------------------
describe('mergedSeverity / mergedConfidence', () => {
  it('takes the maximum, so a second opinion can raise the alarm and never lower it', () => {
    const result = mergeEnsemble({
      vibeguard: suppliedReport(
        vgSide([
          vgFinding('VG-INJ-001', 'samples/vulnerable/sql_injection.py', 8, { severity: 'low', confidence: 'low' }),
        ]),
      ),
      semgrep: suppliedReport(semgrepReport),
      codeql: notSupplied(),
    });
    const row = rowFor(result.merged, 'samples/vulnerable/sql_injection.py', 8, 'injection-sql');
    // VibeGuard low/low (hand-placed above) against the RECORDED Semgrep
    // sqlalchemy-execute-raw-query, whose metadata says severity ERROR and
    // confidence LOW. So severity rises to high and confidence stays low —
    // the maximum of {low, low} is low, and inventing a lift here would be
    // manufacturing certainty out of two tools that both declined to claim any.
    expect(row?.members.map((m) => m.severity).sort()).toEqual(['high', 'low']);
    expect(row?.members.map((m) => m.confidence).sort()).toEqual(['low', 'low']);
    expect(mergedSeverity(row as MergedFinding)).toBe('high');
    expect(mergedConfidence(row as MergedFinding)).toBe('low');
  });

  it('lifts confidence when one member is more certain', () => {
    const result = mergeEnsemble({
      vibeguard: suppliedReport(
        vgSide([
          vgFinding('VG-INJ-001', 'samples/vulnerable/sql_injection.py', 8, { severity: 'low', confidence: 'high' }),
        ]),
      ),
      semgrep: suppliedReport(semgrepReport),
      codeql: notSupplied(),
    });
    const row = rowFor(result.merged, 'samples/vulnerable/sql_injection.py', 8, 'injection-sql');
    expect(mergedConfidence(row as MergedFinding)).toBe('high');
  });

  it('does not depend on the declared tool order', () => {
    // If it did, the answer would be a display constant rather than a judgement.
    const one = mergeEnsemble({
      vibeguard: suppliedReport(
        vgSide([vgFinding('VG-INJ-001', 'samples/vulnerable/sql_injection.py', 8, { severity: 'critical' })]),
      ),
      semgrep: suppliedReport(semgrepReport),
      codeql: notSupplied(),
    });
    const row = rowFor(one.merged, 'samples/vulnerable/sql_injection.py', 8, 'injection-sql');
    expect(mergedSeverity(row as MergedFinding)).toBe('critical');
  });
});
