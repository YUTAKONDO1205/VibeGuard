import { describe, expect, it } from 'vitest';
import {
  allDesignSmellLocations,
  compareConfidence,
  compareSeverity,
  designSmellLocationsAgree,
  emptySummary,
  isDesignSmellFinding,
  isSecurityJudgementSeverity,
  summarize,
  DESIGN_SMELL_CATEGORY,
  DESIGN_SMELL_SCOPE_ORDER,
  SECURITY_JUDGEMENT_SEVERITIES,
  SEVERITY_ORDER,
  type DesignSmellFinding,
  type DesignSmellScope,
  type Finding,
  type Severity,
} from './index.js';

const fakeFinding = (severity: Finding['severity']): Finding => ({
  findingId: 'f1',
  ruleId: 'r1',
  title: 't',
  description: 'd',
  severity,
  confidence: 'high',
  category: 'test',
  sourceEngine: 'core-rule',
});

describe('summarize', () => {
  it('returns zeros for empty input', () => {
    expect(summarize([])).toEqual(emptySummary());
  });

  it('counts severities correctly', () => {
    const findings = [
      fakeFinding('critical'),
      fakeFinding('high'),
      fakeFinding('high'),
      fakeFinding('low'),
    ];
    expect(summarize(findings)).toEqual({
      critical: 1,
      high: 2,
      medium: 0,
      low: 1,
      info: 0,
      total: 4,
    });
  });
});

describe('compareSeverity', () => {
  it('sorts critical before high', () => {
    expect(compareSeverity('critical', 'high')).toBeLessThan(0);
  });
  it('sorts info last', () => {
    expect(compareSeverity('info', 'low')).toBeGreaterThan(0);
  });
});

describe('isSecurityJudgementSeverity', () => {
  it('covers critical, high and medium', () => {
    expect(isSecurityJudgementSeverity('critical')).toBe(true);
    expect(isSecurityJudgementSeverity('high')).toBe(true);
    // The medium band is the one the confidence-floor measurement showed to be
    // the practical hiding place, so it is inside the boundary on purpose.
    expect(isSecurityJudgementSeverity('medium')).toBe(true);
  });

  it('leaves low and info to the utility mechanisms', () => {
    expect(isSecurityJudgementSeverity('low')).toBe(false);
    expect(isSecurityJudgementSeverity('info')).toBe(false);
  });

  it('decides every severity in the schema', () => {
    // The table is total by design: a severity added to `Severity` without a
    // decision here must not silently fall out as "not a security judgement".
    for (const severity of Object.keys(SEVERITY_ORDER) as Severity[]) {
      expect(SECURITY_JUDGEMENT_SEVERITIES[severity]).toBeTypeOf('boolean');
    }
    expect(Object.keys(SECURITY_JUDGEMENT_SEVERITIES).sort()).toEqual(
      Object.keys(SEVERITY_ORDER).sort(),
    );
  });

  it('is a contiguous top slice of the severity ladder', () => {
    // Mutation control: this fails if anyone punches a hole in the middle of
    // the band (e.g. flipping `medium` to false while `low` stays false is
    // fine, but marking `low` true while `medium` is false is not a boundary,
    // it is a bug). The predicate must be monotone in SEVERITY_ORDER.
    const ladder = (Object.keys(SEVERITY_ORDER) as Severity[]).sort(
      (a, b) => SEVERITY_ORDER[b] - SEVERITY_ORDER[a],
    );
    const included = ladder.map((s) => isSecurityJudgementSeverity(s));
    const firstExcluded = included.indexOf(false);
    expect(firstExcluded).toBeGreaterThan(0); // not empty
    expect(included.slice(firstExcluded).every((v) => v === false)).toBe(true);
  });

  it('agrees with the boundary the confidence floor drew', () => {
    // Seeded-violation guard for the shared-predicate claim: D5 / A1-LIMIT and
    // SEVERITY_CONFIDENCE_FLOOR must not drift apart. The floor gates exactly
    // critical/high/medium (non-null floor); this predicate must match.
    const flooredByConfidenceGate: Severity[] = ['critical', 'high', 'medium'];
    for (const severity of Object.keys(SEVERITY_ORDER) as Severity[]) {
      expect(isSecurityJudgementSeverity(severity)).toBe(
        flooredByConfidenceGate.includes(severity),
      );
    }
  });
});

describe('compareConfidence', () => {
  it('sorts high before medium', () => {
    expect(compareConfidence('high', 'medium')).toBeLessThan(0);
  });
  it('sorts low last', () => {
    expect(compareConfidence('low', 'medium')).toBeGreaterThan(0);
  });
  it('treats equal confidence as a tie', () => {
    expect(compareConfidence('medium', 'medium')).toBe(0);
  });
  it('reads as "at least as confident as" when compared against a threshold', () => {
    // The idiom --min-confidence relies on: `<= 0` means the finding survives.
    expect(compareConfidence('high', 'low')).toBeLessThanOrEqual(0);
    expect(compareConfidence('low', 'low')).toBeLessThanOrEqual(0);
    expect(compareConfidence('low', 'high')).toBeGreaterThan(0);
  });
});

// ── Design smells (0.3.0-α, #21 SCHEMA) ─────────────────────────────────────

const fakeSmell = (over: Partial<DesignSmellFinding> = {}): DesignSmellFinding => ({
  findingId: 's1',
  ruleId: 'VG-SMELL-010',
  title: 'Scattered Authorization',
  description: 'd',
  severity: 'medium',
  confidence: 'medium',
  category: DESIGN_SMELL_CATEGORY,
  sourceEngine: 'core-rule',
  scope: 'project',
  filePath: 'src/routes/admin.ts',
  startLine: 12,
  ...over,
});

describe('isDesignSmellFinding', () => {
  it('classifies by category, not by the presence of a scope field', () => {
    expect(isDesignSmellFinding(fakeSmell())).toBe(true);
    // A finding carrying a scope but the wrong category is NOT in the partition:
    // membership is what the E2 regression contract is written in terms of.
    const impostor = { ...fakeSmell(), category: 'injection' } as Finding;
    expect(isDesignSmellFinding(impostor)).toBe(false);
  });

  it('leaves ordinary findings out', () => {
    expect(isDesignSmellFinding(fakeFinding('critical'))).toBe(false);
  });

  it('partitions a mixed list without touching the other half', () => {
    const core = [fakeFinding('critical'), fakeFinding('low')];
    const mixed: Finding[] = [...core, fakeSmell()];
    expect(mixed.filter((f) => !isDesignSmellFinding(f))).toEqual(core);
  });
});

describe('designSmellLocationsAgree', () => {
  it('accepts a finding with no primaryLocation (absence is not a contradiction)', () => {
    expect(designSmellLocationsAgree(fakeSmell())).toBe(true);
  });

  it('accepts a primaryLocation that mirrors the flat fields', () => {
    const f = fakeSmell({
      primaryLocation: { filePath: 'src/routes/admin.ts', startLine: 12 },
    });
    expect(designSmellLocationsAgree(f)).toBe(true);
  });

  it('rejects a drifted path', () => {
    const f = fakeSmell({
      primaryLocation: { filePath: 'src/routes/users.ts', startLine: 12 },
    });
    expect(designSmellLocationsAgree(f)).toBe(false);
  });

  it('rejects a drifted line', () => {
    const f = fakeSmell({
      primaryLocation: { filePath: 'src/routes/admin.ts', startLine: 44 },
    });
    expect(designSmellLocationsAgree(f)).toBe(false);
  });

  it('rejects an endLine present on one side only', () => {
    const f = fakeSmell({
      primaryLocation: { filePath: 'src/routes/admin.ts', startLine: 12, endLine: 20 },
    });
    expect(designSmellLocationsAgree(f)).toBe(false);
  });
});

describe('allDesignSmellLocations', () => {
  it('puts the primary first and preserves related order', () => {
    const f = fakeSmell({
      primaryLocation: { filePath: 'src/routes/admin.ts', startLine: 12 },
      relatedLocations: [
        { filePath: 'src/routes/users.ts', startLine: 44 },
        { filePath: 'src/routes/settings.ts', startLine: 31 },
      ],
    });
    expect(allDesignSmellLocations(f).map((l) => l.filePath)).toEqual([
      'src/routes/admin.ts',
      'src/routes/users.ts',
      'src/routes/settings.ts',
    ]);
  });

  it('synthesises the primary from the flat fields when it is absent', () => {
    const f = fakeSmell({ relatedLocations: [{ filePath: 'b.ts', startLine: 1 }] });
    expect(allDesignSmellLocations(f)).toEqual([
      { filePath: 'src/routes/admin.ts', startLine: 12, endLine: undefined },
      { filePath: 'b.ts', startLine: 1 },
    ]);
  });

  it('returns nothing when there is no location at all (snippet scan)', () => {
    const f = fakeSmell({ filePath: undefined, startLine: undefined });
    expect(allDesignSmellLocations(f)).toEqual([]);
  });
});

describe('DESIGN_SMELL_SCOPE_ORDER', () => {
  it('runs narrowest to widest', () => {
    const scopes: DesignSmellScope[] = ['line', 'symbol', 'class', 'file', 'module', 'project'];
    const ranks = scopes.map((s) => DESIGN_SMELL_SCOPE_ORDER[s]);
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });

  it('is total, so adding a scope breaks the build rather than defaulting', () => {
    expect(Object.keys(DESIGN_SMELL_SCOPE_ORDER)).toHaveLength(6);
  });
});
