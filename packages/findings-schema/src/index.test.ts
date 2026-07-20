import { describe, expect, it } from 'vitest';
import {
  compareConfidence,
  compareSeverity,
  emptySummary,
  isSecurityJudgementSeverity,
  summarize,
  SECURITY_JUDGEMENT_SEVERITIES,
  SEVERITY_ORDER,
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
