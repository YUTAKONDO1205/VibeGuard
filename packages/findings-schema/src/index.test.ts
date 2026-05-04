import { describe, expect, it } from 'vitest';
import { compareSeverity, emptySummary, summarize, type Finding } from './index.js';

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
