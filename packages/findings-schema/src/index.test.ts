import { describe, expect, it } from 'vitest';
import {
  compareConfidence,
  compareSeverity,
  emptySummary,
  summarize,
  type Finding,
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
