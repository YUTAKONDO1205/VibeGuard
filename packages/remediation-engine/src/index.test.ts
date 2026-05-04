import { describe, expect, it } from 'vitest';
import type { RuleDefinition } from '@vibeguard/rules';
import { buildRemediation } from './index.js';

const baseRule: RuleDefinition = {
  ruleId: 'TEST-1',
  name: 'demo',
  description: 'demo desc',
  languages: ['*'],
  category: 'injection',
  severity: 'high',
  defaultConfidence: 'medium',
  match: () => [],
};

describe('buildRemediation', () => {
  it('falls back when rule has no remediation template', () => {
    const r = buildRemediation(baseRule);
    expect(r.why).toBe('demo desc');
    expect(r.how).toMatch(/manually/i);
    expect(r.references?.length).toBeGreaterThan(0);
  });

  it('uses template fields when present', () => {
    const r = buildRemediation({
      ...baseRule,
      remediation: { why: 'because', how: 'do that', exampleFix: 'foo()' },
    });
    expect(r.why).toBe('because');
    expect(r.how).toBe('do that');
    expect(r.exampleFix).toBe('foo()');
  });

  it('merges rule references with category defaults uniquely', () => {
    const r = buildRemediation({
      ...baseRule,
      references: ['https://example.com/extra'],
      remediation: { why: 'a', how: 'b' },
    });
    const refs = r.references ?? [];
    expect(refs).toContain('https://example.com/extra');
    expect(new Set(refs).size).toBe(refs.length);
  });
});
