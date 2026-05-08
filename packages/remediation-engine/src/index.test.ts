import { describe, expect, it } from 'vitest';
import type { RuleDefinition, RuleMatch } from '@vibeguard/rules';
import { buildRemediation } from './index.js';

function makeMatch(variables?: Record<string, string>): RuleMatch {
  return {
    startLine: 1,
    endLine: 1,
    startColumn: 1,
    endColumn: 2,
    evidence: 'x',
    variables,
  };
}

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

  it('interpolates ${var} in why/how/exampleFix when match.variables provided', () => {
    const r = buildRemediation(
      {
        ...baseRule,
        remediation: {
          why: 'unsafe table ${table}',
          how: 'fix ${table}',
          exampleFix: 'SELECT * FROM ${table}',
        },
      },
      makeMatch({ table: 'users' }),
    );
    expect(r.why).toBe('unsafe table users');
    expect(r.how).toBe('fix users');
    expect(r.exampleFix).toBe('SELECT * FROM users');
  });

  it('leaves unresolved ${unknown} verbatim', () => {
    const r = buildRemediation(
      {
        ...baseRule,
        remediation: { why: 'leftover ${nope}', how: 'no-op' },
      },
      makeMatch({ other: 'x' }),
    );
    expect(r.why).toBe('leftover ${nope}');
  });

  it('is a no-op when match is omitted (back-compat)', () => {
    const r = buildRemediation({
      ...baseRule,
      remediation: { why: 'plain ${var}', how: 'plain' },
    });
    expect(r.why).toBe('plain ${var}');
  });

  it('does not interpolate references', () => {
    const r = buildRemediation(
      {
        ...baseRule,
        references: ['https://example.com/${table}'],
        remediation: { why: 'w', how: 'h' },
      },
      makeMatch({ table: 'users' }),
    );
    expect(r.references).toContain('https://example.com/${table}');
  });
});
