import { describe, expect, it } from 'vitest';
import { Analyzer, scan } from './analyzer.js';

describe('Analyzer', () => {
  it('returns empty result for empty content', () => {
    const r = scan({ targetType: 'snippet', content: '', mode: 'standard' });
    expect(r.findings).toEqual([]);
    expect(r.summary.total).toBe(0);
  });

  it('detects an inline eval', () => {
    const r = scan({
      targetType: 'snippet',
      content: 'const v = eval("1+1");',
      mode: 'fast',
      filePath: 'inline.js',
    });
    expect(r.findings.some((f) => f.ruleId === 'VG-INJ-004')).toBe(true);
  });

  it('detects multiple categories in one input', () => {
    const code = `
const AWS = "AKIAIOSFODNN7EXAMPLE";
function go() { eval(input); el.innerHTML = data; }
`;
    const r = scan({ targetType: 'snippet', content: code, mode: 'standard', filePath: 'a.js' });
    const ruleIds = new Set(r.findings.map((f) => f.ruleId));
    expect(ruleIds.has('VG-INJ-004')).toBe(true);
    expect(ruleIds.has('VG-INJ-006')).toBe(true);
    expect(ruleIds.has('VG-SEC-001')).toBe(true);
  });

  it('orders findings by severity', () => {
    const code = `
// medium first in source, critical second
const slowKey = "abcdefghijklmnopqrstuvwxyz";
const apiKey = "AKIAIOSFODNN7EXAMPLE";
`;
    const r = scan({ targetType: 'snippet', content: code, mode: 'standard', filePath: 'a.js' });
    if (r.findings.length >= 2) {
      const first = r.findings[0]!;
      const last = r.findings[r.findings.length - 1]!;
      const order = ['critical', 'high', 'medium', 'low', 'info'];
      expect(order.indexOf(first.severity)).toBeLessThanOrEqual(order.indexOf(last.severity));
    }
  });

  it('omits remediation when requested', () => {
    const r = scan({
      targetType: 'snippet',
      content: 'const v = eval(x);',
      mode: 'standard',
      filePath: 'a.js',
      includeRemediation: false,
    });
    for (const f of r.findings) {
      expect(f.remediation).toBeUndefined();
    }
  });

  it('masks the secret category snippet', () => {
    const code = 'const k = "AKIAIOSFODNN7EXAMPLE";';
    const r = scan({ targetType: 'snippet', content: code, mode: 'standard', filePath: 'a.js' });
    const aws = r.findings.find((f) => f.ruleId === 'VG-SEC-001');
    expect(aws).toBeDefined();
    if (aws?.snippet) {
      expect(aws.snippet).not.toContain('AKIAIOSFODNN7EXAMPLE');
    }
  });

  it('does not crash on unknown language', () => {
    const r = scan({
      targetType: 'snippet',
      content: '<some xml>',
      mode: 'fast',
      language: 'xml',
    });
    expect(r.findings).toBeDefined();
  });

  it('Analyzer instance reuses configuration', () => {
    const a = new Analyzer();
    const r1 = a.scan({ targetType: 'snippet', content: 'eval(x)', mode: 'fast', filePath: 'a.js' });
    const r2 = a.scan({ targetType: 'snippet', content: 'eval(y)', mode: 'fast', filePath: 'b.js' });
    expect(r1.findings.length).toBeGreaterThan(0);
    expect(r2.findings.length).toBeGreaterThan(0);
  });
});
