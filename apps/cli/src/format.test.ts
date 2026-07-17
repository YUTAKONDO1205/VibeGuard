import { describe, expect, it } from 'vitest';
import type { Finding, ScanResponse } from '@vibeguard/findings-schema';
import { formatHuman, formatMarkdown } from './format.js';

function scan(findings: Finding[], executionTimeMs = 12): ScanResponse {
  const summary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
    total: findings.length,
  };
  for (const f of findings) summary[f.severity] += 1;
  return {
    summary,
    findings,
    executionTimeMs,
    engineVersions: { core: '0.1.0' },
    generatedAt: '2026-05-09T00:00:00.000Z',
  };
}

function finding(over: Partial<Finding> = {}): Finding {
  return {
    findingId: 'f1',
    ruleId: 'SEC-001',
    title: 'Hardcoded API Key',
    description: 'Detected a hardcoded API key.',
    severity: 'high',
    confidence: 'high',
    category: 'secret',
    filePath: 'packages/foo/src/bar.ts',
    startLine: 42,
    sourceEngine: 'core-rule',
    remediation: {
      why: 'Secrets in source code can leak via VCS.',
      how: 'Move the key to an environment variable.',
      exampleFix: 'const key = process.env.API_KEY;',
    },
    ...over,
  };
}

describe('formatMarkdown', () => {
  it('renders an empty-findings message', () => {
    const md = formatMarkdown(scan([]));
    expect(md).toContain('## VibeGuard Security Scan');
    expect(md).toContain('No findings detected');
    expect(md).toContain('Scanned in 12ms');
  });

  it('renders the summary line and finding details', () => {
    const md = formatMarkdown(scan([finding()]));
    expect(md).toContain('**critical**: 0');
    expect(md).toContain('**high**: 1');
    expect(md).toContain('total: 1 / scanned in 12ms');
    expect(md).toContain('#### 🔴 HIGH — Hardcoded API Key (`SEC-001`)');
    expect(md).toContain('`packages/foo/src/bar.ts:42`');
    expect(md).toContain('_why_:');
    expect(md).toContain('_fix_:');
    expect(md).toContain('process.env.API_KEY');
  });

  it('sorts findings by severity descending', () => {
    const md = formatMarkdown(
      scan([
        finding({ findingId: 'a', severity: 'low', title: 'Low one', ruleId: 'QUAL-001' }),
        finding({ findingId: 'b', severity: 'critical', title: 'Crit one', ruleId: 'INJ-001' }),
        finding({ findingId: 'c', severity: 'medium', title: 'Med one', ruleId: 'AUTH-001' }),
      ]),
    );
    const critIdx = md.indexOf('Crit one');
    const medIdx = md.indexOf('Med one');
    const lowIdx = md.indexOf('Low one');
    expect(critIdx).toBeGreaterThan(-1);
    expect(critIdx).toBeLessThan(medIdx);
    expect(medIdx).toBeLessThan(lowIdx);
  });

  it('truncates above the per-comment cap', () => {
    const many = Array.from({ length: 35 }, (_, i) =>
      finding({ findingId: `f${i}`, ruleId: `RULE-${i}`, startLine: i + 1 }),
    );
    const md = formatMarkdown(scan(many));
    expect(md).toContain('+5 more, see SARIF');
    expect((md.match(/^#### /gm) ?? []).length).toBe(30);
  });

  it('surfaces ruleErrors in markdown, even with no findings', () => {
    const response: ScanResponse = {
      ...scan([]),
      ruleErrors: [{ ruleId: 'VG-TEST-BOOM', message: 'kaboom' }],
    };
    const md = formatMarkdown(response);
    expect(md).toContain('errored and were skipped');
    expect(md).toContain('VG-TEST-BOOM');
    expect(md).toContain('kaboom');
  });

  it('surfaces ruleErrors in human output', () => {
    const response: ScanResponse = {
      ...scan([]),
      ruleErrors: [{ ruleId: 'VG-TEST-BOOM', message: 'kaboom' }],
    };
    const out = formatHuman(response, false);
    expect(out).toContain('errored and were skipped');
    expect(out).toContain('VG-TEST-BOOM: kaboom');
  });

  it('omits the ruleErrors block when there are none', () => {
    expect(formatMarkdown(scan([]))).not.toContain('errored and were skipped');
    expect(formatHuman(scan([]), false)).not.toContain('errored and were skipped');
  });
});
