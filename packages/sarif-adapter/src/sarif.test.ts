// vibeguard:disable-file
// Test fixtures contain intentional vulnerable code to exercise the rules.
import { describe, expect, it } from 'vitest';
import type { Finding, ScanResponse } from '@vibeguard/findings-schema';
import { toSarif } from './index.js';

const fakeFinding = (overrides: Partial<Finding> = {}): Finding => ({
  findingId: 'f-1',
  ruleId: 'VG-TEST-001',
  title: 'demo',
  description: 'demo description',
  severity: 'high',
  confidence: 'high',
  category: 'injection',
  filePath: 'src/a.ts',
  startLine: 4,
  endLine: 4,
  snippet: 'eval(x)',
  evidence: ['eval(x)'],
  sourceEngine: 'core-rule',
  ...overrides,
});

const wrap = (findings: Finding[]): ScanResponse => ({
  summary: { critical: 0, high: findings.length, medium: 0, low: 0, info: 0, total: findings.length },
  findings,
  executionTimeMs: 1,
  engineVersions: { core: '0.1.0' },
  generatedAt: '2026-05-04T00:00:00Z',
});

describe('toSarif', () => {
  it('produces a valid 2.1.0 envelope', () => {
    const sarif = toSarif(wrap([fakeFinding()]));
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0]!.tool.driver.name).toBe('VibeGuard');
  });

  it('deduplicates rule descriptors', () => {
    const sarif = toSarif(wrap([fakeFinding(), fakeFinding({ findingId: 'f-2' })]));
    expect(sarif.runs[0]!.tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0]!.results).toHaveLength(2);
  });

  it('maps severity to SARIF level', () => {
    const sarif = toSarif(
      wrap([
        fakeFinding({ severity: 'critical' }),
        fakeFinding({ findingId: 'f-2', severity: 'low', ruleId: 'VG-TEST-002' }),
      ]),
    );
    const levels = sarif.runs[0]!.results.map((r) => r.level);
    expect(levels).toEqual(['error', 'note']);
  });

  it('emits a region with startLine', () => {
    const sarif = toSarif(wrap([fakeFinding()]));
    const region = sarif.runs[0]!.results[0]!.locations[0]!.physicalLocation.region;
    expect(region.startLine).toBe(4);
  });
});
