// SARIF carries `compileLossEvidence` through as the two integers, under its
// own key, and only when a consumer supplied one.
//
// The property bag is where a downstream dashboard goes looking for a number,
// so this is the surface on which "113 of 133" would most plausibly be turned
// into something with no denominator. It is also the surface on which an absent
// annotation would most plausibly become a present-and-undefined one, which
// tells an enumerating consumer that a corpus was counted when none was.
import { describe, expect, it } from 'vitest';
import type { CompileLossEvidence, Finding, ScanResponse } from '@vibeguard/findings-schema';
import { toSarif } from './index.js';

const R2_CLANG_O2: CompileLossEvidence = {
  num: 113,
  den: 133,
  corpusId: 'r2',
  vendor: 'clang-18',
  optLevel: '-O2',
};

const finding = (overrides: Partial<Finding> = {}): Finding => ({
  findingId: 'f-1',
  ruleId: 'VG-TEST-001',
  title: 'demo',
  description: 'demo description',
  severity: 'high',
  confidence: 'high',
  category: 'memory',
  filePath: 'src/a.c',
  startLine: 4,
  endLine: 4,
  sourceEngine: 'core-rule',
  ...overrides,
});

const wrap = (findings: Finding[]): ScanResponse => ({
  summary: {
    critical: 0,
    high: findings.length,
    medium: 0,
    low: 0,
    info: 0,
    total: findings.length,
  },
  findings,
  executionTimeMs: 1,
  engineVersions: { core: '0.3.3' },
  generatedAt: '2026-09-12T00:00:00Z',
});

describe('SARIF properties carry compileLossEvidence', () => {
  it('passes the cell through unchanged', () => {
    const log = toSarif(wrap([finding({ compileLossEvidence: R2_CLANG_O2 })]));
    expect(log.runs[0]!.results[0]!.properties!.compileLossEvidence).toEqual(R2_CLANG_O2);
  });

  it('omits the key entirely when the finding has no cell', () => {
    const log = toSarif(wrap([finding()]));
    const props = log.runs[0]!.results[0]!.properties!;
    // Not `toBeUndefined`: an enumerating consumer sees a key holding
    // `undefined`, and this channel's whole contract is that absence means
    // "nobody counted a corpus for this rule".
    expect('compileLossEvidence' in props).toBe(false);
    expect(JSON.stringify(log)).not.toContain('compileLossEvidence');
  });

  it('keeps both integers, so nothing downstream can quote one without the other', () => {
    const json = JSON.stringify(
      toSarif(wrap([finding({ compileLossEvidence: R2_CLANG_O2 })])),
    );
    expect(json).toContain('"num":113');
    expect(json).toContain('"den":133');
  });

  it('does not touch the confidence property it is not a modifier of', () => {
    const plain = toSarif(wrap([finding()])).runs[0]!.results[0]!.properties!;
    const annotated = toSarif(wrap([finding({ compileLossEvidence: R2_CLANG_O2 })])).runs[0]!
      .results[0]!.properties!;
    expect(annotated.confidence).toBe(plain.confidence);
    expect(annotated.severity).toBe(plain.severity);
  });
});
