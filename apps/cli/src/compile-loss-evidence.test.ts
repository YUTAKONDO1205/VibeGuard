// The CLI is where the sentence actually reaches a person, so this is where
// the wording rule is worth the most and where the temptation to "just show a
// share" is strongest. Both renderers print the one permitted sentence and
// nothing derived from it, and neither prints anything at all when no consumer
// supplied a cell.
import { describe, expect, it } from 'vitest';
import type {
  CompileLossEvidence,
  Finding,
  ScanResponse,
} from '@vibeguard/findings-schema';
import { formatHuman, formatMarkdown } from './format.js';

const R2_CLANG_O2: CompileLossEvidence = {
  num: 113,
  den: 133,
  corpusId: 'r2',
  vendor: 'clang-18',
  optLevel: '-O2',
};

const SENTENCE =
  '113 of 133 files with this idiom lost the wipe under clang-18 -O2 in corpus r2';

function finding(over: Partial<Finding> = {}): Finding {
  return {
    findingId: 'f1',
    ruleId: 'VG-MEM-001',
    title: 'Wipe may be removed by the compiler',
    description: 'A secret is cleared with a call the optimiser is free to drop.',
    severity: 'high',
    confidence: 'high',
    category: 'memory',
    filePath: 'src/keys.c',
    startLine: 42,
    sourceEngine: 'core-rule',
    ...over,
  };
}

function scan(findings: Finding[], over: Partial<ScanResponse> = {}): ScanResponse {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: findings.length };
  for (const f of findings) summary[f.severity] += 1;
  return {
    summary,
    findings,
    executionTimeMs: 12,
    engineVersions: { core: '0.3.3' },
    generatedAt: '2026-09-12T00:00:00.000Z',
    ...over,
  };
}

describe('the human renderer', () => {
  it('prints the permitted sentence, verbatim', () => {
    const out = formatHuman(scan([finding({ compileLossEvidence: R2_CLANG_O2 })]), false);
    expect(out).toContain(`corpus: ${SENTENCE}`);
  });

  it('prints nothing when no cell was supplied', () => {
    const out = formatHuman(scan([finding()]), false);
    expect(out).not.toContain('corpus:');
    expect(out).not.toContain('lost the wipe');
  });

  it('names the malformed entries a consumer supplied instead of dropping them in silence', () => {
    const out = formatHuman(
      scan([finding()], {
        compileLossEvidenceRejections: [
          { ruleId: 'VG-MEM-001', detail: 'compileLossEvidence supplied for VG-MEM-001 was dropped.' },
        ],
      }),
      false,
    );
    expect(out).toContain('VG-MEM-001 was dropped');
  });

  it('says it on the zero-findings path too', () => {
    const out = formatHuman(
      scan([], {
        compileLossEvidenceRejections: [
          { ruleId: 'VG-MEM-001', detail: 'compileLossEvidence supplied for VG-MEM-001 was dropped.' },
        ],
      }),
      false,
    );
    expect(out).toContain('✓ No findings.');
    expect(out).toContain('VG-MEM-001 was dropped');
  });
});

describe('the markdown renderer', () => {
  it('prints the permitted sentence, verbatim', () => {
    const out = formatMarkdown(scan([finding({ compileLossEvidence: R2_CLANG_O2 })]));
    expect(out).toContain(`- _corpus_: ${SENTENCE}`);
  });

  it('prints nothing when no cell was supplied', () => {
    const out = formatMarkdown(scan([finding()]));
    expect(out).not.toContain('_corpus_');
    expect(out).not.toContain('lost the wipe');
  });

  it('names malformed entries', () => {
    const out = formatMarkdown(
      scan([finding()], {
        compileLossEvidenceRejections: [
          { ruleId: 'VG-MEM-001', detail: 'compileLossEvidence supplied for VG-MEM-001 was dropped.' },
        ],
      }),
    );
    expect(out).toContain('VG-MEM-001 was dropped');
  });
});

describe('neither renderer reshapes the ratio', () => {
  it('emits no derived quantity anywhere in either output', () => {
    // Needles assembled from fragments so this file cannot match itself if the
    // sweep is ever widened to the test sources, following
    // `scripts/check-disclosure-shape.mjs`.
    const needles = [
      new RegExp(String.fromCharCode(37)),
      new RegExp(['perc', 'ent'].join(''), 'i'),
      new RegExp(['prob', 'abil'].join(''), 'i'),
      new RegExp('0\\.8'), // 113/133, had anyone divided
    ];
    const outputs = [
      formatHuman(scan([finding({ compileLossEvidence: R2_CLANG_O2 })]), false),
      formatHuman(scan([finding({ compileLossEvidence: R2_CLANG_O2 })]), true),
      formatMarkdown(scan([finding({ compileLossEvidence: R2_CLANG_O2 })])),
    ];
    for (const out of outputs) {
      for (const needle of needles) {
        expect(needle.test(out), `rendered output reshapes the ratio:\n${out}`).toBe(false);
      }
    }
  });
});
