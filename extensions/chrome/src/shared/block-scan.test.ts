// vibeguard:disable-file VG-INJ-006
// The JS fixture is an innerHTML sink on purpose: the whole point is that a
// mixed-language page must not lose it. Named rule, not a blanket suppression.
import { describe, expect, it } from 'vitest';
import { scan, detectLanguageFromContent } from '@vibeguard/analyzer-core/browser';
import type { ScanResponse } from '@vibeguard/findings-schema';
import { languageForBlock, scanBlocks, type ScanBlocksDeps } from './block-scan.js';

const PY_SINK = 'import subprocess\n\ndef run(name):\n    subprocess.call("ls " + name, shell=True)\n';
const JS_SINK =
  'function render(userInput) {\n  const el = document.getElementById("out");\n  el.innerHTML = userInput;\n}\n';

const real: ScanBlocksDeps = { scan, detectLanguageFromContent };

/**
 * The property that matters: a page whose blocks are in different languages
 * must not lose one language's findings.
 *
 * The old panel concatenated every block into one snippet and scanned it once,
 * under one language, so whichever language it picked, the other language's
 * sinks were invisible — and the page then rendered as clean.
 */
describe('scanBlocks scans each block in its own language', () => {
  it('finds sinks in BOTH a python and a javascript block', () => {
    const results = scanBlocks(
      [
        { text: PY_SINK, language: 'python' },
        { text: JS_SINK, language: 'javascript' },
      ],
      real,
    );
    expect(results).toHaveLength(2);
    expect(results[0]!.findings.length).toBeGreaterThan(0);
    expect(results[1]!.findings.length).toBeGreaterThan(0);
  });

  // The measurement that motivated the change, kept as an executable statement
  // of it: joining loses a finding whichever language is chosen.
  it('finds strictly more than scanning the same blocks joined into one', () => {
    const blocks = [
      { text: PY_SINK, language: 'python' },
      { text: JS_SINK, language: 'javascript' },
    ];
    const perBlock = scanBlocks(blocks, real).flatMap((r) => r.findings).length;

    const joined = blocks
      .map((b, i) => `// --- block ${i + 1} (${b.language}) ---\n${b.text}`)
      .join('\n\n');
    for (const language of ['python', 'javascript']) {
      const r = scan({
        targetType: 'snippet',
        mode: 'standard',
        content: joined,
        language,
        filePath: 'snippet',
      });
      expect(r.findings.length).toBeLessThan(perBlock);
    }
  });

  it('does not depend on block order', () => {
    const a = scanBlocks(
      [{ text: PY_SINK, language: 'python' }, { text: JS_SINK, language: 'javascript' }],
      real,
    ).flatMap((r) => r.findings).length;
    const b = scanBlocks(
      [{ text: JS_SINK, language: 'javascript' }, { text: PY_SINK, language: 'python' }],
      real,
    ).flatMap((r) => r.findings).length;
    expect(a).toBe(b);
  });
});

describe('languageForBlock', () => {
  it('prefers the block tag over sniffing and over the page fallback', () => {
    expect(languageForBlock({ text: PY_SINK, language: 'python' }, { ...real, fallbackLanguage: 'javascript' }))
      .toBe('python');
  });

  it('falls back to the page picker only when nothing else identifies the block', () => {
    const deps: ScanBlocksDeps = {
      scan,
      detectLanguageFromContent: () => undefined,
      fallbackLanguage: 'ruby',
    };
    expect(languageForBlock({ text: 'x = 1' }, deps)).toBe('ruby');
  });
});

/**
 * An empty finding list is only CLEAN when the block was actually scanned.
 * Rendering the same green tick for "nothing found" and "could not look" turns
 * an engine failure into a pass.
 */
describe('scanBlocks distinguishes clean from unknown', () => {
  const throwing: ScanBlocksDeps = {
    scan: () => {
      throw new Error('boom');
    },
    detectLanguageFromContent: () => 'javascript',
  };

  it('marks a block whose scan threw as unscanned, without failing the rest', () => {
    const results = scanBlocks([{ text: 'const a = 1;\n' }], throwing);
    expect(results[0]!.findings).toEqual([]);
    expect(results[0]!.unscanned).toContain('boom');
  });

  it('leaves `unscanned` absent for a block that really is clean', () => {
    const results = scanBlocks([{ text: 'const a = 1;\n', language: 'javascript' }], real);
    expect(results[0]!.findings).toEqual([]);
    expect(results[0]!.unscanned).toBeUndefined();
  });

  it('marks a block whose rules errored as unscanned', () => {
    const withRuleErrors: ScanBlocksDeps = {
      scan: () =>
        ({
          summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 },
          findings: [],
          ruleErrors: [{ ruleId: 'VG-TEST-1', message: 'threw' }],
          executionTimeMs: 1,
          engineVersions: { core: '0.0.0' },
          generatedAt: '2026-07-29T00:00:00Z',
        }) as ScanResponse,
      detectLanguageFromContent: () => 'javascript',
    };
    const results = scanBlocks([{ text: 'const a = 1;\n' }], withRuleErrors);
    expect(results[0]!.findings).toEqual([]);
    expect(results[0]!.unscanned).toMatch(/rule\(s\) errored/);
  });
});
